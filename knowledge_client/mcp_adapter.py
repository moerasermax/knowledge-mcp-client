"""
stdio MCP adapter：透過 HTTP 將工具呼叫轉送至 FastAPI backend。

職責是維持 MCP 的 stdio 服務可用，並在 backend 失聯或卡死時重啟及重試；
backend 無法恢復時也不能讓 adapter 本身退出。
"""

import asyncio
import json
import logging
import os
import subprocess
import sys
from pathlib import Path
from typing import NamedTuple

import httpx
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

log = logging.getLogger(__name__)

BACKEND_HOST = os.environ.get("KNOWLEDGE_BACKEND_HOST", "127.0.0.1")
BACKEND_PORT = int(os.environ.get("KNOWLEDGE_BACKEND_PORT", "19530"))

# 舊的 host+port 組法無法表達 https://xxx.ngrok.app。KNOWLEDGE_BACKEND_URL
# 是完整 URL，設了就以它為準。
BACKEND_URL = (
    os.environ.get("KNOWLEDGE_BACKEND_URL", "").rstrip("/")
    or f"http://{BACKEND_HOST}:{BACKEND_PORT}"
)

_LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost", ""}


def _resolve_backend_mode() -> str:
    """local = backend 由本 adapter 管理；remote = backend 在別台機器上。

    未明示時由 URL 主機名推導：loopback 才算 local。這個預設方向是安全的
    ——把遠端誤判成 local 會讓 adapter 在**使用者自己這台**開 backend、
    甚至拿本機 port 找 PID 去 tree-kill。
    """
    explicit = os.environ.get("KNOWLEDGE_BACKEND_MODE", "").strip().lower()
    if explicit in ("local", "remote"):
        return explicit
    from urllib.parse import urlparse

    host = (urlparse(BACKEND_URL).hostname or "").lower()
    return "local" if host in _LOOPBACK_HOSTS else "remote"


BACKEND_MODE = _resolve_backend_mode()
IS_REMOTE = BACKEND_MODE == "remote"


def _assert_transport_is_safe() -> None:
    """遠端連線必須是 https。明文 http 出了 loopback 就是把簽章標頭與
    知識內容一起攤在網路上。"""
    if not IS_REMOTE:
        return
    from urllib.parse import urlparse

    parsed = urlparse(BACKEND_URL)
    if parsed.scheme != "https":
        raise SystemExit(
            f"拒絕啟動：遠端 backend {BACKEND_URL} 不是 https。"
            "遠端連線一律要求 TLS。"
        )


_CLIENT_KEY_ID = os.environ.get("KNOWLEDGE_CLIENT_KEY_ID", "")
_CLIENT_KEY_FILE = os.environ.get("KNOWLEDGE_CLIENT_KEY_FILE", "")
_signing_key = None


def _get_signing_key():
    """延遲載入私鑰；未設定就回 None（本機 loopback 模式不需要簽章）。"""
    global _signing_key
    if _signing_key is not None:
        return _signing_key
    if not (_CLIENT_KEY_ID and _CLIENT_KEY_FILE):
        return None
    from .auth import load_private_key

    _signing_key = load_private_key(Path(_CLIENT_KEY_FILE))
    return _signing_key


def _signature_headers(method: str, path: str, body: bytes, query: str = "") -> dict:
    """委派給 auth.build_signature_headers——簽章只有一份實作。

    先前 adapter 與 CLI 各有一份，只要一邊漏改 canonical_request 的欄位順序，
    症狀就是「有時候 401」這種很難追的失敗。
    """
    key = _get_signing_key()
    if key is None:
        return {}

    from .auth import build_signature_headers

    return build_signature_headers(
        key, _CLIENT_KEY_ID, method=method, path=path, body=body, query=query
    )


async def _backend_get(path: str, *, timeout: float) -> httpx.Response:
    headers = _signature_headers("GET", path, b"")
    async with httpx.AsyncClient(timeout=timeout) as client:
        return await client.get(f"{BACKEND_URL}{path}", headers=headers)


async def _backend_post_json(path: str, payload: dict, *, timeout: float) -> httpx.Response:
    """簽章必須涵蓋**實際送出的 wire bytes**。

    先自行序列化再用 content= 送出；若交給 httpx 的 json= 再序列化一次，
    空白、Unicode escaping、key 順序都可能與簽章當下不同，簽的與送的
    就是兩份東西。
    """
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    headers = {"content-type": "application/json"}
    headers.update(_signature_headers("POST", path, body))
    async with httpx.AsyncClient(timeout=timeout) as client:
        return await client.post(f"{BACKEND_URL}{path}", content=body, headers=headers)

_DATA_DIR = Path(os.environ.get("KNOWLEDGE_MCP_DATA_DIR", str(Path.home() / ".knowledge-mcp")))
_BACKEND_LOG = _DATA_DIR / "backend.log"
_PID_FILE = _DATA_DIR / "server.pid"
_HEALTH_TIMEOUT_SECONDS = 5
_DEFAULT_TOOL_TIMEOUT_SECONDS = 120
_LONG_RUNNING_TOOL_TIMEOUT_SECONDS = 1800
_READ_ONLY_TOOLS = frozenset({
    "knowledge_list",
    "knowledge_read",
    "knowledge_search",
    "knowledge_namespaces",
})
_LONG_RUNNING_TOOLS = frozenset({
    "knowledge_build_index",
    "knowledge_rebuild_embeddings",
    "knowledge_sync",
    "knowledge_nightly_patrol",
})
_EMBEDDING_DEPENDENT_TOOLS = frozenset({
    "knowledge_rebuild_embeddings",
})

app = Server("knowledge-mcp")
_backend_ensure_lock = asyncio.Lock()
_backend_ensure_task: asyncio.Task[bool] | None = None
_embedding_state: str | None = None
_embedding_degraded_error: str | None = None


class _EmbeddingHealth(NamedTuple):
    """由新舊 health 格式正規化後的 embedding 狀態。"""

    state: str
    error: str | None
    seconds_in_state: float


def _clear_wedged_backend_sync(reason: str) -> bool:
    """在工作執行緒終止 wedged backend；僅在成功時才移除 PID 檔。"""
    if IS_REMOTE:
        # 這段會讀**本機** PID 檔、查**本機** port owner，然後 tree-kill。
        # backend 在別台機器上時，它殺得到的只有自己這台碰巧佔用 19530 的
        # 行程——那是誤傷，不是復原。遠端的生命週期由 SSH 管理。
        log.warning("遠端模式：不嘗試終止遠端 backend（%s）", reason)
        return False
    from .__main__ import _clear_pid, _find_listening_pid, _read_pid, _tree_kill

    pid = _read_pid()
    if pid is None:
        pid = _find_listening_pid(BACKEND_PORT)
        if pid is None:
            log.error("Backend health %s，但沒有可終止的 server.pid 或 port owner", reason)
            return False
        log.warning(
            "Backend health %s，server.pid 缺失；以 port %s owner PID %s 復原",
            reason, BACKEND_PORT, pid,
        )

    log.warning(
        "Backend health %s；判定為 wedged，tree-kill PID %s", reason, pid,
    )
    if not _tree_kill(pid):
        # 進程可能仍存活；保留 PID 檔讓下一次復原仍有可終止目標。
        log.error("無法確認 wedged backend PID %s 已終止；保留 PID 檔", pid)
        return False

    _clear_pid()
    log.info("已 tree-kill wedged backend PID %s 並清除 PID 檔", pid)
    return True


async def _clear_wedged_backend(reason: str) -> bool:
    """不阻塞 adapter event loop 地清除 wedged backend。"""
    return await asyncio.to_thread(_clear_wedged_backend_sync, reason)


def _spawn_backend() -> int | None:
    """在工作執行緒啟動 backend，避免檔案與 process syscall 阻塞 event loop。"""
    if IS_REMOTE:
        # 遠端不可達時在本機開一台 backend 毫無用處：BACKEND_URL 仍指向遠端，
        # health 依舊失敗，只是在使用者機器上留下一個吃記憶體的孤兒行程。
        log.error("遠端模式：backend %s 不可達，且不會在本機代為啟動", BACKEND_URL)
        return None
    _DATA_DIR.mkdir(parents=True, exist_ok=True)
    log_handle = open(_BACKEND_LOG, "a", encoding="utf-8")

    kwargs: dict = {}
    if sys.platform == "win32":
        # 只用 CREATE_NO_WINDOW，**不要**再 or 上 DETACHED_PROCESS。
        # 兩個一起給時 Windows 直接忽略 CREATE_NO_WINDOW，backend 變成「完全沒有
        # console」；而 sys.executable 在 uv venv 底下是個 trampoline，它會再 spawn
        # 真正的直譯器且不帶任何 flag —— 那個孫子沒有 console 可繼承，Windows 就配一個
        # 新的給它，交給預設終端機（Windows Terminal）顯示，工作列於是冒出一個視窗。
        # CREATE_NO_WINDOW 單獨用會給一個「不顯示」的 console，孫子繼承它，不開視窗；
        # 同時它仍是獨立的 console group，父行程的 Ctrl+C 不會傳下來，
        # 原本用 DETACHED_PROCESS 想要的隔離依然成立。
        kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
    else:
        kwargs["start_new_session"] = True

    try:
        process = subprocess.Popen(
            [sys.executable, "-m", "knowledge_mcp", "serve",
             "--port", str(BACKEND_PORT)],
            stdin=subprocess.DEVNULL,
            stdout=log_handle,
            stderr=log_handle,
            **kwargs,
        )
    except OSError as exc:
        log.exception("Backend spawn failed: %s", exc)
        return None
    finally:
        log_handle.close()

    return process.pid


async def _restart_after_read_timeout(operation: str) -> bool:
    """health 無回應的讀取逾時後，復原 wedged backend。"""
    return await _ensure_backend(wedged_reason=f"{operation} 讀取逾時")


def _finish_backend_ensure(task: asyncio.Task[bool]) -> None:
    """清除已完成的共享 task，並記錄未由呼叫端取得的例外。"""
    global _backend_ensure_task

    if _backend_ensure_task is task:
        _backend_ensure_task = None

    if task.cancelled():
        log.warning("Backend ensure task was cancelled")
        return

    try:
        task.result()
    except Exception:
        log.exception("Backend ensure task failed")


async def _ensure_backend(wedged_reason: str | None = None) -> bool:
    """共用進行中的 backend 檢查，避免背景與工具呼叫重複 spawn。"""
    global _backend_ensure_task

    async with _backend_ensure_lock:
        task = _backend_ensure_task
        if task is None or task.done():
            task = asyncio.create_task(
                _ensure_backend_once(wedged_reason),
                name="knowledge-backend-ensure",
            )
            task.add_done_callback(_finish_backend_ensure)
            _backend_ensure_task = task
        elif wedged_reason is not None:
            log.warning(
                "Backend ensure 已在進行中；%s 將等待同一個復原結果",
                wedged_reason,
            )
        else:
            log.info("Backend ensure 已在進行中；等待同一個結果")

    try:
        return await asyncio.shield(task)
    except asyncio.CancelledError:
        raise
    except Exception:
        # 完整 traceback 已由 task 完成回呼記錄；adapter 必須持續提供服務。
        return False


async def _ensure_backend_once(wedged_reason: str | None = None) -> bool:
    """確認 backend 可用；失聯或讀取逾時時重啟，成功時回傳 ``True``。"""
    if wedged_reason is not None:
        if not await _clear_wedged_backend(wedged_reason):
            return False
    else:
        try:
            resp = await _backend_get("/health", timeout=_HEALTH_TIMEOUT_SECONDS)
            resp.raise_for_status()
            _record_embedding_health(resp)
            log.info("Backend already running at %s", BACKEND_URL)
            return True
        except httpx.HTTPError as exc:
            if isinstance(exc, httpx.ReadTimeout):
                # TCP 已連上卻沒有 health 回應時，該 process 不能再視為健康。
                if not await _clear_wedged_backend("讀取逾時"):
                    return False
            else:
                log.warning("Backend health check failed (%s): %s", type(exc).__name__, exc)
                if IS_REMOTE:
                    # 本機 port owner 與遠端 backend 無關，查它只會得出錯誤結論。
                    return False
                # 非 ReadTimeout 無法證明 process 已死，不能刪掉唯一的終止線索。
                from .__main__ import _find_listening_pid
                port_owner = await asyncio.to_thread(_find_listening_pid, BACKEND_PORT)
                if port_owner is not None:
                    log.warning(
                        "Backend port %s 仍由 PID %s 佔用；保留 PID 檔且不重複 spawn",
                        BACKEND_PORT, port_owner,
                    )
                    return False

    log.info("Backend not running at %s, auto-starting...", BACKEND_URL)

    launcher_pid = await asyncio.to_thread(_spawn_backend)
    if launcher_pid is None:
        return False
    log.info(
        "Spawned backend launcher PID %s (%s, port %s)",
        launcher_pid, sys.executable, BACKEND_PORT,
    )

    # embedding worker 會在背景預載，/health 不必等待模型完成。
    max_wait_seconds = 30
    for attempt in range(1, max_wait_seconds * 2 + 1):
        await asyncio.sleep(0.5)
        try:
            resp = await _backend_get("/health", timeout=3)
            if resp.status_code == 200:
                log.info("Backend started successfully")
                return True
        except httpx.HTTPError as exc:
            if attempt % 20 == 0:
                log.info(
                    "Waiting for backend health: %ss/%ss (%s)",
                    attempt // 2, max_wait_seconds, type(exc).__name__,
                )
            continue

        if attempt % 20 == 0:
            log.info(
                "Waiting for backend health: %ss/%ss (HTTP %s)",
                attempt // 2, max_wait_seconds, resp.status_code,
            )

    log.warning(
        "Backend did not become ready within %ss — check %s",
        max_wait_seconds, _BACKEND_LOG,
    )
    return False


async def _backend_health_responds() -> bool:
    """確認 backend event loop 能否回應；任何 HTTP 回應都代表未 wedged。"""
    try:
        resp = await _backend_get("/health", timeout=_HEALTH_TIMEOUT_SECONDS)
        _record_embedding_health(resp)
        return True
    except httpx.HTTPError as exc:
        log.warning("Backend health probe failed after tool timeout (%s): %s", type(exc).__name__, exc)
        return False


def _tool_timeout_seconds(name: str) -> int:
    """為已知耗時工具保留足夠時間，避免正常工作被當成故障。"""
    if name in _LONG_RUNNING_TOOLS:
        return _LONG_RUNNING_TOOL_TIMEOUT_SECONDS
    return _DEFAULT_TOOL_TIMEOUT_SECONDS


def _embedding_health_from_payload(payload: object) -> _EmbeddingHealth | None:
    """nested health 優先，缺少時相容舊版平面欄位。"""
    if not isinstance(payload, dict):
        return None

    nested = payload.get("embedding")
    if isinstance(nested, dict):
        state = nested.get("state")
        if state in {"starting", "ready", "degraded"}:
            raw_seconds = nested.get("seconds_in_state", 0.0)
            try:
                seconds_in_state = max(0.0, float(raw_seconds))
            except (TypeError, ValueError):
                seconds_in_state = 0.0
            raw_error = nested.get("error") if state == "degraded" else None
            error = str(raw_error) if raw_error else None
            if state == "degraded" and error is None:
                error = "Embedding worker is degraded."
            return _EmbeddingHealth(state, error, seconds_in_state)

    # 新舊 backend 交錯部署時，尚未提供 nested 物件的後端維持舊行為。
    legacy_fields = {"embedding_degraded", "embedding_error", "model_ready", "model_loaded"}
    if not legacy_fields.intersection(payload):
        return None
    if payload.get("embedding_degraded", False):
        raw_error = payload.get("embedding_error")
        error = str(raw_error) if raw_error else "Embedding worker is degraded."
        return _EmbeddingHealth("degraded", error, 0.0)
    if payload.get("model_ready", False) or payload.get("model_loaded", False):
        return _EmbeddingHealth("ready", None, 0.0)
    return _EmbeddingHealth("starting", None, 0.0)


def _record_embedding_health(response: httpx.Response) -> _EmbeddingHealth | None:
    """記錄狀態轉換；降級警告只在狀態或錯誤變動時輸出。"""
    global _embedding_state, _embedding_degraded_error

    try:
        payload = response.json()
    except (json.JSONDecodeError, ValueError):
        return None
    health = _embedding_health_from_payload(payload)
    if health is None:
        return None

    previous_state = _embedding_state
    previous_error = _embedding_degraded_error
    if health.state == "degraded":
        if previous_state != "degraded" or health.error != previous_error:
            log.warning("Embedding worker degraded: %s", health.error)
    elif previous_state == "degraded":
        log.info("Embedding worker health recovered (state=%s)", health.state)
    elif health.state == "starting" and previous_state != "starting":
        log.info("Embedding worker is starting")

    _embedding_state = health.state
    _embedding_degraded_error = health.error if health.state == "degraded" else None
    return health


async def _embedding_health_for_tool(name: str) -> _EmbeddingHealth | None:
    """只在真正依賴向量的工具前檢查 worker；health 失聯時不預先攔截。"""
    if name not in _EMBEDDING_DEPENDENT_TOOLS:
        return None
    try:
        response = await _backend_get("/health", timeout=_HEALTH_TIMEOUT_SECONDS)
        response.raise_for_status()
        return _record_embedding_health(response)
    except httpx.HTTPError:
        # 連線／wedged 復原仍交給原本的工具呼叫路徑處理。
        return None


def _tool_timeout_error(name: str, backend_healthy: bool) -> TextContent:
    """回傳明確的逾時訊息，避免使用者重試可能已執行的寫入操作。"""
    if backend_healthy:
        message = (
            f"Tool {name} exceeded its response timeout, but the backend health check succeeded. "
            "The operation may still be running; do not retry a mutating tool."
        )
    else:
        message = (
            f"Backend became unresponsive while processing {name}. Recovery was attempted; "
            "the tool was not retried because its result may be unknown."
        )
    return TextContent(type="text", text=json.dumps({"error": message}, ensure_ascii=False))


@app.list_tools()
async def list_tools() -> list[Tool]:
    for attempt in range(2):
        try:
            resp = await _backend_get("/tools/list", timeout=10)
            resp.raise_for_status()
            return [Tool(**t) for t in resp.json()]
        except httpx.ReadTimeout:
            if await _backend_health_responds():
                log.warning("list_tools timed out while backend health remained responsive")
                return []
            if attempt == 0:
                log.warning("list_tools: backend health 無回應，嘗試自動重啟...")
                if await _restart_after_read_timeout("list_tools"):
                    continue
            log.error("Backend not reachable at %s — check %s", BACKEND_URL, _BACKEND_LOG)
            return []
        except httpx.ConnectError:
            if attempt == 0:
                log.warning("list_tools: backend unreachable，嘗試自動啟動...")
                if await _ensure_backend():
                    continue
            log.error("Backend not reachable at %s — check %s", BACKEND_URL, _BACKEND_LOG)
            return []
        except Exception as e:
            log.error("Failed to fetch tool list: %s", e)
            return []
    return []


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    embedding_health = await _embedding_health_for_tool(name)
    if embedding_health is not None and embedding_health.state == "starting":
        return [TextContent(
            type="text",
            text=json.dumps({
                "error": (
                    "Embedding 模型仍在載入"
                    f"（已 {embedding_health.seconds_in_state:.1f} 秒），請稍後重試"
                ),
                "retryable": True,
            }, ensure_ascii=False),
        )]
    if embedding_health is not None and embedding_health.state == "degraded":
        return [TextContent(
            type="text",
            text=json.dumps({
                "error": f"Embedding worker is degraded; {name} is temporarily unavailable.",
                "embedding_error": embedding_health.error,
            }, ensure_ascii=False),
        )]

    for attempt in range(2):
        try:
            resp = await _backend_post_json(
                "/tools/call",
                {"name": name, "arguments": arguments or {}},
                timeout=_tool_timeout_seconds(name),
            )
            resp.raise_for_status()
            data = resp.json()

            if isinstance(data, str):
                return [TextContent(type="text", text=data)]

            return [TextContent(type="text", text=json.dumps(data, ensure_ascii=False, indent=2))]

        except httpx.ReadTimeout:
            if await _backend_health_responds():
                log.warning(
                    "call_tool(%s) response timed out, but backend health is responsive; not restarting or retrying",
                    name,
                )
                return [_tool_timeout_error(name, backend_healthy=True)]

            log.warning("call_tool(%s): backend health 無回應，嘗試復原...", name)
            backend_ready = await _restart_after_read_timeout(f"call_tool({name})")
            if name in _READ_ONLY_TOOLS and attempt == 0 and backend_ready:
                log.info("call_tool(%s): wedged backend 已復原，重試唯讀呼叫", name)
                continue
            return [_tool_timeout_error(name, backend_healthy=False)]
        except httpx.ConnectError:
            log.warning("call_tool(%s): backend unreachable，嘗試啟動...", name)
            backend_ready = await _ensure_backend()
            if name in _READ_ONLY_TOOLS and attempt == 0 and backend_ready:
                log.info("call_tool(%s): backend 已啟動，重試唯讀呼叫", name)
                continue
            return [TextContent(
                type="text",
                text=json.dumps({
                    "error": (
                        f"Knowledge backend not reachable at {BACKEND_URL}. "
                        "Recovery was attempted; the tool was not retried because its result may be unknown."
                    ),
                }, ensure_ascii=False),
            )]
        except Exception as e:
            return [TextContent(
                type="text",
                text=json.dumps({"error": str(e)}, ensure_ascii=False),
            )]
    return [TextContent(type="text", text=json.dumps({"error": "unexpected retry exhaustion"}, ensure_ascii=False))]


async def _start_backend_in_background() -> None:
    """在 stdio 已可服務後啟動 backend，失敗只記錄而不影響 MCP 連線。"""
    try:
        backend_ready = await _ensure_backend()
        if not backend_ready:
            log.error("Backend 無法在背景啟動階段就緒；MCP adapter 仍提供 stdio 服務")
    except asyncio.CancelledError:
        log.info("Background backend startup task cancelled")
        raise
    except Exception:
        log.exception("Backend 背景啟動檢查失敗；MCP adapter 仍提供 stdio 服務")


async def run():
    """先啟動 stdio MCP，backend 則在背景檢查與復原。"""
    _assert_transport_is_safe()
    log.info("Backend mode=%s url=%s signed=%s", BACKEND_MODE, BACKEND_URL,
             bool(_CLIENT_KEY_ID and _CLIENT_KEY_FILE))
    async with stdio_server() as (read_stream, write_stream):
        startup_task = asyncio.create_task(
            _start_backend_in_background(),
            name="knowledge-backend-startup",
        )
        try:
            await app.run(read_stream, write_stream, app.create_initialization_options())
        finally:
            startup_task.cancel()
            try:
                await startup_task
            except asyncio.CancelledError:
                pass
