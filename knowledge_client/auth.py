# ============================================================================
# 職責：後端 HTTP 的 Ed25519 請求簽章、client 憑證登錄、scope 授權、防重放。
# 不含任何知識庫邏輯；store / api_server 皆不反向依賴本模組的內部結構。
# ============================================================================

"""Ed25519 request signing for the knowledge backend.

為什麼是非對稱而不是共享密鑰：

* Bearer token + server 存 ``sha512(token)``：server 不持有可用密鑰，但 token
  每次請求都要過網路——ngrok 在自己的 edge 終止 TLS，明文會經過它看得到的地方。
* HMAC：密鑰不上線，但 server 必須持有可簽章的金鑰才能重算，被入侵即可偽造。

共享密鑰無法同時具備兩個性質。Ed25519 讓 client 持私鑰、server 只存公鑰，
兩者兼得；而它內部的雜湊本來就是 SHA-512。
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import sqlite3
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

log = logging.getLogger(__name__)

# 簽章協定版本。canonical string 的第一行，任何欄位變動都必須改版號，
# 否則新舊 client 會對同一份請求算出不同摘要卻都自認正確。
SIGNATURE_VERSION = "knowledge-sig-v1"

# 時間窗。過寬會拉長重放的可用期；過窄會被兩台機器的時鐘偏差誤殺。
_DEFAULT_SKEW_SECONDS = 300


def _skew_seconds() -> int:
    raw = os.environ.get("KNOWLEDGE_AUTH_MAX_SKEW_SECONDS")
    if not raw:
        return _DEFAULT_SKEW_SECONDS
    try:
        value = int(raw)
    except ValueError:
        log.warning("KNOWLEDGE_AUTH_MAX_SKEW_SECONDS 非整數，改用預設值")
        return _DEFAULT_SKEW_SECONDS
    return value if value > 0 else _DEFAULT_SKEW_SECONDS


# ── Scopes ───────────────────────────────────────────────────────────────────

SCOPE_READ = "read"
SCOPE_WRITE = "write"
SCOPE_DELETE = "delete"
SCOPE_MAINTENANCE = "maintenance"

ALL_SCOPES = (SCOPE_READ, SCOPE_WRITE, SCOPE_DELETE, SCOPE_MAINTENANCE)

# 工具 → 所需 scope。**預設拒絕**：不在此表的工具名一律視為 maintenance，
# 新增工具時若忘了登錄，最壞情況是「權限過嚴」而不是「無人看管的後門」。
TOOL_SCOPES: dict[str, str] = {
    "knowledge_search": SCOPE_READ,
    "knowledge_list": SCOPE_READ,
    "knowledge_read": SCOPE_READ,
    "knowledge_namespaces": SCOPE_READ,
    "knowledge_export": SCOPE_READ,
    "knowledge_context_pack": SCOPE_READ,
    "knowledge_skill_bundle": SCOPE_READ,
    "knowledge_iteration_budget": SCOPE_READ,
    "knowledge_write": SCOPE_WRITE,
    "knowledge_delete": SCOPE_DELETE,
    "knowledge_rebuild_embeddings": SCOPE_MAINTENANCE,
    "knowledge_sync": SCOPE_MAINTENANCE,
    "knowledge_build_index": SCOPE_MAINTENANCE,
    "knowledge_archive": SCOPE_MAINTENANCE,
    "knowledge_nightly_patrol": SCOPE_MAINTENANCE,
}


def required_scope(tool_name: str) -> str:
    """未登錄的工具名一律要求 maintenance（fail-closed）。"""
    return TOOL_SCOPES.get(tool_name, SCOPE_MAINTENANCE)


class AuthError(Exception):
    """認證/授權失敗。``status`` 用於 HTTP 回應碼。

    ``detail`` 只寫進 server log，不回給遠端——把「key 不存在」與「簽章錯誤」
    的差異告訴呼叫端等於免費的帳號列舉。
    """

    def __init__(self, message: str, status: int = 401, detail: str = ""):
        super().__init__(message)
        self.message = message
        self.status = status
        self.detail = detail or message


# ── 金鑰 ─────────────────────────────────────────────────────────────────────


def generate_keypair() -> tuple[bytes, str]:
    """產生 Ed25519 金鑰對；回傳 (私鑰 PEM bytes, 公鑰 base64)。

    私鑰以未加密 PEM 輸出，保護靠檔案系統 ACL——這是個人單機部署的取捨；
    加密 PEM 需要每次啟動輸入密碼，而 adapter 由 Claude Code 以 stdio 啟動，
    沒有可互動的地方。
    """
    private = Ed25519PrivateKey.generate()
    pem = private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return pem, encode_public_key(private.public_key())


def encode_public_key(public: Ed25519PublicKey) -> str:
    raw = public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(raw).decode("ascii")


def decode_public_key(encoded: str) -> Ed25519PublicKey:
    try:
        raw = base64.b64decode(encoded, validate=True)
    except Exception as exc:
        raise ValueError(f"公鑰不是合法 base64：{exc}") from exc
    if len(raw) != 32:
        raise ValueError(f"Ed25519 公鑰必須是 32 bytes，收到 {len(raw)}")
    return Ed25519PublicKey.from_public_bytes(raw)


def load_private_key(pem_path: Path) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(pem_path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError(f"{pem_path} 不是 Ed25519 私鑰")
    return key


# ── Client 登錄表 ────────────────────────────────────────────────────────────


def registry_path(data_dir: Path) -> Path:
    return data_dir / "clients.json"


def load_registry(path: Path) -> dict:
    if not path.exists():
        return {"version": 1, "clients": {}}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        # 讀不到就當「沒有任何 client 獲授權」，不是「全部放行」。
        raise AuthError(
            "認證設定無法讀取",
            status=503,
            detail=f"讀取 {path} 失敗：{exc}",
        ) from exc
    if not isinstance(data, dict) or not isinstance(data.get("clients"), dict):
        raise AuthError(
            "認證設定格式錯誤",
            status=503,
            detail=f"{path} 缺少 clients 物件",
        )
    return data


def save_registry(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + f".tmp{os.getpid()}")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, path)
    if os.name == "nt":
        _restrict_windows_acl(path)


def _restrict_windows_acl(path: Path) -> None:
    """把檔案 ACL 收成只有目前使用者可讀寫。失敗只記警告，不阻斷。"""
    import subprocess

    user = os.environ.get("USERNAME")
    if not user:
        return
    try:
        subprocess.run(
            ["icacls", str(path), "/inheritance:r", "/grant:r", f"{user}:F"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        log.warning("無法收緊 %s 的 ACL：%s", path, exc)


def register_client(
    path: Path,
    name: str,
    public_key_b64: str,
    scopes: Iterable[str],
) -> dict:
    decode_public_key(public_key_b64)  # 先驗格式，別把壞資料寫進登錄表
    scope_list = sorted(set(scopes))
    unknown = [s for s in scope_list if s not in ALL_SCOPES]
    if unknown:
        raise ValueError(f"未知的 scope：{unknown}；可用：{list(ALL_SCOPES)}")
    if not scope_list:
        raise ValueError("至少要給一個 scope")

    data = load_registry(path)
    record = {
        "public_key": public_key_b64,
        "scopes": scope_list,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "revoked": False,
    }
    data["clients"][name] = record
    save_registry(path, data)
    return record


def revoke_client(path: Path, name: str) -> bool:
    data = load_registry(path)
    record = data["clients"].get(name)
    if not record or record.get("revoked"):
        return False
    # 保留紀錄而非刪除：撤銷的歷史本身是稽核資訊。
    record["revoked"] = True
    record["revoked_at"] = datetime.now(timezone.utc).isoformat()
    save_registry(path, data)
    return True


def list_clients(path: Path) -> dict:
    return load_registry(path)["clients"]


# ── Canonical request ────────────────────────────────────────────────────────


def canonical_request(
    *,
    method: str,
    path: str,
    query: str,
    key_id: str,
    timestamp: str,
    nonce: str,
    body: bytes,
) -> bytes:
    """組出雙方都必須算出同一份的位元組串。

    body 一定要是**實際送出去的 wire bytes**：client 若簽自己 json.dumps 的結果
    卻讓 HTTP 函式庫再序列化一次，空白、Unicode escaping、key 順序都可能不同，
    簽章就會對不起來（或更糟——簽的與送的是兩份東西）。
    """
    body_digest = hashlib.sha512(body).hexdigest()
    parts = [
        SIGNATURE_VERSION,
        method.upper(),
        path,
        query,
        key_id,
        timestamp,
        nonce,
        body_digest,
    ]
    return "\n".join(parts).encode("utf-8")


def sign_request(private_key: Ed25519PrivateKey, message: bytes) -> str:
    return base64.b64encode(private_key.sign(message)).decode("ascii")


def build_signature_headers(
    private_key: Ed25519PrivateKey,
    key_id: str,
    *,
    method: str,
    path: str,
    body: bytes,
    query: str = "",
) -> dict:
    """產生一次請求所需的四個簽章標頭。

    唯一的實作，adapter 與 CLI 共用。分成兩份的話，只要有一邊漏改
    canonical_request 的欄位順序，症狀就是「有時候 401」而非明確失敗。

    ``body`` 必須是實際會送出去的 wire bytes——見 ``canonical_request``。
    """
    timestamp = str(time.time())
    nonce = base64.b64encode(os.urandom(16)).decode("ascii")
    message = canonical_request(
        method=method,
        path=path,
        query=query,
        key_id=key_id,
        timestamp=timestamp,
        nonce=nonce,
        body=body,
    )
    return {
        HEADER_KEY_ID: key_id,
        HEADER_TIMESTAMP: timestamp,
        HEADER_NONCE: nonce,
        HEADER_SIGNATURE: sign_request(private_key, message),
    }


# ── 防重放 ───────────────────────────────────────────────────────────────────


class NonceStore:
    """以 SQLite 持久化的 nonce 記錄。

    為什麼不用記憶體 LRU：server 一重啟 cache 就空，時間窗內攔截到的請求可以
    原封不動再送一次；多 worker 時各有各的 cache，重放打到另一個 worker 也會過。
    UNIQUE 約束讓「檢查」與「寫入」變成單一原子操作，不需要額外的鎖。
    """

    _SCHEMA = """
    CREATE TABLE IF NOT EXISTS auth_nonce (
        key_id     TEXT NOT NULL,
        nonce      TEXT NOT NULL,
        expires_at REAL NOT NULL,
        PRIMARY KEY (key_id, nonce)
    );
    CREATE INDEX IF NOT EXISTS idx_auth_nonce_expiry ON auth_nonce(expires_at);
    """

    def __init__(self, db_path: Path):
        self._path = db_path
        self._lock = threading.Lock()
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(db_path), timeout=10, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode = WAL")
        self._conn.executescript(self._SCHEMA)
        self._conn.commit()
        self._last_purge = 0.0

    def claim(self, key_id: str, nonce: str, expires_at: float) -> bool:
        """第一次見到回 True；重複回 False。"""
        with self._lock:
            try:
                self._conn.execute(
                    "INSERT INTO auth_nonce (key_id, nonce, expires_at) VALUES (?, ?, ?)",
                    (key_id, nonce, expires_at),
                )
                self._conn.commit()
            except sqlite3.IntegrityError:
                return False
            self._maybe_purge()
            return True

    def _maybe_purge(self) -> None:
        now = time.time()
        if now - self._last_purge < 60:
            return
        self._last_purge = now
        try:
            self._conn.execute("DELETE FROM auth_nonce WHERE expires_at < ?", (now,))
            self._conn.commit()
        except sqlite3.Error as exc:
            log.warning("清理過期 nonce 失敗：%s", exc)

    def close(self) -> None:
        with self._lock:
            try:
                self._conn.close()
            except sqlite3.Error:
                pass


# ── 驗證 ─────────────────────────────────────────────────────────────────────

HEADER_KEY_ID = "x-knowledge-key-id"
HEADER_TIMESTAMP = "x-knowledge-timestamp"
HEADER_NONCE = "x-knowledge-nonce"
HEADER_SIGNATURE = "x-knowledge-signature"

_MAX_NONCE_LEN = 128


def verify_request(
    *,
    registry: dict,
    nonce_store: NonceStore,
    method: str,
    path: str,
    query: str,
    headers: dict,
    body: bytes,
    now: Optional[float] = None,
) -> tuple[str, dict]:
    """驗證簽章並回傳 (key_id, client 記錄)；任何問題一律拋 AuthError。

    順序是刻意的：先做不碰狀態的檢查（欄位齊全、時間窗、簽章），確認來源
    真的持有私鑰之後才寫 nonce。反過來的話，任何匿名者都能用亂數 nonce
    把表灌爆、把有效項目擠掉。
    """
    now = time.time() if now is None else now

    key_id = headers.get(HEADER_KEY_ID, "")
    timestamp = headers.get(HEADER_TIMESTAMP, "")
    nonce = headers.get(HEADER_NONCE, "")
    signature_b64 = headers.get(HEADER_SIGNATURE, "")

    if not (key_id and timestamp and nonce and signature_b64):
        raise AuthError("缺少簽章標頭", status=401, detail="signature headers missing")
    if len(nonce) > _MAX_NONCE_LEN:
        raise AuthError("簽章標頭無效", status=401, detail="nonce too long")

    try:
        ts = float(timestamp)
    except ValueError as exc:
        raise AuthError(
            "簽章標頭無效", status=401, detail=f"timestamp not numeric: {exc}"
        ) from exc

    skew = _skew_seconds()
    if abs(now - ts) > skew:
        raise AuthError(
            "請求時間超出允許範圍",
            status=401,
            detail=f"timestamp skew {now - ts:.1f}s exceeds {skew}s",
        )

    record = registry.get("clients", {}).get(key_id)
    # 找不到 key 與簽章錯誤回同一個訊息，避免變成帳號列舉的 oracle。
    if record is None or record.get("revoked"):
        raise AuthError("簽章驗證失敗", status=401, detail=f"unknown/revoked key {key_id!r}")

    try:
        public_key = decode_public_key(record["public_key"])
    except (KeyError, ValueError) as exc:
        raise AuthError(
            "認證設定格式錯誤", status=503, detail=f"client {key_id!r} 公鑰無效：{exc}"
        ) from exc

    message = canonical_request(
        method=method,
        path=path,
        query=query,
        key_id=key_id,
        timestamp=timestamp,
        nonce=nonce,
        body=body,
    )
    try:
        signature = base64.b64decode(signature_b64, validate=True)
    except Exception as exc:
        raise AuthError("簽章驗證失敗", status=401, detail=f"signature not base64: {exc}") from exc

    try:
        public_key.verify(signature, message)
    except InvalidSignature as exc:
        raise AuthError("簽章驗證失敗", status=401, detail="invalid signature") from exc

    # 到這裡才確定對方持有私鑰，寫 nonce 是安全的。
    if not nonce_store.claim(key_id, nonce, ts + skew):
        raise AuthError("請求已被使用過", status=401, detail="nonce replay")

    return key_id, record


def authorize_tool(record: dict, tool_name: str) -> None:
    needed = required_scope(tool_name)
    granted = record.get("scopes") or []
    if needed not in granted:
        raise AuthError(
            "權限不足",
            status=403,
            detail=f"tool {tool_name!r} 需要 scope {needed!r}，該 client 只有 {granted}",
        )
