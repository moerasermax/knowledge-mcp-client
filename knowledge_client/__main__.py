"""knowledge-client 進入點。

這份 bundle **只做 remote**：backend 一定在別台機器上。所以在匯入 adapter
之前就把模式釘死——`mcp_adapter` 是在 import 時就決定 BACKEND_MODE 的。

為什麼要釘死：本機模式下 adapter 會在 backend 短暫不健康時 tree-kill 並自己
spawn 一個。在 client 機器上那毫無意義（BACKEND_URL 仍指向遠端，health 依舊
失敗），只會留下一個吃記憶體的孤兒行程，甚至誤殺這台機器上碰巧佔用同一個
port 的東西。
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

os.environ["KNOWLEDGE_BACKEND_MODE"] = "remote"


# ── 本機模式專用的名稱 ────────────────────────────────────────────────────
# mcp_adapter 在幾個「本機模式才會走到」的分支裡會 lazy import 這四個。這份
# bundle 永遠是 remote，所以它們不該被呼叫到；提供明確的錯誤勝過 ImportError。
def _remote_only(*_args, **_kwargs):
    raise RuntimeError(
        "knowledge-client 是 remote-only：不管理任何本機 backend 行程。"
        "走到這裡代表模式判定有問題。"
    )


_read_pid = _clear_pid = _find_listening_pid = _tree_kill = _remote_only


def _restrict_key_acl(path: Path) -> None:
    """私鑰只讓目前使用者讀寫。失敗要講出來——使用者得知道保護沒生效。"""
    if sys.platform != "win32":
        try:
            path.chmod(0o600)
        except OSError as exc:
            print(f"警告：無法收緊 {path} 權限：{exc}", file=sys.stderr)
        return
    user = os.environ.get("USERNAME")
    if not user:
        print(f"警告：無法取得使用者名稱，{path} 的 ACL 未收緊", file=sys.stderr)
        return
    try:
        result = subprocess.run(
            ["icacls", str(path), "/inheritance:r", "/grant:r", f"{user}:F"],
            stdin=subprocess.DEVNULL, capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=15, check=False,
        )
        if result.returncode != 0:
            print(f"警告：{path} 的 ACL 未收緊：{result.stderr.strip()[:200]}", file=sys.stderr)
    except (OSError, subprocess.TimeoutExpired) as exc:
        print(f"警告：無法收緊 {path} 權限：{exc}", file=sys.stderr)


def cmd_key_generate(args) -> int:
    """在**這台機器**產生金鑰對。私鑰永遠不離開這台。"""
    from .auth import generate_keypair

    out = Path(args.out) if args.out else Path.home() / ".knowledge-mcp" / "keys" / f"{args.name}.pem"
    if out.exists() and not args.force:
        print(f"已存在：{out}（要覆蓋請加 --force）", file=sys.stderr)
        return 1
    out.parent.mkdir(parents=True, exist_ok=True)

    pem, public_b64 = generate_keypair()
    out.write_bytes(pem)
    _restrict_key_acl(out)

    print(f"私鑰已寫入：{out}")
    print()
    print("把下面這行帶到 server 執行（SSH 過去），才算註冊完成：")
    print(f"  knowledge_mcp client register --name {args.name} "
          f"--pubkey {public_b64} --scopes read,write")
    print()
    print("然後在這台機器的 MCP 設定裡填：")
    print(f"  KNOWLEDGE_CLIENT_KEY_ID   = {args.name}")
    print(f"  KNOWLEDGE_CLIENT_KEY_FILE = {out}")
    return 0


def cmd_check(args) -> int:
    """不啟動 MCP，只確認設定與連線是否可用——新機器裝完先跑這個。"""
    import base64
    import json
    import time
    import urllib.error
    import urllib.request

    from .auth import build_signature_headers, load_private_key

    url = (os.environ.get("KNOWLEDGE_BACKEND_URL") or "").rstrip("/")
    key_id = os.environ.get("KNOWLEDGE_CLIENT_KEY_ID", "")
    key_file = os.environ.get("KNOWLEDGE_CLIENT_KEY_FILE", "")
    missing = [n for n, v in (("KNOWLEDGE_BACKEND_URL", url),
                              ("KNOWLEDGE_CLIENT_KEY_ID", key_id),
                              ("KNOWLEDGE_CLIENT_KEY_FILE", key_file)) if not v]
    if missing:
        print("缺少環境變數：" + "、".join(missing), file=sys.stderr)
        return 2
    if not url.startswith("https://"):
        print(f"拒絕：{url} 不是 https。遠端連線一律要求 TLS。", file=sys.stderr)
        return 2

    print(f"  backend : {url}")
    print(f"  key id  : {key_id}")
    try:
        with urllib.request.urlopen(url + "/health", timeout=30) as r:
            print(f"  /health : HTTP {r.status} {r.read(200).decode('utf-8', 'replace')}")
    except Exception as exc:  # noqa: BLE001
        print(f"  /health : 失敗 {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

    body = json.dumps({"name": "knowledge_namespaces", "arguments": {}}).encode("utf-8")
    key = load_private_key(Path(key_file))
    headers = {"content-type": "application/json"}
    headers.update(build_signature_headers(key, key_id, method="POST",
                                           path="/tools/call", body=body))
    started = time.time()
    try:
        req = urllib.request.Request(url + "/tools/call", data=body,
                                     headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=60) as r:
            data = json.loads(r.read())
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:200]
        print(f"  簽章請求: HTTP {exc.code} {detail}", file=sys.stderr)
        if exc.code == 401:
            print("  → 金鑰未註冊、已撤銷，或 server 與 client 的時間差超過 300 秒", file=sys.stderr)
        return 1
    except Exception as exc:  # noqa: BLE001
        print(f"  簽章請求: 失敗 {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

    names = data.get("namespaces", [])
    print(f"  簽章請求: HTTP 200（{time.time() - started:.2f}s）")
    print(f"  namespace: {len(names)} 個")
    print()
    print("一切正常，可以把這台的 MCP 設定接上了。")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="knowledge_client",
        description="Knowledge MCP client — 連到遠端知識庫 server 的 MCP adapter。",
    )
    sub = parser.add_subparsers(dest="command")

    key = sub.add_parser("key", help="金鑰管理（在 client 這台執行）")
    key_sub = key.add_subparsers(dest="key_command")
    gen = key_sub.add_parser("generate", help="產生 Ed25519 金鑰對")
    gen.add_argument("--name", required=True, help="這台 client 的識別名稱")
    gen.add_argument("--out", help="私鑰路徑（預設 ~/.knowledge-mcp/keys/<name>.pem）")
    gen.add_argument("--force", action="store_true")

    sub.add_parser("check", help="檢查設定與連線（不啟動 MCP）")

    args = parser.parse_args()
    if args.command == "key":
        if args.key_command == "generate":
            return cmd_key_generate(args)
        parser.parse_args(["key", "--help"])
        return 2
    if args.command == "check":
        return cmd_check(args)

    # 沒有子命令 = 以 MCP stdio server 執行，這是 Claude Code / Codex 的用法。
    import asyncio

    from .mcp_adapter import run
    asyncio.run(run())
    return 0


if __name__ == "__main__":
    sys.exit(main())
