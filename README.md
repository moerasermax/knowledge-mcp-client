# knowledge-client

連到遠端知識庫 server 的 MCP client。**這台機器不存任何知識**——所有查詢與寫入
都是簽章後送到 server，資料只有一份，在 server 上。

> 這個資料夾是**產生出來的**，不要直接修改。`auth.py` 與 `mcp_adapter.py` 是
> server repo 的逐位元組複製；改這裡只會讓兩邊的簽章協定不一致，而症狀是
> 「有時候 401」這種極難追的失敗。要改請改 server repo 再重新產生。

- 產生自 server repo commit `41e0007`
- 簽章協定版本 `knowledge-sig-v1`
- backend：**由你自己填**。下面範例裡的 `https://knowledge.example.com` 是佔位字串，換成你的實際端點。

## 為什麼是一個 bundle 而不是 clone 整個 repo

clone 會把 `data/vault`（整個知識庫的原文）複製到這台機器，而 client 一筆都不
需要；而且每台設備都得有私有 repo 的 GitHub 憑證。這份 bundle 兩者都不需要。

## 安裝

只需要 Python 3.11+。**不需要** GPU、torch、也不需要下載任何模型。

```powershell
# Windows
.\install.ps1
```
```bash
# macOS / Linux
./install.sh
```

裝完會印出 venv 裡 python 的完整路徑，下面的設定要用到。

## 取得金鑰

在**這台機器**產生（私鑰永遠不離開這台）：

```
<venv-python> -m knowledge_client key generate --name <這台的名稱>
```

它會印出一行註冊指令。**把那行帶到 server 上執行**（SSH 過去），client 才算被
授權。給 `read,write` 就夠寫知識；不給 `delete` 的話，這台即使金鑰外洩也刪不掉
任何東西。

## 先驗證再接 MCP

```
$env:KNOWLEDGE_BACKEND_URL="https://knowledge.example.com"
$env:KNOWLEDGE_CLIENT_KEY_ID="<名稱>"
$env:KNOWLEDGE_CLIENT_KEY_FILE="<剛才印出的路徑>"
<venv-python> -m knowledge_client check
```

看到 `namespace: N 個` 才代表整條路徑通了。**先驗這個再去設定 MCP**——
設定錯的症狀是工具靜靜地不出現，不會有錯誤訊息告訴你哪裡錯。

## 接上 MCP

> **Windows 路徑先看這段。** JSON 裡單一反斜線是非法跳脫，把
> `C:\Users\me\...` 直接貼進去會讓整個設定檔解析失敗——而症狀是
> **MCP 工具靜靜地不出現**，沒有任何訊息告訴你是語法錯。
> 下面的 JSON 範例一律用**正斜線**（`C:/Users/...`），Windows 的 Python
> 完全吃得下，也省掉整個跳脫問題。TOML 則用單引號包起來即可。

### Claude Code

編輯 `~/.claude.json`，在根層的 `mcpServers` 加（把三個 `C:/...` 換成你的實際路徑）：

```json
{
  "mcpServers": {
    "knowledge": {
      "type": "stdio",
      "command": "C:/knowledge-client/.venv/Scripts/python.exe",
      "args": ["-m", "knowledge_client"],
      "env": {
        "PYTHONPATH": "C:/knowledge-client",
        "KNOWLEDGE_BACKEND_URL": "https://knowledge.example.com",
        "KNOWLEDGE_CLIENT_KEY_ID": "work-laptop",
        "KNOWLEDGE_CLIENT_KEY_FILE": "C:/Users/me/.knowledge-mcp/keys/work-laptop.pem"
      }
    }
  }
}
```

放在**根層**的話所有專案都能用；只想給特定專案就放在 `projects.<路徑>.mcpServers`。

macOS / Linux 就是一般路徑，例如 `/home/me/knowledge-client/.venv/bin/python`。

### Codex

編輯 `~/.codex/config.toml`：

```toml
[mcp_servers.knowledge]
command = 'C:\knowledge-client\.venv\Scripts\python.exe'
args = ['-m', 'knowledge_client']
startup_timeout_sec = 120

[mcp_servers.knowledge.env]
PYTHONPATH = 'C:\knowledge-client'
KNOWLEDGE_BACKEND_URL = "https://knowledge.example.com"
KNOWLEDGE_CLIENT_KEY_ID = "work-laptop"
KNOWLEDGE_CLIENT_KEY_FILE = 'C:\Users\me\.knowledge-mcp\keys\work-laptop.pem'
```

兩個容易錯的地方：env 是**獨立的一個表**（`[mcp_servers.knowledge.env]`），
不是寫在上面那個表裡面；含反斜線的路徑要用**單引號**（TOML 的單引號字串
不處理跳脫字元，雙引號會）。

## 要收回這台的權限

在 server 上執行，立即生效，不必動這台機器：

```
knowledge_mcp client revoke <名稱>
```

## 出錯時

| 症狀 | 原因 |
|---|---|
| `check` 卡在 `/health` | 網路不通，或 server／tunnel 沒起來 |
| `HTTP 401` | 金鑰沒註冊、已被撤銷，或**兩邊時間差超過 300 秒**（先對時） |
| `HTTP 403` | 金鑰有效但缺 scope（例如只有 `read` 卻想寫入） |
| MCP 工具沒出現 | 設定檔路徑或 JSON/TOML 語法錯。先跑 `check` 排除連線問題，再檢查設定 |
| `拒絕啟動：... 不是 https` | 遠端連線一律要求 TLS，這是刻意的 |

## 更新

協定或 adapter 有變更時，在 server repo 重跑 `scripts/make-client-bundle.py`，
把新的 bundle 覆蓋過來即可（`.venv` 與金鑰都不受影響）。
`CHANGELOG.md` 會標註需要各 client 更新的變更。
