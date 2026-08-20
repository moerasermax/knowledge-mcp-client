# knowledge-client 安裝（Windows）
$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $here

$py = if ($env:KNOWLEDGE_PYTHON) { $env:KNOWLEDGE_PYTHON } else { "python" }
& $py --version
if ($LASTEXITCODE -ne 0) { throw "找不到 python，請先安裝 Python 3.11+ 或設定 KNOWLEDGE_PYTHON" }

Write-Host "建立 venv ..."
& $py -m venv .venv
Write-Host "安裝相依套件（約 30-50 MB）..."
& ".\.venv\Scripts\python.exe" -m pip install --quiet --upgrade pip
& ".\.venv\Scripts\python.exe" -m pip install --quiet -r requirements.txt

Write-Host ""
Write-Host "完成。python 路徑（MCP 設定要用）："
Write-Host ("  " + (Resolve-Path ".\.venv\Scripts\python.exe"))
Write-Host ""
Write-Host "下一步："
Write-Host "  .\.venv\Scripts\python.exe -m knowledge_client key generate --name <這台的名稱>"
