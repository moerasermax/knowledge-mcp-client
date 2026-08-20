#!/usr/bin/env bash
# knowledge-client 安裝（macOS / Linux）
set -euo pipefail
cd "$(dirname "$0")"

PY="${KNOWLEDGE_PYTHON:-python3}"
"$PY" --version

echo "建立 venv ..."
"$PY" -m venv .venv
echo "安裝相依套件（約 30-50 MB）..."
./.venv/bin/python -m pip install --quiet --upgrade pip
./.venv/bin/python -m pip install --quiet -r requirements.txt

echo
echo "完成。python 路徑（MCP 設定要用）："
echo "  $(pwd)/.venv/bin/python"
echo
echo "下一步："
echo "  ./.venv/bin/python -m knowledge_client key generate --name <這台的名稱>"
