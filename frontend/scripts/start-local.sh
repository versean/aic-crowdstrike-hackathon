#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
export OLLAMA_MODEL="${OLLAMA_MODEL:-qwen3:0.6b}"
export OLLAMA_URL="${OLLAMA_URL:-http://127.0.0.1:11434/api/chat}"
if [[ -x .local/ollama/ollama ]]; then
  export PATH="$PWD/.local/ollama:$PATH"
  export OLLAMA_MODELS="${OLLAMA_MODELS:-$PWD/.local/models}"
fi
if ! command -v ollama >/dev/null; then
  echo 'Install Ollama from https://ollama.com/download (macOS: brew install ollama), then rerun this script.'
  exit 1
fi
if [[ ! -x .venv/bin/python ]]; then
  python3 -m venv .venv
fi
.venv/bin/python -m pip install -r frontend/requirements.txt
# The launcher owns only a server it starts, and shuts it down on exit.
ollama_pid=''
cleanup() { if [[ -n "$ollama_pid" ]]; then kill "$ollama_pid" 2>/dev/null || true; fi; }
trap cleanup EXIT
if ! curl -fsS "${OLLAMA_URL%/api/chat}/api/tags" >/dev/null; then
  if [[ "$OLLAMA_URL" != 'http://127.0.0.1:11434/api/chat' ]]; then
    echo 'Start the Ollama server configured by OLLAMA_URL, then rerun.'
    exit 1
  fi
  ollama serve > /tmp/alertlens-ollama.log 2>&1 &
  ollama_pid=$!
  for attempt in {1..30}; do
    if curl -fsS "${OLLAMA_URL%/api/chat}/api/tags" >/dev/null 2>&1; then break; fi
    sleep 1
  done
fi
OLLAMA_HOST="${OLLAMA_URL%/api/chat}" ollama pull "$OLLAMA_MODEL"
.venv/bin/python frontend/scripts/check-local.py
.venv/bin/streamlit run frontend/app.py --server.address 127.0.0.1
