# AI Control Layer: `just --list` shows everything. Run inside the devshell (direnv or `nix develop`).

# gateway (:8000) and dashboard (:3000) together; Ctrl-C stops both
dev:
    #!/usr/bin/env bash
    trap 'kill 0' EXIT
    just gateway &
    just dashboard &
    wait

# policy engine + adapters (FastAPI, auto-reload) on :8000
gateway:
    cd gateway && uv run fastapi dev main.py --port 8000

# Next.js dashboard on :3000 (proxies /api/* to :8000)
dashboard:
    cd dashboard && npm run dev

# local model server on :11434 (CPU on yoga)
ollama:
    ollama serve

# pull the small models we plan to use (run once, before the wifi gets bad)
models:
    ollama pull llama-guard3:1b
    ollama pull qwen3:4b

# install or update all dependencies
install:
    cd gateway && uv sync
    cd dashboard && npm install

# the self-testing suite (positive + negative cases)
test:
    cd gateway && uv run pytest -q

health:
    curl -s localhost:8000/api/health; echo

# lint and type-check both halves
lint:
    cd gateway && ruff check . && ruff format --check . && basedpyright main.py acl
    cd dashboard && npm run lint && npx tsc --noEmit

fmt:
    cd gateway && ruff format . && ruff check --fix .
