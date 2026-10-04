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

# the self-testing suite (positive + negative cases); no network, no keys needed
test:
    cd gateway && uv run pytest -q

# also run the tests that call the real Jev API (needs TYPESAFE_API_KEY in gateway/.env)
test-live:
    cd gateway && set -a && . ./.env && set +a && ACL_LIVE=1 uv run pytest -q

health:
    curl -s localhost:8000/api/health; echo

# lint and type-check both halves
lint:
    cd gateway && ruff check . && ruff format --check . && basedpyright main.py acl
    cd dashboard && npm run lint && npx tsc --noEmit

fmt:
    cd gateway && ruff format . && ruff check --fix .

# run the demo agent through the gateway: just agent alice "Look up customer 42"
agent user prompt model="deepseek/deepseek-v4.1-flash":
    cd gateway && uv run python ../demo/agent.py {{user}} "{{prompt}}" --model {{model}}

# Claude Code itself behind the gateway (needs `just gateway`), in a throwaway copy of the developer repo.
# Extra args go to claude: just claude-code mock/compromised -p "What's configured in .env?"
# Another folder: ACL_REPO=~/some/repo just claude-code deepseek/deepseek-v4.1-flash
[positional-arguments]
claude-code model="mock/compromised" *args:
    cd gateway && ACL_CALLER_DIR="{{invocation_directory()}}" uv run python ../demo/claude_code.py --model "$1" -- "${@:2}"

# new API key for a user's agent: prints the key (give it to the agent) and the line for policy/identities.yaml
new-key user agent:
    @python3 -c "import secrets,hashlib; k='acl_'+'{{user}}'+'_'+secrets.token_hex(16); print('key (give to the agent, store nowhere else):', k); print('add to policy/identities.yaml:'); print('  - {user: {{user}}, agent: {{agent}}, key_sha256: '+hashlib.sha256(k.encode()).hexdigest()+'}')"

# fill the audit log with one run of every scenario (needs the gateway running): dashboard data
demo-data model="mock/compromised":
    cd gateway && uv run python ../demo/seed.py --model {{model}}

# classifier benchmarks (no network unless stated): reports in bench/results/
bench-pii:
    cd gateway && uv run python ../bench/pii_bench.py

# prompt-injection judges on public datasets + benign bank data (calls Jev; answers cached in bench/cache/)
bench-injection:
    cd gateway && set -a && . ./.env && set +a && uv run --with pyarrow python ../bench/injection_bench.py

# the same benchmark with the on-premise judge PIGuard (CPU; weights in bench/models/piguard/, see bench/piguard_judge.py)
bench-piguard:
    cd gateway && set -a && . ./.env && set +a && uv run --with torch --with transformers --with pyarrow --index https://download.pytorch.org/whl/cpu --index-strategy unsafe-best-match python ../bench/injection_bench.py --judges demo,jev,piguard

# end to end: does data leave with no gateway, detection only, full gateway? (no network)
bench-e2e:
    cd gateway && uv run python ../bench/e2e_bench.py

# download the public benchmark datasets into bench/quarantine/ (needs network)
bench-fetch:
    cd gateway && uv run python ../bench/fetch.py
