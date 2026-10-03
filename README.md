# AI Control Layer

[![test](https://github.com/TheRealStartup/flow-guard/actions/workflows/test.yml/badge.svg)](https://github.com/TheRealStartup/flow-guard/actions/workflows/test.yml)

HackYeah 2026 · Goldman Sachs partner task. A policy gateway between AI agents and
models and tools: policy checks, reversible redaction, budgets and an audit log.

## Protection, integration and audit visibility

The current MVP is an OpenAI-compatible model proxy. An MCP gateway enforces
controls at the tool boundary; the two approaches can work together.

| Point | AI Control Layer: current model proxy | MCP gateway |
| --- | --- | --- |
| Protects | Checks messages before they reach the model, replaces detected sensitive values with reversible tokens, marks tool results as data rather than instructions (spotlighting), and filters the model's proposed tool calls before returning them to the agent. | Checks actual tool requests before execution and can filter tool results before returning them to the agent. Model traffic needs separate protection. |
| Integration | Point an agent using Chat Completions at `http://localhost:8000/v1`; send a bearer API key, `X-Purpose`, and a stable `X-Session`. The key maps to a user and agent in `policy/identities.yaml`. Anthropic Messages (`/v1/messages`) works too: the unmodified Claude Code runs through the gateway with `ANTHROPIC_BASE_URL` (see [docs/claude-code.md](docs/claude-code.md)); its streamed answer is replayed after the check. Works with ordinary function tools without migrating them to MCP. The OpenAI Responses API and streaming on Chat Completions are not supported yet. | Route protected tool access through MCP servers and the gateway. Model API choice is independent of that tool connection. |
| Audit action visibility | Records policy decisions about model requests and proposed tool calls, including user, session, policy version, reasons, timing and cumulative usage. Sees tool results only when the agent sends them in a later model request. | Can record actual tool invocations and returned results at the tool boundary, including calls made without consulting a model. Actions that bypass the gateway remain outside its visibility. |

An allowed tool call in our audit log means the gateway permitted the proposal;
it does not prove the agent executed it or that its external effect succeeded.
The agent still receives raw tool results and executes tools itself. Direct tool
calls and model calls that bypass this proxy are invisible to it. The hash-chained
log helps detect changes to recorded entries; it does not make the record complete.

For example, policy can permit a card token to be restored for `charge_card` while
blocking that same token from leaving through `send_email`. Enforcing this rule
at the actual tool boundary as well requires an MCP adapter, tool middleware or
an agent execution hook; those integrations are not implemented in this MVP.
See [the architecture decision](docs/decisions.md) for the enforcement tradeoffs.

## Run with Docker Compose

Install and start Docker Desktop (Linux containers) on Windows/macOS, or Docker
Engine with the Compose plugin on Linux. Windows needs WSL 2 and hardware
virtualization; a restart may be required after installation.

On Windows, run these in an administrator PowerShell if Docker/WSL are missing:

```powershell
winget install --id Microsoft.WSL --exact --accept-package-agreements --accept-source-agreements
winget install --id Docker.DockerDesktop --exact --accept-package-agreements --accept-source-agreements
```

Restart Windows if prompted, then open Docker Desktop and wait for its engine to
start. See [Docker's Windows installation guide](https://docs.docker.com/desktop/setup/install/windows-install/).

From this repository:

```sh
docker compose up --build -d --wait
```

- Dashboard/test prompt: http://localhost:3000
- Gateway API documentation: http://localhost:8000/docs
- Health: http://localhost:8000/api/health
- Metrics and audit: `/api/metrics`, `/api/events`, `/api/audit/verify`

No `.env` or external service keys are required for the default **offline demo**.
The dashboard and demo agent use the public local-test identity keys from
`demo/dev-keys.env`; requests still authenticate with a bearer key and state a
purpose. Set the dashboard's server-side `ACL_KEY` to use another registered key.
It uses
`mock/compromised` (a scripted model, not a conversational LLM) and `ACL_JUDGE=demo`
(a deterministic keyword checker, **not** Jev or a production security classifier).
The prompt page shows the completion and policy decisions. Try a card number such
as `4111111111111111` to see reversible redaction. Other policy controls stay active.
Outside Compose, the gateway still defaults to the real Jev judge and fails closed
when its key is missing.

Edit `policy/policy.yaml` (every field documented in [docs/policy.md](docs/policy.md)) or `policy/signatures.json` on the host to test live policy
changes. Audit history persists in a named Docker volume; session budgets and token
vaults are in memory and reset when the gateway restarts. Ports bind to localhost.
The dashboard shares the gateway's network namespace so its API proxy reaches the
gateway over loopback, including the localhost-only `/api/try` endpoint. Both
published ports belong to the gateway service. Use Compose to recreate the stack
together when changing its network configuration.
The image includes the public `demo/dev-keys.env` fixture for the built-in demos;
private environment files are excluded from the build context.

```sh
docker compose logs -f
docker compose down
docker compose --profile test run --build --rm tests
```

To run the tool-using bank demo (fake tools, no external email sent):

```sh
docker compose exec gateway python /app/demo/agent.py alice "Look up customer 7" --model mock/compromised
```

For the onboarding scenario, use the same model and
`--scenario onboarding` with user `olivia` and a client such as `NW-2041`.

**Demo data for the dashboard** (one run of every scenario's key moments: redaction, quarantine, information
barrier, scope block, MNPI flow block, budget stop, identity denial):

```sh
docker compose exec gateway python /app/demo/seed.py
```

Without Docker: `just demo-data`.

## Live services (optional)

Copy `.env.example` to `.env` (`Copy-Item .env.example .env` in PowerShell).
For real semantic checks, set `ACL_JUDGE=jev` and `TYPESAFE_API_KEY`.
For an OpenRouter model, also set `OPENROUTER_API_KEY` and
`ACL_MODEL=deepseek/deepseek-v4.1-flash` (must be allowed in the policy).
Recreate services after changing `.env`:

```sh
docker compose up -d --wait
```

For a local Ollama model, set `ACL_MODEL=qwen3:4b` and run:

```sh
docker compose --profile ollama up --build -d --wait
docker compose exec ollama ollama pull qwen3:4b
```

Ollama runs on CPU by default and stores downloaded models in a named volume.
The gateway uses `http://ollama:11434` internally. Real Jev checks still require
the TypeSafe key; keep `ACL_JUDGE=demo` only for demonstrations.

## Development without Docker

With Python 3.12+, uv and Node 22+, run `uv sync` inside `gateway` and `npm ci`
inside `dashboard`. Start `uv run uvicorn main:app --host 0.0.0.0 --port 8000`
and `npm run dev` in their respective directories. For an offline run, set
`ACL_JUDGE=demo` in the gateway environment. Run `uv run pytest -q` in `gateway`
(the same suite as `just test`; GitHub Actions runs it on every push and PR, no keys needed).
The Nix/direnv workflow and `just` commands remain available.
