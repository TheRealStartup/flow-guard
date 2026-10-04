# FlowGuard: AI Control Layer

[![test](https://github.com/TheRealStartup/flow-guard/actions/workflows/test.yml/badge.svg)](https://github.com/TheRealStartup/flow-guard/actions/workflows/test.yml)

HackYeah 2026 · Goldman Sachs partner task. FlowGuard is a gateway between AI agents and the models they use. It
checks every request and every tool result: it hides personal data behind tokens, quarantines planted instructions,
enforces data classes and information barriers, caps budgets, and writes a tamper-evident audit log.

## Fastest way to see it (no setup)

1. **Watch the submission video:** VIDEO_LINK
2. **Open the live dashboard:** https://flowguard.91.98.65.108.sslip.io
   User and password are in our submission form.

## Run it yourself with Docker

Needs Docker Desktop (Windows/macOS) or Docker Engine with the Compose plugin (Linux).

```sh
docker compose up --build -d --wait
```

- Dashboard: http://localhost:3000
- Gateway API docs: http://localhost:8000/docs

This starts the gateway, the dashboard and the signature feed. No keys needed: by default it runs offline with a
scripted model (`mock/compromised`) and a keyword stand-in for the injection check (`ACL_JUDGE=demo`). Fill the
dashboard with one run of every scenario:

```sh
docker compose exec gateway python /app/demo/seed.py
```

**With real models** (optional): copy `.env.example` to `.env`, set `ACL_JUDGE=jev`, `TYPESAFE_API_KEY`,
`OPENROUTER_API_KEY` and `ACL_MODEL=deepseek/deepseek-v4.1-flash`, then run `docker compose up -d --wait` again.

Tests and shutdown:

```sh
docker compose --profile test run --build --rm tests
docker compose down
```

## Learn more

- [docs/policy.md](docs/policy.md): every control and policy field
- [docs/decisions.md](docs/decisions.md): design decisions and their trade-offs
- [docs/onboarding-desk.md](docs/onboarding-desk.md): the real Claude Code doing KYC onboarding through FlowGuard
- [docs/benchmarks.md](docs/benchmarks.md): measured detection rates
- Development without Docker: Nix devshell and `just dev` (see `justfile`)
