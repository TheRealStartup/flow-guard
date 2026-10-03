# AI Control Layer

HackYeah 2026 · Goldman Sachs partner task. A policy gateway between AI agents and the models, MCP tools
and APIs they use: one central policy, rule-based and AI-based controls, data-flow tracking across a
session, reversible redaction, approvals, budgets, an audit log and a dashboard.

## Protection, integration and audit visibility

The current MVP is an OpenAI-compatible model proxy. An MCP gateway enforces
controls at the tool boundary; the two approaches can work together.

| Point | AI Control Layer: current model proxy | MCP gateway |
| --- | --- | --- |
| Protects | Checks messages before they reach the model, replaces detected sensitive values with reversible tokens, and filters the model's proposed tool calls before returning them to the agent. | Checks actual tool requests before execution and can filter tool results before returning them to the agent. Model traffic needs separate protection. |
| Integration | Point an agent using Chat Completions at `http://localhost:8000/v1`; send `X-User` and a stable `X-Session`. Works with ordinary function tools without migrating them to MCP. Streaming, Responses and Anthropic Messages are not supported yet. | Route protected tool access through MCP servers and the gateway. Model API choice is independent of that tool connection. |
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

Status: setting up. See `CLAUDE.md` for the plan and `just --list` for commands.
