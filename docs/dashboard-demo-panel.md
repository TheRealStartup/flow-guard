# Demo panel: show what the gateway actually does

For Inez, from Paul + the code session (Sat ~19:50). It replaces the "denied before database retrieval" wording, which
we don't do. Below are the three checkpoints the gateway really has, the wording for each, and the API field that feeds it.

## The three checkpoints (the flow strip)

```
User request → Model proposes an action → ① ACTION CHECK → Tool runs → ② RESULT CHECK → Model sees only the filtered result → ③ OUTBOUND CHECK
```

| # | Checkpoint | What really happens | Wording on the panel |
|---|---|---|---|
| ① | **Before the agent acts** | The gateway checks every tool call the model proposes: role → allowed tools, attack signatures, budget. A blocked call is removed from the model's answer, so the agent never runs it. | "Stopped before it ran" |
| ② | **Before the model reads** | Tool results pass the gateway on the way back to the model. Card, IBAN, PESEL and secrets become tokens; text with hidden instructions is quarantined. | "Removed before the model saw it" |
| ③ | **Before data leaves** | Outgoing calls (email, web) carrying sensitive data are blocked. Real values are put back **only** for tools the policy names (e.g. the payment or sanctions-screening tool). | "Blocked before it left" / "Released only to an approved tool" |

## Copy changes (current → honest)

| Current | Replace with |
|---|---|
| "Evaluate before read · Filter before AI context" | "Check before acting · Filter before the model · Block before leaving" |
| "Database → FlowGuard redaction → AI agent. Blocked fields never reach the model." | "Tool → gateway → model. Sensitive values never reach the model or the model provider." (keep **model**, not "agent": the agent program does receive the raw tool result) |
| "national_id was denied before database retrieval. It was not read, logged as a value, or sent to the AI agent." | "The national ID was removed from the tool result before the model saw it. It was never sent to the model provider and is not stored in the audit log." |
| "Not retrieved / not returned" | "Tokenized → `[[PESEL#9c41de]]`" or "Removed" |
| "Scope verified · Read constrained · Output sanitized · Context released" | "Action allowed (support_junior may call get_customer) · Result filtered (3 values tokenized) · Answer checked · Nothing left the organisation" |
| "Define what your AI agents can see. Stop sensitive data before it enters their context." | Keep it: it is true (context = what the model sees). |

## The results table

Columns: **What was found · Where · Decision · What the model saw instead · Rule**

| What was found | Where | Decision | What the model saw instead | Rule |
|---|---|---|---|---|
| Card number | tool result `get_customer` | Tokenized | `[[CARD#3f2a1b ****4444]]` | `pii.card` |
| PESEL | tool result | Tokenized | `[[PESEL#9c41de]]` | `pii.pesel` |
| Note with hidden instructions | tool result | Quarantined (p = 0.98) | "Content removed: suspected prompt injection" | `injection.jev` |
| `send_email` to pci-review@… | model's next action | Stopped before it ran | — | `flow.sensitive_to_external` |

Data: `POST /api/try` → `steps[].acl.decisions[]`, using `control`, `where`, `action`, `reason`, `score` and `excerpt`.
Allowed values (name, email) are not listed as decisions; show "everything else passed unchanged".

## Banner states (one per run, the most severe one wins)
- **Blocked before it left:** a `flow.*` block.
- **Stopped before it ran:** an `access.tools`, `signatures` or `budget` block on a tool call.
- **Removed before the model saw it:** any redaction or quarantine.
- **Released only to an approved tool:** `pii.detokenize`.
- **Passed:** nothing found.

## Footer (one honest sentence)
"The tool did read these values; the gateway kept them in its token vault and gave the model placeholders. Real values
are only put back for tools the policy allows."

## Possible backend additions (ask the code session)
- `tool_calls` on every audit entry (planned): lets the panel show allowed actions too, not just blocked ones.
- Field names for JSON tool results (`card`, `iban` instead of "CARD detected").
- **A rule on tool arguments** ("support staff may only open their assigned customers"). This is a real pre-retrieval block: the `get_customer` call for someone else's client never runs. It is the honest version of the mockup's "Customer record boundary".
