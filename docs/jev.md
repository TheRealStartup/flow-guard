# Jev (TypeSafe) API: what we use

Source: https://docs.typesafe.ai/api (read 2026-10-03). Key: `TYPESAFE_API_KEY` in `gateway/.env` (gitignored).

`POST https://api.typesafe.ai/v1/systemone`, header `Authorization: Bearer $TYPESAFE_API_KEY`.

Body: `model: "jev-latest"`, `state` (string or object: the content to judge), and `questions`, a map
from our own key to a question:
- `{"type":"noul","instructions":"…","criteria":{"true":"…","false":"…"}}` → `{"noul": 0.98}` (probability of "yes")
- `{"type":"choice","instructions":"…","criteria":{"allow":"…","review":"…","block":"…"}}` → `choice`, `confidence`, `probabilities`
- `{"type":"score","instructions":"…","criteria":["level 0", "…"]}` (2–10 levels)

Errors: 401 auth, 422 validation, 429/529 → retry with backoff (and our policy's `on_error`).

What Jev receives: `state.text` is permitted content in clear text, sent outside the bank. Identifiers are tokens by
then, but business facts are not, so the engine sends only content at or below `injection.jev.max_class` (default
`internal`). P2/DP30 content is never sent; a request that would need it checked is blocked (docs/decisions.md D6,
tests/test_classification.py).

Verified 14:45 Sat with a fake injection in a tool output: `prompt_injection` 0.98, `risk` = block (0.98),
0.95 s total for two questions (one call, including the TLS handshake).
