# Signature feed (published side)

This folder plays the security team's feed server: `just feed` serves it on http://127.0.0.1:8100.
The gateway pulls `signatures.json` from `controls.signatures.feed_url` (policy.yaml) on start and every
`refresh_s` seconds, checks it, and writes the last good copy to `policy/signatures.json`.

Each signature: `id`, `where` (prompt | tool_result | tool_args | tool_description), `pattern` (regex,
case-insensitive), `ref`, and optionally `title`, `severity`, `published`, `cve`, `sources` and `examples`
(`match` / `no_match`). A feed whose patterns do not compile, or miss their own examples, is rejected as a whole.
