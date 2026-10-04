# Boundary fixes and Live demo wording — 4 October 2026

The test gateway now selects an explicit enforced baseline in its temporary policy, preserving the YAML layout.
Changing controls in the running dashboard no longer changes the suite's initial expectations. The real policy and
its current dashboard toggles are preserved. The review expectations follow the calibrated Jev threshold and the
gateway's direct neutral reply to a restricted prompt.

The gateway now checks supported multipart answers, reasoning, reasoning details and refusal text; removes opaque
provider fields; honors output blocking; applies the caller's information barrier to answers and tool arguments;
and protects nested tool-schema descriptions, examples and defaults. Sensitive tool identifiers and schema keys
are refused instead of silently renamed. Approved tools retain their explicit detokenization exception.

Semantic verdicts and quarantined replacements are scoped to the effective policy version. Fail-open judge errors
are never cached as successful checks, and an in-flight check does not authorize another request.

External arguments are inspected after bounded JSON, Base64, URL and hex decoding (two levels, 64 candidates and
64 KiB total). Calls exceeding the inspection limit are refused when egress enforcement is enabled. This does not
guarantee detection of arbitrary splitting, encryption or transformations; session-mode egress remains stronger.

Completion allowances are capped to remaining session/daily token budgets when budget enforcement is enabled.
Reservations prevent concurrent completions in the same gateway process from spending the same allowance and
are released on provider failure. This caps requested output; input-token estimates, provider accounting, monetary
overshoot and reservations shared across independent gateway processes are not hard guarantees.

New audit entries are masked before hashing. Sensitive identifiers get stable distinct public hashes, while raw
session keys remain internal. Live session/metric views use the same masking. Existing historical records are not
rewritten. A separate local `.head.json` checkpoint detects log-tail truncation, including after restart, and
refuses appending onto a mismatched log. The checkpoint must itself be preserved: an administrator able to replace
both files requires an independent trusted anchor. A crash between log flush and checkpoint replacement fails
closed and needs inspection, rather than automatically trusting an unanchored tail.

In Live demo, a muted check and “Used in this run” sit below each control name. The blue configured-action pill,
policy selector and findings consistently say “Hidden”; the tooltip explains reversible tokens. The controls
column says “Configured action” so configuration is not mistaken for the current run's result.
Scopes describe what each privacy check detects, without promising tokenization when its action is Allow or Block.
Issued passport tokens are preserved in the findings and are not tokenized again; forged or altered markers still
receive sensitive-data inspection. The Docker test image includes the shipped signature feed.

Validation includes the original 50 protection checks and synthetic regressions in `tests/test_boundary_regressions.py`.
All checks use isolated policies and controlled responses; no paid APIs or quarantine text inspection is required.

Actor context now uses one consistent “Access for this actor” label, with plain-language permissions for all six
actors and an explanation that active controls determine enforcement. Repeated job titles and raw tool identifiers
are removed. Switching actors updates the description without overflowing the panel.

Validation: 458 tests passed, 1 skipped; dashboard TypeScript, ESLint and Docker production build passed.
