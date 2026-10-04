# HR protection assessment

Claude Opus implemented and independently reviewed the HR safeguards. The demo uses invented employee records and a fictional handbook.

## Implemented

- `access.purpose` blocks configured HR performance-review, ranking and termination purposes before either the task model or Jev. It also checks common judging requests when the header claims an administrative purpose, including retained history.
- `get_employee` is DP30. Calls whose results exceed the model or judge ceiling are stopped before fetching records; supplied results are classified and withheld. Employee scope also applies.
- Ordinary handbook questions use `get_hr_policy`, classified internal. Unknown or sensitive tool results are withheld from demo previews.
- `hr_admin.redact_purpose` hides free-text purpose headers in new audit records and session reports, independently of the purpose control. Raw purpose remains available in memory for enforcement. Early identity denials also withhold purpose.

## Review and verification

Review found plain named-person judging gaps and an event-question false block. Opus fixed them and added both-adapter regressions. Review also found raw purpose-header persistence; the reporting change covers allowed, blocked and early-denied requests.

The final integrated suite passed **289 tests**, with **one live-network test skipped**. Tests capture actual task-model and Jev inputs and check audit and preview outputs.

## Remaining limits

The signatures cover tested common requests, not every paraphrase or obfuscation. Confirmed conservative false blocks for technical server/query performance questions and negated system instructions or assistant refusals are tracked in [issue #20](https://github.com/TheRealStartup/flow-guard/issues/20).

Historical audit entries are not rewritten; previously recorded free-text purposes can remain in old exports and session steps. The reporting protection applies to new records.

Run the handbook demo through a running gateway:

```sh
cd gateway
uv run python ../demo/agent.py hana "What is the parental leave policy?" --scenario hr --purpose hr-admin --model mock/compromised
```
