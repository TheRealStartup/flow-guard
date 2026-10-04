"""What an audit entry means, in plain language: one verdict, a headline, a reason and counts.

Computed when an entry is served (never stored), so the hash chain stays intact, old entries get the same wording,
and every page (Overview, Audit, Live demo) shows the same label and the same numbers for the same event.

Verdicts and their labels follow the "one term per concept" table in docs/ux-review.md:
attack (Attack caught) > blocked (Blocked) > quarantined > withheld > hidden > released > flagged > allowed.
"""

import re
from typing import Any

from .engine import threats_in

LABEL = {
    "attack": "Attack caught",
    "blocked": "Blocked",
    "quarantined": "Quarantined",
    "withheld": "Withheld",
    "hidden": "Hidden",
    "released": "Released",
    "flagged": "Flagged",
    "allowed": "Allowed",
    "policy": "Policy",
    "rejected": "Rejected",
}

# Values the PII and secret controls replace with reversible tokens.
VALUE_CONTROLS = {"pii.card", "pii.iban", "pii.pesel", "pii.passport", "pii.dob", "secrets"}
KIND = {"CARD": "card number", "IBAN": "IBAN", "PESEL": "national ID", "PASSPORT": "passport number",
        "DOB": "date of birth", "SECRET": "secret", "MNPI": "deal information"}
CLASS = {"public": "public", "internal": "internal", "P2": "P2 client data", "DP30": "DP30 deal secrets"}


def _plural(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 's'}"


def _tool(where: str) -> str | None:
    return where[10:] if where.startswith("tool_call:") else None


def _join(names: list[str]) -> str:
    return " and ".join(names) if len(names) < 3 else ", ".join(names[:-1]) + " and " + names[-1]


def _kinds(text: str) -> str:
    """'SECRET/CARD' → 'secret and card number'."""
    return _join([KIND.get(k, k.lower()) for k in text.split("/") if k])


def _from(d: dict[str, Any]) -> str:
    src = d.get("source")
    if src:
        return f"the {src.split()[0]} result"
    return {"prompt": "the user's request", "tool_result": "a tool result", "model_output": "the model's answer",
            "assistant": "the model's earlier answer"}.get(d.get("where", ""), "the request")


def _percent(score: float | None) -> str:
    return f"{round(score * 100)}%" if score is not None else "?"


def _threshold(reason: str) -> str | None:
    m = re.search(r">=?\s*([0-9.]+)", reason)
    return f"{round(float(m.group(1)) * 100)}%" if m else None


def explain(d: dict[str, Any], user: str | None = None) -> tuple[str, str]:
    """(short headline, one plain sentence) for the decisive decision of an entry."""
    c, a, r, where = d.get("control", ""), d.get("action", ""), d.get("reason", ""), d.get("where", "")
    tool = _tool(where)
    who = user or "this user"

    if c == "injection.jev":
        if d.get("score") is None and "check failed" in r:
            return ("Injection check unavailable",
                    "The AI injection check (Jev) did not answer, so the request was "
                    + ("stopped to be safe (fail closed)." if a == "block" else "let through and flagged."))
        if d.get("score") is None:  # content too sensitive to send to the external check
            m = re.match(r"(\S+) content may not be sent", r)
            cls = CLASS.get(m.group(1), m.group(1)) if m else "Restricted content"
            return ("Too sensitive to check, blocked",
                    f"{cls[0].upper() + cls[1:]} may not go to the external AI injection check (Jev), and nothing unchecked "
                    "reaches the model. The request was blocked.")
        limit = _threshold(r)
        odds = f"{_percent(d.get('score'))} likely an injection" + (f", limit {limit}" if limit else "")
        if a == "redact":
            return (f"Hidden instruction quarantined in {_from(d)}",
                    f"{_from(d)[0].upper() + _from(d)[1:]} contained text that tries to instruct the agent ({odds}). "
                    "It was removed before the model saw it.")
        if a == "block":
            return (f"Hidden instruction in {_from(d)}, blocked",
                    f"{_from(d)[0].upper() + _from(d)[1:]} contained text that tries to instruct the agent ({odds}). "
                    "The request was blocked.")
        return (f"Possible injection in {_from(d)}, flagged", f"The AI injection check rated it {odds}. Let through and recorded.")

    if c == "flow.sensitive_to_external":
        m = re.match(r"(\S+) data would leave the organisation via (.+?)(?: \(mode=\w+\))?$", r)
        what, via = (_kinds(m.group(1)), m.group(2)) if m else ("Sensitive", tool or "an outside tool")
        sink = via.split(" (")[0]
        if a == "block":
            return (f"Blocked: {what} would have left via {sink}",
                    f"The agent tried to send {what} data out of the organisation via {via}. Blocked before it left.")
        return (f"{what[0].upper() + what[1:]} sent out via {sink}, flagged",
                f"The agent sent {what} data out of the organisation via {via}. Let through and recorded.")

    if c == "access.scope":
        m = re.match(r"(\w+)=(['\"]?)(.*?)\2 is not in (\S+?)'s (\w+)", r)
        val, owner = (m.group(3), m.group(4)) if m else ("this record", who)
        thing = "client" if m and "client" in m.group(5) else "record"
        return (f"Client scope: {val} is not {owner}'s {thing}",
                f"{owner} may only work on their assigned {thing}s, "
                + (f"so {tool} never ran." if a == "block" and tool else "so this was recorded for review."))

    if c == "access.tools":
        m = re.match(r"role '?([^']+?)'? may not call (\S+)", r)
        role, name = (m.group(1), m.group(2)) if m else ("this role", tool or "this tool")
        return (f"Role access: {name} is not allowed",
                f"The role {role} may not use {name}. " + ("Blocked before it ran." if a == "block" else "Let through and flagged."))

    if c == "budget":
        if "tool-call budget" in r:
            n = re.search(r"budget (\d+)", r)
            return ("Budget: tool-call limit reached",
                    f"This session used its {n.group(1) if n else ''} tool calls. "
                    + (f"{tool} was stopped." if tool else "The request was stopped.").replace("  ", " "))
        m = re.search(r"exhausted: (\w+)=", r) or re.search(r"(daily)", r)
        what = {"max_tokens": "token", "max_cost_usd": "cost", "max_tool_calls": "tool-call", "max_compute_seconds": "compute time",
                "daily": "daily"}.get(m.group(1) if m else "", "")
        return (f"Budget: {what} limit reached".replace("  ", " "),
                f"This {'user' if what == 'daily' else 'session'} reached its {what} limit. ".replace("  ", " ")
                + ("The request was stopped." if a == "block" else "Recorded for review."))

    if c == "identity":
        return ("Refused: no valid API key", "Every request must name its user and agent with a valid key. Refused at the door.")

    if c == "classification":
        if "was not sent to any model" in r:
            return ("Blocked: request names restricted content",
                    "The request names content that may not go to this model. It was answered with a neutral message "
                    "and not sent to any model.")
        m = re.match(r"(\S+) returns (\S+) data, above the (\S+) limit for model (\S+)", r)
        if m:
            return (f"Data class: {m.group(1)} returns {m.group(2)} data",
                    f"{m.group(1)} returns {CLASS.get(m.group(2), m.group(2))}, above what model {m.group(4)} may see "
                    f"({m.group(3)}). The call never ran.")
        m = re.match(r"(\S+) content is above the (.+?) limit for (.+?); withheld", r)
        if m:
            cls, cap, dest = CLASS.get(m.group(1), m.group(1)), m.group(2), m.group(3)
            verb = "blocked" if a == "block" else "withheld"
            return (f"Data class: {cls} {verb}",
                    f"{cls[0].upper() + cls[1:]} is above the {cap} limit for {dest}. It was {verb}.")
        return ("Data class limit", r)

    if c == "barrier.mnpi":
        verb = "withheld" if a == "redact" else "blocked" if a == "block" else "flagged"
        return (f"Information barrier: restricted deal {verb}",
                f"{who} is not on the deal team, so restricted deal content was {verb} with a neutral message.")

    if c == "access.purpose":
        message = r.split("; ", 1)[1] if "; " in r else r
        return ("Purpose rule: " + ("blocked" if a == "block" else "flagged"), message)

    if c == "access.datalake":
        return ("Data lake: query refused", "This query is not available to this user. It never ran.")

    if c == "models.allowlist":
        m = re.search(r"model '([^']+)'", r)
        model = m.group(1) if m else "This model"
        if a == "block":
            return (f"Model {model} not approved", f"{model} is not on the approved model list. Refused.")
        return (f"Model {model} not approved, flagged", f"{model} is not on the approved list. Let through, recorded, lowest data class only.")

    if c == "signatures":
        sig = r.split(":", 1)[0]
        verb = {"block": "blocked", "redact": "removed", "flag": "flagged"}.get(a, a)
        return (f"Known attack pattern {verb}", f"Matched threat signature {sig} in {_from(d)}. It was {verb}.")

    if c == "spotlight":
        return ("Fake data marker escaped", f"{_from(d)[0].upper() + _from(d)[1:]} tried to end its data block early and "
                "speak as the system. The fake marker was escaped.")

    if c == "pii.detokenize":
        return (f"Real values released to {tool or 'an approved tool'}",
                f"The real values behind the tokens went only to {tool or 'an approved tool'}, which the policy allows. "
                "The model never saw them.")

    if c in VALUE_CONTROLS:
        kind = KIND.get(r.split()[0], r.split()[0].lower()) if r else "value"
        if a == "block":
            return (f"Blocked: {kind} in {_from(d)}", f"A {kind} was found in {_from(d)}. The request was blocked.")
        return (f"{kind[0].upper() + kind[1:]} flagged", f"A {kind} was found in {_from(d)}. Let through and recorded.")

    return (c, r)


def _hidden_sentence(ds: list[dict[str, Any]]) -> tuple[str, str]:
    kinds: dict[str, int] = {}
    for d in ds:
        k = KIND.get((d.get("reason") or "").split()[0], "value")
        kinds[k] = kinds.get(k, 0) + 1
    sources = sorted({d["source"].split()[0] for d in ds if d.get("source")})
    where = (f" in the {' and '.join(sources)} result" if sources
             else " in the model's answer" if all(d.get("where") in ("model_output", "assistant") for d in ds) else "")
    what = _join([_plural(n, k) if n > 1 else k for k, n in kinds.items()])
    n = len(ds)
    return (f"{_plural(n, 'value')} hidden{where}",
            f"{what[0].upper() + what[1:]} replaced with reversible tokens{where}. The model saw only the tokens.")


def counts(decisions: list[dict[str, Any]]) -> dict[str, int]:
    """What one entry did, counted the same way on every page.
    hidden: values replaced by tokens · quarantined: injected texts removed · withheld: restricted items kept back ·
    released: tool calls that got real values back · blocked: 1 if the request or a tool call was stopped."""
    out = {"hidden": 0, "quarantined": 0, "withheld": 0, "released": 0, "blocked": 0}
    for d in decisions:
        c, a = d.get("control"), d.get("action")
        if a == "redact" and c in VALUE_CONTROLS:
            out["hidden"] += 1
        elif c == "injection.jev" and a == "redact":
            out["quarantined"] += 1
        elif a == "redact" and c in ("barrier.mnpi", "classification"):
            out["withheld"] += 1
        elif c == "pii.detokenize":
            out["released"] += 1
    out["blocked"] = int(any(d.get("action") == "block" for d in decisions))
    return out


def summarize(e: dict[str, Any]) -> dict[str, Any]:
    """{verdict, label, headline, reason, control, counts} for one audit entry."""
    if e.get("type", "exchange") == "policy_change":
        n = len(e.get("changes") or [])
        if e.get("error"):
            return {"verdict": "rejected", "label": LABEL["rejected"], "headline": "Policy edit rejected",
                    "reason": "The edited policy was invalid. The last good policy stays active.", "control": None}
        if not n:
            return {"verdict": "policy", "label": LABEL["policy"], "headline": "Policy reloaded, no changes",
                    "reason": f"Version {e.get('version')} loaded ({e.get('profile')} profile).", "control": None}
        return {"verdict": "policy", "label": LABEL["policy"], "headline": f"Policy changed: {_plural(n, 'field')}",
                "reason": f"Now version {e.get('version')} ({e.get('profile')} profile).", "control": None}

    ds = [d for d in e.get("decisions") or [] if d.get("action") != "allow"]
    user = e.get("user")
    threats = e.get("threats")
    if threats is None:
        threats = threats_in(ds)
    n = counts(ds)

    def pick(*tests) -> dict[str, Any] | None:
        for test in tests:
            for d in ds:
                if test(d):
                    return d
        return None

    if threats:
        verdict = "attack"
        # The attack itself, not a side effect (a redacted secret before an exfiltration attempt).
        d = pick(lambda d: d["control"] == "flow.sensitive_to_external" and d["action"] == "block",
                 lambda d: d["control"] == "injection.jev" and d.get("score") is not None and d["action"] in ("redact", "block"),
                 lambda d: d["control"] == "signatures" and d["action"] in ("redact", "block"),
                 lambda d: d["control"] == "spotlight")
    elif n["blocked"]:
        verdict, d = "blocked", pick(lambda d: d["action"] == "block")
    elif n["quarantined"]:
        verdict, d = "quarantined", pick(lambda d: d["control"] == "injection.jev" and d["action"] == "redact")
    elif n["withheld"]:
        verdict, d = "withheld", pick(lambda d: d["action"] == "redact" and d["control"] in ("barrier.mnpi", "classification"))
    elif n["hidden"] or any(d["action"] == "redact" for d in ds):
        verdict, d = "hidden", None
    elif n["released"]:
        verdict, d = "released", pick(lambda d: d["control"] == "pii.detokenize")
    elif ds:
        verdict, d = "flagged", pick(lambda d: d["action"] == "flag")
    else:
        verdict, d = "allowed", None

    if d is not None:
        headline, reason = explain(d, user)
    elif verdict == "hidden":
        hidden = [x for x in ds if x["action"] == "redact" and x["control"] in VALUE_CONTROLS]
        headline, reason = _hidden_sentence(hidden) if hidden else ("Content hidden", "Some content was replaced before the model saw it.")
    else:
        calls = [c["name"] for c in e.get("tool_calls") or []]
        headline = "All checks passed" + (f", {calls[0]} allowed" if len(calls) == 1 else f", {len(calls)} tool calls allowed" if calls else "")
        reason = "Nothing sensitive or suspicious found. " + ("The agent's tool call went ahead." if len(calls) == 1
                                                              else "The agent's tool calls went ahead." if calls else "The request went to the model.")
    extra = []
    if verdict in ("attack", "blocked", "quarantined", "withheld") and n["hidden"]:
        extra.append(f"{_plural(n['hidden'], 'value')} hidden")
    if verdict != "released" and n["released"]:
        extra.append(f"real values released to {', '.join(c['name'] for c in e.get('tool_calls') or [] if c.get('outcome') == 'allowed_with_real_values') or 'an approved tool'}")
    if extra:
        reason += " Also: " + "; ".join(extra) + "."
    return {"verdict": verdict, "label": LABEL[verdict], "headline": headline, "reason": reason,
            "control": d.get("control") if d else None, "counts": n}


def for_readers(e: dict[str, Any]) -> dict[str, Any]:
    """An audit entry as served by the API: `threats` for older entries, and the `summary` above."""
    if e.get("type", "exchange") == "exchange" and "threats" not in e:
        e = {**e, "threats": threats_in(e.get("decisions") or [])}
    return {**e, "summary": summarize(e)}
