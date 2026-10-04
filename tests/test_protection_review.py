"""50 protection checks. Synthetic data, isolated policies, no paid API calls.

The injected judge controls scores to test enforcement, not Jev classification accuracy.
No tools are executed and no quarantine fixture contents are inspected.
"""
import base64
import json

import pytest

from acl.detectors.jev import Verdict

CARD = "4111111111111111"
SECRET = "sk-or-v1-" + "a" * 40


def ask(gw, text="Hello", user="alice", **kw):
    if gw.upstream.next_reply is None:
        gw.upstream.next_reply = {"text": "OK"}
    return gw.chat(user, [{"role": "user", "content": text}], **kw)


def has(response, control, action):
    return any(d["control"] == control and d["action"] == action
               for d in response.json()["acl"]["decisions"])


def tool(gw, name, **args):
    gw.upstream.next_reply = {"tool_call": {"name": name, "arguments": args}}


def calls(response):
    return response.json()["choices"][0]["message"].get("tool_calls", [])


def scored(gw, score):
    async def judge(text, source, timeout_s):
        return Verdict(injection=score, model="review-controlled-score")
    gw.judge.judge = judge


def test_P01_missing_identity_never_reaches_model(gw):
    assert ask(gw, user="unknown").status_code == 401
    assert not gw.upstream.seen


def test_P02_invalid_key_never_reaches_model(gw):
    assert ask(gw, headers={"Authorization": "Bearer invalid"}).status_code == 401
    assert not gw.upstream.seen


def test_P03_identity_header_cannot_escalate(gw):
    assert ask(gw, headers={"X-User": "bob"}).status_code == 403
    assert not gw.upstream.seen


def test_P04_missing_purpose_denied(gw):
    assert ask(gw, headers={"X-Purpose": ""}).status_code == 400
    assert not gw.upstream.seen


def test_P05_session_takeover_denied(gw):
    assert ask(gw, session="owned").status_code == 200
    assert ask(gw, user="bob", session="owned").status_code == 403
    assert len(gw.upstream.seen) == 1


def test_P06_key_revocation_applies_without_restart(gw):
    ask(gw)
    path = gw.dir / "identities.yaml"
    path.write_text("\n".join(x for x in path.read_text().splitlines() if "user: alice" not in x))
    import os
    os.utime(path, (path.stat().st_atime, path.stat().st_mtime + 5))
    assert ask(gw, session="new").status_code == 401


@pytest.mark.parametrize("value,control", [
    pytest.param(CARD, "pii.card", id="P07_compact_card"),
    pytest.param("4111 1111 1111 1111", "pii.card", id="P08_spaced_card"),
    pytest.param("4111-1111-1111-1111", "pii.card", id="P09_dashed_card"),
    pytest.param("378282246310005", "pii.card", id="P10_amex_card"),
    pytest.param("DE89370400440532013000", "pii.iban", id="P11_iban"),
    pytest.param("44051401458", "pii.pesel", id="P12_pesel"),
    pytest.param("passport: C01X00T47", "pii.passport", id="P13_passport"),
    pytest.param(SECRET, "secrets", id="P14_openrouter_secret"),
    pytest.param("AKIA" + "A" * 16, "secrets", id="P15_aws_secret"),
    pytest.param("ghp_" + "a" * 36, "secrets", id="P16_github_secret"),
])
def test_sensitive_input(gw, value, control):
    response = ask(gw, "Test value: " + value)
    assert has(response, control, "redact")
    assert value not in json.dumps(gw.upstream.seen[-1])
    assert value not in json.dumps(gw.judge.calls)


def test_P17_bad_checksum_does_not_trigger_card_redaction(gw):
    r = ask(gw, "Order 4111111111111112")
    assert not has(r, "pii.card", "redact")
    assert "4111111111111112" in json.dumps(gw.upstream.seen[-1])


def test_P18_multipart_prompt_redacted(gw):
    r = ask(gw, [{"type": "text", "text": CARD}, {"type": "text", "text": "explain"}])
    assert has(r, "pii.card", "redact")
    assert CARD not in json.dumps(gw.upstream.seen[-1])


def test_P19_judge_receives_only_masked_secret(gw):
    ask(gw, SECRET)
    assert gw.judge.calls and SECRET not in json.dumps(gw.judge.calls)
    assert "[[SECRET#" in json.dumps(gw.judge.calls)


def test_P20_model_answer_card_redacted(gw):
    gw.upstream.next_reply = {"text": CARD}
    r = ask(gw)
    assert CARD not in r.text and has(r, "pii.card", "redact")


def test_P21_unapproved_model_denied(gw):
    r = ask(gw, model="unapproved/model")
    assert has(r, "models.allowlist", "block") and not gw.upstream.seen


def test_P22_junior_cannot_charge_card(gw):
    tool(gw, "charge_card", card_number="dummy", amount_pln=1)
    r = ask(gw)
    assert not calls(r) and has(r, "access.tools", "block")


def test_P23_authorized_analyst_can_charge(gw):
    tool(gw, "charge_card", card_number="dummy", amount_pln=1)
    assert calls(ask(gw, user="bob"))


def test_P24_unassigned_client_denied(gw):
    tool(gw, "get_client_file", client_id="NW-9999")
    r = ask(gw, user="olivia")
    assert not calls(r) and has(r, "access.scope", "block")


def test_P25_assigned_client_allowed(gw):
    tool(gw, "get_client_file", client_id="NW-2041")
    assert calls(ask(gw, user="olivia"))


def test_P26_raw_card_external_email_denied(gw):
    tool(gw, "send_email", to="sink@example.invalid", body=CARD)
    r = ask(gw)
    assert not calls(r) and has(r, "flow.sensitive_to_external", "block")


def test_P27_token_external_email_denied(gw):
    token = gw.app.state.engine.session("s1", "alice").tokenize("CARD", CARD)
    tool(gw, "send_email", to="sink@example.invalid", body=token)
    r = ask(gw)
    assert not calls(r) and has(r, "flow.sensitive_to_external", "block")


def test_P28_benign_email_allowed_in_value_mode(gw):
    gw.app.state.engine.session("s1", "alice").tokenize("CARD", CARD)
    tool(gw, "send_email", to="sink@example.invalid", body="Your appointment is confirmed.")
    assert calls(ask(gw))


def test_P29_authorized_sink_restores_token(gw):
    token = gw.app.state.engine.session("s1", "bob").tokenize("CARD", CARD)
    tool(gw, "charge_card", card_number=token, amount_pln=1)
    assert CARD in calls(ask(gw, user="bob"))[0]["function"]["arguments"]


def test_P30_token_cannot_resolve_in_another_session(gw):
    token = gw.app.state.engine.session("first", "bob").tokenize("CARD", CARD)
    tool(gw, "charge_card", card_number=token, amount_pln=1)
    assert CARD not in calls(ask(gw, user="bob", session="second"))[0]["function"]["arguments"]


def test_P31_public_user_restricted_input_withheld(gw):
    r = ask(gw, "Project Falcon confidential valuation", user="olivia")
    assert has(r, "barrier.mnpi", "redact")
    assert "Project Falcon" not in json.dumps(gw.upstream.seen[-1])


def test_P32_cleared_user_restricted_input_stays_off_the_model(gw):
    response = ask(gw, "Project Falcon confidential valuation", user="marcus")
    assert not gw.upstream.seen  # the gateway now answers withheld prompts itself
    assert has(response, "classification", "block")
    assert "MNPI" in gw.app.state.engine.sessions["s1"].labels


def test_P33_score_below_threshold_allowed(gw):
    scored(gw, gw.app.state.engine.policies.get().control("injection.jev")["threshold"] - 0.001)
    assert has(ask(gw), "injection.jev", "allow")
    assert gw.upstream.seen


def test_P34_score_at_threshold_quarantined(gw):
    scored(gw, gw.app.state.engine.policies.get().control("injection.jev")["threshold"])
    r = ask(gw, "CONTROLLED_SCORE_TEST")
    assert has(r, "injection.jev", "redact")
    assert "CONTROLLED_SCORE_TEST" not in json.dumps(gw.upstream.seen[-1])


def test_P35_strict_high_score_never_reaches_model(gw):
    gw.edit_policy(lambda p: p.update(active_profile="strict"))
    scored(gw, 0.9)
    assert has(ask(gw), "injection.jev", "block") and not gw.upstream.seen


def test_P36_judge_outage_fails_closed(gw):
    gw.judge.fail = True
    assert has(ask(gw), "injection.jev", "block") and not gw.upstream.seen


def test_P37_tool_budget_enforced(gw):
    gw.edit_policy(lambda p: p["budgets"]["session"].update(max_tool_calls=1))
    tool(gw, "get_customer", customer_id=42)
    assert calls(ask(gw, "first"))
    r = ask(gw, "second")
    assert not calls(r) and has(r, "budget", "block")


def test_P38_exhausted_token_budget_blocks_next_request(gw):
    gw.edit_policy(lambda p: p["budgets"]["session"].update(max_tokens=10))
    ask(gw)
    r = ask(gw, "next")
    assert has(r, "budget", "block") and len(gw.upstream.seen) == 1


def test_P39_sensitive_content_absent_from_audit(gw):
    ask(gw, CARD + " " + SECRET)
    raw = gw.app.state.engine.audit.path.read_text()
    assert CARD not in raw and SECRET not in raw


def test_P40_modified_audit_record_detected(gw):
    ask(gw)
    path = gw.app.state.engine.audit.path
    rows = path.read_text().splitlines()
    e = json.loads(rows[-1]); e["outcome"] = "tampered"; rows[-1] = json.dumps(e)
    path.write_text("\n".join(rows) + "\n")
    assert not gw.client.get("/api/audit/verify").json()["ok"]


def custom_reply(gw, message):
    async def upstream(body, cfg):
        return {"model": body["model"], "choices": [{"index": 0, "message": message, "finish_reason": "stop"}],
                "usage": {"total_tokens": 1}}
    # The router captures the upstream object; replace its __call__ behaviour through next_reply instead
    # by installing a separate app with the same isolated policy and audit path.
    from main import create_app
    from fastapi.testclient import TestClient
    gw.app = create_app(gw.policy_path, gw.app.state.engine.audit.path, gw.judge, upstream)
    gw.client = TestClient(gw.app)


def test_P41_provider_reasoning_must_not_leak_sensitive_values(gw):
    custom_reply(gw, {"role": "assistant", "content": "OK", "reasoning": SECRET})
    assert SECRET not in ask(gw).text


def test_P42_multipart_model_output_must_be_redacted(gw):
    custom_reply(gw, {"role": "assistant", "content": [{"type": "text", "text": CARD}]})
    assert CARD not in ask(gw).text


def test_P43_tool_schema_secret_must_not_reach_provider(gw):
    gw.upstream.next_reply = {"text": "OK"}
    gw.client.post("/v1/chat/completions", headers={
        "Authorization": "Bearer " + __import__("conftest").DEV_KEYS["alice"], "X-Purpose": "review"},
        json={"model": "mock/compromised", "messages": [{"role": "user", "content": "hello"}],
              "tools": [{"type": "function", "function": {"name": "get_customer", "description": SECRET,
                         "parameters": {"type": "object", "properties": {}}}}]})
    assert SECRET not in json.dumps(gw.upstream.seen)


def test_P44_encoded_card_external_email_must_be_denied(gw):
    gw.app.state.engine.session("s1", "alice").tokenize("CARD", CARD)
    tool(gw, "send_email", to="sink@example.invalid", body=base64.b64encode(CARD.encode()).decode())
    assert not calls(ask(gw))


def test_P45_restricted_model_output_must_be_withheld(gw):
    gw.upstream.next_reply = {"text": "Project Falcon confidential valuation"}
    assert "Project Falcon" not in ask(gw, user="olivia").json()["choices"][0]["message"]["content"]


def test_P46_replaying_blocked_prompt_must_stay_blocked(gw):
    gw.edit_policy(lambda p: p.update(active_profile="strict"))
    scored(gw, 0.99)
    assert has(ask(gw, "CONTROLLED_SCORE_TEST"), "injection.jev", "block")
    assert has(ask(gw, "CONTROLLED_SCORE_TEST"), "injection.jev", "block")
    assert not gw.upstream.seen


def test_P47_replaying_after_outage_must_fail_closed(gw):
    gw.judge.fail = True
    assert has(ask(gw, "repeat"), "injection.jev", "block")
    assert has(ask(gw, "repeat"), "injection.jev", "block")
    assert not gw.upstream.seen


def test_P48_token_limit_must_cap_upstream_generation(gw):
    gw.edit_policy(lambda p: p["budgets"]["session"].update(max_tokens=100))
    ask(gw, max_tokens=10000)
    assert not gw.upstream.seen or gw.upstream.seen[-1].get("max_tokens", 10000) <= 100


def test_P49_sensitive_purpose_must_be_masked_in_audit(gw):
    ask(gw, headers={"X-Purpose": "case " + SECRET})
    assert SECRET not in gw.app.state.engine.audit.path.read_text()


def test_P50_deleted_audit_tail_must_be_detected(gw):
    ask(gw, "one"); ask(gw, "two")
    path = gw.app.state.engine.audit.path
    path.write_text("\n".join(path.read_text().splitlines()[:-1]) + "\n")
    assert not gw.client.get("/api/audit/verify").json()["ok"]
