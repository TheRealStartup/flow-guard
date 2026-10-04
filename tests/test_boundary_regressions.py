"""Synthetic boundary cases beyond the original protection review; no network or quarantine reads."""

import asyncio
import base64
import json
from urllib.parse import quote

import pytest

from acl.detectors.jev import Verdict
from acl.protection import public_id
from acl.state import AuditLog

CARD = "4111111111111111"
SECRET = "sk-or-v1-" + "a" * 40


def ask(gw, text="hello", **kwargs):
    gw.upstream.next_reply = {"text": "OK"}
    return gw.chat("alice", [{"role": "user", "content": text}], **kwargs)


def score(gw, value):
    async def judge(text, source, timeout):
        return Verdict(injection=value, model="controlled")
    gw.judge.judge = judge


def decisions(response):
    return {(d["control"], d["action"]) for d in response.json()["acl"]["decisions"]}


def custom_response(gw, message, **extras):
    from fastapi.testclient import TestClient
    from main import create_app

    async def upstream(body, cfg):
        return {"model": body["model"], "choices": [{"message": message, "finish_reason": "stop"}],
                "usage": {"total_tokens": 1}, **extras}
    gw.app = create_app(gw.policy_path, gw.app.state.engine.audit.path, gw.judge, upstream)
    gw.client = TestClient(gw.app)


def test_semantic_cache_rechecks_after_a_profile_change(gw):
    score(gw, 0.3)  # below balanced 0.4, above strict 0.25
    assert ("injection.jev", "allow") in decisions(ask(gw))
    gw.edit_policy(lambda p: p.update(active_profile="strict"))
    assert ("injection.jev", "block") in decisions(ask(gw))
    assert len(gw.upstream.seen) == 1


def test_fail_open_outage_is_rechecked_after_recovery(gw):
    gw.edit_policy(lambda p: p.update(active_profile="permissive"))
    gw.judge.fail = True
    assert ("injection.jev", "flag") in decisions(ask(gw))
    gw.judge.fail = False
    score(gw, 0.99)
    assert ("injection.jev", "flag") in decisions(ask(gw))
    assert gw.app.state.engine.sessions["s1"].judged  # only the successful second verdict is cached


def test_fail_open_to_fail_closed_rechecks_identical_history(gw):
    gw.edit_policy(lambda p: p.update(active_profile="permissive"))
    gw.judge.fail = True
    ask(gw)
    gw.edit_policy(lambda p: p.update(active_profile="balanced"))
    assert ("injection.jev", "block") in decisions(ask(gw))
    assert len(gw.upstream.seen) == 1


def test_quarantine_is_repeated_but_reconsidered_under_a_new_policy(gw):
    score(gw, 0.5)
    ask(gw, "SYNTHETIC_FIELD")
    ask(gw, "SYNTHETIC_FIELD")
    assert all("SYNTHETIC_FIELD" not in json.dumps(b) for b in gw.upstream.seen)
    gw.edit_policy(lambda p: p.update(active_profile="permissive"))
    ask(gw, "SYNTHETIC_FIELD")
    assert "SYNTHETIC_FIELD" in json.dumps(gw.upstream.seen[-1])


def test_identical_concurrent_requests_do_not_skip_inflight_judging(gw):
    engine = gw.app.state.engine
    gw.edit_policy(lambda p: p.update(active_profile="strict"))

    async def run():
        entered, calls = asyncio.Event(), []
        async def judge(text, source, timeout):
            calls.append(text)
            if len(calls) == 2:
                entered.set()
            await asyncio.wait_for(entered.wait(), 2)
            return Verdict(injection=0.99, model="controlled")
        engine.judge.judge = judge
        body = {"model": "mock/compromised", "messages": [{"role": "user", "content": "hello"}]}
        results = await asyncio.gather(*(engine.check_request(body, "alice", "concurrent") for _ in range(2)))
        assert len(calls) == 2 and all(ex.blocked for _, ex in results)
    asyncio.run(run())


@pytest.mark.parametrize("message", [
    {"content": "OK", "reasoning_details": [{"text": SECRET, "summary": {"text": CARD}, "data": SECRET}]},
    {"content": "OK", "refusal": SECRET},
    {"content": [{"type": "output_text", "text": CARD}, {"type": "image", "url": SECRET}]},
    {"content": "OK", "opaque": SECRET, "reasoning_content": SECRET},
])
def test_all_supported_response_text_is_protected_and_opaque_fields_dropped(gw, message):
    custom_response(gw, message, opaque=SECRET)
    response = ask(gw)
    assert SECRET not in response.text and CARD not in response.text
    assert "opaque" not in response.json() and "opaque" not in response.json()["choices"][0]["message"]


def test_strict_output_block_removes_sibling_fields_and_tool_calls(gw):
    gw.edit_policy(lambda p: p.update(active_profile="strict"))
    custom_response(gw, {"content": SECRET, "reasoning": CARD,
                         "tool_calls": [{"id": "t", "function": {"name": "get_customer", "arguments": "{}"}}]})
    response = ask(gw)
    assert ("secrets", "block") in decisions(response)
    assert SECRET not in response.text and CARD not in response.text
    assert not response.json()["choices"][0]["message"].get("tool_calls")


def test_restricted_reasoning_is_withheld_without_confirming_a_deal(gw):
    custom_response(gw, {"content": "OK", "reasoning": "Project Falcon confidential valuation"})
    response = ask(gw)
    assert "Project Falcon" not in response.text
    assert ("barrier.mnpi", "redact") in decisions(response)


def test_cleared_user_may_receive_restricted_output(gw):
    custom_response(gw, {"content": "Project Falcon confidential valuation"})
    response = gw.chat("marcus", [{"role": "user", "content": "hello"}])
    assert "Project Falcon" in response.json()["choices"][0]["message"]["content"]


def test_multipart_response_keeps_harmless_text_and_blocked_tool_notes(gw):
    custom_response(gw, {"content": [{"type": "text", "text": "Public answer"}],
                         "tool_calls": [{"id": "t", "function": {"name": "charge_card", "arguments": "{}"}}]})
    message = ask(gw).json()["choices"][0]["message"]
    assert message["content"][0]["text"] == "Public answer"
    assert "FlowGuard blocked" in message["content"][1]["text"]


def test_nested_tool_schema_values_redacted_without_changing_schema_keys(gw):
    tool = {"type": "function", "function": {"name": "get_customer", "parameters": {
        "type": "object", "properties": {"note": {"type": "string", "description": SECRET,
                                                  "examples": [SECRET], "default": SECRET}}, "required": ["note"]}}}
    ask(gw, tools=[tool])
    sent = gw.upstream.seen[-1]["tools"][0]["function"]["parameters"]
    assert SECRET not in json.dumps(sent)
    assert list(sent["properties"]) == ["note"] and sent["required"] == ["note"]


def test_sensitive_schema_key_is_refused_without_silently_renaming_it(gw):
    tool = {"type": "function", "function": {"name": "get_customer", "parameters": {"properties": {SECRET: {"type": "string"}}}}}
    response = ask(gw, tools=[tool])
    assert not gw.upstream.seen and SECRET not in response.text


@pytest.mark.parametrize("encoded", [
    base64.b64encode(CARD.encode()).decode(),
    base64.urlsafe_b64encode(CARD.encode()).decode().rstrip("="),
    "".join(f"%{ord(c):02X}" for c in CARD),
    CARD.encode().hex(),
    base64.b64encode(base64.b64encode(CARD.encode())).decode(),
    base64.b64encode(b"Project Falcon confidential valuation").decode(),
])
def test_common_encoded_egress_is_blocked(gw, encoded):
    gw.upstream.next_reply = {"tool_call": {"name": "send_email", "arguments": {"body": encoded}}}
    response = gw.chat("alice", [{"role": "user", "content": "hello"}])
    assert ("flow.sensitive_to_external", "block") in decisions(response)
    assert not response.json()["choices"][0]["message"].get("tool_calls")


@pytest.mark.parametrize("encoded", [base64.b64encode(b"Public meeting at noon").decode(), "this%%%is-not-base64", quote("Public meeting at noon")])
def test_benign_and_malformed_encoded_text_is_allowed(gw, encoded):
    gw.upstream.next_reply = {"tool_call": {"name": "send_email", "arguments": {"body": encoded}}}
    response = gw.chat("alice", [{"role": "user", "content": "hello"}])
    assert response.json()["choices"][0]["message"].get("tool_calls")


def test_external_inspection_limit_fails_closed(gw):
    gw.upstream.next_reply = {"tool_call": {"name": "send_email", "arguments": {"body": "a" * 70000}}}
    response = gw.chat("alice", [{"role": "user", "content": "hello"}])
    assert ("flow.sensitive_to_external", "block") in decisions(response)


def test_audit_and_live_reporting_mask_sensitive_metadata_with_stable_ids(gw):
    sid = "case-" + SECRET
    response = ask(gw, session=sid, headers={"X-Purpose": "case " + SECRET})
    assert response.json()["acl"]["session"] == public_id(sid)
    audit = gw.app.state.engine.audit
    assert SECRET not in audit.path.read_text()
    for path in ["/api/events", "/api/metrics", "/api/sessions", f"/api/sessions/{public_id(sid)}", "/api/audit/export"]:
        assert SECRET not in gw.client.get(path).text
    assert audit.verify()["ok"]


def test_denied_identity_metadata_is_masked(gw):
    gw.chat("unknown", [{"role": "user", "content": "hello"}], session=SECRET,
            headers={"X-Purpose": SECRET, "X-User": SECRET})
    assert SECRET not in gw.app.state.engine.audit.path.read_text()


def test_tail_checkpoint_survives_restart_and_refuses_further_appends(tmp_path):
    path = tmp_path / "audit.jsonl"
    audit = AuditLog(path)
    audit.append({"type": "exchange", "n": 1})
    audit.append({"type": "exchange", "n": 2})
    path.write_text(path.read_text().splitlines()[0] + "\n")
    restarted = AuditLog(path)
    assert not restarted.verify()["ok"]
    with pytest.raises(ValueError, match="integrity"):
        restarted.append({"n": 3})


def test_concurrent_generation_reservations_cannot_spend_the_same_allowance(gw):
    gw.edit_policy(lambda p: p["budgets"]["session"].update(max_tokens=100))
    engine = gw.app.state.engine
    async def run():
        body = {"model": "mock/compromised", "max_tokens": 10000, "messages": [{"role": "user", "content": "hello"}]}
        first, ex = await engine.check_request(body, "alice", "budget")
        assert first["max_tokens"] == 100
        _, denied = await engine.check_request(body, "alice", "budget")
        assert denied.blocked and denied.blocked.control == "budget"
        engine.release_budget(ex)
        _, retry = await engine.check_request(body, "alice", "budget")
        assert not retry.blocked
        engine.release_budget(retry)
    asyncio.run(run())


def test_reported_passport_token_is_exactly_the_issued_token(gw):
    response = ask(gw, "passport: C01X00T47")
    decision = next(d for d in response.json()["acl"]["decisions"] if d["control"] == "pii.passport")
    token = decision["token"]
    assert token.startswith("[[PASSPORT#") and "[PASSPORT]" not in token
    session = gw.app.state.engine.sessions["s1"]
    assert session.detokenize(token) == "C01X00T47"
    assert gw.app.state.engine._redact(gw.app.state.engine.policies.get(), session, token, "model_output") == (token, [])
    audit = gw.app.state.engine.audit
    assert token in audit.path.read_text() and audit.verify()["ok"]


def test_forged_passport_token_does_not_bypass_input_redaction(gw):
    forged = "[[PASSPORT#123456]]"
    response = ask(gw, forged)
    assert ("pii.passport", "redact") in decisions(response)
    assert forged not in json.dumps(gw.upstream.seen)


def test_known_token_with_an_untrusted_suffix_does_not_hide_real_values(gw):
    engine = gw.app.state.engine
    session = engine.session("s1", "alice")
    session.vault["a1b2c3"] = "C01X00T47"
    forged = "[[PASSPORT#a1b2c3 passport: C01X00T47]]"
    text, ds = engine._redact(engine.policies.get(), session, forged, "prompt")
    assert "C01X00T47" not in text and ds
