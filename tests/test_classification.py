"""Data classes at every model boundary (issue #13). Each destination has a class limit: DP30 reaches neither the task
model nor Jev; the shipped policy approves both outside vendors for P2, and the tests that lower Jev's limit check the
request stops when a result cannot be checked. The canaries are synthetic business facts with nothing a regex can find (no card, IBAN, ID or
key), so only the class (from the source or a restricted term) can stop them. Each test checks what actually left the
gateway: the bodies the upstream model received, the texts the judge received, and the audit log."""

import json

import httpx
from fastapi.testclient import TestClient

from acl.detectors.jev import JevJudge

DP30 = "Q3 net interest margin guidance was cut to one point eight five before the announcement"
P2 = "client prefers quarterly settlement through the Luxembourg branch after the fee review"
INTERNAL = "the support rota changes on Monday"


def call(cid, name, args="{}"):
    return {"id": cid, "type": "function", "function": {"name": name, "arguments": args}}


def with_result(gw, tool, content, user="alice", session="c1", cid="c1", prompt="Summarise it."):
    gw.upstream.next_reply = {"text": "ok"}
    return gw.chat(user, [{"role": "user", "content": prompt},
                          {"role": "assistant", "content": None, "tool_calls": [call(cid, tool)]},
                          {"role": "tool", "tool_call_id": cid, "content": content}], session=session)


def to_model(gw) -> str:
    return json.dumps(gw.upstream.seen)


def to_jev(gw) -> str:
    return json.dumps(gw.judge.calls)


def audit(gw) -> str:
    return gw.app.state.engine.audit.path.read_text()


def decisions(r):
    return [(d["control"], d["action"]) for d in r.json()["acl"]["decisions"]]


def nowhere(gw, *canaries):
    for c in canaries:
        assert c not in to_model(gw), "reached the model"
        assert c not in to_jev(gw), "reached Jev"
        assert c not in audit(gw), "written to the audit log"


def jev_internal_only(gw):
    """Jev's limit below the client file's class (the shipped policy approves Jev for P2, like the model vendor)."""
    gw.edit_policy(lambda p: p["controls"]["injection.jev"].update(max_class="internal"))


def jev_may_see_p2(gw):
    gw.edit_policy(lambda p: p["controls"]["injection.jev"].update(max_class="P2"))


# ---------- the source sets the class ----------

def test_datalake_rows_reach_no_model_and_no_judge(gw):
    r = with_result(gw, "query_datalake", json.dumps({"rows": [{"note": DP30}]}))
    assert r.status_code == 200 and ("classification", "redact") in decisions(r)
    nowhere(gw, DP30)
    assert "Some results are outside your access." in to_model(gw)  # neutral, no count, no names


def test_masking_identifiers_does_not_lower_the_class(gw):
    r = with_result(gw, "query_datalake", json.dumps({"iban": "GB33BUKB20201555555555", "note": DP30}))
    assert ("classification", "redact") in decisions(r)
    nowhere(gw, DP30, "GB33BUKB")


def test_label_inside_the_content_is_ignored(gw):
    with_result(gw, "query_datalake", json.dumps({"classification": "public", "note": DP30}))
    nowhere(gw, DP30)


def test_tool_without_a_class_is_withheld(gw):
    r = with_result(gw, "export_ledger", json.dumps({"note": INTERNAL}))
    assert any(d["control"] == "classification" and "unclassified" in d["reason"] for d in r.json()["acl"]["decisions"])
    nowhere(gw, INTERNAL)


def test_result_relabelled_as_another_tool_is_withheld(gw):
    """The gateway let call_test through for get_customer; the agent then claims it was send_email."""
    gw.upstream.next_reply = {"tool_call": {"name": "get_customer", "arguments": {"customer_id": "7"}}}
    first = gw.chat("alice", [{"role": "user", "content": "Pull the margins."}], session="relabel")
    assert first.json()["choices"][0]["message"]["tool_calls"]
    gw.upstream.next_reply = {"text": "ok"}
    gw.chat("alice", [{"role": "user", "content": "Pull the margins."},
                      {"role": "assistant", "content": None, "tool_calls": [call("call_test", "send_email")]},
                      {"role": "tool", "tool_call_id": "call_test", "content": json.dumps({"note": DP30})}], session="relabel")
    nowhere(gw, DP30)


# ---------- restricted terms: authorised to read is not authorised to send to a model ----------

def test_deal_team_member_cannot_send_the_deal_to_a_model(gw):
    gw.upstream.next_reply = {"text": "ok"}
    r = gw.chat("marcus", [{"role": "user", "content": f"Project Falcon: {DP30}"}])
    assert r.status_code == 200 and ("classification", "redact") in decisions(r)
    nowhere(gw, DP30, "Falcon")


def test_mixed_documents_keep_the_lower_ones(gw):
    docs = [{"title": "Sector note", "text": INTERNAL}, {"title": "Kestrel Dynamics memo", "text": DP30}]
    with_result(gw, "search_documents", json.dumps(docs), user="marcus")
    nowhere(gw, DP30, "Kestrel")
    assert INTERNAL in to_model(gw) and INTERNAL in to_jev(gw)  # the internal note is still used, and still checked


def test_json_escaped_term_is_still_recognised(gw):
    escaped = '[{"title": "\\u004bestrel Dynamics memo", "text": "' + DP30 + '"}]'  # decodes to "Kestrel"
    with_result(gw, "search_documents", escaped, user="marcus")
    nowhere(gw, DP30)


def test_claude_code_path_is_gated_too(gw):
    from test_claude_code import post, user

    gw.upstream.next_reply = {"text": "ok"}
    r = post(gw, [user(f"Project Falcon: {DP30}")])
    assert r.status_code == 200
    nowhere(gw, DP30)


# ---------- Jev's limit below the data: the request stops (never sent unchecked) ----------

def test_p2_is_not_sent_to_jev_and_the_request_stops(gw):
    jev_internal_only(gw)
    r = with_result(gw, "get_client_file", json.dumps({"note": P2}), user="olivia")
    assert ("injection.jev", "block") in decisions(r)
    assert not gw.upstream.seen and not gw.judge.calls  # never checked, so never sent anywhere
    nowhere(gw, P2)
    assert P2 not in r.json()["choices"][0]["message"]["content"]


def test_p2_stops_even_when_jev_is_down(gw):
    jev_internal_only(gw)
    gw.judge.fail = True
    with_result(gw, "get_client_file", json.dumps({"note": P2}), user="olivia")
    assert not gw.upstream.seen and not gw.judge.calls


def test_p2_retry_is_blocked_again(gw):
    jev_internal_only(gw)
    for _ in range(3):
        r = with_result(gw, "get_client_file", json.dumps({"note": P2}), user="olivia")
        assert ("injection.jev", "block") in decisions(r)
    assert not gw.upstream.seen and not gw.judge.calls


def test_permissive_profile_does_not_lift_the_limits(gw):
    jev_internal_only(gw)
    gw.edit_policy(lambda p: p.update(active_profile="permissive"))
    with_result(gw, "get_client_file", json.dumps({"note": P2}), user="olivia", session="p2")
    with_result(gw, "query_datalake", json.dumps({"note": DP30}), session="dp30")
    nowhere(gw, P2, DP30)


def test_raising_jev_limit_to_p2_lets_it_be_checked(gw):
    jev_may_see_p2(gw)
    r = with_result(gw, "get_client_file", json.dumps({"note": P2}), user="olivia")
    assert ("injection.jev", "allow") in decisions(r)
    assert P2 in to_jev(gw) and P2 in to_model(gw)
    assert "P2" in gw.app.state.engine.sessions["c1"].labels  # the flow rule keeps it inside


def test_jev_limit_never_exceeds_max_to_model(gw):
    gw.edit_policy(lambda p: (p["controls"]["injection.jev"].update(max_class="DP30"),
                              p["classification"].update(max_to_model="internal")))
    with_result(gw, "get_client_file", json.dumps({"note": P2}), user="olivia")
    nowhere(gw, P2)


def test_a_model_can_have_a_lower_limit_of_its_own(gw):
    jev_may_see_p2(gw)
    gw.edit_policy(lambda p: p["models"]["mock/compromised"].update(max_class="internal"))
    r = with_result(gw, "get_client_file", json.dumps({"note": P2}), user="olivia")
    assert ("classification", "redact") in decisions(r)
    nowhere(gw, P2)


def test_lowering_the_limit_applies_to_earlier_messages(gw):
    jev_may_see_p2(gw)
    with_result(gw, "get_client_file", json.dumps({"note": P2}), user="olivia", session="live")
    assert P2 in to_model(gw)
    gw.edit_policy(lambda p: p["classification"].update(max_to_model="internal"))
    gw.upstream.seen.clear()
    gw.judge.calls.clear()
    gw.chat("olivia", [{"role": "user", "content": "Summarise it."},
                       {"role": "assistant", "content": None, "tool_calls": [call("c1", "get_client_file")]},
                       {"role": "tool", "tool_call_id": "c1", "content": json.dumps({"note": P2})},
                       {"role": "user", "content": "And again."}], session="live")
    assert P2 not in to_model(gw) and P2 not in to_jev(gw)


# ---------- the allowed path, and fail-closed policy edits ----------

def test_internal_requests_are_still_checked_by_jev(gw):
    gw.upstream.next_reply = {"text": "ok"}
    r = gw.chat("alice", [{"role": "user", "content": INTERNAL}])
    assert ("injection.jev", "allow") in decisions(r)
    assert INTERNAL in to_jev(gw) and INTERNAL in to_model(gw)


def test_missing_classification_section_fails_closed(gw):
    gw.edit_policy(lambda p: p.pop("classification"))
    gw.upstream.next_reply = {"text": "ok"}
    gw.chat("alice", [{"role": "user", "content": INTERNAL}])
    assert INTERNAL not in to_model(gw) and INTERNAL not in to_jev(gw)


def test_missing_jev_limit_fails_closed(gw):
    gw.edit_policy(lambda p: p["controls"]["injection.jev"].pop("max_class"))
    gw.upstream.next_reply = {"text": "ok"}
    r = gw.chat("alice", [{"role": "user", "content": INTERNAL}])
    assert ("injection.jev", "block") in decisions(r)
    assert not gw.upstream.seen and not gw.judge.calls


def test_misspelt_class_keeps_the_last_good_policy(gw):
    gw.edit_policy(lambda p: p["classification"].update(max_to_model="DP3O"))
    with_result(gw, "query_datalake", json.dumps({"note": DP30}))
    nowhere(gw, DP30)
    assert "DP3O" in gw.app.state.engine.metrics()["policy_error"]


def test_class_denials_are_counted_with_their_latency(gw):
    with_result(gw, "query_datalake", json.dumps({"note": DP30}))
    m = gw.app.state.engine.metrics()
    assert m["by_control"]["classification"]["redact"] >= 1
    assert "classification" in m["latency_ms"]["per_control_avg"]


# ---------- the real Jev client: what goes over HTTP, retries included ----------

def test_real_jev_http_payloads_never_carry_restricted_data(gw, tmp_path):
    from main import create_app

    sent: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(request.content.decode())
        if len(sent) % 2:  # every first attempt is rate limited, so each check also goes through the retry
            return httpx.Response(429)
        return httpx.Response(200, json={"model": "jev-test", "answers": {"injection": {"noul": 0.02}}})

    jev = JevJudge(api_key="test-key")
    jev._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    client = TestClient(create_app(gw.policy_path, tmp_path / "jev-audit.jsonl", jev, gw.upstream))
    gw.client = client
    jev_internal_only(gw)
    docs = [{"title": "Sector note", "text": INTERNAL}, {"title": "Kestrel Dynamics memo", "text": DP30}]
    with_result(gw, "search_documents", json.dumps(docs), user="marcus", session="h1")
    with_result(gw, "get_client_file", json.dumps({"note": P2}), user="olivia", session="h2")
    with_result(gw, "query_datalake", json.dumps({"note": DP30}), session="h3")
    wire = "\n".join(sent)
    assert len(sent) >= 4 and INTERNAL in wire  # the allowed note was checked, through a 429 retry
    assert DP30 not in wire and P2 not in wire and "Kestrel" not in wire
    assert DP30 not in to_model(gw) and P2 not in to_model(gw)
