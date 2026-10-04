"""HR purposes stay out of reporting (docs/decisions.md D8): a role with `redact_purpose: true` (hr_admin) has its
X-Purpose checked in memory but never written to the audit log, events, export or the session API, allowed or blocked,
with access.purpose on or off. Early identity denials never echo the caller's purpose. Other roles keep theirs."""

import sys
from pathlib import Path

import pytest
from conftest import DEV_KEYS

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "demo"))
import hr
from acl.policy import PURPOSE_WITHHELD

CANARY = "HR-PRIVATE-SALARY-HEALTH-CANARY"


def chat(gw, purpose, session="hr-rep", user="hana", content="What is the parental leave policy?", **headers):
    return gw.chat(user, [{"role": "user", "content": content}], session=session,
                   headers={"X-Purpose": purpose, **headers}, tools=hr.TOOLS)


def reports(gw, session):
    """Everything a reader of the gateway's reports can see."""
    return "\n".join([
        gw.app.state.engine.audit.path.read_text(encoding="utf-8"),
        gw.client.get("/api/events?limit=1000").text,
        gw.client.get("/api/audit/export").text,
        gw.client.get("/api/sessions").text,
        gw.client.get(f"/api/sessions/{session}").text,
    ])


def last_exchange(gw):
    return gw.client.get("/api/events?type=exchange&limit=1").json()[0]


def test_blocked_hr_purpose_is_not_reported_but_still_enforced(gw):
    r = chat(gw, f"termination {CANARY}")
    assert r.json()["acl"]["outcome"] == "blocked"
    assert [d["control"] for d in r.json()["acl"]["decisions"]] == ["access.purpose"]  # the raw purpose was checked
    assert CANARY not in reports(gw, "hr-rep")
    assert last_exchange(gw)["purpose"] == PURPOSE_WITHHELD
    assert gw.client.get("/api/sessions/hr-rep").json()["purpose"] == PURPOSE_WITHHELD


def test_allowed_hr_purpose_is_not_reported_and_raw_stays_in_memory(gw):
    gw.upstream.next_reply = {"text": "ok"}
    r = chat(gw, f"leave questions {CANARY}")
    assert r.status_code == 200 and r.json()["acl"]["outcome"] != "blocked"
    assert CANARY not in reports(gw, "hr-rep")
    assert last_exchange(gw)["purpose"] == PURPOSE_WITHHELD
    assert gw.app.state.engine.sessions["hr-rep"].purpose == f"leave questions {CANARY}"


def test_each_request_is_rechecked_against_its_raw_purpose(gw):
    gw.upstream.next_reply = {"text": "ok"}
    assert chat(gw, "leave questions").json()["acl"]["outcome"] != "blocked"
    r = chat(gw, f"performance_review {CANARY}")
    assert [(d["control"], d["action"]) for d in r.json()["acl"]["decisions"]] == [("access.purpose", "block")]
    assert CANARY not in reports(gw, "hr-rep")


def test_hr_purpose_is_withheld_when_access_purpose_is_off(gw):
    gw.edit_policy(lambda p: p["controls"]["access.purpose"].update(action="allow"))
    gw.upstream.next_reply = {"text": "ok"}
    r = chat(gw, f"termination {CANARY}")
    assert "access.purpose" not in [d["control"] for d in r.json()["acl"]["decisions"]]
    assert CANARY not in reports(gw, "hr-rep")
    assert last_exchange(gw)["purpose"] == PURPOSE_WITHHELD


@pytest.mark.parametrize("who", [
    {"user": "hana", "X-User": "bob"},                                        # known HR key claiming someone else
    {"user": "nobody", "Authorization": "Bearer acl_guessed", "X-User": "hana"},  # unknown key
    {"user": "nobody", "Authorization": "Bearer acl_guessed"},                # no identity at all
])
def test_early_identity_denials_do_not_echo_the_purpose(gw, who):
    who = dict(who)
    user = who.pop("user")
    r = chat(gw, f"termination {CANARY}", user=user, **who)
    assert r.status_code in (401, 403)
    assert CANARY not in reports(gw, "hr-rep")
    assert last_exchange(gw)["purpose"] == PURPOSE_WITHHELD


def test_anthropic_adapter_withholds_the_hr_purpose(gw):
    h = {"Authorization": f"Bearer {DEV_KEYS['hana']}", "X-Purpose": f"ranking {CANARY}", "X-Session": "hr-rep",
         "anthropic-version": "2023-06-01"}
    r = gw.client.post("/v1/messages", headers=h, json={"model": "mock/compromised", "max_tokens": 64,
                                                        "messages": [{"role": "user", "content": "Help."}]})
    assert r.status_code == 200
    assert last_exchange(gw)["outcome"] == "blocked"
    assert CANARY not in reports(gw, "hr-rep")


@pytest.mark.parametrize("bad", ["yes", "false", 1, None, ["true"]])
def test_malformed_redact_purpose_keeps_the_last_good_policy(gw, bad):
    gw.edit_policy(lambda p: p["roles"]["hr_admin"].update(redact_purpose=bad))
    gw.upstream.next_reply = {"text": "ok"}
    chat(gw, f"leave questions {CANARY}")
    assert "redact_purpose" in gw.app.state.engine.metrics()["policy_error"]
    assert CANARY not in reports(gw, "hr-rep")


def test_flag_can_be_turned_off_live(gw):
    gw.edit_policy(lambda p: p["roles"]["hr_admin"].update(redact_purpose=False))
    gw.upstream.next_reply = {"text": "ok"}
    chat(gw, "leave questions")
    assert last_exchange(gw)["purpose"] == "leave questions"


def test_non_hr_purpose_is_still_recorded(gw):
    gw.upstream.next_reply = {"text": "ok"}
    r = gw.chat("alice", [{"role": "user", "content": "hi"}], session="sup", headers={"X-Purpose": "refund case 1234"})
    assert r.status_code == 200
    assert last_exchange(gw)["purpose"] == "refund case 1234"
    assert gw.client.get("/api/sessions/sup").json()["purpose"] == "refund case 1234"
    assert "refund case 1234" in gw.client.get("/api/audit/export").text
