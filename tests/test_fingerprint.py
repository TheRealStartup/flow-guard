"""Registered confidential documents and secrets leaving through an agent, also in pieces (EXPERIMENTAL feature).

The memo below is invented for the test. The gateway stores only keyed fingerprints of it; the tests check that an
outgoing call carrying parts of it is recorded, that the parts add up per person and day, that the call crossing the
threshold is blocked, and that the leaked text never reaches the audit log.
"""

import json
import random

import pytest

from acl.detectors.fingerprint import build_registry, normalise, winnow

MEMO = (
    "Project Heron board memo. The acquisition committee recommends an offer of 41.30 per share for Larkspur "
    "Biologics, a premium of 38 percent over the thirty day average. Financing comes from a new term loan of 2.4 "
    "billion arranged with two relationship banks, and the remainder from cash on hand. The target's founder holds "
    "nineteen percent and has agreed in principle to roll over half of her stake. Antitrust counsel sees a second "
    "request as unlikely because the overlap in rare disease pipelines is limited to one phase two asset. The "
    "announcement is planned for the Monday after the quarterly results, before the European open. Until then the "
    "deal team must not discuss pricing with anyone outside the wall, and the data room stays restricted to eleven "
    "named people. Fallback: if the founder declines, the committee will consider a tender offer at 43 per share."
)
BOILERPLATE = ("This document is confidential and intended solely for the use of the addressee. If you received it in "
               "error, please notify the sender immediately and delete it.")
OTHER = "Quarterly staff newsletter. The canteen reopens on the second floor. " + BOILERPLATE
SECRET = "settle-prod-7f3K9qLm2VxR8tWz4NbC"
KEY = b"test-fingerprint-key"


@pytest.fixture
def leakgw(gw, monkeypatch):
    monkeypatch.setenv("FLOWGUARD_FP_KEY", KEY.decode())
    reg = build_registry([{"id": "heron-memo", "title": "Project Heron board memo", "class": "DP30", "text": MEMO + " " + BOILERPLATE},
                          {"id": "newsletter", "title": "Staff newsletter", "class": "internal", "text": OTHER}],
                         [{"id": "settlement-key", "title": "Settlement API key", "value": SECRET}], KEY)
    (gw.dir / "protected.json").write_text(json.dumps(reg))
    gw.app.state.engine.fp_key = KEY
    return gw


def email(gw, body, session="leak", user="olivia"):
    gw.upstream.next_reply = {"tool_call": {"name": "send_email", "arguments": {"to": "someone@outside.example", "body": body}}}
    acl = gw.chat(user, [{"role": "user", "content": "send the update"}], session=session,
                  tools=[{"type": "function", "function": {"name": "send_email", "parameters": {"type": "object"}}}]).json()["acl"]
    return [d for d in acl["decisions"] if d["control"] == "leak.fingerprint"]


def pieces(text, n):
    words = text.split()
    size = len(words) // n + 1
    return [" ".join(words[i : i + size]) for i in range(0, len(words), size)]


def test_registry_holds_fingerprints_not_text():
    reg = json.dumps(build_registry([{"id": "m", "text": MEMO}], [{"id": "s", "value": SECRET}], KEY))
    assert "Larkspur" not in reg and "41.30" not in reg and SECRET not in reg and normalise(SECRET) not in reg


def test_boilerplate_shared_by_documents_is_ignored():
    reg = build_registry([{"id": "a", "text": MEMO + " " + BOILERPLATE}, {"id": "b", "text": OTHER}], [], KEY)
    shared = winnow(BOILERPLATE, KEY)
    assert not (set(reg["documents"][0]["fingerprints"]) & shared)


def test_a_whole_memo_in_one_email_is_blocked(leakgw):
    ds = email(leakgw, MEMO)
    assert ds and ds[0]["action"] == "block" and "Project Heron board memo" in ds[0]["reason"]


def test_small_pieces_add_up_until_the_threshold_blocks(leakgw):
    """Atomization: each piece alone is small and let through (recorded); together they cross 25% and are stopped."""
    actions = []
    for part in pieces(MEMO, 8):
        ds = email(leakgw, f"Hi, quick note: {part} Thanks!")
        actions.append(ds[0]["action"] if ds else "none")
    assert actions[0] == "flag" and "block" in actions
    first_block = actions.index("block")
    assert first_block >= 1 and all(a == "flag" for a in actions[:first_block])


def test_reordered_reformatted_pieces_still_match(leakgw):
    parts = pieces(MEMO, 4)
    random.Random(7).shuffle(parts)
    mangled = "\n\n".join(p.upper().replace(" ", "  ").replace(".", " ;") for p in parts)
    assert email(leakgw, mangled)[0]["action"] == "block"


def test_counted_per_person(leakgw):
    """Olivia's leaked pieces do not count against Marcus: his first piece is a small, recorded share again."""
    for part in pieces(MEMO, 8):
        if email(leakgw, part, session="o", user="olivia")[0]["action"] == "block":
            break
    assert email(leakgw, pieces(MEMO, 8)[0], session="m", user="marcus")[0]["action"] == "flag"


def test_harmless_text_and_boilerplate_do_not_match(leakgw):
    assert email(leakgw, "Please find the agenda for Monday's team meeting attached. " + BOILERPLATE) == []


def test_a_secret_split_over_three_calls_is_blocked_on_the_last(leakgw):
    """A third of the key at a time: recorded, recorded, then blocked once enough of it to rebuild half has left."""
    third = len(SECRET) // 3 + 1
    parts = [SECRET[i : i + third] for i in range(0, len(SECRET), third)]
    actions = [(email(leakgw, f"note {i}: {p}") or [{"action": "none"}])[0]["action"] for i, p in enumerate(parts)]
    assert actions[:2] == ["flag", "flag"] and actions[2] == "block"


def test_a_whole_secret_is_blocked_at_once(leakgw):
    assert email(leakgw, f"the key is {SECRET}")[0]["action"] == "block"


def test_leaked_text_never_reaches_the_audit_log(leakgw):
    email(leakgw, MEMO)
    email(leakgw, "card 4111 1111 1111 1111 " + MEMO)  # a second control (data flow) fires on the same call
    log = leakgw.app.state.engine.audit.path.read_text()
    assert "Larkspur" not in log and "41.30" not in log
    assert "[protected content: not logged]" in log


def test_exposure_survives_a_restart(leakgw):
    from fastapi.testclient import TestClient
    from main import create_app

    for part in pieces(MEMO, 8)[:2]:
        email(leakgw, part)
    before = leakgw.app.state.engine.exposure.copy()
    leakgw.app = create_app(leakgw.policy_path, leakgw.app.state.engine.audit.path, leakgw.judge, leakgw.upstream)
    leakgw.app.state.engine.fp_key = KEY
    leakgw.client = TestClient(leakgw.app)
    assert leakgw.app.state.engine.exposure == before
