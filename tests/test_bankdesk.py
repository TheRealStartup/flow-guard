"""The onboarding desk: the bank's systems as MCP servers (demo/bankdesk.py) and the policy path through the gateway.

Claude Code calls MCP tools as `mcp__<server>__<tool>`. The gateway must treat them like any other tool: the case file
is P2 (may reach the model, as tokens), real identifiers go back only to the screening system, mail is an external
sink, and an analyst only opens her own cases.
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SERVER = ROOT / "demo" / "bankdesk.py"
sys.path.insert(0, str(ROOT / "demo"))
import bankdesk  # noqa: E402
import onboarding  # noqa: E402

ELENA = onboarding.CLIENTS["NW-2041"]["principals"][0]


def mcp(system: str, *messages: dict) -> list[dict]:
    """Talk to one bank system over stdio, as Claude Code does."""
    lines = "".join(json.dumps(m) + "\n" for m in messages)
    out = subprocess.run([sys.executable, str(SERVER), system], input=lines, capture_output=True, text=True, timeout=30)
    return [json.loads(x) for x in out.stdout.splitlines() if x.strip()]


@pytest.mark.parametrize("system", ["hub", "screening", "lei", "mail"])
def test_each_system_speaks_mcp_with_a_title_and_an_icon(system):
    init, tools = mcp(system,
                      {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}},
                      {"jsonrpc": "2.0", "method": "notifications/initialized"},
                      {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    info = init["result"]
    assert info["protocolVersion"] == "2025-06-18" and info["serverInfo"]["title"]
    assert info["serverInfo"]["icons"][0]["src"].startswith("data:image/svg+xml;base64,")
    assert "Fictional" in info["serverInfo"]["description"]
    assert tools["result"]["tools"] and all("inputSchema" in t for t in tools["result"]["tools"])


def test_there_is_no_approve_tool():
    names = {n for s in bankdesk.SYSTEMS.values() for n, *_ in s["tools"]}
    assert not any("approve" in n and "submit" not in n for n in names)
    assert bankdesk.hub_submit_for_approval("NW-2041", "draft")["status"] == "PENDING_APPROVAL"


def test_unknown_method_and_bad_arguments_do_not_crash_the_server():
    bad, wrong = mcp("hub", {"jsonrpc": "2.0", "id": 1, "method": "resources/list"},
                     {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "get_case", "arguments": {}}})
    assert bad["error"]["code"] == -32601 and wrong["result"]["isError"] is True


def test_screening_near_match_is_decided_by_the_identifiers():
    r = bankdesk.screening_screen_party("Elena Marsh", "INDIVIDUAL", ELENA["date_of_birth"], "GB", passport=ELENA["passport"])
    assert r["status"] == "POSSIBLE_MATCH"
    fields = {f["field"]: f["result"] for f in r["results"][0]["secondaryFieldResults"]}
    assert fields == {"date of birth": "NOT_MATCHED", "nationality": "MATCHED", "passport": "NOT_MATCHED"}
    assert ELENA["date_of_birth"] not in json.dumps(r) and ELENA["passport"] not in json.dumps(r)  # not echoed to the model


def test_screening_refuses_tokens_and_individuals_without_date_of_birth():
    assert bankdesk.screening_screen_party("Tomasz Wilk", "INDIVIDUAL", "[[DOB#abc123]]", "PL")["status"] == "REJECTED"
    assert bankdesk.screening_screen_party("Tomasz Wilk", "INDIVIDUAL", "", "PL")["status"] == "REJECTED"
    assert bankdesk.screening_screen_party("Northwind Capital GP Ltd", "ORGANISATION", registered_country="KY")["status"] == "NO_MATCH"


def test_only_a_false_positive_can_be_proposed_by_the_agent():
    assert bankdesk.screening_resolve_result("S", "R1", "FALSE_POSITIVE", "dob differs")["status"] == "PROPOSED_FALSE_POSITIVE"
    assert bankdesk.screening_resolve_result("S", "R1", "POSITIVE", "same person")["status"] == "ESCALATED"


# ---------- through the gateway ----------

def tool_result(name, call_id, content):
    return [{"role": "assistant", "content": None, "tool_calls": [{"id": call_id, "type": "function",
             "function": {"name": name, "arguments": json.dumps({"document_id": "DOC-1109"})}}]},
            {"role": "tool", "tool_call_id": call_id, "content": content}]


def desk(gw, messages, next_call=None):
    gw.upstream.next_reply = {"tool_call": next_call} if next_call else {"text": "ok"}
    return gw.chat("olivia", messages, model="deepseek/deepseek-v4.1-flash")


def test_identity_document_reaches_the_model_only_as_tokens(gw):
    doc = json.dumps(bankdesk.hub_get_document("DOC-1109"))
    desk(gw, [{"role": "user", "content": "Prepare the KYC memo."}, *tool_result("mcp__hub__get_document", "c1", doc)])
    seen = json.dumps(gw.upstream.seen)
    assert "[[PASSPORT#" in seen and "[[DOB#" in seen
    for p in onboarding.CLIENTS["NW-2041"]["principals"]:
        assert p["passport"] not in seen and p["date_of_birth"] not in seen


def test_screening_gets_the_real_identifiers_and_mail_does_not(gw):
    doc = json.dumps(bankdesk.hub_get_document("DOC-1109"))
    msgs = [{"role": "user", "content": "Prepare the KYC memo."}, *tool_result("mcp__hub__get_document", "c1", doc)]
    desk(gw, msgs)
    seen = json.dumps(gw.upstream.seen[-1])
    dob = seen.split("[[DOB#")[1].split("]]")[0]
    passport = seen.split("[[PASSPORT#")[1].split("]]")[0]
    screen = {"name": "mcp__screening__screen_party", "arguments": {
        "name": "Elena Marsh", "party_type": "INDIVIDUAL", "date_of_birth": f"[[DOB#{dob}]]", "nationality": "GB",
        "passport": f"[[PASSPORT#{passport}]]"}}
    r = desk(gw, msgs, screen).json()
    call = r["choices"][0]["message"]["tool_calls"][0]
    assert ELENA["date_of_birth"] in call["function"]["arguments"] and ELENA["passport"] in call["function"]["arguments"]
    mail = {"name": "mcp__mail__send_email", "arguments": {"to": "ops@northwind.example", "subject": "ID",
                                                           "body": f"Passport [[PASSPORT#{passport}]]"}}
    r = desk(gw, msgs, mail).json()
    decisions = [(d["control"], d["action"]) for d in r["acl"]["decisions"]]
    assert ("flow.sensitive_to_external", "block") in decisions and not r["choices"][0]["message"].get("tool_calls")


def test_an_analyst_opens_only_her_own_cases(gw):
    r = desk(gw, [{"role": "user", "content": "Open case AC-7730."}],
             {"name": "mcp__hub__get_case", "arguments": {"case_id": "AC-7730"}}).json()
    assert ("access.scope", "block") in [(d["control"], d["action"]) for d in r["acl"]["decisions"]]
