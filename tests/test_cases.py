"""Runs every case in tests/cases/*.yaml through the real gateway (HTTP), with a fake Jev and a scripted model."""

import json
import re
from pathlib import Path

import pytest
import yaml

CASES = [c for f in sorted((Path(__file__).parent / "cases").glob("*.yaml")) for c in yaml.safe_load(f.read_text())]
TOKEN_OF = re.compile(r"TOKEN_OF:(\d+)")


@pytest.mark.parametrize("case", CASES, ids=[c["name"] for c in CASES])
def test_case(gw, case):
    if "profile" in case:
        gw.edit_policy(lambda p: p.__setitem__("active_profile", case["profile"]))

    messages = [{"role": "system", "content": "You are a bank support assistant."},
                {"role": "user", "content": case["prompt"]}]
    if "tool_result" in case:
        messages += [
            {"role": "assistant", "content": None, "tool_calls": [
                {"id": "c0", "type": "function", "function": {"name": "get_customer", "arguments": '{"customer_id": 42}'}}]},
            {"role": "tool", "tool_call_id": "c0", "content": case["tool_result"]},
        ]

    reply = case.get("reply", {"text": "ok"})
    if "tool_call" in reply:  # "TOKEN_OF:<digits>" -> the token this session uses for that card
        session = lambda: gw.app.state.engine.session("s1", case["user"])  # noqa: E731
        args = json.dumps(reply["tool_call"]["arguments"])
        resolved = TOKEN_OF.sub(lambda m: session().tokenize("CARD", m.group(1)), args) if TOKEN_OF.search(args) else None
        reply = {"tool_call": {**reply["tool_call"], "arguments": json.loads(resolved) if resolved else reply["tool_call"]["arguments"]}}
    gw.upstream.next_reply = reply

    r = gw.chat(case["user"], messages, model=case.get("model", "mock/compromised"))
    assert r.status_code == 200, r.text
    body = r.json()
    acl, exp = body["acl"], case["expect"]
    got = [(d["control"], d["action"]) for d in acl["decisions"]]

    if "outcome" in exp:
        assert acl["outcome"] == exp["outcome"], f"decisions: {got}"
    if "decisions" in exp:
        if exp["decisions"] == []:
            assert [g for g in got if g[1] != "allow"] == [], got
        for d in exp["decisions"]:
            assert (d["control"], d["action"]) in got, f"missing {d}; got {got}"
    if "model_never_sees" in exp:
        sent = json.dumps(gw.upstream.seen)
        for s in exp["model_never_sees"]:
            assert s not in sent, f"{s!r} reached the model"
    msg = body["choices"][0]["message"]
    if "tool_call_kept" in exp:
        assert bool(msg.get("tool_calls")) == exp["tool_call_kept"], msg
    if "tool_args_contain" in exp:
        assert exp["tool_args_contain"] in msg["tool_calls"][0]["function"]["arguments"]
