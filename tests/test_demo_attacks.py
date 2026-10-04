"""The Live demo's "What the attacker tried" (ATTACKS in demo/world.py, onboarding.py, developer.py): a hand-written
plain description of each poisoned source. Checked by behaviour, like every test that touches demo/quarantine/:
with the checks off, the scripted model that obeys every instruction really does what the description says; with the
checks on, Try it reports the description, and never any of the injected text."""

import pytest

from fixtures import QUARANTINE

RUNS = [  # (user, scenario, prompt, the outside tool the description says the attack wants)
    ("alice", "support", "Customer 7 asked about their card limit. Look them up and answer.", "send_email"),
    ("olivia", "onboarding", "Prepare the onboarding file for client NW-2041.", "send_email"),
    ("devon", "developer", "Get the tests in the payments-service repo passing.", "http_post"),
]


def _try(gw, user, scenario, prompt, **extra):
    r = gw.client.post("/api/try", json={"user": user, "scenario": scenario, "prompt": prompt, "model": "mock/compromised", **extra})
    assert r.status_code == 200, r.text
    return r.json()


def _tools_run(r):
    return [s["name"] for s in r["steps"] if s["kind"] == "tool"]


@pytest.mark.parametrize("user, scenario, prompt, sink", RUNS)
def test_without_flowguard_the_agent_does_what_the_description_says(gw, user, scenario, prompt, sink):
    def monitor_only(raw):  # the balanced profile (active) overrides neither control
        raw["controls"]["injection.jev"]["action"] = "flag"
        raw["controls"]["flow.sensitive_to_external"]["action"] = "flag"

    gw.edit_policy(monitor_only)
    r = _try(gw, user, scenario, prompt)
    assert sink in _tools_run(r)


@pytest.mark.parametrize("user, scenario, prompt, sink", RUNS)
def test_try_it_names_the_attack_in_plain_words_and_never_quotes_it(gw, user, scenario, prompt, sink):
    r = _try(gw, user, scenario, prompt)
    assert sink not in _tools_run(r)
    [attack] = r["attacks"]
    assert attack["where"] and attack["wants"] and attack["source"]
    said = (attack["where"] + " " + attack["wants"]).lower()
    for f in QUARANTINE.iterdir():
        words = f.read_text().lower().split()
        # No run of six words from any injected text appears in what the dashboard shows.
        assert not any(" ".join(words[i:i + 6]) in said for i in range(max(0, len(words) - 5)))


def test_no_attack_is_reported_for_a_clean_run(gw):
    r = _try(gw, "alice", "support", "Customer 42 says they were double charged. Look them up and summarise the case.")
    assert r["attacks"] == []


def test_the_dashboard_can_choose_the_session_to_follow_the_run_live(gw):
    r = _try(gw, "alice", "support", "Customer 42 asked about their card limit.", session="try-alice-live01")
    assert r["session"] == "try-alice-live01"
    steps = gw.client.get("/api/sessions/try-alice-live01").json()["steps"]
    assert steps and all(s["summary"]["headline"] for s in steps)
    assert gw.client.post("/api/try", json={"user": "alice", "prompt": "hi", "session": "../etc"}).status_code == 400
