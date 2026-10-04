"""The data lake (first demo): named queries over synthetic datasets, refused before they run when the role may not
run them or their result could not be sent on, labels verified before release, and lower-class views only through a
declared transformation. Every test looks at what actually reached the model and Jev."""

import json
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "demo"))
import datalake

NEUTRAL = "this query is not available; it never ran"


def ask_query(gw, user, query, session="dl"):
    """The model asks for `query`. Returns (the tool calls that reached the agent, the decisions)."""
    gw.upstream.next_reply = {"tool_call": {"name": "query_datalake", "arguments": {"query": query}}}
    r = gw.chat(user, [{"role": "user", "content": "Use the data lake."}], session=session).json()
    return r["choices"][0]["message"].get("tool_calls") or [], r["acl"]["decisions"]


def send_result(gw, user, query, result, session="dl", claimed_query=None):
    """The agent ran the call the gateway let through (id call_test) and sends the result back."""
    gw.upstream.next_reply = {"text": "ok"}
    args = json.dumps({"query": claimed_query or query})
    r = gw.chat(user, [{"role": "user", "content": "Use the data lake."},
                       {"role": "assistant", "content": None, "tool_calls": [
                           {"id": "call_test", "type": "function", "function": {"name": "query_datalake", "arguments": args}}]},
                       {"role": "tool", "tool_call_id": "call_test", "content": result}], session=session)
    return r.json()["acl"]["decisions"]


def run(gw, user, query, session="dl"):
    calls, _ = ask_query(gw, user, query, session)
    assert calls, f"{query} was refused"
    cat = yaml.safe_load(gw.policy_path.read_text())["datalake"]
    return send_result(gw, user, query, datalake.run_query(query, cat), session)


def refused(decisions):
    return [d for d in decisions if d["control"] == "access.datalake" and d["action"] == "block"]


def seen(gw) -> str:
    return json.dumps(gw.upstream.seen) + json.dumps(gw.judge.calls)


# ---------- refused before the query runs, always with the same neutral reason ----------

def test_unknown_query_never_runs(gw):
    calls, ds = ask_query(gw, "olivia", "select_everything")
    assert not calls and refused(ds)


def test_role_without_the_query_never_runs_it(gw):
    calls, ds = ask_query(gw, "olivia", "deal_pipeline")  # public side: not even the derived view
    assert not calls and refused(ds)
    calls, ds = ask_query(gw, "olivia", "pipeline_by_sector", session="dl2")
    assert not calls and refused(ds)


def test_result_above_the_model_limit_is_never_fetched(gw):
    calls, ds = ask_query(gw, "marcus", "deal_pipeline")  # the deal team may read it, no model may receive it
    assert not calls and refused(ds)


def test_p2_result_is_not_fetched_while_jev_cannot_check_it(gw):
    calls, ds = ask_query(gw, "olivia", "client_positions")
    assert not calls and refused(ds)


def test_every_refusal_reads_the_same(gw):
    reasons = set()
    for i, (user, q) in enumerate([("olivia", "nope"), ("olivia", "deal_pipeline"), ("marcus", "deal_pipeline"),
                                   ("olivia", "client_positions")]):
        _, ds = ask_query(gw, user, q, session=f"r{i}")
        reasons |= {d["reason"] for d in refused(ds)}
    assert reasons == {NEUTRAL}  # no hint which datasets exist, what class they are, or who may see them


# ---------- allowed queries, and the label check ----------

def test_public_query_reaches_the_model_and_is_checked(gw):
    run(gw, "olivia", "fx_rates")
    assert "EUR/PLN" in json.dumps(gw.upstream.seen) and "EUR/PLN" in json.dumps(gw.judge.calls)


def test_p2_query_once_jev_may_check_p2(gw):
    gw.edit_policy(lambda p: p["controls"]["injection.jev"].update(max_class="P2"))
    run(gw, "olivia", "client_positions")
    assert "Bund futures" in json.dumps(gw.upstream.seen)
    assert "P2" in gw.app.state.engine.sessions["dl"].labels


def test_derived_view_gives_counts_not_deals(gw):
    run(gw, "marcus", "pipeline_by_sector")
    out = seen(gw)
    assert '\\"industrial technology\\", \\"count\\": 3' in out
    for name in ("Osprey", "Heron", "Merlin", "Kite", "Harrier", "Lanner", "healthcare", "energy", "fee_estimate"):
        assert name not in out  # no deal, and no group small enough to point at one


def test_label_that_disagrees_with_the_catalog_is_withheld(gw):
    calls, _ = ask_query(gw, "olivia", "fx_rates")
    assert calls
    ds = send_result(gw, "olivia", "fx_rates", json.dumps({"query": "fx_rates", "class": "DP30", "rows": [{"pair": "XAU/USD"}]}))
    assert any(d["control"] == "classification" for d in ds)
    assert "XAU/USD" not in seen(gw)


def test_missing_label_is_withheld(gw):
    ask_query(gw, "olivia", "fx_rates")
    send_result(gw, "olivia", "fx_rates", json.dumps({"rows": [{"pair": "XAU/USD"}]}))
    assert "XAU/USD" not in seen(gw)


def test_agent_cannot_swap_the_query_in_history(gw):
    """The gateway let fx_rates (public) through. The agent sends deal rows and claims it ran deal_pipeline."""
    ask_query(gw, "marcus", "fx_rates")
    rows = datalake.run_query("deal_pipeline", yaml.safe_load(gw.policy_path.read_text())["datalake"])
    send_result(gw, "marcus", "fx_rates", rows, claimed_query="deal_pipeline")
    assert "Osprey" not in seen(gw)


# ---------- the catalog is policy: live edits and typos ----------

def test_granting_a_query_takes_effect_live(gw):
    assert not ask_query(gw, "olivia", "pipeline_by_sector")[0]
    gw.edit_policy(lambda p: p["datalake"]["queries"]["pipeline_by_sector"]["roles"].append("onboarding_analyst"))
    assert ask_query(gw, "olivia", "pipeline_by_sector", session="dl2")[0]


def test_query_on_an_unknown_dataset_keeps_the_last_good_policy(gw):
    gw.edit_policy(lambda p: p["datalake"]["queries"].update(leak={"dataset": "everything", "roles": ["onboarding_analyst"]}))
    assert "leak" in gw.app.state.engine.metrics()["policy_error"]
    assert not ask_query(gw, "olivia", "leak")[0]


def test_transformation_suppresses_small_groups():
    rows = json.loads(datalake.run_query("pipeline_by_sector"))
    assert rows["class"] == "internal" and rows["rows"] == [{"sector": "industrial technology", "count": 3}]
