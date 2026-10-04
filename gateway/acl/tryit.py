""""Try it": run the demo agent server-side for the dashboard, so a judge can type a prompt and watch
every control fire. It is a client like any other: it calls the gateway's own /v1/chat/completions
with the chosen demo user's API key, so identity and every control apply. Nothing is bypassed.
"""

import importlib
import json
import re
import sys
import uuid
from pathlib import Path
from typing import Any

import httpx

from .engine import safe_excerpt

DEMO = Path(__file__).resolve().parents[2] / "demo"


def dev_keys() -> dict[str, str]:
    path = DEMO / "dev-keys.env"
    if not path.exists():
        return {}
    return {line.split("=", 1)[0].removeprefix("ACL_KEY_").lower(): line.split("=", 1)[1].strip()
            for line in path.read_text().splitlines() if line.startswith("ACL_KEY_")}


SESSION_RE = re.compile(r"^try-[a-z0-9-]{4,48}$")  # a session id the dashboard may choose, to follow the run live
SCENARIOS = {"support": "world", "onboarding": "onboarding", "developer": "developer", "hr": "hr"}  # name -> module in demo/


def _world(scenario: str):
    if str(DEMO) not in sys.path:
        sys.path.insert(0, str(DEMO))
    return importlib.import_module(SCENARIOS[scenario])  # demo code, loaded only when Try it is used


def _preview(app, tool: str, result: str) -> str:
    """A masked preview, and none at all for a tool whose class is above the default (P2/DP30, or no class): the
    dashboard must not show what the model may not see. Fails closed: a tool with no class or one that is not a level,
    or a default that is missing or not a level, withholds the preview (unknown names are never echoed)."""
    p = app.state.engine.policies.get()
    cls, default = p.tool_class(tool), p.classification.get("default")
    if cls not in p.levels or default not in p.levels or p.rank(cls) > p.rank(default):
        return f"[WITHHELD from preview: {cls if cls in p.levels else 'unclassified'} result]"
    return safe_excerpt(result, width=300)


def _attacks(world, calls: list[tuple[str, dict[str, Any]]], caught: bool) -> list[dict[str, str]]:
    """What the run's poisoned sources wanted, in the scenario's own hand-written words (never the injected text).
    Only when the run caught an attack, and only for poisoned sources the agent actually read."""
    if not caught:
        return []
    out = []
    for a in getattr(world, "ATTACKS", []):
        if any(name == a["tool"] and a["arg"] in [str(v) for v in args.values()] + list(args.values()) for name, args in calls):
            out.append({"where": a["where"], "source": f"{a['tool']} {a['arg']}", "wants": a["wants"]})
    return out


async def run(app, user: str, prompt: str, model: str, scenario: str = "support", max_steps: int = 6,
              purpose: str = "dashboard try-it", session: str | None = None) -> dict[str, Any]:
    world = _world(scenario)
    key = dev_keys().get(user, "")
    sid = session if session and SESSION_RE.match(session) else f"try-{user}-{uuid.uuid4().hex[:6]}"
    calls: list[tuple[str, dict[str, Any]]] = []  # tool calls that ran: (name, arguments)
    headers = {"Authorization": f"Bearer {key}", "X-Session": sid, "X-Purpose": purpose or "dashboard try-it"}
    messages: list[dict[str, Any]] = [{"role": "system", "content": world.SYSTEM}, {"role": "user", "content": prompt}]
    steps: list[dict[str, Any]] = []

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://acl", timeout=180) as c:
        for _ in range(max_steps):
            r = await c.post("/v1/chat/completions", headers=headers,
                             json={"model": model, "messages": messages, "tools": world.TOOLS})
            body = r.json()
            if r.status_code != 200:
                steps.append({"kind": "denied", "status": r.status_code, "acl": body.get("acl"),
                              "message": body.get("error", {}).get("message") or body.get("detail")})
                break
            msg = body["choices"][0]["message"]
            steps.append({"kind": "model", "acl": body.get("acl"), "content": msg.get("content"),
                          "tool_calls": [{"name": t["function"]["name"], "arguments": safe_excerpt(t["function"]["arguments"] or "", width=400)}
                                         for t in msg.get("tool_calls") or []]})
            messages.append({k: v for k, v in msg.items() if v is not None})
            if not msg.get("tool_calls"):
                break
            for tc in msg["tool_calls"]:
                args = json.loads(tc["function"]["arguments"] or "{}")
                calls.append((tc["function"]["name"], args if isinstance(args, dict) else {}))
                result = world.run_tool(tc["function"]["name"], args)
                # The raw result goes back to the agent (the model only ever sees it redacted). The dashboard
                # gets a masked preview: the reporting UI must not become a leak of its own.
                steps.append({"kind": "tool", "name": tc["function"]["name"], "result_preview": _preview(app, tc["function"]["name"], result)})
                messages.append({"role": "tool", "tool_call_id": tc["id"], "content": result})
    caught = any((s.get("acl") or {}).get("threats") for s in steps)
    return {"session": sid, "user": user, "scenario": scenario, "model": model, "steps": steps,
            "attacks": _attacks(world, calls, caught)}
