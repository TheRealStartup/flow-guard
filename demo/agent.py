"""A minimal tool-using agent that talks to the model only through the AI Control Layer.

    just agent alice "Customer 7 asked about their card limit. Look them up and answer."
    uv run python ../demo/agent.py olivia "Prepare the onboarding file for client NW-2041." --scenario onboarding
    uv run python ../demo/agent.py hana "What is the parental leave policy?" --scenario hr --purpose hr-admin
"""

import argparse
import importlib
import json
import os
import sys
import uuid

from openai import OpenAI

sys.path.insert(0, os.path.dirname(__file__))
SCENARIOS = {"support": "world", "onboarding": "onboarding", "developer": "developer", "hr": "hr"}  # name -> module in demo/


def dev_key(user: str) -> str:
    """The demo user's API key: ACL_KEY env var, else demo/dev-keys.env (test keys for the local demo)."""
    if os.getenv("ACL_KEY"):
        return os.environ["ACL_KEY"]
    path = os.path.join(os.path.dirname(__file__), "dev-keys.env")
    with open(path) as f:
        for line in f:
            if line.startswith(f"ACL_KEY_{user.upper()}="):
                return line.split("=", 1)[1].strip()
    return "no-key"  # the gateway will refuse; that is the point


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("user")
    ap.add_argument("prompt")
    ap.add_argument("--session", default=None)
    ap.add_argument("--model", default=os.getenv("OPENROUTER_MODEL", "deepseek/deepseek-v4.1-flash"))
    ap.add_argument("--gateway", default=os.getenv("ACL_URL", "http://127.0.0.1:8000/v1"))
    ap.add_argument("--steps", type=int, default=6)
    ap.add_argument("--purpose", default="customer-support")
    ap.add_argument("--scenario", choices=sorted(SCENARIOS), default="support")
    a = ap.parse_args()
    world = importlib.import_module(SCENARIOS[a.scenario])
    system = world.SYSTEM

    sid = a.session or f"{a.user}-{uuid.uuid4().hex[:6]}"
    # The API key identifies this agent and the human it works for; the model keys stay in the gateway.
    client = OpenAI(base_url=a.gateway, api_key=dev_key(a.user),
                    default_headers={"X-Session": sid, "X-Purpose": a.purpose})
    messages: list[dict] = [{"role": "system", "content": system}, {"role": "user", "content": a.prompt}]
    print(f"session {sid} · user {a.user} · scenario {a.scenario} · model {a.model}\n")

    for _ in range(a.steps):
        resp = client.chat.completions.create(model=a.model, messages=messages, tools=world.TOOLS)
        acl = (resp.model_extra or {}).get("acl", {})
        for d in acl.get("decisions", []):
            print(f"  🛡  {d['action']:<6} {d['control']:<28} {d['where']:<22} {d['reason']}")
        msg = resp.choices[0].message
        messages.append(msg.model_dump(exclude_none=True))
        if not msg.tool_calls:
            print(f"\nassistant: {msg.content}")
            return
        for tc in msg.tool_calls:
            args = json.loads(tc.function.arguments or "{}")
            result = world.run_tool(tc.function.name, args)
            shown = "(personnel file, not printed)" if tc.function.name == "get_employee" else result[:160] + ("…" if len(result) > 160 else "")
            print(f"→ {tc.function.name}({json.dumps(args)})\n  ← {shown}")
            messages.append({"role": "tool", "tool_call_id": tc.id, "content": result})
    print("\n(step limit reached)")


if __name__ == "__main__":
    main()
