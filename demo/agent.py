"""A minimal tool-using agent that talks to the model only through the AI Control Layer.

    just agent alice "Customer 7 asked about their card limit. Look them up and answer."
"""

import argparse
import json
import os
import sys
import uuid

from openai import OpenAI

sys.path.insert(0, os.path.dirname(__file__))
from world import TOOLS, run_tool  # noqa: E402

SYSTEM = (
    "You are a customer-support assistant at a bank. Use the tools to help the support employee. "
    "Sensitive values may appear as tokens like [[CARD#a1b2c3 ****1111]]; pass such tokens to tools unchanged."
)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("user")
    ap.add_argument("prompt")
    ap.add_argument("--session", default=None)
    ap.add_argument("--model", default=os.getenv("OPENROUTER_MODEL", "deepseek/deepseek-v4.1-flash"))
    ap.add_argument("--gateway", default=os.getenv("ACL_URL", "http://127.0.0.1:8000/v1"))
    ap.add_argument("--steps", type=int, default=6)
    a = ap.parse_args()

    sid = a.session or f"{a.user}-{uuid.uuid4().hex[:6]}"
    client = OpenAI(base_url=a.gateway, api_key="unused-the-gateway-holds-the-keys",
                    default_headers={"X-User": a.user, "X-Session": sid})
    messages: list[dict] = [{"role": "system", "content": SYSTEM}, {"role": "user", "content": a.prompt}]
    print(f"session {sid} · user {a.user} · model {a.model}\n")

    for _ in range(a.steps):
        resp = client.chat.completions.create(model=a.model, messages=messages, tools=TOOLS)
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
            result = run_tool(tc.function.name, args)
            print(f"→ {tc.function.name}({json.dumps(args)})\n  ← {result[:160]}{'…' if len(result) > 160 else ''}")
            messages.append({"role": "tool", "tool_call_id": tc.id, "content": result})
    print("\n(step limit reached)")


if __name__ == "__main__":
    main()
