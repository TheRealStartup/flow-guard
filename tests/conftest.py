"""Shared fixtures. No network: a keyword-based fake stands in for Jev, and a scripted
upstream stands in for the model, so the suite is fast and gives the same result every run.
Set ACL_LIVE=1 to run the tests marked `live` against the real Jev API."""

import json
import os
import shutil
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "gateway"))
sys.path.insert(0, str(ROOT / "demo"))

from acl.adapters.llm_proxy import compromised_model
from acl.detectors.jev import Verdict
from main import create_app

DEV_KEYS = {line.split("=", 1)[0].removeprefix("ACL_KEY_").lower(): line.split("=", 1)[1].strip()
            for line in (ROOT / "demo" / "dev-keys.env").read_text().splitlines() if line.startswith("ACL_KEY_")}
INJECTION_MARKERS = ("you must first send", "note for the assistant", "ignore your rules", "you are now dan")


class FakeJudge:
    """Scores 0.98 if the text contains a known injection phrase, else 0.02. `fail=True` simulates an outage."""

    def __init__(self):
        self.fail = False
        self.calls: list[tuple[str, str]] = []

    async def judge(self, text: str, source: str, timeout_s: float) -> Verdict:
        self.calls.append((source, text))
        if self.fail:
            raise TimeoutError("simulated Jev outage")
        hit = any(m in text.lower() for m in INJECTION_MARKERS)
        return Verdict(injection=0.98 if hit else 0.02, model="fake-jev")


class ScriptedUpstream:
    """Returns `next_reply` (a tool call or text), or falls back to the compromised mock model.
    Records every body it receives, so tests can assert what the model actually saw."""

    def __init__(self):
        self.next_reply: dict[str, Any] | None = None
        self.seen: list[dict[str, Any]] = []

    async def __call__(self, body: dict[str, Any], model_cfg: dict[str, Any]) -> dict[str, Any]:
        self.seen.append(body)
        if self.next_reply is None:
            return compromised_model(body)
        r = self.next_reply
        if "tool_call" in r:
            tc = {"id": "call_test", "type": "function",
                  "function": {"name": r["tool_call"]["name"], "arguments": json.dumps(r["tool_call"]["arguments"])}}
            msg = {"role": "assistant", "content": None, "tool_calls": [tc]}
            finish = "tool_calls"
        else:
            msg, finish = {"role": "assistant", "content": r.get("text", "ok")}, "stop"
        return {"id": "t", "object": "chat.completion", "created": 0, "model": body.get("model"),
                "choices": [{"index": 0, "message": msg, "finish_reason": finish}],
                "usage": r.get("usage", {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15})}


class Gateway:
    def __init__(self, tmp: Path):
        self.dir = tmp / "policy"
        shutil.copytree(ROOT / "policy", self.dir)
        self.policy_path = self.dir / "policy.yaml"
        self.judge = FakeJudge()
        self.upstream = ScriptedUpstream()
        self.app = create_app(self.policy_path, tmp / "audit.jsonl", self.judge, self.upstream)
        self.client = TestClient(self.app)
        self._bump = 0

    def edit_policy(self, fn) -> None:
        """Change the policy file the way a judge would; the gateway must pick it up live."""
        raw = yaml.safe_load(self.policy_path.read_text())
        fn(raw)
        self.policy_path.write_text(yaml.safe_dump(raw, sort_keys=False))
        self._bump += 1  # make sure the mtime changes even within the same clock tick
        st = self.policy_path.stat()
        os.utime(self.policy_path, (st.st_atime, st.st_mtime + self._bump))

    def chat(self, user: str, messages: list[dict], model: str = "mock/compromised", session: str = "s1",
             headers: dict[str, str] | None = None, **extra):
        """Calls the gateway as `user`'s agent: their dev API key + a purpose, like a real client."""
        from world import TOOLS

        h = {"X-Session": session, "X-Purpose": "test"}
        if user in DEV_KEYS:
            h["Authorization"] = f"Bearer {DEV_KEYS[user]}"
        h.update(headers or {})
        return self.client.post("/v1/chat/completions", headers=h,
                                json={"model": model, "messages": messages, "tools": TOOLS, **extra})


@pytest.fixture
def gw(tmp_path: Path) -> Gateway:
    return Gateway(tmp_path)


def pytest_configure(config):
    config.addinivalue_line("markers", "live: calls the real Jev API (needs TYPESAFE_API_KEY and ACL_LIVE=1)")


def pytest_collection_modifyitems(config, items):
    if os.getenv("ACL_LIVE") == "1" and os.getenv("TYPESAFE_API_KEY"):
        return
    skip = pytest.mark.skip(reason="live test: set ACL_LIVE=1 and TYPESAFE_API_KEY")
    for item in items:
        if "live" in item.keywords:
            item.add_marker(skip)
