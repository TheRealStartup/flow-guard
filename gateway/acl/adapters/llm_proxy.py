"""Model proxy adapter: an OpenAI-compatible /v1/chat/completions endpoint.

Agents point `base_url` here. A bearer key identifies the user and agent; X-Purpose
states the reason and X-Session identifies the conversation. See docs/decisions.md (D1) for why this is the first
adapter and what it cannot see.
"""

import os
import time
import uuid
from collections.abc import Awaitable, Callable
from typing import Any

import httpx
from fastapi import APIRouter, Header, HTTPException
from fastapi.responses import JSONResponse

from ..engine import Engine
from ..identity import Denied, resolve
from .mock_model import compromised_model

Upstream = Callable[[dict[str, Any], dict[str, Any]], Awaitable[dict[str, Any]]]


async def call_upstream(body: dict[str, Any], model_cfg: dict[str, Any]) -> dict[str, Any]:
    if model_cfg.get("upstream") == "mock":
        return compromised_model(body)
    if model_cfg.get("upstream") == "ollama":
        url = os.getenv("OLLAMA_URL", "http://127.0.0.1:11434") + "/v1/chat/completions"
        headers = {}
    else:
        url = "https://openrouter.ai/api/v1/chat/completions"
        headers = {"Authorization": f"Bearer {os.getenv('OPENROUTER_API_KEY', '')}"}
        body = {**body, "usage": {"include": True}}
        if model_cfg.get("providers"):
            body["provider"] = {"only": model_cfg["providers"]}
    async with httpx.AsyncClient(timeout=120) as client:
        r = await client.post(url, json=body, headers=headers)
        if r.status_code >= 400:
            raise HTTPException(502, f"upstream {r.status_code}: {r.text[:300]}")
        return r.json()


def _blocked_completion(model: str, text: str) -> dict[str, Any]:
    return {
        "id": f"acl-{uuid.uuid4().hex[:12]}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model,
        "choices": [{"index": 0, "message": {"role": "assistant", "content": text}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
    }


def router(engine: Engine, upstream: Upstream = call_upstream) -> APIRouter:
    r = APIRouter()

    @r.post("/v1/chat/completions")
    async def chat_completions(
        body: dict[str, Any],
        authorization: str | None = Header(default=None),
        x_user: str | None = Header(default=None),
        x_session: str | None = Header(default=None),
        x_purpose: str | None = Header(default=None),
    ):
        if body.get("stream"):
            raise HTTPException(400, "streaming is not supported yet by the AI Control Layer (MVP); send stream=false")

        # --- identity (US-1.2): who is the agent, and for which human? ---
        key = authorization.removeprefix("Bearer ").strip() if authorization else None
        who = resolve(engine, key=key, x_user=x_user, x_purpose=x_purpose, x_session=x_session)
        if isinstance(who, Denied):
            entry = engine.deny(who.reason, user=who.user, agent=who.agent, purpose=x_purpose, sid=x_session)
            return JSONResponse({"error": {"type": "acl_denied", "message": who.reason}, "acl": {"seq": entry["seq"], "outcome": "blocked"}},
                                status_code=who.status, headers={"X-ACL-Outcome": "blocked"})
        user, agent, sid = who.user, who.agent, who.sid
        body, ex = await engine.check_request(body, user, sid, agent, who.purpose)

        upstream_ms = None
        if ex.blocked:
            d = ex.blocked
            resp = _blocked_completion(ex.model, f"⛔ Request blocked by AI Control Layer [{d.control}]: {d.reason}")
        else:
            t = time.perf_counter()
            raw = await upstream(body, ex.policy.models.get(ex.model, {}))
            upstream_ms = (time.perf_counter() - t) * 1000
            resp = engine.check_response(raw, ex, upstream_ms)

        entry = engine.record(ex, upstream_ms)
        resp["acl"] = {"seq": entry["seq"], "outcome": entry["outcome"], "decisions": entry["decisions"],
                       "policy_version": entry["policy_version"], "session": sid,
                       "user": user, "agent": agent}
        return JSONResponse(resp, headers={"X-ACL-Outcome": entry["outcome"], "X-ACL-Session": sid})

    return r
