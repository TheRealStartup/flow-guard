"""Model proxy adapter: an OpenAI-compatible /v1/chat/completions endpoint.

Agents point `base_url` here. Who the agent acts for comes from the `X-User` header, and
the conversation from `X-Session`. See docs/decisions.md (D1) for why this is the first
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
        p = engine.policies.get()
        cfg = p.identity

        def deny(status: int, reason: str, user=None, agent=None):
            entry = engine.deny(reason, user=user, agent=agent, purpose=x_purpose, sid=x_session)
            return JSONResponse({"error": {"type": "acl_denied", "message": reason}, "acl": {"seq": entry["seq"], "outcome": "blocked"}},
                                status_code=status, headers={"X-ACL-Outcome": "blocked"})

        if cfg["mode"] == "api_key":
            key = authorization.removeprefix("Bearer ").strip() if authorization else None
            ident = p.identify(key)
            if ident is None:
                return deny(401, "no valid API key: every request must identify its user and agent", user=x_user)
            if x_user and x_user != ident["user"]:
                return deny(403, f"key belongs to {ident['user']!r}, not {x_user!r}: an agent cannot act for someone else",
                            user=ident["user"], agent=ident["agent"])
            user, agent = ident["user"], ident["agent"]
        else:  # header mode: local development only
            if not x_user:
                return deny(401, "no user identity (X-User): requests without a user are denied")
            user, agent = x_user, "unverified-agent"
        if cfg.get("require_purpose") and not x_purpose:
            return deny(400, "no purpose given (X-Purpose header)", user=user, agent=agent)

        sid = x_session or f"{user}-{uuid.uuid4().hex[:8]}"
        if sid in engine.sessions and engine.sessions[sid].user != user:
            return deny(403, f"session {sid!r} belongs to another user", user=user, agent=agent)
        body, ex = await engine.check_request(body, user, sid, agent, x_purpose)

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
