"""Anthropic Messages adapter: `/v1/messages`, so an unmodified Claude Code runs behind the gateway.

    ANTHROPIC_BASE_URL=http://localhost:8000 ANTHROPIC_AUTH_TOKEN=<key> ANTHROPIC_MODEL=<model in policy.yaml> claude

The engine speaks OpenAI chat format, so this adapter only translates: Anthropic request → OpenAI → the same
`check_request` / upstream / `check_response` as `/v1/chat/completions` → back to Anthropic. Claude Code always streams;
we call the model without streaming, check the whole answer, then replay it as one SSE stream. So a blocked tool call
is gone before Claude Code sees it (no token-by-token output: the trade-off). Spec: docs/claude-code.md.
"""

import json
import time
import uuid
from collections.abc import Iterator
from typing import Any

from fastapi import APIRouter, Header
from fastapi.responses import JSONResponse, Response, StreamingResponse

from ..engine import Engine
from ..identity import Denied, resolve
from .llm_proxy import Upstream, _blocked_completion, call_upstream

STOP = {"tool_calls": "tool_use", "stop": "end_turn", "length": "max_tokens", "content_filter": "refusal"}


def _text(content: Any) -> str:
    """Plain text of a string or a list of content blocks (images and other blocks become a short note)."""
    if isinstance(content, str):
        return content
    out = []
    for b in content or []:
        if b.get("type") == "text":
            out.append(b.get("text", ""))
        elif b.get("type") == "image":
            out.append("[image removed by the AI Control Layer]")
    return "\n".join(out)


def to_openai(body: dict[str, Any]) -> dict[str, Any]:
    """Anthropic Messages request → OpenAI chat request. Builds fresh dicts, so `cache_control` (which Claude Code
    moves between turns) never reaches the engine: the same message hashes the same every turn and is checked once."""
    msgs: list[dict[str, Any]] = []
    if body.get("system"):
        msgs.append({"role": "system", "content": _text(body["system"])})
    for m in body.get("messages", []):
        role, content = m.get("role"), m.get("content")
        blocks = [{"type": "text", "text": content}] if isinstance(content, str) else content or []
        if role == "system":  # Claude Code's mid-conversation system messages
            msgs.append({"role": "system", "content": _text(blocks)})
        elif role == "user":
            # tool results first: OpenAI wants them right after the assistant message that asked for them
            for b in blocks:
                if b.get("type") == "tool_result":
                    msgs.append({"role": "tool", "tool_call_id": b.get("tool_use_id"), "content": _text(b.get("content"))})
            parts = [{"type": "text", "text": _text([b])} for b in blocks if b.get("type") in ("text", "image")]
            if parts:
                msgs.append({"role": "user", "content": parts})
        elif role == "assistant":
            text = "\n".join(b.get("text", "") for b in blocks if b.get("type") == "text")
            calls = [{"id": b["id"], "type": "function", "function": {"name": b["name"], "arguments": json.dumps(b.get("input") or {})}}
                     for b in blocks if b.get("type") == "tool_use"]
            msgs.append({"role": "assistant", "content": text or None, **({"tool_calls": calls} if calls else {})})
    out: dict[str, Any] = {"model": body.get("model"), "messages": msgs}
    tools = [{"type": "function", "function": {"name": t["name"], "description": t.get("description", ""),
                                               "parameters": t["input_schema"]}}
             for t in body.get("tools") or [] if "input_schema" in t]  # server tools (web search …) are not ours to run
    if tools:
        out["tools"] = tools
    tc = body.get("tool_choice") or {}
    if tc.get("type") in ("auto", "none"):
        out["tool_choice"] = tc["type"]
    elif tc.get("type") == "any":
        out["tool_choice"] = "required"
    elif tc.get("type") == "tool":
        out["tool_choice"] = {"type": "function", "function": {"name": tc.get("name")}}
    for a, b in (("max_tokens", "max_tokens"), ("temperature", "temperature"), ("top_p", "top_p"), ("stop_sequences", "stop")):
        if body.get(a) is not None:
            out[b] = body[a]
    return out


def to_anthropic(resp: dict[str, Any], model: str) -> dict[str, Any]:
    """OpenAI chat completion (already checked by the engine) → Anthropic message."""
    choice = (resp.get("choices") or [{}])[0]
    msg = choice.get("message") or {}
    content: list[dict[str, Any]] = []
    if msg.get("content"):
        content.append({"type": "text", "text": msg["content"]})
    for tc in msg.get("tool_calls") or []:
        fn = tc.get("function", {})
        try:
            args = json.loads(fn.get("arguments") or "{}")
        except ValueError:
            args = {"_raw": fn.get("arguments")}
        content.append({"type": "tool_use", "id": tc.get("id") or f"toolu_{uuid.uuid4().hex[:12]}", "name": fn.get("name"), "input": args})
    stop = "tool_use" if any(b["type"] == "tool_use" for b in content) else STOP.get(str(choice.get("finish_reason")), "end_turn")
    usage = resp.get("usage") or {}
    return {"id": f"msg_{resp.get('id') or uuid.uuid4().hex[:12]}", "type": "message", "role": "assistant", "model": model,
            "content": content, "stop_reason": stop, "stop_sequence": None,
            "usage": {"input_tokens": int(usage.get("prompt_tokens") or 0), "output_tokens": int(usage.get("completion_tokens") or 0)}}


def sse(message: dict[str, Any]) -> Iterator[str]:
    """One finished message as the Anthropic event stream: one delta per content block."""
    def ev(kind: str, data: dict[str, Any]) -> str:
        return f"event: {kind}\ndata: {json.dumps({'type': kind, **data})}\n\n"

    yield ev("message_start", {"message": {**message, "content": [], "stop_reason": None,
                                           "usage": {**message["usage"], "output_tokens": 0}}})
    for i, b in enumerate(message["content"]):
        if b["type"] == "text":
            yield ev("content_block_start", {"index": i, "content_block": {"type": "text", "text": ""}})
            yield ev("content_block_delta", {"index": i, "delta": {"type": "text_delta", "text": b["text"]}})
        else:
            yield ev("content_block_start", {"index": i, "content_block": {**b, "input": {}}})
            yield ev("content_block_delta", {"index": i, "delta": {"type": "input_json_delta", "partial_json": json.dumps(b["input"])}})
        yield ev("content_block_stop", {"index": i})
    yield ev("message_delta", {"delta": {"stop_reason": message["stop_reason"], "stop_sequence": None},
                               "usage": {"output_tokens": message["usage"]["output_tokens"]}})
    yield ev("message_stop", {})


def _session_hint(body: dict[str, Any], header: str | None) -> str | None:
    """Claude Code's own session id: the X-Claude-Code-Session-Id header, else metadata.user_id (a JSON string)."""
    if header:
        return header
    try:
        return json.loads((body.get("metadata") or {}).get("user_id") or "{}").get("session_id")
    except (ValueError, AttributeError):
        return None


def _error(status: int, kind: str, message: str, headers: dict[str, str] | None = None) -> JSONResponse:
    return JSONResponse({"type": "error", "error": {"type": kind, "message": message}}, status_code=status, headers=headers)


def router(engine: Engine, upstream: Upstream = call_upstream) -> APIRouter:
    r = APIRouter()

    @r.api_route("/api/hello", methods=["GET", "HEAD"])
    def hello():
        """Claude Code probes this path on the base URL at start."""
        return Response(status_code=200)

    @r.post("/v1/messages/count_tokens")
    async def count_tokens(body: dict[str, Any]):
        """An estimate (~4 characters per token); no model call and no audit entry."""
        return {"input_tokens": len(json.dumps(body)) // 4}

    @r.post("/v1/messages")
    async def messages(
        body: dict[str, Any],
        authorization: str | None = Header(default=None),
        x_api_key: str | None = Header(default=None),
        x_user: str | None = Header(default=None),
        x_session: str | None = Header(default=None),
        x_purpose: str | None = Header(default=None),
        x_claude_code_session_id: str | None = Header(default=None),
    ):
        # --- identity (US-1.2): the same keys as every other adapter ---
        key = authorization.removeprefix("Bearer ").strip() if authorization else x_api_key
        who = resolve(engine, key=key, x_user=x_user, x_purpose=x_purpose, x_session=x_session,
                      session_hint=_session_hint(body, x_claude_code_session_id))
        if isinstance(who, Denied):
            entry = engine.deny(who.reason, user=who.user, agent=who.agent, purpose=x_purpose, sid=x_session)
            kind = {401: "authentication_error", 403: "permission_error"}.get(who.status, "invalid_request_error")
            return _error(who.status, kind, f"AI Control Layer: {who.reason} (audit #{entry['seq']})", {"X-ACL-Outcome": "blocked"})

        t = time.perf_counter()
        oa = to_openai(body)
        translate_ms = (time.perf_counter() - t) * 1000
        oa, ex = await engine.check_request(oa, who.user, who.sid, who.agent, who.purpose)

        upstream_ms = None
        if ex.blocked:
            d = ex.blocked
            resp = _blocked_completion(ex.model, f"⛔ Request blocked by AI Control Layer [{d.control}]: {d.reason}")
        else:
            t = time.perf_counter()
            raw = await upstream(oa, ex.policy.models.get(ex.model, {}))
            upstream_ms = (time.perf_counter() - t) * 1000
            resp = engine.check_response(raw, ex, upstream_ms)
        t = time.perf_counter()
        out = to_anthropic(resp, str(body.get("model")))
        ex.controls_ms += translate_ms + (time.perf_counter() - t) * 1000

        entry = engine.record(ex, upstream_ms)
        headers = {"X-ACL-Outcome": entry["outcome"], "X-ACL-Session": who.sid, "X-ACL-Seq": str(entry["seq"])}
        if body.get("stream"):
            return StreamingResponse(sse(out), media_type="text/event-stream", headers=headers)
        out["acl"] = {"seq": entry["seq"], "outcome": entry["outcome"], "decisions": entry["decisions"],
                      "policy_version": entry["policy_version"], "session": who.sid, "user": who.user, "agent": who.agent}
        return JSONResponse(out, headers=headers)

    return r
