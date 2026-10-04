"""Who is calling (US-1.2), shared by every adapter: the OpenAI-style proxy and the Anthropic /v1/messages endpoint.

An API key maps to one (user, agent) pair; the agent gets exactly that user's role. A key may carry a default
purpose (for clients that cannot send the X-Purpose header, such as Claude Code). The session groups one
conversation: the X-Session header, else a hint from the client (Claude Code's own session id), else a new one.
"""

import uuid
from dataclasses import dataclass

from .engine import Engine


@dataclass
class Caller:
    user: str
    agent: str
    purpose: str | None
    sid: str


@dataclass
class Denied:
    status: int
    reason: str
    user: str | None = None
    agent: str | None = None


def resolve(engine: Engine, *, key: str | None, x_user: str | None, x_purpose: str | None,
            x_session: str | None, session_hint: str | None = None) -> Caller | Denied:
    p = engine.policies.get()
    cfg = p.identity
    default_purpose = None
    if cfg["mode"] == "api_key":
        ident = p.identify(key)
        if ident is None:
            return Denied(401, "no valid API key: every request must identify its user and agent", user=x_user)
        if x_user and x_user != ident["user"]:
            return Denied(403, f"key belongs to {ident['user']!r}, not {x_user!r}: an agent cannot act for someone else",
                          ident["user"], ident["agent"])
        user, agent, default_purpose = ident["user"], ident["agent"], ident.get("purpose")
    else:  # header mode: local development only
        if not x_user:
            return Denied(401, "no user identity (X-User): requests without a user are denied")
        user, agent = x_user, "unverified-agent"
    purpose = x_purpose or default_purpose
    if cfg.get("require_purpose") and not purpose:
        return Denied(400, "no purpose given (X-Purpose header, or a default purpose on the key)", user, agent)
    sid = x_session or (f"{user}-{session_hint}" if session_hint else f"{user}-{uuid.uuid4().hex[:8]}")
    if sid in engine.sessions and engine.sessions[sid].user != user:
        return Denied(403, f"session {sid!r} belongs to another user", user, agent)
    return Caller(user, agent, purpose, sid)
