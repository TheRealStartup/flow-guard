"""AI Control Layer: policy engine + model proxy + reporting API.

Run: `just gateway` (port 8000). Agents use base_url http://localhost:8000/v1; Claude Code uses
ANTHROPIC_BASE_URL=http://localhost:8000 (`just claude-code`).
Interactive API docs for the dashboard: http://localhost:8000/docs
"""

import asyncio
import contextlib
import os
import time
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, PlainTextResponse, StreamingResponse
from pydantic import BaseModel

from acl import tryit
from acl.adapters.anthropic import router as anthropic_router
from acl.adapters.llm_proxy import Upstream, call_upstream
from acl.adapters.llm_proxy import router as llm_router
from acl.detectors.demo import DemoJudge
from acl.detectors.jev import JevJudge, Judge
from acl.engine import Engine, with_threats
from acl.feed import FeedPuller
from acl.policy import (
    ACTIONS,
    SUPPORTED_ACTIONS,
    UPSTREAMS,
    PolicyStore,
    add_model,
    remove_model,
    set_control_action,
)
from acl.state import AuditLog
from acl.stream import audit_stream

load_dotenv()
ROOT = Path(__file__).resolve().parent.parent
POLICY = Path(os.getenv("ACL_POLICY", ROOT / "policy" / "policy.yaml"))
AUDIT = Path(os.getenv("ACL_AUDIT", ROOT / "gateway" / "data" / "audit.jsonl"))
LOCAL = {"127.0.0.1", "::1", "localhost", "testclient"}


class ActionRequest(BaseModel):
    action: str  # allow | flag | redact | block


class ModelRequest(BaseModel):
    model: str
    upstream: str = "openrouter"
    max_class: str | None = None  # highest data class it may receive; default: the lowest (classification.default)


class TryRequest(BaseModel):
    user: str = "alice"
    prompt: str
    model: str = "mock/compromised"
    scenario: str = "support"  # support | onboarding | developer | hr
    purpose: str = "dashboard try-it"  # sent as X-Purpose (the HR purpose rule reads it)


def create_app(policy_path: Path, audit_path: Path, judge: Judge | None, upstream: Upstream = call_upstream) -> FastAPI:
    audit = AuditLog(audit_path)
    # Every policy reload (or failed reload) is itself an audit entry: who changed the rules, when, and how.
    policies = PolicyStore(policy_path, on_change=lambda change: audit.append({"type": "policy_change", **change}))
    policies.get()  # fail at startup, not on the first request, if the policy is broken
    engine = Engine(policies, audit, judge)

    feed = FeedPuller(policies)

    @contextlib.asynccontextmanager
    async def lifespan(_app: FastAPI):
        task = asyncio.create_task(feed.run())  # pull the signature feed now and every refresh_s seconds
        try:
            yield
        finally:
            task.cancel()

    app = FastAPI(title="FlowGuard", lifespan=lifespan)
    app.state.feed = feed
    app.state.engine = engine
    app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
    app.include_router(llm_router(engine, upstream))
    app.include_router(anthropic_router(engine, upstream))  # Claude Code: ANTHROPIC_BASE_URL=http://localhost:8000

    @app.get("/api/health")
    def health():
        p = policies.get()
        return {"ok": True, "policy_version": p.version, "profile": p.profile, "policy_error": policies.last_error,
                "judge": "demo" if isinstance(judge, DemoJudge) else "jev" if isinstance(judge, JevJudge) else "custom"}

    @app.get("/api/policy")
    def policy():
        p = policies.get()
        return {"version": p.version, "profile": p.profile, "controls": p.controls, "error": policies.last_error,
                "signatures": [s.id for s in p.signatures], "last_change": policies.history[-1] if policies.history else None}

    @app.get("/api/policy/details")
    def policy_details():
        """Everything the Policy page shows, structured: base controls and profile overrides, models, budgets,
        roles, users, sinks, scopes, barriers, signatures, identities. Leaves out key hashes and the restricted
        deals' ids and terms (naming a deal would itself leak it)."""
        p = policies.get()
        raw = p.raw
        barriers = raw.get("barriers", {})
        # Deal ids are codenames: report how many deals a user is cleared for, never which.
        users = {u: {**{k: v for k, v in info.items() if k != "deals"}, **({"deals": len(info["deals"])} if "deals" in info else {})}
                 for u, info in raw.get("users", {}).items()}
        return {
            "version": p.version, "profile": p.profile, "error": policies.last_error,
            "defaults": raw.get("defaults", {}),
            "base_controls": raw.get("controls", {}), "profiles": raw.get("profiles", {}), "controls": p.controls,
            "models": {m: {**cfg, "effective_class": p.level(p.model_limit(m))} for m, cfg in p.models.items()},
            "levels": p.levels, "upstreams": list(UPSTREAMS),
            "supported_actions": {cid: list(SUPPORTED_ACTIONS.get(cid, ACTIONS)) for cid in p.controls},
            "budgets": raw.get("budgets", {}),
            "identity": {**p.identity, "keys": sorted(p.identities.values(), key=lambda i: i["user"])},
            "users": users, "roles": raw.get("roles", {}), "sinks": raw.get("sinks", {}),
            "scopes": raw.get("scopes", {}),
            "barriers": {"public_message": p.barrier_message,
                         "restricted": [{"terms": len(r.get("terms", []))} for r in barriers.get("restricted", [])]},
            "signatures": [{"id": s.id, "where": s.where, "ref": s.ref, "title": s.title, "severity": s.severity,
                            "published": s.published, "cve": s.cve, "sources": s.sources} for s in p.signatures],
            "feed": feed.status,
        }

    @app.post("/api/policy/controls/{cid}")
    def set_action(cid: str, body: ActionRequest, request: Request):
        """Change one control's action from the dashboard. Writes only that value in policy.yaml (comments stay),
        then reloads: the change is versioned, audited and streamed exactly like a hand edit. Local only."""
        p = policies.get()
        if cid not in p.raw.get("controls", {}):
            raise HTTPException(404, f"no control {cid!r}")
        if "action" in (p.raw.get("profiles", {}).get(p.profile, {}).get(cid) or {}):
            raise HTTPException(409, f"the active profile {p.profile!r} sets this action; edit profiles.{p.profile} in policy.yaml")
        p = write_policy(request, lambda text: set_control_action(text, cid, body.action))
        return {"version": p.version, "control": cid, "action": p.action(cid)}

    def write_policy(request: Request, change):
        """Apply one dashboard edit to policy.yaml: localhost only, validated before writing (a file the gateway would
        reject is never written), comments kept, then reloaded, so it is versioned, audited and streamed like a hand edit."""
        if (request.client.host if request.client else "") not in LOCAL:
            raise HTTPException(403, "Policy edits are only accepted from localhost")
        try:
            text = change(policy_path.read_text())
            policies.check(text)
        except ValueError as e:
            raise HTTPException(400, str(e))
        tmp = policy_path.with_suffix(".yaml.tmp")
        tmp.write_text(text)
        try:
            tmp.replace(policy_path)  # atomic: a reader never sees half a file
        except OSError:  # e.g. a Docker Desktop bind mount on Windows refuses to rename over an open file
            policy_path.write_text(text)
            tmp.unlink(missing_ok=True)
        return policies.get()

    @app.post("/api/feed/refresh")
    async def refresh_feed(request: Request):
        """Pull the signature feed now instead of waiting for the next refresh (dashboard button, local only)."""
        if (request.client.host if request.client else "") not in LOCAL:
            raise HTTPException(403, "Feed refresh is only accepted from localhost")
        return await feed.pull()

    @app.post("/api/policy/models")
    def approve_model(body: ModelRequest, request: Request):
        """Add a model to the approved list (dashboard). It gets the lowest data class unless a higher one is chosen:
        a new vendor sees no client data until someone decides it may."""
        p = policies.get()
        cls = body.max_class or p.classification.get("default", "internal")
        if cls not in p.levels:
            raise HTTPException(400, f"max_class must be one of {p.levels}")
        p = write_policy(request, lambda text: add_model(text, body.model, body.upstream, cls))
        return {"version": p.version, "model": body.model, "settings": p.models.get(body.model)}

    @app.delete("/api/policy/models/{model:path}")
    def remove_approved_model(model: str, request: Request):
        p = write_policy(request, lambda text: remove_model(text, model))
        return {"version": p.version, "removed": model}

    last_poll = [0.0]

    async def poll_policy():
        """At most once a second across all open streams; get() reloads the files if their mtime changed."""
        if time.monotonic() - last_poll[0] >= 1.0:
            last_poll[0] = time.monotonic()
            await asyncio.to_thread(policies.get)

    @app.get("/api/stream")
    async def stream(request: Request, since: int | None = None, last_event_id: str | None = Header(None)):
        """Server-Sent Events: each new audit entry as `event: audit` (id = seq, data = the same JSON as an
        /api/events item), plus `event: policy` (the /api/policy payload) after a reload. `since=<seq>` or the
        Last-Event-ID header (sent by EventSource on reconnect, and preferred) replays the entries after that seq."""
        after = int(last_event_id) if last_event_id and last_event_id.strip().lstrip("-").isdigit() else since
        return StreamingResponse(
            audit_stream(engine.audit, after, request.is_disconnected, policy, poll_policy, with_threats),
            media_type="text/event-stream",
            # no-transform + X-Accel-Buffering: ask proxies (Next.js rewrites, nginx) not to buffer or compress.
            headers={"Cache-Control": "no-cache, no-transform", "X-Accel-Buffering": "no"})

    @app.get("/api/policy/history")
    def policy_history():
        """Newest first: each reload with the exact fields that changed, or the error if an edit was rejected."""
        policies.get()
        return policies.history[::-1]

    @app.get("/api/policy/raw", response_class=PlainTextResponse)
    def policy_raw():
        return policy_path.read_text()

    @app.get("/api/metrics")
    def metrics():
        return engine.metrics()

    @app.get("/api/metrics/timeseries")
    def metrics_timeseries(minutes: int = 30):
        return engine.timeseries(max(1, min(minutes, 24 * 60)))

    @app.get("/api/events")
    def events(limit: int = 100, outcome: str | None = None, type: str | None = None):
        ev = [e for e in engine.audit.events
              if (type is None or e.get("type", "exchange") == type) and (outcome is None or e.get("outcome") == outcome)]
        return [with_threats(e) for e in ev[-limit:][::-1]]

    @app.get("/api/sessions")
    def sessions():
        seen: dict[str, dict] = {}
        for e in engine.exchanges():
            sid = e.get("session")
            if not sid:
                continue
            s = seen.setdefault(sid, {"session": sid, "user": e.get("user"), "agent": e.get("agent"), "steps": 0,
                                      "blocked": 0, "first_ts": e["ts"]})
            s["steps"] += 1
            s["blocked"] += e["outcome"] == "blocked"
            s["last_ts"] = e["ts"]
            s["labels"] = (e.get("usage") or {}).get("labels", [])
        return sorted(seen.values(), key=lambda s: s["last_ts"], reverse=True)

    @app.get("/api/sessions/{sid}")
    def session(sid: str):
        v = engine.session_view(sid)
        if v is None:
            raise HTTPException(404, f"no session {sid!r}")
        return v

    @app.post("/api/try")
    async def try_it(req: TryRequest, request: Request):
        """Run the demo agent as a demo user, through the gateway's own front door (same identity and controls).
        Local only: it holds the demo users' keys."""
        if (request.client.host if request.client else "") not in LOCAL:
            raise HTTPException(403, "Try it is only available from localhost")
        if req.user not in tryit.dev_keys():
            raise HTTPException(400, f"unknown demo user {req.user!r}; known: {sorted(tryit.dev_keys())}")
        if req.scenario not in tryit.SCENARIOS:
            raise HTTPException(400, f"unknown scenario {req.scenario!r}; known: {sorted(tryit.SCENARIOS)}")
        return await tryit.run(app, req.user, req.prompt, req.model, req.scenario, purpose=req.purpose)

    @app.get("/api/audit/verify")
    def audit_verify():
        return engine.audit.verify()

    @app.get("/api/audit/export")
    def audit_export():
        return FileResponse(engine.audit.path, media_type="application/x-ndjson", filename="acl-audit.jsonl")

    return app


judge_mode = os.getenv("ACL_JUDGE", "jev")
if judge_mode not in ("demo", "jev"):
    raise ValueError("ACL_JUDGE must be 'demo' or 'jev'")
app = create_app(POLICY, AUDIT, DemoJudge() if judge_mode == "demo" else JevJudge())
