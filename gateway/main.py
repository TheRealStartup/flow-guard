"""AI Control Layer: policy engine + model proxy + reporting API.

Run: `just gateway` (port 8000). Agents use base_url http://localhost:8000/v1.
Interactive API docs for the dashboard: http://localhost:8000/docs
"""

import os
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, PlainTextResponse
from pydantic import BaseModel

from acl import tryit
from acl.adapters.llm_proxy import Upstream, call_upstream
from acl.adapters.llm_proxy import router as llm_router
from acl.detectors.jev import JevJudge, Judge
from acl.engine import Engine
from acl.policy import PolicyStore
from acl.state import AuditLog

load_dotenv()
ROOT = Path(__file__).resolve().parent.parent
POLICY = Path(os.getenv("ACL_POLICY", ROOT / "policy" / "policy.yaml"))
AUDIT = Path(os.getenv("ACL_AUDIT", ROOT / "gateway" / "data" / "audit.jsonl"))
LOCAL = {"127.0.0.1", "::1", "localhost", "testclient"}


class TryRequest(BaseModel):
    user: str = "alice"
    prompt: str
    model: str = "mock/compromised"


def create_app(policy_path: Path, audit_path: Path, judge: Judge | None, upstream: Upstream = call_upstream) -> FastAPI:
    audit = AuditLog(audit_path)
    # Every policy reload (or failed reload) is itself an audit entry: who changed the rules, when, and how.
    policies = PolicyStore(policy_path, on_change=lambda change: audit.append({"type": "policy_change", **change}))
    policies.get()  # fail at startup, not on the first request, if the policy is broken
    engine = Engine(policies, audit, judge)

    app = FastAPI(title="AI Control Layer")
    app.state.engine = engine
    app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
    app.include_router(llm_router(engine, upstream))

    @app.get("/api/health")
    def health():
        p = policies.get()
        return {"ok": True, "policy_version": p.version, "profile": p.profile, "policy_error": policies.last_error}

    @app.get("/api/policy")
    def policy():
        p = policies.get()
        return {"version": p.version, "profile": p.profile, "controls": p.controls, "error": policies.last_error,
                "signatures": [s.id for s in p.signatures], "last_change": policies.history[-1] if policies.history else None}

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
        return ev[-limit:][::-1]

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
        return await tryit.run(app, req.user, req.prompt, req.model)

    @app.get("/api/audit/verify")
    def audit_verify():
        return engine.audit.verify()

    @app.get("/api/audit/export")
    def audit_export():
        return FileResponse(engine.audit.path, media_type="application/x-ndjson", filename="acl-audit.jsonl")

    return app


app = create_app(POLICY, AUDIT, JevJudge())
