"""AI Control Layer: policy engine + model proxy + reporting API.

Run: `just gateway` (port 8000). Agents use base_url http://localhost:8000/v1.
"""

import os
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

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

def create_app(policy_path: Path, audit_path: Path, judge: Judge | None, upstream: Upstream = call_upstream) -> FastAPI:
    policies = PolicyStore(policy_path)
    policies.get()  # fail at startup, not on the first request, if the policy is broken
    engine = Engine(policies, AuditLog(audit_path), judge)

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
                "signatures": [s.id for s in p.signatures]}

    @app.get("/api/metrics")
    def metrics():
        return engine.metrics()

    @app.get("/api/events")
    def events(limit: int = 100, outcome: str | None = None):
        ev = [e for e in engine.audit.events if outcome is None or e["outcome"] == outcome]
        return ev[-limit:][::-1]

    @app.get("/api/audit/verify")
    def audit_verify():
        return engine.audit.verify()

    @app.get("/api/audit/export")
    def audit_export():
        return FileResponse(engine.audit.path, media_type="application/x-ndjson", filename="acl-audit.jsonl")

    return app


app = create_app(POLICY, AUDIT, JevJudge())
