"""AI Control Layer: policy engine API. Adapters (model proxy, MCP gateway, hooks) mount here."""

from fastapi import FastAPI

app = FastAPI(title="AI Control Layer")


@app.get("/api/health")
def health():
    return {"ok": True}
