"""Live audit feed (`GET /api/stream`, Server-Sent Events): replay after a seq, new entries on an open stream,
heartbeats, and cleanup on disconnect. TestClient buffers whole responses, so these drive the ASGI app directly."""

import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "gateway"))
from acl import stream as stream_mod

SYSTEM = {"role": "system", "content": "You are a bank support assistant."}


class Stream:
    """An open GET /api/stream on the app, read chunk by chunk; `close()` sends the client's disconnect."""

    def __init__(self, app, query: str = "", headers: dict[str, str] | None = None):
        self.app, self.text, self.status, self.headers = app, "", None, {}
        self._chunks: asyncio.Queue[bytes] = asyncio.Queue()
        self._gone = asyncio.Event()
        self._started = False
        h = [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()]
        self.scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": "GET",
                      "scheme": "http", "path": "/api/stream", "raw_path": b"/api/stream", "root_path": "",
                      "query_string": query.encode(), "headers": h, "client": ("127.0.0.1", 5000),
                      "server": ("testserver", 80)}

    async def _receive(self):
        if not self._started:
            self._started = True
            return {"type": "http.request", "body": b"", "more_body": False}
        await self._gone.wait()
        return {"type": "http.disconnect"}

    async def _send(self, msg):
        if msg["type"] == "http.response.start":
            self.status = msg["status"]
            self.headers = {k.decode(): v.decode() for k, v in msg["headers"]}
        elif msg["type"] == "http.response.body":
            await self._chunks.put(msg.get("body", b""))

    async def __aenter__(self):
        self.task = asyncio.create_task(self.app(self.scope, self._receive, self._send))
        return self

    async def __aexit__(self, *exc):
        self._gone.set()
        await asyncio.wait_for(self.task, 5)

    async def until(self, pred, timeout: float = 5.0) -> str:
        async def loop():
            while not pred(self.text):
                self.text += (await self._chunks.get()).decode()
        await asyncio.wait_for(loop(), timeout)
        return self.text

    def events(self, kind: str = "audit") -> list[tuple[int | None, dict]]:
        out = []
        for block in self.text.split("\n\n"):
            fields = dict(line.split(": ", 1) for line in block.splitlines() if ": " in line and not line.startswith(":"))
            if fields.get("event") == kind:
                out.append((int(fields["id"]) if "id" in fields else None, json.loads(fields["data"])))
        return out


def n_events(kind: str, n: int):
    return lambda text: text.count(f"event: {kind}\n") >= n


def test_replays_entries_after_since_then_streams_new_ones(gw):
    audit = gw.app.state.engine.audit
    seqs = [audit.append({"type": "exchange", "outcome": "allowed", "n": i})["seq"] for i in range(3)]

    async def run():
        async with Stream(gw.app, f"since={seqs[0]}") as s:
            await s.until(n_events("audit", 2))
            assert s.status == 200 and s.headers["content-type"].startswith("text/event-stream")
            assert [i for i, _ in s.events()] == seqs[1:]
            # appended from another thread, like a sync endpoint in the threadpool
            new = await asyncio.to_thread(audit.append, {"type": "exchange", "outcome": "blocked", "n": 3})
            await s.until(n_events("audit", 3))
            seq, data = s.events()[-1]
            assert len(s.events()) == 3 and seq == new["seq"]
            assert data == gw.client.get("/api/events?limit=1").json()[0]  # same JSON as an /api/events item

    asyncio.run(run())
    assert audit.subscribers == 0  # disconnect cleaned up


def test_last_event_id_wins_over_since_and_no_param_means_live_only(gw):
    audit = gw.app.state.engine.audit
    seqs = [audit.append({"type": "exchange", "outcome": "allowed", "n": i})["seq"] for i in range(4)]

    async def run():
        async with Stream(gw.app, f"since={seqs[0]}", {"Last-Event-ID": str(seqs[2])}) as s:
            await s.until(n_events("audit", 1))
            assert [i for i, _ in s.events()] == [seqs[3]]
        async with Stream(gw.app) as s:
            await s.until(lambda t: t.startswith("retry:"))
            new = await asyncio.to_thread(audit.append, {"type": "exchange", "outcome": "allowed", "n": 4})
            await s.until(n_events("audit", 1))
            assert [i for i, _ in s.events()] == [new["seq"]]

    asyncio.run(run())


def test_a_real_request_and_a_policy_edit_show_up_on_an_open_stream(gw):
    async def run():
        async with Stream(gw.app) as s:
            await s.until(lambda t: t.startswith("retry:"))
            gw.upstream.next_reply = {"text": "ok"}
            r = await asyncio.to_thread(gw.chat, "alice", [SYSTEM, {"role": "user", "content": "hello"}])
            await s.until(n_events("audit", 1))
            assert s.events()[0][1]["seq"] == r.json()["acl"]["seq"]

            # nobody calls /api/policy here: the stream's own tick notices the file edit
            gw.edit_policy(lambda p: p["controls"]["pii.iban"].update(action="allow"))
            await s.until(n_events("policy", 1))
            assert s.events()[-1][1]["type"] == "policy_change"
            policy = s.events("policy")[0][1]
            assert policy["controls"]["pii.iban"]["action"] == "allow" and policy["last_change"]

    asyncio.run(run())


def test_heartbeat_when_idle(gw, monkeypatch):
    monkeypatch.setattr(stream_mod, "TICK_S", 0.02)
    monkeypatch.setattr(stream_mod, "HEARTBEAT_S", 0.05)

    async def run():
        async with Stream(gw.app) as s:
            await s.until(lambda t: ": ping\n\n" in t, timeout=2)

    asyncio.run(run())
    assert gw.app.state.engine.audit.subscribers == 0


def test_slow_subscriber_is_cut_off_and_can_resume(gw, monkeypatch):
    monkeypatch.setattr(stream_mod, "QUEUE_MAX", 2)
    audit = gw.app.state.engine.audit
    loop = asyncio.new_event_loop()
    sub = stream_mod.Subscriber(loop)
    audit.subscribe(sub.push)
    for i in range(5):
        audit.append({"type": "exchange", "outcome": "allowed", "n": i})
    loop.run_until_complete(asyncio.sleep(0))  # run the queued call_soon_threadsafe callbacks
    assert sub.closed and sub.queue.get_nowait() is None  # end of stream, not unbounded memory
    audit.unsubscribe(sub.push)
    loop.close()
    sub.push(audit.events[-1])  # a push after the loop closed is a no-op, not an error
