"""Live audit feed over Server-Sent Events (`GET /api/stream`), so the dashboard needn't poll.

Appends happen on any thread (the threadpool for sync endpoints, the event loop for the proxy), so each
subscriber gets its own bounded asyncio.Queue fed through `call_soon_threadsafe`. A subscriber that falls
behind is cut off instead of growing memory; its EventSource reconnects with Last-Event-ID and replays
from the audit log, so nothing is lost.
"""

import asyncio
import json
import time
from collections.abc import AsyncIterator, Callable
from typing import Any

from .state import AuditLog

HEARTBEAT_S = 15.0  # comment line, keeps proxies from closing an idle stream
TICK_S = 1.0  # how often an idle stream checks for a disconnect and for policy file edits
QUEUE_MAX = 1000
RETRY_MS = 2000  # tells EventSource how long to wait before reconnecting


class Subscriber:
    def __init__(self, loop: asyncio.AbstractEventLoop, maxsize: int | None = None):
        self.loop = loop
        self.queue: asyncio.Queue[dict[str, Any] | None] = asyncio.Queue(maxsize or QUEUE_MAX)
        self.closed = False

    def push(self, entry: dict[str, Any]) -> None:
        """Called from AuditLog.append on any thread; never blocks."""
        try:
            self.loop.call_soon_threadsafe(self._put, entry)
        except RuntimeError:  # loop already closed: the stream is gone
            pass

    def _put(self, entry: dict[str, Any]) -> None:
        if self.closed:
            return
        try:
            self.queue.put_nowait(entry)
        except asyncio.QueueFull:  # too slow: end its stream (None), the client resumes from its last id
            self.closed = True
            while not self.queue.empty():
                self.queue.get_nowait()
            self.queue.put_nowait(None)


def sse(data: Any, event: str | None = None, id: int | None = None) -> str:
    head = (f"event: {event}\n" if event else "") + (f"id: {id}\n" if id is not None else "")
    return f"{head}data: {json.dumps(data, default=str)}\n\n"


async def audit_stream(audit: AuditLog, after: int | None, is_disconnected: Callable[[], Any],
                       policy_view: Callable[[], dict[str, Any]], poll_policy: Callable[[], Any]) -> AsyncIterator[str]:
    """`event: audit` per entry (the same JSON as /api/events items), `event: policy` after each policy_change."""
    sub = Subscriber(asyncio.get_running_loop())
    backlog = audit.subscribe(sub.push, after)
    try:
        yield f"retry: {RETRY_MS}\n\n"
        for e in backlog:
            yield sse(e, "audit", e["seq"])
        last = time.monotonic()
        policy_changed = any(e.get("type") == "policy_change" for e in backlog)
        while True:
            if policy_changed:
                yield sse(policy_view(), "policy")
                policy_changed = False
            try:
                e = await asyncio.wait_for(sub.queue.get(), TICK_S)
            except TimeoutError:
                if await is_disconnected():
                    return
                await poll_policy()  # policy reloads are lazy; a stat per second makes edits show up unprompted
                if time.monotonic() - last >= HEARTBEAT_S:
                    last = time.monotonic()
                    yield ": ping\n\n"
                continue
            if e is None:
                return
            last = time.monotonic()
            policy_changed = e.get("type") == "policy_change"
            yield sse(e, "audit", e["seq"])
    finally:
        sub.closed = True
        audit.unsubscribe(sub.push)
