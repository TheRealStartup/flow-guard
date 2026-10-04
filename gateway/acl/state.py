"""Per-session state (token vault, data-flow labels, budget usage) and the audit log."""

import hashlib
import hmac
import json
import os
import re
import secrets
import threading

try:
    import fcntl  # POSIX file locks; the gateway runs on Linux (Docker included)
except ImportError:  # Windows without Docker: single writer only
    fcntl = None
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from .protection import reporting

TOKEN_RE = re.compile(r"\[\[([A-Z]+)#([0-9a-f]{6})[^\]]*\]\]")
_TOKEN_KEY = os.urandom(16)


@dataclass
class Session:
    id: str
    user: str
    agent: str = "unknown-agent"
    purpose: str | None = None
    vault: dict[str, str] = field(default_factory=dict)  # token id -> real value
    labels: set[str] = field(default_factory=set)  # e.g. {"CARD", "IBAN"}: data-flow labels
    seen: set[str] = field(default_factory=set)  # hashes of messages already checked and logged
    quarantined: dict[str, str] = field(default_factory=dict)  # message hash -> replacement text
    judged: set[str] = field(default_factory=set)  # hashes of messages the injection check has passed
    judge_version: str | None = None
    issued: dict[str, tuple[str, str]] = field(default_factory=dict)  # tool-call id -> (tool, arguments) this gateway let through
    spotlight_id: str = field(default_factory=lambda: secrets.token_hex(4))  # in the tool-data markers; unguessable
    tokens: int = 0
    cost_usd: float = 0.0
    tool_calls: int = 0
    compute_s: float = 0.0

    def tokenize(self, kind: str, value: str, label: bool = True) -> str:
        """Same value -> same token within a session, so the model can refer to it consistently. `label=False` for
        heuristic finds: the value is still hidden, but the session is not marked as holding that kind of data."""
        tid = hmac.new(_TOKEN_KEY, f"{self.id}\0{kind}\0{value}".encode(), "sha256").hexdigest()[:6]
        self.vault[tid] = value
        if label:
            self.labels.add(kind)
        hint = f" ****{value[-4:]}" if kind in ("CARD", "IBAN") else ""
        return f"[[{kind}#{tid}{hint}]]"

    def detokenize(self, text: str) -> str:
        return TOKEN_RE.sub(lambda m: self.vault.get(m.group(2), m.group(0)), text)

    def usage(self) -> dict[str, Any]:
        return {
            "tokens": self.tokens,
            "cost_usd": round(self.cost_usd, 6),
            "tool_calls": self.tool_calls,
            "compute_s": round(self.compute_s, 2),
            "labels": sorted(self.labels),
        }


class AuditLog:
    """Append-only JSONL. Each entry carries the hash of the previous one, so editing or
    deleting any past entry breaks the chain, and `verify()` finds where.

    Safe with several writers (two gateway processes, several workers): every append takes an exclusive
    file lock and first reads what others wrote, so the chain links to the true last entry on disk.
    Without this, each process chained from its own memory and the log forked (seen on Sat 3 Oct)."""

    def __init__(self, path: Path):
        self.path = path
        self.checkpoint = path.with_suffix(path.suffix + ".head.json")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._listeners: list[Callable[[dict[str, Any]], None]] = []
        self._events: list[dict[str, Any]] = []
        self._prev = "0" * 64
        self._offset = 0  # bytes of the file already read into _events
        self._sync()

    def _sync(self) -> None:
        """Read complete lines other writers (or we) appended since the last call."""
        if not self.path.exists():
            return
        with self.path.open("rb") as f:
            f.seek(self._offset)
            data = f.read()
        end = data.rfind(b"\n") + 1  # ignore a half-written last line
        for line in data[:end].splitlines():
            if line.strip():
                e = json.loads(line)
                self._events.append(e)
                self._prev = e["hash"]
                # Every caller holds the lock, so listeners see entries once and in seq order, including
                # entries other writers appended. Listeners must not block (see stream.py).
                for fn in self._listeners:
                    fn(e)
        self._offset += end

    @property
    def events(self) -> list[dict[str, Any]]:
        with self._lock:
            self._sync()
            return self._events

    @staticmethod
    def _digest(prev: str, entry: dict[str, Any]) -> str:
        body = json.dumps({k: v for k, v in entry.items() if k != "hash"}, sort_keys=True, default=str)
        return hashlib.sha256((prev + body).encode()).hexdigest()

    def append(self, entry: dict[str, Any]) -> dict[str, Any]:
        with self._lock, self.path.open("a") as f:
            if fcntl:
                fcntl.flock(f, fcntl.LOCK_EX)  # released when the file closes
            if self.checkpoint.exists() and not self._verify()["ok"]:
                raise ValueError("audit integrity check failed; refusing to append")
            self._sync()  # whatever other writers appended first
            entry = {"seq": len(self._events), "ts": time.time(), **reporting(entry), "prev_hash": self._prev}
            entry["hash"] = self._digest(self._prev, entry)
            f.write(json.dumps(entry, default=str) + "\n")
            f.flush()
            os.fsync(f.fileno())
            temporary = self.checkpoint.with_suffix(".tmp")
            temporary.write_text(json.dumps({"entries": entry["seq"] + 1, "head": entry["hash"]}))
            os.replace(temporary, self.checkpoint)
            self._sync()  # reads the line back, which also notifies the listeners
            return self._events[-1]

    def subscribe(self, fn: Callable[[dict[str, Any]], None], after: int | None = None) -> list[dict[str, Any]]:
        """Call `fn` with every entry appended from now on. Returns the entries after seq `after` (none if None).
        Both happen under the lock, so backlog + live entries have no gap and no duplicate."""
        with self._lock:
            self._sync()  # not self.events: that property takes the (non-reentrant) lock we already hold
            self._listeners.append(fn)
            return [] if after is None else self._events[max(after + 1, 0):]

    def unsubscribe(self, fn: Callable[[dict[str, Any]], None]) -> None:
        with self._lock:
            if fn in self._listeners:
                self._listeners.remove(fn)

    @property
    def subscribers(self) -> int:
        return len(self._listeners)

    def verify(self) -> dict[str, Any]:
        # Match the writer's locking: readers cannot observe the short interval between
        # the durable log append and the checkpoint's atomic replacement.
        with self._lock:
            if not self.path.exists():
                return self._verify()
            with self.path.open("r") as f:
                if fcntl:
                    fcntl.flock(f, fcntl.LOCK_SH)
                return self._verify()

    def _verify(self) -> dict[str, Any]:
        prev = "0" * 64
        lines = [ln for ln in self.path.read_text().splitlines() if ln.strip()] if self.path.exists() else []
        for i, line in enumerate(lines):
            try:
                e = json.loads(line)
            except ValueError:
                return {"ok": False, "entries": len(lines), "broken_at": i}
            if not isinstance(e, dict) or e.get("prev_hash") != prev or self._digest(prev, e) != e.get("hash"):
                return {"ok": False, "entries": len(lines), "broken_at": i}
            prev = e["hash"]
        if self.checkpoint.exists():
            try:
                head = json.loads(self.checkpoint.read_text())
            except ValueError:
                return {"ok": False, "entries": len(lines), "broken_at": len(lines)}
            if head != {"entries": len(lines), "head": prev}:
                return {"ok": False, "entries": len(lines), "broken_at": len(lines), "reason": "audit checkpoint mismatch"}
        elif self._events:
            return {"ok": False, "entries": len(lines), "broken_at": len(lines), "reason": "audit checkpoint missing"}
        return {"ok": True, "entries": len(lines), "head": prev}
