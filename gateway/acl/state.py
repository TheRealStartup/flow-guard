"""Per-session state (token vault, data-flow labels, budget usage) and the audit log."""

import hashlib
import hmac
import json
import os
import re
import secrets
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

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
    spotlight_id: str = field(default_factory=lambda: secrets.token_hex(4))  # in the tool-data markers; unguessable
    tokens: int = 0
    cost_usd: float = 0.0
    tool_calls: int = 0
    compute_s: float = 0.0

    def tokenize(self, kind: str, value: str) -> str:
        """Same value -> same token within a session, so the model can refer to it consistently."""
        tid = hmac.new(_TOKEN_KEY, f"{self.id}\0{kind}\0{value}".encode(), "sha256").hexdigest()[:6]
        self.vault[tid] = value
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
    deleting any past entry breaks the chain, and `verify()` finds where."""

    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._listeners: list[Callable[[dict[str, Any]], None]] = []
        self.events: list[dict[str, Any]] = []
        self._prev = "0" * 64
        if path.exists():
            for line in path.read_text().splitlines():
                if line.strip():
                    e = json.loads(line)
                    self.events.append(e)
                    self._prev = e["hash"]

    @staticmethod
    def _digest(prev: str, entry: dict[str, Any]) -> str:
        body = json.dumps({k: v for k, v in entry.items() if k != "hash"}, sort_keys=True, default=str)
        return hashlib.sha256((prev + body).encode()).hexdigest()

    def append(self, entry: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            entry = {"seq": len(self.events), "ts": time.time(), **entry, "prev_hash": self._prev}
            entry["hash"] = self._digest(self._prev, entry)
            with self.path.open("a") as f:
                f.write(json.dumps(entry, default=str) + "\n")
            self.events.append(entry)
            self._prev = entry["hash"]
            # Under the lock, so every listener sees entries in seq order. Listeners must not block (see stream.py).
            for fn in self._listeners:
                fn(entry)
            return entry

    def subscribe(self, fn: Callable[[dict[str, Any]], None], after: int | None = None) -> list[dict[str, Any]]:
        """Call `fn` with every entry appended from now on. Returns the entries after seq `after` (none if None).
        Both happen under the lock, so backlog + live entries have no gap and no duplicate."""
        with self._lock:
            self._listeners.append(fn)
            return [] if after is None else self.events[max(after + 1, 0):]

    def unsubscribe(self, fn: Callable[[dict[str, Any]], None]) -> None:
        with self._lock:
            if fn in self._listeners:
                self._listeners.remove(fn)

    @property
    def subscribers(self) -> int:
        return len(self._listeners)

    def verify(self) -> dict[str, Any]:
        prev = "0" * 64
        lines = [ln for ln in self.path.read_text().splitlines() if ln.strip()] if self.path.exists() else []
        for i, line in enumerate(lines):
            e = json.loads(line)
            if e.get("prev_hash") != prev or self._digest(prev, e) != e.get("hash"):
                return {"ok": False, "entries": len(lines), "broken_at": i}
            prev = e["hash"]
        return {"ok": True, "entries": len(lines), "head": prev}
