"""Loads policy.yaml, applies the active profile, and reloads when the file changes."""

import copy
import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

ACTIONS = ("allow", "flag", "redact", "block")


@dataclass
class Signature:
    id: str
    pattern: re.Pattern[str]
    where: list[str]
    ref: str = ""


@dataclass
class Policy:
    raw: dict[str, Any]
    version: str  # "0.2@1a2b3c4d": declared version + hash of the file content
    profile: str
    controls: dict[str, dict[str, Any]]
    signatures: list[Signature] = field(default_factory=list)

    def control(self, cid: str) -> dict[str, Any]:
        return self.controls.get(cid, {"action": "allow"})

    def action(self, cid: str) -> str:
        return self.control(cid).get("action", "allow")

    def on_error(self, cid: str) -> str:
        return self.control(cid).get("on_error", self.raw.get("defaults", {}).get("on_error", "block"))

    @property
    def models(self) -> dict[str, dict[str, Any]]:
        return self.raw.get("models", {})

    @property
    def session_budget(self) -> dict[str, float]:
        return self.raw.get("budgets", {}).get("session", {})

    def role_of(self, user: str) -> str:
        return self.raw.get("users", {}).get(user, {}).get("role", "default")

    def allowed_tools(self, user: str) -> list[str]:
        roles = self.raw.get("roles", {})
        return roles.get(self.role_of(user), roles.get("default", {})).get("tools", [])

    def sinks(self, kind: str) -> list[str]:
        return self.raw.get("sinks", {}).get(kind, [])


def _merge(base: dict[str, dict], overrides: dict[str, dict]) -> dict[str, dict]:
    out = copy.deepcopy(base)
    for cid, patch in (overrides or {}).items():
        out.setdefault(cid, {}).update(patch or {})
    return out


def parse(text: str, base_dir: Path, sig_text: str | None = None) -> Policy:
    raw = yaml.safe_load(text) or {}
    profile = raw.get("active_profile", "balanced")
    profiles = raw.get("profiles", {})
    if profile not in profiles:
        raise ValueError(f"active_profile {profile!r} is not defined in profiles")
    controls = _merge(raw.get("controls", {}), profiles[profile])
    for cid, c in controls.items():
        if c.get("action", "allow") not in ACTIONS:
            raise ValueError(f"control {cid}: action must be one of {ACTIONS}")

    sigs: list[Signature] = []
    if sig_text is not None:
        for s in json.loads(sig_text).get("signatures", []):
            sigs.append(Signature(s["id"], re.compile(s["pattern"], re.I), s["where"], s.get("ref", "")))

    digest = hashlib.sha256(text.encode() + (sig_text or "").encode()).hexdigest()[:8]
    return Policy(raw, f"{raw.get('version', '?')}@{digest}", profile, controls, sigs)


class PolicyStore:
    """Holds the current policy. `get()` re-reads the files when their mtime changes.

    A broken edit keeps the last good policy and reports the error, so a judge's typo
    never takes the gateway down (and never silently disables controls).
    """

    def __init__(self, path: Path):
        self.path = path
        self._stamp: tuple[float, float] | None = None
        self._policy: Policy | None = None
        self.last_error: str | None = None

    def _feed_path(self, raw: dict) -> Path | None:
        feed = raw.get("controls", {}).get("signatures", {}).get("feed")
        return (self.path.parent / feed) if feed else None

    def get(self) -> Policy:
        feed = self._feed_path(self._policy.raw) if self._policy else None
        stamp = (self.path.stat().st_mtime, feed.stat().st_mtime if feed and feed.exists() else 0.0)
        if self._policy is None or stamp != self._stamp:
            try:
                text = self.path.read_text()
                feed = self._feed_path(yaml.safe_load(text) or {})
                sig_text = feed.read_text() if feed and feed.exists() else None
                self._policy = parse(text, self.path.parent, sig_text)
                self.last_error = None
            except Exception as e:  # keep the last good policy
                if self._policy is None:
                    raise
                self.last_error = f"{type(e).__name__}: {e}"
            self._stamp = stamp
        return self._policy
