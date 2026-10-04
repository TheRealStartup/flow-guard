"""Loads policy.yaml, applies the active profile, and reloads when the file changes."""

import copy
import hashlib
import json
import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

ACTIONS = ("allow", "flag", "redact", "block")
SPOTLIGHT_MODES = ("delimit", "off")


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
    identities: dict[str, dict[str, str]] = field(default_factory=dict)  # key sha256 -> {user, agent}

    @property
    def identity(self) -> dict[str, Any]:
        return {"mode": "api_key", "require_purpose": True, **self.raw.get("identity", {})}

    def identify(self, api_key: str | None) -> dict[str, str] | None:
        """Who is calling? Compares the SHA-256 of the presented key; the key itself is never stored."""
        if not api_key:
            return None
        return self.identities.get(hashlib.sha256(api_key.encode()).hexdigest())

    def control(self, cid: str) -> dict[str, Any]:
        return self.controls.get(cid, {"action": "allow"})

    def action(self, cid: str) -> str:
        return self.control(cid).get("action", "allow")

    @property
    def spotlight(self) -> str | None:
        """How tool results are marked as data before the model sees them, or None when off (no control, or mode: off)."""
        c = self.controls.get("spotlight")
        mode = c.get("mode", "delimit") if c else "off"
        return None if mode == "off" else mode

    def on_error(self, cid: str) -> str:
        return self.control(cid).get("on_error", self.raw.get("defaults", {}).get("on_error", "block"))

    @property
    def models(self) -> dict[str, dict[str, Any]]:
        return self.raw.get("models", {})

    @property
    def session_budget(self) -> dict[str, float]:
        return self.raw.get("budgets", {}).get("session", {})

    def user(self, user: str) -> dict[str, Any]:
        return self.raw.get("users", {}).get(user, {})

    @property
    def barrier_message(self) -> str:
        return self.raw.get("barriers", {}).get("public_message", "Some results are outside your access.")

    def restricted_hits(self, text: str) -> list[str]:
        """Ids of restricted deals named in `text` (case-insensitive match on their terms)."""
        low = text.lower()
        return [r["id"] for r in self.raw.get("barriers", {}).get("restricted", [])
                if any(t.lower() in low for t in r.get("terms", []))]

    def cleared(self, user: str, deal_id: str) -> bool:
        return deal_id in self.user(user).get("deals", [])

    def scope_for(self, tool: str) -> dict[str, Any] | None:
        return self.raw.get("scopes", {}).get(tool)

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


def parse(text: str, base_dir: Path, sig_text: str | None = None, keys_text: str | None = None) -> Policy:
    raw = yaml.safe_load(text) or {}
    profile = raw.get("active_profile", "balanced")
    profiles = raw.get("profiles", {})
    if profile not in profiles:
        raise ValueError(f"active_profile {profile!r} is not defined in profiles")
    controls = _merge(raw.get("controls", {}), profiles[profile])
    for cid, c in controls.items():
        if c.get("action", "allow") not in ACTIONS:
            raise ValueError(f"control {cid}: action must be one of {ACTIONS}")
    if controls.get("spotlight", {}).get("mode", "delimit") not in SPOTLIGHT_MODES:
        raise ValueError(f"control spotlight: mode must be one of {SPOTLIGHT_MODES}")

    sigs: list[Signature] = []
    if sig_text is not None:
        for s in json.loads(sig_text).get("signatures", []):
            sigs.append(Signature(s["id"], re.compile(s["pattern"], re.IGNORECASE), s["where"], s.get("ref", "")))

    idents: dict[str, dict[str, str]] = {}
    for i in (yaml.safe_load(keys_text) or {}).get("identities", []) if keys_text else []:
        idents[str(i["key_sha256"]).lower()] = {"user": str(i["user"]), "agent": str(i.get("agent", "unknown-agent"))}

    digest = hashlib.sha256(text.encode() + (sig_text or "").encode() + (keys_text or "").encode()).hexdigest()[:8]
    return Policy(raw, f"{raw.get('version', '?')}@{digest}", profile, controls, sigs, idents)


def set_control_action(text: str, cid: str, action: str) -> str:
    """Return policy.yaml text with `controls.<cid>.action` set to `action`, touching only that value, so the
    file's comments and layout survive (a YAML round-trip would drop them). Raises ValueError if it can't."""
    if action not in ACTIONS:
        raise ValueError(f"action must be one of {ACTIONS}")
    lines = text.splitlines(keepends=True)
    start = next((i for i, ln in enumerate(lines) if re.match(r"controls:\s*(#.*)?$", ln)), None)
    if start is None:
        raise ValueError("policy.yaml has no controls section")
    key = re.compile(rf"^  {re.escape(cid)}:")
    for i in range(start + 1, len(lines)):
        ln = lines[i]
        if ln.strip() and not ln.startswith(" ") and not ln.lstrip().startswith("#"):
            break  # next top-level key: the controls section ended
        if not key.match(ln):
            continue
        # Inline mapping on the key's line ({action: redact, ...}), else the indented block below it.
        for j in range(i, len(lines)):
            if j > i and lines[j].strip() and not lines[j].startswith("    ") and not lines[j].lstrip().startswith("#"):
                break
            m = re.search(r"(\baction:\s*)([A-Za-z]+)", lines[j].split("#", 1)[0])
            if m:
                lines[j] = lines[j][: m.start(2)] + action + lines[j][m.end(2):]
                return "".join(lines)
        raise ValueError(f"control {cid} has no action to change")
    raise ValueError(f"no control {cid!r} in policy.yaml")


def diff(old: Policy | None, new: Policy) -> list[dict[str, Any]]:
    """What a reload changed, field by field, in the *effective* controls (after the profile is applied)."""
    if old is None:
        return []
    out: list[dict[str, Any]] = []
    if old.profile != new.profile:
        out.append({"what": "active_profile", "old": old.profile, "new": new.profile})
    for cid in sorted(set(old.controls) | set(new.controls)):
        a, b = old.controls.get(cid), new.controls.get(cid)
        if a is None or b is None:
            out.append({"what": f"controls.{cid}", "old": a, "new": b})
            continue
        for k in sorted(set(a) | set(b)):
            if a.get(k) != b.get(k):
                out.append({"what": f"controls.{cid}.{k}", "old": a.get(k), "new": b.get(k)})
    for key in ("budgets", "models", "users", "roles", "sinks", "identity"):
        if old.raw.get(key) != new.raw.get(key):
            out.append({"what": key, "old": old.raw.get(key), "new": new.raw.get(key)})
    if [x.id for x in old.signatures] != [x.id for x in new.signatures]:
        out.append({"what": "signatures", "old": [x.id for x in old.signatures], "new": [x.id for x in new.signatures]})
    if old.identities.keys() != new.identities.keys():
        out.append({"what": "identities", "old": sorted(v["user"] for v in old.identities.values()),
                    "new": sorted(v["user"] for v in new.identities.values())})
    return out


class PolicyStore:
    """Holds the current policy. `get()` re-reads the files when their mtime changes.

    A broken edit keeps the last good policy and reports the error, so a judge's typo
    never takes the gateway down (and never silently disables controls).
    """

    def __init__(self, path: Path, on_change: Callable[[dict[str, Any]], None] | None = None):
        self.path = path
        self._stamp: tuple[float, ...] | None = None
        self._policy: Policy | None = None
        self.last_error: str | None = None
        self.history: list[dict[str, Any]] = []  # newest last, at most 20: what changed, when, or why a reload failed
        self.on_change = on_change

    def _record(self, entry: dict[str, Any]) -> None:
        self.history = [*self.history, {"ts": time.time(), **entry}][-20:]
        if self.on_change:
            self.on_change(self.history[-1])

    def _side_files(self, raw: dict) -> tuple[Path | None, Path | None]:
        """The signature feed and the identities file, both named in policy.yaml and watched too."""
        feed = raw.get("controls", {}).get("signatures", {}).get("feed")
        keys = raw.get("identity", {}).get("keys_file")
        return (self.path.parent / feed if feed else None, self.path.parent / keys if keys else None)

    @staticmethod
    def _mtime(p: Path | None) -> float:
        return p.stat().st_mtime if p and p.exists() else 0.0

    @staticmethod
    def _read(p: Path | None) -> str | None:
        return p.read_text() if p and p.exists() else None

    def get(self) -> Policy:
        side = self._side_files(self._policy.raw) if self._policy else (None, None)
        stamp = (self.path.stat().st_mtime, *map(self._mtime, side))
        if self._policy is None or stamp != self._stamp:
            try:
                text = self.path.read_text()
                feed, keys = self._side_files(yaml.safe_load(text) or {})
                new = parse(text, self.path.parent, self._read(feed), self._read(keys))
                old, self._policy = self._policy, new
                self.last_error = None
                if old is None or old.version != new.version:
                    self._record({"version": new.version, "previous": old.version if old else None,
                                  "profile": new.profile, "changes": diff(old, new), "error": None})
            except Exception as e:  # keep the last good policy
                if self._policy is None:
                    raise
                self.last_error = f"{type(e).__name__}: {e}"
                self._record({"version": self._policy.version, "previous": self._policy.version,
                              "profile": self._policy.profile, "changes": [],
                              "error": f"{self.last_error} (kept the last good policy)"})
            self._stamp = stamp
        return self._policy
