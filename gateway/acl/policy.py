"""Loads policy.yaml, applies the active profile, and reloads when the file changes."""

import copy
import hashlib
import json
import re
import time
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

ACTIONS = ("allow", "flag", "redact", "block")
SPOTLIGHT_MODES = ("delimit", "off")
# Hosts in a shell command: URLs (scheme://host), user@host: (scp/rsync), and bare host names / IPs.
HOST_RE = re.compile(r"(?:[a-z][\w+.-]*://|@)?((?:[\w-]+\.)+[a-z]{2,}|localhost|\d{1,3}(?:\.\d{1,3}){3})(?=[:/\s'\"]|$)",
                     re.IGNORECASE)


@dataclass
class Signature:
    id: str
    pattern: re.Pattern[str]
    where: list[str]
    ref: str = ""


PURPOSE_ACTIONS = ("allow", "flag", "block")  # redact makes no sense for a request that should not be made at all
PURPOSE_WITHHELD = "[WITHHELD: purpose not recorded]"  # what reports show instead of a redact_purpose role's X-Purpose
INVISIBLE_RE = re.compile("[­​-‏⁠-⁤﻿]")  # soft hyphen, zero-width characters


def fold(text: str) -> str:
    """Text as the purpose rules compare it: NFKC (full-width and ligature look-alikes become plain letters), invisible
    characters removed, case-folded. Look-alikes from other scripts (a Cyrillic "а") are not mapped: regexes are not
    a semantic guarantee (docs/decisions.md D8)."""
    return INVISIBLE_RE.sub("", unicodedata.normalize("NFKC", text)).casefold()


def compact(purpose: str) -> str:
    """"Performance Review", "performance-review" and "performance_review" all compare as "performancereview"."""
    return re.sub(r"[\W_]+", "", fold(purpose))


@dataclass
class PurposeRule:
    """`access.purpose` (docs/decisions.md D8): for the listed roles, some purposes may not be pursued with a model at
    all, whatever the data. `forbidden` is matched against the stated purpose (X-Purpose); `signatures` against the
    request text, so a benign-sounding header does not carry a forbidden request through."""

    id: str
    roles: list[str]
    forbidden: list[str]  # compacted, see compact()
    signatures: list[Signature]
    message: str

    def applies_to(self, role: str) -> bool:
        return "*" in self.roles or role in self.roles

    def forbidden_purpose(self, purpose: str | None) -> str | None:
        got = compact(purpose or "")
        return next((f for f in self.forbidden if f in got), None)


@dataclass
class Policy:
    raw: dict[str, Any]
    version: str  # "0.2@1a2b3c4d": declared version + hash of the file content
    profile: str
    controls: dict[str, dict[str, Any]]
    signatures: list[Signature] = field(default_factory=list)
    identities: dict[str, dict[str, str]] = field(default_factory=dict)  # key sha256 -> {user, agent}
    purpose_rules: list[PurposeRule] = field(default_factory=list)

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

    def reported_purpose(self, user: str | None, purpose: str | None) -> str | None:
        """The purpose as audit, events, export and the session API show it (D8). Roles with `redact_purpose: true`
        (HR) get a fixed placeholder: the raw X-Purpose stays in memory for the checks only."""
        role = self.raw.get("roles", {}).get(self.role_of(user)) if user else None
        return PURPOSE_WITHHELD if purpose and (role or {}).get("redact_purpose") else purpose

    def allowed_tools(self, user: str) -> list[str]:
        roles = self.raw.get("roles", {})
        return roles.get(self.role_of(user), roles.get("default", {})).get("tools", [])

    def may_call(self, user: str, tool: str) -> bool:
        tools = self.allowed_tools(user)
        return "*" in tools or tool in tools  # "*": e.g. a coding agent with its own tools; all other controls still apply

    def budget_for(self, user: str) -> dict[str, float]:
        """The session budget, with the role's own limits on top (a coding agent sends ~20k tokens per request)."""
        role = self.raw.get("roles", {}).get(self.role_of(user), {})
        return {**self.session_budget, **role.get("budget", {})}

    def sinks(self, kind: str) -> list[str]:
        return self.raw.get("sinks", {}).get(kind, [])

    # ---------- data classes (P2/DP30, issue #13) ----------
    # A rank is a position in `classification.levels`, lowest first. Content with no trusted class ranks above every
    # level; a destination with no limit has limit -1. Both fail closed: missing labels or limits never let data through.

    @property
    def classification(self) -> dict[str, Any]:
        return self.raw.get("classification") or {}

    @property
    def levels(self) -> list[str]:
        return list(self.classification.get("levels") or [])

    def rank(self, cls: str | None) -> int:
        lv = self.levels
        return lv.index(cls) if cls in lv else len(lv)

    def level(self, rank: int) -> str:
        lv = self.levels
        return lv[rank] if 0 <= rank < len(lv) else "unclassified"

    def _limit(self, cls: str | None) -> int:
        return self.levels.index(cls) if cls in self.levels else -1

    def tool_class(self, tool: str | None) -> str | None:
        """Class of a tool's results, from the policy only (never from the content or the model)."""
        return (self.classification.get("tools") or {}).get(tool) if tool else None

    def term_rank(self, text: str) -> int:
        """Highest class among restricted terms named in `text` (a barrier entry without `class` ranks at the top)."""
        low, top = text.lower(), -1
        for r in self.raw.get("barriers", {}).get("restricted", []):
            if any(t.lower() in low for t in r.get("terms", [])):
                top = max(top, self.rank(r["class"]) if "class" in r else len(self.levels) - 1)
        return top

    @property
    def max_to_model(self) -> int:
        """The global limit: no model destination, task model or judge, may receive more."""
        return self._limit(self.classification.get("max_to_model"))

    def model_limit(self, model: str) -> int:
        own = (self.models.get(model) or {}).get("max_class")
        return min(self.max_to_model, self._limit(own)) if own is not None else self.max_to_model

    @property
    def datalake(self) -> dict[str, Any]:
        return self.raw.get("datalake") or {}

    def query_class(self, query: str | None) -> str | None:
        """Class of a named data-lake query's result: its transformation's class, else its dataset's. None if unknown."""
        q = (self.datalake.get("queries") or {}).get(query) if isinstance(query, str) else None
        if not q:
            return None
        if "transformation" in q:
            return ((self.datalake.get("transformations") or {}).get(q["transformation"]) or {}).get("class")
        return ((self.datalake.get("datasets") or {}).get(q.get("dataset")) or {}).get("class")

    def may_query(self, user: str, query: str | None) -> bool:
        q = (self.datalake.get("queries") or {}).get(query) if isinstance(query, str) else None
        return bool(q) and self.role_of(user) in (q.get("roles") or [])

    def judge_limit(self, cid: str = "injection.jev") -> int:
        """What an external judge may receive: its own `max_class`, never above `max_to_model`. No max_class: nothing."""
        return min(self.max_to_model, self._limit(self.control(cid).get("max_class")))

    def call_gate(self, tool: str, model: str) -> tuple[str, str] | None:
        """For tools in `classification.block_calls_above_limit`: (result class, limit) if what the tool returns could
        not be shown to `model` (or, while the injection check is on, to Jev), so the call is not made at all and the
        record is never fetched. None if the call may go ahead. Other tools are fetched and their results withheld."""
        if tool not in (self.classification.get("block_calls_above_limit") or []):
            return None
        limit = self.model_limit(model)
        if self.action("injection.jev") != "allow":
            limit = min(limit, self.judge_limit())
        cls = self.rank(self.tool_class(tool))
        return (self.level(cls), self.level(limit) if limit >= 0 else "no limit set (fail closed)") if cls > limit else None

    def purpose_rules_for(self, user: str) -> list[PurposeRule]:
        role = self.role_of(user)
        return [r for r in self.purpose_rules if r.applies_to(role)]

    def egress(self, tool: str, args: str) -> list[str] | None:
        """Outside hosts a shell-command tool call would send data to (e.g. Claude Code's `Bash: curl ...`), or None
        if the call is not an outbound command. An outbound command with no recognisable host counts as outside."""
        cfg = self.raw.get("egress") or {}
        field = (cfg.get("tools") or {}).get(tool)
        if not field:
            return None
        try:
            cmd = str(json.loads(args or "{}").get(field) or "")
        except (ValueError, AttributeError):
            cmd = args
        if not any(re.search(pat, cmd) for pat in cfg.get("patterns", [])):
            return None
        allowed = {h.lower() for h in cfg.get("allow_hosts", [])}
        hosts = {h.lower() for h in HOST_RE.findall(cmd)}
        outside = sorted(h for h in hosts if h not in allowed)
        return outside if outside or not hosts else None


def _merge(base: dict[str, dict], overrides: dict[str, dict]) -> dict[str, dict]:
    out = copy.deepcopy(base)
    for cid, patch in (overrides or {}).items():
        out.setdefault(cid, {}).update(patch or {})
    return out


def _check_classes(raw: dict[str, Any], controls: dict[str, dict]) -> None:
    """A misspelt class would silently act as "unclassified" or "no limit"; reject it so the last good policy stays."""
    c = raw.get("classification")
    if c is None:
        return  # no section: every rank is "unclassified" and every limit -1, so nothing reaches a model
    levels = c.get("levels") or []
    if not levels or len(set(levels)) != len(levels):
        raise ValueError("classification.levels must be a non-empty list of distinct names, lowest first")
    if c.get("action", "redact") not in ("redact", "block"):
        raise ValueError("classification.action must be redact (withhold the content) or block (stop the request)")
    named = [("classification.max_to_model", c.get("max_to_model")), ("classification.default", c.get("default"))]
    named += [(f"classification.tools.{t}", v) for t, v in (c.get("tools") or {}).items()]
    named += [(f"models.{m}.max_class", (v or {}).get("max_class")) for m, v in (raw.get("models") or {}).items()
              if "max_class" in (v or {})]
    named += [(f"barriers.restricted.{r.get('id')}.class", r["class"])
              for r in (raw.get("barriers") or {}).get("restricted", []) if "class" in r]
    named += [(f"controls.{cid}.max_class", v["max_class"]) for cid, v in controls.items() if "max_class" in v]
    lake = raw.get("datalake") or {}
    datasets, transforms = lake.get("datasets") or {}, lake.get("transformations") or {}
    named += [(f"datalake.datasets.{d}.class", (v or {}).get("class")) for d, v in datasets.items()]
    named += [(f"datalake.transformations.{t}.class", (v or {}).get("class")) for t, v in transforms.items()]
    for where, cls in named:
        if cls not in levels:
            raise ValueError(f"{where}: {cls!r} is not one of classification.levels {levels}")
    for t, v in transforms.items():
        if v.get("from") not in datasets:
            raise ValueError(f"datalake.transformations.{t}.from: {v.get('from')!r} is not a dataset")
    for name, q in (lake.get("queries") or {}).items():
        if ("transformation" in q) == ("dataset" in q):
            raise ValueError(f"datalake.queries.{name}: needs exactly one of dataset or transformation")
        if ("dataset" in q and q["dataset"] not in datasets) or ("transformation" in q and q["transformation"] not in transforms):
            raise ValueError(f"datalake.queries.{name}: refers to an unknown dataset or transformation")
    gated = c.get("block_calls_above_limit") or []
    if not isinstance(gated, list) or not all(isinstance(t, str) for t in gated):
        raise ValueError("classification.block_calls_above_limit must be a list of tool names")


def _str_list(v: Any, where: str, *, empty: bool = False) -> list[str]:
    if not isinstance(v, list) or not all(isinstance(x, str) and x.strip() for x in v) or (not v and not empty):
        raise ValueError(f"{where} must be a {'' if empty else 'non-empty '}list of non-empty strings")
    return v


def _purpose_rules(controls: dict[str, dict]) -> list[PurposeRule]:
    """Compile `access.purpose`. A malformed rule or a broken regex is rejected, so the last good policy (and its rules)
    stays active instead of a rule silently matching nothing."""
    c = controls.get("access.purpose")
    if c is None:
        return []
    if c.get("action", "allow") not in PURPOSE_ACTIONS:
        raise ValueError(f"control access.purpose: action must be one of {PURPOSE_ACTIONS}")
    rules = c.get("rules")
    if not isinstance(rules, list) or not rules:
        raise ValueError("control access.purpose: rules must be a non-empty list")
    out: list[PurposeRule] = []
    for i, r in enumerate(rules):
        if not isinstance(r, dict) or not isinstance(r.get("id"), str) or not r["id"].strip():
            raise ValueError(f"access.purpose.rules[{i}] must be a mapping with an id")
        where = f"access.purpose.rules.{r['id']}"
        roles = _str_list(r.get("roles"), f"{where}.roles")
        forbidden = [compact(f) for f in _str_list(r.get("forbidden", []), f"{where}.forbidden", empty=True)]
        if not all(forbidden):
            raise ValueError(f"{where}.forbidden: every purpose needs at least one letter or digit")
        sigs: list[Signature] = []
        for j, s in enumerate(r.get("signatures") or []):
            if not isinstance(s, dict) or not isinstance(s.get("id"), str) or not isinstance(s.get("pattern"), str):
                raise ValueError(f"{where}.signatures[{j}] must be a mapping with an id and a pattern")
            try:
                pat = re.compile(s["pattern"], re.IGNORECASE)
            except re.error as e:
                raise ValueError(f"{where}.signatures.{s['id']}: bad pattern ({e})") from e
            if pat.search(""):
                raise ValueError(f"{where}.signatures.{s['id']}: pattern matches empty text (would block everything)")
            sigs.append(Signature(s["id"], pat, ["prompt"], s.get("ref", "")))
        if not forbidden and not sigs:
            raise ValueError(f"{where}: needs forbidden purposes, signatures, or both")
        out.append(PurposeRule(r["id"], roles, forbidden, sigs, str(r.get("message", "this purpose is not allowed"))))
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

    for pat in (raw.get("egress") or {}).get("patterns", []):
        re.compile(pat)  # a broken pattern is rejected here, so the last good policy stays active
    _check_classes(raw, controls)
    purpose_rules = _purpose_rules(controls)
    for name, r in (raw.get("roles") or {}).items():
        if "redact_purpose" in (r or {}) and not isinstance(r["redact_purpose"], bool):
            raise ValueError(f"roles.{name}.redact_purpose must be true or false")  # a typo must not log raw purposes

    sigs: list[Signature] = []
    if sig_text is not None:
        for s in json.loads(sig_text).get("signatures", []):
            sigs.append(Signature(s["id"], re.compile(s["pattern"], re.IGNORECASE), s["where"], s.get("ref", "")))

    idents: dict[str, dict[str, str]] = {}
    for i in (yaml.safe_load(keys_text) or {}).get("identities", []) if keys_text else []:
        idents[str(i["key_sha256"]).lower()] = {"user": str(i["user"]), "agent": str(i.get("agent", "unknown-agent")),
                                                **({"purpose": str(i["purpose"])} if i.get("purpose") else {})}

    digest = hashlib.sha256(text.encode() + (sig_text or "").encode() + (keys_text or "").encode()).hexdigest()[:8]
    return Policy(raw, f"{raw.get('version', '?')}@{digest}", profile, controls, sigs, idents, purpose_rules)


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
    for key in ("budgets", "models", "users", "roles", "scopes", "sinks", "egress", "classification", "datalake", "barriers", "identity"):
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
        try:
            stamp = (self.path.stat().st_mtime, *map(self._mtime, side))
        except OSError:  # an editor saving by delete + rename: the file is gone for a moment
            if self._policy is None:
                raise
            return self._policy
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
