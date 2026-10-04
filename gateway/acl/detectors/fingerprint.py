"""Fingerprints of the bank's own confidential documents and secrets (experimental, branch feature/leak-fingerprints).

Pattern detectors know what a card number *looks like*; they cannot know that a paragraph is the Falcon deal memo.
Here the bank registers its documents and secrets, and the gateway keeps only keyed fingerprints of them (HMAC with a
key the gateway holds), never the text. Outgoing text is fingerprinted the same way and compared.

- Documents: winnowing (Schleimer, Wilkerson, Aiken 2003, the algorithm behind the Moss plagiarism checker). The text
  is normalised (case, punctuation, spacing), cut into overlapping k-character grams, and in every window of w grams
  the smallest hash is kept. Any shared passage of at least k + w - 1 normalised characters is guaranteed to share a
  fingerprint, wherever it sits in the message and whatever surrounds it, so split, reordered or re-assembled pieces
  still match. Fingerprints shared by several registered documents (templates, disclaimers) are dropped when the
  registry is built, so boilerplate does not raise alarms.
- Secrets: every window of SECRET_K characters of the secret is fingerprinted, so half a key, or a key split over
  several messages, still matches.

What it cannot see: paraphrase, summary or translation (the wording changes, so the hashes do). That needs a semantic
layer on top; see docs/decisions.md.
"""

import hashlib
import hmac
import json
import os
import re
import secrets
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path

K = 25  # characters per gram (after normalisation)
W = 26  # grams per winnowing window: any shared run of K + W - 1 = 50 normalised characters is found
SECRET_K = 8  # characters per window of a registered secret
NON_ALNUM = re.compile(r"[^0-9a-z]+")


def normalise(text: str) -> str:
    """Case, accents, punctuation and spacing do not matter: "Project  Falcon," and "project falcon" are equal."""
    text = unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode().lower()
    return NON_ALNUM.sub("", text)


def _h(key: bytes, s: str) -> str:
    return hmac.new(key, s.encode(), hashlib.sha256).hexdigest()[:16]


def winnow(text: str, key: bytes, k: int = K, w: int = W) -> set[str]:
    norm = normalise(text)
    grams = [_h(key, norm[i : i + k]) for i in range(len(norm) - k + 1)]
    if not grams:
        return set()
    if len(grams) <= w:
        return {min(grams)}
    return {min(grams[i : i + w]) for i in range(len(grams) - w + 1)}


def secret_windows(value: str, key: bytes, k: int = SECRET_K) -> set[str]:
    norm = normalise(value)
    return {_h(key, norm[i : i + k]) for i in range(max(len(norm) - k + 1, 1))} if norm else set()


def load_key(path: Path) -> bytes:
    """The fingerprint key: FLOWGUARD_FP_KEY, else a key file next to the audit log, created on first use."""
    if os.getenv("FLOWGUARD_FP_KEY"):
        return os.environ["FLOWGUARD_FP_KEY"].encode()
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(secrets.token_hex(32))
        path.chmod(0o600)
    return path.read_text().strip().encode()


def build_registry(docs: list[dict], secret_values: list[dict], key: bytes) -> dict:
    """docs: [{id, title, class, text}], secret_values: [{id, title, value}] -> the registry, fingerprints only."""
    fps = {d["id"]: winnow(d["text"], key) for d in docs}
    seen: dict[str, int] = {}
    for f in fps.values():
        for x in f:
            seen[x] = seen.get(x, 0) + 1
    out_docs = []
    for d in docs:
        rare = sorted(x for x in fps[d["id"]] if seen[x] == 1)  # shared with another document: boilerplate, dropped
        out_docs.append({"id": d["id"], "title": d.get("title", d["id"]), "class": d.get("class"), "fingerprints": rare})
    out_secrets = [{"id": s["id"], "title": s.get("title", s["id"]), "windows": sorted(secret_windows(s["value"], key)),
                    "length": len(normalise(s["value"]))} for s in secret_values]
    return {"k": K, "w": W, "secret_k": SECRET_K, "documents": out_docs, "secrets": out_secrets}


@dataclass
class Registry:
    documents: dict[str, dict] = field(default_factory=dict)  # id -> {title, class, fingerprints: set}
    secrets: dict[str, dict] = field(default_factory=dict)  # id -> {title, windows: set, needed: int}

    @classmethod
    def load(cls, path: Path) -> "Registry":
        raw = json.loads(path.read_text())
        if (raw.get("k"), raw.get("w"), raw.get("secret_k")) != (K, W, SECRET_K):
            raise ValueError("fingerprint registry built with other parameters; rebuild it")
        docs = {d["id"]: {**d, "fingerprints": set(d["fingerprints"])} for d in raw.get("documents", []) if d["fingerprints"]}
        secs = {}
        for s in raw.get("secrets", []):
            windows = set(s["windows"])
            # A match needs a run of windows covering at least half the secret (and at least one full window).
            secs[s["id"]] = {**s, "windows": windows, "needed": max(1, (s.get("length", SECRET_K) // 2) - SECRET_K + 1)}
        return cls(docs, secs)

    def match(self, text: str, key: bytes) -> tuple[dict[str, set[str]], dict[str, set[str]]]:
        """Which fingerprints of which registered documents and secrets this text contains. Secret pieces count from
        two windows on (a single 8-character window can occur by chance); the caller adds them up across messages."""
        doc_hits = {}
        if self.documents:
            out = winnow(text, key)
            for did, d in self.documents.items():
                if hit := out & d["fingerprints"]:
                    doc_hits[did] = hit
        secret_hits = {}
        if self.secrets:
            windows = secret_windows(text, key)
            for sid, s in self.secrets.items():
                if len(hit := windows & s["windows"]) >= 2:
                    secret_hits[sid] = hit
        return doc_hits, secret_hits
