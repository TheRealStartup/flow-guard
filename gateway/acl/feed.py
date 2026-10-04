"""The attack-signature feed, pulled from an outside source (the brief: signatures of known attacks "fed from an
externally managed system").

A security team (or a vendor) publishes the feed at a URL; `controls.signatures.feed_url` in policy.yaml says where.
The gateway fetches it on start and every `refresh_s` seconds, checks it with the same parser the policy uses
(`parse_signatures`: valid JSON, patterns compile, each signature matches its own examples), and only then writes it
to the local feed file. The policy's live reload picks the file up, so a new feed version is versioned, audited
("signatures: +2") and streamed like any policy change. A feed that cannot be fetched or fails the check is not
written: the last good signatures stay active, and the rejection is recorded once. In production the feed would also
be signed; that is on the roadmap.
"""

import asyncio
import hashlib
import time
from pathlib import Path
from typing import Any

import httpx

from .policy import PolicyStore, parse_signatures

MAX_BYTES = 1_000_000


class FeedPuller:
    def __init__(self, policies: PolicyStore, client: httpx.AsyncClient | None = None):
        self.policies = policies
        self.client = client
        self.status: dict[str, Any] = {"url": None, "checked": None, "updated": None, "version": None, "error": None}

    def _config(self) -> tuple[str | None, Path | None, float]:
        p = self.policies.get()
        c = p.control("signatures")
        feed = c.get("feed")
        return c.get("feed_url"), (self.policies.path.parent / feed if feed else None), float(c.get("refresh_s", 300))

    async def pull(self) -> dict[str, Any]:
        """Fetch once. Returns the status: whether the feed changed, and the error if it was rejected."""
        url, dest, _ = self._config()
        self.status.update(url=url, checked=time.time())
        if not url or not dest:
            self.status.update(error=None)
            return self.status
        try:
            client = self.client or httpx.AsyncClient(timeout=10, follow_redirects=True)
            try:
                r = await client.get(url)
            finally:
                if self.client is None:
                    await client.aclose()
            r.raise_for_status()
            if len(r.content) > MAX_BYTES:
                raise ValueError(f"feed larger than {MAX_BYTES} bytes")
            text = r.text
            sigs = parse_signatures(text)  # refuse anything unsound before it touches the gateway
        except Exception as e:  # noqa: BLE001 - any failure keeps the last good feed
            error = f"{type(e).__name__}: {e}"
            if error != self.status["error"]:  # record a rejection once, not on every retry
                self.policies.note({"error": f"signature feed from {url} rejected ({error}); kept the last good signatures"})
            self.status.update(error=error)
            return self.status
        version = hashlib.sha256(text.encode()).hexdigest()[:8]
        self.status.update(error=None, version=version, count=len(sigs))
        if not dest.exists() or dest.read_text() != text:
            tmp = dest.with_suffix(".tmp")
            tmp.write_text(text)
            try:
                tmp.replace(dest)
            except OSError:  # Docker Desktop on Windows: no rename over a bind-mounted file
                dest.write_text(text)
                tmp.unlink(missing_ok=True)
            self.status.update(updated=time.time())
            self.policies.get()  # reload now: the change is audited with the signature ids added and removed
        return self.status

    async def run(self) -> None:
        while True:
            await self.pull()
            await asyncio.sleep(max(self._config()[2], 10))
