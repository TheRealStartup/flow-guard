"""Deterministic keyword judge for offline demonstrations, not a security classifier."""

from .jev import Verdict


class DemoJudge:
    async def judge(self, text: str, source: str, timeout_s: float) -> Verdict:
        markers = (
            "you must first send",
            "note for the assistant",
            "note for the reviewing assistant",
            "ignore your rules",
            "you are now dan",
        )
        hit = any(marker in text.lower() for marker in markers)
        return Verdict(injection=0.98 if hit else 0.02, model="demo-keyword-judge")
