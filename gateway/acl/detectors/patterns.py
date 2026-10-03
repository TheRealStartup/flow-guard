"""Deterministic (non-AI) detectors: payment cards, IBANs, PESEL numbers, secrets.

Each detector returns spans (start, end, kind, value). Checksums (Luhn, IBAN mod-97,
PESEL weights) keep false positives low: a random 16-digit order number is not a card.
"""

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Span:
    start: int
    end: int
    kind: str  # CARD | IBAN | PESEL | PASSPORT | SECRET
    value: str
    control: str  # policy control id that owns this detector


def luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d = d * 2 - 9 if d > 4 else d * 2
        total += d
    return total % 10 == 0


def iban_ok(iban: str) -> bool:
    s = iban[4:] + iban[:4]
    return int("".join(str(int(c, 36)) for c in s)) % 97 == 1


def pesel_ok(p: str) -> bool:
    w = (1, 3, 7, 9, 1, 3, 7, 9, 1, 3)
    return (10 - sum(int(a) * b for a, b in zip(p, w)) % 10) % 10 == int(p[10])


CARD_RE = re.compile(r"(?<![\d-])(?:\d[ -]?){12,18}\d(?![\d-])")
IBAN_RE = re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b")
PESEL_RE = re.compile(r"(?<!\d)\d{11}(?!\d)")
# Passport numbers have no common checksum, so we only take them where the text says so ("passport": "C01X00T47").
PASSPORT_RE = re.compile(r"passport(?:[ _-]?(?:no|number|nr))?[\"']?\s*[:=]?\s*[\"']?((?=[A-Z0-9]*\d)[A-Z0-9]{6,9})\b", re.IGNORECASE)
SECRET_RES = [
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),  # AWS access key id
    re.compile(r"\bsk-(?:or-|ant-|proj-)?[A-Za-z0-9_-]{20,}"),  # OpenAI / Anthropic / OpenRouter
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36}\b"),  # GitHub tokens
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
]


def find_sensitive(text: str) -> list[Span]:
    spans: list[Span] = []
    for m in CARD_RE.finditer(text):
        digits = re.sub(r"\D", "", m.group())
        if 13 <= len(digits) <= 19 and luhn_ok(digits):
            spans.append(Span(m.start(), m.end(), "CARD", digits, "pii.card"))
    for m in IBAN_RE.finditer(text):
        compact = m.group().replace(" ", "")
        if 15 <= len(compact) <= 34 and iban_ok(compact):
            spans.append(Span(m.start(), m.end(), "IBAN", compact, "pii.iban"))
    for m in PESEL_RE.finditer(text):
        if pesel_ok(m.group()):
            spans.append(Span(m.start(), m.end(), "PESEL", m.group(), "pii.pesel"))
    for m in PASSPORT_RE.finditer(text):
        spans.append(Span(m.start(1), m.end(1), "PASSPORT", m.group(1), "pii.passport"))
    for rx in SECRET_RES:
        for m in rx.finditer(text):
            spans.append(Span(m.start(), m.end(), "SECRET", m.group(), "secrets"))
    # Drop spans that overlap an earlier, longer one (e.g. digits of an IBAN read as a PESEL).
    spans.sort(key=lambda s: (s.start, -(s.end - s.start)))
    out: list[Span] = []
    for s in spans:
        if not out or s.start >= out[-1].end:
            out.append(s)
    return out
