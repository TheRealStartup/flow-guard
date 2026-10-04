"""Bounded inspection at provider and reporting boundaries. Never executes decoded data."""

import base64
import binascii
import hashlib
import json
import re
from typing import Any
from urllib.parse import unquote

from .detectors.patterns import find_sensitive

DISPLAY_TOKEN = re.compile(r"\[\[(?:CARD|IBAN|PESEL|PASSPORT|DOB|SECRET)#[0-9a-f]{6}(?: \*{4}[A-Z0-9]{4})?\]\]")


def masked(text: str) -> str:
    for span in reversed(find_sensitive(text)):
        text = text[:span.start] + f"[{span.kind}]" + text[span.end:]
    return text


def public_id(value: str) -> str:
    if find_sensitive(value) or len(value) > 256:
        return "masked-" + hashlib.sha256(value.encode()).hexdigest()[:24]
    return value


def reporting(value: Any, field: str = "") -> Any:
    """Mask before persistence/hashing; sensitive identifiers retain distinct stable correlation."""
    if isinstance(value, str):
        # Decision.token is generated internally. Its six-character surrogate is not a
        # labelled passport number; keep it intact so findings show the issued token.
        if field == "token" and DISPLAY_TOKEN.fullmatch(value):
            return value
        return public_id(value) if field in {"session", "user", "agent"} else masked(value)[:4096]
    if isinstance(value, dict):
        return {public_id(str(k)): reporting(v, str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [reporting(v, field) for v in value]
    return value


def encoded_variants(text: str) -> tuple[list[str], bool]:
    """Raw + JSON strings + two decoding levels, at most 64 candidates / 64 KiB total.

    This covers common encodings, not arbitrary encryption, splitting or transformations.
    The caller must refuse an external call if the inspection limit is exceeded.
    """
    limit = 65536
    if len(text) > limit:
        return [text[:limit]], True
    queue = [(text, 0)]
    try:
        doc = json.loads(text)
    except ValueError:
        doc = None

    def strings(node):
        if isinstance(node, str):
            yield node
        elif isinstance(node, dict):
            for key, value in node.items():
                yield key
                yield from strings(value)
        elif isinstance(node, list):
            for value in node:
                yield from strings(value)

    for value in strings(doc):
        queue.append((value, 0))
        if len(queue) > 64:
            return [text], True
    out, seen, size = [], set(), 0
    while queue:
        value, depth = queue.pop(0)
        if value in seen:
            continue
        seen.add(value)
        size += len(value)
        if len(seen) > 64 or size > limit:
            return out, True
        out.append(value)
        if depth == 2:
            continue
        if re.search(r"%[0-9a-fA-F]{2}", value):
            queue.append((unquote(value), depth + 1))
        for match in re.finditer(r"[A-Za-z0-9_+/=-]{12,}", value):
            candidate = match.group()
            try:
                decoded = base64.b64decode(candidate + "=" * (-len(candidate) % 4), altchars=b"-_", validate=True)
                queue.append((decoded.decode("utf-8"), depth + 1))
            except (ValueError, UnicodeError, binascii.Error):
                pass
            if len(candidate) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", candidate):
                try:
                    queue.append((bytes.fromhex(candidate).decode("utf-8"), depth + 1))
                except UnicodeError:
                    pass
            if len(queue) > 64:
                return out, True
    return out, False


def provider_message(raw: dict[str, Any]) -> dict[str, Any]:
    """Only supported, inspectable text and tool calls survive provider metadata."""
    msg: dict[str, Any] = {"role": "assistant", "content": None}
    for key in ("content", "reasoning", "reasoning_content", "refusal"):
        value = raw.get(key)
        if isinstance(value, str):
            msg[key] = value
        elif key == "content" and isinstance(value, list):
            msg[key] = [{"type": "text", "text": part["text"]} for part in value
                        if isinstance(part, dict) and part.get("type") in {"text", "output_text"}
                        and isinstance(part.get("text"), str)]

    def details(node):
        if isinstance(node, (str, int, float)) or node is None:
            return node
        if isinstance(node, list):
            return [details(v) for v in node]
        if isinstance(node, dict):
            return {k: details(v) for k, v in node.items()
                    if k in {"text", "summary", "reasoning", "details", "type", "format", "index", "id"}}
        return None

    if "reasoning_details" in raw:
        msg["reasoning_details"] = details(raw["reasoning_details"])
    if isinstance(raw.get("tool_calls"), list):
        msg["tool_calls"] = [{"id": public_id(str(tc["id"])) if tc.get("id") else None, "type": "function",
                              "function": {"name": tc["function"].get("name", "?"),
                                           "arguments": tc["function"].get("arguments") or ""}}
                             for tc in raw["tool_calls"] if isinstance(tc, dict)
                             and isinstance(tc.get("function"), dict)]
    return msg
