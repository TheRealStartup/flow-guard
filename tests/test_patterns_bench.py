"""Detector fixes found by the PII benchmark (bench/pii_bench.py): each case failed before the fix."""

from acl.detectors.patterns import find_sensitive


def kinds(text: str) -> list[str]:
    return [s.kind for s in find_sensitive(text)]


def test_a_number_that_only_passes_luhn_is_not_a_card():
    assert kinds("Device IMEI 356938035643809 enrolled.") == []  # IMEIs carry a Luhn digit but no card prefix
    assert kinds("event_ts=1700000000006") == []  # a millisecond timestamp that passes Luhn
    assert kinds("Order 1234567890123452 shipped.") == []  # Luhn-valid order id, no card network starts with 12
    assert kinds("Card 4111 1111 1111 1111 on file.") == ["CARD"]  # Visa
    assert kinds("Card 5555555555554444 on file.") == ["CARD"]  # Mastercard
    assert kinds("Card 378282246310005 on file.") == ["CARD"]  # American Express, 15 digits
    assert kinds("Card 2223003122003222 on file.") == ["CARD"]  # Mastercard 2-series


def test_passport_label_with_a_full_stop_or_hash():
    assert kinds("Director, Passport No. AB1234567, nationality GB.") == ["PASSPORT"]
    assert kinds("passport #533380006") == ["PASSPORT"]
    assert kinds("Passport Nr. C01X00T47") == ["PASSPORT"]


def test_a_secret_assignment_after_a_word_with_a_colon_is_found():
    assert kinds("Config found in the repo: SETTLEMENT_DB_PASSWORD=Xq7Rt9Lm2Pz8Wd4Kv6") == ["SECRET"]
    assert kinds('Config: "api_key": "Xq7Rt9Lm2Pz8Wd4Kv6Ab12Cd34"') == ["SECRET"]
    assert kinds("Note: max_tokens=4096 and tokenizer=cl100k_base") == []  # still no false positive
