"""Benchmark: the rule-based PII and secret detectors (gateway/acl/detectors/patterns.py) on synthetic data.

Positives are generated values that are valid by construction (Luhn, mod-97, PESEL checksum, real key formats), each
embedded in a short business sentence. Hard negatives are the look-alikes a bank's tool data is full of: order and
invoice numbers, phone numbers, timestamps, UUIDs, git hashes, ISBNs, IMEIs, invalid checksums, config lines with token
counts and placeholders. All data is synthetic and generated here with a fixed seed; no real person, no download.

    cd gateway && uv run python ../bench/pii_bench.py        (or: just bench-pii)

Writes bench/results/pii.json and bench/results/pii.md. Prints only metrics and case ids, never generated values.
"""

import json
import random
import string
import sys
import time
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "gateway"))

from acl.detectors.patterns import find_sensitive  # noqa: E402

rng = random.Random(20261004)
OUT = ROOT / "bench" / "results"


# ---------- valid values by construction ----------

def luhn_complete(prefix: str, length: int) -> str:
    body = prefix + "".join(rng.choice(string.digits) for _ in range(length - len(prefix) - 1))
    total = 0
    for i, ch in enumerate(reversed(body)):
        d = int(ch)
        if i % 2 == 0:  # these positions are doubled once the check digit is appended
            d = d * 2 - 9 if d * 2 > 9 else d * 2
        total += d
    return body + str((10 - total % 10) % 10)


def luhn_valid(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d = d * 2 - 9 if d * 2 > 9 else d * 2
        total += d
    return total % 10 == 0


def iban(country: str, bban_len: int, alpha: int = 0) -> str:
    bban = "".join(rng.choice(string.ascii_uppercase) for _ in range(alpha)) + "".join(rng.choice(string.digits) for _ in range(bban_len - alpha))
    num = "".join(str(int(c, 36)) for c in bban + country + "00")
    return f"{country}{98 - int(num) % 97:02d}{bban}"


def spaced(s: str) -> str:
    return " ".join(s[i:i + 4] for i in range(0, len(s), 4))


def pesel() -> str:
    year, month, day = rng.randint(1950, 1999), rng.randint(1, 12), rng.randint(1, 28)
    base = f"{year % 100:02d}{month:02d}{day:02d}{rng.randint(0, 9999):04d}"
    w = [1, 3, 7, 9, 1, 3, 7, 9, 1, 3]
    return base + str((10 - sum(int(a) * b for a, b in zip(base, w)) % 10) % 10)


def rand(chars: str, n: int) -> str:
    return "".join(rng.choice(chars) for _ in range(n))


AN = string.ascii_letters + string.digits

# ---------- cases: (id, category, expected kind or None, text) ----------

def positives() -> list[tuple[str, str, str, str]]:
    out = []
    for i in range(60):
        prefix = rng.choice(["4", "51", "52", "55", "37"])
        card = luhn_complete(prefix, 15 if prefix == "37" else 16)  # Visa / Mastercard 16 digits, Amex 15
        fmt = [card, spaced(card), "-".join(card[j:j + 4] for j in range(0, len(card), 4))][i % 3]
        out.append((f"card-{i}", "card", "CARD", f"Customer disputes the charge on card {fmt} from 2 Oct."))
    for i in range(60):
        country, n, a = [("PL", 24, 0), ("DE", 18, 0), ("GB", 18, 4), ("FR", 23, 0), ("NL", 14, 4)][i % 5]
        v = iban(country, n, a)
        out.append((f"iban-{i}", "iban", "IBAN", f"Settle to account {v if i % 2 else spaced(v)} by Friday."))
    for i in range(40):
        out.append((f"pesel-{i}", "pesel", "PESEL", f"Beneficial owner PESEL {pesel()}, resident in Kraków."))
    for i in range(40):
        num = rand(string.ascii_uppercase, rng.randint(1, 2)) + rand(string.digits, 7)
        label = ["passport", "Passport No.", "passport_number:", "Passport number"][i % 4]
        out.append((f"passport-labelled-{i}", "passport (labelled)", "PASSPORT", f"Director, {label} {num}, nationality GB."))
    for i in range(20):  # honest limit: an unlabelled passport number is not detected by design
        num = rand(string.ascii_uppercase, 1) + rand(string.digits, 8)
        out.append((f"passport-unlabelled-{i}", "passport (unlabelled)", "PASSPORT", f"ID document {num} verified on 3 Oct."))
    secrets = [
        ("aws", lambda: "AKIA" + rand(string.ascii_uppercase + string.digits, 16)),
        ("openai", lambda: "sk-proj-" + rand(AN + "_-", 40)),
        ("github", lambda: "ghp_" + rand(AN, 36)),
        ("stripe", lambda: "sk_live_" + rand(AN, 24)),
        ("url-creds", lambda: f"postgres://svc_payments:{rand(AN, 14)}@db.internal:5432/ledger"),
        ("env-assign", lambda: f"SETTLEMENT_DB_PASSWORD={rand(AN + '!#%', 18)}"),
        ("json-assign", lambda: f'"api_key": "{rand(AN, 32)}"'),
        ("private-key", lambda: "-----BEGIN RSA PRIVATE KEY-----"),
    ]
    for i in range(80):
        name, make = secrets[i % len(secrets)]
        out.append((f"secret-{name}-{i}", f"secret ({name})", "SECRET", f"Config found in the repo: {make()}"))
    return out


def negatives() -> list[tuple[str, str, None, str]]:
    out: list[tuple[str, str, None, str]] = []
    def add(cat: str, n: int, make):
        for i in range(n):
            out.append((f"neg-{cat.replace(' ', '-')}-{i}", cat, None, make()))
    add("order number 16 digits", 100, lambda: f"Order {rand(string.digits, 16)} shipped to the branch.")
    add("invalid card checksum", 60, lambda: f"Card on file {bad_luhn(16)} (typo in the form).")
    add("invalid IBAN checksum", 60, lambda: f"Account {bad_iban()} rejected by the bank.")
    add("11-digit number, bad PESEL checksum", 60, lambda: f"Reference {bad_pesel()} in the ledger.")
    add("phone number", 60, lambda: f"Call the client on +48 {rand(string.digits, 3)} {rand(string.digits, 3)} {rand(string.digits, 3)}.")
    add("unix timestamp ms", 60, lambda: f"event_ts={rng.randint(1_600_000_000_000, 1_800_000_000_000)}")
    add("uuid", 60, lambda: f"request_id: {rand('0123456789abcdef', 8)}-{rand('0123456789abcdef', 4)}-4{rand('0123456789abcdef', 3)}-a{rand('0123456789abcdef', 3)}-{rand('0123456789abcdef', 12)}")
    add("git sha", 60, lambda: f"Fixed in commit {rand('0123456789abcdef', 40)}.")
    add("isbn-13", 60, lambda: f"Reference book ISBN {isbn13()}.")
    add("imei", 40, lambda: f"Device IMEI {luhn_complete('35', 15)} enrolled.")  # IMEIs carry a Luhn digit: a known look-alike
    add("amount and date", 60, lambda: f"Settled {rng.randint(100, 99999)}.{rng.randint(0, 99):02d} EUR on 2026-10-0{rng.randint(1, 9)}.")
    add("config token counts", 60, lambda: rng.choice([f"max_tokens: {rng.randint(256, 32768)}", f"input_tokens={rng.randint(10, 9999)}",
                                                        "tokenizer=cl100k_base", f"token_budget: {rng.randint(1000, 90000)}"]))
    add("config placeholders", 60, lambda: rng.choice(["DB_PASSWORD=${DB_PASSWORD}", "api_key: <your-key-here>", "password=changeme",
                                                       "SECRET_KEY={{ secret_key }}", "token: xxxxxxxx", "API_KEY=$API_KEY"]))
    add("iso country + digits", 60, lambda: f"Branch code {rng.choice(['PL', 'DE', 'GB'])}{rand(string.digits, 2)} {rand(string.digits, 4)}.")
    add("word passport, no number", 40, lambda: rng.choice(["Passport copy requested from the client.", "Passport expired, renewal pending.",
                                                            "The passport office closes at 5."]))
    return out


def bad_luhn(n: int) -> str:
    while True:
        s = rand(string.digits, n)
        if not luhn_valid(s):
            return s


def bad_iban() -> str:
    v = iban("PL", 24)
    return v[:2] + f"{(int(v[2:4]) + rng.randint(1, 50)) % 100:02d}" + v[4:]


def bad_pesel() -> str:
    p = pesel()
    return p[:-1] + str((int(p[-1]) + rng.randint(1, 9)) % 10)


def isbn13() -> str:
    body = "978" + rand(string.digits, 9)
    s = sum(int(d) * (1 if i % 2 == 0 else 3) for i, d in enumerate(body))
    return body + str((10 - s % 10) % 10)


# ---------- run ----------

def main() -> None:
    cases = positives() + negatives()
    per_kind = defaultdict(lambda: {"tp": 0, "fn": 0, "fp": 0})
    per_cat = defaultdict(lambda: {"n": 0, "hit": 0})
    misses, false_alarms, times = [], [], []
    for cid, cat, kind, text in cases:
        t = time.perf_counter()
        found = {s.kind for s in find_sensitive(text)}
        times.append((time.perf_counter() - t) * 1000)
        per_cat[cat]["n"] += 1
        if kind:
            hit = kind in found
            per_cat[cat]["hit"] += hit
            per_kind[kind]["tp" if hit else "fn"] += 1
            if not hit:
                misses.append(cid)
            for k in found - {kind}:
                per_kind[k]["fp"] += 1
                false_alarms.append(cid)
        else:
            per_cat[cat]["hit"] += bool(found)
            for k in found:
                per_kind[k]["fp"] += 1
            if found:
                false_alarms.append(cid)

    kinds = {}
    for k, c in sorted(per_kind.items()):
        p = c["tp"] / (c["tp"] + c["fp"]) if c["tp"] + c["fp"] else None
        r = c["tp"] / (c["tp"] + c["fn"]) if c["tp"] + c["fn"] else None
        kinds[k] = {**c, "precision": p, "recall": r, "f1": 2 * p * r / (p + r) if p and r else None}
    times.sort()
    report = {
        "suite": "pii-and-secrets", "detector": "gateway/acl/detectors/patterns.py", "data": "synthetic, generated (seed 20261004)",
        "cases": len(cases), "positives": sum(1 for c in cases if c[2]), "negatives": sum(1 for c in cases if not c[2]),
        "per_kind": kinds,
        "per_category": {k: {**v, "rate": v["hit"] / v["n"]} for k, v in per_cat.items()},
        "latency_ms": {"p50": times[len(times) // 2], "p95": times[int(len(times) * 0.95)]},
        "missed_case_ids": misses, "false_alarm_case_ids": false_alarms,
    }
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "pii.json").write_text(json.dumps(report, indent=2))
    (OUT / "pii.md").write_text(markdown(report))
    print(markdown(report))


def pct(x) -> str:
    return "—" if x is None else f"{100 * x:.1f}%"


def markdown(r: dict) -> str:
    lines = [f"# PII and secret detectors: {r['cases']} synthetic cases ({r['positives']} positive, {r['negatives']} hard negative)", "",
             "| Kind | Precision | Recall | F1 | TP | FN | FP |", "|---|---|---|---|---|---|---|"]
    for k, v in r["per_kind"].items():
        lines.append(f"| {k} | {pct(v['precision'])} | {pct(v['recall'])} | {pct(v['f1'])} | {v['tp']} | {v['fn']} | {v['fp']} |")
    lines += ["", "| Category | Cases | Detected (positives: recall; negatives: false-alarm rate) |", "|---|---|---|"]
    for k, v in r["per_category"].items():
        lines.append(f"| {k} | {v['n']} | {pct(v['rate'])} |")
    lines += ["", f"Latency per text: p50 {r['latency_ms']['p50']:.3f} ms, p95 {r['latency_ms']['p95']:.3f} ms.", ""]
    return "\n".join(lines)


if __name__ == "__main__":
    main()
