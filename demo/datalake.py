"""A small synthetic data lake behind the `query_datalake` tool. All data is invented test data.

The agent names a predefined query; it never writes one. The lake labels every result with its own class: a dataset
has the class it is stored with here, a derived view has the class its transformation declares in policy.yaml. The
gateway checks that label against its catalog before the model sees anything (docs/decisions.md D7).
"""

import json
from collections import Counter
from pathlib import Path

import yaml

POLICY = Path(__file__).resolve().parent.parent / "policy" / "policy.yaml"

# dataset -> (class it is stored with, rows)
DATASETS = {
    "fx_reference": ("public", [
        {"pair": "EUR/USD", "rate": 1.0842, "as_of": "2026-10-02"},
        {"pair": "GBP/USD", "rate": 1.2716, "as_of": "2026-10-02"},
        {"pair": "EUR/PLN", "rate": 4.2875, "as_of": "2026-10-02"},
    ]),
    "client_positions": ("P2", [
        {"client": "NW-2041", "instrument": "Euro Stoxx 50 futures", "side": "long", "notional_musd": 42.5},
        {"client": "NW-2041", "instrument": "Bund futures", "side": "short", "notional_musd": 18.0},
        {"client": "AC-7730", "instrument": "EUR/USD forwards", "side": "long", "notional_musd": 7.25},
    ]),
    "deal_pipeline": ("DP30", [
        {"codename": "Osprey", "sector": "industrial technology", "stage": "due diligence", "fee_estimate_musd": 6.1},
        {"codename": "Heron", "sector": "industrial technology", "stage": "mandate signed", "fee_estimate_musd": 3.4},
        {"codename": "Merlin", "sector": "industrial technology", "stage": "board approval", "fee_estimate_musd": 9.8},
        {"codename": "Kite", "sector": "healthcare", "stage": "first contact", "fee_estimate_musd": 2.2},
        {"codename": "Harrier", "sector": "healthcare", "stage": "due diligence", "fee_estimate_musd": 4.0},
        {"codename": "Lanner", "sector": "energy", "stage": "mandate signed", "fee_estimate_musd": 5.5},
    ]),
}

TOOL = {"type": "function", "function": {
    "name": "query_datalake",
    "description": "Run a predefined data-lake query by name: fx_rates, client_positions, deal_pipeline, pipeline_by_sector.",
    "parameters": {"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]}}}


def catalog(path: Path = POLICY) -> dict:
    return (yaml.safe_load(path.read_text()) or {}).get("datalake") or {}


def _transform(spec: dict) -> list[dict]:
    """The only way to a lower-class view: count rows per value of one field, and drop groups smaller than min_group
    (a group of one would name a deal). Nothing else of the rows comes out."""
    _, rows = DATASETS[spec["from"]]
    counts = Counter(r[spec["count_by"]] for r in rows)
    return [{spec["count_by"]: k, "count": n} for k, n in sorted(counts.items()) if n >= int(spec.get("min_group", 1))]


def run_query(name: str, cat: dict | None = None) -> str:
    cat = catalog() if cat is None else cat
    q = (cat.get("queries") or {}).get(name)
    if not q:
        return json.dumps({"error": "unknown query"})
    if "transformation" in q:
        spec = (cat.get("transformations") or {})[q["transformation"]]
        return json.dumps({"query": name, "class": spec["class"], "rows": _transform(spec)})
    cls, rows = DATASETS[q["dataset"]]
    return json.dumps({"query": name, "class": cls, "rows": rows})
