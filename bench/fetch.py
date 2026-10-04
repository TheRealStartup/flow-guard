"""Download the public benchmark datasets into bench/quarantine/ (prompt-injection and jailbreak test data).

    cd gateway && uv run python ../bench/fetch.py

The files hold attack text written to hijack AI agents. Like demo/quarantine/, they are never read, printed or quoted
by agents or people working on the repo: only benchmark code loads them, and reports carry metrics and case ids only.
Prints file names, sizes and row counts, never contents. Not committed to git (bench/quarantine/ is ignored).
"""

import csv
import io
import sys
from pathlib import Path

import httpx

Q = Path(__file__).resolve().parent / "quarantine"
HF = "https://huggingface.co/datasets"
FILES = {  # local name -> URL (Apache-2.0 datasets on Hugging Face)
    "deepset-prompt-injections-train.parquet": f"{HF}/deepset/prompt-injections/resolve/main/data/train-00000-of-00001-9564e8b05b4757ab.parquet",
    "deepset-prompt-injections-test.parquet": f"{HF}/deepset/prompt-injections/resolve/main/data/test-00000-of-00001-701d16158af87368.parquet",
    "jackhhao-jailbreak-full.csv": f"{HF}/jackhhao/jailbreak-classification/resolve/main/default/jailbreak_dataset_full.csv",
}


def main() -> None:
    Q.mkdir(exist_ok=True)
    with httpx.Client(follow_redirects=True, timeout=60) as c:
        for name, url in FILES.items():
            r = c.get(url)
            r.raise_for_status()
            (Q / name).write_bytes(r.content)
            rows = "?"
            if name.endswith(".csv"):
                rows = sum(1 for _ in csv.reader(io.StringIO(r.text))) - 1
            print(f"{name}: {len(r.content):,} bytes, rows: {rows}")
    sys.exit(0)


if __name__ == "__main__":
    main()
