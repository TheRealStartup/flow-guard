"""Score texts with PIGuard on a GPU pod: reads quarantine/remaining.jsonl ({key, text}), writes cache/piguard-pod.jsonl.
Prints counts and timing only, never text."""

import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from piguard_judge import PIGuardJudge  # noqa: E402

B = Path(__file__).resolve().parent
items = [json.loads(ln) for ln in (B / "quarantine" / "remaining.jsonl").read_text().splitlines()]
j = PIGuardJudge()
print("device", j.device, "texts", len(items), flush=True)
out = (B / "cache" / "piguard-pod.jsonl")
out.parent.mkdir(exist_ok=True)
t0 = time.perf_counter()
with out.open("w") as f:
    for i, it in enumerate(items):
        t = time.perf_counter()
        p = j.score(it["text"])
        f.write(json.dumps({"key": it["key"], "p": p, "ms": (time.perf_counter() - t) * 1000, "device": j.device}) + "\n")
        if i % 500 == 0:
            print(i, f"{time.perf_counter() - t0:.0f}s", flush=True)
print("done", len(items), f"{time.perf_counter() - t0:.0f}s")
