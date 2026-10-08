#!/usr/bin/env python3
"""Measure SQLite/WAL claim latency as the completed-entry count grows.

This is machine time for the storage path, not user-visible task time.
"""
import argparse
import json
import statistics
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

import handoff_check as hc  # noqa: E402
from world import World  # noqa: E402


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=int, default=50)
    ap.add_argument("--sizes", default="0,1000,10000,50000")
    args = ap.parse_args(argv)
    sizes = [int(x) for x in args.sizes.split(",")]
    entry = {"state": "COMPLETED", "handoff_id": "h-seed", "trace_id": "t-seed",
             "from": "planner", "to": "builder", "epoch": 1,
             "packet_sha256": "a" * 64, "claim_token_sha256": "b" * 64,
             "owned_paths": []}
    with tempfile.TemporaryDirectory() as tmp:
        world = World(Path(tmp))
        for size in sizes:
            ledger = Path(tmp) / f"ledger-{size}.sqlite3"
            conn = hc._sqlite_connect(ledger)
            with conn:
                conn.executemany("INSERT INTO claims(key, value) VALUES (?, ?)",
                                 ((f"seed-{i}", json.dumps(entry, separators=(",", ":"))) for i in range(size)))
            conn.close()
            samples = []
            for run in range(args.runs):
                packet = world.packet(idem=f"bench-{size}-{run}")
                started = time.perf_counter()
                result = hc.check(packet, registry=world.registry, ledger_path=ledger,
                                  workspace=world.tmp / "workspace")
                samples.append((time.perf_counter() - started) * 1000)
                assert result["decision"] == "ACCEPT", result
            print(f"ledger_entries={size:6d} claim_p50={statistics.median(samples):8.3f}ms "
                  f"max={max(samples):8.3f}ms")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
