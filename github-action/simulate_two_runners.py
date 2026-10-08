#!/usr/bin/env python3
"""Two-runner simulation of the Handoff Contract GitHub Action.

WHAT THIS IS (and is not)
-------------------------
This is a LOCAL MODEL of GitHub's hosted-runner environment, built to
reproduce and then regression-test the cross-run duplicate-protection
failure that an independent reviewer found in the v0.2 Action design
(two hosted runners starting from the same empty `actions/cache` state
both ACCEPT the same packet, because `actions/cache` is immutable
snapshot storage, not an atomic compare-and-set, and the flock in the
checker only serializes processes that share one filesystem).

It is NOT a real GitHub run. It models exactly the two properties that
matter for the bug:

  * each "runner" is a separate temporary workspace with NO shared
    filesystem (separate dirs; the checker in one cannot see the
    other's ledger or lockfiles);
  * the ledger travels between runners only through an explicit,
    ordered "cache" hand-off (a directory copy standing in for
    actions/cache save/restore).

What it does NOT model: real cache eviction, cache size limits, GitHub's
concurrency-group queueing latency/pending-run semantics, cache restore
partial matches, or runner clock skew. Those still need one real
two-runner GitHub run to verify (see OPTION2_REPORT.md).

Modes
-----
legacy   : both runners restore from the same empty snapshot and run
           concurrently-ish (no cache hand-off between them). Expected
           outcome: BOTH ACCEPT -> the v0.2 cross-run bug.
fixed    : runners are serialized (the `concurrency` group in the
           caller workflow) and runner B restores the ledger cache that
           runner A saved after its claim. Expected: A ACCEPTs, B is
           REJECTED as `duplicate` (key still RESERVED).
complete : like `fixed`, then runner A runs the complete step (flip to
           COMPLETED, save cache again), and a third presentation
           restores that. Expected: REJECT `duplicate`
           (duplicate_idempotency_key, already COMPLETED).

Each "runner" invokes the real, unmodified checker CLI
(github-action/checker/handoff_check.py) as a subprocess, exactly as
action.yml does via run_check.sh -- the checker code and its verdict
states are untouched by the simulation.

Usage:
  python3 simulate_two_runners.py [--mode legacy|fixed|complete|all]
                                  [--keep] [--workdir DIR] [--quiet]

Exit code: 0 iff every mode's expectations hold (for `all`: legacy MUST
double-ACCEPT, fixed and complete MUST single-ACCEPT). 1 otherwise.
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ACTION_DIR = Path(__file__).resolve().parent
REPO_ROOT = ACTION_DIR.parent
CHECKER = ACTION_DIR / "checker" / "handoff_check.py"
SRC_PACKET = REPO_ROOT / "examples" / "valid.json"
SRC_REGISTRY = REPO_ROOT / "examples" / "registry.json"
SRC_ARTIFACT = REPO_ROOT / "examples" / "artifact.txt"
LEDGER_NAME = "ledger.json"


def build_runner(base: Path, name: str) -> Path:
    """Create an isolated runner workspace: packet, registry, artifact.

    Mirrors examples/valid.json, which references the artifact by the
    relative path examples/artifact.txt, so each runner gets its own
    examples/ dir and is invoked with --workspace = runner root.
    """
    ws = base / name
    (ws / "examples").mkdir(parents=True)
    shutil.copy(SRC_PACKET, ws / "packet.json")
    shutil.copy(SRC_REGISTRY, ws / "registry.json")
    shutil.copy(SRC_ARTIFACT, ws / "examples" / "artifact.txt")
    return ws


def copy_cache(src_ws: Path, dst_ws: Path) -> bool:
    """Model actions/cache: hand the saved ledger snapshot to a runner.

    Returns True if a snapshot existed to hand over.
    """
    src = src_ws / LEDGER_NAME
    dst = dst_ws / LEDGER_NAME
    if not src.exists():
        return False
    shutil.copy(src, dst)
    return True


def run_checker(ws: Path, *extra: str) -> dict:
    """Run the real checker CLI inside a runner workspace.

    Returns {decision, state, codes, exit}.
    """
    cmd = [
        sys.executable, str(CHECKER), "packet.json",
        "--registry", "registry.json",
        "--workspace", ".",
        "--ledger", LEDGER_NAME,
        *extra,
    ]
    proc = subprocess.run(cmd, cwd=ws, capture_output=True, text=True)
    try:
        out = json.loads(proc.stdout)
    except json.JSONDecodeError:
        out = {"raw_stdout": proc.stdout, "raw_stderr": proc.stderr}
    reasons = out.get("reasons") or []
    return {
        "decision": out.get("decision"),
        "state": out.get("state") or (reasons[0].get("state") if reasons else None),
        "codes": [r.get("code") for r in reasons],
        "exit": proc.returncode,
    }


def ledger_state(ws: Path) -> str | None:
    """Return the state of the valid.json packet's key in a runner's ledger."""
    led = ws / LEDGER_NAME
    if not led.exists():
        return None
    packet = json.loads((ws / "packet.json").read_text())
    key = packet["handoff"]["idempotency_key"]
    entry = json.loads(led.read_text()).get(key)
    return (entry or {}).get("state") if entry else None


def fmt(res: dict) -> str:
    s = res["decision"] or "?"
    if res["state"]:
        s += f" [{res['state']}" + (f": {','.join(c for c in res['codes'] if c)}" if any(res["codes"]) else "") + "]"
    return s


def mode_legacy(base: Path, log) -> bool:
    """Bug reproduction: two runners, same empty snapshot, no hand-off."""
    log("\n=== MODE: legacy (v0.2 action: independent runners, same empty cache) ===")
    a = build_runner(base, "runner-a")
    b = build_runner(base, "runner-b")
    ra = run_checker(a)   # runner A claims the key
    rb = run_checker(b)   # runner B never sees A's cache save (raced runs)
    log(f"runner A: {fmt(ra)}  (ledger: {ledger_state(a)})")
    log(f"runner B: {fmt(rb)}  (ledger: {ledger_state(b)})")
    ok = ra["decision"] == "ACCEPT" and rb["decision"] == "ACCEPT"
    log("EXPECTED (the bug): both ACCEPT -> " + ("REPRODUCED" if ok else "NOT reproduced"))
    return ok


def mode_fixed(base: Path, log) -> tuple[bool, Path]:
    """Fix semantics: serialized runs, B restores A's post-claim snapshot."""
    log("\n=== MODE: fixed (concurrency group serializes runs; cache chaining) ===")
    a = build_runner(base, "runner-a")
    b = build_runner(base, "runner-b")
    ra = run_checker(a)          # claim phase: ACCEPT + RESERVED, cache saved
    handed = copy_cache(a, b)    # run B starts only after A saved (concurrency)
    rb = run_checker(b)
    log(f"runner A claim : {fmt(ra)}  (ledger: {ledger_state(a)})")
    log(f"cache hand-off A->B: {'snapshot restored' if handed else 'MISSING snapshot'}")
    log(f"runner B claim : {fmt(rb)}  (ledger: {ledger_state(b)})")
    ok = (ra["decision"] == "ACCEPT" and rb["decision"] == "REJECT"
          and rb["state"] == "duplicate")
    log("EXPECTED: exactly one ACCEPT, B REJECT duplicate -> " + ("HOLDS" if ok else "VIOLATED"))
    return ok, a


def mode_complete(base: Path, log) -> bool:
    """Completion path: claim -> effect -> complete step -> replay."""
    ok_fixed, a = mode_fixed(base / "phase1", log)
    if not ok_fixed:
        log("fixed phase failed; completion path cannot be evaluated")
        return False
    rc = run_checker(a, "--complete")   # complete step in A's workspace
    state = ledger_state(a)
    log(f"runner A complete-step: {fmt(rc)}  (ledger: {state})")
    c = build_runner(base / "phase2", "runner-c")
    handed = copy_cache(a, c)            # replay run restores post-complete cache
    rr = run_checker(c)
    log(f"cache hand-off A->C: {'snapshot restored' if handed else 'MISSING snapshot'}")
    log(f"runner C replay : {fmt(rr)}  (ledger: {ledger_state(c)})")
    ok = (rc["decision"] == "COMPLETED" and state == "COMPLETED"
          and rr["decision"] == "REJECT" and rr["state"] == "duplicate")
    log("EXPECTED: complete flips to COMPLETED; replay REJECT duplicate -> "
        + ("HOLDS" if ok else "VIOLATED"))
    return ok


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--mode", choices=["legacy", "fixed", "complete", "all"],
                    default="all")
    ap.add_argument("--keep", action="store_true",
                    help="keep the simulation workspaces for inspection")
    ap.add_argument("--workdir", default=None,
                    help="base dir for workspaces (default: fresh temp dir)")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    log = (lambda *a: None) if args.quiet else print
    base = Path(args.workdir) if args.workdir else Path(
        tempfile.mkdtemp(prefix="synthe-two-runner-"))
    base.mkdir(parents=True, exist_ok=True)
    log(f"two-runner simulation (local model, not a GitHub run); workdir={base}")

    results = {}
    try:
        if args.mode in ("legacy", "all"):
            results["legacy (bug reproduced: double ACCEPT)"] = \
                mode_legacy(base / "legacy", log)
        if args.mode in ("fixed", "all"):
            ok, _ = mode_fixed(base / "fixed", log)
            results["fixed (exactly one ACCEPT)"] = ok
        if args.mode in ("complete", "all"):
            results["complete (replay of COMPLETED is duplicate)"] = \
                mode_complete(base / "complete", log)
    finally:
        if not args.keep and not args.workdir:
            shutil.rmtree(base, ignore_errors=True)

    log("\n--- summary ---")
    all_ok = True
    for name, ok in results.items():
        log(f"{'PASS' if ok else 'FAIL'}  {name}")
        all_ok = all_ok and ok
    if args.keep or args.workdir:
        log(f"workspaces kept at {base}")
    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
