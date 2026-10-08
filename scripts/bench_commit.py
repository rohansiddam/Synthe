#!/usr/bin/env python3
"""Measure Synthe Commit's own overhead: the full commit path, per phase.

Runs N proposals (default 30, after 2 warm-up runs) of the full path against
a local bare repo standing in for GitHub, for two paths:

  isolated    the broker daemon (`synthe_commit.py serve`, its own process) on a
              unix socket; the agent claims and proposes with synthe_client, and
              the commits travel as a git bundle;
  in-process  the dev path: the broker runs inside the caller's process and
              reads the commit from the agent's repo by path.

Each run is a new signed, approved handoff pushing one new commit to a new
branch. Phases (wall clock): claim, bundle (client), transfer (socket, JSON,
base64), validate (commit-time re-check), prepare (unpack the bundle / fetch
the path), fence (ledger lock, claim and dependency checks, recording the
effect), live_check (remote state, fetch, ancestry), inspect (paths of every
pushed commit), push, confirm (remote re-read), receipt (sign, append, fsync),
total. p50/p95 are nearest-rank.

    python3 scripts/bench_commit.py [--runs 30] [--json results.json]

Numbers from this script are the only performance numbers we quote
(docs/PERFORMANCE.md). A real GitHub remote adds network round trips to
live_check, push and confirm; measuring that needs a real `feature/*` branch
and Rishab's OK first.
"""
import argparse
import base64
import json
import math
import os
import platform
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
from world import World, git  # noqa: E402  (throwaway keys, registry, remote, agent clone)
import handoff_check as hc     # noqa: E402
import synthe_client as scl    # noqa: E402
import synthe_commit as cm     # noqa: E402

PHASES = ["claim", "bundle", "transfer", "validate", "prepare", "fence", "live_check", "inspect", "push",
          "confirm", "receipt", "total"]
LABELS = {"claim": "claim (validate + reserve)", "bundle": "bundle (client: bases + git bundle)",
          "transfer": "transfer (socket, JSON, base64)", "validate": "validate (commit-time re-check)",
          "prepare": "prepare (unpack bundle / fetch path)", "fence": "fence (lock, claim, deps, record)",
          "live_check": "live check (remote state, ancestry)", "inspect": "inspect (every pushed path)",
          "push": "push (compare-and-swap)", "confirm": "confirm (re-read remote)",
          "receipt": "receipt (sign, append, fsync)", "total": "**total**"}


def pct(values, p):
    v = sorted(values)
    return v[max(0, math.ceil(p / 100 * len(v)) - 1)] if v else float("nan")


def machine() -> dict:
    cpu = platform.processor()
    try:
        if sys.platform == "darwin":
            cpu = subprocess.run(["sysctl", "-n", "machdep.cpu.brand_string"], capture_output=True,
                                 text=True).stdout.strip() or cpu
        elif Path("/proc/cpuinfo").exists():
            cpu = next((ln.split(":", 1)[1].strip() for ln in Path("/proc/cpuinfo").read_text().splitlines()
                        if ln.lower().startswith(("model name", "hardware"))), cpu)
    except OSError:
        pass
    try:
        import cryptography
        crypto = cryptography.__version__
    except ImportError:
        crypto = "not installed (pure-Python Ed25519)"
    return {"os": platform.platform(), "cpu": cpu, "cores": os.cpu_count(),
            "python": platform.python_version(), "git": git(ROOT, "--version"), "cryptography": crypto}


def new_work(w: World, i: int, tag: str) -> str:
    git(w.agent, "checkout", "-q", "-B", f"work-{tag}-{i}", "main")
    return w.commit({f"src/bench_{tag}_{i}.py": f"print({i})\n"}, msg=f"bench {tag} {i}")


def run_isolated(w: World, n: int, warmup: int) -> list:
    sock_dir = Path(tempfile.mkdtemp(prefix="sy", dir="/tmp"))
    sock = sock_dir / "broker.sock"
    log = open(w.tmp / "broker.log", "w")
    proc = subprocess.Popen([sys.executable, str(ROOT / "src" / "synthe_commit.py"), "serve",
                             "--config", str(w.config_path), "--socket", str(sock)], stderr=log)
    rows = []
    try:
        for _ in range(200):
            if sock.exists():
                break
            time.sleep(0.02)
        c = scl.BrokerClient(f"unix://{sock}")
        for i in range(warmup + n):
            branch = f"feature/iso-{i}"
            p = w.packet(idem=f"iso-{i}", branch=branch)
            sha = new_work(w, i, "iso")
            t0 = time.perf_counter()
            v = c.call("claim", packet=p)
            t1 = time.perf_counter()
            tips = c.call("bundle_bases", remote="origin", branch=branch, base="main")
            data = scl.make_bundle(w.agent, sha, [tips.get("branch"), tips.get("base")])
            t2 = time.perf_counter()
            resp = c.call_full("propose", packet=p, claim_token=v["claim"]["token"], action="push_branch",
                               params={"remote": "origin", "branch": branch, "commit": sha},
                               bundle=base64.b64encode(data).decode(), timings=True)
            t3 = time.perf_counter()
            assert resp["result"]["decision"] == "executed", resp["result"]
            server = resp["timings"]
            row = {"claim": t1 - t0, "bundle": t2 - t1, "transfer": (t3 - t2) - sum(server.values()),
                   **server, "total": t3 - t0, "bundle_bytes": len(data)}
            if i >= warmup:
                rows.append(row)
    finally:
        proc.terminate()
        proc.wait(timeout=10)
        log.close()
        for f in (sock, sock_dir):
            try:
                f.unlink() if f.is_socket() else f.rmdir()
            except OSError:
                pass
    return rows


def run_in_process(w: World, n: int, warmup: int) -> list:
    rows = []
    for i in range(warmup + n):
        branch = f"feature/inp-{i}"
        p = w.packet(idem=f"inp-{i}", branch=branch)
        sha = new_work(w, i, "inp")
        t0 = time.perf_counter()
        v = hc.check(p, registry=json.loads(w.cfg.registry_path.read_text()), ledger_path=w.cfg.ledger_path,
                     workspace=w.cfg.workspace)
        t1 = time.perf_counter()
        server: dict = {}
        r = cm.propose(w.cfg, {"packet": p, "claim_token": v["claim"]["token"], "action": "push_branch",
                               "params": {"remote": "origin", "branch": branch, "commit": sha},
                               "source": str(w.agent)}, timings=server)
        t2 = time.perf_counter()
        assert r["decision"] == "executed", r
        row = {"claim": t1 - t0, "bundle": 0.0, "transfer": 0.0, **server, "total": t2 - t0}
        if i >= warmup:
            rows.append(row)
    return rows


def main() -> int:
    ap = argparse.ArgumentParser(description="Synthe Commit overhead, per phase")
    ap.add_argument("--runs", type=int, default=30)
    ap.add_argument("--warmup", type=int, default=2)
    ap.add_argument("--json", help="also write raw rows and the summary here")
    a = ap.parse_args()
    results = {"machine": machine(), "runs": a.runs, "warmup": a.warmup, "paths": {}}
    for name, fn in (("isolated", run_isolated), ("in-process", run_in_process)):
        with tempfile.TemporaryDirectory(prefix=f"synthe-bench-{name}-") as d:
            w = World(Path(d))
            rows = fn(w, a.runs, a.warmup)
            assert w.chain()["ok"]
        results["paths"][name] = {
            "rows": rows,
            "summary": {ph: {"p50_ms": round(pct([r[ph] for r in rows], 50) * 1000, 2),
                             "p95_ms": round(pct([r[ph] for r in rows], 95) * 1000, 2)} for ph in PHASES}}
    m = results["machine"]
    print(f"Synthe Commit overhead: {a.runs} runs per path (+{a.warmup} warm-up), local bare remote\n"
          f"{m['os']} | {m['cpu']} ({m['cores']} cores) | Python {m['python']} | {m['git']} | "
          f"cryptography {m['cryptography']}\n")
    print("| Phase | isolated p50 | isolated p95 | in-process p50 | in-process p95 |")
    print("|---|---:|---:|---:|---:|")
    for ph in PHASES:
        iso, inp = results["paths"]["isolated"]["summary"][ph], results["paths"]["in-process"]["summary"][ph]
        print(f"| {LABELS[ph]} | {iso['p50_ms']:.1f} ms | {iso['p95_ms']:.1f} ms | "
              f"{inp['p50_ms']:.1f} ms | {inp['p95_ms']:.1f} ms |")
    sizes = [r["bundle_bytes"] for r in results["paths"]["isolated"]["rows"]]
    print(f"\nbundle size: p50 {pct(sizes, 50)} bytes, max {max(sizes)} bytes (thin: one commit on top of main)")
    if a.json:
        Path(a.json).write_text(json.dumps(results, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
