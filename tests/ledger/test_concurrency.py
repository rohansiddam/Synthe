"""T2.1 concurrency stress: 50 parallel claims of one key.

The ledger's claim path holds a file lock across validate + record, so two
concurrent presentations of the same idempotency key cannot both pass. These
tests hammer that guarantee with real OS processes:

  1. 50 parallel claims -> exactly one ACCEPT (epoch 1), 49 REJECT as
     `idempotency_key_reserved`; the ledger holds exactly one RESERVED entry.
  2. Parallel re-claim while RESERVED -> all denied; after release, one
     re-claim wins with epoch 2.
  3. fenced() during a concurrent claim race -> the fenced holder's effect
     runs exactly once; late claimants are denied as duplicates.

Forked children share the World setup; each child calls hc.check() directly
against the same ledger file, which is the real contention point.
"""
import multiprocessing as mp
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests"))
sys.path.insert(0, str(ROOT / "src"))

import handoff_check as hc  # noqa: E402
from world import World  # noqa: E402


def _claim_child(ledger_path, registry, workspace, packet, out_path, idx):
    """Try to claim in a forked child; record the verdict code."""
    try:
        v = hc.check(packet, registry=registry, ledger_path=Path(ledger_path),
                     workspace=Path(workspace))
        with open(f"{out_path}-{idx}", "w") as fh:
            fh.write(v["decision"] + "\n")
            codes = [r["code"] for r in v.get("reasons", [])]
            fh.write(",".join(codes) + "\n")
            fh.write(str(v.get("claim", {}).get("epoch", "")) + "\n")
    except BaseException as e:  # noqa: BLE001
        with open(f"{out_path}-{idx}", "w") as fh:
            fh.write(f"EXC: {e}\n\n\n")


def _run_claim_race(w, packet, n, tmp_path, tag):
    """Fork n claimants at once; return list of (decision, codes, epoch)."""
    out = str(tmp_path / f"race-{tag}")
    ctx = mp.get_context("fork")
    procs = [
        ctx.Process(target=_claim_child,
                    args=(str(w.tmp / "ledger.json"), w.registry,
                          str(w.tmp / "workspace"), packet, out, i))
        for i in range(n)
    ]
    for p in procs:
        p.start()
    for p in procs:
        p.join(timeout=60)
        assert not p.is_alive(), "claimant hung"
    results = []
    for i in range(n):
        lines = open(f"{out}-{i}").read().splitlines()
        while len(lines) < 3:
            lines.append("")
        results.append((lines[0], lines[1], lines[2]))
    return results


@pytest.fixture
def race_world(tmp_path):
    w = World(tmp_path)
    return w, w.packet()


def test_50_parallel_claims_one_winner(tmp_path, race_world):
    w, packet = race_world
    results = _run_claim_race(w, packet, 50, tmp_path, "fifty")

    accepts = [r for r in results if r[0] == "ACCEPT"]
    rejects = [r for r in results if r[0] == "REJECT"]
    assert len(accepts) == 1, f"expected exactly 1 winner, got {len(accepts)}"
    assert len(rejects) == 49
    assert accepts[0][2] == "1", "winner must hold epoch 1"
    for decision, codes, _ in rejects:
        assert "idempotency_key_reserved" in codes, f"loser denied wrong: {codes}"

    entry = w.ledger_entry()
    assert entry["state"] == "RESERVED"
    assert entry["epoch"] == 1
    assert w.chain()["ok"]


def test_parallel_reclaim_denied_then_epoch2_after_release(tmp_path, race_world):
    w, packet = race_world
    # One winner first.
    first = _run_claim_race(w, packet, 1, tmp_path, "first")
    assert first[0][0] == "ACCEPT"
    # 10 more racers while RESERVED: all denied.
    results = _run_claim_race(w, packet, 10, tmp_path, "reclaim")
    assert all(r[0] == "REJECT" for r in results)
    assert all("idempotency_key_reserved" in r[1] for r in results)
    assert w.ledger_entry()["epoch"] == 1

    # Age the claim past the TTL, release it, then one re-claim wins epoch 2.
    import datetime as dt
    import json as _json
    ledger_path = w.tmp / "ledger.json"
    data = _json.loads(ledger_path.read_text())
    for entry in data.values():
        if isinstance(entry, dict):
            entry["reserved_at"] = (dt.datetime.now(dt.timezone.utc)
                                    - dt.timedelta(hours=48)).isoformat()
    ledger_path.write_text(_json.dumps(data))
    rel = hc.release(packet, ledger_path)
    assert rel["decision"] == "RELEASED", rel
    second = _run_claim_race(w, packet, 1, tmp_path, "second")
    assert second[0][0] == "ACCEPT"
    assert second[0][2] == "2", "re-claim must hold epoch 2"
    assert w.ledger_entry()["epoch"] == 2


def test_fenced_holder_wins_race_late_claimants_duplicate(tmp_path, race_world):
    w, packet = race_world
    token = w.claim(packet)
    marker = str(tmp_path / "fenced-effect-done")

    # Holder runs its effect inside fenced(); meanwhile 10 racers try to claim.
    def holder():
        with hc.fenced(packet, w.tmp / "ledger.json", token):
            Path(marker).write_text("effect")
            time.sleep(1.5)

    ctx = mp.get_context("fork")
    hp = ctx.Process(target=holder)
    hp.start()
    time.sleep(0.3)  # let the holder enter the fence
    results = _run_claim_race(w, packet, 10, tmp_path, "during-fence")
    hp.join(timeout=30)
    assert not hp.is_alive()

    # The fenced effect ran exactly once; racers were denied as duplicates.
    assert Path(marker).read_text() == "effect"
    assert w.ledger_entry()["state"] == "COMPLETED"
    assert all(r[0] == "REJECT" for r in results)
    # After completion, the key is COMPLETED: further claims are duplicates.
    again = _run_claim_race(w, packet, 1, tmp_path, "after-complete")
    assert again[0][0] == "REJECT"
    assert "duplicate_idempotency_key" in again[0][1]
