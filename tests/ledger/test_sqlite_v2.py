"""Ledger v2: SQLite/WAL keeps ordinary claim writes independent of ledger size."""
import json
import multiprocessing as mp
import os
import sqlite3
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

import handoff_check as hc  # noqa: E402
from world import World  # noqa: E402


def _claim_child(path, registry, workspace, packet, out, idx):
    try:
        result = hc.check(packet, registry=registry, ledger_path=Path(path), workspace=Path(workspace))
        codes = [r["code"] for r in result.get("reasons", [])]
        Path(f"{out}-{idx}").write_text(json.dumps({"decision": result["decision"], "codes": codes}))
    except BaseException as exc:  # noqa: BLE001
        Path(f"{out}-{idx}").write_text(json.dumps({"error": f"{type(exc).__name__}: {exc}"}))


def test_sqlite_claim_complete_and_lazy_hot_path(tmp_path, monkeypatch):
    w = World(tmp_path)
    ledger = tmp_path / "ledger.sqlite3"
    seed = {f"old-{i}": {"state": "COMPLETED", "handoff_id": f"h-{i}"} for i in range(5000)}
    hc.save_ledger(ledger, seed)

    def no_scan(self):
        pytest.fail("ordinary claim loaded the whole SQLite ledger")

    monkeypatch.setattr(hc.SQLiteLedger, "_load_all", no_scan)
    packet = w.packet(idem="sqlite-new")
    claimed = hc.check(packet, registry=w.registry, ledger_path=ledger, workspace=w.tmp / "workspace")
    assert claimed["decision"] == "ACCEPT", claimed
    completed = hc.complete(packet, ledger, claim_token=claimed["claim"]["token"], require_token=True)
    assert completed["decision"] == "COMPLETED"
    assert hc.load_ledger(ledger).get("sqlite-new")["state"] == "COMPLETED"


def test_sqlite_backend_is_wal_with_full_sync(tmp_path):
    path = tmp_path / "ledger.sqlite3"
    conn = hc._sqlite_connect(path)
    assert conn.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
    assert conn.execute("PRAGMA synchronous").fetchone()[0] == 2
    conn.close()


def test_json_migration_is_verified_and_never_overwrites(tmp_path):
    source, destination = tmp_path / "ledger.json", tmp_path / "ledger.sqlite3"
    original = {"k1": {"state": "RESERVED", "epoch": 3}, "k2": {"state": "COMPLETED"}}
    source.write_text(json.dumps(original))
    report = hc.migrate_ledger(source, destination)
    assert report["entries"] == 2 and json.loads(source.read_text()) == original
    assert hc.load_ledger(destination) == original
    with pytest.raises(FileExistsError):
        hc.migrate_ledger(source, destination)


def test_corrupt_sqlite_fails_closed_with_a_verdict(tmp_path):
    w = World(tmp_path)
    ledger = tmp_path / "ledger.sqlite3"
    ledger.write_bytes(b"not a sqlite database")
    out = hc.check(w.packet(), registry=w.registry, ledger_path=ledger, workspace=w.tmp / "workspace")
    assert out["decision"] == "REJECT"
    assert {r["code"] for r in out["reasons"]} == {"ledger_corrupt"}


@pytest.mark.skipif(os.environ.get("SYNTHE_MUTATION_CHILD") == "1", reason="covered once outside mutation children")
def test_concurrent_sqlite_claim_has_one_winner(tmp_path):
    w = World(tmp_path)
    ledger = tmp_path / "ledger.sqlite3"
    packet = w.packet(idem="one-winner")
    out, count = str(tmp_path / "claim"), 12
    ctx = mp.get_context("fork")
    procs = [ctx.Process(target=_claim_child,
                         args=(str(ledger), w.registry, str(w.tmp / "workspace"), packet, out, i))
             for i in range(count)]
    for proc in procs:
        proc.start()
    for proc in procs:
        proc.join(timeout=60)
        assert not proc.is_alive()
    results = [json.loads(Path(f"{out}-{i}").read_text()) for i in range(count)]
    assert not [r for r in results if "error" in r], results
    assert sum(r["decision"] == "ACCEPT" for r in results) == 1
    assert all(r["decision"] == "ACCEPT" or "idempotency_key_reserved" in r["codes"] for r in results)


def test_sqlite_schema_rejects_non_json_rows(tmp_path):
    path = tmp_path / "ledger.sqlite3"
    conn = hc._sqlite_connect(path)
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("INSERT INTO claims(key, value) VALUES ('bad', 'not-json')")
    conn.close()
