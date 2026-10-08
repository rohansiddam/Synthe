"""Receipt tip: append is O(last receipt), crash-rebuildable, and fail-closed on rewriting."""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

import synthe_commit as cm  # noqa: E402
from world import World  # noqa: E402


def _append(w, decision):
    return cm.append_receipt(w.cfg, w.keys["synthe-broker"], {
        "v": 1, "kind": "test", "time": "2026-10-07T00:00:00+00:00",
        "decision": decision, "reasons": [],
    })


def test_normal_append_uses_tip_without_rescanning_history(tmp_path, monkeypatch):
    w = World(tmp_path)
    first, second = _append(w, "first"), _append(w, "second")
    assert (first["seq"], second["seq"], second["prev"]) == (1, 2, cm.receipt_digest(first))
    tip = json.loads(cm._receipt_tip_path(w.cfg.receipts_path).read_text())
    assert tip == {"v": 1, "seq": 2, "head": cm.receipt_digest(second),
                   "bytes": w.cfg.receipts_path.stat().st_size}

    monkeypatch.setattr(cm, "_read_receipts", lambda path: pytest.fail("append rescanned receipt history"))
    third = _append(w, "third")
    assert third["seq"] == 3 and third["prev"] == cm.receipt_digest(second)


def test_missing_or_crash_stale_tip_rebuilds_before_append(tmp_path):
    w = World(tmp_path)
    first = _append(w, "first")
    tip_path = cm._receipt_tip_path(w.cfg.receipts_path)
    tip_path.write_text("{broken")
    second = _append(w, "second")
    assert second["seq"] == 2 and second["prev"] == cm.receipt_digest(first)
    assert cm.verify_receipts(w.cfg.receipts_path, w.registry)["ok"] is True

    tip = json.loads(tip_path.read_text())
    tip["bytes"] = 0                                                    # append landed; tip update did not
    tip_path.write_text(json.dumps(tip))
    third = _append(w, "third")
    assert third["seq"] == 3 and cm.verify_receipts(w.cfg.receipts_path, w.registry)["ok"] is True


def test_same_size_receipt_rewrite_is_refused_not_adopted(tmp_path):
    w = World(tmp_path)
    _append(w, "first")
    before = w.cfg.receipts_path.read_text()
    tampered = before.replace('"decision":"first"', '"decision":"other"')
    assert tampered != before and len(tampered) == len(before)
    w.cfg.receipts_path.write_text(tampered)
    with pytest.raises(ValueError, match="trusted tip"):
        _append(w, "second")
    assert w.cfg.receipts_path.read_text() == tampered                     # no append after detection


def test_corrupt_chain_without_a_tip_is_refused(tmp_path):
    w = World(tmp_path)
    first = _append(w, "first")
    cm._receipt_tip_path(w.cfg.receipts_path).unlink()
    bad = {**first, "seq": 9}
    with w.cfg.receipts_path.open("a") as fh:
        fh.write(json.dumps(bad) + "\n")
    with pytest.raises(ValueError, match="corrupt"):
        _append(w, "next")
