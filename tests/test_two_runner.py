"""Two-runner simulation tests for the GitHub Action ledger design.

These tests exercise github-action/simulate_two_runners.py, a LOCAL
MODEL of GitHub's hosted-runner environment: each runner is an isolated
temp workspace (no shared filesystem), and the ledger moves between
runners only through an explicit cache hand-off. They are NOT runs on
real GitHub infrastructure and do not claim to be; they pin the
semantics that the failure (and the Option 2 fix) depend on:

  S1  legacy v0.2 shape (two runners restore from the same empty
      snapshot, no serialization): BOTH accept the same key -- the
      cross-run bug, kept as a permanent regression witness.
  S2  fixed shape (runs serialized via the caller workflow's
      `concurrency` group + restore-latest cache chaining): exactly
      one ACCEPT; the second runner is REJECTED `duplicate` while the
      key is RESERVED.
  S3  completion path (claim -> complete step -> replay restoring the
      post-complete snapshot): replay is REJECTED `duplicate` against
      the COMPLETED entry.

The checker CLI itself is unmodified; verdict states come from
src/handoff_check.py v0.2 semantics (see test_conformance.py and
test_invariants.py for the checker-level suite).
"""
import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "simulate_two_runners", ROOT / "github-action" / "simulate_two_runners.py")
SIM = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SIM)


class TwoRunnerSimulationTest(unittest.TestCase):
    def setUp(self):
        import tempfile
        self._tmp = tempfile.TemporaryDirectory()
        self.base = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def test_S1_legacy_shape_double_accepts(self):
        # The v0.2 failure, reproduced in a local model. If this ever
        # FAILS (legacy stops double-accepting), the simulation has
        # drifted from the hosted-runner properties it models.
        self.assertTrue(SIM.mode_legacy(self.base / "legacy", lambda *a: None))

    def test_S2_fixed_shape_exactly_one_accept(self):
        ok, _ = SIM.mode_fixed(self.base / "fixed", lambda *a: None)
        self.assertTrue(ok)

    def test_S3_completion_path_replay_is_terminal_duplicate(self):
        self.assertTrue(SIM.mode_complete(self.base / "complete", lambda *a: None))


if __name__ == "__main__":
    unittest.main()
