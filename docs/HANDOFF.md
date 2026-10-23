# Handoff: "install it and forget it" Synthe

Work in progress on branch `claude/modest-noether-9o09k1`. This note is for whoever picks it up next
(a local Claude Code session or a person). Delete it once the work is merged.

## The goal (founder)

Install Synthe, then just work with agents. You hear from Synthe only when it stops or flags
something, and it tells you why that mattered. Defaults are as autonomous as possible: no caps on
lanes or self-issued tasks unless someone asks for them.

## Done and merged on this branch

| Part | What | Where |
|---|---|---|
| Notifications | `synthe-notify watch / digest / test`: verifies the receipt chain, notifies only on stops and things waiting for a person, plain-English "what this stopped and why it matters" for every reason code, weekly digest | `src/synthe_notify.py`, `docs/NOTIFY.md`, `tests/test_notify.py` |
| One-command lanes | `synthe-task grant / grants / revoke-grant`; setup ends with "How hands-off?" (the autonomous lane is the default answer) | `src/synthe_grant.py`, `src/synthe_init.py` (`lane-offer`), `tests/test_task_grant.py` |
| Risk-aware lanes | grant field `auto_approve` (default `["routine","review"]`); high-risk pushes and pushes outside the lane's paths are staged for a person (`risk_escalated`, `outside_lane_paths`); limits optional (omit `max_uses` / `expires_at` = none) | `src/synthe_risk.py`, `src/synthe_lane_templates.py`, `src/synthe_commit.py`, `tests/test_risk*.py` |
| Self-issued tasks: design | how the broker issues tasks inside a lane so the person stops signing every task | `docs/design/SELF_ISSUED_TASKS.md` |
| Notifications at login | `synthe-notify install-agent / uninstall-agent` (LaunchAgent / `systemd --user`, refused in the agent's and broker's accounts); setup asks "Turn notifications on?" after the lane; installers list `synthe-notify` | `src/synthe_notify.py`, `src/synthe_init.py` (`notify-offer`), `docs/NOTIFY.md` |
| Self-issued tasks (v0.7) | plain `git push` with no signed task inside a self-issue lane: the broker issues a task (issuer key `synthe-issuer`), claims, a routine push lands with nobody asked; `trusted_senders` (Phase 0); revoke/expiry kill unlanded tasks; `task_origin` on receipts, card, reviewer, digest; `synthe-task grant --self-issue` (on for setup's lane); `synthe_start_task` / `synthe-client start` | SPEC.md section 16, `docs/COMMIT.md`, `THREAT_MODEL.md`, `tests/test_self_issue*.py`, `scripts/redteam_live.py` |

Founder decisions already made: no default limits anywhere; dependency manifests, lockfiles,
Dockerfiles and build scripts go out without asking under the default lane (review tier), and the
weekly digest lists them afterwards; only high-risk pushes (CI workflows, secret-like files, large
deletions or diffs) and out-of-lane pushes ask the person.

## Test status

Full suite on a Mac (Python 3.14 with `cryptography`) after the notifications commit: 1979 passed, 81
skipped, 37 xfailed, 0 failed. See the self-issue commits for the run after B.

Environment-only failures in the cloud sandbox (it runs as root, package not installed): 19 in
`tests/test_install_entrypoint.py`, 4 in `tests/test_plugin_mcp_startup.py`. They should pass on a Mac.
Baseline before this work: 1648 passed, those 23 failed.

## Still to do

### A. Integration: DONE except the quickstart
- DONE: escalation notifications, grants with `auto_approve` and omitted limits, `synthe-approver grant`,
  approval card wording, digest of review-tier pushes, `synthe-notify install-agent`, the setup offer and
  installer launchers.
- Quickstart (`QUICKSTART_OPENCLAW.md`) rewritten around install → lane + notifications → work → only hear
  from Synthe when it matters: a rewrite was in progress in the main checkout (uncommitted) when B landed.
  Finish it there, and mention that a plain `git push` needs no task once the lane is open.

### B. Self-issued tasks: DONE
Built from `docs/handoff/self-issue-wip.patch` (applied, then fixed and finished). The design doc's Status
section lists every decision that differs from the design. Tests: `tests/test_self_issue.py` (end to end
through the real broker and git-remote-synthe), `tests/test_self_issue_mutations.py` (each guard removed must
fail it), `tests/test_redteam_rehearsal.py` (rows SI-01..SI-16). Not done: a live red-team run of the SI rows
on an ENFORCED install (part of C), the TLA+ `Issue` action (`formal/` is not in this tree), Studio/console
wording. `docs/handoff/self-issue-wip.patch` is kept for the record; delete it with this note.

### C. Then
- Full suite on a Mac (`python3 -m pytest -q`), then the live red team (`docs/REDTEAM.md`) on a real
  ENFORCED install, adding rows for lanes, risk escalation and self-issue.
- Open a pull request to `main` when green.
