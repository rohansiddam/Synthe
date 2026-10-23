#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""synthe-notify: hear from Synthe only when it stops or flags something, and what that was worth.

  synthe-notify watch  [--once] [--interval 15] [--from-start] [--all-refusals] [--stdout]
  synthe-notify digest [--days 7] [--json]
  synthe-notify test
  synthe-notify install-agent | uninstall-agent    (run `watch` at login: LaunchAgent / systemd --user)

Run it in YOUR account, not the agent's and not the broker's. It reads the broker's receipt chain,
checks the chain against the broker's public key (synthe_verify.py, the same code `synthe-verify`
runs) and only then decides what is worth your attention. A chain that does not verify is never
notified from: you get one loud message that it failed, and nothing else.

Quiet: pushes that went out under a task or lane you already signed, approvals you gave yourself,
repeats of a push that already happened, refusals the agent can simply retry (use --all-refusals to
hear those too).
Notified: a push waiting for you (or sent to you by a reviewer), a risky attempt that was stopped,
and a problem that needs a look (credentials missing, a push GitHub does not show, a grant used up).

Where the receipts come from: `--receipts FILE`, else the broker socket (`--broker`, SYNTHE_BROKER or
the address `synthe-init` wrote to ~/.synthe/setup.json; the same read-only `receipts` call the
console uses, newest 1000). Where the broker's public key comes from: `--key`, else the config file,
else /Users/Shared/Synthe/broker.pub.json. Settings live in ~/.synthe/notify.json (0600 if it holds a
Slack webhook URL, which is never printed or logged); the last receipt notified, and the digest of
it, in ~/.synthe/notify-state.json.

Everything in a receipt that an agent can influence (branch names, paths, messages) is untrusted
text: control codes are stripped, it is shortened, and it is never put into a script or markup.

Exit 0: ran. Exit 1: the chain did not verify. Exit 2: could not run (no key, no receipts, bad args).
Stdlib only.
"""
from __future__ import annotations

import argparse
import datetime as dt
import fnmatch
import html
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))
import synthe_verify as sv  # noqa: E402

HOME_DIR = Path("~/.synthe")
DEFAULT_CONFIG = HOME_DIR / "notify.json"
DEFAULT_STATE = HOME_DIR / "notify-state.json"
KEY_CANDIDATES = (Path("/Users/Shared/Synthe/broker.pub.json"), Path("/var/lib/synthe-shared/broker.pub.json"))
WINDOW = 1000            # the broker's `receipts` call returns at most this many, newest
MAX_RECEIPT_FILE = 256 * 1024 * 1024
BODY_LIMIT = 230         # desktop banners cut long text; keep it short enough to read at a glance
BATCH_LIMIT = 3          # more notifications than this in one poll become one summary
LIST_LIMIT = 10          # lines per list in the digest

# --------------------------------------------------------------------------
# untrusted text

_ANSI = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)?|[@-Z\\-_])")
# C0/C1 controls (newline and tab too), DEL, and the invisible or reordering Unicode controls.
_CONTROL = re.compile("[\x00-\x1f\x7f-\x9f؜​-‏ -‮⁠-⁩﻿]")


def clean(text, limit: int = 120) -> str:
    """Agent-influenced text made safe to show: terminal escapes and control characters removed,
    whitespace collapsed, shortened. Never trust it further than that."""
    s = "" if text is None else str(text)
    s = _CONTROL.sub(" ", _ANSI.sub("", s))
    s = " ".join(s.split())
    return s if len(s) <= limit else s[:max(limit - 1, 0)].rstrip() + "…"


def slack_escape(text: str) -> str:
    """Slack's three reserved characters. Without this a branch named `<!channel>` pings everyone."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


# --------------------------------------------------------------------------
# what each reason code means, in plain English
#
# code -> (category, what happened, why it matters). Categories:
#   stop     the agent went past a line you drew: worth hearing about
#   problem  something broke or ran out and needs a person
#   retry    routine; the agent can fix its request and try again (quiet unless --all-refusals)
#   noise    a harmless repeat
# Keep these honest: say what Synthe did and what it would otherwise have allowed, nothing about
# intent or about whether code is good. A test fails when a code Synthe emits has no entry here.

MESSAGES = {
    # --- where a push would land, and what it would touch
    "path_outside_scope": ("stop", "the agent tried to change files outside the folders this task allows",
                           "A task only covers the paths it was signed for."),
    "path_outside_receiver_policy": ("stop", "the agent tried to change files outside the folders your policy allows it",
                                     "Your policy limits where this agent may write."),
    "path_forbidden": ("stop", "the agent tried to change a file your policy keeps off-limits",
                       "Those paths are marked as never to be touched by an agent."),
    "branch_not_allowed": ("stop", "the agent tried to push to a branch it is not allowed to use",
                           "Agents may only push to the branches you listed, so your main branch is untouched."),
    "remote_unknown": ("stop", "the agent tried to push to a repository Synthe is not set up for",
                       "Synthe only pushes to the repositories you configured."),
    "bad_branch": ("retry", "the agent named a branch that is not valid", "The request was malformed."),
    "non_fast_forward": ("stop", "the agent tried to rewrite branch history (a force-push or rebase)",
                         "That can erase other people's commits. Synthe never does it."),
    "unrelated_history": ("stop", "the agent tried to push history that does not build on the branch",
                          "That would replace the branch with a different history."),
    "too_many_commits": ("stop", "the agent tried to push far more commits than the limit",
                         "A push that large is refused so a person can look at it first."),
    "no_change": ("noise", "the agent proposed a push that changes nothing", "The branch already had it."),
    "base_missing": ("retry", "the agent based a branch on one that does not exist",
                     "There was nothing to build on; the request has to be fixed."),
    "remote_moved": ("retry", "the branch changed after the agent last looked",
                     "The push was refused rather than overwrite newer work. The agent can sync and try again."),
    "remote_moved_during_commit": ("retry", "the branch moved at the moment of the push",
                                   "Synthe's compare-and-swap refused it so newer work was not overwritten."),
    "source_not_allowed": ("stop", "the agent offered commits from a place Synthe does not accept",
                           "Synthe only takes code from locations you allowed."),
    "source_path_not_allowed": ("stop", "the agent pointed Synthe at a folder on its own disk",
                                "Synthe reads only the bundle the agent sends, not arbitrary folders."),
    "commit_unavailable": ("retry", "the agent proposed a commit Synthe could not find",
                           "It was probably not included in what the agent sent."),
    "bundle_too_large": ("retry", "the agent sent more data than the size limit", "Large uploads are refused."),
    "bundle_failed": ("retry", "Synthe could not read the commits the agent sent", "The upload was unusable."),
    "push_rejected": ("problem", "GitHub refused the push (for example a protected branch)",
                      "Nothing reached the branch."),
    "push_failed": ("retry", "GitHub had an error during the push", "Synthe will try again."),
    "remote_unreachable": ("retry", "Synthe could not reach GitHub", "It will try again later."),
    "broker_credentials_missing": ("problem", "Synthe has no GitHub credentials",
                                   "It cannot push anything until that is fixed."),
    "effect_unconfirmed": ("problem", "a push ran but GitHub does not show the commit",
                           "Check the branch before relying on it. Synthe blocks a repeat until it is reconciled."),
    "effect_outcome_unknown": ("problem", "an earlier push attempt ended in an unknown state",
                               "Synthe blocks a repeat until you reconcile it, so nothing is pushed twice."),
    "effect_already_executed": ("noise", "the agent repeated a push that had already gone out",
                                "Synthe pushes each approved change once."),
    "duplicate_idempotency_key": ("noise", "the agent repeated a task it had already started",
                                  "Synthe runs each task once."),
    "effect_not_planned": ("stop", "the agent proposed an action its signed task never listed",
                           "Agents may only do what the task planned."),
    "effect_type_unsupported": ("stop", "the agent asked for a kind of action Synthe does not handle",
                                "Synthe only mediates the actions it was built to check."),
    "effect_params_unplanned": ("stop", "the signed task does not say which branch to push",
                                "Without a pinned target Synthe will not push."),
    "effect_params_mismatch": ("stop", "the agent proposed a different branch or repository than the task named",
                               "A task covers exactly the target it was signed for."),
    "effect_fingerprint_mismatch": ("stop", "the agent reused an earlier proposal for a different push",
                                    "Each approved push is bound to its exact contents."),
    "proposal_malformed": ("retry", "the agent sent a malformed push request", "It was incomplete or invalid."),
    "claim_token_required": ("retry", "the agent proposed a push without its task's claim token",
                             "Synthe only acts on work it registered."),
    "claim_token_invalid": ("stop", "the agent used a claim token that does not belong to this task",
                            "Synthe ties each push to the task it was issued for."),
    # --- file content proposals and reads
    "content_malformed": ("retry", "the agent sent file contents in a shape Synthe cannot use",
                          "The request was malformed."),
    "content_too_large": ("retry", "the agent sent more file content than the limit", "Large changes are refused."),
    "content_base_missing": ("retry", "the agent changed a file without saying which version it started from",
                             "Synthe needs that to be sure it is not overwriting newer work."),
    "content_conflict": ("retry", "a file changed after the agent read it",
                         "The push was refused rather than overwrite the newer version."),
    "path_invalid": ("stop", "the agent used a file path that breaks the path rules (for example one that leaves the repository)",
                     "Synthe refuses paths that could land outside the intended folder."),
    "read_not_allowed": ("stop", "the agent tried to read a branch or repository it may not read",
                         "Reads are limited to what you allowed."),
    "file_not_found": ("retry", "the agent asked for a file that does not exist", "Nothing to return."),
    "file_not_text": ("retry", "the agent asked for a file that is not plain text", "Synthe only serves text."),
    "file_too_large": ("retry", "the agent asked for a file over the size limit", "Synthe only serves small files."),
    # --- approvals
    "approval_missing": ("stop", "the agent tried to push without your approval",
                         "Pushes that need you are meant to wait for you."),
    "approver_not_trusted": ("stop", "an approval came from someone you have not authorized",
                             "Only the people you listed as trusted approvers can approve."),
    "approval_unsigned": ("stop", "an approval carried no signature",
                          "Anyone, including the agent, could write an unsigned approval."),
    "approval_signature_invalid": ("stop", "an approval's signature did not check out",
                                   "It may have been forged or altered."),
    "approval_expired": ("retry", "an approval had expired",
                         "Approvals are short-lived on purpose. Approve again if you still want the push."),
    "approval_expires_invalid": ("retry", "an approval had an unusable expiry time", "It was refused."),
    "approval_params_missing": ("stop", "an approval did not say which branch it covers",
                                "An approval with no target would cover anything."),
    "approval_params_mismatch": ("stop", "an approval was for a different push than the one proposed",
                                 "An approval covers exactly the target you saw."),
    "approval_commit_missing": ("retry", "an approval did not name the exact commit",
                                "Synthe requires it, so the push stays held until you approve that commit."),
    "approval_version_unsupported": ("problem", "an approval was signed with an old format",
                                     "Approve again with the current tools."),
    "approval_budget_missing": ("retry", "an approval set no spending limit", "Approve again with a limit."),
    "approval_budget_exceeded": ("stop", "the task asks for more budget than its approval allows",
                                 "Approvals cap what a task may spend."),
    "approval_estimates_exceeded": ("stop", "the work is estimated above what the approval allows",
                                    "Approvals cap what a task may spend."),
    "approval_kid_required": ("retry", "an approval did not say which key signed it", "It cannot be checked."),
    "approval_key_revoked": ("stop", "an approval was signed with a key that has been revoked",
                             "Revoked keys are no longer trusted."),
    "approval_malformed": ("retry", "an approval was incomplete or malformed", "It was refused."),
    "approval_duplicate": ("noise", "the same approval arrived twice", "The second copy was ignored."),
    "unknown_agent": ("stop", "a message named a sender or receiver Synthe does not know",
                      "Only registered agents are trusted."),
    # --- reviewer (delegate) approvals and escalations
    "delegate_invalid": ("problem", "a lane grant names a reviewer that is not allowed",
                         "Fix or re-sign the grant."),
    "delegate_malformed": ("retry", "a reviewer's decision was malformed", "It was refused."),
    "delegate_signature_invalid": ("stop", "a reviewer's decision had a bad signature",
                                   "It may have been forged or altered."),
    "delegate_not_named": ("stop", "someone other than the grant's reviewer tried to approve a push",
                           "Only the reviewer you named can approve under a grant."),
    "delegate_is_party": ("stop", "the side that proposed a push tried to approve it",
                          "An agent cannot approve its own work."),
    "delegate_approval_missing": ("retry", "the reviewer has not approved the push yet", "The push waits."),
    "delegate_approval_stale": ("retry", "a reviewer's approval no longer matches the push",
                                "The push changed after it was approved."),
    "delegate_approval_expired": ("retry", "a reviewer's approval had expired", "It needs a fresh decision."),
    "delegate_approval_too_long": ("retry", "a reviewer's approval asked to last longer than allowed",
                                   "It was refused."),
    "delegate_escalated": ("retry", "a reviewer sent this push to you", "Only a human approval commits it."),
    "delegate_store_corrupt": ("problem", "Synthe cannot read its record of reviewer decisions",
                               "It refuses to act on a record it cannot trust."),
    # --- lane grants (templates)
    "template_malformed": ("problem", "a lane grant is malformed", "It cannot be used."),
    "template_scope": ("stop", "the agent tried to push outside the lane you granted",
                       "A lane covers only the branch and paths you signed."),
    "template_unavailable": ("problem", "the lane grant a push relied on is not usable", "The push was refused."),
    "template_signature_invalid": ("stop", "a lane grant's signature did not check out",
                                   "It may have been altered after you signed it."),
    "template_expired": ("problem", "a lane grant has expired", "Pushes under it need you again until you renew it."),
    "template_stale": ("problem", "a lane grant no longer matches your policy",
                       "Policy or approvers changed since you signed it. Grant it again."),
    "template_revoked": ("retry", "a push relied on a lane grant you revoked", "Revoked grants stop working at once."),
    "template_exhausted": ("problem", "a lane grant has no pushes left",
                           "Its allowance is used up. Grant more, or approve pushes yourself."),
    "template_id_reused": ("stop", "someone reused the id of an existing lane grant", "Grant ids are never reused."),
    "risk_escalated": ("retry", "your lane sent a push to you instead of letting it through",
                       "It is a riskier kind than the lane approves on its own, so only your approval commits it."),
    "outside_lane_paths": ("retry", "a push touches files outside your lane, so it was sent to you",
                           "A lane only covers the files you signed it for; anything else needs your approval."),
    "risk_rules_invalid": ("problem", "Synthe's risk rules are malformed, so lane pushes wait for you",
                           "Nothing goes out on its own until the rules in the broker's config are fixed."),
    "template_revocation_invalid": ("stop", "a revocation not signed by a trusted person was ignored",
                                    "Only your signature can revoke a grant."),
    "template_store_corrupt": ("problem", "Synthe cannot read its record of lane grants",
                               "It refuses to act on a record it cannot trust."),
    "registry_unreadable": ("problem", "Synthe could not read its list of trusted agents and keys",
                            "It refuses to act without it."),
    "registry_malformed": ("problem", "Synthe's list of trusted agents and keys is malformed",
                           "It refuses to act on a list it cannot read."),
    "registry_signature_invalid": ("problem", "Synthe's signed list of trusted keys does not verify",
                                   "It refuses to act on a list it cannot trust."),
    # --- ordering between tasks
    "dependency_incomplete": ("retry", "a push waits for another task that has not finished", "It will go when that one does."),
    "dependency_unknown": ("retry", "a push waits for a task Synthe has never seen", "It cannot go until that task exists."),
    "dependency_cycle": ("retry", "tasks were set up to wait on each other in a circle", "None of them could ever start."),
    "claim_conflict": ("retry", "another running task may touch the same files", "Synthe held this one back."),
    "staged": ("noise", "a push is being held", "It waits for what it needs."),
    # --- the signed task (checked when a task is accepted, and again at push time)
    "signature_missing": ("stop", "the agent worked from a task that was not signed",
                          "Synthe only acts on tasks signed by someone you trust."),
    "signature_invalid": ("stop", "a task's signature did not check out", "It may have been altered after it was signed."),
    "signature_malformed": ("stop", "a task's signature was unreadable", "Synthe cannot tell who signed it."),
    "signature_unsupported": ("stop", "a task used a signature scheme Synthe does not accept", "It was refused."),
    "signature_alg_unsupported": ("stop", "a task used a signature scheme Synthe does not accept", "It was refused."),
    "signature_kid_required": ("stop", "a task did not say which key signed it", "Synthe cannot check it."),
    "signature_key_unknown": ("stop", "a task was signed by a key Synthe does not know", "Only registered keys are trusted."),
    "signature_key_revoked": ("stop", "a task was signed with a key that has been revoked", "Revoked keys are no longer trusted."),
    "signature_signer_mismatch": ("stop", "a task was signed by someone other than its stated sender", "Synthe refused it."),
    "handoff_expired": ("retry", "the agent used a task that has expired",
                        "Tasks expire on purpose. Issue a new one if the work should continue."),
    "ttl_exceeded": ("stop", "a task asks to live longer than your policy allows", "Synthe refused it."),
    "budget_exceeded": ("stop", "a task asks for more budget than your policy allows", "Synthe refused it."),
    "authority_exceeds_receiver_policy": ("stop", "a task asks for more power than your policy gives this agent",
                                          "Synthe refuses tasks that go beyond the agent's policy."),
    "forbidden_action": ("stop", "a task asks for an action your policy forbids", "Synthe refused it."),
    "tool_not_allowed": ("stop", "a task uses a tool it is not allowed to use", "Synthe refused it."),
    "tool_not_allowed_by_receiver": ("stop", "a task uses a tool this agent's policy does not allow", "Synthe refused it."),
    "receiver_mismatch": ("stop", "a task meant for another agent was used here", "Tasks are bound to the agent they name."),
    "topology_violation": ("stop", "an agent sent work to one it is not allowed to", "Your agent layout does not permit it."),
    "topology_declaration_missing": ("problem", "the agent-roles setup is incomplete", "Synthe cannot check who may talk to whom."),
    "topology_malformed": ("problem", "the agent-roles setup is malformed", "Synthe cannot check who may talk to whom."),
    "topology_role_unbound": ("problem", "an agent role is not bound to a key", "Synthe cannot check who may talk to whom."),
    "topology_signature_invalid": ("problem", "the agent-roles setup does not verify", "Synthe will not rely on it."),
    "topology_signature_missing": ("problem", "the agent-roles setup is unsigned", "Synthe will not rely on it."),
    "topology_signer_not_founder": ("problem", "the agent-roles setup was not signed by its founder", "Synthe will not rely on it."),
    "evidence_hash_mismatch": ("stop", "evidence attached to a task does not match its recorded fingerprint",
                               "It may have been swapped after the task was signed."),
    "evidence_path_escapes_workspace": ("stop", "a task pointed at evidence outside its workspace", "Synthe refused to read it."),
    "evidence_missing": ("retry", "a task is missing evidence it requires", "It cannot be accepted yet."),
    "evidence_ref_missing": ("retry", "a task's evidence points at a file that is not there", "It cannot be accepted yet."),
    "evidence_unreferenced": ("retry", "a task lists evidence it does not use", "It was refused."),
    "evidence_not_verbatim": ("retry", "a task's evidence is not the exact text it claims", "It was refused."),
    "verbatim_evidence_unpinned": ("retry", "a task's exact-text evidence is not pinned to a fingerprint", "It was refused."),
    "artifact_hash_mismatch": ("stop", "a file attached to a task does not match its recorded fingerprint",
                               "It may have been swapped after the task was signed."),
    "artifact_path_escapes_workspace": ("stop", "a task pointed at a file outside its workspace", "Synthe refused to read it."),
    "artifact_missing": ("retry", "a file a task refers to is not there", "It cannot be accepted yet."),
    "capability_not_declared": ("stop", "an agent used a capability it never declared", "Synthe only allows what was declared."),
    "capability_declaration_missing": ("retry", "an agent did not declare its capabilities", "It cannot be accepted yet."),
    "capability_path_unsafe": ("stop", "a declared capability points at an unsafe path", "Synthe refused it."),
    "planned_actions_missing": ("retry", "a task lists no planned actions", "Synthe only acts on planned actions."),
    "workspace_required": ("problem", "Synthe has no workspace folder configured", "It cannot check a task's files."),
    "ledger_required": ("problem", "Synthe has no claim ledger configured", "It cannot track what ran."),
    "ledger_corrupt": ("problem", "Synthe's record of which tasks ran is damaged or unreadable",
                       "It refuses to act until that is looked at, so nothing runs twice."),
    "ledger_rollback": ("problem", "Synthe's record of which tasks ran looks older than it should",
                        "It refuses to act until that is looked at, so nothing runs twice."),
    "ledger_diverged": ("problem", "Synthe's record of which tasks ran does not match its seal",
                        "It refuses to act until that is looked at."),
    "ledger_anchor_unavailable": ("problem", "Synthe cannot check its record of which tasks ran against its anchor",
                                  "It refuses to act until that is looked at."),
    "malformed": ("retry", "a task was malformed", "Synthe could not use it."),
    "missing_field": ("retry", "a task is missing a required field", "Synthe could not use it."),
    "missing_handoff": ("retry", "a request carried no task", "Synthe could not use it."),
    "bad_schema_version": ("retry", "a task used an unsupported format version", "Synthe could not use it."),
    "bad_on_failure": ("retry", "a task has an invalid failure setting", "Synthe could not use it."),
    "bad_expires_at": ("retry", "a task has an unusable expiry time", "Synthe could not use it."),
    "packet_unreadable": ("retry", "a task file could not be read", "Synthe could not use it."),
    "missing_idempotency_key": ("retry", "a task has no unique id", "Synthe could not track it."),
    "alias_not_canonical": ("retry", "a task named an agent by a nonstandard alias", "Synthe could not match it."),
    "unknown_outcome": ("problem", "a task reported an outcome Synthe does not recognise", "Check what happened."),
    "reserved_idempotency_key": ("retry", "a task used a reserved id", "Synthe refused it."),
    "idempotency_key_reserved": ("retry", "a task used a reserved id", "Synthe refused it."),
    "legacy_claim_unbound": ("retry", "an old-style claim has no task attached", "Synthe refused it."),
    "completion_unknown_key": ("retry", "the agent reported finishing a task Synthe never started", "Nothing to complete."),
    "completion_handoff_mismatch": ("stop", "the agent reported finishing a task using a different task's paperwork",
                                    "Completions must match the task that started."),
    "completion_packet_mismatch": ("stop", "the agent reported finishing a task whose contents changed",
                                   "Completions must match the task that started."),
    "release_not_reserved": ("retry", "a request tried to release a claim that is not held", "Nothing to release."),
    "release_claim_fresh": ("retry", "a request tried to release a claim that is still fresh", "It was refused."),
    "replay_receipt_unverified": ("problem", "Synthe's receipts did not verify when it re-checked a finished push",
                                  "It will not repeat or replay the push until that is looked at."),
    "replay_receipt_mismatch": ("problem", "a finished push does not match its stored receipt",
                                "It will not repeat or replay the push until that is looked at."),
    "replay_result_unavailable": ("problem", "Synthe cannot find the result of a push that already ran",
                                  "It will not repeat the push."),
    # --- the broker's own door (these refuse a caller; they rarely appear in receipts)
    "broker_not_isolated": ("stop", "a program running as root or as the broker's own user tried to use the broker",
                            "Such a program could read the broker's keys, so Synthe refused it."),
    "client_not_allowed": ("stop", "an account you did not list tried to use the broker", "Only listed accounts may."),
    "unauthorized": ("stop", "a caller without the right token tried to use the broker", "Synthe refused it."),
    "request_malformed": ("retry", "a request to the broker was malformed", "It was refused."),
    "request_too_large": ("retry", "a request to the broker was too large", "It was refused."),
    "unknown_op": ("retry", "a request asked the broker for something it does not do", "It was refused."),
    "broker_error": ("problem", "the broker hit an internal error", "It keeps running; look at its log."),
    "broker_key_exposed": ("problem", "the broker's key file is readable by others", "Synthe refused to start."),
    "broker_credentials_exposed": ("problem", "the broker's GitHub token file is readable by others",
                                   "Synthe refused to start."),
    "broker_state_writable": ("problem", "the broker's files can be changed by other accounts", "Synthe refused to start."),
    "packet_required": ("retry", "a request carried no task", "It was refused."),
    "staged_unknown": ("retry", "a request named a held push that does not exist", "It was refused."),
    "task_artifact_invalid": ("retry", "a task's attached file was unusable", "Synthe refused the task."),
    "task_conflict": ("retry", "a task conflicts with one already issued for this branch", "Synthe refused it."),
    "task_hash_mismatch": ("stop", "a task file does not match its recorded fingerprint", "It may have been altered."),
    "task_path_invalid": ("stop", "a task named a file path that breaks the path rules", "Synthe refused it."),
    "task_sender_not_human": ("stop", "a task was issued by something other than a person you registered",
                              "Only a person you registered can issue tasks."),
    "task_too_large": ("retry", "a task file was larger than the limit", "Synthe refused it."),
}

SEVERITY = {"noise": 0, "retry": 1, "problem": 2, "stop": 3}
PREFIX = {"stop": "Blocked", "problem": "Needs a look", "retry": "Refused", "noise": "Ignored"}

GENERIC = ("problem", "Synthe refused something for a reason this notifier does not know",
           "See the receipt for the reason code.")

# Paths worth naming in plain words. Matched against the paths Synthe lists in a path refusal.
CI_PATHS = (".github/workflows/*", ".github/actions/*", ".gitlab-ci.yml", ".circleci/*", "jenkinsfile",
            "azure-pipelines.yml", ".buildkite/*")
SECRET_PATHS = ("*.pem", "*.key", "*.p12", "id_rsa*", "id_ed25519*", ".env", ".env.*", "*secret*", "*credential*",
                ".npmrc", ".netrc")
BUILD_PATHS = ("dockerfile", "dockerfile.*", "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
               "requirements*.txt", "pyproject.toml", "setup.py", "makefile", "cargo.toml", "cargo.lock",
               "go.mod", "go.sum", "gemfile", "gemfile.lock", "pom.xml", "build.gradle")
PATH_MEANING = {
    "ci": ("the agent tried to change a CI workflow",
           "That file controls what runs in CI, often with your secrets."),
    "secret": ("the agent tried to change a file that looks like it holds secrets or keys",
               "Files like that should not travel through an agent."),
    "build": ("the agent tried to change a build or dependency file",
              "Those files decide what code runs when your project is built or installed."),
}
_LISTED_PATH = re.compile(r"([^,]+?) \(path_[a-z_]+\)")


def lookup(code) -> tuple[str, str, str, bool]:
    """(category, what happened, why it matters, known) for a reason code. A code with a detail after
    a colon (`malformed:purpose`) uses the entry for the part before it."""
    base = str(code).split(":", 1)[0]
    entry = MESSAGES.get(base)
    return (*entry, True) if entry else (*GENERIC, False)


def path_class(paths) -> str | None:
    """'ci', 'secret' or 'build' when one of the listed paths is that kind of file (most serious first)."""
    found = set()
    for p in paths:
        low = p.lower()
        names = (low, low.rsplit("/", 1)[-1])
        for label, globs in (("ci", CI_PATHS), ("secret", SECRET_PATHS), ("build", BUILD_PATHS)):
            if any(fnmatch.fnmatch(n, g) for n in names for g in globs):
                found.add(label)
    return next((k for k in ("ci", "secret", "build") if k in found), None)


def listed_paths(reasons) -> list[str]:
    """The paths a path refusal names (`3 path(s) not allowed: a (path_forbidden), b (...)`)."""
    out = []
    for r in reasons:
        if isinstance(r, dict) and str(r.get("code", "")).startswith("path_") and isinstance(r.get("message"), str):
            tail = r["message"].split("not allowed:", 1)[-1]
            out += [m.group(1).strip() for m in _LISTED_PATH.finditer(tail)]
    return out


# What a lane's own escalation says (the receipt's `risk` and `lane_scope` objects). The broker wrote them,
# but they carry agent-influenced text (paths), so every string is cleaned and every field type-checked.
TIER_WORDS = {"routine": "routine", "review": "review-level", "high": "high-risk"}
PATH_VERBS = {"ci": "changes a CI workflow", "secret": "changes a file that looks like it holds secrets or keys",
              "build": "changes a build or dependency file"}
ESCALATIONS = ("risk_escalated", "outside_lane_paths")
SEE_DIFF = "Run synthe-approve to see the diff."


def _strings(x, limit: int, n: int = 50) -> list[str]:
    return [clean(p, limit) for p in x[:n] if isinstance(p, str)] if isinstance(x, list) else []


def _count(x, floor: int) -> int:
    return x if isinstance(x, int) and not isinstance(x, bool) and x >= floor else floor


def _and(items: list[str]) -> str:
    return items[0] if len(items) == 1 else ", ".join(items[:-1]) + " and " + items[-1]


def risk_words(r: dict, branch: str) -> tuple[str, str]:
    """(headline, why) for a push your lane sent to you because of its risk."""
    risk = r.get("risk") if isinstance(r.get("risk"), dict) else {}
    who = branch or "this push"
    tier = risk.get("tier") if isinstance(risk.get("tier"), str) and risk["tier"] in TIER_WORDS else None
    paths, reasons = _strings(risk.get("paths"), 70), _strings(risk.get("reasons"), 80)
    kind = path_class(paths)
    if kind:  # the path reasons ("changes x and 2 more") are covered by naming the kind of file
        extra = [x for x in reasons if not x.startswith("changes ")][:3]
        said = f"{who} {PATH_VERBS[kind]} ({paths[0]}{', …' if len(paths) > 1 else ''})" + "".join(f"; {x}" for x in extra)
    elif reasons:
        said = f"{who}: " + "; ".join(reasons[:3])
    else:
        said = f"{who} is a {TIER_WORDS.get(tier, 'riskier')} push"
    lets = [t for t in _strings(risk.get("auto_approve"), 20, 3) if t in TIER_WORDS]
    why = (f"Your lane lets {_and([TIER_WORDS[t] for t in lets])} work through; this one is {TIER_WORDS[tier]}."
           if lets and tier else "Your lane sends this kind of push to you.")
    return f"Needs you: {said}", f"{why} {SEE_DIFF}"


def scope_words(r: dict, branch: str) -> tuple[str, str]:
    """(headline, why) for a push that touches files outside your lane."""
    scope = r.get("lane_scope") if isinstance(r.get("lane_scope"), dict) else {}
    who = branch or "this push"
    outside, covers = _strings(scope.get("outside_paths"), 70), _strings(scope.get("path_scope"), 70, 3)
    n = _count(scope.get("outside_count"), len(outside))
    said = f"{who} changes {n} file{'s' if n != 1 else ''} outside your lane" if n else f"{who} changes files outside your lane"
    if outside:
        said += f" ({outside[0]}{', …' if n > 1 else ''})"
    more = " …" if isinstance(scope.get("path_scope"), list) and len(scope["path_scope"]) > 3 else ""
    why = f"Your lane covers {_and(covers)}{more}; anything else asks you." if covers else "Your lane does not cover them."
    return f"Needs you: {said}", f"{why} {SEE_DIFF}"


# --------------------------------------------------------------------------
# one receipt -> what to tell the person (or nothing)

LEVELS = ("quiet", "retry", "problem", "waiting", "stop")   # least to most worth hearing about
NOTIFY_LEVELS = ("stop", "waiting", "problem")
TITLES = {"stop": "Synthe stopped something", "waiting": "Synthe is waiting for you",
          "problem": "Synthe needs a look", "retry": "Synthe refused a push"}
WAIT_WORDS = {"approval": "your approval", "escalated": "your decision (a reviewer sent it to you)",
              "review": "its reviewer", "dependency": "another task"}
HUMAN_WAITS = {"approval", "escalated"}   # what in `staged.waiting_for` means a person
QUIET_WAITS = {"review", "dependency"}    # waits Synthe resolves without you
REFUSALS = ("denied", "errored", "unconfirmed", "approval_rejected", "delegate_approval_rejected",
            "escalation_rejected")
QUIET_SUFFIXES = ("_accepted", "_granted", "_revoked", "_issued")   # what a person did, or what settled


def _s(x):
    return x if isinstance(x, str) else ""


def proposal_id(r: dict) -> str | None:
    """`idempotency_key/action`: the id a staged push, its approval and its outcome share."""
    staged = r.get("staged") if isinstance(r.get("staged"), dict) else {}
    if _s(staged.get("id")):
        return staged["id"]
    h = r.get("handoff") if isinstance(r.get("handoff"), dict) else {}
    e = r.get("effect") if isinstance(r.get("effect"), dict) else {}
    d = r.get("delegate") if isinstance(r.get("delegate"), dict) else {}
    a = r.get("approval") if isinstance(r.get("approval"), dict) else {}
    action = _s(e.get("action")) or _s(d.get("action")) or _s(a.get("action"))
    return f"{h['idempotency_key']}/{action}" if _s(h.get("idempotency_key")) and action else None


def _waiting_for(r: dict) -> list[str]:
    staged = r.get("staged") if isinstance(r.get("staged"), dict) else {}
    w = staged.get("waiting_for")
    return [x for x in w if isinstance(x, str)] if isinstance(w, list) else []


def _reasons(r: dict) -> list[dict]:
    reasons = r.get("reasons")
    return [x for x in reasons if isinstance(x, dict)] if isinstance(reasons, list) else []


def _where(r: dict) -> str:
    e = r.get("effect") if isinstance(r.get("effect"), dict) else {}
    return clean(e.get("branch"), 60)


def describe(r: dict) -> dict:
    """Classify one receipt and word it. `level` is one of LEVELS; `quiet` means say nothing. The wording
    only ever uses the reason codes (our table) and a few short, cleaned strings (branch, a path)."""
    kind, decision = r.get("kind"), _s(r.get("decision"))
    reasons = _reasons(r)
    out = {"seq": r.get("seq"), "time": _s(r.get("time")), "kind": clean(kind, 40) if isinstance(kind, str) else None,
           "decision": clean(decision, 40), "id": proposal_id(r), "branch": _where(r), "level": "quiet",
           "codes": [clean(x.get("code"), 60) for x in reasons], "title": "", "body": "", "known": True,
           "headline": "", "why": "", "lane": None}
    observed = r.get("observed") if isinstance(r.get("observed"), dict) else {}
    paths = observed.get("paths") if isinstance(observed.get("paths"), list) else []
    on = f" on '{out['branch']}'" if out["branch"] else ""
    low = decision.lower()

    def say(level, headline, why):
        out.update(level=level, title=TITLES[level], headline=headline, why=why, body=f"{headline}. {why}")
        return out

    # 1. waiting for a person, or sent to one
    waits = _waiting_for(r)
    if (decision == "staged" or ("escalat" in low and "reject" not in low)
            or any(w in low for w in ("await", "pending", "needs_human", "needs_approval"))):
        if decision == "staged" and waits and not set(waits) - QUIET_WAITS:
            return out  # held for its reviewer or another task: Synthe settles that without you
        codes = {x.get("code") for x in reasons}
        if decision == "staged" and "risk_rules_invalid" in codes:
            return say("problem", f"Needs a look: pushes under your lane are waiting for you{on} because the risk "
                                  f"rules in the broker's config are malformed", "Fix them and the lane works again.")
        if decision == "staged" and "risk_escalated" in codes:
            out["lane"] = "risk"
            return say("waiting", *risk_words(r, out["branch"]))
        if decision == "staged" and "outside_lane_paths" in codes:
            out["lane"] = "scope"
            return say("waiting", *scope_words(r, out["branch"]))
        who = ", ".join(WAIT_WORDS.get(w, clean(w, 30)) for w in waits if w not in QUIET_WAITS) or "you"
        what = f"a push{on}" + (f" ({len(paths)} file{'s' if len(paths) != 1 else ''})" if paths else "")
        if "escalat" in low:
            return say("waiting", f"A reviewer sent {what} to you",
                       "Only your approval can commit it. Run synthe-approve to see the diff.")
        return say("waiting", f"The agent wants to make {what}",
                   f"It is waiting for {who}. Run synthe-approve to see the diff.")
    # 2. things that went out, or were accepted
    if decision == "executed" or low.endswith(QUIET_SUFFIXES) or low == "approval_duplicate":
        return out
    # 3. refusals and trouble: worded from the reason table, by the most serious reason
    if decision in REFUSALS:
        ranked = [(SEVERITY[c], c, t, w, k) for c, t, w, k in (lookup(x.get("code")) for x in reasons)]
        if ranked:
            _, cat, tried, why, known = max(ranked, key=lambda t: t[0])
            if len(ranked) > 1:
                why += f" (+{len(ranked) - 1} more reason{'s' if len(ranked) > 2 else ''})"
        else:
            cat, tried, why, known = ("problem", f"Synthe recorded '{clean(decision, 30)}' without a reason",
                                      "Look at the receipt.", False)
        if decision == "unconfirmed":
            cat = max(cat, "problem", key=SEVERITY.get)
        shown = listed_paths(reasons)
        if cat == "stop" and path_class(shown):
            tried, why = PATH_MEANING[path_class(shown)]
            tried += f" ({clean(shown[0], 70)}{', ...' if len(shown) > 1 else ''})"
        out["known"] = known
        if cat == "noise":
            return out
        at = on if cat == "stop" else (f" (branch '{out['branch']}')" if out["branch"] else "")
        say(cat, f"{PREFIX[cat]}: {tried}{at}", why)
        if decision != "unconfirmed":
            out["body"] += " Nothing was pushed."
        return out
    # 4. a decision this notifier has never seen: never silent
    out["known"] = False
    return say("problem", f"Synthe recorded something this notifier does not know ({clean(kind or 'push', 30)}, "
                          f"'{clean(decision, 30)}')", "Look at the receipt.")


def notifiable(event: dict, all_refusals: bool = False) -> bool:
    return event["level"] in NOTIFY_LEVELS or (all_refusals and event["level"] == "retry")


def select(receipts: list, all_refusals: bool = False) -> list:
    """The events worth sending for a batch of new receipts, oldest first. A wait that was settled later in
    the same batch (you approved it, it shipped) is dropped: nobody needs telling about it."""
    events = [describe(r) for r in receipts]
    out = []
    for i, e in enumerate(events):
        if not notifiable(e, all_refusals):
            continue
        if e["level"] == "waiting" and e["id"] and any(
                later["id"] == e["id"] and (later["decision"] in ("executed", "denied", "approval_accepted"))
                for later in events[i + 1:]):
            continue
        out.append(e)
    return out


def summarize_batch(events: list) -> dict:
    """One message for a burst, so a looping agent cannot flood the screen."""
    counts = {lv: sum(1 for e in events if e["level"] == lv) for lv in ("stop", "waiting", "problem", "retry")}
    parts = [f"{n} {word}" for lv, word in (("stop", "stopped"), ("waiting", "waiting for you"),
                                            ("problem", "needing a look"), ("retry", "refused")) if (n := counts[lv])]
    top = max(events, key=lambda e: LEVELS.index(e["level"]))
    return {"level": top["level"], "title": f"Synthe: {len(events)} things happened",
            "body": clean(", ".join(parts) + ". Latest: " + events[-1]["body"], BODY_LIMIT), "seq": events[-1]["seq"]}


# --------------------------------------------------------------------------
# delivery: desktop banner, Slack, plain output

APPLESCRIPT = ("on run argv", "display notification (item 1 of argv) with title (item 2 of argv)", "end run")


def _argv_safe(text: str) -> str:
    """No leading dash (an option to the tool) and never empty."""
    return text.lstrip("-").strip() or "(no text)"


def desktop_command(title: str, body: str, level: str = "waiting", platform: str | None = None,
                    which=shutil.which, environ=None) -> list | None:
    """The argv that shows a desktop banner, or None. The text goes in as separate arguments, never into
    a script or a shell line: on macOS the AppleScript is a fixed program that reads its two arguments."""
    platform, environ = platform or sys.platform, os.environ if environ is None else environ
    title, body = _argv_safe(clean(title, 80)), _argv_safe(clean(body, BODY_LIMIT))
    if platform == "darwin" and which("osascript"):
        cmd = ["osascript"]
        for line in APPLESCRIPT:
            cmd += ["-e", line]
        return cmd + [body, title]
    if platform.startswith("linux") and which("notify-send") and (
            environ.get("DISPLAY") or environ.get("WAYLAND_DISPLAY") or environ.get("DBUS_SESSION_BUS_ADDRESS")):
        urgency = "critical" if level == "stop" else "normal"
        # notify-send shows a little markup; a branch name must not be able to add any.
        return ["notify-send", "--app-name=Synthe", f"--urgency={urgency}", "--",
                html.escape(title, quote=False), html.escape(body, quote=False)]
    return None


def send_desktop(title, body, level="waiting", run=subprocess.run, **kw) -> bool:
    cmd = desktop_command(title, body, level, **kw)
    if cmd is None:
        return False
    try:
        return run(cmd, shell=False, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                   timeout=15, check=False).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def slack_payload(title: str, body: str) -> dict:
    text = f"*{slack_escape(clean(title, 80))}*\n{slack_escape(clean(body, 600))}"
    return {"text": text, "unfurl_links": False, "unfurl_media": False}


def slack_url_ok(url) -> bool:
    p = urlsplit(url) if isinstance(url, str) else None
    return bool(p and p.scheme == "https" and p.hostname and (p.hostname == "slack.com" or p.hostname.endswith(".slack.com"))
                and p.path.startswith("/") and not p.username and not p.password)


def send_slack(url, title, body, opener=urllib.request.urlopen) -> str | None:
    """None on success, else a short reason with no URL in it."""
    if not slack_url_ok(url):
        return "the Slack webhook URL must be https on slack.com"
    req = urllib.request.Request(url, data=json.dumps(slack_payload(title, body)).encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    try:
        with opener(req, timeout=10) as resp:
            return None if 200 <= getattr(resp, "status", 200) < 300 else f"Slack answered {resp.status}"
    except urllib.error.HTTPError as e:
        return f"Slack answered {e.code}"
    except (urllib.error.URLError, OSError, ValueError) as e:
        return f"could not reach Slack ({type(e).__name__})"


class Notifier:
    """Sends one message to every configured place. Desktop banner where the system has one, Slack if a
    webhook is configured, and the terminal (or log) when asked or when nothing else worked."""

    def __init__(self, config: dict | None = None, stdout: bool = False, out=None, err=None, run=subprocess.run,
                 opener=urllib.request.urlopen, clock=time.time):
        self.config, self.stdout = config or {}, stdout
        self.out, self.err = out or sys.stdout, err or sys.stderr
        self.run, self.opener, self.clock = run, opener, clock
        self.slack_warned = False

    def send(self, title: str, body: str, level: str = "waiting") -> list:
        title, body = clean(title, 80), clean(body, BODY_LIMIT * 2)
        done = []
        if self.config.get("desktop", True) and send_desktop(title, body, level, run=self.run):
            done.append("desktop")
        url = self.config.get("slack_webhook")
        if url:
            problem = send_slack(url, title, body, self.opener)
            if problem is None:
                done.append("slack")
            elif not self.slack_warned:
                self.slack_warned = True
                print(f"synthe-notify: Slack delivery failed: {problem}", file=self.err)
        if self.stdout or not done:
            stamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.clock()))
            print(f"[{stamp}] {title}: {body}", file=self.out, flush=True)
            done.append("stdout")
        return done


# --------------------------------------------------------------------------
# config and state (in your account; no secret is ever printed)

def load_config(path) -> tuple[dict, list]:
    """(settings, warnings). A Slack webhook URL is a credential: it is only used from a file that
    others cannot read."""
    p, warnings, cfg = Path(path).expanduser(), [], {}
    try:
        st = p.stat()
        raw = json.loads(p.read_text())
    except FileNotFoundError:
        return {}, []
    except (OSError, ValueError):
        return {}, [f"{p} could not be read as JSON; ignoring it"]
    if not isinstance(raw, dict):
        return {}, [f"{p} is not a JSON object; ignoring it"]
    for k in ("key", "broker", "receipts", "signer"):
        if isinstance(raw.get(k), str) and raw[k]:
            cfg[k] = raw[k]
    for k in ("desktop", "all_refusals"):
        if isinstance(raw.get(k), bool):
            cfg[k] = raw[k]
    if raw.get("slack_webhook"):
        if st.st_mode & 0o077:
            warnings.append(f"{p} holds a Slack webhook but others can read it (chmod 600 {p}); Slack is off")
        elif slack_url_ok(raw["slack_webhook"]):
            cfg["slack_webhook"] = raw["slack_webhook"]
        else:
            warnings.append(f"{p}: slack_webhook must be an https URL on slack.com; Slack is off")
    return cfg, warnings


def load_state(path) -> dict:
    try:
        s = json.loads(Path(path).expanduser().read_text())
        if (isinstance(s, dict) and isinstance(s.get("seq"), int) and not isinstance(s["seq"], bool) and s["seq"] >= 0
                and (s.get("head") is None or isinstance(s["head"], str))):
            return s
    except (OSError, ValueError):
        pass
    return {}


def save_state(path, state: dict) -> None:
    p = Path(path).expanduser()
    p.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = p.with_name(p.name + f".{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(json.dumps(state, indent=2) + "\n")
    os.replace(tmp, p)


# --------------------------------------------------------------------------
# reading and verifying the chain

class SourceError(Exception):
    """The receipts or the key could not be obtained (not the same as a chain that fails to verify)."""


def find_key(explicit: str | None, config: dict, candidates=KEY_CANDIDATES, home: Path | None = None) -> Path:
    """The broker's public key file: the one you named, else a published or dev location. A key found by
    search must not be writable by anyone else, or whoever can write it could choose who is trusted."""
    if explicit or config.get("key"):
        p = Path(explicit or config["key"]).expanduser()
        if not p.is_file():
            raise SourceError(f"no key file at {p}")
        return p
    home = home or Path.home()
    found = [*candidates, home / ".synthe" / "broker" / "registry.json"]
    for p in found:
        try:
            if p.is_file() and not p.stat().st_mode & 0o022:
                sv.load_trust(sv.strict_loads(p.read_text()), None)
                return p
        except (OSError, ValueError):
            continue
    raise SourceError("no broker public key found: pass --key (on a configured Mac it is "
                      "/Users/Shared/Synthe/broker.pub.json)")


def load_trust(path: Path, signer: str | None) -> dict:
    try:
        return sv.load_trust(sv.strict_loads(Path(path).read_text(encoding="utf-8")), signer)
    except (OSError, ValueError) as e:  # TrustError and strict JSON errors are ValueErrors
        raise SourceError(f"cannot use the key file {path}: {clean(e, 120)}") from None


def read_receipt_file(path) -> bytes:
    p = Path(path).expanduser()
    try:
        if p.stat().st_size > MAX_RECEIPT_FILE:
            raise SourceError(f"{p} is too large to read")
        return p.read_bytes()
    except OSError as e:
        raise SourceError(f"cannot read {p}: {clean(e.strerror or e, 80)}") from None


def read_broker(url: str | None, client=None) -> dict:
    """The newest receipts through the broker's read-only `receipts` call: {"receipts", "count"}."""
    try:
        import synthe_client as scl
        client = client or scl.BrokerClient(url, timeout=30)
        res = client.call("receipts", limit=WINDOW)
    except Exception as e:  # BrokerError and everything a socket can raise
        raise SourceError(f"cannot read receipts from the broker: {clean(e, 160)}") from None
    receipts = res.get("receipts") if isinstance(res, dict) else None
    if not isinstance(receipts, list) or not all(isinstance(x, dict) for x in receipts):
        raise SourceError("the broker's answer had no receipts in it")
    return {"receipts": [{k: v for k, v in x.items() if k != "verified"} for x in receipts],  # a display flag
            "count": res.get("count") if isinstance(res.get("count"), int) else len(receipts)}


def _lines(receipts: list) -> bytes:
    return b"\n".join(json.dumps(r, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode() for r in receipts)


def _window_report(receipts: list, trust: dict, anchor: dict | None) -> dict:
    """Verify receipts that do not start at seq 1: every signature and link inside the window, and the
    window itself tied to a receipt this tool verified before (its recorded seq and digest)."""
    errors = []

    def fail(code, detail, seq=None):
        errors.append({"line": None, "seq": seq, "code": code, "detail": detail})

    first = receipts[0].get("seq")
    if not isinstance(first, int) or isinstance(first, bool):
        fail("field_invalid", "seq is not an integer")
        return {"ok": False, "errors": errors, "count": 0, "head": None, "signer": trust["signer"], "decisions": {}}
    digests, prev = {}, None
    for i, r in enumerate(receipts):
        seq = first + i
        if r.get("seq") != seq:
            fail("seq_gap", f"expected seq {seq}", r.get("seq") if isinstance(r.get("seq"), int) else None)
        try:
            digest = sv.receipt_digest(r)
        except (ValueError, UnicodeEncodeError, RecursionError):
            fail("field_invalid", "cannot canonicalize", seq)
            prev = None
            continue
        if prev is not None and r.get("prev") != prev:
            fail("prev_mismatch", "prev is not the digest of the receipt before it", seq)
        sv._check_signature(r, trust, seq, fail)
        digests[seq] = digest
        prev = digest
    if anchor is None or anchor.get("head") is None:
        fail("window_unanchored", f"only receipts from seq {first} on were available and there is no earlier "
                                  f"verified receipt to tie them to; give --receipts FILE for the whole chain")
    elif anchor["seq"] >= first:
        if digests.get(anchor["seq"]) != anchor["head"]:
            fail("checkpoint_mismatch", f"receipt {anchor['seq']} is not the one verified earlier", anchor["seq"])
    elif anchor["seq"] == first - 1:
        if receipts[0].get("prev") != anchor["head"]:
            fail("checkpoint_mismatch", "the window does not continue from the receipt verified earlier", first)
    else:
        fail("window_unanchored", f"receipts {anchor['seq'] + 1} to {first - 1} are missing between what was "
                                  f"verified earlier and what is available now")
    last = first + len(receipts) - 1
    return {"ok": not errors, "errors": errors, "count": last, "head": digests.get(last) if not errors else None,
            "signer": trust["signer"], "decisions": {}}


def verify_chain(trust: dict, *, data: bytes | None = None, receipts: list | None = None,
                 anchor: dict | None = None) -> dict:
    """{"ok", "count", "head", "errors", "receipts", "complete"}. `data` is a whole receipt file; `receipts`
    are the broker's newest N. Reuses synthe_verify for all the cryptography and chain rules."""
    checkpoints = {anchor["seq"]: anchor["head"]} if anchor and anchor.get("seq", 0) >= 1 and anchor.get("head") else None
    if (data is not None and not data.strip()) or (data is None and not receipts):
        # A broker with no receipts yet is normal, unless receipts were seen before: then they were removed.
        report = sv.verify(b"", trust, checkpoints)
        if not checkpoints:
            report = {**report, "ok": True, "errors": [], "count": 0}
        return {**report, "receipts": [], "complete": True}
    if data is not None:
        report = sv.verify(data, trust, checkpoints)
        parsed = []
        if report["ok"]:
            parsed = [sv.strict_loads(line.decode("utf-8")) for line in data.split(b"\n") if line.strip()]
        return {**report, "receipts": parsed, "complete": True}
    receipts = receipts or []
    if any("_unparseable" in r for r in receipts):
        return {"ok": False, "count": len(receipts), "head": None, "signer": trust["signer"], "decisions": {},
                "errors": [{"line": None, "seq": None, "code": "not_json", "detail": "a receipt line is not JSON"}],
                "receipts": [], "complete": False}
    if receipts[0].get("seq") == 1:
        report = sv.verify(_lines(receipts), trust, checkpoints)
        return {**report, "receipts": receipts if report["ok"] else [], "complete": True}
    report = _window_report(receipts, trust, anchor)
    return {**report, "receipts": receipts if report["ok"] else [], "complete": False}


def fetch_and_verify(opts, trust: dict, state: dict) -> dict:
    anchor = {"seq": state["seq"], "head": state.get("head")} if state.get("seq") else None
    path = opts.receipts or opts.config_values.get("receipts")
    if path:
        return {**verify_chain(trust, data=read_receipt_file(path), anchor=anchor), "origin": "file"}
    got = read_broker(opts.broker or opts.config_values.get("broker"))
    report = verify_chain(trust, receipts=got["receipts"], anchor=anchor)
    if report["ok"] and got["count"] > len(got["receipts"]):
        report["complete"] = False
    return {**report, "origin": "broker"}


def explain_failure(report: dict) -> str:
    first = (report.get("errors") or [{}])[0]
    where = f" at receipt {first['seq']}" if first.get("seq") else ""
    return f"{clean(first.get('code'), 40)}{where}: {clean(first.get('detail'), 160)}"


# --------------------------------------------------------------------------
# digest

def parse_time(text) -> dt.datetime | None:
    try:
        t = dt.datetime.fromisoformat(str(text).replace("Z", "+00:00"))
    except ValueError:
        return None
    return t if t.tzinfo else t.replace(tzinfo=dt.timezone.utc)


REVIEW_KINDS = {"build": ("dependency or build change", "dependency or build changes"),
                "file": ("change to a sensitive file", "changes to sensitive files"),
                "delete": ("deletion", "deletions"), "size": ("larger change", "larger changes"),
                "commits": ("multi-commit push", "multi-commit pushes"),
                "other": ("review-level push", "review-level pushes")}


def review_kind(r: dict) -> str | None:
    """For a push that went out under a lane at the review tier (the receipt's `risk` says the lane approved
    it, `escalated: false`): what kind of change made it review-level, else None."""
    risk = r.get("risk") if isinstance(r.get("risk"), dict) else {}
    if risk.get("tier") != "review" or risk.get("escalated") is not False:
        return None
    reasons = _strings(risk.get("reasons"), 80)
    if path_class(_strings(risk.get("paths"), 70)) == "build":
        return "build"
    first = reasons[0] if reasons else ""
    return ("file" if first.startswith("changes ") else "delete" if first.startswith("deletes ")
            else "size" if "lines changed" in first else "commits" if first.endswith(" commits") else "other")


def review_text(r: dict) -> str:
    risk = r["risk"]
    return "; ".join(_strings(risk.get("reasons"), 80)[:3]) or "review-level push"


def build_digest(receipts: list, days: int = 7, now: dt.datetime | None = None) -> dict:
    """Counts and one line per stop, from receipts that already verified."""
    now = now or dt.datetime.now(dt.timezone.utc)
    since = now - dt.timedelta(days=days)
    events = [(r, describe(r), parse_time(r.get("time"))) for r in receipts]
    needed = {e["id"] for r, e, t in events if e["level"] == "waiting" and e["id"]}  # ever needed a person
    inside = [(r, e, t) for r, e, t in events if t is not None and t >= since]
    shipped = [(r, e) for r, e, t in inside if r.get("decision") == "executed"]
    asked = {e["id"] for r, e, t in inside if e["level"] == "waiting" and e["id"]}
    sent = {e["id"]: e["lane"] for r, e, t in inside if e["lane"] and e["id"]}   # why your lane sent it to you
    last = {}  # where each push that needed a person stands now
    for r, e, t in events:
        if e["id"] in asked and r.get("kind") in (None, "effect", "delegate_escalation"):
            last[e["id"]] = r.get("decision")
    after_you = sum(1 for i in asked if last.get(i) == "executed")
    still = sum(1 for i in asked if last.get(i) in ("staged", "escalated"))
    stops, problems, retries, seen = [], [], 0, set()
    for r, e, t in inside:
        if e["level"] not in ("stop", "problem", "retry"):
            continue
        if e["level"] == "retry":
            retries += 1
            continue
        key = (e["id"] or f"seq{e['seq']}", e["codes"][0] if e["codes"] else e["decision"])
        if key in seen:
            continue
        seen.add(key)
        item = {k: e[k] for k in ("seq", "time", "branch", "headline", "why", "codes", "decision", "known")}
        item["text"] = e["body"]
        (stops if e["level"] == "stop" else problems).append(item)
    lane_review = []   # went out under a lane at the review tier: not worth a message, worth seeing afterwards
    for r, e in shipped:
        kind = review_kind(r)
        if kind and e["id"] not in needed:
            lane_review.append({"seq": e["seq"], "time": e["time"], "branch": e["branch"], "kind": kind,
                                "text": review_text(r)})
    return {"days": days, "since": since.isoformat(), "until": now.isoformat(),
            "lane_review": len(lane_review), "lane_review_kinds": dict(Counter(x["kind"] for x in lane_review)),
            "lane_review_items": lane_review,
            "pushes_shipped": len(shipped), "shipped_without_asking": sum(1 for r, e in shipped if e["id"] not in needed),
            "needed_you": len(asked), "needed_you_shipped": after_you, "needed_you_still_waiting": still,
            "lane_high_risk": sum(1 for i in asked if sent.get(i) == "risk"),
            "lane_outside_paths": sum(1 for i in asked if sent.get(i) == "scope"),
            "stopped": len(stops), "problems": len(problems), "routine_refusals": retries,
            "stops": stops, "problem_items": problems}


def _plural(n: int, one: str, many: str | None = None) -> str:
    return f"{n} {one if n == 1 else many or one + 's'}"


def render_digest(d: dict, chain: dict) -> str:
    n = d["days"]
    period = "Today" if n == 1 else f"Last {n} days"
    lines = []
    if not (d["pushes_shipped"] or d["needed_you"] or d["stopped"] or d["problems"] or d["routine_refusals"]):
        lines.append(f"{period}: nothing to report. No pushes, nothing stopped.")
    else:
        bits = [f"{_plural(d['shipped_without_asking'], 'push', 'pushes')} shipped without asking you",
                f"{d['needed_you']} needed you",
                f"{_plural(d['stopped'], 'risky attempt')} stopped"]
        if d["problems"]:
            bits.append(f"{_plural(d['problems'], 'problem')} needing a look")
        lines.append(f"{period}: " + ", ".join(bits) + ".")
        if d["needed_you"]:
            gone = d["needed_you"] - d["needed_you_shipped"] - d["needed_you_still_waiting"]
            lines.append(f"Of the {d['needed_you']} that needed you: {d['needed_you_shipped']} shipped after you approved, "
                         f"{d['needed_you_still_waiting']} still waiting" + (f", {gone} did not ship." if gone else "."))
        if d["lane_high_risk"] or d["lane_outside_paths"]:
            why = [f"{n} {what}" for n, what in ((d["lane_high_risk"], "riskier than your lane lets through"),
                                                 (d["lane_outside_paths"], "outside your lane's files")) if n]
            lines.append(f"Your lane sent {d['lane_high_risk'] + d['lane_outside_paths']} of them to you: "
                         + " and ".join(why) + ". Everything else in the lane went out on its own.")
        if d["routine_refusals"]:
            lines.append(f"Also {_plural(d['routine_refusals'], 'routine refusal')} (a stale branch, a malformed "
                         f"request) that the agent can simply retry.")
    if d["lane_review"]:
        kinds = [f"{n} {REVIEW_KINDS[k][n != 1]}" for k, n in d["lane_review_kinds"].items() if k in REVIEW_KINDS]
        lines += ["", f"{_and(kinds)} went out under your lane without asking you (review level, not high-risk):"]
        for it in d["lane_review_items"][:LIST_LIMIT]:
            when = parse_time(it["time"])
            stamp = when.astimezone().strftime("%b %d %H:%M") if when else "?"
            lines.append(f"  {stamp}  {it['branch'] or 'a push'}: {it['text']}")
        if len(d["lane_review_items"]) > LIST_LIMIT:
            lines.append(f"  ... and {len(d['lane_review_items']) - LIST_LIMIT} more")
        lines.append("  Your lane lets these through; it reads paths and sizes, not code. "
                     "synthe-task grant --auto-approve routine would make them ask you.")
    for title, items in (("Stopped", d["stops"]), ("Needed a look", d["problem_items"])):
        if items:
            lines += ["", f"{title}:"]
            for it in items:
                when = parse_time(it["time"])
                stamp = when.astimezone().strftime("%b %d %H:%M") if when else "?"
                lines.append(f"  {stamp}  {it['text']}")
    lines += ["", f"Verified: {chain['count']} receipts signed by {chain['signer']}, head {(chain['head'] or 'none yet')[:12]}."]
    if not chain.get("complete", True):
        lines.append(f"Only the newest {WINDOW} receipts were read; older activity is not counted.")
    lines.append("\"Without asking you\" means the push ran under a task or lane you had already signed. "
                 "Receipts show which key acted, not which model, and Synthe does not judge whether pushed code is good.")
    return "\n".join(lines)


# --------------------------------------------------------------------------
# commands

def _load(opts):
    """(config, warnings, trust). Raises SourceError."""
    cfg, warnings = load_config(opts.config)
    opts.config_values = cfg
    key = find_key(opts.key, cfg)
    return cfg, warnings, load_trust(key, opts.signer or cfg.get("signer"))


def poll(opts, trust, notifier, state) -> tuple[dict, int]:
    """One look at the chain. Returns (new state, exit code)."""
    try:
        report = fetch_and_verify(opts, trust, state)
    except SourceError as e:
        if state.get("down") != str(e):
            print(f"synthe-notify: {e}", file=notifier.err)
        return {**state, "down": str(e)}, 2
    state = {k: v for k, v in state.items() if k != "down"}
    if not report["ok"]:
        # Say it once, loudly; never notify from receipts that cannot be trusted.
        if not state.get("alerted"):
            reason = explain_failure(report)
            print(f"synthe-notify: NOT VERIFIED: {reason}. Not notifying from this chain.", file=notifier.err)
            notifier.send("Synthe: receipts did not verify",
                          f"The receipt chain failed verification ({reason}). Not notifying from it. "
                          f"Run synthe-verify to investigate.", "stop")
            state["alerted"] = True
        return state, 1
    state.pop("alerted", None)
    receipts = report["receipts"]
    if "seq" not in state and not opts.from_start:  # first run: start from now, not from the whole history
        last = receipts[-1] if receipts else None
        print(f"synthe-notify: watching from receipt {last['seq'] if last else 0} on; "
              f"`synthe-notify digest` covers what came before.", file=notifier.err)
        return {**state, "seq": last["seq"] if last else 0, "head": sv.receipt_digest(last) if last else None}, 0
    if not receipts:
        return state, 0
    new = [r for r in receipts if isinstance(r.get("seq"), int) and r["seq"] > state.get("seq", 0)]
    events = select(new, opts.all_refusals)
    if len(events) > BATCH_LIMIT:
        for e in events:  # the full list still goes to the log
            print(f"[#{e['seq']}] {e['title']}: {e['body']}", file=notifier.err)
        s = summarize_batch(events)
        notifier.send(s["title"], s["body"], s["level"])
    else:
        for e in events:
            notifier.send(e["title"], e["body"], e["level"])
    if new:
        state = {**state, "seq": new[-1]["seq"], "head": sv.receipt_digest(new[-1])}
    return state, 0


def cmd_watch(opts) -> int:
    try:
        cfg, warnings, trust = _load(opts)
    except SourceError as e:
        print(f"synthe-notify: {e}", file=sys.stderr)
        return 2
    for w in warnings:
        print(f"synthe-notify: {w}", file=sys.stderr)
    opts.all_refusals = opts.all_refusals or bool(cfg.get("all_refusals"))
    notifier = Notifier(cfg, stdout=opts.stdout)
    state = load_state(opts.state)
    code = 0
    try:
        while True:
            state, code = poll(opts, trust, notifier, state)
            try:
                save_state(opts.state, state)
            except OSError as e:
                print(f"synthe-notify: cannot save {opts.state}: {clean(e.strerror or e, 80)}", file=sys.stderr)
            if opts.once:
                return code
            time.sleep(max(opts.interval, 1))
    except KeyboardInterrupt:
        return 0


def cmd_digest(opts) -> int:
    try:
        cfg, warnings, trust = _load(opts)
        state = load_state(opts.state)
        report = fetch_and_verify(opts, trust, state)
    except SourceError as e:
        print(f"synthe-notify: {e}", file=sys.stderr)
        return 2
    if not report["ok"]:
        print(f"synthe-notify: NOT VERIFIED: {explain_failure(report)}. No digest from a chain that does not verify.",
              file=sys.stderr)
        return 1
    d = build_digest(report["receipts"], opts.days)
    chain = {"ok": True, "count": report["count"], "head": report["head"], "signer": report["signer"],
             "complete": report["complete"]}
    if opts.json:
        print(json.dumps({**d, "chain": chain}, indent=2))
    else:
        print(render_digest(d, chain))
    return 0


def cmd_test(opts) -> int:
    cfg, warnings = load_config(opts.config)
    for w in warnings:
        print(f"synthe-notify: {w}", file=sys.stderr)
    sample = describe({"seq": 0, "kind": None, "decision": "denied", "effect": {"branch": "agent/example"},
                       "reasons": [{"code": "path_forbidden", "state": "blocked",
                                    "message": "1 path(s) not allowed: .github/workflows/ci.yml (path_forbidden)"}]})
    n = Notifier(cfg, stdout=True)
    done = n.send("Synthe test: " + sample["title"], sample["body"] + " (This is a test; nothing happened.)", "stop")
    others = [d for d in done if d != "stdout"]
    if others:
        print(f"synthe-notify: delivered to {', '.join(others)}.", file=sys.stderr)
        return 0
    print("synthe-notify: no desktop notifier or Slack webhook worked, so the message above is all you will get. "
          "macOS needs osascript; Linux needs notify-send and a desktop session; Slack needs slack_webhook in "
          f"{DEFAULT_CONFIG} (chmod 600).", file=sys.stderr)
    return 1


# ---- run at login: a LaunchAgent (macOS) or a systemd user service (Linux), in YOUR account -------------

LABEL = "com.synthe.notify"
UNIT = "synthe-notify.service"
BROKER_USERS = ("root", "synthe", "_synthe")


def _account_problem(home: Path, user: str | None = None, uid: int | None = None) -> str | None:
    """Why this account must not run the notifier, or None. It is the person's tool: the agent's account would
    let the agent decide what you hear, and the broker's or root's would mix the watcher with the wall."""
    uid = os.geteuid() if uid is None else uid
    user = user or os.environ.get("USER") or ""
    if uid == 0 or user in BROKER_USERS:
        return "run it as yourself, not as root or the broker's account"
    try:
        role = json.loads((home / ".synthe" / "setup.json").read_text()).get("role")
    except (OSError, ValueError, AttributeError):
        role = None
    if role == "agent":
        return ("this is the agent's account (its ~/.synthe/setup.json says so); notifications belong in the "
                "account of the person who approves")
    return None


def _program() -> list[str]:
    """How the service starts the watcher: the installed command, or this file with this interpreter."""
    found = shutil.which("synthe-notify")
    if found:
        return [os.path.realpath(found)]
    return [os.path.realpath(sys.executable), str(Path(__file__).resolve())]


def agent_files(home: Path, platform: str | None = None) -> dict:
    platform = platform or sys.platform
    if platform == "darwin":
        return {"kind": "launchd", "path": home / "Library" / "LaunchAgents" / f"{LABEL}.plist"}
    if platform.startswith("linux"):
        return {"kind": "systemd", "path": home / ".config" / "systemd" / "user" / UNIT}
    raise SourceError(f"running at login is supported on macOS and Linux, not {platform}")


def launchd_plist(program: list, log: Path, interval: float) -> bytes:
    import plistlib
    return plistlib.dumps({"Label": LABEL, "ProgramArguments": [*map(str, program), "watch", "--stdout",
                                                                "--interval", f"{interval:g}"],
                           "RunAtLoad": True, "KeepAlive": True, "ProcessType": "Background",
                           "StandardOutPath": str(log), "StandardErrorPath": str(log)})


def _unit_arg(a) -> str:
    a = str(a)
    if any(c in a for c in "\n\r%\"\\$"):
        raise SourceError(f"cannot put {a!r} in a systemd unit; install synthe-notify on a plain path")
    return f'"{a}"'


def systemd_unit(program: list, interval: float) -> str:
    cmd = " ".join(_unit_arg(a) for a in [*program, "watch", "--stdout", "--interval", f"{interval:g}"])
    return ("[Unit]\nDescription=Synthe notifications (only when Synthe stops or flags something)\n\n"
            f"[Service]\nExecStart={cmd}\nRestart=on-failure\nRestartSec=30\n\n[Install]\nWantedBy=default.target\n")


def install_agent(home: Path | None = None, *, platform: str | None = None, run=subprocess.run, interval: float = 15,
                  program: list | None = None, uid: int | None = None, user: str | None = None, out=print) -> dict:
    """Start `synthe-notify watch` at login for this account and now. Idempotent: an existing service is
    replaced. Refuses the agent's account, the broker's and root."""
    home = Path(home or Path.home())
    why = _account_problem(home, user, uid)
    if why:
        raise SourceError(f"not turning notifications on here: {why}")
    f = agent_files(home, platform)
    program = program or _program()
    path: Path = f["path"]
    path.parent.mkdir(parents=True, exist_ok=True)
    uid = os.geteuid() if uid is None else uid
    if f["kind"] == "launchd":
        log = home / ".synthe" / "notify.log"
        log.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(launchd_plist(program, log, interval))
        os.chmod(path, 0o644)
        run(["launchctl", "bootout", f"gui/{uid}", str(path)], capture_output=True)
        r = run(["launchctl", "bootstrap", f"gui/{uid}", str(path)], capture_output=True, text=True)
        where = f"log: {log}"
    else:
        path.write_text(systemd_unit(program, interval))
        os.chmod(path, 0o644)
        run(["systemctl", "--user", "daemon-reload"], capture_output=True)
        r = run(["systemctl", "--user", "enable", "--now", UNIT], capture_output=True, text=True)
        where = f"log: journalctl --user -u {UNIT}"
    ok = getattr(r, "returncode", 1) == 0
    if ok:
        out(f"Notifications are on: synthe-notify watch runs at login in this account ({path}; {where}).")
    else:
        out(f"Wrote {path}, but starting it failed: {clean(getattr(r, 'stderr', '') or 'no detail', 200)}")
    return {"installed": str(path), "started": ok, "kind": f["kind"]}


def uninstall_agent(home: Path | None = None, *, platform: str | None = None, run=subprocess.run,
                    uid: int | None = None, out=print) -> dict:
    home = Path(home or Path.home())
    f = agent_files(home, platform)
    path: Path = f["path"]
    uid = os.geteuid() if uid is None else uid
    if f["kind"] == "launchd":
        run(["launchctl", "bootout", f"gui/{uid}", str(path)], capture_output=True)
    else:
        run(["systemctl", "--user", "disable", "--now", UNIT], capture_output=True)
    existed = path.exists()
    path.unlink(missing_ok=True)
    if f["kind"] == "systemd":
        run(["systemctl", "--user", "daemon-reload"], capture_output=True)
    out("Notifications are off (the service is removed)." if existed else "Notifications were not installed here.")
    return {"removed": existed}


def cmd_install_agent(opts) -> int:
    try:
        r = install_agent(interval=opts.interval)
    except SourceError as e:
        print(f"synthe-notify: {e}", file=sys.stderr)
        return 2
    return 0 if r["started"] else 1


def cmd_uninstall_agent(opts) -> int:
    try:
        uninstall_agent()
    except SourceError as e:
        print(f"synthe-notify: {e}", file=sys.stderr)
        return 2
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="synthe-notify", description=__doc__.split("\n\n")[0])
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--receipts", help="a receipt file to read instead of asking the broker")
    common.add_argument("--broker", help="broker address (unix:///path or tcp://host:port); default as synthe-client")
    common.add_argument("--key", help="the broker's published public key (broker.pub.json) or a registry")
    common.add_argument("--broker-id", dest="signer", help="signer id to trust in a registry (default synthe-broker)")
    common.add_argument("--state", default=str(DEFAULT_STATE), help=f"default {DEFAULT_STATE}")
    common.add_argument("--config", default=str(DEFAULT_CONFIG), help=f"default {DEFAULT_CONFIG}")
    sub = ap.add_subparsers(dest="cmd", required=True)
    w = sub.add_parser("watch", parents=[common], help="notify when Synthe stops or flags something")
    w.add_argument("--interval", type=float, default=15, help="seconds between looks (default 15)")
    w.add_argument("--once", action="store_true", help="look once and exit (for cron or a test)")
    w.add_argument("--from-start", action="store_true", help="notify from the first receipt, not from now")
    w.add_argument("--all-refusals", action="store_true", help="also notify on refusals the agent can just retry")
    w.add_argument("--stdout", action="store_true", help="also print each notification (launchd or systemd log)")
    d = sub.add_parser("digest", parents=[common], help="what Synthe did for you lately, in plain English")
    d.add_argument("--days", type=int, default=7)
    d.add_argument("--json", action="store_true")
    sub.add_parser("test", parents=[common], help="send a sample notification")
    ia = sub.add_parser("install-agent", help="run `watch` at login in this account (LaunchAgent or systemd --user)")
    ia.add_argument("--interval", type=float, default=15, help="seconds between looks (default 15)")
    sub.add_parser("uninstall-agent", help="stop running `watch` at login")
    opts = ap.parse_args(argv)
    if opts.cmd == "digest" and opts.days < 1:
        ap.error("--days must be at least 1")
    opts.config_values = {}
    return {"watch": cmd_watch, "digest": cmd_digest, "test": cmd_test, "install-agent": cmd_install_agent,
            "uninstall-agent": cmd_uninstall_agent}[opts.cmd](opts)


if __name__ == "__main__":
    sys.exit(main())
