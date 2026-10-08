# Synthe Commit (v0.4)

**Agents propose. Synthe commits. Anyone can verify.**

Up to v0.3, Synthe was an *admission gate*: the receiving agent asked "may I
do this?" and then acted with its own credentials. It could skip the gate, and
the gate never saw what it actually did.

Synthe Commit inverts that. The receiving agent holds **no credentials** for
real-world effects. It sends the broker a *proposal* ("push commit C to branch
B"). The broker holds the credentials and performs the effect itself, but only
after re-checking everything at the moment of commit. It signs a receipt for every
decision.

```
 planner ──signed packet──▶ builder (no push credentials)
                               │  1. claim (ACCEPT → claim token)
                               │  2. do the work in its own repo
                               ▼
                     propose {packet, token, action, params, source}
                               │
                 ┌─────────────▼─────────────────────────────────────┐
                 │ Synthe Commit broker (holds the GitHub token)      │
                 │  a. re-validate the signed handoff NOW             │
                 │  b. effect is a planned action, params as signed   │
                 │  c. a trusted human approval pins the same params  │
                 │  d. inside the claim fence (exactly once):         │
                 │     live remote state, fast-forward only, every    │
                 │     path in every pushed commit vs scope + policy  │
                 │  e. push with compare-and-swap (force-with-lease)  │
                 │  f. observe the remote; EXECUTED only if confirmed │
                 │  g. signed, hash-chained receipt for every outcome │
                 └─────────────┬─────────────────────────────────────┘
                               ▼
                 GitHub  +  receipts.jsonl  +  ledger.json
```

## What this closes (and what it doesn't)

| Gap in v0.3 | With Synthe Commit |
|---|---|
| The gate only works if the receiver calls it | **Closed for mediated effects.** The agent has no credentials, so the broker is the only way to act |
| Nothing checks what the receiver actually did | **Closed for git_push.** The broker inspects every commit it pushes and confirms the remote afterwards |
| `fenced()` only protects actions that run through it | **Closed for mediated effects.** Every mediated effect runs inside the fence, with the check and the effect in one locked step |
| A human approval could be reused after the sender changed the target | **Closed.** Approvals pin the target (`params`) and are signed, and admission and commit both reject a mismatch |
| Check-then-act races | **Closed on the remote.** The push is a compare-and-swap against the exact state that was checked |

**Still out of scope, stated plainly:**

- **The broker only protects credentials it holds.** If an agent has its own GitHub
  token in its environment, that path isn't mediated. Setup must move the token
  into the broker and out of the agent's reach.
- **Isolated by default; dev mode is explicit and receipted (v0.5).** The broker runs as its
  own OS user (or in a container) and agents reach it only through its socket, so they can't read
  its key or token ([`ISOLATION.md`](ISOLATION.md), verified on Linux). Running it inside the
  agent's process, or as the agent's user, needs `"isolation": {"mode": "none"}`, and every receipt
  then says so. Root, passwordless `sudo` and the `docker` group still defeat any isolation.
- **A compromised sender with a valid approval** can still get its approved effect
  executed. That limit applies to every system in the literature. The broker narrows it
  to exactly what the human approved, within the receiver's path policy.
- **Content.** The broker checks *which files* change, not whether the code is good.
- **Model identity.** Receipts prove which keys and connectors acted, not which model wrote the work.

## Get it running (10 minutes)

### 1. Get the code

```bash
git clone https://github.com/rohansiddam/Synthe.git ~/Downloads/benchmark/Synthe-v0.5
```

Python 3.10+ and git are all you need. Installing `cryptography` makes signing faster and
constant-time (the installers below do it for the broker):

```bash
python3 -m pip install cryptography
```

### 2. Watch the demo (safe; a local stand-in for GitHub, throwaway keys)

```bash
python3 ~/Downloads/benchmark/Synthe-v0.5/scripts/demo_commit.py
```

It starts the broker daemon, and the agent talks to it only through its socket. You'll see the
agent fail to push on its own, then the broker execute the approved push. It then denies a replay,
a CI-workflow edit, a token hidden in an intermediate commit, a retarget to `main` and a stolen
claim token, executes the clean change, and verifies the 7-receipt chain. On one OS user the demo
runs in isolation mode `none`, and every receipt says so.

### 3. Open the console

The demo prints the exact command, for example:

```bash
python3 ~/Downloads/benchmark/Synthe-v0.5/src/synthe_commit.py ui --config /tmp/synthe-demo-XXXX/broker.json
```

Then open <http://127.0.0.1:8790/>. The console is read-only and served on loopback only. It
shows the chain status, every receipt (with the reasons for each denial and the paths each push
touched) and the claims ledger.

### 4. Install your own broker, as its own user (once)

```bash
sudo ~/Downloads/benchmark/Synthe-v0.5/deploy/macos/install.sh --agent-user "$USER"
```

(Linux: `deploy/linux/install.sh`; containers: `deploy/docker/`.) This creates the hidden user
`_synthe`, the broker key and `broker.json` in `/var/db/synthe` (0700), and a LaunchDaemon. Then
copy in your registry (with the broker's public key, which the installer prints), put the GitHub
token in a 0600 `token_file` only `_synthe` can read, and set the remote:

```json
"isolation": {"mode": "user", "clients": ["openclaw"]},
"effects": {"git_push": {"max_commits": 200, "remotes": {
  "synthe": {"url": "https://github.com/rohansiddam/Synthe.git", "branches": ["synthe/*", "feature/*"],
             "token_file": "github.token"}
}}}
```

- `branches` is the operator's ceiling. `main` is deliberately absent, so agents land on branches and
  you merge.
- `clients` names the OS users your agents run as. The broker refuses its own user and root.
- Run both doctors before you rely on it (see [`ISOLATION.md`](ISOLATION.md)). The client doctor
  FAILs `direct push` while your own user can still push to GitHub by itself.

The receiver's policy in `registry.json` decides which files an agent may change:

```json
"allowed_paths":   ["src/**", "tests/**", "docs/**", "examples/**", "README.md", "SPEC.md", "THREAT_MODEL.md"],
"forbidden_paths": [".github/**", "**/*.key.json", "LICENSE*", "LICENSING.md"]
```

### 5. A real handoff, end to end

```bash
export SYNTHE_BROKER=unix:///var/db/synthe-run/broker.sock
R=~/Downloads/benchmark/Synthe-v0.5/src
```

1. The planner writes a packet whose push action pins its target:
   `{"name": "push_branch", "tool": "git_push", "params": {"remote": "synthe", "branch": "feature/my-change"}}`.
2. You approve it. The CLI shows exactly what you're approving and signs the params:
   ```bash
   python3 $R/synthe_sign.py approve packets/my.json --key keys/rishab.key.json --action push_branch --expires-at 2026-12-31T23:59:59Z --out packets/my.json
   ```
3. The planner signs:
   ```bash
   python3 $R/synthe_sign.py sign packets/my.json --key keys/planner.key.json --out packets/my.json
   ```
4. The builder claims it through the broker and keeps the output (it holds the claim token):
   ```bash
   python3 $R/synthe_client.py claim packets/my.json > claim.json
   ```
5. The builder does the work in its own repo, commits, and proposes. The commits travel as a git
   bundle, and the token is read from the file (a token in argv is visible to every user via `ps`):
   ```bash
   python3 $R/synthe_client.py push --packet packets/my.json --claim-token-file claim.json --action push_branch --remote synthe --branch feature/my-change --repo <path-to-repo>
   ```
6. Anyone checks the chain:
   ```bash
   python3 $R/synthe_client.py receipts
   ```

### 6. Let Claude Code use it (MCP)

```bash
claude mcp add synthe -- python3 ~/Downloads/benchmark/Synthe-v0.5/src/synthe_mcp.py --broker-url unix:///var/db/synthe-run/broker.sock
```

Claude gets `synthe_validate_handoff`, `synthe_propose_effect`, `synthe_complete_handoff` and
`synthe_receiver_policy`, all forwarded to the broker. The MCP server holds no secrets: it bundles
the commits from `source` on Claude's side and sends them over the socket. For the guarantee to
hold, Claude's own environment must not be able to push: remove its GitHub credentials, or run it
as a user without them. (`--broker broker.json` runs the broker inside the MCP server instead; it is
refused unless the config says isolation mode `none`, for local development only.)

## Proposal format

```json
{
  "packet": {"handoff": {...}, "signature": {...}},
  "claim_token": "<from the ACCEPT>",
  "action": "push_branch",
  "params": {"remote": "synthe", "branch": "feature/x", "commit": "<40-hex>",
             "expected_old": "<40-hex> | new (optional)", "base": "main (new branches)"},
  "bundle": "<base64 git bundle holding the commit; synthe_client builds it>"
}
```

Through the daemon, the commits arrive as a git `bundle` (thin: history the remote already has
is left out, and the broker fetches it itself). A `source` path on the agent's disk is accepted
only in dev setups whose config sets `allow_path_sources` (otherwise `source_path_not_allowed`).

## Receipts

The broker writes one JSON line per proposal, whatever the outcome: `executed`,
`denied`, `errored`, `unconfirmed` or (v0.5) `staged`, and one per detached approval
(`kind: "approval"`: `approval_accepted`, `approval_rejected`, `approval_duplicate`). Each
effect receipt carries:

- `seq`, plus `prev` = the SHA-256 of the previous receipt, which forms the chain;
- the handoff (`id`, `idempotency_key`, `packet_sha256`) and the claim `epoch`;
- the approvals used (approver, `kid`, pinned params);
- the effect (`remote`, redacted `remote_url`, `branch`, `commit`, `before`, `after`);
- what was observed (commit count, every path touched);
- how the proposal arrived (v0.5): `via` (`unix` / `tcp` / `in-process`), `isolation` (for
  example `{"mode": "separate-user", "verified": true, "broker_uid": 480, "peer_uid": 501}`) and
  `commits_from` (`bundle sha256:...`, `content sha256:...`, or `local path` in dev setups);
- for a content proposal (v0.5): `content` (counts, bytes, digest, paths; never the text) and
  `effect.rebased_onto` if it was rebuilt on a newer tip;
- an Ed25519 signature by the broker (domain `synthe/effect-receipt/v1`).

`receipts verify` checks every signature against the broker key in the registry, as
well as `seq` continuity and every `prev` link. Editing, deleting or reordering any
receipt breaks the chain. A denial is recorded as carefully as an execution, so it's
evidence the gate worked.

## Plan anchor (v0.5)

Agents don't keep plans in mind: in *Plans Don't Persist* (arXiv 2606.22953), dropping the plan
from the agent's context cut ALFWorld success by 34.7 points. So every response that moves a
handoff forward hands the plan back: the ACCEPT from `synthe_validate_handoff` (MCP, the Lab), the
broker's `claim`, and **every receipt** (signed into the chain). The MCP tool descriptions tell
the agent to re-read it before every step.

```json
"plan": {
  "purpose": "Add a --version flag and push it for review",
  "handoff": {"id": "h-1", "idempotency_key": "feature-x:cli", "trace_id": "t-1", "from": "planner", "to": "builder"},
  "claim_state": "RESERVED",
  "planned_actions": [
    {"name": "edit_cli", "tool": "edit_files", "status": "not_mediated"},
    {"name": "push_branch", "tool": "git_push", "status": "denied",
     "params": {"remote": "synthe", "branch": "feature/version-flag"}}],
  "remaining": ["push_branch"],
  "constraints": {"owned_paths": ["src/**", "tests/**"], "forbidden": ["force_push"],
                  "allowed_tools": ["edit_files", "git_push"], "approvals_needed": [],
                  "expires_at": "2026-10-31T00:00:00Z", "depends_on": [{"key": "feature-x:api", "state": "COMPLETED"}]},
  "note": "Re-read this plan before every step. ..."
}
```

Statuses: `executed` / `unconfirmed` come from the ledger's effect records; `pending` means not
done yet; `denied` means the latest proposal of that action was refused and it is still pending;
`staged` (v0.5) means the broker holds a checked proposal and commits it when covered;
`not_mediated` is a step the agent does itself, which Synthe doesn't observe. The plan is built
from the signed handoff, the receiver's policy and the ledger, so it never carries a claim token
or any other secret. It is a private feature: the public checker's verdict shape is unchanged.

## Wait-for dependencies and exclusive paths (v0.5)

Two of the commonest multi-agent failures are acting before the work you depend on is
finished, and two agents changing the same files at once. Synthe gates both:

- **`depends_on`** (in the signed handoff) lists upstream idempotency keys. The receiver may
  claim the handoff and work ahead, but the broker refuses to commit until every upstream
  key is `COMPLETED` in the same ledger. The check runs inside the claim fence, in the same
  locked step as the effect. A refused proposal is receipted `denied` with
  `dependency_incomplete` or `dependency_unknown`, and the claim is left untouched, so the
  agent just proposes again once the upstream lands.
- **`exclusive_paths: true`** in the receiver's policy refuses a second live claim whose
  `owned_paths` may overlap one already held on that receiver (`claim_conflict`), until the
  first completes or is released. Overlap is checked conservatively (see `SPEC.md` §8).

```json
"handoff": { "idempotency_key": "feature-x:docs", "depends_on": ["feature-x:api"], ... }
```

## Speculative commit and detached approvals (v0.5)

Waiting for a human is the main thing that slows an agent pipeline down. With speculative commit
the agent keeps working while the approval is on its way, and nothing irreversible happens until
it arrives.

1. **Claim ahead.** `synthe_client.py claim P.json --wait-for-approval` (MCP: `wait_for_approval`
   on `synthe_validate_handoff`) accepts a handoff whose broker-mediated push has no approval
   yet. A present but invalid approval still rejects.
2. **Propose ahead.** `synthe_client.py push ... --wait-for-approval` (MCP: `wait_for_approval`
   on `synthe_propose_effect`). If the only thing missing is the approval, or an unfinished
   `depends_on` upstream, the broker runs every check it can now (claim token, plan and params,
   branch ceiling, the live remote, fast-forward, every path of every commit), keeps the commits
   in its own mirror, pins the branch tip it saw, and answers with a **`staged`** receipt (exit
   code 3). Anything else wrong is denied now, as before.
3. **Approve.** A human signs a *detached* approval, which leaves the packet (and so the claim)
   unchanged:
   ```bash
   python3 src/synthe_sign.py approve handoff.json --key keys/rishab.key.json --action push_branch --detached --out approval.json
   ```
   Anyone can deliver it (`synthe_client.py approve-submit approval.json`, MCP
   `synthe_submit_approval`): only the approver's signature makes it count. The broker verifies
   it like an embedded approval (registered key, signature over this handoff's key, sender and
   receiver, trusted approver, expiry), receipts it either way, and stores it append-only.
4. **Commit.** The broker then re-runs the whole commit protocol for every staged proposal the
   approval covers: validation, the approval's pinned params, the fence, the live remote against
   the pinned tip, path inspection, compare-and-swap, confirmation. It writes the `executed`
   receipt with `triggered_by` and a link to the `staged` receipt. If anything changed in between
   (the branch moved, the handoff expired, the policy changed) it's `denied` with the reason, and
   nothing is pushed. An approval for different params is stored but leaves the proposal staged.

A sweeper thread in the daemon (`staged_sweep_seconds`, default 30, `0` = off) revisits staged
proposals: it commits ones whose upstream completed by another path, retries transient errors
with backoff, and denies ones whose handoff expired. `synthe_client.py staged` lists them
(never their claim tokens). The broker keeps them in `state_dir/staged.json` (mode 0600, because
it holds the claim tokens it commits with); the daemon refuses to start if that file is readable
by others (`broker_credentials_exposed`). Detached approvals live in `approvals.jsonl`
(`"approvals"` in `broker.json`).

**Known limit.** A staged proposal is pinned to the branch tip it saw. If an upstream that is
still pending pushes to the *same* branch, the downstream's commit is denied `remote_moved`, and
the agent proposes again on top of the new tip. Separate branches per task (or proposing after the
upstream lands) avoid this. Re-pinning onto an upstream's receipted commit is a planned follow-up.
Content proposals (next section) don't have this limit: they're re-checked by the blobs they cite.

`scripts/demo_async_approval.py` runs the same pipeline both ways through the daemon and prints
the wall clock of each, with our own measured commit times (`docs/PERFORMANCE.md`).

## Approvals that pin the commit (v0.5)

By default an approval pins the target (`remote`, `branch`), not the commit: whichever commit is
staged when it arrives is committed. A staged proposal can be replaced by a re-proposal, so a
human who read the diff of commit A may end up approving commit B (FINDING-D1).

An approver can now pin the commit they read: `synthe_sign.py approve ... --detached --commit <sha>`
(the Lab's `approve` takes the same `commit`). The signed params then include `commit`; admission
accepts that one extra key even though the sender's plan cannot name it, and the broker compares it
with the proposal. To make it mandatory, set per effect in `broker.json`:

```json
"effects": {"git_push": {"require_approval_commit_pin": true, "remotes": {...}}}
```

Then an approval without a matching `commit` leaves the proposal staged (`approval_commit_missing`).
Default is off, so existing approvals keep working. The Board does not yet display staged
proposals, so until it sends the commit it shows with the click, use the CLI for pinned approvals.

## Content proposals and reading the repo (v0.5)

Chat agents (ChatGPT, Grok and others) have no git and no push rights. They read files through the
broker and send back the full text of what they change; the broker builds the commit itself and
then runs every usual check on it.

**1. Read.** `synthe_read_file(path, ref?)` returns `{remote, ref, commit, path, blob, size, text}`
from the live tip of a readable branch; `synthe_list_files(prefix?, ref?)` returns
`{files: [{path, blob, size}], truncated}` (up to 2000). CLI: `synthe_client.py read PATH`,
`synthe_client.py ls [PREFIX]`. Reads are off unless the operator opts a remote in:

```json
"remotes": {"synthe": {"url": "...", "branches": ["synthe/dogfood"], "readable": true,
                       "readable_refs": ["synthe/dogfood"]}}
```

`readable_refs` defaults to `branches`. Only regular UTF-8 text files up to 200 KB are served.
Reads go to the broker's own mirror; nothing is receipted and nothing is written to the remote.

**2. Propose.** The same `propose` op, with files instead of a commit:

```json
"params": {"remote": "synthe", "branch": "synthe/dogfood",
           "files": {"tests/ledger/test_stress.py": "<full UTF-8 text>"},
           "delete": ["notes/old.md"],
           "base_blobs": {"tests/ledger/test_stress.py": null,
                          "notes/old.md": "<blob id from synthe_read_file>"},
           "message": "T2.1: 50-way claim stress"}
```

- **Every touched path is cited.** An edit or delete cites the blob it was based on; a new file
  cites `null`. Missing → `content_base_missing`. This is PlanFence's rule: cite the exact records
  the plan used, re-check exactly those at commit.
- **The broker validates paths, not git.** In testing, git's own `update-index` accepted
  `.git/config`, `../x` and `/abs`, so the broker refuses them first (`path_invalid`): paths must
  be relative POSIX, NFC-normalized, with no empty, `.` or `..` component, no component ending in a
  dot or space, nothing named `.git` (any case, or `git~N`), no backslash, control, format,
  surrogate, private-use or unassigned characters, ≤ 255 bytes per component and ≤ 1024 per path,
  and no two paths differing only in case.
- **Text only.** UTF-8 without NUL; new files are 100644, an edited file keeps its mode (100644 or
  100755); symlinks, submodules and directories can't be targets (`content_malformed`). Limits per
  proposal: `max_content_files` (100 paths) and `max_content_mb` (2) → `content_too_large`.
- **The commit.** Parent = the live tip of `branch` (or `base` for a new branch). Tree = the
  parent's tree + `files` − `delete`, built in a private index. Author `<agent> via Synthe
  <agent@synthe.invalid>`, committer the broker; message = the first line of `message` (≤ 200
  chars, control characters stripped) plus `Synthe-Handoff`, `Synthe-Key` and `Synthe-Agent`
  trailers. Identical content → `no_change`. A content proposal carries no `commit`, `bundle`,
  `fetch_from` or `source` (`proposal_malformed`).
- **Then the unchanged checks:** plan and params, approvals, branch ceiling, every path of the
  commit against the lane (`path_outside_scope`, `path_forbidden`, ...), fast-forward,
  compare-and-swap, confirmation.

**3. Concurrency: optimistic, per path.** If the branch moved between building the commit and the
push, the broker rebuilds it on the new tip, but only when every cited blob is still what the new
tip holds. Otherwise it's `content_conflict` (stale): nothing is pushed, the claim stays reserved,
and the agent re-reads and re-applies. Since lanes are disjoint, rebases almost always succeed, which
removes most `remote_moved` churn on one shared branch. An explicit `expected_old` opts out:
strict compare-and-swap, no rebase.

**Staged content proposals** (`wait_for_approval`) are not pinned to a tip (`expected_old:
"cited-blobs"` in the staged record). When the approval arrives they're rebuilt on the live tip
under the same citation rule.

**Receipts** carry `content: {files, deletes, bytes, digest, paths}`, where `digest` is the
SHA-256 of the canonical `{files, delete}` JSON. They never carry the file text. `commits_from` is
`content sha256:...`, and `effect.rebased_onto` is set when the commit was rebuilt on a newer tip.

**In the Lab**, a claim on a handoff whose push the broker performs defers that approval (agents
start before a human signs). The handoff shows **Approve** (`approve_at_commit`), which sends a
*detached* approval to the broker, so the packet and any claim stay intact. The broker then commits
whatever staged proposal it now covers, and the detail view lists the approvals and receipts.

## Lane grants and delegate approvers (v0.6)

By default a human approves every push. A human may instead sign a **lane grant**
(`src/synthe_lane_templates.py`): for one receiver, `git_push` only, a remote and a branch pattern, the
paths it may touch, a maximum number of uses, an expiry, and the digests of the receiver policy, the
trusted approvers and the effects config it was signed against (any change makes it `template_stale`).
Only a human in the receiver's `trusted_approvers` signs one (Ed25519 passphrase key or Touch ID key);
any trusted human may revoke it. Uses are reserved under one lock immediately before `git push` and are
never refunded.

A grant **without** a delegate stands in for the per-push approval itself (an unattended lane). A grant
**with** `"delegate": "<identity>"` hands the per-push review to that approver, typically a reviewing
model:

- The delegate is registered with `kind: "model_approver"` and its own key, is named by the grant, and
  is never the sender or the receiver of the handoff it reviews (`delegate_is_party`).
- It approves only a proposal the broker has **staged**, pinned to the staged remote, branch and commit,
  for at most 60 minutes and never past the grant (`submit_delegate_approval`; signing domain
  `synthe/delegate-approval/v1`). Anything else is receipted and refused.
- It may **escalate** instead (`escalate`; domain `synthe/delegate-escalation/v1`; recommendation
  `reject` or `unsure`). An escalation sticks to the proposal (idempotency key + action, whatever commit
  is pushed next): no later delegate approval counts, only a human's.
- At dispatch, under the lane lock, the delegate approval is read again (escalated, expired, or for
  another commit: nothing is pushed and no use is spent), then a use is reserved.
- A human's own approval always works as before and spends no grant use.
- `delegate_grant` (read-only) tells an approver which grant covers a staged push, so it cites the right
  one; staged proposals list `review` (waiting on the delegate) or `escalated` in `waiting_for`.

Receipts: `kind: "delegate_approval"` (`delegate_approval_accepted` / `delegate_approval_rejected`) and
`kind: "delegate_escalation"` (`escalated` / `escalation_rejected`); the push receipt names the delegate,
`delegated_by` (the human who signed the grant) and the grant use. Receipts prove which **key** approved,
not which model holds it.

A grant may also carry a `brief` (up to 4000 characters): the human's own instructions to the reviewer
("small src/ changes only, no new dependencies"). It is signed with the grant, so the reviewer can tell
it apart from the task text and the diff, which agents wrote.

**Running a reviewing model** (`src/synthe_approver.py`, its own OS user; the model never sees the key):

```bash
synthe-approver keygen --agent claude-reviewer --out ~/.synthe-approver/key.json
```

Add the printed entry (`kind: "model_approver"`) to the broker's registry, sign a grant naming it as
`delegate` (Studio or the Lab: `/api/lane-template`; `synthe-approver grant` prints a body to sign),
then give the reviewing model the MCP server:

```bash
synthe-approver mcp --broker unix:///var/run/synthe/broker.sock --key ~/.synthe-approver/key.json
```

Its tools are `synthe_review_queue`, `synthe_review_detail` (the broker's diff, the task, the brief,
each labelled by who wrote it) and `synthe_review_decide` (approve the exact commit read, or escalate
with `reject` / `unsure`). A commit restaged after the model looked is refused (`commit_changed`); the
key file must be private to the approver's user (`approver_key_exposed`).

What it does not do: content proposals (no commit until the broker builds one) are not covered by a
delegate yet, so they wait for a human. A delegate that is fooled (prompt injection in the diff) can
approve what the grant allows; the grant's branch, path, use and time limits bound that, they don't
remove it.

## Reason codes (new in v0.4)

| Code | State | Meaning |
|---|---|---|
| `proposal_malformed`, `claim_token_required` | invalid | the proposal is incomplete |
| `effect_not_planned` | blocked | the action isn't in the signed plan |
| `effect_type_unsupported` | blocked | the broker doesn't mediate that tool |
| `effect_params_unplanned` | blocked | the plan doesn't pin the target (remote, branch) |
| `effect_params_mismatch` | blocked | the proposal differs from the signed plan |
| `approval_params_missing` | blocked | the approval doesn't pin the target |
| `approval_params_mismatch` | blocked | the approval pins a different target (also checked at admission) |
| `approval_commit_missing` | blocked | the broker requires the approval to pin the commit (`require_approval_commit_pin`), and none does for this commit; the proposal stays staged |
| `remote_unknown`, `branch_not_allowed`, `bad_branch` | blocked/invalid | outside the broker config |
| `source_not_allowed`, `commit_unavailable` | blocked/incomplete | the agent repo is outside `source_roots`, or the commit is missing |
| `remote_moved` | stale | the branch isn't where the agent expected |
| `non_fast_forward`, `unrelated_history` | blocked | rewriting history is never mediated |
| `too_many_commits`, `no_change`, `base_missing` | blocked/invalid | sanity limits |
| `path_outside_scope` | blocked | a pushed commit touches a path outside `owned_paths` |
| `path_outside_receiver_policy` | blocked | outside a policy layer's `allowed_paths` |
| `path_forbidden` | blocked | matches `forbidden_paths` |
| `remote_moved_during_commit` | stale | the compare-and-swap refused; nothing was pushed |
| `push_rejected`, `push_failed`, `remote_unreachable`, `broker_credentials_missing` | blocked/retryable | the remote refused, or couldn't be reached |
| `effect_unconfirmed` | unknown | the push ran, but the remote doesn't show the commit; reconcile |
| `effect_already_executed` / `effect_outcome_unknown` | duplicate/unknown | this effect already ran, or its outcome is unknown |
| `dependency_incomplete` | blocked | v0.5: a `depends_on` key is not `COMPLETED` yet; propose again once it is |
| `dependency_unknown` | blocked | v0.5: a `depends_on` key was never claimed in this ledger |
| `dependency_cycle` | invalid | v0.5 (admission): `depends_on` closes a wait-for cycle through live claims |
| `claim_conflict` | blocked | v0.5 (admission): `exclusive_paths` is on and a live claim may touch the same files |
| `source_path_not_allowed` | blocked | v0.5: a path on the agent's disk instead of a bundle, without `allow_path_sources` |
| `bundle_too_large` | invalid | v0.5: the bundle exceeds `max_bundle_mb` |
| `staged` | blocked | v0.5: not an error; the proposal is held until its approval or upstream arrives (listed with the codes it waits on) |
| `approval_malformed` | invalid | v0.5: a detached approval is missing `action`, `approver`, `idempotency_key`, `from` or `to`, or its `params` isn't an object |
| `approval_unsigned` | blocked | a detached approval without a signature (also the v0.3 admission code) |
| `approval_duplicate` | duplicate | v0.5: this exact detached approval was already received |
| `path_invalid` | invalid | v0.5: a content path (or a read path/prefix) breaks the path rules, two paths differ only in case, or a path would sit under an existing file |
| `content_malformed` | invalid | v0.5: `files`/`delete`/`base_blobs` have the wrong shape, text isn't UTF-8 or holds a NUL, a path appears twice, a cited blob isn't 40-hex, or the target path isn't a regular file |
| `content_too_large` | invalid | v0.5: more than `max_content_files` paths (100) or `max_content_mb` (2) of text |
| `content_base_missing` | blocked | v0.5: a changed or deleted path isn't cited in `base_blobs` (cite `null` for a new file) |
| `template_malformed`, `template_scope`, `template_unavailable` | invalid/blocked | v0.6: a lane grant has the wrong shape, doesn't cover this receiver/remote/branch/paths, or the named grant isn't usable |
| `template_signature_invalid`, `template_expired`, `template_stale`, `template_revoked`, `template_exhausted` | blocked | v0.6: the grant's human signature fails, it expired, the policy/approvers/effects changed since it was signed, it was revoked, or its uses are spent |
| `template_id_reused`, `template_revocation_invalid`, `template_store_corrupt`, `registry_unreadable` | invalid | v0.6: a grant id was reused, a revocation isn't signed by a trusted human, or broker state can't be read |
| `delegate_invalid` | invalid | v0.6: a grant names a delegate that isn't a registered `model_approver`, or is the receiver |
| `delegate_malformed`, `delegate_signature_invalid`, `delegate_not_named`, `delegate_is_party` | invalid/blocked | v0.6: a delegate approval/escalation has the wrong shape, its signature fails, its signer isn't the grant's delegate, or the signer is the handoff's sender or receiver |
| `delegate_approval_missing`, `delegate_approval_stale`, `delegate_approval_expired`, `delegate_approval_too_long` | blocked | v0.6: no delegate approval yet; it is not for the staged commit/handoff; it expired; or it asks for more than 60 minutes (or outlives the grant). The proposal stays staged (`review`) |
| `delegate_escalated` | blocked | v0.6: the delegate sent this proposal to a human; only a human approval commits it (`escalated`) |
| `delegate_store_corrupt` | invalid | v0.6: the delegate decisions file can't be read |
| `content_conflict` | stale | v0.5: a cited blob isn't what the branch holds now (someone changed the file, a "new" file exists, a deleted file is gone); nothing pushed, re-read and re-apply |

**Reading the repo (v0.5).** `read_file` / `list_files` errors come back as daemon errors (no
receipt; MCP: `decision: "ERROR"`):

| Code | State | Meaning |
|---|---|---|
| `read_not_allowed` | blocked/invalid | the remote isn't `"readable": true`, the branch isn't in `readable_refs` (else `branches`), or no branch was named and none is plain |
| `file_not_found` | invalid | no such path, or no such branch on the remote |
| `file_not_text` | invalid | a directory, symlink or submodule, or not UTF-8 text |
| `file_too_large` | invalid | over 200 KB |

**Broker daemon (v0.5).** These come back as `{"ok": false, "error": {"code", "message"}}` (no
receipt: the request never reached the commit protocol), or stop the broker from starting:

| Code | Meaning |
|---|---|
| `broker_not_isolated` | the client runs as the broker's user or as root (it could read the keys), or its uid is unreadable |
| `client_not_allowed` | the client's uid is not in `isolation.clients` |
| `unauthorized` | TCP without the right bearer token |
| `request_malformed`, `request_too_large`, `unknown_op` | the request isn't `{"op", "args": {...}}`, is over the size limit, or names an op the daemon doesn't serve (`release` is operator-only) |
| `broker_error` | internal error; the daemon keeps serving |
| `broker_key_exposed`, `broker_credentials_exposed` | startup: the key or a token file is not owned by the broker or is readable by others |
| `broker_state_writable` | startup: config, registry, ledger, receipts, state dir or socket dir is writable by others |

## Next

1. `send_email` as the second mediated effect (recipients pinned by the approval).
2. Extend the TLA+ model in `formal/` to cover the commit step.
3. Anchor the receipt-chain head in a public transparency log (Sigstore Rekor) on a schedule.
4. Attested-enclave mode for the broker (separate user / container by default shipped in v0.5: [`ISOLATION.md`](ISOLATION.md)).
5. Map receipts onto an IETF agent-receipt profile once one wins.
