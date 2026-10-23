# Synthe threat model (v0.7)

One page, so design arguments start from the same place.

## What Synthe is

An **admission gate**: before a receiving agent acts on a handoff, the checker
verifies who sent it, that the authority asked for fits the receiver's policy,
that the bytes it points at haven't changed, that required approvals exist and
are bound to this handoff, and that this unit of work hasn't already been claimed.

A signature proves **who said it**. It never proves **that it's safe**.

The [standalone verifier](docs/VERIFY.md) pins the issuer and optionally previously trusted chain
checkpoints. An unanchored valid prefix may be rolled back; a local signature does not establish an
external effect. [Generic/Claude setup](docs/ANY_AGENT.md) keeps OS separation: shell hooks are bypassable
UX guards, not the credential wall. The new Linux setup path still needs a clean-host acceptance run.

## Assets

| Asset | Where it lives | If it's compromised |
|---|---|---|
| Registry (agents, keys, receiver policy) | `registry.json` | **Root of trust.** Whoever can edit it decides who exists and what's allowed |
| Human approver keys | passphrase-sealed file, or Secure Enclave with a 0600 public metadata/handle file | Attacker who can use one can approve any gated action |
| Agent signing keys | key files; custodial in the lab | Attacker can send handoffs as that agent |
| Ledger | `ledger.json` (Action: `actions/cache` + `SYNTHE_LEDGER_ANCHOR` repo variable) | Deleting or resetting it re-enables duplicates -- unless the out-of-cache anchor is configured, in which case rollback/deletion fails closed |
| Workspace bytes | `--workspace` root | Pins detect changes; they can't stop a changed file being read later |
| Broker key and remote credentials | the broker's own user (`/var/db/synthe`, `/var/lib/synthe`) or container volume, 0600 | Sign receipts; push anywhere the token can |
| Task issuer key (v0.7) | next to the broker key, same OS user, 0600 | Sign self-issued tasks, but only inside a grant a human signed, and the broker still checks its own issue record; whoever holds it also holds the GitHub token |

## In scope: what the gate stops

| Threat | Mechanism | Reason code |
|---|---|---|
| Packet edited in transit | Ed25519 over the canonical handoff | `signature_invalid` |
| Agent spoofs another agent | key must be registered under `from` | `signature_invalid`, `signature_signer_mismatch` |
| Sender grants itself tools or budget | receiver policy is a ceiling | `authority_exceeds_receiver_policy` |
| Sender drops an approval requirement | policy's `approval_required_for` is unioned in | `approval_missing` |
| Forged or typed-in approval | approvals must carry a valid Ed25519 or ES256 signature from a registered, trusted approver key | `approval_unsigned`, `approval_signature_invalid`, `approver_not_trusted` |
| Approval replayed onto another handoff | signature binds `idempotency_key`, `from`, `to` | `approval_signature_invalid` |
| Approved spend stretched after signing | v2 approvals pin the reviewed budget and cost estimates as signed ceilings; signing is refused without a complete budget to bind, and unpinned v2 approvals are rejected outright; pre-v2 approvals are rejected outright | `approval_budget_exceeded`, `approval_estimates_exceeded`, `approval_budget_missing`, `approval_version_unsupported` |
| Same work executed twice | ledger claim (RESERVED → COMPLETED, file lock) | `duplicate_idempotency_key`, `idempotency_key_reserved` |
| Stale cache restores an older ledger (rollback) | HMAC-sealed hash chain + monotonic seq checked against the out-of-cache anchor (repo variable) | `ledger_rollback` |
| Forged or swapped-in ledger file | chain seal (HMAC when `SYNTHE_LEDGER_HMAC_KEY` is set); unsealed file under an anchor refused as downgrade | `ledger_corrupt`, `ledger_rollback` |
| Ledger file deleted / total cache eviction | anchor expects the chain to continue; missing file fails closed | `ledger_rollback` (recover with one `ledger-bootstrap` run) |
| Anchor unavailable when required | fail closed rather than run unanchored | `ledger_anchor_unavailable` |
| Someone else closes your claim | completion bound to the packet digest + claim token (MCP) / connector identity (lab) | `completion_packet_mismatch`, `claim_token_invalid`, `claim_token_required` |
| Slow receiver acts after its claim was released and redispatched | fencing epoch + `fenced()` execution boundary (model-checked, `formal/`) | `claim_token_invalid`, `completion_unknown_key` |
| Stale or swapped inputs | SHA-256 pins against the workspace | `artifact_hash_mismatch`, `evidence_hash_mismatch` |
| Paraphrased "verbatim" quote | verbatim kinds must pin source bytes | `evidence_not_verbatim`, `verbatim_evidence_unpinned` |
| Undeclared side effects | policy can require `planned_actions` | `planned_actions_missing` |
| Checker silently skips a check | fail closed when a policy expects a pin but no workspace exists | `workspace_required` |

## v0.4: what the commit broker changes

For effects the broker mediates (`git_push` today), the agent holds no credentials;
it can only *propose*. That turns three items below from "out of scope" into
enforced, for those effects only (`docs/COMMIT.md`):

| Threat | Mechanism | Reason code |
|---|---|---|
| Receiver skips the gate (item 2) | no credentials: the broker is the only path to the effect | — |
| Receiver does more than declared (item 3) | every path in every pushed commit vs `owned_paths`, `allowed_paths`, `forbidden_paths`; result observed on the remote | `path_outside_scope`, `path_outside_receiver_policy`, `path_forbidden`, `effect_unconfirmed` |
| Effect outside `fenced()` (item 9) | every mediated effect runs inside `fenced_effect()`, with check + effect in one locked step | `effect_already_executed`, `claim_token_invalid` |
| Approval reused after the sender retargets | approvals sign the effect's params; admission and commit both compare | `approval_params_mismatch`, `approval_params_missing` |
| Effect not in the signed plan / different target | plan params are sender-signed and must match | `effect_not_planned`, `effect_params_mismatch` |
| Remote changes between check and push | `--force-with-lease` compare-and-swap | `remote_moved_during_commit` |
| History rewrite | fast-forward only | `non_fast_forward` |
| Silent denials | every decision is a signed, hash-chained receipt | `receipts verify` |
| Retry after a completed effect | exact packet + claim token + full prepared-effect fingerprint returns the original verified receipt; the adapter is not called | `effect_fingerprint_mismatch`, `replay_receipt_mismatch` |

Stored-result replay authenticates and reuses what the broker already recorded. It does not prove
that an external provider told the truth, repair an incomplete effect fingerprint, or make a stale
or negative reconciliation observation authoritative. **No negative observation grants a dispatch
right.** A missing, stale, mismatched or uncertain provider observation stays `unknown` and blocked.
See [`docs/REPLAY.md`](docs/REPLAY.md).

## v0.5: ordering and concurrent changes

| Threat | Mechanism | Reason code |
|---|---|---|
| Effect committed before the upstream work it relies on is finished | signed `depends_on`, checked inside the fence (one locked step with the effect) | `dependency_incomplete`, `dependency_unknown` |
| Dependency dropped by a relay or by the claimant | `depends_on` is inside the signed handoff, and the claim is bound to the packet digest | `signature_invalid`, `completion_packet_mismatch` |
| Handoffs waiting on each other forever | wait-for cycle through live claims refused at admission | `dependency_cycle` |
| Two agents changing the same files at once | `exclusive_paths`: one live claim per overlapping `owned_paths` on a receiver | `claim_conflict` |

Limits: `depends_on` only covers dependencies the **sender declares**; Synthe can't infer
an undeclared one. Exclusivity is per receiver and per ledger, and it is about *declared*
`owned_paths`. For mediated `git_push` the broker enforces those paths on every pushed commit;
for unmediated work they are a promise, not a fence. A claim that is never completed blocks
overlapping claims until the operator releases it (fail closed, at the cost of waiting).

The boundary: **the broker protects only credentials it holds.** An agent with its own
token is not mediated, whatever else is true.

## v0.5: the broker is isolated by default

Up to v0.4, an agent running as the same OS user as the broker could read the broker's key or
keychain: a seatbelt, not a wall. Now the credential holder runs as **its own OS user** (or in a
container) and agents reach it only through its socket. Same-user or in-process use is **dev mode**:
explicit in the config (`"isolation": {"mode": "none"}`) and stated in every receipt.
Details: [`docs/ISOLATION.md`](docs/ISOLATION.md), verified on Linux with two real users.

| Threat | Mechanism | Reason code |
|---|---|---|
| Agent reads the broker's key or GitHub token | broker runs as its own user; key and token files must be 0600 and broker-owned or it won't start | `broker_key_exposed`, `broker_credentials_exposed` |
| Agent runs the broker's code in its own process | in-process use refused unless mode `none`; receipts record `via` and `isolation` | (refused at startup / `NotIsolated`) |
| A client that could read the keys (broker's user, root) | client uid from the kernel (`SO_PEERCRED` / `LOCAL_PEERCRED`), never from the client | `broker_not_isolated` |
| Any other local user talks to the broker | `isolation.clients` allowlist (unknown names: the broker won't start) | `client_not_allowed` |
| Network client without the token (container mode) | bearer token, constant-time compare | `unauthorized` |
| Agent rewrites the registry, ledger or receipts | refuse to start if any of them, or their dirs, is writable by others | `broker_state_writable` |
| Agent swaps the socket for its own (fake broker) | refuse to start if the socket's directory is writable by others; client doctor compares the broker's kernel uid; **a client with `SYNTHE_BROKER_UID` (or `--broker-uid`) checks the kernel uid on every call and refuses before sending anything. Opt-in: without it, only `doctor` checks** | `broker_state_writable`, `broker_not_isolated` |
| Agent points the broker at files on its disk | commits arrive only as a git bundle unless the operator allows paths | `source_path_not_allowed` |
| Malicious bundle (huge, malformed trees such as a `.git` entry) | size cap; `transfer.fsckObjects` on unpack; only the content-addressed commit is used | `bundle_too_large`, `commit_unavailable` |
| Credentials echoed back in errors or receipts | every response and receipt scrubbed (URL userinfo and every held token value) before signing or sending | — |

Limits: root, passwordless `sudo` and membership in the `docker` group defeat any OS-level
isolation (the client doctor FAILs or WARNs on each). Container mode is declared by the operator
and receipted `verified: false`. On macOS the installer exists but is not yet verified on a real
machine.

## v0.5: speculative commit and detached approvals

Agents may now claim and propose before the human has approved; the broker holds the proposal
`STAGED` and commits it when a signed approval arrives. This widens the time between the check
and the effect, so every check runs again at commit.

| Threat | Mechanism | Reason code |
|---|---|---|
| An agent writes or edits its own approval | a detached approval counts only with a registered, trusted approver's signature over this handoff's key, sender and receiver (and pinned params) | `approval_unsigned`, `approval_signature_invalid`, `approver_not_trusted` |
| An approval for one handoff re-addressed to another | the signature covers `idempotency_key`, `from`, `to`; the clear-text copies are only for filing | `approval_signature_invalid` |
| An approval for another target (branch, remote) | its pinned params are checked against the proposal at commit; it stays staged | `approval_params_mismatch` (staged) |
| The commit swapped after the human read it (staged proposal replaced) | opt-in `require_approval_commit_pin`: the approval names the commit; by default an approval binds the target, not the content | `approval_commit_missing` (staged) |
| The world changes while the proposal waits | the branch tip is pinned at staging; the whole protocol (expiry, policy, live remote, fast-forward, paths, compare-and-swap) runs again at commit | `remote_moved`, `handoff_expired`, ... |
| A replayed approval, or two copies at once | duplicate check and store in one locked step; the effect itself is still exactly-once in the fence | `approval_duplicate`, `effect_already_executed` |
| A staged proposal reveals claim tokens | `staged.json` is 0600 and broker-owned (the daemon won't start otherwise); `staged` and every receipt omit tokens | `broker_credentials_exposed` |
| The broker dies while committing a staged proposal | the record stays `COMMITTING`; after 10 minutes it is retried through the fence: if no attempt was recorded it commits, if one was it reports an unknown outcome rather than acting twice | `effect_outcome_unknown` |

Limits: an approval is consent to the signed plan, not to the exact commit; the commit is bounded
by the plan's paths and the receiver's policy, as before. Speculation does not make an agent that
holds its own credentials safe. The branch-tip pin is conservative: a downstream staged on the
same branch as its pending upstream is denied `remote_moved` once the upstream pushes.

## v0.5: content proposals and reading the repo

Chat agents without git send file text; the broker builds the commit in its own mirror. The agent
now chooses the paths and bytes the broker writes into a tree, so the broker validates them before
git sees them.

| Threat | Mechanism | Reason code |
|---|---|---|
| A path that escapes or poisons the repo (`.git/config`, `../x`, `/abs`, `.GIT`, `git~1`, `a/./b`, trailing dot or space, invisible characters, NFC/NFD twins) | the broker validates every path itself (git's own `update-index` accepted `.git/config`, `..` and `/abs` in testing); the built commit then goes through the usual lane path checks | `path_invalid`, then `path_outside_scope`, `path_forbidden` |
| Two paths that collide on case-insensitive checkouts | case-folded duplicates refused | `path_invalid` |
| Binary, symlink, submodule or executable smuggled in as "text" | UTF-8 without NUL only; new files 100644; only regular files can be targets | `content_malformed` |
| Oversized proposal (memory, disk) | caps on paths and bytes per proposal | `content_too_large` |
| Clobbering someone else's change (lost update) | every edited, deleted or created path cites the blob it was based on (`null` = new); checked at build time and again inside the fence before the push; rebuilt on a moved tip only if every cited blob is unchanged | `content_base_missing`, `content_conflict` |
| Forged authorship or trailer injection | author is fixed to `<agent> via Synthe` (agent id sanitized), committer is the broker; message is one line, control characters stripped, trailers added by the broker | — |
| Replay of an executed content proposal | the full normalized content proposal is fingerprinted; an exact completed duplicate returns the stored receipt before rebuilding a commit, while changed content conflicts | `effect_fingerprint_mismatch`, `replay_receipt_mismatch` |
| Secrets in proposed file text leak into the evidence chain | receipts carry counts, paths and a SHA-256 digest, never the text | — |
| Agents read files they shouldn't | reads are opt-in per remote (`"readable": true`) and per branch (`readable_refs`, else `branches`); regular text files up to 200 KB only; read-only, from the broker's mirror | `read_not_allowed`, `file_not_text`, `file_too_large` |

Limits: a read reveals the whole readable branch to every agent that can reach the broker; lanes
restrict writes, not reads. The citation rule protects the cited paths only: an agent that edits
`a.py` based on `b.py` without citing `b.py` can land on a changed `b.py`.

## v0.6: one-command container setup (`deploy/docker/setup.py`)

The setup script is the only place outside the broker that touches the GitHub token, so it is
held to the same rules.

| Threat | Mechanism |
|---|---|
| The token leaks through the setup itself | read from a file (never argv or env), copied into the volume 0600 and owned by the broker's uid; never printed; not in `broker.json` or the registry (tested with a planted token) |
| A human's private key handed to the setup (and so to the broker's volume) | approvers are given as public keys; a file holding `private_key` is refused |
| Agents get `main` or every branch | `main`, `master`, `*` and `**` are refused as branch patterns; agents land on branches and a human merges |
| A re-run wipes an existing broker's key, ledger or receipts | a non-empty volume is refused |
| An approval nobody signed | the agent's policy requires signed packets and signed approvals for `git_push`, from the named approvers only |

Limit: the container is a wall only against users outside the `docker` group (see above).

## v0.6: Touch ID approvals on macOS

`synthe-init touchid` creates an ES256 (P-256) approval key in the Mac's Secure Enclave and registers
its public half next to the existing passphrase-protected Ed25519 key. The private key is
non-exportable and is released for signing only after a biometric check. The key uses
`.biometryCurrentSet`, so enrolling or removing a fingerprint invalidates it instead of silently
expanding who may approve. Packet and receipt signatures remain Ed25519.

| Threat | Mechanism |
|---|---|
| Approval key copied from disk | only a public key and an opaque, device-bound Secure Enclave handle are stored; the private key is not exportable |
| Agent labels one signature as another key or algorithm | the registry selects Ed25519 or ES256 by `kid`; algorithm confusion is refused, and `kid` is required when both approval keys are registered |
| Agent forges what the biometric dialog appears to approve | the prompt is rendered from the broker's staged detail, with control characters removed; the signed bytes pin the action, target and commit |
| Touch ID is cancelled, unavailable or returns malformed output | no approval is submitted and the proposal stays staged |
| Fingerprint enrollment changes after key creation | `.biometryCurrentSet` invalidates the key; the operator must enroll a replacement and update the registry |

Limits: Touch ID proves that the configured Mac authenticated an enrolled fingerprint; it does not
prove that the diff is safe. A process running as the same desktop user can invoke the helper and
choose prompt text, so the operator must first read the broker-derived terminal card and compare its
branch, commit and files with the system prompt. The prompt cannot display the whole diff. Root or a
compromised OS/UI remains outside this boundary. The `synthe-approve --passphrase` path deliberately
keeps the sealed Ed25519 key as a recovery fallback. Details: [`docs/TOUCHID.md`](docs/TOUCHID.md).

## v0.6: lane grants and delegate approvers

A human may sign a bounded grant (receiver, remote, branch pattern, paths, uses, expiry, policy
lineage; since v0.7 uses and expiry are optional, see below). With a `delegate`, each push under it also needs that delegate's own signed approval of the
exact staged commit: a reviewing model approves in the human's place, inside limits the human signed.
Without a delegate, the grant itself approves (an unattended lane). Details:
[`docs/COMMIT.md`](docs/COMMIT.md) "Lane grants and delegate approvers".

| Threat | Mechanism |
|---|---|
| An agent approves its own push through a delegate | the delegate is never the handoff's sender or receiver (`delegate_is_party`), and must be a registered `model_approver` named by the grant |
| An agent mints a grant or a delegate approval | grants need a trusted human's signature; delegate approvals need the named delegate's key, over its own signing domain (never valid as a human approval, or as an escalation, or back) |
| A delegate pre-approves a commit it never saw, or the agent swaps the commit after review | the approval pins the remote, branch and commit of the broker's staged record, and is matched again at commit time and at dispatch |
| An agent re-pushes until the reviewer says yes | an escalation sticks to the proposal (key + action) for every later commit; only a human approves it |
| Escalation or revocation races the push | the delegate approval and the grant are read again under the lane lock immediately before `git push`; a use is reserved only after that |
| A long-lived delegate approval is replayed | at most 60 minutes (also under a grant without expiry), never past the grant; the grant's uses, expiry and lineage still apply |
| Policy or approvers change after the grant was signed | the grant carries their digests: any change makes it `template_stale` |

Limits (say these plainly): a delegate model can be fooled, for example by instructions planted in
the diff or the task text; then it approves what the grant allows. The grant's branch, path, use and
time limits bound that; they don't remove it. Receipts prove which **key** approved, not which model
or prompt produced the decision. The delegate key must live in its own process and OS user (rule:
isolation), never in an agent's; a delegate key an agent can read is an agent approving itself. A grant
without a delegate has no per-push reviewer at all: it trades review for speed within its limits.
Content proposals are not delegated yet (they wait for a human).

## v0.7: risk-aware and standing lanes

A grant may list the risk tiers it approves without a human (`"auto_approve": ["routine", "review"]`, the
default for new grants; `src/synthe_risk.py`, shared with the approval card). Anything else, and any push
that touches a path outside the grant, is staged for a human instead of pushed. A grant may also omit its
use limit and expiry: a standing lane. Details: [`docs/COMMIT.md`](docs/COMMIT.md) "Risk-aware lanes".

| Threat | Mechanism | Reason code |
|---|---|---|
| A CI workflow, dependency file or secret-like file slips through an unattended lane | the broker classifies the exact range it is about to push, on its own mirror, under the lane lock immediately before dispatch; a tier the grant doesn't list stays staged for a human, no use spent | `risk_escalated` |
| The risky file hides in an intermediate commit and the tip looks clean | every path of every pushed commit is classified, not the net diff; renames count both paths | `risk_escalated` |
| The agent describes the push as harmless | the classification reads only the broker's copy (paths, line counts, deletions, commit count); agent text is never an input | — |
| A commit is restaged after it was classified | dispatch classifies again, under the lane lock, whatever was classified at staging | `risk_escalated` |
| A fooled delegate approves a high-risk push | the tier is checked before the delegate is asked and again before its approval is read at dispatch; a delegate approval for an escalated push is refused | `risk_escalated` |
| The agent re-proposes until the grant takes it, or the sweeper re-dispatches an escalated push | an escalated proposal is covered only by a human approval; a new commit is classified on its own merits | — |
| A grant's tiers widened, or the field dropped, after signing | `auto_approve` is in the signed body; unknown, empty or duplicate tiers are refused | `template_signature_invalid`, `template_malformed` |
| The risk rules are loosened after a grant was signed | a risk-aware grant's lineage pins the digest of the effective rules (operator lists and built-in defaults) | `template_stale` |
| A push on the lane's branch touches files outside the grant | staged for a human like any push without a lane (no use spent); receiver-policy paths are still denied outright | `outside_lane_paths`, `path_forbidden`, ... |
| A limit stripped from a signed grant, or "unlimited" smuggled in as a malformed value | only an absent field means "no limit", and absence is covered by the signature; present but malformed limits are refused | `template_signature_invalid`, `template_malformed` |

Limits (say these plainly):

- **Risk is a heuristic.** It reads paths and sizes, not code. A malicious change to an ordinary-looking
  source file (`src/app.py`), small enough and in few enough commits, is `routine` and goes out unattended.
  The tiers catch the changes that most often matter (CI, dependency manifests and lockfiles, build
  scripts, secrets-like files, deletions, very large diffs); they are not a review. With the default
  `["routine", "review"]`, dependency and lockfile changes, Dockerfiles, build scripts, `CODEOWNERS`,
  small deletions and diffs of 200-399 lines also go out unattended; sign `["routine"]` to be asked about
  them.
- **Patterns are the operator's policy.** An operator who replaces the path lists can weaken them; the
  grant then goes stale and a human re-signs, but nothing judges whether the new list is wise.
- **Splitting.** Many small routine pushes are each routine. The grant's branch and path limits, and its
  use limit if it has one, bound that.
- **Grants without `auto_approve`** (signed before v0.7) approve every tier, as before.
- **A standing lane is a standing permission.** A grant signed without `max_uses` or `expires_at` keeps
  approving until a human revokes it or it goes stale. What still bounds it: its receiver, remote and
  branch pattern; its paths (anything outside goes to a human); the receiver policy (owned, allowed and
  forbidden paths, denied outright); risk escalation; fast-forward only; revocation by any trusted human;
  and staleness when the policy, approvers, effects config or risk rules change. Nothing bounds how many
  pushes it carries or for how long; an agent that is compromised while the lane stands can use it until
  someone notices. Prefer limits for lanes nobody watches.

## v0.7: self-issued tasks (work starts without a person reading the task)

Said plainly: inside a lane that allows it, **work starts without a person reading the task.** The agent
decides what to work on, writes the task's purpose, writes the code and the commit message, and a routine
push inside the lane goes out with nobody asked. That is the feature. What bounds it is not a human reading
each task but: **the grant's scope** (receiver, remote, branch pattern, paths, any limits the human set),
**the receiver policy** (owned, allowed and forbidden paths, tools, budget, `max_ttl_hours`), **risk
escalation** (a self-issue grant must send high-risk pushes to a human, or name a reviewer; `escalate_at:
"review"` sends review-tier ones too), **revocation** (any trusted human closes the lane, and every task issued
under it that hasn't landed dies with it, even under a human approval) and **receipts** (every issue
decision and every push, with `task_origin`, listed in the weekly digest). Design and the full analysis:
[`docs/design/SELF_ISSUED_TASKS.md`](docs/design/SELF_ISSUED_TASKS.md); contract: SPEC section 16.

| Threat | Mechanism | Reason code |
|---|---|---|
| A delegate's or the broker's key signs the agent a task (finding F1: the checker had no sender ceiling) | receiver policy `trusted_senders`; setup writes the human approver; an issuer-kind key signs only self-issued packets | `sender_not_trusted`, `issuer_requires_grant` |
| The agent mints tasks without limit | tasks are issued only by the broker, under the lane lock, from a live grant; the human's optional `max_tasks` / `max_open` / `max_per_hour` are enforced when present; issue numbers are never refunded | `self_issue_not_granted`, `self_issue_exhausted`, `self_issue_open_limit`, `self_issue_rate_limited` |
| A task wider than its lane (branch, remote, paths, tools, lifetime, extra fields) | the broker builds the packet from the grant; the checker re-checks containment offline, even for a packet the issuer key signed | `self_issue_scope`, `self_issue_ttl` |
| The agent signs its own authority | the issuer key lives with the broker's user, never the agent's; a packet with `issued_under_grant` from any other identity is refused; the embedded grant must verify under a trusted human's key | `issuer_invalid`, `self_issue_grant_invalid`, `signature_invalid` |
| Self-approval | a self-issued packet carries no approval; its push is approved by the grant, its delegate, risk escalation to a human, or a human, never by the task | `self_issued_approval_present` |
| An issued packet edited, stripped of `issued_under_grant`, or given it | the signing domain is chosen by the signed handoff, so any of these breaks the signature | `signature_invalid` |
| A stolen issuer key (or a bug) signs a task the broker never issued | the broker accepts only the exact packet it recorded issuing | `self_issue_unknown` |
| Revocation or expiry races the work | the grant is re-checked at claim, propose, for staged proposals, and under the lane lock immediately before `git push`, also under a human's approval | `template_revoked`, `template_expired`, `template_stale` |
| An old checker accepts an agent-written task as ordinary | its own signing domain: a checker from before v0.7 rejects it | `signature_invalid` |
| The agent's purpose passes for the human's words, or hides terminal codes | `task_origin` comes from signed fields, never text; the card, the reviewer's detail, the task file and the plan say "written by the agent" and show the human's signed brief next to it; one line, NFC, no control or format characters, bounded length; the risk tier never reads it | `self_issue_purpose_invalid` |
| A retried issue request spends twice, or a request id is reused for other work | the same `request_id` with the same body replays the stored packet and receipt; another body is refused | `self_issue_request_conflict` |

Limits (say these plainly):

- **Nothing checks that the work was wanted.** The human consented to a class of work; within the lane, a
  prompt-injected agent can start and land work nobody asked for, as long as each push is routine (or
  review-tier, under the default lane). The bounds above, not a reviewer, contain it.
- **A delegate can't check "the diff does what the task asks"** for a self-issued task: the same agent wrote
  both. Its yardstick is the human's brief and the grant's limits; its instructions say so.
- **Offline verification is partial.** A standalone checker verifies the issuer signature, the embedded
  grant and containment; revocation, limits and the issue record are broker state, recorded in `task_issue`
  receipts.
- **The issuer key is as safe as the broker's user.** Root, passwordless `sudo` and the `docker` group defeat
  it, as they defeat the broker.
- **Who asked is the broker's receiver.** In separate-user mode the broker records the requester's kernel uid
  but issues only to its own configured receiver; any client the socket admits (the human's account too) can
  ask for a task for that agent.
- **An agent's open tasks can hold off a human's** under `exclusive_paths`; there is no pre-emption: the human
  releases them, or revokes the lane.
- **Standing lanes and long-lived tasks.** A grant without expiry issues tasks that live 30 days unless the
  receiver's `max_ttl_hours` is shorter (72 hours in setup's policy). A self-issued task is a bearer token
  for its lifetime, like any task; revoking the grant kills it.

## Out of scope: what it does NOT stop (be honest about these)

1. **A compromised or prompt-injected sender.** It produces a perfectly valid,
   signed packet for a malicious purpose. The gate checks the envelope and the
   authority, not the intent. The mitigations are narrow receiver policy, human
   approvals on dangerous tools, and small budgets.
2. **A receiver that never calls the gate**, or that "repairs" a rejected packet.
   Markdown rules aren't enforcement. Enforcement strength by entry point:
   GitHub Action / A2A adapter (in the infrastructure path) > CLI in a script >
   MCP tool (the model chooses whether to call it). The MCP gate is a seatbelt:
   it only works when worn. The behaviour study (roadmap Phase 1) measures how
   often models wear it.
3. **A receiver doing more than declared.** `planned_actions`, `owned_paths` and
   budgets are checked *before* the work. Nothing yet verifies what actually
   happened (roadmap: verify the diff on `--complete`). Budgets are checked on
   the sender's *estimates*, so a lying `est_usd` passes.
4. **Whoever controls the registry file but not the operator key** (once a
   genesis key is pinned). The registry can carry an Ed25519 operator
   signature over its body, and operator-key rotation is a verifiable chain
   (each new key is attested by the key it replaces; `synthe-sign
   sign-registry` / `synthe-sign rotate-registry-key`). The trust anchor is a
   genesis pin: the operator's genesis public key (or its sha256 fingerprint)
   from `--registry-genesis-key`, `SYNTHE_REGISTRY_GENESIS_KEY`, or a
   `registry-genesis.key` file the operator places next to the checker. With
   a pin, every caller (the CLI and the broker, commit broker, MCP and A2A
   daemons) requires a signed registry whose chain leads back to the pinned
   key, and fails closed with `registry_signature_invalid` otherwise. Honest
   limits: (a) with no pin configured, which is the default, the registry is
   NOT verified (a self-issued signature proves nothing), so whoever can edit
   it decides who exists; the CLI warns, and `--require-signed-registry`
   turns that into a rejection; (b) the pin is trust-on-first-use: it must
   reach the checker out of band, and whoever provisions it decides which
   operator is trusted. Nothing in this repo ships a pin;
   `examples/registry-genesis.pub` is the throwaway example key, for trying
   the examples only.
5. **Leaked or usable keys.** A leaked key is revoked, not just rotated out: the
   registry's `revocation` section lists revoked (agent, kid) pairs, each record
   signed by a designated revocation operator key, and every signature verification
   (packets, approvals, broker receipts) fails closed on a revoked key
   (`docs/KEY_REVOCATION.md`; `synthe-sign revoke-kid`). Rotating the operator
   key retires its public key into `revocation.past_operators` (verify-only;
   `synthe-sign rotate-operator`), so past revocations keep enforcing — a
   rotation never un-revokes (and a hand-edited rotation still doesn't: records whose signer is gone keep enforcing and are reported). Deleting a revocation record from the file
   (rollback) stays undetected until the registry is signed and pinned per
   the signed-registry item (item 4). Approver keys can be sealed under a passphrase (`synthe-sign keygen --encrypt`,
   `synthe-sign protect`; scrypt + AES-256-GCM), unlocked only at a terminal; `synthe-approve` and
   `synthe-init` refuse plaintext approver keys. On supported Macs, Touch ID keeps an ES256 approval
   key in the Secure Enclave, but a compromised same-user process can still cause a biometric prompt.
   Neither path makes an approval safe if the person approves malicious content.
6. **Truth.** A hash proves the bytes, not that they're correct.
7. **Meaningless content.** The checker validates structure. A packet whose
   `purpose` is `"<one sentence>"` is structurally valid. (The lab refuses unfilled
   template placeholders; the core checker doesn't judge text.)
8. ~~**`state_revision`** is required but not yet compared against anything.~~
   **Resolved:** demoted to optional, informational-only (`schema`,
   `handoff_check.py`, SPEC.md section 2). A required-but-unchecked field
   trains senders to ignore required fields; no sound checkable meaning
   exists within the checker's trust boundary, so ordering across handoffs
   is handled by `depends_on` instead.
9. **Effects outside `fenced()`.** The fencing guarantee covers only effects executed
   through it. A receiver that acts on a stale ACCEPT without the fence can still
   double-act after a release (`formal/README.md`, trace 2).
10. **Ledger durability on CI.** `actions/cache` can be evicted. The v0.6 integrity
   binding narrows this: every ledger write is HMAC-sealed into a hash chain, and the
   Action keeps an out-of-cache anchor (the `SYNTHE_LEDGER_ANCHOR` repository variable)
   that the restored ledger must match or extend -- so a stale restore, a forged file,
   or a deleted ledger fails closed instead of silently resetting duplicate protection.
   What remains: a *total* cache eviction still needs one deliberate `ledger-bootstrap`
   run (documented in `github-action/README.md`); without the HMAC secret the seal is
   tamper-evident, not tamper-proof; and two runs that restore the same snapshot still
   need the `concurrency` group -- the anchor *detects* the divergence after the fact
   (`ledger_diverged`) but cannot serialize the writers.

