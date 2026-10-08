# Handoff Contract v0.5

Every agent-to-agent handoff is an API boundary. The receiver validates the
handoff *before* it starts work, and the checker fails closed: anything it
cannot verify is a REJECT with a reason, never a silent pass.

- Packet wire format: `schema_version: "0.1"` (v0.3–v0.5 fields are additive).
- Ledger semantics: v0.2 claim lifecycle.
- Trust layer: v0.3 receiver policy, signatures, evidence pinning.
- Commit broker: v0.4 mediated effects and receipts (section 14).
- Concurrency: v0.5 wait-for dependencies (`depends_on`) and exclusive paths (section 8).
- Isolation: v0.5 the broker runs as its own OS user or in a container; agents use its socket (section 14).
- Machine-readable shape: [`schema/handoff.schema.json`](schema/handoff.schema.json).

## 1. Roles

| Role | Who | Owns |
|---|---|---|
| **Sender** | agent handing work off | the packet: identity, purpose, artifacts, evidence, planned actions, idempotency key |
| **Receiver** | agent that will do the work | its **policy**: what it will ever accept, its defaults |
| **Approver** | a human (or trusted agent) | signed approvals for specific actions on one specific handoff |
| **Operator** | whoever runs the checker | the registry, the ledger, the workspace root |

The core rule: **authority may only narrow.** A packet can ask for less than
the receiver's policy allows, never more. A sender can never grant itself an
approval or a tool.

## 2. The packet

```json
{
  "handoff": { ... },
  "signature": { "signer": "planner", "kid": "planner-1", "alg": "Ed25519", "sig": "<base64url>" }
}
```

`signature` is optional unless the receiver's policy sets `require_signatures`.

### `handoff` fields

| Field | Required | Meaning |
|---|---|---|
| `schema_version` | yes | `"0.1"` |
| `id` | yes | unique id of this transfer |
| `idempotency_key` | yes | dedupe key: the same key twice means one execution |
| `trace_id` | yes | links sender work, this handoff, receiver work and retries |
| `from` / `to` | yes | canonical agent ids from the registry (aliases are rejected) |
| `purpose` | yes | what the receiver must accomplish, in one sentence |
| `on_failure` | yes* | `reject` / `retry_with_budget` / `escalate` / `request_human` |
| `inputs.artifact_refs[]` | yes | `{path, sha256}`: files the receiver may read, pinned by full 64-hex SHA-256 |
| `inputs.state_revision` | yes | the state the receiver must work from |
| `scope.owned_paths` | yes* | what the receiver may touch (may be empty) |
| `scope.forbidden` | yes* | actions the receiver must not take (may be empty) |
| `authority.allowed_tools` | yes* | tools the receiver may call |
| `authority.budget` | yes* | numeric `tokens`, `usd`, `minutes` |
| `authority.approval_required_for` | yes* | actions/tools that need an approval first (may be empty) |
| `authority.approvals[]` | no | `{action, approver, expires_at?, kid?, sig?}` |
| `planned_actions[]` | policy | `{name, tool, params?, est_tokens?, est_usd?, est_minutes?}` |
| `depends_on[]` | no | v0.5: idempotency keys of upstream handoffs that must be `COMPLETED` (same ledger) before this handoff's effects may commit |
| `acceptance.output_schema` | yes* | what the receiver must produce |
| `acceptance.required_evidence` | yes* | evidence kinds that count as "done" |
| `acceptance.evidence[]` | no | `{kind, ref?, sha256?, verbatim?}` |
| `acceptance.expires_at` | yes* | RFC 3339 timestamp **with a timezone offset** |

`*` = can be filled from the receiver's `policy.defaults` (section 4). Fields
without a `*` are sender facts and are **never** filled for the sender.

When an entry point knows the authenticated caller identity, it supplies
`as_receiver`. A packet whose signed `to` differs is rejected as
`receiver_mismatch`. Offline validation may omit the binding; a multi-tenant
service must derive it from authenticated transport state, never packet data.

Evidence kinds `code_text`, `verbatim_quote` and `legal_text` must carry
`verbatim: true`. Under evidence verification they must also pin `sha256`.

## 3. The registry

One JSON file, fixed by the operator. It decides who exists, which keys they
sign with, and what each receiver will accept.

```json
{
  "policy": { ... },                      // optional: applies to every receiver
  "agents": {
    "planner": { "role": "...", "keys": [ { "kid": "planner-1", "alg": "Ed25519", "public_key": "<b64url>" } ] },
    "builder": { "role": "...", "keys": [ ... ], "policy": { ... } },
    "rishab":  { "role": "human approver", "kind": "human", "keys": [ ... ] },
    "old-name": { "alias_of": "planner" }
  }
}
```

## 4. Receiver policy

| Key | Kind | Effect |
|---|---|---|
| `allowed_tools` | ceiling | packet tools outside it → `authority_exceeds_receiver_policy`; planned tools outside it → `tool_not_allowed_by_receiver` |
| `trusted_approvers` | ceiling | approvals from anyone else → `approver_not_trusted` |
| `forbidden` | restriction | added to the packet's `scope.forbidden` |
| `approval_required_for` | restriction | added to the packet's list, so a sender cannot drop it |
| `budget` | ceiling | packet budget above it → `authority_exceeds_receiver_policy`; estimates are checked against the lower of the two |
| `require_signatures` | flag | unsigned packets → `signature_missing` |
| `require_signed_approvals` | flag | unsigned approvals → `approval_unsigned` |
| `require_planned_actions` | flag | no planned actions → `planned_actions_missing` |
| `verify_evidence` | flag | evidence pinning (section 7); also `--verify-evidence` |
| `exclusive_paths` | flag | v0.5: a second live claim on this receiver whose `owned_paths` may overlap one already held → `claim_conflict` (section 8) |
| `max_ttl_hours` | ceiling | unreleased: a handoff whose `acceptance.expires_at` is more than this many hours after the check → `ttl_exceeded`. A long-lived handoff is a bearer token for whoever holds its bytes. Must be a positive number, or the check refuses with `registry_malformed` |
| `defaults` | fill | receiver-owned fields filled when the sender left them out |

**Merging.** The top-level `policy` and `agents.<receiver>.policy` merge as follows:
restrictions union, ceilings intersect, budgets and `max_ttl_hours` take the minimum,
flags OR together, and later `defaults` override earlier ones.

**Defaults** can fill `owned_paths`, `forbidden`, `allowed_tools`,
`approval_required_for`, `output_schema`, `required_evidence`, `expires_at`,
`budget.{tokens,usd,minutes}` and `on_failure`. Every fill is reported in the
verdict as `defaults_applied`. Defaults are applied to a copy, so the signed
bytes never change.

## 5. Signatures

- Packet signatures and receipts use Ed25519 (RFC 8032). The checker uses `cryptography` when it is
  installed; otherwise it falls back to a pure-Python implementation, which verifies fine, but its
  signing is not constant-time, so don't use it for production keys.
- Approval signatures use the algorithm declared by the registered key: Ed25519, or ES256 (ECDSA
  P-256 with SHA-256 and a 64-byte `r || s` signature). ES256 is approval-only; it cannot sign a
  packet or receipt. The macOS Touch ID integration uses an ES256 key in the Secure Enclave. See
  [`docs/TOUCHID.md`](docs/TOUCHID.md).
- Canonical JSON: sorted keys, compact separators, UTF-8, whole-number floats
  written as ints.
- **Packet signature** signs `"synthe/handoff-signature/v1\n" + canonical(handoff)`.
  `signer` must equal `handoff.from`, and the key must be in `agents.<from>.keys`.
- **Approval signature** signs `"synthe/approval-signature/v1\n" + canonical({action, approver, expires_at, idempotency_key, from, to})`.
  That binds an approval to exactly one handoff, so it can't be replayed onto another.
- Order: approvers sign first, then the sender signs. The sender's signature
  covers the approvals list.
- **`kid` (unreleased).** When the signer or approver has more than one usable key for that signature
  type on record, the signature
  must name its `kid`: `signature_kid_required` for a packet, `approval_kid_required` for an
  approval. Without it the first listed key was picked, so after a rotation that appended the new key
  without removing the old one, the old (possibly leaked) key still verified.

**Strict parsing (unreleased).** A packet, a registry, and every request the MCP server, the commit
broker, the A2A adapter and the Lab receive are parsed strictly. A JSON object that repeats a key is
refused with `duplicate_field:<key>`: parsers disagree on which copy counts, so a signer and a checker
could see different packets. `NaN`, `Infinity` and numbers that overflow to infinity are refused with
`malformed:non_finite_number`: they are not JSON and can't be canonicalized for a signature. A packet
handed to `check()` already parsed is walked for non-finite numbers too, so it is refused with the
same code instead of crashing the checker.

Tooling: `src/synthe_sign.py keygen | approve | sign | verify`.

## 6. Validation order

Receiver defaults are applied to a copy first. Then:

1. **Structure.** Required fields, enums, types, element shapes, full-length hashes,
   non-negative numbers, and `planned_actions` if the policy requires them. *If this step fails,
   checking stops here.*
2. **Identity.** `from`/`to` exist in the registry and are canonical, and the packet signature verifies.
3. **Duplication and conflicts.** The idempotency key is looked up in the ledger (section 8). A
   `depends_on` list that closes a wait-for cycle through live claims is `dependency_cycle`; under
   `exclusive_paths`, `owned_paths` that may overlap another live claim on the receiver are
   `claim_conflict`. Unmet dependencies do **not** fail admission: the receiver may claim and work
   ahead, and the commit waits (section 8).
4. **Freshness.** `acceptance.expires_at` must be parseable, offset-aware and in the future.
5. **Authority.** Planned actions are checked against tools, forbidden actions, approvals and budgets, with the
   receiver policy as a ceiling.
6. **Artifacts** (when a workspace is given). Each path must stay inside the workspace, the file must
   exist, and the SHA-256 must match. If the receiver has a policy and the packet pins artifacts but
   no workspace was given, the check fails closed with `workspace_required`.
7. **Evidence.** Required kinds must be present and verbatim kinds marked verbatim. With
   verification on, each item must also pin its hash and match a file in the workspace.

Steps 2–7 collect every problem they find. The verdict's `state` is the state of
the **first** reason, so earlier steps take precedence.

## 7. Evidence pinning

When `verify_evidence` is on:

- every evidence item needs a `ref` (`path[#fragment]`) to a workspace file;
- verbatim kinds must pin `sha256`;
- a pinned `sha256` must match the file's bytes;
- a workspace root is mandatory. Without one the check fails closed with
  `workspace_required`.

A hash proves the bytes, not that they're true. See the roadmap for attestations.

## 8. Claim lifecycle (ledger)

An ACCEPT is a claim, not a completion.

| Ledger entry | Same key presented again | Verdict |
|---|---|---|
| none | — | normal validation; on ACCEPT the key is written `RESERVED` |
| `RESERVED`, younger than TTL (24h) | | `duplicate` / `idempotency_key_reserved` |
| `RESERVED`, older than TTL | | `unknown` / `unknown_outcome`: reconcile before redispatch |
| `COMPLETED`, same handoff | | `duplicate` / `duplicate_idempotency_key` |
| `COMPLETED`, different handoff | | `conflicting` / `duplicate_idempotency_key` |

The receiver runs `--complete` after the effect is real. Re-running it is a no-op.
Ledger writes happen under an exclusive file lock with an atomic rename. Never reset the
ledger between packets, because resetting it disables duplicate detection.

**Claim binding (v0.3.1).** An ACCEPT records `epoch`, `packet_sha256` (the canonical
handoff's digest) and the hash of a fresh **claim token**, and returns
`claim: {epoch, token}` to the claimant only. Completion must present the exact claimed
packet (`completion_packet_mismatch` otherwise). When a token is given, it must match
(`claim_token_invalid`). The MCP server requires it (`claim_token_required`), because
the sender holds the packet too. Entries written before v0.3.1 complete by key + id, as
before.

**Release and fencing.** Reconciling an `unknown` claim whose effect is *not* on record:
`--release` (only after the TTL unless `--force`) marks it `RELEASED`, and the next claim
gets `epoch + 1`. A released key is otherwise treated as absent. Releasing is only safe
if the old holder can no longer act, so run non-idempotent effects inside
`fenced(packet, ledger, token)`. It executes the effect under the ledger lock only while
that exact claim is still `RESERVED`, and completes it atomically on success. Model
checking showed that without fencing, release-and-redispatch lets a slow receiver
perform the effect twice (`formal/README.md`).

**Reconciliation rule.** **No negative observation grants a dispatch right.** Reconciliation may
move an ambiguous operation forward only from a fresh, authoritative observation that exactly
matches the original logical identity and complete effect. `ABSENT`, stale, mismatched or uncertain
observations leave it `unknown` and blocked. A local receipt can preserve what Synthe observed; it
does not turn an unsigned provider response into provider-signed truth. Release remains an explicit
operator action after the TTL, with the fencing rules above unchanged.

**Wait-for dependencies (v0.5).** `depends_on` lists the idempotency keys of upstream
handoffs. It is a sender fact inside the signed handoff, and the claim is bound to the
packet digest, so neither a relay nor the claimant can drop it. At commit time
(`fenced()`, `fenced_effect()` and `complete()`, all under the ledger lock), every
listed key must be `COMPLETED` in the same ledger: a key in any other state (`RESERVED`,
`RELEASED`) → `dependency_incomplete`; a key the ledger has never claimed →
`dependency_unknown`. Both are `blocked`, and neither consumes the claim; commit again
once the upstream completes. Only an effect run inside the fence (`fenced()` or the commit
broker) is actually held back; for an effect performed outside it, a refused `complete()`
only keeps the ledger from recording the handoff as done before its upstream. The claim records `depends_on`, so a packet that would close
a wait-for cycle through live claims is refused at admission (`dependency_cycle`).

**Exclusive paths (v0.5).** Every claim records its effective `scope.owned_paths`
(receiver defaults applied). When the receiver's policy sets `exclusive_paths`, a claim
whose paths may overlap those of another live (`RESERVED`) claim on the same receiver is
refused with `claim_conflict` (`blocked`) until that claim completes or is released.
Overlap is decided conservatively: two globs are treated as disjoint only when their
literal prefixes (the text before the first wildcard) or their literal suffixes (the text
after the last) rule out a common path; a glob without wildcards is matched exactly;
comparison is case-insensitive. A live claim recorded before v0.5 (no paths) counts as
overlapping.

## 9. Failure states

| State | Meaning | Who acts |
|---|---|---|
| `invalid` | malformed, unknown identity, bad signature, broken rule | sender fixes the packet; never auto-repair |
| `incomplete` | evidence or artifact missing | sender supplies it |
| `stale` | expired, or artifact/evidence bytes changed | sender refreshes |
| `conflicting` | key already completed by a *different* handoff | human resolves |
| `blocked` | authority, policy, approval or budget stops it; or (v0.5) an upstream dependency or a conflicting live claim | owner/approver; or wait for the other work, then retry |
| `duplicate` | key already claimed or completed | nobody: do not run again |
| `unknown` | claim never completed past TTL | operator reconciles |
| `retryable` | reserved for transient failures | runner retries within budget |

## 10. Reason codes

**invalid:** `missing_handoff`, `missing_field:<f>`, `bad_schema_version`,
`bad_on_failure`, `malformed:<f>`, `bad_sha256:<f>`, `planned_actions_missing`,
`unknown_agent:<from|to>`, `alias_not_canonical:<from|to>`, `signature_missing`,
`signature_malformed`, `signature_alg_unsupported`, `signature_signer_mismatch`,
`signature_key_unknown`, `signature_invalid`, `signature_unsupported`,
`bad_expires_at`, `artifact_path_escapes_workspace`, `evidence_not_verbatim`,
`verbatim_evidence_unpinned`, `evidence_path_escapes_workspace`,
`workspace_required`, `packet_unreadable`, `registry_unreadable`,
`registry_malformed`, `ledger_corrupt`, `ledger_required`,
`receiver_mismatch`,
`missing_idempotency_key`, `completion_unknown_key`, `claim_token_required`,
`release_not_reserved`, `dependency_cycle` (v0.5; `malformed:depends_on` is a `malformed:<f>`),
`duplicate_field:<f>`, `malformed:non_finite_number`, `signature_kid_required`, `ttl_exceeded` (unreleased)

**blocked:** `tool_not_allowed`, `tool_not_allowed_by_receiver`,
`forbidden_action`, `approval_missing`, `approval_expired`,
`approval_expires_invalid`, `approver_not_trusted`, `approval_unsigned`,
`approval_signature_invalid`, `authority_exceeds_receiver_policy`,
`budget_exceeded`, `dependency_incomplete`, `dependency_unknown`, `claim_conflict` (v0.5), `approval_kid_required` (unreleased)

**incomplete:** `artifact_missing`, `evidence_missing`,
`evidence_unreferenced`, `evidence_ref_missing`

**stale:** `handoff_expired`, `artifact_hash_mismatch`, `evidence_hash_mismatch`

**broker daemon (v0.5; returned as an error, or the broker refuses to start):**
`broker_not_isolated`, `client_not_allowed`, `unauthorized`, `request_malformed`,
`request_too_large`, `unknown_op`, `broker_error`, `broker_key_exposed`,
`broker_credentials_exposed`, `broker_state_writable`. **Proposal denials (v0.5):**
`source_path_not_allowed` (blocked), `bundle_too_large` (invalid). **Detached approvals (v0.5):**
`approval_malformed` (invalid), `approval_duplicate` (duplicate); a staged proposal's receipt adds
`staged` (blocked) to the codes it waits on. **Content proposals (v0.5):** `path_invalid`,
`content_malformed`, `content_too_large` (invalid), `content_base_missing` (blocked),
`content_conflict` (stale). **Reading the repo (v0.5; returned as an error, never receipted):**
`read_not_allowed` (blocked), `file_not_found`, `file_not_text`, `file_too_large` (invalid), and
`path_invalid` for a bad path or prefix. **Lane grants and delegate approvers (v0.6):**
`template_malformed`, `template_scope`, `template_unavailable`, `template_id_reused`,
`template_revocation_invalid`, `template_store_corrupt`, `registry_unreadable`, `delegate_invalid`,
`delegate_malformed`, `delegate_store_corrupt` (invalid); `template_signature_invalid`,
`template_expired`, `template_stale`, `template_revoked`, `template_exhausted`,
`delegate_signature_invalid`, `delegate_not_named`, `delegate_is_party`,
`delegate_approval_missing`, `delegate_approval_stale`, `delegate_approval_expired`,
`delegate_approval_too_long`, `delegate_escalated` (blocked). The other commit-broker codes are listed in
[`docs/COMMIT.md`](docs/COMMIT.md).

**duplicate / conflicting / unknown:** `idempotency_key_reserved`,
`duplicate_idempotency_key`, `completion_handoff_mismatch`, `completion_packet_mismatch`,
`claim_token_invalid`, `release_claim_fresh`, `unknown_outcome`

## 11. Entry points (one code path)

| Entry point | Use |
|---|---|
| `src/handoff_check.py` | CLI. Exit `0` = ACCEPT/COMPLETED, `2` = REJECT |
| `src/synthe_mcp.py` | MCP server (stdio or HTTP with a bearer token). Tools: `synthe_validate_handoff`, `synthe_complete_handoff` (requires the claim token), `synthe_receiver_policy`; with `--broker-url` every tool is forwarded to the broker daemon and `synthe_propose_effect` is added |
| `src/synthe_a2a.py` | A2A v1.0 extension: wraps a packet as a Message and maps the verdict to a TaskStatus (`SUBMITTED` / `INPUT_REQUIRED` when only an approval is missing / `REJECTED`) |
| `github-action/` | CI gate, with the ledger persisted via `actions/cache` |
| `src/synthe_commit.py` | commit broker: `serve` (the daemon, run as its own OS user or in a container), `doctor`, `init`, `receipts verify|show`, `ui`. In-process `propose`/`push` and `synthe_mcp.py --broker` are dev-only (isolation mode `none`) (section 14) |
| `src/synthe_client.py` | v0.5 agent side of the broker (no secrets): `hello`, `claim`, `push` (commits as a git bundle), `complete`, `receipts`, `doctor` |

On the MCP and A2A entry points, the operator fixes the registry, ledger and workspace on the command line, and the model supplies
only the packet.

## 12. Agent rules

- Validate before acting. On REJECT: report the state and codes to the sender, then stop.
- Never edit a packet to make it pass. Never invent approvals, hashes or evidence.
- Fill only receiver-owned fields, and only from the receiver's policy.
- Run `--complete` only after the effect has actually happened.

## 13. Non-goals (v0.3)

The checker makes no semantic judgment of deliverables, does not fetch URLs, and has no hosted service. It also does not handle
multi-hop delegation chains or key revocation yet (see [`docs/ROADMAP.md`](docs/ROADMAP.md)).

## 14. Mediated effects and receipts (v0.4)

Full detail: [`docs/COMMIT.md`](docs/COMMIT.md).

- **Planned params.** A planned action may carry `params`. For a mediated effect
  (`tool` = `git_push`), `params.remote` and `params.branch` are required: the
  sender signs the target.
- **Approval params.** An approval may carry `params`. They are included in the
  approval signature (v0.3 approvals without `params` verify unchanged). At
  admission, an approval whose params differ from the planned action's →
  `approval_params_mismatch`. An approval may also pin `commit` (not in the plan: the sender cannot know it); the broker enforces it when `require_approval_commit_pin` is set (`approval_commit_missing`). At commit, a mediated effect that needs approval
  requires an approval pinning at least the target keys → `approval_params_missing`.
- **Commit protocol.** The proposal is `{packet, claim_token, action, params, source}`.
  The broker re-runs validation now (ledger ignored; the fence checks the claim), checks
  that the plan and approval params match the proposal, then inside `fenced_effect()`
  checks live state, inspects the effect, performs it with compare-and-swap, and observes
  the result. Only a confirmed effect is recorded `EXECUTED` under
  `ledger[key].effects[action]`. The claim becomes `COMPLETED` once every mediated planned
  action has executed. A denial never consumes the claim.
- **Stored-result replay.** Every mediated proposal has a domain-separated SHA-256 fingerprint over
  the action, effect type and complete effect params (with broker defaults normalized; bundle/source
  transport excluded because the commit hash binds the proposed history). An `EXECUTED` ledger record
  stores that fingerprint and the exact signed receipt sequence. Retrying a `COMPLETED` claim with the
  same packet, claim token, action and fingerprint returns the original receipt unchanged: the effect
  adapter is not called and no second receipt is appended. A different fingerprint under the same
  identity is `conflicting` / `effect_fingerprint_mismatch`; it never executes. Replay also fails
  closed if the receipt chain does not verify or the receipt does not exactly bind the claim, epoch,
  action and fingerprint. Legacy completed entries without these fields remain duplicate and blocked;
  they are never guessed equivalent. Details and limits: [`docs/REPLAY.md`](docs/REPLAY.md).
- **Path policy.** Each path touched by any pushed commit must match the packet's
  `scope.owned_paths` (receiver defaults applied) and every policy layer's
  `allowed_paths`, and must not match `forbidden_paths` (unioned across layers).
- **Receipts.** One signed JSON line per proposal: `seq`, `prev` (SHA-256 of the
  previous receipt's canonical JSON), the handoff, claim epoch, approvals, effect,
  observations, decision and reasons. The signature domain is `synthe/effect-receipt/v1`.
  The chain verifies offline against the broker's registered key.
- **Plan anchor (v0.5).** Every ACCEPT returned by the broker, the MCP server or the Lab, and
  every receipt, carries `plan`: purpose, each planned action with its status (`executed`,
  `unconfirmed`, `pending`, `denied`, `not_mediated`), `remaining`, and the constraints
  (`owned_paths`, `forbidden`, `allowed_tools`, `approvals_needed`, `expires_at`, the state of each
  `depends_on` key). It never contains a claim token. The CLI checker's verdict is unchanged.
  Details: [`docs/COMMIT.md`](docs/COMMIT.md).
- **Isolation (v0.5).** The broker holds the signing key, the remote credentials, the registry,
  the ledger and the receipts, and runs as its own OS user (`synthe_commit.py serve --socket`,
  mode `user`, the default) or in a container (`--listen` + bearer token, mode `container`).
  On a unix socket the client's uid comes from the kernel; the broker's own user and root are
  refused (`broker_not_isolated`), and an `isolation.clients` allowlist refuses others
  (`client_not_allowed`). It refuses to start if its key or token files are readable by others or
  its state, or the socket's directory, is writable by others. Commits arrive as a git bundle
  (fsck'd, size-capped), never as a path on the agent's disk unless the operator allows it.
  Receipts record `via`, `isolation` (mode, `verified`, both uids) and `commits_from`, and no
  response or receipt carries a credential. Mode `none` (same user, or in-process) is for
  development only: it must be set explicitly, and every receipt says it. Details and the
  verified two-user test: [`docs/ISOLATION.md`](docs/ISOLATION.md).
- **Detached approvals (v0.5).** An approval may arrive apart from the packet (so the packet the
  claim is bound to never changes): the same signed object as an embedded approval
  (`action`, `approver`, `kid`, `expires_at`, optional `params`, `sig`, signed over the handoff's
  `idempotency_key`, `from` and `to`), plus those three fields in the clear so the broker can file
  it. It is verified exactly like an embedded one (registered approver key, signature, trusted
  approver, expiry, params), receipted (`kind: "approval"`, decision `approval_accepted`,
  `approval_rejected` or `approval_duplicate`) and stored append-only. An unsigned detached
  approval never counts.
- **Speculative commit (v0.5).** With `wait_for_approval: true`, a claim may be made while the
  approval of a broker-mediated planned action is still missing (recorded as
  `approvals_deferred` on the claim; a present but bad approval still rejects), and a proposal
  whose only problems are that approval, or an unfinished `depends_on` upstream, is checked now
  (claim token, every static and live check, path inspection, without pushing), pinned to the
  remote tip it saw, and stored `STAGED` (receipt decision `staged`). When it is covered (an
  approval arrives, the upstream completes, or the broker's sweep), the broker re-runs the whole
  commit protocol; anything that changed is a denial (`remote_moved`, `handoff_expired`, ...).
  A staged proposal never commits without a valid approval.
- **Content proposals (v0.5).** An agent without git proposes `params.files` (path → full UTF-8
  text), `params.delete` (paths) and `params.base_blobs` (path → the blob id the change was
  based on, or `null` for a new file; every touched path must be cited). The broker validates the
  paths itself (relative, NFC, no `.`/`..`/empty components, nothing under `.git`, no control or
  format characters, ≤ 255 bytes per component and 1024 per path, no case collisions), builds one
  commit on the branch's live tip (author `<agent> via Synthe`, trailers `Synthe-Handoff`,
  `Synthe-Key`, `Synthe-Agent`), and then runs the unchanged commit protocol on it. If the branch
  moved before the push, the commit is rebuilt on the new tip only when every cited blob is still
  current there; otherwise `content_conflict` and nothing is pushed. A staged content proposal is
  re-checked by its cited blobs rather than pinned to a tip. The receipt carries `content`
  (`files`, `deletes`, `bytes`, `digest` = SHA-256 of the canonical files/delete, `paths`), never
  the file text, and `effect.rebased_onto` when it was rebuilt. Read ops (`read_file`,
  `list_files`) serve a branch's files and blob ids from the broker's mirror, only for remotes the
  operator marks `"readable": true` (and only branches in `readable_refs`, else `branches`).
  Details: [`docs/COMMIT.md`](docs/COMMIT.md).
