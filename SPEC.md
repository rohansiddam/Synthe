# Handoff Contract v0.5

Every agent-to-agent handoff is an API boundary. The receiver validates the
handoff *before* it starts work, and the checker fails closed: anything it
cannot verify is a REJECT with a reason, never a silent pass.

- Packet wire format: `schema_version: "0.1"` (v0.3–v0.5 fields are additive).
- Ledger semantics: v0.2 claim lifecycle.
- Trust layer: v0.3 receiver policy, signatures, evidence pinning.
- Effects: v0.4 approvals that pin effect params; v0.5 detached and deferred approvals (section 5).
- Concurrency: v0.5 wait-for dependencies (`depends_on`) and exclusive paths (section 8).
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
| `planned_actions[]` | policy | `{name, tool, params?, est_tokens?, est_usd?, est_minutes?}`; v0.4: `params` are the effect's target (for example a branch or a recipient), signed by the sender |
| `depends_on[]` | no | v0.5: idempotency keys of upstream handoffs that must be `COMPLETED` (same ledger) before this handoff's effects may commit |
| `acceptance.output_schema` | yes* | what the receiver must produce |
| `acceptance.required_evidence` | yes* | evidence kinds that count as "done" |
| `acceptance.evidence[]` | no | `{kind, ref?, sha256?, verbatim?}` |
| `acceptance.expires_at` | yes* | RFC 3339 timestamp **with a timezone offset** |

`*` = can be filled from the receiver's `policy.defaults` (section 4). Fields
without a `*` are sender facts and are **never** filled for the sender.

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
| `forbidden_paths` | list | v0.4: path globs no effect may touch; unioned across policy layers. The checker merges it; whatever performs a file-changing effect enforces it on every touched path |
| `exclusive_paths` | flag | v0.5: a second live claim on this receiver whose `owned_paths` may overlap one already held → `claim_conflict` (section 8) |
| `verify_evidence` | flag | evidence pinning (section 7); also `--verify-evidence` |
| `defaults` | fill | receiver-owned fields filled when the sender left them out |

**Merging.** The top-level `policy` and `agents.<receiver>.policy` merge as follows:
restrictions union, ceilings intersect, budgets take the minimum per
dimension, flags OR together, and later `defaults` override earlier ones.

**Defaults** can fill `owned_paths`, `forbidden`, `allowed_tools`,
`approval_required_for`, `output_schema`, `required_evidence`, `expires_at`,
`budget.{tokens,usd,minutes}` and `on_failure`. Every fill is reported in the
verdict as `defaults_applied`. Defaults are applied to a copy, so the signed
bytes never change.

## 5. Signatures

- Algorithm: Ed25519 (RFC 8032). The checker uses `cryptography` when it is installed; otherwise it falls back to a
  pure-Python implementation, which verifies fine, but its signing is not constant-time, so don't use it for production keys.
- Canonical JSON: sorted keys, compact separators, UTF-8, whole-number floats
  written as ints.
- **Packet signature** signs `"synthe/handoff-signature/v1\n" + canonical(handoff)`.
  `signer` must equal `handoff.from`, and the key must be in `agents.<from>.keys`.
- **Approval signature** signs `"synthe/approval-signature/v1\n" + canonical({action, approver, expires_at, idempotency_key, from, to})`.
  That binds an approval to exactly one handoff, so it can't be replayed onto another.
  v0.4: an approval may carry `params`; they are added to the signed object, so v0.3 approvals
  without `params` verify unchanged. An approval whose params differ from the planned action's →
  `approval_params_mismatch` (the sender cannot retarget an approved action). An approval without
  `params` covers the action as in v0.3.
- **Detached approvals (v0.5).** The same signed approval may arrive apart from the packet, so the
  packet a claim is bound to never changes. It carries `idempotency_key`, `from` and `to` in the
  clear and is checked exactly like an embedded one (`check(..., extra_approvals=[...])`). An
  unsigned detached approval never counts.
- **Deferred approvals (v0.5).** A caller that will check an approval itself at commit time may
  name the action in `defer_approvals`: a *missing* approval is then recorded in the verdict's
  `approvals_deferred` instead of rejecting; a present but bad approval still rejects. Off by
  default, so default verdicts are unchanged.
- **Receipt signature (v0.4)** signs `"synthe/effect-receipt/v1\n" + canonical(receipt without sig)`,
  domain-separated from packets and approvals.
- Order: approvers sign first, then the sender signs. The sender's signature
  covers the approvals list.

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

A hash proves the bytes, not that they're true.

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
(`claim_token_invalid`). Shared entry points should require it (`require_token=True`, which
returns `claim_token_required` without one), because the sender holds the packet too. Entries written before v0.3.1 complete by key + id, as
before.

**Release and fencing.** Reconciling an `unknown` claim whose effect is *not* on record:
`--release` (only after the TTL unless `--force`) marks it `RELEASED`, and the next claim
gets `epoch + 1`. A released key is otherwise treated as absent. Releasing is only safe
if the old holder can no longer act, so run non-idempotent effects inside
`fenced(packet, ledger, token)`. It executes the effect under the ledger lock only while
that exact claim is still `RESERVED`, and completes it atomically on success. Without
fencing, release-and-redispatch lets a slow receiver perform the effect twice.
`fenced_effect(packet, ledger, token, action)` (v0.4) does the same for one named effect of a
multi-effect handoff and records it under `ledger[key].effects[action]`. An effect already
recorded `EXECUTED` is refused with `effect_already_executed`; one that started but whose outcome
was never confirmed is refused with `effect_outcome_unknown` until an operator reconciles it.

**Wait-for dependencies (v0.5).** `depends_on` lists the idempotency keys of upstream
handoffs. It is a sender fact inside the signed handoff, and the claim is bound to the
packet digest, so neither a relay nor the claimant can drop it. At commit time
(`fenced()`, `fenced_effect()` and `complete()`, all under the ledger lock), every
listed key must be `COMPLETED` in the same ledger: a key in any other state (`RESERVED`,
`RELEASED`) → `dependency_incomplete`; a key the ledger has never claimed →
`dependency_unknown`. Both are `blocked`, and neither consumes the claim; commit again
once the upstream completes. Only an effect run inside the fence is actually held back; for
an effect performed outside it, a refused `complete()` only keeps the ledger from recording
the handoff as done before its upstream. The claim records `depends_on`, so a packet that
would close a wait-for cycle through live claims is refused at admission (`dependency_cycle`).

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
| `blocked` | authority, policy, approval or budget stops it; or (v0.5) an upstream dependency or a conflicting live claim | owner/approver; or wait for the other work |
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
`missing_idempotency_key`, `completion_unknown_key`, `claim_token_required`,
`release_not_reserved`, `dependency_cycle` (v0.5; `malformed:depends_on` is a `malformed:<f>`)

**blocked:** `tool_not_allowed`, `tool_not_allowed_by_receiver`,
`forbidden_action`, `approval_missing`, `approval_expired`,
`approval_expires_invalid`, `approver_not_trusted`, `approval_unsigned`,
`approval_signature_invalid`, `authority_exceeds_receiver_policy`,
`budget_exceeded`, `approval_params_mismatch` (v0.4), `dependency_incomplete`,
`dependency_unknown`, `claim_conflict` (v0.5)

**incomplete:** `artifact_missing`, `evidence_missing`,
`evidence_unreferenced`, `evidence_ref_missing`

**stale:** `handoff_expired`, `artifact_hash_mismatch`, `evidence_hash_mismatch`

**duplicate / conflicting / unknown:** `idempotency_key_reserved`,
`duplicate_idempotency_key`, `completion_handoff_mismatch`, `completion_packet_mismatch`,
`claim_token_invalid`, `release_claim_fresh`, `unknown_outcome`, `effect_already_executed` (v0.4,
duplicate), `effect_outcome_unknown` (v0.4, unknown)

## 11. Entry points (one code path)

| Entry point | Use |
|---|---|
| `src/handoff_check.py` | CLI. Exit `0` = ACCEPT/COMPLETED, `2` = REJECT |
| `github-action/` | CI gate, with the ledger persisted via `actions/cache` |

The operator fixes the registry, ledger and workspace; the agent supplies only the packet.

## 12. Agent rules

- Validate before acting. On REJECT: report the state and codes to the sender, then stop.
- Never edit a packet to make it pass. Never invent approvals, hashes or evidence.
- Fill only receiver-owned fields, and only from the receiver's policy.
- Run `--complete` only after the effect has actually happened.

## 13. Non-goals (v0.5)

The checker makes no semantic judgment of deliverables, does not fetch URLs, and has no hosted service. It also does not handle
multi-hop delegation chains or key revocation yet.
