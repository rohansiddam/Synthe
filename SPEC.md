# Handoff Contract v0.7

Setup adapters do not change this contract: [agent-neutral setup](docs/ANY_AGENT.md) and the Claude
Code hook still require the broker's existing authority checks. [Standalone verification](docs/VERIFY.md)
authenticates local receipt bytes and chain continuity, not provider-signed truth or dispatch authority.

Every agent-to-agent handoff is an API boundary. The receiver validates the
handoff *before* it starts work, and the checker fails closed: anything it
cannot verify is a REJECT with a reason, never a silent pass.

- Packet wire format: `schema_version: "0.1"` (v0.3–v0.5 fields are additive).
- Ledger semantics: v0.2 claim lifecycle.
- Trust layer: v0.3 receiver policy, signatures, evidence pinning.
- Commit broker: v0.4 mediated effects and receipts (section 14).
- Concurrency: v0.5 wait-for dependencies (`depends_on`) and exclusive paths (section 8).
- Isolation: v0.5 the broker runs as its own OS user or in a container; agents use its socket (section 14).
- Capabilities and topologies: v0.6 (section 15). Lane grants and delegate approvers: v0.6 ([`docs/COMMIT.md`](docs/COMMIT.md)).
- Self-issued tasks: v0.7 the broker issues a task inside a lane a human signed, under its own signing
  domain; receivers can name who may send them work (`trusted_senders`) (section 16).
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
| `inputs.state_revision` | no | informational only: the state the receiver works from, as the sender saw it when the packet was built. The checker does **not** compare it against anything — it carries no trust semantics and must not be treated as a guarantee of receiver-side state |
| `scope.owned_paths` | yes* | what the receiver may touch (may be empty) |
| `scope.forbidden` | yes* | actions the receiver must not take (may be empty) |
| `authority.allowed_tools` | yes* | tools the receiver may call |
| `authority.budget` | yes* | numeric `tokens`, `usd`, `minutes` |
| `authority.approval_required_for` | yes* | actions/tools that need an approval first (may be empty) |
| `authority.approvals[]` | no | `{action, approver, expires_at?, kid?, sig?, budget?, estimates?}` |
| `planned_actions[]` | policy | `{name, tool, params?, est_tokens?, est_usd?, est_minutes?}` |
| `sender_role` / `receiver_role` | no | v0.6: team role labels for this handoff's edge; verified against the receiver's team topology (section 15) |
| `capability` | policy | v0.6: signed capability declaration — `version` (required), `env[]` (env vars it may read), `paths[]` (file globs it may touch), `tools[]` (tools/APIs it may call), `network` (egress, denied by default), `admission_receipt?` (cross-reference to a skill-admission receipt). The packet signature covers it, so any change (including a version change) requires re-declaration and re-signing |
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

**Planned-action intent (v0.6).** A planned action's `params` may declare what
the action will touch, so the gate can check it against the capability
declaration (section 15) *before* anything executes: `params.env` (env var
names read), `params.paths` (file paths touched), `params.network: true`
(needs egress). Declaring intent is optional; staying inside the declaration
is not. This check is a tripwire, not a guarantee — the intent params are
volunteered by the sender; real enforcement is the runtime hook in 15.1.

Evidence kinds `code_text`, `verbatim_quote` and `legal_text` must carry
`verbatim: true`. Under evidence verification they must also pin `sha256`.

**Note on `inputs.state_revision`.** This field was required in early drafts but
compared against nothing — a required field that means nothing trains everyone
to ignore required fields, so it was demoted to optional and informational. A
sound meaning would need the checker to compare it against an authoritative
record of the receiver's workspace state; the checker is a pure function of
(packet, registry, policy, ledger) and has no such record, and anything the
receiver could supply about its own state is not checkable truth. Ordering
across handoffs is handled by `depends_on` (idempotency keys that must be
`COMPLETED` before this handoff's effects may commit). Senders MAY still set
`state_revision` as a human-readable debugging hint (e.g. a timestamp or branch
stamp); the checker ignores it.

## 3. The registry

One JSON file, fixed by the operator. It decides who exists, which keys they
sign with, and what each receiver will accept.

**Signed registry (optional).** The registry may carry a top-level `signature`
block: an Ed25519 operator signature over the rest of the file plus a rotation
chain back to a genesis key (`synthe-sign sign-registry`,
`synthe-sign rotate-registry-key`). It is enforced only when a genesis key is
pinned (`--registry-genesis-key`, `SYNTHE_REGISTRY_GENESIS_KEY`, or a
`registry-genesis.key` file next to the checker). With a pin, an unsigned,
tampered or differently-rooted registry fails with `registry_signature_invalid`
in every caller. Without one, the registry loads unverified (the CLI warns;
`--require-signed-registry` rejects instead).

```json
{
  "policy": { ... },                      // optional: applies to every receiver
  "topologies": {                         // v0.6: named team topologies (section 15)
    "ship-team": {
      "version": "2026-10-12.1",
      "roles": ["ceo", "designer", "em", "qa", "release"],
      "edges": [["ceo", "designer"], ["designer", "em"], ["em", "qa"],
                ["qa", "release"], ["qa", "em"]],
      "role_capabilities": {
        "qa": { "tools": ["run_tests", "read_repo"], "paths": ["tests/**"],
                "env": [], "network": false }
      },
      "signed_by": "rohan", "kid": "rohan-1", "sig": "<base64url>"
    }
  },
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
| `trusted_senders` | ceiling (v0.7) | who may sign a task for this receiver: a packet whose `from` is not listed → `sender_not_trusted`. Absent: any registered sender whose key verifies, as before v0.7. A self-issued packet (section 16) is from the broker's task issuer and is admitted by the human-signed grant it embeds, not by this list. Setup writes `[<the human approver>]` |
| `forbidden` | restriction | added to the packet's `scope.forbidden` |
| `approval_required_for` | restriction | added to the packet's list, so a sender cannot drop it |
| `budget` | ceiling | packet budget above it → `authority_exceeds_receiver_policy`; estimates are checked against the lower of the two |
| `require_signatures` | flag | unsigned packets → `signature_missing` |
| `require_signed_approvals` | flag | unsigned approvals → `approval_unsigned` |
| `require_planned_actions` | flag | no planned actions → `planned_actions_missing` |
| `verify_evidence` | flag | evidence pinning (section 7); also `--verify-evidence` |
| `exclusive_paths` | flag | v0.5: a second live claim on this receiver whose `owned_paths` may overlap one already held → `claim_conflict` (section 8) |
| `capability` | ceiling (v0.6) | the most a sender's capability declaration may claim: `env`/`tools` must be subsets, each declared path must be covered by a ceiling path, `network: true` needs the ceiling to allow it, and a `version` pin must match. A declaration outside it → `capability_exceeds_receiver_policy` (section 15) |
| `require_capability_declaration` | flag (v0.6) | packet without a `capability` object → `capability_declaration_missing` |
| `topology` | naming (v0.6) | the team topology (registry `topologies` key) this receiver enforces edges against; later policy layers override |
| `require_topology` | flag (v0.6) | packet without `sender_role` and `receiver_role` → `topology_declaration_missing` |
| `max_ttl_hours` | ceiling | unreleased: a handoff whose `acceptance.expires_at` is more than this many hours after the check → `ttl_exceeded`. A long-lived handoff is a bearer token for whoever holds its bytes. Must be a positive number, or the check refuses with `registry_malformed` |
| `defaults` | fill | receiver-owned fields filled when the sender left them out |

**Merging.** The top-level `policy` and `agents.<receiver>.policy` merge as follows:
restrictions union, ceilings intersect, budgets and `max_ttl_hours` take the minimum,
flags OR together, and later `defaults` override earlier ones. A `capability`
ceiling merges by narrowing: `env`/`tools` intersect, `network` ANDs, `paths`
keep only the later layer's paths covered by an earlier path, and a `version`
pin follows the later layer. The `topology` name follows the later layer.

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
- **Self-issued packet signature (v0.7)** signs `"synthe/handoff-signature/self-issued/v1\n" + canonical(handoff)`.
  The checker picks the domain from the **signed** handoff: one that holds `issued_under_grant` is
  self-issued, anything else is ordinary. Removing the field from an issued packet, or adding it to an
  ordinary one, breaks the signature, and a checker from before v0.7 rejects every self-issued packet
  with `signature_invalid` (it fails closed). `schema_version` stays `"0.1"`.
- **Lane grant signature** (the grant a self-issued packet embeds) signs
  `"synthe/approval-template/v1\n" + canonical(grant without sig)` with the human approver's key
  (Ed25519 or ES256, as for approvals).
- **Approval signature** signs `"synthe/approval-signature/v2\n" + canonical({action, approver, expires_at, idempotency_key, from, to, budget, estimates})`.
  That binds an approval to exactly one handoff, so it can't be replayed onto another.
- **Approvals bind the budget.** The approval pins the `budget` (`tokens`, `usd`,
  `minutes`) and the approved action's cost estimates (`est_tokens`, `est_usd`,
  `est_minutes`) the approver reviewed, as signed ceilings: afterwards the packet's
  budget and the action's estimates may only come down, never up. A packet budget
  above the approved budget is `approval_budget_exceeded`; estimates above the
  approved estimates are `approval_estimates_exceeded`. Only the receiver-policy
  ceiling used to limit magnitude; now the approver's cap binds too. Upgrading from v1
  approvals: [`docs/APPROVALS_V2.md`](docs/APPROVALS_V2.md).
- **The pin is the effective budget, and it is mandatory.** Per dimension the pin
  takes the approver's explicit budget first, then the packet's explicit
  `authority.budget`, then the receiver policy's `defaults.budget` -- the same
  merge the checker applies, so the pin is exactly the budget the checker will
  compare against. Signing is refused unless a complete (`tokens`/`usd`/`minutes`)
  budget can be bound: the approver names one (`synthe-sign approve --budget
  '{...}'`) or supplies the receiver policy. An approval with no budget pin caps
  nothing, so it authorizes nothing: a v2 approval carrying no pin is rejected
  outright as `approval_budget_missing`, never treated as unlimited.
- **Retired v1 approvals fail closed.** Approvals signed under
  `synthe/approval-signature/v1` (before the budget binding) are rejected with
  `approval_version_unsupported`: they are never re-verified under the new
  semantics, and they never pass as a confusing `approval_signature_invalid`.
  Have the approver re-approve.
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
   non-negative numbers, and `planned_actions` if the policy requires them. v0.6:
   capability declaration shape (`malformed:capability*`), role shapes
   (`malformed:sender_role` / `malformed:receiver_role`), and the required
   declarations (`capability_declaration_missing`, `topology_declaration_missing`)
   when the receiver's policy demands them. *If this step fails,
   checking stops here.*
2. **Identity.** `from`/`to` exist in the registry and are canonical, and the packet signature verifies
   (in the domain the signed handoff selects, section 5). v0.7: `from` must be in the receiver's
   `trusted_senders` when it has one (`sender_not_trusted`); a sender of kind `task_issuer` must carry
   `issued_under_grant` (`issuer_requires_grant`), and a packet that carries it must come from a
   `task_issuer` (`issuer_invalid`). Step 1 also checks the shape of `issued_under_grant`
   (`malformed:issued_under_grant`) and that a self-issued purpose is one line of NFC text with no control
   or format characters, within the grant's limit (`self_issue_purpose_invalid`).
   **2b. Issuance (v0.7).** A self-issued handoff stays inside the grant it embeds: the grant verifies
   under a key of a human in the receiver's `trusted_approvers` (`self_issue_grant_invalid`); it names
   this receiver and this issuer in `self_issue` (`self_issue_not_granted`); the packet carries no
   approval (`self_issued_approval_present`); it plans exactly one `git_push`, to the grant's remote, on
   a branch its `branch_pattern` matches, with `owned_paths` covered by its `path_scope`, tools within
   `self_issue.tools`, and no `capability` or team roles (`self_issue_scope`); and it expires no later than
   the grant nor `task_hours` after `issued_at` (`self_issue_ttl`). Revocation, use counts and the issue
   record are broker state, checked by the broker (section 16).
3. **Duplication and conflicts.** The idempotency key is looked up in the ledger (section 8). A
   `depends_on` list that closes a wait-for cycle through live claims is `dependency_cycle`; under
   `exclusive_paths`, `owned_paths` that may overlap another live claim on the receiver are
   `claim_conflict`. Unmet dependencies do **not** fail admission: the receiver may claim and work
   ahead, and the commit waits (section 8).
4. **Freshness.** `acceptance.expires_at` must be parseable, offset-aware and in the future.
5. **Authority.** Planned actions are checked against tools, forbidden actions, approvals and budgets, with the
   receiver policy as a ceiling. v0.6: the team-topology edge is checked first
   (`topology_violation`), then the capability declaration against the policy
   ceiling (`capability_exceeds_receiver_policy`), then each planned action's
   declared intent against the narrowed capability (`capability_not_declared`).
   A malformed policy capability or a policy that requires topologies without
   naming one is `registry_malformed`.
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
the sender holds the packet too.

**No backward-compat downgrade (v0.3.1+).** Entries written before claim tokens
existed carry no `claim_token_sha256`, so there is no token a completion could be
bound to. A still-`RESERVED` legacy entry therefore cannot be completed at all:
every completion path (`complete()`, `fenced()`, `fenced_effect()`, the commit
broker) refuses it as `invalid` / `legacy_claim_unbound`, with an operator notice
to release the claim (`--release`) and re-claim it, which issues a real claim
token. Already-`COMPLETED` legacy entries keep their no-op replay semantics.
Token-bound entries are a separate case: the CLI (`--complete` without
`--claim-token`) and `complete()` called without a token still complete by
key + packet digest, as above. Only the MCP server and the commit broker require
the token.

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

**Integrity binding (v0.6): sealed chain + out-of-cache anchor.** Every ledger write
seals a chain header under the reserved top-level key `"~synthe"` -- the ONE reserved
namespace for chain metadata (idempotency keys may not start with `~`;
`reserved_idempotency_key`). The header carries a monotonic `chain_seq` and a `chain_head`
that hash-chains the previous head and the full entry set:

`head_n = MAC("synthe-ledger-chain/v2" || seq_n || head_{n-1} || canonical(entries_n))`

MAC is HMAC-SHA256 keyed by the `SYNTHE_LEDGER_HMAC_KEY` environment variable when set
(a CI secret is the intended home), else plain SHA-256. Without the key the seal detects
accidental corruption (bit-rot, hand edits, truncation) but NOT forgery by a file-holder;
the header records `chain_keyed`, and a keyed seal loaded without the key (or vice versa)
fails closed as `ledger_corrupt`. Key rotation: `SYNTHE_LEDGER_HMAC_KEY_PREVIOUS` is
accepted for verification; sealing always uses the current key.

Rollback -- a stale cache restoring an older snapshot, a forged empty ledger, a deleted
file -- is caught by the monotonic `chain_seq` checked against an anchor stored OUTSIDE
the cache: the `SYNTHE_LEDGER_ANCHOR` environment variable (`"seq:head"`), which the
GitHub Action populates from the `SYNTHE_LEDGER_ANCHOR` repository variable before each
run and republishes after it. A loaded ledger must match or extend the anchor:
older (`ledger_rollback`), same-seq-different-head (`ledger_diverged`), or missing file
(`ledger_rollback`) all fail closed. When anchoring is required
(`SYNTHE_LEDGER_ANCHOR_REQUIRED=1`, set by the Action whenever it fetched an anchor)
but the anchor is unavailable, the checker fails closed as `ledger_anchor_unavailable`.
With no anchor configured (local runs, first run), the seal is still verified and a
legacy unsealed ledger is adopted in place as a new genesis chain -- entries preserved,
no manual migration step -- with a warning that rollback is not provable in that mode.
`SYNTHE_LEDGER_BOOTSTRAP=1` skips anchor enforcement for one run (the documented
recovery after a total cache eviction). The one legal operator (re-)initialization is
`handoff_check.py --init-ledger PATH` (missing -> sealed genesis; sealed -> no-op;
legacy -> adopted; corrupt or anchor-forbidden -> refused, never overwritten).

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
`registry_malformed`, `registry_signature_invalid`, `ledger_corrupt`, `ledger_required`,
`receiver_mismatch`,
`missing_idempotency_key`, `completion_unknown_key`, `claim_token_required`,
`legacy_claim_unbound`,
`release_not_reserved`, `dependency_cycle` (v0.5; `malformed:depends_on` is a `malformed:<f>`),
`duplicate_field:<f>`, `malformed:non_finite_number`, `signature_kid_required`, `ttl_exceeded` (unreleased),
`reserved_idempotency_key`, `ledger_rollback`, `ledger_diverged`,
`ledger_anchor_unavailable` (v0.6 integrity binding; `ledger_corrupt` also covers seal mismatches)

**blocked:** `tool_not_allowed`, `tool_not_allowed_by_receiver`,
`forbidden_action`, `approval_missing`, `approval_expired`,
`approval_expires_invalid`, `approver_not_trusted`, `approval_unsigned`,
`approval_signature_invalid`, `authority_exceeds_receiver_policy`,
`budget_exceeded`, `dependency_incomplete`, `dependency_unknown`, `claim_conflict` (v0.5), `approval_kid_required` (unreleased),
`capability_not_declared` (v0.6), `capability_exceeds_receiver_policy` (v0.6), `topology_violation` (v0.6),
`capability_path_unsafe` (v0.6.1), `topology_role_unbound` (v0.6.1),
`approval_version_unsupported` (v2), `approval_budget_missing` (v2),
`approval_budget_exceeded` (v2), `approval_estimates_exceeded` (v2)

**invalid (v0.6 additions):** `capability_declaration_missing`, `topology_declaration_missing`,
`topology_malformed`, `topology_signature_missing`, `topology_signature_invalid`,
`topology_signer_not_founder`; `malformed:capability*`, `malformed:sender_role`, `malformed:receiver_role`
are `malformed:<f>` codes.

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

**Self-issued tasks (v0.7):** `malformed:issued_under_grant`, `issuer_requires_grant`, `issuer_invalid`,
`self_issue_purpose_invalid`, `self_issued_approval_present`, `self_issue_unknown`, `self_issue_unreviewed`
(invalid); `sender_not_trusted`, `self_issue_grant_invalid`, `self_issue_not_granted`, `self_issue_scope`,
`self_issue_ttl`, `self_issue_exhausted`, `self_issue_open_limit`, `self_issue_rate_limited` (blocked);
`self_issue_request_conflict` (conflicting). The broker doctor warns `sender_ceiling_missing` for a receiver
with no `trusted_senders` while more than one key is registered.

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
| `src/synthe_client.py` | v0.5 agent side of the broker (no secrets): `hello`, `claim`, `push` (commits as a git bundle), `complete`, `receipts`, `doctor`; v0.7 `start` (issue and claim a task inside a lane that allows self-issue) |
| `src/synthe_git_remote.py` | `git-remote-synthe`: a plain `git push` becomes a proposal; v0.7 issues a task when no human-signed one exists for the branch (section 16) |

With a broker, the MCP server also offers `synthe_start_task` (v0.7, section 16).

On the MCP and A2A entry points, the operator fixes the registry, ledger and workspace on the command line, and the model supplies
only the packet.

## 12. Agent rules

- Validate before acting. On REJECT: report the state and codes to the sender, then stop.
- Never edit a packet to make it pass. Never invent approvals, hashes or evidence.
- Fill only receiver-owned fields, and only from the receiver's policy.
- Run `--complete` only after the effect has actually happened.

## 13. Non-goals (v0.3)

The checker makes no semantic judgment of deliverables, does not fetch URLs, and has no hosted service. It also does not handle
multi-hop delegation chains yet. Key revocation is built: see [`docs/KEY_REVOCATION.md`](docs/KEY_REVOCATION.md).

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

## 15. Declared capabilities and role-scoped topologies (v0.6)

The gate checks the envelope; these two features shrink what an injected or
compromised agent can reach. Both are optional unless a receiver's policy
requires them, so old packets and old registries keep working.

### 15.1 Capability declarations

A sender (or an admitted skill acting through it) may carry a signed
capability declaration in `handoff.capability`: the env vars it may read
(`env`), the file paths it may touch (`paths`, globs), the tools/APIs it may
call (`tools`), and whether it may reach the network (`network`, denied by
default). `version` is required and identifies the declaration; an optional
`admission_receipt` cross-references the skill-admission receipt (Feature A).
The declaration is part of the signed handoff, so changing anything —
including the version — requires re-declaration and re-signing by the sender.

**Path safety.** Every path is normalized before matching — declared paths,
ceiling paths, planned-action paths, and runtime paths alike. Absolute paths,
backslashes, and `..` segments are rejected outright (fail closed), so no
traversal can escape its declared root: a declared path that does not
normalize to a safe relative path makes the declaration malformed
(`malformed:capability.paths`, invalid for packets), and a runtime or
planned-action path that does not normalize is rejected with
`capability_path_unsafe` (blocked), not merely "not declared".

**Enforcement.** The checker rejects anything outside the declaration with
`capability_not_declared` (blocked) *before* the action executes:

- a planned action whose `tool` is not in `tools`;
- `params.env` naming an env var not in `env`;
- `params.paths` touching a path no declared glob matches;
- `params.network: true` when `network` is not declared true (network egress
  is denied by default).

This planned-action check is a **tripwire, not a guarantee**: the intent
params (`params.env` / `params.paths` / `params.network`) are volunteered by
the sender, and a malicious sender can volunteer nothing while doing
something else. The real enforcement point is the runtime hook below, called
by the least-privilege proxy that actually performs the reads, writes, and
calls — the admission-time check exists to catch mistakes and honest
declarations early, not to contain an adversary.

A declaration is exhaustive: a dimension it omits allows nothing. The
receiver's policy `capability` ceiling narrows it like every other ceiling —
`env`/`tools` must be subsets, each declared path must be covered by a ceiling
path, `network: true` needs the ceiling to allow it, a `version` pin must
match — else `capability_exceeds_receiver_policy` (blocked). The receiver
role's capability (15.2) narrows it the same way. With
`require_capability_declaration`, a packet without one is
`capability_declaration_missing` (invalid).

**Runtime hook.** `handoff_check.check_capability_use(declaration, kind, value)`
is the same rule for a least-privilege runtime proxy: `kind` is `env`,
`path`, `tool` or `network`, and it returns `None` when the access is inside
the declaration or a `capability_not_declared` reason dict otherwise — except
an unsafe path shape (absolute, backslash, or `..`), which returns
`capability_path_unsafe`. With no declaration in force it denies everything.

### 15.2 Role-scoped handoff topologies

Teams declare a topology in the registry (`topologies.<name>`): named `roles`,
directed `edges` (`[from_role, to_role]` pairs; list both directions
explicitly), per-role `role_capabilities` shaped like a capability declaration
(no `version`; the topology carries that), and `members` — the agent-to-role
binding, `{role: [agent ids]}`, that makes role claims checkable. Packets gain
`sender_role` / `receiver_role`. The gate rejects a handoff whose edge is not
declared with `topology_violation` (blocked). Each role's tools are enforced
exactly like 15.1: a role invoking a tool outside its role declaration is
`capability_not_declared`.

Roles would otherwise be sender-asserted labels: nothing stops a sender from
claiming whichever role has the edge they want. So the gate also checks the
packet's `from` against `members[sender_role]` and its `to` against
`members[receiver_role]` — `from` is already signature-bound (the signer must
equal `from`), so this pins the *role claim* to the *signing agent*. A claim
by an agent not bound to that role is `topology_role_unbound` (blocked), and a
topology with no binding for a claimed role fails closed the same way: an
unverifiable role claim is rejected, never silently passed. `members` is
optional in the topology shape, but any role claim against a topology that
does not bind that role is rejected.

Topology declarations are signed and versioned: `signed_by` must be a
registered human founder (`topology_signer_not_founder` otherwise), the
Ed25519 signature covers the name, version, roles, edges, role capabilities
and members under the domain `synthe/topology-signature/v1`, and the checker
re-verifies it on every check — changing the topology (including the member
binding) without re-signing is `topology_signature_invalid`, a missing
signature is `topology_signature_missing`, a broken shape (including a
malformed `members` map) is `topology_malformed` (all invalid). A packet that
declares roles while the receiver's policy names no topology fails closed with
`topology_violation`: an unverifiable routing claim is rejected, never
silently passed. With `require_topology`, a packet without both roles is
`topology_declaration_missing` (invalid); a policy that sets the flag without
naming a topology, or names one the registry does not define, is
`registry_malformed`.

Synthe does not assign roles or manage the team. It only enforces the
declared topology. An ACCEPT verdict carries the topology name that admitted
the edge.

Topology declarations are signed and versioned: `signed_by` must be a
registered human founder (`topology_signer_not_founder` otherwise), the
Ed25519 signature covers the name, version, roles, edges and role
capabilities under the domain `synthe/topology-signature/v1`, and the checker
re-verifies it on every check — changing the topology without re-signing is
`topology_signature_invalid`, a missing signature is
`topology_signature_missing`, a broken shape is `topology_malformed`
(all invalid). A packet that declares roles while the receiver's policy names
no topology fails closed with `topology_violation`: an unverifiable routing
claim is rejected, never silently passed. With `require_topology`, a packet
without both roles is `topology_declaration_missing` (invalid); a policy that
sets the flag without naming a topology, or names one the registry does not
define, is `registry_malformed`.

Synthe does not assign roles or manage the team. It only enforces the
declared topology. An ACCEPT verdict carries the topology name that admitted
the edge.

## 16. Self-issued tasks (v0.7)

Inside a lane a human signed, the agent can start work without the human signing each task. The broker
issues the task, checks it against the grant at every step, counts it against any limits the human set,
labels it everywhere as written by the agent, and receipts it. Design and threat analysis:
[`docs/design/SELF_ISSUED_TASKS.md`](docs/design/SELF_ISSUED_TASKS.md).

**What it proves, said plainly.** A human signed a lane that lets this agent start tasks on these branches
and paths (until a time, for a number of tasks, if the human set those). The broker checked the lane was
live, and within any limits, when it issued the task. The agent wrote the purpose. It does **not** prove the
human wanted this particular piece of work: the human consented to a class of work, bounded by the lane.

**The grant.** A lane grant (`docs/COMMIT.md`) may carry `self_issue`, signed with the rest of it:

| Field | Rule |
|---|---|
| `issuer` | required: the broker's task issuer (`lane_templates.self_issue.issuer` in broker.json), registered with kind `task_issuer` and a key; never the receiver, the delegate or a trusted approver (`issuer_invalid`) |
| `max_tasks`, `max_open`, `max_per_hour` | optional limits (lifetime tasks; tasks neither completed nor expired; a rolling hour), enforced only when present. Absent: no limit |
| `task_hours` | optional: how long each task lives. Absent: the grant's expiry, or 30 days for a grant without one. The receiver's `max_ttl_hours` (72 by default in setup) always caps it; the push helper simply issues a fresh task when one expires |
| `tools` | optional: ⊆ the receiver's `allowed_tools`, must include `git_push`. Absent: `edit_files`, `git_push` |
| `max_purpose_chars` | optional, 1–1000 (default 280) |
| `escalate_at` | optional: `"review"` also sends review-tier pushes of self-issued tasks to the human (default `"high"`) |

In v0.7 a self-issue grant must keep a human in front of high-risk pushes: it lists `auto_approve`
without `"high"`, or names a `delegate`; otherwise it is refused with `self_issue_unreviewed`. The default
lane (`["routine", "review"]`) qualifies. The issuer key is created at setup next to the broker key, owned
by the broker's OS user, never the agent's.

**Issuing (`issue_task`).** The agent asks the broker (peer uid from the kernel; tasks always go to the
broker's own receiver) with `{request_id, branch, purpose, owned_paths?, depends_on?, template_id?, remote?}`.
A malformed request is a daemon error, not receipted. Under the lane lock the broker: replays a known
`request_id` with the same body (the same packet and the same receipt; nothing spent), refuses one with a
different body (`self_issue_request_conflict`); finds a live grant with `self_issue` covering the branch,
remote and paths (`self_issue_not_granted`, `self_issue_scope`); checks the purpose and the limits
(`self_issue_purpose_invalid`, `self_issue_exhausted`, `self_issue_open_limit`, `self_issue_rate_limited`);
then builds the packet from the grant and the receiver's policy (only `purpose`, `branch`, `owned_paths`,
`depends_on` and `request_id` come from the agent), checks it with the checker itself, records the issue,
writes the task file (`tasks/si-<sha256(template_id)[:8]>-<n>.md`, a fixed header saying who wrote what, the
agent's purpose fenced as data) and signs a receipt. The packet is from the issuer to the receiver, with
`idempotency_key` `si:<template_id>:<n>`, no approvals, `approval_required_for: ["git_push"]`, and
`issued_under_grant: {grant (verbatim), issue, issued_at, request_id}`. Issue numbers are never refunded.
With `claim: true` the broker then runs the ordinary claim; issuing and claiming stay separate steps, and
the claim stays the one admission path.

**At the broker.** At claim, at propose, for staged proposals and again under the lane lock immediately
before dispatch, a self-issued task must have its grant in the broker's store, byte-equal to the embedded
one, valid (signature, expiry, lineage) and not revoked (`template_unavailable`, `template_expired`,
`template_stale`, `template_revoked`), and the broker must have issued exactly this packet
(`self_issue_unknown`). The checker runs first, so an edited or forged packet is refused for what it is.
**Revoking or expiring the grant kills every task issued under it that has not landed, even under a human's
approval:** the human can sign an ordinary task instead. A self-issued push goes through the grant it was
issued under and no other; a human may still approve it (a high-risk push escalates as usual), and that
approval spends no use. A self-issued task's paths sit inside its grant's, so a push outside the lane is
refused (`path_outside_scope`) rather than escalated.

**Receipts.** Every issue decision is a receipt of kind `task_issue` (`task_issued` or `task_issue_refused`)
with the grant, the task (handoff id, key, packet digest, branch, paths, expiry, `purpose_sha256`,
`purpose_author`), `requested_by` and the agent's purpose under `agent_says`. Every later receipt for the
handoff (effects, staged, approvals, delegate decisions) carries `task_origin`, derived from the signed
packet and the registry, never from text: `{"kind": "self_issued", "template_id", "issue", "granted_by",
"issuer", "author", "issue_receipt_seq"}` or `{"kind": "signed", "sender", "sender_kind"}`. The plan anchor
adds `purpose_author`, `task_origin` and, for a self-issued task, the grant's signed `brief`.

**What people see.** The approval card heads the task by origin ("Task written by the agent (self-issued
under lane …, signed by …)", with the human's own brief beneath), the reviewer's detail labels a self-issued
task as written by the agent that wrote the diff, and `synthe-notify digest` lists the tasks the agent
started and which of them shipped.

**`git push`.** `git-remote-synthe` uses, in order: an explicit task, the newest unexpired human-signed task
in the inbox, the open self-issued task this clone holds for the branch, and only then a new issue (the
request id is saved before asking, so a retry never issues twice). The purpose is `-o synthe.purpose=…`, or
the pushed tip commit's subject, cleaned to one plain line. Issued packets never go in the human-written
inbox. Agents that use MCP or the CLI should start the task before working (`synthe_start_task`,
`synthe-client start`), so `exclusive_paths` and `depends_on` apply ahead of the work.

**Compatibility.** Receivers without `trusted_senders`, grants without `self_issue` and human-signed tasks are
unchanged. A broker from before v0.7 refuses a grant carrying `self_issue` (`template_malformed`); a checker
from before v0.7 rejects a self-issued packet (`signature_invalid`). Adding the issuer to a broker's config
changes the grant lineage, so grants signed before it become `template_stale` and are signed again.
