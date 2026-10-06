# Synthe threat model (v0.5)

One page, so design arguments start from the same place.

## What Synthe is

An **admission gate**: before a receiving agent acts on a handoff, the checker
verifies who sent it, that the authority asked for fits the receiver's policy,
that the bytes it points at haven't changed, that required approvals exist and
are bound to this handoff, and that this unit of work hasn't already been claimed.

A signature proves **who said it**. It never proves **that it's safe**.

## Assets

| Asset | Where it lives | If it's compromised |
|---|---|---|
| Registry (agents, keys, receiver policy) | `registry.json` | **Root of trust.** Whoever can edit it decides who exists and what's allowed |
| Human approver keys | key files (`chmod 600`) | Attacker can approve any gated action |
| Agent signing keys | key files (`chmod 600`) | Attacker can send handoffs as that agent |
| Ledger | `ledger.json` (Action: `actions/cache`) | Deleting or resetting it re-enables duplicates |
| Workspace bytes | `--workspace` root | Pins detect changes; they can't stop a changed file being read later |

## In scope: what the gate stops

| Threat | Mechanism | Reason code |
|---|---|---|
| Packet edited in transit | Ed25519 over the canonical handoff | `signature_invalid` |
| Agent spoofs another agent | key must be registered under `from` | `signature_invalid`, `signature_signer_mismatch` |
| Sender grants itself tools or budget | receiver policy is a ceiling | `authority_exceeds_receiver_policy` |
| Sender drops an approval requirement | policy's `approval_required_for` is unioned in | `approval_missing` |
| Forged or typed-in approval | approvals must be signed by a trusted approver | `approval_unsigned`, `approver_not_trusted` |
| Approval replayed onto another handoff | signature binds `idempotency_key`, `from`, `to` | `approval_signature_invalid` |
| Same work executed twice | ledger claim (RESERVED → COMPLETED, file lock) | `duplicate_idempotency_key`, `idempotency_key_reserved` |
| Someone else closes your claim | completion bound to the packet digest + the claim token returned with ACCEPT | `completion_packet_mismatch`, `claim_token_invalid`, `claim_token_required` |
| Slow receiver acts after its claim was released and redispatched | fencing epoch + `fenced()` execution boundary | `claim_token_invalid`, `completion_unknown_key` |
| Stale or swapped inputs | SHA-256 pins against the workspace | `artifact_hash_mismatch`, `evidence_hash_mismatch` |
| Paraphrased "verbatim" quote | verbatim kinds must pin source bytes | `evidence_not_verbatim`, `verbatim_evidence_unpinned` |
| Undeclared side effects | policy can require `planned_actions` | `planned_actions_missing` |
| Checker silently skips a check | fail closed when a policy expects a pin but no workspace exists | `workspace_required` |

## v0.4–v0.5: effect targets, approvals arriving later, and concurrent work

| Threat | Mechanism | Reason code |
|---|---|---|
| Sender retargets an approved action (another branch, another recipient) | the approval can pin `params`; they are inside the approver's signature and must equal the planned action's | `approval_params_mismatch`, `approval_signature_invalid` |
| An approval delivered on its own is forged or meant for another handoff | a detached approval is the same signed object, bound to `idempotency_key`, `from`, `to`, checked like an embedded one | `approval_signature_invalid`, `approver_not_trusted` |
| "Approve later" used to skip a bad approval | deferral only covers a *missing* approval, only when the caller asks for it; a present but bad one still rejects | `approval_params_mismatch`, `approval_expired`, ... |
| Downstream work commits before the work it depends on | `depends_on` is signed by the sender; `fenced()`, `fenced_effect()` and `complete()` refuse until every upstream is `COMPLETED` | `dependency_incomplete`, `dependency_unknown` |
| Handoffs that wait on each other forever | a claim that would close a wait-for cycle through live claims is refused | `dependency_cycle` |
| Two receivers edit the same files at once | `exclusive_paths`: overlapping `owned_paths` on live claims are refused; overlap is judged conservatively | `claim_conflict` |
| One effect of a multi-effect handoff performed twice | `fenced_effect()` records each named effect; an executed or unconfirmed one is refused | `effect_already_executed`, `effect_outcome_unknown` |

Limits: deferral moves the approval check to whoever performs the effect; if that party does not
check, nothing does. `depends_on` holds back only effects run inside the fence.

## Out of scope: what it does NOT stop (be honest about these)

1. **A compromised or prompt-injected sender.** It produces a perfectly valid,
   signed packet for a malicious purpose. The gate checks the envelope and the
   authority, not the intent. The mitigations are narrow receiver policy, human
   approvals on dangerous tools, and small budgets.
2. **A receiver that never calls the gate**, or that "repairs" a rejected packet.
   Markdown rules aren't enforcement. Enforcement strength by entry point:
   GitHub Action (in the infrastructure path) > CLI in a script > a tool the
   model chooses whether to call. A gate the model can skip is a seatbelt: it
   only works when worn.
3. **A receiver doing more than declared.** `planned_actions`, `owned_paths` and
   budgets are checked *before* the work. Nothing here verifies what actually
   happened. Budgets are checked on
   the sender's *estimates*, so a lying `est_usd` passes.
4. **Whoever controls the registry.** It's an unsigned JSON file today. Signed
   registry is planned.
5. **Leaked keys.** There's no revocation yet. Rotate by adding a new `kid` and
   removing the old one. Human keys in plaintext files are the weakest link;
   use the OS keychain now, passkeys/WebAuthn later.
6. **Truth.** A hash proves the bytes, not that they're correct.
7. **Meaningless content.** The checker validates structure. A packet whose
   `purpose` is `"<one sentence>"` is structurally valid. The checker doesn't
   judge text.
8. **`state_revision`** is required but not yet compared against anything.
9. **Effects outside `fenced()`.** The fencing guarantee covers only effects executed
   through it. A receiver that acts on a stale ACCEPT without the fence can still
   double-act after a release.
10. **Ledger durability on CI.** `actions/cache` can be evicted. Fine for demos,
   not an exactly-once store.
