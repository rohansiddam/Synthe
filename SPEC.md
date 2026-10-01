# Handoff Contract v0.1 (draft)

One-page rule for agent-to-agent work transfers. Every handoff is treated as an
API boundary: validate it before the receiver runs. Fail closed.

## Required fields

| Field | Meaning |
|---|---|
| `handoff.id` | unique id of this transfer |
| `handoff.idempotency_key` | dedupe key — same key twice = one execution |
| `handoff.trace_id` | links sender work, this handoff, receiver work, and retries into one audit trail |
| `schema_version` | "0.1" |
| `from` / `to` | canonical agent ids (no aliases — one registry of who is who) |
| `purpose` | what the receiver must accomplish, in one sentence |
| `inputs.artifact_refs` | files/links the receiver may read, each with a hash or revision |
| `inputs.state_revision` | the current state the receiver must work from; stale revision = stale handoff |
| `scope.owned_paths` | what the receiver may touch |
| `scope.forbidden` | actions the receiver must not take (e.g. send email, publish, delete) |
| `authority.allowed_tools` | tools the receiver may call |
| `authority.budget` | token / cost / time limits |
| `authority.approval_required_for` | actions needing a human or named approver first |
| `acceptance.output_schema` | what the receiver must produce |
| `acceptance.required_evidence` | proof that counts as "done" (tests, diffs, screenshots — not vibes) |
| `acceptance.expires_at` | when this handoff goes stale |
| `on_failure` | reject / retry-with-budget / escalate / request-human |

## Validation order

1. Parse + schema check — bad shape = **invalid**, reject with field-level errors.
2. Identity check — unknown sender alias or unverified agent = reject until identity is on record.
3. Freshness check — artifact hash or state revision doesn't match = **stale**, receiver must refresh.
4. Authority check — requested action exceeds budget, tools, or approvals = **blocked**, route to owner.
5. Duplication check — idempotency key already executed = **duplicate**, do not run again.

## Failure states

- **invalid** — schema/identity/authority violation; reject, never auto-repair.
- **incomplete** — required evidence missing from the deliverable; ask for it or escalate.
- **stale** — source or approval expired; refresh, don't proceed on old state.
- **conflicting** — two results disagree; preserve both, route to resolver/human.
- **blocked** — policy or dependency prevents work; stop, notify owner.
- **retryable** — transient failure only; retry within budget, then fail visibly.
- **duplicate** — idempotency key already claimed or completed; do not run again.
- **unknown** — (v0.2) a claim was RESERVED but never completed past its TTL;
  the receiver may have crashed before or after the effect. Reconcile against
  the receiver's effect receipt before redispatching; never blindly re-run.

Core loop: validate → accept / reject → execute. The receiver never starts on an
unvalidated handoff. A rejection always says why and who must act.

## Claim lifecycle (v0.2)

Acceptance is a claim, not a completion. On ACCEPT the checker atomically
records the idempotency key as RESERVED in the ledger; the receiver flips it
to COMPLETED (`--complete`) only after the effect is done. This keeps a crash
before the effect from being mistaken for a finished execution, and a lost
ledger from silently re-arming a completed one: COMPLETED re-presentations
are duplicates, fresh RESERVED re-presentations are duplicates still claimed,
and stale RESERVED claims surface as **unknown** for reconciliation instead of
being quietly allowed or blocked.

## v0.1 non-goals

No UI, no hosted service, no cross-vendor negotiation. One repo: JSON schema +
CLI validator + catch log. Dogfood on Cadros for two weeks before anyone else
sees it.
