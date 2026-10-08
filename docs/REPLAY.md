# Stored-result replay

Synthe returns the result it already recorded when the same broker-mediated effect is proposed again
after its claim is `COMPLETED`. It does not execute the adapter again and does not append a second
receipt. The returned object is the original signed receipt, unchanged.

Replay requires all of these to match:

- the original packet digest and logical idempotency identity;
- the original claim token and fencing epoch;
- the action name; and
- a domain-separated fingerprint of the effect type and every proposed effect parameter, with broker
  defaults normalized.

The ledger's receipt pointer is not trusted on its own. The complete receipt chain must verify, and
the pointed receipt must be the executed receipt for that claim, epoch, action and fingerprint. A
changed effect is `effect_fingerprint_mismatch` (`conflicting`). A missing legacy fingerprint,
unverifiable chain or mismatched pointer blocks replay. None of these cases grants permission to run
the effect again.

For `git_push`, the fingerprint covers the remote name, branch, commit, compare-and-swap expectation,
base and, for content proposals, the complete files/deletes/base-blob citations/message. The source
path or bundle is transport, not effect semantics; the commit hash binds the transported history.
Credentials and token-file configuration are never fingerprint inputs.

## Guarantees and limits

Replay preserves the broker's at-most-once boundary: an exact completed retry returns the retained
result, while changed semantics conflict. It does not create universal exactly-once execution. An
effect that never reached a confirmed receipt remains `UNKNOWN`; it must be reconciled, not guessed.

**No negative observation grants a dispatch right.** Reconciliation needs a fresh, authoritative,
identity- and effect-matching receipt or provider observation. `ABSENT`, stale, mismatched and
uncertain observations leave the operation `UNKNOWN` and blocked. This change does not alter release,
fencing, TTL or claim-token transitions.

## Signed-receipt decision: defer a second format

Synthe already signs each broker receipt with Ed25519 and hash-chains the receipt stream. This change
adds the full effect fingerprint to that existing signed receipt and verifies it before replay. We
defer adopting a second portable receipt schema or treating signatures as provider truth.

The proposed portable design is useful as a future evidence layer, but three boundaries remain:

1. A signature authenticates the canonical bytes; it cannot make incomplete canonicalization safe.
   Synthe's current canonicalizer deliberately covers its own constrained values and is not yet a
   cross-runtime RFC 8785 conformance claim. Independent testing of the reference implementation
   found two concrete JavaScript hazards: assigning `__proto__` into an ordinary object can silently
   omit an effect-bearing field, and rebuilding an object cannot override JavaScript's integer-index
   enumeration order for keys such as `"2"` and `"10"`. Synthe's Python serializer does not have
   either behavior, and regression vectors pin both facts, but that is not a substitute for a shared
   cross-runtime conformance suite.
2. A Synthe signature says what Synthe recorded. It cannot turn an ordinary authenticated provider
   GET into provider-signed truth. Provider identity and resource checks still establish the effect.
3. A self-contained valid hash chain cannot detect rollback to an older valid chain. That requires an
   independently trusted, non-replaceable anchor and verified ancestry.

Adoption should wait for interoperable positive and negative canonicalization vectors, an explicit
issuer/key and trust-tier model, and a real external anchor. The execution-safety path does not need
those features to compare a local effect fingerprint and replay its already verified local receipt.

## Compensatability lint decision: defer until Synthe has workflow graphs

The proposed rule is sound: compensatability belongs to an effect type, and a non-compensatable
effect must have no succeeding effect-bearing node on any path. It is a graph property, including
branches and joins, not a step-name convention.

Synthe's current gate validates one handoff and its declared actions; it does not own a workflow DAG
or an effect-type contract declaring inverses. Adding a lint now would invent an incomplete graph
schema and imply saga guarantees the gate does not provide. Defer it until Synthe accepts a complete
workflow definition. At that boundary, run the check before claims are admitted, emit a stable
diagnostic naming the offending step and edge, and keep compensation execution and its own
idempotency/reconciliation lifecycle as a separate feature.
