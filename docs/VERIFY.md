# Verify a receipt without trusting the broker installation

`synthe-verify` is Apache-2.0 and uses Python's standard library only. It neither imports nor installs
the FSL broker. Run the single `synthe_verify.py` file with Python 3.10+, or install the independently
built `synthe-verify` wheel. This is a release candidate, not a claim that a package is on PyPI.

```sh
synthe-verify receipts.jsonl --key broker.pub.json --json
```

Obtain the public key over a channel you trust, independently of the receipt file. On a configured Mac
the installer publishes it at `/Users/Shared/Synthe/broker.pub.json`. Only use public keys here; never
share broker private state. A public registry is accepted with `--key registry.json --broker synthe-broker`.

The verifier checks strict JSON (no repeated fields, NaN or Infinity), signer identity and key ID,
canonical Ed25519 signatures, consecutive sequence numbers and every predecessor digest. It rejects
ambiguous key IDs and invalid or weak public keys. All receipt fields except the signature are bound,
including unusual JSON property names. The serialization is Synthe v1's sorted Python JSON contract,
**not RFC 8785/JCS interoperability**; changing it would require a versioned migration.

Keep a verified `count:head` checkpoint somewhere the ledger writer cannot replace:

```sh
synthe-verify receipts.jsonl --key broker.pub.json --checkpoint 44:REPLACE_WITH_PREVIOUSLY_TRUSTED_SHA256
```

The placeholder is deliberately invalid: use the exact 64-character digest you recorded. Verification
checks the full chain and the checkpoint at its original position, so a higher-sequence fork does not
win merely by being longer. Without an independently retained checkpoint, a valid older prefix cannot
be distinguished from a current complete chain. A checkpoint stored beside a replaceable ledger is
not an independent rollback defense. This tool does not manage an external anchor or transparency log.

`VERIFIED` means **these bytes were signed by the trusted local issuer and link correctly**. It does
not mean GitHub signed them, the external effect is currently present, a task was good, or the issuer
told the truth. Even a signed field claiming `PROVIDER_SIGNED` is only issuer-controlled data here.
Verification grants no execution, reconciliation or dispatch authority. No negative observation grants
a dispatch right. Keep UNKNOWN blocked until the broker's existing reconciliation requirements pass.

Exit codes: 0 verified; 1 invalid chain/checkpoint; 2 invalid arguments, key file or unreadable input.
Keys and receipt files must be reasonably sized; this CLI reads the chain into memory, not as a stream.

Build without the broker:

```sh
python scripts/build_verifier.py --outdir /absolute/new-empty-output-directory
```

Tests include RFC 8032 vectors, tampering, untrusted signers, wrong checkpoints, an unrelated longer
fork, malformed key files, prototype-named properties and mutation checks. Signatures authenticate
claims; they do not create external truth. Receipt v2/provider roots and managed anchors remain separate
design decisions, not silently added to the execution state machine.
