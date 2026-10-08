# Ledger v2: bounded hot-path writes

## Problem and measured cause

The JSON ledger rewrites every claim on each state change. At 50,000 entries
the research run measured a claim at 189 ms against 2.1 ms when empty. Receipt
append likewise rereads the entire receipt stream only to find its sequence
and previous digest. Those are linear hot-path costs and block a hosted tier.

## Storage design

New broker setups use SQLite in WAL mode (`ledger.sqlite3`). Each idempotency
key is one row containing the existing JSON entry. The checker keeps its dict
semantics through a lazy mapping:

- ordinary claim, complete, release, and fence operations read and update only
  the referenced keys;
- dependency and exclusive-path checks may deliberately scan rows because
  their semantics require a cross-key view;
- `BEGIN IMMEDIATE` supplies the existing one-writer claim serialization;
- `synchronous=FULL`, SQLite's journal, and the existing claim-token fencing
  preserve crash and exactly-once behavior;
- `.json` ledgers remain supported unchanged, and an explicit migration helper
  copies them transactionally without deleting the source.

Receipt append uses an atomically replaced tip sidecar with `{seq, head,
bytes}`. If the sidecar is absent, corrupt, or its byte offset does not match
the stream, Synthe verifies/rebuilds it from the receipt file before appending.
A normal append therefore hashes no historical receipts.

## Checkpoints and retention boundary

The tip is an index, not evidence and not a pruning authority. Signed
checkpoints and archive pruning need a separately versioned checkpoint format,
export destination, retention duration, and recovery policy. Those choices are
recorded in `RECEIPT_V2.md`; this change does not delete ledger or receipt data
and does not alter signed receipt bytes.

## Compatibility and rollback

Existing JSON configs continue to work. Operators can point a config back to
its original JSON ledger because migration never mutates it. SQLite corruption
returns the same fail-closed `ledger_corrupt` verdict. The public packet,
approval, receipt, and conformance-vector contracts do not change.
