# Touch ID approvals on macOS

Touch ID can protect Synthe's human approval key with the Mac's Secure Enclave. It is an optional
replacement for typing the approval passphrase on each push, not a replacement for reading the diff.

## What it protects

`synthe-init touchid` creates a P-256 key in the Secure Enclave and registers its public key as an
ES256 approval key. The private key is non-exportable. The local 0600 key file contains the public
key and an opaque, device-bound handle, not the private key.

Each approval still signs Synthe's canonical approval bytes. Those bytes bind the action to its
handoff, target parameters and pinned commit. The broker selects the registered key by `kid`, so an
Ed25519 signature cannot masquerade as an ES256 signature or vice versa. Task packets and broker
receipts continue to use Ed25519.

The key is created with `.biometryCurrentSet` and device-only access. Adding or removing a fingerprint
invalidates the key. A cancelled or failed Touch ID prompt submits no approval; the proposal remains
staged.

## Enroll and approve

Run enrollment from the Synthe checkout after the normal macOS setup:

```bash
~/synthe-venv/bin/synthe-init touchid
sudo bash deploy/macos/upgrade.sh
```

The first command builds the small Swift helper, creates the Secure Enclave key and stages its public
key in the registry. The second command, which must be run by the operator, installs the updated code
and registry for the isolated broker. Inspect `integrations/macos/touchid/synthe_touchid.swift` before
enrollment if you want to audit the helper that asks macOS to sign.

Approval otherwise uses the normal command:

```bash
SYNTHE_BROKER=unix:///var/db/synthe-run/broker.sock ~/synthe-venv/bin/synthe-approve
```

Read the broker-derived terminal card and whole diff first. After choosing `a`, compare the branch,
commit and file summary in the Touch ID prompt with that card. Touch the sensor only when they match.

## Limits

- Touch ID proves local biometric authentication; it does not prove that a diff is correct or safe.
- The system prompt cannot display the whole diff. The terminal card and `v` view are the review
  surface; the prompt is only a compact confirmation.
- A process running as the same desktop user can invoke the helper and supply its own prompt reason.
  Synthe sanitizes agent-controlled names and builds its reason from the broker's staged detail, but
  you must still reject unexpected prompts and compare the displayed target before touching the
  sensor.
- Root, a compromised OS or UI, and a person approving the wrong proposal are outside this boundary.
- Touch ID availability depends on a supported Mac, an unlocked login session, enrolled fingerprints
  and working Secure Enclave hardware. Failure is closed: no signature means no approval.
- Changing the enrolled fingerprint set invalidates the key. Remove the stale public registry entry,
  enroll a replacement and install the updated registry before using Touch ID again.
- This is a local macOS approval key, not a passkey, WebAuthn credential or remote approval mechanism.

## Passphrase fallback

Enrollment leaves the existing passphrase-protected Ed25519 key registered. Force that path with:

```bash
SYNTHE_BROKER=unix:///var/db/synthe-run/broker.sock ~/synthe-venv/bin/synthe-approve --passphrase
```

Use the fallback when Touch ID is unavailable or after a fingerprint change. It has the same approval
scope and commit binding, but its private key is encrypted on disk with the approval passphrase rather
than held in the Secure Enclave.

## Live verification

On 2026-10-08, the enrollment and upgrade flow was exercised on a real Apple-silicon Mac. A real
OpenClaw proposal was staged, reviewed in `synthe-approve`, authorized with Touch ID and pushed by the
isolated broker. The operator reported that the OpenClaw task took a little over a minute end to end;
the biometric approval itself completed normally. The run also exposed a small review-screen issue:
`v` appeared to do nothing when the entire short diff was already visible. The prompt now offers `v`
only when additional diff lines are hidden, and explains if it is entered for an already-complete card.
