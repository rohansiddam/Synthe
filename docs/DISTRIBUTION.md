# Distribution and update gates

This repository builds candidates; packages, a Homebrew tap and a ClawHub listing are not thereby
published. Never upload a private-repository build as a public release. First review the public export
with both founders. Version 0.6.0 already exists in git: choose the next version at release review;
never replace a tag or an existing package.

## Build without publishing

Install `build` in a throwaway environment. From the reviewed snapshot:

```sh
python -m build --outdir dist/broker
```

```sh
python scripts/build_verifier.py --outdir dist/verifier
```

The full wheel includes setup assets, so `synthe-init prepare` finds them outside a checkout. The
separate verifier has no runtime dependencies or FSL files. Use different environments: both packages
intentionally provide the same `synthe-verify` module/command. Add `--no-isolation` to the verifier build
only when build dependencies are already installed.

The manually dispatched `release-candidate.yml` builds and hashes private artifacts. It has read-only
repository permissions and no publish/OIDC authority. There is no tag-to-public-release automation.
Install a candidate wheel in an empty environment and test setup on a disposable machine before promotion.

## Homebrew candidate

This generator hashes a real sdist, refuses credentials/unversioned URLs and prints a formula. It does
not create a tap, push or upload:

```sh
python scripts/homebrew_verifier.py dist/verifier/synthe_verify-0.6.0.tar.gz --version 0.6.0 --url https://github.com/rohansiddam/Synthe/releases/download/v0.6.0/synthe_verify-0.6.0.tar.gz
```

Use the newly approved version in all three places. Publish identical bytes, then run `brew audit` and
the install test on a clean Mac. This is verifier-only; a full-broker formula with pinned cryptography
build resources remains a separate packaging task.

## OpenClaw / ClawHub

The existing `integrations/openclaw/CLAWHUB_LISTING_DRAFT.md`, plugin and skill are candidates. Run
`node --test` in its plugin directory and a real gateway scratch task. Do not advertise hooks as the
credential wall or claim they cover embedded/local modes. Align Python/MCP/plugin versions at release,
collect the stranger timed setup run and both founders' sign-off. No marketplace publishing is automated.

## Updates

A pip upgrade changes the caller's package, not the root-owned running broker. Keep the previous
reviewed checkout. On macOS the human reviews and runs `deploy/macos/upgrade.sh` with sudo, then doctor
as the agent and one real approved push. Linux finish is fresh-install only: it refuses existing broker
state. In-place Linux migration/rollback needs a separately tested upgrade path. Never remove a ledger,
reset claims or retry UNKNOWN from absence of evidence. Deployment, reviewer enrollment and Studio
releases each require their own approval; a green build does not authorize them.
