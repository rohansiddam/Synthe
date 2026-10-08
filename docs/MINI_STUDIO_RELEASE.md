# Mini Studio release notes

This preview adds a read-only terminal review desk around the existing Synthe broker and approval path.

## Added

- `synthe-studio` with `--demo`, `--once`, `--json`, and `check`.
- Stable-ID proposal normalization and explicit receipt correlation.
- Credential-free sample fixtures.
- Numbered interactive review flow.
- Existing `synthe-approve --id ...` handoff.
- Focused state/safety tests.

## Not included

Lane grants, autonomous planning, server Runner, multi-agent scheduling, hosted previews, public review links, or recurring semantic Queue Steward.

## Release evidence required

Run focused tests plus the existing approval/OpenClaw integration suite, build/install a wheel in a fresh environment, and complete one supported OpenClaw task through staged diff -> explicit approval -> independently verified remote branch.

A unit-test pass alone is not evidence of the live flow.

## Security

Mini Studio does not read approver keys, start a broker, retry external effects, or treat approval acceptance as execution.
