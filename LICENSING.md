# Licensing

Synthe is open-core. What you install and what lets anyone check our claims is open source. The broker,
which holds the credentials and does the push, is source-available: you can read, audit and run it, but
you can't sell it as a competing service. The paid team and hosted features are proprietary.

| License | What | Why |
|---|---|---|
| **Apache-2.0** ([LICENSE](LICENSE)) | Everything not listed below. In particular: the handoff spec (`SPEC.md`, `schema/`, `examples/`, the conformance vectors in `tests/conformance/`); the checker and crypto (`src/handoff_check.py`, `synthe_crypto.py`, `synthe_sign.py`); everything you install and run as yourself or your agent (`synthe_client.py`, `synthe_mcp.py`, `synthe_a2a.py`, `synthe_approve.py`, `synthe_task.py`, `synthe_init.py`, the terminal look `synthe_ui.py`); the OpenClaw plugin and skill (`integrations/openclaw/`); the setup skill (`skills/`); the GitHub Action (`github-action/`); docs and tests. | Adoption, and trust: anyone can read, use and build on what touches their machine, and implement the spec. |
| **FSL-1.1-ALv2** ([LICENSE-FSL.md](LICENSE-FSL.md)) | The broker: `src/synthe_commit.py`, `src/synthe_broker.py`, `src/synthe_plan.py`, `src/synthe_commit_ui.html`, and its installers in `deploy/`. | People must be able to audit what holds their GitHub token. FSL allows any use except offering it as a competing commercial product or service, and each version becomes Apache-2.0 two years after its release. |
| **Proprietary** ([LICENSE-PROPRIETARY.txt](LICENSE-PROPRIETARY.txt)) | `lab/`, `findings/`, `dogfood/`, `formal/` (kept in the private repository, not published). Also the hosted team product (team approvals, hosted receipts and evidence packs), which isn't in this repository. | The paid product, and the research and attack corpus behind our claims. We publish the results, not the test corpus. |

Each source file names its license on an `SPDX-License-Identifier` line.

## Trademark

The license grants rights to the code, not to the name. "Synthe" and the Synthe logo are trademarks of
Synthe. Forks must use a different name and logo.

## Before this ships publicly (for counsel)

- **The licensor.** The copyright lines name the two founders, Rohan Siddamsettiwar and Rishab
  Ramalingam (decided 2026-10-07; Synthe isn't incorporated yet). Once there is a company, the
  founders assign the code to it and the lines change to its legal name.
- **Contributors.** Whether contributions need a CLA or DCO: Rishab's and Rohan's, and AI-assisted
  code.
- **FSL scope.** The "Competing Use" definition, as it applies to a hosted Synthe.
- **The verifier.** Receipt verification currently lives in `synthe_commit.py` (FSL). The plan is an
  Apache-2.0 standalone `synthe-verify`, so anyone can check receipts with no FSL code. Moving it is
  an engineering task.
- **Trademark filing.** For "Synthe" and the logo, after a clearance search that the name is free to register.
- **Packaging.** One `synthe` package holds both the Apache-2.0 and the FSL files, and the Apache MCP
  server and setup import the broker lazily, only in dev (in-process) mode. Each file names its license,
  but the clean boundary is shipping the broker as its own package (`synthe-broker`).
- **Describing it.** The broker is source-available, not open source: FSL isn't OSI-approved, and some
  companies' policies reject non-OSI licenses. Say so wherever we describe the license.
- **Dependencies.** Third-party licenses (`cryptography`, OpenClaw's plugin SDK types) and their
  notices.

This page is a plan agreed by the founders, not legal advice.
