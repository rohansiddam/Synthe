# Synthe Mini Studio

A small terminal review desk for the OpenClaw workflow.

## Sample mode

No broker, credential, approval key, or network access is used:

```bash
synthe-studio --demo
synthe-studio --demo --once
synthe-studio --demo --json
```

Every proposal and outcome is simulated and labeled SAMPLE.

## Live preview

After the existing OpenClaw setup is working:

```bash
synthe-studio
```

The overview reads broker hello/status, staged proposals, and bounded receipts. Select a proposal to fetch its current broker-derived detail. Approval remains the existing flow:

```bash
synthe-approve --id <proposal-id>
```

Mini Studio never loads the approver key and never treats an approval exit code as proof of execution. It refreshes broker state afterward.

For noninteractive use:

```bash
synthe-studio --once
synthe-studio --json
synthe-studio check
```

`check` is read-only and does not claim access to a complete task backlog.

## Compatibility

The tested OpenClaw documentation currently pins 2026.9.8. Compatibility with other versions is not implied until tested.

## Safety

- Sample mode never contacts a broker.
- Proposal selection uses stable IDs.
- Agent-controlled terminal text is sanitized.
- Approval uses an argument-array subprocess, never a shell string.
- Missing or uncorrelated receipts remain unknown.
- Mini Studio does not start a second broker or retry external effects.
