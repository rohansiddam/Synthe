# Claude Code adapter

Preview; hook tests pass locally, a real Claude Code session is still a release acceptance check.
First complete [agent-neutral setup](../../docs/ANY_AGENT.md), then run Claude in the agent's separate
OS account. Put the installed Synthe executables on its PATH. Do not log in to GitHub in that account.

On macOS:

```sh
export PATH="/Library/Synthe/venv/bin:$PATH"
export SYNTHE_BROKER=unix:///var/db/synthe-run/broker.sock
claude --plugin-dir /absolute/path/to/integrations/claude-code
```

On Linux use `/opt/synthe/bin` and `unix:///run/synthe/broker.sock`. Keep the plugin in a trusted,
readable location outside the agent's project; do not run a plugin supplied by an untrusted repository.

The plugin bundles a local stdio MCP connection, a skill, and a `PreToolUse` hook. The hook rejects
recognizable pushes, merges, raw GitHub API commands, and delivery of approvals through MCP. Other
commands get no permission decision, preserving Claude's usual checks. Malformed input is refused.
It never echoes command text, which can contain secrets.

Limits: obfuscated commands, aliases, scripts, other publishing tools, and disabled hooks can bypass
this text matcher. It does not supply credentials, sign approvals or replace account isolation.
Run `synthe-init doctor --repo ~/repo` **as the agent**. No ENFORCED claim from installing a plugin alone.

Format references (checked 2026-10-08): [Claude hooks](https://code.claude.com/docs/en/hooks),
[plugin layout](https://code.claude.com/docs/en/plugins-reference).
