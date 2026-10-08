# Any agent, or no AI

Synthe's enforcement boundary is the separate OS account and credential-holding broker, not a particular
model. The agent proposes; a human approves the exact effect in a different account; the broker pushes.
Do not put GitHub credentials, the approver key, sudo access, or a privileged container socket in the
agent's account. A plugin alone does not make a deployment ENFORCED.

## Prepare (safe for an assistant)

From a checkout or an installed package with its setup assets:

```sh
synthe-init prepare --agent-kind none --agent-account worker --repo-url https://github.com/OWNER/REPO.git --branches 'agent/*' --allowed-paths 'src/**,tests/**'
```

`none` skips Node, OpenClaw installation, plugin configuration and gateway startup. It does **not** skip
the isolated broker, separate agent account, signed task submission, scoped paths/branches, human approval
or doctor checks. The default remains `--agent-kind openclaw`. `--agent` is the registered receiver ID;
it is distinct from the integration kind and must match the broker's registry.

The human—not an assistant—runs the generated command in their own terminal:

```sh
bash ~/.synthe/finish-setup.sh
```

It prompts locally for credentials and uses sudo; never paste these secrets into an agent chat. macOS
uses launchd. Linux uses systemd and requires system-wide Python 3.10+, venv, git, runuser and useradd;
OpenClaw additionally needs system-wide Node/npm. Linux's new wrapper is a fresh-install path, refuses
an existing broker, and is **not yet validated on a clean live Linux host**. It is not an Azure rollout.
Check the generated script before running it. No change here deploys Studio, upgrades a gate or issues
a model-reviewer grant.

Enter the agent account (`sudo -iu worker`, typed by the human). On macOS:

```sh
export PATH="/Library/Synthe/venv/bin:$HOME/.local/bin:$PATH"
```

On Linux:

```sh
export PATH="/opt/synthe/bin:$HOME/.local/bin:$PATH"
```

In that account:

```sh
synthe-init doctor --repo ~/repo
```

No OpenClaw warning is expected for `none`. All credential/isolation failures still count. Read every
check; a mode label is not proof against untested credential sources or root/administrator compromise.

## Local MCP clients

Run the client itself in the isolated agent account, not your founder account. Use a trusted installed
executable's absolute path. The examples below are macOS; on Linux change the command to
`/opt/synthe/bin/synthe-mcp` and the socket to `unix:///run/synthe/broker.sock`. Never configure
`--broker broker.json`: that runs the broker inside the agent process instead of using isolation.

Claude Code can use the [bundled adapter](../integrations/claude-code/README.md), or register local MCP:

```sh
claude mcp add --transport stdio synthe-local -- /Library/Synthe/venv/bin/synthe-mcp --broker-url unix:///var/db/synthe-run/broker.sock
```

Codex, in that account's `~/.codex/config.toml`:

```toml
[mcp_servers.synthe_local]
command = "/Library/Synthe/venv/bin/synthe-mcp"
args = ["--broker-url", "unix:///var/db/synthe-run/broker.sock"]
disabled_tools = ["synthe_submit_approval"]
```

Cursor (`~/.cursor/mcp.json`) or Cline (MCP Servers → Configure MCP Servers), merge this entry without
overwriting existing configuration:

```json
{
  "mcpServers": {
    "synthe-local": {
      "type": "stdio",
      "command": "/Library/Synthe/venv/bin/synthe-mcp",
      "args": ["--broker-url", "unix:///var/db/synthe-run/broker.sock"]
    }
  }
}
```

Disable the approval-delivery tool in clients offering tool filters. It cannot forge a signature, but
approval belongs in the human account. These are configuration examples, not claims of live end-to-end
certification for every client. Restart/reconnect, inspect the advertised tools, then do one scratch task.
Follow the [Synthe task workflow](../integrations/claude-code/skills/synthe/SKILL.md); never release UNKNOWN
or treat missing evidence as permission to retry an effect.

Formats checked 2026-10-08: [Codex MCP](https://learn.chatgpt.com/docs/extend/mcp?surface=cli),
[Claude MCP](https://code.claude.com/docs/en/mcp), [Cursor MCP](https://cursor.com/docs/mcp),
[Cline MCP](https://docs.cline.bot/mcp/mcp-overview).

## No AI needed

In the human terminal, create a signed task:

```sh
synthe-task new "Make the scoped change" --branch agent/example
```

In the separate worker terminal, edit and commit within that task's scope. With the broker-backed
`synthe::` origin created by setup, follow [git push as a proposal](GIT_PUSH.md). A direct GitHub origin
must remain unable to publish. The human reads and approves the staged diff with `synthe-approve` in
their own terminal. A staged proposal is not a successful push: check its signed receipt. Use
[standalone verification](VERIFY.md) to audit exported receipts, with an independently trusted public key.
