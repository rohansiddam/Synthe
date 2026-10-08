# Using Synthe with Any Agent

Synthe's commit barrier protects your GitHub credentials and enforces exactly-once, human-approved pushes. While our default setup uses the OpenClaw gateway plugin to provide early "blocked" feedback, the security guarantee **does not depend on OpenClaw**. The broker isolates the token at the OS level.

You can use Synthe with **any MCP-compatible agent** (like Claude Code, Cursor, Cline, or Codex), or even no AI at all.

## 1. What happens without the OpenClaw plugin

Without the plugin, there is no early "Tool call blocked" message when the agent tries a direct `git push`. Instead, the push will just **fail at GitHub** because the agent's OS account has no GitHub token and no push-capable SSH key.

The security wall is exactly the same:
- The agent proposes changes through the Synthe MCP server.
- The human approves the commit with their passphrase or Touch ID.
- The broker pushes the change exactly once.

## 2. Using an MCP agent (Claude Code, Cursor, Cline)

To use an MCP agent, run it inside the restricted agent account (e.g., the `openclaw` user) created during the setup. 

Configure your agent to connect to the Synthe MCP server using the configuration below. Replace `<your-agent-name>` with a recognizable name (e.g., `claude-code`, `cursor`).

### Claude Code

Add this to your Claude Code MCP configuration (usually `~/.claude.json` or `claude_mcp.json`):

```json
{
  "mcpServers": {
    "synthe": {
      "command": "synthe-mcp",
      "args": [
        "--broker-url",
        "unix:///var/db/synthe-run/broker.sock",
        "--as-receiver",
        "<your-agent-name>"
      ]
    }
  }
}
```

### Cursor / Cline

In your MCP settings UI, add a new server with:
- **Type**: `command`
- **Command**: `synthe-mcp`
- **Arguments**: `--broker-url unix:///var/db/synthe-run/broker.sock --as-receiver <your-agent-name>`

## 3. Testing without an AI

If you want to verify the broker isolation and red-team the barrier yourself without using an AI agent, you can use our built-in stand-in scripts.

1. Switch to the agent's unprivileged account (e.g., `su - openclaw`).
2. Run the agent stand-in script to propose a basic change:
   ```bash
   python3 scripts/agent_stand_in.py
   ```
3. Run the live red-team battery to verify the broker refuses all 33 attacks:
   ```bash
   python3 scripts/redteam_live.py
   ```

Because you are running inside the agent's account, the red-team script has no more access than the agent does, proving that the broker and the OS boundaries hold.
