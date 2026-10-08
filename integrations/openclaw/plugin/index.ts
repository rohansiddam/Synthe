// SPDX-License-Identifier: Apache-2.0
// Synthe commit barrier for OpenClaw.
//
// - before_tool_call: blocks tool calls that would push or publish to a git remote directly
//   (git push, gh pr merge, GitHub API writes, OpenClaw's github_publish), and tells the agent to
//   propose through Synthe instead. A seatbelt in the request path; the wall is that the agent holds
//   no GitHub credential (the broker does), which `synthe doctor` checks.
// - before_prompt_build: one line of Synthe status per turn (what waits for the human's approval,
//   the last receipt), read from the broker, so the agent works from receipts, not memory.
import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";
import { blockMessage, findDirectPush, statusLine } from "./policy.ts";
import { brokerStatus } from "./broker.ts";

type Config = { brokerSocket?: string; blockDirectPush?: boolean; statusLine?: boolean };

export default definePluginEntry({
  id: "synthe-barrier",
  name: "Synthe commit barrier",
  description: "Blocks direct git pushes and shows what waits for your approval in Synthe",
  register(api: any) {
    const cfg: Config = (api.pluginConfig ?? {}) as Config;
    if (cfg.blockDirectPush !== false) {
      api.on(
        "before_tool_call",
        (event: { toolName?: string; params?: unknown }) => {
          const hit = findDirectPush(event.toolName, event.params);
          return hit ? { block: true, blockReason: blockMessage(hit) } : undefined;
        },
        { priority: 100 },
      );
    }
    const address = cfg.brokerSocket ?? process.env.SYNTHE_BROKER;
    if (cfg.statusLine !== false && address) {
      api.on("before_prompt_build", async () => ({ prependContext: statusLine(await brokerStatus(address)) }));
    }
  },
});
