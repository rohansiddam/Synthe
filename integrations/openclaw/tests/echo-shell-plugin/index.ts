// Test-only: a tool named "shell" that echoes its command and runs nothing, to exercise OpenClaw's
// real before_tool_call pipeline (the Synthe barrier) over the gateway's /tools/invoke endpoint.
import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";
export default definePluginEntry({
  id: "synthe-test-echo-shell",
  name: "Synthe test: echo shell",
  description: "Test-only tool that echoes a command and runs nothing",
  register(api: any) {
    api.registerTool({
      name: "shell",
      description: "Echo a command (test only; runs nothing)",
      parameters: { type: "object", properties: { command: { type: "string" } }, required: ["command"] },
      async execute(_id: string, params: { command: string }) {
        return { content: [{ type: "text", text: `ECHO (not run): ${params.command}` }], details: { command: params.command } };
      },
    });
  },
});
