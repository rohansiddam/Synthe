// SPDX-License-Identifier: Apache-2.0
// Synthe commit barrier for OpenClaw: the pure policy (no I/O), so it can be tested on its own.
//
// What it catches: tool calls that would push or publish to a git remote directly, around Synthe.
// What it can't: a command it can't read as one (obfuscated text, a script that pushes, a git library
// in another language). That is why the wall is credentials, not this file: the agent holds no
// GitHub token, the broker does. This is the seatbelt in the request path; `synthe doctor` checks
// the wall. Both ship together.

export type Hit = { rule: string; tool: string; excerpt: string };

// Tools that run shell or code text.
export const EXEC_TOOLS = new Set(["exec", "bash", "process", "code_execution", "shell", "terminal"]);
// Tools that publish to GitHub themselves (OpenClaw's own GitHub identity).
export const PUBLISH_TOOLS = new Set(["github_publish"]);

const WRITE_METHOD = /(?:-X|--request|--method)\s*['"]?(?:POST|PUT|PATCH|DELETE)\b/i;
const GET_METHOD = /(?:-X|--request|--method)\s*['"]?GET\b/i;
// gh api and curl send a write when they carry data, even with no -X (gh api defaults to POST then).
const DATA_FLAGS = /\s(?:-f|-F|-d|--field|--raw-field|--input|--data(?:-raw|-binary|-urlencode)?|--form|--json)\b/;

function isWrite(command: string): boolean {
  return WRITE_METHOD.test(command) || (DATA_FLAGS.test(command) && !GET_METHOD.test(command));
}

const RULES: Array<[string, RegExp, ((matched: string) => boolean)?]> = [
  // git [-c k=v | -C dir | --flag[=v]]... push
  ["git push", /\bgit\b(?:\s+(?:-[cC]\s+\S+|--?[\w.-]+(?:=\S+)?))*\s+push\b/],
  // the same as an argument list in code: ["git", "push", ...], spawn("git", ["-C", dir, "push"])
  ["git push", /["'`]git["'`]\s*,\s*\[?\s*(?:["'`][^"'`\n]*["'`]\s*,\s*)*["'`]push["'`]/],
  ["git send-pack", /\bgit\b(?:\s+\S+)*?\s+(?:send-pack|http-push)\b/],
  ["gh pr merge", /\bgh\s+pr\s+merge\b/],
  ["gh repo sync", /\bgh\s+repo\s+sync\b/],
  ["gh release", /\bgh\s+release\s+(?:create|upload|edit|delete)\b/],
  ["gh api write", /\bgh\s+api\b[^\n;|&]*/, isWrite],
  ["GitHub API write", /\b(?:curl|wget|https?|xh)\b[^\n;|&]*api\.github\.com[^\n;|&]*/i, isWrite],
];

// Every string in a tool's params (bounded), so the policy doesn't depend on one tool's param names.
export function collectStrings(value: unknown, out: string[] = [], depth = 0, budget = { left: 200_000 }): string[] {
  if (budget.left <= 0 || depth > 6) return out;
  if (typeof value === "string") {
    const s = value.slice(0, budget.left);
    budget.left -= s.length;
    out.push(s);
  } else if (Array.isArray(value)) {
    for (const v of value) collectStrings(v, out, depth + 1, budget);
  } else if (value && typeof value === "object") {
    for (const v of Object.values(value as Record<string, unknown>)) collectStrings(v, out, depth + 1, budget);
  }
  return out;
}

// Shell line continuations and runs of whitespace would otherwise split a command.
export function normalize(text: string): string {
  return text.replace(/\\\r?\n/g, " ").replace(/[ \t]+/g, " ");
}

export function findDirectPush(toolName: string | undefined, params: unknown): Hit | null {
  const tool = String(toolName ?? "");
  if (PUBLISH_TOOLS.has(tool)) return { rule: "GitHub publish tool", tool, excerpt: tool };
  if (!EXEC_TOOLS.has(tool)) return null;
  const strings = collectStrings(params);
  // each string on its own, then all of them joined (a command split into command + args params)
  const texts = strings.length > 1 ? [...strings, strings.join(" ")] : strings;
  for (const raw of texts) {
    const text = normalize(raw);
    for (const [rule, re, also] of RULES) {
      const m = re.exec(text);
      if (m && (!also || also(m[0]))) return { rule, tool, excerpt: m[0].slice(0, 120) };
    }
  }
  return null;
}

export function blockMessage(hit: Hit): string {
  return (
    `Synthe blocked this ${hit.tool} call: it would ${hit.rule === "GitHub publish tool" ? "publish to GitHub" : `run "${hit.rule}"`} ` +
    `directly, around the commit barrier. Push through Synthe instead: commit on your agent branch, then call ` +
    `synthe_propose_effect. The human approves it in their own terminal (synthe-approve), and the broker ` +
    `pushes it exactly once and writes a signed receipt.`
  );
}

export type BrokerStatus =
  | { ok: true; waiting: Array<{ id: string; branch?: string; commit?: string }>; last?: { seq?: number; decision?: string; codes?: string[] } }
  | { ok: false; error: string };

// One line of context per turn. It states receipts, never the agent's own memory of what happened:
// agents report success even after duplicating an effect (the exactly-once study), so the ledger is
// the ground truth.
export function statusLine(s: BrokerStatus): string {
  if (!s.ok) {
    return `Synthe commit barrier: on, but the broker is not answering (${s.error}). Do not push; proposals fail until it is back.`;
  }
  const waiting = s.waiting.length
    ? `${s.waiting.length} waiting for the human's approval (${s.waiting.slice(0, 3).map((w) => w.id).join(", ")}${s.waiting.length > 3 ? ", …" : ""}); they approve with synthe-approve in their terminal`
    : "nothing waiting for approval";
  const last = s.last && s.last.seq !== undefined
    ? ` Last receipt: #${s.last.seq} ${s.last.decision ?? "?"}${s.last.codes && s.last.codes.length ? ` (${s.last.codes.join(", ")})` : ""}.`
    : "";
  return `Synthe commit barrier: on. Never push directly; propose pushes with synthe_propose_effect. ${waiting}.${last} Trust receipts, not memory, for what happened.`;
}
