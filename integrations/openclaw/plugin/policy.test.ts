// SPDX-License-Identifier: Apache-2.0
// node --test policy.test.ts   (Node 24+ runs TypeScript with type stripping)
import { test } from "node:test";
import assert from "node:assert/strict";
import { blockMessage, findDirectPush, statusLine } from "./policy.ts";

const exec = (command: string) => findDirectPush("exec", { command });

const BLOCKED: Array<[string, string]> = [
  ["git push origin main", "git push"],
  ["git push", "git push"],
  ["cd repo && git push --force origin HEAD:main", "git push"],
  ["git -c credential.helper=store push origin x", "git push"],
  ["git -C /tmp/repo push", "git push"],
  ["git --no-pager push origin", "git push"],
  ["git \\\n   push origin main", "git push"],
  ["GIT_SSH_COMMAND='ssh -i key' git push origin", "git push"],
  ["git send-pack https://example/repo.git main", "git send-pack"],
  ["git http-push https://example/repo.git main", "git send-pack"],
  ["gh pr merge 12 --squash", "gh pr merge"],
  ["gh repo sync owner/repo", "gh repo sync"],
  ["gh release create v1.0.0", "gh release"],
  ["gh api repos/o/r/merges -f base=main -f head=agent/x", "gh api write"],
  ["gh api -X PUT repos/o/r/contents/a.txt --input body.json", "gh api write"],
  ["curl -X POST https://api.github.com/repos/o/r/git/refs -H 'Authorization: x'", "GitHub API write"],
  ["curl -d '{}' https://api.github.com/repos/o/r/merges", "GitHub API write"],
];

for (const [command, rule] of BLOCKED) {
  test(`blocks: ${command.replace(/\n/g, "\\n")}`, () => {
    const hit = exec(command);
    assert.ok(hit, "expected a block");
    assert.equal(hit.rule, rule);
  });
}

test("blocks git push spelled as an argument list in code", () => {
  for (const code of [
    "import subprocess\nsubprocess.run(['git', 'push', 'origin', 'main'])",
    'require("child_process").spawnSync("git", ["push", "origin"])',
    'execFile("git", ["-C", "/repo", "push"])',
  ]) {
    assert.ok(findDirectPush("code_execution", { code }), code);
  }
});

test("blocks a command split across params (command plus args)", () => {
  assert.ok(findDirectPush("process", { command: "git", args: ["push", "origin", "main"] }));
});

test("blocks OpenClaw's own GitHub publish tool whatever its params", () => {
  assert.equal(findDirectPush("github_publish", {})?.rule, "GitHub publish tool");
});

const ALLOWED = [
  "git status",
  "git commit -m 'push the button'",
  "git log --oneline -5",
  "git fetch origin && git pull --rebase",
  "git stash push -m wip",
  "npm run push",
  "echo 'git is great'",
  "gh pr view 12",
  "gh api repos/o/r/pulls",
  "gh api -X GET repos/o/r/commits -f per_page=5",
  "curl https://api.github.com/repos/o/r",
];

for (const command of ALLOWED) {
  test(`allows: ${command}`, () => assert.equal(exec(command), null));
}

test("only shell-running tools are read", () => {
  assert.equal(findDirectPush("write", { path: "deploy.sh", content: "git push origin main" }), null);
  assert.equal(findDirectPush("synthe__synthe_propose_effect", { action: "push_branch" }), null);
  assert.equal(findDirectPush(undefined, { command: "git push" }), null);
});

// Pinned known gaps: the seatbelt can't read these as pushes. The wall is that the agent holds no
// GitHub credential; `synthe doctor` checks it. A future hardening shows up as a deliberate diff here.
test("known gaps stay documented, not silently claimed", () => {
  assert.equal(exec('eval "$(echo Z2l0IHB1c2g= | base64 -d)"'), null);
  assert.equal(exec("./scripts/release.sh"), null);
  assert.equal(exec("g''it pu''sh origin main"), null);
});

test("params are scanned with a bound", () => {
  const big = "x".repeat(300_000) + " git push";
  assert.equal(exec(big), null); // past the 200k scan budget: a known limit, pinned
});

test("the block message points to the way through", () => {
  const msg = blockMessage({ rule: "git push", tool: "exec", excerpt: "git push" });
  assert.match(msg, /synthe_propose_effect/);
  assert.match(msg, /synthe-approve/);
});

test("status line states receipts and what waits for the human", () => {
  const s = statusLine({
    ok: true,
    waiting: [{ id: "repo:agent/x:task/push_branch" }],
    last: { seq: 42, decision: "denied", codes: ["non_fast_forward"] },
  });
  assert.match(s, /1 waiting for the human's approval \(repo:agent\/x:task\/push_branch\)/);
  assert.match(s, /#42 denied \(non_fast_forward\)/);
  assert.match(s, /Never push directly/);
  assert.match(statusLine({ ok: true, waiting: [] }), /nothing waiting for approval/);
  assert.match(statusLine({ ok: false, error: "ECONNREFUSED" }), /not answering \(ECONNREFUSED\)/);
});
