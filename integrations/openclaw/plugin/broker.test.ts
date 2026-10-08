// SPDX-License-Identifier: Apache-2.0
// node --test broker.test.ts : the read-only status call against a fake broker on a temp unix socket.
import { test } from "node:test";
import assert from "node:assert/strict";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import fs from "node:fs";
import { brokerStatus } from "./broker.ts";

function fakeBroker(reply: (req: any) => any): Promise<{ address: string; close: () => void; seen: any[] }> {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "sy"));
  const sock = path.join(dir, "b.sock");
  const seen: any[] = [];
  const server = net.createServer((c) => {
    let buf = "";
    c.on("data", (d) => {
      buf += d.toString();
      if (!buf.includes("\n")) return;
      const req = JSON.parse(buf.slice(0, buf.indexOf("\n")));
      seen.push(req);
      c.end(JSON.stringify(reply(req)) + "\n");
    });
  });
  return new Promise((resolve) =>
    server.listen(sock, () => resolve({ address: `unix://${sock}`, seen, close: () => { server.close(); fs.rmSync(dir, { recursive: true, force: true }); } })),
  );
}

test("reports what waits for approval and the last receipt, read-only", async () => {
  const b = await fakeBroker((req) =>
    req.op === "staged"
      ? { ok: true, result: { staged: [
          { idempotency_key: "app:agent/x:t1", action: "push_branch", state: "STAGED", waiting_for: ["approval"], params: { branch: "agent/x" } },
          { idempotency_key: "app:agent/y:t2", action: "push_branch", state: "STAGED", waiting_for: ["dependency"] },
          { idempotency_key: "app:agent/z:t3", action: "push_branch", state: "COMMITTED", waiting_for: [] },
        ] } }
      : { ok: true, result: { receipts: [{ seq: 7, decision: "denied", reasons: [{ code: "non_fast_forward" }] }] } },
  );
  try {
    const s = await brokerStatus(b.address);
    assert.deepEqual(s, { ok: true, waiting: [{ id: "app:agent/x:t1/push_branch", branch: "agent/x", commit: undefined }],
                          last: { seq: 7, decision: "denied", codes: ["non_fast_forward"] } });
    assert.deepEqual(b.seen.map((r) => r.op), ["staged", "receipts"]); // only read-only ops
  } finally {
    b.close();
  }
});

test("a broker that is down becomes a status, never an exception", async () => {
  const s = await brokerStatus("unix:///nonexistent/synthe/broker.sock", 300);
  assert.equal(s.ok, false);
});

test("a broker error code is reported", async () => {
  const b = await fakeBroker(() => ({ ok: false, error: { code: "broker_not_isolated", message: "x" } }));
  try {
    assert.deepEqual(await brokerStatus(b.address), { ok: false, error: "broker_not_isolated" });
  } finally {
    b.close();
  }
});
