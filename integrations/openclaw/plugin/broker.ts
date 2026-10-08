// SPDX-License-Identifier: Apache-2.0
// Read-only status from the Synthe broker over its socket: what waits for an approval, and the last
// receipt. One JSON line out, one back, per connection (the broker's protocol). Never throws: a
// broker that doesn't answer becomes { ok: false } and the status line says so.
import net from "node:net";
import type { BrokerStatus } from "./policy.ts";

function call(address: string, op: string, args: Record<string, unknown>, timeoutMs: number): Promise<any> {
  return new Promise((resolve, reject) => {
    const target = address.startsWith("unix://")
      ? { path: address.slice("unix://".length) }
      : address.startsWith("tcp://")
        ? (() => { const u = new URL(address); return { host: u.hostname, port: Number(u.port) }; })()
        : { path: address };
    const token = process.env.SYNTHE_BROKER_TOKEN;
    const sock = net.createConnection(target as net.NetConnectOpts);
    let buf = "";
    const done = (err: Error | null, value?: unknown) => {
      clearTimeout(timer);
      sock.destroy();
      err ? reject(err) : resolve(value);
    };
    const timer = setTimeout(() => done(new Error("timed out")), timeoutMs);
    sock.on("connect", () => sock.write(JSON.stringify({ op, args, ...(token ? { auth: token } : {}) }) + "\n"));
    sock.on("data", (chunk) => {
      buf += chunk.toString("utf8");
      const nl = buf.indexOf("\n");
      if (nl < 0) return;
      try {
        const resp = JSON.parse(buf.slice(0, nl));
        resp.ok ? done(null, resp.result) : done(new Error(resp.error?.code ?? "broker_error"));
      } catch {
        done(new Error("bad reply"));
      }
    });
    sock.on("error", (e) => done(e));
  });
}

export async function brokerStatus(address: string, timeoutMs = 1500): Promise<BrokerStatus> {
  try {
    const staged = await call(address, "staged", {}, timeoutMs);
    const waiting = (staged?.staged ?? [])
      .filter((s: any) => s?.state === "STAGED" && (s?.waiting_for ?? []).includes("approval"))
      .map((s: any) => ({ id: `${s.idempotency_key}/${s.action}`, branch: s.params?.branch, commit: s.params?.commit }));
    let last: { seq?: number; decision?: string; codes?: string[] } | undefined;
    try {
      const r = await call(address, "receipts", { limit: 1 }, timeoutMs);
      const rec = (r?.receipts ?? [])[0];
      if (rec) last = { seq: rec.seq, decision: rec.decision, codes: (rec.reasons ?? []).map((x: any) => x.code).slice(0, 3) };
    } catch {
      // the status still helps without the last receipt
    }
    return { ok: true, waiting, last };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : String(e) };
  }
}
