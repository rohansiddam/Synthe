#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Synthe as an MCP server (stdlib only).

Any MCP-capable agent (Claude, and other clients that speak MCP) can call
Synthe before acting on a handoff, without vendoring the checker:

  stdio (local clients):
    python3 src/synthe_mcp.py --registry agents.json --ledger ledger.json --workspace .

  Streamable HTTP (remote clients; JSON responses, bearer token required):
    SYNTHE_MCP_TOKEN=... python3 src/synthe_mcp.py --http 127.0.0.1:8765 \
        --registry agents.json --ledger ledger.json --workspace .

Security model: the *operator* fixes registry, ledger and workspace on the
command line. The calling model supplies only the packet, so a model cannot
point the checker at a permissive registry or a fresh ledger.

Tools:
  synthe_validate_handoff  validate + claim (RESERVED) a packet
  synthe_complete_handoff  flip a claimed key to COMPLETED after the effect
  synthe_receiver_policy   what a receiver will accept (so senders can build
                           conforming packets instead of guessing)
"""
from __future__ import annotations

import argparse
import hmac
import ipaddress
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import handoff_check as hc  # noqa: E402

SERVER_VERSION = "0.6.0"
SUPPORTED_PROTOCOL_VERSIONS = ["2025-06-18", "2025-03-26", "2024-11-05", "2025-11-25"]
DEFAULT_PROTOCOL_VERSION = "2025-06-18"

INSTRUCTIONS = (
    "Synthe validates agent-to-agent handoff packets before the receiving agent acts. "
    "Call synthe_validate_handoff before starting any handed-off work; if the decision is "
    "REJECT, stop and report the state and reason codes to the sender. Never edit a packet "
    "to make it pass and never invent missing facts (approvals, hashes, evidence). An ACCEPT "
    "and every receipt carry `plan` (purpose, planned actions with their status, what remains, "
    "the constraints): re-read `plan` before every step. After the work's effect is real, call "
    "synthe_complete_handoff with the same packet and the claim token from the ACCEPT. For a "
    "broker-mediated effect, retry the identical synthe_propose_effect call after a lost response: "
    "a completed exact effect replays its stored signed result and a changed effect conflicts."
)

PACKET_SCHEMA = {"type": "object", "description": "A Synthe handoff packet: {\"handoff\": {...}, "
                 "optional \"signature\": {...}}. See schema/handoff.schema.json."}

TOOLS = [
    {
        "name": "synthe_validate_handoff",
        "title": "Validate a handoff packet",
        "description": "Validate an agent-to-agent handoff packet against the operator's registry, "
                       "receiver policy, workspace artifacts and idempotency ledger. On ACCEPT the "
                       "idempotency key is claimed (RESERVED) unless dry_run is true. Returns "
                       "{decision, state, reasons[]} - a REJECT is a normal result, not an error. "
                       "An ACCEPT carries `plan`: the purpose, each planned action with its status, "
                       "what remains and the constraints. Re-read `plan` before every step.",
        "inputSchema": {"type": "object", "properties": {
            "packet": PACKET_SCHEMA,
            "dry_run": {"type": "boolean", "description": "validate only; do not claim the key",
                        "default": False},
            "wait_for_approval": {"type": "boolean", "default": False,
                                  "description": "with a commit broker: claim even though the human "
                                                 "approval of a broker-mediated effect has not arrived yet "
                                                 "(the broker still requires it before committing)"}},
            "required": ["packet"], "additionalProperties": False},
        "annotations": {"readOnlyHint": False, "destructiveHint": False,
                        "idempotentHint": True, "openWorldHint": False},
    },
    {
        "name": "synthe_complete_handoff",
        "title": "Mark a claimed handoff completed",
        "description": "After the handed-off work's effect has actually happened, flip the packet's "
                       "idempotency key from RESERVED to COMPLETED so its effect can never execute again. Pass "
                       "the claim token that synthe_validate_handoff returned with ACCEPT. Only call "
                       "this for effects that really happened.",
        "inputSchema": {"type": "object", "properties": {
            "packet": PACKET_SCHEMA,
            "claim_token": {"type": "string",
                            "description": "claim.token from the ACCEPT verdict"}},
            "required": ["packet", "claim_token"], "additionalProperties": False},
        "annotations": {"readOnlyHint": False, "destructiveHint": False,
                        "idempotentHint": True, "openWorldHint": False},
    },
    {
        "name": "synthe_receiver_policy",
        "title": "Show what a receiver accepts",
        "description": "Return the merged policy a receiving agent enforces (allowed tools, forbidden "
                       "actions, approvals required, trusted approvers, budget ceilings, defaults, "
                       "signature requirements) so a sender can build a conforming packet.",
        "inputSchema": {"type": "object", "properties": {"receiver": {"type": "string"}},
                        "required": ["receiver"], "additionalProperties": False},
        "annotations": {"readOnlyHint": True, "openWorldHint": False},
    },
]


PROPOSE_TOOL = {
    "name": "synthe_propose_effect",
    "title": "Propose an effect for Synthe to commit",
    "description": "You hold no credentials for real-world effects (git push, ...). Propose the effect "
                   "here instead: the Synthe commit broker re-checks the signed handoff and its human "
                   "approval now, checks the effect matches the plan and the receiver's policy, performs "
                   "it with compare-and-swap, observes the result and returns a signed receipt. Pass the "
                   "packet you were handed, the claim token from synthe_validate_handoff's ACCEPT, the "
                   "planned action's name, params (git_push: remote, branch, commit = full SHA, optional "
                   "expected_old = SHA or 'new', optional base = the remote BRANCH a new branch starts "
                   "from, default main, never a commit; leave it out unless the handoff names one) and "
                   "source = the path of your repo (its commits are sent to the broker as a git bundle). "
                   "If this exact completed proposal is retried, the broker returns the original signed "
                   "result without another effect or receipt; changed effect inputs under the same "
                   "identity fail with effect_fingerprint_mismatch. "
                   "Without a repo, send the files instead: "
                   "params {remote, branch, files: {path: full text}, delete: [paths], base_blobs: {path: "
                   "blob id from synthe_read_file, or null for a new file}, message}; Synthe builds the "
                   "commit. decision 'denied' means nothing "
                   "happened: report the reason codes and stop; never try another way to do the effect. "
                   "With wait_for_approval true, a proposal that lacks only its human approval (or an "
                   "upstream handoff) comes back 'staged': the broker holds it and commits it when the "
                   "approval arrives, if nothing changed; do not propose it again or approve it yourself. "
                   "The receipt carries the updated `plan`; re-read it before your next step.",
    "inputSchema": {"type": "object", "properties": {
        "packet": PACKET_SCHEMA,
        "claim_token": {"type": "string", "description": "claim.token from the ACCEPT verdict"},
        "action": {"type": "string", "description": "name of the planned action to perform"},
        "params": {"type": "object", "description": "effect parameters, e.g. remote, branch, commit"},
        "source": {"type": "string", "description": "git_push: path of your repo holding the commit "
                                                    "(packaged as a bundle; the broker never reads your disk)"},
        "wait_for_approval": {"type": "boolean", "default": False,
                              "description": "stage the proposal if only its approval or upstream is missing"}},
        "required": ["packet", "claim_token", "action", "params"], "additionalProperties": False},
    "annotations": {"readOnlyHint": False, "destructiveHint": True,
                    "idempotentHint": True, "openWorldHint": True},
}


SUBMIT_APPROVAL_TOOL = {
    "name": "synthe_submit_approval",
    "title": "Deliver a human's signed approval",
    "description": "Deliver a detached approval that a human signed (synthe_sign.py approve --detached) to "
                   "the commit broker. You are only the courier: the broker verifies the approver's "
                   "signature, trust and expiry, receipts it, and commits any staged proposal it now "
                   "covers. Never create, edit or sign an approval yourself; an unsigned or altered one "
                   "is rejected and receipted.",
    "inputSchema": {"type": "object", "properties": {
        "approval": {"type": "object", "description": "the signed approval object, exactly as the human gave it"}},
        "required": ["approval"], "additionalProperties": False},
    "annotations": {"readOnlyHint": False, "destructiveHint": True,
                    "idempotentHint": True, "openWorldHint": True},
}


READ_TOOLS = [
    {
        "name": "synthe_read_file",
        "title": "Read a file from the repository",
        "description": "Read one file's current text and its blob id from a branch the operator made readable "
                       "(default: the integration branch). Use the blob id in base_blobs when you propose a "
                       "change to that file, so Synthe can tell if someone else changed it first.",
        "inputSchema": {"type": "object", "properties": {
            "path": {"type": "string", "description": "repository path, e.g. docs/COMMIT.md"},
            "ref": {"type": "string", "description": "branch (optional)"},
            "remote": {"type": "string", "description": "broker remote name (optional)"}},
            "required": ["path"], "additionalProperties": False},
        "annotations": {"readOnlyHint": True, "openWorldHint": True},
    },
    {
        "name": "synthe_list_files",
        "title": "List files in the repository",
        "description": "List regular files (path, blob id, size) under a prefix on a readable branch.",
        "inputSchema": {"type": "object", "properties": {
            "prefix": {"type": "string", "description": "directory prefix, e.g. tests/ (optional)"},
            "ref": {"type": "string"}, "remote": {"type": "string"}},
            "additionalProperties": False},
        "annotations": {"readOnlyHint": True, "openWorldHint": True},
    },
]


class SyntheServer:
    def __init__(self, registry_path, ledger_path, workspace, ttl=24.0, verify_evidence=False,
                 broker_config=None, broker_url=None, as_receiver=None):
        self.registry_path = registry_path
        self.ledger_path = Path(ledger_path) if ledger_path else None
        self.workspace = Path(workspace) if workspace else None
        self.ttl = ttl
        self.verify_evidence = verify_evidence
        self.as_receiver = as_receiver
        self.broker = None
        self.client = None
        if broker_url:
            # Isolated: the broker daemon (its own OS user) holds the keys,
            # the ledger and the registry; this server only forwards.
            import synthe_client as scl
            self.client = scl.BrokerClient(broker_url)
        elif broker_config:
            import synthe_commit as cm
            self.broker = cm.BrokerConfig(broker_config)
            if cm.in_process_refusal(self.broker, "--broker"):
                raise SystemExit(
                    "--broker runs the commit broker inside this MCP server, i.e. inside the agent's own "
                    "process, which can then read the broker's key. That is not isolation. Run "
                    "`synthe_commit.py serve` as the broker's own user and pass --broker-url "
                    "unix:///path/to/broker.sock instead (or set isolation mode 'none' for local dev).")
            if self.ledger_path and self.ledger_path.resolve() != self.broker.ledger_path:
                raise SystemExit("--ledger must be the broker's ledger: claims and effects share one ledger")

    def _via_broker(self, op, **args):
        import synthe_client as scl
        try:
            return self.client.call(op, **args)
        except scl.BrokerError as exc:
            return {"decision": "ERROR", "error": {"code": exc.code, "message": exc.message}}

    # -- tools ---------------------------------------------------------------
    def _registry(self):
        return hc.load_registry(self.registry_path)

    def tool_validate(self, args):
        wait = args.get("wait_for_approval") is True
        packet = args.get("packet")
        h = packet.get("handoff") if isinstance(packet, dict) else None
        if self.as_receiver is not None and isinstance(h, dict) and h.get("to") != self.as_receiver:
            return hc._reject("invalid", "receiver_mismatch",
                              f"handoff is addressed to {h.get('to')!r}, not the authenticated receiver "
                              f"{self.as_receiver!r}")
        if self.client:
            return self._via_broker("claim", packet=packet, dry_run=bool(args.get("dry_run", False)),
                                    **({"wait_for_approval": True} if wait else {}))
        registry, err = self._registry()
        if err:
            return err
        extra, defer = (), None
        h = (packet or {}).get("handoff") if isinstance(packet, dict) else None
        if self.broker and isinstance(h, dict):
            import synthe_commit as cm
            extra = cm.load_approvals(self.broker, h)
            if wait:
                defer = {a.get("name") for a in h.get("planned_actions") or []
                         if isinstance(a, dict) and a.get("tool") in self.broker.effects}
        verdict = hc.check(packet, registry=registry, ledger_path=self.ledger_path,
                           workspace=self.workspace, dry_run=bool(args.get("dry_run", False)),
                           reserve_ttl_hours=self.ttl, verify_evidence=self.verify_evidence,
                           extra_approvals=extra, defer_approvals=defer, as_receiver=self.as_receiver)
        import synthe_plan as sp
        return sp.with_plan(verdict, packet, registry, self.ledger_path,
                            tuple(self.broker.effects) if self.broker else ())

    def tool_complete(self, args):
        # Many agents share one MCP endpoint, so completion needs the claim
        # token: holding the packet (the sender has it too) is not enough.
        if self.client:
            return self._via_broker("complete", packet=args.get("packet"), claim_token=args.get("claim_token"))
        return hc.complete(args.get("packet"), self.ledger_path,
                           claim_token=args.get("claim_token"), require_token=True)

    def tool_policy(self, args):
        if self.client:
            return self._via_broker("policy", receiver=args.get("receiver"))
        registry, err = self._registry()
        if err:
            return err
        who = args.get("receiver")
        agents = (registry or {}).get("agents", {})
        if who not in agents:
            return {"receiver": who, "known": False, "message": "receiver is not in the registry"}
        entry = agents[who] or {}
        if entry.get("alias_of"):
            return {"receiver": who, "known": True, "alias_of": entry["alias_of"],
                    "message": "use the canonical id"}
        return {"receiver": who, "known": True,
                "policy": hc.receiver_policy(registry, who) or {},
                "accepts_signatures_from": sorted(a for a, e in agents.items()
                                                  if isinstance(e, dict) and e.get("keys"))}

    def tools(self):
        """Tool definitions advertised by tools/list (subclasses may extend)."""
        return TOOLS + ([PROPOSE_TOOL, SUBMIT_APPROVAL_TOOL, *READ_TOOLS] if self.broker or self.client else [])

    def tool_functions(self):
        """Tool name -> handler (subclasses may extend)."""
        fns = {"synthe_validate_handoff": self.tool_validate,
               "synthe_complete_handoff": self.tool_complete,
               "synthe_receiver_policy": self.tool_policy}
        if self.broker or self.client:
            fns["synthe_propose_effect"] = self.tool_propose
            fns["synthe_submit_approval"] = self.tool_submit_approval
            fns["synthe_read_file"] = self.tool_read_file
            fns["synthe_list_files"] = self.tool_list_files
        return fns

    def _read(self, op, **args):
        if self.client:
            return self._via_broker(op, **args)
        import synthe_commit as cm
        try:
            eff = cm.GitPush(self.broker)
            if op == "read_file":
                return eff.read_file(args.get("remote"), args.get("ref"), args.get("path"))
            return eff.list_files(args.get("remote"), args.get("ref"), args.get("prefix") or "")
        except cm.Deny as d:
            return {"decision": "ERROR", "error": {"code": d.reason["code"], "message": d.reason["message"]}}

    def tool_read_file(self, args):
        return self._read("read_file", path=args.get("path"), ref=args.get("ref"), remote=args.get("remote"))

    def tool_list_files(self, args):
        return self._read("list_files", prefix=args.get("prefix"), ref=args.get("ref"), remote=args.get("remote"))

    def tool_submit_approval(self, args):
        if self.client:
            return self._via_broker("submit_approval", approval=args.get("approval"))
        import synthe_commit as cm
        return cm.submit_approval(self.broker, args.get("approval"))

    def tool_propose(self, args):
        if self.client:
            import synthe_client as scl
            try:
                return scl.propose_from_args(self.client, args)
            except scl.BrokerError as exc:
                return {"decision": "ERROR", "error": {"code": exc.code, "message": exc.message}}
        import synthe_commit as cm
        return cm.propose(self.broker, args)

    # -- JSON-RPC ------------------------------------------------------------
    def handle(self, msg):
        """Handle one JSON-RPC message. Returns a response dict, or None for
        notifications."""
        if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0" or not isinstance(msg.get("method"), str):
            return _error(msg.get("id") if isinstance(msg, dict) else None, -32600, "Invalid Request")
        mid, method, params = msg.get("id"), msg["method"], msg.get("params") or {}
        is_notification = "id" not in msg
        try:
            if method == "initialize":
                requested = params.get("protocolVersion")
                version = requested if requested in SUPPORTED_PROTOCOL_VERSIONS else DEFAULT_PROTOCOL_VERSION
                result = {"protocolVersion": version,
                          "capabilities": {"tools": {"listChanged": False}},
                          "serverInfo": {"name": "synthe", "title": "Synthe handoff checker",
                                         "version": SERVER_VERSION},
                          "instructions": INSTRUCTIONS}
            elif method == "ping":
                result = {}
            elif method == "tools/list":
                result = {"tools": self.tools()}
            elif method == "tools/call":
                name, args = params.get("name"), params.get("arguments") or {}
                fn = self.tool_functions().get(name)
                if fn is None:
                    return _error(mid, -32602, f"Unknown tool: {name}")
                if not isinstance(args, dict):
                    return _error(mid, -32602, "arguments must be an object")
                out = fn(args)
                result = {"content": [{"type": "text", "text": json.dumps(out, indent=2)}],
                          "structuredContent": out, "isError": False}
            elif method.startswith("notifications/"):
                return None
            else:
                return None if is_notification else _error(mid, -32601, f"Method not found: {method}")
        except Exception as exc:  # never crash the server on one bad call
            if is_notification:
                return None
            return {"jsonrpc": "2.0", "id": mid, "result": {
                "content": [{"type": "text", "text": f"internal error: {exc}"}], "isError": True}}
        return None if is_notification else {"jsonrpc": "2.0", "id": mid, "result": result}


def _error(mid, code, message):
    return {"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": message}}


def serve_stdio(server: SyntheServer):
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = hc.strict_loads(line)
        except hc.StrictJSONError as exc:  # duplicate keys, NaN/Infinity: refuse, never guess
            resp = _error(None, -32700, f"Parse error: {exc.code}: {exc}")
        except ValueError:
            resp = _error(None, -32700, "Parse error")
        else:
            resp = server.handle(msg)
        if resp is not None:
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()


def make_http_handler(server: SyntheServer, token: str | None, allowed_origins: set, path="/mcp"):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *a):  # keep stdout clean; log to stderr
            sys.stderr.write("synthe-mcp: " + (fmt % a) + "\n")

        def _send(self, status, body=None, ctype="application/json"):
            data = b"" if body is None else json.dumps(body).encode()
            self.send_response(status)
            if body is not None:
                self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            if data:
                self.wfile.write(data)

        def _authorized(self):
            origin = self.headers.get("Origin")
            if origin and origin not in allowed_origins:  # DNS-rebinding guard
                self._send(403, _error(None, -32000, "Origin not allowed"))
                return False
            if token is None:
                return True
            got = self.headers.get("Authorization", "")
            if not hmac.compare_digest(got.encode(), f"Bearer {token}".encode()):
                self._send(401, _error(None, -32001, "Unauthorized"))
                return False
            return True

        def do_POST(self):
            if self.path.split("?", 1)[0] != path:
                return self._send(404, _error(None, -32000, "Not found"))
            if not self._authorized():
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length > 4 * 1024 * 1024:
                    return self._send(413, _error(None, -32000, "Payload too large"))
                msg = hc.strict_loads(self.rfile.read(length) or b"null")
            except hc.StrictJSONError as exc:  # duplicate keys, NaN/Infinity: refuse, never guess
                return self._send(400, _error(None, -32700, f"Parse error: {exc.code}: {exc}"))
            except ValueError:
                return self._send(400, _error(None, -32700, "Parse error"))
            resp = server.handle(msg)
            if resp is None:
                return self._send(202)
            self._send(200, resp)

        def do_GET(self):  # no server-initiated stream
            self.send_response(405)
            self.send_header("Allow", "POST")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def do_DELETE(self):
            self.do_GET()

    return Handler


def main(argv=None):
    ap = argparse.ArgumentParser(description="Synthe MCP server")
    ap.add_argument("--registry", help="agent registry (default: the broker config's)")
    ap.add_argument("--ledger", help="claim ledger (default: the broker config's)")
    ap.add_argument("--workspace", default=None)
    ap.add_argument("--broker-url", metavar="URL",
                    help="isolated broker daemon to forward every tool to (unix:///path/broker.sock or "
                         "tcp://host:port with $SYNTHE_BROKER_TOKEN); adds synthe_propose_effect. The "
                         "broker holds the keys, ledger and registry; this server holds no secrets")
    ap.add_argument("--broker", metavar="BROKER_JSON",
                    help="dev only (broker isolation mode 'none'): run the commit broker in this process")
    ap.add_argument("--reserve-ttl-hours", type=float, default=24.0)
    ap.add_argument("--verify-evidence", action="store_true")
    ap.add_argument("--as-receiver", help="authenticated receiver identity; reject packets addressed elsewhere")
    ap.add_argument("--http", metavar="HOST:PORT", help="serve Streamable HTTP (JSON responses) instead of stdio")
    ap.add_argument("--token-env", default="SYNTHE_MCP_TOKEN",
                    help="env var holding the bearer token required on HTTP (default SYNTHE_MCP_TOKEN)")
    ap.add_argument("--allow-no-auth", action="store_true",
                    help="permit HTTP without a token (loopback addresses only)")
    ap.add_argument("--allowed-origin", action="append", default=[],
                    help="browser Origin allowed to call the HTTP endpoint (repeatable)")
    a = ap.parse_args(argv)
    broker_url = (a.broker_url or "").strip()
    if not broker_url or broker_url == "${SYNTHE_BROKER}":
        import synthe_client as scl
        broker_url = os.environ.get("SYNTHE_BROKER", "").strip() or (scl.configured_broker() or "")

    if broker_url:
        server = SyntheServer(None, None, None, broker_url=broker_url, as_receiver=a.as_receiver)
    else:
        if a.broker:
            import synthe_commit as cm
            bc = cm.BrokerConfig(a.broker)
            a.registry = a.registry or str(bc.registry_path)
            a.ledger = a.ledger or str(bc.ledger_path)
            a.workspace = a.workspace or (str(bc.workspace) if bc.workspace else None)
        if not a.registry or not a.ledger:
            ap.error("--registry and --ledger are required (or pass --broker-url)")
        server = SyntheServer(a.registry, a.ledger, a.workspace or ".", a.reserve_ttl_hours,
                              a.verify_evidence, broker_config=a.broker, as_receiver=a.as_receiver)
    if not a.http:
        serve_stdio(server)
        return 0
    host, _, port = a.http.rpartition(":")
    token = os.environ.get(a.token_env) or None
    if token is None:
        try:
            loopback = ipaddress.ip_address(host).is_loopback
        except ValueError:
            loopback = host == "localhost"
        if not (a.allow_no_auth and loopback):
            sys.exit(f"refusing to serve HTTP without a bearer token: set ${a.token_env} "
                     f"(or --allow-no-auth on a loopback address for local testing)")
    httpd = ThreadingHTTPServer((host, int(port)), make_http_handler(server, token, set(a.allowed_origin)))
    sys.stderr.write(f"synthe-mcp: serving Streamable HTTP on http://{host}:{port}/mcp\n")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
