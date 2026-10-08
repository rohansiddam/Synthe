#!/usr/bin/env python3
"""Regenerate the v0.3 example packets. Deterministic: the test keys below are
derived from public strings and are published on purpose. NEVER use them for
anything real."""
import copy, hashlib, json, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / "src"))
import synthe_crypto as sc          # noqa: E402
import synthe_sign as ss            # noqa: E402

AGENTS = ["cora", "caddy", "rohan", "mallory"]


def test_key(name):
    secret = hashlib.sha256(f"synthe-v03-PUBLIC-TEST-KEY:{name}".encode()).digest()
    return {"agent": name, "kid": f"{name}-test-1", "alg": sc.ALG,
            "private_key": sc.b64u(secret), "_secret": secret}


def sha(p):
    return hashlib.sha256((HERE / "workspace" / p).read_bytes()).hexdigest()


def dump(obj, path):
    obj = {k: v for k, v in obj.items() if not k.startswith("_")} if "private_key" in obj else obj
    (HERE / path).write_text(json.dumps(obj, indent=2) + "\n")


keys = {n: test_key(n) for n in AGENTS}
for n, k in keys.items():
    dump(k, f"test-keys/{n}.key.json")

registry = {
    "agents": {
        "cora": {"role": "cto"},
        "caddy": {
            "role": "rules-integration",
            "policy": {
                "allowed_tools": ["read_repo", "run_tests", "gmail_send"],
                "forbidden": ["publish", "delete", "force_push"],
                "approval_required_for": ["send_email"],
                "trusted_approvers": ["rohan"],
                "budget": {"tokens": 100000, "usd": 5, "minutes": 60},
                "require_signatures": True,
                "require_signed_approvals": True,
                "require_planned_actions": True,
                "verify_evidence": True,
                "defaults": {
                    "owned_paths": ["rules/**"],
                    "output_schema": "verdict_pack.v1",
                    "budget": {"tokens": 50000, "usd": 2, "minutes": 30},
                },
            },
        },
        "rohan": {"role": "human-approver", "kind": "human"},
        "mallory": {"role": "untrusted-test-agent"},
        "lebron": {"role": "head-build"},
        "lebron-crown": {"alias_of": "lebron"},
    }
}
for n, k in keys.items():
    registry["agents"][n]["keys"] = [{"kid": k["kid"], "alg": sc.ALG,
                                      "public_key": sc.b64u(sc.public_key(k["_secret"]))}]
dump(registry, "registry.json")

# Minimal packet: everything the RECEIVER owns (owned_paths, output_schema,
# budget) comes from caddy's policy defaults; the sender states only its facts.
base = {"handoff": {
    "schema_version": "0.1", "id": "h-v03-0001", "trace_id": "trace-v03-0001",
    "idempotency_key": "cadros:verdict-pack:m1:rev-7", "on_failure": "reject",
    "from": "cora", "to": "caddy",
    "purpose": "Verify the M-1 verdict pack and email the summary to the district contact",
    "inputs": {"artifact_refs": [{"path": "input.txt", "sha256": sha("input.txt")}],
               "state_revision": "rev-7"},
    "scope": {"forbidden": ["publish"]},
    "authority": {"allowed_tools": ["read_repo", "run_tests", "gmail_send"],
                  "approval_required_for": ["send_email"], "approvals": []},
    "planned_actions": [
        {"name": "verify_pack", "tool": "run_tests", "est_tokens": 4000, "est_minutes": 5},
        {"name": "send_email", "tool": "gmail_send", "est_tokens": 300, "est_minutes": 1}],
    "acceptance": {
        "expires_at": "2999-01-01T00:00:00Z",
        "required_evidence": ["verbatim_quote", "test_output"],
        "evidence": [
            {"kind": "verbatim_quote", "ref": "evidence/quote.md#m1-u-12",
             "sha256": sha("evidence/quote.md"), "verbatim": True},
            {"kind": "test_output", "ref": "evidence/tests.txt", "sha256": sha("evidence/tests.txt")}]},
}}


def signed(pkt, approve=True):
    pkt = copy.deepcopy(pkt)
    if approve:
        ss.approve_packet(pkt, keys["rohan"], "send_email", "2999-01-01T00:00:00Z")
    return ss.sign_packet(pkt, keys["cora"])


out = {}
out["valid-signed"] = signed(base)

p = copy.deepcopy(out["valid-signed"])                 # edited in transit after signing
p["handoff"]["planned_actions"][1]["name"] = "send_email_to_all_customers"
p["handoff"]["purpose"] = "Email every customer"
out["attack-tampered-after-signing"] = p

p = copy.deepcopy(base)                                # mallory signs while claiming to be cora
p = ss.approve_packet(p, keys["rohan"], "send_email", "2999-01-01T00:00:00Z")
sig = sc.sign_bytes(keys["mallory"]["_secret"], sc.packet_signing_input(p["handoff"]))
p["signature"] = {"signer": "cora", "kid": "cora-test-1", "alg": sc.ALG, "sig": sc.b64u(sig)}
out["attack-spoofed-sender"] = p

p = copy.deepcopy(base)                                # sender drops the approval requirement
p["handoff"]["authority"]["approval_required_for"] = []
out["attack-self-granted-authority"] = signed(p, approve=False)

p = copy.deepcopy(base)                                # sender types rohan's approval itself
p["handoff"]["authority"]["approvals"] = [
    {"action": "send_email", "approver": "rohan", "expires_at": "2999-01-01T00:00:00Z"}]
out["attack-forged-approval"] = signed(p, approve=False)

other = copy.deepcopy(base)                            # rohan approved a DIFFERENT handoff
other["handoff"]["idempotency_key"] = "cadros:verdict-pack:m1:rev-6"
ss.approve_packet(other, keys["rohan"], "send_email", "2999-01-01T00:00:00Z")
p = copy.deepcopy(base)
p["handoff"]["authority"]["approvals"] = other["handoff"]["authority"]["approvals"]
out["attack-replayed-approval"] = signed(p, approve=False)

p = copy.deepcopy(base)                                # sender widens tools beyond receiver policy
p["handoff"]["authority"]["allowed_tools"].append("publish_site")
p["handoff"]["planned_actions"].append({"name": "post_results", "tool": "publish_site"})
out["attack-exceeds-receiver-policy"] = signed(p)

p = copy.deepcopy(base)                                # "verbatim" quote that isn't the source bytes
p["handoff"]["acceptance"]["evidence"][0]["sha256"] = hashlib.sha256(
    b'> M-1 U-12: ADUs are basically allowed in R-1.\n').hexdigest()
out["attack-paraphrased-verbatim"] = signed(p)

p = copy.deepcopy(base)                                # no planned actions: nothing to check authority against
p["handoff"]["planned_actions"] = []
out["attack-undeclared-actions"] = signed(p)

for name, pkt in out.items():
    dump(pkt, f"packets/{name}.json")
print("wrote", len(out), "packets")
