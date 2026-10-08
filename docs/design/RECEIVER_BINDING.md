# Receiver binding (A3)

## Threat

A valid packet names its intended receiver in signed field `handoff.to`.
Signature verification proves who sent the packet, but without a locally
trusted receiver identity any agent sharing a validator endpoint can present a
packet addressed to another agent and claim it.

## Design

The checker gains optional operator input `as_receiver`. When present it must
equal the signed `handoff.to`, otherwise validation rejects with
`receiver_mismatch`. Omitting it preserves compatibility for offline checking
and endpoints that do not know the caller's identity.

The OpenClaw setup is single-receiver, so it records that receiver in the
operator-owned broker config. The broker supplies this value to every claim,
task admission, proposal revalidation, and staged retry; the client cannot
override it. A direct MCP deployment may pin the same value with
`--as-receiver`. The generated OpenClaw MCP command includes that explicit
identity as defense in depth, although an isolated broker trusts its own
config rather than the forwarded argument.

## Non-goals

This does not create identity or infer it from packet data. Multi-tenant
services must map an authenticated URL, token, or socket peer to a registered
agent and pass that verified identity. Receipt-level principals remain part
of the separate receipt-v2 design decision.
