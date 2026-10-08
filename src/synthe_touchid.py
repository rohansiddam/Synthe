#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Approve with Touch ID: a signing key in this Mac's Secure Enclave.

The key is made by `synthe-touchid` (integrations/macos/touchid/synthe_touchid.swift, built on first
use with the Xcode command-line tools). Its private half never leaves the Secure Enclave, and it signs
only after a Touch ID check with the fingerprints enrolled when it was made. Synthe registers its public
half as an ES256 approval key next to the passphrase key, which stays as the fallback.

  enroll(home, approver)       build the helper if needed, make the key, return its registry entry
  signing_key(path, reason)    a key object synthe_sign signs approvals with; each signature shows
                               `reason` in the Touch ID prompt and needs a finger on the sensor

Nothing here can sign on its own: every signature goes through the helper's Touch ID prompt.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

KEY_NAME = "approver.touchid.json"
HELPER = "synthe-touchid"
SOURCE = Path("integrations") / "macos" / "touchid" / "synthe_touchid.swift"


class TouchIDError(Exception):
    """Touch ID can't be used, or this approval wasn't given (cancelled, failed, no finger)."""


def key_path(home: Path) -> Path:
    return Path(home).expanduser() / KEY_NAME


def helper_path(home: Path) -> Path:
    return Path(os.environ.get("SYNTHE_TOUCHID") or Path(home).expanduser() / "bin" / HELPER)


def build_helper(home: Path, source_root: Path) -> Path:
    """Compile the helper into HOME/bin (once). It's a few lines of Swift: read it before you trust it."""
    out = helper_path(home)
    if out.exists():
        return out
    src = Path(source_root) / SOURCE
    if not src.is_file():
        raise TouchIDError(f"{src} is missing: run this from a Synthe checkout")
    swiftc = shutil.which("swiftc")
    if not swiftc:
        raise TouchIDError("swiftc wasn't found: install the Xcode command-line tools (xcode-select --install)")
    out.parent.mkdir(parents=True, exist_ok=True)
    r = subprocess.run([swiftc, "-O", "-o", str(out), str(src)], capture_output=True, text=True)
    if r.returncode != 0:
        raise TouchIDError("couldn't build the Touch ID helper: " + (r.stderr.strip()[-400:] or "swiftc failed"))
    return out


def available(home: Path) -> tuple[bool, str]:
    h = helper_path(home)
    if not h.exists():
        return False, "the Touch ID helper isn't built yet (synthe-init touchid)"
    r = subprocess.run([str(h), "available"], capture_output=True, text=True)
    return r.returncode == 0, (r.stderr.strip().removeprefix("synthe-touchid: ") or "available")


def enroll(home: Path, approver: str, source_root: Path, kid: str | None = None) -> dict:
    """Make the Touch ID key and return its registry entry {kid, alg: ES256, public_key}. Never replaces
    an existing key file: remove it yourself (and its registry entry) to start over."""
    home = Path(home).expanduser()
    path = key_path(home)
    if path.exists():
        raise TouchIDError(f"{path} already exists; this Mac already has a Touch ID key for Synthe")
    helper = build_helper(home, source_root)
    ok, why = available(home)
    if not ok:
        raise TouchIDError(why)
    r = subprocess.run([str(helper), "create", str(path)], capture_output=True, text=True)
    if r.returncode != 0:
        raise TouchIDError(r.stderr.strip().removeprefix("synthe-touchid: ") or "the helper couldn't make a key")
    record = json.loads(path.read_text())
    entry = {"kid": kid or f"{approver}-touchid-1", "alg": "ES256", "public_key": record["public_key"]}
    record.update(agent=approver, kid=entry["kid"])
    tmp = path.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(json.dumps(record, indent=2, sort_keys=True) + "\n")
    os.replace(tmp, path)
    return entry


def signing_key(path: Path, reason: str, helper: Path | None = None) -> dict:
    """A key object for synthe_sign.approve_packet: {agent, kid, _sign}. `_sign(msg)` runs the helper,
    which shows `reason` in the Touch ID prompt; it raises TouchIDError unless the person approves."""
    path = Path(path).expanduser()
    try:
        record = json.loads(path.read_text())
    except (OSError, ValueError) as e:
        raise TouchIDError(f"can't read {path}: {e}")
    if record.get("kind") != "synthe-touchid-key" or not record.get("agent") or not record.get("kid"):
        raise TouchIDError(f"{path} isn't an enrolled Synthe Touch ID key (run synthe-init touchid)")
    exe = Path(helper) if helper else helper_path(path.parent)

    def _sign(msg: bytes) -> bytes:
        r = subprocess.run([str(exe), "sign", str(path), reason], input=msg, capture_output=True)
        if r.returncode != 0:
            raise TouchIDError(r.stderr.decode(errors="replace").strip().removeprefix("synthe-touchid: ")
                               or "Touch ID didn't sign")
        import synthe_crypto as sc
        sig = sc.unb64u(r.stdout.decode().strip())
        if len(sig) != 64:
            raise TouchIDError("the helper returned something that isn't a P-256 signature")
        return sig

    return {"agent": record["agent"], "kid": record["kid"], "alg": "ES256", "_sign": _sign}
