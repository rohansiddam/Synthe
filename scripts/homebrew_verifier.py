#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Print a verifier-only Homebrew formula with the digest of a real, already-built sdist. No publish."""
import argparse
import hashlib
import re
from pathlib import Path
from urllib.parse import urlsplit


def formula(sdist: Path, version: str, url: str) -> str:
    parsed = urlsplit(url)
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise ValueError("version must be a stable X.Y.Z release")
    if parsed.scheme != "https" or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("an immutable HTTPS artifact URL without credentials is required")
    if not re.fullmatch(r"https://github\.com/[A-Za-z0-9_-]+/[A-Za-z0-9_.-]+/releases/download/v" +
                        re.escape(version) + r"/synthe_verify-" + re.escape(version) + r"\.tar\.gz", url):
        raise ValueError("expected the exact versioned GitHub release artifact URL")
    if sdist.name != f"synthe_verify-{version}.tar.gz":
        raise ValueError("artifact filename/version mismatch")
    digest = hashlib.sha256(sdist.read_bytes()).hexdigest()
    return f'''# Generated from a local candidate. Publish the identical artifact before installing this formula.
class SyntheVerify < Formula
  include Language::Python::Virtualenv
  desc "Offline verification of Synthe receipt chains"
  homepage "https://github.com/rohansiddam/Synthe"
  url "{url}"
  sha256 "{digest}"
  license "Apache-2.0"
  depends_on "python@3.13"

  def install
    virtualenv_install_with_resources
  end

  test do
    assert_match "--checkpoint", shell_output("#{{bin}}/synthe-verify --help")
  end
end
'''


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("sdist", type=Path)
    ap.add_argument("--version", required=True)
    ap.add_argument("--url", required=True)
    a = ap.parse_args()
    try:
        print(formula(a.sdist, a.version, a.url), end="")
    except (OSError, ValueError) as e:
        ap.error(str(e))


if __name__ == "__main__":
    main()
