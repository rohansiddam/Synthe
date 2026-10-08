#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build only the Apache-2.0 verifier in an isolated staging directory; never publish.

Requires `python -m pip install build`. No broker, private research, or runtime state is copied.
"""
import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FILES = {"src/synthe_verify.py": "synthe_verify.py", "LICENSE": "LICENSE",
         "packaging/verify/pyproject.toml": "pyproject.toml", "docs/VERIFY.md": "README.md"}


def stage(dest):
    dest.mkdir(parents=True, exist_ok=True)
    if any(dest.iterdir()):
        raise ValueError("verifier staging directory must be empty")
    for source, target in FILES.items():
        shutil.copyfile(ROOT / source, dest / target)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--outdir", required=True)
    ap.add_argument("--no-isolation", action="store_true", help="use already-installed build dependencies (offline builds)")
    a = ap.parse_args(argv)
    output = Path(a.outdir).resolve()
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        ap.error("output must be empty; artifacts are never overwritten")
    with tempfile.TemporaryDirectory(prefix="synthe-verify-build-") as tmp:
        stage(Path(tmp))
        subprocess.run([sys.executable, "-m", "build", *(["--no-isolation"] if a.no_isolation else []),
                        "--outdir", str(output), tmp], check=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
