#!/usr/bin/env python3
"""
One command to publish a new version; GitHub Actions then builds Windows, macOS and Linux
binaries and attaches them to a GitHub Release marked "Latest".

    python tools/release.py 7.1.0          # bump → commit → tag v7.1.0 → push
    python tools/release.py patch|minor|major
"""
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
META = ROOT / "app_meta.py"


def sh(*a, check=True):
    return subprocess.run(a, cwd=ROOT, check=check, text=True, capture_output=True).stdout.strip()


def current():
    return re.search(r'VERSION = "([^"]+)"', META.read_text(encoding="utf-8")).group(1)


def bump(cur, how):
    M, m, p = (int(x) for x in cur.split("."))
    return {"major": f"{M+1}.0.0", "minor": f"{M}.{m+1}.0", "patch": f"{M}.{m}.{p+1}"}[how]


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    arg = sys.argv[1].lstrip("v")
    new = bump(current(), arg) if arg in ("major", "minor", "patch") else arg
    if not re.fullmatch(r"\d+\.\d+\.\d+", new):
        sys.exit("version must look like 7.1.0")
    if sh("git", "status", "--porcelain"):
        print("⚠ working tree has uncommitted changes; they will be included in the release commit.")
    META.write_text(re.sub(r'VERSION = "[^"]+"', f'VERSION = "{new}"', META.read_text(encoding="utf-8")), encoding="utf-8")
    sh("git", "add", "-A")
    sh("git", "commit", "-m", f"release: v{new}", check=False)
    sh("git", "tag", "-a", f"v{new}", "-m", f"PCAP Analyzer v{new}")
    sh("git", "push", "origin", "HEAD")
    sh("git", "push", "origin", f"v{new}")
    print(f"🚀 v{new} pushed. Watch the build: https://github.com/mr-coder20/pcap-analyzer/actions")
    print("   Downloads appear at: https://github.com/mr-coder20/pcap-analyzer/releases/latest")


if __name__ == "__main__":
    main()
