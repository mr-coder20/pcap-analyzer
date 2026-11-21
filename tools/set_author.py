#!/usr/bin/env python3
"""Change author / GitHub user / repo name everywhere.

    python tools/set_author.py --author "Your Name" --user your-github --repo pcap-analyzer
"""
import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import app_meta as M  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--author", default=M.AUTHOR)
ap.add_argument("--user", default=M.GITHUB_USER)
ap.add_argument("--repo", default=M.APP_SLUG)
a = ap.parse_args()
repls = [(f"github.com/{M.GITHUB_USER}/{M.APP_SLUG}", f"github.com/{a.user}/{a.repo}"),
         (f"github.com/{M.GITHUB_USER}", f"github.com/{a.user}"),
         (f"@{M.GITHUB_USER}", f"@{a.user}"),
         (f"{M.GITHUB_USER}/{M.APP_SLUG}", f"{a.user}/{a.repo}")]
exts = {".py", ".md", ".yml", ".yaml", ".txt", ".toml", ".json", ""}
n = 0
for p in ROOT.rglob("*"):
    if not p.is_file() or ".git" in p.parts or p.suffix not in exts or p.name == "set_author.py":
        continue
    try:
        t = p.read_text(encoding="utf-8")
    except Exception:
        continue
    o = t
    for x, y in repls:
        t = t.replace(x, y)
    if p.name == "app_meta.py":
        t = re.sub(r'AUTHOR = ".*"', f'AUTHOR = "{a.author}"', t)
        t = re.sub(r'GITHUB_USER = ".*"', f'GITHUB_USER = "{a.user}"', t)
        t = re.sub(r'APP_SLUG = ".*"', f'APP_SLUG = "{a.repo}"', t)
    t = t.replace(f"by {M.AUTHOR}", f"by {a.author}").replace(f"Copyright (c) 2026 {M.AUTHOR}", f"Copyright (c) 2026 {a.author}")
    if t != o:
        p.write_text(t, encoding="utf-8")
        n += 1
print(f"updated {n} files → author={a.author} github={a.user}/{a.repo}")
