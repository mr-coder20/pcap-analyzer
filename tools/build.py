#!/usr/bin/env python3
"""
Build a standalone PCAP Analyzer for the CURRENT operating system.

    python tools/build.py            # → dist/release/<asset>

Output names are version-less on purpose so that the permanent URLs
    https://github.com/mr-coder20/pcap-analyzer/releases/latest/download/<asset>
always point at the newest release.
"""
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import app_meta as META  # noqa: E402

NAME = "PCAP-Analyzer"
OUT = ROOT / "dist" / "release"
SEP = ";" if os.name == "nt" else ":"


def run(cmd):
    print("->", " ".join(map(str, cmd)))
    subprocess.check_call(cmd, cwd=ROOT)


def pyinstaller(extra):
    sysname = platform.system()
    hidden = ["app_meta", "pcap_glass_ui", "pcap_safe_output", "pcap_plain_fa", "pcap_extra_detect",
              "pcap_fastio", "pcap_protocols", "pcap_extract", "pcap_report_cyber", "pcap_themes", "pcap_threats",
              "pcap_rules_en", "pcap_i18n", "i18n_part_a", "i18n_gui", "i18n_misc",   # i18n_* are imported dynamically
              "PIL._tkinter_finder"]
    cmd = [sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean", "--name", NAME,
           "--collect-submodules", "scapy.layers", "--collect-submodules", "scapy.contrib",
           "--add-data", f"{ROOT / 'assets'}{SEP}assets", "--specpath", str(ROOT / "build")]
    for h in hidden:
        cmd += ["--hidden-import", h]
    for opt in ("brotli", "pyzipper"):
        try:
            __import__(opt)
            cmd += ["--hidden-import", opt]
        except ImportError:
            pass
    icon = {"Windows": "icon.ico", "Darwin": "icon.icns"}.get(sysname)
    if icon and (ROOT / "assets" / icon).exists():
        cmd += ["--icon", str(ROOT / "assets" / icon)]
    cmd += extra + [str(ROOT / "pcap_analyzer.py")]
    run(cmd)


def main():
    sysname, machine = platform.system(), platform.machine().lower()
    arch = "arm64" if machine in ("arm64", "aarch64") else "x64"
    shutil.rmtree(ROOT / "dist" / NAME, ignore_errors=True)
    OUT.mkdir(parents=True, exist_ok=True)
    docs = [ROOT / "README.md", ROOT / "LICENSE"]

    if sysname == "Windows":
        pyinstaller(["--onefile", "--noconsole"])
        dst = OUT / f"{NAME}-windows-{arch}.exe"
        shutil.copy2(ROOT / "dist" / f"{NAME}.exe", dst)
    elif sysname == "Darwin":
        pyinstaller(["--windowed", "--onedir", "--osx-bundle-identifier", f"io.github.{META.GITHUB_USER}.{META.APP_SLUG}"])
        app = ROOT / "dist" / f"{NAME}.app"
        dst = OUT / f"{NAME}-macos-{arch}.zip"
        run(["ditto", "-c", "-k", "--keepParent", str(app), str(dst)])
    else:
        pyinstaller(["--onefile"])
        binp = ROOT / "dist" / NAME
        dst = OUT / f"{NAME}-linux-{arch}.tar.gz"
        with tarfile.open(dst, "w:gz") as tf:
            tf.add(binp, arcname=f"{NAME}/{NAME}")
            for d in docs:
                tf.add(d, arcname=f"{NAME}/{d.name}")
    print("\nbuilt:", dst, f"({dst.stat().st_size / 1e6:.1f} MB)")


if __name__ == "__main__":
    main()
