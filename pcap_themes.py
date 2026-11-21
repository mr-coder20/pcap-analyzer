# -*- coding: utf-8 -*-
"""
pcap_themes — تم‌های «دارک سایبری» مشترک بین گزارش HTML و رابط دسکتاپ
=====================================================================
هر تم یک پالت کامل است. گزارش HTML همه‌ی تم‌ها را داخل خودش دارد و کاربر زنده عوض می‌کند؛
رابط Tk تم انتخاب‌شده را هنگام اجرا می‌خواند (ذخیره در ~/.pcap_analyzer/config.json).

Author: mr-coder20 · https://github.com/mr-coder20/pcap-analyzer · MIT
"""
from __future__ import annotations

import json
from pathlib import Path

# کلیدها: bg (پس‌زمینه) · bg2 · panel · panel2 · line · ink (متن) · mut · dim · acc · acc2 · acc3 · ok · warn · bad · orange
THEMES = {
    "neon-night": {
        "name": "Neon Night", "fa": "شب نئونی", "dark": True,
        "bg": "#05060d", "bg2": "#0a0d1c", "panel": "#0c1126", "panel2": "#121a38", "line": "#1d2a55",
        "ink": "#e8f4ff", "mut": "#8fa3c8", "dim": "#5b6b93",
        "acc": "#00e5ff", "acc2": "#ff2bd6", "acc3": "#7c5cff", "ok": "#22ffa0", "warn": "#ffd23f", "bad": "#ff3b6b", "orange": "#ff8a3d",
    },
    "matrix": {
        "name": "Matrix", "fa": "ماتریکس", "dark": True,
        "bg": "#020804", "bg2": "#04120a", "panel": "#06170d", "panel2": "#0a2314", "line": "#0f4a28",
        "ink": "#d7ffe6", "mut": "#78c99a", "dim": "#3f8460",
        "acc": "#00ff88", "acc2": "#b6ff3b", "acc3": "#00d1ff", "ok": "#00ff88", "warn": "#e6ff3d", "bad": "#ff4466", "orange": "#ffa23d",
    },
    "synthwave": {
        "name": "Synthwave", "fa": "سینت‌ویو", "dark": True,
        "bg": "#0b0418", "bg2": "#140626", "panel": "#1a0a33", "panel2": "#25104a", "line": "#44207f",
        "ink": "#fdeaff", "mut": "#c09be6", "dim": "#8161b0",
        "acc": "#ff4fd8", "acc2": "#37e8ff", "acc3": "#ffb347", "ok": "#3dffb0", "warn": "#ffd84d", "bad": "#ff4d6d", "orange": "#ff9a3d",
    },
    "crimson-ops": {
        "name": "Crimson Ops", "fa": "عملیات سرخ", "dark": True,
        "bg": "#0a0305", "bg2": "#14070a", "panel": "#1b0a0e", "panel2": "#2a1015", "line": "#5a1a26",
        "ink": "#ffe9ec", "mut": "#d09aa4", "dim": "#8a5560",
        "acc": "#ff2e4d", "acc2": "#ff8a3d", "acc3": "#ffd23f", "ok": "#4dffb0", "warn": "#ffd23f", "bad": "#ff2e4d", "orange": "#ff8a3d",
    },
    "amber-terminal": {
        "name": "Amber Terminal", "fa": "ترمینال کهربایی", "dark": True,
        "bg": "#080500", "bg2": "#120b00", "panel": "#171000", "panel2": "#241800", "line": "#5a3d00",
        "ink": "#ffe9b8", "mut": "#d6a84a", "dim": "#8c6a22",
        "acc": "#ffb000", "acc2": "#ff7a00", "acc3": "#ffe14d", "ok": "#9dff4d", "warn": "#ffe14d", "bad": "#ff4d3d", "orange": "#ff7a00",
    },
    "ice-circuit": {
        "name": "Ice Circuit", "fa": "مدار یخی", "dark": True,
        "bg": "#040a12", "bg2": "#08121f", "panel": "#0b1829", "panel2": "#10243b", "line": "#1d4468",
        "ink": "#eaf6ff", "mut": "#8fb4d4", "dim": "#59799a",
        "acc": "#6ad7ff", "acc2": "#a5b4ff", "acc3": "#5effd6", "ok": "#5effb0", "warn": "#ffe066", "bad": "#ff5c7a", "orange": "#ff9d5c",
    },
    "toxic-lime": {
        "name": "Toxic Lime", "fa": "لیموی سمی", "dark": True,
        "bg": "#06080a", "bg2": "#0c1014", "panel": "#10161b", "panel2": "#18222a", "line": "#2c3f2a",
        "ink": "#f2ffe0", "mut": "#a3bd84", "dim": "#667a4f",
        "acc": "#c6ff00", "acc2": "#00e5ff", "acc3": "#ff3df0", "ok": "#53ff9a", "warn": "#ffe14d", "bad": "#ff4d6d", "orange": "#ff9a3d",
    },
    "paper-light": {
        "name": "Paper (Print)", "fa": "کاغذی (چاپ)", "dark": False,
        "bg": "#f4f6fb", "bg2": "#e9edf6", "panel": "#ffffff", "panel2": "#f0f3fa", "line": "#cfd6e6",
        "ink": "#0f172a", "mut": "#475569", "dim": "#64748b",
        "acc": "#0077c8", "acc2": "#c2185b", "acc3": "#5b3df5", "ok": "#0a8f5b", "warn": "#b45309", "bad": "#c81e4a", "orange": "#c2570c",
    },
}
DEFAULT_THEME = "neon-night"
MATERIALS = {
    "glass": ("Glass", "شیشه‌ای مات"),
    "solid": ("Solid", "جامد و سریع"),
    "hologram": ("Hologram", "هولوگرام نئونی"),
    "terminal": ("Terminal", "ترمینال تیز"),
}
DEFAULT_MATERIAL = "glass"
CONFIG_DIR = Path.home() / ".pcap_analyzer"
CONFIG_FILE = CONFIG_DIR / "config.json"


def get_theme(tid):
    return THEMES.get(tid) or THEMES[DEFAULT_THEME]


def tk_palette(tid):
    """پالت مورد انتظار pcap_glass_ui.PAL"""
    t = get_theme(tid)
    return {
        "bg": t["bg"], "ink": t["ink"], "mut": t["mut"], "dim": t["dim"], "acc": t["acc"], "acc2": t["acc2"], "pink": t["acc3"],
        "ok": t["ok"], "warn": t["warn"], "bad": t["bad"], "orange": t["orange"], "well": t["bg2"], "well2": t["panel"],
        "line": t["line"], "glass": t["panel2"],
    }


def theme_css():
    """متغیرهای CSS همه‌ی تم‌ها"""
    out = []
    for tid, t in THEMES.items():
        vars_ = ";".join(f"--{k}:{t[k]}" for k in ("bg", "bg2", "panel", "panel2", "line", "ink", "mut", "dim", "acc", "acc2", "acc3", "ok", "warn", "bad", "orange"))
        out.append(f'html[data-theme="{tid}"]{{{vars_};color-scheme:{"dark" if t["dark"] else "light"}}}')
    return "\n".join(out)


def load_config():
    try:
        return json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def save_config(**kw):
    cfg = load_config()
    cfg.update({k: v for k, v in kw.items() if v is not None})
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        CONFIG_FILE.write_text(json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")
    except OSError:
        pass
    return cfg
