# -*- coding: utf-8 -*-
"""
pcap_extract — استخراج کامل و دقیق فایل‌های منتقل‌شده + بسته‌بندی در ZIP
=========================================================================
• تشخیص نوع واقعی فایل با magic bytes (نه فقط پسوند)، دسته‌بندی، آنتروپی، پرچم خطر
• تعیین نام فایل: Content-Disposition (RFC 6266/5987) ← مسیر URL ← نوع محتوا
• ذخیره‌ی همه‌ی فایل‌ها با «نام اصلی» در یک ZIP (AES-256 با رمز «infected» اگر pyzipper نصب باشد)
  + MANIFEST.json / MANIFEST.csv / README.txt داخل ZIP و کنار آن (بدون نیاز به باز کردن ZIP)
• پیش‌نمایش امن (متن/هگز/تصویر کوچک) برای گزارش HTML

Author: mr-coder20 · https://github.com/mr-coder20/pcap-analyzer · MIT
"""
from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import math
import os
import re
import time
import zipfile
import zlib
from urllib.parse import unquote

try:
    import pyzipper  # type: ignore
    HAS_PYZIPPER = True
except ImportError:  # pragma: no cover
    pyzipper = None
    HAS_PYZIPPER = False

from pcap_safe_output import _xor_bytes, XOR_MAGIC  # noqa: E402  (ظرف خنثی حالت بدون pyzipper)

# ================================================================================================
#  تشخیص نوع فایل
# ================================================================================================
CATEGORIES = {
    "executable": "برنامه اجرایی", "script": "اسکریپت / میان‌بر", "archive": "آرشیو / فشرده",
    "document": "سند / آفیس", "image": "تصویر", "media": "صوت / ویدیو", "web": "وب (HTML/JS/CSS/JSON)",
    "text": "متن", "font": "فونت", "database": "پایگاه‌داده", "capture": "ضبط شبکه", "data": "داده خام", "email": "ایمیل",
}
RISKY_CATEGORIES = {"executable", "script"}
RISKY_EXT = {".exe", ".dll", ".sys", ".scr", ".com", ".msi", ".bat", ".cmd", ".ps1", ".psm1", ".vbs", ".vbe", ".js",
             ".jse", ".wsf", ".wsh", ".hta", ".lnk", ".jar", ".swf", ".iso", ".img", ".apk", ".dex", ".elf", ".so",
             ".docm", ".xlsm", ".pptm", ".sh", ".py", ".pl", ".reg", ".cpl", ".msc", ".vhd", ".cab"}
COMPRESSED_EXT = {".zip", ".jar", ".docx", ".xlsx", ".pptx", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".png", ".jpg",
                  ".jpeg", ".gif", ".webp", ".mp3", ".mp4", ".mkv", ".webm", ".ogg", ".woff", ".woff2", ".apk", ".cab"}

MIME_EXT = {
    "text/html": ".html", "text/css": ".css", "text/plain": ".txt", "text/xml": ".xml", "application/xml": ".xml",
    "application/json": ".json", "application/javascript": ".js", "text/javascript": ".js", "application/x-javascript": ".js",
    "image/png": ".png", "image/jpeg": ".jpg", "image/gif": ".gif", "image/webp": ".webp", "image/svg+xml": ".svg",
    "image/x-icon": ".ico", "image/vnd.microsoft.icon": ".ico", "image/bmp": ".bmp", "application/pdf": ".pdf",
    "application/zip": ".zip", "application/x-zip-compressed": ".zip", "application/gzip": ".gz",
    "application/x-gzip": ".gz", "application/x-msdownload": ".exe", "application/x-dosexec": ".exe",
    "application/octet-stream": ".bin", "application/x-shockwave-flash": ".swf", "application/java-archive": ".jar",
    "audio/mpeg": ".mp3", "video/mp4": ".mp4", "application/x-7z-compressed": ".7z", "application/vnd.rar": ".rar",
    "application/x-rar-compressed": ".rar", "application/msword": ".doc", "application/vnd.ms-excel": ".xls",
    "application/rtf": ".rtf", "font/woff": ".woff", "font/woff2": ".woff2", "application/wasm": ".wasm",
    "application/x-www-form-urlencoded": ".txt", "text/csv": ".csv", "application/x-msi": ".msi",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": ".docx",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": ".xlsx",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation": ".pptx",
}


def _pe_kind(d):
    try:
        e = int.from_bytes(d[0x3C:0x40], "little")
        if d[e:e + 4] != b"PE\x00\x00":
            return None
        ch = int.from_bytes(d[e + 22:e + 24], "little")
        if ch & 0x2000:
            return "PE DLL", ".dll"
        sub = int.from_bytes(d[e + 24 + 68:e + 24 + 70], "little") if len(d) > e + 94 else 0
        if sub == 1:
            return "PE Driver (sys)", ".sys"
        return "PE EXE", ".exe"
    except Exception:
        return None


def sniff_type(data: bytes, name: str = "", mime: str = ""):
    """(label, category, ext, flags[])  — ext پسوند پیشنهادی بر مبنای محتوا"""
    d = data[:4096]
    flags = []
    n = len(data)
    if n == 0:
        return "Empty", "data", "", flags
    if d[:2] == b"MZ":
        k = _pe_kind(d)
        if k:
            return k[0], "executable", k[1], flags
        return "DOS/MZ executable", "executable", ".exe", flags
    if d[:4] == b"\x7fELF":
        return "ELF executable", "executable", ".elf", flags
    if d[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf"):
        return "Mach-O executable", "executable", ".macho", flags
    if d[:4] == b"\xca\xfe\xba\xbe":
        return ("Java class" if int.from_bytes(d[6:8], "big") >= 44 else "Mach-O universal"), "executable", ".class", flags
    if d[:3] in (b"FWS", b"CWS", b"ZWS"):
        return "Flash SWF", "executable", ".swf", flags
    if d[:4] == b"dex\n":
        return "Android DEX", "executable", ".dex", flags
    if d[:4] == b"MSCF":
        return "Microsoft CAB", "archive", ".cab", flags
    if d[:4] == b"PK\x03\x04" or d[:4] == b"PK\x05\x06":
        head = data[:min(n, 262144)]
        if b"AndroidManifest.xml" in head:
            return "Android APK", "executable", ".apk", flags
        if b"META-INF/MANIFEST.MF" in head or b"META-INF/" in head[:2000]:
            return "Java JAR", "executable", ".jar", flags
        if b"word/" in head:
            if b"vbaProject.bin" in head:
                flags.append("macro")
            return "Word DOCX" + (" (macro)" if flags else ""), "document", ".docm" if flags else ".docx", flags
        if b"xl/" in head:
            if b"vbaProject.bin" in head:
                flags.append("macro")
            return "Excel XLSX" + (" (macro)" if flags else ""), "document", ".xlsm" if flags else ".xlsx", flags
        if b"ppt/" in head:
            return "PowerPoint PPTX", "document", ".pptx", flags
        return "ZIP archive", "archive", ".zip", flags
    if d[:6] == b"7z\xbc\xaf\x27\x1c":
        return "7-Zip archive", "archive", ".7z", flags
    if d[:4] == b"Rar!":
        return "RAR archive", "archive", ".rar", flags
    if d[:2] == b"\x1f\x8b":
        return "GZIP", "archive", ".gz", flags
    if d[:3] == b"BZh":
        return "BZIP2", "archive", ".bz2", flags
    if d[:6] == b"\xfd7zXZ\x00":
        return "XZ", "archive", ".xz", flags
    if d[257:262] == b"ustar":
        return "TAR archive", "archive", ".tar", flags
    if d[:5] == b"%PDF-":
        if b"/JavaScript" in data[:200000] or b"/JS" in data[:200000] or b"/Launch" in data[:200000]:
            flags.append("active-content")
        return "PDF document", "document", ".pdf", flags
    if d[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        if b"VBA" in data[:600000] or b"_VBA_PROJECT" in data[:600000]:
            flags.append("macro")
        return "OLE2 (DOC/XLS/PPT/MSI)", "document", ".doc", flags
    if d[:5] == b"{\\rtf":
        return "RTF document", "document", ".rtf", flags
    if d[:8] == b"\x89PNG\r\n\x1a\n":
        return "PNG image", "image", ".png", flags
    if d[:3] == b"\xff\xd8\xff":
        return "JPEG image", "image", ".jpg", flags
    if d[:6] in (b"GIF87a", b"GIF89a"):
        return "GIF image", "image", ".gif", flags
    if d[:2] == b"BM" and n > 30:
        return "BMP image", "image", ".bmp", flags
    if d[:4] == b"RIFF" and d[8:12] == b"WEBP":
        return "WEBP image", "image", ".webp", flags
    if d[:4] == b"\x00\x00\x01\x00":
        return "ICO icon", "image", ".ico", flags
    if d[:4] in (b"II*\x00", b"MM\x00*"):
        return "TIFF image", "image", ".tif", flags
    if d[:4] == b"RIFF" and d[8:12] == b"WAVE":
        return "WAV audio", "media", ".wav", flags
    if d[:3] == b"ID3" or d[:2] in (b"\xff\xfb", b"\xff\xf3", b"\xff\xf2"):
        return "MP3 audio", "media", ".mp3", flags
    if d[4:8] == b"ftyp":
        return "MP4/MOV video", "media", ".mp4", flags
    if d[:4] == b"\x1a\x45\xdf\xa3":
        return "Matroska/WebM video", "media", ".mkv", flags
    if d[:4] == b"OggS":
        return "OGG media", "media", ".ogg", flags
    if d[:3] == b"FLV":
        return "FLV video", "media", ".flv", flags
    if d[:4] == b"wOFF" or d[:4] == b"wOF2":
        return "WOFF font", "font", ".woff", flags
    if d[:4] in (b"\x00\x01\x00\x00", b"OTTO", b"true"):
        return "TrueType/OpenType font", "font", ".ttf", flags
    if d[:15] == b"SQLite format 3":
        return "SQLite database", "database", ".sqlite", flags
    if d[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x0a\x0d\x0d\x0a"):
        return "PCAP capture", "capture", ".pcap", flags
    if d[:4] == b"L\x00\x00\x00" and d[4:20] == b"\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00F":
        return "Windows shortcut (LNK)", "script", ".lnk", flags
    if d[:8] == b"\x00asm\x01\x00\x00\x00"[:8]:
        return "WebAssembly", "executable", ".wasm", flags
    if d[:4] == b"CD001" or data[0x8001:0x8006] == b"CD001":
        return "ISO 9660 image", "archive", ".iso", flags
    # ----- متنی‌ها
    sample = d[:2048]
    textish = _is_text(sample)
    if textish:
        try:
            t = sample.decode("utf-8", "ignore").lstrip("﻿ \t\r\n").lower()
        except Exception:
            t = ""
        if t.startswith(("<!doctype html", "<html", "<head", "<body", "<!--")) or "<html" in t[:300]:
            return "HTML", "web", ".html", flags
        if t.startswith("<?xml") or t.startswith("<rss") or t.startswith("<feed"):
            return "XML", "web", ".xml", flags
        if t.startswith("<svg") or "<svg" in t[:300]:
            return "SVG image", "image", ".svg", flags
        if t.startswith("#!"):
            return "Shell script", "script", ".sh", flags
        if t.startswith(("from:", "received:", "return-path:", "mime-version:", "message-id:")):
            return "E-mail (RFC822)", "email", ".eml", flags
        if t[:1] in "{[" and re.match(r'^[\[{]\s*["\[{\d-]', t):
            return "JSON", "web", ".json", flags
        ext = os.path.splitext(name)[1].lower()
        if ext in (".js", ".jse", ".mjs"):
            return "JavaScript", "script" if ext == ".jse" else "web", ".js", flags
        if ext == ".css" or re.match(r"^[\w.#@\[:*,>~ -]+\s*\{", t):
            return "CSS", "web", ".css", flags
        if ext in (".ps1", ".psm1") or "param(" in t[:400] or "invoke-expression" in t[:1500] or "[system." in t[:1500]:
            return "PowerShell script", "script", ".ps1", flags
        if ext in (".vbs", ".vbe") or "wscript.shell" in t[:1500] or "createobject(" in t[:1500]:
            return "VBScript", "script", ".vbs", flags
        if ext in (".bat", ".cmd") or t.startswith("@echo off"):
            return "Batch script", "script", ".bat", flags
        if ext == ".hta":
            return "HTA application", "script", ".hta", flags
        if "function(" in t[:800] or "var " in t[:300] or "document." in t[:800] or "=>" in t[:300]:
            return "JavaScript", "web", ".js", flags
        if ext in (".csv",):
            return "CSV", "text", ".csv", flags
        return "Text", "text", ".txt", flags
    return "Binary data", "data", "", flags


def _is_text(sample: bytes) -> bool:
    if not sample:
        return False
    if b"\x00" in sample:
        # UTF-16 با BOM
        return sample[:2] in (b"\xff\xfe", b"\xfe\xff") and sample.count(b"\x00") < len(sample) * 0.6
    bad = sum(1 for b in sample if b < 9 or (13 < b < 32) or b == 127)
    if bad > len(sample) * 0.02:
        return False
    try:
        sample.decode("utf-8")
        return True
    except UnicodeDecodeError:
        high = sum(1 for b in sample if b > 126)
        return high < len(sample) * 0.30


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    d = data[:65536]
    cnt = [0] * 256
    for b in d:
        cnt[b] += 1
    ln = len(d)
    return -sum((c / ln) * math.log2(c / ln) for c in cnt if c)


# ================================================================================================
#  نام فایل
# ================================================================================================
_BAD_CH = re.compile(r'[\x00-\x1f<>:"|?*\\]')
_WIN_RESERVED = {"con", "prn", "aux", "nul", *(f"com{i}" for i in range(1, 10)), *(f"lpt{i}" for i in range(1, 10))}


def safe_name(name: str, default: str = "file", maxlen: int = 120) -> str:
    """نام امن برای ZIP / فایل‌سیستم: بدون ../، بدون کاراکتر ممنوع ویندوز، حفظ پسوند."""
    name = (name or "").replace("\\", "/").split("/")[-1]
    name = _BAD_CH.sub("_", name).strip(" .")
    if not name:
        name = default
    stem, ext = os.path.splitext(name)
    if stem.lower() in _WIN_RESERVED:
        stem = "_" + stem
    if len(stem) + len(ext) > maxlen:
        stem = stem[:max(8, maxlen - len(ext))]
    return stem + ext


def _safe_dir(name: str) -> str:
    n = _BAD_CH.sub("_", (name or "").replace("/", "_")).strip(" .") or "unknown"
    return n[:60]


def filename_from_headers(headers: dict, uri: str, ctype: str = "", method: str = "GET"):
    """
    (name, source) — source ∈ content-disposition | uri | content-type | default
    """
    cd = headers.get("content-disposition", "")
    if cd:
        m = re.search(r"filename\*\s*=\s*([\w-]+)'[^']*'([^;]+)", cd, re.I)
        if m:
            try:
                return unquote(m.group(2).strip().strip('"'), encoding=m.group(1) or "utf-8"), "content-disposition"
            except (LookupError, UnicodeError):
                pass
        m = re.search(r'filename\s*=\s*"([^"]*)"', cd, re.I) or re.search(r"filename\s*=\s*([^;]+)", cd, re.I)
        if m and m.group(1).strip():
            raw = m.group(1).strip()
            try:                       # برخی سرورها نام UTF-8 را خام می‌فرستند
                raw = raw.encode("latin-1").decode("utf-8")
            except (UnicodeError, ValueError):
                pass
            return unquote(raw), "content-disposition"
    path = (uri or "").split("#", 1)[0].split("?", 1)[0]
    last = unquote(path.rstrip("/").rsplit("/", 1)[-1]) if path and path != "/" else ""
    if last and not path.endswith("/"):
        return last, "uri"
    mime = (ctype or "").split(";", 1)[0].strip().lower()
    ext = MIME_EXT.get(mime, "")
    base = "index" if (path.endswith("/") or path in ("", "/")) else "download"
    return base + (ext or ""), "content-type"


# ================================================================================================
#  پیش‌نمایش
# ================================================================================================
def make_preview(data: bytes, label: str, category: str, img_budget=None):
    """{'k': 'text'|'hex'|'image', 'v': str}"""
    if img_budget is None:
        img_budget = [0]
    if category == "image" and label.split()[0] in ("PNG", "JPEG", "GIF", "WEBP", "BMP", "ICO") and len(data) <= 70000 \
            and img_budget[0] > len(data) * 1.4:
        img_budget[0] -= int(len(data) * 1.4)
        mime = {"PNG": "image/png", "JPEG": "image/jpeg", "GIF": "image/gif", "WEBP": "image/webp",
                "BMP": "image/bmp", "ICO": "image/x-icon"}[label.split()[0]]
        return {"k": "image", "v": f"data:{mime};base64," + base64.b64encode(data).decode("ascii")}
    if category in ("web", "text", "script", "email") or (label == "SVG image"):
        t = data[:1800].decode("utf-8", "replace")
        return {"k": "text", "v": t + ("\n…" if len(data) > 1800 else "")}
    chunk = data[:192]
    lines = []
    for i in range(0, len(chunk), 16):
        row = chunk[i:i + 16]
        lines.append("%08x  %-47s  %s" % (i, " ".join("%02x" % b for b in row),
                                           "".join(chr(b) if 32 <= b < 127 else "." for b in row)))
    return {"k": "hex", "v": "\n".join(lines) + ("\n…" if len(data) > 192 else "")}


# ================================================================================================
#  ذخیره‌ساز: ZIP با نام اصلی فایل‌ها
# ================================================================================================
class FileStore:
    """
    store = FileStore(out_dir, "capture", password="infected")
    rec = store.add(data, name, proto="HTTP", host="example.com", meta={...})
    store.close()  → ZIP نهایی + MANIFEST
    """
    ZIP_NAME_FMT = "{base}_extracted_files.zip"

    def __init__(self, out_dir, base, password="infected", max_files=30000, max_total=1 << 30, max_file=256 << 20):
        self.out_dir = out_dir
        self.base = base
        self.password = (password or "infected").encode("utf-8")
        self.max_files = max_files
        self.max_total = max_total
        self.max_file = max_file
        self.records = []
        self.total = 0
        self.skipped = 0
        self.zip_path = os.path.join(out_dir, self.ZIP_NAME_FMT.format(base=base))
        self._zf = None
        self._names = set()
        self._sha_names = {}
        self.mode = "aes" if HAS_PYZIPPER else "plain"
        self.closed = False
        self.entries = []
        self._img_budget = [3 * 1024 * 1024]

    # ---------------------------------------------------------------- zip
    def _open(self):
        if self._zf is not None:
            return
        os.makedirs(self.out_dir, exist_ok=True)
        if self.mode == "aes":
            self._zf = pyzipper.AESZipFile(self.zip_path, "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES)
            self._zf.setpassword(self.password)
            self._zf.setencryption(pyzipper.WZ_AES, nbits=256)
        else:
            self._zf = zipfile.ZipFile(self.zip_path, "w", zipfile.ZIP_DEFLATED)

    @staticmethod
    def _dt(ts):
        try:
            t = time.gmtime(float(ts))
            if t.tm_year < 1980:
                return (1980, 1, 1, 0, 0, 0)
            return (t.tm_year, t.tm_mon, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec)
        except Exception:
            return (1980, 1, 1, 0, 0, 0)

    def _unique(self, path):
        if path.lower() not in self._names:
            self._names.add(path.lower())
            return path
        stem, ext = os.path.splitext(path)
        i = 2
        while f"{stem} ({i}){ext}".lower() in self._names:
            i += 1
        p = f"{stem} ({i}){ext}"
        self._names.add(p.lower())
        return p


    def _zinfo(self, arc, ts):
        # pyzipper's AESZipFile.writestr only accepts ITS OWN zipinfo class (self._zf.zipinfo_cls);
        # passing pyzipper.ZipInfo / zipfile.ZipInfo raises and silently downgraded to plain mode.
        cls = getattr(self._zf, "zipinfo_cls", None) or zipfile.ZipInfo
        return cls(arc, self._dt(ts))

    def _write(self, arc, payload, ts, rec, path_ext, cat):
        comp = zipfile.ZIP_STORED if (path_ext in COMPRESSED_EXT or cat in ("image", "media", "archive")
                                      or rec["entropy"] > 7.5) else zipfile.ZIP_DEFLATED
        for attempt in (1, 2):
            try:
                self._open()
                zi = self._zinfo(arc, ts)
                zi.compress_type = comp
                zi.external_attr = 0o444 << 16
                self._zf.writestr(zi, payload)
                return True
            except Exception:
                if attempt == 1 and self.mode == "aes" and not self.records:
                    # pyzipper مشکل داشت و هنوز چیزی ننوشته‌ایم → حالت ساده + ظرف خنثی
                    try:
                        if self._zf:
                            self._zf.close()
                    except Exception:
                        pass
                    self._zf = None
                    self.mode = "plain"
                    continue
                return False
        return False

    # ---------------------------------------------------------------- add
    def add(self, data: bytes, name: str, proto: str, host: str = "", meta: dict | None = None):
        meta = dict(meta or {})
        if self.closed or not data:
            return None
        if len(self.records) >= self.max_files or self.total + len(data) > self.max_total:
            self.skipped += 1
            return None
        if len(data) > self.max_file:
            data = data[:self.max_file]
            meta.setdefault("flags", []).append("truncated-size-cap")
        name = safe_name(name)
        label, cat, ext, sflags = sniff_type(data, name, meta.get("mime", ""))
        sha256 = hashlib.sha256(data).hexdigest()
        # دوبارگی دقیق (همان نام + همان محتوا) فقط یک‌بار در ZIP می‌آید
        dup = self._sha_names.get((sha256, name.lower(), proto, host))
        if dup is not None:
            self.records[dup].setdefault("dups", 0)
            self.records[dup]["dups"] += 1
            return self.records[dup]
        path_ext = os.path.splitext(name)[1].lower()
        mismatch = bool(ext and path_ext and ext != path_ext and not _ext_equiv(ext, path_ext) and cat != "text"
                        and cat not in ("web",) and label not in ("Text", "Binary data"))
        risky = cat in RISKY_CATEGORIES or path_ext in RISKY_EXT or "macro" in sflags or "active-content" in sflags
        rec = {
            "id": len(self.records) + 1, "name": name, "proto": proto, "host": host,
            "size": len(data), "sha256": sha256, "md5": hashlib.md5(data).hexdigest(),
            "sha1": hashlib.sha1(data).hexdigest(), "crc32": "%08x" % (zlib.crc32(data) & 0xFFFFFFFF),
            "type": label, "category": cat, "category_fa": CATEGORIES.get(cat, cat), "ext_real": ext,
            "mismatch": mismatch, "risky": risky, "entropy": round(entropy(data), 2),
            "flags": list(meta.pop("flags", [])) + sflags, "preview": make_preview(data, label, cat, self._img_budget),
        }
        rec.update(meta)
        if mismatch:
            rec["flags"].append("ext-mismatch")
        # ---- مسیر داخل ZIP
        folder = f"{proto}/{_safe_dir(host)}" if host else proto
        arc = self._unique(f"{folder}/{name}")
        rec["zip_path"] = arc
        store_data, store_arc = data, arc
        if self.mode == "plain" and risky:                 # بدون pyzipper: ظرف خنثی تا AV پاک نکند
            store_data = XOR_MAGIC + _xor_bytes(data)
            store_arc = arc + ".sample"
            rec["zip_path"] = store_arc
            rec["flags"].append("xor-container")
        if not self._write(store_arc, store_data, meta.get("ts"), rec, path_ext, cat):
            self.skipped += 1
            rec["flags"].append("zip-error")
            rec["zip_path"] = None
        self.total += len(data)
        self.records.append(rec)
        self._sha_names[(sha256, name.lower(), proto, host)] = len(self.records) - 1
        return rec

    # ---------------------------------------------------------------- close
    def manifest(self):
        keep = ("id", "name", "zip_path", "proto", "host", "url", "direction", "src", "dst", "ts_str", "size", "type",
                "category", "mime", "name_source", "sha256", "md5", "sha1", "crc32", "entropy", "risky", "mismatch", "flags", "note")
        return [{k: r.get(k) for k in keep} for r in self.records]

    def close(self):
        if self.closed:
            return None
        self.closed = True
        if not self.records:
            if self._zf:
                self._zf.close()
            return None
        man = self.manifest()
        text_json = json.dumps({"tool": "PCAP Analyzer", "files": man}, ensure_ascii=False, indent=2, default=str)
        buf = io.StringIO()
        wr = csv.writer(buf)
        cols = list(man[0].keys())
        wr.writerow(cols)
        for r in man:
            wr.writerow([";".join(map(str, r[c])) if isinstance(r[c], list) else r[c] for c in cols])
        readme = (
            "PCAP Analyzer — extracted files\n================================\n"
            f"Files: {len(self.records)}   Total: {self.total:,} bytes\n"
            + (f"Password: {self.password.decode()}  (AES-256)\n" if self.mode == "aes" else
               "Dangerous files are stored as *.sample (neutral container). Restore with: "
               "python pcap_analyzer.py --restore FILE.sample\n")
            + "WARNING: open only inside a virtual machine / sandbox. Several files may be malware.\n"
            "MANIFEST.csv / MANIFEST.json list every file with URL, hashes and type.\n"
        )
        try:
            for nm, payload in (("MANIFEST.json", text_json), ("MANIFEST.csv", buf.getvalue()), ("README.txt", readme)):
                zi = self._zinfo(nm, time.time())
                zi.compress_type = zipfile.ZIP_DEFLATED
                self._zf.writestr(zi, payload.encode("utf-8"))
            info = {i.filename: i for i in self._zf.infolist()}
        except Exception:
            info = {}
        finally:
            try:
                self._zf.close()
            except Exception:
                pass
        for r in self.records:
            zi = info.get(r.get("zip_path") or "")
            if zi is not None:
                r["packed"] = zi.compress_size
        for suffix, payload in (("manifest.json", text_json), ("manifest.csv", buf.getvalue())):
            try:
                with open(os.path.join(self.out_dir, f"{self.base}_extracted_{suffix}"), "w", encoding="utf-8", newline="") as fh:
                    fh.write(payload)
            except OSError:
                pass
        return self.zip_path

    def summary(self):
        by_cat = {}
        for r in self.records:
            c = by_cat.setdefault(r["category"], {"count": 0, "bytes": 0})
            c["count"] += 1
            c["bytes"] += r["size"]
        return {"zip": os.path.basename(self.zip_path) if self.records else None, "zip_abs": self.zip_path if self.records else None,
                "mode": self.mode, "password": self.password.decode() if self.mode == "aes" else None,
                "count": len(self.records), "bytes": self.total, "skipped": self.skipped, "by_category": by_cat,
                "risky": sum(1 for r in self.records if r["risky"])}


def _ext_equiv(a, b):
    groups = [{".jpg", ".jpeg", ".jpe"}, {".htm", ".html", ".xhtml", ".php", ".asp", ".aspx", ".jsp"}, {".tif", ".tiff"},
              {".doc", ".dot"}, {".exe", ".dll", ".scr", ".sys", ".com", ".cpl"}, {".js", ".mjs", ".jse"},
              {".zip", ".jar", ".docx", ".xlsx", ".pptx", ".apk", ".docm", ".xlsm", ".pptm", ".xpi", ".odt", ".ods"},
              {".gz", ".tgz"}, {".mp4", ".m4v", ".mov", ".m4a"}, {".mkv", ".webm"}, {".sqlite", ".db", ".sqlite3"},
              {".txt", ".log", ".conf", ".ini", ".csv", ".md"}, {".pcap", ".pcapng", ".cap"}, {".bin", ".dat"}]
    return any(a in g and b in g for g in groups)
