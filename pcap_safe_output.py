# -*- coding: utf-8 -*-
"""
pcap_safe_output — ذخیره‌سازی امن خروجی‌ها در ویندوز / مک / لینوکس
=================================================================
مشکل: وقتی تحلیلگر یک فایل مخرب (EXE / SWF / ماکرو ...) را از PCAP بیرون می‌کشد و روی
دیسک می‌نویسد، آنتی‌ویروس (Windows Defender و ...) فوراً آن را پاک یا قرنطینه می‌کند.

راه‌حل چندلایه (به ترتیب امنیت):
  1) zip  : هر نمونه داخل ZIP رمزدار AES-256 با رمز «infected» (استاندارد دنیای تحلیل بدافزار).
            آنتی‌ویروس محتوای رمزشده را نمی‌بیند، پس پاک نمی‌کند. (نیاز به: pip install pyzipper)
  2) xor  : اگر pyzipper نبود، نمونه با یک «ظرف خنثی» (.sample) ذخیره می‌شود که بدون هیچ
            وابستگی با دستور  --restore  به فایل اصلی برمی‌گردد.
  3) raw  : ذخیره خام (فقط با اجازه صریح کاربر). در ویندوز برای جلوگیری از حذف، می‌توان —
            فقط با تأیید کاربر و UAC — «پوشه خروجی اختصاصی» را به استثناهای Defender اضافه کرد
            و در پایان کار آن را برداشت.

اصول ایمنی این ماژول:
  • هیچ استثنایی بدون پرسیدن و گرفتن تأیید صریح کاربر اضافه نمی‌شود.
  • فقط یک پوشه اختصاصی (دارای فایل نشانه) استثنا می‌شود؛ نه درایو، نه Desktop/Downloads/Windows.
  • هیچ‌وقت خود فایل نمونه یا پوشه‌های عمومی سیستم استثنا نمی‌شوند.
  • همه استثناهای ثبت‌شده در یک فایل وضعیت نگهداری می‌شوند تا با --cleanup-exclusions برداشته شوند.
  • دستور PowerShell بدون -EncodedCommand و بدون دور زدن ExecutionPolicy اجرا می‌شود (شفاف و قابل‌ممیزی).
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import stat
import subprocess
import sys
import time
from pathlib import Path

try:
    import pyzipper  # type: ignore
    HAS_PYZIPPER = True
except ImportError:  # pragma: no cover
    pyzipper = None
    HAS_PYZIPPER = False

SYSTEM = platform.system()                      # "Windows" | "Darwin" | "Linux"
IS_WINDOWS = SYSTEM == "Windows"
IS_MAC = SYSTEM == "Darwin"
IS_LINUX = SYSTEM == "Linux"
NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

ZIP_PASSWORD = b"infected"
XOR_MAGIC = b"SOCQ1\x00"
XOR_KEY = hashlib.sha256(b"pcap-analyzer/quarantine/v1").digest()
MARKER_NAME = ".pcap_analyzer_output"
STATE_DIR = Path.home() / ".pcap_analyzer"
STATE_FILE = STATE_DIR / "exclusions.json"


# ---------------------------------------------------------------------------
# ابزارهای عمومی
# ---------------------------------------------------------------------------
def is_admin() -> bool:
    try:
        if IS_WINDOWS:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
        return False


def defang(value: str) -> str:
    """بی‌خطر کردن IOC برای اشتراک‌گذاری: http→hxxp و نقطه→[.]  (هش‌ها دست‌نخورده می‌مانند)."""
    v = str(value)
    if re.fullmatch(r"[0-9a-fA-F]{32,128}", v) or v.upper().startswith(("SHA256:", "JA3:", "JA3S:", "MD5:")):
        return v
    v = re.sub(r"(?i)\bhttp(s?)://", lambda m: f"hxxp{m.group(1)}://", v)
    v = re.sub(r"(?<=\w)\.(?=\w)", "[.]", v)
    return v


def _risky_path_reason(p: Path) -> str | None:
    """اگر مسیر برای استثنا بیش از حد گسترده یا خطرناک باشد، دلیلش را برمی‌گرداند."""
    try:
        rp = p.resolve()
    except OSError:
        return "مسیر قابل تفسیر نیست"
    parts = [x for x in rp.parts if x not in (rp.anchor,)]
    if len(parts) < 2:
        return "مسیر خیلی کلی است (ریشه درایو یا پوشه سطح‌بالا)"
    home = Path.home().resolve()
    protected = {home, home / "Desktop", home / "Documents", home / "Downloads", home / "AppData",
                 Path(os.environ.get("TEMP", "/tmp")).resolve(), Path(os.environ.get("SystemRoot", "C:\\Windows")),
                 Path(os.environ.get("ProgramFiles", "C:\\Program Files")),
                 Path(os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)"))}
    if rp in protected:
        return "این پوشه عمومی/سیستمی است؛ باید پوشه اختصاصی ساخته شود"
    low = str(rp).lower()
    for bad in ("\\windows", "\\system32", "\\program files", "/usr", "/bin", "/etc", "/system", "/library"):
        if low.endswith(bad) or (bad + "\\") in low or (bad + "/") in low:
            return "داخل مسیرهای سیستمی است"
    return None


def prepare_output_dir(path: str | os.PathLike) -> str:
    """ساخت پوشه خروجی اختصاصی + فایل نشانه (برای اینکه فقط همین پوشه استثنا شود)."""
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    marker = p / MARKER_NAME
    if not marker.exists():
        marker.write_text("Created by PCAP Analyzer. Dedicated output folder.\n", encoding="utf-8")
    return str(p)


def lock_file(path: str) -> None:
    """فایل نمونه را فقط‌خواندنی و غیرقابل‌اجرا می‌کند (جلوگیری از دابل‌کلیک اتفاقی)."""
    try:
        os.chmod(path, stat.S_IREAD if IS_WINDOWS else 0o440)
    except OSError:
        pass


def verify_files(paths, wait: float = 2.5) -> list[str]:
    """چند ثانیه صبر می‌کند و فایل‌هایی را که آنتی‌ویروس پاک کرده برمی‌گرداند."""
    time.sleep(wait)
    return [p for p in paths if p and not os.path.exists(p)]


# ---------------------------------------------------------------------------
# ذخیره امن نمونه‌ها
# ---------------------------------------------------------------------------
def _xor_bytes(data: bytes) -> bytes:
    if not data:
        return b""
    key = (XOR_KEY * (len(data) // len(XOR_KEY) + 1))[:len(data)]
    n = len(data)
    return (int.from_bytes(data, "big") ^ int.from_bytes(key, "big")).to_bytes(n, "big")


def restore_sample(path: str, out_path: str | None = None) -> str:
    """بازیابی نمونه ذخیره‌شده با حالت xor (فایل .sample) به فایل اصلی. ⚠️ فقط در محیط ایزوله!"""
    raw = Path(path).read_bytes()
    if not raw.startswith(XOR_MAGIC):
        raise ValueError("این فایل در قالب SOCQ1 نیست.")
    data = _xor_bytes(raw[len(XOR_MAGIC):])
    out = out_path or re.sub(r"\.sample$", ".restored.bin", path)
    Path(out).write_bytes(data)
    return out


class SampleStore:
    """مدیریت ذخیره‌سازی نمونه‌های استخراج‌شده. mode: auto | zip | xor | raw"""

    def __init__(self, directory: str, mode: str = "auto"):
        self.dir = prepare_output_dir(directory)
        if mode == "auto":
            mode = "zip" if HAS_PYZIPPER else "xor"
        if mode == "zip" and not HAS_PYZIPPER:
            mode = "xor"
        self.mode = mode
        self._readme_written = False

    def _write_readme(self):
        if self._readme_written:
            return
        self._readme_written = True
        txt = {
            "zip": "نمونه‌ها داخل ZIP رمزدار (AES-256) هستند. رمز: infected\n"
                   "⚠️ فقط در ماشین مجازی/Sandbox باز کنید.\n",
            "xor": "نمونه‌ها با پسوند .sample و ظرف خنثی ذخیره شده‌اند.\n"
                   "بازیابی: python pcap_analyzer.py --restore <file.sample>\n"
                   "⚠️ فقط در ماشین مجازی/Sandbox بازیابی کنید.\n",
            "raw": "⚠️ نمونه‌ها به‌صورت خام و واقعی ذخیره شده‌اند و خطرناکند. روی آن‌ها دابل‌کلیک نکنید!\n",
        }[self.mode]
        try:
            (Path(self.dir) / "README_SAMPLES.txt").write_text(txt, encoding="utf-8")
        except OSError:
            pass

    def save(self, raw: bytes, sha256: str, ext: str):
        """ذخیره یک نمونه. خروجی: (مسیر، حالت)"""
        self._write_readme()
        ext = ext if ext.startswith(".") else "." + ext
        if self.mode == "zip":
            path = os.path.join(self.dir, f"{sha256}.zip")
            with pyzipper.AESZipFile(path, "w", compression=pyzipper.ZIP_DEFLATED,
                                     encryption=pyzipper.WZ_AES) as zf:
                zf.setpassword(ZIP_PASSWORD)
                zf.writestr(f"{sha256}{ext}", raw)
        elif self.mode == "xor":
            path = os.path.join(self.dir, f"{sha256}{ext}.sample")
            with open(path, "wb") as fh:
                fh.write(XOR_MAGIC + _xor_bytes(raw))
        else:
            path = os.path.join(self.dir, f"{sha256}{ext}.sample_raw")   # پسوند غیرقابل‌اجرا
            with open(path, "wb") as fh:
                fh.write(raw)
        lock_file(path)
        return path, self.mode


def bundle_reports(out_dir: str, files, name: str = "reports_bundle.zip") -> str | None:
    """همه گزارش‌ها در یک ZIP (رمزدار اگر ممکن باشد) برای اشتراک‌گذاری امن با تیم."""
    try:
        path = os.path.join(out_dir, name)
        if HAS_PYZIPPER:
            with pyzipper.AESZipFile(path, "w", compression=pyzipper.ZIP_DEFLATED,
                                     encryption=pyzipper.WZ_AES) as zf:
                zf.setpassword(ZIP_PASSWORD)
                for f in files:
                    if os.path.isfile(f):
                        zf.write(f, os.path.basename(f))
        else:
            import zipfile
            with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
                for f in files:
                    if os.path.isfile(f):
                        zf.write(f, os.path.basename(f))
        return path
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Windows Defender — فقط با اجازه صریح کاربر
# ---------------------------------------------------------------------------
def _ps(script: str, timeout: int = 120, env_extra: dict | None = None):
    """PowerShell را با اسکریپت از stdin اجرا می‌کند (بدون مشکل quoting و بدون EncodedCommand)."""
    env = os.environ.copy()
    env.update(env_extra or {})
    r = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", "-"],
        input=script, capture_output=True, text=True, timeout=timeout,
        creationflags=NO_WINDOW, env=env
    )
    return r.returncode, (r.stdout or "") + (r.stderr or "")


def defender_status() -> dict | None:
    """وضعیت Defender را برمی‌گرداند (None اگر ویندوز نیست یا Defender در دسترس نیست)."""
    if not IS_WINDOWS:
        return None
    try:
        code, out = _ps("Get-MpComputerStatus | Select-Object AMServiceEnabled,RealTimeProtectionEnabled,"
                        "IsTamperProtected | ConvertTo-Json -Compress", timeout=20)
        if code == 0 and out.strip().startswith("{"):
            return json.loads(out.strip())
    except Exception:
        pass
    return None


def _load_state() -> list:
    try:
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except Exception:
        return []


def _save_state(items: list) -> None:
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        STATE_FILE.write_text(json.dumps(items, ensure_ascii=False, indent=2), encoding="utf-8")
    except OSError:
        pass


_EXCLUSION_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$op   = $env:PCAP_EXC_OP
$path = $env:PCAP_EXC_PATH
if ($op -ne 'Add-MpPreference' -and $op -ne 'Remove-MpPreference') { exit 3 }
$q = $path.Replace("'", "''")
$cmd = "$op -ExclusionPath '$q'"
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
try {
  if ($admin) { Invoke-Expression $cmd; exit 0 }
  $p = Start-Process powershell.exe -Verb RunAs -Wait -PassThru -WindowStyle Hidden -ArgumentList '-NoProfile','-NonInteractive','-Command',$cmd
  exit $p.ExitCode
} catch { exit 9 }
"""


def _change_exclusion(path: str, op: str):
    code, out = _ps(_EXCLUSION_SCRIPT, timeout=180, env_extra={"PCAP_EXC_OP": op, "PCAP_EXC_PATH": path})
    if code == 0:
        return True, "انجام شد."
    if code == 9:
        return False, "کاربر دسترسی مدیر (UAC) را تأیید نکرد یا اجرا ممکن نشد."
    return False, f"ویندوز اجازه تغییر نداد (کد {code}). احتمالاً Tamper Protection روشن است یا آنتی‌ویروس دیگری فعال است."


def add_defender_exclusion(path: str):
    """⚠️ فقط پس از تأیید صریح کاربر صدا زده شود."""
    if not IS_WINDOWS:
        return False, "این قابلیت فقط ویندوز است."
    reason = _risky_path_reason(Path(path))
    if reason:
        return False, f"برای امنیت رد شد: {reason}"
    if not (Path(path) / MARKER_NAME).exists():
        return False, "فقط پوشه‌های اختصاصی ساخته‌شده توسط خود برنامه قابل استثنا هستند."
    ok, msg = _change_exclusion(str(Path(path).resolve()), "Add-MpPreference")
    if ok:
        items = _load_state()
        rp = str(Path(path).resolve())
        if rp not in items:
            items.append(rp)
            _save_state(items)
    return ok, msg


def remove_defender_exclusion(path: str):
    if not IS_WINDOWS:
        return False, "این قابلیت فقط ویندوز است."
    ok, msg = _change_exclusion(str(Path(path).resolve()), "Remove-MpPreference")
    if ok:
        rp = str(Path(path).resolve())
        _save_state([x for x in _load_state() if x != rp])
    return ok, msg


def cleanup_all_exclusions():
    """همه استثناهایی را که این برنامه اضافه کرده برمی‌دارد."""
    results = []
    for p in list(_load_state()):
        ok, msg = remove_defender_exclusion(p)
        results.append((p, ok, msg))
    return results


CONSENT_TEXT_FA = (
    "ممکن است Windows Defender فایل‌های مخرب استخراج‌شده را پاک کند.\n\n"
    "برای جلوگیری، می‌توانیم فقط این پوشه را به «استثناهای Defender» اضافه کنیم:\n\n{path}\n\n"
    "• ویندوز یک پنجره تأیید مدیر (UAC) نشان می‌دهد.\n"
    "• تا زمانی که استثنا فعال است، هر فایل داخل این پوشه اسکن نمی‌شود؛ هرگز روی آن‌ها دابل‌کلیک نکنید.\n"
    "• پایان کار، استثنا را برمی‌داریم (یا با --cleanup-exclusions).\n\n"
    "اجازه می‌دهید؟"
)


def request_defender_exclusion(out_dir: str, ask_fn, log=print):
    """
    جریان کامل و امن: بررسی → توضیح ساده → پرسیدن از کاربر → UAC → ثبت.
    ask_fn(title, text) -> bool  (در GUI یک messagebox و در CLI یک prompt)
    """
    if not IS_WINDOWS:
        for line in platform_notes():
            log(line)
        return False
    st = defender_status()
    if st is not None and not st.get("RealTimeProtectionEnabled", True):
        log("ℹ️ حفاظت لحظه‌ای Defender خاموش است؛ نیازی به استثنا نیست.")
        return False
    if st is not None and st.get("IsTamperProtected"):
        log("⚠️ Tamper Protection روشن است؛ ممکن است ویندوز تغییر استثنا را رد کند. "
            "حالت ذخیره امن (zip/xor) توصیه می‌شود.")
    if not ask_fn("اجازه افزودن استثنا به Defender", CONSENT_TEXT_FA.format(path=out_dir)):
        log("⏭️ کاربر اجازه نداد؛ هیچ تغییری در Defender انجام نشد.")
        return False
    ok, msg = add_defender_exclusion(out_dir)
    log(("✅ " if ok else "❌ ") + msg)
    return ok


def platform_notes() -> list[str]:
    """راهنمای ساده مخصوص هر سیستم‌عامل."""
    if IS_WINDOWS:
        return ["🪟 ویندوز: پیش‌فرض ذخیره امن (zip رمزدار) است. اگر ذخیره خام خواستید، برنامه اجازه شما را می‌گیرد "
                "و فقط پوشه خروجی را در Defender استثنا می‌کند."]
    if IS_MAC:
        return ["🍎 مک: Gatekeeper/XProtect فایل‌هایی را که خودِ برنامه می‌نویسد معمولاً حذف نمی‌کند. "
                "نمونه‌ها غیرقابل‌اجرا (chmod 440) ذخیره می‌شوند. اگر آنتی‌ویروس شخص‌ثالث دارید، پوشه خروجی را "
                "دستی در تنظیمات آن استثنا کنید."]
    return ["🐧 لینوکس: ClamAV/On-Access یا EDR سازمانی ممکن است فایل را بردارد. برنامه هیچ تنظیم سیستمی را بدون root "
            "تغییر نمی‌دهد؛ حالت zip/xor توصیه می‌شود. برای استثنا در ClamAV: OnAccessExcludePath در clamd.conf."]
