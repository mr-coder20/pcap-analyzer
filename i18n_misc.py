# -*- coding: utf-8 -*-
"""Small leftovers of the English dictionary."""
UI_EN = {
    "بومی سریع": "native fast",
    "فارسی": "فارسی",
    "ورود FTP بدون رمزنگاری.": "Unencrypted FTP login.",
}
UI_PATTERNS = [
    (r"^🚨 ([\d,]+) رخداد فعال$", r"🚨 \1 active event(s)"),
    (r"^(.+?) از «(.+?)» (\d+) فایل دانلود کرد \(([\d,]+) بایت\): (.*?) — ⚠️ (\d+) مورد اجرایی/پرخطر$",
     r"\1 downloaded \3 file(s) from “\2” (\4 bytes): \5 — ⚠️ \6 executable/risky"),
    (r"^(.+?) از «(.+?)» (\d+) فایل دانلود کرد \(([\d,]+) بایت\): (.*)$",
     r"\1 downloaded \3 file(s) from “\2” (\4 bytes): \5"),
]
UI_EN.update({
    "بدون رخداد": "no events",
    "⚪ بدون رخداد": "⚪ no events",
    "⚠ اجرایی/پرخطر — فقط در VM باز کنید": "⚠ executable/risky — open only in a VM",
    "# فیلتر دامنه‌های مشکوک، گیت‌های تغییر مسیر و تونلینگ:": "# Filter for suspicious domains, redirect gates and tunneling:",
    "# فیلتر شکار فایل‌های اجرایی، فلش (SWF) و درخواست‌های وب در Wireshark:": "# Wireshark hunting filter for executables, Flash (SWF) and web requests:",
})
