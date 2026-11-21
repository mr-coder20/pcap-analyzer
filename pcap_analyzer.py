#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PCAP Analyzer v8.0 — Offline Forensics, Threat Hunting & Detection Suite
Author: mr-coder20 · https://github.com/mr-coder20/pcap-analyzer · MIT
=========================================================================================
ویژگی‌های ارتقایافته در نسخه ۵.۰ (موتور تمام‌آفلاین بدون وابستگی به اینترنت):
1) حالت دوگانه CLI + GUI: اجرای تمام‌اتوماتیک در خط فرمان (--cli) برای سرورها و اسکریپت‌نویسی + داشبورد دسکتاپ
2) بازسازی دوطرفه TCP + دیکدر خودکار Brotli / Gzip / Deflate / Chunked + استخراج Multipart/Form-Data و پیوست‌ها
3) شکارچی عمیق بدافزارهای استتارشده: رمزگشای خودکار Single-Byte & Multi-Byte XOR، شناسایی PE/ELF/SWF/ZIP/PDF/Office Macro/JAR
4) تحلیلگر تخصصی TLS: استخراج JA3، JA3S، SNI، نسخه پروتکل، گواهی‌های Self-Signed و تشخیص ناهنجاری‌های رمزنگاری
5) موتور تشخیص حملات لایه ۲ تا ۷: DHCP Starvation/Rogue، DNS Tunneling/DGA/NXDOMAIN، SMB/Kerberos/NTLM، RDP، HTTP/2 & Web Exploits
6) موتور تجمیع لاگ‌های SIEM/Sysmon/Linux: پشتیبانی از EVTX-JSON، Syslog، Nginx/Apache، Windows Security/Sysmon و Zeek/Suricata eve.json
7) زرادخانه قوانین دفاعی خودکار: تولید فیلتر Wireshark، قوانین Suricata، قوانین YARA (به همراه هش‌ها و رشته‌های خاص)، Splunk SPL و Elastic KQL
8) گزارش‌ساز تعاملی HTML با داشبورد تاریک، زنجیره کشتار سایبری (Kill Chain)، مدل الماس، هرم درد و تحلیلگر جریان‌ها
9) [جدید v6] ذخیره امن نمونه‌های مخرب (ZIP رمزدار AES) برای ویندوز/مک/لینوکس؛ استثنای Defender فقط با اجازه صریح کاربر
10) [جدید v6] توضیح همه هشدارها به زبان ساده فارسی + حالت «ساده/فنی» در گزارش
11) [جدید v6] ۸ تشخیص جدید + تطبیق آفلاین با فهرست IOC شخصی (--ioc-file) + IOC بی‌خطرشده (Defang)
"""

import argparse
import base64
import collections
import csv
import datetime as dt
import hashlib
import html
import ipaddress
import json
import math
import os
import queue
import re
import shutil
import statistics
import struct
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import webbrowser
import zlib
from pathlib import Path
from urllib.parse import unquote, unquote_plus, unquote_to_bytes

import app_meta as META

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from pcap_safe_output import (
        SampleStore, HAS_PYZIPPER, IS_WINDOWS, defang, prepare_output_dir, verify_files,
        request_defender_exclusion, remove_defender_exclusion, cleanup_all_exclusions,
        restore_sample, bundle_reports, defender_status, platform_notes, is_admin, SYSTEM,
    )
    from pcap_plain_fa import plain_for, plain_summary_html
    from pcap_extra_detect import EXTRA_RULES, ExtraDetectMixin
    from pcap_threats import THREAT_RULES, ThreatMixin
    import pcap_fastio as FIO
    import pcap_themes as THEMES
    import pcap_i18n as I18N
    from pcap_rules_en import RULES_EN
    from pcap_report_cyber import build_cyber_report
    from pcap_plain_fa import VERDICT as PLAIN_VERDICT
    from pcap_protocols import ProtocolHubMixin, ENCRYPTED as HUB_ENCRYPTED
    from pcap_extract import FileStore
except ImportError as _imp_err:  # pragma: no cover
    print(f"[CRITICAL] ماژول‌های همراه برنامه پیدا نشد ({_imp_err}). همه فایل‌های .py را کنار هم نگه دارید.", file=sys.stderr)
    sys.exit(1)

# ---- language: English by default, Persian on request (--lang fa / PCAP_LANG / saved config) ----
def _early_lang():
    for i, a in enumerate(sys.argv):
        if a == "--lang" and i + 1 < len(sys.argv):
            return sys.argv[i + 1]
        if a.startswith("--lang="):
            return a.split("=", 1)[1]
    return None


I18N.init(_early_lang())
_builtin_print = print


def print(*a, **k):                       # noqa: A001 — every CLI message goes through the translator
    _builtin_print(*[I18N.tr(x) if isinstance(x, str) else x for x in a], **k)


def plain_text(f):
    """(what, why, todo) in the active language for a finding dict."""
    if I18N.get_lang() == "en":
        return (f.get("description_en") or f.get("description", ""), "", f.get("recommendation_en") or f.get("recommendation", ""))
    pf = plain_for(f.get("id", ""))
    if pf[0].startswith("الگوی مشکوکی"):
        return (f.get("description_fa") or f.get("description", ""), "", f.get("recommendation_fa") or f.get("recommendation", ""))
    return pf


DEFANG_REPORT = True   # IOCها در HTML/TXT بی‌خطر (defang) نوشته شوند

try:
    import brotli
    HAS_BROTLI = True
except ImportError:
    HAS_BROTLI = False

try:
    from scapy.all import (
        ARP, DHCP, DNS, DNSQR, DNSRR, ICMP, IP, TCP, UDP, IPv6, Raw, PcapReader, conf
    )
    conf.verb = 0
    try:
        import scapy.layers.snmp  # noqa: F401
        import scapy.layers.dns  # noqa: F401
        import scapy.layers.inet6  # noqa: F401
        import scapy.layers.dhcp  # noqa: F401
    except Exception:
        pass
    HAS_SCAPY = True
except ImportError:
    # v8: موتور بومی سریع (pcap_fastio) بدون scapy هم کار می‌کند؛ scapy فقط برای لینک‌تایپ‌های نادر لازم است
    HAS_SCAPY = False
    ARP = DHCP = DNS = DNSQR = DNSRR = ICMP = IP = TCP = UDP = IPv6 = Raw = PcapReader = conf = None

HAS_TK = True
try:
    import tkinter as tk
    import tkinter.font as tkfont
    from tkinter import ttk, filedialog, messagebox
    from tkinter.scrolledtext import ScrolledText
except Exception:
    HAS_TK = False

# ============================================================================
# ۱. ثوابت، امتیازدهی و بانک‌های اطلاعاتی آفلاین (Threat Intel & JA3 & Signatures)
# ============================================================================
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEV_FA = {
    "critical": "بحرانی",
    "high": "بالا",
    "medium": "متوسط",
    "low": "کم",
    "info": "اطلاعاتی"
}
SEV_COLOR = {
    "critical": "#ff4d6d",
    "high": "#ff8c42",
    "medium": "#ffc93c",
    "low": "#4cc9f0",
    "info": "#8d99ae"
}
NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

SERVICES = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP-Server", 68: "DHCP-Client", 69: "TFTP", 80: "HTTP",
    88: "Kerberos", 110: "POP3", 111: "RPCbind", 123: "NTP", 135: "MSRPC",
    137: "NetBIOS-NS", 138: "NetBIOS-DGM", 139: "NetBIOS-SSN", 143: "IMAP",
    161: "SNMP", 389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS",
    514: "Syslog", 587: "SMTP-Sub", 593: "RPC-HTTP", 636: "LDAPS", 873: "Rsync",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle", 2049: "NFS",
    3306: "MySQL", 3389: "RDP", 4444: "Metasploit", 5432: "PostgreSQL",
    5900: "VNC", 5985: "WinRM-HTTP", 5986: "WinRM-HTTPS", 6379: "Redis",
    8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 9001: "Tor", 9200: "Elasticsearch",
    11211: "Memcached", 27017: "MongoDB"
}

BRUTE_PORTS = {21, 22, 23, 25, 88, 110, 143, 389, 445, 1433, 3306, 3389, 5432, 5900, 5985, 6379}
BAD_PORTS = {
    4444: "Metasploit Meterpreter Default",
    1337: "Backdoor / Leet Port",
    31337: "Back Orifice / Elite Backdoor",
    6667: "IRC Botnet C2 Channel",
    6697: "IRC-TLS Botnet C2",
    5555: "Android ADB / RAT",
    9001: "Tor ORPort Relay",
    9050: "Tor SOCKS Proxy",
    2323: "Mirai IoT Botnet Telnet",
    12345: "NetBus Trojan",
    8888: "Uncommon Proxy / RAT",
    1080: "SOCKS Proxy",
    4443: "Alt-HTTPS C2 Channel",
    7777: "Generic RAT / Backdoor",
    2404: "AsyncRAT / Quasar Default C2",
    6606: "AsyncRAT Default C2",
    1604: "DarkComet RAT",
    3360: "VenomRAT / HVNC",
    50050: "Cobalt Strike TeamServer Default"
}
HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"PATCH ", b"PROPFIND ", b"CONNECT ")
SUSPICIOUS_TLDS = (
    ".top", ".xyz", ".su", ".ru", ".pw", ".tk", ".cc", ".biz", ".icu",
    ".gq", ".cf", ".ml", ".onion", ".bit", ".click", ".work", ".zip", ".mov"
)

TLS_GREASE = {
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
    0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa
}

KNOWN_JA3_DB = {
    "72a589da586844d7f0818ce684948eea": ("Metasploit / Cobalt Strike Malleable C2", True),
    "a0e9f5d64349fb13191bc781f81f42e1": ("Metasploit Meterpreter HTTPS", True),
    "51c64c77e60f3980eea90869b68c58a8": ("Cobalt Strike Beacon TLS Client", True),
    "e7d705a3286e19ea42f587b344ee6865": ("Tor Browser / Tor Client", True),
    "6734f37431670b3ab4292b8f60f29984": ("TrickBot / IcedID / Malware Dropper TLS", True),
    "4d7a28d6f2263ed61de88ca66eb011e3": ("Emotet / QakBot Loader TLS", True),
    "fc54e0d16d9764783542f0146a98b300": ("AsyncRAT / Quasar C2 TLS", True),
    "3b5074b1b5d032e5620f69f9f700ff0e": ("Python urllib / Requests (Automated Script)", False),
    "b32309a26951912be7dba376398abc3b": ("Python Requests / Automated Scanner", False),
    "456523fc94726331a4d5a2e1d40b2cd7": ("cURL CLI Client", False),
    "e35df3e00ca4ef31d42b34bebaa2f86e": ("Go net/http Client (Often used by Sliver/Merlin/Scanners)", False),
}

KNOWN_JA3S_DB = {
    "ae4edc6faf64d08308082ad26be60767": ("Cobalt Strike Default TeamServer TLS", True),
    "fd4bc6cea4877646ccd62f0792ec0b62": ("Metasploit Multi/Handler TLS", True),
    "15af977ce25de452b96affa2addb1036": ("Sliver C2 Server TLS", True),
}

# الگوهای Regex حملات وب، Exploit Kits، بدافزار، شبکه، لاگ و YARA-Lite
RE_EK_LANDING = re.compile(
    r"(?i)(ActiveXObject|WScript\.Shell|Scripting\.FileSystemObject|ADODB\.Stream|Shell\.Application|"
    r"msxml2\.xmlhttp|Microsoft\.XMLDOM|ExecuteGlobal|res://mshtml\.dll|vbscript:|"
    r"ShockwaveFlash\.ShockwaveFlash|Kaspersky\.IeVirtualKeyboardPlugin|AgControl\.AgControl|"
    r"eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,\s*d)"
)
RE_RIG_URI = re.compile(
    r"(?i)(^/[a-z0-9_-]{3,12}\.php\?[a-z0-9_=-]{15,}|"
    r"\?[a-z0-9]{1,4}=[a-z0-9_-]{20,}(?:&[a-z0-9]{1,4}=[a-z0-9_-]{10,})+|"
    r"/\?[a-z0-9+/=_-]{35,})"
)
RE_REDLINE = re.compile(
    r"(?i)(http://tempuri\.org/|SOAPAction:.*(?:GetBrowsers|RecieveSettings|CheckConnect|WriteLog)|"
    r"<s:Envelope[^>]*>.*tempuri\.org)"
)
RE_ICEDID_EMOTET = re.compile(
    r"(?i)(Cookie:\s*[^\r\n]*(?:__gads=[a-f0-9]{32,}|_gat=[0-9a-f]{20,}.*_ga=[0-9a-f]{20,}))"
)
RE_STEALER_EXFIL = re.compile(
    r"(?i)(api\.telegram\.org/bot[0-9]{8,}:[A-Za-z0-9_-]{30,}|discord(?:app)?\.com/api/webhooks/|"
    r"Subject:\s*(?:PW_|Passwords|AgentTesla|HawkEye|Snake\s*Keylogger|FormBook|Lumma|Vidar)|"
    r"Computer\s*Name\s*:.*User\s*Name\s*:)"
)
RE_SQLI = re.compile(
    r"(?i)(union\s+(all\s+)?select|\bor\s+1\s*=\s*1|'\s*or\s*'1'\s*=\s*'1|sleep\(\d+\)|"
    r"benchmark\(|information_schema|xp_cmdshell|;\s*drop\s+table|extractvalue\(|load_file\(|waitfor\s+delay)"
)
RE_XSS = re.compile(r"(?i)(<script|javascript:|onerror\s*=|onload\s*=|<svg[^>]*onload|<iframe|alert\(|document\.cookie)")
RE_TRAV = re.compile(r"(?i)(\.\./\.\./|\.\.\\\.\.\\|/etc/passwd|/etc/shadow|boot\.ini|win\.ini|/proc/self/environ)")
RE_CMDI = re.compile(
    r"(?i)((;|\||`|\$\()\s*(cat|ls|id|whoami|wget|curl|nc|bash|sh|powershell|uname|netstat|ipconfig|ifconfig|chmod)\b(?!\s*=)|"
    r"cmd\.exe|/bin/(ba)?sh|\bnc\s+-e\b)"
)
RE_LOG4J = re.compile(r"(?i)\$\{(jndi|lower|upper|env|sys|java|base64):")
RE_SHOCK = re.compile(r"\(\)\s*\{\s*:;\s*\}\s*;")
RE_XXE_SSRF = re.compile(
    r"(?i)(<!ENTITY\s+\w+\s+SYSTEM|file:///|gopher://|dict://|169\.254\.169\.254|127\.0\.0\.1:)"
)
RE_WEBSHELL = re.compile(
    r"(?i)(c99\.php|r57\.php|wso\.php|b374k|shell\.php|cmd\.php|eval\(base64_decode|passthru\(|shell_exec\(|system\(|assert\()"
)
RE_REVSHELL = re.compile(
    r"(?i)(uid=\d+\([a-z0-9_-]+\)\s+gid=\d+|Microsoft Windows \[Version\s+\d+|/bin/sh\s+-i|bash\s+-i\s+>&|/dev/tcp/|nc\.exe\s+-e)"
)
RE_POWERSHELL_B64 = re.compile(
    r"(?i)(powershell(?:\.exe)?\s+.*-(?:e|enc|encodedcommand)\s+[A-Za-z0-9+/=]{16,}|FromBase64String\(|IEX\s*\(\s*New-Object\s+Net\.WebClient)"
)
RE_CRED_DUMP_YARA = re.compile(
    r"(?i)(sekurlsa::logonpasswords|lsadump::sam|Invoke-Mimikatz|procdump(?:\.exe)?\s+.*lsass|comsvcs\.dll.*MiniDump|ntds\.dit)"
)
RE_SCANNER_UA = re.compile(
    r"(?i)(sqlmap|nikto|nmap|masscan|dirbuster|gobuster|hydra|wpscan|nessus|"
    r"acunetix|zgrab|burp|havij|metasploit|openvas|feroxbuster|nuclei|wfuzz|commix|httpx)"
)
RE_SENS_PATH = re.compile(
    r"(?i)(/\.env|/\.git/|/wp-login\.php|/phpmyadmin|/manager/html|/server-status|"
    r"/cgi-bin/|/\.aws/|/id_rsa|/web-inf/|/actuator|/\.htpasswd|/xmlrpc\.php|/config\.php\.bak|/backup\.sql)"
)
RE_PASSFIELD = re.compile(
    r"(?i)(?:^|[&\s\"'])(password|passwd|pass|pwd|secret|token|apikey|api_key|access_token)=([^&\s\"']{1,64})"
)

# ============================================================================
# ۲. بانک قوانین پیشرفته با نگاشت MITRE ATT&CK + MITRE D3FEND + MITRE CAR + Kill Chain
# ============================================================================
RULES = {
    "ek_exploit_kit": {
        "sev": "critical", "cat": "کیت بهره‌برداری (Exploit Kit)", "kill_chain": "Exploitation",
        "pyramid": "TTPs", "mitre": "T1189", "d3fend": "D3-HBPI / Browser Isolation", "car": "CAR-2020-11-001",
        "title": "شناسایی حمله Exploit Kit (RIG EK / Landing Page / VBScript / ActiveX)",
        "desc": "الگوهای اختصاصی کیت‌های بهره‌برداری (مانند RIG Exploit Kit) شامل لندینگ‌پیج مبهم‌سازی‌شده، فراخوانی اشیاء COM/ActiveX (WScript.Shell / ADODB.Stream) یا الگوی گیت‌های RIG در ترافیک HTTP کشف شد.",
        "rec": "ایزوله‌سازی فوری کلاینت هدف، مسدودسازی دامنه/IPهای گیت و لندینگ، بررسی پوشه Temp کاربر برای یافتن پی‌لود اجراشده و تحلیل حافظه."
    },
    "ek_flash_payload": {
        "sev": "critical", "cat": "تحویل اکسپلویت (Exploit Delivery)", "kill_chain": "Delivery",
        "pyramid": "Hash Values", "mitre": "T1203", "d3fend": "D3-FA (File Analysis)", "car": "CAR-2013-05-004",
        "title": "انتقال فایل اکسپلویت Flash / SWF (ZWS / CWS / FWS — مشخصه RIG EK)",
        "desc": "فایل Shockwave Flash فشرده (با امضای ZWS/CWS/FWS) در ترافیک وب شناسایی و استخراج شد؛ تکنیک اصلی RIG Exploit Kit برای اجرای شل‌کد در مرورگر قربانی.",
        "rec": "بررسی هش SHA-256 فایل فلش استخراج‌شده در پوشه _artifacts، بررسی پروسس‌های فرزند مرورگر در Sysmon و قرنطینه سیستم."
    },
    "xor_mal_payload": {
        "sev": "critical", "cat": "تحویل بدافزار (Malware Delivery)", "kill_chain": "Installation",
        "pyramid": "Hash Values", "mitre": "T1027", "d3fend": "D3-FA (Entropy & XOR Analysis)", "car": "CAR-2019-04-002",
        "title": "انتقال پی‌لود باینری رمزنگاری‌شده با XOR (XOR-Obfuscated PE Dropper)",
        "desc": "فایل اجرایی ویندوز که با کلید XOR (تک‌بایتی یا چندبایتی) مبهم‌سازی شده است در جریان HTTP شناسایی، رمزگشایی و استخراج شد.",
        "rec": "بررسی فایل رمزگشایی‌شده در پوشه _artifacts، مسدودسازی هش SHA-256 در EDR و بررسی مسیرهای %TEMP% و %APPDATA% در سیستم قربانی."
    },
    "exploit_kit_activity": {
        "sev": "critical", "cat": "تحویل و بهره‌برداری چندمرحله‌ای (Exploit Kit)",
        "kill_chain": "Exploitation", "pyramid": "TTPs",
        "mitre": "T1189", "d3fend": "D3-NTA / D3-IV", "car": "CAR-2020-11-001",
        "title": "زنجیره مشکوک Exploit Kit / Drive-by Download در جریان بازسازی‌شده TCP",
        "desc": "چند نشانه مرتبط با صفحه فرود Exploit Kit، مبهم‌سازی اسکریپت، محتوای بهره‌برداری یا تحویل Payload در جریان بازسازی‌شده شبکه مشاهده شده است.",
        "rec": "جریان کامل TCP و زنجیره Redirect را بازبینی کنید؛ فایل‌های SWF/JavaScript/PE استخراج‌شده در پوشه _artifacts را تحلیل نمایید."
    },
    "http_driveby_chain": {
        "sev": "high", "cat": "کیت بهره‌برداری (Exploit Kit)", "kill_chain": "Delivery",
        "pyramid": "TTPs", "mitre": "T1189", "d3fend": "D3-DNSDL / Web Proxy", "car": "CAR-2020-11-001",
        "title": "زنجیره تغییر مسیر مشکوک وب (Drive-By Download / Gate Redirect Chain)",
        "desc": "کلاینت در فاصله زمانی کوتاه از طریق هدر Referer یا کدهای 301/302 بین چندین دامنه/میزبان مختلف هدایت شده است.",
        "rec": "بررسی زنجیره کامل دامنه‌ها در تب آمار شبکه، مسدودسازی دامنه‌های واسط (Gates) و فعال‌سازی DNS RPZ."
    },
    "malware_c2_family": {
        "sev": "critical", "cat": "فرماندهی و کنترل (C2)", "kill_chain": "Command & Control",
        "pyramid": "TTPs", "mitre": "T1071.001", "d3fend": "D3-NTA / C2 Blocking", "car": "CAR-2014-11-002",
        "title": "شناسایی ارتباط C2 خانواده بدافزار (RedLine / IcedID / Cobalt Strike / Stealer)",
        "desc": "الگوی ارتباطی اختصاصی بدافزارهای سرقت اطلاعات یا چارچوب‌های C2 (مانند SOAP RedLine، کوکی‌های IcedID، Checksum8 در Cobalt Strike یا بات تلگرام/دیسکورد) شناسایی شد.",
        "rec": "قطع فوری دسترسی اینترنت میزبان آلوده، ریست کردن تمام رمزهای ذخیره‌شده در مرورگرهای سیستم و اجرای اسکن کامل حافظه."
    },
    "http_direct_ip": {
        "sev": "high", "cat": "ناهنجاری و C2 (Anomaly)", "kill_chain": "Command & Control",
        "pyramid": "IP Addresses", "mitre": "T1071.001", "d3fend": "D3-OTF (Outbound Filtering)", "car": "CAR-2013-05-002",
        "title": "ارسال درخواست HTTP مستقیم به آدرس IP خام (بدون نام دامنه / Direct-to-IP)",
        "desc": "درخواست HTTP بدون استفاده از نام دامنه (DNS) مستقیماً به یک آدرس IPv4 عمومی ارسال شده است؛ رفتار رایج در بدافزارها، Cobalt Strike و دانلودرهای مرحله دوم.",
        "rec": "مسدودسازی درخواست‌های HTTP به IPهای خام در Proxy/Firewall و بررسی پروسس ایجادکننده ارتباط."
    },
    "zero_day_entropy": {
        "sev": "high", "cat": "تشخیص ناشناخته (Zero-Day / Anomaly)", "kill_chain": "Command & Control",
        "pyramid": "TTPs", "mitre": "T1573", "d3fend": "D3-NTA (Entropy Analysis)", "car": "CAR-2014-11-002",
        "title": "[Zero-Day Anomaly] جریان داده با آنتروپی بسیار بالا روی پورت غیررمزنگاری",
        "desc": "انتقال داده شبه‌تصادفی/رمزنگاری‌شده با آنتروپی بالا روی پورتی که مربوط به TLS/SSH نیست مشاهده شد؛ نشانه احتمالی پی‌لود مبهم‌سازی‌شده یا کانال C2 سفارشی.",
        "rec": "بررسی جریان در Wireshark، شناسایی پروسس مبدأ و بررسی فایل‌های استخراج‌شده."
    },
    "proto_port_mismatch": {
        "sev": "medium", "cat": "تشخیص ناشناخته (Zero-Day / Evasion)", "kill_chain": "Command & Control",
        "pyramid": "TTPs", "mitre": "T1571", "d3fend": "D3-PH (Protocol Enforcement)", "car": "CAR-2014-11-002",
        "title": "[Evasion] عدم تطابق پروتکل و پورت استاندارد (Protocol-Port Mismatch)",
        "desc": "پروتکل شناسایی‌شده در لایه کاربرد با پورت استاندارد آن همخوانی ندارد (مانند HTTP روی پورت غیرمعمول یا TLS روی پورت 80).",
        "rec": "فعال‌سازی بازرسی عمیق بسته (DPI) در فایروال به جای تکیه صرف بر شماره پورت."
    },
    "suspicious_tld": {
        "sev": "medium", "cat": "فرماندهی و کنترل (C2)", "kill_chain": "Delivery",
        "pyramid": "Domain Names", "mitre": "T1583.001", "d3fend": "D3-DNSDL", "car": "CAR-2013-05-003",
        "title": "ارتباط با پسوندهای دامنه پرخطر و مشکوک (Suspicious TLD)",
        "desc": "درخواست DNS یا HTTP به دامنه‌هایی با پسوندهای پرکاربرد در کمپین‌های بدافزاری (.top, .xyz, .su, .ru, .pw, .tk, .cc, .icu, .zip) مشاهده شد.",
        "rec": "بررسی اعتبار دامنه در سامانه‌های Threat Intelligence و محدودسازی دسترسی به TLDهای پرخطر."
    },
    "port_scan": {
        "sev": "high", "cat": "شناسایی (Reconnaissance)", "kill_chain": "Reconnaissance",
        "pyramid": "Network Artifacts", "mitre": "T1046", "d3fend": "D3-NTA (Network Traffic Analysis)", "car": "CAR-2013-07-002",
        "title": "اسکن پورت عمودی (Vertical Port Scan)",
        "desc": "یک میزبان تعداد زیادی پورت مختلف از یک هدف را با بسته‌های SYN بررسی کرده است؛ نشانه مرحله شناسایی قبل از نفوذ.",
        "rec": "مسدودسازی IP مهاجم در فایروال/IPS، اعمال Rate-Limit روی بسته‌های SYN و بستن پورت‌های غیرضروری."
    },
    "host_sweep": {
        "sev": "medium", "cat": "شناسایی (Reconnaissance)", "kill_chain": "Reconnaissance",
        "pyramid": "Network Artifacts", "mitre": "T1046", "d3fend": "D3-NI (Network Isolation)", "car": "CAR-2013-07-002",
        "title": "جاروب شبکه افقی (Horizontal Host Sweep)",
        "desc": "یک میزبان یک پورت مشخص را روی تعداد زیادی IP مختلف تست کرده است تا سرویس‌های آسیب‌پذیر شبکه را کشف کند.",
        "rec": "سگمنت‌بندی شبکه (VLAN)، محدودسازی ترافیک افقی (East-West) و فعال‌سازی مانیتورینگ Zeek/Suricata."
    },
    "stealth_scan": {
        "sev": "high", "cat": "شناسایی (Reconnaissance)", "kill_chain": "Reconnaissance",
        "pyramid": "TTPs", "mitre": "T1046", "d3fend": "D3-ITF (Inbound Traffic Filtering)", "car": "CAR-2013-07-002",
        "title": "اسکن مخفی شبکه (TCP NULL / FIN / Xmas Scan)",
        "desc": "بسته‌های TCP با ترکیب فلگ غیرعادی دیده شد که ابزارهایی مانند Nmap برای دور زدن فایروال‌های ساده استفاده می‌کنند.",
        "rec": "استفاده از فایروال Stateful با قابلیت Drop کردن فلگ‌های نامعتبر TCP و فعال‌سازی IPS."
    },
    "syn_flood": {
        "sev": "critical", "cat": "اختلال سرویس (Impact / DoS)", "kill_chain": "Actions on Objectives",
        "pyramid": "Network Artifacts", "mitre": "T1498", "d3fend": "D3-ITF (Traffic Filtering)", "car": "CAR-2014-04-002",
        "title": "حمله سیل‌آسای SYN Flood (DoS / DDoS)",
        "desc": "تعداد بسیار زیادی بسته SYN به یک هدف ارسال شده و پاسخ SYN-ACK متناسبی دریافت نشده است.",
        "rec": "فعال‌سازی SYN Cookies در کرنل سیستم‌عامل، اعمال Rate-Limit در لبه شبکه و استفاده از تجهیزات Anti-DDoS."
    },
    "dhcp_starvation": {
        "sev": "high", "cat": "اختلال سرویس / MITM (DHCP Attack)", "kill_chain": "Exploitation",
        "pyramid": "Network Artifacts", "mitre": "T1557", "d3fend": "D3-NB (DHCP Snooping)", "car": "CAR-2020-09-001",
        "title": "حمله گرسنگی DHCP یا سرور جعلی (DHCP Starvation / Rogue DHCP)",
        "desc": "تعداد زیادی درخواست DHCP Discover/Request با MACهای متفاوت یا بیش از یک سرور پاسخ‌دهنده DHCP Offer در شبکه مشاهده شد.",
        "rec": "فعال‌سازی DHCP Snooping روی سوئیچ‌های دسترسی و محدود کردن پورت‌های Trusted DHCP."
    },
    "brute_force": {
        "sev": "high", "cat": "دسترسی به اعتبارنامه (Credential Access)", "kill_chain": "Exploitation",
        "pyramid": "TTPs", "mitre": "T1110", "d3fend": "D3-AL (Account Locking) / D3-MFA", "car": "CAR-2013-07-001",
        "title": "حمله Brute-Force / Password Spraying",
        "desc": "تعداد زیادی اتصال مکرر و کوتاه‌مدت از یک مبدأ به سرویس احراز هویت (SSH/RDP/FTP/SMB/DB) ثبت شده است.",
        "rec": "قفل شدن خودکار حساب (Account Lockout)، فعال‌سازی MFA، استقرار Fail2ban/CrowdSec و محدودسازی IP."
    },
    "arp_spoof": {
        "sev": "critical", "cat": "حمله مرد میانی (MITM)", "kill_chain": "Exploitation",
        "pyramid": "TTPs", "mitre": "T1557.002", "d3fend": "D3-NB (Network Broadcast Filtering)", "car": "CAR-2020-09-001",
        "title": "مسموم‌سازی جدول ARP (ARP Spoofing / Poisoning)",
        "desc": "برای یک آدرس IP بیش از یک آدرس MAC در شبکه اعلام شده است؛ نشانه کلاسیک حمله MITM در شبکه محلی.",
        "rec": "فعال‌سازی Dynamic ARP Inspection (DAI) و DHCP Snooping روی سوئیچ‌ها و تعریف Static ARP برای گیت‌وی."
    },
    "arp_flood": {
        "sev": "medium", "cat": "حمله مرد میانی (MITM)", "kill_chain": "Delivery",
        "pyramid": "Network Artifacts", "mitre": "T1557.002", "d3fend": "D3-NB", "car": "CAR-2020-09-001",
        "title": "ارسال حجم بالای Gratuitous ARP Reply",
        "desc": "یک آدرس MAC تعداد زیادی پاسخ ARP ارسال کرده که می‌تواند مقدمه مسموم‌سازی جدول ARP باشد.",
        "rec": "فعال‌سازی Port Security و Dynamic ARP Inspection روی پورت‌های سوئیچ."
    },
    "dns_tunnel": {
        "sev": "high", "cat": "فرماندهی و کنترل (C2)", "kill_chain": "Command & Control",
        "pyramid": "Domain Names", "mitre": "T1071.004", "d3fend": "D3-DNSDL (DNS Denylisting)", "car": "CAR-2013-05-003",
        "title": "تونل‌زنی و نشت داده از طریق DNS (DNS Tunneling)",
        "desc": "تعداد بسیار زیادی زیردامنه یکتا یا کوئری‌های طولانی با آنتروپی بالا برای یک دامنه خاص ثبت شده است.",
        "rec": "مسدودسازی DNS خروجی مستقیم و الزام به استفاده از DNS سرور داخلی، فعال‌سازی DNS RPZ و تحلیل طول/Entropy."
    },
    "dns_suspicious": {
        "sev": "medium", "cat": "فرماندهی و کنترل (C2)", "kill_chain": "Command & Control",
        "pyramid": "Domain Names", "mitre": "T1568.002", "d3fend": "D3-DNSDL", "car": "CAR-2013-05-003",
        "title": "کوئری DNS مشکوک با آنتروپی یا طول غیرعادی",
        "desc": "نام دامنه با ظاهر تصادفی (شبه‌رمزنگاری/Base64) یا بسیار طولانی مشاهده شد که مشخصه DGA یا تونل پنهان است.",
        "rec": "بررسی دامنه در سامانه‌های CTI/MISP، بلاک در DNS Firewall و بررسی پروسس درخواست‌کننده با Sysmon (Event ID 22)."
    },
    "dga": {
        "sev": "high", "cat": "فرماندهی و کنترل (C2)", "kill_chain": "Command & Control",
        "pyramid": "TTPs", "mitre": "T1568.002", "d3fend": "D3-DNSDL", "car": "CAR-2013-05-003",
        "title": "الگوریتم تولید دامنه بدافزار (DGA / High NXDOMAIN)",
        "desc": "یک کلاینت تعداد زیادی دامنه ناموجود (NXDOMAIN) را کوئری گرفته است؛ رفتار رایج بدافزارها برای یافتن سرور C2 فعال.",
        "rec": "ایزوله‌سازی سریع میزبان در شبکه، اجرای اسکن کامل EDR/Loki/ThorLite و بررسی لاگ‌های Sysmon DNS."
    },
    "beacon": {
        "sev": "high", "cat": "فرماندهی و کنترل (C2)", "kill_chain": "Command & Control",
        "pyramid": "TTPs", "mitre": "T1071", "d3fend": "D3-NTA (Outbound Traffic Filtering)", "car": "CAR-2014-11-002",
        "title": "رفتار ارتباط دوره‌ای منظم با مرکز فرماندهی (C2 Beaconing)",
        "desc": "اتصال‌ها به یک مقصد با فاصله زمانی ثابت و ضریب تغییرات (Jitter/CV) پایین برقرار شده است؛ الگوی کلاسیک Implantهای C2.",
        "rec": "شناسایی پروسس مبدأ روی سیستم داخلی با Sysmon Event ID 3، قطع ارتباط مقصد در فایروال و اعمال Egress Filtering."
    },
    "ja3_malicious": {
        "sev": "critical", "cat": "فرماندهی و کنترل (C2)", "kill_chain": "Command & Control",
        "pyramid": "Hash Values", "mitre": "T1071.001", "d3fend": "D3-NTA (TLS Inspection)", "car": "CAR-2021-01-001",
        "title": "شناسایی اثرانگشت مخرب TLS (Malicious JA3 / JA3S Fingerprint)",
        "desc": "هش JA3/JA3S استخراج‌شده از مذاکره TLS با امضای ابزارهای مهاجم و C2 (مانند Cobalt Strike / Metasploit / Sliver / Tor) مطابقت دارد.",
        "rec": "مسدودسازی فوری IP مقصد و هش JA3 در فایروال نسل جدید (NGFW/Suricata) و قرنطینه سیستم مبدأ."
    },
    "exfil": {
        "sev": "high", "cat": "نشت داده (Exfiltration)", "kill_chain": "Actions on Objectives",
        "pyramid": "TTPs", "mitre": "T1041", "d3fend": "D3-OTF (Outbound Traffic Filtering)", "car": "CAR-2013-05-002",
        "title": "خروج حجم بالای داده به خارج از شبکه (Data Exfiltration)",
        "desc": "حجم قابل‌توجهی داده از یک IP داخلی به یک مقصد عمومی ارسال شده و نسبت ارسال به دریافت کاملاً نامتقارن است.",
        "rec": "بررسی سریع نشست، پیاده‌سازی DLP، اعمال محدودیت ترافیک خروجی و مسدودسازی IP مقصد."
    },
    "icmp_tunnel": {
        "sev": "high", "cat": "فرماندهی و کنترل (C2)", "kill_chain": "Command & Control",
        "pyramid": "Network Artifacts", "mitre": "T1095", "d3fend": "D3-ITF", "car": "CAR-2014-05-001",
        "title": "تونل‌زنی پنهان روی پروتکل ICMP (ICMP Tunneling)",
        "desc": "تعداد زیادی بسته ICMP Echo با Payload بزرگ بین دو میزبان تبادل شده که نشانه کانال ارتباطی پنهان است.",
        "rec": "محدودسازی اندازه و نرخ بسته‌های ICMP در فایروال و مسدودسازی ICMP خروجی غیرضروری."
    },
    "ping_sweep": {
        "sev": "low", "cat": "شناسایی (Reconnaissance)", "kill_chain": "Reconnaissance",
        "pyramid": "Network Artifacts", "mitre": "T1018", "d3fend": "D3-ITF", "car": "CAR-2013-07-002",
        "title": "جاروب پینگ شبکه (ICMP Ping Sweep)",
        "desc": "یک میزبان به تعداد زیادی آدرس IP درخواست Echo فرستاده تا میزبان‌های زنده شبکه را شناسایی کند.",
        "rec": "محدودسازی پاسخ به ICMP Echo در زیرشبکه‌های حساس و مانیتورینگ سیستم مبدأ."
    },
    "icmp_redirect": {
        "sev": "medium", "cat": "حمله مرد میانی (MITM)", "kill_chain": "Exploitation",
        "pyramid": "Network Artifacts", "mitre": "T1557", "d3fend": "D3-ITF", "car": "CAR-2020-09-001",
        "title": "تغییر مسیر ترافیک با ICMP Redirect",
        "desc": "پیام‌های ICMP Redirect مشاهده شد که می‌تواند مسیر ترافیک را به سمت سیستم مهاجم منحرف کند.",
        "rec": "غیرفعال‌سازی پذیرش بسته‌های ICMP Redirect در تنظیمات شبکه سیستم‌عامل‌ها (sysctl) و روترها."
    },
    "http_sqli": {
        "sev": "critical", "cat": "بهره‌برداری وب (Web Exploit)", "kill_chain": "Exploitation",
        "pyramid": "TTPs", "mitre": "T1190", "d3fend": "D3-IV (Input Validation) / WAF", "car": "CAR-2020-11-001",
        "title": "حمله تزریق دستورات دیتابیس (SQL Injection)",
        "desc": "الگوهای تزریق SQL در پارامترهای URL، هدرها یا بدنه درخواست HTTP شناسایی شد.",
        "rec": "استفاده از Prepared Statements در کد برنامه، فعال‌سازی WAF و محدود کردن دسترسی کاربر دیتابیس."
    },
    "http_xss": {
        "sev": "high", "cat": "بهره‌برداری وب (Web Exploit)", "kill_chain": "Exploitation",
        "pyramid": "Network Artifacts", "mitre": "T1189", "d3fend": "D3-IV", "car": "CAR-2020-11-001",
        "title": "حمله اسکریپت‌نویسی متقابل (Cross-Site Scripting - XSS)",
        "desc": "تزریق تگ‌های اسکریپت یا رویدادهای جاوااسکریپت در درخواست HTTP مشاهده شد.",
        "rec": "اعمال Output Encoding، تنظیم هدر Content-Security-Policy (CSP) و فعال‌سازی فلگ HttpOnly کوکی‌ها."
    },
    "http_traversal": {
        "sev": "high", "cat": "بهره‌برداری وب (Web Exploit)", "kill_chain": "Exploitation",
        "pyramid": "Network Artifacts", "mitre": "T1190", "d3fend": "D3-IV", "car": "CAR-2020-11-001",
        "title": "پیمایش مسیر و شمول فایل محلی (Path Traversal / LFI)",
        "desc": "تلاش برای خواندن فایل‌های حساس سیستم‌عامل با کاراکترهای ../ یا مسیرهای سیستمی در درخواست وب.",
        "rec": "اعتبارسنجی مسیر فایل‌ها (Canonicalization)، عدم دریافت مستقیم نام فایل از کاربر و تنظیم WAF."
    },
    "http_cmdi": {
        "sev": "critical", "cat": "اجرای کد از راه دور (RCE)", "kill_chain": "Exploitation",
        "pyramid": "TTPs", "mitre": "T1059", "d3fend": "D3-PSA (Process Spawn Analysis)", "car": "CAR-2016-03-002",
        "title": "تزریق فرمان سیستم‌عامل (OS Command Injection / RCE)",
        "desc": "الگوهای اجرای مستقیم دستورات شل (لینوکس/ویندوز) در درخواست HTTP مشاهده شد.",
        "rec": "عدم ارسال ورودی کاربر به توابع سیستمی، ایزوله‌سازی سرویس وب و بررسی لاگ‌های Auditd / Sysmon Event ID 1."
    },
    "http_log4j": {
        "sev": "critical", "cat": "اجرای کد از راه دور (RCE)", "kill_chain": "Exploitation",
        "pyramid": "TTPs", "mitre": "T1190", "d3fend": "D3-SU (Software Update) / D3-OTF", "car": "CAR-2021-12-001",
        "title": "تلاش برای اکسپلویت Log4Shell (CVE-2021-44228)",
        "desc": "رشته مخرب ${jndi:...} در هدرها یا پارامترهای HTTP جهت بهره‌برداری از آسیب‌پذیری Log4j شناسایی شد.",
        "rec": "به‌روزرسانی فوری کتابخانه Log4j به نسخه امن و مسدودسازی اتصالات خروجی LDAP/RMI از سرورها."
    },
    "http_shellshock": {
        "sev": "critical", "cat": "اجرای کد از راه دور (RCE)", "kill_chain": "Exploitation",
        "pyramid": "TTPs", "mitre": "T1190", "d3fend": "D3-SU", "car": "CAR-2014-09-001",
        "title": "تلاش برای اکسپلویت Shellshock (CVE-2014-6271)",
        "desc": "الگوی () { :; }; در هدرهای درخواست HTTP جهت اجرای کد در Bash مشاهده شد.",
        "rec": "به‌روزرسانی فوری پکیج Bash و غیرفعال کردن اسکریپت‌های CGI قدیمی روی وب‌سرور."
    },
    "http_xxe_ssrf": {
        "sev": "high", "cat": "بهره‌برداری وب (Web Exploit)", "kill_chain": "Exploitation",
        "pyramid": "TTPs", "mitre": "T1190", "d3fend": "D3-IV", "car": "CAR-2020-11-001",
        "title": "تلاش برای حمله SSRF یا XXE Injection",
        "desc": "الگوهای تعریف Entity خارجی XML یا ارجاع به آدرس‌های لوکال/متادیتا (169.254.169.254 / 127.0.0.1) در درخواست وب.",
        "rec": "غیرفعال‌سازی External Entities در پارسر XML و فیلتر کردن آدرس‌های خصوصی در درخواست‌های سمت سرور."
    },
    "http_webshell": {
        "sev": "critical", "cat": "پایداری و دسترسی (Persistence)", "kill_chain": "Installation",
        "pyramid": "Host Artifacts", "mitre": "T1505.003", "d3fend": "D3-FA (File Analysis)", "car": "CAR-2013-07-005",
        "title": "شناسایی فعالیت وب‌شل (Webshell Upload / Execution)",
        "desc": "نام فایل‌های وب‌شل شناخته‌شده یا توابع اجرای کد PHP/ASP در ترافیک HTTP شناسایی شد.",
        "rec": "بررسی فوری دایرکتوری‌های وب‌سرور با اسکنر YARA/Loki، قرنطینه فایل‌های تغییر یافته و بررسی لاگ‌های دسترسی."
    },
    "reverse_shell": {
        "sev": "critical", "cat": "فرماندهی و کنترل (C2)", "kill_chain": "Command & Control",
        "pyramid": "TTPs", "mitre": "T1059", "d3fend": "D3-PSA / D3-NTCD", "car": "CAR-2016-03-002",
        "title": "شناسایی شل معکوس یا تعاملی (Interactive Reverse / Bind Shell)",
        "desc": "در پی‌لود خام TCP خروجی خط فرمان ویندوز یا شل لینوکس (مانند uid=0 یا /bin/sh) به صورت مستقیم مشاهده شد.",
        "rec": "قطع فوری ارتباط شبکه سیستم آلوده، بررسی درخت پروسس‌ها (Sysmon/Auditd) و انجام فارنزیک حافظه با Volatility."
    },
    "yara_powershell": {
        "sev": "critical", "cat": "اجرای کد (Execution)", "kill_chain": "Exploitation",
        "pyramid": "TTPs", "mitre": "T1059.001", "d3fend": "D3-PSA (Script Block Logging)", "car": "CAR-2014-04-003",
        "title": "[YARA] اجرای دستورات رمزنگاری‌شده PowerShell (EncodedCommand / IEX)",
        "desc": "امضای اجرای دستورات پاورشل Base64 یا دانلودر وب (IEX WebClient) در پی‌لود شبکه یا لاگ شناسایی شد.",
        "rec": "بررسی Event ID 4104 پاورشل و Event ID 1 در Sysmon، دیکد کردن رشته Base64 و مسدودسازی مبدأ."
    },
    "yara_creddump": {
        "sev": "critical", "cat": "دسترسی به اعتبارنامه (Credential Access)", "kill_chain": "Actions on Objectives",
        "pyramid": "Tools", "mitre": "T1003.001", "d3fend": "D3-CP (Credential Hardening)", "car": "CAR-2019-04-004",
        "title": "[YARA] شناسایی الگوهای استخراج رمز (Mimikatz / LSASS Dump)",
        "desc": "رشته‌های مرتبط با ابزار Mimikatz، دامپ حافظه LSASS یا استخراج فایل NTDS.dit در ترافیک یا لاگ‌ها مشاهده شد.",
        "rec": "فعال‌سازی LSA Protection (RunAsPPL)، Credential Guard و بازنشانی فوری رمز حساب‌های ادمین دامنه."
    },
    "smb_lateral": {
        "sev": "high", "cat": "حرکت جانبی (Lateral Movement)", "kill_chain": "Exploitation",
        "pyramid": "TTPs", "mitre": "T1021.002", "d3fend": "D3-NI (SMB Restriction)", "car": "CAR-2013-09-003",
        "title": "ترافیک مشکوک SMB / Admin Shares (IPC$ / ADMIN$ / C$ / SMBv1)",
        "desc": "دسترسی به اشتراک‌های مدیریتی ویندوز (ADMIN$, C$, IPC$) یا مذاکره پروتکل آسیب‌پذیر SMBv1 (EternalBlue) مشاهده شد.",
        "rec": "غیرفعال‌سازی کامل SMBv1، مسدودسازی پورت 445 بین ایستگاه‌های کاری و بررسی Event ID 5140/5145 ویندوز."
    },
    "kerberos_attack": {
        "sev": "high", "cat": "دسترسی به اعتبارنامه (Credential Access)", "kill_chain": "Exploitation",
        "pyramid": "TTPs", "mitre": "T1558.003", "d3fend": "D3-CP (Strong Encryption)", "car": "CAR-2019-04-004",
        "title": "ناهنجاری احراز هویت Kerberos (احتمال Kerberoasting / AS-REP Roasting / RC4 Downgrade)",
        "desc": "ترافیک Kerberos با رمزنگاری ضعیف RC4-HMAC (etype 23) یا حجم بالای درخواست‌های TGS-REQ مشاهده شد.",
        "rec": "الزام به استفاده از رمزنگاری AES-256 برای حساب‌های سرویس و بررسی Event ID 4769 در Domain Controller."
    },
    "scanner_ua": {
        "sev": "medium", "cat": "شناسایی (Reconnaissance)", "kill_chain": "Reconnaissance",
        "pyramid": "Tools", "mitre": "T1595", "d3fend": "D3-UA (User-Agent Filtering)", "car": "CAR-2020-11-001",
        "title": "شناسایی ابزار اسکن و نفوذ در هدر User-Agent",
        "desc": "در هدر User-Agent نام ابزارهای تست نفوذ و اسکنرهای خودکار (مانند sqlmap, nikto, nuclei, nmap) ثبت شده است.",
        "rec": "مسدودسازی IP مبدأ در WAF/فایروال و بررسی تمامی درخواست‌های ثبت‌شده از این آدرس."
    },
    "sensitive_path": {
        "sev": "medium", "cat": "شناسایی (Reconnaissance)", "kill_chain": "Reconnaissance",
        "pyramid": "Network Artifacts", "mitre": "T1083", "d3fend": "D3-FH (File Hardening)", "car": "CAR-2020-11-001",
        "title": "تلاش برای کشف فایل‌ها و مسیرهای حساس وب (.env / .git / backup)",
        "desc": "درخواست‌هایی به مسیرهای حساس مانند .env, .git, phpmyadmin, wp-login یا فایل‌های بکاپ ارسال شده است.",
        "rec": "حذف فایل‌های مخزن و تنظیمات از ریشه وب‌سرور و محدودسازی دسترسی به پنل‌های مدیریتی بر اساس IP."
    },
    "http_basic_auth": {
        "sev": "high", "cat": "نشت اطلاعات هویتی", "kill_chain": "Exploitation",
        "pyramid": "Network Artifacts", "mitre": "T1040", "d3fend": "D3-ET (Encrypted Tunnels)", "car": "CAR-2013-07-001",
        "title": "ارسال اطلاعات هویتی Basic Auth روی HTTP غیرامن",
        "desc": "نام کاربری و رمز عبور به صورت Base64 (قابل دیکد شدن فوری) روی بستر غیررمزنگاری‌شده ارسال شده است.",
        "rec": "الزام به استفاده از HTTPS، فعال‌سازی هدر HSTS و تغییر فوری رمز عبور افشاشده."
    },
    "http_pass_form": {
        "sev": "high", "cat": "نشت اطلاعات هویتی", "kill_chain": "Exploitation",
        "pyramid": "Network Artifacts", "mitre": "T1040", "d3fend": "D3-ET", "car": "CAR-2013-07-001",
        "title": "ارسال رمز عبور یا توکن در فرم HTTP آشکار",
        "desc": "فیلدهای حاوی رمز عبور یا کلید API در بدنه درخواست HTTP بدون رمزنگاری TLS مشاهده شد.",
        "rec": "انتقال تمام صفحات لاگین و APIها به بستر HTTPS و ابطال توکن‌ها/رمزهای عبور افشاشده."
    },
    "ftp_cred": {
        "sev": "high", "cat": "نشت اطلاعات هویتی", "kill_chain": "Exploitation",
        "pyramid": "Network Artifacts", "mitre": "T1040", "d3fend": "D3-ET", "car": "CAR-2013-07-001",
        "title": "ارسال نام کاربری و رمز عبور FTP به صورت متن آشکار",
        "desc": "دستورات USER و PASS پروتکل FTP بدون رمزنگاری در شبکه مخابره شده است.",
        "rec": "جایگزینی سرویس FTP با SFTP یا FTPS و تغییر رمزهای عبور استفاده‌شده."
    },
    "telnet": {
        "sev": "high", "cat": "پروتکل ناامن", "kill_chain": "Exploitation",
        "pyramid": "Network Artifacts", "mitre": "T1040", "d3fend": "D3-PH (Protocol Hardening)", "car": "CAR-2013-07-001",
        "title": "استفاده از پروتکل ناامن Telnet",
        "desc": "ترافیک Telnet روی پورت 23 مشاهده شد که تمامی دستورات و رمزها را به صورت متن آشکار منتقل می‌کند.",
        "rec": "غیرفعال‌سازی کامل سرویس Telnet و جایگزینی آن با پروتکل امن SSH."
    },
    "mail_cred": {
        "sev": "high", "cat": "نشت اطلاعات هویتی", "kill_chain": "Exploitation",
        "pyramid": "Network Artifacts", "mitre": "T1040", "d3fend": "D3-ET", "car": "CAR-2013-07-001",
        "title": "احراز هویت ایمیل (SMTP/POP3/IMAP) در متن آشکار",
        "desc": "اطلاعات ورود به سرور ایمیل بدون رمزنگاری TLS در شبکه ارسال شده است.",
        "rec": "اجبار به استفاده از پورت‌های امن (IMAPS/POP3S/SMTPS) و غیرفعال کردن Plaintext Auth."
    },
    "cleartext_db": {
        "sev": "high", "cat": "پروتکل ناامن", "kill_chain": "Exploitation",
        "pyramid": "Network Artifacts", "mitre": "T1040", "d3fend": "D3-ET", "car": "CAR-2013-07-001",
        "title": "ارتباط یا احراز هویت دیتابیس بدون رمزنگاری",
        "desc": "دستورات یا احراز هویت دیتابیس (مانند Redis AUTH یا کوئری‌های مستقیم SQL) به صورت آشکار در شبکه دیده شد.",
        "rec": "محدودسازی دسترسی به پورت دیتابیس فقط برای سرورهای داخلی مجاز و فعال‌سازی TLS روی دیتابیس."
    },
    "snmp_community": {
        "sev": "medium", "cat": "پروتکل ناامن", "kill_chain": "Reconnaissance",
        "pyramid": "Network Artifacts", "mitre": "T1040", "d3fend": "D3-PH", "car": "CAR-2013-07-001",
        "title": "افشای Community String در پروتکل SNMPv1/v2c",
        "desc": "بسته‌های SNMP نسخه‌های قدیمی حاوی رشته Community به صورت متن آشکار در شبکه مشاهده شد.",
        "rec": "مهاجرت به پروتکل امن SNMPv3 با رمزنگاری، تغییر رشته‌های پیش‌فرض public/private و اعمال ACL."
    },
    "tls_legacy": {
        "sev": "medium", "cat": "رمزنگاری ضعیف", "kill_chain": "Delivery",
        "pyramid": "Network Artifacts", "mitre": "T1557", "d3fend": "D3-PH", "car": "CAR-2021-01-001",
        "title": "استفاده از نسخه‌های منسوخ و آسیب‌پذیر SSLv3 / TLS 1.0 / TLS 1.1",
        "desc": "مذاکره رمزنگاری با نسخه‌های قدیمی TLS مشاهده شد که در برابر حملات تنزل نسخه و رمزگشایی آسیب‌پذیرند.",
        "rec": "غیرفعال‌سازی نسخه‌های قدیمی در سرور و الزام به استفاده از حداقل TLS 1.2 یا TLS 1.3."
    },
    "exe_over_http": {
        "sev": "critical", "cat": "تحویل بدافزار (Malware Delivery)", "kill_chain": "Delivery",
        "pyramid": "Hash Values", "mitre": "T1105", "d3fend": "D3-FA (File Hashing & Sandbox)", "car": "CAR-2013-05-004",
        "title": "انتقال فایل اجرایی باینری (PE/ELF) یا آرشیو حساس روی بستر HTTP",
        "desc": "امضای هدر فایل اجرایی ویندوز (MZ / PE) یا لینوکس (ELF) یا آرشیو حساس در ترافیک HTTP شناسایی، استخراج و هش آن محاسبه شد.",
        "rec": "بررسی هش SHA-256 فایل استخراج‌شده در پوشه _artifacts، قرنطینه سیستم مقصد و مسدودسازی URL."
    },
    "bad_port": {
        "sev": "medium", "cat": "فرماندهی و کنترل (C2)", "kill_chain": "Command & Control",
        "pyramid": "Network Artifacts", "mitre": "T1571", "d3fend": "D3-OTF", "car": "CAR-2014-11-002",
        "title": "ارتباط روی پورت‌های غیرمعمول و منتسب به RAT / C2 / Backdoor",
        "desc": "ترافیک روی پورت‌هایی دیده شد که به طور پیش‌فرض توسط ابزارهای نفوذ (Metasploit, Cobalt Strike, Tor, IRC, RAT) استفاده می‌شوند.",
        "rec": "اعمال سیاست فیلترینگ خروجی (Egress Filtering) و بررسی پروسس بازکننده پورت با دستور netstat / Sysmon."
    },
}

KILL_CHAIN_STAGES = [
    ("Reconnaissance", "۱. شناسایی (Recon)"),
    ("Weaponization", "۲. تسلیح (Weaponization)"),
    ("Delivery", "۳. تحویل (Delivery)"),
    ("Exploitation", "۴. بهره‌برداری (Exploitation)"),
    ("Installation", "۵. نصب و پایداری (Installation)"),
    ("Command & Control", "۶. فرماندهی و کنترل (C2)"),
    ("Actions on Objectives", "۷. اقدام روی هدف (Exfil/Impact)")
]

RULES.update(EXTRA_RULES)
RULES.update(THREAT_RULES)

# ============================================================================
# ۳. توابع کمکی، رمزگشایی Gzip/Brotli/XOR، تشخیص فایل‌ها، JA3/JA3S و TShark
# ============================================================================
esc = html.escape


def mask_str(v, do_mask=True):
    v = str(v)
    if not do_mask:
        return v
    return v[:1] + "*" * max(len(v) - 1, 3)


def is_private_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def fmt_ts(ts):
    if not ts:
        return "-"
    try:
        return dt.datetime.fromtimestamp(float(ts)).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(ts)


def human_bytes(n):
    n = float(n)
    for u in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {u}" if u != "B" else f"{int(n)} B"
        n /= 1024
    return f"{n:.1f} PB"


_NONTEXT_DEL = bytes(range(9, 14)) + bytes(range(32, 127))  # text bytes (deleted -> remainder = nontext)


def calc_entropy(data):
    if not data:
        return 0.0
    if isinstance(data, str):
        data = data.encode("latin-1", "ignore")
    c = collections.Counter(data)
    length = len(data)
    return -sum(v / length * math.log2(v / length) for v in c.values())


def is_cobalt_strike_checksum8(uri):
    clean = uri.strip("/").split("?")[0]
    if len(clean) == 4 and clean.isalnum():
        return sum(ord(c) for c in clean) % 256 in (92, 93)
    return False


def detect_pe_or_xor_pe(data):
    """
    شناسایی دقیق انواع فایل‌های استخراج‌شده و مخفی‌شده در ترافیک شبکه:
    - Shockwave Flash (ZWS / CWS / FWS)
    - فایل‌های اجرایی Windows PE (EXE / DLL / SYS) حتی در میانه جریان
    - فایل‌های اجرایی Linux ELF
    - فایل‌های آرشیو ZIP / JAR / DOCX / XLSX / Office Macro
    - فایل‌های PDF
    - پی‌لودهای رمزنگاری‌شده با Single-Byte XOR (تمام ۲۵۵ کلید) و Multi-Byte XOR (کلید ۲ بایتی)
    """
    if not data or len(data) < 64:
        return False, None, False, data

    # 1. Flash SWF (RIG EK)
    for sig in (b"ZWS", b"CWS", b"FWS"):
        pos = data.find(sig, 0, 128)
        if pos != -1 and pos + 8 <= len(data) and 6 <= data[pos + 3] <= 45:
            return True, f"Shockwave Flash Exploit ({sig.decode('ascii')} v{data[pos + 3]})", False, data[pos:]

    # 2. Linux ELF
    if data.startswith(b"\x7fELF"):
        return True, "ELF Binary (Linux Executable)", False, data

    # 3. Windows PE Direct
    if data.startswith(b"MZ") and len(data) > 0x40:
        peoff = int.from_bytes(data[0x3c:0x40], "little")
        if 0 < peoff < len(data) - 4 and data[peoff:peoff + 4] == b"PE\x00\x00":
            return True, "PE Binary (Windows EXE/DLL)", False, data

    # 4. Windows PE Embedded
    dos_pos = data.find(b"This program cannot be run in DOS mode")
    if dos_pos == -1:
        dos_pos = data.find(b"This program must be run under Win32")
    if dos_pos != -1:
        mz_start = max(0, dos_pos - 0x4e)
        if data[mz_start:mz_start + 2] == b"MZ":
            return True, "PE Binary (Windows EXE/DLL)", False, data[mz_start:]
        return True, "PE Binary (Embedded Windows EXE/DLL)", False, data

    # 5. ZIP / JAR / Office OpenXML
    if data.startswith(b"PK\x03\x04") and len(data) > 128:
        if b"META-INF/" in data[:2048] or b".class" in data[:4096]:
            return True, "Java Archive (JAR / Applet)", False, data
        if b"word/vbaProject.bin" in data[:8192] or b"xl/vbaProject.bin" in data[:8192]:
            return True, "MS Office Macro-Enabled Document (Malicious Doc)", False, data
        return True, "ZIP Archive / Compressed Payload", False, data

    # 6. OLE2 Compound Binary (Legacy .doc / .xls with Macros)
    if data.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1") and len(data) > 512:
        if b"VBA" in data[:16384] or b"Macros" in data[:16384]:
            return True, "MS Office OLE2 Macro Document", False, data

    # 7. PDF Document
    if data.startswith(b"%PDF-") and len(data) > 256:
        if b"/JavaScript" in data[:16384] or b"/JS" in data[:16384] or b"/OpenAction" in data[:16384]:
            return True, "PDF Document with Embedded JS/OpenAction", False, data

    # 8. Single-Byte XOR Obfuscated PE (1..255)
    marker = b"This program cannot"
    sample = data[:8192]
    for key in range(1, 256):
        xored_marker = bytes(x ^ key for x in marker)
        if xored_marker in sample:
            decrypted = bytes(b ^ key for b in data)
            return True, f"XOR-Obfuscated PE Binary (1-Byte Key=0x{key:02x})", True, decrypted

    # 9. 2-Byte Repeating XOR Obfuscated PE (بررسی بر اساس MZ\x90\x00)
    # در هدر استاندارد PE، چهار بایت اول اغلب MZ\x90\x00 است
    if len(sample) >= 64:
        k0 = sample[0] ^ 0x4D  # 'M'
        k1 = sample[1] ^ 0x5A  # 'Z'
        if (k0 != 0 or k1 != 0) and (sample[2] ^ k0 == 0x90) and (sample[3] ^ k1 == 0x00):
            dec_sample = bytes(b ^ (k0 if idx % 2 == 0 else k1) for idx, b in enumerate(sample))
            if b"PE\x00\x00" in dec_sample[:512] or b"DOS mode" in dec_sample[:512]:
                decrypted = bytes(b ^ (k0 if idx % 2 == 0 else k1) for idx, b in enumerate(data))
                return True, f"XOR-Obfuscated PE Binary (2-Byte Key=0x{k0:02x}{k1:02x})", True, decrypted

    return False, None, False, data


def parse_tls_client_hello_ja3(p):
    try:
        if len(p) < 45 or p[0] != 0x16 or p[5] != 0x01:
            return None, None, None, None
        client_ver = int.from_bytes(p[9:11], "big")
        i = 43
        if i >= len(p):
            return client_ver, None, None, None
        sess_len = p[i]
        i += 1 + sess_len
        if i + 2 > len(p):
            return client_ver, None, None, None
        cs_len = int.from_bytes(p[i:i + 2], "big")
        i += 2
        ciphers = []
        for k in range(0, cs_len, 2):
            if i + k + 2 <= len(p):
                cval = int.from_bytes(p[i + k:i + k + 2], "big")
                if cval not in TLS_GREASE:
                    ciphers.append(str(cval))
        i += cs_len
        if i >= len(p):
            return client_ver, None, None, None
        comp_len = p[i]
        i += 1 + comp_len

        sni = None
        exts = []
        curves = []
        pt_fmts = []

        if i + 2 <= len(p):
            ext_total_len = int.from_bytes(p[i:i + 2], "big")
            i += 2
            end = min(i + ext_total_len, len(p))
            while i + 4 <= end:
                ext_type = int.from_bytes(p[i:i + 2], "big")
                ext_len = int.from_bytes(p[i + 2:i + 4], "big")
                i += 4
                ext_data = p[i:i + ext_len]
                if ext_type not in TLS_GREASE:
                    exts.append(str(ext_type))
                if ext_type == 0 and len(ext_data) >= 5:
                    nl = int.from_bytes(ext_data[3:5], "big")
                    sni = ext_data[5:5 + nl].decode("ascii", "ignore")
                elif ext_type == 10 and len(ext_data) >= 2:
                    g_len = int.from_bytes(ext_data[0:2], "big")
                    for gk in range(2, min(2 + g_len, len(ext_data)), 2):
                        gval = int.from_bytes(ext_data[gk:gk + 2], "big")
                        if gval not in TLS_GREASE:
                            curves.append(str(gval))
                elif ext_type == 11 and len(ext_data) >= 1:
                    pf_len = ext_data[0]
                    for pk in range(1, min(1 + pf_len, len(ext_data))):
                        pt_fmts.append(str(ext_data[pk]))
                i += ext_len

        ja3_str = f"{client_ver},{'-'.join(ciphers)},{'-'.join(exts)},{'-'.join(curves)},{'-'.join(pt_fmts)}"
        ja3_hash = hashlib.md5(ja3_str.encode("ascii")).hexdigest()
        return client_ver, sni, ja3_hash, ja3_str
    except Exception:
        return None, None, None, None


def parse_tls_server_hello_ja3s(p):
    """استخراج اثرانگشت JA3S از بسته TLS ServerHello برای شناسایی سرورهای C2"""
    try:
        if len(p) < 42 or p[0] != 0x16 or p[5] != 0x02:
            return None, None
        srv_ver = int.from_bytes(p[9:11], "big")
        i = 43
        if i >= len(p):
            return srv_ver, None
        sess_len = p[i]
        i += 1 + sess_len
        if i + 3 > len(p):
            return srv_ver, None
        cipher = int.from_bytes(p[i:i + 2], "big")
        i += 3  # cipher (2) + compression (1)
        exts = []
        if i + 2 <= len(p):
            ext_total_len = int.from_bytes(p[i:i + 2], "big")
            i += 2
            end = min(i + ext_total_len, len(p))
            while i + 4 <= end:
                ext_type = int.from_bytes(p[i:i + 2], "big")
                ext_len = int.from_bytes(p[i + 2:i + 4], "big")
                i += 4 + ext_len
                if ext_type not in TLS_GREASE:
                    exts.append(str(ext_type))
        ja3s_str = f"{srv_ver},{cipher},{'-'.join(exts)}"
        ja3s_hash = hashlib.md5(ja3s_str.encode("ascii")).hexdigest()
        return srv_ver, ja3s_hash
    except Exception:
        return None, None


def get_base_domain(q):
    parts = q.strip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else q


def find_tshark_binary():
    path = shutil.which("tshark")
    if path:
        return path
    win_paths = [
        r"C:\Program Files\Wireshark\tshark.exe",
        r"C:\Program Files (x86)\Wireshark\tshark.exe"
    ]
    for wp in win_paths:
        if os.path.isfile(wp):
            return wp
    return None


# ============================================================================
# ۴. تنظیمات موتور تشخیص
# ============================================================================
class _UdpShim:
    """شبیه لایه UDP scapy برای extra_udp (فقط sport/dport/payload)"""
    __slots__ = ("sport", "dport", "payload")

    def __init__(self, sport, dport, payload):
        self.sport, self.dport, self.payload = sport, dport, payload


class EngineConfig:
    def __init__(self):
        self.max_packets = 0
        self.port_scan_thresh = 20
        self.host_sweep_thresh = 20
        self.brute_force_thresh = 15
        self.syn_flood_thresh = 300
        self.dns_tunnel_subs = 40
        self.dga_nx_thresh = 30
        self.exfil_mb_thresh = 5.0
        self.beacon_cv_thresh = 0.20
        self.mask_passwords = True
        self.use_tshark_if_available = True
        self.max_streams = 60000
        self.max_stream_bytes = 64 * 1024 * 1024        # سقف هر جهت جریان (برای فایل‌های بزرگ)
        self.max_total_stream_bytes = 1536 * 1024 * 1024  # سقف کل حافظه‌ی بازسازی جریان‌ها
        self.fast_io = True                              # پکت‌خوان بومی سریع (بدون scapy)
        self.extract_files = True                        # استخراج فایل‌های منتقل‌شده به ZIP
        self.extract_scope = "all"                       # all | downloads (بدون HTML/JS/CSS/JSON وب)
        self.zip_password = "infected"
        self.max_extract_mb = 1024
        self.out_dir = None          # پوشه خروجی اختصاصی
        self.sample_mode = "auto"     # auto | zip | xor | raw
        self.ioc_file = None         # فهرست IOC شخصی (آفلاین)
        self.raw_samples = False     # تیک GUI برای ذخیره خام
        self.theme = "neon-night"    # تم پیش‌فرض گزارش و رابط
        self.material = "glass"      # glass | solid | hologram | terminal
        self.report_style = "cyber"  # cyber | classic | both
        self.formats = ("html", "json", "csv", "rules", "iocs")   # خروجی‌های انتخابی


# ============================================================================
# ۵. هسته اصلی تحلیلگر چندلایه (Network + Sequence Reassembly + Exploit Kit + YARA)
# ============================================================================
class PcapAnalyzer(ExtraDetectMixin, ProtocolHubMixin, ThreatMixin):
    def __init__(self, config: EngineConfig = None):
        self.cfg = config or EngineConfig()
        self.stop_requested = False
        self.errors = 0
        self.read_error = None

        self.total = 0
        self.bytes = 0
        self.t_first = self.t_last = None
        self.proto = collections.Counter()
        self.per_sec = collections.Counter()
        self.pair_bytes = collections.Counter()
        self.pair_pkts = collections.Counter()
        self.ip_out = collections.Counter()
        self.ip_in = collections.Counter()
        self.dports = collections.Counter()

        self.hits = {}
        self._evidence_seen = set()
        self.tcp_stream_quality = {}
        self.first_syn = {}
        self.syn_targets = collections.defaultdict(set)
        self.syn_times = collections.defaultdict(list)
        self.syn_by_target = collections.Counter()
        self.synack_by_server = collections.Counter()
        self.stealth = collections.Counter()
        self.stealth_first = {}

        self.arp_map = collections.defaultdict(set)
        self.arp_replies = collections.Counter()
        self.arp_first = {}

        self.dhcp_macs = set()
        self.dhcp_servers = set()

        self.dns_q = collections.Counter()
        self.dns_subs = collections.defaultdict(set)
        self.dns_lens = collections.defaultdict(list)
        self.dns_resolved = {}
        self.nx = collections.Counter()
        self.nx_first = {}

        self.sni = collections.Counter()
        self.ja3_Seen = collections.Counter()
        self.ja3_details = {}
        self.ja3s_seen = collections.Counter()
        self.http_hosts = collections.Counter()
        self.http_uas = collections.Counter()
        self.http_methods = collections.Counter()
        self.http_urls = []
        self.http_redirects = []
        self.client_referers = collections.defaultdict(list)
        self.ping_targets = collections.defaultdict(set)
        self.icmp_big = collections.Counter()
        self.icmp_first = {}
        self.badport_seen = set()
        self.cleartext_hosts = collections.Counter()

        self.carved_artifacts = []
        self.seen_hashes = set()
        self.artifact_dir = None

        self.ioc_ips = collections.defaultdict(set)
        self.ioc_domains = set()
        self.ioc_uas = set()
        self.ioc_hashes = set()
        self.ioc_artifacts = set()
        self.ioc_tools = set()
        self.ioc_creds = []
        self.tshark_summary = []

        self.tcp_segments = collections.defaultdict(list)
        self.tcp_stream_bytes = collections.Counter()
        self.streams_truncated = 0
        self.reassembled_streams = 0
        self.sample_store = None
        self._base_name = "capture"
        self._hub_cache = None
        self._first_errors = []
        self._init_extra()
        self._init_hub()
        self._init_threats()

    def hit(self, rid, n, ts, text, src_ip=None, dst_ip=None, tool_name=None, artifact=None):
        if rid not in RULES:
            return
        evidence_key = (
            rid, n, round(float(ts), 6) if ts is not None else None,
            src_ip, dst_ip, artifact, str(text)[:240]
        )
        if evidence_key in self._evidence_seen:
            return
        self._evidence_seen.add(evidence_key)
        h = self.hits.setdefault(rid, {"count": 0, "ex": [], "first": None, "actors": set(), "targets": set()})
        h["count"] += 1
        if h["first"] is None:
            h["first"] = (n, ts)
        if src_ip:
            h["actors"].add(src_ip)
            if rid in ("port_scan", "host_sweep", "stealth_scan", "scanner_ua", "ping_sweep"):
                self.ioc_ips[src_ip].add("Scanner / Recon")
            elif rid in ("http_sqli", "http_xss", "http_traversal", "http_cmdi", "http_log4j",
                         "http_shellshock", "http_xxe_ssrf", "http_webshell", "brute_force",
                         "yara_powershell", "yara_creddump", "smb_lateral", "kerberos_attack"):
                self.ioc_ips[src_ip].add("Attacker / Exploiter")
            elif rid in ("ek_exploit_kit", "ek_flash_payload", "xor_mal_payload",
                         "exploit_kit_activity", "exe_over_http"):
                self.ioc_ips[src_ip].add("Exploit Kit / Malware Delivery Server")
            elif rid in ("arp_spoof", "arp_flood", "icmp_redirect", "dhcp_starvation"):
                self.ioc_ips[src_ip].add("MITM / Spoofer")
            elif rid in ("exfil", "dga", "dns_tunnel", "ja3_malicious", "malware_c2_family", "http_direct_ip",
                         "stealer_credentials", "stealer_family_report", "infection_chain", "suspicious_user_agent", "ip_recon_lookup"):
                self.ioc_ips[src_ip].add("Compromised / Infected Host")
        if dst_ip:
            h["targets"].add(dst_ip)
            if rid in ("beacon", "bad_port", "reverse_shell", "exfil", "ja3_malicious",
                       "malware_c2_family", "http_direct_ip", "c2_service_abuse", "ioc_feed_match",
                       "stealer_ftp_exfil", "stealer_smtp_exfil", "exfil_webhook", "malware_gate_post", "irc_botnet", "cloud_staging"):
                self.ioc_ips[dst_ip].add("Suspected C2 / External Dest")

        if tool_name:
            self.ioc_tools.add(tool_name)
        if artifact:
            self.ioc_artifacts.add(artifact)

        if len(h["ex"]) < 15:
            loc = f"#{n} | " if n else ""
            h["ex"].append(f"{loc}{fmt_ts(ts) if ts else ''} | {text}")

    def run(self, path, progress_cb=None):
        ext = os.path.splitext(path)[1].lower()
        if ext in (".log", ".txt", ".json", ".jsonl", ".xml", ".csv"):
            self._run_log_analyzer(path, progress_cb)
            return

        try:
            base_dir = self.cfg.out_dir or os.path.dirname(os.path.abspath(path))
            self.artifact_dir = os.path.join(base_dir, os.path.splitext(os.path.basename(path))[0] + "_artifacts")
            self.sample_store = SampleStore(self.artifact_dir, self.cfg.sample_mode)
        except OSError:
            self.artifact_dir = None
            self.sample_store = None

        self._base_name = os.path.splitext(os.path.basename(path))[0]
        file_size = os.path.getsize(path) if os.path.isfile(path) else 0
        start_wall = time.time()
        last_cb = 0.0
        max_pkts = self.cfg.max_packets
        packet = self.packet

        used_fast = False
        if getattr(self.cfg, "fast_io", True):
            try:
                used_fast = self._run_fast(path, progress_cb, start_wall, file_size)
            except FIO.Unsupported:
                used_fast = False
            except Exception as e:           # فایل خراب: هرچه تا اینجا خوانده شد معتبر است
                self.read_error = f"{type(e).__name__}: {e}"
                used_fast = True
        if not used_fast and not HAS_SCAPY:
            raise RuntimeError("این فرمت/لینک‌تایپ با پکت‌خوان داخلی پشتیبانی نمی‌شود و scapy هم نصب نیست.\n"
                               "نصب: pip install scapy")

        try:
            if used_fast:
                raise StopIteration
            with PcapReader(path) as rd:
                fobj = getattr(rd, "f", None)
                for n, pkt in enumerate(rd, 1):
                    if self.stop_requested:
                        break
                    if max_pkts and n > max_pkts:
                        break
                    try:
                        packet(n, pkt)
                    except Exception:
                        self.errors += 1
                        continue

                    if progress_cb and (n & 0x3FF) == 0:
                        now = time.time()
                        if now - last_cb >= 0.12:
                            last_cb = now
                            pos = self.bytes
                            if fobj is not None:
                                try:
                                    pos = fobj.tell()
                                except Exception:
                                    pos = self.bytes
                            progress_cb(n, pos, file_size, int(n / max(now - start_wall, 0.001)))
        except StopIteration:
            pass
        except Exception as e:
            self.read_error = f"{type(e).__name__}: {e}"

        if self.total == 0 and self.read_error:
            raise RuntimeError(f"فایل قابل خواندن نیست یا فرمت آن پشتیبانی نمی‌شود:\n{self.read_error}")

        self.finish()

        if self.cfg.use_tshark_if_available and not self.stop_requested:
            self._run_optional_tshark(path)

        if progress_cb:
            elapsed = max(time.time() - start_wall, 0.001)
            progress_cb(self.total, file_size, file_size, int(self.total / elapsed), done=True)

    def _run_log_analyzer(self, path, progress_cb=None):
        file_size = os.path.getsize(path) if os.path.isfile(path) else 1
        start_wall = time.time()
        now_ts = time.time()
        self.t_first = now_ts
        self.t_last = now_ts

        re_ip = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
        ssh_fail_counter = collections.Counter()

        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            for n, line in enumerate(fh, 1):
                if self.stop_requested:
                    break
                self.total += 1
                b_len = len(line.encode("utf-8", "ignore"))
                self.bytes += b_len
                self.proto["LOG-LINE"] += 1

                ips = re_ip.findall(line)
                src = ips[0] if ips else "LogSource"
                dst = ips[1] if len(ips) > 1 else "LocalHost"
                if ips:
                    self.ip_out[src] += b_len

                for rid, rx in (
                    ("ek_exploit_kit", RE_EK_LANDING),
                    ("malware_c2_family", RE_REDLINE),
                    ("malware_c2_family", RE_STEALER_EXFIL),
                    ("http_sqli", RE_SQLI),
                    ("http_xss", RE_XSS),
                    ("http_traversal", RE_TRAV),
                    ("http_cmdi", RE_CMDI),
                    ("http_log4j", RE_LOG4J),
                    ("http_shellshock", RE_SHOCK),
                    ("http_xxe_ssrf", RE_XXE_SSRF),
                    ("http_webshell", RE_WEBSHELL),
                    ("reverse_shell", RE_REVSHELL),
                    ("yara_powershell", RE_POWERSHELL_B64),
                    ("yara_creddump", RE_CRED_DUMP_YARA),
                ):
                    m = rx.search(line)
                    if m:
                        self.hit(rid, n, now_ts, f"Line #{n} ({src}): {line.strip()[:140]}", src, dst)

                if ("Failed password for" in line or "authentication failure" in line or
                        '"EventID":4625' in line or '"event_id":4625' in line):
                    ssh_fail_counter[src] += 1

                m_ua = RE_SCANNER_UA.search(line)
                if m_ua:
                    self.ioc_tools.add(m_ua.group(0))
                    self.hit("scanner_ua", n, now_ts, f"Line #{n} ({src}): Scanner={m_ua.group(0)}", src, dst, tool_name=m_ua.group(0))

                if progress_cb and n % 1000 == 0:
                    elapsed = max(time.time() - start_wall, 0.001)
                    progress_cb(n, self.bytes, file_size, int(n / elapsed))

        for src_ip, cnt in ssh_fail_counter.items():
            if cnt >= 5:
                self.hit("brute_force", None, now_ts, f"{src_ip}: {cnt} تلاش ناموفق ورود در فایل لاگ", src_ip, "LocalHost")

        if progress_cb:
            elapsed = max(time.time() - start_wall, 0.001)
            progress_cb(self.total, self.bytes, file_size, int(self.total / elapsed), done=True)

    def _run_optional_tshark(self, pcap_path):
        tshark_bin = find_tshark_binary()
        if not tshark_bin:
            return
        try:
            cmd = [tshark_bin, "-r", pcap_path, "-n", "-q", "-z", "io,phs"]
            res = subprocess.run(
                cmd, capture_output=True, text=True, timeout=25,
                encoding="utf-8", errors="ignore", creationflags=NO_WINDOW
            )
            if res.returncode == 0 and res.stdout:
                lines = [ln.strip() for ln in res.stdout.splitlines() if ln.strip()]
                self.tshark_summary = lines[:40]
        except Exception:
            pass

    # ------------------------------------------------------------------ مسیر سریع بومی
    def _run_fast(self, path, progress_cb, start_wall, file_size):
        rd = FIO.CaptureReader(path)          # Unsupported → هسته به scapy برمی‌گردد
        max_pkts = self.cfg.max_packets
        pkt_native = self.packet_native
        last_cb = 0.0
        n = 0
        try:
            for ts, lt, data, orig in rd:
                n += 1
                if self.stop_requested:
                    break
                if max_pkts and n > max_pkts:
                    break
                try:
                    pkt_native(n, ts, lt, data, orig)
                except Exception:
                    self.errors += 1
                    if len(self._first_errors) < 3:
                        self._first_errors.append(traceback.format_exc(limit=4))
                if progress_cb and (n & 0x7FF) == 0:
                    now = time.time()
                    if now - last_cb >= 0.12:
                        last_cb = now
                        progress_cb(n, rd.pos, file_size, int(n / max(now - start_wall, 0.001)))
        finally:
            rd.close()
        self.fast_used = True
        return True

    def packet_native(self, n, ts, lt, data, orig):
        size = len(data)
        self.total += 1
        self.bytes += size
        if self.t_first is None or ts < self.t_first:
            self.t_first = ts
        if self.t_last is None or ts > self.t_last:
            self.t_last = ts
        self.per_sec[int(ts)] += 1
        rec = FIO.decode(data, lt)
        if rec is None:
            self.proto["Other-L2"] += 1
            return
        kind, src, dst, a, b, fl, seq, payload, _wire = rec
        if kind == FIO.K_ARP:
            self._arp(n, ts, size, a, src, dst, fl[0], fl[1])
            return
        self._ip_common(n, ts, size, src, dst)
        if kind == FIO.K_TCP:
            self._tcp_packet(n, ts, size, src, dst, a, b, fl, seq, payload)
        elif kind == FIO.K_UDP:
            self._udp_packet(n, ts, size, src, dst, a, b, payload)
        elif kind == FIO.K_ICMP:
            self._icmp_packet(n, ts, size, src, dst, a, b, payload)
        elif kind == FIO.K_ICMP6:
            self.proto["ICMPv6"] += 1
            self.hub_flow("ICMPv6", src, 0, dst, 0, size, ts, n)
        else:
            self.proto["Other-L4"] += 1

    # ------------------------------------------------------------------ مسیر scapy (لینک‌تایپ‌های نادر)
    def packet(self, n, pkt):
        ts = float(pkt.time)
        size = len(pkt)
        self.total += 1
        self.bytes += size
        if self.t_first is None or ts < self.t_first:
            self.t_first = ts
        if self.t_last is None or ts > self.t_last:
            self.t_last = ts
        self.per_sec[int(ts)] += 1

        a = pkt.getlayer(ARP)
        if a is not None:
            self._arp(n, ts, size, int(a.op), a.psrc, a.pdst, a.hwsrc, a.hwdst)
            return
        ip = pkt.getlayer(IP)
        if ip is None:
            ip = pkt.getlayer(IPv6)
        if ip is None:
            self.proto["Other-L2"] += 1
            return
        src, dst = ip.src, ip.dst
        self._ip_common(n, ts, size, src, dst)
        l4 = ip.payload
        t = l4 if isinstance(l4, TCP) else None
        u = l4 if isinstance(l4, UDP) else None
        ic = l4 if isinstance(l4, ICMP) else None
        if t is None and u is None and ic is None and getattr(ip, "version", 4) == 6:
            t = pkt.getlayer(TCP)
            if t is None:
                u = pkt.getlayer(UDP)
        if t is not None:
            raw = t.getlayer(Raw)
            self._tcp_packet(n, ts, size, src, dst, t.sport, t.dport, int(t.flags) & 0x3F, int(getattr(t, "seq", 0)),
                             bytes(raw.load) if raw is not None else b"")
        elif u is not None:
            self._udp_packet(n, ts, size, src, dst, u.sport, u.dport, bytes(u.payload))
        elif ic is not None:
            raw = ic.getlayer(Raw)
            self._icmp_packet(n, ts, size, src, dst, int(ic.type), int(getattr(ic, "code", 0)), bytes(raw.load) if raw is not None else b"")
        else:
            self.proto["Other-L4"] += 1

    # ------------------------------------------------------------------ منطق مشترک (هر دو مسیر)
    def _arp(self, n, ts, size, op, psrc, pdst, hwsrc, hwdst):
        self.proto["ARP"] += 1
        if op == 2:
            self.arp_map[psrc].add(hwsrc)
            self.arp_replies[hwsrc] += 1
            self.arp_first.setdefault(psrc, (n, ts))
        self.hub_flow("ARP", psrc, 0, pdst, 0, size, ts, n)
        self.hub_arp(n, ts, op, psrc, pdst, hwsrc, hwdst)

    def _ip_common(self, n, ts, size, src, dst):
        pair = (src, dst)
        self.pair_bytes[pair] += size
        self.pair_pkts[pair] += 1
        self.ip_out[src] += size
        self.ip_in[dst] += size
        if self.ioc_feed["ips"]:
            self.feed_check_ip(n, ts, src, dst)

    def _tcp_packet(self, n, ts, size, src, dst, sp, dp, fl, seq, payload):
        self.proto["TCP"] += 1
        self.dports[dp] += 1
        is_synack = False
        if fl & 0x17 == 0x02:
            self.syn_targets[src].add((dst, dp))
            lst = self.syn_times[(src, dst, dp)]
            if len(lst) < 5000:
                lst.append(ts)
            self.syn_by_target[dst] += 1
            self.first_syn.setdefault(src, (n, ts))
        elif fl & 0x17 == 0x12:
            is_synack = True
            self.synack_by_server[src] += 1
        elif fl in (0x00, 0x01, 0x29):
            self.stealth[src] += 1
            self.stealth_first.setdefault(src, (n, ts, fl, dst))

        if dp in BAD_PORTS:
            bp = dp
        elif is_synack and sp in BAD_PORTS:
            bp = sp
        else:
            bp = 0
        if bp and (src, dst, bp) not in self.badport_seen:
            self.badport_seen.add((src, dst, bp))
            self.hit("bad_port", n, ts, f"{src}:{sp} → {dst}:{dp}  ({BAD_PORTS[bp]})",
                     src, dst, tool_name=BAD_PORTS[bp], artifact=f"TCP/{bp}")

        f = self.hub_flow("TCP", src, sp, dst, dp, size, ts, n, fl, len(payload))
        if payload:
            p = bytes(payload)
            if f is not None and not (f[8] & 0x100) and (f[9] + f[10]) < 4096:
                self.hub_detect(f, p, sp, dp, "TCP")
            self.tcp_payload(n, ts, src, dst, sp, dp, p, seq=seq, flow=f)

    def _udp_packet(self, n, ts, size, src, dst, sp, dp, p):
        self.proto["UDP"] += 1
        try:
            self.extra_udp(n, ts, src, dst, _UdpShim(sp, dp, p))
        except Exception:
            pass
        self.dports[dp] += 1
        f = self.hub_flow("UDP", src, sp, dst, dp, size, ts, n, 0, len(p))
        if p and f is not None and not (f[8] & 0x100) and (f[9] + f[10]) < 1200:
            self.hub_detect(f, p, sp, dp, "UDP")
        if p:
            if sp == 53 or dp == 53:
                msg = FIO.parse_dns(p)
                if msg is not None and (msg["qd"] or msg["an"]):
                    self.proto["DNS"] += 1
                    self.dns_native(n, ts, src, dst, msg)
            elif dp in (67, 68) or sp in (67, 68):
                self.proto["DHCP"] += 1
                d = FIO.parse_dhcp(p)
                if d:
                    self.dhcp_native(n, ts, src, dst, d)
            elif dp == 161 or sp == 161:
                self.proto["SNMP"] += 1
                self.snmp_native(n, ts, src, dst, p)
            elif dp == 88 or sp == 88:
                self.proto["Kerberos"] += 1
                if b"\x00\x00\x00\x17" in p[:200]:
                    self.hit("kerberos_attack", n, ts, f"{src} → {dst}:88 (Kerberos RC4-HMAC etype 23 detected)", src, dst, artifact="Kerberos RC4")
            self.hub_udp(n, ts, src, dst, sp, dp, p, f)

    def _icmp_packet(self, n, ts, size, src, dst, typ, code, p):
        self.proto["ICMP"] += 1
        pair = (src, dst)
        self.hub_flow("ICMP", src, 0, dst, 0, size, ts, n, 0, len(p))
        if typ == 8:
            self.ping_targets[src].add(dst)
            if len(p) > 100:
                self.icmp_big[pair] += 1
                self.icmp_first.setdefault(pair, (n, ts))
        elif typ == 5:
            self.hit("icmp_redirect", n, ts, f"{src} → {dst}", src, dst, artifact="ICMP Type 5 Redirect")
        self.hub_icmp(n, ts, src, dst, typ, code, len(p))

    def dhcp_native(self, n, ts, src, dst, d):
        msg_type = d["msg"]
        if msg_type in ("DISCOVER", "REQUEST") and d["mac"]:
            self.dhcp_macs.add(d["mac"])
        elif msg_type == "OFFER":
            self.dhcp_servers.add(src)
            if len(self.dhcp_servers) > 1:
                self.hit("dhcp_starvation", n, ts,
                         f"چندین سرور DHCP Offer در شبکه شناسایی شد: {', '.join(sorted(self.dhcp_servers))}",
                         src, dst, tool_name="Rogue DHCP Server", artifact="DHCP Offer")

    def dns_native(self, n, ts, src, dst, msg):
        if not msg["qr"]:
            if not msg["qd"]:
                return
            q = msg["qd"][0][0].rstrip(".").lower()
            if not q:
                return
            self.dns_q[q] += 1
            self.extra_name(n, ts, src, dst, q, "DNS")
            bd = get_base_domain(q)
            if len(self.dns_subs[bd]) < 20000:
                self.dns_subs[bd].add(q)
            if len(self.dns_lens[bd]) < 5000:
                self.dns_lens[bd].append(len(q))
            label = q.split(".")[0]
            if len(q) > 60 or (len(label) >= 20 and calc_entropy(label) > 3.7):
                self.ioc_domains.add(bd)
                self.hit("dns_suspicious", n, ts, f"{src} → {q[:90]}", src, dst, artifact=q[:50])
            if any(q.endswith(tld) for tld in SUSPICIOUS_TLDS):
                self.ioc_domains.add(bd)
                self.hit("suspicious_tld", n, ts, f"{src} → DNS Query for suspicious TLD: {q}", src, dst, artifact=bd)
        else:
            if msg["rcode"] == 3:
                self.nx[dst] += 1
                self.nx_first.setdefault(dst, (n, ts))
            elif msg["an"]:
                for name, rt, _ttl, data in msg["an"]:
                    if rt in (1, 28):
                        self.dns_resolved[str(data)] = name.rstrip(".").lower()

    def snmp_native(self, n, ts, src, dst, p):
        com = FIO.parse_snmp_community(p)
        if com is not None:
            masked = mask_str(com, self.cfg.mask_passwords)
            self.ioc_creds.append(f"SNMP {src} → {dst} (community={masked})")
            self.hit("snmp_community", n, ts, f"{src} → {dst}  community={masked}", src, dst, artifact="SNMP v1/v2c")
        else:
            self.hit("snmp_community", n, ts, f"{src} → {dst} (SNMP v1/v2c)", src, dst, artifact="SNMP v1/v2c")

    # ---- کمک‌های TLS برای ماژول پروتکل‌ها
    def _tls_ja3(self, p):
        return parse_tls_client_hello_ja3(p)

    @staticmethod
    def _ja3_name(h):
        return KNOWN_JA3_DB.get(h) if h else None

    def _carve_payload(self, n, ts, flow, file_type, raw_bytes):
        sha256 = hashlib.sha256(raw_bytes).hexdigest()
        md5 = hashlib.md5(raw_bytes).hexdigest()
        if sha256 in self.seen_hashes:
            return sha256, md5
        self.seen_hashes.add(sha256)
        self.extra_hash(n, ts, flow, sha256, md5)
        ent = calc_entropy(raw_bytes)
        self.ioc_hashes.add(f"SHA256:{sha256} ({file_type})")
        saved_path = None
        if "Flash" in file_type or "SWF" in file_type:
            suffix = ".swf"
        elif "PE" in file_type:
            suffix = ".exe"
        elif "ELF" in file_type:
            suffix = ".elf"
        elif "JAR" in file_type:
            suffix = ".jar"
        elif "ZIP" in file_type:
            suffix = ".zip"
        elif "Office" in file_type:
            suffix = ".docm"
        elif "PDF" in file_type:
            suffix = ".pdf"
        else:
            suffix = ".bin"
        try:
            self._carved_pending.append((raw_bytes, f"carved_{sha256[:12]}{suffix}", dict(
                n=n, ts=ts, flow=flow, direction="carved", name_source="carver", note=file_type, flags=["carved"], url="")))
        except Exception:
            pass
        if self.artifact_dir and self.sample_store:
            try:
                saved_path, _mode = self.sample_store.save(raw_bytes, sha256, suffix)
            except (OSError, RuntimeError, ValueError):
                saved_path = None
        if len(self.carved_artifacts) < 120:
            self.carved_artifacts.append({
                "pkt": n,
                "ts": fmt_ts(ts),
                "flow": flow,
                "type": file_type,
                "size": human_bytes(len(raw_bytes)),
                "bytes": len(raw_bytes),
                "entropy": round(ent, 2),
                "md5": md5,
                "sha256": sha256,
                "path": saved_path
            })
        return sha256, md5

    def tcp_payload(self, n, ts, src, dst, sp, dp, p, seq=None, flow=None):
        fr = flow            # رکورد جریان hub (می‌تواند None باشد)
        flow = f"{src}:{sp} → {dst}:{dp}"
        try:
            self.extra_tcp(n, ts, src, dst, sp, dp, p, flow)
        except Exception:
            pass
        if p and seq is not None and not (fr is not None and fr[7] in HUB_ENCRYPTED):
            key = (src, sp, dst, dp)
            if key in self.tcp_segments or len(self.tcp_segments) < self.cfg.max_streams:
                if self.tcp_stream_bytes[key] < self.cfg.max_stream_bytes and self.total_stream_mem < self.cfg.max_total_stream_bytes:
                    room = self.cfg.max_stream_bytes - self.tcp_stream_bytes[key]
                    chunk = p if len(p) <= room else bytes(p[:room])
                    if chunk:
                        self.tcp_segments[key].append((int(seq), chunk, n, ts))
                        self.tcp_stream_bytes[key] += len(chunk)
                        self.total_stream_mem += len(chunk)
                else:
                    self.streams_truncated += 1
        try:
            self.hub_tcp(n, ts, src, dst, sp, dp, p, fr)
        except Exception:
            pass

        # TLS ClientHello (JA3 + SNI)
        if p[:1] == b"\x16" and len(p) > 45 and p[5:6] == b"\x01":
            self.proto["TLS"] += 1
            if dp == 80 or sp == 80:
                self.hit("proto_port_mismatch", n, ts, f"{flow} [TLS handshake on HTTP port 80]", src, dst, artifact="TLS/80")
            ver, sni, ja3_hash, _ja3_str = parse_tls_client_hello_ja3(p)
            if sni:
                self.sni[sni] += 1
                self.extra_name(n, ts, src, dst, sni, "TLS SNI")
                if any(sni.lower().endswith(tld) for tld in SUSPICIOUS_TLDS):
                    self.ioc_domains.add(sni.lower())
                    self.hit("suspicious_tld", n, ts, f"{flow} TLS SNI={sni}", src, dst, artifact=sni.lower())
            if ja3_hash:
                self.ja3_Seen[ja3_hash] += 1
                self.ja3_details[ja3_hash] = f"SNI={sni or '-'} | Src={src}"
                if ja3_hash in KNOWN_JA3_DB:
                    desc, is_mal = KNOWN_JA3_DB[ja3_hash]
                    self.ioc_tools.add(desc)
                    self.ioc_hashes.add(f"JA3:{ja3_hash} ({desc})")
                    if is_mal:
                        self.hit(
                            "ja3_malicious", n, ts,
                            f"{flow}  JA3={ja3_hash} [{desc}] SNI={sni}",
                            src, dst, tool_name=desc, artifact=f"JA3:{ja3_hash}"
                        )
            if ver in (0x0300, 0x0301, 0x0302):
                name = {0x0300: "SSLv3", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1"}[ver]
                self.hit("tls_legacy", n, ts, f"{flow}  {name}  SNI={sni}", src, dst, artifact=name)
            return

        # TLS ServerHello (JA3S)
        if p[:1] == b"\x16" and len(p) > 42 and p[5:6] == b"\x02":
            self.proto["TLS"] += 1
            _, ja3s_hash = parse_tls_server_hello_ja3s(p)
            if ja3s_hash:
                self.ja3s_seen[ja3s_hash] += 1
                if ja3s_hash in KNOWN_JA3S_DB:
                    desc, is_mal = KNOWN_JA3S_DB[ja3s_hash]
                    self.ioc_tools.add(desc)
                    self.ioc_hashes.add(f"JA3S:{ja3s_hash} ({desc})")
                    if is_mal:
                        self.hit(
                            "ja3_malicious", n, ts,
                            f"{flow}  JA3S={ja3s_hash} [{desc}]",
                            dst, src, tool_name=desc, artifact=f"JA3S:{ja3s_hash}"
                        )
            return

        if dp in (445, 139) or sp in (445, 139):
            self.proto["SMB"] += 1
            if b"\xffSMB" in p[:64] or b"IPC$" in p or b"ADMIN$" in p or b"C$" in p or b"\x00I\x00P\x00C\x00$" in p:
                tag = "SMBv1 / Admin Share Access"
                self.hit("smb_lateral", n, ts, f"{flow} ({tag})", src, dst, artifact="SMB IPC$/ADMIN$/SMBv1")

        if dp == 88 or sp == 88:
            self.proto["Kerberos"] += 1
            if b"\x00\x00\x00\x17" in p[:250]:
                self.hit("kerberos_attack", n, ts, f"{flow} (Kerberos RC4-HMAC etype 23 detected)", src, dst, artifact="Kerberos RC4")

        if p.startswith(HTTP_METHODS):
            self.proto["HTTP"] += 1
            self.http(n, ts, flow, src, dst, dp, p)
            return

        if len(p) >= 600 and dp not in (443, 8443, 22, 993, 995, 465) and sp not in (443, 8443, 22, 993, 995, 465):
            _s = p[:8192]
            nontext = len(_s.translate(None, _NONTEXT_DEL)) / len(_s)
            if nontext >= 0.38:
                ent = calc_entropy(_s)
                if ent >= 7.60:
                    self.hit(
                        "zero_day_entropy", n, ts,
                        f"{flow} [high-entropy binary stream: entropy={ent:.2f}, nontext={nontext:.0%}]",
                        src, dst, artifact=f"HighEntropy:{ent:.2f}"
                    )

        low = p[:2500].decode("latin-1", "ignore")
        up = low.upper()
        _h = p[:2500]
        _texty = len(_h.translate(None, _NONTEXT_DEL)) * 2 < len(_h)

        m_ek = RE_EK_LANDING.search(low) if _texty else None
        if m_ek:
            self.hit(
                "ek_exploit_kit", n, ts,
                f"{flow}  [Exploit Kit Script Indicator: {m_ek.group(0)[:45]!r}]",
                src, dst, tool_name="RIG / Exploit Kit Landing", artifact=m_ek.group(0)[:35]
            )

        m_rev = RE_REVSHELL.search(low) if _texty else None
        if m_rev:
            self.hit("reverse_shell", n, ts, f"{flow}  [match: {m_rev.group(0)[:45]!r}]", src, dst, artifact="Reverse Shell Stream")

        m_ps = RE_POWERSHELL_B64.search(low) if _texty else None
        if m_ps:
            self.hit("yara_powershell", n, ts, f"{flow}  [match: {m_ps.group(0)[:50]!r}]", src, dst, tool_name="PowerShell Empire/Encoded")

        m_cd = RE_CRED_DUMP_YARA.search(low) if _texty else None
        if m_cd:
            self.hit("yara_creddump", n, ts, f"{flow}  [match: {m_cd.group(0)[:50]!r}]", src, dst, tool_name="Mimikatz / LSASS Dumper")

        if dp == 21 or sp == 21:
            self.proto["FTP"] += 1
            m = re.match(r"(USER|PASS)\s+(.+)", low.strip(), re.I)
            if m and dp == 21:
                val = mask_str(m.group(2).strip(), self.cfg.mask_passwords if m.group(1).upper() == "PASS" else False)
                self.ioc_creds.append(f"FTP {src} → {dst}: {m.group(1)} {val}")
                self.hit("ftp_cred", n, ts, f"{flow}  {m.group(1)} {val}", src, dst, artifact="FTP Cleartext")

        elif dp == 23 or sp == 23:
            self.proto["Telnet"] += 1
            if dp == 23:
                self.cleartext_hosts[dst] += 1
                if self.hits.get("telnet", {}).get("count", 0) < 5 or len(p) > 3:
                    self.hit("telnet", n, ts, f"{flow}  ({len(p)} bytes)", src, dst, artifact="Telnet/23")

        elif dp in (110, 143, 25, 587):
            if re.match(r"(USER|PASS|AUTH|LOGIN|\w+\s+LOGIN)\s+", up.strip()):
                parts = low.strip().split()
                masked = mask_str(parts[-1], self.cfg.mask_passwords) if len(parts) > 1 else ""
                self.ioc_creds.append(f"Mail {src} → {dst}:{dp} ({parts[0]} {masked})")
                self.hit("mail_cred", n, ts, f"{flow}  {parts[0]} {masked}", src, dst, artifact=f"Cleartext Mail/{dp}")

        elif dp in (6379, 3306, 5432, 1433):
            if b"AUTH " in p[:60].upper() or b"SELECT " in p[:100].upper():
                self.hit("cleartext_db", n, ts, f"{flow} ({SERVICES.get(dp, 'DB')} cleartext)", src, dst, artifact=f"DB/{dp}")

    def http(self, n, ts, flow, src, dst, dp, p):
        head, _, body = p.partition(b"\r\n\r\n")
        text = head.decode("latin-1", "ignore")
        lines = text.split("\r\n")
        try:
            method, uri, _ver = lines[0].split(" ", 2)
        except ValueError:
            return
        hdr = {}
        for ln in lines[1:]:
            if ":" in ln:
                k, v = ln.split(":", 1)
                hdr[k.strip().lower()] = v.strip()
        host = hdr.get("host", dst)
        ua = hdr.get("user-agent", "")
        referer = hdr.get("referer", "")
        self.http_hosts[host] += 1
        self.http_methods[method] += 1
        if ua:
            self.http_uas[ua[:120]] += 1
        if len(self.http_urls) < 80:
            self.http_urls.append(f"{method} {host}{uri[:120]}")
        self.cleartext_hosts[dst] += 1

        if referer:
            ref_list = self.client_referers[src]
            if not ref_list or ref_list[-1][1] != host:
                ref_list.append((ts, host, referer[:80], uri[:60]))

        body_str = body[:4000].decode("latin-1", "ignore")
        decoded = unquote_plus(unquote_plus(lines[0])) + " " + unquote(body_str) + " " + unquote(text[len(lines[0]):len(lines[0]) + 60000])
        decoded += " " + " ".join(hdr.get(h, "") for h in ("cookie", "referer", "x-forwarded-for", "user-agent"))
        tag = f"{flow}  {method} {host}{uri[:80]}"

        for rid, rx in (
            ("http_sqli", RE_SQLI),
            ("http_xss", RE_XSS),
            ("http_traversal", RE_TRAV),
            ("http_cmdi", RE_CMDI),
            ("http_log4j", RE_LOG4J),
            ("http_shellshock", RE_SHOCK),
            ("http_xxe_ssrf", RE_XXE_SSRF),
            ("http_webshell", RE_WEBSHELL),
            ("yara_powershell", RE_POWERSHELL_B64),
        ):
            m = rx.search(decoded) or (rx.search(text) if rid == "http_shellshock" else None)
            if m:
                self.hit(rid, n, ts, f"{tag}  [match: {m.group(0)[:40]!r}]", src, dst, artifact=uri[:50])

        if ua:
            m_ua = RE_SCANNER_UA.search(ua)
            if m_ua:
                self.ioc_uas.add(ua[:100])
                self.hit("scanner_ua", n, ts, f"{src} UA={ua[:70]}", src, dst, tool_name=m_ua.group(0), artifact=ua[:50])

        if RE_SENS_PATH.search(uri):
            self.hit("sensitive_path", n, ts, tag, src, dst, artifact=uri[:50])

        host_header = hdr.get("host", "")
        host_clean = host_header.split(":", 1)[0].strip("[]")
        if host_header:
            try:
                ip_obj = ipaddress.ip_address(host_clean)
                if not ip_obj.is_private:
                    self.hit("http_direct_ip", n, ts, f"{tag} [HTTP Host is a literal public IP: {host_clean}]", src, dst, artifact=host_clean)
            except ValueError:
                pass
        host_l = host_clean.lower().rstrip(".")
        if any(host_l.endswith(tld) for tld in SUSPICIOUS_TLDS):
            self.ioc_domains.add(host_l)
            self.hit("suspicious_tld", n, ts, f"{tag} [domain suffix={next(t for t in SUSPICIOUS_TLDS if host_l.endswith(t))}]", src, dst, artifact=host_l)

        if RE_EK_LANDING.search(decoded) or RE_RIG_URI.search(uri):
            m = RE_EK_LANDING.search(decoded) or RE_RIG_URI.search(uri)
            if host_l:
                self.ioc_domains.add(host_l)
            self.hit("ek_exploit_kit", n, ts, f"{tag} [exploit-kit indicator={m.group(0)[:55]!r}]", dst, src, tool_name="RIG Exploit Kit", artifact=uri[:80])

        malware_match = RE_REDLINE.search(decoded) or RE_ICEDID_EMOTET.search(decoded) or RE_STEALER_EXFIL.search(decoded)
        if malware_match:
            self.hit("malware_c2_family", n, ts, f"{tag} [family/exfil indicator={malware_match.group(0)[:55]!r}]", src, dst, tool_name="Malware C2 / Stealer", artifact=host_l or dst)

        if is_cobalt_strike_checksum8(uri):
            self.hit("malware_c2_family", n, ts, f"{tag} [Cobalt Strike checksum8-like URI]", src, dst, tool_name="Cobalt Strike Stager", artifact=uri[:60])

        if dp in (443, 8443, 9443) and p.startswith(HTTP_METHODS):
            self.hit("proto_port_mismatch", n, ts, f"{tag} [cleartext HTTP on TLS-associated port {dp}]", src, dst, artifact=f"TCP/{dp}")

        if (RE_EK_LANDING.search(decoded) or RE_RIG_URI.search(uri)) and re.search(r"(?i)(\.swf|\.exe|\.dll|\.cab|\.zip|application/x-shockwave-flash)", decoded):
            self.hit("http_driveby_chain", n, ts, f"{tag} [exploit landing page + payload/download indicator]", dst, src, tool_name="Drive-By Exploit Chain", artifact=uri[:80])

        auth = hdr.get("authorization", "")
        if auth.lower().startswith("basic "):
            try:
                u, _, pw = base64.b64decode(auth[6:]).decode("utf-8", "ignore").partition(":")
                mpw = mask_str(pw, self.cfg.mask_passwords)
                self.ioc_creds.append(f"HTTP BasicAuth {host}: user={u} pass={mpw}")
                self.hit("http_basic_auth", n, ts, f"{flow}  user={u}  pass={mpw}", src, dst, artifact=f"HTTP BasicAuth ({host})")
            except Exception:
                pass

        for m in RE_PASSFIELD.finditer(body_str):
            mpw = mask_str(unquote(m.group(2)), self.cfg.mask_passwords)
            self.ioc_creds.append(f"HTTP Form {host}: {m.group(1)}={mpw}")
            self.hit("http_pass_form", n, ts, f"{tag}  {m.group(1)}={mpw}", src, dst, artifact=f"Cleartext Form ({host})")
            break

    @staticmethod
    def _merge_tcp_segments(segments):
        if not segments:
            return b"", None, None
        capture_order = sorted(segments, key=lambda x: x[2])
        base = int(capture_order[0][0]) & 0xffffffff
        unwrapped = []
        for seq, data, n, ts in capture_order:
            raw = int(seq) & 0xffffffff
            delta = ((raw - base + (1 << 31)) & 0xffffffff) - (1 << 31)
            unwrapped.append((base + delta, bytes(data), n, ts))
        ordered = sorted(unwrapped, key=lambda x: (x[0], x[2]))
        start_seq = ordered[0][0]
        out = bytearray()
        first_n, first_ts = capture_order[0][2], capture_order[0][3]
        for seq, data, n, ts in ordered:
            if not data:
                continue
            offset = seq - start_seq
            if offset > len(out):
                out.extend(b"\x00" * min(offset - len(out), 2 * 1024 * 1024))
            if offset < len(out):
                overlap = min(len(out) - offset, len(data))
                if overlap >= len(data):
                    continue
                data = data[overlap:]
                offset += overlap
            if offset == len(out):
                out.extend(data)
        return bytes(out), first_n, first_ts

    @staticmethod
    def _decode_http_content(data, headers):
        enc = headers.get("content-encoding", "").lower().strip()
        limit = 32 * 1024 * 1024
        try:
            if ("br" in enc) and HAS_BROTLI:
                out = brotli.decompress(data)
                return out if out else data
            if "gzip" in enc or data.startswith(b"\x1f\x8b\x08"):
                obj = zlib.decompressobj(16 + zlib.MAX_WBITS)
                out = obj.decompress(data, limit)
                try:
                    out += obj.flush()
                except Exception:
                    pass
                return out if out else data
            if "deflate" in enc:
                for wbits in (zlib.MAX_WBITS, -zlib.MAX_WBITS):
                    try:
                        obj = zlib.decompressobj(wbits)
                        out = obj.decompress(data, limit)
                        return out if out else data
                    except zlib.error:
                        continue
        except Exception:
            return data
        return data

    @staticmethod
    def _decode_chunked(data, max_output=32 * 1024 * 1024):
        out, pos = bytearray(), 0
        while pos < len(data):
            eol = data.find(b"\r\n", pos)
            if eol < 0:
                break
            try:
                size = int(data[pos:eol].split(b";", 1)[0].strip(), 16)
            except ValueError:
                return bytes(out) if out else None
            pos = eol + 2
            if size == 0:
                return bytes(out)
            if size < 0 or len(out) + size > max_output:
                break
            chunk_end = min(pos + size, len(data))
            out.extend(data[pos:chunk_end])
            pos = chunk_end + 2
        return bytes(out) if out else None

    @staticmethod
    def _parse_http_headers(head):
        headers = {}
        for line in head.split(b"\r\n")[1:]:
            if b":" not in line:
                continue
            k, v = line.split(b":", 1)
            key = k.decode("latin-1", "ignore").strip().lower()
            value = v.decode("latin-1", "ignore").strip()
            headers[key] = headers[key] + ", " + value if key in headers else value
        return headers

    @staticmethod
    def _http_message_body(body, headers, max_len=32 * 1024 * 1024):
        if "chunked" in headers.get("transfer-encoding", "").lower():
            decoded = PcapAnalyzer._decode_chunked(body, max_len)
            return (decoded, True, len(decoded)) if decoded is not None else (body, len(body) > 0, len(body))
        if "content-length" in headers:
            try:
                n = int(headers["content-length"])
                if n < 0 or n > max_len:
                    return body, len(body) > 0, min(len(body), max_len)
                return body[:n], len(body) > 0, min(n, len(body))
            except ValueError:
                return body, len(body) > 0, len(body)
        return body, len(body) > 0, len(body)

    def _analyze_reassembled_streams(self):
        exploit_markers = (
            b"unescape(", b"activexobject", b"createobject(", b"shellcode",
            b"spray(", b"heap spray", b"document.write(", b"flashvars",
            b"swfobject", b"application/x-shockwave-flash", b"java.applet",
            b"deployjava", b"cve-2013-", b"cve-2014-", b"cve-2015-",
            b"cve-2016-", b"cve-2021-", b"exploit kit", b"exploit-kit", b"gate.php",
            b"landing.php", b"redirect.php", b"adodb.stream", b"wscript.shell"
        )
        suspicious_script = (
            b"fromcharcode(", b"atob(", b"eval(unescape(", b"function(p,a,c,k,e",
            b"document.createelement('iframe')", b"window.location",
            b"navigator.plugins", b"activexobject", b"vbscript:"
        )
        req_re = re.compile(rb"(?i)(?:GET|POST|PUT|HEAD|OPTIONS|DELETE|PATCH) [^\r\n]{1,4096} HTTP/1\.[01]\r\n")
        resp_re = re.compile(rb"HTTP/1\.[01] [0-9]{3} [^\r\n]*\r\n")

        for flow_key, segments in list(self.tcp_segments.items()):
            stream, first_n, first_ts = self._merge_tcp_segments(segments)
            if not stream:
                continue
            self.reassembled_streams += 1
            src, sp, dst, dp = flow_key
            flow = f"{src}:{sp} → {dst}:{dp}"
            seqs = sorted((int(x[0]) & 0xffffffff, len(x[1])) for x in segments if x[1])
            has_gap = False
            if len(seqs) > 1:
                prev_end = seqs[0][0] + seqs[0][1]
                for q, ln in seqs[1:]:
                    if q > prev_end and q - prev_end < 0x80000000:
                        has_gap = True
                    prev_end = max(prev_end, q + ln)
            self.tcp_stream_quality[flow_key] = {
                "has_gap": has_gap, "segments": len(segments), "bytes": len(stream)
            }

            starts = sorted(
                [(m.start(), "request") for m in req_re.finditer(stream)] +
                [(m.start(), "response") for m in resp_re.finditer(stream)]
            )

            for idx, (pos, kind) in enumerate(starts[:100]):
                next_pos = starts[idx + 1][0] if idx + 1 < len(starts) else len(stream)
                msg = stream[pos:next_pos]
                head, sep, raw_body = msg.partition(b"\r\n\r\n")
                if not sep:
                    continue
                hdrs = self._parse_http_headers(head)
                body, has_body, _ = self._http_message_body(raw_body, hdrs)
                decoded_body = body

                if kind == "request":
                    try:
                        self.http(first_n or 0, first_ts, flow, src, dst, dp, head + b"\r\n\r\n" + body)
                    except Exception:
                        pass
                elif has_body:
                    if "location" in hdrs and len(self.http_redirects) < 50:
                        self.http_redirects.append(f"{src} → {dst} Redirects to: {hdrs['location'][:100]}")

                    decoded_body = self._decode_http_content(body, hdrs)
                    found_bin, bin_type, is_xor, carved_bytes = detect_pe_or_xor_pe(decoded_body)
                    if found_bin:
                        sha256, _ = self._carve_payload(first_n or 0, first_ts, flow, bin_type, carved_bytes)
                        if "Flash" in bin_type:
                            self.hit(
                                "ek_flash_payload", first_n, first_ts,
                                f"{flow} | HTTP Response ({len(carved_bytes):,} bytes) | {bin_type} | SHA256={sha256}",
                                src, dst, tool_name="RIG Exploit Kit (Flash Exploit)", artifact=f"SWF:{sha256[:16]}"
                            )
                        elif is_xor:
                            self.hit(
                                "xor_mal_payload", first_n, first_ts,
                                f"{flow} | HTTP Response ({len(carved_bytes):,} bytes) | {bin_type} | Decrypted SHA256={sha256}",
                                src, dst, tool_name="RIG EK XOR Dropper", artifact=f"XOR-PE:{sha256[:16]}"
                            )
                        else:
                            self.hit(
                                "exe_over_http", first_n, first_ts,
                                f"{flow} | HTTP Response ({len(carved_bytes):,} bytes) | {bin_type} | SHA256={sha256}",
                                src, dst, tool_name="HTTP Malware Dropper", artifact=f"SHA256:{sha256[:16]}"
                            )

                    resp_text = decoded_body[:65536].decode("latin-1", "ignore")
                    m_ek_resp = RE_EK_LANDING.search(resp_text)
                    if m_ek_resp:
                        self.hit(
                            "ek_exploit_kit", first_n, first_ts,
                            f"{flow} | Decompressed HTTP Response Landing Page | match={m_ek_resp.group(0)[:55]!r}",
                            src, dst, tool_name="RIG Exploit Kit Landing Page", artifact=m_ek_resp.group(0)[:40]
                        )

                sample = (head + b"\r\n\r\n" + decoded_body)[:1024 * 1024].lower()
                decoded_sample = sample
                for _ in range(2):          # v8: روی بایت‌ها و فقط وقتی «%» هست (۲۰× سریع‌تر از unquote_plus روی str)
                    if b"%" not in decoded_sample and b"+" not in decoded_sample:
                        break
                    try:
                        decoded_sample = unquote_to_bytes(decoded_sample.replace(b"+", b" "))
                    except Exception:
                        break
                markers = [m.decode("latin-1", "ignore") for m in exploit_markers if m in decoded_sample]
                scripts = [m.decode("latin-1", "ignore") for m in suspicious_script if m in decoded_sample]
                if len(markers) >= 2 or (markers and len(scripts) >= 2):
                    self.hit(
                        "exploit_kit_activity", first_n, first_ts,
                        f"{flow} | reconstructed HTTP {kind} | markers={', '.join((markers + scripts)[:8])}",
                        src, dst, tool_name="Exploit-kit / drive-by heuristic",
                        artifact=f"HTTP stream {src}:{sp}->{dst}:{dp}"
                    )

            if not starts:
                found_raw, raw_type, raw_xor, raw_carved = detect_pe_or_xor_pe(stream)
                if found_raw:
                    sha256, _ = self._carve_payload(first_n or 0, first_ts, flow, raw_type, raw_carved)
                    rid = "ek_flash_payload" if "Flash" in raw_type else ("xor_mal_payload" if raw_xor else "exe_over_http")
                    self.hit(rid, first_n, first_ts, f"{flow} | Raw TCP Stream | {raw_type} | SHA256={sha256}", src, dst, artifact=f"SHA256:{sha256[:16]}")

    def finish(self):
        self.hub_prepare_store()
        self._analyze_reassembled_streams()
        self.hub_finish()
        self.threat_finish()

        if len(self.dhcp_macs) >= 40:
            self.hit(
                "dhcp_starvation", None, self.t_first,
                f"ارسال درخواست‌های DHCP از {len(self.dhcp_macs)} آدرس MAC مختلف (احتمال حمله DHCP Starvation)",
                None, None, tool_name="Yersinia / DHCP Starvation"
            )

        for client_ip, hops in self.client_referers.items():
            distinct_hosts = []
            for _, h, _, _ in hops:
                if h not in distinct_hosts:
                    distinct_hosts.append(h)
            if len(distinct_hosts) >= 3:
                chain_str = " → ".join(distinct_hosts[:6])
                self.hit(
                    "http_driveby_chain", None, hops[0][0],
                    f"کلاینت {client_ip} در زنجیره تغییر مسیر چندمرحله‌ای وب: {chain_str}",
                    client_ip, None, tool_name="Drive-By Redirect Chain", artifact=chain_str[:65]
                )

        by_port = collections.defaultdict(set)
        for src, targets in self.syn_targets.items():
            per_dst = collections.defaultdict(set)
            for d, p in targets:
                per_dst[d].add(p)
                by_port[(src, p)].add(d)
            for d, ps in per_dst.items():
                if len(ps) >= self.cfg.port_scan_thresh:
                    n, ts = self.first_syn[src]
                    self.hit(
                        "port_scan", n, ts,
                        f"{src} → {d}: {len(ps)} پورت مختلف (نمونه: {sorted(ps)[:8]})",
                        src, d, tool_name="Port Scanner (Nmap/Masscan)"
                    )
        for (src, p), dsts in by_port.items():
            if len(dsts) >= self.cfg.host_sweep_thresh:
                n, ts = self.first_syn[src]
                self.hit("host_sweep", n, ts, f"{src} → پورت {p}: {len(dsts)} میزبان مختلف", src, None)

        for src, c in self.stealth.items():
            if c >= 5:
                n, ts, fl, dst = self.stealth_first[src]
                kind = {0: "NULL", 1: "FIN", 0x29: "Xmas"}.get(fl, "?")
                self.hit("stealth_scan", n, ts, f"{src} → {dst}: {c} بسته {kind}", src, dst, tool_name=f"Nmap {kind} Scan")

        for (src, dst, dp), times in self.syn_times.items():
            times.sort()
            if dp in BRUTE_PORTS and len(times) >= self.cfg.brute_force_thresh:
                dur = max(times[-1] - times[0], 1)
                self.hit(
                    "brute_force", None, times[0],
                    f"{src} → {dst}:{dp} ({SERVICES.get(dp, '')})  {len(times)} اتصال در {dur:.0f}s",
                    src, dst, tool_name="Hydra/Medusa/BruteForcer", artifact=f"{SERVICES.get(dp, 'Port')}/{dp}"
                )
            elif len(times) >= 8 and dp != 53:
                iv = [b - a for a, b in zip(times, times[1:])]
                mean = statistics.mean(iv)
                if 1 <= mean <= 3600:
                    cv = statistics.pstdev(iv) / mean
                    if cv < self.cfg.beacon_cv_thresh:
                        self.hit(
                            "beacon", None, times[0],
                            f"{src} → {dst}:{dp}  {len(times)} اتصال منظم، میانگین فاصله {mean:.1f}s (CV={cv:.2f})",
                            src, dst, artifact=f"Beacon {dst}:{dp}"
                        )

        for dst, c in self.syn_by_target.items():
            if c >= self.cfg.syn_flood_thresh and self.synack_by_server[dst] < c * 0.3:
                self.hit(
                    "syn_flood", None, self.t_first,
                    f"هدف {dst}: {c} بسته SYN دریافت شده، فقط {self.synack_by_server[dst]} پاسخ SYN-ACK",
                    None, dst
                )

        for ip, macs in self.arp_map.items():
            if len(macs) > 1:
                n, ts = self.arp_first.get(ip, (None, None))
                self.hit(
                    "arp_spoof", n, ts,
                    f"IP {ip} با چند آدرس MAC دیده شد: {', '.join(sorted(macs))}",
                    ip, None, tool_name="ARP Spoofer (Ettercap/Bettercap)"
                )
        for mac, c in self.arp_replies.items():
            if c >= 50:
                self.hit("arp_flood", None, self.t_first, f"MAC {mac}: ارسال {c} پاسخ ARP Reply", None, None)

        for bd, subs in self.dns_subs.items():
            avg = statistics.mean(self.dns_lens[bd]) if self.dns_lens[bd] else 0
            if len(subs) >= self.cfg.dns_tunnel_subs or (len(subs) >= 10 and avg > 50):
                self.ioc_domains.add(bd)
                self.hit(
                    "dns_tunnel", None, self.t_first,
                    f"دامنه {bd}: {len(subs)} زیردامنه یکتا، میانگین طول {avg:.0f} کاراکتر",
                    tool_name="DNS Tunnel (Iodine/DNScat2)", artifact=bd
                )
        for client, c in self.nx.items():
            if c >= self.cfg.dga_nx_thresh:
                n, ts = self.nx_first[client]
                self.hit("dga", n, ts, f"کلاینت {client}: دریافت {c} پاسخ NXDOMAIN", client, None)

        for src, t in self.ping_targets.items():
            if len(t) >= self.cfg.host_sweep_thresh:
                self.hit("ping_sweep", None, self.t_first, f"{src} → پینگ به {len(t)} میزبان", src, None)
        for (s, d), c in self.icmp_big.items():
            if c >= 15:
                n, ts = self.icmp_first[(s, d)]
                self.hit("icmp_tunnel", n, ts, f"{s} → {d}: {c} بسته Echo با Payload بزرگتر از 100 بایت", s, d)

        exfil_bytes_limit = self.cfg.exfil_mb_thresh * 1024 * 1024
        for (s, d), b in self.pair_bytes.items():
            if is_private_ip(s) and not is_private_ip(d) and b >= exfil_bytes_limit:
                back = self.pair_bytes.get((d, s), 1)
                if b / max(back, 1) > 5:
                    self.hit(
                        "exfil", None, self.t_first,
                        f"{s} → {d}: {human_bytes(b)} داده ارسالی در برابر {human_bytes(back)} دریافتی",
                        s, d
                    )

    def findings(self):
        out = []
        for rid, h in self.hits.items():
            r = RULES[rid]
            out.append({
                "id": rid,
                "severity": r["sev"],
                "category": I18N.rule_text(rid, "cat", RULES, RULES_EN),
                "kill_chain": r["kill_chain"],
                "pyramid": r["pyramid"],
                "title": I18N.rule_text(rid, "title", RULES, RULES_EN),
                "description": I18N.rule_text(rid, "desc", RULES, RULES_EN),
                "mitre": r["mitre"],
                "d3fend": r["d3fend"],
                "car": r["car"],
                "recommendation": I18N.rule_text(rid, "rec", RULES, RULES_EN),
                "category_fa": r["cat"], "title_fa": r["title"], "description_fa": r["desc"], "recommendation_fa": r["rec"],
                "category_en": (r.get("en") or {}).get("cat") or RULES_EN.get(rid, ("",) * 4)[0] or r["cat"],
                "title_en": (r.get("en") or {}).get("title") or RULES_EN.get(rid, ("", ""))[1] or r["title"],
                "description_en": (r.get("en") or {}).get("desc") or RULES_EN.get(rid, ("", "", ""))[2] or r["desc"],
                "recommendation_en": (r.get("en") or {}).get("rec") or RULES_EN.get(rid, ("", "", "", ""))[3] or r["rec"],
                "count": h["count"],
                "evidence": h["ex"],
                "actors": sorted(h["actors"]),
                "targets": sorted(h["targets"]),
                "first_ts": fmt_ts(h["first"][1]) if h["first"] and h["first"][1] else "-",
                "first_packet": h["first"][0] if h["first"] else None
            })
        out.sort(key=lambda f: (SEV_ORDER[f["severity"]], -f["count"]))
        return out

    def stats(self):
        dur = (self.t_last - self.t_first) if (self.t_first and self.t_last) else 0
        bins = [0] * 60
        if self.per_sec and dur > 0:
            for s, c in self.per_sec.items():
                bins[max(0, min(int((s - self.t_first) / dur * 60), 59))] += c
        elif self.per_sec:
            bins[0] = self.total

        return {
            "packets": self.total,
            "bytes": self.bytes,
            "duration_s": round(dur, 2),
            "start": fmt_ts(self.t_first) if self.t_first else "-",
            "end": fmt_ts(self.t_last) if self.t_last else "-",
            "protocols": dict(self.proto.most_common(15)),
            "top_talkers": [
                {
                    "src": s, "dst": d,
                    "dst_domain": self.dns_resolved.get(d, ""),
                    "bytes": b, "packets": self.pair_pkts[(s, d)]
                }
                for (s, d), b in self.pair_bytes.most_common(15)
            ],
            "top_ports": [
                {"port": p, "service": SERVICES.get(p, "Unknown"), "packets": c}
                for p, c in self.dports.most_common(15)
            ],
            "top_dns": self.dns_q.most_common(20),
            "tls_sni": self.sni.most_common(20),
            "ja3_fingerprints": [
                {"hash": h, "count": c, "info": self.ja3_details.get(h, ""), "known": KNOWN_JA3_DB.get(h, ("Unknown Client", False))[0]}
                for h, c in self.ja3_Seen.most_common(15)
            ],
            "ja3s_fingerprints": [
                {"hash": h, "count": c, "known": KNOWN_JA3S_DB.get(h, ("Unknown Server", False))[0]}
                for h, c in self.ja3s_seen.most_common(10)
            ],
            "carved_files": self.carved_artifacts,
            "artifact_dir": self.artifact_dir,
            "sample_mode": self.sample_store.mode if self.sample_store else None,
            "feed_loaded": getattr(self, "feed_loaded", 0),
            "http_hosts": self.http_hosts.most_common(15),
            "http_user_agents": self.http_uas.most_common(12),
            "http_methods": dict(self.http_methods),
            "http_sample": self.http_urls[:25],
            "http_redirects": self.http_redirects[:25],
            "unique_ips": len(set(self.ip_out) | set(self.ip_in)),
            "timeline": bins,
            "top_senders": self.ip_out.most_common(10),
            "tshark_phs": self.tshark_summary,
            "reassembled_streams": self.reassembled_streams,
            "streams_truncated": self.streams_truncated,
            "streams_with_gaps": sum(1 for q in self.tcp_stream_quality.values() if q.get("has_gap")),
            "tcp_stream_quality": [{"flow": str(k), **v} for k, v in list(self.tcp_stream_quality.items())[:100]],
            "hub": self._hub(),
            "engine": {"fast_io": bool(getattr(self, "fast_used", False)), "scapy": HAS_SCAPY, "errors": self.errors,
                       "read_error": self.read_error, "flows": len(self.flows)},
        }

    def _hub(self):
        if self._hub_cache is None:
            self._hub_cache = self.hub_export(self.findings())
        return self._hub_cache

    def generate_detection_arsenal(self, f_list):
        bad_ips = [
            ip for ip, roles in self.ioc_ips.items()
            if any(k in str(roles) for k in ("Attacker", "Scanner", "C2", "MITM", "Exploit", "Server"))
        ]
        bad_doms = sorted(self.ioc_domains)
        bad_ja3 = [h for h in self.ja3_Seen if h in KNOWN_JA3_DB and KNOWN_JA3_DB[h][1]]

        ws_filters = []
        if bad_ips:
            ip_expr = " || ".join(f"ip.addr == {ip}" for ip in bad_ips[:8])
            ws_filters.append(f"# فیلتر ترافیک IPهای مهاجم، Exploit Kit و C2:\n({ip_expr})")
        if bad_doms:
            dom_expr = " || ".join(f'http.host contains "{d}" || dns.qry.name contains "{d}"' for d in bad_doms[:5])
            ws_filters.append(f"# فیلتر دامنه‌های مشکوک، گیت‌های تغییر مسیر و تونلینگ:\n({dom_expr})")
        ws_filters.append('# فیلتر شکار فایل‌های اجرایی، فلش (SWF) و درخواست‌های وب در Wireshark:\nhttp.request || http.content_type contains "shockwave" || frame contains "MZ" || frame contains "ZWS" || frame contains "CWS"')

        suri_rules = []
        sid = 9000001
        for ip in bad_ips[:6]:
            suri_rules.append(
                f'drop ip {ip} any -> $HOME_NET any (msg:"[PCAP-ANALYZER] Malicious Traffic from {ip}"; '
                f'classtype:trojan-activity; sid:{sid}; rev:1;)'
            )
            sid += 1
        for dom in bad_doms[:5]:
            suri_rules.append(
                f'alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"[PCAP-ANALYZER] Suspicious Domain/Gate {dom}"; '
                f'http.host; content:"{dom}"; nocase; classtype:trojan-activity; sid:{sid}; rev:1;)'
            )
            sid += 1
        for jh in bad_ja3[:4]:
            suri_rules.append(
                f'alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"[PCAP-ANALYZER] Malicious JA3 Fingerprint {jh}"; '
                f'ja3.hash; content:"{jh}"; classtype:command-and-control; sid:{sid}; rev:1;)'
            )
            sid += 1
        if not suri_rules:
            suri_rules.append("# هیچ IP یا دامنه مهاجمی برای تولید قانون مسدودسازی Suricata یافت نشد.")

        yara_strs = []
        idx = 1
        for ua in list(self.ioc_uas)[:4]:
            clean_ua = ua.replace('"', '\\"')[:50]
            yara_strs.append(f'        $ua_{idx} = "{clean_ua}" ascii nocase')
            idx += 1
        for dom in bad_doms[:4]:
            yara_strs.append(f'        $dom_{idx} = "{dom}" ascii nocase')
            idx += 1
        for c in self.carved_artifacts[:4]:
            yara_strs.append(f'        // Carved Payload: {c["type"]} | SHA256: {c["sha256"]}')
        yara_has_specific = bool(self.ioc_uas or bad_doms or self.carved_artifacts)
        if not yara_has_specific:
            yara_strs.append('        $s1 = "WScript.Shell" ascii nocase\n        $s2 = "ADODB.Stream" ascii nocase\n        $s3 = "${jndi:" ascii')

        yara_rule = (
            f"rule PCAP_Analyzer_Generated_Hunt_Rule {{\n"
            f"    meta:\n"
            f'        author = "{META.AUTHOR} / {META.APP_NAME}"\n'
            f'        reference = "{META.REPO_URL}"\n'
            f'        date = "{dt.datetime.now().strftime("%Y-%m-%d")}"\n'
            f'        description = "Auto-generated YARA rule from captured network/log artifacts"\n'
            f"    strings:\n" + "\n".join(yara_strs) + "\n"
            f"    condition:\n"
            f"        any of them\n"
            f"}}"
        )

        ip_list_q = ", ".join(f'"{ip}"' for ip in bad_ips[:8])
        if bad_ips:
            spl_query = (
                f"index=main OR index=network OR index=sysmon (src_ip IN ({ip_list_q}) OR dest_ip IN ({ip_list_q}))\n"
                f"| stats count values(dest_port) as ports values(action) as actions by src_ip, dest_ip, sourcetype\n"
                f"| sort - count"
            )
        else:
            spl_query = (
                "# No verified IP IOC was extracted; replace with an environment-specific hunt.\n"
                "index=main OR index=network OR index=sysmon\n"
                "| stats count by sourcetype"
            )
        kql_ip_part = " or ".join(f'source.ip : "{ip}" or destination.ip : "{ip}"' for ip in bad_ips[:6]) or 'event.category : "network"'
        kql_query = f'({kql_ip_part}) and (event.kind : "alert" or event.category : ("network", "process", "web"))'

        return {
            "wireshark": "\n\n".join(ws_filters),
            "suricata": "\n".join(suri_rules),
            "yara": yara_rule,
            "splunk_spl": spl_query,
            "elastic_kql": kql_query
        }

    def correlate_offline(self):
        f_list = self.findings()
        st = self.stats()

        weights = {"critical": 40, "high": 23, "medium": 11, "low": 4, "info": 0}
        base_score = 0.0
        has_high_conf = False
        high_conf_ids = {
            "ek_exploit_kit", "ek_flash_payload", "xor_mal_payload", "exploit_kit_activity",
            "exe_over_http", "malware_c2_family", "reverse_shell", "http_webshell",
            "http_cmdi", "http_log4j", "ja3_malicious", "yara_creddump", "yara_powershell",
            "smb_psexec", "crypto_miner", "ioc_feed_match"
        }

        for finding in f_list:
            sev = finding["severity"]
            count = max(1, int(finding.get("count", 1)))
            base_score += weights.get(sev, 0) * (1.0 + min(0.75, math.log2(count) * 0.14))
            if finding["id"] in high_conf_ids:
                has_high_conf = True

        unique_kc = len({f["kill_chain"] for f in f_list if f["severity"] in ("critical", "high", "medium")})
        unique_categories = len({f["category"] for f in f_list if f["severity"] in ("critical", "high", "medium")})
        independent_iocs = sum(bool(x) for x in (
            self.ioc_ips, self.ioc_domains, self.ioc_hashes, self.ioc_tools, self.ioc_artifacts
        ))
        correlation_bonus = min(25, max(0, unique_kc - 1) * 6 + max(0, unique_categories - 1) * 4)
        corroboration_bonus = min(12, max(0, independent_iocs - 1) * 3)
        score = min(100, int(round(base_score + correlation_bonus + corroboration_bonus)))

        if has_high_conf:
            score = max(score, 88 if unique_kc >= 2 else 80)
            if len(self.carved_artifacts) >= 1 and unique_kc >= 2:
                score = max(score, 95)

        level = "critical" if score >= 80 else "high" if score >= 55 else "medium" if score >= 28 else "low"
        confidence = min(95, int(20 + min(25, unique_categories * 6) +
                                 min(25, independent_iocs * 5) +
                                 min(20, max(0, unique_kc - 1) * 6))) if f_list else 0

        ttps_list = sorted({f"{f['mitre']} ({f['title']})" for f in f_list})
        pyramid_of_pain = {
            "ttps": ttps_list,
            "tools": sorted(self.ioc_tools),
            "artifacts": sorted(self.ioc_artifacts) or [f"Cred: {c}" for c in self.ioc_creds[:6]],
            "domains": sorted(self.ioc_domains),
            "ips": [f"{ip} [{', '.join(sorted(roles))}]" for ip, roles in self.ioc_ips.items()],
            "hashes": sorted(self.ioc_hashes)
        }

        adversaries = [
            f"{ip} ({'/'.join(r)})" for ip, r in self.ioc_ips.items()
            if any(k in str(r) for k in ("Attacker", "Scanner", "MITM", "Exploit", "Server"))
        ]
        capabilities = sorted(self.ioc_tools) + [f"{f['title']} [{f['mitre']}]" for f in f_list[:5]]
        infrastructures = [f"{ip} (C2/Server)" for ip, r in self.ioc_ips.items() if "C2" in str(r) or "Server" in str(r)] + sorted(self.ioc_domains)[:6]
        victims = sorted({t for f in f_list for t in f["targets"]})

        diamond_model = {
            "adversary": adversaries[:8] or ["شناسایی نشده (ترافیک عادی یا داخلی)"],
            "capability": capabilities[:8] or ["بدون اکسپلویت یا ابزار تهاجمی"],
            "infrastructure": infrastructures[:8] or sorted(self.ioc_ips.keys())[:5] or ["شبکه محلی (LAN)"],
            "victim": victims[:8] or ["میزبان‌های هدف داخلی"]
        }

        kc_map = collections.defaultdict(list)
        for f in f_list:
            kc_map[f["kill_chain"]].append(f)

        kill_chain_status = []
        for stage_en, stage_fa in KILL_CHAIN_STAGES:
            matched = kc_map.get(stage_en, [])
            kill_chain_status.append({
                "stage_en": stage_en,
                "stage_fa": stage_fa,
                "active": len(matched) > 0,
                "count": sum(x["count"] for x in matched),
                "findings": [f"{x['title']} ({x['mitre']} | x{x['count']})" for x in matched],
                "evidence": matched[0]["evidence"][0] if matched and matched[0]["evidence"] else ""
            })

        crit_cnt = sum(1 for f in f_list if f["severity"] == "critical")
        high_cnt = sum(1 for f in f_list if f["severity"] == "high")
        med_cnt = sum(1 for f in f_list if f["severity"] == "medium")

        if not f_list:
            exec_summary = (
                f"در بررسی آفلاین {st['packets']:,} واحد داده ({human_bytes(st['bytes'])})، هیچ‌گونه امضای حمله، اسکن شبکه، "
                f"ابزار مخرب یا ناهنجاری پروتکلی شناسایی نشد. وضعیت امنیتی ترافیک «عادی» ارزیابی می‌گردد."
            )
        else:
            active_stages = [s["stage_fa"] for s in kill_chain_status if s["active"]]
            stages_str = " ← ".join(active_stages)
            carved_note = f" همچنین {len(self.carved_artifacts)} فایل اجرایی/فلش/آرشیو استخراج و در پوشه _artifacts ذخیره شد." if self.carved_artifacts else ""
            exec_summary = (
                f"طی تحلیل عمیق و آفلاین {st['packets']:,} بسته/رکورد ({human_bytes(st['bytes'])}) و بازسازی {st['reassembled_streams']:,} جریان TCP، "
                f"مجموعاً {len(f_list)} نوع تهدید امنیتی (شامل {crit_cnt} مورد بحرانی، {high_cnt} مورد ریسک بالا و {med_cnt} مورد متوسط) کشف شد.{carved_note} "
                f"بر اساس چارچوب Cyber Kill Chain، فعالیت مهاجم در مراحل [{stages_str}] مشاهده شده است. "
                f"امتیاز ریسک کلی شبکه {score} از ۱۰۰ (سطح: {SEV_FA[level]} | شاخص همبستگی شواهد: {confidence}%) محاسبه گردید."
            )

        immediate, short_term, long_term = [], [], []
        if crit_cnt > 0:
            immediate.append("ایزوله‌سازی فوری میزبان‌های درگیر در هشدارهای بحرانی (Exploit Kit / Malware Dropper / RCE / Webshell / Reverse Shell).")
        if self.carved_artifacts:
            immediate.append(f"بررسی فوری {len(self.carved_artifacts)} فایل استخراج‌شده در پوشه _artifacts و مسدودسازی هش‌های SHA-256 در EDR.")
        if adversaries:
            immediate.append(f"اعمال قوانین Suricata/Firewall تولیدشده در همین گزارش جهت مسدودسازی IPهای مهاجم: {', '.join(adversaries[:4])}")
        if self.ioc_creds:
            immediate.append("تغییر فوری رمزهای عبور و توکن‌های ارسال‌شده به صورت متن آشکار (Cleartext Credentials).")

        for f in f_list:
            line = f"[{f['d3fend']}] {f['title']}: {f['recommendation']}"
            if f["severity"] in ("critical", "high") and len(short_term) < 6:
                if line not in short_term:
                    short_term.append(line)
            elif len(long_term) < 6:
                if line not in long_term:
                    long_term.append(line)

        if not immediate:
            immediate.append("بررسی لاگ‌های میزبان و فایروال برای رخدادهای ثبت‌شده.")
        if not short_term:
            short_term.append("اعمال قوانین MITRE D3FEND و بستن پورت‌های غیرضروری در شبکه.")
        long_term.extend([
            "پیاده‌سازی Sysmon و Auditd روی تمام سرورها و ارسال لاگ‌ها به SIEM (Elastic / Splunk) به همراه اسکن دوره‌ای با Chainsaw / Zircolite.",
            "فعال‌سازی بازرسی TLS، استفاده از لیست سیاه JA3/JA3S و استقرار اسکنرهای YARA / Loki روی فایل‌های دریافتی."
        ])

        forensic_steps = [
            "اجرای فیلترهای Wireshark تولیدشده در تب «قوانین و کوئری‌های شکار تهدید» جهت بررسی کامل جریان‌های TCP (Follow Stream).",
            "بررسی فایل‌های باینری، اسناد ماکرو و SWF ذخیره شده در پوشه کنار فایل PCAP (_artifacts) در محیط ایزوله Sandbox.",
            "در صورت مشاهده Exploit Kit یا بیکن C2: بررسی پوشه %TEMP% و تهیه ایمیج حافظه (RAM) جهت تحلیل با Volatility."
        ]

        return {
            "executive_summary": exec_summary,
            "risk_level": level,
            "risk_score": score,
            "confidence_score": confidence,
            "pyramid_of_pain": pyramid_of_pain,
            "diamond_model": diamond_model,
            "kill_chain": kill_chain_status,
            "detection_arsenal": self.generate_detection_arsenal(f_list),
            "recommendations": {
                "immediate": immediate,
                "short_term": short_term,
                "long_term": long_term[:6]
            },
            "iocs": {
                "ips": pyramid_of_pain["ips"],
                "domains": pyramid_of_pain["domains"],
                "user_agents": sorted(self.ioc_uas),
                "hashes": pyramid_of_pain["hashes"],
                "credentials": self.ioc_creds[:25]
            },
            "forensic_next_steps": forensic_steps
        }


# ============================================================================
# ۶. سازنده گزارش HTML تعاملی (Analyst-First Dark Cyber Dashboard + Vanilla JS)
# ============================================================================
HTML_CSS = """
:root{color-scheme:dark;--bg:#070b17;--card:#10172a;--card2:#16203a;--tx:#e8ecf8;--mut:#94a3b8;--line:#233256;--acc:#3b82f6;--acc2:#06b6d4}
*{box-sizing:border-box}
body{margin:0;font-size:14px;line-height:1.9;background-image:radial-gradient(900px 500px at 8% 0%,rgba(6,182,212,.10),transparent 60%),radial-gradient(1000px 600px at 95% 10%,rgba(59,130,246,.13),transparent 62%),linear-gradient(180deg,#070b17,#090f20 65%,#070b17);color:var(--tx);font-family:Tahoma,'Segoe UI',sans-serif}
.wrap{max-width:1440px;margin:auto;padding:28px clamp(14px,3vw,38px) 80px}
header{display:flex;gap:24px;align-items:center;flex-wrap:wrap;background:linear-gradient(125deg,#162648,#0c1528);border:1px solid #31466e;border-radius:20px;padding:24px 28px;box-shadow:0 22px 65px rgba(0,0,0,.32)}
header h1{margin:0 0 8px;font-size:clamp(20px,2.4vw,28px);line-height:1.5;color:#fff}header p{margin:3px 0;color:var(--mut);font-size:13.5px}
.gauge{margin-inline-start:auto;text-align:center}.gauge b{font-size:24px}
h2{font-size:clamp(17px,2vw,21px);margin:38px 0 14px;display:flex;align-items:center;gap:10px;color:#93c5fd}
h2:before{content:"";width:6px;height:22px;border-radius:4px;background:linear-gradient(180deg,var(--acc),var(--acc2))}
.grid{display:grid;gap:14px}.g4{grid-template-columns:repeat(auto-fit,minmax(200px,1fr))}
.g2{grid-template-columns:repeat(auto-fit,minmax(420px,1fr))}.g3{grid-template-columns:repeat(auto-fit,minmax(320px,1fr))}
.card{background:linear-gradient(145deg,#111c32,#0c1425);border:1px solid #263957;border-radius:16px;padding:16px 18px;box-shadow:0 10px 28px rgba(0,0,0,.18)}
.stat .v{font-size:25px;font-weight:800;color:#fff}.stat .l{color:var(--mut);font-size:13px}
.badge{display:inline-block;padding:2px 10px;border-radius:99px;font-size:12px;font-weight:700;color:#090d16}
.tag-mitre{background:#1e293b;border:1px solid #3b82f6;color:#93c5fd;padding:1px 8px;border-radius:6px;font-size:11.5px;direction:ltr;display:inline-block;margin:2px}
.tag-d3fend{background:#064e3b;border:1px solid #10b981;color:#6ee7b7;padding:1px 8px;border-radius:6px;font-size:11.5px;direction:ltr;display:inline-block;margin:2px}
.sevrow{display:flex;gap:10px;flex-wrap:wrap}.sevrow .card{flex:1;min-width:120px;text-align:center}
.sevrow .n{font-size:28px;font-weight:800}
.kc-chain{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px}
.kc-node{background:#0b1120;border:1px solid var(--line);border-radius:12px;padding:12px;text-align:center;position:relative}
.kc-node.active{background:linear-gradient(160deg,#2a1225,#131c38);border-color:#ff4d6d;box-shadow:0 0 15px rgba(255,77,109,.25)}
.kc-node .st{font-weight:700;font-size:13px;margin-bottom:4px}
.kc-node .cnt{font-size:12px;color:#ff8c42}
.diamond-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:14px}
.dm-box{background:linear-gradient(145deg,#121c36,#0c1324);border:1px solid #2e4372;border-radius:14px;padding:14px}
.dm-box h4{margin:0 0 8px;color:#38bdf8;font-size:15px;border-bottom:1px dashed var(--line);padding-bottom:6px}
.pyramid-wrap{max-width:820px;margin:10px auto;display:flex;flex-direction:column;gap:8px;align-items:center}
.pyr-level{border-radius:10px;padding:10px 16px;color:#fff;text-align:center;border:1px solid rgba(255,255,255,.15);transition:.2s}
.pyr-level b{display:block;font-size:14px;margin-bottom:4px}
.pyr-items{font-size:12px;direction:ltr;opacity:.95}
.filter-bar{position:sticky;top:8px;z-index:10;padding:10px;background:rgba(7,11,23,.94);backdrop-filter:blur(14px);border:1px solid var(--line);border-radius:14px;display:flex;gap:10px;flex-wrap:wrap;margin-bottom:14px;align-items:center}
.filter-bar input{flex:1;min-width:240px;background:#090e1c;border:1px solid var(--line);color:#fff;padding:9px 14px;border-radius:10px;font-family:inherit}
.fbtn{background:var(--card2);border:1px solid var(--line);color:var(--tx);padding:7px 14px;border-radius:10px;cursor:pointer;font-family:inherit;font-size:12.5px;font-weight:700}
.fbtn.active{background:var(--acc);color:#fff;border-color:var(--acc)}
details.f{background:var(--card);border:1px solid var(--line);border-radius:14px;margin:10px 0;overflow:hidden;box-shadow:0 8px 24px rgba(0,0,0,.16)}
details.f[open] summary{background:rgba(59,130,246,.07);border-bottom:1px solid var(--line)}
details.f summary{cursor:pointer;padding:14px 18px;display:flex;gap:10px;align-items:center;list-style:none;flex-wrap:wrap}
details.f summary::-webkit-details-marker{display:none}
details.f summary .t{font-weight:700;flex:1;min-width:220px}.f .body{padding:8px 20px 18px;border-top:1px dashed var(--line)}
.explain-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:10px;margin:12px 0}
.explain{background:#0b172b;border:1px solid #263957;border-radius:12px;padding:12px 14px}.explain b{color:#93c5fd}.explain p{margin:5px 0 0;color:#d5deed;font-size:13px}
.explain.caution{background:#211b12;border-color:#71532b}.explain.caution b{color:#fbbf24}
.meta-line{margin:12px 0;padding:9px 12px;background:#0a1222;border-radius:9px}
.mini{padding:12px 14px;box-shadow:none}.mini p{margin:4px 0}
.analyst-panel{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:12px}
.clean-list{margin:8px 0;padding-right:22px}.clean-list li{margin:5px 0}.muted{color:var(--mut)}
.kv{color:var(--mut);font-size:13px}.rec{background:#0b2620;border:1px solid #10b981;border-radius:10px;padding:10px 14px;margin-top:10px}
.rec:before{content:"🛡️ راهکار تدافعی (MITRE D3FEND): ";font-weight:700;color:#34d399}
pre,code{direction:ltr;text-align:left;font-family:Consolas,monospace;font-size:12.5px}
pre{background:#060a14;border:1px solid var(--line);border-radius:10px;padding:12px;overflow:auto;white-space:pre-wrap;word-break:break-all;margin:6px 0;color:#a5f3fc}
.copy-btn{float:right;background:#1e293b;color:#93c5fd;border:1px solid #3b82f6;border-radius:6px;padding:3px 10px;font-size:11px;cursor:pointer}
.copy-btn:hover{background:#3b82f6;color:#fff}
table{width:100%;border-collapse:collapse;font-size:13px}th,td{padding:8px 10px;border-bottom:1px solid var(--line);text-align:right}
td.ltr,.ltr{direction:ltr;text-align:left;unicode-bidi:plaintext;font-family:Consolas,monospace}th{color:var(--mut);font-weight:600;background:#0d1426}
.bar{height:8px;border-radius:6px;background:linear-gradient(90deg,var(--acc),var(--acc2));min-width:2px}.barbg{background:#070b14;border-radius:6px}
.pill{display:inline-block;background:#080d1a;border:1px solid var(--line);border-radius:8px;padding:2px 9px;margin:3px;font-size:12px;direction:ltr;color:#cbd5e1}
.note{color:var(--mut);font-size:12.5px;margin-top:45px;text-align:center}
@media print{body{background:#fff!important;color:#111!important;font-size:11pt}.wrap{max-width:none;padding:0}.card,details.f,.explain{background:#fff!important;color:#111!important;box-shadow:none;border:1px solid #bbb}.filter-bar,.copy-btn{display:none!important}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f5f5f5!important;color:#111!important}}
"""

HTML_JS = """
function filterFindings(sev, btn) {
  if (btn) {
    document.querySelectorAll('.fbtn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    window.currentSev = sev;
  }
  const q = (document.getElementById('findSearch').value || '').toLowerCase();
  const activeSev = window.currentSev || 'all';
  document.querySelectorAll('details.f').forEach(el => {
    const s = el.getAttribute('data-sev');
    const txt = el.innerText.toLowerCase();
    const matchSev = (activeSev === 'all' || s === activeSev);
    const matchQ = (!q || txt.includes(q));
    el.style.display = (matchSev && matchQ) ? '' : 'none';
  });
}
function copyBlock(id, btn) {
  const el = document.getElementById(id);
  if (!el) return;
  navigator.clipboard.writeText(el.innerText).then(() => {
    const old = btn.innerText;
    btn.innerText = '✔ کپی شد!';
    setTimeout(() => btn.innerText = old, 1800);
  });
}
"""



V6_CSS = """
.toolbar{display:flex;gap:8px;flex-wrap:wrap;margin:14px 0 6px}
.tbtn{background:linear-gradient(145deg,#1b2a4d,#101a33);border:1px solid #35508a;color:#dbe7ff;padding:8px 16px;border-radius:12px;cursor:pointer;font-family:inherit;font-weight:700;font-size:13px;transition:.15s}
.tbtn:hover{transform:translateY(-1px);border-color:#60a5fa;box-shadow:0 6px 18px rgba(59,130,246,.25)}
.verdict-card{display:flex;gap:20px;align-items:center;margin:22px 0 14px;padding:22px 26px;border-radius:20px;background:linear-gradient(130deg,#1a2744,#0d1630);border:1px solid #3a5388;box-shadow:0 18px 50px rgba(0,0,0,.35)}
.vc-icon{font-size:56px;line-height:1}.vc-title{margin:0 0 6px!important;font-size:clamp(20px,2.6vw,28px)!important;color:#fff!important}
.vc-title:before{display:none!important}
.muted{color:var(--mut)}.steps{margin:8px 0 0;padding-inline-start:22px}.steps li{margin:8px 0}
.gloss summary{cursor:pointer;font-weight:800;color:#93c5fd}.gloss dt{font-weight:800;margin-top:10px;color:#e2e8f0}.gloss dd{margin:2px 0 0;color:var(--mut)}
.plain{display:grid;gap:10px;margin:10px 0 14px}
.plain .pr{border-radius:14px;padding:12px 16px;border:1px solid #2c4170;background:linear-gradient(145deg,#0f1a33,#0b1326)}
.plain .pr b{display:block;margin-bottom:3px;font-size:13.5px}
.plain .pr.what{border-inline-start:5px solid #38bdf8}.plain .pr.why{border-inline-start:5px solid #fbbf24}.plain .pr.todo{border-inline-start:5px solid #34d399}
.safe-card{border-inline-start:5px solid #34d399}
body.simple .tech,body.simple .explain-grid{display:none!important}
html.light{filter:invert(1) hue-rotate(180deg)}
@media print{.toolbar,.filter-bar{display:none!important}html{filter:invert(1) hue-rotate(180deg)}details.f{break-inside:avoid}details>*{display:block}}
@media(max-width:640px){.verdict-card{flex-direction:column;text-align:center}.g2{grid-template-columns:1fr}}
"""
HTML_CSS += V6_CSS

V7_CSS = """
/* ===== PCAP Analyzer v8 — Cyber ===== */
:root{--glass:rgba(255,255,255,.055);--glass2:rgba(255,255,255,.085);--edge:rgba(255,255,255,.16);--edge2:rgba(255,255,255,.04)}
html{background:#05070f}
body{background:
 radial-gradient(60vmax 40vmax at 12% -8%,rgba(124,92,255,.34),transparent 60%),
 radial-gradient(55vmax 38vmax at 92% 4%,rgba(34,211,238,.26),transparent 62%),
 radial-gradient(50vmax 40vmax at 70% 108%,rgba(244,114,182,.20),transparent 60%),
 #05070f;background-attachment:fixed;font-family:'Vazirmatn','Segoe UI Variable','Segoe UI',system-ui,Tahoma,sans-serif;letter-spacing:.005em}
header,.card,.verdict-card,details.f,.plain .pr,.safe-card,.tbtn,.filter-bar{
 background:linear-gradient(145deg,var(--glass2),var(--glass))!important;
 -webkit-backdrop-filter:blur(26px) saturate(170%);backdrop-filter:blur(26px) saturate(170%);
 border:1px solid var(--edge)!important;
 box-shadow:inset 0 1px 0 rgba(255,255,255,.22),inset 0 -1px 0 rgba(255,255,255,.04),0 24px 60px -18px rgba(0,0,0,.65)!important}
header{border-radius:28px!important;padding:30px 34px!important;position:relative;overflow:hidden}
header:after,.verdict-card:after{content:"";position:absolute;inset:-40% -10% auto auto;width:60%;height:140%;background:radial-gradient(closest-side,rgba(255,255,255,.12),transparent);pointer-events:none;transform:rotate(18deg)}
.verdict-card{position:relative;overflow:hidden;border-radius:26px!important}
.card,details.f,.plain .pr{border-radius:20px!important}
.tbtn{border-radius:999px!important;padding:9px 20px!important;color:#eaf2ff!important;transition:transform .2s cubic-bezier(.2,.8,.2,1),box-shadow .2s,background .2s}
.tbtn:hover{transform:translateY(-2px) scale(1.02);background:linear-gradient(145deg,rgba(255,255,255,.16),rgba(255,255,255,.07))!important;box-shadow:inset 0 1px 0 rgba(255,255,255,.3),0 14px 34px -10px rgba(99,102,241,.55)!important}
h2{font-weight:800;letter-spacing:.01em}
code,pre{background:rgba(0,0,0,.38)!important;border:1px solid rgba(255,255,255,.08);border-radius:12px}
table{border-collapse:separate;border-spacing:0 4px}
tr:hover td{background:rgba(255,255,255,.05)}
.note{margin-top:46px;text-align:center;color:var(--mut)}
.brand-foot{display:inline-flex;gap:10px;align-items:center;margin-top:10px;padding:8px 18px;border-radius:999px;background:var(--glass);border:1px solid var(--edge);-webkit-backdrop-filter:blur(18px);backdrop-filter:blur(18px)}
.brand-foot a{color:#a5b4fc;text-decoration:none;font-weight:800}.brand-foot a:hover{color:#fff}
::-webkit-scrollbar{width:10px;height:10px}::-webkit-scrollbar-thumb{background:rgba(255,255,255,.18);border-radius:10px}
@media (prefers-reduced-motion:reduce){*{transition:none!important}}
"""
HTML_CSS += V7_CSS
HTML_JS += """
function toggleSimple(b){document.body.classList.toggle('simple');b.innerText=document.body.classList.contains('simple')?'🔬 نمایش جزئیات فنی':'🧒 حالت ساده'}
function toggleTheme(b){document.documentElement.classList.toggle('light');b.innerText=document.documentElement.classList.contains('light')?'🌙 حالت تاریک':'☀️ حالت روشن'}
"""


def plain_block(f):
    what, why, todo = plain_text(f)
    return (
        '<div class="plain">'
        f'<div class="pr what"><b>🧐 چه اتفاقی افتاده؟</b>{esc(what)}</div>'
        f'<div class="pr why"><b>⚠️ چرا مهم است؟</b>{esc(why)}</div>'
        f'<div class="pr todo"><b>✅ الان چه کنم؟</b>{esc(todo)}</div></div>'
    )


def safe_output_card(st):
    mode = st.get("sample_mode")
    n = len(st.get("carved_files", []))
    if not n or not mode:
        return ""
    msg = {
        "zip": "نمونه‌ها داخل ZIP رمزدار AES-256 ذخیره شدند (رمز: <code>infected</code>) تا آنتی‌ویروس آن‌ها را پاک نکند.",
        "xor": "نمونه‌ها با ظرف خنثی <code>.sample</code> ذخیره شدند. بازیابی: <code>--restore فایل.sample</code>.",
        "raw": "نمونه‌ها به‌صورت خام ذخیره شدند و خطرناک‌اند؛ روی آن‌ها دابل‌کلیک نکنید.",
    }.get(mode, "")
    return ('<div class="card safe-card"><h3 style="margin-top:0">🛡️ ذخیره امن نمونه‌های مخرب</h3>'
            f'<p>{n} فایل استخراج شد. {msg}</p>'
            '<p class="muted">فقط در ماشین مجازی/Sandbox باز کنید. پوشه: '
            f'<code class="ltr">{esc(str(st.get("artifact_dir")))}</code></p></div>')


def sev_badge(s):
    return f'<span class="badge" style="background:{SEV_COLOR[s]}">{SEV_FA[s]}</span>'


def gauge_svg(score, level):
    col = "#ff4d6d" if score >= 75 else "#ff8c42" if score >= 50 else "#ffc93c" if score >= 25 else "#4cc9f0"
    c = 2 * math.pi * 52
    off = c * (1 - score / 100)
    return (
        f'<div class="gauge"><svg width="145" height="145" viewBox="0 0 120 120">'
        f'<circle cx="60" cy="60" r="52" fill="none" stroke="#233256" stroke-width="10"/>'
        f'<circle cx="60" cy="60" r="52" fill="none" stroke="{col}" stroke-width="10" stroke-linecap="round" '
        f'stroke-dasharray="{c:.1f}" stroke-dashoffset="{off:.1f}" transform="rotate(-90 60 60)"/>'
        f'<text x="60" y="66" text-anchor="middle" fill="#fff" font-size="26" font-weight="800">{score}</text></svg>'
        f'<div>سطح ریسک: <b style="color:{col}">{esc(SEV_FA.get(level, level))}</b></div></div>'
    )


def bars_html(rows, fmt=lambda v: str(v)):
    if not rows:
        return '<div class="kv">داده‌ای ثبت نشده است</div>'
    mx = max(v for _, v in rows) or 1
    out = ["<table>"]
    for k, v in rows:
        out.append(
            f'<tr><td class="ltr" style="width:46%">{esc(str(k))}</td>'
            f'<td><div class="barbg"><div class="bar" style="width:{v / mx * 100:.1f}%"></div></div></td>'
            f'<td class="ltr" style="width:90px">{esc(fmt(v))}</td></tr>'
        )
    out.append("</table>")
    return "".join(out)


def timeline_svg(bins):
    w, h = 1000, 140
    mx = max(bins) or 1
    pts = [(i * w / max(len(bins) - 1, 1), h - 10 - (v / mx) * (h - 24)) for i, v in enumerate(bins)]
    line = " ".join(f"{x:.1f},{y:.1f}" for x, y in pts)
    return (
        f'<svg viewBox="0 0 {w} {h}" width="100%" preserveAspectRatio="none">'
        f'<defs><linearGradient id="g" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#3b82f6" stop-opacity=".55"/>'
        f'<stop offset="1" stop-color="#06b6d4" stop-opacity="0"/></linearGradient></defs>'
        f'<polygon points="0,{h} {line} {w},{h}" fill="url(#g)"/>'
        f'<polyline points="{line}" fill="none" stroke="#38bdf8" stroke-width="2.5"/></svg>'
    )


def _analyst_interpretation(f):
    rid = f.get("id", "")
    mapping = {
        "ek_exploit_kit": ("تفسیر تحلیلگر (Exploit Kit)", "لندینگ‌پیج یا الگوی URI مرتبط با کیت بهره‌برداری (مانند RIG EK) و اشیاء ActiveX/VBScript مشاهده شد.", "موفقیت بهره‌برداری به نسخه مرورگر/پلاگین‌های قربانی و اجرای پی‌لود مرحله بعد بستگی دارد."),
        "ek_flash_payload": ("تفسیر تحلیلگر (Flash Exploit)", "فایل فلش SWF فشرده (ZWS/CWS/FWS) در جریان HTTP استخراج شد که در RIG EK برای اجرای شل‌کد استفاده می‌شود.", "فایل استخراج‌شده در پوشه _artifacts باید با ابزارهای تحلیل SWF/YARA بررسی شود."),
        "xor_mal_payload": ("تفسیر تحلیلگر (XOR Payload)", "فایل اجرایی ویندوز که با کلید XOR مبهم‌سازی شده بود شناسایی، رمزگشایی و استخراج گردید.", "این تکنیک برای دور زدن IDS/AV استفاده می‌شود؛ هش فایل رمزگشایی‌شده را در Threat Intel بررسی کنید."),
        "exe_over_http": ("تفسیر تحلیلگر (Binary Download)", "یک فایل اجرایی کامل (PE/ELF) یا آرشیو حساس از جریان بازسازی‌شده HTTP استخراج و هش‌نگاری شد.", "انتقال فایل اجرایی روی HTTP غیررمزنگاری‌شده بسیار پرریسک است؛ منبع دانلود و پروسس اجراکننده بررسی شود."),
        "dns_tunnel": ("تفسیر تحلیلگر (DNS Anomaly)", "تعداد یا طول زیردامنه‌های کوئری‌شده برای یک دامنه پایه بیش از آستانه استاندارد است.", "برخی سرویس‌های آنتی‌ویروس و CDN نیز کوئری‌های طولانی ایجاد می‌کنند؛ دامنه پایه بررسی شود."),
        "zero_day_entropy": ("تفسیر تحلیلگر (High Entropy)", "جریان داده دارای توزیع بایت با آنتروپی بسیار بالا روی پورت غیر TLS است.", "آنتروپی بالا می‌تواند ناشی از فایل فشرده، ویدیو یا کانال C2 رمزنگاری‌شده سفارشی باشد."),
    }
    default = ("تفسیر تحلیلگر", f.get("description", "یک الگوی تشخیصی ثبت شده است."), "یافته را در کنار سایر مراحل Kill Chain و لاگ‌های میزبان (Sysmon/EDR) بررسی کنید.")
    title, meaning, caveat = mapping.get(rid, default)
    actors = ", ".join(f.get("actors", [])[:8]) or "در شواهد این یافته مشخص نشده"
    targets = ", ".join(f.get("targets", [])[:8]) or "در شواهد این یافته مشخص نشده"
    return title, meaning, caveat, actors, targets


def _html_list(items, empty="موردی ثبت نشده است"):
    if not items:
        return f'<p class="muted">{esc(empty)}</p>'
    return '<ul class="clean-list">' + "".join(f"<li>{esc(str(x))}</li>" for x in items) + "</ul>"


def finding_html(f):
    ev = "".join(f"<pre>{esc(e)}</pre>" for e in f.get("evidence", []))
    sev = f.get("severity", "info")
    open_attr = "open" if sev in ("critical", "high") else ""
    interp = _analyst_interpretation(f)
    return (
        f'<details class="f" data-sev="{sev}" {open_attr}>'
        f'<summary>{sev_badge(sev)}'
        f'<span class="t">{esc(f["title"])}</span>'
        f'<span class="tag-mitre">ATT&CK: {esc(f["mitre"])}</span>'
        f'<span class="tag-d3fend">{esc(f["d3fend"])}</span>'
        f'<span class="kv">x{f["count"]:,}</span></summary>'
        f'<div class="body">{plain_block(f)}<div class="tech"><div class="explain-grid">'
        f'<div class="explain"><b>شرح فنی قانون</b><p>{esc(f["description"])}</p></div>'
        f'<div class="explain"><b>{esc(interp[0])}</b><p>{esc(interp[1])}</p></div>'
        f'<div class="explain caution"><b>نکته تحلیلی</b><p>{esc(interp[2])}</p></div></div>'
        f'<div class="kv meta-line">دسته: <b>{esc(f["category"])}</b> &nbsp;|&nbsp; '
        f'Kill Chain: <b>{esc(f["kill_chain"])}</b> &nbsp;|&nbsp; '
        f'MITRE CAR: <b>{esc(f["car"])}</b> &nbsp;|&nbsp; '
        f'اولین مشاهده: {esc(f["first_ts"])}</div>'
        f'<div class="grid g2"><div class="card mini"><b>مبدأ / سرورهای مرتبط</b><p class="ltr">{esc(interp[3])}</p></div>'
        f'<div class="card mini"><b>مقصد / اهداف مرتبط</b><p class="ltr">{esc(interp[4])}</p></div></div>'
        f'{ev}<div class="rec">{esc(f["recommendation"])}</div></div></div></details>'
    )


def build_html_report(path, st, findings, corr):
    cnt = collections.Counter(f.get("severity", "info") for f in findings)
    score = corr["risk_score"]
    level = corr["risk_level"]
    pop = corr["pyramid_of_pain"]
    dm = corr["diamond_model"]
    arsenal = corr["detection_arsenal"]

    h = [
        '<!doctype html><html lang="fa" dir="rtl"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width,initial-scale=1">',
        f'<title>{META.APP_NAME} v{META.VERSION} Report — {esc(os.path.basename(path))}</title>',
        f'<style>{HTML_CSS}</style><script>{HTML_JS}</script></head><body><div class="wrap">'
    ]

    h.append(
        f'<header><div><h1>🛡️ گزارش جامع مرکز عملیات امنیت و شکار تهدید (PCAP Analyzer v{META.VERSION})</h1>'
        f'<p>فایل مورد بررسی: <code>{esc(os.path.basename(path))}</code></p>'
        f'<p>بازه زمانی ترافیک: {esc(st["start"])} تا {esc(st["end"])} ({st["duration_s"]} ثانیه) | جریان‌های TCP بازسازی‌شده: {st.get("reassembled_streams", 0):,}</p>'
        f'<p>موتورهای فعال: <b>TCP Sequence Reassembler + Exploit Kit Hunter (RIG/SWF/Multi-XOR) + JA3/JA3S + YARA + MITRE ATT&CK/D3FEND</b></p></div>'
        f'{gauge_svg(score, level)}</header>'
    )
    h.append('<div class="toolbar"><button class="tbtn" onclick="toggleSimple(this)">🧒 حالت ساده</button>'
             '<button class="tbtn" onclick="toggleTheme(this)">☀️ حالت روشن</button>'
             '<button class="tbtn" onclick="window.print()">🖨️ چاپ / PDF</button></div>')
    h.append(plain_summary_html(level, score, findings, esc))
    h.append(safe_output_card(st))

    h.append(f'<h2>خلاصه مدیریتی و وضعیت ریسک (Executive Summary)</h2><div class="card"><p>{esc(corr["executive_summary"])}</p></div>')

    top_names = [f'{x["title"]} — {SEV_FA.get(x["severity"], x["severity"])} (x{x["count"]})' for x in findings[:3]]
    next_steps = corr.get("forensic_next_steps", [])[:3]
    h.append('<h2>راهنمای سریع تحلیلگر | اول چه چیزی را بررسی کنم؟</h2>')
    h.append('<div class="analyst-panel">')
    h.append(f'<div class="card"><div class="kv">۱. مهم‌ترین یافته‌های اولویت‌دار</div>{_html_list(top_names, "هیچ یافته‌ای ثبت نشده است.")}</div>')
    h.append(f'<div class="card"><div class="kv">۲. گام‌های بعدی فارنزیک</div>{_html_list(next_steps)}</div>')
    h.append(f'<div class="card"><div class="kv">۳. پوشش بازسازی جریان‌ها</div><p>بسته‌ها: <b>{st["packets"]:,}</b> · جریان‌های TCP بازسازی‌شده: <b>{st.get("reassembled_streams", 0):,}</b> · فایل‌های استخراج‌شده: <b>{len(st["carved_files"])}</b> · شاخص همبستگی شواهد: <b>{corr.get("confidence_score", 0)}%</b></p></div>')
    h.append('</div>')

    h.append('<h2>توزیع هشدارها و آمار کلان شبکه</h2><div class="sevrow">' + "".join(
        f'<div class="card" style="border-top:3px solid {SEV_COLOR[s]}"><div class="n" style="color:{SEV_COLOR[s]}">{cnt.get(s, 0)}</div>'
        f'<div class="kv">{SEV_FA[s]}</div></div>' for s in SEV_ORDER
    ) + '</div>')

    h.append('<div class="grid g4" style="margin-top:14px">' + "".join(
        f'<div class="card stat"><div class="v">{v}</div><div class="l">{l}</div></div>' for l, v in (
            ("تعداد کل بسته‌ها / رکوردها", f'{st["packets"]:,}'),
            ("حجم کل داده پردازش‌شده", human_bytes(st["bytes"])),
            ("آدرس‌های IP یکتا", st["unique_ips"]),
            ("فایل‌های استخراج‌شده (Carved)", len(st["carved_files"]))
        )
    ) + '</div>')

    h.append(f'<div class="card" style="margin-top:14px"><div class="kv">نرخ زمانی ترافیک (Timeline)</div>{timeline_svg(st["timeline"])}</div>')

    h.append('<h2>زنجیره کشتار سایبری (Cyber Kill Chain & UKC Mapping)</h2><div class="kc-chain">')
    for kc in corr["kill_chain"]:
        cls = "kc-node active" if kc["active"] else "kc-node"
        status_txt = f"🚨 {kc['count']:,} رخداد فعال" if kc["active"] else "⚪ بدون رخداد"
        items_html = "<br>".join(esc(x) for x in kc["findings"][:3])
        h.append(
            f'<div class="{cls}"><div class="st">{esc(kc["stage_fa"])}</div>'
            f'<div class="cnt">{status_txt}</div>'
            f'<div class="kv" style="font-size:11.5px;margin-top:6px">{items_html}</div></div>'
        )
    h.append('</div>')

    h.append('<h2>مدل الماس تحلیل نفوذ (Diamond Model of Intrusion Analysis)</h2><div class="diamond-grid">')
    for title, key in (
        ("👤 مهاجم (Adversary / Threat Actor)", "adversary"),
        ("⚔️ قابلیت و ابزار (Capability / TTPs)", "capability"),
        ("🌐 زیرساخت (Infrastructure / C2)", "infrastructure"),
        ("🎯 قربانی (Victim / Target Surface)", "victim")
    ):
        pills = "".join(f'<span class="pill">{esc(x)}</span>' for x in dm.get(key, []))
        h.append(f'<div class="dm-box"><h4>{title}</h4><div>{pills}</div></div>')
    h.append('</div>')

    h.append('<h2>هرم درد شاخص‌های نفوذ (David Bianco\'s Pyramid of Pain)</h2><div class="card"><div class="pyramid-wrap">')
    pyr_tiers = [
        ("۶. رفتارها و تکنیک‌ها — TTPs (Tough!)", pop["ttps"], "46%", "#991b1b"),
        ("۵. ابزارهای تهاجمی — Tools (Challenging)", pop["tools"], "56%", "#b45309"),
        ("۴. آرتیفکت‌های شبکه و میزبان — Artifacts (Annoying)", pop["artifacts"], "66%", "#a16207"),
        ("۳. نام‌های دامنه — Domain Names (Simple)", pop["domains"], "76%", "#15803d"),
        ("۲. آدرس‌های IP — IP Addresses (Easy)", pop["ips"], "86%", "#1d4ed8"),
        ("۱. مقادیر هش (JA3 / SHA256) — Hash Values (Trivial)", pop["hashes"], "96%", "#334155"),
    ]
    for label, items, width, bg in pyr_tiers:
        sample = " | ".join(esc(str(x)) for x in items[:5]) if items else "موردی ثبت نشد"
        h.append(
            f'<div class="pyr-level" style="width:{width};background:{bg}">'
            f'<b>{label} ({len(items)} مورد)</b>'
            f'<div class="pyr-items">{sample}</div></div>'
        )
    h.append('</div></div>')

    h.append('<h2>یافته‌ها و هشدارهای امنیتی (با نگاشت MITRE ATT&CK + D3FEND + CAR)</h2>')
    h.append(
        """<div class="filter-bar">
        <input type="text" id="findSearch" placeholder="🔍 جستجوی زنده در عنوان، IP، کد MITRE یا شواهد بسته..." oninput="filterFindings(null, null)">
        <button class="fbtn active" onclick="filterFindings('all', this)">همه</button>
        <button class="fbtn" onclick="filterFindings('critical', this)">بحرانی</button>
        <button class="fbtn" onclick="filterFindings('high', this)">ریسک بالا</button>
        <button class="fbtn" onclick="filterFindings('medium', this)">متوسط</button>
        <button class="fbtn" onclick="filterFindings('low', this)">کم</button>
        </div>"""
    )
    h.append("".join(finding_html(f) for f in findings) or '<div class="card">✅ هیچ مورد مشکوکی شناسایی نشد.</div>')

    h.append('<h2>زرادخانه قوانین دفاعی و کوئری‌های شکار تهدید (Suricata / YARA / Wireshark / SPL / KQL)</h2><div class="grid g2">')
    for idx, (title, key) in enumerate([
        ("🦈 فیلترهای آماده Wireshark / TShark", "wireshark"),
        ("🛡️ قوانین آماده IPS/IDS (Suricata / Snort)", "suricata"),
        ("🧬 قانون تولیدشده YARA (YaraGen Engine)", "yara"),
        ("🔎 کوئری‌های شکار تهدید در Splunk (SPL) و Elastic (KQL)", "splunk_spl")
    ]):
        content = arsenal[key]
        if key == "splunk_spl":
            content = f"--- Splunk SPL ---\n{arsenal['splunk_spl']}\n\n--- Elastic KQL ---\n{arsenal['elastic_kql']}"
        bid = f"code_blk_{idx}"
        h.append(
            f"""<div class="card"><button class="copy-btn" onclick="copyBlock('{bid}', this)">📋 کپی کد</button>"""
            f"""<h3 style="margin-top:0;font-size:15px">{title}</h3>"""
            f"""<pre id="{bid}">{esc(content)}</pre></div>"""
        )
    h.append('</div>')

    if st["ja3_fingerprints"] or st["carved_files"]:
        h.append('<h2>انگشت‌نگاری JA3 TLS و فایل‌های استخراج‌شده (Malware / Payload Carving)</h2><div class="grid g2">')
        if st["ja3_fingerprints"]:
            rows = "".join(
                f'<tr><td class="ltr">{esc(j["hash"])}</td><td>{esc(j["known"])}</td>'
                f'<td class="ltr">{esc(j["info"])}</td><td class="ltr">{j["count"]}</td></tr>'
                for j in st["ja3_fingerprints"]
            )
            h.append(
                f'<div class="card"><h3 style="margin-top:0">اثرانگشت‌های TLS کلاینت (JA3 Hashes)</h3>'
                f'<table><tr><th>JA3 MD5 Hash</th><th>تشخیص کلاینت</th><th>جزئیات</th><th>تعداد</th></tr>{rows}</table></div>'
            )
        if st["carved_files"]:
            rows = "".join(
                f'<tr><td>{esc(c["type"])}</td><td class="ltr">{esc(c["size"])}</td>'
                f'<td class="ltr">{c["entropy"]}</td><td class="ltr">{esc(c["sha256"])}</td></tr>'
                for c in st["carved_files"]
            )
            h.append(
                f'<div class="card"><h3 style="margin-top:0">فایل‌های باینری و SWF استخراج‌شده در پوشه _artifacts</h3>'
                f'<table><tr><th>نوع فایل</th><th>حجم</th><th>Entropy</th><th>SHA-256 کامل</th></tr>{rows}</table></div>'
            )
        h.append('</div>')

    rc = corr.get("recommendations", {})
    h.append('<h2>نقشه راه پاسخ به رخداد و بهینه‌سازی امنیت</h2><div class="grid g3">' + "".join(
        f'<div class="card"><h3 style="margin-top:0">{ic} {t}</h3><ul>' +
        "".join(f"<li>{esc(x)}</li>" for x in rc.get(k, [])) + "</ul></div>"
        for k, t, ic in (
            ("immediate", "اقدامات فوری مهار (Immediate)", "🚨"),
            ("short_term", "اصلاحات کوتاه‌مدت (MITRE D3FEND)", "🛠"),
            ("long_term", "معماری بلندمدت SOC", "🏗")
        )
    ) + "</div>")

    ioc = corr.get("iocs", {})

    def _pills(items):
        return "".join(f'<span class="pill">{esc(defang(str(x)) if DEFANG_REPORT else str(x))}</span>' for x in items[:80]) or '<span class="kv">موردی ثبت نشد</span>'

    h.append('<h2>شاخص‌های نفوذ استخراج‌شده (IOC)</h2><div class="grid g2">')
    for idx2, (title, key) in enumerate((
        ("🌐 آدرس‌های IP مشکوک", "ips"), ("🔗 دامنه‌های مشکوک", "domains"),
        ("🧰 User-Agent ابزارهای تهاجمی", "user_agents"), ("#️⃣ هش‌ها (SHA-256 / JA3)", "hashes"),
        ("🔑 اطلاعات هویتی مکشوفه (ماسک‌شده)", "credentials"),
    )):
        bid = f"ioc_blk_{idx2}"
        h.append(
            f"""<div class="card"><button class="copy-btn" onclick="copyBlock('{bid}', this)">📋 کپی</button>"""
            f"""<h3 style="margin-top:0;font-size:15px">{title}</h3>"""
            f"""<div id="{bid}">{_pills(ioc.get(key, []))}</div></div>"""
        )
    h.append('</div>')

    h.append('<h2>آمار تفصیلی پروتکل‌ها، پورت‌ها و ارتباطات شبکه</h2><div class="grid g2">')
    h.append(f'<div class="card"><h3 style="margin-top:0">توزیع پروتکل‌ها</h3>{bars_html(list(st["protocols"].items()))}</div>')
    port_rows = [(f"{p['port']} ({p['service']})", p["packets"]) for p in st["top_ports"]]
    h.append('<div class="card"><h3 style="margin-top:0">پورت‌های مقصد برتر</h3>' + bars_html(port_rows) + '</div>')
    talk_rows = [(f"{t['src']} → {t['dst']}" + (f" ({t['dst_domain']})" if t.get("dst_domain") else ""), t["bytes"]) for t in st["top_talkers"]]
    h.append('<div class="card"><h3 style="margin-top:0">برترین ارتباطات (Top Talkers)</h3>' + bars_html(talk_rows, human_bytes) + '</div>')
    h.append(f'<div class="card"><h3 style="margin-top:0">برترین کوئری‌های DNS</h3>{bars_html(st["top_dns"])}</div>')
    h.append(f'<div class="card"><h3 style="margin-top:0">نام سرورهای TLS (SNI)</h3>{bars_html(st["tls_sni"])}</div>')
    h.append(f'<div class="card"><h3 style="margin-top:0">میزبان‌های HTTP</h3>{bars_html(st["http_hosts"])}</div>')
    h.append(f'<div class="card"><h3 style="margin-top:0">User-Agentهای HTTP</h3>{bars_html(st["http_user_agents"])}</div>')
    h.append(f'<div class="card"><h3 style="margin-top:0">پرفرستنده‌ترین IPها (حجم خروجی)</h3>{bars_html(st["top_senders"], human_bytes)}</div>')
    h.append("</div>")

    if st.get("tshark_phs"):
        h.append('<h2>خروجی سلسله‌مراتب پروتکل‌ها از موتور TShark CLI</h2><div class="card"><pre>' + esc("\n".join(st["tshark_phs"])) + '</pre></div>')

    h.append(
        '<div class="note">تولید شده به صورت ۱۰۰٪ آفلاین و لوکال توسط '
        f'<b>{esc(META.APP_NAME)} v{esc(META.VERSION)}</b><br>'
        f'<span class="brand-foot">ساخته‌شده با ♥ توسط <a href="{esc(META.GITHUB_PROFILE)}" target="_blank" rel="noopener">{esc(META.AUTHOR)}</a>'
        f' · <a href="{esc(META.REPO_URL)}" target="_blank" rel="noopener">GitHub</a>'
        f' · <a href="{esc(META.LATEST_RELEASE_URL)}" target="_blank" rel="noopener">آخرین نسخه</a></span></div></div></body></html>')
    return "".join(h)



# ============================================================================
# ۶-ب. نوشتن امن همه گزارش‌ها (مشترک بین CLI و GUI)
# ============================================================================
def default_out_dir(target):
    """پوشه اختصاصی خروجی در Home (در هر سه سیستم‌عامل قابل‌نوشتن و قابل‌استثنا)."""
    base = os.path.splitext(os.path.basename(target))[0]
    stamp = time.strftime("%Y%m%d_%H%M%S")
    return str(Path.home() / "PCAP_Analyzer_Reports" / f"{base}_{stamp}")


def _strip_heavy(st):
    """نسخه سبک stats برای JSON: بدون پیش‌نمایش تصویر/هگز فایل‌ها"""
    import copy
    st2 = dict(st)
    hub = dict(st.get("hub") or {})
    hub["files"] = [{k: v for k, v in f.items() if k != "preview"} for f in hub.get("files", [])]
    st2["hub"] = hub
    return st2


def write_all_reports(target, out_dir, st, findings, corr, do_defang=True, style="cyber", theme="neon-night",
                      material="glass", formats=("html", "json", "csv", "rules", "iocs")):
    """HTML (cyber/classic/both) + JSON + CSV + Suricata + YARA + IOC را می‌نویسد؛ فهرست فایل‌ها را برمی‌گرداند."""
    out_dir = prepare_output_dir(out_dir)
    base = os.path.splitext(os.path.basename(target))[0]
    files = []
    formats = set(formats or ())

    def w(name, text):
        p = os.path.join(out_dir, f"{base}_{name}")
        with open(p, "w", encoding="utf-8", newline="") as fh:
            fh.write(text)
        files.append(p)

    if "html" in formats:
        if style in ("cyber", "both"):
            lvl = corr.get("risk_level", "info")
            w("pcap_report.html", build_cyber_report(
                target, st, findings, corr, theme=theme, material=material,
                defang=(defang if do_defang else (lambda x: x)), plain_for=plain_for,
                verdict=PLAIN_VERDICT.get(lvl, PLAIN_VERDICT["info"]), sev_fa=SEV_FA, sev_color=SEV_COLOR))
        if style in ("classic", "both"):
            w("pcap_report_classic.html" if style == "both" else "pcap_report.html", build_html_report(target, st, findings, corr))
    if "json" in formats:
        w("pcap_report.json", json.dumps({"stats": _strip_heavy(st), "findings": findings, "correlation": corr},
                                        ensure_ascii=False, indent=2, default=str))
    ars = corr["detection_arsenal"]
    if "rules" in formats:
        w("suricata.rules", ars["suricata"] + "\n")
        w("hunt.yar", ars["yara"] + "\n")
    if "iocs" in formats:
        lines = []
        for k, vals in corr["iocs"].items():
            lines.append(f"## {k.upper()}")
            lines.extend(defang(str(v)) if do_defang else str(v) for v in vals)
            lines.append("")
        w("iocs_defanged.txt" if do_defang else "iocs.txt", "\n".join(lines))
    if "csv" in formats:
        import io
        buf = io.StringIO()
        wr = csv.writer(buf)
        wr.writerow(["severity", "title", "count", "mitre", "kill_chain", "actors", "targets", "first_ts"])
        for f in findings:
            wr.writerow([f["severity"], f["title"], f["count"], f["mitre"], f["kill_chain"],
                         " ".join(f["actors"][:5]), " ".join(f["targets"][:5]), f["first_ts"]])
        w("findings.csv", buf.getvalue())
        hub = st.get("hub") or {}
        buf = io.StringIO()
        wr = csv.writer(buf)
        wr.writerow(["protocol", "time", "client", "server", "kind", "summary", "flag"])
        for pr, evs in (hub.get("events") or {}).items():
            for e in evs:
                wr.writerow([pr, e["ts"], f'{e["a"]}:{e["ap"]}', f'{e["b"]}:{e["bp"]}', e["k"], e["s"], e["x"]])
        w("protocol_events.csv", buf.getvalue())
    return files

# ============================================================================
# ۷. رابط کاربری گرافیکی دسکتاپ (Tkinter Dark Cyber SOC Suite)
# ============================================================================
if HAS_TK:
    import pcap_glass_ui as G
    _saved_cfg = THEMES.load_config()
    G.apply_palette(THEMES.tk_palette(_saved_cfg.get("theme", THEMES.DEFAULT_THEME)))
    UI = {  # legacy keys, now fed from the glass palette
        "bg": G.PAL["bg"], "card": G.PAL["glass"], "card2": G.PAL["well2"], "line": G.PAL["line"],
        "fg": G.PAL["ink"], "mut": G.PAL["mut"], "acc": G.PAL["acc"], "acc2": G.PAL["acc2"],
        "ok": G.PAL["ok"], "warn": G.PAL["warn"], "bad": G.PAL["bad"], "code": G.PAL["well"], "panel": G.PAL["well"],
    }
    CHART_PALETTE = [
        G.PAL["acc"], G.PAL["acc2"], G.PAL["pink"], G.PAL["ok"], G.PAL["warn"], "#60a5fa",
        G.PAL["orange"], "#a3e635", "#2dd4bf", "#e879f9", "#818cf8", G.PAL["bad"],
    ]

    class PcapAnalyzerApp(tk.Tk):
        def __init__(self, initial_file=None):
            super().__init__()
            self.title(f"{META.APP_NAME} — v{META.VERSION}")
            self.geometry("1500x940")
            self.minsize(1180, 780)
            self.configure(bg=G.PAL["bg"])
            self.backdrop = G.Backdrop(self)
            self._icon = G.set_window_icon(self)
            G.enable_dark_titlebar(self)

            self.cfg = EngineConfig()
            self.cfg.theme = _saved_cfg.get("theme", THEMES.DEFAULT_THEME)
            self.cfg.material = _saved_cfg.get("material", THEMES.DEFAULT_MATERIAL)
            self.cfg.report_style = _saved_cfg.get("report_style", "cyber")
            self.analyzer = None
            self.worker_thread = None
            self.running = False
            self.msgq = queue.Queue()

            self.current_file = tk.StringVar()
            self.auto_open = tk.BooleanVar(value=False)
            tshark_ok = "فعال (نصب شده)" if find_tshark_binary() else "موتور داخلی Scapy + TCP Reassembler"
            self.status_text = tk.StringVar(
                value=f"آماده بارگذاری فایل (PCAP / PCAPNG / LOG / JSON) | وضعیت موتور: {tshark_ok}"
            )
            self.search_var = tk.StringVar()
            self.sev_filter_var = tk.StringVar(value="همه (All)")

            self.last_stats = None
            self.last_findings = []
            self.last_corr = None
            self.last_html_path = None
            self.last_hub = {}
            self._chart_data = {
                "protocols": [],
                "timeline": [],
                "score": 0,
                "level": "low",
                "kill_chain": [{"stage_en": en, "stage_fa": fa, "active": False, "count": 0} for en, fa in KILL_CHAIN_STAGES]
            }

            self._pick_fonts()
            self._setup_styles()
            self._build_ui()
            self._bind_keys()

            self.protocol("WM_DELETE_WINDOW", self._on_close)
            self.after(80, self._poll_queue)
            if initial_file and os.path.isfile(initial_file):
                self.current_file.set(initial_file)

        def report_callback_exception(self, exc, val, tb):
            err = "".join(traceback.format_exception(exc, val, tb))
            try:
                messagebox.showerror("خطای غیرمنتظره در رابط کاربری", err[-1800:])
            except Exception:
                pass

        def _pick_fonts(self):
            self.F, self.FM = G.pick_fonts(self)

        def _bind_keys(self):
            self.bind("<Control-o>", lambda e: self.browse_file())
            self.bind("<F5>", lambda e: self.start_analysis())
            self.bind("<Escape>", lambda e: self.stop_analysis())
            for n in range(1, 8):
                self.bind(f"<Control-Key-{n}>", lambda e, k=n - 1: self.goto_page(k))

        def _on_close(self):
            if self.analyzer:
                self.analyzer.stop_requested = True
            self.destroy()

        def _setup_styles(self):
            G.setup_ttk(self, self.F, self.FM)

        def _mk_text(self, parent, bg=None, fg=None, mono=True, size=10):
            return G.make_text(parent, self.F, self.FM, mono=mono, size=size, bg=bg, fg=fg)

        # ---------------------------------------------------------------- layout
        def _build_ui(self):
            F, FM = self.F, self.FM
            P = G.PAL

            # ── top bar: brand · file · actions
            top = G.GlassPanel(self, radius=28, pad=10, height=96)
            top.pack(fill="x", padx=14, pady=(12, 0))
            ti = top.inner
            self._logo = None
            if G.HAS_PIL:
                try:
                    self._logo = G.ImageTk.PhotoImage(G.make_app_icon(256).resize((52, 52), G.Image.LANCZOS))
                except Exception:
                    self._logo = None
            brand = tk.Frame(ti, bd=0)
            brand.pack(side="left", padx=(6, 18))
            if self._logo:
                tk.Label(brand, image=self._logo, bd=0).pack(side="left", padx=(0, 12))
            col = tk.Frame(brand, bd=0)
            col.pack(side="left")
            tk.Label(col, text=META.APP_NAME, fg=P["ink"], font=(F, 16, "bold"), anchor="w").pack(anchor="w")
            tk.Label(col, text=f"v{META.VERSION}  ·  Dark Cyber Console", fg=P["dim"], font=(F, 9), anchor="w").pack(anchor="w")

            act = tk.Frame(ti, bd=0)
            act.pack(side="right")
            self.btn_stop = G.GlassButton(act, "توقف", self.stop_analysis, "ghost", height=40, state="disabled",
                                          font=(F, 10, "bold"), width=84)
            self.btn_stop.pack(side="right", padx=(8, 0))
            self.btn_start = G.GlassButton(act, "شروع تحلیل", self.start_analysis, "primary", height=40,
                                           font=(F, 11, "bold"), width=150, icon="▶")
            self.btn_start.pack(side="right")

            fbox = tk.Frame(ti, bd=0)
            fbox.pack(side="left", fill="x", expand=True, padx=(0, 14))
            self.btn_browse = G.GlassButton(fbox, "انتخاب فایل", self.browse_file, "ghost", height=40,
                                            font=(F, 10, "bold"), width=118, icon="⌕")
            self.btn_browse.pack(side="right", padx=(10, 0))
            self.field_file = G.GlassField(fbox, self.current_file, (FM, 10), height=40, fg=P["acc2"])
            self.field_file.pack(side="right", fill="x", expand=True)

            # ── nav + exports
            navp = G.GlassPanel(self, radius=24, pad=8, height=70)
            navp.pack(fill="x", padx=14, pady=(8, 0))
            ni = navp.inner
            exp = tk.Frame(ni, bd=0)
            exp.pack(side="left", padx=(8, 0))
            self.btn_html = G.GlassButton(exp, "گزارش HTML", self.export_and_open_html, "success", height=36,
                                          font=(F, 9, "bold"), state="disabled", icon="↗")
            self.btn_json = G.GlassButton(exp, "JSON", self.export_json, "ghost", height=36, font=(F, 9, "bold"), state="disabled")
            self.btn_csv = G.GlassButton(exp, "CSV", self.export_csv, "ghost", height=36, font=(F, 9, "bold"), state="disabled")
            self.btn_ioc = G.GlassButton(exp, "IOC و قوانین", self.export_ioc, "ghost", height=36, font=(F, 9, "bold"), state="disabled")
            for b in (self.btn_html, self.btn_json, self.btn_csv, self.btn_ioc):
                b.pack(side="left", padx=3)
            names = ["داشبورد", "پروتکل‌ها و فایل‌ها", "هشدارها", "هرم درد و الماس", "قوانین تشخیص", "آزمایشگاه فایل‌ها", "تنظیمات"]
            self._nav_n = len(names)
            self.nav = G.SegmentedNav(ni, list(reversed(names)), lambda i: self._show_page(self._nav_n - 1 - i),
                                      font=(F, 10, "bold"), height=46)
            self.nav.pack(side="right", fill="x", expand=True, padx=(0, 14))

            # ── status / progress / credits (packed before content so it keeps its space)
            foot = G.GlassPanel(self, radius=22, pad=6, height=82)
            foot.pack(side="bottom", fill="x", padx=14, pady=(0, 12))
            fi = foot.inner
            self.progress = G.GlassProgress(fi, height=8)
            self.progress.pack(fill="x", pady=(4, 6))
            line = tk.Frame(fi, bd=0)
            line.pack(fill="x")
            cred = tk.Frame(line, bd=0)
            cred.pack(side="left")
            small = (F, 9)
            tk.Label(cred, text=f"{META.APP_NAME} v{META.VERSION} · by", fg=P["dim"], font=small).pack(side="left")
            G.Link(cred, META.AUTHOR, lambda: webbrowser.open(META.GITHUB_PROFILE), (F, 9, "bold"), fg=P["acc"]).pack(side="left", padx=(5, 0))
            for txt, url in (("GitHub", META.REPO_URL), ("آخرین نسخه", META.LATEST_RELEASE_URL)):
                tk.Label(cred, text="·", fg=P["dim"], font=small).pack(side="left", padx=6)
                G.Link(cred, txt, lambda u=url: webbrowser.open(u), small).pack(side="left")
            tk.Label(cred, text="·", fg=P["dim"], font=small).pack(side="left", padx=6)
            G.Link(cred, "بررسی به‌روزرسانی", self.check_updates, small).pack(side="left")
            tk.Label(line, textvariable=self.status_text, fg=P["acc2"], font=(F, 9, "bold"), anchor="e").pack(side="right")

            # ── content
            self.content = G.GlassPanel(self, radius=30, pad=12, level=1)
            self.content.pack(fill="both", expand=True, padx=14, pady=8)
            ci = self.content.inner
            self.pages = []
            for _ in range(self._nav_n):
                pg = tk.Frame(ci, bd=0)
                pg.place(x=0, y=0, relwidth=1, relheight=1)
                self.pages.append(pg)
            (self.tab_dash, self.tab_hub, self.tab_findings, self.tab_frameworks,
             self.tab_arsenal, self.tab_stats, self.tab_settings) = self.pages

            self._build_dashboard_tab()
            self._build_hub_tab()
            self._build_findings_tab()
            self._build_frameworks_tab()
            self._build_arsenal_tab()
            self._build_stats_tab()
            self._build_settings_tab()
            self.nav.select(self._nav_n - 1, fire=False)
            self._show_page(0)

        def _show_page(self, i):
            self.pages[i].tkraise()
            self._page = i

        def goto_page(self, i):
            if 0 <= i < self._nav_n:
                self.nav.select(self._nav_n - 1 - i)

        # ------------------------------------------------------------- dashboard
        def _build_dashboard_tab(self):
            F, P = self.F, G.PAL
            pg = self.tab_dash
            cards_row = tk.Frame(pg, bd=0)
            cards_row.pack(fill="x", pady=(0, 2))
            self.stat_labels = {}
            stat_defs = [
                ("risk", "امتیاز ریسک", "—", P["bad"]),
                ("critical", "بحرانی", "0", P["bad"]),
                ("high", "بالا", "0", P["orange"]),
                ("medium", "متوسط", "0", P["warn"]),
                ("packets", "بسته‌ها", "0", P["acc2"]),
                ("bytes", "حجم داده", "0 B", "#93c5fd"),
                ("ips", "IPهای یکتا", "0", P["ok"]),
                ("carved", "فایل / JA3", "0 / 0", P["pink"]),
            ]
            for i, (key, title, default, color) in enumerate(stat_defs):
                card = G.StatCard(cards_row, title, default, color, F)
                card.grid(row=0, column=i, sticky="nsew")
                cards_row.columnconfigure(i, weight=1, uniform="cards")
                self.stat_labels[key] = card

            charts = tk.Frame(pg, bd=0)
            charts.pack(fill="x")
            charts.columnconfigure(0, weight=0)
            charts.columnconfigure(1, weight=1, uniform="ch")
            charts.columnconfigure(2, weight=1, uniform="ch")

            def mk(parent, col, h=226, width=None):
                c = G.GlassPanel(parent, radius=22, inset=6, pad=0, level=1, inner_widget=False, height=h,
                                 **({"width": width} if width else {}))
                c.grid(row=0, column=col, sticky="nsew")
                return c
            self.cv_gauge = mk(charts, 0, width=250)
            self.cv_proto = mk(charts, 1)
            self.cv_time = mk(charts, 2)
            self.cv_killchain = G.GlassPanel(pg, radius=22, inset=6, pad=0, level=1, inner_widget=False, height=112)
            self.cv_killchain.pack(fill="x")
            for cv in (self.cv_gauge, self.cv_proto, self.cv_time, self.cv_killchain):
                cv.bind("<Configure>", lambda e: self.after_idle(self._redraw_charts), add="+")
                cv.bind("<<GlassFill>>", lambda e: self.after_idle(self._redraw_charts), add="+")

            self.txt_dashboard = self._mk_text(pg, mono=False, size=11)
            self.txt_dashboard.pack(fill="both", expand=True, padx=8, pady=(6, 8))
            t = self.txt_dashboard
            t.tag_configure("h1", foreground=P["acc"], font=(F, 12, "bold"), spacing1=6)
            t.tag_configure("crit", foreground=P["bad"])
            t.tag_configure("ok", foreground=P["ok"])
            t.tag_configure("mut", foreground=P["dim"])
            t.tag_configure("hero", foreground=P["ink"], font=(F, 20, "bold"), spacing3=6)
            t.tag_configure("sub", foreground=P["mut"], font=(F, 11))
            t.insert("end", f"{META.APP_NAME}\n", "hero")
            t.insert("end", "یک فایل PCAP / PCAPNG / لاگ را انتخاب کنید و «شروع تحلیل» را بزنید. همه‌چیز کاملاً آفلاین است.\n\n", "sub")
            t.insert("end",
                     "•  بازسازی جریان‌های TCP و دیکد خودکار Gzip / Brotli / Chunked\n"
                     "•  استخراج PE / ELF / SWF / ZIP / PDF / ماکرو (حتی XOR شده) و ذخیره امن در ZIP رمزدار\n"
                     "•  JA3 / JA3S، DNS Tunneling و DGA، Beaconing، اسکن‌ها، SMB / Kerberos و حملات وب\n"
                     "•  نگاشت به MITRE ATT&CK و D3FEND + قوانین Suricata / YARA / Splunk / Elastic\n\n")
            t.insert("end", "میانبرها:  Ctrl+O انتخاب فایل   ·   F5 شروع   ·   Esc توقف   ·   Ctrl+1…7 جابه‌جایی بین بخش‌ها\n", "mut")
            self._redraw_charts()

        # ------------------------------------------------- protocols & files
        def _build_hub_tab(self):
            F, FM, P = self.F, self.FM, G.PAL
            pg = self.tab_hub
            pg.columnconfigure(0, weight=2, uniform="h")
            pg.columnconfigure(1, weight=5, uniform="h")
            pg.rowconfigure(0, weight=1)

            def mk_tree(parent, cols, headers, widths, row, rowspan=1, pady=(0, 0)):
                fr = tk.Frame(parent, bg=P["well"], highlightthickness=1, highlightbackground=P["line"], bd=0)
                fr._glass_keep = True
                fr.grid(row=row, column=0, sticky="nsew", pady=pady)
                tv = ttk.Treeview(fr, columns=cols, show="headings", selectmode="browse")
                for c, h, w in zip(cols, headers, widths):
                    tv.heading(c, text=h, command=lambda c=c, tv=tv: self._sort_tree(tv, c, False))
                    tv.column(c, width=w, anchor="w")
                vsb = ttk.Scrollbar(fr, orient="vertical", command=tv.yview, style="Glass.Vertical.TScrollbar")
                tv.configure(yscrollcommand=vsb.set)
                vsb.pack(side="right", fill="y", padx=(0, 2), pady=4)
                tv.pack(side="left", fill="both", expand=True, padx=2, pady=2)
                return tv, fr

            left = tk.Frame(pg, bd=0)
            left.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
            left.rowconfigure(0, weight=1)
            left.columnconfigure(0, weight=1)
            self.tree_proto, _ = mk_tree(left, ("proto", "flows", "bytes", "events"),
                                         ("پروتکل", "جریان", "حجم", "رویداد"), (130, 62, 90, 70), 0)
            self.tree_proto.bind("<<TreeviewSelect>>", self._on_proto_select)

            right = tk.Frame(pg, bd=0)
            right.grid(row=0, column=1, sticky="nsew", padx=(6, 0))
            right.columnconfigure(0, weight=1)
            right.rowconfigure(0, weight=3)
            right.rowconfigure(2, weight=2)
            self.tree_events, _ = mk_tree(right, ("time", "route", "kind", "summary"),
                                          ("زمان", "مسیر", "نوع", "خلاصه رویداد"), (150, 250, 100, 560), 0, pady=(0, 6))
            bar = tk.Frame(right, bd=0)
            bar.grid(row=1, column=0, sticky="ew", pady=(0, 6))
            self.lbl_files = tk.Label(bar, text="فایل‌ها: —", fg=P["acc2"], font=(F, 10, "bold"))
            self.lbl_files.pack(side="left", padx=6)
            G.GlassButton(bar, "باز کردن پوشه ZIP", self._open_zip_folder, "ghost", height=34, font=(F, 9, "bold")).pack(side="right", padx=3)
            G.GlassButton(bar, "جزئیات فایل", self._show_file_detail, "ghost", height=34, font=(F, 9, "bold")).pack(side="right", padx=3)
            self.tree_files, _ = mk_tree(right, ("name", "size", "type", "proto", "src", "sha"),
                                         ("نام فایل", "حجم", "نوع واقعی", "پروتکل", "منبع", "SHA-256"), (240, 80, 150, 70, 170, 300), 2)
            self.tree_files.bind("<Double-1>", lambda e: self._show_file_detail())
            for t in (self.tree_events, self.tree_files):
                t.tag_configure("x1", foreground=P["warn"])
                t.tag_configure("x2", foreground=P["bad"])

        def _populate_hub_tab(self, hub):
            self.last_hub = hub or {}
            self.tree_proto.delete(*self.tree_proto.get_children())
            for p in self.last_hub.get("protocols", []):
                self.tree_proto.insert("", "end", iid=p["name"], values=(p["name"], f"{p['flows']:,}", human_bytes(p["bytes"]), f"{p['events']:,}"))
            self.tree_files.delete(*self.tree_files.get_children())
            files = self.last_hub.get("files", [])
            for r in files:
                self.tree_files.insert("", "end", iid=str(r["id"]), tags=("x2",) if r["risky"] else (),
                                       values=(r["name"], human_bytes(r["size"]), r["type"], r["proto"],
                                               r.get("host") or r.get("src") or "", r["sha256"]))
            fs = self.last_hub.get("files_summary", {})
            if fs.get("count"):
                self.lbl_files.configure(text=f"فایل‌ها: {fs['count']} ({human_bytes(fs['bytes'])}) — {fs.get('zip')}" + (f" · رمز: {fs['password']}" if fs.get("password") else ""))
            else:
                self.lbl_files.configure(text="فایل‌ها: موردی استخراج نشد")
            kids = self.tree_proto.get_children()
            if kids:
                self.tree_proto.selection_set(kids[0])

        def _on_proto_select(self, _e=None):
            sel = self.tree_proto.selection()
            if not sel:
                return
            name = sel[0]
            self.tree_events.delete(*self.tree_events.get_children())
            for i, e in enumerate((self.last_hub.get("events", {}).get(name) or [])[:4000]):
                self.tree_events.insert("", "end", iid=f"{i}", tags=(f"x{e['x']}",) if e["x"] else (),
                                        values=(e["ts"], f"{e['a']}:{e['ap']} → {e['b']}:{e['bp']}" if e["ap"] or e["bp"] else f"{e['a']} → {e['b']}",
                                                e["k"], e["s"]))

        def _open_zip_folder(self):
            z = (self.last_hub.get("files_summary") or {}).get("zip_abs")
            if z and os.path.isfile(z):
                webbrowser.open(Path(z).parent.resolve().as_uri())
            else:
                messagebox.showinfo("ZIP موجود نیست", "فایلی استخراج نشده است.")

        def _show_file_detail(self):
            sel = self.tree_files.selection()
            if not sel:
                return
            r = next((x for x in self.last_hub.get("files", []) if str(x["id"]) == sel[0]), None)
            if not r:
                return
            messagebox.showinfo("جزئیات فایل", "\n".join([
                f"نام اصلی: {r['name']}", f"مسیر در ZIP: {r.get('zip_path')}", f"نوع واقعی: {r['type']} ({r['category_fa']})",
                f"حجم: {r['size']:,} بایت", f"پروتکل: {r['proto']} ({r.get('direction', '')})", f"URL: {r.get('url', '')}",
                f"از: {r.get('src', '')}  به: {r.get('dst', '')}", f"MD5: {r['md5']}", f"SHA-256: {r['sha256']}",
                "⚠ اجرایی/پرخطر — فقط در VM باز کنید" if r["risky"] else ""]))

        # -------------------------------------------------------------- findings
        def _build_findings_tab(self):
            F, FM, P = self.F, self.FM, G.PAL
            pg = self.tab_findings
            bar = tk.Frame(pg, bd=0)
            bar.pack(fill="x", pady=(0, 8))
            self.lbl_count = tk.Label(bar, text="", fg=P["dim"], font=(F, 9))
            self.lbl_count.pack(side="left", padx=6)
            cmb = ttk.Combobox(bar, textvariable=self.sev_filter_var, state="readonly", width=18, font=(F, 10),
                               values=["همه (All)", "بحرانی (critical)", "بالا (high)", "متوسط (medium)",
                                       "کم (low)", "اطلاعاتی (info)"])
            cmb.pack(side="right", padx=(8, 0), ipady=3)
            cmb.bind("<<ComboboxSelected>>", lambda *_: self.refresh_findings_table())
            tk.Label(bar, text="شدت:", fg=P["mut"], font=(F, 10)).pack(side="right", padx=(14, 6))
            G.GlassField(bar, self.search_var, (F, 10), width=300, height=38).pack(side="right")
            tk.Label(bar, text="جستجو:", fg=P["mut"], font=(F, 10)).pack(side="right", padx=(0, 8))
            self.search_var.trace_add("write", lambda *_: self.refresh_findings_table())

            body = tk.Frame(pg, bd=0)
            body.pack(fill="both", expand=True)
            body.rowconfigure(0, weight=3)
            body.rowconfigure(1, weight=2)
            body.columnconfigure(0, weight=1)

            tree_frame = tk.Frame(body, bg=P["well"], highlightthickness=1, highlightbackground=P["line"], bd=0)
            tree_frame._glass_keep = True
            tree_frame.grid(row=0, column=0, sticky="nsew", pady=(0, 8))
            cols = ("sev", "title", "kill_chain", "mitre", "d3fend", "count", "actors")
            self.tree_findings = ttk.Treeview(tree_frame, columns=cols, show="headings", selectmode="browse")
            headers = {
                "sev": ("شدت", 80), "title": ("عنوان تهدید / ناهنجاری", 310),
                "kill_chain": ("مرحله Kill Chain", 145), "mitre": ("ATT&CK", 90),
                "d3fend": ("MITRE D3FEND", 185), "count": ("رخداد", 80), "actors": ("IPهای مبدأ / سرور مهاجم", 220),
            }
            for col, (text, w) in headers.items():
                self.tree_findings.heading(col, text=text, command=lambda c=col: self._sort_tree(self.tree_findings, c, False))
                self.tree_findings.column(col, width=w, anchor="center" if col in ("sev", "mitre", "count") else "e")
            for sev, color in SEV_COLOR.items():
                self.tree_findings.tag_configure(sev, foreground=color)
            vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree_findings.yview, style="Glass.Vertical.TScrollbar")
            self.tree_findings.configure(yscrollcommand=vsb.set)
            vsb.pack(side="right", fill="y", padx=(0, 2), pady=4)
            self.tree_findings.pack(side="left", fill="both", expand=True, padx=2, pady=2)
            self.tree_findings.bind("<<TreeviewSelect>>", self.on_finding_select)
            self.tree_findings.bind("<Button-3>", self._finding_menu)
            self.tree_findings.bind("<Button-2>", self._finding_menu)

            self.menu_finding = tk.Menu(self, tearoff=0, bg=P["well"], fg=P["ink"], activebackground=P["acc"],
                                        activeforeground="#fff", bd=0, relief="flat", font=(F, 10))
            self.menu_finding.add_command(label="کپی شواهد این هشدار", command=self._copy_finding_evidence)
            self.menu_finding.add_command(label="کپی IPهای مبدأ", command=self._copy_finding_actors)

            self.txt_finding_detail = self._mk_text(body, bg=P["well"])
            self.txt_finding_detail.grid(row=1, column=0, sticky="nsew")

        def _build_frameworks_tab(self):
            self.txt_frameworks = self._mk_text(self.tab_frameworks)
            self.txt_frameworks.pack(fill="both", expand=True, padx=2, pady=2)

        def _build_arsenal_tab(self):
            self.txt_arsenal = self._mk_text(self.tab_arsenal, fg="#a5f3fc")
            self.txt_arsenal.pack(fill="both", expand=True, padx=2, pady=2)

        def _build_stats_tab(self):
            self.txt_stats = self._mk_text(self.tab_stats)
            self.txt_stats.pack(fill="both", expand=True, padx=2, pady=2)

        # -------------------------------------------------------------- settings
        def _build_settings_tab(self):
            F, FM, P = self.F, self.FM, G.PAL
            pg = self.tab_settings
            pg.columnconfigure(0, weight=3, uniform="s")
            pg.columnconfigure(1, weight=2, uniform="s")
            pg.rowconfigure(0, weight=1)

            self.setting_vars = {
                "max_packets": tk.IntVar(value=self.cfg.max_packets),
                "port_scan_thresh": tk.IntVar(value=self.cfg.port_scan_thresh),
                "host_sweep_thresh": tk.IntVar(value=self.cfg.host_sweep_thresh),
                "brute_force_thresh": tk.IntVar(value=self.cfg.brute_force_thresh),
                "syn_flood_thresh": tk.IntVar(value=self.cfg.syn_flood_thresh),
                "dns_tunnel_subs": tk.IntVar(value=self.cfg.dns_tunnel_subs),
                "dga_nx_thresh": tk.IntVar(value=self.cfg.dga_nx_thresh),
                "exfil_mb_thresh": tk.DoubleVar(value=self.cfg.exfil_mb_thresh),
                "beacon_cv_thresh": tk.DoubleVar(value=self.cfg.beacon_cv_thresh),
                "mask_passwords": tk.BooleanVar(value=self.cfg.mask_passwords),
                "use_tshark_if_available": tk.BooleanVar(value=self.cfg.use_tshark_if_available),
                "raw_samples": tk.BooleanVar(value=self.cfg.raw_samples),
                "extract_files": tk.BooleanVar(value=self.cfg.extract_files),
                "fast_io": tk.BooleanVar(value=self.cfg.fast_io),
            }
            self.var_theme = tk.StringVar(value=self.cfg.theme)
            self.var_lang = tk.StringVar(value=I18N.get_lang())
            self.var_material = tk.StringVar(value=self.cfg.material)
            self.var_style = tk.StringVar(value=self.cfg.report_style)
            left = G.GlassPanel(pg, radius=24, inset=6, pad=16, level=2)
            left.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
            li = left.inner
            tk.Label(li, text="آستانه‌های موتور تشخیص", fg=P["ink"], font=(F, 13, "bold"), anchor="e").pack(fill="x", pady=(0, 10))
            fields = [
                ("حداکثر تعداد بسته (۰ = کل فایل)", "max_packets"),
                ("اسکن پورت (تعداد پورت یکتا)", "port_scan_thresh"),
                ("جاروب شبکه / Host Sweep (تعداد IP)", "host_sweep_thresh"),
                ("حمله Brute-Force (تعداد تلاش)", "brute_force_thresh"),
                ("SYN Flood (تعداد بسته SYN)", "syn_flood_thresh"),
                ("DNS Tunneling (زیردامنه یکتا)", "dns_tunnel_subs"),
                ("DGA (خطای NXDOMAIN)", "dga_nx_thresh"),
                ("نشت داده Exfiltration (مگابایت)", "exfil_mb_thresh"),
                ("Beaconing (ضریب پراکندگی CV کمتر از)", "beacon_cv_thresh"),
            ]
            for key_i, (label_text, key) in enumerate(fields):
                row = tk.Frame(li, bd=0)
                row.pack(fill="x", pady=3)
                is_float = key in ("exfil_mb_thresh", "beacon_cv_thresh")
                inc = 0.05 if key == "beacon_cv_thresh" else (0.5 if is_float else 1)
                G.GlassField(row, self.setting_vars[key], (FM, 10), width=170, height=36, spin=(0, 10000000, inc),
                             fg=P["acc2"]).pack(side="left")
                tk.Label(row, text=label_text, fg=P["mut"], font=(F, 10), anchor="e").pack(side="right")
            btns = tk.Frame(li, bd=0)
            btns.pack(fill="x", pady=(14, 0))
            G.GlassButton(btns, "بازگشت به پیش‌فرض", self._reset_settings, "ghost", height=36, font=(F, 9, "bold"),
                          icon="↺").pack(side="right")

            right = tk.Frame(pg, bd=0)
            right.grid(row=0, column=1, sticky="nsew", padx=(6, 0))
            right.rowconfigure(0, weight=3)
            right.rowconfigure(1, weight=2)
            right.columnconfigure(0, weight=1)
            sw = G.GlassPanel(right, radius=24, inset=6, pad=16, level=2)
            sw.grid(row=0, column=0, sticky="nsew", pady=(0, 6))
            si = sw.inner
            tk.Label(si, text="رفتار برنامه", fg=P["ink"], font=(F, 13, "bold"), anchor="e").pack(fill="x", pady=(0, 8))
            for text, var, color in (
                ("ماسک کردن رمز عبور و توکن‌ها در گزارش‌ها", self.setting_vars["mask_passwords"], P["ok"]),
                ("استفاده از TShark در صورت نصب بودن", self.setting_vars["use_tshark_if_available"], P["acc2"]),
                ("باز کردن خودکار گزارش HTML پس از تحلیل", self.auto_open, P["warn"]),
                ("ذخیره خام نمونه‌های مخرب (خطرناک؛ با تأیید)", self.setting_vars["raw_samples"], P["bad"]),
                ("استخراج فایل‌های منتقل‌شده در ZIP (HTTP/FTP/SMTP/TFTP)", self.setting_vars["extract_files"], P["ok"]),
                ("پکت‌خوان بومی سریع (بدون scapy)", self.setting_vars["fast_io"], P["acc"]),
            ):
                G.GlassSwitch(si, text, var, (F, 10), color=color).pack(fill="x", pady=2)
            tk.Label(si, text="ظاهر و خروجی", fg=P["ink"], font=(F, 12, "bold"), anchor="e").pack(fill="x", pady=(10, 4))
            for label, var, vals, cb in (
                ("Language / زبان (restart)", self.var_lang, list(I18N.LANGS), self._on_lang_change),
                ("تم رنگی (نیازمند راه‌اندازی مجدد)", self.var_theme, list(THEMES.THEMES), self._on_theme_change),
                ("متریال گزارش HTML", self.var_material, list(THEMES.MATERIALS), self._on_output_change),
                ("قالب گزارش (cyber / classic / both)", self.var_style, ["cyber", "classic", "both"], self._on_output_change),
            ):
                row = tk.Frame(si, bd=0)
                row.pack(fill="x", pady=2)
                cmb = ttk.Combobox(row, textvariable=var, values=vals, state="readonly", width=18, font=(F, 10))
                cmb.pack(side="left", ipady=2)
                cmb.bind("<<ComboboxSelected>>", cb)
                tk.Label(row, text=label, fg=P["mut"], font=(F, 10), anchor="e").pack(side="right")

            ab = G.GlassPanel(right, radius=24, inset=6, pad=16, level=2)
            ab.grid(row=1, column=0, sticky="nsew", pady=(6, 0))
            ai = ab.inner
            tk.Label(ai, text="درباره", fg=P["ink"], font=(F, 13, "bold"), anchor="e").pack(fill="x")
            tk.Label(ai, text=f"{META.APP_NAME}  v{META.VERSION}", fg=P["acc"], font=(F, 11, "bold"), anchor="e").pack(fill="x", pady=(6, 0))
            tk.Label(ai, text=f"ساخته‌شده توسط {META.AUTHOR}  ·  مجوز {META.LICENSE_NAME}", fg=P["mut"], font=(F, 10), anchor="e").pack(fill="x")
            row = tk.Frame(ai, bd=0)
            row.pack(fill="x", pady=(12, 0))
            G.GlassButton(row, "پروفایل", lambda: webbrowser.open(META.GITHUB_PROFILE), "ghost", height=34, font=(F, 9, "bold")).pack(side="right", padx=3)
            G.GlassButton(row, "مخزن", lambda: webbrowser.open(META.REPO_URL), "ghost", height=34, font=(F, 9, "bold")).pack(side="right", padx=3)
            G.GlassButton(row, "دانلودها", lambda: webbrowser.open(META.RELEASES_URL), "ghost", height=34, font=(F, 9, "bold")).pack(side="right", padx=3)
            G.GlassButton(row, "نسخه جدید؟", self.check_updates, "primary", height=34, font=(F, 9, "bold")).pack(side="right", padx=3)

        def _on_output_change(self, _e=None):
            self.cfg.material = self.var_material.get()
            self.cfg.report_style = self.var_style.get()
            THEMES.save_config(material=self.cfg.material, report_style=self.cfg.report_style, theme=self.var_theme.get())

        def _on_theme_change(self, _e=None):
            t = self.var_theme.get()
            self.cfg.theme = t
            THEMES.save_config(theme=t, material=self.var_material.get(), report_style=self.var_style.get())
            if messagebox.askyesno("تم جدید", f"تم «{THEMES.get_theme(t)['fa']}» ذخیره شد.\nبرای اعمال روی رابط، برنامه همین حالا دوباره اجرا شود؟\n(گزارش HTML بعدی هم با این تم ساخته می‌شود)"):
                self._restart()

        def _on_lang_change(self, _e=None):
            lg = self.var_lang.get()
            THEMES.save_config(lang=lg)
            if messagebox.askyesno("Language / زبان", "Language saved. Restart now to apply it?\nزبان ذخیره شد. برای اعمال، برنامه دوباره اجرا شود؟"):
                self._restart()

        def _restart(self):
            try:
                args = [sys.executable] + ([] if getattr(sys, "frozen", False) else [os.path.abspath(sys.argv[0])])
                cur = self.current_file.get().strip()
                if cur:
                    args.append(cur)
                self.destroy()
                os.execv(sys.executable, args)
            except Exception as ex:
                messagebox.showwarning("راه‌اندازی مجدد", f"به‌صورت خودکار ممکن نشد؛ برنامه را خودتان ببندید و باز کنید.\n{ex}")

        # ---------------------------------------------------------- update check
        def check_updates(self):
            """Opt-in only: the app never phones home by itself."""
            self.status_text.set("در حال بررسی آخرین نسخه در GitHub …")

            def work():
                try:
                    import urllib.request
                    req = urllib.request.Request(META.LATEST_API_URL, headers={"User-Agent": META.APP_SLUG})
                    with urllib.request.urlopen(req, timeout=8) as r:
                        tag = json.loads(r.read().decode("utf-8")).get("tag_name", "")
                    self.msgq.put(("update", tag, None))
                except Exception as ex:
                    self.msgq.put(("update", None, str(ex)))
            threading.Thread(target=work, daemon=True).start()

        def _on_update_result(self, tag, err):
            def ver(v):
                return tuple(int(x) for x in re.findall(r"\d+", v)[:3]) or (0,)
            if err or not tag:
                self.status_text.set("بررسی نسخه ناموفق بود (اینترنت یا هنوز نسخه‌ای منتشر نشده)")
                return
            if ver(tag) > ver(META.VERSION):
                self.status_text.set(f"نسخه جدید {tag} موجود است")
                if messagebox.askyesno("نسخه جدید", f"نسخه {tag} منتشر شده (نسخه شما {META.VERSION}).\nصفحه دانلود باز شود؟"):
                    webbrowser.open(META.LATEST_RELEASE_URL)
            else:
                self.status_text.set(f"شما آخرین نسخه ({META.VERSION}) را دارید ✔")

        def _reset_settings(self):
            d = EngineConfig()
            for k, var in self.setting_vars.items():
                try:
                    var.set(getattr(d, k))
                except Exception:
                    pass

        def _apply_settings(self):
            bad = []
            for k, var in self.setting_vars.items():
                try:
                    setattr(self.cfg, k, var.get())
                except (tk.TclError, ValueError):
                    bad.append(k)
            if bad:
                messagebox.showwarning("مقدار نامعتبر", "مقدار این تنظیمات عددی معتبر نیست و نادیده گرفته شد:\n" + ", ".join(bad))
            return True

        # ----------------------------------------------------------------- charts
        def _redraw_charts(self):
            try:
                self._draw_gauge()
                self._draw_bars()
                self._draw_timeline()
                self._draw_killchain()
            except tk.TclError:
                pass

        def _cv(self, c):
            c.delete("fg")
            w, h = c.winfo_width(), c.winfo_height()
            return w, h, getattr(c, "fill", G.PAL["glass"])

        def _arc_glow(self, c, box, start, extent, col, base, width):
            for k, (ww, t) in enumerate(((width + 14, .86), (width + 8, .72), (width + 3, .5))):
                c.create_arc(*box, start=start, extent=extent, style="arc", width=ww, outline=G.mix(base, col, 1 - t), tags="fg")
            c.create_arc(*box, start=start, extent=extent, style="arc", width=width, outline=col, tags="fg")

        def _draw_gauge(self):
            c = self.cv_gauge
            w, h, fill = self._cv(c)
            if w < 60 or h < 60:
                return
            P = G.PAL
            score = int(self._chart_data["score"])
            level = self._chart_data["level"]
            col = SEV_COLOR.get(level, P["acc2"]) if score else P["dim"]
            cx, cy = w / 2, h / 2 + 12
            r = min(w, h) / 2 - 34
            c.create_text(w - 22, 22, anchor="e", text="امتیاز ریسک کل", fill=P["mut"], font=(self.F, 10, "bold"), tags="fg")
            box = (cx - r, cy - r, cx + r, cy + r)
            c.create_arc(*box, start=225, extent=-270, style="arc", width=12, outline=G.mix(fill, "#ffffff", .10), tags="fg")
            if score > 0:
                self._arc_glow(c, box, 225, -270 * score / 100, col, fill, 12)
            c.create_text(cx, cy - 4, text=str(score), fill="#ffffff", font=(self.F, 34, "bold"), tags="fg")
            c.create_text(cx, cy + 32, text=SEV_FA.get(level, level) if score else "منتظر تحلیل", fill=col, font=(self.F, 11, "bold"), tags="fg")

        def _draw_bars(self):
            c = self.cv_proto
            w, h, fill = self._cv(c)
            P = G.PAL
            c.create_text(w - 22, 22, anchor="e", text="توزیع پروتکل‌ها", fill=P["mut"], font=(self.F, 10, "bold"), tags="fg")
            items = self._chart_data["protocols"][:8]
            if not items or w < 160:
                c.create_text(w / 2, h / 2 + 8, text="—", fill=P["dim"], font=(self.F, 18), tags="fg")
                return
            mx = max(v for _, v in items) or 1
            top, left, right = 44, 24, w - 24
            row_h = max(16, min(28, (h - top - 14) / len(items)))
            lab_w, val_w = 74, 70
            for i, (name, val) in enumerate(items):
                y = top + i * row_h
                x0, x1 = left + lab_w, right - val_w
                bh = max(8, row_h - 11)
                yy = y + (row_h - bh) / 2
                c.create_text(left, y + row_h / 2, anchor="w", text=str(name)[:10], fill=P["ink"], font=(self.FM, 9), tags="fg")
                self._pill(c, x0, yy, x1, yy + bh, G.mix(fill, "#ffffff", .07))
                bw = max(bh, (x1 - x0) * val / mx)
                col = CHART_PALETTE[i % len(CHART_PALETTE)]
                self._pill(c, x0, yy, x0 + bw, yy + bh, col)
                c.create_text(right, y + row_h / 2, anchor="e", text=f"{val:,}", fill=P["mut"], font=(self.FM, 9), tags="fg")

        def _pill(self, c, x1, y1, x2, y2, col):
            r = (y2 - y1) / 2
            x2 = max(x2, x1 + 2 * r)
            c.create_oval(x1, y1, x1 + 2 * r, y2, fill=col, outline="", tags="fg")
            c.create_oval(x2 - 2 * r, y1, x2, y2, fill=col, outline="", tags="fg")
            c.create_rectangle(x1 + r, y1, x2 - r, y2, fill=col, outline="", tags="fg")

        def _draw_timeline(self):
            c = self.cv_time
            w, h, fill = self._cv(c)
            P = G.PAL
            c.create_text(w - 22, 22, anchor="e", text="حجم ترافیک در طول زمان", fill=P["mut"], font=(self.F, 10, "bold"), tags="fg")
            bins = self._chart_data["timeline"]
            if not bins or max(bins) == 0 or w < 160:
                c.create_text(w / 2, h / 2 + 8, text="—", fill=P["dim"], font=(self.F, 18), tags="fg")
                return
            mx = max(bins)
            left, right, top, bottom = 26, w - 26, 52, h - 26
            for k in range(4):
                y = top + (bottom - top) * k / 3
                c.create_line(left, y, right, y, fill=G.mix(fill, "#ffffff", .07), tags="fg")
            n = len(bins)
            pts = []
            for i, v in enumerate(bins):
                pts.append((left + (right - left) * i / max(n - 1, 1), bottom - (bottom - top) * v / mx))
            flat = [p for xy in pts for p in xy]
            for k, t in enumerate((.88, .8, .7)):   # faux gradient fill
                yk = [(x, y + (bottom - y) * (k / 3)) for x, y in pts]
                c.create_polygon([left, bottom] + [p for xy in yk for p in xy] + [right, bottom],
                                 fill=G.mix(fill, P["acc2"], 1 - t + .02), outline="", tags="fg")
            c.create_line(flat, fill=G.mix(fill, P["acc2"], .25), width=7, smooth=True, tags="fg")
            c.create_line(flat, fill=P["acc2"], width=2.5, smooth=True, tags="fg")
            px, py = max(pts, key=lambda p: -p[1])
            c.create_oval(px - 6, py - 6, px + 6, py + 6, fill=G.mix(fill, P["acc2"], .4), outline="", tags="fg")
            c.create_oval(px - 3, py - 3, px + 3, py + 3, fill="#ffffff", outline="", tags="fg")
            c.create_text(left, 22, anchor="w", text=f"اوج {mx:,}", fill=P["acc2"], font=(self.FM, 9), tags="fg")

        def _draw_killchain(self):
            c = self.cv_killchain
            w, h, fill = self._cv(c)
            if w < 240:
                return
            P = G.PAL
            c.create_text(w - 22, 20, anchor="e", text="زنجیره کشتار سایبری (Kill Chain)", fill=P["mut"], font=(self.F, 10, "bold"), tags="fg")
            kc_list = self._chart_data.get("kill_chain", [])
            if not kc_list:
                return
            n = len(kc_list)
            pad_x, gap = 22, 8
            box_w = (w - 2 * pad_x - (n - 1) * gap) / n
            y1, y2 = 38, h - 16
            for idx, stage in enumerate(kc_list):
                x1 = pad_x + (n - 1 - idx) * (box_w + gap)
                x2 = x1 + box_w
                active = stage.get("active", False)
                cnt = stage.get("count", 0)
                if active:
                    for grow, t in ((5, .88), (2, .7)):
                        self._rr(c, x1 - grow, y1 - grow, x2 + grow, y2 + grow, 14, G.mix(fill, P["bad"], 1 - t))
                    self._rr(c, x1, y1, x2, y2, 12, G.mix(fill, P["bad"], .32), outline=P["bad"])
                else:
                    self._rr(c, x1, y1, x2, y2, 12, G.mix(fill, "#ffffff", .045), outline=G.mix(fill, "#ffffff", .12))
                cx = (x1 + x2) / 2
                c.create_text(cx, y1 + (y2 - y1) * .36, text=stage["stage_fa"], fill="#ffffff" if active else P["mut"],
                              font=(self.F, 8, "bold"), width=box_w - 8, tags="fg")
                c.create_text(cx, y1 + (y2 - y1) * .74, text=f"{cnt:,} رخداد" if active else "—",
                              fill=P["orange"] if active else P["dim"], font=(self.F, 8, "bold"), tags="fg")

        def _rr(self, c, x1, y1, x2, y2, r, fill, outline=""):
            pts = [x1 + r, y1, x2 - r, y1, x2, y1, x2, y1 + r, x2, y2 - r, x2, y2, x2 - r, y2,
                   x1 + r, y2, x1, y2, x1, y2 - r, x1, y1 + r, x1, y1]
            c.create_polygon(pts, smooth=True, fill=fill, outline=outline, width=1, tags="fg")

        def browse_file(self):
            path = filedialog.askopenfilename(
                title="انتخاب فایل شبکه (PCAP/PCAPNG) یا لاگ (LOG/JSON/TXT)",
                filetypes=[
                    ("All Supported Files", "*.pcap *.pcapng *.cap *.log *.json *.jsonl *.txt"),
                    ("Packet Capture", "*.pcap *.pcapng *.cap"),
                    ("Log & SIEM Files", "*.log *.json *.jsonl *.txt *.xml *.csv"),
                    ("All Files", "*.*"),
                ]
            )
            if path:
                self.current_file.set(path)

        def start_analysis(self):
            if self.running:
                return
            path = self.current_file.get().strip().strip("\"'")
            if not path or not os.path.isfile(path):
                messagebox.showwarning("فایل نامعتبر", "لطفاً یک فایل معتبر انتخاب کنید.")
                return

            self._apply_settings()
            self.cfg.out_dir = prepare_output_dir(default_out_dir(path))
            self.cfg.sample_mode = "auto"
            if self.cfg.raw_samples:
                if messagebox.askyesno("ذخیره خام نمونه‌ها", "نمونه‌های مخرب به‌صورت خام و واقعی ذخیره می‌شوند و خطرناک‌اند.\nادامه می‌دهید؟"):
                    self.cfg.sample_mode = "raw"
                    request_defender_exclusion(self.cfg.out_dir, lambda t, x: messagebox.askyesno(t, x), log=lambda m: self.status_text.set(m))
            analyzer = PcapAnalyzer(self.cfg)
            self.analyzer = analyzer
            self.running = True

            self.btn_start.configure(state="disabled")
            self.btn_stop.configure(state="normal")
            for b in (self.btn_html, self.btn_json, self.btn_csv, self.btn_ioc):
                b.configure(state="disabled")
            self.progress["value"] = 0
            self.status_text.set("⏳ در حال بازسازی جریان‌های TCP، دیکد Gzip/Brotli، شکار Exploit Kit و نگاشت MITRE...")

            self.worker_thread = threading.Thread(target=self._run_worker, args=(analyzer, path), daemon=True)
            self.worker_thread.start()

        def stop_analysis(self):
            if self.running and self.analyzer:
                self.analyzer.stop_requested = True
                self.status_text.set("⏸ در حال توقف و ساخت گزارش از داده‌های خوانده‌شده...")

        def _write_report(self, path, st, findings, corr):
            try:
                files = write_all_reports(path, self.cfg.out_dir, st, findings, corr, DEFANG_REPORT, style=self.cfg.report_style,
                                          theme=self.cfg.theme, material=self.cfg.material, formats=self.cfg.formats)
                return next((f for f in files if f.endswith(".html")), None)
            except Exception:
                return None

        def _run_worker(self, analyzer, path):
            try:
                def prog_cb(pkts, read_bytes, total_bytes, rate, done=False):
                    self.msgq.put(("progress", pkts, read_bytes, total_bytes, rate, done))

                analyzer.run(path, progress_cb=prog_cb)
                st = analyzer.stats()
                findings = analyzer.findings()
                corr = analyzer.correlate_offline()
                html_path = None
                try:
                    html_path = self._write_report(path, st, findings, corr)
                except Exception:
                    html_path = None
                self.msgq.put(("done", st, findings, corr, html_path, analyzer.read_error, analyzer.errors))
            except Exception:
                self.msgq.put(("error", traceback.format_exc()))

        def _poll_queue(self):
            last_prog = None
            try:
                for _ in range(400):
                    m = self.msgq.get_nowait()
                    if m[0] == "progress":
                        last_prog = m
                    elif m[0] == "done":
                        self._on_complete(*m[1:])
                    elif m[0] == "error":
                        self._on_error(m[1])
                    elif m[0] == "update":
                        self._on_update_result(m[1], m[2])
            except queue.Empty:
                pass
            if last_prog is not None:
                self._update_progress_ui(*last_prog[1:])
            self.after(80, self._poll_queue)

        def _update_progress_ui(self, pkts, read_bytes, total_bytes, rate, done):
            if not self.running:
                return
            pct = 100 if done else (min(99.0, read_bytes / total_bytes * 100) if total_bytes > 0 else 0)
            self.progress["value"] = pct
            if not done:
                self.status_text.set(
                    f"⏳ {pct:.0f}% | پردازش‌شده: {pkts:,} واحد ({human_bytes(read_bytes)}) | سرعت: {rate:,} pkt/s"
                )

        def _on_error(self, err_msg):
            self.running = False
            self.btn_start.configure(state="normal")
            self.btn_stop.configure(state="disabled")
            self.status_text.set("❌ خطا در تحلیل فایل")
            messagebox.showerror("خطا", f"خطا هنگام تحلیل:\n{err_msg[-1500:]}")

        def _on_complete(self, st, findings, corr, html_path, read_error=None, parse_errors=0):
            self.running = False
            self.last_stats, self.last_findings, self.last_corr, self.last_html_path = st, findings, corr, html_path

            self.btn_start.configure(state="normal")
            self.btn_stop.configure(state="disabled")
            self.btn_json.configure(state="normal")
            self.btn_csv.configure(state="normal")
            self.btn_ioc.configure(state="normal")
            self.btn_html.configure(state="normal" if html_path else "disabled")
            self.progress["value"] = 100

            extra = ""
            if read_error:
                extra += " | ⚠ فایل ناقص بود (نتایج بخش خوانده‌شده نمایش داده شد)"
            if parse_errors:
                extra += f" | {parse_errors:,} بسته غیرقابل‌پردازش رد شد"
            self.status_text.set(
                f"✔ تحلیل کامل شد: {st['packets']:,} بسته | {len(findings)} هشدار امنیتی | ریسک: {corr['risk_score']}/100"
                + (" | گزارش HTML آماده است" if html_path else "") + extra
            )

            cnt = collections.Counter(f["severity"] for f in findings)
            score = corr["risk_score"]
            self.stat_labels["risk"].configure(text=f"{score}/100")
            self.stat_labels["critical"].configure(text=str(cnt.get("critical", 0)))
            self.stat_labels["high"].configure(text=str(cnt.get("high", 0)))
            self.stat_labels["medium"].configure(text=str(cnt.get("medium", 0)))
            self.stat_labels["packets"].configure(text=f"{st['packets']:,}")
            self.stat_labels["bytes"].configure(text=human_bytes(st["bytes"]))
            self.stat_labels["ips"].configure(text=str(st["unique_ips"]))
            self.stat_labels["carved"].configure(text=f"{len(st['carved_files'])} / {len(st['ja3_fingerprints'])}")

            self._chart_data = {
                "protocols": list(st["protocols"].items()),
                "timeline": list(st["timeline"]),
                "score": score,
                "level": corr["risk_level"],
                "kill_chain": corr["kill_chain"],
            }
            self._redraw_charts()

            t = self.txt_dashboard
            t.delete("1.0", "end")
            t.insert("end", f"🛡️ خلاصه مدیریتی SOC — سطح ریسک: {SEV_FA[corr['risk_level']]} (امتیاز {score} از 100)\n", "h1")
            t.insert("end", corr["executive_summary"] + "\n\n")
            t.insert("end", "⛓️ جزئیات مراحل فعال زنجیره کشتار سایبری (Cyber Kill Chain):\n", "h1")
            for kc in corr["kill_chain"]:
                if kc["active"]:
                    t.insert("end", f"  🚨 [فعال]  {kc['stage_fa']}  (رخداد: {kc['count']:,})\n", "crit")
                    for fn in kc["findings"]:
                        t.insert("end", f"        └── {fn}\n")
                else:
                    t.insert("end", f"  ⚪ [بدون رخداد]  {kc['stage_fa']}\n", "mut")
            t.insert("end", "\n")
            if st.get("artifact_dir") and st["carved_files"]:
                t.insert("end", f"📦 فایل‌های اجرایی/فلش استخراج‌شده در پوشه زیر ذخیره شدند:\n{st['artifact_dir']}\n\n", "ok")
            if html_path:
                t.insert("end", f"🌐 گزارش HTML تعاملی ذخیره شد (با دکمه سبز بالا باز می‌شود):\n{html_path}\n", "ok")

            self._populate_hub_tab(st.get("hub"))
            self.refresh_findings_table()
            self._populate_frameworks_tab(corr)
            self._populate_arsenal_tab(corr["detection_arsenal"])
            self._populate_stats_tab(st)

            if self.auto_open.get() and html_path:
                self.export_and_open_html()

        def _sort_tree(self, tree, col, reverse):
            rows = [(tree.set(k, col), k) for k in tree.get_children("")]

            def keyf(v):
                s = v[0].replace(",", "")
                try:
                    return (0, float(s), "")
                except ValueError:
                    return (1, 0.0, v[0].lower())

            rows.sort(key=keyf, reverse=reverse)
            for i, (_, k) in enumerate(rows):
                tree.move(k, "", i)
            tree.heading(col, command=lambda: self._sort_tree(tree, col, not reverse))

        def refresh_findings_table(self):
            self.tree_findings.delete(*self.tree_findings.get_children())
            q = self.search_var.get().strip().lower()
            sev_f = self.sev_filter_var.get()
            shown = 0
            for idx, f in enumerate(self.last_findings):
                if sev_f != "همه (All)" and f["severity"] not in sev_f:
                    continue
                hay = (f"{f['title']} {f['category']} {f['mitre']} {f['d3fend']} "
                       f"{' '.join(f['actors'])} {' '.join(f['targets'])} {' '.join(f['evidence'])}").lower()
                if q and q not in hay:
                    continue
                self.tree_findings.insert(
                    "", "end", iid=str(idx),
                    values=(SEV_FA[f["severity"]], f["title"], f["kill_chain"], f["mitre"], f["d3fend"],
                            f"{f['count']:,}", ", ".join(f["actors"][:3]) or "-"),
                    tags=(f["severity"],)
                )
                shown += 1
            try:
                self.lbl_count.configure(text=f"{shown} از {len(self.last_findings)} هشدار")
            except Exception:
                pass

        def _selected_finding(self):
            sel = self.tree_findings.selection()
            if not sel:
                return None
            try:
                return self.last_findings[int(sel[0])]
            except (ValueError, IndexError):
                return None

        def _finding_menu(self, event):
            row = self.tree_findings.identify_row(event.y)
            if row:
                self.tree_findings.selection_set(row)
                self.menu_finding.tk_popup(event.x_root, event.y_root)

        def _copy_text(self, text):
            self.clipboard_clear()
            self.clipboard_append(text)
            self.status_text.set("📋 در کلیپ‌بورد کپی شد")

        def _copy_finding_evidence(self):
            f = self._selected_finding()
            if f:
                self._copy_text("\n".join(f["evidence"]))

        def _copy_finding_actors(self):
            f = self._selected_finding()
            if f:
                self._copy_text("\n".join(f["actors"]))

        def on_finding_select(self, _event=None):
            sel = self.tree_findings.selection()
            if not sel:
                return
            f = self.last_findings[int(sel[0])]
            self.txt_finding_detail.delete("1.0", "end")
            lines = [
                f"عنوان تهدید:   {f['title']}  [{SEV_FA[f['severity']]}]",
                f"MITRE ATT&CK: {f['mitre']}   |   MITRE D3FEND: {f['d3fend']}   |   MITRE CAR: {f['car']}",
                f"Kill Chain:   {f['kill_chain']}   |   لایه هرم درد: {f['pyramid']}   |   تعداد رخداد: {f['count']:,}",
                f"مبدأ (Actors): {', '.join(f['actors']) or '-'}   |   هدف (Targets): {', '.join(f['targets']) or '-'}",
                "-" * 90,
                f"شرح فنی:\n{f['description']}",
                f"\n🛡️ راهکار تدافعی و مهار (D3FEND):\n{f['recommendation']}",
                "-" * 90,
                "📦 شواهد بسته‌ها / جریان‌های بازسازی‌شده (Evidence):"
            ]
            for ev in f["evidence"]:
                lines.append(f"  • {ev}")
            self.txt_finding_detail.insert("end", "\n".join(lines))

        def _populate_frameworks_tab(self, corr):
            self.txt_frameworks.delete("1.0", "end")
            pop = corr["pyramid_of_pain"]
            dm = corr["diamond_model"]
            lines = [
                "================================================================================",
                "🔺 هرم درد شاخص‌های نفوذ (David Bianco's Pyramid of Pain)",
                "================================================================================",
                "\n[لایه ۶ - بسیار دشوار برای مهاجم] TTPs (رفتارها و تکنیک‌های MITRE ATT&CK):",
                *(f"  • {x}" for x in (pop["ttps"] or ["موردی ثبت نشد."])),
                "\n[لایه ۵ - چالش‌برانگیز] Tools (ابزارهای تهاجمی و Exploit Kitهای شناسایی‌شده):",
                *(f"  • {x}" for x in (pop["tools"] or ["موردی ثبت نشد."])),
                "\n[لایه ۴ - آزاردهنده] Network / Host Artifacts (آرتیفکت‌های شبکه، URIها و اطلاعات هویتی):",
                *(f"  • {x}" for x in (pop["artifacts"] or ["موردی ثبت نشد."])),
                "\n[لایه ۳ - ساده] Domain Names (دامنه‌های مشکوک / Gateها / DNS Tunnel / DGA):",
                *(f"  • {x}" for x in (pop["domains"] or ["موردی ثبت نشد."])),
                "\n[لایه ۲ - آسان] IP Addresses (آدرس‌های IP سرور اکسپلویت، مهاجم، اسکنر و C2):",
                *(f"  • {x}" for x in (pop["ips"] or ["موردی ثبت نشد."])),
                "\n[لایه ۱ - پیش‌پاافتاده] Hash Values (هش فایل‌های استخراج‌شده SHA-256 و هش‌های JA3 TLS):",
                *(f"  • {x}" for x in (pop["hashes"] or ["موردی ثبت نشد."])),
                "\n================================================================================",
                "💎 مدل الماس تحلیل نفوذ (Diamond Model of Intrusion Analysis)",
                "================================================================================",
                f"\n👤 مهاجم (Adversary):        {', '.join(dm['adversary'])}",
                f"⚔️ قابلیت و ابزار (Capability): {', '.join(dm['capability'])}",
                f"🌐 زیرساخت (Infrastructure): {', '.join(dm['infrastructure'])}",
                f"🎯 قربانی (Victim):          {', '.join(dm['victim'])}",
            ]
            self.txt_frameworks.insert("end", "\n".join(lines))

        def _populate_arsenal_tab(self, ars):
            self.txt_arsenal.delete("1.0", "end")
            lines = [
                "================================================================================",
                "🦈 ۱. فیلترهای آماده Wireshark / TShark جهت بررسی دقیق بسته‌ها",
                "================================================================================",
                ars["wireshark"],
                "\n================================================================================",
                "🛡️ ۲. قوانین آماده Suricata / Snort IDS/IPS جهت مسدودسازی و هشدار",
                "================================================================================",
                ars["suricata"],
                "\n================================================================================",
                "🧬 ۳. قانون خودکار YARA (به سبک YaraGen / Loki) جهت اسکن فایل و حافظه",
                "================================================================================",
                ars["yara"],
                "\n================================================================================",
                "🔎 ۴. کوئری شکار تهدید در Splunk (SPL)",
                "================================================================================",
                ars["splunk_spl"],
                "\n================================================================================",
                "🔎 ۵. کوئری شکار تهدید در Elastic SIEM / Kibana (KQL)",
                "================================================================================",
                ars["elastic_kql"],
            ]
            self.txt_arsenal.insert("end", "\n".join(lines))

        def _populate_stats_tab(self, st):
            self.txt_stats.delete("1.0", "end")
            lines = [
                "================================================================================",
                "📦 فایل‌های باینری و اکسپلویت‌های استخراج‌شده از جریان TCP (Carved Payloads)",
                "================================================================================",
                *(
                    f"  • بسته #{c['pkt']} | {c['type']} | حجم: {c['size']} | Entropy: {c['entropy']}\n"
                    f"    SHA256: {c['sha256']}\n"
                    f"    مسیر ذخیره: {c.get('path') or '-'}"
                    for c in st["carved_files"]
                ),
                *(["  فایل اجرایی (PE/ELF/SWF/Macro) در ترافیک مشاهده نشد."] if not st["carved_files"] else []),
                "\n================================================================================",
                "🔀 زنجیره تغییر مسیرهای HTTP (301/302 Redirects & Gates)",
                "================================================================================",
                *(f"  • {r}" for r in (st.get("http_redirects") or ["تغییر مسیر 301/302 ثبت نشد."])),
                "\n================================================================================",
                "🔐 اثرانگشت‌های استخراج‌شده TLS (JA3 Client & JA3S Server Fingerprints)",
                "================================================================================",
                *(
                    f"  JA3: {j['hash']} | تعداد: {j['count']:<5} | تشخیص: {j['known']:<35} | {j['info']}"
                    for j in (st["ja3_fingerprints"] or [{"hash": "-", "count": 0, "known": "ترافیک TLS دیده نشد", "info": ""}])
                ),
                *(
                    f"  JA3S (Server): {js['hash']} | تعداد: {js['count']:<5} | تشخیص: {js['known']}"
                    for js in st.get("ja3s_fingerprints", [])
                ),
                "\n================================================================================",
                "🌐 توزیع پروتکل‌ها و برترین ارتباطات (Top Talkers)",
                "================================================================================",
                *(f"  {k:<14} : {v:,}" for k, v in st["protocols"].items()),
                "-" * 60,
                *(
                    f"  {t['src']:<18} → {t['dst']:<18} {('(' + t['dst_domain'] + ')') if t.get('dst_domain') else '':<26} | {human_bytes(t['bytes']):<12} ({t['packets']:,} pkts)"
                    for t in st["top_talkers"]
                ),
            ]
            if st.get("tshark_phs"):
                lines.append("\n================================================================================")
                lines.append("🦈 خروجی سلسله‌مراتب پروتکل‌ها از موتور TShark CLI")
                lines.append("================================================================================")
                lines.extend(st["tshark_phs"])
            self.txt_stats.insert("end", "\n".join(lines))

        def export_and_open_html(self):
            if self.last_html_path and os.path.isfile(self.last_html_path):
                webbrowser.open(Path(self.last_html_path).resolve().as_uri())
            else:
                messagebox.showwarning("گزارش موجود نیست", "فایل گزارش HTML یافت نشد؛ تحلیل را دوباره اجرا کنید.")

        def export_json(self):
            if not self.last_stats:
                return
            path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON", "*.json")])
            if path:
                try:
                    with open(path, "w", encoding="utf-8") as fh:
                        json.dump({"stats": _strip_heavy(self.last_stats), "findings": self.last_findings,
                                   "correlation": self.last_corr}, fh, ensure_ascii=False, indent=2, default=str)
                    messagebox.showinfo("ذخیره شد", f"گزارش JSON ذخیره شد:\n{path}")
                except OSError as e:
                    messagebox.showerror("خطا در ذخیره", str(e))

        def export_ioc(self):
            if not self.last_corr:
                return
            path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text", "*.txt")])
            if not path:
                return
            c = self.last_corr
            ioc, ars = c["iocs"], c["detection_arsenal"]
            lines = ["# PCAP Analyzer v8.0 — IOC & Detection Rules", f"# Generated: {dt.datetime.now():%Y-%m-%d %H:%M:%S}", ""]
            for title, key in (("IP Addresses", "ips"), ("Domains", "domains"), ("User-Agents", "user_agents"),
                               ("Hashes (SHA256 / JA3)", "hashes"), ("Credentials (masked)", "credentials")):
                lines.append(f"## {title}")
                lines.extend(f"  {x}" for x in (ioc.get(key) or ["-"]))
                lines.append("")
            for title, key in (("Wireshark Filters", "wireshark"), ("Suricata / Snort Rules", "suricata"),
                               ("YARA Rule", "yara"), ("Splunk SPL", "splunk_spl"), ("Elastic KQL", "elastic_kql")):
                lines += [f"## {title}", ars[key], ""]
            try:
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write("\n".join(lines))
                messagebox.showinfo("ذخیره شد", f"فایل IOC و قوانین ذخیره شد:\n{path}")
            except OSError as e:
                messagebox.showerror("خطا در ذخیره", str(e))

        def export_csv(self):
            if not self.last_findings:
                return
            path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")])
            if path:
                try:
                    with open(path, "w", encoding="utf-8-sig", newline="") as fh:
                        w = csv.writer(fh)
                        w.writerow(["Severity", "Title", "KillChain", "MITRE_ATTACK", "MITRE_D3FEND", "MITRE_CAR",
                                    "Pyramid_Tier", "Count", "FirstSeen", "Actors", "Targets"])
                        for f in self.last_findings:
                            w.writerow([f["severity"], f["title"], f["kill_chain"], f["mitre"], f["d3fend"], f["car"],
                                        f["pyramid"], f["count"], f["first_ts"],
                                        " | ".join(f["actors"]), " | ".join(f["targets"])])
                    messagebox.showinfo("ذخیره شد", f"فایل CSV ذخیره شد:\n{path}")
                except OSError as e:
                    messagebox.showerror("خطا در ذخیره", str(e))


# ============================================================================
# ۸. خط فرمان (CLI) برای ویندوز / مک / لینوکس + ابزارهای کمکی (--doctor / --restore)
# ============================================================================
def _ask_cli(title, text):
    print("\n" + "=" * 70 + f"\n{title}\n" + "=" * 70 + f"\n{text}")
    if not sys.stdin or not sys.stdin.isatty():
        print("(ورودی تعاملی نیست؛ پاسخ پیش‌فرض: نه)")
        return False
    return input("[y/N] > ").strip().lower() in ("y", "yes", "بله", "آره")


def run_doctor():
    print(f"🩺 بررسی محیط — {META.APP_NAME} v{META.VERSION} | سیستم‌عامل: {SYSTEM} | Python {sys.version.split()[0]}")
    print(f"  author       : {META.AUTHOR} — {META.REPO_URL}")
    print(f"  scapy        : {'✅' if HAS_SCAPY else '➖ اختیاری (پکت‌خوان بومی فعال است)'}")
    print(f"  fast reader  : ✅ pcap_fastio (pcap/pcapng، Ethernet/VLAN/SLL/Raw)")
    print(f"  brotli       : {'✅' if HAS_BROTLI else '➖ اختیاری (pip install brotli)'}")
    print(f"  pyzipper     : {'✅ ZIP رمزدار AES' if HAS_PYZIPPER else '➖ اختیاری؛ بدون آن از حالت xor استفاده می‌شود'}")
    print(f"  tkinter (GUI): {'✅' if HAS_TK else '➖ نصب نیست؛ فقط CLI'}")
    print(f"  tshark       : {'✅ ' + str(find_tshark_binary()) if find_tshark_binary() else '➖ اختیاری'}")
    print(f"  دسترسی مدیر  : {'بله' if is_admin() else 'خیر (لازم نیست)'}")
    if IS_WINDOWS:
        st = defender_status()
        print(f"  Defender     : {st if st else 'در دسترس نیست / آنتی‌ویروس دیگر'}")
    for line in platform_notes():
        print("  " + line)


def run_cli_mode(args):
    global DEFANG_REPORT
    target = args.file
    if not target or not os.path.isfile(target):
        print(f"[!] فایل ورودی یافت نشد: {target}", file=sys.stderr)
        sys.exit(1)
    DEFANG_REPORT = not args.no_defang

    cfg = EngineConfig()
    cfg.max_packets = args.max_packets
    cfg.mask_passwords = not args.unmask
    cfg.ioc_file = args.ioc_file
    cfg.sample_mode = args.sample_mode
    cfg.out_dir = prepare_output_dir(args.out or default_out_dir(target))
    cfg.fast_io = not args.no_fast
    cfg.extract_files = not args.no_extract
    cfg.extract_scope = args.extract_scope
    cfg.zip_password = args.zip_password
    cfg.max_extract_mb = args.max_extract_mb
    cfg.max_stream_bytes = args.max_stream_mb * 1024 * 1024
    cfg.max_total_stream_bytes = args.max_mem_mb * 1024 * 1024
    saved = THEMES.load_config()
    theme = args.theme or saved.get("theme") or THEMES.DEFAULT_THEME
    material = args.material or saved.get("material") or THEMES.DEFAULT_MATERIAL
    if theme not in THEMES.THEMES:
        print(f"[!] تم ناشناخته «{theme}» — از neon-night استفاده شد. فهرست: --list-themes", file=sys.stderr)
        theme = THEMES.DEFAULT_THEME
    if material not in THEMES.MATERIALS:
        material = THEMES.DEFAULT_MATERIAL
    formats = tuple(x.strip() for x in args.formats.split(",") if x.strip())

    print("=" * 78)
    print(f"🛡️  {META.APP_NAME} v{META.VERSION} — تحلیل آفلاین (CLI)")
    print(f"    by {META.AUTHOR} · {META.REPO_URL}")
    print(f"[*] فایل هدف : {target}")
    print(f"[*] پوشه خروجی: {cfg.out_dir}")
    print("=" * 78)
    if cfg.sample_mode != "raw":
        for line in platform_notes():
            print(line)

    added_exclusion = False
    if cfg.sample_mode == "raw":
        print("⚠️ حالت raw: نمونه‌های مخرب به‌صورت خام ذخیره می‌شوند.")
        ask = (lambda t, x: True) if args.allow_defender_exclusion else _ask_cli
        added_exclusion = request_defender_exclusion(cfg.out_dir, ask, log=print)
    elif args.allow_defender_exclusion:
        print("ℹ️ در حالت امن (zip/xor) استثنای Defender لازم نیست؛ نادیده گرفته شد.")

    analyzer = PcapAnalyzer(cfg)
    if args.ioc_file:
        print(f"[*] فهرست IOC شخصی: {getattr(analyzer, 'feed_loaded', 0)} مورد بارگذاری شد")
    t0 = time.time()
    analyzer.run(target)
    st = analyzer.stats()
    findings = analyzer.findings()
    corr = analyzer.correlate_offline()
    elapsed = time.time() - t0

    files = write_all_reports(target, cfg.out_dir, st, findings, corr, DEFANG_REPORT,
                              style=args.report_style, theme=theme, material=material, formats=formats)
    sample_paths = [c["path"] for c in st["carved_files"] if c.get("path")]
    fsum = (st.get("hub") or {}).get("files_summary") or {}
    if fsum.get("zip_abs"):
        sample_paths.append(fsum["zip_abs"])
    missing = verify_files(files + sample_paths, wait=1.5 if (files or sample_paths) else 0)
    if not args.no_bundle:
        b = bundle_reports(cfg.out_dir, files)
        if b:
            files.append(b)

    rate = int(st['packets'] / max(elapsed, 0.001))
    print(f"[+] زمان: {elapsed:.2f}s ({rate:,} بسته/ثانیه · موتور {'بومی سریع' if st['engine']['fast_io'] else 'scapy'}) | بسته‌ها: {st['packets']:,} | جریان‌های بازسازی‌شده: {st['reassembled_streams']:,}")
    hub = st.get("hub") or {}
    print("[+] پروتکل‌ها: " + " · ".join(f"{p['name']}({p['flows']})" for p in hub.get("protocols", [])[:12]))
    if fsum.get("count"):
        print(f"[+] فایل‌های استخراج‌شده: {fsum['count']} ({human_bytes(fsum['bytes'])}) → {fsum['zip_abs']}"
              + (f"  [رمز: {fsum['password']}]" if fsum.get("password") else "  [بدون رمز؛ فایل‌های خطرناک *.sample]"))
        for r in (hub.get("files") or [])[:40]:
            print(f"    • {'⚠' if r['risky'] else ' '} {r['proto']:<5} {r['name']}  ({human_bytes(r['size'])}, {r['type']})  ← {r.get('host') or r.get('src') or ''}")
    print(f"[+] امتیاز ریسک: {corr['risk_score']}/100 ({SEV_FA[corr['risk_level']]}) | هشدارها: {len(findings)}")
    print("-" * 78)
    for f in findings:
        what = plain_text(f)[0]
        print(f"  [{f['severity'].upper():<8}] {f['title']} (x{f['count']}) | {f['mitre']}")
        print(f"             ↳ {what}")
    if st["carved_files"]:
        print("-" * 78)
        print(f"[+] نمونه‌های استخراج‌شده ({len(st['carved_files'])}) — حالت ذخیره: {st.get('sample_mode')}")
        for c in st["carved_files"]:
            print(f"  • {c['type']} | {c['size']} | SHA256: {c['sha256']}")
    print("-" * 78)
    if missing:
        print(f"⚠️ {len(missing)} فایل بلافاصله پس از ذخیره ناپدید شد (احتمالاً آنتی‌ویروس):")
        for m in missing:
            print("   ✗", m)
        print("   راه‌حل: --sample-mode zip (پیش‌فرض) یا در ویندوز: --sample-mode raw --allow-defender-exclusion")
    else:
        print(f"[✔] همه خروجی‌ها سالم ذخیره شدند → {cfg.out_dir}")

    if added_exclusion and not args.keep_exclusion:
        ok, msg = remove_defender_exclusion(cfg.out_dir)
        print(("🧹 استثنای Defender برداشته شد." if ok else f"⚠️ برداشتن استثنا ناموفق: {msg}  (بعداً: --cleanup-exclusions)"))
    elif added_exclusion:
        print("ℹ️ استثنا فعال ماند. برداشتن: python pcap_analyzer.py --cleanup-exclusions")


def _fix_frozen_windows_console():
    """Windowed (no-console) Windows builds: re-attach to the parent terminal so --cli/--doctor print."""
    if os.name != "nt" or not getattr(sys, "frozen", False):
        return
    try:
        import ctypes
        if sys.stdout is None or sys.stderr is None:
            wants_console = any(a in sys.argv for a in ("--cli", "--doctor", "--help", "-h", "--restore",
                                                        "--cleanup-exclusions", "--version"))
            if wants_console and ctypes.windll.kernel32.AttachConsole(-1):
                sys.stdout = open("CONOUT$", "w", encoding="utf-8", buffering=1)
                sys.stderr = open("CONOUT$", "w", encoding="utf-8", buffering=1)
                sys.stdin = open("CONIN$", "r", encoding="utf-8")
            else:
                sys.stdout = sys.stdout or open(os.devnull, "w")
                sys.stderr = sys.stderr or open(os.devnull, "w")
    except Exception:
        pass


def main():
    _fix_frozen_windows_console()
    parser = argparse.ArgumentParser(
        description=f"{META.APP_NAME} v{META.VERSION} — تحلیلگر آفلاین PCAP و لاگ (ویندوز / مک / لینوکس) · {META.REPO_URL}",
        epilog=f"Made by {META.AUTHOR} · {META.GITHUB_PROFILE} · Releases: {META.RELEASES_URL}",
    )
    parser.add_argument("--version", action="version", version=f"{META.APP_NAME} {META.VERSION}")
    parser.add_argument("file", nargs="?", help="مسیر فایل PCAP / PCAPNG / LOG / JSON")
    parser.add_argument("--cli", action="store_true", help="اجرای خودکار در ترمینال بدون رابط گرافیکی")
    parser.add_argument("-o", "--out", help="پوشه اختصاصی خروجی (پیش‌فرض: ~/PCAP_Analyzer_Reports/...)")
    parser.add_argument("--max-packets", type=int, default=0, help="حداکثر تعداد بسته (0 = همه)")
    parser.add_argument("--unmask", action="store_true", help="عدم ماسک رمزهای عبور در گزارش")
    parser.add_argument("--sample-mode", choices=["auto", "zip", "xor", "raw"], default="auto",
                        help="ذخیره نمونه‌های مخرب: auto/zip (رمزدار، امن) | xor (ظرف خنثی) | raw (خام، خطرناک)")
    parser.add_argument("--allow-defender-exclusion", action="store_true",
                        help="[ویندوز، فقط با raw] اجازه می‌دهم پوشه خروجی به استثناهای Defender اضافه شود (UAC لازم است)")
    parser.add_argument("--keep-exclusion", action="store_true", help="استثنای Defender پس از پایان برداشته نشود")
    parser.add_argument("--cleanup-exclusions", action="store_true", help="همه استثناهای اضافه‌شده توسط این برنامه را بردار")
    parser.add_argument("--restore", metavar="FILE.sample", help="بازیابی نمونه‌ی حالت xor (فقط در محیط ایزوله!)")
    parser.add_argument("--ioc-file", help="فهرست IOC شخصی (IP/دامنه/URL/هش، هر خط یکی) برای تطبیق آفلاین")
    parser.add_argument("--no-defang", action="store_true", help="IOCها بدون بی‌خطرسازی نوشته شوند")
    parser.add_argument("--no-bundle", action="store_true", help="ZIP یکپارچه گزارش‌ها ساخته نشود")
    parser.add_argument("--doctor", action="store_true", help="بررسی سلامت محیط و وابستگی‌ها")
    parser.add_argument("--theme", help="تم گزارش/رابط (neon-night, matrix, synthwave, crimson-ops, amber-terminal, ice-circuit, toxic-lime, paper-light)")
    parser.add_argument("--material", choices=list(THEMES.MATERIALS), help="جنس پنل‌ها: glass | solid | hologram | terminal")
    parser.add_argument("--report-style", choices=["cyber", "classic", "both"], default="cyber", help="قالب گزارش HTML")
    parser.add_argument("--formats", default="html,json,csv,rules,iocs", help="خروجی‌های دلخواه، جداشده با کاما: html,json,csv,rules,iocs")
    parser.add_argument("--list-themes", action="store_true", help="نمایش فهرست تم‌ها و خروج")
    parser.add_argument("--no-extract", action="store_true", help="فایل‌های منتقل‌شده استخراج و ZIP نشوند")
    parser.add_argument("--extract-scope", choices=["all", "downloads"], default="all", help="all: همه‌چیز · downloads: بدون HTML/JS/CSS/JSON وب")
    parser.add_argument("--zip-password", default="infected", help="رمز ZIP فایل‌های استخراج‌شده (با pyzipper)")
    parser.add_argument("--max-extract-mb", type=int, default=1024, help="سقف حجم کل فایل‌های استخراج‌شده (MB)")
    parser.add_argument("--max-stream-mb", type=int, default=64, help="سقف هر جهت جریان TCP برای بازسازی (MB)")
    parser.add_argument("--max-mem-mb", type=int, default=1536, help="سقف کل حافظه بازسازی جریان‌ها (MB)")
    parser.add_argument("--lang", choices=["en", "fa"], default=None, help="Interface language: en (default) or fa / زبان رابط")
    parser.add_argument("--no-fast", action="store_true", help="غیرفعال‌سازی پکت‌خوان بومی (استفاده از scapy)")
    for _a in parser._actions:                      # translate --help texts
        if _a.help:
            _a.help = I18N.tr(_a.help)
    parser.description = I18N.tr(parser.description)
    args = parser.parse_args()
    if args.lang:
        I18N.set_lang(args.lang)
    if I18N.get_lang() != "fa" and not args.cli:
        I18N.install_tk_hooks()

    if args.list_themes:
        for tid, t in THEMES.THEMES.items():
            print(f"  {tid:<16} {t['name']:<16} {t['fa']}")
        print("materials:", ", ".join(THEMES.MATERIALS))
        return
    if args.doctor:
        run_doctor()
        return
    if args.cleanup_exclusions:
        res = cleanup_all_exclusions()
        for p, ok, msg in res or []:
            print(("✅" if ok else "❌"), p, "-", msg)
        if not res:
            print("استثنای ثبت‌شده‌ای وجود ندارد.")
        return
    if args.restore:
        print("⚠️ فقط در ماشین مجازی/Sandbox ادامه دهید. خروجی:", restore_sample(args.restore))
        return

    if args.cli or not HAS_TK:
        if not args.file:
            parser.print_help()
            sys.exit(1)
        run_cli_mode(args)
        return

    if os.name == "nt":
        try:
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass
    app = PcapAnalyzerApp(args.file)
    app.mainloop()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception:
        err = traceback.format_exc()
        if HAS_TK:
            try:
                messagebox.showerror("خطای غیرمنتظره", err[-1800:])
            except Exception:
                print(err)
        else:
            print(err)
