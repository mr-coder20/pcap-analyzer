# -*- coding: utf-8 -*-
"""
pcap_extra_detect — تشخیص‌های جدید نسخه ۶ (کاملاً آفلاین)
قوانین: سوءاستفاده از سرویس‌های عمومی به‌عنوان C2، ماینر، LLMNR/NBNS Poisoning، PsExec،
نشت با POST حجیم، DoH، دانلود اسکریپت/میان‌بر، و تطبیق با فهرست IOC شخصی (بدون اینترنت).
"""
import re

EXTRA_RULES = {
    "c2_service_abuse": {
        "sev": "high", "cat": "فرماندهی و کنترل (C2)", "kill_chain": "Command & Control", "pyramid": "Domain Names",
        "mitre": "T1102", "d3fend": "D3-OTF (Outbound Filtering)", "car": "CAR-2014-11-002",
        "title": "سوءاستفاده از سرویس‌های عمومی به‌عنوان کانال C2 / نشت داده (ngrok، Discord، Telegram، Pastebin ...)",
        "desc": "ارتباط با سرویس‌های ابری/پیام‌رسان/تونل که مهاجمان برای کنترل از راه دور یا خروج داده سوءاستفاده می‌کنند.",
        "rec": "منشأ اتصال را شناسایی کنید؛ اگر استفاده مجاز نبود دامنه را مسدود و میزبان را بررسی کنید."
    },
    "crypto_miner": {
        "sev": "high", "cat": "تأثیر (Impact)", "kill_chain": "Actions on Objectives", "pyramid": "Tools",
        "mitre": "T1496", "d3fend": "D3-NTA", "car": "CAR-2020-05-003",
        "title": "فعالیت استخراج ارز دیجیتال (Stratum / XMRig)",
        "desc": "پروتکل Stratum یا امضای XMRig در ترافیک دیده شد؛ نشانه Cryptojacking.",
        "rec": "فرایند ماینر را پیدا و حذف کنید و مسیر ورود اولیه (آسیب‌پذیری/دانلود) را ببندید."
    },
    "llmnr_poison": {
        "sev": "high", "cat": "دسترسی به اعتبارنامه (Credential Access)", "kill_chain": "Exploitation", "pyramid": "Tools",
        "mitre": "T1557.001", "d3fend": "D3-NTF", "car": "CAR-2020-11-004",
        "title": "مسموم‌سازی LLMNR / NBT-NS / mDNS (Responder)",
        "desc": "یک میزبان به چندین پرسش نام‌یابی پخشی پاسخ می‌دهد؛ رفتار ابزارهایی مثل Responder برای سرقت هش NTLM.",
        "rec": "LLMNR و NBT-NS را با GPO غیرفعال و SMB Signing را اجباری کنید؛ میزبان پاسخ‌دهنده را بررسی کنید."
    },
    "smb_psexec": {
        "sev": "critical", "cat": "حرکت جانبی (Lateral Movement)", "kill_chain": "Installation", "pyramid": "Tools",
        "mitre": "T1569.002", "d3fend": "D3-NTF", "car": "CAR-2013-09-005",
        "title": "اجرای سرویس از راه دور روی SMB (PsExec / svcctl / atsvc)",
        "desc": "نام سرویس PSEXESVC یا پایپ‌های مدیریت سرویس/زمان‌بند روی SMB مشاهده شد؛ تکنیک رایج حرکت جانبی.",
        "rec": "حساب مدیر استفاده‌شده را بررسی و رمزش را عوض کنید؛ رویدادهای 7045 و 4697 را در مقصد ببینید."
    },
    "http_big_post": {
        "sev": "high", "cat": "نشت داده (Exfiltration)", "kill_chain": "Actions on Objectives", "pyramid": "Network Artifacts",
        "mitre": "T1048.003", "d3fend": "D3-OTF", "car": "CAR-2013-05-002",
        "title": "ارسال حجم زیاد داده با HTTP POST به آدرس عمومی",
        "desc": "درخواست POST با Content-Length بالا به مقصد خارج از شبکه داخلی مشاهده شد.",
        "rec": "مقصد و محتوا را بررسی و در صورت نشت، دسترسی را مسدود کنید."
    },
    "doh_bypass": {
        "sev": "medium", "cat": "فرار از دفاع (Defense Evasion)", "kill_chain": "Command & Control", "pyramid": "Domain Names",
        "mitre": "T1572", "d3fend": "D3-DNSDL", "car": "CAR-2014-11-002",
        "title": "استفاده از DNS-over-HTTPS بیرون از DNS سازمانی",
        "desc": "اتصال به ارائه‌دهندگان عمومی DoH که کنترل و ثبت DNS سازمان را دور می‌زند.",
        "rec": "اگر سیاست سازمان اجازه نمی‌دهد، دامنه‌های DoH را مسدود و DNS داخلی را اجباری کنید."
    },
    "script_download": {
        "sev": "medium", "cat": "تحویل بدافزار (Delivery)", "kill_chain": "Delivery", "pyramid": "Host Artifacts",
        "mitre": "T1105", "d3fend": "D3-FA", "car": "CAR-2013-05-004",
        "title": "دانلود فایل اسکریپت / میان‌بر / ایمیج (ps1, vbs, hta, lnk, js, iso ...) روی HTTP",
        "desc": "پسوندهای رایج مرحله اول آلودگی در یک درخواست GET دیده شد.",
        "rec": "فایل و منبع را بررسی کنید و اجرای اسکریپت‌ها را با AppLocker/WDAC محدود کنید."
    },
    "ioc_feed_match": {
        "sev": "critical", "cat": "تطبیق اطلاعات تهدید (Threat Intel)", "kill_chain": "Command & Control", "pyramid": "Hash Values",
        "mitre": "T1071", "d3fend": "D3-NTA", "car": "CAR-2014-11-002",
        "title": "تطبیق با فهرست IOC شخصی شما (--ioc-file)",
        "desc": "یک IP، دامنه، URL یا هش از فهرست خودتان در این داده پیدا شد.",
        "rec": "بر اساس رویه پاسخ به رخداد سازمان اقدام کنید و دستگاه‌های درگیر را ایزوله نمایید."
    },
}

C2_SERVICES = (
    "ngrok.io", "ngrok-free.app", "ngrok.app", "trycloudflare.com", "serveo.net", "localtunnel.me", "loca.lt",
    "pastebin.com", "paste.ee", "hastebin.com", "ghostbin", "transfer.sh", "anonfiles.com", "gofile.io",
    "discord.com/api/webhooks", "discordapp.com/api/webhooks", "cdn.discordapp.com", "api.telegram.org",
    "duckdns.org", "ddns.net", "hopto.org", "no-ip.com", "zapto.org", "serveousercontent.com",
    "webhook.site", "requestbin", "pipedream.net", "interact.sh", "oast.pro", "oast.live", "burpcollaborator.net",
)
DOH_HOSTS = (
    "dns.google", "cloudflare-dns.com", "mozilla.cloudflare-dns.com", "dns.quad9.net", "doh.opendns.com",
    "dns.nextdns.io", "doh.dns.sb", "dns.adguard.com", "doh.cleanbrowsing.org",
)
SCRIPT_EXT = (".ps1", ".vbs", ".vbe", ".hta", ".lnk", ".js", ".jse", ".wsf", ".bat", ".cmd", ".iso", ".img", ".scr", ".msi", ".jar")
RE_MINER = re.compile(rb'(mining\.(subscribe|authorize)|"method"\s*:\s*"(login|mining\.[a-z_]+)"|stratum\+(tcp|ssl)|xmrig|cpuminer)', re.I)
RE_CLEN = re.compile(rb"content-length:\s*(\d+)", re.I)
PSEXEC_MARKERS = (b"PSEXESVC", b"P\x00S\x00E\x00X\x00E\x00S\x00V\x00C\x00", b"s\x00v\x00c\x00c\x00t\x00l\x00",
                  b"a\x00t\x00s\x00v\x00c\x00", b"\\pipe\\svcctl", b"\\pipe\\atsvc")


def _priv(ip):
    import ipaddress
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_loopback or a.is_link_local or a.is_multicast
    except ValueError:
        return True


class ExtraDetectMixin:
    """به کلاس PcapAnalyzer اضافه می‌شود (فراخوانی از hookهای موتور اصلی)."""

    def _init_extra(self):
        self.llmnr_replies = {}          # src -> set(names)
        self.ioc_feed = {"ips": set(), "domains": set(), "hashes": set(), "urls": set()}
        self.feed_hits = 0
        self._svc_seen = set()
        path = getattr(self.cfg, "ioc_file", None)
        if path:
            self.load_ioc_feed(path)

    # ---------- فهرست IOC شخصی (آفلاین) ----------
    def load_ioc_feed(self, path):
        n = 0
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                for raw in fh:
                    v = raw.strip().lower().replace("[.]", ".").replace("hxxp", "http")
                    if not v or v.startswith("#"):
                        continue
                    if re.fullmatch(r"[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}", v):
                        self.ioc_feed["hashes"].add(v)
                    elif re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", v):
                        self.ioc_feed["ips"].add(v)
                    elif v.startswith("http"):
                        self.ioc_feed["urls"].add(v)
                    else:
                        self.ioc_feed["domains"].add(v.lstrip("*."))
                    n += 1
        except OSError as e:
            self.read_error = f"خواندن فایل IOC ممکن نشد: {e}"
        self.feed_loaded = n

    def _feed_domain(self, name):
        name = name.lower().rstrip(".")
        parts = name.split(".")
        return any(".".join(parts[i:]) in self.ioc_feed["domains"] for i in range(len(parts) - 1))

    def feed_check_ip(self, n, ts, src, dst):
        f = self.ioc_feed["ips"]
        if not f:
            return
        for ip, other in ((dst, src), (src, dst)):
            if ip in f and (ip, other) not in self._svc_seen:
                self._svc_seen.add((ip, other))
                self.hit("ioc_feed_match", n, ts, f"{src} ↔ {dst}  [IP در فهرست IOC: {ip}]", src, dst, artifact=f"IOC-IP:{ip}")

    def feed_check_name(self, n, ts, src, dst, name, where):
        if self.ioc_feed["domains"] and name and self._feed_domain(name):
            self.hit("ioc_feed_match", n, ts, f"{src} → {name}  [{where} در فهرست IOC]", src, dst, artifact=f"IOC-DOM:{name}")

    # ---------- نام (DNS/SNI/Host) ----------
    def extra_name(self, n, ts, src, dst, name, where):
        name = (name or "").lower().rstrip(".")
        if not name:
            return
        self.feed_check_name(n, ts, src, dst, name, where)
        for s in C2_SERVICES:
            if "/" not in s and (name == s or name.endswith("." + s)):
                key = (src, s)
                if key not in self._svc_seen:
                    self._svc_seen.add(key)
                    self.ioc_domains.add(name)
                    self.hit("c2_service_abuse", n, ts, f"{src} → {name} ({where})", src, dst, artifact=name)
                break
        for d in DOH_HOSTS:
            if name == d or name.endswith("." + d):
                if (src, d) not in self._svc_seen:
                    self._svc_seen.add((src, d))
                    self.hit("doh_bypass", n, ts, f"{src} → {name} ({where})", src, dst, artifact=name)
                break

    # ---------- UDP: LLMNR / NBNS ----------
    def extra_udp(self, n, ts, src, dst, u):
        try:
            sp, dp = u.sport, u.dport
        except Exception:
            return
        if sp in (5355, 137):                                     # پاسخ LLMNR یا NBNS
            raw = bytes(u.payload)
            if len(raw) >= 12 and raw[2] & 0x80:                 # بیت QR=1 یعنی پاسخ
                names = self.llmnr_replies.setdefault(src, set())
                names.add(raw[12:40])
                if len(names) == 3:
                    self.hit("llmnr_poison", n, ts, f"{src} به ≥۳ پرسش پخشی پاسخ داد (پورت {sp})",
                             src, dst, tool_name="Responder / LLMNR-NBNS Poisoner", artifact=f"LLMNR/{sp}")

    # ---------- TCP payload ----------
    def extra_tcp(self, n, ts, src, dst, sp, dp, p, flow):
        if RE_MINER.search(p[:600]) and dp not in (443,):
            self.hit("crypto_miner", n, ts, f"{flow}  [Stratum/XMRig]", src, dst, tool_name="XMRig / Stratum Miner", artifact="Stratum")
        if (dp in (445, 139) or sp in (445, 139)) and any(m in p[:4096] for m in PSEXEC_MARKERS):
            self.hit("smb_psexec", n, ts, f"{flow}  [PsExec/svcctl marker]", src, dst, tool_name="PsExec", artifact="PSEXESVC")
        if p[:5] in (b"POST ", b"GET /") or p[:4] == b"GET ":
            head = p[:1500]
            m_host = re.search(rb"\r\nhost:\s*([^\r\n:]+)", head, re.I)
            if m_host:
                self.extra_name(n, ts, src, dst, m_host.group(1).decode("latin-1", "ignore"), "HTTP Host")
            if p[:5] == b"POST ":
                m = RE_CLEN.search(head)
                if m and int(m.group(1)) >= 1_000_000 and not _priv(dst):
                    self.hit("http_big_post", n, ts, f"{flow}  [POST {int(m.group(1)) / 1e6:.1f} MB]", src, dst, artifact="POST>1MB")
            else:
                line = head.split(b"\r\n", 1)[0].decode("latin-1", "ignore")
                parts = line.split(" ")
                if len(parts) >= 2:
                    path = parts[1].split("?", 1)[0].lower()
                    if path.endswith(SCRIPT_EXT):
                        self.hit("script_download", n, ts, f"{flow}  GET {parts[1][:100]}", src, dst, artifact=path.rsplit('/', 1)[-1][:40])
                    for u in self.ioc_feed["urls"]:
                        if m_host and (m_host.group(1).decode("latin-1", "ignore").lower() + parts[1].lower()) in u.replace("http://", "").replace("https://", ""):
                            self.hit("ioc_feed_match", n, ts, f"{flow}  [URL در فهرست IOC]", src, dst, artifact=f"IOC-URL:{u[:60]}")
                            break

    def extra_hash(self, n, ts, flow, sha256, md5, src=None, dst=None):
        if self.ioc_feed["hashes"] and (sha256 in self.ioc_feed["hashes"] or md5 in self.ioc_feed["hashes"]):
            self.hit("ioc_feed_match", n, ts, f"{flow}  [هش فایل در فهرست IOC: {sha256[:16]}…]", src, dst, artifact=f"IOC-HASH:{sha256}")
