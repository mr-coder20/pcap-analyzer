# -*- coding: utf-8 -*-
"""
pcap_threats — Behavioural & content-based threat detection (v8, fully offline)
================================================================================
Runs AFTER the protocol hub has reassembled streams and extracted files, so it can reason about
*what was actually transferred*:

  * infostealer exfiltration over FTP / SMTP / HTTP (AgentTesla, Snake, HawkEye, LokiBot, Raccoon style)
  * credential-dump content inside uploaded files, e-mail attachments and POST bodies
  * loader staging from cloud hosting (GuLoader / Remcos / Formbook delivery via Drive, Discord, GitHub...)
  * IP-geolocation / sandbox-check lookups, dynamic-DNS, Tor, IRC botnets, webhook exfiltration
  * ransom notes, leaked secrets (private keys, API tokens, card numbers), Office macros, disguised executables
  * multi-stage *infection chain* correlation per victim host

Every rule is bilingual (English default + Persian).  Nothing here touches the network.
"""
from __future__ import annotations

import ipaddress
import re
from collections import defaultdict

# --------------------------------------------------------------------------------------------------
#  Rules  (fa = Persian fields, en = English fields)
# --------------------------------------------------------------------------------------------------


def _r(sev, mitre, kc, pyr, d3, car, fa, en):
    return {"sev": sev, "mitre": mitre, "kill_chain": kc, "pyramid": pyr, "d3fend": d3, "car": car,
            "cat": fa[0], "title": fa[1], "desc": fa[2], "rec": fa[3],
            "en": {"cat": en[0], "title": en[1], "desc": en[2], "rec": en[3]}}


THREAT_RULES = {
    "infection_chain": _r(
        "critical", "T1204", "Installation", "TTPs", "D3-PSA", "CAR-2020-09-001",
        ("زنجیره آلودگی", "زنجیره آلودگی چندمرحله‌ای بدافزار (لودر ← سرقت اطلاعات ← نشت داده)",
         "یک میزبان داخلی به‌ترتیب: بدافزار/لودر از میزبانی ابری دریافت کرد، IP عمومی خود را جست‌وجو کرد و سپس داده‌ی سرقت‌شده را به بیرون فرستاد. این الگو مشخصه‌ی خانواده‌هایی مثل GuLoader + AgentTesla / Formbook / Snake است.",
         "میزبان را فوراً از شبکه جدا کنید، تمام رمزهای ذخیره‌شده در مرورگر/ایمیل‌کلاینت را تغییر دهید، حافظه و دیسک را بررسی و IOCهای این گزارش را مسدود کنید."),
        ("Infection chain", "Multi-stage malware infection chain (loader → infostealer → exfiltration)",
         "One internal host, in order: pulled a payload from cloud hosting, looked up its own public IP, then sent stolen data out. This is the signature of GuLoader + AgentTesla / Formbook / Snake style campaigns.",
         "Isolate the host immediately, rotate every password saved in browsers / mail clients, image memory and disk, and block the IOCs from this report.")),
    "stealer_ftp_exfil": _r(
        "critical", "T1048.003", "Actions on Objectives", "Tools", "D3-OTF", "CAR-2014-11-002",
        ("نشت داده", "نشت داده‌ی سرقت‌شده از راه FTP به سرور خارجی (الگوی AgentTesla / HawkEye / Snake)",
         "یک کلاینت داخلی با نام‌کاربری/رمز به یک سرور FTP بیرونی وارد شد و فایل آپلود کرد؛ در بدافزارهای سارق اطلاعات (Infostealer) این روش معمول است.",
         "اتصال را قطع کنید، حساب FTP مهاجم را گزارش دهید، فایل‌های آپلودشده را بررسی کنید (در ZIP خروجی هست) تا بدانید چه اطلاعاتی لو رفته و آن‌ها را تغییر دهید."),
        ("Exfiltration", "Stolen data exfiltrated over FTP to an external server (AgentTesla / HawkEye / Snake pattern)",
         "An internal client logged in to an external FTP server and uploaded files — the classic infostealer exfiltration channel.",
         "Cut the connection, report the attacker FTP account, inspect the uploaded files (they are in the output ZIP) to learn what leaked, and rotate those secrets.")),
    "stealer_smtp_exfil": _r(
        "critical", "T1048.003", "Actions on Objectives", "Tools", "D3-OTF", "CAR-2014-11-002",
        ("نشت داده", "نشت داده با ایمیل SMTP توسط بدافزار سارق (AgentTesla / Snake / Formbook)",
         "کلاینت داخلی مستقیماً به یک سرور SMTP بیرونی وصل شد و نامه‌ای با پیوست/لاگ ارسال کرد؛ رفتار نمونه‌ی سارق اطلاعات.",
         "ارتباط SMTP مستقیم از ایستگاه‌ها را مسدود کنید، حساب مقصد را گزارش دهید و محتوای نامه را بررسی کنید."),
        ("Exfiltration", "Stolen data exfiltrated via direct SMTP (AgentTesla / Snake / Formbook)",
         "An internal client connected straight to an external SMTP server and sent a message with attachments/log data — infostealer behaviour.",
         "Block direct outbound SMTP from workstations, report the destination mailbox and review the message content.")),
    "stealer_credentials": _r(
        "critical", "T1555", "Actions on Objectives", "Artifacts", "D3-FA", "CAR-2020-05-001",
        ("دسترسی به اعتبارنامه", "محتوای سرقت رمز عبور / اعتبارنامه ذخیره‌شده در داده‌ی منتقل‌شده",
         "داده‌ی ارسال‌شده شامل فهرست «سایت / نام‌کاربری / رمز» استخراج‌شده از مرورگر یا برنامه‌های ایمیل است (قالب بدافزارهای سارق).",
         "تمام رمزهای فاش‌شده را فوراً تغییر دهید، MFA را فعال کنید و نشست‌های باز را باطل کنید."),
        ("Credential Access", "Stolen credential dump found inside transferred data",
         "The transferred data contains a harvested \"host / username / password\" list from browsers or mail clients (infostealer report format).",
         "Rotate every exposed credential now, enforce MFA and revoke active sessions.")),
    "stealer_family_report": _r(
        "critical", "T1056.001", "Actions on Objectives", "Tools", "D3-FA", "CAR-2020-05-001",
        ("خانواده بدافزار", "گزارش اختصاصی یک خانواده‌ی شناخته‌شده‌ی سارق اطلاعات در داده‌ی منتقل‌شده",
         "قالب متنی/نام فایل با امضای یک خانواده‌ی سارق (مثلاً AgentTesla، Snake Keylogger، HawkEye، LokiBot) مطابقت دارد.",
         "میزبان آلوده را پاک‌سازی/بازسازی کنید و همه‌ی اعتبارنامه‌ها را تغییر دهید."),
        ("Malware family", "Known infostealer family report format found in transferred data",
         "The text layout / file name matches the signature of a known infostealer family (AgentTesla, Snake Keylogger, HawkEye, LokiBot ...).",
         "Rebuild the infected host and rotate all credentials.")),
    "address_book_harvest": _r(
        "high", "T1114", "Actions on Objectives", "Artifacts", "D3-FA", "CAR-2020-05-001",
        ("جمع‌آوری اطلاعات", "سرقت دفترچه‌ی آدرس ایمیل (فهرست حجیم آدرس ایمیل در داده‌ی خروجی)",
         "فایل خروجی فهرستی از ده‌ها آدرس ایمیل دارد؛ بدافزار مخاطبین قربانی را برای هرزنامه/فیشینگ ثانویه جمع کرده است.",
         "به مخاطبین هشدار فیشینگ بدهید و حساب‌های ایمیل را بررسی کنید."),
        ("Collection", "E-mail address-book harvesting (large address list in outbound data)",
         "The outbound file holds dozens of e-mail addresses; malware harvested the victim's contacts for secondary spam / phishing.",
         "Warn the contacts about phishing and review the mail accounts.")),
    "ip_recon_lookup": _r(
        "medium", "T1016", "Reconnaissance", "Domain Names", "D3-OTF", "CAR-2014-11-002",
        ("شناسایی", "جست‌وجوی IP عمومی / موقعیت جغرافیایی (رفتار بدافزار و بررسی Sandbox)",
         "میزبان از سرویس‌های «IP من چیست / ژئولوکیشن» پرسید؛ بدافزار برای شناسایی قربانی یا تشخیص محیط تحلیل/هاستینگ (مثلاً ip-api.com?fields=hosting) این کار را می‌کند.",
         "اگر برنامه‌ی ناشناخته این درخواست را زد، پروسه‌ی مبدأ را بیابید؛ با سایر هشدارهای همین میزبان تطبیق دهید."),
        ("Reconnaissance", "Public-IP / geolocation lookup (malware victim profiling & sandbox check)",
         "The host queried an \"what is my IP\" / geolocation service — used by malware to profile the victim or detect analysis / hosting environments (e.g. ip-api.com?fields=hosting).",
         "Find the originating process if the program is unknown, and correlate with other alerts on the same host.")),
    "cloud_staging": _r(
        "high", "T1105", "Delivery", "Domain Names", "D3-OTF", "CAR-2014-11-002",
        ("تحویل", "دانلود احتمالی بدافزار از میزبانی ابری عمومی (Google Drive / Discord / GitHub / Dropbox / Mega ...)",
         "ارتباط با سرویس‌های اشتراک فایل که لودرهایی مثل GuLoader، Remcos و Formbook پی‌لود رمزشده را از آن‌ها می‌گیرند. اگر کاربر آگاهانه دانلود نکرده باشد، مشکوک است.",
         "منبع اتصال (مرورگر یا پروسه‌ی ناشناس) را بررسی کنید؛ پی‌لودهای دانلودشده در Temp/AppData را بیابید."),
        ("Delivery", "Possible malware staging from public cloud hosting (Google Drive / Discord / GitHub / Dropbox / Mega ...)",
         "Connection to file-sharing services from which loaders such as GuLoader, Remcos or Formbook fetch encrypted payloads. Suspicious if the user did not knowingly download anything.",
         "Identify the connecting process (browser vs unknown binary) and look for dropped payloads in Temp / AppData.")),
    "dyndns_domain": _r(
        "medium", "T1568", "Command & Control", "Domain Names", "D3-OTF", "CAR-2014-11-002",
        ("فرماندهی و کنترل", "استفاده از دامنه‌ی DNS پویا (DuckDNS / No-IP / ddns.net ...)",
         "دامنه‌های DNS پویا ارزان و گمنام‌اند و بدافزارهای RAT برای C2 از آن‌ها استفاده می‌کنند (Remcos، njRAT، AsyncRAT، XWorm).",
         "هدف را بررسی و در صورت نبود نیاز کسب‌وکاری مسدود کنید."),
        ("Command & Control", "Dynamic-DNS domain in use (DuckDNS / No-IP / ddns.net ...)",
         "Dynamic-DNS domains are cheap and anonymous; RATs (Remcos, njRAT, AsyncRAT, XWorm) commonly use them for C2.",
         "Investigate the destination and block it unless there is a business need.")),
    "tor_traffic": _r(
        "medium", "T1090.003", "Command & Control", "Network Artifacts", "D3-OTF", "CAR-2014-11-002",
        ("فرماندهی و کنترل", "نشانه‌ی ترافیک Tor / دامنه‌ی onion",
         "DNS یا SNI مربوط به Tor، .onion یا دروازه‌های tor2web دیده شد؛ می‌تواند فرار از نظارت یا C2 باشد.",
         "اگر Tor در سیاست سازمان مجاز نیست، مسدود و میزبان را بررسی کنید."),
        ("Command & Control", "Tor / .onion traffic indicators",
         "DNS or SNI for Tor, .onion or tor2web gateways was seen; may be monitoring evasion or C2.",
         "Block and investigate the host if Tor is not allowed by policy.")),
    "irc_botnet": _r(
        "high", "T1071", "Command & Control", "Tools", "D3-NTA", "CAR-2014-11-002",
        ("فرماندهی و کنترل", "ارتباط IRC (احتمال Botnet)",
         "نشست IRC با دستورهای NICK/JOIN دیده شد. در شبکه‌های سازمانی این معمولاً کانال فرمان باتنت است.",
         "میزبان مبدأ را بررسی و ارتباط IRC را مسدود کنید."),
        ("Command & Control", "IRC session (possible botnet C2)",
         "An IRC session with NICK/JOIN commands was observed. On corporate networks this is usually botnet command & control.",
         "Investigate the source host and block outbound IRC.")),
    "exfil_webhook": _r(
        "high", "T1567", "Actions on Objectives", "Domain Names", "D3-OTF", "CAR-2014-11-002",
        ("نشت داده", "نشت داده از راه Webhook / Bot API (Discord / Telegram / Slack / Pastebin / transfer.sh)",
         "داده با درخواست مستقیم به Webhook یا API ربات یا سرویس اشتراک متن/فایل ارسال شده است؛ روش رایج سارق‌ها و RATها.",
         "پروسه‌ی مبدأ را پیدا کنید، آدرس Webhook/توکن را به‌عنوان IOC ثبت و مسدود کنید."),
        ("Exfiltration", "Data exfiltration via Webhook / Bot API (Discord / Telegram / Slack / Pastebin / transfer.sh)",
         "Data was pushed to a webhook, bot API or paste/file-drop service — a favourite channel of stealers and RATs.",
         "Find the originating process and record/block the webhook URL or token as an IOC.")),
    "suspicious_user_agent": _r(
        "medium", "T1071.001", "Command & Control", "Tools", "D3-NTA", "CAR-2014-11-002",
        ("فرماندهی و کنترل", "User-Agent مشکوک / غیرمرورگر (اسکریپت، لودر، ابزار خط‌فرمان، IE7 جعلی)",
         "User-Agent خالی یا متعلق به ابزار برنامه‌نویسی/دانلودر یا IE قدیمی جعلی که بدافزارهایی مثل LokiBot و Formbook استفاده می‌کنند.",
         "پروسه‌ی مبدأ را بررسی کنید؛ این هشدار به‌تنهایی قطعی نیست و با سایر شواهد معنا می‌دهد."),
        ("Command & Control", "Suspicious / non-browser User-Agent (script, loader, CLI tool, fake IE7)",
         "Empty User-Agent, programming-library / downloader agent, or the fake old-IE agent used by LokiBot and Formbook.",
         "Check the originating process; on its own this is weak evidence and gains meaning alongside other findings.")),
    "malware_gate_post": _r(
        "high", "T1041", "Command & Control", "Network Artifacts", "D3-NTA", "CAR-2014-11-002",
        ("فرماندهی و کنترل", "ارسال POST به «گیت» پنل بدافزار (gate.php / fre.php / panel)",
         "POST به مسیرهای مرسوم پنل‌های C2 سارق‌ها (LokiBot fre.php، پنل‌های gate.php) همراه نشانه‌های غیرمرورگری.",
         "آدرس را مسدود، بدنه‌ی درخواست را بررسی و میزبان را ایزوله کنید."),
        ("Command & Control", "POST to a malware panel gate (gate.php / fre.php / panel)",
         "POST to paths typical of stealer C2 panels (LokiBot fre.php, gate.php panels) with non-browser traits.",
         "Block the URL, inspect the request body and isolate the host.")),
    "ransom_note": _r(
        "critical", "T1486", "Actions on Objectives", "Artifacts", "D3-FA", "CAR-2020-05-003",
        ("تأثیر", "نشانه‌ی باج‌افزار: متن یادداشت باج یا فایل رمزشده",
         "متن یادداشت اخاذی (مثل «your files have been encrypted») یا پسوندهای رمزشده در داده‌ی منتقل‌شده دیده شد.",
         "میزبان را فوراً ایزوله، پشتیبان‌ها را حفاظت و پاسخ به حادثه را آغاز کنید."),
        ("Impact", "Ransomware indicators: ransom-note text or encrypted-file markers",
         "Extortion-note wording (\"your files have been encrypted\" ...) or ransomware file markers were found in transferred data.",
         "Isolate the host immediately, protect backups and start incident response.")),
    "secret_leak": _r(
        "high", "T1552", "Actions on Objectives", "Artifacts", "D3-FA", "CAR-2020-05-001",
        ("دسترسی به اعتبارنامه", "نشت کلید خصوصی / توکن API / شماره کارت در متن آشکار",
         "داده‌ی ارسال‌شده شامل کلید خصوصی، توکن ابری (AWS/GitHub/Slack/Google) یا شماره‌ی کارت معتبر (Luhn) است.",
         "کلیدها و توکن‌ها را فوراً باطل و تعویض کنید."),
        ("Credential Access", "Private key / API token / payment-card number leaked in clear text",
         "Transferred data contains a private key, cloud token (AWS / GitHub / Slack / Google) or Luhn-valid card numbers.",
         "Revoke and rotate the keys and tokens immediately.")),
    "office_macro": _r(
        "high", "T1566.001", "Delivery", "Artifacts", "D3-FA", "CAR-2020-05-001",
        ("تحویل", "سند Office دارای ماکرو (VBA) منتقل شد",
         "سند Word/Excel حاوی پروژه‌ی VBA منتقل شد؛ مسیر رایج تحویل لودرهای فیشینگ.",
         "سند را فقط در VM باز و ماکروها را تحلیل کنید؛ اجرای ماکرو را در سازمان محدود کنید."),
        ("Delivery", "Office document with VBA macros transferred",
         "A Word / Excel document containing a VBA project was transferred — a common phishing-loader vector.",
         "Open only in a VM and analyse the macros; restrict macro execution organisation-wide.")),
    "disguised_executable": _r(
        "high", "T1036.007", "Delivery", "Artifacts", "D3-FA", "CAR-2020-05-001",
        ("فرار از دفاع", "فایل اجرایی مخفی‌شده (پسوند دوگانه یا نوع واقعی با پسوند نامتجانس)",
         "محتوای واقعی فایل اجرایی/اسکریپت است ولی نام یا نوع اعلام‌شده چیز دیگری نشان می‌دهد (مثل invoice.pdf.exe یا get.php که PE است).",
         "فایل را در VM بررسی و منبع آن را مسدود کنید."),
        ("Defense Evasion", "Disguised executable (double extension or content/extension mismatch)",
         "The real content is an executable/script but the name or declared type says otherwise (e.g. invoice.pdf.exe, or get.php that is actually a PE).",
         "Analyse the file in a VM and block its source.")),
    "mail_malicious_attachment": _r(
        "high", "T1566.001", "Delivery", "Artifacts", "D3-FA", "CAR-2020-05-001",
        ("تحویل", "ایمیل با پیوست اجرایی/خطرناک (exe، js، vbs، scr، iso، lnk، macro)",
         "نامه‌ای با پیوست از نوع قابل اجرا دیده شد؛ مسیر اصلی ورود بدافزار.",
         "پیوست را در VM بررسی، فرستنده را مسدود و گیرندگان را مطلع کنید."),
        ("Delivery", "E-mail with executable / dangerous attachment (exe, js, vbs, scr, iso, lnk, macro)",
         "A message carrying an executable-type attachment was seen — the main malware entry vector.",
         "Analyse the attachment in a VM, block the sender and warn recipients.")),
    "smtp_spam_bot": _r(
        "high", "T1071.003", "Command & Control", "Tools", "D3-NTA", "CAR-2014-11-002",
        ("فرماندهی و کنترل", "ارسال انبوه ایمیل از یک میزبان (Spam Bot)",
         "تعداد زیادی نامه از یک ایستگاه به سرورهای SMTP خارجی ارسال شده است.",
         "SMTP خروجی ایستگاه‌ها را مسدود و میزبان را ضدبدافزار کنید."),
        ("Command & Control", "Mass e-mail sending from one host (spam bot)",
         "A single workstation sent many messages to external SMTP servers.",
         "Block outbound SMTP from workstations and clean the host.")),
}

# --------------------------------------------------------------------------------------------------
#  Intelligence tables (offline)
# --------------------------------------------------------------------------------------------------
IP_LOOKUP = (
    "ip-api.com", "ipify.org", "api.ipify.org", "ifconfig.me", "ifconfig.co", "icanhazip.com", "ipinfo.io", "checkip.amazonaws.com",
    "checkip.dyndns.org", "myexternalip.com", "whatismyipaddress.com", "wtfismyip.com", "ipecho.net", "ident.me", "ipwho.is",
    "geoplugin.net", "ipapi.co", "ip-api.io", "freegeoip.app", "ipgeolocation.io", "api.myip.com", "myip.com", "bot.whatismyipaddress.com",
    "ip.42.pl", "ipv4bot.whatismyipaddress.com", "ipinfo.io", "ip.sb", "api64.ipify.org", "ifconfig.io", "ipleak.net", "api.ip.sb",
)
CLOUD_STAGING = (
    "drive.usercontent.google.com", "drive.google.com", "docs.google.com", "onedrive.live.com", "1drv.ms", "dl.dropboxusercontent.com",
    "dropbox.com", "mediafire.com", "mega.nz", "mega.io", "cdn.discordapp.com", "media.discordapp.net", "raw.githubusercontent.com",
    "gist.githubusercontent.com", "pastebin.com", "paste.ee", "transfer.sh", "anonfiles.com", "gofile.io", "catbox.moe", "files.catbox.moe",
    "temp.sh", "filebin.net", "bashupload.com", "sendspace.com", "4shared.com", "zippyshare.com", "wetransfer.com", "we.tl", "file.io",
    "uploadhaven.com", "pixeldrain.com", "send.cm", "bitbucket.org", "sharepoint.com", "box.com", "github.com", "githubusercontent.com",
)
DYNDNS = (
    "duckdns.org", "no-ip.com", "no-ip.org", "no-ip.biz", "ddns.net", "hopto.org", "zapto.org", "servebeer.com", "serveblog.net",
    "sytes.net", "3utilities.com", "myftp.biz", "myftp.org", "redirectme.net", "servehttp.com", "serveftp.com", "servegame.com",
    "dynu.com", "dynu.net", "ddnsking.com", "freeddns.org", "afraid.org", "chickenkiller.com", "mooo.com", "strangled.net",
    "ignorelist.com", "linkpc.net", "webhop.me", "gotdns.ch", "dyndns.org", "dyndns.info", "dynamic-dns.net", "publicvm.com",
    "bounceme.net", "myvnc.com", "viewdns.net", "ydns.eu", "casacam.net", "kozow.com", "nsupdate.info", "loginto.me",
)
WEBHOOK_HOSTS = (
    "discord.com/api/webhooks", "discordapp.com/api/webhooks", "api.telegram.org/bot", "hooks.slack.com", "pastebin.com/api",
    "transfer.sh", "webhook.site", "requestbin", "pipedream.net", "ngrok", "api.anonfiles.com",
)
WEBHOOK_SNI = ("api.telegram.org", "discord.com", "discordapp.com", "hooks.slack.com", "webhook.site", "pipedream.net", "transfer.sh")
TOR_HINTS = (".onion", "tor2web.", "onion.ly", "onion.to", "torproject.org", "onion.pet", "onion.ws")

UA_SUSPICIOUS = (
    (re.compile(r"^$"), "empty User-Agent"),
    (re.compile(r"(?i)^(python-requests|python-urllib|urllib|aiohttp|httpx)"), "Python HTTP library"),
    (re.compile(r"(?i)^(curl|wget|libwww-perl|go-http-client|java/|okhttp|node-fetch|axios|powershell|windowspowershell|winhttp|"
                r"microsoft bits|autoit|vbscript|msxml|certutil|bitsadmin|mshta)"), "scripted / CLI HTTP client"),
    (re.compile(r"Mozilla/4\.0 \(compatible; MSIE [678]\.0"), "fake legacy IE agent (LokiBot / Formbook style)"),
    (re.compile(r"(?i)(agent ?tesla|lokibot|formbook|azorult|raccoon|redline|vidar|nanocore|remcos|asyncrat|snake|hawkeye)"), "malware family string"),
)
GATE_URI = re.compile(r"(?i)/(?:[a-z0-9_-]{2,20}/)?(?:fre|gate|panel|logs?|report|collect|post|submit|upload|send|inject|api/gate|gate/connect)\.php(?:\?|$)")

RISKY_EXT = (".exe", ".dll", ".scr", ".com", ".pif", ".bat", ".cmd", ".js", ".jse", ".vbs", ".vbe", ".wsf", ".hta", ".lnk", ".iso",
             ".img", ".msi", ".jar", ".ps1", ".cpl", ".docm", ".xlsm", ".pptm", ".xlam", ".one", ".chm")
DOUBLE_EXT = re.compile(r"(?i)\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|txt|rtf|zip)\s*\.(exe|scr|com|bat|cmd|js|vbs|hta|lnk|pif)$")

STEALER_FILE = re.compile(r"(?i)^(?:PW|SC|KL|CO|CC|LOG|LOGS|PWD|PASS(?:WORDS?)?|COOKIES?|AUTOFILL|SCREENSHOT|SCREEN|KEYLOG(?:GER)?|RECOVERED|HAWKEYE|SNAKE|"
                         r"CONTACTS?|CREDS?|STEALER|INFO|SYSINFO|WALLETS?)[_\-\s]")
FAMILY_PATTERNS = (
    (re.compile(r"User Name:.{0,60}Computer Name:.{0,80}OSFullName:", re.S), "Agent Tesla"),
    (re.compile(r"(?i)snake\s*keylogger"), "Snake Keylogger"),
    (re.compile(r"(?i)hawk\s*eye\s*(keylogger|reborn)"), "HawkEye"),
    (re.compile(r"(?i)recovered\s+passwords?\s+from"), "Generic password recovery stealer"),
    (re.compile(r"(?i)(?:^|\n)\s*(?:Pony|Fareit)\b"), "Pony / Fareit"),
    (re.compile(r"(?i)lokibot|loki\s*pwd"), "LokiBot"),
    (re.compile(r"(?i)vidar|raccoon\s*stealer|redline\s*stealer"), "Vidar / Raccoon / RedLine"),
    (re.compile(r"(?i)stealer\s*log|=+\s*system\s*info\s*=+"), "Generic stealer log"),
)
CRED_RECORD = re.compile(r"(?is)(?:Host|URL|Site|Hostname)\s*[:=]\s*\S+.{0,160}?(?:User\s*Name|Username|Login|E-?mail)\s*[:=]\s*\S+.{0,160}?Pass(?:word)?\s*[:=]\s*\S+")
APP_MARK = re.compile(r"(?i)Application\s*[:=]\s*(Thunderbird|Chrome|Firefox|Edge|Opera|Outlook|FileZilla|WinSCP|Foxmail|Pidgin|Brave|Vivaldi|Safari|OpenVPN|CoreFTP|SmartFTP)")
EMAIL_RE = re.compile(rb"[A-Za-z0-9._%+\-]{2,40}@[A-Za-z0-9.\-]{3,40}\.[A-Za-z]{2,10}")
RANSOM_RE = re.compile(r"(?is)(your (?:files|data|network|documents) (?:have|has) been (?:encrypted|locked|stolen)|all your files are encrypted|"
                       r"to (?:decrypt|restore) your files|\.onion.{0,80}(?:decrypt|ransom|bitcoin)|pay(?:ment)? .{0,60}(?:bitcoin|btc|monero|xmr).{0,80}decrypt|"
                       r"how to (?:recover|decrypt) (?:your )?files|!!!\s*read\s*me\s*!!!|ransom)")
RANSOM_EXT = re.compile(r"(?i)\.(?:locked|crypt|crypted|encrypted|lockbit|conti|ryuk|wncry|wnry|akira|blackcat|royal|hive|cerber|locky|zepto|djvu|stop|phobos|dharma|basta|medusa|play)$")
SECRET_PATTERNS = (
    (re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY"), "private key"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS access key"),
    (re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "Google API key"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), "GitHub token"),
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9\-]{10,}"), "Slack token"),
    (re.compile(r"\bsk_live_[0-9a-zA-Z]{24,}"), "Stripe live key"),
    (re.compile(r"\b[0-9]{8,10}:AA[0-9A-Za-z_\-]{33}\b"), "Telegram bot token"),
)
CARD_RE = re.compile(r"\b(?:\d[ -]?){13,19}\b")


def _luhn(num: str) -> bool:
    d = [int(c) for c in num if c.isdigit()]
    if not 13 <= len(d) <= 19:
        return False
    s = 0
    for i, x in enumerate(reversed(d)):
        if i % 2:
            x *= 2
            if x > 9:
                x -= 9
        s += x
    return s % 10 == 0


def _is_private(ip) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_loopback or a.is_link_local or a.is_multicast or a.is_reserved
    except (ValueError, TypeError):
        return True


def _suffix(name, table):
    name = (name or "").lower().rstrip(".")
    for t in table:
        if name == t or name.endswith("." + t):
            return t
    return None


def _mask(s):
    s = s or ""
    return (s[:1] + "*" * min(len(s) - 1, 6)) if len(s) > 1 else "*"


class ThreatMixin:
    """Mixed into PcapAnalyzer — call threat_finish() once after hub_finish()."""

    def _init_threats(self):
        self._peek = {}
        self.threat_signals = defaultdict(list)       # victim ip -> [(ts, kind, text)]

    # ------------------------------------------------------------------ helpers
    def _sig(self, ip, ts, kind, text):
        if ip:
            self.threat_signals[ip].append((ts or 0, kind, text))

    def _names(self):
        """(name, ts, n, client, server, kind) from DNS / TLS-SNI / HTTP-Host."""
        out = []
        for ev in self.hub_events.get("DNS", []):
            if ev["k"] == "query":
                nm = ev["d"].get("name")
                if nm:
                    out.append((nm.lower(), ev["t"], ev["n"], ev["a"], ev["b"], "dns"))
        for ev in self.hub_events.get("TLS", []):
            sni = ev["d"].get("sni")
            if sni:
                out.append((sni.lower(), ev["t"], ev["n"], ev["a"], ev["b"], "sni"))
        for ev in self.hub_events.get("HTTP", []):
            h = (ev["d"].get("host") or "").lower().split(":")[0]
            if h:
                out.append((h, ev["t"], ev["n"], ev["a"], ev["b"], "http"))
        return out

    # ------------------------------------------------------------------ main
    def threat_finish(self):
        steps = (self._t_names, self._t_ftp, self._t_mail, self._t_http, self._t_files, self._t_irc, self._t_chain)
        for fn in steps:
            try:
                fn()
            except Exception as e:                       # one detector must never kill the analysis
                self.errors += 1
                self.hub_errors = getattr(self, "hub_errors", []) + [f"{fn.__name__}: {type(e).__name__}: {e}"]

    # ------------------------------------------------------------------ names (DNS / SNI / Host)
    def _t_names(self):
        seen = set()
        for name, ts, n, cli, srv, kind in self._names():
            t = _suffix(name, IP_LOOKUP)
            if t and (cli, t) not in seen:
                seen.add((cli, t))
                self.hit("ip_recon_lookup", n, ts, f"{cli} → {name} ({kind})", cli, srv, artifact=f"IPLookup:{t}")
                self._sig(cli, ts, "lookup", name)
            t = _suffix(name, CLOUD_STAGING)
            if t and kind in ("sni", "http") and (cli, t, "c") not in seen:
                seen.add((cli, t, "c"))
                self.hit("cloud_staging", n, ts, f"{cli} → {name} ({kind})", cli, srv, artifact=f"Staging:{t}")
                self._sig(cli, ts, "staging", name)
            t = _suffix(name, DYNDNS)
            if t and (cli, name, "d") not in seen:
                seen.add((cli, name, "d"))
                self.hit("dyndns_domain", n, ts, f"{cli} → {name} ({kind})", cli, srv, artifact=f"DynDNS:{name}")
                self.ioc_domains.add(name)
            if any(h in name for h in TOR_HINTS) and (cli, "tor") not in seen:
                seen.add((cli, "tor"))
                self.hit("tor_traffic", n, ts, f"{cli} → {name} ({kind})", cli, srv, artifact=f"Tor:{name}")
            if kind == "sni" and name in WEBHOOK_SNI and (cli, name, "w") not in seen:
                seen.add((cli, name, "w"))
                self._sig(cli, ts, "webhook-sni", name)

    # ------------------------------------------------------------------ FTP
    def _t_ftp(self):
        sess = defaultdict(lambda: {"user": None, "pw": None, "stor": [], "ts": None, "n": None})
        for ev in self.hub_events.get("FTP", []):
            if ev["k"] == "command":
                cmd = ev["d"].get("command", "").upper()
                arg = ev["d"].get("arg", "")
                s = sess[(ev["a"], ev["b"])]
                if cmd == "USER":
                    s["user"] = arg
                    s["ts"] = s["ts"] or ev["t"]
                    s["n"] = s["n"] or ev["n"]
                elif cmd == "PASS":
                    s["pw"] = arg
                elif cmd in ("STOR", "APPE", "STOU") and arg:
                    s["stor"].append(arg)
                    s["ts"] = s["ts"] or ev["t"]
                    s["n"] = s["n"] or ev["n"]
            elif ev["k"] == "transfer" and ev["d"].get("direction") == "upload":
                # the data channel runs between the same two hosts as the control session
                for (c, sv), ss in sess.items():
                    if {c, sv} == {ev["a"], ev["b"]}:
                        fn = ev["d"].get("filename")
                        if fn and fn not in ss["stor"]:
                            ss["stor"].append(fn)
                        break
        for (cli, srv), s in sess.items():
            if not s["stor"] or _is_private(srv):
                continue
            names = ", ".join(s["stor"][:4])
            who = f"user={s['user']} pass={_mask(s['pw']) if self.cfg.mask_passwords else s['pw']}" if s["user"] else "anonymous/unknown login"
            self.hit("stealer_ftp_exfil", s["n"], s["ts"], f"{cli} → ftp://{srv}  {who}  uploaded: {names}", cli, srv,
                     artifact=f"FTP:{srv}:{s['user'] or ''}")
            self.ioc_ips[srv].add("Exfiltration Server (FTP)")
            if s["user"]:
                self.ioc_artifacts.add(f"FTP-account:{s['user']}@{srv}")
            self._sig(cli, s["ts"], "exfil", f"FTP {srv}")
            for nm in s["stor"]:
                if STEALER_FILE.search(nm.rsplit("/", 1)[-1]):
                    self.hit("stealer_family_report", s["n"], s["ts"], f"{cli} → ftp://{srv}  filename pattern: {nm}", cli, srv,
                             tool_name="Infostealer exfil filename (PW_/SC_/KL_/CO_...)", artifact=f"File:{nm[:40]}")

    # ------------------------------------------------------------------ mail
    def _t_mail(self):
        per_src = defaultdict(list)
        for proto in ("SMTP", "POP3", "IMAP"):
            for ev in self.hub_events.get(proto, []):
                if ev["k"] != "message":
                    continue
                d = ev["d"]
                atts = d.get("attachments") or []
                risky = [a for a in atts if a.lower().endswith(RISKY_EXT) or DOUBLE_EXT.search(a)]
                if proto == "SMTP":
                    per_src[ev["a"]].append(ev)
                if risky:
                    self.hit("mail_malicious_attachment", ev["n"], ev["t"],
                             f"{proto} {d.get('from', '')} → {d.get('to', '')}  subject='{(d.get('subject') or '')[:60]}'  attachment: {', '.join(risky[:3])}",
                             ev["a"], ev["b"], artifact=f"Attach:{risky[0][:40]}")
                if proto == "SMTP" and not _is_private(ev["b"]):
                    subj = (d.get("subject") or "")
                    body = (d.get("body") or "")
                    if atts or STEALER_FILE.search(subj) or CRED_RECORD.search(body) or "Computer Name" in body:
                        self.hit("stealer_smtp_exfil", ev["n"], ev["t"],
                                 f"{ev['a']} → smtp://{ev['b']}  subject='{subj[:60]}'  attachments: {', '.join(atts[:3]) or '-'}", ev["a"], ev["b"],
                                 artifact=f"SMTP:{ev['b']}")
                        self._sig(ev["a"], ev["t"], "exfil", f"SMTP {ev['b']}")
                        if CRED_RECORD.search(body) or any(p.search(body) for p, _ in FAMILY_PATTERNS):
                            self.hit("stealer_credentials", ev["n"], ev["t"], f"credential-style records in mail body → {ev['b']}", ev["a"], ev["b"])
        for src, evs in per_src.items():
            ext = [e for e in evs if not _is_private(e["b"])]
            if len(ext) >= 10:
                self.hit("smtp_spam_bot", ext[0]["n"], ext[0]["t"], f"{src} sent {len(ext)} messages to external SMTP servers", src, ext[0]["b"],
                         tool_name="Spam bot")

    # ------------------------------------------------------------------ HTTP
    def _t_http(self):
        seen = set()
        for ev in self.hub_events.get("HTTP", []):
            d = ev["d"]
            ua = d.get("ua", "")
            cli, srv, host = ev["a"], ev["b"], (d.get("host") or "")
            uri = d.get("uri") or ""
            url = d.get("url") or f"http://{host}{uri}"
            for rx, label in UA_SUSPICIOUS:
                if rx.search(ua):
                    key = (cli, label, host)
                    if key not in seen:
                        seen.add(key)
                        self.hit("suspicious_user_agent", ev["n"], ev["t"], f"{cli} → {host}{uri[:70]}   UA='{ua[:80]}'   [{label}]", cli, srv,
                                 artifact=f"UA:{ua[:40]}")
                    break
            hostl = host.lower()
            low = url.lower()
            if any(w in low for w in WEBHOOK_HOSTS) and d.get("method") in ("POST", "PUT", "GET"):
                self.hit("exfil_webhook", ev["n"], ev["t"], f"{cli} → {url[:120]}", cli, srv, artifact=f"Webhook:{hostl}")
                self._sig(cli, ev["t"], "exfil", f"webhook {hostl}")
            if d.get("method") == "POST" and GATE_URI.search(uri):
                ipx = "ip-host" in (d.get("flags") or [])
                weak_ua = any(rx.search(ua) for rx, _ in UA_SUSPICIOUS)
                if ipx or weak_ua or not d.get("referer"):
                    self.hit("malware_gate_post", ev["n"], ev["t"], f"{cli} → POST {host}{uri[:80]}  ({d.get('rsize_req', 0)} B)", cli, srv,
                             artifact=f"Gate:{hostl}{uri[:30]}")
                    self.ioc_domains.add(hostl)
                    self._sig(cli, ev["t"], "exfil", f"gate {hostl}")

    # ------------------------------------------------------------------ files (content)
    def _t_files(self):
        recs = {r["id"]: r for r in getattr(self, "file_records", [])}
        for rid, data in list(self._peek.items()):
            rec = recs.get(rid)
            if not rec:
                continue
            name = rec["name"]
            proto = rec["proto"]
            direction = rec.get("direction", "")
            src, dst = rec.get("src"), rec.get("dst")
            n, flow = None, rec.get("flow", "")
            ts = None
            outbound = direction == "upload" or proto in ("SMTP",)
            txt = data[:200000].decode("utf-8", "ignore") if rec.get("category") not in ("executable", "image", "archive", "media") else ""
            where = f"{proto} {name}  ({rec['size']:,} B)  sha256={rec['sha256'][:16]}…"
            low_name = name.lower()

            if DOUBLE_EXT.search(name) or (rec.get("mismatch") and rec.get("risky")):
                self.hit("disguised_executable", n, ts, f"{where}  type={rec['type']}  src={rec.get('url') or flow}", src, dst, artifact=f"SHA256:{rec['sha256'][:16]}")
            if RANSOM_EXT.search(low_name) or (txt and RANSOM_RE.search(txt[:6000]) and rec.get("category") in ("text", "web", "document", "")):
                if txt and RANSOM_RE.search(txt[:6000]) or RANSOM_EXT.search(low_name):
                    self.hit("ransom_note", n, ts, where, src, dst, artifact=f"Ransom:{name[:40]}")
            head = data[:8]
            if head[:4] == b"\xd0\xcf\x11\xe0" or head[:2] == b"PK":
                blob = data[:400000]
                if (head[:4] == b"\xd0\xcf\x11\xe0" and (b"VBA" in blob or b"M\x00a\x00c\x00r\x00o\x00s" in blob or b"Macros" in blob)) or \
                        (head[:2] == b"PK" and b"vbaProject.bin" in blob):
                    self.hit("office_macro", n, ts, where, src, dst, artifact=f"Macro:{rec['sha256'][:16]}")
            if not txt:
                continue
            fam = None
            for rx, label in FAMILY_PATTERNS:
                if rx.search(txt[:60000]):
                    fam = label
                    break
            if STEALER_FILE.search(name) and not fam:
                fam = "Infostealer log file naming"
            creds = CRED_RECORD.findall(txt[:200000])
            apps = set(m.group(1) for m in APP_MARK.finditer(txt[:200000]))
            if len(creds) >= 1 and (len(creds) >= 2 or apps):
                self.hit("stealer_credentials", n, ts, f"{where}: {len(creds)} credential record(s)" + (f" from {', '.join(sorted(apps))}" if apps else ""),
                         src, dst, artifact=f"CredDump:{rec['sha256'][:16]}")
            if fam:
                self.hit("stealer_family_report", n, ts, f"{where}: matches {fam}", src, dst, tool_name=fam, artifact=f"Stealer:{fam}")
                if "Tesla" in fam:
                    self.ioc_tools.add("AgentTesla")
            emails = set(EMAIL_RE.findall(data[:300000]))
            if len(emails) >= 15 and (outbound or creds or fam):
                self.hit("address_book_harvest", n, ts, f"{where}: {len(emails)} distinct e-mail addresses", src, dst, artifact=f"Emails:{rec['sha256'][:16]}")
            for rx, label in SECRET_PATTERNS:
                if rx.search(txt[:300000]):
                    self.hit("secret_leak", n, ts, f"{where}: {label}", src, dst, artifact=f"Secret:{label}")
                    break
            else:
                cards = [m.group(0) for m in CARD_RE.finditer(txt[:100000]) if _luhn(m.group(0))]
                if len(cards) >= 3:
                    self.hit("secret_leak", n, ts, f"{where}: {len(cards)} Luhn-valid card numbers", src, dst, artifact="Cards")
            if outbound and (fam or creds):
                self._sig(src, ts, "exfil-content", name)

    # ------------------------------------------------------------------ IRC
    def _t_irc(self):
        by = {}
        for ev in self.hub_events.get("IRC", []):
            s = ev["s"].upper()
            if s.startswith(("NICK", "JOIN", "USER")) and not _is_private(ev["b"]):
                by.setdefault((ev["a"], ev["b"]), ev)
        for (cli, srv), ev in by.items():
            self.hit("irc_botnet", ev["n"], ev["t"], f"{cli} → irc://{srv}:{ev['bp']}  {ev['s'][:60]}", cli, srv, artifact=f"IRC:{srv}")

    # ------------------------------------------------------------------ correlation
    def _t_chain(self):
        for ip, sigs in self.threat_signals.items():
            if _is_private(ip) and not sigs:
                continue
            kinds = {k for _, k, _ in sigs}
            exfil = [s for s in sigs if s[1] in ("exfil", "exfil-content")]
            pre = [s for s in sigs if s[1] in ("staging", "lookup")]
            if not exfil or not pre:
                continue
            order = sorted(sigs)
            txt = "  →  ".join(f"[{k}] {t}" for _, k, t in order[:8])
            tool = "GuLoader/AgentTesla-style" if "staging" in kinds and "lookup" in kinds else "Loader + stealer"
            self.hit("infection_chain", None, order[0][0], f"victim {ip}: {txt}", ip, None, tool_name=tool, artifact=f"Chain:{ip}")
            self.ioc_ips[ip].add("Victim / Infected Host")
