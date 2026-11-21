# -*- coding: utf-8 -*-
"""English translations for pcap_analyzer.py lines 1-2450 (pure data)."""
Z = "‌"

UI_EN = {
    "بحرانی": "Critical",
    "بالا": "High",
    "متوسط": "Medium",
    "کم": "Low",
    "اطلاعاتی": "Info",
    "۱. شناسایی (Recon)": "1. Reconnaissance (Recon)",
    "۲. تسلیح (Weaponization)": "2. Weaponization",
    "۳. تحویل (Delivery)": "3. Delivery",
    f"۴. بهره{Z}برداری (Exploitation)": "4. Exploitation",
    "۵. نصب و پایداری (Installation)": "5. Installation & Persistence",
    "۶. فرماندهی و کنترل (C2)": "6. Command & Control (C2)",
    "۷. اقدام روی هدف (Exfil/Impact)": "7. Actions on Objectives (Exfil/Impact)",
    f"این فرمت/لینک{Z}تایپ با پکت{Z}خوان داخلی پشتیبانی نمی{Z}شود و scapy هم نصب نیست.\nنصب: pip install scapy":
        "This format/link type is not supported by the built-in packet reader and scapy is not installed.\nInstall: pip install scapy",
    f"فایل قابل خواندن نیست یا فرمت آن پشتیبانی نمی{Z}شود:\n": "File is unreadable or its format is not supported:\n",
    "شناسایی نشده (ترافیک عادی یا داخلی)": "None identified (normal or internal traffic)",
    "بدون اکسپلویت یا ابزار تهاجمی": "No exploits or offensive tools",
    "شبکه محلی (LAN)": "Local network (LAN)",
    f"میزبان{Z}های هدف داخلی": "Internal target hosts",
    f"# فیلتر شکار فایل{Z}های اجرایی، فلش (SWF) و درخواست{Z}های وب در Wireshark:\nhttp.request || http.content_type contains \"shockwave\" || frame contains \"MZ\" || frame contains \"ZWS\" || frame contains \"CWS\"":
        "# Wireshark filter to hunt executables, Flash (SWF) and web requests:\nhttp.request || http.content_type contains \"shockwave\" || frame contains \"MZ\" || frame contains \"ZWS\" || frame contains \"CWS\"",
    "# هیچ IP یا دامنه مهاجمی برای تولید قانون مسدودسازی Suricata یافت نشد.":
        "# No attacker IP or domain found to generate Suricata blocking rules.",
    f"ایزوله{Z}سازی فوری میزبان{Z}های درگیر در هشدارهای بحرانی (Exploit Kit / Malware Dropper / RCE / Webshell / Reverse Shell).":
        "Immediately isolate hosts involved in critical alerts (Exploit Kit / Malware Dropper / RCE / Webshell / Reverse Shell).",
    f"تغییر فوری رمزهای عبور و توکن{Z}های ارسال{Z}شده به صورت متن آشکار (Cleartext Credentials).":
        "Immediately rotate passwords and tokens sent in cleartext (Cleartext Credentials).",
    f"بررسی لاگ{Z}های میزبان و فایروال برای رخدادهای ثبت{Z}شده.": "Review host and firewall logs for the recorded events.",
}

UI_PATTERNS = []
def P(fa, en):
    UI_PATTERNS.append((fa, en))

# NOTE: some regexes use ^...$ ; Persian text literal with ZWNJ kept exactly.
P(r"^\[CRITICAL\] ماژول‌های همراه برنامه پیدا نشد \((.+?)\)\. همه فایل‌های \.py را کنار هم نگه دارید\.$",
  r"[CRITICAL] Bundled application modules not found (\1). Keep all .py files together.")
P(r"^فایل قابل خواندن نیست یا فرمت آن پشتیبانی نمی‌شود:\n(.*)$",
  r"File is unreadable or its format is not supported:\n\1")
P(r"^(.+?): (\d[\d,\.]*) تلاش ناموفق ورود در فایل لاگ$", r"\1: \2 failed login attempts in log file")
P(r"^چندین سرور DHCP Offer در شبکه شناسایی شد: (.+)$", r"Multiple DHCP Offer servers detected on the network: \1")
P(r"^ارسال درخواست‌های DHCP از (\d[\d,\.]*) آدرس MAC مختلف \(احتمال حمله DHCP Starvation\)$",
  r"DHCP requests sent from \1 different MAC addresses (possible DHCP Starvation attack)")
P(r"^کلاینت (.+?) در زنجیره تغییر مسیر چندمرحله‌ای وب: (.+)$", r"Client \1 in multi-stage web redirect chain: \2")
P(r"^(.+?) → (.+?): (\d[\d,\.]*) پورت مختلف \(نمونه: (.+)\)$", r"\1 → \2: \3 distinct ports (sample: \4)")
P(r"^(.+?) → پورت (\d[\d,\.]*): (\d[\d,\.]*) میزبان مختلف$", r"\1 → port \2: \3 distinct hosts")
P(r"^(.+?) → (.+?): (\d[\d,\.]*) بسته (.+)$", r"\1 → \2: \3 \4 packets")
P(r"^(.+?) → (.+?):(\d+) \((.*?)\)  (\d[\d,\.]*) اتصال در (.+?)s$", r"\1 → \2:\3 (\4)  \5 connections in \6s")
P(r"^(.+?) → (.+?):(\d+)  (\d[\d,\.]*) اتصال منظم، میانگین فاصله (.+?)s \(CV=(.+?)\)$",
  r"\1 → \2:\3  \4 regular connections, mean interval \5s (CV=\6)")
P(r"^هدف (.+?): (\d[\d,\.]*) بسته SYN دریافت شده، فقط (\d[\d,\.]*) پاسخ SYN-ACK$",
  r"Target \1: \2 SYN packets received, only \3 SYN-ACK responses")
P(r"^IP (.+?) با چند آدرس MAC دیده شد: (.+)$", r"IP \1 seen with multiple MAC addresses: \2")
P(r"^MAC (.+?): ارسال (\d[\d,\.]*) پاسخ ARP Reply$", r"MAC \1: sent \2 ARP Reply packets")
P(r"^دامنه (.+?): (\d[\d,\.]*) زیردامنه یکتا، میانگین طول (.+?) کاراکتر$",
  r"Domain \1: \2 unique subdomains, average length \3 characters")
P(r"^کلاینت (.+?): دریافت (\d[\d,\.]*) پاسخ NXDOMAIN$", r"Client \1: received \2 NXDOMAIN responses")
P(r"^(.+?) → پینگ به (\d[\d,\.]*) میزبان$", r"\1 → pinged \2 hosts")
P(r"^(.+?) → (.+?): (\d[\d,\.]*) بسته Echo با Payload بزرگتر از 100 بایت$",
  r"\1 → \2: \3 Echo packets with payload larger than 100 bytes")
P(r"^(.+?) → (.+?): (.+?) داده ارسالی در برابر (.+?) دریافتی$", r"\1 → \2: \3 sent vs \4 received")
P(r"^# فیلتر ترافیک IPهای مهاجم، Exploit Kit و C2:\n(\(.*\))$", r"# Traffic filter for attacker IPs, Exploit Kits and C2:\n\1")
P(r"^# فیلتر دامنه‌های مشکوک، گیت‌های تغییر مسیر و تونلینگ:\n(\(.*\))$",
  r"# Filter for suspicious domains, redirect gates and tunneling:\n\1")
P(r"^بررسی فوری (\d[\d,\.]*) فایل استخراج‌شده در پوشه _artifacts و مسدودسازی هش‌های SHA-256 در EDR\.$",
  r"Immediately review \1 extracted files in the _artifacts folder and block their SHA-256 hashes in EDR.")
P(r"^اعمال قوانین Suricata/Firewall تولیدشده در همین گزارش جهت مسدودسازی IPهای مهاجم: (.+)$",
  r"Apply the Suricata/Firewall rules generated in this report to block attacker IPs: \1")
P(r"^در بررسی آفلاین (\d[\d,\.]*) واحد داده \((.+?)\)، هیچ‌گونه امضای حمله، اسکن شبکه، ابزار مخرب یا ناهنجاری پروتکلی شناسایی نشد\. وضعیت امنیتی ترافیک «عادی» ارزیابی می‌گردد\.$",
  r"In offline analysis of \1 data units (\2), no attack signatures, network scans, malicious tools or protocol anomalies were detected. Traffic security posture is assessed as \"normal\".")
P(r"^ همچنین (\d[\d,\.]*) فایل اجرایی/فلش/آرشیو استخراج و در پوشه _artifacts ذخیره شد\.$",
  r" Additionally, \1 executable/Flash/archive files were extracted and saved to the _artifacts folder.")

# Executive summary (2424-2427): one pattern per severity level x carved note presence
_SEV = {"بحرانی": "Critical", "بالا": "High", "متوسط": "Medium", "کم": "Low", "اطلاعاتی": "Info"}
_CARVED_FA = r" همچنین (\d[\d,\.]*) فایل اجرایی/فلش/آرشیو استخراج و در پوشه _artifacts ذخیره شد\."
_HEAD = (r"^طی تحلیل عمیق و آفلاین (\d[\d,\.]*) بسته/رکورد \((.+?)\) و بازسازی (\d[\d,\.]*) جریان TCP، مجموعاً (\d[\d,\.]*) نوع تهدید امنیتی "
         r"\(شامل (\d[\d,\.]*) مورد بحرانی، (\d[\d,\.]*) مورد ریسک بالا و (\d[\d,\.]*) مورد متوسط\) کشف شد\.")
def _tail(sev):
    return (r" بر اساس چارچوب Cyber Kill Chain، فعالیت مهاجم در مراحل \[(.*?)\] مشاهده شده است\. امتیاز ریسک کلی شبکه (\d[\d,\.]*) از ۱۰۰ "
            r"\(سطح: " + sev + r" \| شاخص همبستگی شواهد: (\d[\d,\.]*)%\) محاسبه گردید\.$")
for _fa, _en in _SEV.items():
    P(_HEAD + _CARVED_FA + _tail(_fa),
      r"Deep offline analysis of \1 packets/records (\2) and \3 reassembled TCP streams found \4 security threat types "
      r"(\5 critical, \6 high-risk and \7 medium). Additionally, \8 executable/Flash/archive files were extracted and saved to the _artifacts folder. "
      r"Per the Cyber Kill Chain framework, attacker activity was observed in stages [\9]. Overall network risk score: \g<10> of 100 "
      r"(level: " + _en + r" | evidence correlation index: \g<11>%).")
    P(_HEAD + _tail(_fa),
      r"Deep offline analysis of \1 packets/records (\2) and \3 reassembled TCP streams found \4 security threat types "
      r"(\5 critical, \6 high-risk and \7 medium). "
      r"Per the Cyber Kill Chain framework, attacker activity was observed in stages [\8]. Overall network risk score: \9 of 100 "
      r"(level: " + _en + r" | evidence correlation index: \g<10>%).")

# Persian digit variants are not expected; the 1-9 backrefs above use \g<10>/\g<11> where needed.
