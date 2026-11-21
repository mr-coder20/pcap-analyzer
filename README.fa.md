<div dir="rtl">

<div align="center">

# PCAP Analyzer نسخه ۸ — سایبری

**تحلیل آفلاین PCAP / PCAPNG و شکار تهدید. گزارش دارک‌سایبری، جزئیات هر پروتکل و هر مسیر با یک کلیک، و تحویل همه‌ی فایل‌های منتقل‌شده در ZIP با نام اصلی.**

🇬🇧 [English](README.md) · 🇮🇷 فارسی

</div>

## ویژگی‌های اصلی

- **روی هر پروتکل یا مسیر کلیک کنید** و ببینید چه اتفاقی افتاده: در HTTP تک‌تک درخواست/پاسخ‌ها، وضعیت، هاست، آدرس و **نام فایل‌های دانلودشده**؛ در DNS پرسش‌ها/پاسخ‌ها/NXDOMAIN؛ در TLS مقادیر SNI/ALPN/JA3؛ در FTP دستورها و انتقال‌ها؛ در SMTP/POP3 نامه‌ها و پیوست‌ها؛ و نیز SMB، DHCP، TFTP، ARP، ICMP.
- **استخراج دقیق فایل‌ها در ZIP.** فایل‌ها از روی جریان‌ها بازسازی می‌شوند (Content-Length، chunked، تا بسته‌شدن اتصال؛ رمزگشایی gzip/deflate/brotli؛ آپلود multipart و PUT؛ کانال داده‌ی FTP؛ پیوست ایمیل؛ TFTP) و با ساختار `PROTO/host/نام-اصلی` داخل `<نام>_extracted_files.zip` قرار می‌گیرند؛ همراه `MANIFEST.json`، `MANIFEST.csv` و README. برای هر فایل SHA-256، نوع واقعی (magic bytes)، آنتروپی و هشدار «پسوند نامتجانس / نوع پرخطر» ثبت می‌شود.
- **ظاهر قابل انتخاب**: ۸ تم، ۴ متریال، افکت‌ها (شبکه، خطوط اسکن، درخشش، باران ماتریکس، انیمیشن)، تراکم، اندازه‌ی فونت، RTL/LTR و حالت ساده — زنده در خود گزارش عوض می‌شود و در مرورگر ذخیره می‌ماند.
- **سریع**: خواننده‌ی بومی mmap و پارسرهای داخلی؛ دیگر به scapy نیاز نیست.
- تشخیص‌های نسخه‌ی ۷ حفظ شده: DGA/تونل DNS، beaconing، اسکن، C2 روی سرویس‌های عمومی، ماینر، PsExec/SMB، Kerberos، حمله‌های وب، MITRE ATT&CK / D3FEND، قوانین Suricata/YARA/Splunk/Elastic، تطبیق آفلاین IOC.
- کاملاً آفلاین؛ گزارش HTML تک‌فایل.

## تشخیص تهدید (نسخه ۸)

علاوه بر تشخیص‌های نسخه ۷، حالا برنامه درباره‌ی **محتوایی که واقعاً منتقل شده** استدلال می‌کند (اول جریان‌ها بازسازی و فایل‌ها استخراج می‌شوند):

| قانون | چه چیزی را می‌گیرد | ATT&CK |
|---|---|---|
| `infection_chain` | برای هر میزبان قربانی «دریافت از میزبانی ابری ← جست‌وجوی IP عمومی ← نشت داده» را به هم وصل می‌کند (سبک GuLoader + AgentTesla / Formbook / Snake) | T1204 |
| `stealer_ftp_exfil` | ورود میزبان داخلی به FTP خارجی و آپلود فایل (رمزها در شواهد ماسک می‌شوند) | T1048.003 |
| `stealer_smtp_exfil` | نشت مستقیم با SMTP و پیوست/لاگ | T1048.003 |
| `stealer_credentials` | فهرست «Host / Username / Password / Application» در فایل‌ها و نامه‌ها | T1555 |
| `stealer_family_report` | قالب گزارش AgentTesla / Snake / HawkEye / LokiBot و نام فایل‌های `PW_ SC_ KL_ CO_` | T1056.001 |
| `address_book_harvest` | ده‌ها آدرس ایمیل در داده‌ی خروجی | T1114 |
| `ip_recon_lookup` | ip-api، ipify، ifconfig.me و … (از جمله بررسی Sandbox با `fields=hosting`) | T1016 |
| `cloud_staging` | Drive، OneDrive، Dropbox، Mega، Discord CDN، GitHub raw، Pastebin، transfer.sh … | T1105 |
| `dyndns_domain` ، `tor_traffic` ، `irc_botnet` | DuckDNS / No-IP / ddns.net، Tor / onion، کانال IRC باتنت | T1568 · T1090.003 · T1071 |
| `exfil_webhook` ، `malware_gate_post` ، `suspicious_user_agent` | Webhook دیسکورد/تلگرام/اسلک، پنل‌های `gate.php`/`fre.php`، User-Agent جعلی IE7 / خالی / اسکریپتی | T1567 · T1041 · T1071.001 |
| `ransom_note` ، `secret_leak` ، `office_macro` ، `disguised_executable` ، `mail_malicious_attachment` ، `smtp_spam_bot` | یادداشت باج، کلید خصوصی / توکن API / کارت معتبر، ماکروی VBA، `invoice.pdf.exe`، پیوست خطرناک، اسپم‌بات | T1486 · T1552 · T1566.001 · T1036.007 · T1071.003 |

روی یک کپچر واقعی *GuLoader ← AgentTesla ← نشت FTP* (۳۵۳ بسته) امتیاز از ۲۶ («متوسط») به **۱۰۰ / بحرانی** رسید، کل زنجیره توضیح داده شد و هر دو فایل داده‌ی سرقت‌شده داخل ZIP تحویل شد.

## زبان‌ها

پیش‌فرض همه‌جا **انگلیسی** است و فارسی با یک کلید فعال می‌شود.

- خط فرمان: `--lang en|fa` (یا `PCAP_LANG=fa`)؛ `--help` و همه‌ی پیام‌ها ترجمه می‌شوند.
- گزارش HTML: دکمه‌ی 🌐 در نوار کناری، زبان **و** جهت (چپ‌به‌راست/راست‌به‌چپ) را فوراً عوض می‌کند، از جمله متن قوانین، شواهد و توضیحات ساده.
- برنامه‌ی دسکتاپ: تنظیمات ← *Language / زبان* (در `~/.pcap_analyzer/config.json` ذخیره می‌شود؛ برای اعمال راه‌اندازی مجدد لازم است).
- گزارش قدیمی `classic` فقط فارسی است؛ گزارش پیش‌فرض `cyber` کاملاً دوزبانه است.

## نصب و اجرا

```bash
pip install -r requirements.txt              # pillow (برای رابط گرافیکی)
pip install -r requirements-optional.txt     # pyzipper (ZIP رمزدار AES)، brotli، scapy (جایگزین)

python pcap_analyzer.py                       # رابط گرافیکی
python pcap_analyzer.py capture.pcap --cli    # خط فرمان
python pcap_analyzer.py capture.pcap --cli --theme matrix --material terminal -o out/
python pcap_analyzer.py --list-themes
python pcap_analyzer.py --doctor
```

پایتون ۳.۹ به بالا. هسته فقط به کتابخانه‌ی استاندارد نیاز دارد.

## گزینه‌های جدید خط فرمان

| گزینه | معنی |
|---|---|
| `--theme ID` | neon-night (پیش‌فرض)، matrix، synthwave، crimson-ops، amber-terminal، ice-circuit، toxic-lime، paper-light |
| `--material M` | glass · solid · hologram · terminal |
| `--report-style S` | cyber · classic · both |
| `--formats LIST` | فهرست جداشده با کاما از html,json,csv,rules,iocs |
| `--no-extract` | بدون استخراج فایل و ZIP |
| `--extract-scope` | `all` یا `downloads` (بدون HTML/JS/CSS/JSON وب) |
| `--zip-password PW` | رمز ZIP (پیش‌فرض `infected`؛ نیازمند pyzipper) |
| `--max-extract-mb N` | سقف حجم داده‌ی استخراجی |
| `--max-stream-mb N` ، `--max-mem-mb N` | سقف حافظه برای هر جریان / کل |
| `--no-fast` | اجبار مسیر قدیمی با scapy |
| `--sample-mode` ، `--ioc-file` ، `--no-defang` ، `--unmask` ، `--max-packets` ، `--no-bundle` | مثل نسخه‌ی ۷ |

## پوشه‌ی خروجی

`<نام>_pcap_report.html` (گزارش سایبری) · `.json` · `_findings.csv` · `_protocol_events.csv` · `_suricata.rules` · `_hunt.yar` · `_iocs_defanged.txt` · **`<نام>_extracted_files.zip`** · `_extracted_manifest.json/.csv` · `reports_bundle.zip`.

## کار با ZIP — ایمنی

فایل‌های استخراج‌شده ممکن است **بدافزار واقعی** باشند.
- اگر **pyzipper** نصب باشد، ZIP با AES-256 رمز می‌شود؛ رمز: **`infected`**.
- در غیر این صورت ZIP ساده است و فایل‌های پرخطر (اجرایی، اسکریپت و…) به‌صورت ظرف خنثی `*.sample` (XOR) ذخیره می‌شوند (بازیابی با `--restore FILE.sample`).
- فقط داخل ماشین مجازی ایزوله باز یا بازیابی کنید. هرگز فایل اجرایی استخراج‌شده را دابل‌کلیک نکنید.

## گزارش

بخش‌ها: **نمای کلی · پروتکل‌ها · مسیرها · فایل‌ها (مرورگر ZIP: درخت/جدول، فیلتر، جست‌وجو، پیش‌نمایش، هش، خروجی CSV) · هشدارها · شناخت تهدید · آمار**. روی پروتکل کلیک کنید تا تب رویدادهایش باز شود؛ روی مسیر (میزبان ↔ میزبان) کلیک کنید تا همه‌ی تبادلات آن مسیر، از جمله فایل‌ها، نمایش یابد. همه‌ی داده‌ها با `textContent` رسم می‌شوند، پس فایل مخرب نمی‌تواند در گزارش کد تزریق کند.

## معماری

| ماژول | نقش |
|---|---|
| `pcap_fastio.py` | خواندن mmap برای pcap/pcapng، رمزگشایی لایه‌ها، پارسر DNS/DHCP/SNMP/SMB2/TLS |
| `pcap_protocols.py` | هاب پروتکل‌ها: رویدادها، جریان‌ها، استخراج HTTP/FTP/ایمیل/TFTP |
| `pcap_extract.py` | تشخیص نوع، پیش‌نمایش، `FileStore` (ZIP، مانیفست، حالت‌های ایمن) |
| `pcap_report_cyber.py` | گزارش HTML سایبری تک‌فایل |
| `pcap_themes.py` | تم‌ها و متریال‌های مشترک گزارش و رابط |
| `pcap_analyzer.py` | موتور، تشخیص‌ها، CLI و رابط Tk |

## آزمون‌ها

```bash
pip install pytest
pytest -q tests
```
`tests/make_native_pcap.py` یک کپچر بی‌خطر (هدر PE ساختگی، بدون بدافزار واقعی) بدون scapy می‌سازد. آزمون قدیمی `test_smoke.py` اگر scapy نباشد رد می‌شود.

## محدودیت‌ها (صادقانه)

- ترافیک رمزنگاری‌شده (TLS/SSH/QUIC) بدون کلید قابل استخراج نیست؛ فقط فراداده (SNI، ALPN، JA3) نمایش داده می‌شود.
- استخراج تابع سقف حافظه/حجم است؛ کپچرهای ناقص یا نامرتب ممکن است فایل ناقص بدهند (با برچسب).
- رابط Tk و مسیر ZIP رمزدار AES در محیط توسعه اجرا نشدند (نبود نمایشگر و pyzipper)؛ مسیرهای CLI و گزارش آزمون شده‌اند. لطفاً مشکلات را گزارش کنید.

مجوز MIT · mr-coder20

</div>
