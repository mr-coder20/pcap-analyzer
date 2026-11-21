<div align="center">

# PCAP Analyzer v8 — Cyber

**Offline PCAP / PCAPNG forensics & threat hunting. Dark-cyber reports, per-protocol / per-route drill-down, and every transferred file delivered in a ZIP with its original name.**

🇮🇷 [فارسی](README.fa.md) · 🇬🇧 English

</div>

## Highlights

- **Click any protocol or route** in the report and see what happened: for HTTP every request/response, status, host, URI, and the **names of downloaded files**; for DNS queries/answers/NXDOMAIN; TLS SNI/ALPN/JA3; FTP commands & transfers; SMTP/POP3 mail and attachments; SMB, DHCP, TFTP, ARP, ICMP.
- **Exact file extraction → ZIP.** Files are rebuilt from the streams (Content-Length, chunked, until-close; gzip/deflate/brotli decoded; multipart and PUT uploads; FTP data channels; mail attachments; TFTP) and stored as `PROTO/host/original-name` in `<capture>_extracted_files.zip` with `MANIFEST.json`, `MANIFEST.csv` and a README inside. Each file has SHA-256, magic-byte type, entropy, and flags for extension mismatch / risky types.
- **Selectable look**: 8 themes, 4 materials, effects (grid, scanlines, glow, matrix rain, animation), density, font size, RTL/LTR, simple mode — changed live in the report, remembered in your browser.
- **Fast**: native mmap reader and parsers; scapy no longer required.
- Detections kept from v7: DGA/DNS tunneling, beaconing, scans, C2 over public services, miners, PsExec/SMB, Kerberos, web attacks, MITRE ATT&CK / D3FEND, Suricata/YARA/Splunk/Elastic rules, offline IOC matching.
- 100 % offline. Single-file HTML report.

## Threat detection (v8)

Besides the v7 detections, v8 reasons about **what was actually transferred** (streams are reassembled and files extracted first):

| Rule | What it catches | ATT&CK |
|---|---|---|
| `infection_chain` | Correlates, per victim host, *cloud staging → public-IP lookup → exfiltration* (GuLoader + AgentTesla / Formbook / Snake style) | T1204 |
| `stealer_ftp_exfil` | Internal host logs in to an external FTP server and uploads files (credentials masked in evidence) | T1048.003 |
| `stealer_smtp_exfil` | Direct SMTP exfiltration with attachments / log bodies | T1048.003 |
| `stealer_credentials` | "Host / Username / Password / Application" dumps in uploads, mail bodies, POSTs | T1555 |
| `stealer_family_report` | AgentTesla / Snake / HawkEye / LokiBot report layouts and `PW_ SC_ KL_ CO_` file-name conventions | T1056.001 |
| `address_book_harvest` | Dozens of e-mail addresses in outbound data | T1114 |
| `ip_recon_lookup` | ip-api, ipify, ifconfig.me, … (incl. `fields=hosting` sandbox checks) | T1016 |
| `cloud_staging` | Drive, OneDrive, Dropbox, Mega, Discord CDN, GitHub raw, Pastebin, transfer.sh … | T1105 |
| `dyndns_domain`, `tor_traffic`, `irc_botnet` | DuckDNS / No-IP / ddns.net, .onion / Tor, IRC bot channels | T1568 · T1090.003 · T1071 |
| `exfil_webhook`, `malware_gate_post`, `suspicious_user_agent` | Discord / Telegram / Slack hooks, `gate.php`/`fre.php` panels, fake-IE7 / empty / scripted UAs | T1567 · T1041 · T1071.001 |
| `ransom_note`, `secret_leak`, `office_macro`, `disguised_executable`, `mail_malicious_attachment`, `smtp_spam_bot` | Ransom notes, private keys / API tokens / Luhn-valid cards, VBA macros, `invoice.pdf.exe`, dangerous attachments, spam bots | T1486 · T1552 · T1566.001 · T1036.007 · T1071.003 |

On a real *GuLoader → AgentTesla → FTP exfil* capture (353 packets) the score went from 26 ("medium") to **100 / critical** with the whole chain explained and both stolen-data files delivered in the ZIP.

## Languages

English is the default everywhere; Persian is one switch away.

- CLI: `--lang en|fa` (or `PCAP_LANG=fa`), `--help` and all messages are translated.
- HTML report: 🌐 button in the sidebar flips language **and** direction (LTR/RTL) instantly, including rule texts, evidence and plain-language explanations.
- Desktop app: Settings → *Language / زبان* (saved in `~/.pcap_analyzer/config.json`, restart to apply).
- The legacy `classic` HTML report remains Persian-only; the default `cyber` report is fully bilingual.

## Install & run

```bash
pip install -r requirements.txt              # pillow (GUI)
pip install -r requirements-optional.txt     # pyzipper (AES ZIP), brotli, scapy fallback

python pcap_analyzer.py                       # GUI
python pcap_analyzer.py capture.pcap --cli    # CLI
python pcap_analyzer.py capture.pcap --cli --theme matrix --material terminal -o out/
python pcap_analyzer.py --list-themes
python pcap_analyzer.py --doctor
```

Python 3.9+. The core engine needs only the standard library.

## CLI options (new in v8)

| Flag | Meaning |
|---|---|
| `--theme ID` | neon-night (default), matrix, synthwave, crimson-ops, amber-terminal, ice-circuit, toxic-lime, paper-light |
| `--material M` | glass · solid · hologram · terminal |
| `--report-style S` | cyber · classic · both |
| `--formats LIST` | comma list of html,json,csv,rules,iocs |
| `--no-extract` | don't extract files / no ZIP |
| `--extract-scope` | `all` or `downloads` (skip web HTML/JS/CSS/JSON) |
| `--zip-password PW` | ZIP password (default `infected`; needs pyzipper) |
| `--max-extract-mb N` | cap on extracted data |
| `--max-stream-mb N`, `--max-mem-mb N` | per-stream / total reassembly memory caps |
| `--no-fast` | force the legacy scapy path |
| `--sample-mode`, `--ioc-file`, `--no-defang`, `--unmask`, `--max-packets`, `--no-bundle` | as in v7 |

## Output folder

`<name>_pcap_report.html` (cyber report) · `.json` · `_findings.csv` · `_protocol_events.csv` · `_suricata.rules` · `_hunt.yar` · `_iocs_defanged.txt` · **`<name>_extracted_files.zip`** · `_extracted_manifest.json/.csv` · `reports_bundle.zip`.

## Working with the ZIP — safety

Extracted files can be **real malware**.
- With **pyzipper** installed the ZIP is AES-256 encrypted, password **`infected`**.
- Without it the ZIP is plain, and risky files (executables, scripts, etc.) are stored as neutral `*.sample` XOR containers (restore with `--restore FILE.sample`).
- Open/restore only inside an isolated VM. Never double-click extracted executables.

## The report

Views: **Overview · Protocols · Routes · Files (ZIP explorer: tree/table, filters, search, previews, hashes, CSV export) · Findings · Intel · Stats**. Click a protocol → tabs of its events; click a route (host ↔ host) → everything exchanged on it, including its files. All data is rendered with `textContent` (no HTML injection from hostile captures).

## Architecture

| Module | Role |
|---|---|
| `pcap_fastio.py` | mmap pcap/pcapng reader, link/IP/TCP/UDP decode, DNS/DHCP/SNMP/SMB2/TLS parsers |
| `pcap_protocols.py` | protocol hub: events, flows, HTTP/FTP/mail/TFTP extraction |
| `pcap_extract.py` | type sniffing, previews, `FileStore` (ZIP, manifest, safe modes) |
| `pcap_report_cyber.py` | single-file cyber HTML report |
| `pcap_themes.py` | themes/materials shared by report and GUI |
| `pcap_analyzer.py` | engine, detections, CLI, Tk GUI |

## Tests

```bash
pip install pytest
pytest -q tests
```
`tests/make_native_pcap.py` builds a harmless capture (fake PE header, no real malware) without scapy. The legacy `test_smoke.py` is skipped if scapy is missing.

## Honest limitations

- Encrypted traffic (TLS/SSH/QUIC) can't be extracted without keys; only metadata (SNI, ALPN, JA3) is shown.
- Extraction is capped by memory/size limits; truncated or out-of-order captures may yield partial files (flagged).
- The Tk GUI and the AES-ZIP path could not be executed in the development sandbox (no display, no pyzipper); the static checks and CLI/report paths were tested. Please report issues.

MIT License · by mr-coder20
