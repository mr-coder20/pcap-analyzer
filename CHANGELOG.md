# Changelog

## 8.0.0 — Cyber release
- **New native engine** (`pcap_fastio.py`): pure-Python mmap pcap/pcapng reader, Ethernet/VLAN/SLL/SLL2/Raw/Null, native DNS/DHCP/SNMP/SMB2/TLS parsers. scapy is now optional.
- **Protocol hub** (`pcap_protocols.py`): per-protocol events and per-route (host↔host) drill-down for HTTP, DNS, TLS, FTP, SMTP/POP3, SMB, DHCP, TFTP, ARP, ICMP…
- **Exact file extraction into ZIP** (`pcap_extract.py`): HTTP (Content-Length / chunked / until-close, gzip/deflate/brotli, Content-Disposition names, multipart & PUT uploads), FTP data channels, SMTP/POP3 attachments, TFTP, SMB names. Original names kept under `PROTO/host/name`; MANIFEST.json/.csv/README.txt included.
- **Safe handling**: AES-256 ZIP (`infected`) when pyzipper is present; otherwise risky files are stored as neutral `.sample` (XOR) containers.
- **Cyber HTML report** (`pcap_report_cyber.py`): 8 dark-cyber themes + print theme, 4 materials, effects, RTL/LTR, simple mode, ZIP explorer, clickable protocols & routes. XSS-hardened (textContent only, `<` escaped in embedded JSON).
- GUI: theme/material pickers, new Protocols & Files page.
- CLI: `--theme --material --report-style --formats --list-themes --no-extract --extract-scope --zip-password --max-extract-mb --max-stream-mb --max-mem-mb --no-fast`.
- Speed: ~3× faster on large captures (fast path, no 1 MB URL-decode, byte-translate heuristics, regex gating).
- Fix: crash in `stats()` for captures shorter than one second.
- **Threat engine** (`pcap_threats.py`): 17 new content-aware rules incl. infostealer FTP/SMTP exfiltration, credential-dump content, GuLoader/AgentTesla-style infection-chain correlation, IP-lookup / cloud-staging / dyn-DNS / Tor / IRC / webhook detection, ransom notes, leaked secrets, Office macros, disguised executables.
- **Bilingual**: English default, Persian via `--lang fa`, report 🌐 toggle (language + RTL/LTR), GUI language setting.
- Tests: `tests/test_native.py` (scapy-free), incl. a synthetic stealer-chain regression and language tests.
