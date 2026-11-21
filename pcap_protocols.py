# -*- coding: utf-8 -*-
"""
pcap_protocols — «چه اتفاقی در هر پروتکل و هر مسیر افتاد؟»
===========================================================
ProtocolHubMixin به PcapAnalyzer اضافه می‌شود و:
  • هر جریان (flow) و هر مسیر (میزبان↔میزبان) را با شمارنده‌ها ثبت می‌کند
  • پروتکل واقعی هر جریان را از محتوا تشخیص می‌دهد (نه فقط شماره پورت)
  • برای هر پروتکل رویدادهای معنادار می‌سازد: تراکنش‌های HTTP، پرسش/پاسخ DNS، TLS، FTP، SMTP، POP3، SMB، DHCP ...
  • فایل‌های منتقل‌شده را (HTTP دانلود/آپلود، FTP، SMTP/POP3 پیوست، TFTP) با نام واقعی استخراج و در ZIP می‌ریزد

Author: mr-coder20 · https://github.com/mr-coder20/pcap-analyzer · MIT
"""
from __future__ import annotations

import base64
import bisect
import collections
import email
import email.policy
import ipaddress
import re
import struct
import time
import zlib
from urllib.parse import unquote, unquote_plus, urlsplit

import pcap_fastio as FIO
from pcap_extract import FileStore, filename_from_headers, MIME_EXT, sniff_type, safe_name

try:
    import brotli  # type: ignore
    _HAS_BROTLI = True
except ImportError:  # pragma: no cover
    _HAS_BROTLI = False

# ------------------------------------------------------------------------------------------------
PROTO_ORDER = ["HTTP", "TLS", "DNS", "FTP", "SMTP", "POP3", "IMAP", "SMB", "SSH", "RDP", "Telnet", "DHCP", "ICMP", "ARP",
               "TFTP", "SNMP", "NTP", "Kerberos", "LDAP", "IRC", "VNC", "SIP", "mDNS", "LLMNR", "NBNS", "SSDP", "Syslog",
               "QUIC", "BitTorrent", "TCP", "UDP"]

PORT_PROTO = {
    80: "HTTP", 8080: "HTTP", 8000: "HTTP", 8008: "HTTP", 8888: "HTTP", 3128: "HTTP", 443: "TLS", 8443: "TLS", 9443: "TLS",
    993: "TLS", 995: "TLS", 465: "TLS", 636: "TLS", 22: "SSH", 21: "FTP", 25: "SMTP", 587: "SMTP", 110: "POP3", 143: "IMAP",
    445: "SMB", 139: "SMB", 3389: "RDP", 23: "Telnet", 88: "Kerberos", 389: "LDAP", 6667: "IRC", 6697: "IRC", 5900: "VNC",
    5060: "SIP", 5061: "SIP", 514: "Syslog", 69: "TFTP", 123: "NTP", 161: "SNMP", 162: "SNMP", 53: "DNS", 5353: "mDNS",
    5355: "LLMNR", 137: "NBNS", 138: "NBNS", 1900: "SSDP", 67: "DHCP", 68: "DHCP",
}
ENCRYPTED = {"TLS", "SSH", "RDP", "QUIC"}          # بازسازی جریان برایشان بی‌فایده است
HTTP_METHODS_B = (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ", b"PATCH ", b"CONNECT ", b"TRACE ",
                  b"PROPFIND ", b"REPORT ")

RULE_PROTO_PREFIX = (("http_", "HTTP"), ("ek_", "HTTP"), ("exe_over_http", "HTTP"), ("xor_mal", "HTTP"),
                     ("exploit_kit", "HTTP"), ("scanner_ua", "HTTP"), ("sensitive_path", "HTTP"), ("script_download", "HTTP"),
                     ("malware_c2", "HTTP"), ("dns", "DNS"), ("dga", "DNS"), ("doh_", "DNS"), ("ja3", "TLS"), ("tls_", "TLS"),
                     ("smb", "SMB"), ("ftp", "FTP"), ("mail_", "SMTP"), ("telnet", "Telnet"), ("kerberos", "Kerberos"),
                     ("arp", "ARP"), ("dhcp", "DHCP"), ("icmp", "ICMP"), ("ping_", "ICMP"), ("snmp", "SNMP"),
                     ("llmnr", "LLMNR"))


def rule_proto(rid: str) -> str | None:
    for pre, pr in RULE_PROTO_PREFIX:
        if rid.startswith(pre):
            return pr
    return None


def _priv(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_loopback or a.is_link_local or a.is_multicast
    except ValueError:
        return True


def _ts_str(ts):
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(float(ts))) + ".%03d" % int((float(ts) % 1) * 1000)
    except Exception:
        return "-"


REQ_START = re.compile(rb"(GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH|CONNECT|TRACE|PROPFIND|REPORT) [^\r\n ]{1,4096} HTTP/1\.[01]\r\n")
RESP_START = re.compile(rb"HTTP/1\.[01] [0-9]{3}[^\r\n]{0,200}\r\n")
SENS_HDR = {"authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token"}


# ================================================================================================
class ProtocolHubMixin:
    # ------------------------------------------------------------------ init
    def _init_hub(self):
        self.flows = {}                       # (l4, a, ap, b, bp) → [pk_ab, by_ab, pk_ba, by_ba, t0, t1, n0, proto, flags, payload_ab, payload_ba]
        self.flow_cap = 400000
        self.flow_overflow = 0
        self.hub_events = collections.defaultdict(list)
        self.hub_total = collections.Counter()
        self.hub_cap = 6000
        self._dns_pending = collections.OrderedDict()
        self._tls_seen = {}
        self.ftp_sessions = collections.defaultdict(list)       # (c,cp,s,sp) → [(n, ts, dir, line)]
        self.tftp = {}                                           # (client, cport, server) → state
        self.smb_seen = collections.Counter()
        self.file_store = None
        self.file_records = []
        self.http_txns = []
        self.http_orphans = 0
        self._hdr_budget = 700
        self._banners = {}
        self._text_events = collections.Counter()
        self._hub_files_done = False
        self._carved_pending = []
        self.total_stream_mem = 0
        self.arp_events_seen = set()
        self.dhcp_clients = {}

    # ------------------------------------------------------------------ helpers
    def hub_event(self, proto, kind, ts, n, src, sp, dst, dp, summary, d=None, flag=0, fid=None):
        """flag: 0 عادی · 1 قابل‌توجه · 2 خطرناک"""
        self.hub_total[proto] += 1
        lst = self.hub_events[proto]
        if len(lst) >= self.hub_cap:
            return None
        ev = {"i": len(lst), "p": proto, "t": ts, "ts": _ts_str(ts) if ts else "-", "n": n, "a": src, "ap": sp,
              "b": dst, "bp": dp, "k": kind, "s": summary, "d": d or {}, "x": flag}
        if fid is not None:
            ev["f"] = fid
        lst.append(ev)
        return ev

    def hub_flow(self, l4, src, sp, dst, dp, size, ts, n, fl=0, plen=0):
        """به‌روزرسانی شمارنده‌های جریان. برمی‌گرداند: رکورد جریان"""
        k = (l4, src, sp, dst, dp)
        f = self.flows.get(k)
        if f is not None:
            f[0] += 1
            f[1] += size
            f[5] = ts
            f[9] += plen
            if fl:
                f[8] |= fl
            return f
        rk = (l4, dst, dp, src, sp)
        f = self.flows.get(rk)
        if f is not None:
            f[2] += 1
            f[3] += size
            f[5] = ts
            f[10] += plen
            if fl:
                f[8] |= fl
            return f
        if len(self.flows) >= self.flow_cap:
            self.flow_overflow += 1
            return None
        proto = PORT_PROTO.get(dp) or PORT_PROTO.get(sp) or l4
        f = [1, size, 0, 0, ts, ts, n, proto, fl, plen, 0]
        self.flows[k] = f
        return f

    def hub_detect(self, f, p, sp, dp, l4="TCP"):
        """تشخیص پروتکل از محتوای اولین payload جریان؛ نام را برمی‌گرداند"""
        if f is None or not p:
            return None
        cur = f[7]
        if cur not in ("TCP", "UDP") and cur in PORT_PROTO.values() and f[8] & 0x100:
            return cur                                                  # قبلاً با محتوا قطعی شده
        name = None
        h = p[:32]
        if l4 == "TCP":
            if h.startswith(HTTP_METHODS_B) or h.startswith(b"HTTP/1."):
                name = "HTTP"
            elif h[:1] in (b"\x16", b"\x17", b"\x15", b"\x14") and h[1:2] == b"\x03" and h[2:3] in (b"\x00", b"\x01", b"\x02", b"\x03", b"\x04"):
                name = "TLS"
            elif h.startswith(b"SSH-"):
                name = "SSH"
            elif h.startswith(b"RFB "):
                name = "VNC"
            elif h.startswith(b"\x13BitTorrent protocol"):
                name = "BitTorrent"
            elif h[4:8] in (b"\xffSMB", b"\xfeSMB") or h[:4] in (b"\xffSMB", b"\xfeSMB"):
                name = "SMB"
            elif h[:2] == b"\x03\x00" and (b"mstshash" in p[:120] or p[5:6] == b"\xe0" or p[5:6] == b"\xd0"):
                name = "RDP"
            elif h.startswith(b"220") and (sp in (21, 2121) or b"FTP" in p[:120].upper()):
                name = "FTP"
            elif h.startswith((b"220 ", b"220-")) and (b"SMTP" in p[:160].upper() or sp in (25, 587, 465) or b"ESMTP" in p[:160].upper()):
                name = "SMTP"
            elif h.startswith((b"EHLO ", b"HELO ")):
                name = "SMTP"
            elif h.startswith((b"USER ", b"PASS ")) and dp in (21, 2121):
                name = "FTP"
            elif h.startswith(b"+OK") and (sp == 110 or b"POP3" in p[:100].upper()):
                name = "POP3"
            elif h.startswith(b"* OK") and (sp == 143 or b"IMAP" in p[:120].upper()):
                name = "IMAP"
            elif h.startswith((b"NICK ", b"JOIN ", b"PING :", b":")) and (dp in (6667, 6697, 6660, 7000) or sp in (6667, 6697) or b" PRIVMSG " in p[:200]):
                name = "IRC"
            elif h.startswith((b"INVITE sip:", b"REGISTER sip:", b"SIP/2.0", b"OPTIONS sip:")):
                name = "SIP"
        else:
            if sp == 53 or dp == 53:
                name = "DNS"
            elif sp in (5353,) or dp in (5353,):
                name = "mDNS"
            elif sp in (5355,) or dp in (5355,):
                name = "LLMNR"
            elif sp in (137,) or dp in (137,):
                name = "NBNS"
            elif sp in (67, 68) or dp in (67, 68):
                name = "DHCP"
            elif dp == 123 or sp == 123:
                name = "NTP"
            elif dp in (161, 162) or sp in (161, 162):
                name = "SNMP"
            elif dp == 1900 or sp == 1900:
                name = "SSDP"
            elif dp == 514:
                name = "Syslog"
            elif dp == 69:
                name = "TFTP"
            elif dp == 88 or sp == 88:
                name = "Kerberos"
            elif (dp == 443 or sp == 443) and len(p) > 20 and (p[0] & 0x80):
                name = "QUIC"
            elif h.startswith((b"INVITE sip:", b"REGISTER sip:", b"SIP/2.0", b"OPTIONS sip:")):
                name = "SIP"
            elif h.startswith((b"M-SEARCH", b"NOTIFY * HTTP")):
                name = "SSDP"
        if name:
            f[7] = name
            f[8] |= 0x100
        return name

    # ------------------------------------------------------------------ packet-time: TCP payload
    def hub_tcp(self, n, ts, src, dst, sp, dp, p, f):
        """رویدادهای سبک پروتکل‌های متنی/بانر (در لحظه پکت)"""
        proto = f[7] if f else PORT_PROTO.get(dp) or PORT_PROTO.get(sp) or "TCP"
        if proto == "FTP":
            self._hub_ftp(n, ts, src, dst, sp, dp, p)
        elif proto == "SMTP" or proto == "POP3" or proto == "IMAP":
            self._hub_mail_cmd(proto, n, ts, src, dst, sp, dp, p)
        elif proto == "SMB":
            self._hub_smb(n, ts, src, dst, sp, dp, p)
        elif proto == "SSH":
            if p.startswith(b"SSH-"):
                banner = p.split(b"\r\n", 1)[0].decode("latin-1", "replace")[:120]
                if (src, sp, banner) not in self._banners:
                    self._banners[(src, sp, banner)] = 1
                    self.hub_event("SSH", "banner", ts, n, src, sp, dst, dp, banner, {"banner": banner})
        elif proto == "VNC":
            if p.startswith(b"RFB "):
                self.hub_event("VNC", "banner", ts, n, src, sp, dst, dp, p[:12].decode("latin-1", "replace").strip(), {})
        elif proto == "RDP":
            m = re.search(rb"Cookie: mstshash=([^\r\n]{1,64})", p[:200])
            if m:
                u = m.group(1).decode("latin-1", "replace")
                self.hub_event("RDP", "login-cookie", ts, n, src, sp, dst, dp, f"mstshash={u}", {"user": u}, 1)
        elif proto == "IRC":
            for line in p[:1500].split(b"\r\n")[:6]:
                if line.startswith((b"NICK ", b"JOIN ", b"PRIVMSG ", b"USER ", b"PASS ", b"NOTICE ")) or b" PRIVMSG " in line[:80]:
                    t = line.decode("latin-1", "replace")[:160]
                    if t.startswith("PASS "):
                        t = "PASS ***"
                    self.hub_event("IRC", "message", ts, n, src, sp, dst, dp, t, {}, 1)
        elif proto == "Telnet":
            txt = bytes(b for b in p[:400] if 32 <= b < 127 or b in (10, 13, 9)).decode("ascii", "replace").strip()
            if txt and self._text_events["telnet"] < 1500:
                self._text_events["telnet"] += 1
                self.hub_event("Telnet", "data", ts, n, src, sp, dst, dp, txt[:160].replace("\r", " ").replace("\n", " ⏎ "), {"text": txt[:600]},
                               1 if re.search(r"(?i)login|password|passwd|username", txt) else 0)
        elif proto == "SIP":
            line = p.split(b"\r\n", 1)[0].decode("latin-1", "replace")[:140]
            self.hub_event("SIP", "message", ts, n, src, sp, dst, dp, line, {})
        elif proto == "LDAP" and p[:1] == b"\x30":
            pass
        elif proto == "TLS":
            self._hub_tls(n, ts, src, dst, sp, dp, p)

    # ---- TLS
    def _hub_tls(self, n, ts, src, dst, sp, dp, p):
        if len(p) < 48 or p[0] != 0x16:
            return
        hs = p[5]
        if hs == 1:                                   # ClientHello
            try:
                ver, sni, ja3, _ = self._tls_ja3(p)
            except Exception:
                ver, sni, ja3 = 0, "", ""
            alpn, sv, ncs = FIO.tls_client_extras(p)
            key = (src, sp, dst, dp)
            self._tls_seen[key] = len(self.hub_events["TLS"])
            v = FIO.TLS_VERSIONS.get(max(sv) if sv else ver, "?")
            d = {"sni": sni, "version": v, "record_version": FIO.TLS_VERSIONS.get(ver, hex(ver)), "ja3": ja3, "alpn": ",".join(alpn),
                 "ciphers_offered": ncs, "known_client": self._ja3_name(ja3)}
            flag = 1 if (ver in (0x0300, 0x0301, 0x0302) and not sv) else 0
            if d["known_client"] and d["known_client"][1]:
                flag = 2
            self.hub_event("TLS", "client-hello", ts, n, src, sp, dst, dp,
                           f"{sni or dst}  ·  {v}" + (f"  ·  ALPN {','.join(alpn)}" if alpn else ""), d, flag)
        elif hs == 2:                                 # ServerHello
            ver, cs = FIO.tls_server_info(p)
            idx = self._tls_seen.get((dst, dp, src, sp))
            if idx is not None and idx < len(self.hub_events["TLS"]):
                self.hub_events["TLS"][idx]["d"]["server_version"] = FIO.TLS_VERSIONS.get(ver, hex(ver))
                self.hub_events["TLS"][idx]["d"]["cipher_suite"] = "0x%04x" % cs
            else:
                self.hub_event("TLS", "server-hello", ts, n, src, sp, dst, dp, f"{FIO.TLS_VERSIONS.get(ver, hex(ver))}  cipher 0x{cs:04x}", {})

    # ---- FTP
    def _hub_ftp(self, n, ts, src, dst, sp, dp, p):
        is_client = dp in (21, 2121) or (sp not in (21, 2121) and dp > sp)
        key = (src, sp, dst, dp) if is_client else (dst, dp, src, sp)
        for raw in p[:2000].split(b"\r\n"):
            line = raw.decode("latin-1", "replace").strip()
            if not line:
                continue
            self.ftp_sessions[key].append((n, ts, "c" if is_client else "s", line))
            if is_client:
                cmd, _, arg = line.partition(" ")
                cmd = cmd.upper()
                if cmd == "PASS":
                    arg = "***"
                flag = 1 if cmd in ("USER", "PASS", "RETR", "STOR", "DELE", "SITE", "RNFR", "MKD", "RMD") else 0
                self.hub_event("FTP", "command", ts, n, src, sp, dst, dp, f"{cmd} {arg}".strip(), {"command": cmd, "arg": arg}, flag)
            else:
                m = re.match(r"(\d{3})[ -](.*)", line)
                if m:
                    code = int(m.group(1))
                    if code in (220, 227, 229, 230, 226, 250, 331, 425, 426, 530, 550, 150, 125, 421):
                        self.hub_event("FTP", "reply", ts, n, src, sp, dst, dp, line[:150], {"code": code, "text": m.group(2)[:200]},
                                       1 if code in (530, 550, 421) else 0)

    # ---- SMTP / POP3 / IMAP
    def _hub_mail_cmd(self, proto, n, ts, src, dst, sp, dp, p):
        line = p.split(b"\r\n", 1)[0].decode("latin-1", "replace")[:200]
        up = line.upper()
        client = dp in (25, 587, 110, 143, 2525)
        interesting = up.startswith(("EHLO", "HELO", "MAIL FROM", "RCPT TO", "AUTH", "STARTTLS", "USER ", "PASS ", "RETR", "LIST",
                                     "STAT", "QUIT", "LOGIN", "SELECT", "FETCH", "DATA")) or " LOGIN " in up or " FETCH " in up
        if client and interesting:
            if up.startswith(("PASS ", "AUTH PLAIN", "AUTH LOGIN")) or " LOGIN " in up:
                line = re.sub(r"(?i)(PASS |AUTH PLAIN |LOGIN \S+ )\S+", r"\1***", line)
            self.hub_event(proto, "command", ts, n, src, sp, dst, dp, line, {"command": line.split(" ", 1)[0]},
                           1 if up.startswith(("PASS", "AUTH", "USER", "LOGIN")) else 0)
        elif not client and p[:3].isdigit() and p[:3] in (b"220", b"250", b"354", b"535", b"550", b"221", b"235", b"554", b"451", b"452"):
            self.hub_event(proto, "reply", ts, n, src, sp, dst, dp, line, {}, 1 if p[:3] in (b"535", b"550", b"554") else 0)

    # ---- SMB
    def _hub_smb(self, n, ts, src, dst, sp, dp, p):
        if b"\xffSMB" in p[:64]:
            key = (src, dst, "SMB1")
            if key not in self.smb_seen:
                self.smb_seen[key] = 1
                self.hub_event("SMB", "smb1", ts, n, src, sp, dst, dp, "SMBv1 traffic (legacy, vulnerable)", {"version": "SMB1"}, 1)
            return
        if b"\xfeSMB" not in p[:2048]:
            return
        for cmd, resp, detail in FIO.parse_smb2(p[:8192]):
            if resp or not detail:
                continue
            key = (src, dst, cmd, detail)
            if key in self.smb_seen:
                continue
            self.smb_seen[key] = 1
            flag = 1 if (cmd == "TREE_CONNECT" and re.search(r"(?i)\\(ipc|admin|c)\$", detail)) else 0
            if cmd == "CREATE" and re.search(r"(?i)\.(exe|dll|ps1|bat|vbs|scr)$|svcctl|psexe", detail):
                flag = 2 if re.search(r"(?i)svcctl|psexe", detail) else 1
            self.hub_event("SMB", cmd.lower(), ts, n, src, sp, dst, dp, f"{cmd}  {detail}", {"command": cmd, "path": detail}, flag)

    # ------------------------------------------------------------------ packet-time: UDP
    def hub_udp(self, n, ts, src, dst, sp, dp, p, f):
        proto = f[7] if f else "UDP"
        if proto == "UDP" and self.tftp and p[:2] == b"\x00\x03":
            self._hub_tftp(n, ts, src, dst, sp, dp, p)
            return
        if proto == "DNS":
            self._hub_dns(n, ts, src, dst, sp, dp, p)
        elif proto == "DHCP":
            self._hub_dhcp(n, ts, src, dst, sp, dp, p)
        elif proto == "SNMP":
            com = FIO.parse_snmp_community(p)
            if com is not None:
                shown = com[:2] + "***" if self.cfg.mask_passwords and len(com) > 2 else com
                self.hub_event("SNMP", "request" if dp in (161, 162) else "response", ts, n, src, sp, dst, dp,
                               f"community={shown}", {"community": shown}, 1 if com.lower() in ("public", "private") else 0)
        elif proto == "TFTP":
            self._hub_tftp(n, ts, src, dst, sp, dp, p)
        elif proto in ("mDNS", "LLMNR", "NBNS"):
            msg = FIO.parse_dns(p) if proto != "NBNS" else None
            if msg and msg["qd"]:
                self.hub_event(proto, "query" if not msg["qr"] else "reply", ts, n, src, sp, dst, dp,
                               ", ".join(q for q, _ in msg["qd"])[:140], {"names": [q for q, _ in msg["qd"]][:6]})
        elif proto == "SSDP":
            line = p.split(b"\r\n", 1)[0].decode("latin-1", "replace")[:120]
            if line:
                self.hub_event("SSDP", "message", ts, n, src, sp, dst, dp, line, {})
        elif proto == "Syslog":
            txt = p[:300].decode("latin-1", "replace").strip()
            if txt and self._text_events["syslog"] < 1500:
                self._text_events["syslog"] += 1
                self.hub_event("Syslog", "message", ts, n, src, sp, dst, dp, txt[:160], {"text": txt})
        elif proto == "NTP" and len(p) >= 48:
            mode = p[0] & 7
            if (src, dst) not in self._banners:
                self._banners[(src, dst)] = 1
                self.hub_event("NTP", "sync", ts, n, src, sp, dst, dp, f"mode {mode} · v{(p[0] >> 3) & 7}", {})

    def _hub_dns(self, n, ts, src, dst, sp, dp, p):
        msg = FIO.parse_dns(p)
        if msg is None:
            return
        if not msg["qr"]:                                          # query
            for name, qt in msg["qd"][:1]:
                key = (src, dst, msg["id"], name)
                ev = self.hub_event("DNS", "query", ts, n, src, sp, dst, dp, f"{FIO.QTYPES.get(qt, qt)}  {name}",
                                    {"name": name, "qtype": FIO.QTYPES.get(qt, str(qt)), "answers": [], "rcode": "", "txid": msg["id"]})
                if ev is not None:
                    self._dns_pending[key] = ev
                    if len(self._dns_pending) > 20000:
                        self._dns_pending.popitem(last=False)
        else:                                                      # response
            qname = msg["qd"][0][0] if msg["qd"] else ""
            key = (dst, src, msg["id"], qname)
            ev = self._dns_pending.pop(key, None)
            answers = [f"{FIO.QTYPES.get(t, t)} {d}" for _, t, _ttl, d in msg["an"]][:12]
            rc = FIO.RCODES.get(msg["rcode"], str(msg["rcode"]))
            if ev is not None:
                ev["d"]["answers"] = answers
                ev["d"]["rcode"] = rc
                ev["d"]["rtt_ms"] = round((ts - ev["t"]) * 1000, 2) if ts and ev["t"] else None
                ev["d"]["ttl"] = msg["an"][0][2] if msg["an"] else None
                if rc == "NXDOMAIN":
                    ev["x"] = 1
                ev["s"] = ev["s"] + ("   →   " + " , ".join(answers[:3]) if answers else f"   →   {rc}")
            elif qname:
                self.hub_event("DNS", "response", ts, n, dst, dp, src, sp, f"{FIO.QTYPES.get(msg['qd'][0][1], '?')}  {qname}   →   " +
                               (" , ".join(answers[:3]) or rc),
                               {"name": qname, "qtype": "", "answers": answers, "rcode": rc}, 1 if rc == "NXDOMAIN" else 0)

    def _hub_dhcp(self, n, ts, src, dst, sp, dp, p):
        d = FIO.parse_dhcp(p)
        if not d or not d["msg"]:
            return
        who = d["host"] or d["mac"]
        ip = d["yiaddr"] if d["yiaddr"] != "0.0.0.0" else (d["req_ip"] or "")
        if d["msg"] in ("ACK", "REQUEST", "OFFER", "DISCOVER", "INFORM", "RELEASE") and d["mac"]:
            self.dhcp_clients[d["mac"]] = (who, ip or self.dhcp_clients.get(d["mac"], ("", ""))[1])
        self.hub_event("DHCP", d["msg"].lower(), ts, n, src, sp, dst, dp,
                       f"{d['msg']}  {who}" + (f"  → {ip}" if ip else ""),
                       {"message": d["msg"], "mac": d["mac"], "hostname": d["host"], "ip": ip, "server": d["server"], "vendor": d["vendor"]})

    def _hub_tftp(self, n, ts, src, dst, sp, dp, p):
        if len(p) < 4:
            return
        op = struct.unpack_from("!H", p, 0)[0]
        if op in (1, 2):                                            # RRQ / WRQ
            parts = p[2:].split(b"\x00")
            fname = parts[0].decode("latin-1", "replace")[:200] if parts else ""
            mode = parts[1].decode("latin-1", "replace") if len(parts) > 1 else ""
            self.tftp[(src, sp, dst)] = {"op": op, "name": fname, "mode": mode, "blocks": {}, "ts": ts, "n": n, "server": dst, "client": src,
                                         "cport": sp, "dir": "download" if op == 1 else "upload", "last": 0}
            self.hub_event("TFTP", "read" if op == 1 else "write", ts, n, src, sp, dst, dp, f"{'RRQ' if op == 1 else 'WRQ'}  {fname}  ({mode})",
                           {"filename": fname, "mode": mode}, 1)
        elif op == 3:                                               # DATA
            blk = struct.unpack_from("!H", p, 2)[0]
            for key, st in self.tftp.items():
                if st["dir"] == "download" and st["client"] == dst and st["cport"] == dp and st["server"] == src:
                    if len(st["blocks"]) < 200000 and blk not in st["blocks"]:
                        st["blocks"][blk] = p[4:]
                    break
                if st["dir"] == "upload" and st["client"] == src and st["cport"] == sp and st["server"] == dst:
                    if len(st["blocks"]) < 200000 and blk not in st["blocks"]:
                        st["blocks"][blk] = p[4:]
                    break

    # ------------------------------------------------------------------ ARP / ICMP
    def hub_arp(self, n, ts, op, psrc, pdst, hwsrc, hwdst):
        key = (op, psrc, hwsrc)
        if key in self.arp_events_seen or len(self.arp_events_seen) > 8000:
            return
        self.arp_events_seen.add(key)
        if op == 1:
            self.hub_event("ARP", "who-has", ts, n, psrc, 0, pdst, 0, f"who-has {pdst}? tell {psrc} ({hwsrc})", {"sender_mac": hwsrc})
        else:
            self.hub_event("ARP", "is-at", ts, n, psrc, 0, pdst, 0, f"{psrc} is-at {hwsrc}", {"sender_mac": hwsrc})

    def hub_icmp(self, n, ts, src, dst, typ, code, plen):
        names = {0: "echo-reply", 3: "dest-unreachable", 5: "redirect", 8: "echo-request", 11: "time-exceeded", 13: "timestamp"}
        if typ in (0, 8):
            return                                                  # ping: در شمارنده‌ها / جریان‌ها دیده می‌شود
        self.hub_event("ICMP", names.get(typ, f"type-{typ}"), ts, n, src, 0, dst, 0, f"{names.get(typ, typ)} code {code}", {"type": typ, "code": code},
                       1 if typ == 5 else 0)

    # ================================================================================================
    #  Finish-time: HTTP، فایل‌ها، FTP، SMTP/POP3، TFTP
    # ================================================================================================
    def hub_prepare_store(self):
        if self.file_store is not None or not getattr(self.cfg, "extract_files", True):
            return
        out_dir = self.cfg.out_dir
        if not out_dir:
            return
        import os
        base = getattr(self, "_base_name", "capture")
        try:
            self.file_store = FileStore(out_dir, base, password=getattr(self.cfg, "zip_password", "infected"),
                                        max_total=int(getattr(self.cfg, "max_extract_mb", 1024)) << 20)
        except Exception:
            self.file_store = None

    def hub_add_file(self, data, name, proto, host="", **meta):
        if self.file_store is None or not data:
            return None
        if meta.get("direction") == "carved":
            import hashlib as _h
            sh = _h.sha256(data).hexdigest()
            if any(x["sha256"] == sh for x in self.file_records):
                return None
        scope = getattr(self.cfg, "extract_scope", "all")
        if scope == "downloads" and meta.get("web_resource"):
            return None
        if "ts" in meta and meta["ts"]:
            meta.setdefault("ts_str", _ts_str(meta["ts"]))
        rec = self.file_store.add(data, name, proto, host, meta)
        if rec is not None and rec not in self.file_records:
            self.file_records.append(rec)
            if len(self._peek) < 4000:
                self._peek[rec["id"]] = bytes(data[:300000])
            try:
                self.extra_hash(meta.get("n") or 0, meta.get("ts"), meta.get("flow", ""), rec["sha256"], rec["md5"])
            except Exception:
                pass
        return rec

    # ------------------------------------------------------------------ merge با شاخص زمانی
    @staticmethod
    def _merge_indexed(segments):
        """(stream, offsets[], n_ts[]) — offsets[i] آغاز داده‌ی بسته‌ی i در stream"""
        if not segments:
            return b"", [], []
        capture_order = sorted(segments, key=lambda x: x[2])
        base = int(capture_order[0][0]) & 0xffffffff
        items = []
        for seq, data, n, ts in capture_order:
            raw = int(seq) & 0xffffffff
            delta = ((raw - base + (1 << 31)) & 0xffffffff) - (1 << 31)
            items.append((base + delta, data, n, ts))
        items.sort(key=lambda x: (x[0], x[2]))
        start_seq = items[0][0]
        out = bytearray()
        offs, meta = [], []
        for seq, data, n, ts in items:
            if not data:
                continue
            offset = seq - start_seq
            if offset > len(out):
                out.extend(b"\x00" * min(offset - len(out), 2 * 1024 * 1024))
            if offset < len(out):
                ov = min(len(out) - offset, len(data))
                if ov >= len(data):
                    continue
                data = data[ov:]
                offset += ov
            if offset == len(out):
                offs.append(len(out))
                meta.append((n, ts))
                out.extend(data)
        return bytes(out), offs, meta

    @staticmethod
    def _at(offs, meta, pos):
        if not offs:
            return None, None
        i = bisect.bisect_right(offs, pos) - 1
        n, ts = meta[max(i, 0)]
        return n, ts

    # ------------------------------------------------------------------ HTTP parser
    @staticmethod
    def _http_headers(head: bytes):
        lines = head.split(b"\r\n")
        first = lines[0].decode("latin-1", "replace")
        h = {}
        order = []
        for ln in lines[1:]:
            if b":" not in ln:
                continue
            k, v = ln.split(b":", 1)
            key = k.decode("latin-1", "replace").strip().lower()
            val = v.decode("latin-1", "replace").strip()
            h[key] = (h[key] + ", " + val) if key in h else val
            order.append(key)
        return first, h

    @staticmethod
    def _chunked(data: bytes, pos: int, limit=256 << 20):
        """(decoded, end_pos, complete)"""
        out = bytearray()
        n = len(data)
        while pos < n:
            eol = data.find(b"\r\n", pos)
            if eol < 0:
                return bytes(out), n, False
            try:
                size = int(data[pos:eol].split(b";", 1)[0].strip() or b"0", 16)
            except ValueError:
                return bytes(out), n, False
            pos = eol + 2
            if size == 0:
                end = data.find(b"\r\n\r\n", pos - 2)
                return bytes(out), (end + 4 if end >= 0 else n), True
            if len(out) + size > limit:
                return bytes(out), n, False
            out.extend(data[pos:pos + size])
            if pos + size > n:
                return bytes(out), n, False
            pos += size + 2
        return bytes(out), n, False

    def _parse_http_stream(self, stream: bytes, offs, meta, is_request: bool, methods=None, cap=800):
        rx = REQ_START if is_request else RESP_START
        msgs = []
        pos = 0
        n = len(stream)
        while pos < n and len(msgs) < cap:
            m = rx.match(stream, pos)
            if not m:
                m = rx.search(stream, pos)
                if not m:
                    break
                pos = m.start()
            he = stream.find(b"\r\n\r\n", pos)
            if he < 0:
                he = n
                body_start = n
                complete_head = False
            else:
                body_start = he + 4
                complete_head = True
            head = stream[pos:he]
            first, hdr = self._http_headers(head)
            msg = {"pos": pos, "head": head, "first": first, "h": hdr, "complete_head": complete_head}
            msg["n"], msg["ts"] = self._at(offs, meta, pos)
            idx = len(msgs)
            end = body_start
            body = b""
            complete = True
            te = hdr.get("transfer-encoding", "").lower()
            if is_request:
                parts = first.split(" ", 2)
                msg["method"] = parts[0]
                msg["uri"] = parts[1] if len(parts) > 1 else ""
                msg["version"] = parts[2] if len(parts) > 2 else ""
            else:
                parts = first.split(" ", 2)
                msg["version"] = parts[0]
                try:
                    msg["status"] = int(parts[1])
                except (ValueError, IndexError):
                    msg["status"] = 0
                msg["reason"] = parts[2] if len(parts) > 2 else ""
            no_body = False
            if not is_request:
                st = msg.get("status", 0)
                mth = (methods[idx] if methods and idx < len(methods) else "GET")
                no_body = (100 <= st < 200) or st in (204, 304) or mth == "HEAD" or mth == "CONNECT" and 200 <= st < 300
            elif msg["method"] in ("GET", "HEAD", "DELETE", "OPTIONS", "TRACE", "CONNECT") and "content-length" not in hdr and "chunked" not in te:
                no_body = True
            if complete_head and not no_body:
                if "chunked" in te:
                    body, end, complete = self._chunked(stream, body_start)
                elif "content-length" in hdr:
                    try:
                        cl = int(hdr["content-length"])
                    except ValueError:
                        cl = -1
                    if cl >= 0:
                        end = min(body_start + cl, n)
                        body = stream[body_start:end]
                        complete = len(body) == cl
                        msg["declared"] = cl
                    else:
                        body, end, complete = stream[body_start:], n, False
                elif not is_request:
                    body, end, complete = stream[body_start:], n, True       # تا بستن اتصال
                else:
                    end = body_start
            msg["body"] = body
            msg["end"] = end
            msg["complete"] = complete
            msg["end_ts"] = self._at(offs, meta, max(end - 1, 0))[1]
            msgs.append(msg)
            if not is_request and msg.get("status") == 101:
                break
            pos = max(end, pos + 1)
        return msgs

    @staticmethod
    def _decode_body(body: bytes, hdr: dict):
        enc = hdr.get("content-encoding", "").lower()
        tes = hdr.get("transfer-encoding", "").lower()
        if not body:
            return body, ""
        try:
            if "br" in enc and _HAS_BROTLI:
                out = brotli.decompress(body)
                return (out or body), "br"
            if "gzip" in enc or "gzip" in tes or body[:3] == b"\x1f\x8b\x08":
                obj = zlib.decompressobj(16 + zlib.MAX_WBITS)
                out = obj.decompress(body, 128 << 20)
                try:
                    out += obj.flush()
                except Exception:
                    pass
                return (out or body), "gzip"
            if "deflate" in enc:
                for wb in (zlib.MAX_WBITS, -zlib.MAX_WBITS):
                    try:
                        obj = zlib.decompressobj(wb)
                        out = obj.decompress(body, 128 << 20)
                        return (out or body), "deflate"
                    except zlib.error:
                        continue
        except Exception:
            return body, enc + "?"
        return body, ""

    # ------------------------------------------------------------------ HTTP transactions + files
    def hub_extract_http(self):
        segs = self.tcp_segments
        keys = list(segs.keys())
        done = set()
        merged_cache = {}

        def merged(k):
            if k not in merged_cache:
                merged_cache[k] = self._merge_indexed(segs[k]) if k in segs else (b"", [], [])
            return merged_cache[k]

        for key in keys:
            if key in done:
                continue
            stream, offs, meta = merged(key)
            if not stream:
                continue
            head = stream[:200]
            m = REQ_START.search(head)
            if m is None:
                continue
            c, cp, s, sp = key
            rkey = (s, sp, c, cp)
            done.add(key)
            done.add(rkey)
            reqs = self._parse_http_stream(stream, offs, meta, True)
            rs, roffs, rmeta = merged(rkey) if rkey in segs else (b"", [], [])
            resps = self._parse_http_stream(rs, roffs, rmeta, False, [r["method"] for r in reqs]) if rs else []
            gap = bool(self.tcp_stream_quality.get(rkey, {}).get("has_gap"))
            for i in range(max(len(reqs), len(resps))):
                self._add_txn(c, cp, s, sp, reqs[i] if i < len(reqs) else None, resps[i] if i < len(resps) else None, gap)
            merged_cache.pop(key, None)
            merged_cache.pop(rkey, None)
        # پاسخ‌هایی که درخواستشان در ضبط نیست
        for key in keys:
            if key in done:
                continue
            stream, offs, meta = merged(key)
            if not stream or not RESP_START.match(stream[:64]):
                merged_cache.pop(key, None)
                continue
            s, sp, c, cp = key
            resps = self._parse_http_stream(stream, offs, meta, False)
            gap = bool(self.tcp_stream_quality.get(key, {}).get("has_gap"))
            for r in resps:
                self.http_orphans += 1
                self._add_txn(c, cp, s, sp, None, r, gap)
            merged_cache.pop(key, None)

    def _add_txn(self, c, cp, s, sp, req, resp, gap):
        rh = req["h"] if req else {}
        ph = resp["h"] if resp else {}
        method = req["method"] if req else "?"
        uri = req["uri"] if req else ""
        host = (rh.get("host") or s).strip()
        hostname = host.split(":", 1)[0].strip("[]")
        if uri.startswith("http://") or uri.startswith("https://"):
            try:
                u = urlsplit(uri)
                host = u.netloc or host
                path = (u.path or "/") + ("?" + u.query if u.query else "")
                url = uri
                uri_path = path
            except ValueError:
                url, uri_path = f"http://{host}{uri}", uri
        else:
            url, uri_path = f"http://{host}{uri}" if req else f"http://{s}/", uri
        status = resp.get("status") if resp else None
        ctype = ph.get("content-type", "")
        ts = (req or resp)["ts"]
        n = (req or resp)["n"]
        flow = f"{c}:{cp} → {s}:{sp}"
        flags = []
        rec_file = None
        body_raw = resp["body"] if resp else b""
        body = body_raw
        enc = ""
        if resp and body_raw:
            body, enc = self._decode_body(body_raw, ph)
        partial = bool(resp and (not resp["complete"] or gap or status == 206))
        fname = fsrc = None
        # ---- فایل دانلودشده
        post_noise = method in ("POST", "PUT", "PATCH", "DELETE") and "attachment" not in ph.get("content-disposition", "").lower() \
            and ph.get("content-type", "").split(";")[0].strip().lower() in ("text/plain", "application/json", "text/html", "text/xml", "application/xml", "")
        if resp and body and not post_noise and (status in (200, 203, 206, 226) or (status or 0) // 100 == 2):
            fname, fsrc = filename_from_headers(ph, uri_path, ctype, method)
            web = False
            mime = ctype.split(";", 1)[0].strip().lower()
            if mime in ("text/html", "text/css", "application/javascript", "text/javascript", "application/json", "text/xml",
                        "application/xml", "application/x-javascript", "application/xhtml+xml", "text/plain") and "attachment" not in ph.get("content-disposition", "").lower():
                web = True
            fl = []
            if partial:
                fl.append("partial")
            if enc:
                fl.append(f"decoded-{enc}")
            rec_file = self.hub_add_file(body, fname, "HTTP", hostname, n=n, ts=resp["ts"] or ts, flow=flow, src=s, dst=c, url=url,
                                         direction="download", mime=mime, name_source=fsrc, web_resource=web, flags=fl,
                                         sport=sp, dport=cp, method=method, status=status)
        # ---- آپلود (multipart / PUT)
        up_files = []
        if req and req["body"] and method in ("POST", "PUT", "PATCH"):
            up_files = self._extract_uploads(req, c, cp, s, sp, hostname, url, flow, n, ts)
        # ---- پرچم‌ها
        if rec_file is not None:
            if rec_file["risky"]:
                flags.append("risky-file")
            if rec_file["mismatch"]:
                flags.append("ext-mismatch")
        try:
            ipo = ipaddress.ip_address(hostname)
            if not ipo.is_private:
                flags.append("ip-host")
        except ValueError:
            pass
        if status and status >= 400:
            flags.append("error")
        if status and 300 <= status < 400:
            flags.append("redirect")
        try:
            if method == "POST" and req and int(rh.get("content-length", "0") or 0) > 1_000_000:
                flags.append("big-post")
        except ValueError:
            pass
        sev = 2 if ("risky-file" in flags and ("ip-host" in flags or "ext-mismatch" in flags)) else (1 if flags and any(f in flags for f in ("risky-file", "ext-mismatch", "ip-host", "big-post")) else 0)
        dur = None
        if req and resp and req["ts"] and resp["end_ts"]:
            dur = round(max(resp["end_ts"] - req["ts"], 0), 4)
        d = {
            "method": method, "host": host, "uri": uri_path, "url": url, "status": status, "reason": resp.get("reason") if resp else "",
            "ctype": ctype.split(";")[0], "clen": ph.get("content-length"), "size": len(body) if resp else 0, "wire": len(body_raw), "enc": enc,
            "server": ph.get("server", ""), "ua": rh.get("user-agent", ""), "referer": rh.get("referer", ""), "location": ph.get("location", ""),
            "filename": fname, "name_src": fsrc, "partial": partial, "dur": dur, "flags": flags, "version": (resp or req).get("version", ""),
            "cookie_names": [x.split("=", 1)[0].strip() for x in ph.get("set-cookie", "").split(", ") if "=" in x][:6],
            "uploads": [{"name": u["name"], "size": u["size"], "id": u["id"]} for u in up_files],
            "rsize_req": len(req["body"]) if req else 0, "complete": bool(resp and resp["complete"]),
        }
        if self._hdr_budget > 0 or sev:
            self._hdr_budget -= 1
            d["req_head"] = self._mask_head(req["head"]) if req else ""
            d["resp_head"] = self._mask_head(resp["head"]) if resp else ""
        status_txt = f"{status}" if status else "—"
        summary = f"{method}  {host}{uri_path[:110]}  →  {status_txt}" + (f"  ·  {fname} ({len(body):,} B)" if rec_file else "")
        ev = self.hub_event("HTTP", "transaction", ts, n, c, cp, s, sp, summary, d, sev, rec_file["id"] if rec_file else None)
        self.http_txns.append(ev if ev is not None else d)
        if rec_file is not None and ev is not None:
            rec_file["event"] = ev["i"]
        return ev

    @staticmethod
    def _mask_head(head: bytes) -> str:
        out = []
        for ln in head[:3000].decode("latin-1", "replace").split("\r\n"):
            k = ln.split(":", 1)[0].strip().lower()
            if k in SENS_HDR and ":" in ln:
                v = ln.split(":", 1)[1].strip()
                ln = f"{ln.split(':', 1)[0]}: {v[:6]}…[{len(v)} chars]"
            out.append(ln)
        return "\n".join(out)

    def _extract_uploads(self, req, c, cp, s, sp, hostname, url, flow, n, ts):
        out = []
        h = req["h"]
        ct = h.get("content-type", "")
        body = req["body"]
        if "multipart/" in ct.lower():
            m = re.search(r'boundary="?([^";]+)"?', ct, re.I)
            if m:
                bnd = b"--" + m.group(1).encode("latin-1")
                for part in body.split(bnd)[1:]:
                    if part.startswith(b"--"):
                        break
                    head, sep, data = part.lstrip(b"\r\n").partition(b"\r\n\r\n")
                    if not sep:
                        continue
                    if data.endswith(b"\r\n"):
                        data = data[:-2]
                    hh = self._http_headers(b"x\r\n" + head)[1]
                    cd = hh.get("content-disposition", "")
                    fm = re.search(r'filename\*?=(?:"([^"]*)"|([^;]+))', cd, re.I)
                    if fm and data:
                        fname = unquote((fm.group(1) or fm.group(2) or "upload.bin").strip())
                        rec = self.hub_add_file(data, fname, "HTTP", hostname, n=n, ts=ts, flow=flow, src=c, dst=s, url=url,
                                                direction="upload", mime=hh.get("content-type", ""), name_source="multipart",
                                                sport=cp, dport=sp, method=req["method"])
                        if rec:
                            out.append(rec)
        elif req["method"] == "PUT" and body:
            fname, _ = filename_from_headers({}, urlsplit(url).path, ct)
            rec = self.hub_add_file(body, fname, "HTTP", hostname, n=n, ts=ts, flow=flow, src=c, dst=s, url=url, direction="upload",
                                    mime=ct, name_source="uri", sport=cp, dport=sp, method="PUT")
            if rec:
                out.append(rec)
        return out

    # ------------------------------------------------------------------ FTP (کنترل + کانال داده)
    def hub_extract_ftp(self):
        if not self.ftp_sessions:
            return
        # اندیس جریان‌های داده بر اساس endpoint
        by_ep = collections.defaultdict(list)
        for k in self.tcp_segments:
            by_ep[(k[0], k[1])].append(k)
            by_ep[(k[2], k[3])].append(k)
        used = set()
        for (c, cp, s, sp), lines in self.ftp_sessions.items():
            pending = None            # (ip, port, active?)
            cwd = "/"
            for n, ts, who, line in sorted(lines, key=lambda x: x[0]):
                if who == "s":
                    m = re.search(r"\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)", line)
                    if line.startswith("227") and m:
                        g = list(map(int, m.groups()))
                        pending = (".".join(map(str, g[:4])), g[4] * 256 + g[5])
                    elif line.startswith("229"):
                        m2 = re.search(r"\|\|\|(\d+)\|", line)
                        if m2:
                            pending = (s, int(m2.group(1)))
                    continue
                cmd, _, arg = line.partition(" ")
                cmd = cmd.upper()
                if cmd == "PORT":
                    m = re.match(r"(\d+),(\d+),(\d+),(\d+),(\d+),(\d+)", arg)
                    if m:
                        g = list(map(int, m.groups()))
                        pending = (".".join(map(str, g[:4])), g[4] * 256 + g[5])
                elif cmd == "EPRT":
                    m = re.match(r"\|\d\|([^|]+)\|(\d+)\|", arg)
                    if m:
                        pending = (m.group(1), int(m.group(2)))
                elif cmd == "CWD" and arg:
                    cwd = arg
                elif cmd in ("RETR", "STOR", "APPE", "LIST", "NLST", "MLSD") and pending:
                    ip, port = pending
                    pending = None
                    cand = [k for k in by_ep.get((ip, port), []) if k not in used]
                    if not cand:
                        continue
                    k = cand[0]
                    used.add(k)
                    stream, offs, meta = self._merge_indexed(self.tcp_segments[k])
                    if not stream:
                        continue
                    n0, ts0 = self._at(offs, meta, 0)
                    # جهت: RETR/LIST → سرور→کلاینت ؛ STOR → کلاینت→سرور. اگر جهت اشتباه بود، جریان مقابل را هم امتحان کن
                    if cmd in ("LIST", "NLST", "MLSD"):
                        listing = stream[:60000].decode("latin-1", "replace")
                        self.hub_event("FTP", "listing", ts0 or ts, n0 or n, k[0], k[1], k[2], k[3], f"{cmd} {arg or cwd}  ({len(stream):,} B)",
                                       {"listing": listing[:3000], "dir": arg or cwd}, 0)
                        continue
                    name = safe_name(arg.rsplit("/", 1)[-1] or "ftp_file")
                    direction = "download" if cmd == "RETR" else "upload"
                    rec = self.hub_add_file(stream, name, "FTP", s, n=n0, ts=ts0, flow=f"{k[0]}:{k[1]} → {k[2]}:{k[3]}", src=s if direction == "download" else c,
                                            dst=c if direction == "download" else s, url=f"ftp://{s}{('/' + arg.lstrip('/')) if arg else ''}",
                                            direction=direction, name_source="ftp-command", sport=sp, dport=cp, flags=[] if not self.tcp_stream_quality.get(k, {}).get("has_gap") else ["partial"])
                    self.hub_event("FTP", "transfer", ts0 or ts, n0 or n, k[0], k[1], k[2], k[3], f"{cmd} {arg}  ({len(stream):,} B)",
                                   {"filename": arg, "size": len(stream), "direction": direction, "sha256": rec["sha256"] if rec else ""},
                                   1, rec["id"] if rec else None)

    # ------------------------------------------------------------------ SMTP / POP3 : ایمیل و پیوست‌ها
    def hub_extract_mail(self):
        for key, segs in list(self.tcp_segments.items()):
            c, cp, s, sp = key
            proto = None
            if sp in (25, 587, 2525) or cp in (25, 587, 2525):
                proto = "SMTP"
            elif sp == 110 or cp == 110:
                proto = "POP3"
            else:
                continue
            stream, offs, meta = self._merge_indexed(segs)
            if len(stream) < 40:
                continue
            msgs = []
            if proto == "SMTP" and sp in (25, 587, 2525):                      # client → server (مقصد = پورت سرور)
                for m in re.finditer(rb"\r\nDATA\r\n|^DATA\r\n", stream):
                    st = m.end()
                    en = stream.find(b"\r\n.\r\n", st)
                    if en < 0:
                        en = len(stream)
                    msgs.append((st, stream[st:en].replace(b"\r\n..", b"\r\n.")))
            elif proto == "POP3" and cp == 110 or (proto == "POP3" and key[1] == 110):   # server → client
                for m in re.finditer(rb"\+OK[^\r\n]*\r\n", stream):
                    st = m.end()
                    en = stream.find(b"\r\n.\r\n", st)
                    if en > st + 40 and re.match(rb"(?i)(received|from|return-path|mime-version|date|subject|message-id|x-)", stream[st:st + 24]):
                        msgs.append((st, stream[st:en]))
            for off, raw in msgs[:200]:
                if proto == "POP3":      # جهت سرور→کلاینت: کلید (server, 110, client, port)
                    self._mail_message(proto, s, sp, c, cp, raw, *self._at(offs, meta, off))
                else:
                    self._mail_message(proto, c, cp, s, sp, raw, *self._at(offs, meta, off))

    def _mail_message(self, proto, c, cp, s, sp, raw, n, ts):
        try:
            msg = email.message_from_bytes(raw, policy=email.policy.default)
        except Exception:
            return
        subj = str(msg.get("subject", ""))[:200]
        frm = str(msg.get("from", ""))[:160]
        to = str(msg.get("to", ""))[:200]
        atts = []
        try:
            for part in msg.walk():
                fn = part.get_filename()
                if fn:
                    data = part.get_payload(decode=True) or b""
                    rec = self.hub_add_file(data, str(fn), proto, s if proto == "SMTP" else c, n=n, ts=ts, flow=f"{c}:{cp} → {s}:{sp}",
                                            src=c if proto == "SMTP" else s, dst=s if proto == "SMTP" else c, url=f"mail://{frm}",
                                            direction="upload" if proto == "SMTP" else "download", mime=part.get_content_type(),
                                            name_source="mime-attachment", note=f"{subj[:80]}", sport=cp, dport=sp)
                    if rec:
                        atts.append(rec)
        except Exception:
            pass
        flag = 2 if any(a["risky"] for a in atts) else (1 if atts else 0)
        body_prev = ""
        try:
            b = msg.get_body(preferencelist=("plain", "html"))
            if b is not None:
                body_prev = b.get_content()[:600]
        except Exception:
            pass
        self.hub_event(proto, "message", ts, n, c, cp, s, sp, f"{subj or '(no subject)'}  ·  {frm} → {to}" + (f"  ·  {len(atts)} attachment(s)" if atts else ""),
                       {"subject": subj, "from": frm, "to": to, "date": str(msg.get("date", "")), "attachments": [a["name"] for a in atts],
                        "body": body_prev}, flag, atts[0]["id"] if atts else None)

    def hub_extract_tftp(self):
        for st in self.tftp.values():
            blocks = st["blocks"]
            if not blocks:
                continue
            data = b"".join(blocks[k] for k in sorted(blocks))
            gaps = sorted(blocks) != list(range(1, max(blocks) + 1))
            rec = self.hub_add_file(data, safe_name(st["name"].rsplit("/", 1)[-1] or "tftp_file"), "TFTP", st["server"], n=st["n"], ts=st["ts"],
                                    flow=f"{st['client']}:{st['cport']} ↔ {st['server']}", src=st["server"] if st["dir"] == "download" else st["client"],
                                    dst=st["client"] if st["dir"] == "download" else st["server"], url=f"tftp://{st['server']}/{st['name']}",
                                    direction=st["dir"], name_source="tftp-request", flags=["partial"] if gaps else [])
            if rec:
                self.hub_event("TFTP", "transfer", st["ts"], st["n"], st["client"], st["cport"], st["server"], 69,
                               f"{st['dir']}  {st['name']}  ({len(data):,} B)", {"sha256": rec["sha256"], "size": len(data)}, 1, rec["id"])

    # ------------------------------------------------------------------ orchestrator
    def hub_finish(self):
        if self._hub_files_done:
            return
        self._hub_files_done = True
        self.hub_prepare_store()
        for fn in (self.hub_extract_http, self.hub_extract_ftp, self.hub_extract_mail, self.hub_extract_tftp):
            try:
                fn()
            except Exception as e:           # یک پروتکل خراب نباید کل تحلیل را بیندازد
                self.errors += 1
                self.hub_errors = getattr(self, "hub_errors", []) + [f"{fn.__name__}: {type(e).__name__}: {e}"]
        for raw, nm, meta in self._carved_pending:       # نمونه‌های استخراج‌شده/رمزگشایی‌شده که با فایل اصلی یکی نیستند
            try:
                self.hub_add_file(raw, nm, "CARVED", "", **meta)
            except Exception:
                pass
        self._carved_pending = []
        if self.file_store is not None:
            self.file_store.close()
        # DNS: پرسش‌هایی که پاسخ نگرفتند
        for ev in list(self._dns_pending.values()):
            if not ev["d"].get("rcode"):
                ev["d"]["rcode"] = "NO-RESPONSE"
                ev["x"] = max(ev["x"], 0)
        self._dns_pending.clear()

    # ================================================================================================
    #  خروجی برای گزارش
    # ================================================================================================
    def hub_export(self, findings=None):
        """ساختار JSON‌پذیر کامل برای گزارش «کنسول سایبری»"""
        flows_out = []
        proto_stats = collections.defaultdict(lambda: {"flows": 0, "packets": 0, "bytes": 0, "hosts": set(), "t0": None, "t1": None,
                                                       "up": 0, "down": 0})
        pair = {}
        for (l4, a, ap, b, bp), f in self.flows.items():
            pk = f[0] + f[2]
            by = f[1] + f[3]
            pr = f[7]
            ps = proto_stats[pr]
            ps["flows"] += 1
            ps["packets"] += pk
            ps["bytes"] += by
            ps["up"] += f[1]
            ps["down"] += f[3]
            ps["hosts"].add(a)
            ps["hosts"].add(b)
            ps["t0"] = f[4] if ps["t0"] is None else min(ps["t0"], f[4])
            ps["t1"] = f[5] if ps["t1"] is None else max(ps["t1"], f[5])
            pk_key = (a, b) if a <= b else (b, a)
            pr_ = pair.setdefault(pk_key, {"a": pk_key[0], "b": pk_key[1], "flows": 0, "packets": 0, "bytes": 0, "protos": collections.Counter(),
                                           "t0": f[4], "t1": f[5], "ports": collections.Counter()})
            pr_["flows"] += 1
            pr_["packets"] += pk
            pr_["bytes"] += by
            pr_["protos"][pr] += by or 1
            pr_["t0"] = min(pr_["t0"], f[4])
            pr_["t1"] = max(pr_["t1"], f[5])
            pr_["ports"][bp if bp < 49152 else ap] += 1
            flows_out.append({"l4": l4, "a": a, "ap": ap, "b": b, "bp": bp, "pk1": f[0], "by1": f[1], "pk2": f[2], "by2": f[3],
                              "t0": f[4], "t1": f[5], "p": pr, "n": f[6], "fl": f[8] & 0xFF, "pl1": f[9], "pl2": f[10]})
        flows_out.sort(key=lambda x: -(x["by1"] + x["by2"]))
        flows_cap = 6000
        # پروتکل‌هایی که فقط رویداد دارند (ARP / DNS بدون جریان ...)
        for pr, evs in self.hub_events.items():
            ps = proto_stats[pr]
            for e in evs[:2000]:
                ps["hosts"].add(e["a"])
                ps["hosts"].add(e["b"])
                if e["t"]:
                    ps["t0"] = e["t"] if ps["t0"] is None else min(ps["t0"], e["t"])
                    ps["t1"] = e["t"] if ps["t1"] is None else max(ps["t1"], e["t"])
        protocols = []
        order = {p: i for i, p in enumerate(PROTO_ORDER)}
        for pr, ps in proto_stats.items():
            tot = self.hub_total.get(pr, 0)
            protocols.append({"name": pr, "flows": ps["flows"], "packets": ps["packets"], "bytes": ps["bytes"], "up": ps["up"], "down": ps["down"],
                              "hosts": len(ps["hosts"]), "t0": ps["t0"], "t1": ps["t1"], "events": tot, "shown": len(self.hub_events.get(pr, [])),
                              "flagged": sum(1 for e in self.hub_events.get(pr, []) if e["x"]), "rank": order.get(pr, 99)})
        protocols.sort(key=lambda x: (-(x["bytes"] + x["events"] * 100), x["rank"]))
        pairs = []
        for pp in pair.values():
            pp["protos"] = dict(pp["protos"].most_common(8))
            pp["ports"] = [p for p, _ in pp["ports"].most_common(5)]
            pairs.append(pp)
        pairs.sort(key=lambda x: -x["bytes"])
        files = []
        for r in self.file_records:
            rr = {k: v for k, v in r.items() if k not in ("md5", "sha1") or True}
            files.append(rr)
        # ارتباط یافته‌ها با پروتکل
        by_proto_find = collections.defaultdict(list)
        for f in findings or []:
            pr = rule_proto(f["id"]) or "—"
            by_proto_find[pr].append({"id": f["id"], "title": f["title"], "severity": f["severity"], "count": f["count"], "mitre": f["mitre"]})
        return {
            "protocols": protocols,
            "events": {pr: evs for pr, evs in self.hub_events.items()},
            "events_total": dict(self.hub_total),
            "flows": flows_out[:flows_cap], "flows_total": len(flows_out), "flow_overflow": self.flow_overflow,
            "pairs": pairs[:3000], "pairs_total": len(pairs),
            "files": files,
            "files_summary": self.file_store.summary() if self.file_store else {"zip": None, "count": 0, "bytes": 0, "mode": None, "by_category": {}, "risky": 0},
            "findings_by_proto": dict(by_proto_find),
            "http_story": self._http_story(),
            "http_orphans": self.http_orphans,
            "dhcp_clients": [{"mac": m, "host": h, "ip": i} for m, (h, i) in list(self.dhcp_clients.items())[:200]],
            "errors": getattr(self, "hub_errors", []),
        }

    def _http_story(self):
        """روایت ساده فارسی: چه کسی از کجا چه فایل‌هایی دانلود کرد"""
        grp = collections.defaultdict(list)
        for r in self.file_records:
            if r.get("proto") == "HTTP" and r.get("direction") == "download" and not r.get("web_resource"):
                grp[(r.get("dst"), r.get("host"))].append(r)
        out = []
        for (cl, host), fs in sorted(grp.items(), key=lambda kv: -sum(x["size"] for x in kv[1]))[:25]:
            names = "، ".join(f"«{x['name']}»" for x in fs[:6]) + (f" و {len(fs) - 6} فایل دیگر" if len(fs) > 6 else "")
            tot = sum(x["size"] for x in fs)
            risky = sum(1 for x in fs if x["risky"])
            out.append({"client": cl, "host": host, "count": len(fs), "bytes": tot, "risky": risky,
                        "text": f"{cl} از «{host}» {len(fs)} فایل دانلود کرد ({tot:,} بایت): {names}" + (f" — ⚠️ {risky} مورد اجرایی/پرخطر" if risky else "")})
        return out
