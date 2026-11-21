# -*- coding: utf-8 -*-
"""
pcap_fastio — پکت‌خوان بومی و سریع (بدون وابستگی به scapy)
============================================================
• خواندن PCAP (micro/nano، هر دو endian) و PCAPNG (SHB/IDB/EPB/SPB، tsresol) با mmap
• دیکد Ethernet / 802.1Q / QinQ / Linux-SLL / SLL2 / Raw-IP / Loopback → IPv4 / IPv6 → TCP / UDP / ICMP / ARP
• تجزیه‌گر بومی DNS / DHCP / SNMP / SMB2 / TLS-extras

چرا؟ scapy برای هر بسته یک درخت لایه می‌سازد (≈ ۵-۱۰ هزار بسته در ثانیه). این ماژول فقط فیلدهای لازم
را با struct.unpack_from می‌خواند و معمولاً ۱۵ تا ۴۰ برابر سریع‌تر است. اگر فرمت/لینک‌تایپ پشتیبانی نشود
هسته به‌صورت خودکار به scapy برمی‌گردد.

Author: mr-coder20 · https://github.com/mr-coder20/pcap-analyzer · MIT
"""
from __future__ import annotations

import mmap
import socket
import struct
from socket import AF_INET6, inet_ntoa, inet_ntop

# --- kinds returned by decode() ---------------------------------------------------------------
K_OTHER, K_ICMP, K_TCP, K_UDP, K_ARP, K_ICMP6 = 0, 1, 6, 17, 0x0806, 58

LT_NULL, LT_ETHERNET, LT_RAW, LT_LOOP, LT_RAW4, LT_RAW6 = 0, 1, 101, 108, 228, 229
LT_SLL, LT_SLL2, LT_RAW_ALT, LT_RAW_ALT2 = 113, 276, 12, 14
SUPPORTED_LINKTYPES = {LT_NULL, LT_ETHERNET, LT_RAW, LT_LOOP, LT_RAW4, LT_RAW6, LT_SLL, LT_SLL2, LT_RAW_ALT, LT_RAW_ALT2}


class Unsupported(Exception):
    """فرمت فایل یا لینک‌تایپ توسط پکت‌خوان بومی پشتیبانی نمی‌شود (هسته به scapy برمی‌گردد)."""


# ================================================================================================
#  خواندن فایل
# ================================================================================================
def _open_map(path):
    f = open(path, "rb")
    try:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
    except (ValueError, OSError):          # فایل خالی یا mmap ناممکن
        data = f.read()
        f.close()
        return data, None
    return mm, f


def sniff_format(path):
    """'pcap' | 'pcapng' | None"""
    try:
        with open(path, "rb") as fh:
            m = fh.read(4)
    except OSError:
        return None
    if m in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
        return "pcap"
    if m == b"\x0a\x0d\x0d\x0a":
        return "pcapng"
    return None


class CaptureReader:
    """
    for ts, linktype, data, origlen in CaptureReader(path): ...
    اگر فرمت ناشناخته باشد Unsupported پرتاب می‌شود.
    """

    def __init__(self, path):
        self.path = path
        self.format = sniff_format(path)
        if self.format is None:
            raise Unsupported("magic ناشناخته")
        self.buf, self._f = _open_map(path)
        self.size = len(self.buf)
        self.pos = 0                      # برای نوار پیشرفت
        self.linktypes = set()

    def close(self):
        try:
            if hasattr(self.buf, "close"):
                self.buf.close()
        finally:
            if self._f:
                self._f.close()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()

    def __iter__(self):
        return self._iter_pcap() if self.format == "pcap" else self._iter_pcapng()

    # ---- classic pcap -------------------------------------------------------------------------
    def _iter_pcap(self):
        buf, size = self.buf, self.size
        if size < 24:
            return
        m = bytes(buf[:4])
        endian = "<" if m in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
        nano = m in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
        lt = struct.unpack_from(endian + "I", buf, 20)[0] & 0x0FFFFFFF
        if lt not in SUPPORTED_LINKTYPES:
            raise Unsupported(f"linktype {lt}")
        self.linktypes.add(lt)
        div = 1e9 if nano else 1e6
        unpack = struct.Struct(endian + "IIII").unpack_from
        pos = 24
        while pos + 16 <= size:
            sec, frac, caplen, orig = unpack(buf, pos)
            pos += 16
            if caplen > 0x4000000 or pos + caplen > size:   # رکورد خراب / فایل ناقص
                if pos + caplen > size and caplen <= 0x4000000 and pos < size:
                    caplen = size - pos                      # آخرین بسته‌ی بریده‌شده
                else:
                    return
            self.pos = pos
            yield sec + frac / div, lt, buf[pos:pos + caplen], orig
            pos += caplen

    # ---- pcapng -------------------------------------------------------------------------------
    def _iter_pcapng(self):
        buf, size = self.buf, self.size
        pos = 0
        endian = "<"
        ifaces = []            # [(linktype, ts_divisor)]
        while pos + 12 <= size:
            btype = struct.unpack_from("<I", buf, pos)[0]
            if btype == 0x0A0D0D0A:                      # Section Header Block
                magic = bytes(buf[pos + 8:pos + 12])
                endian = "<" if magic == b"\x4d\x3c\x2b\x1a" else ">"
                ifaces = []
            blen = struct.unpack_from(endian + "I", buf, pos + 4)[0]
            btype = struct.unpack_from(endian + "I", buf, pos)[0]
            if blen < 12 or pos + blen > size:
                if pos + blen > size and blen >= 12 and btype in (6, 3, 2):
                    blen = size - pos
                else:
                    return
            body = pos + 8
            if btype == 1:                                # Interface Description Block
                lt = struct.unpack_from(endian + "H", buf, body)[0]
                if lt not in SUPPORTED_LINKTYPES:
                    if not self.linktypes and not ifaces:
                        raise Unsupported(f"linktype {lt}")      # هنوز بسته‌ای پردازش نشده → برگشت به scapy
                    lt = None                                      # اینترفیس ناشناخته: بسته‌هایش نادیده گرفته می‌شود
                else:
                    self.linktypes.add(lt)
                div = 1e6
                o = body + 8
                end = pos + blen - 4
                while o + 4 <= end:
                    code, olen = struct.unpack_from(endian + "HH", buf, o)
                    if code == 0:
                        break
                    if code == 9 and olen >= 1:           # if_tsresol
                        v = buf[o + 4]
                        div = float(2 ** (v & 0x7F)) if v & 0x80 else float(10 ** (v & 0x7F))
                    o += 4 + ((olen + 3) & ~3)
                ifaces.append((lt, div))
            elif btype == 6 and blen >= 32:               # Enhanced Packet Block
                iid, th, tl, cap, orig = struct.unpack_from(endian + "IIIII", buf, body)
                if iid < len(ifaces) and ifaces[iid][0] is not None:
                    lt, div = ifaces[iid]
                    d0 = body + 20
                    self.pos = d0
                    yield ((th << 32) | tl) / div, lt, buf[d0:d0 + cap], orig
            elif btype == 3 and ifaces and ifaces[0][0] is not None:   # Simple Packet Block
                orig = struct.unpack_from(endian + "I", buf, body)[0]
                cap = min(orig, blen - 16)
                self.pos = body + 4
                yield 0.0, ifaces[0][0], buf[body + 4:body + 4 + cap], orig
            elif btype == 2 and blen >= 28:               # Packet Block (obsolete)
                iid, _drops, th, tl, cap, orig = struct.unpack_from(endian + "HHIIII", buf, body)
                if iid < len(ifaces) and ifaces[iid][0] is not None:
                    lt, div = ifaces[iid]
                    d0 = body + 20
                    yield ((th << 32) | tl) / div, lt, buf[d0:d0 + cap], orig
            pos += blen


# ================================================================================================
#  دیکد لایه ۲/۳/۴
# ================================================================================================
_ip4_cache: dict = {}
_ip6_cache: dict = {}
_mac_cache: dict = {}


def ip4(b):
    s = _ip4_cache.get(b)
    if s is None:
        s = inet_ntoa(b)
        if len(_ip4_cache) < 400000:
            _ip4_cache[b] = s
    return s


def ip6(b):
    s = _ip6_cache.get(b)
    if s is None:
        s = inet_ntop(AF_INET6, b)
        if len(_ip6_cache) < 100000:
            _ip6_cache[b] = s
    return s


def mac_str(b):
    s = _mac_cache.get(b)
    if s is None:
        s = ":".join("%02x" % x for x in b)
        if len(_mac_cache) < 100000:
            _mac_cache[b] = s
    return s


_U_H = struct.Struct("!HH").unpack_from
_U_HH = struct.Struct("!HHHH").unpack_from
_U_TCP = struct.Struct("!HHII").unpack_from
_U_H2 = struct.Struct("!H").unpack_from


def decode(data, lt):
    """
    خروجی: (kind, src, dst, a, b, flags, seq, payload, wire_len)
      TCP : a=sport b=dport flags=TCP flags seq=sequence payload=bytes
      UDP : a=sport b=dport payload
      ICMP: a=type  b=code  payload
      ARP : a=opcode b=0 src=psrc dst=pdst flags=(hwsrc, hwdst)
    یا None اگر لایه ۳ شناخته‌شده نباشد.
    """
    n = len(data)
    off = 0
    proto_eth = 0
    if lt == LT_ETHERNET:
        if n < 14:
            return None
        et = (data[12] << 8) | data[13]
        off = 14
        while et in (0x8100, 0x88A8, 0x9100) and n >= off + 4:      # VLAN / QinQ
            et = (data[off + 2] << 8) | data[off + 3]
            off += 4
        proto_eth = et
    elif lt == LT_SLL:
        if n < 16:
            return None
        proto_eth = (data[14] << 8) | data[15]
        off = 16
    elif lt == LT_SLL2:
        if n < 20:
            return None
        proto_eth = (data[0] << 8) | data[1]
        off = 20
    elif lt in (LT_NULL, LT_LOOP):
        if n < 5:
            return None
        off = 4
        v = data[4] >> 4
        proto_eth = 0x0800 if v == 4 else 0x86DD if v == 6 else 0
    else:                                                          # Raw IP
        if n < 1:
            return None
        v = data[0] >> 4
        proto_eth = 0x0800 if v == 4 else 0x86DD if v == 6 else 0

    if proto_eth == 0x0800:                                        # ---------------- IPv4
        if n < off + 20:
            return None
        ihl = (data[off] & 0x0F) * 4
        if ihl < 20 or n < off + ihl:
            return None
        tot = (data[off + 2] << 8) | data[off + 3]
        frag = ((data[off + 6] & 0x1F) << 8) | data[off + 7]
        proto = data[off + 9]
        src = ip4(bytes(data[off + 12:off + 16]))
        dst = ip4(bytes(data[off + 16:off + 20]))
        end = off + tot if 0 < tot <= n - off else n
        l4 = off + ihl
        wire = tot or (n - off)
        if frag:                                                   # قطعه غیر اول: فقط شمارش
            return (K_OTHER, src, dst, 0, 0, 0, 0, b"", wire)
    elif proto_eth == 0x86DD:                                      # ---------------- IPv6
        if n < off + 40:
            return None
        pl = (data[off + 4] << 8) | data[off + 5]
        proto = data[off + 6]
        src = ip6(bytes(data[off + 8:off + 24]))
        dst = ip6(bytes(data[off + 24:off + 40]))
        l4 = off + 40
        end = l4 + pl if 0 < pl <= n - l4 else n
        wire = pl + 40
        hops = 0
        while proto in (0, 43, 60, 44, 51) and hops < 6 and l4 + 8 <= n:
            nxt = data[l4]
            if proto == 44:
                if ((data[l4 + 2] << 8) | data[l4 + 3]) >> 3:
                    return (K_OTHER, src, dst, 0, 0, 0, 0, b"", wire)
                ln = 8
            elif proto == 51:
                ln = (data[l4 + 1] + 2) * 4
            else:
                ln = (data[l4 + 1] + 1) * 8
            l4 += ln
            proto = nxt
            hops += 1
    elif proto_eth == 0x0806:                                      # ---------------- ARP
        if n < off + 28:
            return None
        op = (data[off + 6] << 8) | data[off + 7]
        hs = bytes(data[off + 8:off + 14])
        ps = bytes(data[off + 14:off + 18])
        hd = bytes(data[off + 18:off + 24])
        pd = bytes(data[off + 24:off + 28])
        return (K_ARP, ip4(ps), ip4(pd), op, 0, (mac_str(hs), mac_str(hd)), 0, b"", 28)
    else:
        return None

    if proto == 6:                                                 # ---------------- TCP
        if end < l4 + 20:
            return (K_OTHER, src, dst, 0, 0, 0, 0, b"", wire)
        sp, dp, seq, _ack = _U_TCP(data, l4)
        doff = (data[l4 + 12] >> 4) * 4
        if doff < 20:
            doff = 20
        flags = data[l4 + 13] & 0x3F
        payload = data[l4 + doff:end] if end > l4 + doff else b""
        return (K_TCP, src, dst, sp, dp, flags, seq, payload, wire)
    if proto == 17:                                                # ---------------- UDP
        if end < l4 + 8:
            return (K_OTHER, src, dst, 0, 0, 0, 0, b"", wire)
        sp, dp, ulen, _c = _U_HH(data, l4)
        e2 = l4 + ulen if 8 <= ulen <= end - l4 else end
        return (K_UDP, src, dst, sp, dp, 0, 0, data[l4 + 8:e2], wire)
    if proto == 1:                                                 # ---------------- ICMP
        if end < l4 + 8:
            return (K_OTHER, src, dst, 0, 0, 0, 0, b"", wire)
        return (K_ICMP, src, dst, data[l4], data[l4 + 1], 0, 0, data[l4 + 8:end], wire)
    if proto == 58:                                                # ---------------- ICMPv6
        return (K_ICMP6, src, dst, data[l4] if l4 < n else 0, 0, 0, 0, b"", wire)
    return (K_OTHER, src, dst, 0, 0, 0, 0, b"", wire)


# ================================================================================================
#  DNS
# ================================================================================================
QTYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV",
          41: "OPT", 43: "DS", 46: "RRSIG", 47: "NSEC", 48: "DNSKEY", 52: "TLSA", 64: "SVCB", 65: "HTTPS",
          99: "SPF", 250: "TSIG", 251: "IXFR", 252: "AXFR", 255: "ANY", 257: "CAA"}
RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}


def _dns_name(msg, pos, depth=0):
    """(name, next_pos). پشتیبانی از compression pointer."""
    labels = []
    jumped = False
    nxt = pos
    n = len(msg)
    hops = 0
    while pos < n and hops < 64:
        ln = msg[pos]
        if ln == 0:
            pos += 1
            break
        if ln & 0xC0 == 0xC0:
            if pos + 1 >= n:
                break
            ptr = ((ln & 0x3F) << 8) | msg[pos + 1]
            if not jumped:
                nxt = pos + 2
                jumped = True
            pos = ptr
            hops += 1
            continue
        pos += 1
        labels.append(bytes(msg[pos:pos + ln]).decode("ascii", "replace"))
        pos += ln
        hops += 1
    if not jumped:
        nxt = pos
    return ".".join(labels), nxt


def parse_dns(msg):
    """dict یا None.  کلیدها: id qr opcode rcode qd[(name,type)] an[(name,type,ttl,data)] ns ar tc aa rd ra"""
    try:
        if len(msg) < 12:
            return None
        tid, fl, qd, an, ns, ar = struct.unpack_from("!HHHHHH", msg, 0)
        if qd > 32 or an > 200 or ns > 200 or ar > 200:
            return None
        pos = 12
        out = {"id": tid, "qr": fl >> 15, "opcode": (fl >> 11) & 15, "aa": (fl >> 10) & 1, "tc": (fl >> 9) & 1,
               "rd": (fl >> 8) & 1, "ra": (fl >> 7) & 1, "rcode": fl & 15, "qd": [], "an": [], "ns": 0, "ar": 0}
        for _ in range(qd):
            name, pos = _dns_name(msg, pos)
            if pos + 4 > len(msg):
                return out
            qt, _qc = struct.unpack_from("!HH", msg, pos)
            pos += 4
            out["qd"].append((name, qt))
        for _ in range(an):
            name, pos = _dns_name(msg, pos)
            if pos + 10 > len(msg):
                break
            rt, _rc, ttl, rl = struct.unpack_from("!HHIH", msg, pos)
            pos += 10
            rd = msg[pos:pos + rl]
            if rt == 1 and rl == 4:
                data = inet_ntoa(bytes(rd))
            elif rt == 28 and rl == 16:
                data = inet_ntop(AF_INET6, bytes(rd))
            elif rt in (2, 5, 12):
                data = _dns_name(msg, pos)[0]
            elif rt == 15 and rl >= 3:
                data = "%d %s" % (struct.unpack_from("!H", msg, pos)[0], _dns_name(msg, pos + 2)[0])
            elif rt == 16:
                parts, o = [], 0
                while o < rl:
                    L = rd[o]
                    parts.append(bytes(rd[o + 1:o + 1 + L]).decode("utf-8", "replace"))
                    o += 1 + L
                data = " ".join(parts)[:300]
            else:
                data = bytes(rd[:24]).hex()
            out["an"].append((name, rt, ttl, data))
            pos += rl
        out["ns"], out["ar"] = ns, ar
        return out
    except Exception:
        return None


# ================================================================================================
#  DHCP / SNMP / SMB2
# ================================================================================================
DHCP_TYPES = {1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 4: "DECLINE", 5: "ACK", 6: "NAK", 7: "RELEASE", 8: "INFORM"}


def parse_dhcp(p):
    """dict یا None"""
    try:
        if len(p) < 240 or p[236:240] != b"\x63\x82\x53\x63":
            return None
        out = {"op": p[0], "xid": struct.unpack_from("!I", p, 4)[0], "ciaddr": inet_ntoa(bytes(p[12:16])),
               "yiaddr": inet_ntoa(bytes(p[16:20])), "siaddr": inet_ntoa(bytes(p[20:24])),
               "mac": mac_str(bytes(p[28:34])), "msg": None, "host": "", "req_ip": "", "server": "", "vendor": ""}
        o = 240
        n = len(p)
        while o < n:
            c = p[o]
            if c == 255:
                break
            if c == 0:
                o += 1
                continue
            if o + 1 >= n:
                break
            ln = p[o + 1]
            v = bytes(p[o + 2:o + 2 + ln])
            if c == 53 and ln >= 1:
                out["msg"] = DHCP_TYPES.get(v[0], str(v[0]))
            elif c == 12:
                out["host"] = v.decode("latin-1", "replace").strip("\x00")
            elif c == 50 and ln == 4:
                out["req_ip"] = inet_ntoa(v)
            elif c == 54 and ln == 4:
                out["server"] = inet_ntoa(v)
            elif c == 60:
                out["vendor"] = v.decode("latin-1", "replace")[:60]
            o += 2 + ln
        return out
    except Exception:
        return None


def parse_snmp_community(p):
    """community string (str) یا None — BER: SEQUENCE{ INTEGER version, OCTET STRING community, ... }"""
    try:
        if len(p) < 8 or p[0] != 0x30:
            return None
        o = 1
        ln = p[o]
        o += 1 + (ln & 0x7F if ln & 0x80 else 0)
        if p[o] != 0x02:
            return None
        o += 2 + p[o + 1]
        if p[o] != 0x04:
            return None
        cl = p[o + 1]
        return bytes(p[o + 2:o + 2 + cl]).decode("latin-1", "replace")
    except Exception:
        return None


SMB2_CMDS = {0: "NEGOTIATE", 1: "SESSION_SETUP", 2: "LOGOFF", 3: "TREE_CONNECT", 4: "TREE_DISCONNECT", 5: "CREATE",
             6: "CLOSE", 7: "FLUSH", 8: "READ", 9: "WRITE", 10: "LOCK", 11: "IOCTL", 12: "CANCEL", 13: "ECHO",
             14: "QUERY_DIRECTORY", 15: "CHANGE_NOTIFY", 16: "QUERY_INFO", 17: "SET_INFO"}


def parse_smb2(p):
    """فهرست رویدادهای SMB2 داخل payload: [(command_name, is_response, detail)]"""
    out = []
    o = 0
    guard = 0
    while guard < 24:
        guard += 1
        i = p.find(b"\xfeSMB", o)
        if i < 0 or i + 64 > len(p):
            break
        try:
            cmd = struct.unpack_from("<H", p, i + 12)[0]
            flags = struct.unpack_from("<I", p, i + 16)[0]
            resp = bool(flags & 1)
            name = SMB2_CMDS.get(cmd, str(cmd))
            detail = ""
            body = i + 64
            if not resp and cmd == 3 and body + 8 <= len(p):          # TREE_CONNECT → \\server\share
                po, pl = struct.unpack_from("<HH", p, body + 4)
                detail = bytes(p[i + po:i + po + pl]).decode("utf-16le", "replace")
            elif not resp and cmd == 5 and body + 56 <= len(p):       # CREATE → file name
                no, nl = struct.unpack_from("<HH", p, body + 44)
                detail = bytes(p[i + no:i + no + nl]).decode("utf-16le", "replace")
            elif not resp and cmd == 14 and body + 32 <= len(p):      # QUERY_DIRECTORY pattern
                no, nl = struct.unpack_from("<HH", p, body + 24)
                detail = bytes(p[i + no:i + no + nl]).decode("utf-16le", "replace")
            out.append((name, resp, detail))
            o = i + 4
        except Exception:
            break
    return out


# ================================================================================================
#  TLS (فراتر از JA3): نسخه، ALPN، cipher
# ================================================================================================
TLS_VERSIONS = {0x0300: "SSL 3.0", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1", 0x0303: "TLS 1.2", 0x0304: "TLS 1.3"}


def tls_client_extras(p):
    """(alpn_list, supported_versions[], n_ciphers) — بهترین تلاش؛ خطا → ([], [], 0)"""
    try:
        o = 5 + 4 + 2 + 32                         # record hdr + hs hdr + ver + random
        sl = p[o]
        o += 1 + sl
        cl = struct.unpack_from("!H", p, o)[0]
        ncs = cl // 2
        o += 2 + cl
        o += 1 + p[o]
        el = struct.unpack_from("!H", p, o)[0]
        o += 2
        end = min(len(p), o + el)
        alpn, sv = [], []
        while o + 4 <= end:
            et, ln = struct.unpack_from("!HH", p, o)
            o += 4
            v = p[o:o + ln]
            if et == 16 and len(v) >= 3:           # ALPN
                q = 2
                while q < len(v):
                    L = v[q]
                    alpn.append(bytes(v[q + 1:q + 1 + L]).decode("ascii", "replace"))
                    q += 1 + L
            elif et == 43 and len(v) >= 3:         # supported_versions
                for q in range(1, len(v) - 1, 2):
                    sv.append(struct.unpack_from("!H", v, q)[0])
            o += ln
        return alpn, sv, ncs
    except Exception:
        return [], [], 0


def tls_server_info(p):
    """(version, cipher_suite) از ServerHello"""
    try:
        o = 5 + 4
        ver = struct.unpack_from("!H", p, o)[0]
        o += 2 + 32
        o += 1 + p[o]
        cs = struct.unpack_from("!H", p, o)[0]
        o += 3
        ext_len = struct.unpack_from("!H", p, o)[0]
        o += 2
        end = min(len(p), o + ext_len)
        while o + 4 <= end:
            et, ln = struct.unpack_from("!HH", p, o)
            if et == 43 and ln == 2:
                ver = struct.unpack_from("!H", p, o + 4)[0]
            o += 4 + ln
        return ver, cs
    except Exception:
        return 0, 0
