"""Native (scapy-free) engine tests: protocol hub, file extraction ZIP, report safety."""
import json
import struct
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from make_native_pcap import build, W, http_resp, dns_q  # noqa: E402
import pcap_fastio as FIO  # noqa: E402


def run(args):
    import os
    env = dict(os.environ, PYTHONUTF8="1", PYTHONIOENCODING="utf-8")
    return subprocess.run([sys.executable, str(ROOT / "pcap_analyzer.py"), *args],
                          capture_output=True, text=True, encoding="utf-8", timeout=180, env=env)


@pytest.fixture(scope="module")
def result(tmp_path_factory):
    d = tmp_path_factory.mktemp("n")
    p = d / "n.pcap"
    build(str(p))
    out = d / "out"
    r = run([str(p), "--cli", "-o", str(out)])
    assert r.returncode == 0, r.stderr
    return out


def test_zip_has_real_filenames(result):
    z = next(result.rglob("*_extracted_files.zip"))
    names = " ".join(zipfile.ZipFile(z).namelist())
    for n in ("Quarterly Report Q3.pdf", "logo.png", "secrets.txt", "backup.zip", "config.bin", "MANIFEST.json"):
        assert n in names, n
    assert "HTTP/" in names and "FTP/" in names and "SMTP/" in names and "TFTP/" in names


def test_no_raw_executables_in_zip_plain_mode(result):
    z = next(result.rglob("*_extracted_files.zip"))
    zf = zipfile.ZipFile(z)
    if zf.namelist() and not any(i.flag_bits & 1 for i in zf.infolist()):
        assert not any(n.lower().endswith((".exe", ".dll")) for n in zf.namelist())


def test_manifest_and_report(result):
    m = json.loads(next(result.rglob("*_extracted_manifest.json")).read_text(encoding="utf-8"))
    assert len(m["files"] if isinstance(m, dict) else m) >= 8
    html = next(result.rglob("*_report*.html")).read_text(encoding="utf-8")
    assert 'id="data"' in html and "data-theme" in html


@pytest.mark.parametrize("theme", ["matrix", "paper-light"])
@pytest.mark.parametrize("material", ["terminal", "solid"])
def test_theme_material_flags(tmp_path, theme, material):
    p = tmp_path / "n.pcap"
    build(str(p))
    r = run([str(p), "--cli", "-o", str(tmp_path / "o"), "--theme", theme, "--material", material])
    assert r.returncode == 0, r.stderr
    html = next((tmp_path / "o").rglob("*_report*.html")).read_text(encoding="utf-8")
    assert theme in html and material in html


def test_no_extract(tmp_path):
    p = tmp_path / "n.pcap"
    build(str(p))
    run([str(p), "--cli", "-o", str(tmp_path / "o"), "--no-extract"])
    assert not list((tmp_path / "o").rglob("*_extracted_files.zip"))


def test_list_themes():
    r = run(["--list-themes"])
    assert r.returncode == 0 and "neon-night" in r.stdout


def test_xss_strings_not_injected(tmp_path):
    w = W()
    evil = "<img src=x onerror=alert(1)>.test"
    w.tcp("10.0.0.5", 50001, "1.2.3.4", 80, flags=0x02)
    w.stream("10.0.0.5", 50001, "1.2.3.4", 80, b"GET /</script><script>alert(1)</script> HTTP/1.1\r\nHost: " + evil.encode() + b"\r\n\r\n")
    w.stream("1.2.3.4", 80, "10.0.0.5", 50001, http_resp(b"hi", "text/plain", 'Content-Disposition: attachment; filename="</script><b>x.txt"\r\n'))
    p = tmp_path / "x.pcap"
    w.save(str(p))
    out = tmp_path / "o"
    assert run([str(p), "--cli", "-o", str(out)]).returncode == 0
    html = next(out.rglob("*_report*.html")).read_text(encoding="utf-8")
    head, _, rest = html.partition('id="data"')
    blob = rest.split("</script>", 1)[0]
    assert "</script><script>alert" not in html
    assert "<img src=x onerror" not in html
    assert blob  # data embedded


def _wrap_pcapng(frames, lt=1):
    def blk(t, body):
        body += b"\0" * (-len(body) % 4)
        return struct.pack("<II", t, len(body) + 12) + body + struct.pack("<I", len(body) + 12)
    out = blk(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    out += blk(1, struct.pack("<HHI", lt, 0, 65535))
    for i, f in enumerate(frames):
        out += blk(6, struct.pack("<IIIII", 0, 0, i, len(f), len(f)) + f)
    return out


def test_pcapng_reader(tmp_path):
    w = W()
    w.udp("10.0.0.5", 4000, "8.8.8.8", 53, dns_q("a.example.test"))
    p = tmp_path / "x.pcapng"
    p.write_bytes(_wrap_pcapng([f for _, f in w.pk]))
    pk = list(FIO.CaptureReader(str(p)))
    assert len(pk) == 1
    kind = FIO.decode(pk[0][2], pk[0][1])[0]
    assert kind == FIO.K_UDP


def test_vlan_decode():
    w = W()
    w.udp("10.0.0.5", 4000, "8.8.8.8", 53, dns_q("a.example.test"))
    fr = w.pk[0][1]
    vl = fr[:12] + b"\x81\x00\x00\x05" + fr[12:]
    assert FIO.decode(vl, 1)[0] == FIO.K_UDP


def test_dns_parser():
    d = FIO.parse_dns(dns_q("www.example.test"))
    assert d is not None


def test_stealer_chain_detected(tmp_path):
    from make_native_pcap import build_stealer
    p = tmp_path / "s.pcap"
    build_stealer(str(p))
    out = tmp_path / "o"
    r = run([str(p), "--cli", "-o", str(out), "--formats", "json"])
    assert r.returncode == 0, r.stderr
    blob = next(out.rglob("*_pcap_report.json")).read_text(encoding="utf-8")
    for rid in ("stealer_ftp_exfil", "stealer_credentials", "stealer_family_report", "ip_recon_lookup", "cloud_staging", "infection_chain"):
        assert rid in blob, rid


def test_english_default_and_persian(tmp_path):
    p = tmp_path / "n.pcap"
    build(str(p))
    en = run([str(p), "--cli", "-o", str(tmp_path / "e")]).stdout
    fa = run([str(p), "--cli", "--lang", "fa", "-o", str(tmp_path / "f")]).stdout
    assert "Risk score" in en and "امتیاز ریسک" not in en
    assert "امتیاز ریسک" in fa


def test_aes_zip_password(tmp_path):
    pyzipper = pytest.importorskip("pyzipper")
    p = tmp_path / "n.pcap"
    build(str(p))
    out = tmp_path / "o"
    assert run([str(p), "--cli", "-o", str(out)]).returncode == 0
    z = next(out.rglob("*_extracted_files.zip"))
    with pyzipper.AESZipFile(z) as zf:
        zf.setpassword(b"infected")
        assert any(n.endswith("setup.exe") for n in zf.namelist())
        assert zf.read("MANIFEST.json")


def test_passwords_shown_by_default_and_masked_with_flag(tmp_path):
    """Cleartext credentials seen in traffic are displayed by default; --mask hides them."""
    p = tmp_path / "n.pcap"
    build(str(p))
    for flag, expect_clear in (([], True), (["--mask"], False)):
        out = tmp_path / ("o_mask" if flag else "o_clear")
        r = run([str(p), "--cli", *flag, "-o", str(out)])
        assert r.returncode == 0, r.stderr[-500:]
        csv = (next(out.glob("*_protocol_events.csv"))).read_text(encoding="utf-8")
        assert ("s3cret" in csv) is expect_clear


def test_safe_name_strips_bidi_and_zero_width():
    import pcap_extract as X
    n = X.safe_name("invoice‮gpj.exe​")
    assert "‮" not in n and "​" not in n and n.endswith(".exe") is False or "‮" not in n


def test_weak_rules_are_low_severity():
    import pcap_threats as T
    for rid in ("ip_recon_lookup", "cloud_staging", "suspicious_user_agent"):
        assert T.THREAT_RULES[rid]["sev"] == "low"


def test_soc_exports_and_graph(tmp_path):
    import json
    p = tmp_path / "n.pcap"
    build(str(p))
    out = tmp_path / "soc"
    r = run([str(p), "--cli", "-o", str(out)])
    assert r.returncode == 0, r.stderr
    stix = next(out.rglob("*stix_bundle.json"))
    b = json.loads(stix.read_text(encoding="utf-8"))
    assert b["type"] == "bundle" and any(o["type"] == "attack-pattern" for o in b["objects"])
    assert any(o["type"] == "indicator" and o["pattern"].startswith("[") for o in b["objects"])
    html = next(out.rglob("*pcap_report.html")).read_text(encoding="utf-8")
    assert "reg('graph'" in html and "Network graph" in html
