import os, sys, subprocess, zipfile
from pathlib import Path
import pytest
pytest.importorskip("scapy", reason="legacy scapy-built smoke test")

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from make_test_pcap import build  # noqa: E402
import pcap_safe_output as so  # noqa: E402


@pytest.fixture(scope="module")
def pcap(tmp_path_factory):
    p = tmp_path_factory.mktemp("d") / "t.pcap"
    build(str(p))
    return p


def run(args):
    return subprocess.run([sys.executable, str(ROOT / "pcap_analyzer.py"), *args],
                          capture_output=True, text=True, encoding="utf-8", timeout=120)


def test_doctor():
    assert run(["--doctor"]).returncode == 0


@pytest.mark.parametrize("mode", ["auto", "xor"])
def test_cli_detects_and_saves_safely(pcap, tmp_path, mode):
    out = tmp_path / "out"
    r = run([str(pcap), "--cli", "-o", str(out), "--sample-mode", mode])
    assert r.returncode == 0, r.stderr
    names = " ".join(p.name for p in out.rglob("*"))
    assert "pcap_report.html" in names and "suricata.rules" in names
    # هیچ فایل خام اجرایی نباید نوشته شده باشد
    assert not any(p.suffix.lower() in (".exe", ".dll") for p in out.rglob("*"))
    for key in ("PsExec", "T1102", "T1496", "T1557.001"):
        assert key in r.stdout or key in (out / "t_pcap_report.json").read_text(encoding="utf-8")


def test_xor_roundtrip(tmp_path):
    store = so.SampleStore(str(tmp_path), "xor")
    data = os.urandom(5000)
    path, mode = store.save(data, "a" * 64, ".exe")
    assert mode == "xor" and Path(path).read_bytes()[:6] == so.XOR_MAGIC
    out = so.restore_sample(path, str(tmp_path / "r.bin"))
    assert Path(out).read_bytes() == data


@pytest.mark.skipif(not so.HAS_PYZIPPER, reason="pyzipper not installed")
def test_zip_is_encrypted(tmp_path):
    path, _ = so.SampleStore(str(tmp_path), "zip").save(b"MZ" + b"\0" * 100, "b" * 64, ".exe")
    with zipfile.ZipFile(path) as z:
        with pytest.raises(Exception):
            z.read(z.namelist()[0])          # بدون رمز باز نمی‌شود


def test_defang_and_path_guard():
    assert so.defang("http://evil.com/a") == "hxxp://evil[.]com/a"
    assert so.defang("a" * 64) == "a" * 64
    assert so._risky_path_reason(Path("/")) is not None
    assert so._risky_path_reason(Path.home() / "Downloads") is not None


def test_exclusion_refuses_unmarked_dir(tmp_path):
    if so.IS_WINDOWS:
        ok, msg = so.add_defender_exclusion(str(tmp_path))
        assert not ok
    else:
        assert so.add_defender_exclusion(str(tmp_path))[0] is False


def test_meta_and_branding():
    import app_meta as m
    assert m.GITHUB_USER == "mr-coder20" and m.APP_SLUG == "pcap-analyzer"
    assert m.LATEST_RELEASE_URL.endswith("/releases/latest")
    for f in ROOT.glob("*.py"):
        assert "soc_omni" not in f.read_text(encoding="utf-8").lower(), f.name


def test_glass_renderer_headless():
    pytest.importorskip("PIL")
    try:
        import pcap_glass_ui as G
    except ImportError:  # python without tkinter
        pytest.skip("tkinter unavailable")
    bd = G.make_backdrop(400, 300)
    img, mean = G.render_glass(bd, 20, 20, 200, 120)
    assert img.size == (200, 120) and mean.startswith("#")
    assert G.make_app_icon(128).size == (128, 128)
