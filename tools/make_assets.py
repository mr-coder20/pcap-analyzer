#!/usr/bin/env python3
"""Generate app icons + social banner (needs Pillow). Run: python tools/make_assets.py"""
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from PIL import Image, ImageDraw, ImageFont, ImageFilter  # noqa: E402
import pcap_glass_ui as G  # noqa: E402
import app_meta as META  # noqa: E402

out = ROOT / "assets"
out.mkdir(exist_ok=True)
icon = G.make_app_icon(1024)
icon.resize((512, 512), Image.LANCZOS).save(out / "icon.png")
icon.save(out / "icon.ico", sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
try:
    icon.save(out / "icon.icns")
except Exception as e:  # PIL may lack icns writer on some builds
    print("icns skipped:", e)

# banner 1280x640 (GitHub social preview)
W, H = 1280, 640
bg = G.make_backdrop(W, H).convert("RGBA")
panel, _ = G.render_glass(bg.convert("RGB"), 90, 110, 1100, 420, radius=44, inset=14, level=2, sheen_on=True)
bg = panel.convert("RGBA")
bg.alpha_composite(icon.resize((200, 200), Image.LANCZOS), (150, 230))
d = ImageDraw.Draw(bg)
def font(sz, bold=True):
    for n in ("Inter-Bold.ttf", "DejaVuSans-Bold.ttf", "DejaVuSans.ttf"):
        try:
            return ImageFont.truetype(n, sz)
        except Exception:
            pass
    return ImageFont.load_default()
d.text((400, 240), META.APP_NAME, font=font(86), fill=(245, 247, 255, 255))
d.text((404, 346), "Offline PCAP / PCAPNG forensics · Windows · macOS · Linux", font=font(30), fill=(170, 180, 215, 255))
d.text((404, 410), f"by {META.AUTHOR}  ·  github.com/{META.GITHUB_USER}/{META.APP_SLUG}", font=font(26), fill=(139, 123, 255, 255))
bg.convert("RGB").save(out / "banner.png")
print("assets written to", out)
