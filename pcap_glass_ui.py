# -*- coding: utf-8 -*-
"""
PCAP Analyzer — "Liquid Glass" widget kit for Tkinter.

Tk has no real transparency/blur, so the glass is *rendered*: a soft aurora
backdrop is generated once, and every panel crops the backdrop beneath it,
frosts it, adds a specular edge + sheen + shadow and paints the result as its
own image. With Pillow missing everything degrades to flat rounded shapes.

Author: mr-coder20 · https://github.com/mr-coder20/pcap-analyzer
"""
import math
import sys
import tkinter as tk
from tkinter import ttk

try:
    from PIL import Image, ImageChops, ImageDraw, ImageFilter, ImageTk
    HAS_PIL = True
except Exception:  # pragma: no cover
    HAS_PIL = False

# ----------------------------------------------------------------------------
# Palette
# ----------------------------------------------------------------------------
PAL = {
    "bg": "#05070f", "ink": "#f5f7ff", "mut": "#9ba6c6", "dim": "#667191",
    "acc": "#8b7bff", "acc2": "#22d3ee", "pink": "#f472b6",
    "ok": "#34d399", "warn": "#fbbf24", "bad": "#fb7185", "orange": "#fb923c",
    "well": "#090d1b", "well2": "#0d1224", "line": "#26304f", "glass": "#10162b",
}


def hex2rgb(h):
    h = h.lstrip("#")
    return tuple(int(h[i:i + 2], 16) for i in (0, 2, 4))


def rgb2hex(c):
    return "#%02x%02x%02x" % tuple(max(0, min(255, int(v))) for v in c)


def mix(a, b, t):
    """Blend colour a→b by t (0..1), hex in, hex out."""
    ra, rb = hex2rgb(a), hex2rgb(b)
    return rgb2hex([ra[i] + (rb[i] - ra[i]) * t for i in range(3)])


def apply_palette(pal):
    """جایگزینی پالت (قبل از ساخت هر ویجت صدا زده شود)"""
    PAL.update(pal)


def pick_fonts(root):
    from tkinter import font as tkfont
    try:
        fams = set(tkfont.families(root))
    except Exception:
        fams = set()

    def pick(*names, default):
        for n in names:
            if n in fams:
                return n
        return default
    ui = pick("Vazirmatn", "Vazir", "Segoe UI Variable Text", "Segoe UI", "SF Pro Text", "Helvetica Neue",
              "Inter", "Noto Sans", "DejaVu Sans", "Tahoma", default="TkDefaultFont")
    mono = pick("Cascadia Mono", "JetBrains Mono", "SF Mono", "Menlo", "Consolas", "DejaVu Sans Mono",
                "Courier New", default="TkFixedFont")
    return ui, mono


# ----------------------------------------------------------------------------
# Backdrop (aurora)
# ----------------------------------------------------------------------------
def _blobs():
    """لکه‌های aurora بر اساس تم فعال (PAL)"""
    def tint(h, k):
        c = hex2rgb(h)
        return tuple(int(c[i] * k) for i in range(3))
    return [  # (cx, cy, radius, colour) in fractions of the canvas
        (0.06, 0.00, 0.34, tint(PAL["pink"], .34)),
        (0.96, 0.02, 0.30, tint(PAL["acc"], .26)),
        (0.82, 1.02, 0.34, tint(PAL["acc2"], .26)),
        (0.14, 1.00, 0.28, tint(PAL["acc"], .20)),
        (0.52, 0.50, 0.20, tint(PAL["pink"], .10)),
    ]


def make_backdrop(w, h):
    """Aurora gradient as a PIL image (w×h)."""
    w, h = max(64, int(w)), max(64, int(h))
    s = 6
    sw, sh = max(16, w // s), max(16, h // s)
    base = Image.new("RGB", (sw, sh), hex2rgb(PAL["bg"]))
    m = max(sw, sh)
    for cx, cy, r, col in _blobs():
        layer = Image.new("RGB", (sw, sh), (0, 0, 0))
        d = ImageDraw.Draw(layer)
        rr = r * m
        d.ellipse([cx * sw - rr, cy * sh - rr, cx * sw + rr, cy * sh + rr], fill=col)
        layer = layer.filter(ImageFilter.GaussianBlur(radius=rr * 0.45))
        base = ImageChops.add(base, layer)
    img = base.resize((w, h), Image.BICUBIC)
    try:  # fine grain removes banding
        noise = Image.effect_noise((w, h), 14).convert("RGB")
        img = ImageChops.add(img, noise.point(lambda v: max(0, v - 118) // 3 if v > 118 else 0))
    except Exception:
        pass
    return img


# ----------------------------------------------------------------------------
# Glass rendering
# ----------------------------------------------------------------------------
def _rr_mask(size, box, radius, ss=2):
    w, h = size
    m = Image.new("L", (w * ss, h * ss), 0)
    ImageDraw.Draw(m).rounded_rectangle([v * ss for v in box], radius=radius * ss, fill=255)
    return m.resize((w, h), Image.LANCZOS)


def _rr_ring(size, box, radius, width=1, ss=3):
    w, h = size
    m = Image.new("L", (w * ss, h * ss), 0)
    ImageDraw.Draw(m).rounded_rectangle([v * ss for v in box], radius=radius * ss, outline=255, width=width * ss)
    return m.resize((w, h), Image.LANCZOS)


def render_glass(backdrop, x, y, w, h, radius=22, inset=8, level=1, tint=None, shadow=True, flat=None, sheen_on=True):
    """Return (PIL image w×h, mean inner colour hex)."""
    if flat:
        crop = Image.new("RGB", (w, h), hex2rgb(flat))
    else:
        crop = backdrop.crop((x, y, x + w, y + h))
        if crop.size != (w, h):
            crop = crop.resize((w, h))
    box = (inset, inset, w - inset - 1, h - inset - 1)
    out = crop.copy()
    if shadow and inset >= 4:
        sh = Image.new("L", (w, h), 0)
        ImageDraw.Draw(sh).rounded_rectangle([box[0] + 1, box[1] + 9, box[2] - 1, box[3] + 7], radius=radius, fill=150)
        sh = sh.filter(ImageFilter.GaussianBlur(inset * 1.1))
        out = Image.composite(Image.new("RGB", (w, h), (0, 0, 0)), out, sh.point(lambda v: int(v * .55)))
    mask = _rr_mask((w, h), box, radius)
    inner = crop.filter(ImageFilter.GaussianBlur(12))
    mean = inner.resize((1, 1), Image.BOX).getpixel((0, 0))
    inner = Image.blend(inner, Image.new("RGB", (w, h), mean), 0.55)          # frosted + calmer
    if tint:
        inner = Image.blend(inner, Image.new("RGB", (w, h), hex2rgb(tint)), 0.18)
    inner = Image.blend(inner, Image.new("RGB", (w, h), (7, 9, 22)), 0.42)     # smoky glass → readable text
    lift = 0.040 + 0.024 * level
    inner = Image.blend(inner, Image.new("RGB", (w, h), (255, 255, 255)), lift)
    # diagonal sheen
    g = Image.linear_gradient("L").resize((w, h)).rotate(0)
    sheen = ImageChops.multiply(g.point(lambda v: 255 - v), Image.new("L", (w, h), 255)).point(lambda v: int(v * (.06 if flat else .10)))
    if sheen_on:
        inner = Image.composite(Image.new("RGB", (w, h), (255, 255, 255)), inner, sheen)
    out = Image.composite(inner, out, mask)
    # edges: soft full ring + bright specular on top edge fading downward
    ring = _rr_ring((w, h), box, radius, 1)
    out = Image.composite(Image.new("RGB", (w, h), (255, 255, 255)), out, ring.point(lambda v: int(v * .16)))
    vg = Image.linear_gradient("L").resize((w, h)).point(lambda v: max(0, 255 - v * 2))
    spec = ImageChops.multiply(ring, vg)
    out = Image.composite(Image.new("RGB", (w, h), (255, 255, 255)), out, spec.point(lambda v: int(v * .62)))
    ring2 = _rr_ring((w, h), (box[0] + 1, box[1] + 1, box[2] - 1, box[3] - 1), radius - 1, 1)
    out = Image.composite(Image.new("RGB", (w, h), (255, 255, 255)), out,
                          ImageChops.multiply(ring2, vg).point(lambda v: int(v * .10)))
    inner_mean = inner.resize((1, 1), Image.BOX).getpixel((0, 0))
    return out, rgb2hex(inner_mean)


def render_pill(w, h, c1, c2=None, bg="#000000", glow=True, border=True, alpha=1.0, glass=False, ss=3):
    """Gradient/glass pill button image, composited on `bg`."""
    base = Image.new("RGB", (w, h), hex2rgb(bg))
    box = (3, 3, w - 4, h - 4)
    r = (box[3] - box[1]) // 2
    mask = _rr_mask((w, h), box, r, ss)
    if glow and not glass:
        gl = Image.new("L", (w, h), 0)
        ImageDraw.Draw(gl).rounded_rectangle([box[0], box[1] + 2, box[2], box[3] + 2], radius=r, fill=255)
        gl = gl.filter(ImageFilter.GaussianBlur(6)).point(lambda v: int(v * .45))
        base = Image.composite(Image.new("RGB", (w, h), hex2rgb(c1)), base, gl)
    if glass:
        fill = Image.blend(Image.new("RGB", (w, h), hex2rgb(bg)), Image.new("RGB", (w, h), (255, 255, 255)), .09 + .08 * alpha)
    else:
        a, b = hex2rgb(c1), hex2rgb(c2 or c1)
        grad = Image.linear_gradient("L").rotate(90).resize((w, h))  # left→right
        fill = Image.composite(Image.new("RGB", (w, h), b), Image.new("RGB", (w, h), a), grad)
        if alpha < 1:
            fill = Image.blend(Image.new("RGB", (w, h), hex2rgb(bg)), fill, alpha)
    base = Image.composite(fill, base, mask)
    # top gloss
    gloss = Image.new("L", (w, h), 0)
    ImageDraw.Draw(gloss).rounded_rectangle([box[0] + 2, box[1] + 1, box[2] - 2, (box[1] + box[3]) // 2], radius=r, fill=255)
    gloss = ImageChops.multiply(gloss.filter(ImageFilter.GaussianBlur(1.2)), mask).point(lambda v: int(v * (.22 if not glass else .10)))
    base = Image.composite(Image.new("RGB", (w, h), (255, 255, 255)), base, gloss)
    if border:
        ring = _rr_ring((w, h), box, r, 1)
        vg = Image.linear_gradient("L").resize((w, h)).point(lambda v: max(60, 255 - v))
        base = Image.composite(Image.new("RGB", (w, h), (255, 255, 255)), base,
                               ImageChops.multiply(ring, vg).point(lambda v: int(v * .45)))
    return base


# ----------------------------------------------------------------------------
# Backdrop manager
# ----------------------------------------------------------------------------
class Backdrop:
    """Owns the aurora image; keeps a Label under the whole window showing it."""

    def __init__(self, root):
        self.root = root
        self.img = None
        self._photo = None
        self._after = None
        self.label = None
        self.size = (0, 0)
        if HAS_PIL:
            self.label = tk.Label(root, bd=0, highlightthickness=0, bg=PAL["bg"])
            self.label.place(x=0, y=0, relwidth=1, relheight=1)
            self.label.lower()
            root.bind("<Configure>", self._on_cfg, add="+")
            self._rebuild(root.winfo_width() or 1500, root.winfo_height() or 940)

    def _on_cfg(self, e):
        if e.widget is not self.root:
            return
        if self._after:
            self.root.after_cancel(self._after)
        self._after = self.root.after(90, lambda: self._rebuild(e.width, e.height))

    def _rebuild(self, w, h):
        self._after = None
        if w < 100 or h < 100 or (w, h) == self.size:
            return
        self.size = (w, h)
        self.img = make_backdrop(w, h)
        self._photo = ImageTk.PhotoImage(self.img)
        self.label.configure(image=self._photo)
        self.root.event_generate("<<BackdropChanged>>", when="tail")


def _backdrop_of(widget):
    root = widget.winfo_toplevel()
    return getattr(root, "backdrop", None)


# ----------------------------------------------------------------------------
# GlassPanel
# ----------------------------------------------------------------------------
class GlassPanel(tk.Canvas):
    """A frosted-glass rounded panel. Put child widgets into `.inner`."""

    def __init__(self, parent, radius=22, inset=8, pad=14, level=1, tint=None, shadow=True,
                 inner_widget=True, **kw):
        kw.setdefault("highlightthickness", 0)
        kw.setdefault("bd", 0)
        kw.setdefault("bg", PAL["bg"])
        super().__init__(parent, **kw)
        self.radius, self.inset, self.pad, self.level, self.tint, self.shadow = radius, inset, pad, level, tint, shadow
        self._photo = None
        self._key = None
        self._after = None
        self.fill = PAL["glass"]
        self.inner = None
        self._win = None
        if inner_widget:
            self.inner = tk.Frame(self, bg=self.fill, bd=0, highlightthickness=0)
            self._win = self.create_window(inset + pad, inset + pad, window=self.inner, anchor="nw", tags="inner")
        self.bind("<Configure>", self._on_cfg)
        self.bind("<<BackdropChanged>>", lambda e: self.schedule())
        self.after(30, lambda: self._bind_root())

    def _bind_root(self):
        par = self._glass_parent()
        if par is not None:
            par.bind("<<GlassFill>>", lambda e: self.schedule(), add="+")
        try:
            self.winfo_toplevel().bind("<<BackdropChanged>>", lambda e: self.schedule(force=True), add="+")
        except tk.TclError:
            pass

    def _on_cfg(self, e):
        if self.inner is not None:
            iw = max(10, e.width - 2 * (self.inset + self.pad))
            ih = max(10, e.height - 2 * (self.inset + self.pad))
            self.itemconfigure(self._win, width=iw, height=ih)
        self.schedule()

    def schedule(self, force=False):
        if force:
            self._key = None
        if self._after:
            try:
                self.after_cancel(self._after)
            except tk.TclError:
                return
        self._after = self.after(50, self.paint)

    def _glass_parent(self):
        w = self.master
        while w is not None:
            if isinstance(w, GlassPanel):
                return w
            w = getattr(w, "master", None)
        return None

    def _origin(self):
        top = self.winfo_toplevel()
        return self.winfo_rootx() - top.winfo_rootx(), self.winfo_rooty() - top.winfo_rooty()

    def paint(self):
        self._after = None
        try:
            w, h = self.winfo_width(), self.winfo_height()
        except tk.TclError:
            return
        if w < 24 or h < 24:
            return
        bd = _backdrop_of(self)
        if HAS_PIL and bd is not None and bd.img is not None:
            x, y = self._origin()
            par = self._glass_parent()
            flat = par.fill if par is not None else None
            key = (w, h, x, y, bd.size, self.level, self.tint, flat)
            if key == self._key:
                return
            self._key = key
            img, mean = render_glass(bd.img, x, y, w, h, self.radius, self.inset, self.level, self.tint, self.shadow, flat=flat, sheen_on=self.inner is None)
            self._photo = ImageTk.PhotoImage(img)
            self.delete("glass")
            self.create_image(0, 0, image=self._photo, anchor="nw", tags="glass")
            self.tag_lower("glass")
            self._set_fill(mean)
        else:
            self.delete("glass")
            i = self.inset
            self._rounded(i, i, w - i, h - i, self.radius, fill=PAL["glass"], outline=PAL["line"], tags="glass")
            self.tag_lower("glass")
            self._set_fill(PAL["glass"])

    def _set_fill(self, col):
        if col == self.fill and self.inner is not None and getattr(self, "_filled", False):
            return
        self._filled = True
        self.fill = col
        if self.inner is not None:
            self.inner.configure(bg=col)
            self._recolor(self.inner, col)
        self.event_generate("<<GlassFill>>")

    def _recolor(self, widget, col):
        for ch in widget.winfo_children():
            if isinstance(ch, GlassPanel):
                continue
            if getattr(ch, "_glass_transparent", False):
                try:
                    ch.configure(bg=col)
                    if hasattr(ch, "_draw"):
                        ch._draw()
                except tk.TclError:
                    pass
            if isinstance(ch, (tk.Frame, tk.Label)) and not getattr(ch, "_glass_keep", False):
                try:
                    ch.configure(bg=col)
                except tk.TclError:
                    pass
            self._recolor(ch, col)

    def _rounded(self, x1, y1, x2, y2, r, **kw):
        pts = [x1 + r, y1, x2 - r, y1, x2, y1, x2, y1 + r, x2, y2 - r, x2, y2, x2 - r, y2,
               x1 + r, y2, x1, y2, x1, y2 - r, x1, y1 + r, x1, y1]
        return self.create_polygon(pts, smooth=True, **kw)

    def content_box(self):
        i = self.inset
        return i, i, self.winfo_width() - i, self.winfo_height() - i


def _parent_bg(w):
    try:
        return w.cget("bg")
    except Exception:
        return PAL["glass"]


# ----------------------------------------------------------------------------
# GlassButton
# ----------------------------------------------------------------------------
class GlassButton(tk.Canvas):
    VARIANTS = {
        "primary": ("#7c6cff", "#22b8e8"),
        "success": ("#10b981", "#2dd4bf"),
        "danger": ("#f43f5e", "#fb7185"),
        "ghost": (None, None),
    }

    def __init__(self, parent, text="", command=None, variant="ghost", width=None, height=38,
                 font=None, state="normal", icon=None, **kw):
        bg = kw.pop("bg", None) or _parent_bg(parent)
        super().__init__(parent, bg=bg, highlightthickness=0, bd=0, height=height, cursor="hand2", **kw)
        self._glass_transparent = True
        self.text, self.command, self.variant, self._state = text, command, variant, state
        self.font = font or ("TkDefaultFont", 10, "bold")
        self.icon = icon
        self._hover = self._down = False
        self._photos = {}
        self._cur = None
        self._req_w = width
        import tkinter.font as tkf
        try:
            tw = tkf.Font(font=self.font).measure(text + (("  " + icon) if icon else ""))
        except tk.TclError:
            tw = len(text) * 8
        self.configure(width=width or tw + 44)
        self.bind("<Configure>", lambda e: self._draw())
        self.bind("<Enter>", lambda e: self._set(hover=True))
        self.bind("<Leave>", lambda e: self._set(hover=False, down=False))
        self.bind("<ButtonPress-1>", lambda e: self._set(down=True))
        self.bind("<ButtonRelease-1>", self._release)
        self.bind("<Return>", self._release)
        self.bind("<space>", self._release)

    # compat with ttk-ish API
    def configure(self, cnf=None, **kw):
        if cnf:
            kw.update(cnf)
        redraw = False
        if "state" in kw:
            self._state = kw.pop("state")
            self.configure_cursor()
            redraw = True
        if "text" in kw:
            self.text = kw.pop("text")
            redraw = True
        if "command" in kw:
            self.command = kw.pop("command")
        if "bg" in kw:
            self._photos.clear()
            redraw = True
        if kw:
            super().configure(**kw)
        if redraw:
            self._draw()
    config = configure

    def configure_cursor(self):
        try:
            super().configure(cursor="hand2" if self._state == "normal" else "arrow")
        except tk.TclError:
            pass

    def _set(self, hover=None, down=None):
        if hover is not None:
            self._hover = hover
        if down is not None:
            self._down = down
        self._draw()

    def _release(self, e=None):
        was = self._down
        self._down = False
        self._draw()
        if self._state == "normal" and self.command and (was or e is None or e.type == "2"):
            self.command()

    def _draw(self):
        w, h = self.winfo_width(), self.winfo_height()
        if w < 10 or h < 10:
            return
        disabled = self._state != "normal"
        st = "off" if disabled else ("down" if self._down else ("hover" if self._hover else "idle"))
        bg = self.cget("bg")
        key = (w, h, st, self.variant, bg)
        self.delete("all")
        c1, c2 = self.VARIANTS.get(self.variant, (None, None))
        if HAS_PIL:
            ph = self._photos.get(key)
            if ph is None:
                if self.variant == "ghost" or c1 is None:
                    a = {"idle": .0, "hover": .8, "down": 1.0, "off": 0.0}[st]
                    img = render_pill(w, h, "#ffffff", None, bg, glow=False, glass=True, alpha=a)
                else:
                    al = {"idle": .92, "hover": 1.0, "down": .78, "off": .28}[st]
                    img = render_pill(w, h, c1, c2, bg, glow=(st != "off"), alpha=al)
                ph = ImageTk.PhotoImage(img)
                self._photos[key] = ph
            self.create_image(0, 0, image=ph, anchor="nw")
        else:
            col = c1 or PAL["well2"]
            self.create_rectangle(2, 2, w - 2, h - 2, fill=col, outline=PAL["line"])
        fg = "#8993b5" if disabled else ("#ffffff" if self.variant != "ghost" else PAL["ink"])
        label = self.text if not self.icon else f"{self.icon}  {self.text}"
        self.create_text(w / 2, h / 2 + (1 if self._down else 0), text=label, fill=fg, font=self.font)


# ----------------------------------------------------------------------------
# Segmented navigation
# ----------------------------------------------------------------------------
class SegmentedNav(tk.Canvas):
    def __init__(self, parent, items, on_select, font, height=44, **kw):
        bg = kw.pop("bg", None) or _parent_bg(parent)
        super().__init__(parent, bg=bg, highlightthickness=0, bd=0, height=height, cursor="hand2", **kw)
        self._glass_transparent = True
        self.items, self.on_select, self.font = items, on_select, font
        self.index = 0
        self._x = None       # animated highlight x
        self._anim = None
        self._photo = None
        self._hover = -1
        self.bind("<Configure>", lambda e: self._draw())
        self.bind("<Button-1>", self._click)
        self.bind("<Motion>", self._motion)
        self.bind("<Leave>", lambda e: (setattr(self, "_hover", -1), self._draw()))

    def _slot(self, i):
        w = self.winfo_width() - 8
        n = len(self.items)
        sw = w / n
        return 4 + i * sw, 4 + (i + 1) * sw

    def _which(self, x):
        n = len(self.items)
        i = int((x - 4) / max(1, (self.winfo_width() - 8) / n))
        return max(0, min(n - 1, i))

    def _motion(self, e):
        h = self._which(e.x)
        if h != self._hover:
            self._hover = h
            self._draw()

    def _click(self, e):
        self.select(self._which(e.x))

    def select(self, i, fire=True):
        if i == self.index and self._x is not None:
            return
        self.index = i
        self._animate()
        if fire:
            self.on_select(i)

    def _animate(self):
        target = self._slot(self.index)[0]
        if self._x is None:
            self._x = target
            self._draw()
            return
        if self._anim:
            self.after_cancel(self._anim)

        def step():
            d = target - self._x
            if abs(d) < 1.2:
                self._x = target
                self._anim = None
            else:
                self._x += d * 0.32
                self._anim = self.after(14, step)
            self._draw()
        step()

    def _draw(self):
        w, h = self.winfo_width(), self.winfo_height()
        if w < 50:
            return
        self.delete("all")
        bg = self.cget("bg")
        n = len(self.items)
        sw = (w - 8) / n
        if self._anim is None:
            self._x = self._slot(self.index)[0]
        if HAS_PIL:
            key = (w, h, bg)
            if getattr(self, "_trough_key", None) != key:
                self._trough = ImageTk.PhotoImage(render_pill(w, h, "#000000", None, bg, glow=False, glass=True, alpha=-0.6 + 0.6))
                self._trough_key = key
            self.create_image(0, 0, image=self._trough, anchor="nw")
            pw = int(sw)
            pk = (pw, h - 6, bg)
            if getattr(self, "_pill_key", None) != pk:
                self._pill = ImageTk.PhotoImage(render_pill(pw, h - 6, "#7c6cff", "#22b8e8", bg, glow=True, alpha=.95))
                self._pill_key = pk
            self.create_image(self._x, 3, image=self._pill, anchor="nw")
        else:
            self.create_rectangle(2, 2, w - 2, h - 2, outline=PAL["line"], fill=PAL["well2"])
            self.create_rectangle(self._x, 4, self._x + sw, h - 4, outline="", fill=PAL["acc"])
        for i, label in enumerate(self.items):
            x1, x2 = self._slot(i)
            active = (i == self.index)
            col = "#ffffff" if active else (PAL["ink"] if i == self._hover else "#b4bcdb")
            self.create_text((x1 + x2) / 2, h / 2, text=label, fill=col, font=self.font)


# ----------------------------------------------------------------------------
# Progress, switch, field, stat card, link label
# ----------------------------------------------------------------------------
class GlassProgress(tk.Canvas):
    def __init__(self, parent, height=10, **kw):
        bg = kw.pop("bg", None) or _parent_bg(parent)
        super().__init__(parent, bg=bg, height=height, highlightthickness=0, bd=0, **kw)
        self._glass_transparent = True
        self.value = 0.0
        self._shown = 0.0
        self._t = 0
        self._job = None
        self.bind("<Configure>", lambda e: self._draw())

    def __setitem__(self, k, v):
        if k == "value":
            self.value = float(v)
            if not self._job:
                self._tick()
        else:
            super().__setitem__(k, v)

    def _tick(self):
        self._t += 1
        d = self.value - self._shown
        self._shown = self.value if abs(d) < .15 else self._shown + d * .25
        self._draw()
        self._job = self.after(30, self._tick) if (abs(self.value - self._shown) > .15 or 0 < self._shown < 100) else None

    def _draw(self):
        w, h = self.winfo_width(), self.winfo_height()
        if w < 10:
            return
        self.delete("all")
        r = h // 2
        self._pill(0, 0, w, h, PAL["well2"], r)
        fw = w * self._shown / 100
        if fw > 2:
            steps = max(2, int(fw // 6))
            for i in range(steps):
                x1 = fw * i / steps
                x2 = fw * (i + 1) / steps
                col = mix("#7c6cff", "#22d3ee", (i / steps))
                if i == 0:
                    self._pill(0, 1, x2 + 2, h - 1, col, r - 1)
                elif i == steps - 1:
                    self._pill(x1 - 4, 1, fw, h - 1, col, r - 1)
                else:
                    self.create_rectangle(x1, 1, x2 + 1, h - 1, outline="", fill=col)
            if 0 < self._shown < 100:  # moving shimmer
                sx = (self._t * 14) % (fw + 60) - 30
                self.create_rectangle(max(0, sx), 2, min(fw, sx + 26), h - 2, outline="", fill=mix("#22d3ee", "#ffffff", .5), stipple="gray50")

    def _pill(self, x1, y1, x2, y2, col, r):
        r = max(1, min(r, (x2 - x1) / 2, (y2 - y1) / 2))
        self.create_oval(x1, y1, x1 + 2 * r, y2, fill=col, outline="")
        self.create_oval(x2 - 2 * r, y1, x2, y2, fill=col, outline="")
        self.create_rectangle(x1 + r, y1, x2 - r, y2, fill=col, outline="")


class GlassSwitch(tk.Canvas):
    def __init__(self, parent, text, variable, font, color=None, **kw):
        bg = kw.pop("bg", None) or _parent_bg(parent)
        super().__init__(parent, bg=bg, height=34, highlightthickness=0, bd=0, cursor="hand2", **kw)
        self._glass_transparent = True
        self.var, self.text, self.font, self.color = variable, text, font, color or PAL["ink"]
        self._pos = 1.0 if variable.get() else 0.0
        self.bind("<Button-1>", self._toggle)
        self.bind("<Configure>", lambda e: self._draw())
        self.var.trace_add("write", lambda *_: self._anim())

    def _toggle(self, e=None):
        self.var.set(not self.var.get())

    def _anim(self):
        target = 1.0 if self.var.get() else 0.0
        if abs(self._pos - target) < .05:
            self._pos = target
            self._draw()
            return
        self._pos += (target - self._pos) * .4
        self._draw()
        self.after(16, self._anim)

    def _draw(self):
        w, h = self.winfo_width(), self.winfo_height()
        if w < 20:
            return
        self.delete("all")
        tw, th = 42, 22
        x0, y0 = w - tw - 2, (h - th) / 2          # right side (RTL)
        col = mix(PAL["well2"], PAL["acc"], self._pos)
        r = th / 2
        self.create_oval(x0, y0, x0 + th, y0 + th, fill=col, outline="")
        self.create_oval(x0 + tw - th, y0, x0 + tw, y0 + th, fill=col, outline="")
        self.create_rectangle(x0 + r, y0, x0 + tw - r, y0 + th, fill=col, outline="")
        kx = x0 + 3 + (tw - th) * self._pos
        self.create_oval(kx, y0 + 3, kx + th - 6, y0 + th - 3, fill="#ffffff", outline="")
        self.create_text(x0 - 12, h / 2, text=self.text, anchor="e", fill=self.color, font=self.font, justify="right")


class GlassField(tk.Canvas):
    """Rounded 'well' that hosts an Entry or Spinbox."""

    def __init__(self, parent, textvariable, font, width=220, height=36, spin=None, fg=None, **kw):
        bg = kw.pop("bg", None) or _parent_bg(parent)
        super().__init__(parent, bg=bg, height=height, width=width, highlightthickness=0, bd=0, **kw)
        self._glass_transparent = True
        self.focus = False
        common = dict(bg=PAL["well"], fg=fg or PAL["ink"], insertbackground="#ffffff", relief="flat", bd=0,
                      highlightthickness=0, font=font, textvariable=textvariable,
                      selectbackground=PAL["acc"], selectforeground="#fff")
        if spin:
            self.entry = tk.Spinbox(self, from_=spin[0], to=spin[1], increment=spin[2], buttonbackground=PAL["well2"],
                                    justify="left", **common)
        else:
            self.entry = tk.Entry(self, **common)
        self.entry._glass_keep = True
        self._win = self.create_window(14, height / 2, window=self.entry, anchor="w")
        self.bind("<Configure>", self._cfg)
        self.entry.bind("<FocusIn>", lambda e: self._f(True))
        self.entry.bind("<FocusOut>", lambda e: self._f(False))

    def _f(self, v):
        self.focus = v
        self._draw()

    def _cfg(self, e):
        self.itemconfigure(self._win, width=max(20, e.width - 28))
        self.coords(self._win, 14, e.height / 2)
        self._draw()

    def _draw(self):
        w, h = self.winfo_width(), self.winfo_height()
        if w < 20:
            return
        self.delete("bgw")
        r = h / 2 - 1
        col = PAL["well"]
        edge = PAL["acc"] if self.focus else PAL["line"]
        for (x1, x2) in ((1, 1 + 2 * r), (w - 1 - 2 * r, w - 1)):
            self.create_oval(x1, 1, x2, h - 1, fill=col, outline=edge, tags="bgw")
        self.create_rectangle(1 + r, 1, w - 1 - r, h - 1, fill=col, outline="", tags="bgw")
        self.create_line(1 + r, 1, w - 1 - r, 1, fill=edge, tags="bgw")
        self.create_line(1 + r, h - 1, w - 1 - r, h - 1, fill=edge, tags="bgw")
        self.create_rectangle(r + 2, 3, w - r - 2, h - 3, fill=col, outline="", tags="bgw")
        self.tag_lower("bgw")


class StatCard(GlassPanel):
    """KPI tile drawn directly on the glass (transparent text)."""

    def __init__(self, parent, title, value, color, fonts, **kw):
        super().__init__(parent, radius=18, inset=6, pad=0, level=1, inner_widget=False, height=92, **kw)
        self.title, self.value, self.color, self.F = title, value, color, fonts
        self.bind("<Configure>", lambda e: (self.schedule(), self._text()), add="+")

    def configure(self, cnf=None, **kw):
        if "text" in kw:
            self.value = kw.pop("text")
            self._text()
        if kw or cnf:
            super().configure(cnf, **kw)
    config = configure

    def paint(self):
        super().paint()
        self._text()

    def _text(self):
        w, h = self.winfo_width(), self.winfo_height()
        if w < 40:
            return
        self.delete("txt")
        self.create_oval(w - 26, 24, w - 18, 32, fill=self.color, outline="", tags="txt")
        self.create_oval(w - 29, 21, w - 15, 35, outline=mix(self.color, "#000000", .55), tags="txt")
        self.create_text(w - 34 if False else w - 38, 28, text=self.title, anchor="e", fill=PAL["mut"],
                         font=(self.F, 9), tags="txt")
        self.create_text(w - 22, h / 2 + 12, text=self.value, anchor="e", fill=self.color,
                         font=(self.F, 19, "bold"), tags="txt")


class Link(tk.Label):
    def __init__(self, parent, text, url_cmd, font, fg=None, **kw):
        super().__init__(parent, text=text, font=font, fg=fg or PAL["mut"], cursor="hand2", bd=0, **kw)
        self._normal = fg or PAL["mut"]
        self.bind("<Enter>", lambda e: self.configure(fg="#ffffff"))
        self.bind("<Leave>", lambda e: self.configure(fg=self._normal))
        self.bind("<Button-1>", lambda e: url_cmd())


# ----------------------------------------------------------------------------
# ttk styles (tree, scrollbars, combobox)
# ----------------------------------------------------------------------------
def setup_ttk(root, F, FM):
    st = ttk.Style(root)
    st.theme_use("clam")
    st.configure(".", background=PAL["bg"], foreground=PAL["ink"], font=(F, 10))
    st.configure("Treeview", background=PAL["well"], foreground=PAL["ink"], fieldbackground=PAL["well"],
                 rowheight=32, borderwidth=0, font=(F, 10), relief="flat")
    st.configure("Treeview.Heading", background=PAL["well2"], foreground=PAL["mut"], font=(F, 9, "bold"),
                 padding=(8, 9), relief="flat", borderwidth=0)
    st.map("Treeview", background=[("selected", mix(PAL["well"], PAL["acc"], .45))], foreground=[("selected", "#ffffff")])
    st.map("Treeview.Heading", background=[("active", PAL["line"])], foreground=[("active", "#fff")])
    st.layout("Treeview", [("Treeview.treearea", {"sticky": "nswe"})])
    for o, tag in (("Vertical", "Glass.Vertical.TScrollbar"), ("Horizontal", "Glass.Horizontal.TScrollbar")):
        st.layout(tag, [(f"{o}.Scrollbar.trough", {"children": [(f"{o}.Scrollbar.thumb", {"expand": "1", "sticky": "nswe"})],
                                                      "sticky": "ns" if o == "Vertical" else "ew"})])
        st.configure(tag, background=mix(PAL["well2"], "#ffffff", .22), troughcolor=PAL["well"],
                     bordercolor=PAL["well"], lightcolor=mix(PAL["well2"], "#ffffff", .22),
                     darkcolor=mix(PAL["well2"], "#ffffff", .22), relief="flat", gripcount=0, width=9)
        st.map(tag, background=[("active", PAL["acc"]), ("pressed", PAL["acc"])])
    st.configure("TCombobox", fieldbackground=PAL["well"], background=PAL["well2"], foreground=PAL["ink"],
                 arrowcolor=PAL["mut"], bordercolor=PAL["line"], lightcolor=PAL["well"], darkcolor=PAL["well"],
                 padding=6, relief="flat")
    st.map("TCombobox", fieldbackground=[("readonly", PAL["well"])], foreground=[("readonly", PAL["ink"])],
           bordercolor=[("focus", PAL["acc"])])
    root.option_add("*TCombobox*Listbox.background", PAL["well"])
    root.option_add("*TCombobox*Listbox.foreground", PAL["ink"])
    root.option_add("*TCombobox*Listbox.selectBackground", PAL["acc"])
    root.option_add("*TCombobox*Listbox.font", (F, 10))
    return st


def make_text(parent, F, FM, mono=True, size=10, bg=None, fg=None):
    """Borderless Text + slim scrollbar in a well frame. Returns the Text (frame in .wrap)."""
    wrap = tk.Frame(parent, bg=bg or PAL["well"], bd=0, highlightthickness=1,
                    highlightbackground=PAL["line"], highlightcolor=PAL["line"])
    wrap._glass_keep = True
    t = tk.Text(wrap, bg=bg or PAL["well"], fg=fg or PAL["ink"], insertbackground="#fff",
                font=(FM if mono else F, size), wrap="word", relief="flat", padx=18, pady=16,
                borderwidth=0, highlightthickness=0, spacing1=2, spacing3=3,
                selectbackground=mix(PAL["well"], PAL["acc"], .6), cursor="arrow")
    t._glass_keep = True
    vs = ttk.Scrollbar(wrap, orient="vertical", command=t.yview, style="Glass.Vertical.TScrollbar")
    t.configure(yscrollcommand=vs.set)
    vs.pack(side="right", fill="y", padx=(0, 2), pady=4)
    t.pack(side="left", fill="both", expand=True)
    t.wrap = wrap
    # make pack/grid/place of the Text apply to the wrapper
    for m in ("pack", "grid", "place"):
        setattr(t, "_" + m + "_orig", getattr(t, m))
        setattr(t, m, getattr(wrap, m))
    return t


# ----------------------------------------------------------------------------
# App icon (rendered with the same glass language)
# ----------------------------------------------------------------------------
def make_app_icon(size=512):
    """Liquid-glass shield with a signal pulse. Returns PIL RGBA."""
    s = size
    bgimg = make_backdrop(s, s).convert("RGBA")
    mask = Image.new("L", (s * 2, s * 2), 0)
    ImageDraw.Draw(mask).rounded_rectangle([s * .08, s * .08, s * 1.92, s * 1.92], radius=s * .44, fill=255)
    mask = mask.resize((s, s), Image.LANCZOS)
    tile = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    tile.paste(bgimg, (0, 0), mask)
    # glass shield
    ss = 2
    sh = Image.new("L", (s * ss, s * ss), 0)
    d = ImageDraw.Draw(sh)
    cx, top, bot = s * ss / 2, s * ss * .22, s * ss * .80
    wd = s * ss * .27
    pts = [(cx - wd, top + s * .02), (cx, top - s * .02), (cx + wd, top + s * .02), (cx + wd, s * ss * .52),
           (cx + wd * .72, s * ss * .68), (cx, bot), (cx - wd * .72, s * ss * .68), (cx - wd, s * ss * .52)]
    d.polygon(pts, fill=255)
    sh = sh.filter(ImageFilter.GaussianBlur(s * .006)).resize((s, s), Image.LANCZOS)
    grad = Image.linear_gradient("L").resize((s, s))
    fill = Image.composite(Image.new("RGBA", (s, s), (255, 255, 255, 70)), Image.new("RGBA", (s, s), (255, 255, 255, 18)), grad.point(lambda v: 255 - v))
    glow = sh.filter(ImageFilter.GaussianBlur(s * .04)).point(lambda v: int(v * .5))
    tile = Image.composite(Image.new("RGBA", (s, s), (110, 100, 255, 255)), tile, glow)
    tile.paste(fill, (0, 0), sh)
    edge = ImageChops.subtract(sh, sh.filter(ImageFilter.MinFilter(5)))
    tile.paste(Image.new("RGBA", (s, s), (255, 255, 255, 200)), (0, 0), edge)
    # pulse line
    pl = Image.new("RGBA", (s * ss, s * ss), (0, 0, 0, 0))
    pd = ImageDraw.Draw(pl)
    y = s * ss * .47
    xs = [cx - wd * .72, cx - wd * .3, cx - wd * .12, cx + wd * .08, cx + wd * .26, cx + wd * .72]
    ys = [y, y, y - s * .13, y + s * .14, y, y]
    pd.line(list(zip(xs, ys)), fill=(125, 240, 255, 255), width=int(s * .028), joint="curve")
    pl = pl.resize((s, s), Image.LANCZOS)
    blur = pl.filter(ImageFilter.GaussianBlur(s * .012))
    tile = Image.alpha_composite(tile, blur)
    tile = Image.alpha_composite(tile, pl)
    return tile


def set_window_icon(root):
    if not HAS_PIL:
        return None
    try:
        ico = make_app_icon(256)
        photo = ImageTk.PhotoImage(ico.resize((128, 128), Image.LANCZOS))
        root.iconphoto(True, photo)
        return photo
    except Exception:
        return None


def enable_dark_titlebar(root):
    """Windows 10/11 immersive dark title bar (no-op elsewhere)."""
    if sys.platform != "win32":
        return
    try:
        import ctypes
        root.update_idletasks()
        hwnd = ctypes.windll.user32.GetParent(root.winfo_id())
        val = ctypes.c_int(1)
        for attr in (20, 19):
            ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, attr, ctypes.byref(val), ctypes.sizeof(val))
    except Exception:
        pass
