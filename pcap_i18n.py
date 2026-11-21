# -*- coding: utf-8 -*-
"""
pcap_i18n — English (default) / Persian runtime localisation
============================================================
* The code base was written with Persian source strings.  ``tr(text)`` maps them to English when the
  active language is ``en`` (exact dictionary first, then regex patterns for f-strings).
* Rules carry both languages; ``rule_text(rid, field)`` returns the right one.
* Language order of precedence: ``--lang`` / ``PCAP_LANG`` env / saved config / **English**.
"""
from __future__ import annotations

import os
import re

try:
    import pcap_themes as _TH
except Exception:                                 # pragma: no cover
    _TH = None

LANGS = {"en": "English", "fa": "فارسی"}
DEFAULT_LANG = "en"
_lang = DEFAULT_LANG
_EXACT: dict = {}
_PATTERNS: list = []
_loaded = False
_cache: dict = {}


def _load():
    global _loaded
    if _loaded:
        return
    _loaded = True
    for mod in ("i18n_misc", "i18n_part_a", "i18n_part_b", "i18n_part_c", "i18n_gui", "i18n_ui2"):
        try:
            m = __import__(mod)
        except Exception:
            continue
        _EXACT.update(getattr(m, "UI_EN", {}))
        for rx, rep in getattr(m, "UI_PATTERNS", []):
            try:
                _PATTERNS.append((re.compile(rx, re.S), rep))
            except re.error:
                pass


def init(cli_lang=None):
    """Resolve and set the language; returns it."""
    lang = cli_lang or os.environ.get("PCAP_LANG")
    if not lang and _TH:
        lang = (_TH.load_config() or {}).get("lang")
    set_lang(lang if lang in LANGS else DEFAULT_LANG)
    return _lang


def set_lang(lang):
    global _lang
    _lang = lang if lang in LANGS else DEFAULT_LANG
    _cache.clear()
    return _lang


def get_lang():
    return _lang


_FA = re.compile("[؀-ۿ]")


def tr(s, lang=None):
    """Persian source string -> active language (or ``lang`` when given)."""
    if (lang or _lang) == "fa" or not isinstance(s, str) or not s or not _FA.search(s):
        return s
    r = _cache.get(s)
    if r is not None:
        return r
    _load()
    r = _EXACT.get(s)
    if r is None:
        t = s.strip()
        if t != s and t in _EXACT:
            r = s.replace(t, _EXACT[t])
    if r is None:
        for rx, rep in _PATTERNS:
            if rx.match(s):
                try:
                    r = rx.sub(rep, s, count=1)
                except (re.error, IndexError):
                    r = None
                if r is not None:
                    # nested dynamic fragments (e.g. a Persian IP-label inside) — translate leftovers once
                    if _FA.search(r) and r != s:
                        r = _translate_fragments(r)
                    break
    if r is None and "\n" in s:                       # multi-block texts: translate block by block / line by line
        sep = "\n\n" if "\n\n" in s else "\n"
        r = sep.join(tr(b) for b in s.split(sep))
        if r == s:
            r = None
    if r is None:
        r = _translate_fragments(s)
    if len(_cache) < 20000:
        _cache[s] = r
    return r


def _translate_fragments(s):
    """Last resort: replace known dictionary phrases (longest first) that occur inside a longer text."""
    if not _FA.search(s):
        return s
    keys = _frag_keys()
    out = s
    for k in keys:
        if k in out:
            out = out.replace(k, _EXACT[k])
            if not _FA.search(out):
                break
    return out


_fk = None


def _frag_keys():
    global _fk
    if _fk is None:
        _fk = sorted((k for k in _EXACT if len(k) >= 4 and _FA.search(k)), key=len, reverse=True)
    return _fk


def rule_text(rid, field, rules, en_table=None):
    """field: cat|title|desc|rec  -> text in the active language."""
    r = rules[rid]
    if _lang == "fa":
        return r[field]
    en = r.get("en")
    if en:
        return en[field]
    if en_table and rid in en_table:
        return en_table[rid][("cat", "title", "desc", "rec").index(field)]
    return r[field]


def localize_obj(o):
    """Recursively translate Persian strings inside JSON-like data (used before building English reports)."""
    if _lang == "fa":
        return o
    if isinstance(o, str):
        return tr(o)
    if isinstance(o, list):
        return [localize_obj(x) for x in o]
    if isinstance(o, tuple):
        return tuple(localize_obj(x) for x in o)
    if isinstance(o, dict):
        return {k: localize_obj(v) for k, v in o.items()}
    return o


# ------------------------------------------------------------------ Tk hook (generic, via the options choke point)
def install_tk_hooks():
    """Translate every widget text / menu label / messagebox string automatically. Safe no-op on failure."""
    try:
        import tkinter as tk
        from tkinter import messagebox, ttk
    except Exception:
        return False
    if getattr(tk, "_pcap_i18n", False):
        return True
    orig = tk.Misc._options

    def _options(self, cnf, kw=None):
        try:
            if kw:
                kw = {k: (tr(v) if k in ("text", "label", "title") and isinstance(v, str) else v) for k, v in kw.items()}
            if cnf and isinstance(cnf, dict):
                cnf = {k: (tr(v) if k in ("text", "label") and isinstance(v, str) else v) for k, v in cnf.items()}
        except Exception:
            pass
        return orig(self, cnf, kw)
    tk.Misc._options = _options
    for name in ("showinfo", "showwarning", "showerror", "askyesno", "askokcancel", "askquestion", "askretrycancel", "askyesnocancel"):
        f = getattr(messagebox, name, None)
        if f is None:
            continue

        def mk(f):
            def w(title=None, message=None, **kw):
                return f(tr(title) if title else title, tr(message) if message else message, **kw)
            return w
        setattr(messagebox, name, mk(f))
    try:
        ow = tk.Wm.wm_title

        def wm_title(self, string=None):
            return ow(self, tr(string) if isinstance(string, str) else string)
        tk.Wm.wm_title = wm_title
        tk.Wm.title = wm_title
    except Exception:
        pass
    try:                                           # ttk.Notebook / Combobox values
        on = ttk.Notebook.add

        def nb_add(self, child, **kw):
            if isinstance(kw.get("text"), str):
                kw["text"] = tr(kw["text"])
            return on(self, child, **kw)
        ttk.Notebook.add = nb_add
    except Exception:
        pass
    try:                                           # Text.insert / Canvas.create_text / Treeview.heading
        t_ins = tk.Text.insert

        def text_insert(self, index, chars, *args):
            return t_ins(self, index, tr(chars) if isinstance(chars, str) else chars, *args)
        tk.Text.insert = text_insert
        c_ct = tk.Canvas.create_text

        def create_text(self, *args, **kw):
            if isinstance(kw.get("text"), str):
                kw["text"] = tr(kw["text"])
            return c_ct(self, *args, **kw)
        tk.Canvas.create_text = create_text
        tv_h = ttk.Treeview.heading

        def heading(self, column, option=None, **kw):
            if isinstance(kw.get("text"), str):
                kw["text"] = tr(kw["text"])
            return tv_h(self, column, option, **kw) if option is not None else tv_h(self, column, **kw)
        ttk.Treeview.heading = heading
    except Exception:
        pass
    tk._pcap_i18n = True
    return True


def collect_persian(o, out, limit=6000):
    """Collect every distinct Persian string inside JSON-like data."""
    if len(out) >= limit:
        return out
    if isinstance(o, str):
        if _FA.search(o):
            out.add(o)
    elif isinstance(o, (list, tuple)):
        for x in o:
            collect_persian(x, out, limit)
    elif isinstance(o, dict):
        for v in o.values():
            collect_persian(v, out, limit)
    return out


def ui_table(data):
    """Persian -> English map embedded in the HTML report so it can switch language live."""
    _load()
    tab = {k: v for k, v in _EXACT.items() if len(k) <= 400}
    for sx in collect_persian(data, set()):
        if sx not in tab:
            e = tr(sx, "en")
            if e != sx:
                tab[sx] = e
    return tab
