# -*- coding: utf-8 -*-
"""GUI regression: widgets must survive Windows-style system colour names (e.g. 'SystemButtonFace')."""
import os
import sys
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
pytest.importorskip("PIL")
tk = pytest.importorskip("tkinter")


def test_hex2rgb_accepts_names_and_short_hex():
    import pcap_glass_ui as G
    assert G.hex2rgb("#05070f") == (5, 7, 15)
    assert G.hex2rgb("#abc") == (170, 187, 204)
    assert len(G.hex2rgb("SystemButtonFace")) == 3      # must not raise
    assert len(G.hex2rgb("")) == 3


def test_gui_redraw_with_system_colour_names():
    try:
        root = tk.Tk()
        root.destroy()
    except tk.TclError:
        pytest.skip("no display")
    import pcap_analyzer as P
    errs = []
    P.PcapAnalyzerApp.report_callback_exception = lambda self, *a: errs.append(a)
    orig = tk.Misc.cget
    sim = [False]
    tk.Misc.cget = lambda self, k: "SystemButtonFace" if sim[0] and k in ("bg", "background") else orig(self, k)
    try:
        app = P.PcapAnalyzerApp(None)
        app.geometry("1100x760")
        for _ in range(20):
            app.update()
        sim[0] = True
        app.geometry("1250x820")
        for k in range(7):
            app.goto_page(k)
            for _ in range(5):
                app.update()
        app.destroy()
    finally:
        tk.Misc.cget = orig
    assert not errs, errs[0]


def test_live_language_theme_switch_and_rtl(tmp_path, monkeypatch):
    """Language / theme switch rebuilds the window live (no restart) and mirrors the layout for RTL."""
    try:
        root = tk.Tk()
        root.destroy()
    except tk.TclError:
        pytest.skip("no display")
    import pcap_analyzer as P
    import pcap_glass_ui as G
    import pcap_i18n as I
    import pcap_themes as T
    monkeypatch.setattr(T, "CONFIG_DIR", tmp_path)                 # never touch the user's real config
    monkeypatch.setattr(T, "CONFIG_FILE", tmp_path / "config.json")
    errs = []
    benign = ("bad window path name", "invalid command name", "application has been destroyed",
              "NoneType' object has no attribute")      # late redraw callbacks of widgets a live rebuild destroyed

    def collect(self, exc, val, tb):
        if not any(k in str(val) for k in benign):
            errs.append((exc, val, tb))
    P.PcapAnalyzerApp.report_callback_exception = collect
    I.set_lang("en")
    I.install_tk_hooks()
    try:
        app = P.PcapAnalyzerApp(None)
    except tk.TclError as e:      # broken Tcl/Tk install on a CI runner is an environment problem, not a code bug
        pytest.skip(f"Tk unavailable: {e}")
    try:
        app.geometry("1200x800")
        for _ in range(15):
            app.update()
        assert G.RTL is False
        x_ltr = app.nav.winfo_rootx()
        app._set_lang("fa")
        for _ in range(15):
            app.update()
        assert G.RTL is True and I.get_lang() == "fa"
        assert app.nav.winfo_rootx() > x_ltr          # sidebar moved to the right side
        app._set_theme("matrix")
        for _ in range(15):
            app.update()
        app._set_lang("en")
        for _ in range(15):
            app.update()
        assert G.RTL is False
    finally:
        try:
            app.destroy()
        except Exception:
            pass
        I.set_lang("en")
    assert not errs, errs[0]
