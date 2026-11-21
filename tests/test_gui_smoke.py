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
