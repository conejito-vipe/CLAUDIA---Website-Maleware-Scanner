"""Oberfläche 2.5.0 im echten Browser: Deinstallations-Dialog, Hilfefenster, Safe-Browsing-Link, Kopfzeile."""
import os
import sys
import tempfile
import threading
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

try:
    from playwright.sync_api import sync_playwright
except ImportError:  # pragma: no cover
    sync_playwright = None


@unittest.skipIf(sync_playwright is None, "Playwright nicht installiert")
class Ui(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        base = tempfile.mkdtemp(prefix="claudia_uiw_")
        os.environ["CLAUDIA_REPORTS"] = base + "/b"
        from claudia.server import make_server
        cls.srv = make_server(directory=base + "/d")
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.pw = sync_playwright().start()
        cls.br = cls.pw.chromium.launch()

    @classmethod
    def tearDownClass(cls):
        cls.br.close()
        cls.pw.stop()
        cls.srv.shutdown()

    def page(self, w=1100, h=700):
        pg = self.br.new_page(viewport={"width": w, "height": h})
        pg.goto(self.srv.entry_url())
        pg.wait_for_selector("#uninstall")
        return pg

    def box(self, pg, sel):
        return pg.evaluate("s=>{const b=document.querySelector(s).getBoundingClientRect();return {l:b.left,t:b.top,r:b.right,b:b.bottom,w:b.width,h:b.height}}", sel)

    def test_uninstall_dialog_layout(self):
        pg = self.page(1100, 520)
        pg.click("#uninstall")
        pg.wait_for_selector(".uni-foot")
        d, x, sc, ft = (self.box(pg, s) for s in ("#unidlg", ".dlg-x", ".uni-scroll", ".uni-foot"))
        self.assertLessEqual(x["r"], d["r"] + 1)                         # Schließen-Knopf im Dialog, oben rechts
        self.assertLess(x["l"], d["r"])
        self.assertGreater(x["l"], d["l"] + d["w"] / 2)
        self.assertLessEqual(x["b"], sc["t"] + 1)                        # liegt in der festen Kopfzeile, nicht im Bildlauf-Bereich
        self.assertGreaterEqual(ft["t"], sc["b"] - 1)                    # Knöpfe stehen fest unter dem Bildlauf-Bereich
        self.assertLessEqual(ft["b"], d["b"] + 1)                        # und sind auch bei niedrigem Fenster sichtbar
        self.assertEqual(pg.evaluate("innerHeight") >= ft["b"], True)
        go = self.box(pg, ".uni-foot .danger-fill")
        main = self.box(pg, "#uninstall")
        self.assertAlmostEqual(go["h"], main["h"], delta=1)              # gleiche Höhe wie im Hauptfenster
        pg.close()

    def test_uninstall_button_same_row_as_connect_button(self):
        pg = self.page(1280, 900)
        u = self.box(pg, "#uninstall")
        c = pg.evaluate("()=>{const b=[...document.querySelectorAll('button')].find(b=>b.textContent.startsWith('Verbindung'));const r=b.getBoundingClientRect();return {t:r.top,b:r.bottom,h:r.height}}")
        self.assertAlmostEqual(u["h"], c["h"], delta=2)                  # gleiche Größe
        self.assertAlmostEqual(u["b"], c["b"], delta=6)                  # gleiche Höhe (Unterkante)
        pg.close()

    def test_help_in_main_window_keeps_sidebar(self):
        """Seit 3.1.0: Hilfe öffnet sich im Hauptfenster, die Seitenleiste bleibt sichtbar."""
        pg = self.page()
        pg.click("#help")
        pg.wait_for_selector("#view .help-view .docs-head")
        self.assertTrue(pg.evaluate("!!document.querySelector('.rail')&&document.querySelector('.rail').getBoundingClientRect().width>100"))
        self.assertFalse(pg.evaluate("!!document.querySelector('dialog[open]')"))
        pg.close()

    def test_safe_browsing_key_link_on_start(self):
        pg = self.page()
        href = pg.evaluate("()=>{const a=[...document.querySelectorAll('a')].find(a=>a.href.includes('safe-browsing'));return a?a.href:''}")
        self.assertTrue(href.startswith("https://"), href)
        pg.close()

    def test_logo_in_sidebar_has_margin_to_edges(self):
        """Seit 3.0.0: Das Logo steht in der Seitenleiste mit Abstand zu allen Rändern; Seitenleiste mindestens 140 px breit (3.1.0: Abstand auch beim Ein- und Ausblenden)."""
        pg = self.page()
        logo, top = self.box(pg, ".rail-logo"), self.box(pg, ".rail")
        self.assertGreaterEqual(top["r"] - top["l"], 140)
        self.assertGreaterEqual(logo["t"] - top["t"], 20)
        self.assertGreaterEqual(logo["l"] - top["l"], 14)
        self.assertGreaterEqual(top["r"] - logo["r"], 14)
        pg.close()

    def test_footer_bar_is_fixed_at_bottom(self):
        pg = self.page()
        bar = self.box(pg, ".sbar")
        self.assertAlmostEqual(bar["b"], pg.evaluate("window.innerHeight"), delta=10)
        self.assertGreater(bar["r"] - bar["l"], 600)
        pg.close()


if __name__ == "__main__":
    unittest.main()
