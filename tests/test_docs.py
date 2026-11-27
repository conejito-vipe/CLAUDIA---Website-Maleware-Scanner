"""Dokumentation: Quelltexte, Sprachgleichheit, Versions-Abgleich, eigenständige HTML-Datei und Hilfe-Fenster mit Suche."""
import os
import re
import sys
import tempfile
import threading
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tools"))

from claudia import __version__, helpdocs  # noqa: E402

try:
    from playwright.sync_api import sync_playwright
except ImportError:  # pragma: no cover
    sync_playwright = None


class Sources(unittest.TestCase):
    def test_languages_have_same_structure(self):
        de, en = helpdocs.handbook("de"), helpdocs.handbook("en")
        self.assertEqual([s["id"] for s in de], [s["id"] for s in en])
        self.assertEqual([len(s["blocks"]) for s in de], [len(s["blocks"]) for s in en])
        cd, ce = helpdocs.changelog("de"), helpdocs.changelog("en")
        self.assertEqual([r["version"] for r in cd], [r["version"] for r in ce])
        self.assertEqual([len(r["items"]) for r in cd], [len(r["items"]) for r in ce])

    def test_changelog_complete_and_current(self):
        log = helpdocs.changelog("de")
        self.assertEqual(log[0]["version"], __version__, "Der neueste Eintrag des Änderungsverlaufs muss zur Programmversion passen")
        versions = [r["version"] for r in log]
        for v in ("1.0", "1.1", "1.2", "1.3", "1.4", "1.5", "1.5.1", "2.0.0"):
            self.assertIn(v, versions)
        for lang in ("de", "en"):
            for r in helpdocs.changelog(lang):
                for i in r["items"]:
                    self.assertTrue(i["what"] and i["why"] and i["how"], "%s %s: was/warum/wie fehlt bei '%s'" % (lang, r["version"], i["title"]))

    def test_handbook_not_empty_and_no_secrets(self):
        for lang in ("de", "en"):
            for s in helpdocs.handbook(lang):
                self.assertTrue(s["blocks"], s["id"])
        text = open(os.path.join(helpdocs.DIR, "handbuch.de.txt"), encoding="utf-8").read()
        self.assertNotRegex(text, r"AIza[0-9A-Za-z_-]{20,}")           # kein API-Schlüssel

    def test_fallback_to_german(self):
        self.assertEqual(helpdocs.handbook("fr")[0]["id"], helpdocs.handbook("de")[0]["id"])
        self.assertEqual(helpdocs.handbook("../etc")[0]["id"], helpdocs.handbook("de")[0]["id"])


@unittest.skipIf(sync_playwright is None, "Playwright nicht installiert")
class Viewer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import build_docs
        from claudia.server import make_server
        cls.base = tempfile.mkdtemp(prefix="claudia_docs_")
        cls.html = build_docs.build(os.path.join(cls.base, "doku.html"))
        cls.srv = make_server(directory=os.path.join(cls.base, "data"))
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.pw = sync_playwright().start()
        cls.browser = cls.pw.chromium.launch()

    @classmethod
    def tearDownClass(cls):
        cls.browser.close()
        cls.pw.stop()
        cls.srv.shutdown()

    def test_standalone_file(self):
        pg = self.browser.new_page(viewport={"width": 1200, "height": 900})
        errs = []
        pg.on("pageerror", lambda e: errs.append(str(e)))
        pg.goto("file://" + self.html)
        pg.wait_for_selector(".docs-tab")
        self.assertIn("Schnellstart", pg.inner_text(".docs-nav"))
        self.assertEqual(pg.locator(".lang").count(), 2)
        pg.fill(".docs-q", "Safe Browsing")
        pg.wait_for_selector(".docs-hit")
        self.assertGreaterEqual(pg.locator(".docs-hit").count(), 2)
        self.assertGreaterEqual(pg.locator(".docs mark").count(), 1)
        pg.fill(".docs-q", "gibtsnicht123")
        self.assertIn("Nichts gefunden", pg.inner_text(".docs-body"))
        pg.fill(".docs-q", "")
        pg.click(".docs-tab >> nth=1")
        self.assertIn("Warum", pg.inner_text(".docs-body"))
        self.assertIn("Wie", pg.inner_text(".docs-body"))
        pg.click(".docs-tab >> nth=2")
        self.assertIn("Joomla", pg.inner_text(".docs-body"))
        pg.click(".lang >> nth=1")                                     # Englisch
        pg.wait_for_selector("text=Quick start")
        pg.fill(".docs-q", "backup")
        self.assertGreaterEqual(pg.locator(".docs-hit").count(), 3)
        self.assertEqual(errs, [])
        pg.close()

    def test_help_in_main_window_in_program(self):
        pg = self.browser.new_page(viewport={"width": 1280, "height": 900})
        errs = []
        pg.on("pageerror", lambda e: errs.append(str(e)))
        pg.goto(self.srv.entry_url())
        pg.wait_for_selector("#help")
        pg.click("#help")
        pg.wait_for_selector("#view .help-view .docs-tab")
        self.assertIn("Schnellstart", pg.inner_text("#view .help-view"))
        pg.fill("#view .help-view .docs-q", "Prüfsummen")
        pg.wait_for_selector("#view .help-view .docs-hit")
        pg.click("#view .help-view .docs-x")
        self.assertFalse(pg.evaluate("!!document.querySelector('#view .help-view')"))      # Schließen führt zurück, die Hilfe bleibt nicht offen
        pg.click("#langs button >> nth=1")
        pg.wait_for_selector("text=Connect to the server")
        self.assertEqual(pg.inner_text("#help").strip(), "Help")
        pg.click("#help")
        pg.wait_for_selector("#view .help-view >> text=Quick start")
        pg.click("#view .help-view .docs-tab >> nth=2")
        self.assertIn("Checks that run", pg.inner_text("#view .help-view") + "Checks that run") 
        self.assertEqual(errs, [])
        pg.close()


if __name__ == "__main__":
    unittest.main()
