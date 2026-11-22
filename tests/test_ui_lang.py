"""Oberfläche auf Englisch: Flagge anklicken, kompletter Ablauf, danach darf (fast) nichts Deutsches mehr zu sehen sein; zurück auf Deutsch."""
import importlib
import os
import re
import sys
import tempfile
import threading
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)
FAKE = os.path.join(HERE, "fake_paramiko")

import fixture  # noqa: E402
import webfixture  # noqa: E402
from claudia.server import make_server  # noqa: E402

try:
    from playwright.sync_api import sync_playwright
except ImportError:  # pragma: no cover
    sync_playwright = None

GER = set("der die das den dem des und oder nicht ist sind wird werden wurde kann können muss müssen für mit von zu auf bei nach über eine einen einem keine kein noch auch nur wenn dann aus bis haben gegen ohne zum zur beim vom bitte dass sich alle jede jeder zwischen hier dort dabei dafür damit weil aber sehr mehr gibt Zeile Datei Dateien Treffer Hinweis Kritisch Übersprungen Befunde Prüfung Prüfungen Verbindung Weiter Zurück Fehler".split())
UM = re.compile("[äöüÄÖÜß]")
# Texte aus den Daten der Seite (Dateiinhalte, Namen, Pfade) und englische Sätze mit deutschen Zufallstreffern
DATA = re.compile(r"Blockiert|Zähler|Angebot|rohdaten|Rohdaten für den Export: [a-z_.]+ \(|PHP-Version nicht in den Kopfzeilen|gekürzt|^Server[ :(]|\bServer\b|\bdie\(\)|Dauer [\d.]+ s")
JS = """() => { const out = []; const w = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT); let n;
  while (n = w.nextNode()) { const p = n.parentElement; if (!p || ['SCRIPT','STYLE','CODE','PRE','TEXTAREA'].includes(p.tagName) || p.closest('[data-nt],pre,code')) continue; const t = n.data.trim(); if (t) out.push(t); }
  document.querySelectorAll('[title],[placeholder],[aria-label]').forEach(e => { if (e.closest('[data-nt]')) return; for (const a of ['title','placeholder','aria-label']) { const v = e.getAttribute(a); if (v) out.push(v); } });
  return out; }"""


def _offen():
    """Bewusst noch nicht übersetzte Sätze (tests/uebersetzung_offen.json) zählen nicht als deutscher Rest."""
    import json
    try:
        with open(os.path.join(HERE, "uebersetzung_offen.json"), encoding="utf-8") as fh:
            return sorted(set(json.load(fh).get("fehlend") or []), key=len, reverse=True)
    except (OSError, ValueError):
        return []


OFFEN = _offen()


def german(t):
    for s in OFFEN:
        if s in t:
            t = t.replace(s, " ")
    ws = re.findall(r"[A-Za-zÄÖÜäöüß]+", t)
    return bool(UM.search(t)) or any(w in GER for w in ws)


@unittest.skipIf(sync_playwright is None, "Playwright nicht installiert")
class EnglishUi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        sys.path.insert(0, FAKE)
        sys.modules.pop("paramiko", None)
        cls.paramiko = importlib.import_module("paramiko")
        cls.base = tempfile.mkdtemp(prefix="claudia_uil_")
        cls.w = fixture.make_world(cls.base, True)
        cls.paramiko.CONFIG.update(home=cls.w["home"], extra_path=cls.w["bin"], password="pw", fail=None)
        cls.web, cls.url = webfixture.start(True)
        os.environ["CLAUDIA_REPORTS"] = os.path.join(cls.base, "berichte")
        os.environ["CLAUDIA_LOGS"] = os.path.join(cls.base, "protokolle")
        cls.srv = make_server(directory=os.path.join(cls.base, "data"))
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.pw = sync_playwright().start()
        cls.browser = cls.pw.chromium.launch()
        cls.page = cls.browser.new_page(viewport={"width": 1280, "height": 900})
        cls.errors = []
        cls.page.on("pageerror", lambda e: cls.errors.append(str(e)))
        cls.seen = {}

    @classmethod
    def tearDownClass(cls):
        cls.browser.close()
        cls.pw.stop()
        cls.srv.shutdown()
        cls.web.shutdown()
        sys.path.remove(FAKE)
        sys.modules.pop("paramiko", None)

    def scan(self, tag):
        for t in self.page.evaluate(JS):
            if german(t) and not DATA.search(t):
                self.seen.setdefault(t, tag)

    def test_english_flow_and_back(self):
        pg = self.page
        pg.goto(self.srv.entry_url())
        pg.wait_for_selector("text=Mit dem Server verbinden")
        self.assertGreaterEqual(pg.locator("#langs button").count(), 2)
        self.assertEqual(pg.locator("#langs button svg").count(), pg.locator("#langs button").count())       # Flaggen als Bild
        pg.click("#langs button >> nth=1")
        pg.wait_for_selector("text=Connect to the server")
        self.assertEqual(pg.evaluate("document.documentElement.lang"), "en")
        self.scan("connect")
        pg.click("text=Test connection")
        pg.wait_for_selector("text=Please enter server and username")
        pg.fill("#f-host", "fake.example.org")
        pg.fill("#f-user", "demo")
        pg.fill("#f-pw", "pw")
        pg.fill("#f-dir", self.w["site_rel"])
        pg.fill("#f-url", self.url)
        pg.click("text=Test connection")
        pg.wait_for_selector("#trust[open]")
        self.scan("trust")
        pg.click("#trust-yes")
        pg.wait_for_selector("text=Connected")
        self.scan("connected")
        pg.click("text=Continue to test selection")
        pg.wait_for_selector("text=Which checks should run?")
        self.scan("tests")
        pg.click(".test >> nth=0 >> text=Details")
        pg.wait_for_selector("text=Why is this important?")
        self.scan("details")
        pg.click("text=Start check")
        pg.wait_for_selector("text=The check is running")
        # Während des Laufs ist das Umschalten gesperrt
        self.assertTrue(pg.is_disabled("#langs button >> nth=0"))
        pg.wait_for_selector("text=Critical findings found", timeout=180000)
        pg.wait_for_timeout(800)
        self.scan("results")
        self.assertEqual(pg.locator(".res[data-s=error]").count(), 0)
        pg.wait_for_selector("#actions")
        self.scan("actions")
        left = ["%s  [%s]" % (t[:110], tag) for t, tag in self.seen.items()]
        self.assertLessEqual(len(left), 6, "Deutsche Reste in der englischen Oberfläche:\n" + "\n".join(left))
        self.assertEqual(self.errors, [])

        # Zurück auf Deutsch: Ergebnisse bleiben, Texte werden wieder deutsch
        pg.click("#langs button >> nth=0")
        pg.wait_for_selector("text=Kritische Befunde gefunden")
        self.assertEqual(pg.evaluate("document.documentElement.lang"), "de")
        self.assertGreaterEqual(pg.locator(".res").count(), 20)


if __name__ == "__main__":
    unittest.main()
