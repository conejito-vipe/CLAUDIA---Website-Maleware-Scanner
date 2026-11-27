"""Dashboard und Lizenz im echten Browser: Übersicht, Trend, Vergleich, Löschen in zwei Schritten, Server-Bestand mit Aktionen, Lizenz-Dialog."""
import os
import shutil
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

try:
    from playwright.sync_api import sync_playwright
except ImportError:  # pragma: no cover
    sync_playwright = None

DAY = 86400


@unittest.skipIf(sync_playwright is None, "Playwright nicht installiert")
class Ui(unittest.TestCase):
    def setUp(self):
        from claudia import server, verlauf
        self.base = tempfile.mkdtemp(prefix="claudia_uidash_")
        self.addCleanup(shutil.rmtree, self.base, True)
        env = mock.patch.dict(os.environ, {"CLAUDIA_NO_UPDATE_CHECK": "1", "CLAUDIA_NO_RESTART": "1", "CLAUDIA_REPORTS": self.base + "/b"})
        env.start()
        os.environ.pop("CLAUDIA_OFFLINE", None)
        self.addCleanup(env.stop)
        self.srv = server.make_server(directory=self.base + "/d")
        self.app = self.srv.app
        now = int(time.time())

        def res(cid, st, *t, sev="warn"):
            return {"id": cid, "status": st, "findings": [{"sev": sev, "title": x} for x in t]}
        verlauf.record_run(self.app.dir, verlauf.run_entry("s1", "shop.example : html", "wordpress", "6.8.1", [res("a", "crit", "Hintertür gefunden", sev="crit"), res("b", "warn", "Altes Plugin")], now - 3 * DAY))
        verlauf.record_run(self.app.dir, verlauf.run_entry("s1", "shop.example : html", "wordpress", "6.8.2", [res("a", "ok"), res("b", "warn", "Altes Plugin"), res("c", "warn", "Neu")], now - 1 * DAY))
        verlauf.record_run(self.app.dir, verlauf.run_entry("s2", "blog.example : html", "joomla", "6.2.0", [res("a", "ok")], now - 60 * DAY))
        verlauf.record_action(self.app.dir, "s1", "shop.example : html", "block_users", "Konten sperren", True, now - 2 * DAY)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.addCleanup(self.srv.shutdown)
        self.pw = sync_playwright().start()
        self.addCleanup(self.pw.stop)
        self.br = self.pw.chromium.launch()
        self.addCleanup(self.br.close)

    def page(self):
        pg = self.br.new_page(viewport={"width": 1200, "height": 800})
        pg.goto(self.srv.entry_url())
        pg.wait_for_selector("#dashbtn")
        return pg

    def test_uebersicht(self):
        pg = self.page()
        pg.click("#dashbtn")
        pg.wait_for_selector("#view .dash-view .sitecard")
        text = pg.inner_text("#view")
        for t in ("shop.example : html", "blog.example : html", "WordPress 6.8.2", "Joomla 6.2.0", "Keine Auffälligkeiten", "Hinweise", "1 Fund behoben", "1 Aktion ausgeführt",
                  "Konten sperren", "Die letzte Prüfung ist 60 Tage her", "noch keine Sicherung", "Funde behoben"):
            self.assertIn(t, text)
        self.assertEqual(pg.locator("#view .sitecard").count(), 2)
        self.assertEqual(pg.locator("#view .dash-view .dcard svg polyline").count(), 2)          # gewählte Seite: kritisch und Hinweise

    def test_vergleich_aufklappen(self):
        pg = self.page()
        pg.click("#dashbtn")
        pg.wait_for_selector("#view .dash-view details")
        pg.click("#view .dash-view details summary")
        text = pg.inner_text("#view .dash-view details")
        self.assertIn("Hintertür gefunden", text)                   # behoben
        self.assertIn("Neu", text)
        self.assertIn("unverändert", text)

    def test_loeschen_in_zwei_schritten(self):
        pg = self.page()
        pg.click("#dashbtn")
        pg.wait_for_selector("#view .dash-view .sitecard")
        pg.locator("#view .sitecard").first.locator("text=Verlauf dieser Seite löschen").click()
        self.assertEqual(pg.locator("#view .sitecard").count(), 2)           # erster Klick löscht noch nichts
        pg.locator("text=Wirklich löschen?").first.click()
        pg.wait_for_function("()=>document.querySelectorAll('#view .sitecard').length===1")
        from claudia import verlauf
        self.assertEqual(len({r["site"] for r in verlauf.load(self.app.dir)["runs"]}), 1)

    def test_ohne_verbindung_hinweis(self):
        pg = self.page()
        pg.click("#dashbtn")
        pg.wait_for_selector("#view #dash-srv")
        self.assertIn("Verbinde dich zuerst", pg.inner_text("#dash-srv"))

    def test_server_bestand_und_aktionen(self):
        self.app.runner = object()
        self.app.conn = {"host": "shop.example", "user": "u", "site_dir": "html"}
        self.app.info = {"cms": "joomla", "joomla": "6.2.0", "host": "shop.example", "user": "u", "php": "8.2", "php_candidates": []}
        now = int(time.time())
        scan = {"backups": [{"name": "claudia-sicherung-20261101-100000", "mtime": now - 20 * DAY, "kb": 2048, "kind": "Vollsicherung (Datenbank + Dateien)", "malware": False, "files": []}],
                "quarantines": [{"name": "claudia-quarantaene-20261101-100000", "mtime": now - 20 * DAY, "site": "html", "count": 1, "kb": 4, "own": True,
                                 "entries": [{"id": "0001", "size": 10, "mode": "644", "owner": "u", "sha": "x", "state": "frei", "origin": "./images/x.php"}]}],
                "tmp": [], "local_logs": [], "quarantine_dirs": []}
        self.addCleanup(lambda: (setattr(self.app, "runner", None), setattr(self.app, "conn", {})))
        with mock.patch.object(type(self.app), "_scan", lambda self: dict(scan, _at=time.monotonic())), \
                mock.patch.object(type(self.app), "ensure_connected", lambda self: None):
            pg = self.page()
            pg.click("#dashbtn")
            pg.wait_for_selector("#view .dash-view")
            pg.wait_for_selector("text=Bestand auf dem Server ansehen")
            pg.click("text=Bestand auf dem Server ansehen")
            pg.wait_for_selector("#dash-srv table")
            text = pg.inner_text("#dash-srv")
            self.assertIn("claudia-sicherung-20261101-100000", text)
            self.assertIn("claudia-quarantaene-20261101-100000", text)
            self.assertIn("./images/x.php", text)
            self.assertIn("bewusst nicht automatisch", text)
            pg.wait_for_selector("#dash-acts .action")
            titles = pg.locator("#dash-acts h4").all_inner_texts()
            self.assertTrue(any("Sicherung" in t for t in titles), titles)
            self.assertTrue(any("Quarantäne" in t for t in titles), titles)
            # jede Aktion verlangt erst die Befehle zu sehen: kein 'Jetzt ausführen' ohne Vorschau
            self.assertEqual(pg.locator("#dash-acts >> text=Jetzt ausführen").count(), 0)

    def test_export_und_support_paket(self):
        import glob
        pg = self.page()
        pg.click("#dashbtn")
        pg.wait_for_selector("#view .dash-view .sitecard")
        pg.click("text=Gesamten Verlauf als CSV speichern")
        pg.wait_for_selector("#dash-msg >> text=Gespeichert:")
        csv = glob.glob(os.path.join(self.base, "b", "verlauf_*", "verlauf.csv"))
        self.assertEqual(len(csv), 1)
        self.assertIn("shop.example : html", open(csv[0], encoding="utf-8").read())
        pg.locator("#view .sitecard").first.locator("text=Bericht für diese Seite").click()
        pg.wait_for_function("()=>document.querySelectorAll('#dash-msg .notice.ok').length===1 && document.querySelector('#dash-msg').innerText.includes('bericht.html')")
        self.assertEqual(len(glob.glob(os.path.join(self.base, "b", "verlauf_*", "bericht.html"))), 1)
        pg.click("text=Support-Paket erstellen")
        pg.wait_for_selector("#dash-msg textarea")
        self.assertIn("CLAUDIA Support-Paket", pg.input_value("#dash-msg textarea"))
        self.assertEqual(len(glob.glob(os.path.join(self.base, "b", "support_*.txt"))), 1)

    def test_nachkontrolle_wird_angezeigt(self):
        from claudia import verlauf
        verlauf.record_action(self.app.dir, "s2", "blog.example : html", "remove_shells", "Schadcode entfernen", True, int(time.time()) - 5 * DAY)
        pg = self.page()
        pg.click("#dashbtn")
        pg.wait_for_selector("#view .dash-view .sitecard")
        self.assertIn("Nachkontrolle fällig", pg.inner_text("#view"))

    def test_sicherung_pruefen_knopf(self):
        from claudia import actions
        self.app.runner = object()
        self.app.conn = {"host": "shop.example", "user": "u", "site_dir": "html"}
        self.app.info = {"cms": "joomla", "joomla": "6.2.0", "host": "shop.example", "user": "u", "php": "8.2", "php_candidates": []}
        now = int(time.time())
        name = "claudia-sicherung-20261101-100000"
        scan = {"backups": [{"name": name, "mtime": now - DAY, "kb": 2048, "kind": "Vollsicherung (Datenbank + Dateien)", "malware": False, "files": []}],
                "quarantines": [], "tmp": [], "local_logs": [], "quarantine_dirs": []}
        self.addCleanup(lambda: (setattr(self.app, "runner", None), setattr(self.app, "conn", {})))
        antwort = {"name": name, "found": True, "ok": False, "files": [{"name": "db.sql.gz", "size": 10, "ok": True, "detail": "Gzip-Archiv vollständig lesbar"},
                                                                      {"name": "dateien.tgz", "size": 5, "ok": False, "detail": "Gzip-Archiv beschädigt oder abgeschnitten"}]}
        with mock.patch.object(type(self.app), "_scan", lambda self: dict(scan, _at=time.monotonic())), mock.patch.object(type(self.app), "ensure_connected", lambda self: None), \
                mock.patch.object(actions, "verify_backup", lambda runner, site, n: antwort if n == name else {}):
            pg = self.page()
            pg.click("#dashbtn")
            pg.wait_for_selector("text=Bestand auf dem Server ansehen")
            pg.click("text=Bestand auf dem Server ansehen")
            pg.wait_for_selector("#dash-srv table")
            pg.click("#dash-srv >> text=Sicherung prüfen")
            pg.wait_for_selector("#dash-srv >> text=Fehler gefunden")
            text = pg.inner_text("#dash-srv")
            self.assertIn("Gzip-Archiv beschädigt", text)
            self.assertIn("db.sql.gz", text)

    def test_lizenz_knopf_ist_ohne_schluessel_unsichtbar(self):
        pg = self.page()
        self.assertFalse(pg.is_visible("#licbtn"))

    def test_lizenz_dialog(self):
        from claudia import lizenz
        with mock.patch.dict(lizenz.PUBLIC_KEYS, {"k1": "AAAA"}):
            self._lizenz_dialog(lizenz)

    def _lizenz_dialog(self, lizenz):
        pg = self.page()
        self.assertTrue(pg.is_visible("#licbtn"))
        pg.click("#licbtn")
        pg.wait_for_selector("#licdlg[open] textarea")
        text = pg.inner_text("#licdlg")
        self.assertIn("kein Lizenzschlüssel", text)
        self.assertIn("nichts gesperrt", text)
        self.assertIn("Die Prüfung", text)
        pg.fill("#lickey", "CL1.unsinn.unsinn")
        pg.click("#licdlg button.primary")
        pg.wait_for_selector("#licdlg .notice.err")
        self.assertIn("kein gültiger Lizenzschlüssel", pg.inner_text("#licdlg"))
        self.assertEqual(lizenz.load(self.app.dir), "")                      # nichts gespeichert

    def test_gesperrter_bereich_zeigt_meldung(self):
        from claudia import lizenz
        with mock.patch.object(lizenz, "GESPERRT_OHNE_LIZENZ", ("dashboard",)):
            pg = self.page()
            pg.click("#dashbtn")
            pg.wait_for_selector("#view .dash-view")
            self.assertIn("Lizenzschlüssel", pg.inner_text("#view"))
            self.assertIn("Die Prüfung bleibt immer frei", pg.inner_text("#view"))


if __name__ == "__main__":
    unittest.main()
