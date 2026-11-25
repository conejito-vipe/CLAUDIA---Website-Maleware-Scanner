"""Oberflächentest mit echtem Browser (Playwright): kompletter Ablauf gegen die künstliche Seite.

Der SSH-Weg läuft über die paramiko-Attrappe (Host-Key-Dialog, falsches Passwort, Lauf, Ergebnis)."""
import os
import sys
import tempfile
import threading
import time
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

SHOTS = os.environ.get("CLAUDIA_SHOTS", "")


@unittest.skipIf(sync_playwright is None, "Playwright nicht installiert")
class UiFlow(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Attrappe fest einhängen (andere Testdateien entfernen sie wieder aus sys.modules)
        import importlib
        sys.path.insert(0, FAKE)
        sys.modules.pop("paramiko", None)
        cls.paramiko = importlib.import_module("paramiko")
        paramiko = cls.paramiko
        cls.base = tempfile.mkdtemp(prefix="claudia_ui_")
        cls.w = fixture.make_world(cls.base, True)
        paramiko.CONFIG.update(home=cls.w["home"], extra_path=cls.w["bin"], password="pw", fail=None)
        cls.web, cls.url = webfixture.start(True)
        cls.reports = os.path.join(cls.base, "berichte")
        os.environ["CLAUDIA_REPORTS"] = cls.reports
        cls.logs = os.path.join(cls.base, "protokolle")
        os.environ["CLAUDIA_LOGS"] = cls.logs
        cls.srv = make_server(directory=os.path.join(cls.base, "data"))
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.pw = sync_playwright().start()
        cls.browser = cls.pw.chromium.launch()
        cls.page = cls.browser.new_page(viewport={"width": 1280, "height": 900})
        cls.errors = []
        cls.page.on("pageerror", lambda e: cls.errors.append(str(e)))
        cls.page.on("console", lambda m: cls.errors.append(m.text) if m.type == "error" else None)

    @classmethod
    def tearDownClass(cls):
        cls.browser.close()
        cls.pw.stop()
        cls.srv.shutdown()
        cls.web.shutdown()
        sys.path.remove(FAKE)
        sys.modules.pop("paramiko", None)

    def shot(self, name):
        if SHOTS:
            os.makedirs(SHOTS, exist_ok=True)
            self.page.screenshot(path=os.path.join(SHOTS, name))

    def fill(self, password):
        pg = self.page
        pg.fill("#f-host", "fake.example.org")
        pg.fill("#f-user", "demo")
        pg.fill("#f-pw", password)
        pg.fill("#f-dir", self.w["site_rel"])
        pg.fill("#f-url", self.url)

    def test_1_flow(self):
        pg = self.page
        pg.goto(self.srv.entry_url())
        pg.wait_for_selector("text=Mit dem Server verbinden")
        self.shot("1_verbinden.png")

        # leere Eingabe -> verständliche Fehlermeldung
        pg.click("text=Verbindung testen")
        pg.wait_for_selector("text=Bitte Server und Benutzername eingeben")

        # falsches Passwort
        self.fill("falsch")
        pg.click("text=Verbindung testen")
        pg.wait_for_selector("#trust[open]")
        pg.click("#trust-yes")
        pg.wait_for_selector("text=Anmeldung abgelehnt")
        self.shot("2_fehler.png")

        # richtiges Passwort; Server ist inzwischen als vertraut gespeichert (kein Dialog mehr)
        pg.fill("#f-pw", "pw")
        pg.click("text=Verbindung testen")
        pg.wait_for_selector("text=Verbindung steht")
        self.assertIn("Joomla", pg.inner_text("main"))
        self.shot("3_verbunden.png")
        pg.click("text=Weiter zur Testauswahl")

        # Testauswahl: Details lesen, Voreinstellung wechseln
        pg.wait_for_selector("text=Welche Prüfungen sollen laufen?")
        pg.click(".test >> nth=0 >> text=Details")
        pg.wait_for_selector("text=Warum ist das wichtig?")
        n_hack = pg.locator(".test-main input:checked").count()
        self.assertGreaterEqual(n_hack, 20)
        pg.click(".preset >> nth=0")
        self.assertLess(pg.locator(".test-main input:checked").count(), n_hack)
        pg.click(".preset >> nth=1")
        pg.uncheck("#t-access_logs")
        self.assertIn("ausgewählt", pg.inner_text(".bar"))
        self.shot("4_tests.png")

        # Protokolle sichern: erst suchen, dann ausdrücklich bestätigen, dann kopieren
        self.assertIn("Protokolle auf deinen PC sichern", pg.inner_text("#logsave"))
        pg.click("#logsave >> text=Protokolle suchen")
        pg.wait_for_selector("#logsave >> text=Noch zu sichern")
        self.assertIn("Datenschutz", pg.inner_text("#logsave"))
        self.assertTrue(pg.is_disabled("#logsave >> text=Jetzt sichern"))
        pg.check("#ls-ok")
        pg.click("#logsave >> text=Jetzt sichern")
        pg.wait_for_selector("#ls-done")
        self.assertIn("gesichert", pg.inner_text("#ls-done"))
        saved_logs = [os.path.join(dp, f) for dp, _d, fs in os.walk(self.logs) for f in fs]
        self.assertTrue(any(f.endswith("access.log") for f in saved_logs), saved_logs)
        self.assertTrue(any(f.endswith("SICHERUNG_PRUEFSUMMEN.txt") for f in saved_logs))
        self.shot("4b_protokolle.png")

        # Lauf
        pg.click("text=Prüfung starten")
        pg.wait_for_selector("text=Die Prüfung läuft")
        self.shot("5_lauf.png")
        pg.wait_for_selector("text=Kritische Befunde gefunden", timeout=180000)
        self.assertGreaterEqual(pg.locator(".res").count(), 20)
        self.assertEqual(pg.locator(".res[data-s=error]").count(), 0, "kein Test darf abstürzen")
        self.assertIn("nicht", pg.inner_text(".caveat"))
        pg.wait_for_timeout(800)
        self.shot("6_ergebnis.png")

        # Filter und Sprung aus dem Prüfstreifen
        pg.click(".count >> nth=0")
        self.assertTrue(all(s == "crit" for s in pg.eval_on_selector_all(".res", "els => els.map(e => e.dataset.s)")))
        pg.click(".count >> nth=0")
        pg.click(".pad-btn >> nth=1")

        # Export: ZIP-Download und Dateien speichern
        import zipfile
        with pg.expect_download() as dl:
            pg.click("text=ZIP herunterladen")
        zpath = dl.value.path()
        names = zipfile.ZipFile(zpath).namelist()
        self.assertIn("bericht.txt", names)
        self.assertIn("ergebnisse.json", names)
        pg.click("text=Alle Berichte als Dateien speichern")
        pg.wait_for_selector("text=Gespeichert")
        folders = os.listdir(self.reports)
        self.assertEqual(len(folders), 1)
        saved = os.listdir(os.path.join(self.reports, folders[0]))
        for f in ("bericht.html", "bericht.txt", "ergebnisse.json", "fuer_claude.zip", "rohdaten"):
            self.assertIn(f, saved)
        self.shot("7_export.png")

        # Übergabe an Claude: Ordner öffnen, Text bereitstellen, Claude im neuen Tab (hier abgefangen)
        pg.context.route("https://claude.ai/**", lambda route: route.abort())
        pg.click("text=An Claude übergeben")
        pg.wait_for_selector("#handover-text")
        text = pg.input_value("#handover-text") if pg.locator("#handover-text").evaluate("e => e.tagName") == "INPUT" else pg.eval_on_selector("#handover-text", "e => e.value")
        self.assertIn("CLAUDIA", text)
        self.assertIn("fuer_claude.zip", text)
        self.assertIn("kritisch", text)
        self.assertNotIn("pw", text.split())
        self.shot("7b_uebergabe.png")

        # Lösungen auf Knopfdruck: Warnung sichtbar, nichts wird ohne Bestätigung ausgeführt
        pg.wait_for_selector("#actions")
        self.assertIn("auf dem Webserver zu ändern", pg.inner_text("#actions"))
        self.assertIn("frage Claude oder einen Spezialisten", pg.inner_text("#actions"))
        self.assertEqual(pg.eval_on_selector_all("#actions .redbold", "els => els.map(e => getComputedStyle(e).fontWeight)"), ["700", "700", "700"])   # seit 2.5.0 auch "Zuerst ein Rückweg" in rot
        gap = pg.evaluate("() => { const a = document.querySelector('#actions .actions-intro').getBoundingClientRect(), b = document.querySelector('#actions .finding.action').getBoundingClientRect(); return b.top - a.bottom; }")
        self.assertGreaterEqual(gap, 20)                       # Abstand zum darunterliegenden Element
        self.assertGreaterEqual(pg.locator("#actions .finding.action").count(), 1)
        self.shot("7c_aktionen.png")

        # Befehle im roten Codefenster mit Kopieren-Knopf, danach Statusfenster mit Erfolgs-/Fehlermeldung
        ids = pg.eval_on_selector_all("#actions .finding.action", "els => els.map(e => e.id)")
        self.assertNotIn("act-core_update", ids)               # Joomla-Update nur, wenn es ein Update gibt
        pick = [i for i in ids if pg.locator("#%s select" % i).count() == 0 and "update_extensions" not in i][0]
        pg.click("#%s >> text=Befehle ansehen" % pick)
        pg.wait_for_selector("#%s .codebox" % pick)
        self.assertGreaterEqual(pg.locator("#%s .codebox >> text=Kopieren" % pick).count(), 1)
        rgb = pg.eval_on_selector("#%s .codebox pre.code" % pick, "e => getComputedStyle(e).color")
        r_, g_, b_ = [int(x) for x in rgb[rgb.index("(") + 1:rgb.index(")")].replace("/", ",").split(",")[:3]]
        self.assertTrue(r_ > g_ + 40 and r_ > b_ + 40, rgb)    # Rotton
        pg.click("#%s .codebox >> text=Kopieren" % pick)
        self.assertTrue(pg.is_disabled("#%s button.primary" % pick))
        pg.check("#%s input[type=checkbox]" % pick)
        pg.click("#%s button.primary" % pick)
        pg.wait_for_selector("#status-modal")
        pg.wait_for_selector("#st-final", timeout=60000)
        self.assertIn("abgeschlossen", pg.inner_text("#st-final"))
        self.assertIn("Befehl an den Server", pg.inner_text("#st-term"))
        self.assertIn("Antwort des Servers", pg.inner_text("#st-term"))
        self.shot("7d_status.png")
        pg.click("#st-close")
        pg.wait_for_selector("#status-modal", state="detached")

        # keine Geheimnisse in der Oberfläche
        html = pg.content()
        for secret in ("GEHEIM-DB-PASSWORT", "GEHEIMES-SECRET-123"):
            self.assertNotIn(secret, html)
        real = [e for e in self.errors if not e.startswith("Failed to load resource")]   # erwartete 4xx der Fehlertests
        self.assertEqual(real, [])

    def test_2_texts_are_never_html(self):
        pg = self.page
        pg.goto(self.srv.entry_url())
        pg.wait_for_selector("h1")
        evil = "<img src=x onerror=\"window.__pwned=1\"><script>window.__pwned=1</script>"
        pg.evaluate("""(evil) => {
            const r = {id: "joomla_info", title: evil, group: "grundlagen", status: "crit", seconds: 0.1, message: evil, raw_files: [],
                       findings: [{sev: "crit", title: evil, detail: evil, items: [evil], hint: evil}]};
            document.querySelector("main").append(resultCard(r));
        }""", evil)
        pg.wait_for_timeout(300)
        self.assertIsNone(pg.evaluate("window.__pwned"))
        self.assertGreaterEqual(pg.locator("main >> text=<img src=x").count(), 1)
        self.assertEqual(pg.locator("main img").count(), 0)

    def test_3_server_protection(self):
        import json
        import urllib.error
        import urllib.request
        base = self.srv.url
        sid = self.srv.new_session()
        ok = {"X-Claudia": "1", "Cookie": "claudia=" + sid}

        def code(req):
            with self.assertRaises(urllib.error.HTTPError) as c:
                urllib.request.urlopen(req)
            return c.exception.code
        # ohne Sitzung: weder Oberfläche noch Daten
        self.assertEqual(code(base), 403)
        self.assertEqual(code(base + "api/init"), 403)
        # Cookie allein genügt nicht, der Kopf X-Claudia fehlt (fremde Seiten können ihn nicht setzen)
        self.assertEqual(code(urllib.request.Request(base + "api/init", headers={"Cookie": "claudia=" + sid})), 403)
        # erfundenes Cookie
        self.assertEqual(code(urllib.request.Request(base + "api/init", headers={"X-Claudia": "1", "Cookie": "claudia=erfunden"})), 403)
        # falscher Host-Kopf (DNS-Rebinding)
        self.assertEqual(code(urllib.request.Request(base + "api/init", headers=dict(ok, Host="evil.example:80"))), 403)
        # fremder Origin
        self.assertEqual(code(urllib.request.Request(base + "api/init", headers=dict(ok, Origin="http://evil.example"))), 403)
        # Startschlüssel gilt nur einmal und liegt nie in der Seite
        key = self.srv.new_key()
        self.assertEqual(code(base + "?k=falsch"), 403)
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *a, **k):
                return None
        op = urllib.request.build_opener(NoRedirect)
        with self.assertRaises(urllib.error.HTTPError) as c:
            op.open(base + "?k=" + key)
        self.assertEqual(c.exception.code, 302)
        self.assertIn("HttpOnly", c.exception.headers["Set-Cookie"])
        self.assertIn("SameSite=Strict", c.exception.headers["Set-Cookie"])
        with self.assertRaises(urllib.error.HTTPError) as c2:
            op.open(base + "?k=" + key)
        self.assertEqual(c2.exception.code, 403)
        sid2 = c.exception.headers["Set-Cookie"].split(";")[0].split("=", 1)[1]
        page = urllib.request.urlopen(urllib.request.Request(base, headers={"Cookie": "claudia=" + sid2})).read().decode("utf-8")
        self.assertNotIn(sid2, page)
        self.assertNotIn("claudia-token", page)
        # mit Sitzung
        data = json.load(urllib.request.urlopen(urllib.request.Request(base + "api/init", headers=ok)))
        self.assertEqual(len(data["checks"]), 74)

    def test_4_profile_has_no_password(self):
        path = os.path.join(self.base, "data", "profile.json")
        pg = self.page
        self.srv.app.disconnect()
        pg.goto(self.srv.entry_url())
        pg.wait_for_selector("text=Mit dem Server verbinden")
        self.fill("pw")
        pg.check("text=Diese Einstellungen als Profil speichern")
        pg.fill("#f-pn", "Testseite")
        pg.click("text=Verbindung testen")
        pg.wait_for_selector("text=Verbindung steht")
        pg.wait_for_selector("text=Profil gespeichert")
        txt = open(path, encoding="utf-8").read()
        self.assertIn("Testseite", txt)
        self.assertIn("fake.example.org", txt)
        self.assertNotIn('"pw"', txt)
        import json
        prof = json.loads(txt)["Testseite"]
        self.assertNotIn("password", prof)          # kein Schlüssel für Passwörter
        self.assertNotIn("pw", prof.values())       # und das eingegebene Passwort steht nirgends

    def test_5_cancel(self):
        import time
        app = self.srv.app
        app.disconnect()
        app.connect({"host": "fake.example.org", "port": 22, "user": "demo", "password": "pw", "auth": "password",
                     "site_dir": self.w["site_rel"]})
        ids = [c["id"] for c in app.init_payload()["checks"]]
        app.start(ids, {"site_dir": self.w["site_rel"]})
        app.cancel.set()
        for _ in range(100):
            if not app.running:
                break
            time.sleep(0.1)
        st = app.state(0)
        self.assertFalse(st["running"])
        self.assertTrue(st["cancelled"])
        self.assertLess(len(st["results"]), len(ids))
        self.assertTrue(st["summary"])
        app.disconnect()

    def test_6_countdown_and_php_fallback(self):
        import stat
        extra = tempfile.mkdtemp(prefix="claudia_ui_bin_")
        for name, body in (("php", "sleep 100"), ("php8.3", 'echo "PHP 8.3.6 (cli)"')):
            path = os.path.join(extra, name)
            with open(path, "w") as fh:
                fh.write("#!/bin/sh\n" + body + "\n")
            os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC)
        import phpshadow
        phpshadow.shadow_real_php(extra, keep=("php", "php8.3"))  # echtes PHP des Testrechners ausblenden
        old = self.paramiko.CONFIG["extra_path"]
        self.paramiko.CONFIG["extra_path"] = extra + os.pathsep + old
        try:
            self.srv.app.disconnect()
            pg = self.page
            pg.goto(self.srv.entry_url())
            pg.wait_for_selector("text=Mit dem Server verbinden")
            self.fill("pw")
            pg.click("text=Verbindung testen")
            pg.wait_for_selector("#cprog")
            self.assertRegex(pg.inner_text("#cprog"), r"Zeitlimit: noch \d+ s")
            self.assertEqual(pg.locator("#cprog .cprog-steps li").count(), 5)
            self.shot("8_countdown.png")
            pg.wait_for_selector("text=Verbindung steht", timeout=40000)
            facts = pg.inner_text(".facts")
            self.assertIn("PHP 8.3.6", facts)
            self.assertIn("vorhanden (", facts)        # Datenbank-Programm gefunden
            self.shot("9_verbunden_php.png")
        finally:
            self.paramiko.CONFIG["extra_path"] = old

    def test_7_timeout_is_reported(self):
        # Zeitgrenze: ein Job, dessen Frist abgelaufen ist, meldet eine verständliche Ursache
        app = self.srv.app
        app.disconnect()
        from claudia.server import ConnectJob
        job = app.job = ConnectJob(0.01)
        time.sleep(0.05)
        st = app.connect_state()
        self.assertTrue(st["done"])
        self.assertEqual(st["error"]["kind"], "timeout")
        self.assertIn("Sekunden", st["error"]["error"])

    def test_8_code_window_status_scroll_and_labels(self):
        pg = self.page
        pg.goto(self.srv.entry_url())
        pg.wait_for_selector("h1")
        # Codefenster: eingeklappt, schwarz, grüner Code, rote Markierung, Kopierfunktion
        pg.evaluate("""() => {
            const ev = {file: "./components/com_x/a.php", line: 2, note: "Test", code: [{n: 1, t: "<?php", hit: null}, {n: 2, t: "$f = 'ev' . 'al';", hit: [5, 16]}]};
            const r = {id: "malware_patterns", title: "t", group: "hintertueren", status: "crit", seconds: 0.1, message: "m", raw_files: [],
                       findings: [{sev: "crit", title: "x", detail: "d", items: [], hint: "", evidence: [ev]}]};
            document.querySelector("main").append(resultCard(r));
        }""")
        d = pg.locator("details.cw").first
        self.assertFalse(d.evaluate("e => e.open"))
        d.locator("summary").click()
        self.assertTrue(d.evaluate("e => e.open"))
        self.assertIn("a.php, Zeile 2", d.locator("summary").inner_text())
        self.assertEqual(d.locator(".cw-pre mark").inner_text(), "'ev' . 'al'")
        bg = d.evaluate("e => getComputedStyle(e).backgroundColor")
        self.assertEqual(bg, "rgb(10, 13, 11)")
        col = d.locator(".cw-pre").evaluate("e => getComputedStyle(e).color")
        r_, g_, b_ = [int(x) for x in col[col.index("(") + 1:col.index(")")].split(",")[:3]]
        self.assertTrue(g_ > r_ + 80 and g_ > b_ + 40, col)                               # grün
        self.assertTrue(d.locator("button:has-text('Kopieren')").count() == 1)
        # Statusfenster: nach oben gescrollt bleibt die Stelle stehen, ganz unten folgt es dem aktuellen Stand
        pg.evaluate("""() => {
            S.status = {id: "x", title: "T", events: [], done: false, elapsed: 1};
            for (let i = 0; i < 120; i++) S.status.events.push({t: "info", text: "Zeile " + i});
            showStatus();
        }""")
        term = pg.locator("#st-term")
        pg.wait_for_timeout(200)
        self.assertTrue(term.evaluate("e => e.scrollTop + e.clientHeight >= e.scrollHeight - 5"))   # folgt anfangs dem Ende
        term.evaluate("e => { e.scrollTop = 0; }")
        pg.wait_for_timeout(100)
        for _ in range(3):
            pg.evaluate("() => { S.status.events.push({t: 'info', text: 'neu'}); updateStatus(); }")
            pg.wait_for_timeout(60)
        self.assertEqual(pg.locator("#st-term").evaluate("e => e.scrollTop"), 0)                  # bleibt oben stehen
        self.assertTrue(pg.locator("#st-jump").is_visible())
        pg.locator("#st-jump").click()
        pg.evaluate("() => { S.status.events.push({t: 'info', text: 'ganz neu'}); updateStatus(); }")
        pg.wait_for_timeout(100)
        self.assertTrue(pg.locator("#st-term").evaluate("e => e.scrollTop + e.clientHeight >= e.scrollHeight - 5"))
        pg.evaluate("() => { S.status = null; document.getElementById('status-modal').remove(); }")
        # Verbindungsanzeige: Profilname vor Serveradresse, sonst nur die Adresse
        lab = pg.evaluate("""() => {
            S.init.profiles = {Kunde: {host: "h.example.org", user: "u"}}; S.form.profile = "";
            S.conn = {host: "h.example.org", user: "u", mode: "ssh"}; const a = connLabel();
            S.conn = {host: "andere.example.org", user: "u", mode: "ssh"}; const b = connLabel();
            return [a, b];
        }""")
        self.assertEqual(lab, ["Kunde · h.example.org", "andere.example.org"])
        # Deinstallieren (seit 2.4.1): roter Button rechts, direkt über der Fußzeile, Auswahlfeld nicht weiß
        box = pg.locator("#uninstall").bounding_box()
        self.assertTrue(box["x"] > 640 and box["y"] > 150, box)    # ohne Maßnahmenplan ist die Seite kürzer
        self.assertTrue(pg.locator("#uninstall").evaluate("e => e.closest('footer') === null && (e.closest('.uni-slot') !== null || e.closest('#uni-bar') !== null)"))   # beim Start neben "Verbindung testen" (außerhalb des Kastens), im Ergebnis in der Leiste über der Fußzeile
        self.assertEqual(pg.locator("#uni-bar").evaluate("e => e.nextElementSibling.tagName"), "FOOTER")
        self.assertIn("rgb(", pg.locator("#uninstall").evaluate("e => getComputedStyle(e).backgroundColor"))
        pg.evaluate("() => { const d = document.getElementById('unidlg'); document.getElementById('uni-body').textContent = 'x'; d.showModal(); }")
        dbg = pg.locator("#unidlg").evaluate("e => getComputedStyle(e).backgroundColor")
        mbg = pg.evaluate("() => getComputedStyle(document.documentElement).getPropertyValue('--bg').trim()")
        self.assertEqual(dbg, "rgb(231, 237, 240)")                                              # gleicher Ton wie die Hauptseiten (--bg)
        pg.evaluate("() => document.getElementById('unidlg').close()")


if __name__ == "__main__":
    unittest.main()
