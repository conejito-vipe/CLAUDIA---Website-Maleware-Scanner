"""Externer Modus: Erkennung, Versionen, Erweiterungen und vergessene Dateien für alle sieben Systeme; Lauf gegen einen lokalen Platzhalter-Server."""
import http.server
import os
import sys
import threading
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
os.environ["CLAUDIA_OFFLINE"] = "1"

from claudia import cms as cmsmod  # noqa: E402
from claudia.checks import extern as ex  # noqa: E402
from claudia.engine import Engine, Settings  # noqa: E402
from claudia.registry import REGISTRY, load_all, ordered  # noqa: E402

load_all()

HTML = {
    "wordpress": '<html><head><meta name="generator" content="WordPress 6.4.1"></head><body><script src="/wp-content/plugins/akismet/a.js?ver=5.3"></script><link href="/wp-content/themes/twentytwenty/style.css?ver=2.1"></body></html>',
    "joomla": '<html><head><meta name="generator" content="Joomla! - Open Source Content Management"><script src="/media/system/js/core.js"></script><script src="/components/com_foo/foo.js"></script></head></html>',
    "drupal": '<html><head><meta name="Generator" content="Drupal 10 (https://www.drupal.org)"><script src="/modules/contrib/pathauto/x.js"></script><script>drupalSettings={}</script></head></html>',
    "typo3": '<html><head><meta name="generator" content="TYPO3 CMS"><link href="/typo3conf/ext/news/Resources/Public/a.css"></head><!-- This website is powered by TYPO3 --></html>',
    "contao": '<html><head><meta name="generator" content="Contao Open Source CMS"><script src="/bundles/contaocore/core.js"></script><script src="/bundles/acmefoo/x.js"></script></head></html>',
    "prestashop": '<html><head><meta name="generator" content="PrestaShop"></head><script>var prestashop = {};</script><script src="/modules/ps_shoppingcart/a.js"></script><script src="/modules/mymod/b.js?v=1.2.3"></script></html>',
    "shopware": '<html><head><meta name="application-name" content="Shopware"></head><link href="/theme/0123456789abcdef0123456789abcdef/css/all.css"><script src="/bundles/storefront/a.js"></script></html>',
}


class DetectTest(unittest.TestCase):
    def test_alle_systeme_erkannt(self):
        for cms, html in HTML.items():
            d = ex.detect(html)
            self.assertEqual(d["cms"], cms, cms)
            self.assertTrue(d["evidence"], cms)

    def test_unklar_bleibt_leer(self):
        self.assertEqual(ex.detect("<html><body>Hallo</body></html>")["cms"], "")
        self.assertEqual(ex.detect("")["cms"], "")

    def test_kopfzeile_und_cookie(self):
        d = ex.detect("<html></html>", {"X-Generator": "Drupal 9 (https://www.drupal.org)", "X-Drupal-Cache": "HIT"})
        self.assertEqual(d["cms"], "drupal")
        d = ex.detect("<html></html>", {}, ["fe_typo_user=abc; path=/", "x"], {"/typo3/": (200, "TYPO3 CMS Login")})
        self.assertEqual(d["cms"], "typo3")

    def test_probe_nur_bei_200(self):
        d = ex.detect("<html></html>", {}, [], {"/administrator/": (404, "Joomla!")})
        self.assertEqual(d["cms"], "")

    def test_zwei_systeme_ohne_abstand_ist_unklar(self):
        d = ex.detect(HTML["wordpress"] + HTML["joomla"])
        self.assertIn(d["cms"], ("", "wordpress", "joomla"))
        self.assertLessEqual(max(d["scores"].values()), 12)


class VersionTest(unittest.TestCase):
    def test_wordpress(self):
        self.assertEqual(ex.parse_version("wordpress", HTML["wordpress"])[0], "6.4.1")
        self.assertEqual(ex.parse_version("wordpress", "<html></html>", None, {"/feed/": (200, "<generator>https://wordpress.org/?v=6.2.2</generator>")})[0], "6.2.2")
        self.assertEqual(ex.parse_version("wordpress", "", None, {"/readme.html": (200, "<br />\nVersion 5.9.3\n")})[0], "5.9.3")

    def test_joomla(self):
        p = {"/administrator/manifests/files/joomla.xml": (200, "<extension><version>4.4.2</version></extension>")}
        self.assertEqual(ex.parse_version("joomla", "", None, p)[0], "4.4.2")
        self.assertEqual(ex.parse_version("joomla", "", None, {})[0], "")

    def test_drupal(self):
        p = {"/core/CHANGELOG.txt": (200, "Drupal 10.2.3, 2024-02-01\n---")}
        self.assertEqual(ex.parse_version("drupal", "", None, p)[0], "10.2.3")
        v, src = ex.parse_version("drupal", HTML["drupal"])
        self.assertEqual(v, "10")
        self.assertIn("Hauptversion", src)
        self.assertEqual(ex.parse_version("drupal", "", None, {"/CHANGELOG.txt": (200, "Drupal 7.98, 2023-05-17")})[0], "7.98")

    def test_typo3_shopware_und_nicht_lesbare(self):
        self.assertEqual(ex.parse_version("typo3", "", None, {"/typo3/": (200, "TYPO3 CMS 12.4.8 Login")})[0], "12.4.8")
        self.assertEqual(ex.parse_version("shopware", "", None, {"/api/_info/version": (200, '{"version":"6.5.8.2"}')})[0], "6.5.8.2")
        self.assertEqual(ex.parse_version("shopware", "", None, {"/api/_info/version": (200, '{"version":"<script>"}')})[0], "")
        self.assertEqual(ex.parse_version("contao", HTML["contao"])[0], "")
        self.assertEqual(ex.parse_version("prestashop", HTML["prestashop"])[0], "")


class ComponentsTest(unittest.TestCase):
    def slugs(self, cms):
        return {(c["kind"], c["slug"]): c["version"] for c in ex.components(cms, HTML[cms])}

    def test_wordpress(self):
        s = self.slugs("wordpress")
        self.assertEqual(s[("Plugin", "akismet")], "5.3")
        self.assertIn(("Theme", "twentytwenty"), s)

    def test_joomla(self):
        self.assertIn(("Komponente", "com_foo"), self.slugs("joomla"))

    def test_drupal(self):
        self.assertIn(("Modul", "pathauto"), self.slugs("drupal"))

    def test_typo3(self):
        self.assertIn(("Erweiterung", "news"), self.slugs("typo3"))

    def test_contao_ohne_kernpakete(self):
        s = self.slugs("contao")
        self.assertIn(("Paket", "acmefoo"), s)
        self.assertNotIn(("Paket", "contaocore"), s)

    def test_prestashop(self):
        s = self.slugs("prestashop")
        self.assertEqual(s[("Modul", "mymod")], "1.2.3")

    def test_shopware_ohne_kernpakete(self):
        s = self.slugs("shopware")
        self.assertNotIn(("Paket", "storefront"), s)

    def test_hilfsfunktionen(self):
        self.assertEqual(ex.readme_stable_tag("=== X ===\nStable tag: 2.4.1\n"), "2.4.1")
        self.assertEqual(ex.wp_plugin_latest('{"version":"3.1"}'), "3.1")
        self.assertEqual(ex.wp_plugin_latest("kaputt"), "")


class FilesTest(unittest.TestCase):
    def test_jede_datei_hat_eine_pruefung_je_system(self):
        for cms in ex.SYSTEMS:
            names = [f[0] for f in ex.files_for(cms)]
            self.assertIn(".env", names)
            self.assertGreater(len(names), 20, cms)
        self.assertIn("wp-config.php.bak", [f[0] for f in ex.files_for("wordpress")])
        self.assertNotIn("wp-config.php.bak", [f[0] for f in ex.files_for("joomla")])
        self.assertIn("config/jwt/private.pem", [f[0] for f in ex.files_for("shopware")])

    def test_treffer_braucht_signatur(self):
        self.assertTrue(ex.is_real_hit(".env", 200, "DB_PASSWORD=geheim\nAPP_ENV=prod", b"", None))
        self.assertFalse(ex.is_real_hit(".env", 200, "<html>Seite nicht gefunden</html>", b"", None))
        self.assertFalse(ex.is_real_hit(".env", 404, "DB_PASSWORD=x", b"", None))
        self.assertTrue(ex.is_real_hit(".git/HEAD", 200, "ref: refs/heads/main", b"", None))
        self.assertTrue(ex.is_real_hit("backup.zip", 200, "", b"PK\x03\x04abc", None))

    def test_weiche_404_wird_ignoriert(self):
        page = "<html>" + "Willkommen " * 50 + "DB_PASSWORD=x</html>"
        self.assertFalse(ex.is_real_hit(".env", 200, page, b"", (200, page)))

    def test_unbekannter_pfad_kein_treffer(self):
        self.assertFalse(ex.is_real_hit("gibt-es-nicht", 200, "alles", b"", None))


class RegistryTest(unittest.TestCase):
    def test_extern_markierung(self):
        for cms in ex.SYSTEMS:
            ids = {c.id for c in ordered(cms) if c.extern}
            for need in ("ext_fingerprint", "ext_components", "ext_files", "web_source", "web_headers"):
                self.assertIn(need, ids, "%s fehlt bei %s" % (need, cms))
            for c in ordered(cms):
                if c.extern:
                    self.assertIn(c.needs, ("web", "local"), c.id)

    def test_public_enthaelt_extern(self):
        self.assertTrue(REGISTRY["ext_files"].public("wordpress")["extern"])
        self.assertFalse(REGISTRY["root_files"].public("wordpress")["extern"])


class Site:
    """Kleiner Platzhalter-Server: je nach Modus ein Webseitenaufbau."""

    def __init__(self, cms, soft404=False):
        self.cms, self.soft404 = cms, soft404
        site = self

        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                p = self.path.split("?")[0]
                body, code = site.page(p)
                self.send_response(code)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(body if isinstance(body, bytes) else body.encode())

            def log_message(self, *a):
                pass
        self.srv = http.server.HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.url = "http://127.0.0.1:%d/" % self.srv.server_port

    def page(self, p):
        home = HTML[self.cms]
        if p in ("/", "/index.php"):
            return home, 200
        if self.cms == "wordpress":
            if p == "/wp-config.php.bak":
                return "<?php define('DB_PASSWORD','x');", 200
            if p == "/wp-content/plugins/akismet/readme.txt":
                return "Stable tag: 5.3\n", 200
        if self.cms == "shopware" and p == "/config/jwt/private.pem":
            return "-----BEGIN " + "PRIVATE KEY-----\nabc\n", 200
        if p == "/.env" and not self.soft404:
            return "DB_PASSWORD=geheim\nAPP_ENV=prod\n", 200
        return (home, 200) if self.soft404 else ("nicht gefunden", 404)

    def close(self):
        self.srv.shutdown()


def lauf(site, cms, ids):
    eng = Engine(None, Settings(url=site.url, cms=cms, extern=True), {})
    return {r.id: r for r in eng.run(ids, lambda e: None, threading.Event())}


class LaufTest(unittest.TestCase):
    def test_wordpress_komplett(self):
        s = Site("wordpress")
        try:
            r = lauf(s, "wordpress", ["ext_fingerprint", "ext_components", "ext_files", "root_files"])
        finally:
            s.close()
        self.assertNotIn("root_files", r)                     # nicht extern: wird im externen Modus ausgelassen
        fp = r["ext_fingerprint"]
        self.assertTrue(any("WordPress 6.4.1" in f.title for f in fp.findings))
        self.assertTrue(any("akismet" in " ".join(f.items) for f in r["ext_components"].findings))
        files = r["ext_files"]
        self.assertEqual(files.status, "crit")
        txt = " ".join(" ".join(f.items) for f in files.findings)
        self.assertIn("wp-config.php.bak", txt)
        self.assertIn(".env", txt)
        self.assertNotIn("geheim", txt)                       # Inhalte werden nie gemeldet

    def test_shopware_schluessel(self):
        s = Site("shopware")
        try:
            r = lauf(s, "shopware", ["ext_files"])
        finally:
            s.close()
        self.assertIn("private.pem", " ".join(" ".join(f.items) for f in r["ext_files"].findings))

    def test_weiche_404_keine_fehlalarme(self):
        for cms in ("joomla", "drupal", "typo3", "contao", "prestashop"):
            s = Site(cms, soft404=True)
            try:
                r = lauf(s, cms, ["ext_files"])
            finally:
                s.close()
            crit = [f for f in r["ext_files"].findings if f.sev == "crit"]
            self.assertEqual(crit, [], cms)

    def test_alle_systeme_laufen_ohne_fehler(self):
        for cms in ex.SYSTEMS:
            s = Site(cms)
            try:
                ids = ["ext_fingerprint", "ext_components", "ext_files"]
                r = lauf(s, cms, ids)
            finally:
                s.close()
            for i in ids:
                self.assertNotIn(r[i].status, ("error",), "%s %s %s" % (cms, i, r[i].message))
            self.assertTrue(any(NAME in f.title for f in r["ext_fingerprint"].findings for NAME in [ex.NAMES[cms]]), cms)

    def test_ohne_adresse_wird_uebersprungen(self):
        eng = Engine(None, Settings(url="", cms="wordpress", extern=True), {})
        res = eng.run(["ext_fingerprint"], lambda e: None, threading.Event())
        self.assertEqual(res[0].status, "skipped")

    def test_unerreichbar(self):
        eng = Engine(None, Settings(url="http://127.0.0.1:9/", cms="wordpress", extern=True), {})
        res = eng.run(["ext_fingerprint"], lambda e: None, threading.Event())
        self.assertIn(res[0].status, ("skipped", "info"))

    def test_extern_laesst_ssh_pruefungen_aus(self):
        ids = [c.id for c in ordered("drupal")]
        eng = Engine(None, Settings(url="http://127.0.0.1:9/", cms="drupal", extern=True), {})
        res = eng.run(ids, lambda e: None, threading.Event())
        for r in res:
            self.assertTrue(REGISTRY[r.id].extern or REGISTRY[r.id].needs == "local", r.id)


class ServerTest(unittest.TestCase):
    def app(self):
        import tempfile
        from claudia.server import App
        return App(tempfile.mkdtemp(prefix="claudia_ext_"))

    def test_verbinden_erkennt_system_ohne_ssh(self):
        for cms in ("wordpress", "drupal", "shopware"):
            s = Site(cms)
            old = os.environ.pop("CLAUDIA_OFFLINE")
            try:
                app = self.app()
                r = app.connect({"mode": "none", "url": s.url})
            finally:
                os.environ["CLAUDIA_OFFLINE"] = old
                s.close()
            self.assertTrue(r["ok"])
            self.assertIsNone(app.runner)
            self.assertEqual(app.cms(), cms)
            self.assertTrue(app.conn["external"])
            self.assertEqual(r["info"]["detected"]["cms"], cms)

    def test_manuelle_wahl_und_start_nur_extern(self):
        app = self.app()
        r = app.connect({"mode": "none", "url": "https://example.invalid", "cms": "typo3"})
        self.assertEqual(r["info"]["cms"], "typo3")
        self.assertEqual(app.cms(), "typo3")
        app.start(["ext_files", "root_files"], {})
        app.thread.join(60)
        ids = [x["id"] for x in app.results]
        self.assertNotIn("root_files", ids)
        self.assertIn("ext_files", ids)
        self.assertTrue(app.run_settings["externer_modus"])

    def test_ungueltige_adresse(self):
        from claudia.server import ApiError
        with self.assertRaises(ApiError):
            self.app().connect({"mode": "none", "url": "https://"})

    def test_ohne_adresse_geht(self):
        app = self.app()
        r = app.connect({"mode": "none"})
        self.assertTrue(r["ok"])


class JudgeTest(unittest.TestCase):
    def test_offline_gibt_info(self):
        for cms in ex.SYSTEMS:
            sev, text = ex.judge_version(cms, "1.2.3")
            self.assertEqual(sev, "info", cms)
        self.assertEqual(ex.judge_version("contao", "")[0], "info")


if __name__ == "__main__":
    unittest.main()
