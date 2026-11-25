"""Integrationstests: alle Prüfungen gegen die künstliche 'infizierte' und 'saubere' Seite."""
import json
import os
import sys
import tempfile
import threading
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

import fixture  # noqa: E402
import webfixture  # noqa: E402
from claudia.engine import Engine, Settings  # noqa: E402
from claudia.registry import load_all, ordered  # noqa: E402
from claudia.runner import LocalRunner  # noqa: E402

ADV = json.load(open(os.path.join(ROOT, "claudia", "advisories.json"), encoding="utf-8"))


def run_all(infected, with_web=True):
    load_all()
    base = tempfile.mkdtemp(prefix="claudia_i_")
    w = fixture.make_world(base, infected)
    srv, url = webfixture.start(infected)
    s = Settings(site_dir=w["site_rel"], url=url if with_web else "", log_dir="logs",
                 opts={"local_logs": {"path": os.path.join(w["home"], "logs")},
                       "web_source": {"must_block": "/backup-open/"}},
                 allow_hosts=[])
    eng = Engine(LocalRunner(w["home"], extra_path=w["bin"]), s, ADV)
    ids = [c.id for c in ordered()]
    out = eng.run(ids, lambda e: None, threading.Event())
    srv.shutdown()
    return {r.id: r for r in out}, w


def titles(res, sev=None):
    return [f.title for f in res.findings if sev is None or f.sev == sev]


def has(res, text, sev=None):
    return any(text.lower() in t.lower() for t in titles(res, sev))


class InfectedSite(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.r, cls.w = run_all(True)

    def test_no_test_crashed(self):
        bad = {k: v.message for k, v in self.r.items() if v.status == "error"}
        self.assertEqual(bad, {})

    def test_node_modules_and_js(self):
        self.assertEqual(self.r["node_modules"].status, "crit")
        js = self.r["js_scan"]
        self.assertTrue(has(js, "Schadcode-Merkmale", "crit"))
        self.assertTrue(has(js, "Verschleierter Code", "crit"))
        items = " ".join(i for f in js.findings for i in f.items)
        self.assertIn("jquery.min.js", items)
        self.assertIn("package.json", items)          # Versions-Widerspruch Kopf vs. package.json

    def test_webshells_and_uploads(self):
        self.assertTrue(has(self.r["php_in_uploads"], "PHP-Datei(en) in images", "crit"))
        self.assertTrue(has(self.r["php_in_uploads"], "harmloser Endung", "crit"))
        self.assertTrue(has(self.r["php_in_uploads"], "versteckte", "warn"))
        self.assertTrue(has(self.r["webshells"], "Hintertür-Mustern", "crit"))
        self.assertTrue(has(self.r["suspicious_names"], "Hintertür-Namen", "crit"))
        self.assertTrue(has(self.r["root_files"], "Unbekannte PHP-Datei", "warn"))

    def test_config_and_htaccess(self):
        self.assertTrue(has(self.r["configuration"], "Unerwartete Zeilen", "crit"))
        self.assertTrue(has(self.r["configuration"], "Debug", "warn"))
        self.assertTrue(has(self.r["configuration"], "Schrägstrich", "warn"))
        self.assertTrue(has(self.r["htaccess"], "gefährliche", "crit"))
        self.assertTrue(has(self.r["htaccess"], "Cloaking", "crit"))
        self.assertTrue(has(self.r["entry_points"], "Template-Dateien", "warn"))
        raw = self.r["configuration"].raw["configuration_maskiert"]
        self.assertNotIn("GEHEIM", raw)

    def test_extensions(self):
        e = self.r["extensions_fs"]
        self.assertTrue(has(e, "bekannter Sicherheitslücke", "crit"))
        text = " ".join(i for f in e.findings for i in f.items)
        for name in ("JCE Editor", "Tassos Framework", "Convert Forms"):
            self.assertIn(name, text)
        self.assertIn("erweiterungen.csv", e.raw)

    def test_database(self):
        self.assertEqual(self.r["db_access"].status, "ok")
        self.assertTrue(has(self.r["db_users"], "angelegt", "warn"))
        self.assertTrue(has(self.r["db_users"], "API-Token", "warn"))
        self.assertTrue(has(self.r["db_jce"], "php", "crit"))
        c = self.r["db_content"]
        self.assertTrue(has(c, "verdächtigem Code", "crit"))
        self.assertTrue(any("GTM-AAAA111" in i for f in c.findings for i in f.items))
        x = self.r["db_extensions"]
        self.assertTrue(any("plugins/system/t4" in i for f in x.findings for i in f.items))   # verwaister T4-Ordner
        self.assertTrue(has(self.r["db_actionlog"], "nie jemand angemeldet", "warn"))
        self.assertTrue(has(self.r["db_redirects"], "unbekannte Domains", "warn"))

    def test_logs_and_web(self):
        a = self.r["access_logs"]
        self.assertTrue(has(a, "JCE", "crit") and has(a, "Tassos", "crit") and has(a, "tmp", "crit"))
        self.assertEqual(titles(a, "crit"), titles(self.r["local_logs"], "crit"))
        self.assertTrue(has(self.r["joomla_logs"], "Programmcode-Eingaben", "crit"))
        w = self.r["web_source"]
        self.assertTrue(has(w, "Cloaking", "crit"))
        self.assertTrue(has(w, "öffentlich abrufbar", "crit"))
        self.assertTrue(has(w, "Schadcode-Merkmale", "crit"))

    def test_backups_and_world(self):
        self.assertTrue(has(self.r["backups_in_webroot"], "ohne Zugriffssperre", "crit"))
        self.assertTrue(has(self.r["other_installs"], "weitere Installation", "warn"))

    def test_no_secret_leak_anywhere(self):
        blob = json.dumps({k: v.to_dict() for k, v in self.r.items()}, ensure_ascii=False)
        self.assertNotIn("GEHEIM-DB-PASSWORT", blob)
        self.assertNotIn("GEHEIMES-SECRET", blob)
        self.assertNotIn("198.51.100.7", blob)         # IPs sind standardmäßig gekürzt


class CleanSite(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.r, cls.w = run_all(False)

    def test_no_crash_no_crit(self):
        self.assertEqual({k: v.message for k, v in self.r.items() if v.status == "error"}, {})
        crit = {k: titles(v, "crit") for k, v in self.r.items() if titles(v, "crit")}
        # einzig erwarteter Treffer: die Testadresse /backup-open/ ist im Webserver-Fixture absichtlich offen
        self.assertEqual(list(crit), ["web_source"], crit)

    def test_only_expected_warnings(self):
        warn = {k: titles(v, "warn") for k, v in self.r.items() if titles(v, "warn")}
        self.assertEqual(set(warn), {"other_installs", "backup_tool", "auto_updates"}, warn)   # backup_tool: Sicherungs-Erweiterung ohne Archiv am üblichen Ort; auto_updates: im Testkonto ist kein Mailversand eingerichtet


class DbFallback(unittest.TestCase):
    def test_skip_without_mysql(self):
        load_all()
        base = tempfile.mkdtemp(prefix="claudia_f_")
        w = fixture.make_world(base, True)
        s = Settings(site_dir=w["site_rel"])
        eng = Engine(LocalRunner(w["home"], extra_path=None), s, ADV)   # ohne mysql-Attrappe im PATH
        out = eng.run(["db_users", "db_jce"], lambda e: None, threading.Event())
        for r in out:
            self.assertEqual(r.status, "skipped")
            self.assertIn("sql_manuell", r.raw)
            self.assertIn("SELECT", r.raw["sql_manuell"])
            self.assertIn("j_users", out[0].raw["sql_manuell"])
            self.assertNotIn("GEHEIM", r.raw["sql_manuell"])

    def test_wrong_password(self):
        load_all()
        base = tempfile.mkdtemp(prefix="claudia_p_")
        w = fixture.make_world(base, True)
        os.environ["CLAUDIA_TEST_PW"] = "anderes-passwort"
        try:
            eng = Engine(LocalRunner(w["home"], extra_path=w["bin"]), Settings(site_dir=w["site_rel"]), ADV)
            out = eng.run(["db_access"], lambda e: None, threading.Event())
            self.assertEqual(out[0].status, "skipped")
            self.assertIn("verweigert", out[0].message)
        finally:
            del os.environ["CLAUDIA_TEST_PW"]


if __name__ == "__main__":
    unittest.main(verbosity=2)
