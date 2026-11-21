"""PrestaShop (2.12.0): Profil, Erkennung, Parser, Auswertungen und alle PrestaShop-Prüfungen auf einer nachgebauten PrestaShop-8.2-Testwelt. Nur lesend, keine Geheimnisse im Ergebnis."""
import hashlib
import io
import json
import os
import sys
import tempfile
import threading
import unittest
import zipfile
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))
os.environ["CLAUDIA_OFFLINE"] = "1"

import prestashopfixture as pf  # noqa: E402
import test_konto as k  # noqa: E402
from claudia import cms as cmsmod, prestashop, prestashopref, registry  # noqa: E402
from claudia.checks import auswertung_prestashop as ap  # noqa: E402
from claudia.checks import web as webmod  # noqa: E402
from claudia.engine import Engine, Settings  # noqa: E402
from claudia.runner import LocalRunner  # noqa: E402

NOW = 1_795_000_000.0
DAY = 86400
IDS = {"prestashop_core", "prestashop_settings", "prestashop_exposed", "prestashop_modules", "prestashop_users", "prestashop_shop", "prestashop_db_code"}


def run(w, ids, url=""):
    s = Settings(site_dir=w["site_rel"], log_dir="logs", cms="prestashop", url=url, allow_hosts=k.ADV["allow_hosts"])
    eng = Engine(LocalRunner(w["home"], extra_path=w["bin"]), s, k.ADV)
    return eng.run(ids, lambda e: None, threading.Event())


def adv_json(pkg="prestashop/prestashop", affected=">=8.2.0,<8.2.2"):
    return json.dumps({"advisories": {pkg: [{"advisoryId": "PKSA-7", "packageName": pkg, "title": "SQL-Einschleusung", "link": "https://x.example", "cve": "CVE-2026-0003",
                                             "affectedVersions": affected, "reportedAt": "2026-05-01 00:00:00"}]}})


class Profile(unittest.TestCase):
    def test_known(self):
        self.assertEqual(cmsmod.PROFILES["prestashop"]["name"], "PrestaShop")
        self.assertEqual(cmsmod.PROFILES["prestashop"]["common_checks"], cmsmod.PROFILES["drupal"]["common_checks"])

    def test_checks_only_for_prestashop(self):
        for cms in ("joomla", "wordpress", "drupal", "typo3", "contao"):
            self.assertFalse(IDS & {c.id for c in registry.ordered(cms)}, cms)
        self.assertTrue(IDS <= {c.id for c in registry.ordered("prestashop")})
        self.assertNotIn("joomla_core", {c.id for c in registry.ordered("prestashop")})

    def test_cluster_group_and_texts(self):
        for c in registry.ordered("prestashop"):
            if c.id.startswith("prestashop_"):
                self.assertTrue(c.cluster_for("prestashop"), c.id)
                self.assertIn(c.group, [g[0] for g in registry.groups_for("prestashop")])
            self.assertNotIn("configuration.php", json.dumps(c.view("prestashop"), ensure_ascii=False), c.id)


class Parsers(unittest.TestCase):
    def test_version(self):
        self.assertEqual(prestashop.parse_core_version(pf.KERNEL % "8.2.1"), "8.2.1")
        self.assertEqual(prestashop.parse_core_version("", "", "define('_PS_VERSION_', '1.6.1.24');"), "1.6.1.24")
        self.assertEqual(prestashop.parse_core_version("", "$version = 1;"), "")
        self.assertEqual(prestashop.parse_core_version("nichts"), "")

    def test_lifecycle(self):
        self.assertEqual(prestashop.lifecycle("9.1.0")["state"], "supported")
        self.assertEqual(prestashop.lifecycle("9.0.2")["state"], "security")
        self.assertEqual(prestashop.lifecycle("8.2.1")["state"], "security")
        self.assertEqual(prestashop.lifecycle("8.1.7")["state"], "ended")
        self.assertEqual(prestashop.lifecycle("1.7.8.11")["state"], "ended")
        self.assertEqual(prestashop.lifecycle("1.6.1.24")["state"], "ended")
        self.assertEqual(prestashop.lifecycle("99.0.0")["state"], "unknown")
        self.assertEqual(prestashop.lifecycle("")["state"], "unknown")

    def test_settings_and_no_secret_leak(self):
        r = prestashop.parse_settings(pf.PARAMS_GOOD, pf.DEFINES_GOOD)
        v = r["vars"]
        self.assertEqual((v["host"], v["user"], v["db"], v["dbprefix"]), ("127.0.0.1", "ps_user", "ps_db", "ps_"))
        self.assertTrue(r["prestashop"]["dev_known"])
        self.assertFalse(r["prestashop"]["dev_mode"])
        self.assertEqual(r["prestashop"]["cookie_len"], 64)
        self.assertNotIn("GEHEIM-SECRET", json.dumps(r["prestashop"]))
        self.assertEqual(r["unexpected"], [])

    def test_settings_bad(self):
        r = prestashop.parse_settings(pf.PARAMS_BAD, pf.DEFINES_BAD)
        self.assertTrue(r["prestashop"]["dev_mode"])
        self.assertEqual(r["prestashop"]["cookie_len"], 4)
        self.assertTrue(r["unexpected"])

    def test_settings_legacy_16(self):
        s16 = "<?php\ndefine('_DB_SERVER_', 'dbh');\ndefine('_DB_NAME_', 'n');\ndefine('_DB_USER_', 'u');\ndefine('_DB_PASSWD_', 'p');\ndefine('_DB_PREFIX_', 'x_');\ndefine('_COOKIE_KEY_', 'abc');\n"
        r = prestashop.parse_settings("", "", s16)
        self.assertEqual((r["vars"]["host"], r["vars"]["db"], r["prefix"]), ("dbh", "n", "x_"))
        self.assertTrue(r["prestashop"]["legacy"])

    def test_split_config_output(self):
        p = prestashop.split_config_output("@@F app/config/parameters.php\n<?php x\n@@F app/AppKernel.php\nK\n@@DIRS\nadmin123\ninstall/\n")
        self.assertEqual(sorted(p["files"]), ["app/AppKernel.php", "app/config/parameters.php"])
        self.assertEqual(p["dirs"], ["admin123", "install"])
        self.assertEqual(prestashop.split_config_output("@@DIRS\nadmin\n")["dirs"], ["admin"])

    def test_release_list(self):
        t = json.dumps({"packages": {"prestashop/prestashop": [{"version": "8.2.1"}, {"version": "dev-develop"}, {"version": "9.0.0-beta.1"}]}})
        self.assertEqual([r["version"] for r in prestashop.parse_release_list(t)], ["8.2.1"])
        self.assertEqual(prestashop.parse_release_list("kaputt"), [])


class Judges(unittest.TestCase):
    def test_core_levels(self):
        self.assertEqual(ap.judge_core("1.7.8.11", [], [])[0][0], "crit")
        self.assertEqual(ap.judge_core("8.1.7", [], [])[0][0], "crit")
        self.assertEqual(ap.judge_core("8.2.1", [], [])[0][0], "warn")
        self.assertEqual(ap.judge_core("", [], [])[0][0], "info")
        self.assertTrue(any(f[0] == "crit" and "Sicherheitsmeldung" in f[1] for f in ap.judge_core("9.1.0", [], [{"id": "X", "title": "t"}])))
        self.assertTrue(any(f[0] == "ok" for f in ap.judge_core("9.1.0", [{"version": "9.1.0", "date": ""}], [])))
        self.assertFalse(any(f[0] == "ok" for f in ap.judge_core("9.1.0", [], [], adv_ok=False)))

    def test_core_files(self):
        self.assertEqual(ap.judge_core_files("p", 100, [], [], [])[0][0], "ok")
        r = ap.judge_core_files("p", 100, ["a"], ["b"], ["x.php", "y.txt"])
        self.assertIn("crit", [f[0] for f in r])

    def test_settings_levels(self):
        cfg = prestashop.parse_settings(pf.PARAMS_BAD, pf.DEFINES_BAD)
        t = " | ".join(f[1] for f in ap.judge_settings(cfg, ["install", "admin", "admin123abc"], {"app/config/parameters.php": "666 u"}))
        for s in ("auffällige Befehle", "Entwicklungsmodus", "cookie_key", "Installationsordner", "leicht zu erratenden", "für alle beschreibbar"):
            self.assertIn(s, t)
        good = prestashop.parse_settings(pf.PARAMS_GOOD, pf.DEFINES_GOOD)
        self.assertEqual([f[0] for f in ap.judge_settings(good, ["admin123abc"], {"app/config/parameters.php": "600 u"})], ["ok"])

    def test_settings_unusable(self):
        self.assertEqual(ap.judge_settings(None)[0][0], "info")
        self.assertEqual(ap.judge_settings({"missing": True})[0][0], "info")

    def test_modules(self):
        inv = [{"key": "a", "name": "a", "version": "1.0.0", "pkg": "x/a", "core": False}, {"key": "b", "name": "b", "version": "2", "pkg": "", "core": True}]
        r = ap.judge_modules(inv, {"a": [{"id": "X", "title": "t"}]}, 1, True, ["override/classes/Product.php"])
        self.assertEqual(sorted(f[0] for f in r), ["crit", "info", "info"])
        self.assertEqual(ap.judge_modules(None, None)[0][0], "info")

    def test_users(self):
        us = [{"uid": 1, "name": "Admin Admin", "super": True, "active": True, "created_ts": NOW - 2 * DAY, "access_ts": None},
              {"uid": 2, "name": "x", "super": True, "active": False, "created_ts": None, "access_ts": 5}]
        t = " | ".join(f[1] for f in ap.judge_users(us, NOW))
        for s in ("letzten 14 Tagen", "nie angemeldet", "leicht zu erratenden"):
            self.assertIn(s, t)
        self.assertEqual(ap.judge_users(None)[0][0], "info")

    def test_shop(self):
        t = " | ".join(f[1] + f[0] for f in ap.judge_shop({"PS_WEBSERVICE": "1", "PS_SSL_ENABLED": "0", "PS_SSL_ENABLED_EVERYWHERE": "0"}, [{"id": 1, "descr": "x", "active": True, "write": True}]))
        self.assertIn("HTTPS", t)
        self.assertIn("Webservice", t)
        self.assertEqual(ap.judge_shop({"PS_WEBSERVICE": "0", "PS_SSL_ENABLED": "1", "PS_SSL_ENABLED_EVERYWHERE": "1", "PS_DISABLE_OVERRIDES": "1"}, [])[0][0], "ok")
        self.assertEqual(ap.judge_shop(None, None)[0][0], "info")

    def test_exposed(self):
        web = [{"kind": "file", "label": "Einstellungsdatei", "url": "u/p", "status": 200, "body": "<?php return array('database_password' => 'x');"},
               {"kind": "install", "label": "Installation", "url": "u/i", "status": 200, "body": "PrestaShop Installation Assistant"},
               {"kind": "dir", "label": "modules", "url": "u/m", "status": 200, "body": "<title>Index of /modules"},
               {"kind": "api", "label": "Webservice", "url": "u/api", "status": 401, "body": ""},
               {"kind": "file", "label": "soft404", "url": "u/x", "status": 200, "body": "<!DOCTYPE html><html>database_password"}]
        r = ap.judge_exposed(web)
        self.assertEqual(sorted(f[0] for f in r), ["crit", "info", "warn"])
        self.assertEqual(ap.judge_exposed([{"kind": "file", "label": "x", "url": "u", "status": 403, "body": ""}])[0][0], "ok")

    def test_db_code(self):
        self.assertEqual(ap.judge_db_code([{"table": "cms_lang.content", "id": 1, "text": "<script>eval(1)</script>"}])[0][0], "crit")
        self.assertEqual(ap.judge_db_code(None)[0][0], "info")


class Reference(unittest.TestCase):
    @staticmethod
    def zipped(n=250):
        b = io.BytesIO()
        with zipfile.ZipFile(b, "w") as z:
            for i in range(n):
                z.writestr("PrestaShop-8.2.1/classes/T%d.php" % i, "<?php //%d" % i)
            z.writestr("PrestaShop-8.2.1/README.md", "x")
        return b.getvalue()

    def test_only_core(self):
        self.assertEqual(sorted(prestashopref.only_core({"classes/a.php": "1", "README.md": "2", "src/b.php": "3", "var/c.php": "4"})), ["classes/a.php", "src/b.php"])

    def test_version_pattern(self):
        self.assertTrue(prestashopref.VERSION_RE.match("8.2.1"))
        self.assertTrue(prestashopref.VERSION_RE.match("1.7.8.11"))
        self.assertFalse(prestashopref.VERSION_RE.match("8.2.1-beta.1"))

    def test_compare_and_server_hash_parse(self):
        srv = prestashopref.parse_server_hashes("%s  ./classes/a.php\n%s  ./classes/b.php\nmuell\n" % ("a" * 64, "b" * 64))
        self.assertEqual(len(srv), 2)
        d = prestashopref.compare({"classes/a.php": "a" * 64, "classes/c.php": "c" * 64}, srv)
        self.assertEqual((d["changed"], d["missing"], d["extra"]), ([], ["classes/c.php"], ["classes/b.php"]))


class Integration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base = tempfile.mkdtemp(prefix="claudia_ps_")
        cls.bad = pf.make_prestashop_world(cls.base, True)
        cls.good = pf.make_prestashop_world(cls.base, False)
        for w in (cls.bad, cls.good):
            k.install(w["bin"], "crontab", k.FAKE_CRONTAB)
            k.install(w["bin"], "ssh-keygen", k.FAKE_KEYGEN)
            k.install(w["bin"], "ps", k.FAKE_PS)
        ids = [c.id for c in registry.ordered("prestashop")]
        os.environ["CLAUDIA_TEST_DB"] = cls.bad["db"]
        cls.rb = {r.id: r for r in run(cls.bad, ids)}
        os.environ["CLAUDIA_TEST_DB"] = cls.good["db"]
        cls.rg = {r.id: r for r in run(cls.good, ids)}

    def test_no_check_crashes(self):
        for rr in (self.rb, self.rg):
            for i, r in rr.items():
                self.assertNotEqual(r.status, "error", (i, k.blob(r)[:300]))

    def test_infected_findings(self):
        b = self.rb
        t = " | ".join(f.title for f in b["prestashop_settings"].findings)
        for s in ("auffällige Befehle", "Entwicklungsmodus", "Installationsordner"):
            self.assertIn(s, t)
        self.assertIn(("crit", "2 Inhalt(e) enthalten verschleierten oder fremden Code"), k.tt(b["prestashop_db_code"]))
        t = " | ".join(f.title for f in b["prestashop_users"].findings)
        self.assertIn("letzten 14 Tagen", t)
        t = " | ".join(f.title for f in b["prestashop_shop"].findings)
        self.assertIn("HTTPS", t)
        self.assertTrue(any("Override" in f.title for f in b["prestashop_modules"].findings))
        self.assertEqual(b["webshells"].status, "crit")

    def test_clean_has_no_crit(self):
        for i in ("prestashop_settings", "prestashop_users", "prestashop_shop", "prestashop_db_code"):
            self.assertNotIn("crit", [f.sev for f in self.rg[i].findings], i)
        self.assertEqual(k.tt(self.rg["prestashop_settings"]), [("ok", "Die Einstellungen sind unauffällig")])

    def test_database_access_uses_parameters(self):
        self.assertEqual(self.rg["db_access"].findings[0].sev, "ok")

    def test_core_offline_reads_version(self):
        self.assertNotEqual(self.rg["prestashop_core"].status, "error")
        self.assertIn("8.2.1", " ".join(f.title for f in self.rg["prestashop_core"].findings))

    def test_no_secrets_in_any_result(self):
        for rr in (self.rb, self.rg):
            for r in rr.values():
                b = k.blob(r)
                for s in ("GEHEIM-DB-PASSWORT", "GEHEIM-SECRET", "GEHEIM-WS-KEY", "c" * 30):
                    self.assertNotIn(s, b)

    def test_exposed_needs_url(self):
        self.assertEqual(self.rg["prestashop_exposed"].status, "skipped")

    def test_online_core_files_and_advisory(self):
        os.environ["CLAUDIA_TEST_DB"] = self.bad["db"]
        files = {"classes/Teil%d.php" % i: hashlib.sha256(("<?php\n// classes %d\n" % i).encode()).hexdigest() for i in range(60)}
        files["classes/Fehlt.php"] = "0" * 64
        fake_ref = lambda v: {"files": dict(files), "package": "x.zip", "sha256": "x", "verified": False}   # noqa: E731

        def fake(url, ua, *a, **kw):
            f = webmod.Fetched()
            f.url = url
            f.status = 200
            f.body = adv_json() if "security-advisories" in url else json.dumps({"packages": {"prestashop/prestashop": [{"version": "8.2.1"}, {"version": "8.2.5"}]}})
            return f
        os.environ.pop("CLAUDIA_OFFLINE", None)
        try:
            with mock.patch.object(webmod, "fetch", fake), mock.patch.object(prestashopref, "reference", fake_ref):
                r = run(self.bad, ["prestashop_core"])[0]
        finally:
            os.environ["CLAUDIA_OFFLINE"] = "1"
        t = k.tt(r)
        self.assertIn(("crit", "Für PrestaShop 8.2.1 sind 1 Sicherheitsmeldung(en) bekannt"), t)
        self.assertTrue(any(s == "crit" and "unbekannte PHP-Datei" in x for s, x in t), t)

    def test_online_exposed_with_fake_web(self):
        def fake(url, ua, *a, **kw):
            f = webmod.Fetched()
            f.url = url
            f.status = 200 if url.endswith("/app/config/parameters.php") else 403
            f.body = "<?php return array('database_password' => 'x');" if f.status == 200 else ""
            return f
        with mock.patch.object(webmod, "fetch", fake):
            r = run(self.bad, ["prestashop_exposed"], "https://www.testseite.example")[0]
        self.assertEqual(r.findings[0].sev, "crit")


class Detection(unittest.TestCase):
    def test_probe_detects_prestashop(self):
        from claudia import probe
        w = pf.make_prestashop_world(tempfile.mkdtemp(), False)
        info = probe.probe(LocalRunner(w["home"], extra_path=w["bin"]), w["site_rel"])
        self.assertEqual(info["cms"], "prestashop")
        self.assertEqual(info["prestashop"], "8.2.1")
        self.assertTrue(info["prestashop_config"])


if __name__ == "__main__":
    unittest.main()
