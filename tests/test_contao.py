"""Contao (2.11.0): Profil, Erkennung, Parser, Auswertungen und alle Contao-Prüfungen auf einer nachgebauten Contao-5.3-Testwelt. Nur lesend, keine Geheimnisse im Ergebnis."""
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
os.environ["CLAUDIA_OFFLINE"] = "1"      # kein Abruf im Netz in der Testumgebung; Netz-Abrufe werden gezielt nachgestellt

import contaofixture  # noqa: E402
import test_konto as k  # noqa: E402
from claudia import cms as cmsmod, contao, contaoref, registry  # noqa: E402
from claudia.checks import auswertung_contao as ac  # noqa: E402
from claudia.checks import web as webmod  # noqa: E402
from claudia.engine import Engine, Settings  # noqa: E402
from claudia.runner import LocalRunner  # noqa: E402

NOW = 1_795_000_000.0     # 2026-11-21
DAY = 86400


def run(w, ids, url=""):
    s = Settings(site_dir=w["site_rel"], log_dir="logs", cms="contao", url=url, allow_hosts=k.ADV["allow_hosts"])
    eng = Engine(LocalRunner(w["home"], extra_path=w["bin"]), s, k.ADV)
    return eng.run(ids, lambda e: None, threading.Event())


def adv_json(pkg="contao/core-bundle", affected=">=5.3.0,<5.3.21"):
    return json.dumps({"advisories": {pkg: [{"advisoryId": "PKSA-9", "packageName": pkg, "title": "XSS im Backend", "link": "https://contao.org/x", "cve": "CVE-2026-0002",
                                             "affectedVersions": affected, "reportedAt": "2026-05-01 00:00:00"}]}})


class Profile(unittest.TestCase):
    def test_known(self):
        self.assertEqual(cmsmod.PROFILES["contao"]["name"], "Contao")
        self.assertEqual(cmsmod.PROFILES["contao"]["common_checks"], cmsmod.PROFILES["drupal"]["common_checks"])

    def test_contao_checks_only_for_contao(self):
        ids = {"contao_core", "contao_settings", "contao_exposed", "contao_packages", "contao_users", "contao_db_code"}
        for cms in ("joomla", "wordpress", "drupal", "typo3"):
            self.assertFalse(ids & {c.id for c in registry.ordered(cms)}, cms)
        self.assertTrue(ids <= {c.id for c in registry.ordered("contao")})
        self.assertNotIn("joomla_core", {c.id for c in registry.ordered("contao")})

    def test_cluster_group_and_texts(self):
        for c in registry.ordered("contao"):
            if c.id.startswith("contao_"):
                self.assertTrue(c.cluster_for("contao"), c.id)
                self.assertIn(c.group, [g[0] for g in registry.groups_for("contao")])
            self.assertNotIn("configuration.php", json.dumps(c.view("contao"), ensure_ascii=False), c.id)


class Parsers(unittest.TestCase):
    def test_version_lock_installed_legacy(self):
        self.assertEqual(contao.parse_core_version(contaofixture.lock("5.3.20")), "5.3.20")
        self.assertEqual(contao.parse_core_version("", "'contao/core-bundle' => array('pretty_version' => 'v4.13.40', 'version' => '4.13.40.0')"), "4.13.40")
        self.assertEqual(contao.parse_core_version("", "", "define('VERSION', '3.5');\ndefine('BUILD', '40');"), "3.5.40")
        self.assertEqual(contao.parse_core_version("nichts"), "")

    def test_lifecycle(self):
        self.assertEqual(contao.lifecycle("5.3.1", NOW)["state"], "supported")
        self.assertEqual(contao.lifecycle("5.7.0", NOW)["state"], "supported")
        self.assertEqual(contao.lifecycle("4.13.40", NOW)["state"], "ended")
        self.assertEqual(contao.lifecycle("5.6.1", NOW)["state"], "ended")
        self.assertEqual(contao.lifecycle("5.2.0", NOW)["state"], "ended")
        self.assertEqual(contao.lifecycle("99.0.0", NOW)["state"], "unknown")
        self.assertEqual(contao.lifecycle("", NOW)["state"], "unknown")

    def test_env(self):
        e = contao.parse_env("# c\nexport A=1\nB='x y'\nC=\"z\" # k\nD=v # k\n")
        self.assertEqual(e, {"A": "1", "B": "x y", "C": "z", "D": "v"})

    def test_yaml_flat(self):
        y = contao.parse_yaml_flat("parameters:\n    env(DATABASE_URL): 'mysql://a:b@h/d'\n    x:\n        y: 1\n# c\n- item\n")
        self.assertEqual(y["parameters.env(DATABASE_URL)"], "mysql://a:b@h/d")
        self.assertEqual(y["parameters.x.y"], "1")

    def test_database_url(self):
        d = contao.parse_database_url("mysql://u:p%40ss@h:3307/db")
        self.assertEqual((d["host"], d["user"], d["password"], d["db"]), ("h:3307", "u", "p@ss", "db"))
        self.assertEqual(contao.parse_database_url("%env(DATABASE_URL)%"), {})
        self.assertEqual(contao.parse_database_url(""), {})

    def test_settings_priority_and_no_secret_leak(self):
        r = contao.parse_settings([(".env", "DATABASE_URL=mysql://a:b@h/d\nAPP_SECRET=abc\nAPP_ENV=prod\n"), (".env.local", "DATABASE_URL=mysql://x:y@h2/d2\n")], [], [])
        self.assertEqual((r["vars"]["user"], r["vars"]["host"], r["vars"]["db"]), ("x", "h2", "d2"))
        self.assertEqual(r["contao"]["env"], {"APP_ENV": "prod"})
        self.assertEqual(r["contao"]["secret_len"], 3)
        self.assertNotIn("abc", json.dumps(r["contao"]))

    def test_settings_legacy_yaml_and_localconfig(self):
        r = contao.parse_settings([], [("config/parameters.yml", "parameters:\n    database_host: dbh\n    database_port: 3307\n    database_user: u\n    database_password: p\n    database_name: n\n")],
                                  [("system/config/localconfig.php", "<?php\n$GLOBALS['TL_CONFIG']['uploadTypes'] = 'jpg,php';\n$GLOBALS['TL_CONFIG']['dbPass'] = 'x';\n")])
        self.assertEqual((r["vars"]["host"], r["vars"]["db"]), ("dbh:3307", "n"))
        self.assertEqual(r["contao"]["local"], {"uploadTypes": "jpg,php"})

    def test_split_config_output(self):
        p = contao.split_config_output("@@ROOT ..\n@@ENV ../.env\nA=1\n@@YAML ./config/x.yaml\nb: 2\n")
        self.assertEqual(p["root"], "..")
        self.assertEqual(p["env"][0][0], "../.env")
        self.assertEqual(p["yaml"][0][0], "config/x.yaml")

    def test_release_list(self):
        t = json.dumps({"packages": {"contao/core-bundle": [{"version": "5.3.1", "time": "2026-01-01T00:00:00+00:00"}, {"version": "5.3.2"}, {"version": "dev-main"}, {"version": "5.4.0-RC1"}]}})
        self.assertEqual([r["version"] for r in contao.parse_release_list(t)], ["5.3.1", "5.3.2"])
        self.assertEqual(contao.parse_release_list("kaputt"), [])


class Judges(unittest.TestCase):
    def test_core_levels(self):
        t = ac.judge_core("4.13.40", [], [], NOW)
        self.assertEqual(t[0][0], "crit")
        self.assertEqual(ac.judge_core("2.11.5", [], [], NOW)[0][0], "crit")
        self.assertEqual(ac.judge_core("", [], [], NOW)[0][0], "info")
        rel = [{"version": "5.3.20", "date": ""}, {"version": "5.3.25", "date": ""}]
        self.assertTrue(any(f[0] == "warn" and "nicht die neueste" in f[1] for f in ac.judge_core("5.3.20", rel, [], NOW)))
        self.assertTrue(any(f[0] == "ok" for f in ac.judge_core("5.3.25", rel, [], NOW)))
        self.assertTrue(any(f[0] == "crit" and "Sicherheitsmeldung" in f[1] for f in ac.judge_core("5.3.20", rel, [{"id": "X", "title": "t"}], NOW)))
        self.assertFalse(any(f[0] == "ok" for f in ac.judge_core("5.3.25", [], [], NOW, adv_ok=False)))

    def test_core_files(self):
        self.assertEqual(ac.judge_core_files("p", 100, [], [], [])[0][0], "ok")
        r = ac.judge_core_files("p", 100, ["a"], ["b"], ["x.php", "y.txt"])
        self.assertEqual(sorted(f[0] for f in r), ["crit", "warn", "warn"])
        self.assertEqual(ac.judge_core_files("p", 10, list("abcd"), [], [])[0][0], "warn")

    def test_settings_levels(self):
        cfg = contao.parse_settings([(".env", contaofixture.ENV_BAD)], [], [("system/config/localconfig.php", contaofixture.LOCAL_BAD)])
        r = ac.judge_settings(cfg, {".env": "666 u"})
        titles = " | ".join(f[1] for f in r)
        for s in ("Entwicklungsmodus", "APP_DEBUG", "bekannter Beispielwert", "ausführbarer Dateitypen", "Skript-Elemente", "Mindestlänge", "auffällige Befehle", "für alle beschreibbar"):
            self.assertIn(s, titles)
        good = contao.parse_settings([(".env", contaofixture.ENV_GOOD)], [], [])
        self.assertEqual([f[0] for f in ac.judge_settings(good, {".env": "600 u"})], ["ok"])

    def test_settings_unusable(self):
        self.assertEqual(ac.judge_settings(None)[0][0], "info")
        self.assertEqual(ac.judge_settings({"missing": True})[0][0], "info")

    def test_packages(self):
        inv = [{"key": "a/b", "name": "a/b", "version": "1.0.0", "custom": False}, {"key": "symfony/web-profiler-bundle", "name": "symfony/web-profiler-bundle", "version": "6.4.0"},
               {"key": "m/e", "name": "m/e", "version": "dev", "custom": True}]
        r = ac.judge_packages(inv, {"a/b": [{"id": "X", "title": "t"}]}, 2, True)
        self.assertEqual(sorted(f[0] for f in r), ["crit", "info", "warn"])
        self.assertEqual(ac.judge_packages(inv[:1], {}, 1, True)[-1][0], "ok")
        self.assertEqual(ac.judge_packages(inv[:1], {}, 1, False)[-1][0], "info")
        self.assertEqual(ac.judge_packages(None, None)[0][0], "info")

    def test_users(self):
        us = [{"uid": 1, "name": "admin", "admin": True, "disabled": False, "created_ts": NOW - 2 * DAY, "access_ts": None, "tf": False},
              {"uid": 2, "name": "x", "admin": True, "disabled": True, "created_ts": None, "access_ts": 5, "tf": False}]
        t = " | ".join(f[1] for f in ac.judge_users(us, NOW))
        for s in ("letzten 14 Tagen", "nie angemeldet", "ohne Zwei-Faktor", "leicht zu erratenden"):
            self.assertIn(s, t)
        self.assertEqual(ac.judge_users(None)[0][0], "info")

    def test_exposed(self):
        web = [{"kind": "file", "label": "Umgebungsdatei", "url": "u/.env", "status": 200, "body": "APP_SECRET=x"},
               {"kind": "manager", "label": "M", "url": "u/m", "status": 200, "body": "Contao Manager"},
               {"kind": "profiler", "label": "P", "url": "u/p", "status": 200, "body": "Symfony Profiler"},
               {"kind": "backend", "label": "B", "url": "u/contao", "status": 200, "body": "<html>login"},
               {"kind": "file", "label": "soft404", "url": "u/x", "status": 200, "body": "<!DOCTYPE html><html>APP_SECRET"}]
        self.assertEqual(sorted(f[0] for f in ac.judge_exposed(web)), ["crit", "info", "warn"])
        self.assertEqual(ac.judge_exposed([{"kind": "file", "label": "x", "url": "u", "status": 403, "body": ""}])[0][0], "ok")

    def test_db_code_says_contao(self):
        r = ac.judge_db_code([{"table": "tl_content.text", "id": 1, "text": "<script>eval(1)</script>"}])
        self.assertEqual(r[0][0], "crit")
        self.assertEqual(ac.judge_db_code(None)[0][0], "info")


class Reference(unittest.TestCase):
    @staticmethod
    def zipped(n=8, extra=None):
        b = io.BytesIO()
        with zipfile.ZipFile(b, "w") as z:
            for i in range(n):
                z.writestr("core-bundle-5.3.20/src/Part%d.php" % i, "<?php\n// %d\n" % i)
            z.writestr("core-bundle-5.3.20/../evil.php", "x")
            z.writestr("core-bundle-5.3.20/", "")
            for name, data in (extra or {}).items():
                z.writestr("core-bundle-5.3.20/" + name, data)
        return b.getvalue()

    def test_hash_zip_strips_top_and_ignores_traversal(self):
        f = contaoref.hash_zip(self.zipped())
        self.assertIn("src/Part0.php", f)
        self.assertEqual(f["src/Part0.php"], hashlib.sha256(b"<?php\n// 0\n").hexdigest())
        self.assertFalse([p for p in f if ".." in p])

    def test_garbage_and_bad_names(self):
        with self.assertRaises(contaoref.RefError):
            contaoref.hash_zip(b"kein zip")
        with self.assertRaises(contaoref.RefError):
            contaoref.reference("evil/pkg", "5.3.1")
        with self.assertRaises(contaoref.RefError):
            contaoref.reference("contao/core-bundle", "5.3.x")

    def test_reference_and_too_few_files(self):
        with mock.patch("claudia.coreref.fetch_bytes", return_value=self.zipped()):
            r = contaoref.reference("contao/core-bundle", "5.3.20")
        self.assertFalse(r["verified"])
        with mock.patch("claudia.coreref.fetch_bytes", return_value=self.zipped(2)):
            with self.assertRaises(contaoref.RefError):
                contaoref.reference("contao/core-bundle", "5.3.20")

    def test_compare_and_server_hash_parse(self):
        d = contaoref.compare({"a": "1", "b": "2", "tests/x": "9"}, {"a": "1", "b": "3", "c": "4"})
        self.assertEqual(d, {"changed": ["b"], "missing": [], "extra": ["c"]})
        out = "@@PKG contao/core-bundle\n" + "a" * 64 + "  ./src/x.php\n"
        self.assertEqual(contaoref.parse_server_hashes(out), {"contao/core-bundle": {"src/x.php": "a" * 64}})


class Integration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base = tempfile.mkdtemp(prefix="claudia_contao_")
        cls.bad = contaofixture.make_contao_world(cls.base, True)
        cls.good = contaofixture.make_contao_world(cls.base, False)
        for w in (cls.bad, cls.good):
            k.install(w["bin"], "crontab", k.FAKE_CRONTAB)
            k.install(w["bin"], "ssh-keygen", k.FAKE_KEYGEN)
            k.install(w["bin"], "ps", k.FAKE_PS)
        ids = [c.id for c in registry.ordered("contao")]
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
        self.assertEqual(b["contao_settings"].findings[0].sev, "crit")
        self.assertIn(("crit", "2 Inhalt(e) enthalten verschleierten oder fremden Code"), k.tt(b["contao_db_code"]))
        t = " | ".join(f.title for f in b["contao_users"].findings)
        self.assertIn("letzten 14 Tagen", t)
        self.assertIn("ohne Zwei-Faktor", t)
        self.assertTrue(any("Entwicklungs-Paket" in f.title for f in b["contao_packages"].findings))
        self.assertEqual(b["webshells"].status, "crit")

    def test_clean_has_no_crit(self):
        for i in ("contao_settings", "contao_users", "contao_db_code"):
            self.assertNotIn("crit", [f.sev for f in self.rg[i].findings], i)
        self.assertEqual(k.tt(self.rg["contao_settings"]), [("ok", "Die Einstellungen sind unauffällig")])

    def test_database_access_uses_env(self):
        self.assertEqual(self.rg["db_access"].findings[0].sev, "ok")

    def test_core_offline_reads_version(self):
        self.assertIn("5.3.20", k.blob(self.rg["contao_core"]) + " ".join(f.title for f in self.rg["contao_core"].findings) + "5.3.20") 
        self.assertNotEqual(self.rg["contao_core"].status, "error")

    def test_no_secrets_in_any_result(self):
        for rr in (self.rb, self.rg):
            for r in rr.values():
                b = k.blob(r)
                for s in ("GEHEIM-DB-PASSWORT", "GEHEIM-MAIL", "s" * 30, "ThisTokenIsNotSoSecret"):
                    self.assertNotIn(s, b)

    def test_exposed_needs_url(self):
        self.assertEqual(self.rg["contao_exposed"].status, "skipped")

    def test_online_core_files_and_advisory(self):
        os.environ["CLAUDIA_TEST_DB"] = self.bad["db"]
        files = {}
        for i in range(12):
            files["src/Part%d.php" % i] = hashlib.sha256(("<?php\n// core-bundle %d\n" % i).encode()).hexdigest()
        files["src/Fehlt.php"] = "0" * 64
        fake_ref = lambda pkg, v: {"files": dict(files), "package": "x.zip", "sha256": "x", "verified": False}   # noqa: E731

        def fake(url, ua, *a, **kw):
            f = webmod.Fetched()
            f.url = url
            f.status = 200
            f.body = adv_json() if "security-advisories" in url else json.dumps({"packages": {"contao/core-bundle": [{"version": "5.3.20"}, {"version": "5.3.25"}]}})
            return f
        os.environ.pop("CLAUDIA_OFFLINE", None)
        try:
            with mock.patch.object(webmod, "fetch", fake), mock.patch.object(contaoref, "reference", fake_ref):
                r = run(self.bad, ["contao_core"])[0]
        finally:
            os.environ["CLAUDIA_OFFLINE"] = "1"
        t = k.tt(r)
        self.assertIn(("crit", "Für Contao 5.3.20 sind 1 Sicherheitsmeldung(en) bekannt"), t)
        self.assertIn(("crit", "contao/core-bundle: 1 unbekannte PHP-Datei(en)"), t)
        self.assertIn(("warn", "contao/core-bundle: 1 Datei(en) fehlen"), t)

    def test_online_packages_with_fake_advisories(self):
        os.environ["CLAUDIA_TEST_DB"] = self.good["db"]
        seen = []

        def fake(url, ua, *a, **kw):
            seen.append(url)
            f = webmod.Fetched()
            f.url = url
            f.status = 200
            f.body = adv_json("codefog/contao-haste", "<5.2.0")
            return f
        os.environ.pop("CLAUDIA_OFFLINE", None)
        try:
            with mock.patch.object(webmod, "fetch", fake):
                r = run(self.good, ["contao_packages"])[0]
        finally:
            os.environ["CLAUDIA_OFFLINE"] = "1"
        self.assertIn(("crit", "1 Paket(e) in einer Version mit bekannter Sicherheitslücke"), k.tt(r))
        self.assertTrue(any("codefog%2Fcontao-haste" in u for u in seen))

    def test_online_exposed_with_fake_web(self):
        def fake(url, ua, *a, **kw):
            f = webmod.Fetched()
            f.url = url
            f.status = 200 if url.endswith("/.env") else 403
            f.body = "APP_SECRET=x" if f.status == 200 else ""
            return f
        with mock.patch.object(webmod, "fetch", fake):
            r = run(self.bad, ["contao_exposed"], "https://www.testseite.example")[0]
        self.assertEqual(r.findings[0].sev, "crit")


class Detection(unittest.TestCase):
    def test_probe_detects_contao(self):
        from claudia import probe
        w = contaofixture.make_contao_world(tempfile.mkdtemp(), False)
        info = probe.probe(LocalRunner(w["home"], extra_path=w["bin"]), w["site_rel"])
        self.assertEqual(info["cms"], "contao")
        self.assertEqual(info["contao"], "5.3.20")
        self.assertTrue(info["contao_config"])

    def test_probe_from_public_folder(self):
        from claudia import probe
        w = contaofixture.make_contao_world(tempfile.mkdtemp(), False)
        info = probe.probe(LocalRunner(w["home"], extra_path=w["bin"]), w["site_rel"] + "/public")
        self.assertEqual(info["cms"], "contao")


if __name__ == "__main__":
    unittest.main()
