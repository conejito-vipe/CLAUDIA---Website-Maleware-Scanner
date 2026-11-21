"""Shopware (2.13.0): Profil, Erkennung, Parser, Auswertungen und alle Shopware-Prüfungen auf einer nachgebauten Shopware-6.6-Testwelt. Nur lesend, keine Geheimnisse im Ergebnis."""
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

import shopwarefixture as sf  # noqa: E402
import test_konto as k  # noqa: E402
from claudia import cms as cmsmod, registry, shopware, shopwareref, typo3  # noqa: E402
from claudia.checks import auswertung_shopware as ash  # noqa: E402
from claudia.checks import shopware_checks as sc  # noqa: E402
from claudia.checks import web as webmod  # noqa: E402
from claudia.engine import Engine, Settings  # noqa: E402
from claudia.runner import LocalRunner  # noqa: E402

NOW = 1_795_000_000.0
DAY = 86400
IDS = {"shopware_core", "shopware_settings", "shopware_exposed", "shopware_packages", "shopware_users", "shopware_shop", "shopware_db_code"}


def run(w, ids, url=""):
    s = Settings(site_dir=w["site_rel"], log_dir="logs", cms="shopware", url=url, allow_hosts=k.ADV["allow_hosts"])
    eng = Engine(LocalRunner(w["home"], extra_path=w["bin"]), s, k.ADV)
    return eng.run(ids, lambda e: None, threading.Event())


def adv_json(pkg="shopware/core", affected=">=6.6.0.0,<6.6.10.1"):
    return json.dumps({"advisories": {pkg: [{"advisoryId": "PKSA-9", "packageName": pkg, "title": "SQL-Einschleusung", "link": "https://x.example", "cve": "CVE-2026-0009",
                                             "affectedVersions": affected, "reportedAt": "2026-05-01 00:00:00"}]}})


class Profile(unittest.TestCase):
    def test_known(self):
        self.assertEqual(cmsmod.PROFILES["shopware"]["name"], "Shopware")
        self.assertEqual(cmsmod.PROFILES["shopware"]["common_checks"], cmsmod.PROFILES["drupal"]["common_checks"])

    def test_checks_only_for_shopware(self):
        for cms in ("joomla", "wordpress", "drupal", "typo3", "contao", "prestashop"):
            self.assertFalse(IDS & {c.id for c in registry.ordered(cms)}, cms)
        self.assertTrue(IDS <= {c.id for c in registry.ordered("shopware")})
        self.assertNotIn("joomla_core", {c.id for c in registry.ordered("shopware")})

    def test_cluster_group_and_texts(self):
        for c in registry.ordered("shopware"):
            if c.id.startswith("shopware_"):
                self.assertTrue(c.cluster_for("shopware"), c.id)
                self.assertIn(c.group, [g[0] for g in registry.groups_for("shopware")])
            self.assertNotIn("configuration.php", json.dumps(c.view("shopware"), ensure_ascii=False), c.id)


class Versions(unittest.TestCase):
    def test_four_part_versions_in_advisories(self):
        self.assertTrue(typo3.affected("6.6.10.0", ">=6.6.0.0,<6.6.10.1"))
        self.assertFalse(typo3.affected("6.6.10.1", ">=6.6.0.0,<6.6.10.1"))
        self.assertTrue(typo3.affected("1.7.8.11", ">=1.7.0.0,<1.7.8.12"))
        self.assertTrue(typo3.affected("12.4.8", ">=12.0.0,<12.4.9"))
        self.assertLess(typo3.version_key("6.6.9.9"), typo3.version_key("6.6.10.0"))
        self.assertLess(typo3.version_key("6.7.0.0-rc1"), typo3.version_key("6.7.0.0"))

    def test_lifecycle(self):
        self.assertEqual(shopware.lifecycle("6.7.1.0", NOW)["state"], "supported")
        self.assertEqual(shopware.lifecycle("6.6.10.0", NOW)["state"], "security")
        self.assertEqual(shopware.lifecycle("6.5.8.19", NOW)["state"], "security")
        self.assertEqual(shopware.lifecycle("6.4.20.2", NOW)["state"], "ended")
        self.assertEqual(shopware.lifecycle("5.7.20", NOW)["state"], "ended")
        self.assertEqual(shopware.lifecycle("6.9.0.0", NOW)["state"], "unknown")
        self.assertEqual(shopware.lifecycle("", NOW)["state"], "unknown")
        self.assertEqual(shopware.lifecycle("6.5.8.19", 1_900_000_000.0)["state"], "ended")


class Parsers(unittest.TestCase):
    def test_core_version(self):
        self.assertEqual(shopware.parse_core_version(sf.lock("6.6.10.0")), "6.6.10.0")
        self.assertEqual(shopware.parse_core_version("", "'shopware/core' => array('pretty_version' => 'v6.5.8.1'"), "6.5.8.1")
        self.assertEqual(shopware.parse_core_version("kaputt"), "")

    def test_settings_and_no_secret_leak(self):
        r = shopware.parse_settings([(".env", sf.ENV_GOOD)])
        v = r["vars"]
        self.assertEqual((v["host"], v["user"], v["db"]), ("127.0.0.1:3306", "sw_user", "sw_db"))
        self.assertEqual(r["shopware"]["secret_len"], 64)
        self.assertEqual(r["shopware"]["env"]["APP_ENV"], "prod")
        self.assertNotIn("GEHEIM", json.dumps(r["shopware"]))
        self.assertNotIn("DATABASE_URL", json.dumps(r["shopware"]))

    def test_split_config_output(self):
        p = shopware.split_config_output('@@ROOT .\n@@ENV ./.env\nAPP_ENV=prod\n@@JWT ./config/jwt/private.pem\n')
        self.assertEqual([x[0] for x in p["env"]], [".env"])
        self.assertEqual(p["jwt"], ["config/jwt/private.pem"])
        self.assertNotIn("@@JWT", p["env"][0][1])

    def test_extensions(self):
        e = sc.parse_extensions('@@M plugin Fremd\n{"name": "acme/fremd", "version": "1.0.0"}\n@@M plugin Ohne\n\n', '@@M app Meine\n<version>2.0.1</version>\n')
        self.assertEqual([(x["kind"], x["name"], x["version"], x["pkg"]) for x in e], [("plugin", "Fremd", "1.0.0", "acme/fremd"), ("plugin", "Ohne", "", ""), ("app", "Meine", "2.0.1", "")])


class Judges(unittest.TestCase):
    def test_core_levels(self):
        self.assertEqual(ash.judge_core("5.7.20", [], [], NOW)[0][0], "crit")
        self.assertEqual(ash.judge_core("6.4.20.2", [], [], NOW)[0][0], "crit")
        self.assertEqual(ash.judge_core("6.6.10.0", [], [], NOW)[0][0], "warn")
        self.assertEqual(ash.judge_core("", [], [])[0][0], "info")
        self.assertTrue(any(f[0] == "crit" and "Sicherheitsmeldung" in f[1] for f in ash.judge_core("6.7.1.0", [], [{"id": "X", "title": "t"}], NOW)))
        self.assertTrue(any(f[0] == "ok" for f in ash.judge_core("6.7.1.0", [{"version": "6.7.1.0", "date": ""}], [], NOW)))
        self.assertTrue(any("vor 6.5.8" in f[1] for f in ash.judge_core("6.5.7.0", [], [], NOW)))
        self.assertFalse(any(f[0] == "ok" for f in ash.judge_core("6.7.1.0", [], [], NOW, adv_ok=False)))

    def test_settings_levels(self):
        cfg = shopware.parse_settings([(".env", sf.ENV_BAD)])
        t = " | ".join(f[1] for f in ash.judge_settings(cfg, {".env": "666 u", "config/jwt/private.pem": "644 u"}))
        for s in ("Entwicklungsmodus", "APP_DEBUG", "APP_SECRET ist kurz", "APP_URL", "für alle beschreibbar", "private.pem ist für alle lesbar"):
            self.assertIn(s, t)
        good = shopware.parse_settings([(".env", sf.ENV_GOOD)])
        self.assertEqual([f[0] for f in ash.judge_settings(good, {".env": "600 u", "config/jwt/private.pem": "600 u"})], ["ok"])
        self.assertEqual(ash.judge_settings(None)[0][0], "info")
        self.assertEqual(ash.judge_settings({"missing": True})[0][0], "info")

    def test_packages(self):
        inv = [{"key": "a", "name": "a", "version": "1.0.0", "pkg": "x/a", "custom": False, "ext": True}, {"key": "phpunit/phpunit", "name": "phpunit/phpunit", "version": "9", "pkg": "", "custom": False}]
        r = ash.judge_packages(inv, {"a": [{"id": "X", "title": "t"}]}, 1, True)
        self.assertEqual(sorted(f[0] for f in r), ["crit", "info", "warn"])
        self.assertEqual(ash.judge_packages(None, None)[0][0], "info")

    def test_users(self):
        us = [{"uid": "1", "name": "admin", "admin": True, "active": True, "created_ts": NOW - 2 * DAY}, {"uid": "2", "name": "x", "admin": False, "active": True, "created_ts": None}]
        t = " | ".join(f[1] for f in ash.judge_users(us, NOW))
        for s in ("letzten 14 Tagen", "leicht zu erratenden"):
            self.assertIn(s, t)
        self.assertEqual(ash.judge_users(None)[0][0], "info")

    def test_shop(self):
        r = ash.judge_shop([{"url": "http://a.example"}], [{"label": "K", "admin": True, "created_ts": None}], [{"name": "h", "event": "e", "url": "http://f.example/x", "active": True}])
        self.assertEqual(sorted(f[0] for f in r), ["crit", "info", "warn", "warn"])
        self.assertEqual(ash.judge_shop([{"url": "https://a.example"}], [], [])[0][0], "ok")
        self.assertEqual(ash.judge_shop(None, None, None)[0][0], "info")

    def test_shop_secrets_not_in_output(self):
        r = ash.judge_shop([{"url": "https://a.example"}], [{"label": "K", "admin": True, "access_key": "GEHEIM-ACCESS-KEY"}], [])
        self.assertNotIn("GEHEIM", json.dumps(r))

    def test_exposed(self):
        web = [{"kind": "file", "label": "Umgebungsdatei", "url": "u/.env", "status": 200, "body": "APP_SECRET=x\nDATABASE_URL=y"},
               {"kind": "installer", "label": "Web-Installer", "url": "u/i", "status": 200, "body": "Shopware Web Installer"},
               {"kind": "api", "label": "API", "url": "u/a", "status": 200, "body": '{"openapi": "3.0.0"}'},
               {"kind": "dir", "label": "var", "url": "u/v", "status": 200, "body": "<title>Index of /var"},
               {"kind": "admin", "label": "Verwaltung", "url": "u/admin", "status": 200, "body": "<html>"},
               {"kind": "file", "label": "soft404", "url": "u/x", "status": 200, "body": "<!DOCTYPE html><html>APP_SECRET"}]
        r = ash.judge_exposed(web)
        self.assertEqual(sorted(f[0] for f in r), ["crit", "info", "warn"])
        self.assertEqual(ash.judge_exposed([{"kind": "file", "label": "x", "url": "u", "status": 403, "body": ""}])[0][0], "ok")

    def test_db_code(self):
        self.assertEqual(ash.judge_db_code([{"table": "snippet.value", "id": 1, "text": "<script>eval(1)</script>"}])[0][0], "crit")
        self.assertEqual(ash.judge_db_code(None)[0][0], "info")


class Reference(unittest.TestCase):
    def test_version_pattern_and_package(self):
        self.assertTrue(shopwareref.VERSION_RE.match("6.6.10.0"))
        self.assertTrue(shopwareref.VERSION_RE.match("6.6.10"))
        self.assertFalse(shopwareref.VERSION_RE.match("6.7.0.0-rc1"))
        self.assertTrue(shopwareref.PACKAGE_RE.match("shopware/core"))
        self.assertFalse(shopwareref.PACKAGE_RE.match("shopware/../x"))
        with self.assertRaises(shopwareref.RefError):
            shopwareref.reference("symfony/console", "6.4.1")

    def test_server_hash_sh_only_known_packages(self):
        sh = shopwareref.server_hash_sh(["shopware/core", "evil/x;rm"])
        self.assertIn("for p in core;", sh)
        self.assertNotIn("evil", sh)

    def test_reference_from_zip(self):
        b = io.BytesIO()
        with zipfile.ZipFile(b, "w") as z:
            for i in range(10):
                z.writestr("core-6.6.10.0/src/T%d.php" % i, "<?php //%d" % i)
        with mock.patch("claudia.coreref.fetch_bytes", lambda *a, **kw: b.getvalue()):
            ref = shopwareref.reference("shopware/core", "6.6.10.0")
        self.assertEqual(len(ref["files"]), 10)
        self.assertFalse(ref["verified"])


class Integration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base = tempfile.mkdtemp(prefix="claudia_sw_")
        cls.bad = sf.make_shopware_world(cls.base, True)
        cls.good = sf.make_shopware_world(cls.base, False)
        for w in (cls.bad, cls.good):
            k.install(w["bin"], "crontab", k.FAKE_CRONTAB)
            k.install(w["bin"], "ssh-keygen", k.FAKE_KEYGEN)
            k.install(w["bin"], "ps", k.FAKE_PS)
        ids = [c.id for c in registry.ordered("shopware")]
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
        t = " | ".join(f.title for f in b["shopware_settings"].findings)
        for s in ("Entwicklungsmodus", "APP_DEBUG", "APP_URL"):
            self.assertIn(s, t)
        self.assertIn(("crit", "2 Inhalt(e) enthalten verschleierten oder fremden Code"), k.tt(b["shopware_db_code"]))
        self.assertIn("letzten 14 Tagen", " | ".join(f.title for f in b["shopware_users"].findings))
        t = " | ".join(f.title for f in b["shopware_shop"].findings)
        for s in ("ohne HTTPS", "Administratorrechten", "Webhook"):
            self.assertIn(s, t)
        self.assertEqual(b["webshells"].status, "crit")

    def test_clean_has_no_crit(self):
        for i in ("shopware_settings", "shopware_users", "shopware_shop", "shopware_db_code", "shopware_packages"):
            self.assertNotIn("crit", [f.sev for f in self.rg[i].findings], i)
        self.assertEqual(k.tt(self.rg["shopware_settings"]), [("ok", "Die Einstellungen sind unauffällig")])
        self.assertEqual(k.tt(self.rg["shopware_shop"])[0][0], "ok")

    def test_packages_inventory(self):
        t = " ".join(f.title + " " + " ".join(f.items or []) for f in self.rg["shopware_packages"].findings)
        self.assertIn("Shopware-Erweiterung", t)
        self.assertIn("Plugin FremdPlugin", t)
        self.assertIn("App MeineApp", t)

    def test_database_access_uses_env(self):
        self.assertEqual(self.rg["db_access"].findings[0].sev, "ok")

    def test_core_offline_reads_version(self):
        self.assertNotEqual(self.rg["shopware_core"].status, "error")
        self.assertIn("6.6", " ".join(f.title for f in self.rg["shopware_core"].findings))

    def test_no_secrets_in_any_result(self):
        for rr in (self.rb, self.rg):
            for r in rr.values():
                b = k.blob(r)
                for s in ("GEHEIM-DB-PASSWORT", "GEHEIM-JWT", "GEHEIM-ACCESS-KEY", "GEHEIM-SECRET-KEY", "s" * 30):
                    self.assertNotIn(s, b)

    def test_exposed_needs_url(self):
        self.assertEqual(self.rg["shopware_exposed"].status, "skipped")

    def test_online_core_files_and_advisory(self):
        os.environ["CLAUDIA_TEST_DB"] = self.bad["db"]
        import hashlib
        base = {"src/Teil%d.php" % i: hashlib.sha256(("<?php\n// core %d\n" % i).encode()).hexdigest() for i in range(40)}
        base["src/Fehlt.php"] = "0" * 64
        fake_ref = lambda pkg, v: {"files": dict(base), "package": "x.zip", "sha256": "x", "verified": False}   # noqa: E731

        def fake(url, ua, *a, **kw):
            f = webmod.Fetched()
            f.url = url
            f.status = 200
            f.body = adv_json() if "security-advisories" in url else json.dumps({"packages": {"shopware/core": [{"version": "v6.6.10.0"}, {"version": "v6.6.10.5"}]}})
            return f
        os.environ.pop("CLAUDIA_OFFLINE", None)
        try:
            with mock.patch.object(webmod, "fetch", fake), mock.patch.object(shopwareref, "reference", fake_ref):
                r = run(self.bad, ["shopware_core"])[0]
        finally:
            os.environ["CLAUDIA_OFFLINE"] = "1"
        t = k.tt(r)
        self.assertIn(("crit", "Für Shopware 6.6.10.0 sind 1 Sicherheitsmeldung(en) bekannt"), t)
        self.assertTrue(any(s == "crit" and "unbekannte PHP-Datei" in x for s, x in t), t)

    def test_online_exposed_with_fake_web(self):
        def fake(url, ua, *a, **kw):
            f = webmod.Fetched()
            f.url = url
            f.status = 200 if url.endswith("/.env") else 403
            f.body = "APP_SECRET=x\nDATABASE_URL=mysql://u:p@h/d" if f.status == 200 else ""
            return f
        with mock.patch.object(webmod, "fetch", fake):
            r = run(self.bad, ["shopware_exposed"], "https://www.testseite.example")[0]
        self.assertEqual(r.findings[0].sev, "crit")


class Detection(unittest.TestCase):
    def test_probe_detects_shopware(self):
        from claudia import probe
        w = sf.make_shopware_world(tempfile.mkdtemp(), False)
        info = probe.probe(LocalRunner(w["home"], extra_path=w["bin"]), w["site_rel"])
        self.assertEqual(info["cms"], "shopware")
        self.assertEqual(info["shopware"], "6.6.10.0")
        self.assertTrue(info["shopware_config"])


if __name__ == "__main__":
    unittest.main()
