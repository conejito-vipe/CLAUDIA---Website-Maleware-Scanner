"""Bedrohungslage: NVD/CVE + VEL vor jedem Lauf laden, mit Version und Erweiterungen abgleichen, gezielt in Protokollen suchen."""
import json
import os
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

import fixture  # noqa: E402
from claudia import coreref, intel  # noqa: E402
from claudia.checks import threat  # noqa: E402
from claudia.engine import Engine, Settings  # noqa: E402
from claudia.registry import load_all  # noqa: E402
from claudia.runner import LocalRunner  # noqa: E402

ROOT = os.path.dirname(HERE)
ADV = json.load(open(os.path.join(ROOT, "claudia", "advisories.json"), encoding="utf-8"))
load_all()


def nvd_item(cid, text, score, cpes, pub="2026-10-20T10:00:00.000"):
    return {"cve": {"id": cid, "published": pub, "descriptions": [{"lang": "en", "value": text}],
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": score, "baseSeverity": "CRITICAL" if score >= 9 else "HIGH"}}]},
                    "configurations": [{"nodes": [{"cpeMatch": cpes}]}]}}


def cpe(product, vendor="x", **kw):
    d = {"vulnerable": True, "criteria": "cpe:2.3:a:%s:%s:*:*:*:*:*:*:*:*" % (vendor, product)}
    d.update(kw)
    return d


NVD = {"totalResults": 4, "vulnerabilities": [
    nvd_item("CVE-2026-1001", "Joomla core flaw allows remote code execution.", 9.8, [cpe("joomla\\!", "joomla", versionStartIncluding="6.0.0", versionEndExcluding="6.2.1")]),
    nvd_item("CVE-2026-1002", "Old Joomla bug.", 7.5, [cpe("joomla\\!", "joomla", versionStartIncluding="4.0.0", versionEndExcluding="4.4.9")]),
    nvd_item("CVE-2026-1003", "JCE Joomla Content Editor profile import allows file upload.", 9.9, [cpe("jce", "widgetfactory", versionEndExcluding="2.9.99.5")]),
    nvd_item("CVE-2026-1004", "SQL injection in the Convert Forms component for Joomla before 5.0.", 6.1, []),
]}
VEL = [{"title": "Demo", "cve_id": "", "install_data": "{}", "start_version": "", "vulnerable_version": "", "patch_version": "", "status": "1"}]


class Parse(unittest.TestCase):
    def test_compact_and_ranges(self):
        c = intel.compact_cve(NVD["vulnerabilities"][0])
        self.assertEqual((c["id"], c["score"], c["pub"]), ("CVE-2026-1001", 9.8, "2026-10-20"))
        cp = c["cpes"][0]
        self.assertEqual((cp["v"], cp["p"]), ("joomla", "joomla!"))
        self.assertTrue(intel.version_affected("6.2.0", cp))
        self.assertFalse(intel.version_affected("6.2.1", cp))          # Ende ausgeschlossen
        self.assertFalse(intel.version_affected("5.9.0", cp))
        self.assertFalse(intel.version_affected("", cp))
        self.assertTrue(intel.version_affected("1.0", {"ver": "*"}))
        self.assertIsNone(intel.compact_cve({"cve": {"id": "nonsense"}}))

    def test_hits(self):
        data = {"cves": [intel.compact_cve(v) for v in NVD["vulnerabilities"]]}
        core = intel.core_hits(data, "joomla", "6.2.0")
        self.assertEqual([c["id"] for c in core], ["CVE-2026-1001"])
        self.assertEqual(intel.core_hits(data, "joomla", "6.2.1"), [])
        e = intel.extension_hits(data, ["JCE"], "2.9.99.3")
        self.assertEqual([c["match"] for c in e["JCE"]], ["confirmed"])
        self.assertEqual(intel.extension_hits(data, ["JCE"], "2.9.99.7"), {})           # behobene Version: kein Treffer
        e = intel.extension_hits(data, ["Convert Forms"], "4.4.1")
        self.assertEqual(e["Convert Forms"][0]["match"], "name")
        self.assertEqual(intel.extension_hits(data, ["Convert Forms"], "5.2.7"), {})     # Text nennt "before 5.0", installiert ist 5.2.7: keine Meldung

    def test_fixed_by_text(self):
        self.assertTrue(intel.fixed_by_text("Flaw in X before 9.1.2 allows ...", "9.1.2"))
        self.assertFalse(intel.fixed_by_text("Flaw in X before 9.1.2 allows ...", "9.1.1"))
        self.assertTrue(intel.fixed_by_text("X through 8.4.1 is affected", "8.5"))
        self.assertFalse(intel.fixed_by_text("X through 8.4.1 is affected", "8.4.1"))
        self.assertFalse(intel.fixed_by_text("X is affected", "1.0"))                  # ohne Versionsangabe bleibt der Hinweis

    def test_addon_plugin_is_not_the_product(self):
        """ConvertForms-Plugin 'acymailing' (Gruppe convertforms) ist nicht AcyMailing: keine AcyMailing-Lücke melden."""
        from claudia.checks import threat
        data = {"cves": [intel.compact_cve(nvd_item("CVE-2026-94132", "RCE in AcyMailing Enterprise.", 9.5, [cpe("acymailing", "acyba", versionEndExcluding="10.6")]))]}
        ctx = mock.MagicMock(cms="joomla")
        with mock.patch("claudia.checks.ext.get_ext_fs", return_value={"manifests": [
                {"type": "plugin", "group": "convertforms", "element": "acymailing", "name": "PLG_CONVERTFORMS_ACYMAILING", "version": "1.0", "author": "Tassos Marinos"},
                {"type": "component", "group": "", "element": "com_acym", "name": "AcyMailing", "version": "9.0", "author": "Acyba"}]}):
            inv = threat.inventory(ctx)
        hits = threat.evaluate(data, "", inv, "joomla")["ext"]
        self.assertEqual([h["inv"]["label"] for h in hits], ["AcyMailing"])         # nur das echte Produkt


class Load(unittest.TestCase):
    def setUp(self):
        self.cache = tempfile.mkdtemp()
        from claudia.checks import online
        for p in (mock.patch.dict(os.environ, {"CLAUDIA_CACHE": self.cache}), mock.patch.object(online, "VEL_URLS", ["https://extensions.joomla.org/vel-feed"])):
            p.start()
            self.addCleanup(p.stop)

    def fake(self, urls):
        def f(url, max_bytes=5_000_000, timeout=30.0):
            urls.append(url)
            if "nvd.nist.gov" in url:
                return json.dumps(NVD).encode()
            if "vel-feed" in url:
                return json.dumps({"items": [{"title": "T", "install_data": "{}", "status": 1, "junk": 1}]}).encode()
            raise coreref.RefError("nein")
        return f

    def test_load_caches_and_reports(self):
        urls = []
        with mock.patch.object(coreref, "fetch_bytes", self.fake(urls)):
            d = intel.load("joomla")
            self.assertTrue(d["nvd_ok"] and d["vel_ok"])
            self.assertEqual(len(d["cves"]), 4)
            n = len(urls)
            self.assertIn("keywordSearch=joomla", urls[0])
            d2 = intel.load("joomla")
            self.assertTrue(d2["cached"])
            self.assertEqual(len(urls), n)                                               # zweiter Lauf: aus dem Zwischenspeicher
            d3 = intel.load("joomla", now=time.time() + 7200)
            self.assertFalse(d3["cached"])                                               # nach einer Stunde wird neu geladen
            self.assertGreater(len(urls), n)

    def test_unreachable_uses_stale_data_or_reports_errors(self):
        with mock.patch.object(coreref, "fetch_bytes", self.fake([])):
            intel.load("joomla")
        with mock.patch.object(coreref, "fetch_bytes", side_effect=coreref.RefError("kein Netz")):
            d = intel.load("joomla", now=time.time() + 9999)
        self.assertTrue(d["stale"] and d["cves"])
        self.assertIn("NVD: kein Netz", d["errors"][0])
        other = tempfile.mkdtemp()
        with mock.patch.dict(os.environ, {"CLAUDIA_CACHE": other}), mock.patch.object(coreref, "fetch_bytes", side_effect=coreref.RefError("kein Netz")):
            d = intel.load("wordpress")
        self.assertFalse(d["cves"])
        self.assertTrue(d["errors"])
        with mock.patch.dict(os.environ, {"CLAUDIA_CACHE": tempfile.mkdtemp()}):
            d = intel.load("joomla", offline=True)
        self.assertIn("Offline", d["errors"][0])


class CheckRun(unittest.TestCase):
    def run_ids(self, ids, infected, data, opts=None):
        w = fixture.make_world(tempfile.mkdtemp(prefix="claudia_th_"), infected)
        s = Settings(site_dir=w["site_rel"], log_dir="logs", cms="joomla", url="", allow_hosts=ADV["allow_hosts"], opts=opts or {})
        eng = Engine(LocalRunner(w["home"], extra_path=w["bin"]), s, ADV)
        with mock.patch.object(intel, "load", lambda cms, offline=False, now=None: data):
            return {r.id: r for r in eng.run(ids, lambda e: None, threading.Event())}

    def data(self):
        return {"stand": "2026-11-03 06:00", "cves": [intel.compact_cve(v) for v in NVD["vulnerabilities"]], "vel": VEL, "nvd_ok": True, "vel_ok": True, "errors": []}

    def test_infected_site_matches_core_and_jce(self):
        r = self.run_ids(["threat_intel"], True, self.data())["threat_intel"]
        t = [(f.sev, f.title) for f in r.findings]
        self.assertTrue(any(s == "crit" and x.startswith("CVE-2026-1001") for s, x in t), t)             # Fixture: Joomla 6.2.0
        self.assertTrue(any(s == "crit" and "JCE" in x.upper() and "2.9.99.3" in x for s, x in t), t)
        self.assertFalse(any(x.startswith("Bedrohungslage vom") for _, x in t), t)           # keine allgemeine Liste, nur Treffer zum Server
        self.assertEqual(r.status, "crit")

    def test_clean_site_has_no_jce_hit(self):
        r = self.run_ids(["threat_intel"], False, self.data())["threat_intel"]
        t = [(f.sev, f.title) for f in r.findings]
        self.assertFalse(any("JCE" in x.upper() and s in ("crit", "warn") for s, x in t), t)
        self.assertTrue(any(x.startswith("CVE-2026-1001") for _, x in t))

    def test_no_data_is_skipped_with_reason(self):
        d = {"cves": [], "vel": [], "errors": ["NVD: kein Netz"], "stand": "x"}
        r = self.run_ids(["threat_intel"], True, d)["threat_intel"]
        self.assertEqual(r.status, "skipped")
        self.assertIn("kein Netz", r.message)

    def test_log_search_gets_targeted_pattern_and_finds_post(self):
        res = self.run_ids(["access_logs"], True, self.data(), opts={})
        r = res["access_logs"]
        titles = [f.title for f in r.findings]
        self.assertNotEqual(r.status, "error", r.message)
        self.assertTrue(any("com_jce" in t.lower() or "jce" in t.lower() for t in titles), titles)

    def test_watch_patterns_only_for_confirmed(self):
        w = fixture.make_world(tempfile.mkdtemp(prefix="claudia_th_"), False)
        eng = Engine(LocalRunner(w["home"], extra_path=w["bin"]), Settings(site_dir=w["site_rel"], cms="joomla"), ADV)
        ctx = __import__("claudia.engine", fromlist=["Ctx"]).Ctx(eng.runner, eng.settings, ADV, lambda e: None, threading.Event())
        ctx.shared["intel"] = self.data()
        self.assertEqual(threat.watch_patterns(ctx), [])                          # saubere Seite: JCE 2.9.99.7 ist behoben
        w2 = fixture.make_world(tempfile.mkdtemp(prefix="claudia_th_"), True)
        ctx2 = __import__("claudia.engine", fromlist=["Ctx"]).Ctx(LocalRunner(w2["home"], extra_path=w2["bin"]), Settings(site_dir=w2["site_rel"], cms="joomla"), ADV, lambda e: None, threading.Event())
        ctx2.shared["intel"] = self.data()
        pats = threat.watch_patterns(ctx2)
        self.assertTrue(pats and all(p["severity"] == "warn" for p in pats))
        import re
        self.assertTrue(any(re.search(p["regex"], '1.2.3.4 - - [x] "POST /index.php?option=com_jce&task=x HTTP/1.1" 200') for p in pats))
        self.assertFalse(any(re.search(p["regex"], '1.2.3.4 - - [x] "GET /index.php?option=com_jce HTTP/1.1" 200') for p in pats))


if __name__ == "__main__":
    unittest.main()


class GenericNames(unittest.TestCase):
    def test_generic_tokens_never_match(self):
        cve = intel.compact_cve({"cve": {"id": "CVE-2026-9", "published": "2026-11-01T00:00:00", "descriptions": [{"lang": "en", "value": "Joomla core issue in Joomla before 6.2.1"}],
                                          "metrics": {}, "configurations": []}})
        data = {"cves": [cve]}
        self.assertEqual(intel.extension_hits(data, ["joomla", "system"], "1.0"), {})
