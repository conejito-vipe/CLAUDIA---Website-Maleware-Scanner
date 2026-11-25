"""Prüfung 'Laufen die automatischen Updates wirklich?' (Joomla ab 5.4: Einstellung, API, Quelle, Firewall; WordPress: Cron). Alles ohne echten Server:
ein Platzhalter-Kontext liefert Datenbankzeilen und die Antworten der Aufrufe der eigenen Seite."""
import json
import os
import sys
import time
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

from claudia.checks import auto_updates as au  # noqa: E402
from claudia.model import CheckResult  # noqa: E402
from claudia.registry import REGISTRY, load_all  # noqa: E402

load_all()
UA_OK = "HTTP/2 401\ncontent-type: application/vnd.api+json; charset=utf-8\nserver: Apache\n"
HTML_403 = "HTTP/1.1 403 Forbidden\nContent-Type: text/html\nServer: Apache\n"
CF_403 = "HTTP/2 403\ncontent-type: text/html\nserver: cloudflare\ncf-ray: abc\n"
HOME_OK = "HTTP/2 200\ncontent-type: text/html\n"


class FakeDb:
    ok = True
    error = ""

    def __init__(self, tables):
        self.tables = tables            # Stichwort in der Abfrage -> Zeilen
        self.queries = []

    def query(self, sql, timeout=90.0):
        self.queries.append(sql)
        for key, rows in self.tables.items():
            if key in sql:
                return rows(sql) if callable(rows) else rows
        return []


class FakeCtx:
    def __init__(self, cms="joomla", db=None, probes=None, cfg=None, security=None, version="6.1.0", shell_extra=None):
        self.cms = cms
        self.db_obj = db
        self.probes = probes or {}
        self.cfg = cfg if cfg is not None else {"vars": {"offline": "0", "mailonline": "1", "mailfrom": "a@b.de"}}
        self.shared = {"joomla_version": version}
        if security is not None:
            self.shared["security_tools"] = security
        self.scripts = []
        self.shell_extra = shell_extra or {}

    def own_host(self):
        return "example.org"

    def db(self):
        return self.db_obj or type("N", (), {"ok": False, "error": "kein mysql"})()

    def config(self):
        return self.cfg

    def mask(self, t):
        return t

    def sh(self, script, timeout=120, raw="", **kw):
        self.scripts.append(script)
        out = ""
        for label, txt in self.probes.items():
            if "'@@%s'" % label in script:
                out += "@@%s\n%s\n" % (label, txt)
        for key, txt in self.shell_extra.items():
            if key in script:
                out += txt
        return type("R", (), {"out": out, "err": "", "rc": 0, "timed_out": False})()


def joomla_db(params=None, plugins=None, sites=None, core=None, log=None, ext_rows=None):
    params = {"autoupdate": "1", "updatesource": "default", "minimum_stability": "4"} if params is None else params
    plugins = plugins if plugins is not None else [
        {"folder": "webservices", "element": "joomlaupdate", "enabled": "1"}, {"folder": "webservices", "element": "content", "enabled": "1"},
        {"folder": "api-authentication", "element": "token", "enabled": "1"}, {"folder": "user", "element": "token", "enabled": "1"}]
    sites = sites if sites is not None else [{"name": "Joomla! Core", "location": "https://update.joomla.org/core/list.xml", "enabled": "1", "ts": "1"}]
    return FakeDb({
        "com_joomlaupdate": [{"p": json.dumps(params)}],
        "folder = 'webservices'": plugins,
        "#__update_sites": sites,
        "#__updates": core or [],
        "#__action_logs": log or [],
        "information_schema.tables": [],
        "information_schema.columns": [],
        "FROM #__extensions WHERE element LIKE": ext_rows or [],
    })


GOOD = {"API_CURL": UA_OK, "API_BROWSER": UA_OK, "HOME": HOME_OK}


def run(ctx):
    res = CheckResult("auto_updates", "t", "grundlagen")
    REGISTRY["auto_updates"].fn(ctx, res)
    res.finalize()
    return res


def titles(res):
    return [f.title for f in res.findings]


class Helfer(unittest.TestCase):
    def test_probe_parsing(self):
        p = au.parse_probe(CF_403)
        self.assertEqual((p["code"], p["cloudflare"]), ("403", "ja"))
        self.assertEqual(au.parse_probe("")["code"], "000")
        self.assertIn("json", au.parse_probe(UA_OK)["ctype"])

    def test_blocked_only_when_not_json(self):
        self.assertTrue(au.probe_blocked(au.parse_probe(HTML_403)))
        self.assertFalse(au.probe_blocked(au.parse_probe("HTTP/2 403\ncontent-type: application/vnd.api+json\n")))   # Joomla selbst antwortet
        self.assertFalse(au.probe_blocked(au.parse_probe(UA_OK)))
        self.assertFalse(au.probe_blocked(au.parse_probe("")))                                                       # nicht erreichbar ist nicht gesperrt
        self.assertTrue(au.probe_blocked(au.parse_probe("HTTP/1.1 503 Service Unavailable\ncontent-type: text/html\n")))

    def test_params_garbage(self):
        for t in ("", "kein json", "[1,2]", "null", "{"):
            self.assertEqual(au.parse_params(t), {})

    def test_fw_params_hides_secrets_and_irrelevant(self):
        rows = [{"element": "com_htprotect", "type": "component", "p": json.dumps({"api_block": "1", "license_key": "GEHEIM123", "bot_filter": {"useragent_empty": 1, "api_token": "X"}, "farbe": "blau"})}]
        out = " ".join(au.fw_params(rows))
        self.assertIn("api_block = 1", out)
        self.assertIn("useragent_empty = 1", out)
        self.assertNotIn("GEHEIM123", out)
        self.assertNotIn("blau", out)
        self.assertIn("(nicht angezeigt)", out)

    def test_cron_times(self):
        s = 'a:2:{i:1700000000;a:1:{s:16:"wp_version_check";a:1:{s:32:"abc";a:3:{}}}i:1700000500;a:1:{s:20:"wp_maybe_auto_update";a:0:{}}}'
        t = au.cron_times(s)
        self.assertEqual(t, {"wp_version_check": 1700000000, "wp_maybe_auto_update": 1700000500})
        self.assertEqual(au.cron_times("kaputt"), {})


class JoomlaCheck(unittest.TestCase):
    def setUp(self):
        p = mock.patch.dict(os.environ)                       # andere Tests setzen CLAUDIA_OFFLINE; hier sollen die Aufrufe der Seite laufen
        p.start()
        self.addCleanup(p.stop)
        os.environ.pop("CLAUDIA_OFFLINE", None)

    def test_everything_fine(self):
        res = run(FakeCtx(db=joomla_db(), probes=GOOD))
        self.assertEqual(res.status, "ok", titles(res))
        self.assertIn("nicht prüfbar", " ".join(res.findings[0].items))

    def test_old_joomla_not_applicable(self):
        res = run(FakeCtx(version="5.3.1", db=joomla_db(), probes=GOOD))
        self.assertEqual(res.status, "info")
        self.assertIn("keine automatischen", res.findings[0].title)

    def test_autoupdate_off(self):
        res = run(FakeCtx(db=joomla_db(params={"autoupdate": "0"}), probes=GOOD))
        self.assertEqual(res.status, "warn")
        self.assertTrue(any("ausgeschaltet" in t for t in titles(res)))

    def test_missing_setting_is_note_not_alarm(self):
        res = run(FakeCtx(db=joomla_db(params={}), probes=GOOD))
        self.assertEqual(res.status, "ok")
        self.assertIn("nicht gespeichert", " ".join(res.findings[0].items))

    def test_source_and_stability(self):
        res = run(FakeCtx(db=joomla_db(params={"autoupdate": "1", "updatesource": "next", "minimum_stability": "1"}), probes=GOOD))
        t = " ".join(titles(res))
        self.assertIn("Standard-Update-Quelle", t)
        self.assertIn("Mindeststabilität", t)

    def test_api_plugins_off_is_critical(self):
        plugs = [{"folder": "webservices", "element": "joomlaupdate", "enabled": "0"}, {"folder": "webservices", "element": "content", "enabled": "0"},
                 {"folder": "api-authentication", "element": "token", "enabled": "1"}]
        res = run(FakeCtx(db=joomla_db(plugins=plugs), probes=GOOD))
        self.assertEqual(res.status, "crit")
        f = res.findings[0]
        self.assertIn("API", f.title)
        self.assertIn("Joomla-API abschalten", f.detail)           # nennt die naheliegende Ursache

    def test_api_off_but_autoupdate_off_not_double_reported(self):
        plugs = [{"folder": "webservices", "element": "content", "enabled": "0"}]
        res = run(FakeCtx(db=joomla_db(params={"autoupdate": "0"}, plugins=plugs), probes=GOOD))
        self.assertEqual(len([t for t in titles(res) if "API" in t]), 0)

    def test_update_source_disabled(self):
        res = run(FakeCtx(db=joomla_db(sites=[{"name": "Joomla! Core", "location": "https://update.joomla.org/core/list.xml", "enabled": "0", "ts": "1"}]), probes=GOOD))
        self.assertEqual(res.status, "crit")

    def test_update_waiting_although_everything_ok(self):
        res = run(FakeCtx(db=joomla_db(core=[{"version": "6.1.3"}, {"version": "6.0.9"}]), probes=GOOD))
        self.assertEqual(res.status, "warn")
        self.assertIn("6.1.3", res.findings[0].title)

    def test_no_update_waiting_when_current(self):
        res = run(FakeCtx(db=joomla_db(core=[{"version": "6.1.0"}]), probes=GOOD))
        self.assertEqual(res.status, "ok")

    def test_firewall_blocks_without_browser_agent(self):
        res = run(FakeCtx(db=joomla_db(), probes={"API_CURL": HTML_403, "API_BROWSER": UA_OK, "HOME": HOME_OK}))
        self.assertEqual(res.status, "crit")
        self.assertIn("Browser-Kennung", res.findings[0].title)

    def test_api_blocked_for_everyone(self):
        res = run(FakeCtx(db=joomla_db(), probes={"API_CURL": HTML_403, "API_BROWSER": HTML_403, "HOME": HOME_OK}))
        self.assertEqual(res.status, "crit")
        self.assertIn("abgewiesen", res.findings[0].title)

    def test_cloudflare_note_only_when_not_blocked(self):
        res = run(FakeCtx(db=joomla_db(), probes={"API_CURL": "HTTP/2 401\ncontent-type: application/json\nserver: cloudflare\n", "API_BROWSER": UA_OK, "HOME": HOME_OK}))
        self.assertEqual(res.status, "ok")
        self.assertIn("Cloudflare", " ".join(res.findings[0].items))

    def test_home_protected(self):
        res = run(FakeCtx(db=joomla_db(), probes={"API_CURL": UA_OK, "API_BROWSER": UA_OK, "HOME": "HTTP/1.1 401 Unauthorized\ncontent-type: text/html\n"}))
        self.assertTrue(any("nicht frei abrufbar" in t for t in titles(res)))

    def test_offline_and_mail(self):
        res = run(FakeCtx(db=joomla_db(), probes=GOOD, cfg={"vars": {"offline": "1", "mailonline": "0", "mailfrom": ""}}))
        t = " ".join(titles(res))
        self.assertIn("Offline", t)
        self.assertIn("Mailversand", t)

    def test_htaccess_rules(self):
        res = run(FakeCtx(db=joomla_db(), probes=GOOD, shell_extra={".htaccess api/.htaccess": ".htaccess:12:RewriteRule ^api/ - [F,L]\n"}))
        self.assertTrue(any(".htaccess" in t for t in titles(res)))

    def test_without_database_no_false_alarm_and_no_ok_claim_of_settings(self):
        res = run(FakeCtx(db=None, probes=GOOD))
        self.assertEqual(res.status, "ok")
        self.assertIn("Datenbank", " ".join(res.findings[0].items))

    def test_firewall_extension_listed_with_settings_and_logs(self):
        ext = [{"element": "com_htprotect", "type": "component", "p": json.dumps({"api_block": "1", "bot_agents": ["curl", "python"], "license": "X"})}]

        def tables(sql):
            return [{"t": "jos_htprotect_log"}] if "information_schema.tables" in sql else []
        db = joomla_db(ext_rows=ext)
        db.tables["information_schema.tables"] = tables
        db.tables["information_schema.columns"] = [{"c": "url"}, {"c": "reason"}]
        db.tables["COUNT(*)"] = [{"n": "7"}]
        db.tables["LEFT(CONCAT_WS"] = [{"s": "/api/index.php/v1/ | blocked bot"}]
        order = {k: db.tables[k] for k in ("COUNT(*)", "LEFT(CONCAT_WS")}
        db.tables = {**order, **{k: v for k, v in db.tables.items() if k not in order}}
        sec = {"present": {"htprotect": ["x/com_htprotect"]}, "active": {"htprotect": True}, "host": []}
        res = run(FakeCtx(db=db, probes=GOOD, security=sec))
        f = [x for x in res.findings if "Firewall-Erweiterung" in x.title][0]
        text = " ".join(f.items)
        self.assertIn("api_block = 1", text)
        self.assertNotIn("license", text.replace("(nicht angezeigt)", ""))
        self.assertIn("7 Eintrag", text)
        self.assertIn("Beispiel", text)
        self.assertEqual(f.sev, "info")


class WordPressCheck(unittest.TestCase):
    def setUp(self):
        p = mock.patch.dict(os.environ)
        p.start()
        self.addCleanup(p.stop)
        os.environ.pop("CLAUDIA_OFFLINE", None)

    def wp(self, defines=None, probes=None, cron=None, extra=None, db=True):
        d = FakeDb({"option_name = 'cron'": [{"v": cron or ""}]}) if db else None
        return FakeCtx(cms="wordpress", db=d, probes=probes or {"CRON_CURL": HOME_OK, "CRON_BROWSER": HOME_OK}, cfg={"defines": defines or {}}, shell_extra=extra or {})

    def fresh(self):
        t = int(time.time()) + 600
        return 'a:1:{i:%d;a:1:{s:16:"wp_version_check";a:0:{}}}' % t

    def test_fine(self):
        res = run(self.wp(cron=self.fresh()))
        self.assertEqual(res.status, "ok", titles(res))

    def test_stale_schedule(self):
        old = int(time.time()) - 5 * 86400
        res = run(self.wp(cron='a:1:{i:%d;a:1:{s:16:"wp_version_check";a:0:{}}}' % old))
        self.assertEqual(res.status, "crit")
        self.assertIn("steht", res.findings[0].title)

    def test_cron_blocked(self):
        res = run(self.wp(cron=self.fresh(), probes={"CRON_CURL": HTML_403, "CRON_BROWSER": HTML_403}))
        self.assertEqual(res.status, "crit")

    def test_disabled_cron_without_system_cron(self):
        res = run(self.wp(defines={"DISABLE_WP_CRON": "true"}, cron=self.fresh()))
        self.assertTrue(any("DISABLE_WP_CRON" in t for t in titles(res)))

    def test_disabled_cron_with_system_cron_is_fine(self):
        res = run(self.wp(defines={"DISABLE_WP_CRON": "true"}, cron=self.fresh(), extra={"crontab -l": "@@CRONTAB\n*/10 * * * * wget -q -O - https://x/wp-cron.php\n"}))
        self.assertEqual(res.status, "ok", titles(res))

    def test_vcs_folder(self):
        res = run(self.wp(cron=self.fresh(), extra={"@@VCS": "@@VCS\n./.git\n"}))
        self.assertTrue(any("Versionsverwaltung" in t for t in titles(res)))


class Registrierung(unittest.TestCase):
    def test_registered_for_both_systems_in_update_cluster(self):
        d = REGISTRY["auto_updates"]
        self.assertEqual(d.cms, "both")
        self.assertEqual(d.cluster, "update")
        self.assertIn("WordPress", d.wp.get("title", ""))
        self.assertIn("schnell", d.presets)

    def test_no_writes_in_scripts(self):
        ctx = FakeCtx(db=joomla_db(), probes=GOOD)
        run(ctx)
        for s in ctx.scripts:
            self.assertNotRegex(s, r"\b(rm|mv|cp|chmod|chown|tee|sed -i)\b|>\s*[^/&\s]")
        for q in ctx.db_obj.queries:
            self.assertRegex(q.strip().upper(), r"^SELECT")


if __name__ == "__main__":
    unittest.main()
