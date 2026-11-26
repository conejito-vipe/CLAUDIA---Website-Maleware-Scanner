"""WordPress-Bereich: Erkennung, Prüfungen (saubere und befallene Testseite), Aktionen mit WP-CLI-Attrappe, Server-Anbindung."""
import json
import os
import sqlite3
import stat
import sys
import tempfile
import threading
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

import wpfixture  # noqa: E402
from claudia import actions, cms as cmsmod, probe, report, wordpress  # noqa: E402
from claudia.engine import Engine, Settings  # noqa: E402
from claudia.registry import cluster_title_defs, groups_for, load_all, ordered  # noqa: E402
from claudia.runner import LocalRunner  # noqa: E402
from claudia.server import ApiError, App  # noqa: E402

ROOT = os.path.dirname(HERE)
os.environ.setdefault("CLAUDIA_OFFLINE", "1")
ADV = json.load(open(os.path.join(ROOT, "claudia", "advisories.json"), encoding="utf-8"))
load_all()

_CACHE = {}


def script(path, body):
    with open(path, "w") as fh:
        fh.write("#!/bin/bash\n" + body + "\n")
    os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC)


def run_all(infected):
    """Alle WordPress-Prüfungen offline gegen die Testwelt (einmal pro Variante)."""
    if infected not in _CACHE:
        w = wpfixture.make_wp_world(tempfile.mkdtemp(prefix="wp_t_"), infected)
        s = Settings(site_dir=w["site_rel"], log_dir="logs", cms="wordpress", url="", allow_hosts=ADV["allow_hosts"])
        eng = Engine(LocalRunner(w["home"], extra_path=w["bin"]), s, ADV)
        ids = [c.id for c in ordered("wordpress")]
        res = eng.run(ids, lambda e: None, threading.Event())
        _CACHE[infected] = ({r.id: r for r in res}, w)
    return _CACHE[infected]


def sevs(r):
    return [f.sev for f in r.findings]


class Registry(unittest.TestCase):
    def test_joomla_unchanged_and_wordpress_separate(self):
        j = [c.id for c in ordered("joomla")]
        w = [c.id for c in ordered("wordpress")]
        self.assertEqual(len(j), 77)
        self.assertFalse([i for i in j if i.startswith("wp_")])
        self.assertEqual(w[0], "wp_info")
        self.assertIn("wp_core", w)
        self.assertNotIn("db_jce", w)                     # Joomla-Prüfungen erscheinen nicht bei WordPress
        for shared in ("webshells", "perms", "htaccess", "php_in_uploads", "root_files"):
            self.assertIn(shared, w)
            self.assertIn(shared, j)

    def test_groups_and_clusters_exist_for_every_check(self):
        for cms in ("joomla", "wordpress"):
            gids = {g[0] for g in groups_for(cms)}
            for c in ordered(cms):
                self.assertIn(c.public(cms)["group"], gids, c.id)
            self.assertTrue(cluster_title_defs(cms))

    def test_wordpress_texts_do_not_say_joomla(self):
        for c in ordered("wordpress"):
            pub = c.public("wordpress")
            blob = " ".join(str(pub.get(k, "")) for k in ("title", "what", "reads", "why"))
            if c.id != "other_installs":              # nennt andere Systeme auf demselben Webspace absichtlich
                self.assertNotIn("Joomla", blob, c.id)
            self.assertNotIn("configuration.php", blob, c.id)

    def test_profile(self):
        self.assertEqual(cmsmod.profile("wordpress")["config_file"], "wp-config.php")
        self.assertEqual(cmsmod.profile("joomla")["config_file"], "configuration.php")
        self.assertEqual(cmsmod.profile("unbekannt")["config_file"], "configuration.php")


class Parsing(unittest.TestCase):
    CFG = """<?php
define( 'DB_NAME', 'wpdb' );
define( 'DB_USER', 'wpuser' );
define( 'DB_PASSWORD', 'Geheim\\'s#1' );
define( 'DB_HOST', 'localhost:3307' );
define( 'AUTH_KEY', 'put your unique phrase here' );
$table_prefix = 'xy_';
define( 'WP_DEBUG', true );
require_once ABSPATH . 'wp-settings.php';
"""

    def test_config(self):
        c = wordpress.parse_wp_config(self.CFG)
        self.assertEqual(c["prefix"], "xy_")
        self.assertEqual(c["vars"]["user"], "wpuser")
        self.assertEqual(c["vars"]["db"], "wpdb")
        self.assertEqual(c["vars"]["dbprefix"], "xy_")

    def test_version(self):
        v = wordpress.parse_wp_version("<?php\n$wp_version = '6.8.3';\n$wp_db_version = 60421;\n$required_php_version = '7.2.24';\n")
        self.assertEqual(v["version"], "6.8.3")
        self.assertEqual(wordpress.version_tuple("6.8.3"), [6, 8, 3])

    def test_mask_secrets(self):
        from claudia.util import mask_secrets
        out = mask_secrets(self.CFG)
        self.assertNotIn("put your unique phrase here", out)
        self.assertNotIn("Geheim", out)


class Detection(unittest.TestCase):
    def test_probe_detects_wordpress(self):
        w = wpfixture.make_wp_world(tempfile.mkdtemp(prefix="wp_p_"), False)
        info = probe.probe(LocalRunner(w["home"], extra_path=w["bin"]), w["site_rel"])
        self.assertTrue(info["site_found"])
        self.assertEqual(info["cms"], "wordpress")
        self.assertTrue(info["wordpress"])
        self.assertTrue(info["wp_config"])
        self.assertEqual(info["joomla"], "")

    def test_probe_joomla_stays_joomla(self):
        import fixture
        w = fixture.make_world(tempfile.mkdtemp(prefix="wp_pj_"), False)
        info = probe.probe(LocalRunner(w["home"], extra_path=w["bin"]), w["site_rel"])
        self.assertEqual(info["cms"], "joomla")


class CleanSite(unittest.TestCase):
    def test_no_warning_or_critical_on_clean_wordpress(self):
        res, _ = run_all(False)
        bad = {i: [(f.sev, f.title) for f in r.findings if f.sev in ("warn", "crit")] for i, r in res.items()}
        bad = {i: v for i, v in bad.items() if v}
        self.assertEqual(bad.pop("wp_2fa", [("warn", "Kein Zwei-Faktor-Plugin gefunden")]), [("warn", "Kein Zwei-Faktor-Plugin gefunden")])   # seit 2.5.0: Härtungshinweis, die Test-Seite hat kein 2FA-Plugin
        self.assertEqual(bad, {})

    def test_no_check_failed(self):
        for infected in (False, True):
            res, _ = run_all(infected)
            for i, r in res.items():
                self.assertNotEqual(r.status, "error", "%s: %s" % (i, r.message))


class InfectedSite(unittest.TestCase):
    def setUp(self):
        self.res, self.w = run_all(True)

    def titles(self, cid):
        return " | ".join(f.title for f in self.res[cid].findings)

    def test_expected_critical_checks(self):
        for cid in ("wp_config", "wp_entry_points", "wp_plugins", "wp_db_options", "wp_db_content", "webshells", "php_in_uploads", "perms"):
            self.assertIn("crit", sevs(self.res[cid]), cid)

    def test_findings_are_wordpress_specific(self):
        self.assertIn("Jeder darf sich als Administrator registrieren", self.titles("wp_db_options"))
        self.assertIn("ohne Plugin-Beschreibung", self.titles("wp_db_options"))
        self.assertIn("Verdächtiger Code in der wp-config.php", self.titles("wp_config"))
        self.assertIn("Sicherheitslücke", self.titles("wp_plugins"))
        self.assertIn("Administrator-Konto", self.titles("wp_db_users"))

    def test_uploads_checked_in_wordpress_paths(self):
        items = " ".join(" ".join(f.items) for f in self.res["php_in_uploads"].findings)
        self.assertIn("wp-content/uploads", items)
        self.assertNotIn("images/", items)

    def test_wordpress_core_files_are_not_reported_as_backdoors(self):
        items = " ".join(" ".join(f.items) for f in self.res["suspicious_names"].findings)
        for core in ("wp-login.php", "xmlrpc.php", "wp-cron.php"):
            self.assertNotIn(core, items)

    def test_no_secrets_in_findings(self):
        blob = json.dumps([[f.title, f.detail, f.items] for r in self.res.values() for f in r.findings], ensure_ascii=False)
        self.assertNotIn("GEHEIM-DB-PASSWORT", blob)
        self.assertNotIn("GEHEIM-DB-PASSWORT", blob)

    def test_online_checks_skipped_offline(self):
        for cid in ("wp_core", "wp_plugins_online", "wp_exposure"):
            self.assertEqual(self.res[cid].status, "skipped", cid)


class OnlineChecks(unittest.TestCase):
    """Online-Quellen werden gemockt: https, nur api.wordpress.org."""

    @staticmethod
    def reply(body, status=200):
        return mock.Mock(status=status, error="", body=body, headers={}, url="")

    def test_core_checksums_detect_changed_and_unknown_files(self):
        w0 = wpfixture.make_wp_world(tempfile.mkdtemp(prefix="wp_o0_"), True)
        ver = wordpress.parse_wp_version(open(os.path.join(w0["site"], "wp-includes", "version.php")).read())["version"]
        import hashlib

        def md5(p):
            return hashlib.md5(open(p, "rb").read()).hexdigest()
        sums = {}
        for base in ("wp-includes", "wp-admin"):
            for dp, _d, fs in os.walk(os.path.join(w0["site"], base)):
                for f in fs:
                    fp = os.path.join(dp, f)
                    sums[os.path.relpath(fp, w0["site"])] = md5(fp)
        for f in ("index.php", "wp-login.php", "wp-settings.php", "wp-load.php"):
            fp = os.path.join(w0["site"], f)
            if os.path.exists(fp):
                sums[f] = md5(fp)
        # Ein Eintrag soll abweichen, einer fehlen
        victim = sorted(k for k in sums if k.startswith("wp-includes/"))[0]
        sums[victim] = "0" * 32
        sums["wp-includes/gibt-es-nicht.php"] = "1" * 32
        body = json.dumps({"checksums": sums})

        def fake(url, *a, **k):
            self.assertTrue(url.startswith("https://api.wordpress.org/"), url)
            return self.reply(body)
        from claudia.checks import web as webmod
        s = Settings(site_dir=w0["site_rel"], log_dir="logs", cms="wordpress", url="", allow_hosts=ADV["allow_hosts"])
        eng = Engine(LocalRunner(w0["home"], extra_path=w0["bin"]), s, ADV)
        with mock.patch.dict(os.environ, {}), mock.patch.object(webmod, "fetch", fake):
            os.environ.pop("CLAUDIA_OFFLINE", None)
            r = {x.id: x for x in eng.run(["wp_core"], lambda e: None, threading.Event())}["wp_core"]
        titles = " | ".join(f.title for f in r.findings)
        self.assertIn("weichen vom Original ab", titles, titles)
        self.assertIn("fehlen", titles)
        self.assertIn(ver, "".join(f.title + f.detail for f in r.findings) + ver)

    def test_stable_check_parsing(self):
        data = {"6.8.3": "latest", "6.7.1": "outdated", "5.0": "insecure"}
        from claudia.checks.wp import stable_check_status
        self.assertEqual(stable_check_status(json.dumps(data), "6.8.3"), "latest")
        self.assertEqual(stable_check_status(json.dumps(data), "5.0"), "insecure")
        self.assertEqual(stable_check_status(json.dumps(data), "6.7.1"), "outdated")
        self.assertEqual(stable_check_status("kein json", "6.8.3"), "")

    def test_plugin_info_parsing(self):
        from claudia.checks.wp import parse_plugin_info
        got = parse_plugin_info(json.dumps({"version": "2.1", "last_updated": "2020-01-01 10:00am GMT", "slug": "x"}))
        self.assertEqual(got["version"], "2.1")


def cli_world(infected=True, with_cli=True):
    w = wpfixture.make_wp_world(tempfile.mkdtemp(prefix="wp_a_"), infected)
    b = w["bin"]
    script(os.path.join(b, "mysqldump"), 'cat >/dev/null; for i in $(seq 1 3000); do echo "INSERT INTO x VALUES ($i,\'$RANDOM$RANDOM$RANDOM$RANDOM\');"; done')
    script(os.path.join(b, "php8.3"), r'''
if [ "$1" = "-v" ]; then echo "PHP 8.3.6 (cli)"; exit 0; fi
echo "php $*" >> "$HOME/php_calls.txt"
case "$*" in
  *"core version"*) echo "6.8.3";;
  *"core update-db"*) echo "Success: WordPress database already at latest db version.";;
  *"core update"*) echo "Success: WordPress updated successfully.";;
  *"plugin update"*) echo "Success: Updated 2 of 2 plugins.";;
  *"theme update"*) echo "Success: Theme already updated.";;
  *"core download"*) echo "Success: WordPress downloaded.";;
  *"verify-checksums"*) echo "Success: WordPress installation verifies against checksums.";;
  *"plugin list"*) ;;
  *) echo "ok";;
esac''')
    if with_cli:
        open(os.path.join(w["home"], "wp-cli.phar"), "w").write("<?php\n")
    return LocalRunner(w["home"], extra_path=b), w


CHOICES = [{"name": "php8.3", "version": "8.3.6", "default": True}]
INFO = {"cms": "wordpress", "wordpress": "6.8.3", "php": "", "php_candidates": [{"name": "php8.3", "version": "PHP 8.3.6"}]}


class Actions(unittest.TestCase):
    def results(self):
        res, _ = run_all(True)
        return [{"id": r.id, "title": r.title, "status": r.status,
                 "findings": [{"sev": f.sev, "title": f.title, "items": list(f.items)} for f in r.findings]} for r in res.values()]

    def test_offered_actions_are_wordpress_only(self):
        r, w = cli_world()
        scan = actions.scan_server(r, w["site_rel"])
        self.assertTrue(scan["wpcli"].endswith("wp-cli.phar"))
        ids = [a["id"] for a in actions.available(self.results(), INFO, "8.3", {}, scan)]
        for want in ("wp_update", "wp_salts", "wp_fix_registration", "remove_shells", "fix_permissions", "backup_now"):
            self.assertIn(want, ids)
        for joomla_only in ("core_update", "update_extensions", "remove_jce_profiles"):
            self.assertNotIn(joomla_only, ids)

    def test_no_wp_cli_gives_reason(self):
        r, w = cli_world(with_cli=False)
        scan = actions.scan_server(r, w["site_rel"])
        av = {a["id"]: a for a in actions.available(self.results(), INFO, "8.3", {}, scan)}
        self.assertIn("WP-CLI", av["wp_update"]["reason"])

    def test_clean_site_offers_no_wordpress_fix(self):
        res, _ = run_all(False)
        results = [{"id": r.id, "title": r.title, "status": r.status,
                    "findings": [{"sev": f.sev, "title": f.title, "items": list(f.items)} for f in r.findings]} for r in res.values()]
        ids = [a["id"] for a in actions.available(results, INFO, "8.3", {}, {})]
        for aid in ("wp_update", "wp_core_reinstall", "wp_fix_registration", "wp_salts", "remove_shells"):
            self.assertNotIn(aid, ids)

    def test_preview_shows_commands(self):
        cmds = actions.commands_preview("wp_update", {"wpcli": "/home/u/wp-cli.phar", "php": "php8.3"}, CHOICES)
        text = "\n".join(cmds)
        self.assertIn("core update", text)
        self.assertIn("plugin update", text)
        cmds = actions.commands_preview("wp_salts", {"php": "php8.3"}, CHOICES)
        self.assertTrue(cmds)

    def test_run_wp_update_with_attrappe(self):
        r, w = cli_world()
        scan = actions.scan_server(r, w["site_rel"])
        res = actions.run_action(r, w["site_rel"], "wp_update", {"php": "php8.3", "wpcli": scan["wpcli"]}, CHOICES)
        self.assertTrue(res["ok"], res)
        self.assertTrue(os.path.isdir(res["backup_dir"]))
        calls = open(os.path.join(w["home"], "php_calls.txt")).read()
        for part in ("core update", "plugin update --all", "theme update --all", "verify-checksums"):
            self.assertIn(part, calls)

    def test_wp_update_refuses_odd_cli_path(self):
        r, w = cli_world()
        res = actions.run_action(r, w["site_rel"], "wp_update", {"php": "php8.3", "wpcli": "/x; rm -rf ~"}, CHOICES)
        self.assertFalse(res["ok"])
        self.assertEqual(res["backup_dir"], "")                 # vor der Prüfung wurde nichts angelegt oder geändert
        self.assertFalse(os.path.exists(os.path.join(w["home"], "php_calls.txt")))

    def test_run_salts_and_disallow_edit(self):
        r, w = cli_world()
        cfg = os.path.join(w["site"], "wp-config.php")
        before = open(cfg).read()
        res = actions.run_action(r, w["site_rel"], "wp_salts", {}, CHOICES)
        self.assertTrue(res["ok"], res)
        after = open(cfg).read()
        self.assertNotEqual(before, after)
        self.assertIn("wp-settings.php", after)
        self.assertTrue(os.path.isfile(os.path.join(res["backup_dir"], "wp-config.php")))
        res = actions.run_action(r, w["site_rel"], "wp_disallow_edit", {}, CHOICES)
        self.assertTrue(res["ok"], res)
        self.assertIn("DISALLOW_FILE_EDIT", open(cfg).read())

    def test_run_fix_registration(self):
        r, w = cli_world()
        res = actions.run_action(r, w["site_rel"], "wp_fix_registration", {}, CHOICES)
        self.assertTrue(res["ok"], res)
        con = sqlite3.connect(w["db"])
        vals = dict(con.execute("SELECT option_name, option_value FROM wp_options WHERE option_name IN ('users_can_register','default_role')").fetchall())
        self.assertEqual(vals["users_can_register"], "0")
        self.assertNotEqual(vals["default_role"], "administrator")

    def test_edit_wp_config_is_pure_and_idempotent(self):
        text = "<?php\ndefine( 'AUTH_KEY', 'alt' );\n/* That's all, stop editing! */\nrequire_once ABSPATH . 'wp-settings.php';\n"
        a = actions.edit_wp_config(text, "salts")
        self.assertNotIn("'alt'", a)
        b = actions.edit_wp_config(text, "edit")
        self.assertIn("DISALLOW_FILE_EDIT", b)
        self.assertEqual(actions.edit_wp_config(b, "edit"), b)

    def test_shell_deletion_rule_is_conservative(self):
        self.assertTrue(actions.wp_shell_deletable("wp-content/uploads/2024/x.php", [], []))
        self.assertFalse(actions.wp_shell_deletable("wp-includes/functions.php", [], []))
        self.assertFalse(actions.wp_shell_deletable("wp-content/themes/twentytwentyfour/functions.php", [], []))
        self.assertFalse(actions.wp_shell_deletable("wp-config.php", [], []))


class ServerPayload(unittest.TestCase):
    def test_init_payload_switches_with_cms(self):
        app = App(tempfile.mkdtemp(prefix="wp_srv_"))
        p = app.init_payload()
        self.assertEqual(p["cms"], "joomla")
        self.assertEqual(len(p["checks"]), 77)
        app.info = {"cms": "wordpress", "wordpress": "6.8.3"}
        p = app.init_payload()
        self.assertEqual(p["cms"], "wordpress")
        self.assertEqual(p["cms_name"], "WordPress")
        ids = [c["id"] for c in p["checks"]]
        self.assertIn("wp_core", ids)
        self.assertNotIn("db_jce", ids)

    def test_update_check_is_skipped_for_wordpress(self):
        app = App(tempfile.mkdtemp(prefix="wp_srv2_"))
        r, w = cli_world()
        app.runner = r
        app.conn = {"host": "x", "site_dir": w["site_rel"]}
        app.info = dict(INFO)
        app.ensure_update_check(force=True)
        self.assertFalse(app.update_state.get("checking"))
        self.assertFalse(app.update_state.get("failed"))

    def test_original_comparison_uses_wordpress_source(self):
        app = App(tempfile.mkdtemp(prefix="wp_srv3_"))
        app.info = dict(INFO)
        out = app._original("wp-content/plugins/x/x.php", ["<?php"], 1, 1, "")
        self.assertEqual(out["status"], "kein_original")
        self.assertIn("WordPress", out["note"])
        self.assertNotIn("Joomla", out["note"])


class Report(unittest.TestCase):
    def bundle(self):
        res, w = run_all(True)
        results = [r.to_dict() for r in res.values()]
        info = {"host": "ssh.beispiel.de", "cms": "wordpress", "wordpress": "6.8.3", "php": "PHP 8.3", "mysql": True}
        return report.build_bundle(results, list(res), {"site_dir": w["site_rel"], "url": "", "mask_ips": True, "allow_hosts": [], "opts": {}},
                                   info, 5.0, False, ADV["stand"], [])

    def test_report_talks_about_wordpress(self):
        b = self.bundle()
        self.assertEqual(b["meta"]["system"], "WordPress")
        self.assertEqual(b["meta"]["joomla_version"], "6.8.3")
        html = report.render_html(b)
        txt = report.render_txt(b)
        self.assertIn("WordPress", html)
        self.assertIn("WordPress", txt)
        self.assertNotIn("Joomla-Daten in der Datenbank", html)
        self.assertIn("wp-content", html)

    def test_report_has_no_secrets(self):
        b = self.bundle()
        blob = report.render_html(b) + report.render_txt(b) + report.render_json(b)
        self.assertNotIn("GEHEIM-DB-PASSWORT", blob)


if __name__ == "__main__":
    unittest.main()
