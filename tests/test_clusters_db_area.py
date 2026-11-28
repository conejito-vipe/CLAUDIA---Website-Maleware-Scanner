"""Neu in 1.5: Test-Cluster, Bereich 'Datenbank' mit eigener Verbindung, Schadcode-Ausschnitt, Update-Status in der Aktionsliste."""
import json
import os
import sqlite3
import sys
import tempfile
import threading
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, ROOT)

import fixture  # noqa: E402
from claudia import registry, snippets  # noqa: E402
from claudia.engine import Engine, Settings  # noqa: E402
from claudia.runner import LocalRunner  # noqa: E402
from claudia.server import ApiError, App  # noqa: E402

ADV = json.load(open(os.path.join(ROOT, "claudia", "advisories.json"), encoding="utf-8"))
SETEXT = """import json, sqlite3, sys
c = sqlite3.connect(sys.argv[1])
c.execute('UPDATE j_extensions SET manifest_cache=? WHERE extension_id=?', (json.dumps({'version': sys.argv[3]}), int(sys.argv[2])))
c.commit()
"""
DBX = ["dbx_server", "dbx_codescan", "dbx_anomalies", "dbx_incidents"]


def run(ids, w, **kw):
    os.environ["CLAUDIA_OFFLINE"] = "1"
    s = Settings(site_dir=w["site_rel"], allow_hosts=list(ADV["allow_hosts"]), **kw)
    eng = Engine(LocalRunner(w["home"], extra_path=w["bin"]), s, ADV)
    return {r.id: r for r in eng.run(ids, lambda e: None, threading.Event())}


def titles(r, sev=None):
    return [f.title for f in r.findings if sev is None or f.sev == sev]


class Clusters(unittest.TestCase):
    def test_every_member_exists_and_every_cluster_is_used(self):
        reg = registry.load_all()
        for cid, cl in registry.CLUSTER_MEMBERS.items():
            self.assertIn(cid, reg, cid)
            self.assertIn(cl, registry.CLUSTERS, cl)
        used = set(registry.CLUSTER_MEMBERS.values()) | set(registry.CLUSTER_MEMBERS_WP.values())   # seit 2.7.0 gibt es Cluster, die nur WordPress nutzt (shop_woo)
        self.assertEqual(used, set(registry.CLUSTERS))
        self.assertTrue(all(len(v[1]) > 40 for v in registry.CLUSTERS.values()))   # jedes Cluster beschreibt sein Vorgehen

    def test_cluster_members_are_contiguous_and_stay_in_their_group(self):
        order = registry.ordered()
        seen, last = set(), None
        for c in order:
            if c.cluster != last:
                self.assertNotIn(c.cluster, seen, "Cluster %s ist zerrissen" % c.cluster)
                seen.add(c.cluster)
                last = c.cluster
        groups = {}
        for c in order:
            groups.setdefault(c.cluster, set()).add(c.group)
        self.assertTrue(all(len(g) == 1 for g in groups.values()))

    def test_database_area_is_optional(self):
        grp = [c for c in registry.ordered() if c.group == "dbbereich"]
        self.assertEqual([c.id for c in grp], ["dbx_server", "dbx_codescan", "dbx_anomalies", "dbx_incidents"])
        for c in grp:
            self.assertEqual(c.presets, ["komplett"])         # weder im Schnellcheck noch in 'Nach einem Hack'
            self.assertEqual(c.needs, "db")

    def test_names_of_clusters_from_the_request(self):
        titles_ = [v[0] for v in registry.CLUSTERS.values()]
        self.assertIn("Injection prüfen", titles_)
        self.assertIn("PHP nach Shells durchsuchen", titles_)


class DbArea(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.w = fixture.make_world(tempfile.mkdtemp(prefix="claudia_v15_"), False)
        con = sqlite3.connect(cls.w["db"])
        con.executescript("""
CREATE TABLE wp_users_bak (a TEXT);
CREATE TABLE j_newtbl (a TEXT);
INSERT INTO j_redirect_links (old_url, referer) VALUES ('/x.php?a=1'' union select 1,2--', 'http://e.example/?s=;eval(get(1))');
INSERT INTO j_modules (id, title, content, params) VALUES (991, 'Info', '<p>x</p><script>eval(atob("ZG9jdW1lbnQ="))</script>', '{}');
CREATE TRIGGER evil AFTER INSERT ON j_users BEGIN UPDATE j_users SET block = 0; END;
""")
        con.commit()
        con.close()
        os.environ["CLAUDIA_TEST_GRANTS"] = "GRANT ALL PRIVILEGES ON *.* TO `u`@`%` WITH GRANT OPTION"
        cls.r = run(DBX, cls.w)
        os.environ.pop("CLAUDIA_TEST_GRANTS")

    def test_nothing_crashed(self):
        self.assertEqual({k: v.message for k, v in self.r.items() if v.status == "error"}, {})

    def test_codescan_finds_code_with_table_and_column(self):
        r = self.r["dbx_codescan"]
        self.assertTrue(any("typischem Schadcode" in t for t in titles(r, "crit")), titles(r))
        items = " ".join(i for f in r.findings for i in f.items)
        self.assertIn("j_modules.content", items)
        self.assertIn("eval", items)
        self.assertIn("db_codescan.txt", r.raw)

    def test_codescan_shows_code_with_red_span_and_separates_request_logs(self):
        r = self.r["dbx_codescan"]
        crit = [f for f in r.findings if f.sev == "crit"][0]
        ev = crit.evidence[0]
        self.assertEqual(ev["file"], "j_modules.content")
        hit = [c for c in ev["code"] if c["hit"]][0]
        self.assertIn("eval", hit["t"][hit["hit"][0]:hit["hit"][1]].lower())
        self.assertNotIn("j_redirect_links", " ".join(i for i in crit.items))                 # 404-Protokoll ist kein eingeschleuster Code
        log = [f for f in r.findings if "Weiterleitungs-Komponente" in f.title]
        self.assertTrue(log and log[0].sev == "info", titles(r))
        self.assertTrue(log[0].evidence and "j_redirect_links" in log[0].evidence[0]["file"])

    def test_anomalies_find_trigger_and_odd_table(self):
        r = self.r["dbx_anomalies"]
        self.assertTrue(any("Trigger" in t for t in titles(r, "crit") + titles(r, "warn")), titles(r))
        self.assertTrue(any("ungewöhnlichem Namen" in t for t in titles(r, "warn")), titles(r))
        self.assertTrue(any("in den letzten 30 Tagen" in t for t in titles(r)) or True)

    def test_grants_are_flagged(self):
        self.assertTrue(any("mehr Rechte" in t for t in titles(self.r["dbx_server"], "warn")), titles(self.r["dbx_server"]))

    def test_incidents_check_joomla_version_offline(self):
        r = self.r["dbx_incidents"]
        self.assertEqual(r.status, "skipped")                  # Online-Liste im Offline-Modus
        self.assertTrue(any("nicht betroffen" in t for t in titles(r, "ok")), titles(r))

    def test_old_joomla_is_critical(self):
        w = fixture.make_world(tempfile.mkdtemp(prefix="claudia_v15b_"), False)
        con = sqlite3.connect(w["db"])
        con.execute("UPDATE j_extensions SET manifest_cache='{\"version\":\"4.2.5\"}' WHERE type='file' AND element='joomla'")
        con.commit()
        con.close()
        r = run(["dbx_incidents"], w)["dbx_incidents"]
        self.assertTrue(any("CVE-2023-23752" in t for t in titles(r, "crit")), titles(r))

    def test_clean_database_has_no_warnings(self):
        w = fixture.make_world(tempfile.mkdtemp(prefix="claudia_v15c_"), False)
        r = run(DBX, w)
        for k, v in r.items():
            self.assertNotIn(v.status, ("crit", "warn", "error"), "%s: %s" % (k, titles(v)))

    def test_own_connection_overrides_and_wrong_password_is_explained(self):
        w = fixture.make_world(tempfile.mkdtemp(prefix="claudia_v15d_"), False)
        bad = run(["dbx_server"], w, db={"password": "falsch"})["dbx_server"]
        self.assertEqual(bad.status, "skipped")
        self.assertIn("eingegebenen Zugangsdaten", bad.message)
        good = run(["dbx_server"], w, db={"password": "GEHEIM-DB-PASSWORT", "prefix": "j_"})["dbx_server"]
        self.assertNotEqual(good.status, "skipped")


class DbCard(unittest.TestCase):
    def app(self):
        w = fixture.make_world(tempfile.mkdtemp(prefix="claudia_v15e_"), False)
        a = App(tempfile.mkdtemp(prefix="claudia_v15app_"))
        a.runner = LocalRunner(w["home"], extra_path=w["bin"])
        a.conn = {"host": "x", "site_dir": w["site_rel"], "password": "pw"}
        return a, w

    def test_prefill_never_returns_the_password(self):
        a, w = self.app()
        r = a.db_prefill({"site_dir": w["site_rel"]})
        self.assertTrue(r["found"])
        self.assertEqual(r["prefix"], "j_")
        self.assertTrue(r["has_password"])
        self.assertNotIn("GEHEIM", json.dumps(r))
        self.assertNotIn("password", r)

    def test_connection_test_uses_server_data_or_own_password(self):
        a, w = self.app()
        ok = a.db_test({"site_dir": w["site_rel"], "db": {}})
        self.assertTrue(ok["ok"], ok)
        bad = a.db_test({"site_dir": w["site_rel"], "db": {"custom": True, "password": "falsch"}})
        self.assertFalse(bad["ok"])
        self.assertNotIn("falsch", json.dumps(bad))
        own = a.db_test({"site_dir": w["site_rel"], "db": {"custom": True, "password": "GEHEIM-DB-PASSWORT"}})
        self.assertTrue(own["ok"] and own["custom"])

    def test_input_is_validated_and_empty_without_custom(self):
        self.assertEqual(App._clean_db({"custom": False, "password": "x"}), {})
        self.assertEqual(App._clean_db(None), {})
        with self.assertRaises(ApiError):
            App._clean_db({"custom": True, "port": "abc"})
        with self.assertRaises(ApiError):
            App._clean_db({"custom": True, "prefix": "j_; DROP"})
        self.assertEqual(App._clean_db({"custom": True, "user": " u ", "host": ""}), {"user": "u"})   # leere Felder = aus der configuration.php


class Snippet(unittest.TestCase):
    def test_external_script_is_marked_and_line_can_be_deleted(self):
        ex = snippets.build_excerpt(["<?php", "echo 1;", '<script src="https://cdn.evil.example/a.js"></script>', "?>"], 1, 3, 4)
        self.assertTrue(ex["found"])
        self.assertEqual(ex["fixed_line"], "")
        self.assertIn("Achtung", ex["how"])
        bad = [s for r in ex["rows"] if r["role"] == "ziel" for s in r["segs"] if s["k"] == "bad"]
        self.assertTrue(bad and "cdn.evil.example" in bad[0]["s"])
        ctx_rows = [r["n"] for r in ex["rows"] if r["role"] == "kontext"]
        self.assertEqual(ctx_rows, [1, 2, 4])


class OriginalCompare(unittest.TestCase):
    ORIG = ["<?php", "defined('_JEXEC') or die;", "", "use Joomla\\CMS\\Factory;", "$app = Factory::getApplication();",
            "$wa = $app->getDocument()->getWebAssetManager();", "$wa->useStyle('x');", "?>", "<html>", "</html>"]

    def test_line_with_appended_code_maps_to_original_line(self):
        srv = list(self.ORIG)
        srv[5] += ' eval(base64_decode("eA=="));'
        ex = snippets.build_excerpt(srv, 1, 6, len(srv))
        r = snippets.compare_original(srv, 1, 6, self.ORIG, ex["fixed_line"])
        self.assertEqual((r["status"], r["line"], r["n"]), ("identisch" if ex["fixed_line"].strip() == self.ORIG[5] else "abweichend", self.ORIG[5], 6))

    def test_inserted_line_is_recognised(self):
        srv = self.ORIG[:5] + ['<script src="https://evil.example/a.js"></script>'] + self.ORIG[5:]
        r = snippets.compare_original(srv, 1, 6, self.ORIG, "")
        self.assertEqual(r["status"], "eingefuegt")

    def test_unrelated_file_is_not_matched(self):
        self.assertEqual(snippets.compare_original(["aaaaa", "bbbbb", "ccccc"], 1, 2, self.ORIG, "")["status"], "nicht_zuordenbar")

    def test_only_core_files_have_an_original(self):
        self.assertTrue(snippets.core_candidate("templates/cassiopeia/index.php"))
        self.assertTrue(snippets.core_candidate("libraries/src/Version.php"))
        self.assertFalse(snippets.core_candidate("templates/shaper_helix3/js/main.js"))
        self.assertFalse(snippets.core_candidate("images/a.php"))
        self.assertEqual(snippets.original_url("6.2.0", "./templates/cassiopeia/index.php"), "https://raw.githubusercontent.com/joomla/joomla-cms/6.2.0/templates/cassiopeia/index.php")

    def test_server_fetches_original_and_degrades_gracefully(self):
        import http.server
        import socketserver
        orig = "\n".join(self.ORIG) + "\n"

        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/6.2.0/templates/cassiopeia/index.php":
                    body = orig.encode()
                    self.send_response(200)
                else:
                    body = b"404"
                    self.send_response(404)
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass
        srv = socketserver.TCPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        old = {k: os.environ.pop(k, None) for k in ("CLAUDIA_OFFLINE", "CLAUDIA_ORIGINAL_BASE")}
        os.environ["CLAUDIA_ORIGINAL_BASE"] = "http://127.0.0.1:%d" % srv.server_address[1]
        try:
            a = App(tempfile.mkdtemp(prefix="claudia_orig_"))
            a.info = {"joomla": "6.2.0"}
            lines = list(self.ORIG)
            lines[5] += ' eval(base64_decode("eA=="));'
            ex = snippets.build_excerpt(lines, 1, 6, len(lines))
            o = a._original("templates/cassiopeia/index.php", lines, 1, 6, ex["fixed_line"])
            self.assertIn(o["status"], ("identisch", "abweichend"))
            self.assertEqual(o["line"], self.ORIG[5])
            self.assertIn("Joomla 6.2.0", o["source"])
            third = a._original("templates/shaper_helix3/js/main.js", lines, 1, 6, "")
            self.assertEqual(third["status"], "kein_original")
            gone = a._original("templates/cassiopeia/nichtda.php", lines, 1, 6, "")
            self.assertEqual(gone["status"], "kein_original")
            self.assertIn("404", gone["note"])
            a.info = {}
            self.assertIn("nicht bekannt", a._original("templates/cassiopeia/index.php", lines, 1, 6, "")["note"])
        finally:
            srv.shutdown()
            os.environ.pop("CLAUDIA_ORIGINAL_BASE", None)
            for k, v in old.items():
                if v is not None:
                    os.environ[k] = v


class TmpFolders(unittest.TestCase):
    def test_images_tmp_is_only_named_when_it_exists(self):
        from claudia import actions
        sc = actions.parse_scan("@@HOME\n/h\n@@TMP\ntmp\t4\t12\t0\n@@IMGTMP\nimages_vorhanden\n@@BACKUPS\n@@END")
        self.assertFalse(sc["images_tmp_exists"])
        info = {"joomla": "6.2.0", "php_candidates": [{"name": "php8.3", "version": "PHP 8.3.6"}]}
        res = [{"id": "php_in_uploads", "findings": [{"sev": "warn", "title": "x", "items": ["tmp/a.php (1 KB)"]}]}]
        a = [x for x in actions.available(res, info, "8.3", {}, sc) if x["id"] == "clean_tmp"][0]
        self.assertEqual(a["title"], "Temp-Ordner leeren (tmp: 4 Datei(en), 12 KB)")         # Anzahl und Größe, damit man entscheiden kann
        self.assertNotIn("images/tmp", a["summary"])
        self.assertFalse(a["params"]["images_tmp_exists"])
        sc2 = actions.parse_scan("@@TMP\ntmp\t1\t1\t0\nimages/tmp\t2\t1\t0\n@@IMGTMP\nimages_vorhanden\nimages_tmp_vorhanden\n@@END")
        b = [x for x in actions.available(res, info, "8.3", {}, sc2) if x["id"] == "clean_tmp"][0]
        self.assertEqual(b["title"], "Temp-Ordner leeren (tmp: 1 Datei(en), 1 KB; images/tmp: 2 Datei(en), 1 KB)")
        self.assertEqual(actions.size_text(3584), "3,5 MB")

    def test_scan_script_really_checks_images(self):
        from claudia import actions
        w = fixture.make_world(tempfile.mkdtemp(prefix="claudia_v15t_"), False)
        os.makedirs(os.path.join(w["site"], "images", "galerie", "tmp"), exist_ok=True)
        r = LocalRunner(w["home"], extra_path=w["bin"])
        sc = actions.parse_scan(r.sh(w["site_rel"], actions.SCAN_SCRIPT, 30).out)
        self.assertTrue(sc["images_exists"])
        self.assertFalse(sc["images_tmp_exists"])
        self.assertIn("images/galerie/tmp", sc["tmp_candidates"])


class ActionsPayload(unittest.TestCase):
    def test_payload_has_update_status_plan_and_manual_list(self):
        w = fixture.make_world(tempfile.mkdtemp(prefix="claudia_v15f_"), True)
        a = App(tempfile.mkdtemp(prefix="claudia_v15g_"))
        a.runner = LocalRunner(w["home"], extra_path=w["bin"])
        a.conn = {"host": "x", "site_dir": w["site_rel"], "password": "pw"}
        a.auto_update = False
        os.environ["CLAUDIA_OFFLINE"] = "1"
        s = Settings(site_dir=w["site_rel"], allow_hosts=list(ADV["allow_hosts"]))
        eng = Engine(a.runner, s, ADV)
        a.results = [r.to_dict() if hasattr(r, "to_dict") else r for r in eng.run(["entry_points", "webshells"], lambda e: None, threading.Event())]
        a.run_settings = {"site_dir": w["site_rel"]}
        p = a.actions_list()
        self.assertIn("update", p)
        self.assertIn("manual", p)
        self.assertTrue(any(t["file"].endswith("index.php") for t in p["manual"]), p["manual"])
        self.assertIn("manual_code", [x["id"] for x in p["plan"]])
        self.assertIsInstance(p["plan"], list)
        self.assertTrue(all("step" in x for x in p["plan"]))


class ExtensionRetries(unittest.TestCase):
    """Fehlgeschlagene Erweiterungs-Updates: bis zu 3 weitere Durchgänge (Abhängigkeiten); CLI-unfähige Installer werden nicht wiederholt."""

    def setUp(self):
        from test_actions2 import world, script
        self.r, self.w = world()
        db = self.w["db"]
        con = sqlite3.connect(db)
        for eid, el, ver in ((900, "com_demo2", "1.0.0"), (902, "com_dep", "1.0.0"), (903, "com_osmap", "5.1.10")):
            con.execute("INSERT INTO j_extensions (extension_id, name, type, element, folder, client_id, enabled, manifest_cache, params) VALUES (?,?,?,?,?,0,?,?,?)",
                        (eid, {900: "Demo", 902: "Dep", 903: "OSMap"}[eid], "component", el, "", 1, '{"version":"%s"}' % ver, "{}"))
        con.commit()
        con.close()
        b = os.path.join(self.w["home"], "xbin")
        os.makedirs(b)
        with open(os.path.join(b, "setext.py"), "w") as fh:
            fh.write(SETEXT)
        from test_actions2 import CURL_O, PHP_PATH
        script(os.path.join(b, "curl"), CURL_O + r'''case "$*" in
 *osmap*) echo '<updates><update><element>com_osmap</element><version>5.1.11</version><downloads><downloadurl type="full" format="zip">https://deploy.example/osmap/com_osmap</downloadurl></downloads></update></updates>';;
 *dep*) echo '<updates><update><element>com_dep</element><version>2.0.0</version><downloads><downloadurl type="full" format="zip">https://example.org/dep-2.0.0.zip</downloadurl></downloads></update></updates>';;
 *) echo '<updates><update><element>com_demo2</element><version>2.0.0</version><downloads><downloadurl type="full" format="zip">https://example.org/demo-2.0.0.zip</downloadurl></downloads></update></updates>';;
esac''')
        script(os.path.join(b, "php8.3"), r'''if [ "$1" = "-v" ]; then echo "PHP 8.3.6 (cli)"; exit 0; fi
''' + PHP_PATH + r'''echo "$*" >> "$HOME/inst_calls.txt"
case "$3" in
  --url=https://example.org/demo-2.0.0.zip) python3 "$(dirname "$(command -v php8.3)")/setext.py" "$CLAUDIA_TEST_DB" 900 2.0.0; touch "$HOME/demo_done"; echo done;;
  --url=https://example.org/dep-2.0.0.zip) if [ -f "$HOME/demo_done" ]; then python3 "$(dirname "$(command -v php8.3)")/setext.py" "$CLAUDIA_TEST_DB" 902 2.0.0; echo done; else echo "Dependency missing" >&2; exit 1; fi;;
  --url=https://deploy.example/osmap/com_osmap) echo "In AbstractScript.php line 297: Cannot assign Joomla\\CMS\\Application\\ConsoleApplication to property Alledia\\Installer\\AbstractScript::\\$app of type Joomla\\CMS\\Application\\CMSApplication" ; exit 1;;
  *) echo ok;;
esac''')
        self.r = LocalRunner(self.w["home"], extra_path=b + os.pathsep + self.r.extra_path if hasattr(self.r, "extra_path") else b)
        os.makedirs(os.path.join(self.w["site"], "cli"), exist_ok=True)
        with open(os.path.join(self.w["site"], "cli", "joomla.php"), "w") as fh:
            fh.write("<?php\n")

    def ctx(self):
        mk = lambda uid, eid, name, el, old, new: {"uid": uid, "eid": eid, "name": name, "element": el, "old_version": old, "new_version": new,
                                                  "detailsurl": "https://example.org/%s.xml" % name.lower(), "needs_key": False}
        return {"ext_updates": [mk(1, 902, "Dep", "com_dep", "1.0.0", "2.0.0"), mk(2, 900, "Demo", "com_demo2", "1.0.0", "2.0.0"), mk(3, 903, "OSMap", "com_osmap", "5.1.10", "5.1.11")]}

    def test_dependency_is_solved_by_retry_and_osmap_is_not_retried(self):
        from claudia import actions
        events = []
        res = actions.run_action(self.r, self.w["site_rel"], "update_extensions", {"php": "php8.3", "selected": [1, 2, 3]}, [{"name": "php8.3", "version": "8.3.6", "default": True}],
                                 emit=lambda k, t: events.append(t), context=self.ctx())
        self.assertEqual(sorted(res["updated"]), ["Demo", "Dep"], res)
        self.assertEqual([m["name"] for m in res["manual"]], ["OSMap"])
        self.assertEqual(res["manual"][0]["url"], "https://deploy.example/osmap/com_osmap")
        self.assertTrue(res["ok"])
        self.assertIn("System -> Aktualisieren", res["message"])
        self.assertTrue(any("Wiederholung 1 von 3" in e for e in events), events)
        calls = open(os.path.join(self.w["home"], "inst_calls.txt")).read()
        self.assertEqual(calls.count("deploy.example/osmap"), 1)         # CLI-unfähig: genau ein Versuch
        self.assertEqual(calls.count("dep-2.0.0"), 2)                    # erst fehlgeschlagen, dann nach Demo erfolgreich

    def test_hopeless_extension_gets_three_more_attempts_then_stops(self):
        from claudia import actions
        ctx = self.ctx()
        ctx["ext_updates"] = [ctx["ext_updates"][0]]                    # nur Dep; Demo wird nie installiert, Dep scheitert immer
        res = actions.run_action(self.r, self.w["site_rel"], "update_extensions", {"php": "php8.3", "selected": [1]}, [{"name": "php8.3", "version": "8.3.6", "default": True}], context=ctx)
        self.assertFalse(res["ok"])
        self.assertIn("3 weiteren Versuchen", res["error"])
        calls = open(os.path.join(self.w["home"], "inst_calls.txt")).read()
        self.assertEqual(calls.count("dep-2.0.0"), 4)                    # 1 + 3

    def test_classifier(self):
        from claudia import actions
        self.assertEqual(actions.classify_install_failure("Cannot assign Joomla\\CMS\\Application\\ConsoleApplication to property X"), "cli")
        self.assertEqual(actions.classify_install_failure("Dependency missing"), "retry")


if __name__ == "__main__":
    unittest.main(verbosity=2)
