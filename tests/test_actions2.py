"""Neue Aktionen: tmp leeren, schädliche JCE-Profile löschen, Hintertüren entfernen, Erweiterungs-Updates, Statusfenster-Ereignisse."""
import json
import os
import sqlite3
import stat
import sys
import tarfile
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

import fixture  # noqa: E402
from claudia import actions  # noqa: E402
from claudia.runner import LocalRunner  # noqa: E402
from claudia.server import ApiError, App  # noqa: E402

CHOICES = [{"name": "php8.3", "version": "8.3.6", "default": True}]
XML = """<?xml version="1.0"?><updates>
 <update><name>Demo</name><element>com_demo2</element><version>1.0.0</version><downloads><downloadurl type="full" format="zip">https://example.org/old.zip</downloadurl></downloads></update>
 <update><name>Demo</name><element>com_demo2</element><version>2.0.0</version><downloads><downloadurl type="full" format="zip">https://example.org/demo-2.0.0.zip</downloadurl></downloads></update>
</updates>"""


# curl-Ersatz: mit -o DATEI wird ein "Paket" geschrieben (PK + Adresse), sonst das Manifest ausgegeben
CURL_O = r'''out=""; url=""; for a in "$@"; do if [ "$prev" = "-o" ]; then out="$a"; fi; case "$a" in -*) ;; *) [ "$prev" = "-o" ] || url="$a";; esac; prev="$a"; done
if [ -n "$out" ]; then printf 'PK%s' "$url" > "$out"; exit 0; fi
'''
# php-Ersatz: extension:install --path=DATEI wird auf die Adresse im "Paket" zurückgeführt
PHP_PATH = r'''case "$3" in --path=*) set -- "$1" "$2" "--url=$(tail -c +3 "${3#--path=}")";; esac
'''


def script(path, body):
    with open(path, "w") as fh:
        fh.write("#!/bin/bash\n" + body + "\n")
    os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC)


def world(infected=False):
    w = fixture.make_world(tempfile.mkdtemp(prefix="claudia_b_"), infected)
    b = tempfile.mkdtemp(prefix="claudia_bbin_")
    db = w["db"]
    script(os.path.join(b, "mysqldump"), 'for a in "$@"; do case "$a" in --connect-timeout*|--max-allowed-packet*|--no-tablespaces-x) echo "mysqldump: [ERROR] unknown variable ${a#--}" >&2; exit 7;; --no-tablespaces) [ -n "$CLAUDIA_REJECT_NOTBS" ] && { echo "mysqldump: unknown option --no-tablespaces" >&2; exit 7; };; esac; done; cat >/dev/null; for i in $(seq 1 400); do echo "INSERT INTO x VALUES ($i,\'abcdefghijklmnopqrstuvwxyz\');"; done')
    script(os.path.join(b, "curl"), CURL_O + "cat <<'EOF'\n%s\nEOF" % XML)
    with open(os.path.join(b, "setver.py"), "w") as fh:
        fh.write("import sqlite3, sys\nc = sqlite3.connect(sys.argv[1])\n"
                 "c.execute('UPDATE j_extensions SET manifest_cache=? WHERE extension_id=900', ('{\"version\":\"2.0.0\"}',))\nc.commit()\n")
    script(os.path.join(b, "php8.3"), r'''
if [ "$1" = "-v" ]; then echo "PHP 8.3.6 (cli)"; exit 0; fi
case "$3" in --path=*) set -- "$1" "$2" "--url=$(tail -c +3 "${3#--path=}")";; esac
echo "php $*" >> "$HOME/php_calls.txt"
case "$2" in
  extension:install)
    case "$3" in
      --url=https://example.org/demo-2.0.0.zip) python3 "$(dirname "$(command -v php8.3)")/setver.py" "$CLAUDIA_TEST_DB"; echo "Extension installed successfully.";;
      *) echo "unbekannte Adresse $3" >&2; exit 1;;
    esac;;
  update:extensions:check) echo "Found";;
  cache:clean) echo "Cache cleaned";;
esac''')
    return LocalRunner(w["home"], extra_path=b + os.pathsep + w["bin"]), w


def sql(w, q, *a):
    c = sqlite3.connect(w["db"])
    c.execute(q, a)
    c.commit()
    c.close()


def rows(w, q, *a):
    c = sqlite3.connect(w["db"])
    r = c.execute(q, a).fetchall()
    c.close()
    return r


class Parse(unittest.TestCase):
    def test_core_check(self):
        self.assertEqual(actions.parse_core_check("New Joomla version 6.2.1 is available.", "6.2.0"), {"has_update": True, "latest": "6.2.1"})
        self.assertEqual(actions.parse_core_check("Update available: 6.2.1", "6.2.0")["has_update"], True)
        self.assertEqual(actions.parse_core_check("You already have the latest Joomla version 6.2.0", "6.2.0")["has_update"], False)
        self.assertIsNone(actions.parse_core_check("ok", "6.2.0"))

    def test_pick_download_takes_exact_version_and_https_only(self):
        self.assertEqual(actions.pick_download(XML, "2.0.0"), "https://example.org/demo-2.0.0.zip")
        self.assertEqual(actions.pick_download(XML, "9.9.9"), "")
        self.assertEqual(actions.pick_download(XML.replace("https://example.org/demo-2.0.0.zip", "http://example.org/x.zip"), "2.0.0"), "")
        self.assertEqual(actions.pick_download("<!DOCTYPE x [<!ENTITY a 'b'>]><updates/>", "1"), "")
        self.assertEqual(actions.pick_download("kein xml", "1"), "")

    def test_mask_hides_keys_and_password(self):
        t = actions.Traced(None, lambda k, x: None, ["GEHEIM"])
        self.assertNotIn("GEHEIM", t.mask("x GEHEIM y"))
        self.assertNotIn("abc123", t.mask("https://a.b/c.zip?dlid=abc123&x=1"))


class Available(unittest.TestCase):
    INFO = {"php": "", "php_candidates": [{"name": "php8.3", "version": "PHP 8.3.6"}]}

    def ids(self, res, update=None):
        return [a["id"] for a in actions.available(res, self.INFO, "8.3", update)]

    def test_core_update_only_with_update(self):
        self.assertNotIn("core_update", self.ids([]))
        older = [{"id": "joomla_info", "findings": [{"sev": "warn", "title": "Joomla ist älter als die neueste bekannte Version (6.2.5)", "items": []}]}]
        self.assertIn("core_update", self.ids(older))
        self.assertIn("core_update", self.ids([], {"checked": True, "has_update": True, "latest": "6.3.0"}))
        self.assertNotIn("core_update", self.ids(older, {"checked": True, "has_update": False}))
        self.assertNotIn("core_update", self.ids([], {"checked": True, "has_update": None}))

    def test_update_extensions_offered_only_for_free_updates(self):
        ups = [{"uid": 1, "name": "A", "old_version": "1.0.0", "new_version": "1.1.0", "detailsurl": "https://a.example/u.xml", "needs_key": False, "type": "component"},
               {"uid": 2, "name": "B", "old_version": "1.0.0", "new_version": "2.0.0", "detailsurl": "https://b.example/u.xml", "needs_key": True, "type": "plugin"}]
        a = [x for x in actions.available([], self.INFO, "8.3", {"checked": True, "ext_updates": ups}) if x["id"] == "update_extensions"][0]
        self.assertEqual([u["uid"] for u in a["params"]["updates"]], [1])
        self.assertTrue(a["backup"])
        self.assertNotIn("update_extensions", self.ids([], {"checked": True, "ext_updates": [ups[1]]}))
        major = [x for x in actions.available([], self.INFO, "8.3", {"checked": True, "ext_updates": [dict(ups[1], needs_key=False)]}) if x["id"] == "update_extensions"][0]
        self.assertTrue(major["params"]["updates"][0]["major"])

    def test_cleanup_actions_come_from_findings(self):
        res = [{"id": "db_jce", "findings": [{"sev": "crit", "title": "3 JCE-Profil(e) erwähnen 'php' in den Einstellungen",
                                                "items": ["#6 jce_exploit: ...php,php3", "#7 cve48907_x: ...php,phtml"]}]},
               {"id": "webshells", "findings": [{"sev": "crit", "title": "4 Datei(en) mit typischen Hintertür-Mustern",
                                                  "items": ["./mac.php - 15:base64_decode('B/1N", "./images/jce_pwn.php - 1:shell_exec($_GET", "./tmp/x.xml.php - 1:system($_GET"]}]},
               {"id": "php_in_uploads", "findings": [{"sev": "crit", "title": "299 PHP-Datei(en) in images/files/tmp",
                                                      "items": ["images/jce_x.php  (2026-06-22 05:22, 638 Byte)", "tmp/a.php  (2026-04-22 06:49, 5669 Byte)"]}]}]
        av = {a["id"]: a for a in actions.available(res, self.INFO, "8.3")}
        self.assertEqual(av["remove_jce_profiles"]["params"]["ids"], [6, 7])
        self.assertEqual(av["remove_shells"]["params"]["files"], ["./mac.php", "./images/jce_pwn.php"])      # tmp-Dateien erledigt 'tmp leeren'
        self.assertTrue(av["remove_shells"]["params"]["images"])
        self.assertIn("clean_tmp", av)
        self.assertNotIn("clean_tmp", self.ids([]))
        self.assertNotIn("remove_jce_profiles", self.ids([]))


class CleanTmp(unittest.TestCase):
    def test_backup_first_then_empty_keep_index(self):
        r, w = world()
        tmp = os.path.join(w["site"], "tmp")
        os.makedirs(os.path.join(tmp, "install_x", "sub"), exist_ok=True)
        open(os.path.join(tmp, "index.html"), "w").write("<html></html>")
        open(os.path.join(tmp, ".htaccess"), "w").write("Require all denied")
        open(os.path.join(tmp, "joomla.xml.php"), "w").write("<?php system($_GET['c']);")
        open(os.path.join(tmp, "install_x", "sub", "a.zip"), "w").write("zipzip")
        res = actions.run_action(r, w["site_rel"], "clean_tmp", {}, [])
        self.assertTrue(res["ok"], res)
        self.assertEqual(sorted(os.listdir(tmp)), [".htaccess", "index.html"])
        names = tarfile.open(os.path.join(res["backup_dir"], "tmp.tgz")).getnames()
        self.assertIn("tmp/joomla.xml.php", names)
        self.assertIn("tmp/install_x/sub/a.zip", names)
        titles = [s["title"] for s in res["steps"]]
        self.assertTrue(titles[0].startswith("Inhalt von tmp sichern") and titles[-1] == "Ordner leeren")
        self.assertIn("geleert", res["message"])

    def test_symlinked_tmp_is_refused(self):
        r, w = world()
        tmp = os.path.join(w["site"], "tmp")
        target = tempfile.mkdtemp(prefix="claudia_tmpt_")
        open(os.path.join(target, "wichtig.txt"), "w").write("x")
        if os.path.isdir(tmp):
            import shutil
            shutil.rmtree(tmp)
        os.symlink(target, tmp)
        res = actions.run_action(r, w["site_rel"], "clean_tmp", {}, [])
        self.assertFalse(res["ok"])
        self.assertTrue(os.path.exists(os.path.join(target, "wichtig.txt")))


class JceProfiles(unittest.TestCase):
    def test_deletes_only_bad_ones_and_protects_defaults(self):
        r, w = world(infected=True)
        sql(w, "INSERT INTO j_wf_profiles (id,name,description,users,types,components,area,device,rows,plugins,published,ordering,params) VALUES (6,'jce_exploit','x','','','',0,'desktop','','',1,6,?)", '{"upload":1,"extensions":"php,phtml"}')
        sql(w, "UPDATE j_wf_profiles SET params=? WHERE id=1", '{"x":"php"}')
        before = {x[0] for x in rows(w, "SELECT id FROM j_wf_profiles")}
        res = actions.run_action(r, w["site_rel"], "remove_jce_profiles", {"ids": [6, 1]}, [])
        self.assertTrue(res["ok"], res)
        after = {x[0] for x in rows(w, "SELECT id FROM j_wf_profiles")}
        self.assertEqual(before - after, {6})                      # nur das schädliche Profil; 'Default' bleibt, auch mit 'php'
        self.assertTrue(os.path.getsize(os.path.join(res["backup_dir"], "wf_profiles.sql.gz")) > 100)
        self.assertEqual([s["title"] for s in res["steps"]][-3:], ["Tabelle der JCE-Profile sichern", "Profile löschen", "Kontrolle"])

    def test_no_backup_no_delete(self):
        r, w = world(infected=True)
        sql(w, "INSERT INTO j_wf_profiles (id,name,description,users,types,components,area,device,rows,plugins,published,ordering,params) VALUES (6,'jce_exploit','x','','','',0,'desktop','','',1,6,?)", '{"extensions":"php"}')
        broken = tempfile.mkdtemp(prefix="claudia_nodump_")
        script(os.path.join(broken, "mysqldump"), "echo kaputt >&2; exit 2")          # Sicherung scheitert
        r2 = LocalRunner(w["home"], extra_path=broken + os.pathsep + w["bin"])
        res = actions.run_action(r2, w["site_rel"], "remove_jce_profiles", {"ids": [6]}, [])
        self.assertFalse(res["ok"])
        self.assertEqual(len(rows(w, "SELECT id FROM j_wf_profiles WHERE id=6")), 1)       # ohne Sicherung wird nichts gelöscht


def _has(cmd):
    import shutil
    return shutil.which(cmd) is not None


class Shells(unittest.TestCase):
    def test_moves_listed_and_images_php_into_quarantine(self):
        r, w = world()
        s = w["site"]
        os.makedirs(os.path.join(s, "images", "sub"), exist_ok=True)
        for rel, body in (("mac.php", "<?php eval(base64_decode('x'));"), ("images/jce_pwn.php", "<?php system($_GET[1]);"),
                          ("images/sub/u.jpg.php", "<?php 1;"), ("images/ok.jpg", "JPEGDATA"), ("images/index.php", ""), ("legit.php", "<?php echo 1;")):
            open(os.path.join(s, rel), "w").write(body)
        res = actions.run_action(r, w["site_rel"], "remove_shells", {"files": ["./mac.php", "./legit.php"], "images": True}, [], allowed_files=["./mac.php"])
        self.assertTrue(res["ok"], res)
        self.assertFalse(os.path.exists(os.path.join(s, "mac.php")))
        self.assertFalse(os.path.exists(os.path.join(s, "images", "jce_pwn.php")))
        self.assertFalse(os.path.exists(os.path.join(s, "images", "sub", "u.jpg.php")))
        self.assertTrue(os.path.exists(os.path.join(s, "images", "ok.jpg")))            # Bilder bleiben
        self.assertTrue(os.path.exists(os.path.join(s, "images", "index.php")))         # leere Platzhalter bleiben
        self.assertTrue(os.path.exists(os.path.join(s, "legit.php")))                   # nicht gemeldet -> bleibt
        held = sorted(os.listdir(os.path.join(res["backup_dir"], "d")))          # verschoben, nicht gelöscht
        self.assertEqual(held, ["0001.q", "0002.q", "0003.q"])
        self.assertIn("mac.php", open(os.path.join(res["backup_dir"], "QUARANTAENE.txt"), encoding="utf-8").read())

    def test_pick_removes_only_selected_and_writes_list(self):
        r, w = world()
        s = w["site"]
        os.makedirs(os.path.join(s, "images", "sub"), exist_ok=True)
        for rel, body in (("mac.php", "<?php eval(1);"), ("other.php", "<?php eval(2);"), ("images/a.php", "<?php 1;"), ("images/b.php", "<?php 2;"), ("images/ok.jpg", "J")):
            open(os.path.join(s, rel), "w").write(body)
        params = {"files": ["./mac.php", "./other.php"], "images": True, "selected_pick": ["f:./mac.php", "f:./images/a.php", "f:./images/ok.jpg", "f:../x.php", "f:./other.php.bak"]}
        res = actions.run_action(r, w["site_rel"], "remove_shells", params, [], allowed_files=["./mac.php", "./other.php"])
        self.assertTrue(res["ok"], res)
        self.assertFalse(os.path.exists(os.path.join(s, "mac.php")))
        self.assertFalse(os.path.exists(os.path.join(s, "images", "a.php")))
        for keep in ("other.php", "images/b.php", "images/ok.jpg"):      # nicht angehakt, oder kein PHP: bleibt
            self.assertTrue(os.path.exists(os.path.join(s, keep)), keep)
        self.assertEqual(len(os.listdir(os.path.join(res["backup_dir"], "d"))), 2)
        lst = open(os.path.join(res["backup_dir"], "QUARANTAENE.txt"), encoding="utf-8").read()
        self.assertIn("./mac.php", lst)
        self.assertIn("./images/a.php", lst)
        self.assertNotIn("other.php", lst)
        row = [l for l in lst.splitlines() if l.endswith("./mac.php")][0].split("\t")
        import hashlib
        self.assertEqual(row[1], hashlib.sha256(b"<?php eval(1);").hexdigest())
        self.assertEqual(row[2], str(len("<?php eval(1);")))

    def test_pick_list_offered_and_preview_follows_selection(self):
        res = [{"id": "webshells", "findings": [{"sev": "crit", "title": "2 Datei(en) mit typischen Hintertür-Mustern", "items": ["./mac.php - 15:base64_decode('B/1N"]}]},
               {"id": "php_in_uploads", "findings": [{"sev": "crit", "title": "2 PHP-Datei(en) in images/files/tmp", "items": ["images/x.php  (2026-06-22 05:22, 638 Byte)"]}]}]
        a = [x for x in actions.available(res, {"cms": "joomla"}, "8.3") if x["id"] == "remove_shells"][0]
        keys = [x["key"] for x in a["params"]["pick"]]
        self.assertEqual(keys, ["f:./mac.php", "f:./images/x.php"])
        pv = actions.commands_preview("remove_shells", {"files": ["./mac.php"], "images": True, "selected_pick": ["f:./mac.php"]}, [])
        self.assertTrue(any(l.startswith("mv -n -- ./mac.php ~/claudia-quarantaene-<datum>/d/") for l in pv))
        self.assertFalse(any(l.startswith("rm ") for l in pv))                          # nichts wird gelöscht
        self.assertFalse(any("find " in l for l in pv))
        self.assertTrue(any("QUARANTAENE.txt" in l for l in pv))

    def test_symlinks_and_traversal_are_ignored(self):
        r, w = world()
        s = w["site"]
        outside = os.path.join(os.path.dirname(s), "..", "outside.php")
        open(os.path.abspath(outside), "w").write("<?php")
        os.symlink(os.path.abspath(outside), os.path.join(s, "link.php"))
        res = actions.run_action(r, w["site_rel"], "remove_shells", {"files": ["./link.php", "../outside.php", "./../outside.php"]}, [])
        self.assertTrue(os.path.exists(os.path.abspath(outside)))
        self.assertTrue(os.path.islink(os.path.join(s, "link.php")))
        self.assertTrue(res["ok"] or res.get("error"))


class CheckedPackageInstall(unittest.TestCase):
    """JCE 3.0.6 scheiterte mit 'Unable to install extension': Joomla erkennt bei Adressen wie index.php?...&file=pkg.zip die Datei nicht.
    Jetzt: Paket in tmp/ laden, ZIP prüfen, Prüfsumme des Herstellers vergleichen, aus der Datei installieren."""
    URL = "https://www.joomlacontenteditor.net/index.php?option=com_releases&task=update.download&file=pkg_jce_306.zip"

    def setUp(self):
        self.r, self.w = world()
        os.makedirs(os.path.join(self.w["site"], "cli"), exist_ok=True)
        open(os.path.join(self.w["site"], "cli", "joomla.php"), "w").write("<?php\n")
        b = self.r.extra_path.split(os.pathsep)[0]
        script(os.path.join(b, "php8.3"), PHP_PATH + 'echo "php $*" >> "$HOME/php_calls.txt"; echo "Extension installed successfully."')
        self.steps = []

    def run_install(self, sha256):
        import hashlib
        best = {"version": "3.0.6", "url": self.URL, "sha256": sha256, "sha512": ""}
        return actions._joomla_install_checked(self.r, self.w["site_rel"], "php8.3", best,
                                               lambda t, ok, out: self.steps.append((t, ok, out)), require_sum=True)

    def calls(self):
        p = os.path.join(self.w["home"], "php_calls.txt")
        return open(p).read() if os.path.exists(p) else ""

    def test_matching_checksum_installs_from_local_file(self):
        import hashlib
        r = self.run_install(hashlib.sha256(("PK" + self.URL).encode()).hexdigest())
        self.assertEqual(r.rc, 0, r.out)
        self.assertIn("Prüfsumme (sha256) stimmt", r.out)
        self.assertIn("extension:install --url=" + self.URL, self.calls())      # Ersatz-php: --path auf die Adresse im Paket zurückgeführt
        self.assertEqual([f for f in os.listdir(os.path.join(self.w["site"], "tmp")) if f.startswith("claudia-ext-")], [])   # Paket wieder gelöscht

    def test_wrong_checksum_never_installs(self):
        r = self.run_install("0" * 64)
        self.assertEqual(r.rc, 44)
        self.assertEqual(self.calls(), "")
        self.assertFalse(self.steps[-1][1])

    def test_sums_for_version(self):
        xml = ("<updates><update><version>3.0.6</version><sha256>%s</sha256></update>"
               "<update><version>2.9.99.15</version><sha256>%s</sha256></update></updates>") % ("a" * 64, "b" * 64)
        self.assertEqual(actions.sums_for_version(xml, "3.0.6")["sha256"], "a" * 64)
        self.assertEqual(actions.sums_for_version(xml, "9.9.9"), {"sha256": "", "sha512": ""})


class UpdateExtensions(unittest.TestCase):
    def setUp(self):
        self.r, self.w = world()
        sql(self.w, "INSERT INTO j_extensions (extension_id,name,type,element,folder,client_id,enabled,manifest_cache,params) VALUES (900,'Demo','component','com_demo2','',1,1,?,'{}')", '{"version":"1.0.0"}')
        sql(self.w, "INSERT INTO j_extensions (extension_id,name,type,element,folder,client_id,enabled,manifest_cache,params) VALUES (901,'Paid','component','com_paid','',1,1,?,'{}')", '{"version":"1.0.0"}')
        c = sqlite3.connect(self.w["db"])
        c.execute("CREATE TABLE j_updates (update_id INTEGER PRIMARY KEY, update_site_id INTEGER, extension_id INTEGER, name TEXT, description TEXT, element TEXT, type TEXT, folder TEXT, client_id INTEGER, version TEXT, data TEXT, detailsurl TEXT, infourl TEXT, extra_query TEXT)")
        c.execute("INSERT INTO j_updates VALUES (1,1,900,'Demo','', 'com_demo2','component','',1,'2.0.0','','https://example.org/demo.xml','','')")
        c.execute("INSERT INTO j_updates VALUES (2,1,901,'Paid','', 'com_paid','component','',1,'3.0.0','','https://example.org/paid.xml','','dlid=SECRET123')")
        c.execute("INSERT INTO j_updates VALUES (3,1,700,'Joomla','', 'joomla','file','',0,'6.2.1','','https://update.joomla.org/x.xml','','')")
        c.commit()
        c.close()
        os.makedirs(os.path.join(self.w["site"], "cli"), exist_ok=True)
        open(os.path.join(self.w["site"], "cli", "joomla.php"), "w").write("<?php\n")

    def test_check_lists_updates_without_core_and_marks_keys(self):
        res = actions.run_action(self.r, self.w["site_rel"], "check_updates", {"php": "php8.3"}, CHOICES, context={"joomla": "6.2.0"})
        ups = {u["name"]: u for u in res["ext_updates"]}
        self.assertEqual(sorted(ups), ["Demo", "Paid"])             # Joomla selbst gehört nicht in die Erweiterungsliste
        self.assertEqual((ups["Demo"]["old_version"], ups["Demo"]["new_version"], ups["Demo"]["needs_key"]), ("1.0.0", "2.0.0", False))
        self.assertTrue(ups["Paid"]["needs_key"])
        self.assertNotIn("SECRET123", json.dumps(res))

    def test_update_runs_backup_first_installs_and_verifies(self):
        ctx = {"ext_updates": [{"uid": 1, "eid": 900, "name": "Demo", "element": "com_demo2", "old_version": "1.0.0", "new_version": "2.0.0",
                                "detailsurl": "https://example.org/demo.xml", "needs_key": False},
                               {"uid": 2, "eid": 901, "name": "Paid", "element": "com_paid", "old_version": "1.0.0", "new_version": "3.0.0",
                                "detailsurl": "https://example.org/paid.xml", "needs_key": True}]}
        events = []
        res = actions.run_action(self.r, self.w["site_rel"], "update_extensions", {"php": "php8.3", "selected": [1, 2]}, CHOICES,
                                 emit=lambda k, t: events.append((k, t)), context=ctx)
        self.assertTrue(res["ok"], res)
        self.assertEqual(res["updated"], ["Demo"])
        titles = [s["title"] for s in res["steps"]]
        self.assertLess(titles.index("Sicherung prüfen"), titles.index("Installieren: Demo"))
        self.assertIn("Version kontrollieren: Demo", titles)
        calls = open(os.path.join(self.w["home"], "php_calls.txt")).read()
        self.assertIn("extension:install --url=https://example.org/demo-2.0.0.zip", calls)     # Paket von dieser Adresse, installiert per --path
        self.assertNotIn("paid", calls)                              # Erweiterung mit Download-Schlüssel wird nie angefasst
        self.assertEqual(rows(self.w, "SELECT json_extract(manifest_cache,'$.version') FROM j_extensions WHERE extension_id=900")[0][0], "2.0.0")
        kinds = [k for k, _ in events]
        self.assertEqual(kinds[0], "info")
        self.assertIn("cmd", kinds)
        self.assertIn("out", kinds)
        self.assertEqual(kinds[-1], "done")

    def test_failed_install_stops_and_reports(self):
        ctx = {"ext_updates": [{"uid": 1, "eid": 900, "name": "Demo", "element": "com_demo2", "old_version": "1.0.0", "new_version": "7.7.7",
                                "detailsurl": "https://example.org/demo.xml", "needs_key": False}]}
        res = actions.run_action(self.r, self.w["site_rel"], "update_extensions", {"php": "php8.3", "selected": [1]}, CHOICES, context=ctx)
        self.assertFalse(res["ok"])                                  # Version 7.7.7 steht nicht im Manifest
        self.assertEqual(rows(self.w, "SELECT json_extract(manifest_cache,'$.version') FROM j_extensions WHERE extension_id=900")[0][0], "1.0.0")

    def test_only_selected_known_ids_are_used(self):
        res = actions.run_action(self.r, self.w["site_rel"], "update_extensions", {"php": "php8.3", "selected": [99]}, CHOICES, context={"ext_updates": []})
        self.assertFalse(res["ok"])


class StatusWindow(unittest.TestCase):
    def test_job_streams_commands_and_server_answers(self):
        r, w = world()
        app = App(tempfile.mkdtemp(prefix="claudia_sw_"))
        app.runner = r
        app.conn = {"host": "x", "site_dir": w["site_rel"], "password": "GEHEIM-DB-PASSWORT"}
        app.info = {"php": "", "php_candidates": [{"name": "php8.3", "version": "PHP 8.3.6"}], "joomla": "6.2.0"}
        res = app.action_run({"id": "clear_cache", "php": "php8.3", "confirm": True})
        self.assertTrue(res["ok"])
        st = app.action_state(0)
        self.assertTrue(st["done"] and st["ok"])
        kinds = [e["t"] for e in st["events"]]
        self.assertEqual(kinds[0], "info")
        self.assertEqual(kinds[-1], "done")
        self.assertIn("cache:clean", " ".join(e["text"] for e in st["events"] if e["t"] == "cmd"))
        self.assertIn("Cache cleaned", " ".join(e["text"] for e in st["events"] if e["t"] == "out"))
        self.assertNotIn("GEHEIM-DB-PASSWORT", json.dumps(st))
        self.assertEqual(app.action_state(st["next"])["events"], [])          # nur Neues wird nachgeliefert
        self.assertTrue(os.path.isfile(res["log"]))
        with self.assertRaises(ApiError):
            app.action_start({"id": "clear_cache", "php": "php8.3"})           # ohne Bestätigung

    def test_check_sets_update_state_and_unlocks_actions(self):
        r, w = world()
        app = App(tempfile.mkdtemp(prefix="claudia_sw2_"))
        app.runner = r
        app.conn = {"host": "x", "site_dir": w["site_rel"], "password": "GEHEIM-DB-PASSWORT"}
        app.info = {"php": "", "php_candidates": [{"name": "php8.3", "version": "PHP 8.3.6"}], "joomla": "6.2.0"}
        os.makedirs(os.path.join(w["site"], "cli"), exist_ok=True)
        open(os.path.join(w["site"], "cli", "joomla.php"), "w").write("<?php\n")
        # php-Attrappe meldet ein Joomla-Update
        script(os.path.join(w["bin"], "php8.3"), 'if [ "$1" = "-v" ]; then echo "PHP 8.3.6"; exit 0; fi\ncase "$2" in core:check-updates) echo "New Joomla version 6.2.1 is available.";; *) echo ok;; esac')
        app.runner = LocalRunner(w["home"], extra_path=w["bin"])
        self.assertNotIn("core_update", [a["id"] for a in app.actions_list()["actions"]])
        app.action_run({"id": "check_updates", "php": "php8.3", "confirm": True})
        self.assertEqual((app.update_state["checked"], app.update_state["has_update"], app.update_state["latest"]), (True, True, "6.2.1"))
        self.assertIn("core_update", [a["id"] for a in app.actions_list()["actions"]])


if __name__ == "__main__":
    unittest.main(verbosity=2)
