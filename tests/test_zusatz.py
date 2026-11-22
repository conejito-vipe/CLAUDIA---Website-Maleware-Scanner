"""Zusatzprüfungen 2.15.0: versteckter WordPress-Code, versteckte Optionen, bekannte Joomla-Angriffe, Spam-Sitemaps, WebSocket-Skimmer, Shared Memory."""
import os
import subprocess
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "fake_paramiko"))
sys.path.insert(0, os.path.dirname(HERE))

from claudia.checks import konto, skimmer, zusatz  # noqa: E402
from claudia.util import split_sections  # noqa: E402


def sh(script, cwd):
    return subprocess.run(["bash", "-c", script], cwd=cwd, capture_output=True, text=True).stdout


def sevs(rows):
    return [r[0] for r in rows]


class WpHidden(unittest.TestCase):
    def world(self, files):
        d = tempfile.mkdtemp(prefix="zus_")
        for path, body in files.items():
            p = os.path.join(d, path)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "w") as fh:
                fh.write(body)
        return d

    def run_script(self, d):
        return zusatz.evaluate_wp_hidden(split_sections(sh(zusatz.WP_HIDDEN_SCRIPT.replace("@KNOWN@", " ".join(zusatz.WP_KNOWN_PATHS)), d)))

    def test_clean(self):
        d = self.world({"wp-content/index.php": "<?php // x", "wp-content/plugins/akismet/akismet.php": "<?php /* a */"})
        self.assertEqual(self.run_script(d), [])

    def test_hidden_user_and_dropin(self):
        d = self.world({"wp-content/mu-plugins/widget-cache.php": "<?php add_action('pre_user_query', function(){}); add_filter('views_users', 'x');",
                        "wp-content/db.php": "<?php echo 1;", "wp-content/.c1b12371.php": "<?php",
                        "wp-content/plugins/swift-calm-river-1a2b/a.php": "", "wp-content/mu-plugins/stub.php": ""})
        rows = self.run_script(d)
        titles = " | ".join(r[1] for r in rows)
        self.assertIn("bekannten WordPress-Angriffen", titles)
        self.assertIn("verstecken Benutzer", titles)
        self.assertIn("db.php enthält keine", titles)
        self.assertIn("versteckte PHP-Datei", titles)
        self.assertIn("Zufallsnamen", titles)
        self.assertIn("leere Datei", titles)
        self.assertEqual(sevs(rows).count("crit"), 4)

    def test_real_dropin_and_legit_plugin(self):
        d = self.world({"wp-content/db.php": "<?php class MyDB extends wpdb {}", "wp-content/plugins/roles/r.php": "<?php add_action('pre_user_query', 'f');",
                        "wp-content/plugins/real-plugin-name/real.php": "<?php /* x */", "wp-content/plugins/real-plugin-name/index.php": ""})
        rows = self.run_script(d)
        self.assertEqual(sevs(rows), ["info"])          # nur der Hinweis auf das echte Drop-in
        self.assertIn("Datenbank-Schicht", rows[0][1])

    def test_plugin_hook_with_views_is_warn(self):
        d = self.world({"wp-content/plugins/x/x.php": "<?php add_action('pre_user_query','a'); add_filter('views_users','b');"})
        self.assertEqual(sevs(self.run_script(d)), ["warn"])


class WpOptions(unittest.TestCase):
    def test_known_and_base64(self):
        rows = zusatz.evaluate_wp_options([{"name": "_tds_stats", "len": "300"}], [{"name": "_x", "len": "90000", "head": "A" * 70}, {"name": "big_json", "len": "30000", "head": "{\"a\":1}"}], [], "shop.de", [])
        self.assertEqual(sevs(rows), ["crit", "warn"])
        self.assertIn("_x", rows[1][3][0])
        self.assertEqual(len(rows[1][3]), 1)

    def test_websocket_foreign_vs_own(self):
        ws = [{"name": "fk_external", "v": "wss://protect-wss.com/ws"}, {"name": "chat", "v": "wss://shop.de/live"}]
        rows = zusatz.evaluate_wp_options([], [], ws, "shop.de", [])
        self.assertEqual(sevs(rows), ["warn"])
        self.assertEqual(len(rows[0][3]), 1)

    def test_clean(self):
        self.assertEqual(zusatz.evaluate_wp_options([], [{"name": "elementor", "len": "50000", "head": "a:3:{s:3"}], [], "a.de", []), [])


class JoomlaKnown(unittest.TestCase):
    def test_versions(self):
        sec = split_sections("@@VER\nV\tplugins/ajax/helix3/helix3.xml\t3.0.5\nV\tadministrator/components/com_jce/jce.xml\t2.9.99.5\n@@COX\ntemplates/shaper_x/cox.json\n")
        rows = zusatz.evaluate_joomla_files(sec)
        self.assertEqual(sevs(rows), ["crit", "crit"])
        self.assertIn("Helix3", rows[0][1])
        self.assertIn("cox.json", rows[1][1])

    def test_safe_versions(self):
        sec = split_sections("@@VER\nV\tplugins/ajax/helix3/helix3.xml\t3.1.2\nV\tadministrator/components/com_jce/jce.xml\t2.9.99.4\n@@COX\n")
        rows = zusatz.evaluate_joomla_files(sec)
        self.assertEqual(sevs(rows), ["crit"])        # JCE 2.9.99.4 ist verwundbar
        ok = zusatz.evaluate_joomla_files(split_sections("@@VER\nV\tplugins/ajax/helix3/helix3.xml\t3.1.2\n@@COX\n"))
        self.assertEqual([len(r) for r in ok], [5])    # alle Zeilen haben die gleiche Form (Schwere, Titel, Text, Liste, Hinweis)
        self.assertIn("JCE", rows[0][1])

    def test_script_runs(self):
        d = tempfile.mkdtemp(prefix="zj_")
        os.makedirs(os.path.join(d, "plugins/ajax/helix3"))
        with open(os.path.join(d, "plugins/ajax/helix3/helix3.xml"), "w") as fh:
            fh.write("<extension><version>3.0.1</version></extension>")
        files = [f for v in zusatz.JOOMLA_VULN for f in v[1]]
        rows = zusatz.evaluate_joomla_files(split_sections(sh(zusatz.JOOMLA_SCRIPT.replace("@VERFILES@", " ".join(files)), d)))
        self.assertEqual(sevs(rows), ["crit"])

    def test_template_defacement(self):
        rows = zusatz.evaluate_joomla_templates([{"id": "9", "name": "shaper_helix3", "v": "document.body.innerHTML='hacked by x';position:fixed;z-index:2147483647"},
                                                 {"id": "4", "name": "cassiopeia", "v": "x innerHTML y position:fixed"}])
        self.assertEqual(sevs(rows), ["crit", "warn"])


class SeoSpam(unittest.TestCase):
    def test_foreign_sitemap_and_robots(self):
        now = time.time()
        sec = split_sections("@@SITEMAPS\nS\t./sitemap1.xml\t5000\t%d\nL\tspam-pharma.example\t290\nL\tshop.de\t10\nS\t./sitemap.xml\t900\t%d\nL\tshop.de\t40\n"
                             "@@ROBOTS\nSitemap: https://shop.de/sitemap.xml\nSitemap: https://spam.example/s.xml\n@@ADS\nA\tads.txt\t%d\t3\n" % (now, now, now))
        rows = zusatz.evaluate_spam(sec, "www.shop.de", now)
        self.assertEqual(sevs(rows), ["crit", "warn", "info"])
        self.assertEqual(len(rows[0][3]), 1)

    def test_clean(self):
        sec = split_sections("@@SITEMAPS\nS\t./sitemap.xml\t900\t1000\nL\tshop.de\t40\n@@ROBOTS\nSitemap: https://shop.de/sitemap.xml\n@@ADS\n")
        self.assertEqual(zusatz.evaluate_spam(sec, "shop.de", time.time()), [])

    def test_script_runs(self):
        d = tempfile.mkdtemp(prefix="zs_")
        with open(os.path.join(d, "sitemap.xml"), "w") as fh:
            fh.write("<urlset><url><loc>https://x.example/a</loc></url><url><loc>https://x.example/b</loc></url></urlset>")
        with open(os.path.join(d, "robots.txt"), "w") as fh:
            fh.write("User-agent: *\nSitemap: https://x.example/sitemap.xml\n")
        rows = zusatz.evaluate_spam(split_sections(sh(zusatz.SPAM_SCRIPT, d)), "shop.de")
        self.assertEqual(sevs(rows), ["crit", "warn"])


class Skimmer(unittest.TestCase):
    def test_parse_ws(self):
        out = "@@LOADERS\n@@WS\n./js/a.js:WebSocket('wss://evil.example\n./b.php:WebSocket( \"ws://x.test\n"
        self.assertEqual([w["host"] for w in skimmer.parse_ws(out)], ["evil.example", "x.test"])

    def test_gate_flag_parsed(self):
        it = skimmer.parse("@@@F\t./a.js\nFLAGS\t1\t0\t0\t1\nHOST\thttps://evil.example\n@@LOADERS\n")[0]
        self.assertTrue(it["gate"])
        it = skimmer.parse("@@@F\t./a.js\nFLAGS\t1\t0\t0\nHOST\thttps://e.example\n@@LOADERS\n")[0]
        self.assertFalse(it["gate"])

    def test_ws_script(self):
        d = tempfile.mkdtemp(prefix="zk_")
        with open(os.path.join(d, "c.js"), "w") as fh:
            fh.write("var s=new WebSocket('wss://protect-wss.example/ws');")
        script = skimmer.SCRIPT.replace("@SKIP@", "").replace("@CARD@", "xxnomatch").replace("@SEND@", "x").replace("@OBF@", "xxnomatch").replace("@LOAD@", "x").replace("@GATE@", "x")
        self.assertEqual([w["host"] for w in skimmer.parse_ws(sh(script, d))], ["protect-wss.example"])


class Shm(unittest.TestCase):
    def test_parse(self):
        out = "@@PS\n 1 0 00:10 php-fpm\n@@EXE\n@@SHM\n0x00001234 98304 0\n@@END\n"
        info = konto.parse_procs(out)
        self.assertEqual(info["shm"], [{"key": "0x00001234", "bytes": 98304, "attached": "0"}])
        self.assertEqual(konto.parse_procs("@@PS\n@@EXE\n@@END\n")["shm"], [])


if __name__ == "__main__":
    unittest.main()


class Locked(unittest.TestCase):
    def test_immutable_and_foreign(self):
        sec = split_sections("@@ME\nweb1\n@@IMM\n----i---------e------- ./wp-content/mu-plugins/x.php\n-----a--------e------- ./old dir\n@@FOREIGN\nroot\td\t./wp-content/cache\nweb1\tf\t./a\n")
        rows = zusatz.evaluate_locked(sec)
        self.assertEqual(sevs(rows), ["crit", "warn"])
        self.assertEqual(len(rows[0][3]), 2)
        self.assertEqual(len(rows[1][3]), 1)

    def test_clean(self):
        self.assertEqual(zusatz.evaluate_locked(split_sections("@@ME\nweb1\n@@IMM\n@@FOREIGN\nweb1\tf\t./a\n")), [])

    def test_script_runs_without_error(self):
        d = tempfile.mkdtemp(prefix="zl_")
        with open(os.path.join(d, "a.txt"), "w") as fh:
            fh.write("x")
        rows = zusatz.evaluate_locked(split_sections(sh(zusatz.LOCK_SCRIPT, d)))
        self.assertEqual(rows, [])
