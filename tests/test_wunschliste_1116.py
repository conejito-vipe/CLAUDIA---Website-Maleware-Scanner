"""Wunschliste 2.5.0 (16.11.): Hoster-Liste, Funktions-Scan, fehlende Paketdateien, Preisgruppen, Ordner-Übernahme, Oberfläche."""
import os
import re
import shutil
import sys
import tempfile
import threading
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

from claudia import hoster, server  # noqa: E402
from claudia.checks import ext_integrity, php_config, security_ext  # noqa: E402


def finding(sev, title, items=None):
    return {"sev": sev, "title": title, "items": items or []}


class Hoster(unittest.TestCase):
    def results(self):
        return [
            {"id": "php_settings", "findings": [finding("warn", "7 von 7 gefährlichen Funktionen sind nicht gesperrt", ["nicht gesperrt: exec, system"]),
                                                  finding("ok", "allow_url_include ist aus")]},
            {"id": "mail_dns", "findings": [finding("warn", "SPF ohne Wirkung (?all)", ["v=spf1 include:x ?all"])]},
            {"id": "tls_protocols", "findings": [finding("crit", "TLS 1.0 wird noch angeboten")]},
            {"id": "webshells", "findings": [finding("crit", "Shell gefunden")]},          # nicht beim Hoster änderbar
        ]

    def test_collects_only_hoster_points_sorted_by_severity(self):
        items = hoster.collect(self.results())
        self.assertEqual([i["check"] for i in items], ["tls_protocols", "php_settings", "mail_dns"])
        self.assertTrue(all(i["ask"] for i in items))

    def test_function_names_are_taken_from_finding(self):
        ask = [i for i in hoster.collect(self.results()) if i["check"] == "php_settings"][0]["ask"]
        self.assertIn("exec, system", ask)

    def test_spf_text_names_the_record(self):
        ask = [i for i in hoster.collect(self.results()) if i["check"] == "mail_dns"][0]["ask"]
        self.assertIn("~all", ask)
        self.assertIn("v=spf1 include:x ?all", ask)

    def test_same_request_only_once(self):
        r = self.results() + [{"id": "mail_dns", "findings": [finding("warn", "SPF ohne Wirkung (?all)", ["v=spf1 include:x ?all"])]}]
        self.assertEqual(len(hoster.collect(r)), 3)

    def test_ok_findings_are_ignored_and_empty_list_gives_no_mail(self):
        b = hoster.build([{"id": "php_settings", "findings": [finding("ok", "allow_url_include ist aus")]}], "https://x.de")
        self.assertEqual(b["items"], [])
        self.assertEqual(b["mail"], {"subject": "", "body": ""})

    def test_mail_text(self):
        b = hoster.build(self.results(), "https://x.de", "srv1")
        self.assertIn("https://x.de", b["mail"]["subject"])
        self.assertIn("1. ", b["mail"]["body"])
        self.assertIn("3. ", b["mail"]["body"])
        self.assertIn("srv1", b["mail"]["body"])


class FunctionScan(unittest.TestCase):
    def test_call_forms(self):
        out = "@@USERS\n".join(["", ""]) + "\n".join([
            "plugins/system/akeeba/x.php:exec(",
            "administrator/components/com_foo/y.php: system(",
            "plugins/content/bar/z.php:exec(",
            "garbage line",
        ])
        u = php_config.parse_func_users(out, "joomla")
        self.assertEqual(u["exec"], {"akeeba/x.php".split("/")[0] + "/system (Plugin)" if False else "system/akeeba (Plugin)": 1, "content/bar (Plugin)": 1})
        self.assertEqual(u["system"], {"com_foo": 1})

    def test_ext_key_wordpress(self):
        self.assertEqual(php_config.ext_key("wp-content/plugins/updraftplus/a/b.php", "wordpress"), "updraftplus")
        self.assertEqual(php_config.ext_key("wp-content/themes/twenty/x.php", "wordpress"), "twenty")

    def rows(self):
        return [("warn", "7 von 7 gefährlichen Funktionen sind nicht gesperrt", "Detail.", ["nicht gesperrt: exec, system, popen"], "Hinweis alt")]

    def test_nothing_found_means_all_lockable(self):
        r = php_config.apply_func_users(self.rows(), {})
        self.assertIn("ohne Risiko", " ".join(r[0][3]))
        self.assertIn("alle beim Hoster sperren", r[0][4])

    def test_used_function_is_named_with_extension(self):
        r = php_config.apply_func_users(self.rows(), {"exec": {"akeeba": 3}})
        joined = " ".join(r[0][3])
        self.assertIn("exec wird gefunden in: akeeba (3x)", joined)
        self.assertIn("system, popen", joined)                          # die ungenutzten
        self.assertIn("nur die Funktionen", r[0][4])

    def test_not_searched_leaves_row_unchanged(self):
        self.assertEqual(php_config.apply_func_users(self.rows(), None), self.rows())


class MissingPackageFiles(unittest.TestCase):
    def test_split_install_only(self):
        normal, inst = ext_integrity.split_missing([
            "Akeeba: src/Foo.php", "Akeeba: script.install.php", "Pack: packages/lib_x.zip", "Foo: helper/installer.php", "Foo: uninstall.sql", "Foo: sub/real.php"])
        self.assertEqual(normal, ["Akeeba: src/Foo.php", "Foo: sub/real.php"])
        self.assertEqual(len(inst), 4)

    def test_count_by_ext_is_compact(self):
        rows = ext_integrity.count_by_ext(["A: x.php", "A: y.php", "B: z.php"])
        self.assertEqual(rows, ["A: 2 Datei(en)", "B: 1 Datei(en)"])


class PriceGroups(unittest.TestCase):
    def test_groups(self):
        g = security_ext.price_group
        self.assertEqual(g({"price": "kostenlos"}), 0)
        self.assertEqual(g({"price": "kostenlos, Pro kostenpflichtig"}), 0)
        self.assertEqual(g({"price": "kostenpflichtig (ab 49 $)"}), 2)
        self.assertEqual(g({"price": ""}), 1)
        self.assertEqual(g({}), 0)                                      # WordPress-Verzeichnis: ohne Preisfeld

    def test_grouped_free_first_then_paid_with_headings(self):
        tools = [{"name": "P", "price": "kostenpflichtig"}, {"name": "F", "price": "kostenlos"}, {"name": "B", "price": "kostenpflichtig", "background": True}]
        out = security_ext.grouped(tools, lambda t: t["name"])
        self.assertEqual(out, ["Kostenlos:", "F", "Kostenpflichtig:", "P"])

    def test_single_group_has_no_heading(self):
        self.assertEqual(security_ext.grouped([{"name": "A", "price": "kostenlos"}, {"name": "B", "price": "kostenlos"}], lambda t: t["name"]), ["A", "B"])

    def test_real_data_has_both_groups_for_joomla(self):
        import json
        d = json.load(open(os.path.join(ROOT, "claudia", "security_tools.json"), encoding="utf-8"))
        groups = {security_ext.price_group(t) for t in d["joomla"]}
        self.assertIn(0, groups)


class AdoptFolder(unittest.TestCase):
    def setUp(self):
        self.base = tempfile.mkdtemp(prefix="claudia_adopt_")

    def mk(self, name, files=3):
        p = os.path.join(self.base, name)
        os.makedirs(os.path.join(p, "sub"))
        for i in range(files):
            with open(os.path.join(p, "sub", "f%d.txt" % i), "w") as fh:
                fh.write("x" * (i + 1))
        return p

    def test_rename_when_new_missing(self):
        old, new = self.mk("alt"), os.path.join(self.base, "neu")
        self.assertEqual(server.adopt_folder(old, new), new)
        self.assertTrue(os.path.isdir(new) and not os.path.isdir(old))

    def test_new_exists_keeps_new(self):
        old, new = self.mk("alt"), self.mk("neu", 1)
        self.assertEqual(server.adopt_folder(old, new), new)
        self.assertTrue(os.path.isdir(old))

    def test_copy_fallback_when_rename_fails(self):
        old, new = self.mk("alt"), os.path.join(self.base, "neu")
        from unittest import mock
        with mock.patch("os.rename", side_effect=PermissionError("gesperrt")):
            self.assertEqual(server.adopt_folder(old, new), new)
        self.assertEqual(server._tree_stats(old), server._tree_stats(new))
        self.assertTrue(os.path.isdir(old))                              # Original bleibt unberührt

    def test_failed_copy_keeps_old(self):
        old, new = self.mk("alt"), os.path.join(self.base, "neu")
        from unittest import mock
        with mock.patch("os.rename", side_effect=PermissionError("x")), mock.patch("shutil.copytree", side_effect=OSError("voll")):
            self.assertEqual(server.adopt_folder(old, new), old)
        self.assertFalse(os.path.exists(new))

    def tearDown(self):
        shutil.rmtree(self.base, ignore_errors=True)


class NoOldNames(unittest.TestCase):
    """Alter Programmname und das Kürzel dürfen nirgends mehr lesbar im Projekt stehen."""

    def test_no_old_spelling_or_acronym(self):
        import re
        bad = re.compile("|".join(["Joomla" + "[ _-]?Sicherheits" + "check", r"\b" + "J" + "S" + "C" + r"\b", "J" + "S" + "C_"]), re.I)
        hits = []
        for r, ds, fs in os.walk(ROOT):
            ds[:] = [d for d in ds if d not in ("__pycache__", ".git", "node_modules")]
            for f in fs:
                if not f.endswith((".py", ".js", ".css", ".html", ".md", ".txt", ".json", ".bat")) or f == os.path.basename(__file__):
                    continue
                try:
                    txt = open(os.path.join(r, f), encoding="utf-8").read()
                except (OSError, UnicodeDecodeError):
                    continue
                if bad.search(txt):
                    hits.append(os.path.relpath(os.path.join(r, f), ROOT))
        self.assertEqual(hits, [])


class Statics(unittest.TestCase):
    def read(self, *p):
        return open(os.path.join(ROOT, *p), encoding="utf-8").read()

    def test_footer_text_everywhere(self):
        html = re.sub(r"<a [^>]*>(conejito-vipe)</a>", r"\1", self.read("claudia", "web", "index.html"))   # seit 2.15.0 ist der Name ein Link zum GitHub-Profil
        self.assertIn("vibecoded with Claude (Anthropic) by conejito-vipe with love", html)
        self.assertIn('href="https://github.com/conejito-vipe"', self.read("claudia", "web", "index.html"))

    def test_uninstall_dialog_uses_fixed_head_and_foot(self):
        js = self.read("claudia", "web", "app.js")
        a = js.index("async function openUninstall()")
        body = js[a:js.index("function renderLangs()")]
        for cls in ("uni-head", "uni-scroll", "uni-foot", "danger-fill"):
            self.assertIn(cls, body)

    def test_rz_strip_outside_scrollbar(self):
        css = self.read("claudia", "web", "app.css")
        self.assertIn("html.has-titlebar body", css)


if __name__ == "__main__":
    unittest.main()
