"""Technik-Kapitel: vollständig (jede Prüfung und Aktion), echter Quelltext, zweisprachig, keine Geheimnisse, im Hilfe-Fenster abrufbar."""
import json
import os
import re
import sys
import threading
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tools"))
sys.path.insert(0, HERE)

from claudia import actions, helpdocs, techdoc  # noqa: E402
from claudia.registry import load_all, ordered  # noqa: E402

try:
    from playwright.sync_api import sync_playwright
except ImportError:  # pragma: no cover
    sync_playwright = None


class Content(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        load_all()
        cls.p = techdoc.payload("de")

    def test_every_check_has_code(self):
        ids = {c.id for cms in ("joomla", "wordpress", "drupal", "typo3", "contao", "prestashop") for c in ordered(cms)}
        got = {c["id"]: c for c in self.p["checks"]}
        self.assertEqual(ids, set(got))
        for cid, c in got.items():
            self.assertTrue(c["blocks"], cid)
            self.assertTrue(any(b["kind"] == "func" for b in c["blocks"]), cid)
            for b in c["blocks"]:
                self.assertTrue(b["code"].strip(), (cid, b["name"]))
                compile(b["code"], cid, "exec") if b["kind"] == "func" and not b["code"].lstrip().startswith("@") and "# ..." not in b["code"] else None

    def test_every_action_has_entry_and_text(self):
        got = {a["id"]: a for a in self.p["actions"]}
        self.assertEqual(set(actions.ACTIONS), set(got))
        for lang in ("de", "en"):
            texts = techdoc._texts(lang)
            for aid in actions.ACTIONS:
                self.assertIn("a:" + aid, texts, "%s fehlt in technik.%s.txt" % (aid, lang))
                self.assertTrue(texts["a:" + aid]["blocks"], (lang, aid))
        for aid, a in got.items():
            self.assertTrue(a["blocks"], aid)
            self.assertTrue(a["text"], aid)

    def test_action_commands_shown(self):
        for a in self.p["actions"]:
            if a["id"] not in ("check_updates", "core_update", "clear_cache"):
                self.assertTrue(a["commands"].strip(), a["id"])

    def test_texts_have_no_orphans_and_same_structure(self):
        de, en = techdoc._texts("de"), techdoc._texts("en")
        self.assertEqual(list(de), list(en))
        for k in de:
            self.assertEqual(len(de[k]["blocks"]), len(en[k]["blocks"]), k)
            if k.startswith("a:"):
                self.assertIn(k[2:], actions.ACTIONS)
            else:
                self.assertIn(k[2:], [b[0] for b in techdoc.BASICS])

    def test_basics_complete(self):
        for b in self.p["basics"]:
            self.assertTrue(b["text"], b["id"])
            self.assertTrue(b["code"], b["id"])
        names = [x["name"] for b in self.p["basics"] for x in b["code"]]
        for must in ("wrap_script", "sq", "make_backup", "Traced", "_mysql_script"):
            self.assertIn(must, names)

    def test_code_is_real_source(self):
        """Der gezeigte Code steht wörtlich in der Quelldatei."""
        seen = 0
        for part in (self.p["checks"], self.p["actions"]):
            for e in part:
                for b in e["blocks"]:
                    if b["kind"] == "branch" or "# ..." in b["code"] or not b["line"] or b["line"] == "0":
                        continue
                    path = os.path.join(ROOT, *b["file"].split("/"))
                    with open(path, encoding="utf-8") as fh:
                        text = fh.read()
                    first = b["code"].split("\n")[0].strip()
                    self.assertIn(first, text, (e["id"], b["name"]))
                    seen += 1
        self.assertGreater(seen, 100)

    def test_no_secrets_in_text(self):
        blob = json.dumps(techdoc.payload("de")) + json.dumps(techdoc.payload("en"))
        self.assertNotRegex(blob, r"BEGIN [A-Z ]*PRIVATE KEY")
        self.assertNotRegex(blob, r"ssh-(?:rsa|ed25519) AAAA")
        self.assertNotRegex(blob, r"\b[0-9a-fA-F]{40,}\b")
        self.assertNotIn("/home/claude", blob)

    def test_titles_translated_code_not(self):
        en = techdoc.payload("en")
        de = self.p
        self.assertNotEqual([a["title"] for a in en["actions"]], [a["title"] for a in de["actions"]])
        self.assertEqual([[b["code"] for b in a["blocks"]] for a in en["actions"]], [[b["code"] for b in a["blocks"]] for a in de["actions"]])

    def test_size_reasonable(self):
        self.assertLess(len(json.dumps(self.p)), 1_500_000)   # 2.5.0: von 1_000_000 angehoben, weil jede neue Prüfung ihren Quelltext im Technik-Kapitel mitbringt


@unittest.skipIf(sync_playwright is None, "playwright fehlt")
class Browser(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import build_docs
        import tempfile
        cls.base = tempfile.mkdtemp(prefix="claudia_tech_")
        cls.html = build_docs.build(os.path.join(cls.base, "doku.html"))
        cls.pw = sync_playwright().start()
        cls.browser = cls.pw.chromium.launch()

    @classmethod
    def tearDownClass(cls):
        cls.browser.close()
        cls.pw.stop()

    def test_tab_search_and_copy(self):
        pg = self.browser.new_page(viewport={"width": 1400, "height": 900})
        errs = []
        pg.on("pageerror", lambda e: errs.append(str(e)))
        pg.goto("file://" + self.html)
        pg.wait_for_selector(".docs-tab")
        pg.click(".docs-tab:has-text('Tech Doku')")                           # ein Bereich: Prüfungen, Aktionen und Technik
        pg.wait_for_selector("#doc-toc")
        pg.wait_for_selector(".docs-toclist li")
        self.assertGreater(pg.locator(".docs-toclist li").count(), 60)       # Inhaltsverzeichnis mit allen Einträgen
        self.assertGreaterEqual(pg.locator(".docs-nav a").count(), 5)
        self.assertIn("Wie ein Befehl zum Server kommt", pg.inner_text(".docs-body"))
        # jeder Eintrag hat einen Anker zurück zum Inhaltsverzeichnis
        self.assertGreaterEqual(pg.locator(".docs-item .docs-back").count(), 60)
        pg.click(".docs-toclist a:has-text('Hintertüren und PHP-Dateien')")
        item = pg.locator("[id='doc-c:backdoors']") if pg.locator("[id='doc-c:backdoors']").count() else pg.locator(".docs-item:has(h4:has-text('Hintertüren und PHP-Dateien')) >> nth=0")
        self.assertTrue(item.is_visible())
        # Reihenfolge je Eintrag: erst Was, dann Warum, dann Wie, dann der Code
        heads = [x.strip().upper() for x in item.locator("h5.docs-sub").all_inner_texts()]
        self.assertEqual([h for h in heads if h in ("WAS", "WARUM", "WIE")], ["WAS", "WARUM", "WIE"], heads)
        # Codeblöcke: eingeklappt, schwarz, mit Kopierfunktion
        wins = item.locator("details.docs-cw")
        self.assertGreaterEqual(wins.count(), 2)
        self.assertEqual(item.locator("details.docs-cw[open]").count(), 0)
        self.assertEqual(item.locator("details.docs-cw .docs-copy").count(), wins.count())
        self.assertEqual(wins.first.evaluate("e => getComputedStyle(e).backgroundColor"), "rgb(10, 13, 11)")
        wins.first.locator("summary").click()
        self.assertTrue(wins.first.locator("pre").inner_text().strip())
        self.assertIn("rgb(61, 220, 132)", wins.first.locator("pre").evaluate("e => getComputedStyle(e).color"))
        # zurück zum Inhaltsverzeichnis
        item.locator(".docs-back").first.click()
        self.assertTrue(pg.locator("#doc-toc h3").is_visible())
        pg.fill(".docs-q", "mysqldump")
        pg.wait_for_selector(".docs-hit")
        self.assertGreaterEqual(pg.locator(".docs-hit").count(), 3)
        pg.click(".docs-hit a >> nth=0")
        pg.wait_for_selector("#doc-toc")
        self.assertGreaterEqual(pg.locator("details.docs-cw").count(), 1)
        self.assertEqual(errs, [])
        pg.close()


if __name__ == "__main__":
    unittest.main()
