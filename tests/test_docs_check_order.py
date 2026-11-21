"""2.4.1: Im Prüfkatalog der Doku stehen die Prüfungen je System alphabetisch (in der Sprache der Anzeige)."""
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tools"))

JS = """() => [...document.querySelectorAll('.docs-tocg')].map(g => {
  const items = [...g.querySelectorAll('.docs-toclist li')].map(x => x.textContent.trim());
  const ref = [...items].sort((a, b) => a.localeCompare(b, 'de', {sensitivity: 'base', numeric: true}));
  return {t: g.querySelector('.docs-sub').textContent, n: items.length, sorted: JSON.stringify(items) === JSON.stringify(ref)};
})"""


class Order(unittest.TestCase):
    def test_code_sorts_catalog_groups(self):
        js = open(os.path.join(ROOT, "claudia", "web", "docs.js"), encoding="utf-8").read()
        self.assertIn("localeCompare(y.title, data.lang", js)

    def test_rendered_catalog_is_sorted(self):
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            self.skipTest("Playwright nicht vorhanden")
        import build_docs
        out = build_docs.build(os.path.join(tempfile.mkdtemp(prefix="claudia_docs_"), "d.html"))
        with sync_playwright() as p:
            try:
                b = p.chromium.launch()
            except Exception as e:
                self.skipTest("Chromium nicht startbar: %s" % str(e)[:60])
            pg = b.new_page()
            pg.goto("file://" + out)
            pg.locator(".docs-tab").nth(2).click()      # Tech Doku (enthält den Prüfkatalog)
            groups = pg.evaluate(JS)
            b.close()
        checks = [g for g in groups if g["t"].startswith("Prüfungen für")]
        self.assertEqual(len(checks), 7)      # Joomla, WordPress, Drupal, TYPO3, Contao, PrestaShop, mehrere Systeme (seit 2.12.0)
        for g in checks:
            self.assertGreater(g["n"], 5)
            self.assertTrue(g["sorted"], g["t"])


if __name__ == "__main__":
    unittest.main()
