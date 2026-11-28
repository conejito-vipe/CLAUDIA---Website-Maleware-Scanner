"""3.1.1: Erweiterungen gegen das Paket des Herstellers ohne Fehlalarme (Bericht familienperspektive.de vom 28.11.2026).

- Komponente mit admin-Ordner im Paket (Joomlashack-Aufbau): keine falsch "fehlenden" Dateien
- Paket-Sammlung mit eingebettetem Plugin-ZIP (z. B. ACF): wird geöffnet statt "Paketaufbau nicht unterstützt"
- gemeinsame Bibliothek (osmylicensesmanager): identisch mit der Datei aus einem anderen Paket -> in Ordnung
- nur Zeilenenden anders -> in Ordnung; echte Änderung -> kritisch mit Gegenüberstellung im Codefenster
- Joomla-eigene Erweiterungen (Update-Adresse joomla.org) erscheinen nicht unter "nicht prüfbar"
"""
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

import fixture  # noqa: E402
from test_integrity_themes_extensions import run, titles, zip_of  # noqa: E402
from claudia import extsums  # noqa: E402

UPD = ('<updates><update><element>%s</element><type>%s</type><folder>%s</folder><client>0</client><version>%s</version><tags><tag>stable</tag></tags>'
       '<downloadurl type="full" format="zip">https://vendor.example/%s.zip</downloadurl><targetplatform name="joomla" version="[56]\\.[0-9]+"/></update></updates>')
LIB = "<?php\n// gemeinsame Installer-Bibliothek\nclass Loader { const V = 2; }\n"
LIB_OLD = "<?php\n// gemeinsame Installer-Bibliothek\nclass Loader { const V = 1; }\n"

# Komponente: Seitenteil ohne folder-Angabe, aber mit Einträgen; admin-Ordner im Paket
MAN_COM = ('<?xml version="1.0"?><extension type="component" method="upgrade"><name>OSMeta</name><version>4.0.0</version>'
           '<files><filename>osmeta.php</filename></files>'
           '<administration><files folder="admin"><filename>controller.php</filename><folder>library</folder></files></administration></extension>')
MAN_PLG = ('<?xml version="1.0"?><extension type="plugin" group="system" method="upgrade"><name>Lic</name><version>2.0.0</version>'
           '<files><filename plugin="osmylic">osmylic.php</filename><folder>library</folder></files></extension>')
MAN_ACF = ('<?xml version="1.0"?><extension type="plugin" group="system" method="upgrade"><name>ACF</name><version>3.0.0</version>'
           '<files><filename plugin="acf">acf.php</filename><folder>ACF</folder></files></extension>')
MAN_PKG = ('<?xml version="1.0"?><extension type="package" method="upgrade"><name>pkg_acf</name><packagename>acf</packagename><version>3.0.0</version>'
           '<files folder="packages"><file type="plugin" id="acf" group="system">plg_system_acf.zip</file></files></extension>')


class Fehlalarme(unittest.TestCase):
    def setUp(self):
        self.w = fixture.make_world(tempfile.mkdtemp(prefix="claudia_ext311_"), False)
        s = self.w["site"]
        self.srv = {
            "components/com_osmeta/osmeta.php": "<?php echo 'site';\n",
            "administrator/components/com_osmeta/controller.php": "<?php echo 'admin';\n",
            "administrator/components/com_osmeta/library/Installer/Loader.php": LIB,
            "plugins/system/osmylic/osmylic.php": "<?php echo 'lic';\n",
            "plugins/system/osmylic/library/Installer/Loader.php": LIB,          # von OSMeta überschrieben
            "plugins/system/acf/acf.php": "<?php echo 'acf';\r\n",                 # nur Zeilenende anders
            "plugins/system/acf/ACF/Item.php": "<?php class Item {}\n",
        }
        for rel, t in self.srv.items():
            fixture.w(os.path.join(s, rel), t, days_ago=30)
        self.pkgs = {
            "com": zip_of({"osmeta.xml": MAN_COM, "osmeta.php": self.srv["components/com_osmeta/osmeta.php"],
                           "admin/controller.php": self.srv["administrator/components/com_osmeta/controller.php"],
                           "admin/library/Installer/Loader.php": LIB, "script.installer.php": "<?php // nur Installation"}),
            "plg": zip_of({"osmylic.xml": MAN_PLG, "osmylic.php": self.srv["plugins/system/osmylic/osmylic.php"],
                           "library/Installer/Loader.php": LIB_OLD}),
            "acf": zip_of({"pkg_acf.xml": MAN_PKG, "packages/plg_system_acf.zip":
                           zip_of({"acf.xml": MAN_ACF, "acf.php": "<?php echo 'acf';\n", "ACF/Item.php": self.srv["plugins/system/acf/ACF/Item.php"]})}),
        }
        mk = lambda eid, name, el, typ, folder, ver, loc: {"sid": eid, "eid": eid, "name": name, "element": el, "type": typ, "folder": folder, "client": "0",
                                                          "version": ver, "location": loc, "needs_key": "0", "age": "10"}
        self.rows = [mk("1", "OSMeta", "com_osmeta", "component", "", "4.0.0", "https://vendor.example/com.xml"),
                     mk("2", "Lic", "osmylic", "plugin", "system", "2.0.0", "https://vendor.example/plg.xml"),
                     mk("3", "ACF", "acf", "plugin", "system", "3.0.0", "https://vendor.example/acf.xml"),
                     mk("4", "com_joomlaupdate", "com_joomlaupdate", "component", "", "4.0.3", "https://update.joomla.org/core/list.xml")]

    def get(self, url):
        key = url.rsplit("/", 1)[-1][:-4]
        meta = {"com": ("com_osmeta", "component", "", "4.0.0"), "plg": ("osmylic", "plugin", "system", "2.0.0"), "acf": ("acf", "plugin", "system", "3.0.0")}
        if key in meta:
            return UPD % (meta[key] + (key,))
        return None

    def go(self):
        patches = [("claudia.checks.ext_integrity.need_db", {"return_value": object()}),
                   ("claudia.checks.ext_integrity.fetch", {"return_value": self.rows}),
                   ("claudia.updcheck._get", {"side_effect": self.get}),
                   ("claudia.updcheck.PAUSE", {"new": 0}),
                   ("claudia.coreref.fetch_bytes", {"side_effect": lambda url, *a, **k: self.pkgs[url.rsplit("/", 1)[-1][:-4]]})]
        return run(self.w, "ext_integrity", "joomla", patches)

    def items(self, r, word):
        return " ".join(" ".join(f.items) for f in r.findings if word in f.title)

    def test_no_false_alarms(self):
        r = self.go()
        t = titles(r)
        self.assertFalse(any(s in ("crit", "warn") for s, _ in t), t)
        self.assertFalse(any("fehlen auf dem Server" in x for _, x in t), t)          # admin-Ordner richtig zugeordnet
        self.assertIn("osmylic: plugins/system/osmylic/library/Installer/Loader.php", self.items(r, "gemeinsamen Bibliothek"))
        self.assertIn("com_osmeta", self.items(r, "gemeinsamen Bibliothek"))
        self.assertIn("acf: plugins/system/acf/acf.php", self.items(r, "Zeilenenden"))       # eingebettetes Plugin-ZIP geöffnet
        self.assertNotIn("Paketaufbau", " ".join(" ".join(f.items) for f in r.findings))
        self.assertNotIn("com_joomlaupdate", " ".join(" ".join(f.items) for f in r.findings))
        self.assertEqual(r.status, "ok")

    def test_real_change_shows_diff(self):
        fixture.w(os.path.join(self.w["site"], "plugins/system/acf/ACF/Item.php"), "<?php class Item {}\n@eval($_POST['x']);\n", days_ago=1)
        r = self.go()
        crit = [f for f in r.findings if f.sev == "crit"]
        self.assertEqual(len(crit), 1, titles(r))
        self.assertIn("acf: plugins/system/acf/ACF/Item.php", crit[0].items)
        ev = crit[0].evidence[0]
        self.assertEqual(ev["kind"], "diff")
        added = [c["t"] for c in ev["code"] if c["t"].startswith("+")]
        self.assertIn("+@eval($_POST['x']);", added)
        self.assertTrue(all("hit" in c for c in ev["code"] if c["t"][:1] in "+-"))

    def test_helpers(self):
        self.assertTrue(extsums.normalized_equal(b"a\r\nb  \r\n\r\n", b"a\nb\n"))
        self.assertFalse(extsums.normalized_equal(b"a\nb\n", b"a\nc\n"))
        self.assertEqual(extsums.only_entries({"osmeta.php": "1", "admin/x.php": "2", "script.php": "3"}, ["osmeta.php"], []), {"osmeta.php": "1"})
        self.assertEqual(extsums.only_entries({"a.php": "1", "admin/x.php": "2"}, [], ["admin"]), {"a.php": "1"})
        files, man, _, top = extsums.resolve_package(zip_of({"pkg-1.0/mod.xml": '<extension type="module"/>', "pkg-1.0/mod.php": "x"}), {"type": "module"})
        self.assertTrue(top)                                                            # ZIP mit Oberordner
        self.assertIn("mod.php", files)


if __name__ == "__main__":
    unittest.main(verbosity=2)
