"""3.1.0: Installationsprüfung (PRUEFSUMMEN.txt), Dashboard-Befunde und Verlauf, Schutz der Update-Automatik beim Abschalten der API."""
import hashlib
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

from claudia import actions, integritaet, verlauf  # noqa: E402


def _sum(text):
    return hashlib.sha256(text).hexdigest()


class Integritaet(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="claudia-int-")
        os.makedirs(os.path.join(self.dir, "claudia"))
        self.files = {"claudia/a.py": b"print(1)\n", "README.md": b"hallo\n"}
        for rel, data in self.files.items():
            with open(os.path.join(self.dir, *rel.split("/")), "wb") as f:
                f.write(data)
        lines = ["# Test"] + ["%s  %s" % (_sum(d), rel) for rel, d in self.files.items()]
        with open(os.path.join(self.dir, "PRUEFSUMMEN.txt"), "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")

    def test_alles_da(self):
        r = integritaet.pruefen(self.dir)
        self.assertTrue(r["ok"])
        self.assertEqual(r["gesamt"], 2)

    def test_fehlende_datei_wird_gemeldet(self):
        os.remove(os.path.join(self.dir, "claudia", "a.py"))
        r = integritaet.pruefen(self.dir)
        self.assertFalse(r["ok"])
        self.assertEqual(r["fehlend"], ["claudia/a.py"])

    def test_veraenderte_datei_wird_gemeldet(self):
        with open(os.path.join(self.dir, "README.md"), "wb") as f:
            f.write(b"anders\n")
        r = integritaet.pruefen(self.dir)
        self.assertEqual(r["geaendert"], ["README.md"])

    def test_ohne_liste_wird_das_gesagt(self):
        os.remove(os.path.join(self.dir, "PRUEFSUMMEN.txt"))
        r = integritaet.pruefen(self.dir)
        self.assertFalse(r["liste_da"])
        self.assertFalse(r["ok"])

    def test_pfade_ausserhalb_werden_ignoriert(self):
        with open(os.path.join(self.dir, "PRUEFSUMMEN.txt"), "a", encoding="utf-8") as f:
            f.write("%s  ../../etc/passwd\n" % ("0" * 64))
        r = integritaet.pruefen(self.dir)
        self.assertEqual(r["gesamt"], 2)


class AutoUpdateBeimAbschalten(unittest.TestCase):
    def test_update_dienst_bleibt_ausserhalb_der_api_abschaltung(self):
        self.assertIn("joomlaupdate", actions.AUTOUPDATE_PLUGIN_SQL)
        self.assertIn("'token'", actions.AUTOUPDATE_PLUGIN_SQL)
        self.assertIn("api-authentication", actions.AUTOUPDATE_PLUGIN_SQL)
        self.assertIn("AUTOUPDATE_PLUGIN_SQL", open(actions.__file__, encoding="utf-8").read())


class Verlauf31(unittest.TestCase):
    def test_befunde_und_verlauf_im_dashboard(self):
        base = tempfile.mkdtemp(prefix="claudia-verl-")
        res = [{"id": "x_check", "status": "crit", "findings": [{"sev": "crit", "title": "Schadcode"}]},
               {"id": "y_check", "status": "warn", "findings": [{"sev": "warn", "title": "Header fehlt"}]}]
        verlauf.record_run(base, verlauf.run_entry("seite.example", "Seite", "joomla", "5.2", res, ts=1000))
        verlauf.record_run(base, verlauf.run_entry("seite.example", "Seite", "joomla", "5.2", res[1:], ts=2000))
        d = verlauf.dashboard(base, now=3000)
        s = d["sites"][0]
        self.assertEqual(len(s["history"]), 2)
        self.assertEqual(s["findings"][0]["sev"], "warn")          # letzte Prüfung enthält nur den Hinweis
        self.assertEqual(s["findings"][0]["id"], "y_check")
        base2 = tempfile.mkdtemp(prefix="claudia-verl-")
        verlauf.record_run(base2, verlauf.run_entry("s", "S", "joomla", "5", res, ts=1000))
        s2 = verlauf.dashboard(base2, now=3000)["sites"][0]
        self.assertEqual([f["sev"] for f in s2["findings"]], ["crit", "warn"])   # kritisch zuerst


if __name__ == "__main__":
    unittest.main()
