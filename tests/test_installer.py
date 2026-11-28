"""Installer: Inno-Skript, Workflow, Mac-Skript und Erkennung einer Installation durch den Windows-Installer."""
import os, re, tempfile, unittest
from claudia import __version__, uninstall

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def rd(*p):
    return open(os.path.join(ROOT, *p), encoding="utf-8").read()


class InstallerTests(unittest.TestCase):
    def test_iss_per_user(self):
        s = rd("installer", "claudia.iss")
        self.assertIn("PrivilegesRequired=lowest", s)
        self.assertIn(r"{localappdata}\Programs\{#AppShortName}", s)
        self.assertIn("AppVersion \"%s\"" % __version__, s)
        self.assertIn("conejito-vipe", s)

    def test_iss_code_compiles_in_principle(self):
        """Der Inno-Compiler läuft nur im Windows-Build; typische Fehler hier schon abfangen."""
        s = rd("installer", "claudia.iss")
        code = s.split("[Code]")[1]
        # StringChange und Delete verändern ihr erstes Argument: es muss eine Variable sein, kein Aufruf
        for fn in ("StringChange", "Delete"):
            for m in re.finditer(fn + r"\(\s*([^,]+),", code):
                self.assertRegex(m.group(1).strip(), r"^[A-Za-z_]\w*$", "%s braucht eine Variable: %s" % (fn, m.group(0)))
        # LoadStringFromFile liefert AnsiString; vor der Weiterverarbeitung in String wandeln
        self.assertIn("String(Raw)", code)
        # Die Seite mit Logo und SmartScreen-Hinweis muss erhalten bleiben
        self.assertIn("procedure InitializeWizard;", code)
        self.assertIn("hinweis_smartscreen.bmp", code)
        self.assertIn("function ReadInstalledVersion", code)
        self.assertIn("WizardResizable=yes", s)
        self.assertIn("WizardImageAlphaFormat=defined", s)                  # kleines Logo transparent
        self.assertIn("WizardForm.ReadyMemo.ScrollBars := ssNone;", code)   # keine Bildlaufleisten auf "Bereit zur Installation"
        self.assertIn("WizardForm.PageDescriptionLabel.Left := WizardForm.PageNameLabel.Left;", code)   # auf allen Seiten bündig zur Überschrift
        self.assertIn("WizardForm.InnerNotebook.Left := WizardForm.PageNameLabel.Left;", code)
        self.assertLess(code.index("AlignWithHeading;"), code.index("CreateCustomPage"))
        import struct
        with open(os.path.join(ROOT, "installer", "wizard_small.bmp"), "rb") as f:
            d = f.read()
        self.assertEqual(struct.unpack("<H", d[28:30])[0], 32)               # 32 Bit mit Alphakanal
        self.assertEqual(d[struct.unpack("<I", d[10:14])[0] + 3], 0)        # Ecke durchsichtig

    def test_iss_keeps_user_data(self):
        s = rd("installer", "claudia.iss")
        inst = s.split("[InstallDelete]")[1].split("[Files]")[0]
        inst = re.sub(r"#ifdef FrozenApp.*?#endif", "", inst, flags=re.S)          # nur beim Wechsel auf die einzelne Programmdatei wird die alte .venv entfernt
        self.assertNotIn(".venv\"", inst)
        self.assertNotIn("{userappdata}", s)

    def test_workflow_manual(self):
        s = rd(".github", "workflows", "release.yml")
        self.assertIn("workflow_dispatch", s)
        self.assertIn("claudia.iss", s)
        self.assertFalse(os.path.exists(os.path.join(ROOT, ".github", "workflows", "build-windows.yml")))        # ersetzt durch release.yml

    def test_mac_script(self):
        s = rd("install.command")
        self.assertIn("$HOME/Applications/CLAUDIA", s)
        self.assertNotIn("sudo", s)
        self.assertTrue(os.access(os.path.join(ROOT, "install.command"), os.X_OK))

    def test_installed_by_setup(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertFalse(uninstall.installed_by_setup(d))
            open(os.path.join(d, "unins000.exe"), "w").close()
            self.assertTrue(uninstall.installed_by_setup(d))
            self.assertFalse(uninstall.installed_by_setup(os.path.join(d, "nix")))


if __name__ == "__main__":
    unittest.main()
