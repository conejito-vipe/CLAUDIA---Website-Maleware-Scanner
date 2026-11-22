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

    def test_iss_keeps_user_data(self):
        s = rd("installer", "claudia.iss")
        inst = s.split("[InstallDelete]")[1].split("[Files]")[0]
        self.assertNotIn(".venv\"", inst)
        self.assertNotIn("{userappdata}", s)

    def test_workflow_manual(self):
        s = rd(".github", "workflows", "build-windows.yml")
        self.assertIn("workflow_dispatch", s)
        self.assertIn("claudia.iss", s)

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
