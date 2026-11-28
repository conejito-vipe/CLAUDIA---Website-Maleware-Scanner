"""Einzelne Programmdatei (.exe / Mac-App): Update-Sperre, Deinstallation ohne .venv, Selbsttest der Programmdaten, Build-Aufruf, Release-Notizen.

Gebaut wird hier nichts (Windows und Mac gehen nur auf dem jeweiligen System, siehe .github/workflows/release.yml); geprüft wird die Mechanik drumherum."""
import hashlib
import io
import os
import shutil
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, "tools"))
sys.path.insert(0, os.path.join(ROOT, "installer"))

from claudia import __main__ as main_mod, appupdate, uninstall  # noqa: E402
from test_appupdate import make_zip, old_program, release  # noqa: E402
import build_exe  # noqa: E402
import exe_main  # noqa: E402


def tree(root):
    out = {}
    for base, _d, names in os.walk(root):
        for n in names:
            p = os.path.join(base, n)
            with open(p, "rb") as fh:
                out[os.path.relpath(p, root)] = fh.read()
    return out


class UpdateSperre(unittest.TestCase):
    def setUp(self):
        self.base = tempfile.mkdtemp(prefix="claudia_exe_")
        self.addCleanup(shutil.rmtree, self.base, True)
        self.root = old_program(self.base)
        self.data = os.path.join(self.base, "daten")
        self.zip = make_zip()
        self.info = appupdate.parse_release(release(sha=hashlib.sha256(self.zip).hexdigest()), "2.15.0")
        self.fetched = []

    def fetch(self, url, *a):
        self.fetched.append(url)
        return self.zip

    def test_frozen_never_installs_and_touches_nothing(self):
        before = tree(self.root)
        with mock.patch.object(appupdate, "FROZEN", True):
            r = appupdate.install(self.info, self.root, self.data, None, self.fetch, current="2.15.0")
        self.assertFalse(r["ok"])
        self.assertIn("Release-Seite", r["error"])
        self.assertEqual(self.fetched, [])                           # nicht einmal geladen
        self.assertEqual(tree(self.root), before)

    def test_not_frozen_still_installs(self):
        with mock.patch.object(appupdate, "FROZEN", False):
            r = appupdate.install(self.info, self.root, self.data, None, self.fetch, current="2.15.0")
        self.assertTrue(r["ok"], r)

    def test_frozen_flag_follows_pyinstaller_marker(self):
        import subprocess
        code = "import sys\nsys.path.insert(0, %r)\nif len(sys.argv) > 1: sys.frozen = True\nfrom claudia import appupdate\nprint(appupdate.FROZEN)" % ROOT
        for arg, want in (([], "False"), (["1"], "True")):
            out = subprocess.run([sys.executable, "-I", "-c", code] + arg, cwd=ROOT, capture_output=True, text=True, timeout=60)
            self.assertEqual(out.stdout.strip(), want, out.stderr)


class Deinstallation(unittest.TestCase):
    def setUp(self):
        self.base = tempfile.mkdtemp(prefix="claudia_exe_")
        self.addCleanup(shutil.rmtree, self.base, True)
        self.root = old_program(self.base)
        self.data = os.path.join(self.base, "daten")
        os.makedirs(os.path.join(self.data, "cache"))
        self.reports = os.path.join(self.data, "Berichte")

    def ids(self):
        return [i["id"] for i in uninstall.plan(self.root, self.data, self.reports)]

    def test_normal_has_venv_and_program(self):
        with mock.patch.object(sys, "frozen", False, create=True):
            ids = self.ids()
        self.assertIn("venv", ids)
        self.assertIn("cache", ids)

    def test_frozen_has_neither_venv_nor_program_folder(self):
        with mock.patch.object(sys, "frozen", True, create=True):
            ids = self.ids()
            self.assertNotIn("venv", ids)
            self.assertNotIn("program", ids)
            self.assertIn("cache", ids)                              # Nutzerdaten lassen sich weiterhin entfernen
            self.assertFalse(uninstall.window_available())           # kein Python für ein Zusatzfenster: sichtbares Löschskript

    def test_frozen_script_only_names_data_paths(self):
        with mock.patch.object(sys, "frozen", True, create=True):
            chosen = uninstall.validate(uninstall.plan(self.root, self.data, self.reports), ["cache"], self.root, self.data)
            script = uninstall.build_script(chosen, [4242], self.data, windows=False)
        self.assertIn(os.path.join(self.data, "cache"), script)
        self.assertNotIn(".venv", script)
        self.assertNotIn(self.root, script)


class Selbsttest(unittest.TestCase):
    def test_resources_present(self):
        ok, missing = main_mod.resources_ok()
        self.assertTrue(ok, missing)

    def test_missing_resource_is_reported(self):
        with mock.patch.object(main_mod, "RESOURCES", main_mod.RESOURCES + ("web/gibt_es_nicht.js",)):
            ok, missing = main_mod.resources_ok()
        self.assertFalse(ok)
        self.assertEqual(missing, ["web/gibt_es_nicht.js"])

    def test_selftest_fails_when_data_missing(self):
        buf = io.StringIO()
        with mock.patch.object(main_mod, "resources_ok", return_value=(False, ["web/index.html"])), redirect_stdout(buf):
            code = main_mod.selftest()
        self.assertEqual(code, 1)
        self.assertIn("FEHLEN: web/index.html", buf.getvalue())

    def test_selftest_ok(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main_mod.selftest()
        self.assertEqual(code, 0, buf.getvalue())
        self.assertIn("Programmdaten: vollständig", buf.getvalue())


class EinstiegUndBuild(unittest.TestCase):
    def test_entry_replaces_missing_streams(self):
        d = tempfile.mkdtemp(prefix="claudia-log-")
        with mock.patch.dict(os.environ, {"CLAUDIA_LOG_DIR": d}), \
                mock.patch.object(sys, "stdout", None), mock.patch.object(sys, "stderr", None), \
                mock.patch("faulthandler.enable"), mock.patch("logging.basicConfig"):
            exe_main._streams()
            self.assertIsNotNone(sys.stdout)
            sys.stdout.write("x-ausgabe")                            # darf nicht abstürzen
            self.assertIsNotNone(sys.stderr)
            sys.stdout.close()
        with open(os.path.join(d, "claudia.log"), encoding="utf-8") as f:
            text = f.read()
        self.assertIn("===== Start", text)                           # Programmprotokoll für die Fehlersuche
        self.assertIn("x-ausgabe", text)

    def test_log_rotates_when_large(self):
        d = tempfile.mkdtemp(prefix="claudia-log-")
        with open(os.path.join(d, "claudia.log"), "w") as f:
            f.write("a" * (exe_main.MAX_LOG + 10))
        with mock.patch.dict(os.environ, {"CLAUDIA_LOG_DIR": d}):
            exe_main._log_oeffnen().close()
        self.assertTrue(os.path.isfile(os.path.join(d, "claudia.alt.log")))
        self.assertLess(os.path.getsize(os.path.join(d, "claudia.log")), 1000)

    def test_entry_keeps_existing_streams(self):
        out = io.StringIO()
        with mock.patch.object(sys, "stdout", out):
            exe_main._streams()
            self.assertIs(sys.stdout, out)

    def test_entry_calls_main_with_argv(self):
        with mock.patch.object(main_mod, "main", return_value=7) as m:
            self.assertEqual(exe_main.run(["--selftest"]), 7)
        m.assert_called_once_with(["--selftest"])

    def test_pyinstaller_args(self):
        staged = build_exe.stage_package(os.path.join(tempfile.mkdtemp(prefix="claudia_stage_"), "d"))
        self.addCleanup(shutil.rmtree, os.path.dirname(os.path.dirname(staged)), True)
        for pf, windowed in (("linux", False), ("win32", True), ("darwin", True)):
            with mock.patch.object(sys, "platform", pf):
                a = build_exe.pyinstaller_args("/tmp/w", staged)
            self.assertEqual("--windowed" in a, windowed, pf)
            self.assertIn("--onedir", a)
            self.assertTrue(a[-1].endswith("exe_main.py"))
            self.assertIn("--collect-submodules", a)
            self.assertIn("claudia", a)
        self.assertEqual(os.path.basename(staged), "claudia")
        self.assertTrue(os.path.isfile(os.path.join(staged, "web", "index.html")))
        self.assertTrue(os.path.isfile(os.path.join(staged, "techdoc.py")))                  # Quelltext für das Kapitel Technik
        self.assertFalse(any("__pycache__" in p for p, _d, _f in os.walk(staged)))

    def test_zip_keeps_layout_and_exec_bit(self):
        base = tempfile.mkdtemp(prefix="claudia_zip_")
        self.addCleanup(shutil.rmtree, base, True)
        src = os.path.join(base, "src")
        os.makedirs(os.path.join(src, "_internal"))
        exe = os.path.join(src, "CLAUDIA")
        open(exe, "w").write("x")
        os.chmod(exe, 0o755)
        open(os.path.join(src, "_internal", "a.txt"), "w").write("a")
        z = os.path.join(base, "o.zip")
        build_exe.zip_dir(src, z, "CLAUDIA")
        import zipfile
        with zipfile.ZipFile(z) as f:
            names = sorted(f.namelist())
            mode = f.getinfo("CLAUDIA/CLAUDIA").external_attr >> 16
        self.assertEqual(names, ["CLAUDIA/CLAUDIA", "CLAUDIA/_internal/a.txt"])
        self.assertTrue(mode & 0o111)


class ReleaseText(unittest.TestCase):
    def setUp(self):
        import release_body
        self.rb = release_body
        self.dir = tempfile.mkdtemp(prefix="claudia_rb_")
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.v = __import__("claudia").__version__
        self.notes = "# CLAUDIA %s - Title\n\n- **A**: b\n\n<details>\n<summary>Deutsch</summary>\n\n- **A**: b\n</details>\n" % self.v
        self.zip = os.path.join(self.dir, "CLAUDIA_v%s.zip" % self.v)
        with open(self.zip, "wb") as f:
            f.write(b"paket")

    def test_body_has_hash_line_of_package_and_files(self):
        t = self.rb.body(self.dir, self.notes, self.v)
        self.assertIn("SHA-256: " + hashlib.sha256(b"paket").hexdigest(), t)
        self.assertIn("`CLAUDIA_v%s.zip`" % self.v, t)
        self.assertIn("SHA256SUMS.txt", t)
        self.assertNotIn("Setup", t)                                   # nur Dateien, die es gibt
        self.assertTrue(t.startswith("# CLAUDIA %s" % self.v))
        self.assertIn("<details>", t)

    def test_update_reads_hash_and_hides_file_list(self):
        t = self.rb.body(self.dir, self.notes, self.v)
        info = appupdate.parse_release({"tag_name": "v" + self.v, "body": t, "html_url": "https://github.com/x", "assets": [
            {"name": "CLAUDIA_v%s.zip" % self.v, "browser_download_url": appupdate.DOWNLOAD_PREFIX + "x.zip", "size": 5}]}, "0.0.1")
        self.assertEqual(info["sha256"], hashlib.sha256(b"paket").hexdigest())
        for lang in ("en", "de"):
            shown = appupdate.notes_for_lang(t, lang)
            self.assertNotIn("SHA-256", shown)
            self.assertNotIn("## Files", shown)
            self.assertNotIn("<details>", shown)

    def test_other_hash_lines_never_in_body(self):
        for n in ("CLAUDIA_v%s_Mac.zip" % self.v, "CLAUDIA_v%s_Windows.zip" % self.v, "CLAUDIA-Setup-%s.exe" % self.v):
            with open(os.path.join(self.dir, n), "wb") as f:
                f.write(n.encode())
        self.rb.write_sums(self.dir)
        t = self.rb.body(self.dir, self.notes, self.v)
        import re
        self.assertEqual(len(re.findall(r"[0-9a-f]{64}", t)), 1)       # nur die Prüfsumme des Pakets
        sums = open(os.path.join(self.dir, "SHA256SUMS.txt"), encoding="utf-8").read().splitlines()
        self.assertEqual(len(sums), 4)
        self.assertNotIn("SHA256SUMS.txt", " ".join(sums))

    def test_wrong_version_or_missing_zip_refused(self):
        with self.assertRaises(ValueError):
            self.rb.body(self.dir, self.notes.replace(self.v, "0.0.1"), self.v)
        os.remove(self.zip)
        with self.assertRaises(ValueError):
            self.rb.body(self.dir, self.notes, self.v)

    def test_current_release_notes_match_version(self):
        self.assertEqual(self.rb.notes_version(open(os.path.join(ROOT, "RELEASE_NOTES.md"), encoding="utf-8").read()), self.v)


class Workflow(unittest.TestCase):
    def setUp(self):
        self.s = open(os.path.join(ROOT, ".github", "workflows", "release.yml"), encoding="utf-8").read()

    def test_manual_and_least_privilege(self):
        import re
        self.assertIn("workflow_dispatch", self.s)
        self.assertEqual(len(re.findall(r"contents: write", self.s)), 1)   # nur der Release-Job darf schreiben
        top = self.s.split("jobs:")[0]
        self.assertIn("contents: read", top)
        release = self.s.split("\n  release:")[1]
        self.assertIn("contents: write", release)
        self.assertNotIn("contents: write", self.s.split("\n  release:")[0])

    def test_actions_pinned_by_commit(self):
        import re
        for m in re.finditer(r"uses:\s*(\S+)", self.s):
            self.assertRegex(m.group(1), r"@[0-9a-f]{40}$", m.group(1))

    def test_release_steps(self):
        for part in ("gh release create", "gh release upload", "--clobber", "release_body.md", "tools/release_body.py", "tools/build_exe.py",
                     "tools/build_release.py", "--selftest", "FrozenApp=1", "needs: [package, windows, mac]"):
            self.assertIn(part, self.s, part)

    def test_no_license_info_in_release_files(self):
        low = self.s.lower() + open(os.path.join(ROOT, "tools", "release_body.py"), encoding="utf-8").read().lower()
        for word in ("lizenz", "license key", "paypal", "pro-version"):
            self.assertNotIn(word, low)


if __name__ == "__main__":
    unittest.main()
