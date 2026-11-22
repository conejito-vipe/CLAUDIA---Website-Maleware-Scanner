"""2.9.0 Mac: Startdatei start.command, Speicherorte, Browser-Suche, Fenster mit normalem Rahmen, Fehlerfenster, Deinstallations-Hinweis, Zip-Rechte.
Die Tests laufen auf Linux und Mac; der Mac wird dabei über sys.platform nachgestellt, die Shell-Prüfungen laufen mit echter bash."""
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import types
import unittest
import zipfile
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tools"))

from claudia import launcher, server, uninstall, window  # noqa: E402

START = os.path.join(ROOT, "start.command")


class StartFile(unittest.TestCase):
    def test_exists_executable_shebang(self):
        self.assertTrue(os.path.isfile(START))
        self.assertTrue(os.stat(START).st_mode & stat.S_IXUSR, "start.command braucht das Ausführrecht")
        with open(START, encoding="utf-8") as fh:
            self.assertEqual(fh.readline().strip(), "#!/bin/bash")

    def test_no_windows_line_endings(self):
        with open(START, "rb") as fh:
            self.assertNotIn(b"\r", fh.read())

    @unittest.skipUnless(shutil.which("bash"), "bash fehlt")
    def test_syntax(self):
        r = subprocess.run(["bash", "-n", START], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)

    @unittest.skipUnless(shutil.which("bash"), "bash fehlt")
    def test_dryrun_finds_python_and_logs(self):
        d = tempfile.mkdtemp(prefix="claudia_mac_")
        prog = os.path.join(d, "CLAUDIA")
        os.makedirs(os.path.join(prog, "claudia"))
        shutil.copy(START, os.path.join(prog, "start.command"))
        open(os.path.join(prog, "claudia", "launcher.py"), "w").close()
        stub = os.path.join(d, "bin")
        os.makedirs(stub)
        py = os.path.join(stub, "python3.13")
        with open(py, "w") as fh:
            fh.write("#!/bin/sh\nexit 0\n")           # besteht die Versionsprüfung
        os.chmod(py, 0o755)
        env = dict(os.environ, HOME=os.path.join(d, "home"), PATH=stub + os.pathsep + os.environ.get("PATH", ""), CLAUDIA_START_DRYRUN="1")
        os.makedirs(env["HOME"])
        r = subprocess.run(["bash", os.path.join(prog, "start.command")], capture_output=True, text=True, env=env, timeout=60)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("PY=" + py, r.stdout)
        self.assertNotIn("INSTALL", r.stdout)

    @unittest.skipUnless(shutil.which("bash"), "bash fehlt")
    def test_wrong_folder_message(self):
        d = tempfile.mkdtemp(prefix="claudia_mac_")
        shutil.copy(START, os.path.join(d, "start.command"))
        env = dict(os.environ, HOME=d)
        r = subprocess.run(["bash", os.path.join(d, "start.command")], capture_output=True, text=True, env=env, stdin=subprocess.DEVNULL, timeout=60)
        self.assertEqual(r.returncode, 1)
        self.assertIn("entpackten Ordner", r.stdout)


class Paths(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.mkdtemp(prefix="claudia_home_")
        self.env = mock.patch.dict(os.environ, {"HOME": self.home, "USERPROFILE": self.home})
        self.env.start()
        os.environ.pop("CLAUDIA_HOME", None)          # andere Tests setzen sie; hier soll die Vorgabe geprüft werden
        os.environ.pop("CLAUDIA_REPORTS", None)
        self.plat = mock.patch.object(sys, "platform", "darwin")
        self.plat.start()

    def tearDown(self):
        self.plat.stop()
        self.env.stop()

    @unittest.skipIf(os.name == "nt", "nur Mac/Linux")
    def test_data_dir_application_support(self):
        self.assertEqual(server.data_dir(), os.path.join(self.home, "Library", "Application Support", "CLAUDIA"))

    @unittest.skipIf(os.name == "nt", "nur Mac/Linux")
    def test_documents_dir(self):
        self.assertEqual(server.documents_dir(), "")
        os.makedirs(os.path.join(self.home, "Documents"))
        self.assertEqual(server.documents_dir(), os.path.join(self.home, "Documents"))

    @unittest.skipIf(os.name == "nt", "nur Mac/Linux")
    def test_linux_unchanged(self):
        with mock.patch.object(sys, "platform", "linux"):
            self.assertEqual(server.data_dir(), os.path.join(self.home, ".claudia"))

    @unittest.skipIf(os.name == "nt", "nur Mac/Linux")
    def test_app_browser_finds_mac_apps(self):
        exe = os.path.join(self.home, "Applications", "Google Chrome.app", "Contents", "MacOS", "Google Chrome")
        os.makedirs(os.path.dirname(exe))
        open(exe, "w").close()
        with mock.patch.object(window.shutil, "which", return_value=None):
            found = window.app_browser()
        self.assertTrue(found == exe or found.startswith("/Applications/"), found)

    @unittest.skipIf(os.name == "nt", "nur Mac/Linux")
    def test_app_browser_none(self):
        with mock.patch.object(window.shutil, "which", return_value=None), mock.patch.object(window.os.path, "isfile", return_value=False):
            self.assertIsNone(window.app_browser())


class RealStart(unittest.TestCase):
    """Echter Start des Programms ohne Fenster: der Server meldet Stichworte, aber weder Adresse noch Startschlüssel."""

    def test_starts_and_reports_keywords_only(self):
        import queue
        home = tempfile.mkdtemp(prefix="claudia_home_")
        env = dict(os.environ, CLAUDIA_HOME=home, CLAUDIA_REPORTS=os.path.join(home, "b"), PYTHONPATH=ROOT,
                   PYTHONIOENCODING="utf-8", CLAUDIA_TEST_NO_WINDOW="1")
        p = subprocess.Popen([sys.executable, "-u", "-m", "claudia", "--parent-pid", str(os.getpid())], cwd=ROOT, env=env,
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8")
        q = queue.Queue()

        def pump():
            for line in p.stdout:
                q.put(line)
            q.put(None)
        threading.Thread(target=pump, daemon=True).start()
        out = []
        try:
            import time
            t0 = time.time()
            while time.time() - t0 < 60:
                try:
                    line = q.get(timeout=1)
                except queue.Empty:
                    continue
                if line is None:
                    break
                out.append(line)
                if "CLAUDIA_WINDOW" in line:
                    break
            joined = "".join(out)
            msg = "Ausgabe: %r, Prozess beendet: %s" % (joined, p.poll())
            self.assertIn("CLAUDIA_READY", joined, msg)
            self.assertIn("CLAUDIA_WINDOW", joined, msg)
            self.assertNotIn("?k=", joined)
            self.assertNotRegex(joined, r"127\.0\.0\.1")
        finally:
            p.terminate()
            try:
                p.wait(10)
            except subprocess.TimeoutExpired:
                p.kill()


class FakeWebview:
    def __init__(self):
        self.settings = {}
        self.screens = None
        self.kwargs = []

    def create_window(self, title, url, **kw):
        self.kwargs.append(kw)
        return types.SimpleNamespace(events=types.SimpleNamespace(closing=[]), destroy=lambda: None)

    def start(self, debug=False):
        return None


class WindowFrame(unittest.TestCase):
    def make(self):
        srv = types.SimpleNamespace(entry_url=lambda: "http://127.0.0.1:1/x", page_loaded=threading.Event(), on_stop=[], app=None)
        return window.Window(srv, lambda: None, webview_module=FakeWebview())

    def test_mac_uses_native_frame(self):
        w = self.make()
        with mock.patch.object(sys, "platform", "darwin"):
            w._try_webview()
        kw = w._webview.kwargs[0]
        self.assertNotIn("frameless", kw)
        self.assertNotIn("js_api", kw)

    def test_other_platforms_keep_custom_frame(self):
        w = self.make()
        with mock.patch.object(sys, "platform", "linux"):
            w._try_webview()
        self.assertTrue(w._webview.kwargs[0].get("frameless"))

    def test_dock_icon_is_harmless_without_appkit(self):
        with mock.patch.object(sys, "platform", "darwin"):
            window._mac_dock_icon()


class LauncherMac(unittest.TestCase):
    def test_as_str_escapes(self):
        self.assertEqual(launcher._as_str('A "b"\nC\\'), '"A \\"b\\"" & return & "C\\\\"')

    def test_error_dialog_uses_osascript(self):
        ui = launcher.ConsoleUi()
        calls = []
        with mock.patch.object(sys, "platform", "darwin"), mock.patch.object(launcher.subprocess, "run", side_effect=lambda *a, **k: calls.append(a[0])):
            ui.error("Titel", "Text", "Details", "/tmp/x.log")
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][0], "osascript")
        self.assertIn("display dialog", calls[0][2])
        self.assertTrue(ui.failed)

    @unittest.skipIf(os.name == "nt", "nur Mac/Linux")
    def test_program_starts_in_own_session(self):
        self.assertEqual(launcher.DETACH, {"start_new_session": True})


class UninstallMac(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="claudia_uni_")
        self.data = os.path.join(self.d, "data")
        os.makedirs(self.data)

    def test_hint_with_marker_on_mac(self):
        open(os.path.join(self.data, uninstall.PY_MARKER_ORG), "w").close()
        with mock.patch.object(sys, "platform", "darwin"):
            hint = uninstall.python_org_hint(self.data)
        self.assertIn("start.command", hint)
        self.assertIn("Papierkorb", hint)

    def test_no_hint_without_marker(self):
        with mock.patch.object(sys, "platform", "darwin"):
            self.assertEqual(uninstall.python_org_hint(self.data), "")

    def test_safe_root_accepts_start_command(self):
        r = os.path.join(self.d, "prog")
        os.makedirs(r)
        open(os.path.join(r, "start.command"), "w").close()
        self.assertTrue(uninstall._safe_root(r))


class ZipRights(unittest.TestCase):
    def test_start_command_executable_in_zip(self):
        import build_release
        d = tempfile.mkdtemp(prefix="claudia_zip_")
        out = os.path.join(d, "t.zip")
        with zipfile.ZipFile(out, "w") as z:
            build_release.add_file(z, START, "CLAUDIA/start.command")
            build_release.add_file(z, os.path.join(ROOT, "README.md"), "CLAUDIA/README.md")
        with zipfile.ZipFile(out) as z:
            modes = {i.filename: (i.external_attr >> 16) & 0o777 for i in z.infolist()}
            self.assertEqual(modes["CLAUDIA/start.command"], 0o755)
            self.assertEqual(modes["CLAUDIA/README.md"], 0o644)
            self.assertEqual(z.read("CLAUDIA/start.command"), open(START, "rb").read())


if __name__ == "__main__":
    unittest.main()
