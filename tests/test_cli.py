"""Start über die Kommandozeile (wie start.bat): Server startet, liefert Oberfläche, Selbsttest läuft."""
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)


class Cli(unittest.TestCase):
    def env(self):
        e = dict(os.environ)
        e["CLAUDIA_HOME"] = tempfile.mkdtemp(prefix="claudia_home_")
        e["CLAUDIA_REPORTS"] = os.path.join(e["CLAUDIA_HOME"], "b")
        e["PYTHONPATH"] = ROOT
        e["PYTHONIOENCODING"] = "utf-8"
        return e

    def test_selftest(self):
        p = subprocess.run([sys.executable, "-m", "claudia", "--selftest"], cwd=ROOT, env=self.env(),
                           capture_output=True, text=True, timeout=60)
        self.assertIn("74 geladen", p.stdout)
        self.assertIn("beschreibbar", p.stdout)

    def test_starts_without_key_leak(self):
        """Der Prozess meldet nur Stichworte; weder Adresse noch Startschlüssel erscheinen in der Ausgabe."""
        e = self.env()
        e["CLAUDIA_TEST_NO_WINDOW"] = "1"
        p = subprocess.Popen([sys.executable, "-u", "-m", "claudia", "--parent-pid", str(os.getpid())], cwd=ROOT, env=e,
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8")
        try:
            out = []
            t0 = time.time()
            while time.time() - t0 < 20:
                line = p.stdout.readline()
                out.append(line)
                if "CLAUDIA_WINDOW" in line:
                    break
            joined = "".join(out)
            self.assertIn("CLAUDIA_READY", joined)
            self.assertIn("CLAUDIA_WINDOW", joined)
            self.assertNotIn("?k=", joined)
            self.assertNotRegex(joined, r"127\.0\.0\.1")
        finally:
            p.terminate()
            p.wait(10)

    def test_main_with_stub_window_serves_ui(self):
        import io
        import contextlib
        from claudia.__main__ import main
        seen = {}

        def show(srv):
            import http.cookiejar
            op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
            seen["page"] = op.open(srv.entry_url()).read().decode("utf-8")           # Startschlüssel -> Cookie -> Oberfläche
            srv.stop()
            return "test"
        e = self.env()
        os.environ.update(CLAUDIA_HOME=e["CLAUDIA_HOME"], CLAUDIA_REPORTS=e["CLAUDIA_REPORTS"])
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = main([], show=show)
        self.assertEqual(rc, 0)
        self.assertIn("CLAUDIA_READY", buf.getvalue())
        self.assertIn("CLAUDIA", seen["page"])
        self.assertNotIn("claudia-token", seen["page"])


if __name__ == "__main__":
    unittest.main()
