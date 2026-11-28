"""3.1.1: Abbrechen einer hängenden Prüfung und Trennen (Bericht 28.11.: Test hing bei 'Von außen: System und Version erkennen',
Abbruch dauerte lange, danach 'Es läuft bereits eine Prüfung', Trennen trennte nicht wirklich)."""
import os
import sys
import tempfile
import threading
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

from claudia.server import make_server  # noqa: E402


class HangingEngine:
    """Hängt in einem 'Netzwerkaufruf', der nicht auf Abbrechen reagiert, und meldet danach noch ein Ergebnis."""
    def __init__(self, release):
        self.release = release

    def run(self, ids, emit, cancel):
        emit({"type": "start", "id": "ext_fingerprint"})
        self.release.wait(10)
        emit({"type": "done", "result": {"id": "ext_fingerprint", "status": "ok", "findings": []}})


class Abbrechen(unittest.TestCase):
    def setUp(self):
        self.srv = make_server(directory=tempfile.mkdtemp(prefix="claudia_cancel_"))
        self.app = self.srv.app

    def tearDown(self):
        self.srv.server_close()

    def start_hanging(self):
        release = threading.Event()
        self.app.cancel = threading.Event()
        self.app.running = True
        self.app.started = time.time()
        self.app.thread = threading.Thread(target=self.app._work, args=(HangingEngine(release), ["ext_fingerprint"], self.app.cancel), daemon=True)
        self.app.thread.start()
        time.sleep(0.05)
        return release

    def test_cancel_frees_run_quickly_and_old_thread_writes_nothing(self):
        release = self.start_hanging()
        t0 = time.monotonic()
        self.app.cancel_run(wait=0.2)
        self.assertLess(time.monotonic() - t0, 1.5)                 # nicht minutenlang warten
        self.assertFalse(self.app.running)                          # neuer Lauf sofort möglich
        self.assertTrue(self.app.cancelled)
        release.set()                                               # der hängende Teil kommt später zurück
        self.app.thread.join(2)
        self.assertEqual(self.app.results, [])                      # ... und schreibt nichts mehr
        self.assertFalse(self.app.running)

    def test_disconnect_cancels_running_check_and_closes(self):
        release = self.start_hanging()
        closed = []

        class R:
            def close(self):
                closed.append(1)
        self.app.runner = R()
        self.app.conn = {"host": "h", "user": "u"}
        t0 = time.monotonic()
        self.app.disconnect()
        self.assertLess(time.monotonic() - t0, 3.0)
        self.assertFalse(self.app.running)
        self.assertEqual(closed, [1])
        self.assertIsNone(self.app.runner)
        self.assertEqual(self.app.conn, {})
        release.set()


if __name__ == "__main__":
    unittest.main(verbosity=2)


class StartseiteNichtErreichbar(unittest.TestCase):
    def test_unreachable_homepage_skips_probes(self):
        from unittest import mock
        from claudia.checks import extern, web
        from claudia.model import CheckSkipped
        calls = []

        def fetch(url, *a, **k):
            calls.append(url)
            f = web.Fetched()
            f.error = "timed out"
            return f
        ctx = mock.MagicMock()
        ctx.shared = {}
        ctx.s.url = "kinderperspektive.example"
        with mock.patch.object(web, "fetch", side_effect=fetch):
            with self.assertRaises(CheckSkipped) as cm:
                extern.gather(ctx)
            self.assertIn("nicht erreichbar", str(cm.exception))
            with self.assertRaises(CheckSkipped):
                extern.gather(ctx)                                  # nächster externer Test: sofort, ohne neuen Abruf
        self.assertEqual(len(calls), 1)                             # nur die Startseite, keine 12 Standardadressen

    def test_slow_site_stops_after_three_misses(self):
        from unittest import mock
        from claudia.checks import extern, web
        n = []

        def fetch(url, *a, **k):
            n.append(url)
            f = web.Fetched()
            if url.endswith("/"):
                f.status, f.body = (200, "<html></html>") if len(n) == 1 else (0, "")
            if len(n) > 1:
                f.error = "timed out"
            return f
        ctx = mock.MagicMock()
        ctx.shared = {}
        ctx.s.url = "langsam.example"
        with mock.patch.object(web, "fetch", side_effect=fetch):
            extern.gather(ctx)
        self.assertLessEqual(len(n), 1 + 1 + 3)                     # Startseite, Vergleichswert, höchstens 3 Fehlversuche
        self.assertTrue(any("Standardadresse 1 von" in str(c) for c in ctx.progress.call_args_list))


class FensterOhneThreadZugriff(unittest.TestCase):
    def test_no_winforms_access_from_event_threads(self):
        """Weißes Fenster / "reagiert nicht" (28.11.): das Fenstersymbol wurde im shown-Ereignis (eigener Thread) direkt am WinForms-Fenster gesetzt."""
        src = open(os.path.join(os.path.dirname(HERE), "claudia", "window.py"), encoding="utf-8").read()
        self.assertNotIn("events.shown +=", src)
        self.assertNotIn("win.native.Icon", src)
        self.assertIn("icon=window_icon()", src)
        self.assertIn("dump_traceback_later", src)               # hängt der Start, landet die Stelle im Protokoll
