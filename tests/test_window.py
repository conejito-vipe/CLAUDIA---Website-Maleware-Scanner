"""Programmfenster: Wege (pywebview, App-Modus, Notfall-Browser), Einmal-Startschlüssel, Schließen-Nachfrage."""
import os
import sys
import tempfile
import threading
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from claudia import window  # noqa: E402
from claudia.server import make_server  # noqa: E402


class Base(unittest.TestCase):
    def setUp(self):
        os.environ.pop("CLAUDIA_TEST_NO_WINDOW", None)
        self.srv = make_server(directory=tempfile.mkdtemp(prefix="claudia_win_"))
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.announced = []

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()

    def open_page(self, url):
        """Wie das Fenster: Startschlüssel einlösen (gelingt nur einmal) und die Seite laden."""
        import http.cookiejar
        import urllib.request
        op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        return op.open(url).read().decode("utf-8")


class FakeWebview:
    def __init__(self, test):
        self.test = test
        self.settings = {}
        self.urls = []

    def create_window(self, title, url, **kw):
        self.urls.append(url)
        self.title = title
        win = type("W", (), {})()
        win.events = type("E", (), {"closing": type("C", (), {"__iadd__": lambda s, f: s})()})()
        win.destroy = lambda: None
        return win

    def start(self, **kw):
        page = self.test.open_page(self.urls[0])
        self.test.assertIn("CLAUDIA", page)


class Ways(Base):
    def test_pywebview_way(self):
        wv = FakeWebview(self)
        w = window.Window(self.srv, lambda: self.announced.append(1), webview_module=wv)
        self.assertEqual(w.show(), "webview")
        self.assertTrue(wv.settings.get("ALLOW_DOWNLOADS"))
        self.assertIn("?k=", wv.urls[0])
        self.assertIn("CLAUDIA", wv.title)
        time.sleep(0.3)
        self.assertEqual(self.announced, [1])             # Startfenster darf sich schließen, sobald die Seite geladen ist

    def test_key_works_only_once(self):
        url = self.srv.entry_url()
        self.assertIn("CLAUDIA", self.open_page(url))
        with self.assertRaises(Exception):
            self.open_page(url)

    def test_app_mode_way_when_pywebview_missing(self):
        calls = []

        class Proc:
            def __init__(s):
                s.n = 0

            def poll(s):
                s.n += 1
                return 0 if s.n > 3 else None

            def terminate(s):
                pass

        def popen(args, **kw):
            calls.append(args)
            threading.Thread(target=lambda: self.open_page([a for a in args if a.startswith("--app=")][0][6:]), daemon=True).start()
            return Proc()
        w = window.Window(self.srv, lambda: self.announced.append(1), webview_module=False, popen=popen, browser_finder=lambda: "/usr/bin/edge")
        w._try_webview = lambda: False
        self.assertEqual(w.show(), "app")
        args = calls[0]
        self.assertTrue(any(a.startswith("--app=http://127.0.0.1:") and "?k=" in a for a in args))
        profile = [a for a in args if a.startswith("--user-data-dir=")][0].split("=", 1)[1]
        self.assertFalse(os.path.exists(profile), "Temporäres Profil muss aufgeräumt werden")
        time.sleep(0.3)
        self.assertEqual(self.announced, [1])

    def test_browser_fallback_ends_without_heartbeat(self):
        opened = []
        old = window.PING_TIMEOUT
        window.PING_TIMEOUT = 1.5
        try:
            w = window.Window(self.srv, lambda: None, opener=lambda u: opened.append(u) or self.open_page(u), browser_finder=lambda: None)
            w._try_webview = lambda: False
            t0 = time.time()
            self.assertEqual(w.show(), "browser")
            self.assertLess(time.time() - t0, 15)
            self.assertIn("?k=", opened[0])
        finally:
            window.PING_TIMEOUT = old


class BlankWindow(Base):
    def test_reloads_once_when_page_stays_blank(self):
        import io, contextlib, time
        calls = []

        class Win:
            def load_url(self, url):
                calls.append(url)
        w = window.Window(self.srv, lambda: None)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            w._reload_if_blank(Win(), wait=0.05)
            time.sleep(0.4)
        self.assertEqual(len(calls), 1)
        self.assertIn("nicht geladen", err.getvalue())                 # steht im Programmprotokoll

    def test_no_reload_when_page_loaded(self):
        import time
        calls = []

        class Win:
            def load_url(self, url):
                calls.append(url)
        self.srv.note_page_load()
        window.Window(self.srv, lambda: None)._reload_if_blank(Win(), wait=0.05)
        time.sleep(0.2)
        self.assertEqual(calls, [])


class Closing(Base):
    def test_closing_asks_only_while_busy(self):
        w = window.Window(self.srv, lambda: None)
        asked = []
        w._win = type("W", (), {"create_confirmation_dialog": lambda s, t, m: asked.append(m) or False})()
        self.assertTrue(w._on_closing())
        self.assertEqual(asked, [])
        self.srv.app.running = True
        self.assertFalse(w._on_closing())                  # Nutzer sagt "nein": Fenster bleibt
        self.assertEqual(len(asked), 1)
        w._stopping.set()
        self.assertTrue(w._on_closing())                   # 'Programm beenden' in der Oberfläche: nicht nachfragen


class Browsers(unittest.TestCase):
    def test_app_mode_args(self):
        a = window.app_mode_args("/x/edge", "http://127.0.0.1:1/?k=a", "/tmp/p")
        self.assertEqual(a[0], "/x/edge")
        self.assertIn("--app=http://127.0.0.1:1/?k=a", a)
        self.assertIn("--user-data-dir=/tmp/p", a)

    def test_login_brake(self):
        from claudia.server import ApiError, App
        app = App(tempfile.mkdtemp(prefix="claudia_lb_"))
        app.LOGIN_MIN_GAP = 0
        for _ in range(app.LOGIN_MAX_FAILS):
            app._login_gate()
            app._login_failed()
        with self.assertRaises(ApiError) as c:
            app._login_gate()
        self.assertEqual(c.exception.status, 429)


if __name__ == "__main__":
    unittest.main()
