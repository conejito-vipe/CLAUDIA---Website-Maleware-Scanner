"""2.4.0: Programmfenster ohne Systemrahmen mit eigener Titelleiste (Chip, Minimieren, Maximieren, Schließen), Rückfall auf normalen Rahmen."""
import os
import sys
import tempfile
import threading
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

from claudia import window  # noqa: E402
from claudia.server import make_server  # noqa: E402
from test_window import Base, FakeWebview  # noqa: E402


class Spy(FakeWebview):
    def create_window(self, title, url, **kw):
        self.kw = kw
        win = super().create_window(title, url, **kw)
        win.calls = []
        win.minimize = lambda: win.calls.append("min")
        win.maximize = lambda: win.calls.append("max")
        win.restore = lambda: win.calls.append("restore")
        win.destroy = lambda: win.calls.append("destroy")
        self.win = win
        return win


class Old(Spy):
    """pywebview ohne frameless/shadow/js_api."""
    def create_window(self, title, url, **kw):
        if "frameless" in kw or "js_api" in kw:
            raise TypeError("unexpected keyword")
        return super().create_window(title, url, **kw)


class Frameless(Base):
    def test_frameless_window_with_api(self):
        wv = Spy(self)
        w = window.Window(self.srv, lambda: None, webview_module=wv)
        self.assertEqual(w.show(), "webview")
        self.assertTrue(wv.kw["frameless"] and wv.kw["shadow"] and not wv.kw["easy_drag"])
        api = wv.kw["js_api"]
        self.assertTrue(api.is_custom_frame())
        api.minimize()
        api.toggle_maximize()
        api.toggle_maximize()
        api.close()
        self.assertEqual(wv.win.calls, ["min", "max", "restore", "destroy"])

    def test_api_exposes_only_the_title_bar_functions(self):
        public = sorted(n for n in dir(window.WindowApi) if not n.startswith("_"))
        self.assertEqual(public, ["close", "get_rect", "get_size", "is_custom_frame", "is_maximized", "minimize", "resize_by", "set_size", "toggle_maximize"])

    def test_old_pywebview_falls_back_to_normal_frame(self):
        wv = Old(self)
        w = window.Window(self.srv, lambda: None, webview_module=wv)
        self.assertEqual(w.show(), "webview")
        self.assertNotIn("frameless", wv.kw)

    def test_env_switch_disables_frameless(self):
        os.environ["CLAUDIA_NO_FRAMELESS"] = "1"
        try:
            wv = Spy(self)
            window.Window(self.srv, lambda: None, webview_module=wv).show()
            self.assertNotIn("frameless", wv.kw)
        finally:
            os.environ.pop("CLAUDIA_NO_FRAMELESS", None)

    def test_close_asks_when_a_run_is_active(self):
        wv = Spy(self)
        w = window.Window(self.srv, lambda: None, webview_module=wv)
        w.show()
        self.srv.app.running = True
        wv.win.create_confirmation_dialog = lambda t, m: False          # Nutzer sagt: nicht beenden
        wv.kw["js_api"].close()
        self.assertNotIn("destroy", wv.win.calls)
        self.srv.app.running = False

    def test_page_has_titlebar_hidden_by_default_and_favicon(self):
        page = open(os.path.join(os.path.dirname(HERE), "claudia", "web", "index.html"), encoding="utf-8").read()
        self.assertIn('id="titlebar"', page)
        self.assertIn('class="titlebar pywebview-drag-region" hidden', page)
        self.assertIn("favicon-64.png", page)
        self.assertNotIn("logo.svg", page)


if __name__ == "__main__":
    unittest.main()
