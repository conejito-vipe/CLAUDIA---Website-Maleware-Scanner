"""2.4.1 Programmfenster: mittig auf dem Hauptbildschirm, nie größer als der Bildschirm, Größe per Ziehgriff änderbar.
Geprüft wird die Logik mit nachgebildetem pywebview. Das echte Verhalten unter Windows (Mitte, Ziehen, Skalierung) ist damit NICHT bewiesen."""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

from claudia import window  # noqa: E402
from test_frameless import Spy  # noqa: E402
from test_window import Base  # noqa: E402

ROOT = os.path.dirname(HERE)


class Scr:
    def __init__(self, x, y, w, h):
        self.x, self.y, self.width, self.height = x, y, w, h


class Geometry(unittest.TestCase):
    def test_large_screen_keeps_base_size_and_centers(self):
        g = window.start_geometry([Scr(0, 0, 2560, 1440)])
        self.assertEqual((g["width"], g["height"]), (window.WIDTH, window.HEIGHT))
        self.assertEqual(g["x"], (2560 - window.WIDTH) // 2)
        self.assertEqual(g["y"], (1440 - window.HEIGHT) // 2 - 20)

    def test_small_screen_gets_smaller_window_that_still_fits(self):
        g = window.start_geometry([Scr(0, 0, 1366, 768)])
        self.assertLessEqual(g["width"], 1366)
        self.assertLessEqual(g["height"], 768)
        self.assertGreaterEqual(g["x"], 0)
        self.assertGreaterEqual(g["y"], 0)
        self.assertEqual(g["x"] * 2 + g["width"], 1366 - (1366 - g["width"]) % 2)

    def test_second_monitor_offset_is_respected_and_primary_first(self):
        g = window.start_geometry([Scr(-1920, 0, 1920, 1080), Scr(0, 0, 1920, 1080)])
        self.assertLess(g["x"], 0)

    def test_missing_or_broken_screen_info_falls_back(self):
        for bad in (None, [], [object()], [Scr(0, 0, 0, 0)]):
            self.assertEqual(window.start_geometry(bad), {"width": window.WIDTH, "height": window.HEIGHT})


class Api(Base):
    def make(self):
        wv = Spy(self)
        w = window.Window(self.srv, lambda: None, webview_module=wv)
        w.show()
        wv.win.width, wv.win.height = 1200, 800
        sizes = []
        wv.win.resize = lambda a, b: sizes.append((a, b))
        return wv, w, sizes

    def test_window_is_created_with_position_and_size(self):
        wv = Spy(self)
        window.Window(self.srv, lambda: None, webview_module=wv).show()
        self.assertIn("width", wv.kw)
        self.assertIn("height", wv.kw)
        self.assertEqual(wv.kw["min_size"], (window.MIN_W, window.MIN_H))

    def test_resize_is_limited_and_validated(self):
        wv, w, sizes = self.make()
        api = wv.kw["js_api"]
        self.assertEqual(api.get_size(), [1200, 800])
        self.assertTrue(api.set_size(1500.7, 900))
        self.assertTrue(api.set_size(10, 10))
        self.assertTrue(api.set_size(10 ** 9, 10 ** 9))
        self.assertEqual(sizes, [(1500, 900), (window.MIN_W, window.MIN_H), (window.MAX_SIZE, window.MAX_SIZE)])
        for bad in (("a", 1), (None, None), ([], {})):
            self.assertFalse(api.set_size(*bad))
        self.assertEqual(len(sizes), 3)

    def test_no_resize_while_maximized(self):
        wv, w, sizes = self.make()
        api = wv.kw["js_api"]
        api.toggle_maximize()
        self.assertFalse(api.set_size(1400, 900))
        api.toggle_maximize()
        self.assertTrue(api.set_size(1400, 900))


class Page(unittest.TestCase):
    def test_handles_and_ui_wiring(self):
        html = open(os.path.join(ROOT, "claudia", "web", "index.html"), encoding="utf-8").read()
        js = open(os.path.join(ROOT, "claudia", "web", "app.js"), encoding="utf-8").read()
        for rid in ("rz-l", "rz-bl", "rz-r", "rz-b", "rz-br"):
            self.assertIn('id="%s"' % rid, html)
        self.assertIn("api.resize_by(", js)
        self.assertNotIn('id="quit"', html)                              # "Programm beenden" entfällt, das X der Titelleiste übernimmt
        self.assertNotIn('$("#quit")', js)
        self.assertIn('id="tb-ver"', html)                               # Versionsnummer neben dem festen CLAUDIA oben
        self.assertLess(html.index('id="uni-bar"'), html.index('<footer'))   # Deinstallieren steht über der Fußzeile
        self.assertIn("btn danger-fill", html)
        self.assertIn('bar.hidden = S.step !== "result"', js)               # im Ergebnis in der Leiste unten, beim Start im Verbindungsbild neben "Verbindung testen"
        self.assertIn('class: "uni-slot"', js)
        docs = open(os.path.join(ROOT, "claudia", "web", "docs.js"), encoding="utf-8").read()
        self.assertIn('class: "docs-x"', docs)
        self.assertIn("api.get_rect()", js)


if __name__ == "__main__":
    unittest.main()
