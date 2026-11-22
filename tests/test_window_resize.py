"""Fenster am linken Rand skalieren und beim Schließen nur einmal nachfragen."""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from claudia import window  # noqa: E402


class FakeWin:
    def __init__(self):
        self.x, self.y, self.width, self.height = 100, 50, 1200, 800
        self.calls = []

    def resize(self, w, h):
        self.width, self.height = w, h
        self.calls.append(("resize", w, h))

    def move(self, x, y):
        self.x, self.y = x, y
        self.calls.append(("move", x, y))

    def destroy(self):
        self.calls.append("destroy")
        self.owner._on_closing()                       # wie pywebview: destroy löst das Schließen-Ereignis aus

    def create_confirmation_dialog(self, *a):
        self.calls.append("ask")
        return True


class FakeApp:
    running = False
    job = {"done": True}                               # nach einer Prüfung bleibt der Auftrag stehen


class FakeSrv:
    on_stop = []
    app = FakeApp()


class Resize(unittest.TestCase):
    def setUp(self):
        self.w = window.Window(FakeSrv(), lambda: None)
        self.w._win = FakeWin()
        self.w._win.owner = self.w
        self.api = window.WindowApi(self.w, True)

    def test_left_edge_keeps_right_edge(self):
        self.assertTrue(self.api.resize_by(100, 50, 1200, 800, -200, 0, "l"))
        self.assertEqual((self.w._win.x, self.w._win.width), (-100, 1400))
        self.assertEqual(self.w._win.x + self.w._win.width, 1300)       # rechte Kante unverändert

    def test_left_edge_respects_minimum(self):
        self.api.resize_by(100, 50, 1200, 800, 900, 0, "l")
        self.assertEqual(self.w._win.width, window.MIN_W)
        self.assertEqual(self.w._win.x + self.w._win.width, 1300)

    def test_right_bottom_and_corner(self):
        self.api.resize_by(100, 50, 1200, 800, 40, 30, "rb")
        self.assertEqual((self.w._win.width, self.w._win.height, self.w._win.x), (1240, 830, 100))
        self.api.resize_by(100, 50, 1200, 800, -30, 30, "lb")
        self.assertEqual((self.w._win.width, self.w._win.height), (1230, 830))

    def test_bad_values_and_maximized(self):
        self.assertFalse(self.api.resize_by("x", 0, 0, 0, 0, 0, "l"))
        self.w._maximized = True
        self.assertFalse(self.api.resize_by(0, 0, 1200, 800, 5, 5, "r"))

    def test_close_asks_only_once(self):
        self.api.close()
        self.assertEqual(self.w._win.calls.count("ask"), 1)
        self.assertIn("destroy", self.w._win.calls)

    def test_get_rect(self):
        self.assertEqual(self.api.get_rect(), [100, 50, 1200, 800])


if __name__ == "__main__":
    unittest.main()
