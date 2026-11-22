"""Programm-Update im echten Browser: Dialog erscheint von selbst, Knöpfe, Überspringen, manuelle Suche, Fortschritt."""
import hashlib
import json
import os
import shutil
import sys
import tempfile
import threading
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

try:
    from playwright.sync_api import sync_playwright
except ImportError:  # pragma: no cover
    sync_playwright = None


@unittest.skipIf(sync_playwright is None, "Playwright nicht installiert")
class Ui(unittest.TestCase):
    def setUp(self):
        from test_appupdate import make_zip, old_program, release
        from claudia.server import make_server
        self.base = tempfile.mkdtemp(prefix="claudia_uiupd_")
        self.addCleanup(shutil.rmtree, self.base, True)
        os.environ["CLAUDIA_REPORTS"] = self.base + "/b"
        self.root = old_program(self.base)
        self.zip = make_zip()
        self.rel = release(sha=hashlib.sha256(self.zip).hexdigest())
        self.srv = make_server(directory=self.base + "/d")
        self.srv.app.selfupd_fetch = lambda url, *a: json.dumps(self.rel).encode() if "api.github.com" in url else self.zip
        self.srv.app.selfupd_root = self.root
        env = mock.patch.dict(os.environ, {"CLAUDIA_NO_RESTART": "1"})
        env.start()
        os.environ.pop("CLAUDIA_OFFLINE", None)
        self.addCleanup(env.stop)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.addCleanup(self.srv.shutdown)
        self.pw = sync_playwright().start()
        self.addCleanup(self.pw.stop)
        self.br = self.pw.chromium.launch()
        self.addCleanup(self.br.close)

    def page(self):
        pg = self.br.new_page(viewport={"width": 1100, "height": 760})
        pg.goto(self.srv.entry_url())
        pg.wait_for_selector("#updbtn")
        return pg

    def test_dialog_appears_by_itself_with_notes_and_three_buttons(self):
        self.srv.app.selfupd_check()
        pg = self.page()
        pg.wait_for_selector("#upddlg[open] .upd-notes")
        text = pg.inner_text("#upddlg")
        self.assertIn("9.9.0", text)
        self.assertIn("Update-Check", text)                              # Release Notes werden gezeigt
        for b in ("Abbrechen", "Update überspringen", "Update installieren"):
            self.assertIn(b, text)
        self.assertTrue(pg.evaluate("document.querySelector('#updbtn').classList.contains('has-upd')"))

    def test_skip_hides_dialog_but_button_still_works(self):
        self.srv.app.selfupd_check()
        pg = self.page()
        pg.wait_for_selector("#upddlg[open] .upd-notes")
        pg.click("text=Update überspringen")
        pg.wait_for_function("()=>!document.querySelector('#upddlg').open")
        pg2 = self.page()
        pg2.wait_for_timeout(1500)
        self.assertFalse(pg2.evaluate("document.querySelector('#upddlg').open"))   # übersprungene Version fragt nicht mehr von selbst
        pg2.click("#updbtn")
        pg2.wait_for_selector("#upddlg[open]")

    def test_no_update_says_current(self):
        self.rel = dict(self.rel, tag_name="v2.0.0")
        pg = self.page()
        pg.click("#updbtn")
        pg.wait_for_selector("#upddlg[open]")
        pg.wait_for_function("()=>document.querySelector(\'#upddlg\').innerText.includes(\'aktuelle Version\')")

    def test_install_shows_progress_then_restart_message(self):
        self.srv.app.selfupd_check()
        pg = self.page()
        pg.wait_for_selector("#upddlg[open] .upd-notes")
        pg.click("text=Update installieren")
        pg.wait_for_function("()=>document.querySelector(\'#upddlg\').innerText.includes(\'neu gestartet\')", timeout=15000)
        with open(os.path.join(self.root, "claudia", "__init__.py")) as fh:
            self.assertIn("9.9.0", fh.read())

    def test_failed_install_shows_error_and_log(self):
        self.srv.app.selfupd_check()
        self.rel["assets"][0]["digest"] = "sha256:" + "0" * 64
        self.srv.app.selfupd_check()
        pg = self.page()
        pg.wait_for_selector("#upddlg[open] .upd-notes")
        pg.click("text=Update installieren")
        pg.wait_for_function("()=>document.querySelector(\'#upddlg\').innerText.includes(\'fehlgeschlagen\')", timeout=15000)
        self.assertIn("Prüfsumme", pg.inner_text("#upddlg"))
        self.assertIn("update.log", pg.inner_text("#upddlg"))


if __name__ == "__main__":
    unittest.main()
