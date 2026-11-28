"""2.5.0 Radar-Animation im Prüfungs-Bildschirm (claudia/web/radar.js, Einbau in viewRun/updateRun).

Geprüft im echten Browser (Playwright, ohne Playwright übersprungen): Farben je Stufe (kritisch = Bernstein, nie rot), ruhiges Standbild bei
'Animationen reduzieren', Aufräumen beim Verlassen der Ansicht, Hell/Dunkel über die CSS-Variablen. Die Optik selbst (Gefallen, Lesbarkeit
auf dem echten Windows-Fenster) ist damit NICHT bewiesen."""
import os
import sys
import tempfile
import threading
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

try:
    from playwright.sync_api import sync_playwright
except ImportError:  # pragma: no cover
    sync_playwright = None

WEB = os.path.join(ROOT, "claudia", "web")
RADAR_JS = open(os.path.join(WEB, "radar.js"), encoding="utf-8").read()

PAGE = """<!doctype html><html><head><style>
:root{--ok:#2b8a58;--info:#3a6db0;--warn:#d28a00;--crit:#c53a2b;--skip:#8896a3;--accent:#0b6e7f}
:root[data-theme=dark]{--ok:#4fb581;--info:#78a6e6;--warn:#e6a526;--crit:#ff8a80;--skip:#78899a;--accent:#4cc3d4}
body{margin:0;background:#fff}.radar{width:300px;height:300px;padding:4px;box-sizing:border-box}canvas{width:100%;height:100%;display:block}
</style></head><body><div class="radar"><canvas id="c"></canvas></div><script>""" + RADAR_JS + """</script></body></html>"""

PLAN = ["a_ok", "b_info", "c_warn", "d_crit", "e_skip", "f_wait"]
STATUS = {"a_ok": "ok", "b_info": "info", "c_warn": "warn", "d_crit": "crit", "e_skip": "skipped"}

SET_JS = """([plan, status, current, running]) => { window.__r = ClaudiaRadar.mount(document.getElementById('c'));
  window.__r.set({plan, status, current, running}); return window.__r.positions(); }"""
PIX_JS = """([x, y]) => { const c = document.getElementById('c'), d = c.getContext('2d').getImageData(Math.round(x * c.width / c.getBoundingClientRect().width), Math.round(y * c.width / c.getBoundingClientRect().width), 1, 1).data; return [d[0], d[1], d[2]]; }"""
RED_JS = """() => { const c = document.getElementById('c'), d = c.getContext('2d').getImageData(0, 0, c.width, c.height).data; let n = 0;
  for (let i = 0; i < d.length; i += 4) if (d[i + 3] > 200 && d[i] > 180 && d[i + 1] < 100 && d[i + 2] < 100) n++; return n; }"""
SNAP_JS = """() => document.getElementById('c').toDataURL()"""


@unittest.skipIf(sync_playwright is None, "Playwright nicht installiert")
class RadarDrawing(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pw = sync_playwright().start()
        cls.browser = cls.pw.chromium.launch()

    @classmethod
    def tearDownClass(cls):
        cls.browser.close()
        cls.pw.stop()

    def page(self, reduced=True, theme=""):
        ctx = self.browser.new_context(viewport={"width": 400, "height": 400}, reduced_motion="reduce" if reduced else "no-preference")
        self.addCleanup(ctx.close)
        pg = ctx.new_page()
        errs = []
        pg.on("pageerror", lambda e: errs.append(str(e)))
        pg.set_content(PAGE)
        if theme:
            pg.evaluate("t => document.documentElement.setAttribute('data-theme', t)", theme)
        self.addCleanup(lambda: self.assertEqual(errs, []))
        return pg

    def colors(self, pg):
        pos = pg.evaluate(SET_JS, [PLAN, STATUS, "f_wait", True])
        return {p["id"]: pg.evaluate(PIX_JS, [p["x"], p["y"]]) for p in pos}

    def test_critical_is_red_ok_is_calm(self):
        """Seit 3.1.1: kritisch in Rot wie in Legende und Ergebnis (vorher Bernstein)."""
        for theme in ("", "dark"):
            with self.subTest(theme=theme or "hell"):
                pg = self.page(theme=theme)
                col = self.colors(pg)
                r, g, b = col["d_crit"]
                self.assertTrue(r > 150 and r > g + 40 and r > b + 40, "kritisch muss rot sein: %s" % col["d_crit"])
                ok, crit = col["a_ok"], col["d_crit"]
                self.assertLess(sum(ok), 200, "In Ordnung wird nicht als Punkt gezeigt (nur Funde)")
                self.assertLess(sum(col["e_skip"]), 200, "Uebersprungen wird nicht als Punkt gezeigt")
                info = col["b_info"]
                self.assertGreater(info[2], info[0], "Hinweis ist bläulich")
                warn = col["c_warn"]
                self.assertLess(sum(warn), sum(crit), "Bitte pruefen ist schwaecher als kritisch")

    def test_still_mode_is_static_and_destroy_is_safe(self):
        pg = self.page(reduced=True)
        self.colors(pg)
        a = pg.evaluate(SNAP_JS)
        pg.wait_for_timeout(300)
        self.assertEqual(a, pg.evaluate(SNAP_JS), "bei 'Animationen reduzieren' bleibt das Bild ruhig")
        pg.evaluate("window.__r.destroy()")
        pg.evaluate("window.__r.set({plan:[], status:{}, current:null, running:false})")   # nach destroy folgenlos

    def test_motion_option_moves_even_with_reduced_motion(self):
        """Seit 3.1.3: In der Prüfungsansicht dreht sich der Strahl auch bei ausgeschalteten Windows-Animationseffekten."""
        pg = self.page(reduced=True)
        pg.evaluate("""([plan, status]) => { if (window.__r) window.__r.destroy(); window.__r = ClaudiaRadar.mount(document.getElementById('c'), { motion: true });
            window.__r.set({ plan, status, current: null, running: true }); }""", [PLAN, STATUS])
        pg.wait_for_timeout(150)
        a = pg.evaluate(SNAP_JS)
        pg.wait_for_timeout(300)
        self.assertNotEqual(a, pg.evaluate(SNAP_JS), "der Strahl dreht sich trotz 'Animationen reduzieren'")
        app = open(os.path.join(ROOT, "claudia", "web", "app.js"), encoding="utf-8").read()
        self.assertIn("ClaudiaRadar.mount(cv, { motion: true })", app)

    def test_animated_mode_moves_and_stops_after_destroy(self):
        pg = self.page(reduced=False)
        self.colors(pg)
        a = pg.evaluate(SNAP_JS)
        pg.wait_for_timeout(250)
        self.assertNotEqual(a, pg.evaluate(SNAP_JS), "der Strahl bewegt sich")
        pg.evaluate("window.__r.destroy()")
        b = pg.evaluate(SNAP_JS)
        pg.wait_for_timeout(250)
        self.assertEqual(b, pg.evaluate(SNAP_JS), "nach destroy wird nichts mehr gezeichnet")

    def test_theme_switch_rereads_variables(self):
        pg = self.page(reduced=True, theme="")
        before = self.colors(pg)["d_crit"]
        pg.evaluate("document.documentElement.setAttribute('data-theme','dark')")
        pg.wait_for_timeout(200)
        pos = pg.evaluate("window.__r.positions()")
        p = [x for x in pos if x["id"] == "d_crit"][0]
        self.assertNotEqual(before, pg.evaluate(PIX_JS, [p["x"], p["y"]]), "Farben folgen dem Wechsel hell/dunkel")

    def test_bad_input_does_not_crash(self):
        pg = self.page()
        pg.evaluate("() => { const r = ClaudiaRadar.mount(document.getElementById('c')); r.set({}); r.set({plan:['x'], status:{x:'unbekannt'}}); r.set({plan:[], status:null}); r.destroy(); }")


@unittest.skipIf(sync_playwright is None, "Playwright nicht installiert")
class RadarInApp(unittest.TestCase):
    """Einbau in die echte Oberfläche: Radar nur in der Prüfungsansicht, mit den Texten daneben, und beim Verlassen zerstört."""

    @classmethod
    def setUpClass(cls):
        from claudia.server import make_server
        cls.base = tempfile.mkdtemp(prefix="claudia_radar_")
        os.environ.setdefault("CLAUDIA_REPORTS", os.path.join(cls.base, "berichte"))
        os.environ.setdefault("CLAUDIA_LOGS", os.path.join(cls.base, "protokolle"))
        cls.srv = make_server(directory=os.path.join(cls.base, "data"))
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.pw = sync_playwright().start()
        cls.browser = cls.pw.chromium.launch()

    @classmethod
    def tearDownClass(cls):
        cls.browser.close()
        cls.pw.stop()
        cls.srv.shutdown()

    def test_radar_only_in_run_view(self):
        pg = self.browser.new_page(viewport={"width": 1280, "height": 900})
        errs = []
        pg.on("pageerror", lambda e: errs.append(str(e)))
        pg.goto(self.srv.entry_url())
        pg.wait_for_selector("text=Mit dem Server verbinden")
        pg.evaluate("""() => { Object.assign(S, { step: "run", plan: ["joomla_info", "root_files", "perms"], running: true,
            results: [{ id: "joomla_info", status: "crit", title: "x", findings: [] }], current: { id: "root_files" } }); render(); }""")
        pg.wait_for_selector("#radar")
        self.assertTrue(pg.evaluate("radarInst !== null"))
        self.assertTrue(pg.locator("#now-t").count() == 1 and pg.locator("#run-strip .pad").count() == 3, "Texte und Prüfstreifen bleiben")
        self.assertEqual(pg.locator(".radar").get_attribute("aria-hidden"), "true")
        pg.evaluate("""() => { S.results.push({ id: "root_files", status: "error", title: "y", findings: [] }); updateRun(); }""")
        pos = pg.evaluate("radarInst.positions()")
        self.assertEqual([p["id"] for p in pos], ["joomla_info", "root_files", "perms"])
        pg.evaluate("""() => { S.step = "result"; S.running = false; render(); }""")
        self.assertEqual(pg.locator("#radar").count(), 0)
        self.assertTrue(pg.evaluate("radarInst === null"), "beim Verlassen der Ansicht zerstört")
        self.assertEqual(errs, [])
        pg.close()

    def test_static_route_and_page_reference(self):
        import urllib.request
        html = open(os.path.join(WEB, "index.html"), encoding="utf-8").read()
        self.assertIn('<script src="/radar.js"></script>', html)
        from claudia.server import STATIC
        self.assertIn("/radar.js", STATIC)


if __name__ == "__main__":
    unittest.main()
