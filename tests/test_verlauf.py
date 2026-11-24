"""Dashboard-Verlauf: Aufzeichnen, Vergleichen, Zählen, Hinweise, Grenzen, Löschen, Anbindung an Server und Aktionen."""
import http.client
import json
import os
import shutil
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
from claudia import actions, lizenz, server, verlauf  # noqa: E402

DAY = 86400


def res(cid, status, *titles, sev="warn"):
    return {"id": cid, "status": status, "findings": [{"sev": sev, "title": t} for t in titles]}


def run(site="s1", t=1_700_000_000, results=None, cms="joomla", version="6.2.0"):
    return verlauf.run_entry(site, "host : html", cms, version, results if results is not None else [res("a", "warn", "Fund A"), res("b", "ok")], ts=t)


class Basis(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="claudia_vl_")
        self.addCleanup(shutil.rmtree, self.d, True)

    def test_eintrag_zaehlt_und_kuerzt(self):
        e = run(results=[res("a", "crit", "X" * 500, sev="crit"), res("b", "warn", "w"), res("c", "ok"), res("d", "skipped"), res("e", "error")])
        self.assertEqual((e["counts"]["crit"], e["counts"]["warn"], e["counts"]["ok"], e["counts"]["skipped"], e["counts"]["error"]), (1, 1, 1, 1, 1))
        self.assertEqual(len(e["findings"][0][2]), 90)
        self.assertEqual(sorted(e["ran"]), ["a", "b", "c"])                   # übersprungene/fehlgeschlagene zählen nicht als geprüft

    def test_keine_passwoerter_und_steuerzeichen(self):
        e = run(results=[{"id": "a\x00b", "status": "warn", "findings": [{"sev": "warn", "title": "x\x1b[31m", "items": ["GEHEIM-PW"], "text": "GEHEIM-PW", "raw": "GEHEIM-PW"}]}])
        self.assertNotIn("GEHEIM-PW", json.dumps(e))
        self.assertNotIn("\x00", json.dumps(e, ensure_ascii=False))

    def test_leerer_lauf_wird_nicht_gespeichert(self):
        verlauf.record_run(self.d, run(results=[]))
        verlauf.record_run(self.d, run(results=[res("a", "skipped"), res("b", "error")]))
        self.assertEqual(verlauf.load(self.d)["runs"], [])

    def test_kaputte_dateien(self):
        for inhalt in ("", "{", "[]", '{"runs": 5, "actions": []}', '{"runs": [1, "x", {"site": 3}], "actions": [null]}', "\x00\x01", '{"runs":[],"actions":[]}' + "x" * 10):
            open(verlauf.path(self.d), "w", encoding="utf-8", errors="ignore").write(inhalt)
            self.assertEqual(verlauf.load(self.d)["runs"], [])
            verlauf.record_run(self.d, run())                                 # darf nie werfen, repariert sich selbst
            self.assertEqual(len(verlauf.load(self.d)["runs"]), 1)
            os.remove(verlauf.path(self.d))

    def test_speicherort_nicht_schreibbar_wirft_nicht(self):
        open(os.path.join(self.d, "datei.txt"), "w").write("x")
        verlauf.record_run(os.path.join(self.d, "datei.txt", "unter"), run())          # Ordner nicht anlegbar: kein Fehler

    def test_grenzen(self):
        data = verlauf._empty()
        for i in range(verlauf.MAX_RUNS + 50):
            data["runs"].append(run(site="s%d" % (i % 3), t=1_700_000_000 + i))
        for i in range(verlauf.MAX_ACTIONS + 50):
            data["actions"].append({"ts": i, "site": "s0", "label": "", "id": "x", "title": "t", "ok": True})
        verlauf.save(self.d, data)
        d2 = verlauf.load(self.d)
        self.assertEqual(len(d2["runs"]), verlauf.MAX_RUNS)
        self.assertEqual(len(d2["actions"]), verlauf.MAX_ACTIONS)
        mit = [r for r in d2["runs"] if r["site"] == "s0" and "findings" in r]
        self.assertEqual(len(mit), verlauf.KEEP_DETAIL)                           # ältere behalten nur Zählstände
        self.assertLess(os.path.getsize(verlauf.path(self.d)), 600_000)

    def test_gleichzeitig_nichts_verloren(self):
        ts = [threading.Thread(target=lambda i=i: verlauf.record_run(self.d, run(t=1_700_000_000 + i))) for i in range(40)]
        ts += [threading.Thread(target=lambda i=i: verlauf.record_action(self.d, "s1", "l", "backup_now", "Sicherung", True, 1_700_000_000 + i)) for i in range(40)]
        [t.start() for t in ts]
        [t.join() for t in ts]
        d = verlauf.load(self.d)
        self.assertEqual((len(d["runs"]), len(d["actions"])), (40, 40))

    def test_loeschen_je_seite(self):
        verlauf.record_run(self.d, run("s1"))
        verlauf.record_run(self.d, run("s2"))
        verlauf.record_action(self.d, "s1", "l", "x", "t", True)
        self.assertEqual(verlauf.delete_site(self.d, "s1"), 2)
        d = verlauf.load(self.d)
        self.assertEqual([r["site"] for r in d["runs"]], ["s2"])
        self.assertEqual(d["actions"], [])
        self.assertEqual(verlauf.delete_site(self.d, "gibtsnicht"), 0)


class Vergleich(unittest.TestCase):
    def test_neu_behoben_gleich(self):
        a = run(results=[res("a", "warn", "alt"), res("b", "crit", "bleibt", sev="crit"), res("c", "ok")], t=1)
        b = run(results=[res("a", "ok"), res("b", "crit", "bleibt", sev="crit"), res("c", "warn", "neu")], t=2)
        c = verlauf.compare(a, b)
        self.assertEqual([x[2] for x in c["fixed"]], ["alt"])
        self.assertEqual([x[2] for x in c["new"]], ["neu"])
        self.assertEqual(c["same"], 1)

    def test_nicht_gelaufene_pruefung_gilt_nicht_als_behoben(self):
        a = run(results=[res("a", "warn", "alt")], t=1)
        b = run(results=[res("a", "skipped"), res("z", "ok")], t=2)             # a wurde beim zweiten Mal gar nicht geprüft
        c = verlauf.compare(a, b)
        self.assertEqual(c["fixed"], [])
        self.assertEqual([x[2] for x in c["not_checked"]], ["alt"])

    def test_mutation_behoben_ohne_pruefung_der_ausfuehrung(self):
        """Wird 'ran' ignoriert, würde ein nicht geprüfter Fund als behoben zählen: der Test oben muss das merken."""
        a = run(results=[res("a", "warn", "alt")], t=1)
        b = run(results=[res("a", "error")], t=2)
        b2 = dict(b, ran=["a"])                       # so würde ein Fehler aussehen, wenn 'ran' falsch befüllt wäre
        self.assertEqual(len(verlauf.compare(a, b2)["fixed"]), 1)
        self.assertEqual(len(verlauf.compare(a, b)["fixed"]), 0)

    def test_fixed_total_ueber_mehrere_laeufe(self):
        runs = [run(results=[res("a", "warn", "x"), res("b", "warn", "y")], t=1), run(results=[res("a", "ok"), res("b", "warn", "y")], t=2), run(results=[res("a", "ok"), res("b", "ok")], t=3)]
        self.assertEqual(verlauf.fixed_total(runs), 2)
        runs[1].pop("findings")
        self.assertEqual(verlauf.fixed_total(runs), 2)           # die Lücke wird übersprungen: Stand 1 gegen Stand 3
        for r in runs:
            r.pop("findings", None)
        self.assertEqual(verlauf.fixed_total(runs), 0)           # ganz ohne Detail keine Behauptung


class Dashboard(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="claudia_vl_")
        self.addCleanup(shutil.rmtree, self.d, True)
        self.now = 1_800_000_000

    def test_leer(self):
        o = verlauf.dashboard(self.d, self.now)
        self.assertEqual((o["sites"], o["recent_actions"], o["totals"]["runs"]), ([], [], 0))

    def test_uebersicht_ampel_trend_hinweise(self):
        verlauf.record_run(self.d, run("kritisch", self.now - 40 * DAY, [res("a", "crit", "k", sev="crit")]))
        verlauf.record_run(self.d, run("sauber", self.now - 1 * DAY, [res("a", "ok")]))
        verlauf.record_run(self.d, run("sauber", self.now, [res("a", "ok")]))
        verlauf.record_action(self.d, "sauber", "l", "backup_now", "Sicherung", True, self.now - 2 * DAY)
        o = verlauf.dashboard(self.d, self.now)
        self.assertEqual([s["site"] for s in o["sites"]], ["kritisch", "sauber"])       # kritisch zuerst
        k, s = o["sites"]
        self.assertEqual(k["level"], "crit")
        self.assertTrue(any("40 Tage" in h for h in k["hints"]))
        self.assertTrue(any("noch keine Sicherung" in h for h in k["hints"]))
        self.assertEqual(s["level"], "ok")
        self.assertEqual(s["hints"], [])
        self.assertEqual(len(s["trend"]), 2)
        self.assertEqual(s["runs"], 2)

    def test_alte_sicherung(self):
        verlauf.record_run(self.d, run("s", self.now))
        verlauf.record_action(self.d, "s", "l", "backup_now", "Sicherung", True, self.now - 45 * DAY)
        verlauf.record_action(self.d, "s", "l", "backup_now", "Sicherung", False, self.now - 1 * DAY)         # misslungen zählt nicht
        h = verlauf.dashboard(self.d, self.now)["sites"][0]["hints"]
        self.assertTrue(any("45 Tage" in x for x in h), h)

    def test_erledigt_zaehler(self):
        verlauf.record_run(self.d, run("s", self.now - 2 * DAY, [res("a", "warn", "x")]))
        verlauf.record_run(self.d, run("s", self.now - 1 * DAY, [res("a", "ok")]))
        verlauf.record_action(self.d, "s", "l", "block_users", "Konten sperren", True)
        verlauf.record_action(self.d, "s", "l", "clean_tmp", "tmp", False)
        s = verlauf.dashboard(self.d, self.now)["sites"][0]
        self.assertEqual((s["fixed"], s["actions_ok"], s["actions_failed"]), (1, 1, 1))
        self.assertEqual(len(s["compare"]["fixed"]), 1)


class Anbindung(unittest.TestCase):
    """Server und Aktionen schreiben den Verlauf; das Dashboard ist über die API erreichbar und gehört zum sperrbaren Bereich 'dashboard'."""

    @classmethod
    def setUpClass(cls):
        cls.base = tempfile.mkdtemp(prefix="claudia_vlsrv_")
        cls._env = mock.patch.dict(os.environ, {"CLAUDIA_NO_UPDATE_CHECK": "1", "CLAUDIA_NO_RESTART": "1", "CLAUDIA_REPORTS": cls.base + "/b"})
        cls._env.start()
        os.environ.pop("CLAUDIA_OFFLINE", None)
        cls.srv = server.make_server(directory=os.path.join(cls.base, "daten"))
        cls.app = cls.srv.app
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.sid = cls.srv.new_session()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls._env.stop()
        shutil.rmtree(cls.base, True)

    def setUp(self):
        verlauf_datei = verlauf.path(self.app.dir)
        if os.path.exists(verlauf_datei):
            os.remove(verlauf_datei)
        self.app.conn = {"host": "example.test", "user": "u", "site_dir": "html"}
        self.app.info = {"cms": "wordpress", "wordpress": "6.8.1", "host": "example.test", "user": "u"}
        self.addCleanup(lambda: setattr(self.app, "conn", {}))

    def call(self, method, path, body=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=15)
        try:
            c.request(method, path, body=json.dumps(body if body is not None else {}) if method == "POST" else None,
                      headers={"Cookie": "claudia=" + self.sid, "X-Claudia": "1", "Content-Type": "application/json"})
            r = c.getresponse()
            return r.status, json.loads(r.read() or b"{}")
        finally:
            c.close()

    def test_lauf_wird_aufgezeichnet(self):
        self.app.results = [{"id": "a", "status": "warn", "findings": [{"sev": "warn", "title": "Fund"}]}, {"id": "b", "status": "ok", "findings": []}]
        self.app.cancelled, self.app.run_error = False, ""
        self.app._verlauf_run()
        st, o = self.call("GET", "/api/dashboard")
        self.assertEqual(st, 200)
        self.assertEqual(len(o["sites"]), 1)
        s = o["sites"][0]
        self.assertEqual((s["cms"], s["version"], s["level"], s["runs"]), ("wordpress", "6.8.1", "warn", 1))
        self.assertEqual(o["current"], s["site"])
        self.assertNotIn("password", json.dumps(o).lower())

    def test_ohne_verbindung_kein_eintrag(self):
        self.app.conn = {}
        self.app.results = [{"id": "a", "status": "ok", "findings": []}]
        self.app._verlauf_run()
        self.assertEqual(verlauf.load(self.app.dir)["runs"], [])

    def test_aktion_wird_aufgezeichnet(self):
        a = {"id": "clean_tmp", "title": "Temp leeren", "params": {}, "php_choices": []}
        with mock.patch.object(actions, "run_action", lambda *x, **k: {"ok": True, "steps": []}), mock.patch.object(server.ActionJob, "_write_log", lambda self, res: None):
            self.app.runner = object()
            self.addCleanup(lambda: setattr(self.app, "runner", None))
            j = server.ActionJob(self.app, a, {})
            j.start()
            j.thread.join(20)
        acts = verlauf.load(self.app.dir)["actions"]
        self.assertEqual([(x["id"], x["ok"]) for x in acts], [("clean_tmp", True)])

    def test_stille_suche_wird_nicht_aufgezeichnet(self):
        a = {"id": "check_updates", "title": "Suche", "params": {}, "php_choices": []}
        with mock.patch.object(actions, "run_action", lambda *x, **k: {"ok": True, "steps": [], "assess": {}}), mock.patch.object(server.ActionJob, "_write_log", lambda self, res: None):
            self.app.runner = object()
            self.addCleanup(lambda: setattr(self.app, "runner", None))
            j = server.ActionJob(self.app, a, {})
            j.silent = True
            j.start()
            j.thread.join(20)
        self.assertEqual(verlauf.load(self.app.dir)["actions"], [])

    def test_loeschen_ueber_api(self):
        self.app.results = [{"id": "a", "status": "ok", "findings": []}]
        self.app._verlauf_run()
        site = self.call("GET", "/api/dashboard")[1]["sites"][0]["site"]
        self.assertEqual(self.call("POST", "/api/dashboard-delete", {"site": site})[1]["deleted"], 1)
        self.assertEqual(self.call("GET", "/api/dashboard")[1]["sites"], [])
        st, _ = self.call("POST", "/api/dashboard-delete", {})
        self.assertEqual(st, 400)

    def test_dashboard_server_ohne_verbindung(self):
        self.app.runner = None
        self.assertEqual(self.call("GET", "/api/dashboard-server")[1], {"connected": False})

    def test_bereich_dashboard_sperrbar(self):
        with mock.patch.object(lizenz, "GESPERRT_OHNE_LIZENZ", ("dashboard",)):
            lizenz.remove(self.app.dir)
            st, o = self.call("GET", "/api/dashboard")
            self.assertEqual((st, o.get("lizenz"), o.get("area")), (403, True, "dashboard"))
            self.assertEqual(self.call("GET", "/api/dashboard-server")[0], 403)
            self.assertEqual(self.call("GET", "/api/init")[0], 200)                 # alles andere bleibt frei


if __name__ == "__main__":
    unittest.main()
