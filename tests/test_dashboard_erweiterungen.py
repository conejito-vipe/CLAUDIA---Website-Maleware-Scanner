"""Nachkontrolle, Export (CSV und Bericht), Sicherung prüfen und Support-Paket."""
import gzip
import io
import os
import shutil
import sys
import tarfile
import tempfile
import time
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from claudia import actions, support, verlauf  # noqa: E402
from claudia.runner import LocalRunner  # noqa: E402

DAY = 86400
NOW = 1_800_000_000


def res(cid, st, *t, sev="warn"):
    return {"id": cid, "status": st, "findings": [{"sev": sev, "title": x} for x in t]}


def act(aid, ts, ok=True):
    return {"ts": ts, "site": "s", "id": aid, "title": "T-" + aid, "ok": ok}


def run(ts, *r):
    return verlauf.run_entry("s", "s", "joomla", "6", list(r), ts)


class Nachkontrolle(unittest.TestCase):
    def test_keine_bereinigung_keine_nachkontrolle(self):
        self.assertIsNone(verlauf.nachkontrolle([run(NOW - DAY, res("a", "ok"))], [act("backup_now", NOW - DAY), act("remove_shells", NOW - DAY, ok=False)], NOW))

    def test_wartet_dann_faellig_dann_erledigt(self):
        ts = NOW - 1 * DAY
        r0 = run(ts - DAY, res("a", "warn", "Alt"))
        nk = verlauf.nachkontrolle([r0], [act("remove_shells", ts)], NOW)
        self.assertEqual(nk["state"], "wartet")
        nk = verlauf.nachkontrolle([r0], [act("remove_shells", NOW - 4 * DAY)], NOW)
        self.assertEqual(nk["state"], "faellig")
        self.assertIn("fällig", nk["text"])
        direkt = run(NOW - 3 * DAY, res("a", "ok"))                                    # Prüfung direkt nach der Bereinigung: noch keine Nachkontrolle
        nk = verlauf.nachkontrolle([r0, direkt], [act("remove_shells", NOW - 4 * DAY)], NOW)
        self.assertEqual(nk["state"], "faellig")
        spaeter = run(NOW - 3600, res("a", "ok"))
        nk = verlauf.nachkontrolle([r0, direkt, spaeter], [act("remove_shells", NOW - 4 * DAY)], NOW)
        self.assertEqual(nk["state"], "erledigt")
        self.assertEqual(nk["new"], 0)

    def test_zurueckgekehrte_funde_werden_gemeldet(self):
        r0 = run(NOW - 6 * DAY, res("a", "ok"))
        r1 = run(NOW - 1 * DAY, res("a", "crit", "Hintertür wieder da", sev="crit"))
        nk = verlauf.nachkontrolle([r0, r1], [act("remove_shells", NOW - 5 * DAY)], NOW)
        self.assertEqual((nk["state"], nk["new"]), ("erledigt", 1))
        self.assertIn("1 neue Funde", nk["text"])

    def test_dashboard_zeigt_hinweis_nur_wenn_faellig(self):
        with tempfile.TemporaryDirectory() as d:
            verlauf.record_run(d, run(NOW - 6 * DAY, res("a", "warn", "x")))
            verlauf.record_action(d, "s", "s", "remove_shells", "Schadcode entfernen", True, NOW - 5 * DAY)
            s = verlauf.dashboard(d, NOW)["sites"][0]
            self.assertEqual(s["nachkontrolle"]["state"], "faellig")
            self.assertTrue(any("Nachkontrolle fällig" in h for h in s["hints"]))
            verlauf.record_run(d, run(NOW - 3600, res("a", "ok")))
            s = verlauf.dashboard(d, NOW)["sites"][0]
            self.assertEqual(s["nachkontrolle"]["state"], "erledigt")
            self.assertFalse(any("Nachkontrolle fällig" in h for h in s["hints"]))


class Export(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="claudia_exp_")
        self.addCleanup(shutil.rmtree, self.d, True)
        verlauf.record_run(self.d, verlauf.run_entry("s", "=HYPERLINK(\"x\")", "joomla", "6", [res("a", "crit", "<script>alert(1)</script>", sev="crit")], NOW - DAY))
        verlauf.record_action(self.d, "s", "=HYPERLINK(\"x\")", "block_users", "+cmd|calc", True, NOW - 3600)

    def test_csv_entschaerft_formeln_und_trennt_richtig(self):
        t = verlauf.export_csv(self.d)
        self.assertTrue(t.startswith("﻿"))
        zeilen = t.strip().split("\r\n")
        self.assertEqual(len(zeilen), 3)                                       # Kopf, Prüfung, Aktion
        for z in zeilen[1:]:
            for zelle in z.split('";"'):
                self.assertNotIn(zelle.lstrip('"')[:1], ("=", "+", "@"), zelle)
        self.assertIn("'=HYPERLINK", t)
        self.assertIn("'+cmd|calc", t)
        self.assertEqual(verlauf.export_csv(self.d, "andere").strip().count("\r\n"), 0)       # nur Kopfzeile

    def test_bericht_ist_html_sicher(self):
        t = verlauf.export_html(self.d, "s", NOW)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", t)
        self.assertNotIn("<script>", t)
        self.assertEqual(verlauf.export_html(self.d, "unbekannt", NOW), "")

    def test_mutation_formel_nicht_entschaerft(self):
        with mock.patch.object(verlauf, "_cell", lambda v: '"%s"' % v):
            self.assertIn('"=HYPERLINK', verlauf.export_csv(self.d), "Test merkt nicht, dass Formeln durchgehen")


class SicherungPruefen(unittest.TestCase):
    NAME = "claudia-sicherung-20261101-100000"

    def setUp(self):
        self.home = tempfile.mkdtemp(prefix="claudia_ver_")
        self.addCleanup(shutil.rmtree, self.home, True)
        self.dir = os.path.join(self.home, self.NAME)
        os.makedirs(self.dir)
        self.runner = LocalRunner(home=self.home)

    def gut(self):
        with gzip.open(os.path.join(self.dir, "db.sql.gz"), "wb") as f:
            f.write(b"CREATE TABLE x;\n")
        with tarfile.open(os.path.join(self.dir, "dateien.tgz"), "w:gz") as t:
            ti = tarfile.TarInfo("a.txt")
            ti.size = 3
            t.addfile(ti, io.BytesIO(b"abc"))

    def test_gute_sicherung(self):
        self.gut()
        r = actions.verify_backup(self.runner, self.home, self.NAME)
        self.assertTrue(r["ok"], r)
        self.assertEqual(sorted(f["name"] for f in r["files"]), ["dateien.tgz", "db.sql.gz"])

    def test_beschaedigt_leer_abgeschnitten(self):
        self.gut()
        p = os.path.join(self.dir, "dateien.tgz")
        data = open(p, "rb").read()
        open(p, "wb").write(data[:len(data) // 2])                              # abgeschnitten
        open(os.path.join(self.dir, "leer.gz"), "wb").close()
        r = actions.verify_backup(self.runner, self.home, self.NAME)
        self.assertFalse(r["ok"])
        bad = {f["name"] for f in r["files"] if not f["ok"]}
        self.assertEqual(bad, {"dateien.tgz", "leer.gz"})

    def test_fehlt_und_ungueltiger_name_und_nur_lesend(self):
        self.assertFalse(actions.verify_backup(self.runner, self.home, "claudia-sicherung-20260101-000000")["found"])
        for schlecht in ("", "../etc", "claudia-sicherung-x; touch pwn", self.NAME + "/../.."):
            with self.assertRaises(actions.ActionError):
                actions.verify_backup(self.runner, self.home, schlecht)
        self.gut()
        vorher = {f: os.stat(os.path.join(self.dir, f)).st_mtime_ns for f in os.listdir(self.dir)}
        actions.verify_backup(self.runner, self.home, self.NAME)
        self.assertEqual(vorher, {f: os.stat(os.path.join(self.dir, f)).st_mtime_ns for f in os.listdir(self.dir)})
        self.assertEqual(sorted(os.listdir(self.dir)), ["dateien.tgz", "db.sql.gz"])

    def test_skript_enthaelt_nur_lesende_befehle(self):
        for verboten in ("rm ", "mv ", "cp ", ">>", "tar x", "tar -x", "chmod", "sed -i", "mysql"):
            self.assertNotIn(verboten, actions.VERIFY_SCRIPT, verboten)

    def test_mutation_beschaedigung_nicht_erkannt(self):
        self.gut()
        open(os.path.join(self.dir, "kaputt.gz"), "wb").write(b"kein gzip")
        with mock.patch.object(actions, "VERIFY_SCRIPT", actions.VERIFY_SCRIPT.replace('gzip -t "$f"', "true")):
            r = actions.verify_backup(self.runner, self.home, self.NAME)
        self.assertTrue(r["ok"], "Test merkt nicht, dass die Prüfung nichts mehr prüft")


class SupportPaket(unittest.TestCase):
    def test_ohne_geheimnisse_und_adressen(self):
        hide = ["geheim123", "shop.example.org", "benutzer77", "/pfad/zur/seite"]
        results = [{"id": "joomla_info", "status": "ok", "seconds": 1.2, "findings": []},
                   {"id": "dateien", "status": "error", "seconds": 0.4, "message": "Fehler bei shop.example.org: password = 'geheim123' für benutzer77 in /pfad/zur/seite"},
                   {"id": "malware", "status": "crit", "seconds": 3, "findings": [{"sev": "crit", "title": "Datei /pfad/zur/seite/x.php enthält Schadcode"}]}]
        t = support.build("9.9.9", {"cms": "joomla", "joomla": "6.2.0", "php": "8.2", "host": "shop.example.org"}, results,
                          [{"id": "block_users", "ok": True}], "[ 5 %] Lade shop.example.org\nFEHLER: password=geheim123", "2026-10-25", hide, NOW)
        for g in hide:
            self.assertNotIn(g, t, g)
        self.assertNotIn("Schadcode", t)                                       # Texte der Funde fehlen
        self.assertIn("malware: crit", t)
        self.assertIn("1 kritisch", t)
        self.assertIn("joomla_info: ok", t)
        self.assertIn("block_users: erfolgreich", t)
        self.assertIn("CLAUDIA 9.9.9", t)

    def test_leere_sitzung_und_grenzen(self):
        t = support.build("1.0.0", {}, [], [], "", "", [], NOW)
        self.assertIn("noch keine Prüfung", t)
        grosse = support.build("1.0.0", {}, [{"id": "x%d" % i, "status": "ok"} for i in range(1000)], [], "\n".join("zeile %d" % i for i in range(10000)), "", [], NOW)
        self.assertLess(len(grosse), 40000)

    def test_mutation_geheimnis_nicht_verborgen(self):
        with mock.patch.object(support, "scrub", lambda text, hide: str(text)):
            t = support.build("1", {}, [{"id": "a", "status": "error", "message": "geheim123"}], [], "", "", ["geheim123"], NOW)
        self.assertIn("geheim123", t, "Test merkt nicht, dass nichts mehr verborgen wird")


if __name__ == "__main__":
    unittest.main()
