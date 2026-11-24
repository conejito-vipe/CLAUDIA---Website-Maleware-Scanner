"""Digitale Unterschrift: Prüfung, Programm-Update mit Unterschrift, Wissensdaten. Ohne öffentlichen Schlüssel ändert sich nichts.

Alles mit eigens erzeugten Testschlüsseln und nachgebildeten Abrufen; nie ins Netz."""
import contextlib
import copy
import hashlib
import json
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, "tools"))

import signieren  # noqa: E402
from claudia import appupdate, coreref, signatur, wissen  # noqa: E402
from test_appupdate import make_zip, old_program, release  # noqa: E402

PW = "ein-langes-testpasswort"
PEM, PUB = signieren.make_pair(PW)
PEM2, PUB2 = signieren.make_pair(PW)


def sig(data, zweck="release", kid="s1", pem=PEM):
    return signieren.sign(pem, PW, kid, zweck, data).encode("ascii")


@contextlib.contextmanager
def aktiv(keys=None):
    with mock.patch.dict(signatur.PUBLIC_KEYS, keys or {"s1": PUB}, clear=True):
        yield


class Pruefung(unittest.TestCase):
    def test_ohne_schluessel_nicht_aktiv(self):
        self.assertFalse(signatur.aktiv())
        self.assertFalse(signatur.verify("release", b"x", sig(b"x")))

    def test_gueltig(self):
        with aktiv():
            self.assertTrue(signatur.aktiv())
            self.assertTrue(signatur.verify("release", b"daten", sig(b"daten")))
            self.assertTrue(signatur.verify("release", b"daten", sig(b"daten").decode() + "\n"))       # Zeilenumbruch am Ende stört nicht

    def test_veraendert_und_fremd(self):
        with aktiv():
            s = sig(b"daten")
            self.assertFalse(signatur.verify("release", b"daten ", s))                                   # ein Zeichen mehr
            self.assertFalse(signatur.verify("release", b"Daten", s))
            self.assertFalse(signatur.verify("wissen", b"daten", s))                                      # Unterschrift gilt nur für ihren Zweck
            self.assertFalse(signatur.verify("anderes", b"daten", s))
            self.assertFalse(signatur.verify("release", b"daten", sig(b"daten", pem=PEM2)))               # anderer privater Schlüssel, gleiche ID
            self.assertFalse(signatur.verify("release", b"daten", sig(b"daten", kid="s2", pem=PEM2)))     # unbekannte ID

    def test_muell_wirft_nie(self):
        with aktiv():
            for m in ("", "CS1", "CS1..", "CS1.s1.", "CS1.s1.%%%%", "XX1.s1.AAAA", "CS1.s1.AAAA.BBBB", "CS1." + "s" * 30 + ".AAAA", "A" * 5000, None, 5, True, b"\xff\xfe", [], {}):
                self.assertFalse(signatur.verify("release", b"daten", m), repr(m)[:30])
            for d in (None, "text", 5):
                self.assertFalse(signatur.verify("release", d, sig(b"daten")))

    def test_ein_veraendertes_byte_in_der_unterschrift(self):
        with aktiv():
            s = sig(b"daten").decode()
            teil = s.split(".")
            for i in (0, 10, len(teil[2]) - 3):
                z = teil[2][:i] + ("A" if teil[2][i] != "A" else "B") + teil[2][i + 1:]
                self.assertFalse(signatur.verify("release", b"daten", ".".join([teil[0], teil[1], z])), i)

    def mutation_pruefe(self):
        """Was ein Test über die Prüfung feststellen muss: falsche Daten, falscher Zweck und fremder Schlüssel werden abgelehnt."""
        s = sig(b"daten")
        probleme = []
        if signatur.verify("release", b"manipuliert", s):
            probleme.append("Daten")
        if signatur.verify("wissen", b"daten", s):
            probleme.append("Zweck")
        if signatur.verify("release", b"daten", sig(b"daten", pem=PEM2)):
            probleme.append("Schlüssel")
        return probleme

    def test_pruefung_wirkt(self):
        with aktiv():
            self.assertEqual(self.mutation_pruefe(), [])

    def test_mutation_unterschrift_nicht_geprueft(self):
        with aktiv(), mock.patch.object(signatur, "_pubkey", lambda kid: mock.Mock(verify=lambda s, m: None)):
            self.assertTrue(self.mutation_pruefe(), "Test merkt nicht, dass die Unterschrift nichts mehr prüft")

    def test_mutation_zweck_nicht_im_text(self):
        with aktiv(), mock.patch.object(signatur, "message", lambda zweck, data: b"CLAUDIA-SIG1\n" + data):
            s = sig(b"daten")
            self.assertTrue(signatur.verify("wissen", b"daten", s), "ohne Zweck im Text gälte die Unterschrift überall")


class Werkzeug(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="claudia_sig_")
        self.addCleanup(shutil.rmtree, self.d, True)

    def test_sign_selbstpruefung_und_falsches_passwort(self):
        self.assertTrue(signieren.sign(PEM, PW, "s1", "release", b"x").startswith("CS1.s1."))
        with self.assertRaises(Exception):
            signieren.sign(PEM, "falsches-passwort-xyz", "s1", "release", b"x")
        with self.assertRaises(ValueError):
            signieren.sign(PEM, PW, "s1", "unsinn", b"x")
        with self.assertRaises(ValueError):
            signieren.sign(PEM, PW, "sehr/ungueltige/id", "release", b"x")

    def test_schluesseldatei_nicht_im_repo_und_nie_ueberschreiben(self):
        with mock.patch("getpass.getpass", return_value=PW):
            self.assertEqual(signieren.main(["schluessel", "--datei", os.path.join(ROOT, "x_privat.pem")]), 2)
            self.assertFalse(os.path.exists(os.path.join(ROOT, "x_privat.pem")))
            ziel = os.path.join(self.d, "k.pem")
            self.assertEqual(signieren.main(["schluessel", "--datei", ziel]), 0)
            self.assertEqual(oct(os.stat(ziel).st_mode & 0o777), "0o600")
            vorher = open(ziel, "rb").read()
            self.assertEqual(signieren.main(["schluessel", "--datei", ziel]), 2)
            self.assertEqual(open(ziel, "rb").read(), vorher)

    def test_unterschreiben_schreibt_sig_datei(self):
        k = os.path.join(self.d, "k.pem")
        with open(k, "wb") as fh:
            fh.write(PEM)
        z = os.path.join(self.d, "paket.zip")
        with open(z, "wb") as fh:
            fh.write(b"inhalt")
        with mock.patch("getpass.getpass", return_value=PW):
            self.assertEqual(signieren.main(["unterschreiben", "--privat", k, "--zweck", "release", z]), 0)
        with aktiv():
            self.assertTrue(signatur.verify("release", b"inhalt", open(z + ".sig", "rb").read()))


class Update(unittest.TestCase):
    """Programm-Update: ohne Schlüssel wie bisher, mit Schlüssel nur mit gültiger Unterschrift; sonst bleibt alles unverändert."""
    def setUp(self):
        self.base = tempfile.mkdtemp(prefix="claudia_sigupd_")
        self.addCleanup(shutil.rmtree, self.base, True)
        self.root = old_program(self.base)
        self.data = os.path.join(self.base, "daten")
        self.zip = make_zip()
        rel = release(sha=hashlib.sha256(self.zip).hexdigest())
        rel["assets"].append({"name": "CLAUDIA_v9.9.0.zip.sig", "browser_download_url": appupdate.DOWNLOAD_PREFIX + "v9.9.0/CLAUDIA_v9.9.0.zip.sig", "size": 150})
        self.info = appupdate.parse_release(rel, "2.15.0")
        self.sigbytes = sig(self.zip)
        self.abrufe = []

    def fetch(self, url, *a):
        self.abrufe.append(url)
        return self.sigbytes if url.endswith(".sig") else self.zip

    def snap(self):
        out = {}
        for d, _, fs in os.walk(self.root):
            for f in fs:
                p = os.path.join(d, f)
                out[os.path.relpath(p, self.root)] = open(p, "rb").read()
        return out

    def installiere(self):
        return appupdate.install(self.info, self.root, self.data, None, self.fetch, current="2.15.0")

    def test_sig_adresse_wird_erkannt(self):
        self.assertTrue(self.info["sig_url"].endswith("CLAUDIA_v9.9.0.zip.sig"))

    def test_ohne_schluessel_wie_bisher_und_ohne_zusatzabruf(self):
        r = self.installiere()
        self.assertTrue(r["ok"], r)
        self.assertEqual([u for u in self.abrufe if u.endswith(".sig")], [])

    def test_mit_schluessel_und_gueltiger_unterschrift(self):
        with aktiv():
            r = self.installiere()
        self.assertTrue(r["ok"], r)
        self.assertTrue(any(u.endswith(".sig") for u in self.abrufe))

    def test_ungueltige_unterschrift_aendert_nichts(self):
        vorher = self.snap()
        for schlecht in (sig(b"anderes paket"), sig(self.zip, "wissen"), sig(self.zip, pem=PEM2), b"", b"Muell"):
            self.sigbytes = schlecht
            with aktiv():
                r = self.installiere()
            self.assertFalse(r["ok"])
            self.assertIn("Unterschrift", r["error"])
            self.assertEqual(self.snap(), vorher)

    def test_fehlende_unterschrift_aendert_nichts(self):
        self.info["sig_url"] = ""
        vorher = self.snap()
        with aktiv():
            r = self.installiere()
        self.assertFalse(r["ok"])
        self.assertIn("keine digitale Unterschrift", r["error"])
        self.assertEqual(self.snap(), vorher)

    def test_fremde_unterschrift_adresse_wird_nicht_geladen(self):
        rel = release(sha="a" * 64)
        rel["assets"].append({"name": "CLAUDIA_v9.9.0.zip.sig", "browser_download_url": "https://boese.example/x.sig", "size": 1})
        self.assertEqual(appupdate.parse_release(rel, "2.15.0")["sig_url"], "")

    def test_mutation_unterschrift_nicht_geprueft(self):
        self.sigbytes = b"Muell"
        with aktiv(), mock.patch.object(signatur, "verify", lambda *a, **k: True):
            self.assertTrue(self.installiere()["ok"], "Test merkt nicht, dass die Unterschrift nichts mehr prüft")


class Wissen(unittest.TestCase):
    def setUp(self):
        env = mock.patch.dict(os.environ, {})
        env.start()
        self.addCleanup(env.stop)
        os.environ.pop("CLAUDIA_OFFLINE", None)                 # andere Tests schalten den Offline-Modus ein
        self.base = tempfile.mkdtemp(prefix="claudia_wissen_")
        self.addCleanup(shutil.rmtree, self.base, True)
        self.ref = wissen.bundled()
        neu = copy.deepcopy(self.ref)
        neu["stand"] = "2099-01-01"
        neu["ioc_strings"] = list(neu.get("ioc_strings") or []) + ["NEUER-TESTEINTRAG"]
        self.neu = json.dumps(neu, ensure_ascii=False).encode("utf-8")
        self.abrufe = []
        self.antwort = {wissen.NAME: self.neu, wissen.NAME + ".sig": sig(self.neu, "wissen")}

    def fetch(self, url, *a):
        self.abrufe.append(url)
        name = url.rsplit("/", 1)[1]
        if name not in self.antwort:
            raise coreref.RefError("nicht da")
        return self.antwort[name]

    def test_ohne_schluessel_nichts_laden_und_nie_benutzen(self):
        self.assertEqual(wissen.update(self.base, self.fetch), {"ok": False, "aktiv": False})
        self.assertEqual(self.abrufe, [])
        os.makedirs(wissen.folder(self.base))
        open(os.path.join(wissen.folder(self.base), wissen.NAME), "wb").write(self.neu)
        open(os.path.join(wissen.folder(self.base), wissen.NAME + ".sig"), "wb").write(self.antwort[wissen.NAME + ".sig"])
        self.assertEqual(wissen.load(self.base)["stand"], self.ref["stand"])                     # abgelegte Datei wird ohne Schlüssel nie benutzt

    def test_neue_fassung_wird_uebernommen_und_benutzt(self):
        with aktiv():
            r = wissen.update(self.base, self.fetch)
            self.assertTrue(r["ok"] and r["neu"], r)
            data = wissen.load(self.base)
        self.assertEqual(data["stand"], "2099-01-01")
        self.assertIn("NEUER-TESTEINTRAG", data["ioc_strings"])

    def test_zweiter_abruf_ohne_neuerung(self):
        with aktiv():
            wissen.update(self.base, self.fetch)
            r = wissen.update(self.base, self.fetch)
        self.assertTrue(r["ok"])
        self.assertFalse(r["neu"])

    def test_schlechte_unterschrift_wird_nicht_uebernommen(self):
        for schlecht in (sig(self.neu, "release"), sig(b"anderes", "wissen"), sig(self.neu, "wissen", pem=PEM2), b"Muell"):
            self.antwort[wissen.NAME + ".sig"] = schlecht
            with aktiv():
                r = wissen.update(self.base, self.fetch)
                self.assertFalse(r["ok"])
                self.assertEqual(wissen.load(self.base)["stand"], self.ref["stand"])
            self.assertFalse(os.path.exists(os.path.join(wissen.folder(self.base), wissen.NAME)))

    def test_unbrauchbarer_inhalt_trotz_gueltiger_unterschrift(self):
        d = json.loads(self.neu)
        faelle = {"veraltet": dict(d, stand="2000-01-01"), "ohne_stand": {k: v for k, v in d.items() if k != "stand"},
                  "abschnitt_fehlt": {k: v for k, v in d.items() if k != "ioc_strings"}, "stand_kaputt": dict(d, stand="gestern")}
        for name, inhalt in faelle.items():
            raw = json.dumps(inhalt).encode("utf-8")
            self.antwort = {wissen.NAME: raw, wissen.NAME + ".sig": sig(raw, "wissen")}
            with aktiv():
                r = wissen.update(self.base, self.fetch)
                self.assertFalse(r["ok"] and r.get("neu"), name)
                self.assertEqual(wissen.load(self.base)["stand"], self.ref["stand"], name)
        for raw in (b"[1,2]", b"kein json", b"\xff\xfe", b"{" * 5000):
            self.antwort = {wissen.NAME: raw, wissen.NAME + ".sig": sig(raw, "wissen")}
            with aktiv():
                self.assertFalse(wissen.update(self.base, self.fetch)["ok"])

    def test_abgelegte_datei_wird_beim_lesen_erneut_geprueft(self):
        with aktiv():
            wissen.update(self.base, self.fetch)
            p = os.path.join(wissen.folder(self.base), wissen.NAME)
            open(p, "wb").write(open(p, "rb").read().replace(b"NEUER-TESTEINTRAG", b"BOESER-EINTRAG!!"))     # gleiche Länge, anderer Inhalt
            self.assertEqual(wissen.load(self.base)["stand"], self.ref["stand"])

    def test_netzfehler_und_offline(self):
        with aktiv():
            self.antwort = {}
            r = wissen.update(self.base, self.fetch)
            self.assertFalse(r["ok"])
            with mock.patch.dict(os.environ, {"CLAUDIA_OFFLINE": "1"}):
                self.abrufe.clear()
                self.assertFalse(wissen.update(self.base, self.fetch)["ok"])
                self.assertEqual(self.abrufe, [])

    def test_server_nutzt_neue_fassung_erst_nach_update(self):
        from claudia import server
        with mock.patch.dict(os.environ, {"CLAUDIA_NO_UPDATE_CHECK": "1", "CLAUDIA_REPORTS": self.base + "/b"}), aktiv():
            srv = server.make_server(directory=self.base + "/d")
            self.addCleanup(srv.server_close)
            srv.app.wissen_fetch = self.fetch
            self.assertEqual(srv.app.advisories["stand"], self.ref["stand"])
            r = srv.app.wissen_update()
            self.assertTrue(r.get("neu"), r)
            self.assertEqual(srv.app.advisories["stand"], "2099-01-01")

    def test_mutation_unterschrift_nicht_geprueft(self):
        self.antwort[wissen.NAME + ".sig"] = b"Muell"
        with aktiv(), mock.patch.object(signatur, "verify", lambda *a, **k: True):
            self.assertTrue(wissen.update(self.base, self.fetch).get("neu"), "Test merkt nicht, dass die Unterschrift nichts mehr prüft")

    def test_mutation_abschnitte_nicht_geprueft(self):
        d = json.loads(self.neu)
        d.pop("ioc_strings")
        raw = json.dumps(d).encode("utf-8")
        self.antwort = {wissen.NAME: raw, wissen.NAME + ".sig": sig(raw, "wissen")}
        with aktiv(), mock.patch.object(wissen, "check", lambda raw, ref: json.loads(raw.decode())):
            self.assertTrue(wissen.update(self.base, self.fetch).get("neu"), "Test merkt nicht, dass Abschnitte wegfallen dürften")


if __name__ == "__main__":
    unittest.main()
