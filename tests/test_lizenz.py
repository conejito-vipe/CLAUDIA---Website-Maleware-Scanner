"""Lizenzschlüssel: Prüfung der Unterschrift, Schalter je Bereich, immer freie Prüfung, Erzeugungswerkzeug und Wirksamkeitsbeweis.

Alle Schlüsselpaare entstehen zur Laufzeit im Test (nie ein echter privater Schlüssel im Repo). PUBLIC_KEYS wird nur per Monkeypatch gesetzt."""
import base64
import http.client
import importlib.util
import json
import os
import shutil
import sys
import tempfile
import threading
import unittest
from datetime import date, timedelta
from unittest import mock

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, ROOT)
from claudia import lizenz, server  # noqa: E402

_spec = importlib.util.spec_from_file_location("claudia_lizenz_tool", os.path.join(ROOT, "tools", "lizenz.py"))
tool = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(tool)

PW = "Test-Passwort-nur-fuer-den-Test"
PEM, PUB = tool.make_pair(PW)
PEM2, PUB2 = tool.make_pair(PW)                   # ein zweites, fremdes Paar
ALLE_BEREICHE = tuple(lizenz.BEREICHE)
MORGEN = (date.today() + timedelta(days=200)).isoformat()


def key(bis=MORGEN, bereiche="alle", kid="k1", art="gewerblich", name="Firma Test", pem=None, lid=""):
    with mock.patch.dict(lizenz.PUBLIC_KEYS, {kid: PUB}):
        return tool.issue(pem or PEM, PW, kid, name, art, bis, bereiche, 0, lid, heute=date(2000, 1, 1))


def gut_keys():
    return mock.patch.dict(lizenz.PUBLIC_KEYS, {"k1": PUB}, clear=True)


def _flip(text, pos):
    c = text[pos]
    return text[:pos] + ("B" if c != "B" else "C") + text[pos + 1:]


def pruefe_schluessel():
    """Probleme als Liste (leer = Prüfung wirkt)."""
    probleme = []
    k = key()
    r = lizenz.parse(k)
    if not (r["valid"] and r["name"] == "Firma Test" and r["art"] == "gewerblich" and r["areas"] == "alle"):
        probleme.append("gültiger Schlüssel wird abgelehnt: %s" % r)
    if not lizenz.parse("  " + k[:20] + "\n" + k[20:] + " \n")["valid"]:
        probleme.append("Zeilenumbruch/Leerzeichen aus einer E-Mail stören")
    if not lizenz.parse(key(bereiche=["aktionen", "dashboard"]))["valid"]:
        probleme.append("Schlüssel mit Bereichsliste wird abgelehnt")
    teile = k.split(".")
    # ein verändertes Zeichen in den Angaben oder in der Unterschrift
    for i in (0, 5, len(teile[1]) // 2, len(teile[1]) - 2):
        bad = ".".join([teile[0], _flip(teile[1], i), teile[2]])
        if lizenz.parse(bad)["valid"]:
            probleme.append("veränderte Angaben (Stelle %d) werden angenommen" % i)
    for i in (0, 10, len(teile[2]) - 3):
        bad = ".".join([teile[0], teile[1], _flip(teile[2], i)])
        if lizenz.parse(bad)["valid"]:
            probleme.append("veränderte Unterschrift (Stelle %d) wird angenommen" % i)
    # Angaben austauschen (anderer Name/anderes Datum) mit alter Unterschrift
    body = json.loads(base64.urlsafe_b64decode(teile[1] + "=="))
    body["bis"] = "2099-01-01"
    neu = lizenz.b64e(json.dumps(body, separators=(",", ":")).encode())
    if lizenz.parse(".".join([teile[0], neu, teile[2]]))["valid"]:
        probleme.append("verlängertes Ablaufdatum mit alter Unterschrift wird angenommen")
    if lizenz.parse(key(pem=PEM2))["valid"]:
        probleme.append("Schlüssel eines fremden Schlüsselpaars wird angenommen")
    with mock.patch.dict(lizenz.PUBLIC_KEYS, {"k1": PUB}, clear=True):
        unbekannt = tool.issue(PEM, PW, "k1", "X", "gewerblich", MORGEN)
    with mock.patch.dict(lizenz.PUBLIC_KEYS, {"andere": PUB}, clear=True):
        if lizenz.parse(unbekannt)["valid"]:
            probleme.append("unbekannte Schlüssel-ID wird angenommen")
    abgelaufen = lizenz.parse(key(bis=(date.today() - timedelta(days=1)).isoformat()))
    if abgelaufen["valid"] or abgelaufen["reason"] != "abgelaufen":
        probleme.append("abgelaufener Schlüssel gilt")
    if not lizenz.parse(key(bis=date.today().isoformat()))["valid"]:
        probleme.append("am letzten Tag gültiger Schlüssel wird abgelehnt")
    gesperrt = key(lid="gesperrt1")
    with mock.patch.object(lizenz, "REVOKED", ("gesperrt1",)):
        if lizenz.parse(gesperrt)["valid"]:
            probleme.append("gesperrte Lizenz-ID gilt")
    for muell in (None, 5, [], {}, "", " ", "CL1", "CL1..", "CL1.a.b", "XX1." + ".".join(k.split(".")[1:]), "CL1." + "A" * 100000, "\x00" * 50, "ä" * 50,
                  "CL1." + lizenz.b64e(b"[" * 3000) + "." + lizenz.b64e(b"x"), "CL1." + lizenz.b64e(b"{}") + ".", k + "." + k, k.upper()):
        try:
            if lizenz.parse(muell)["valid"]:
                probleme.append("Müll %r gilt" % (str(muell)[:20],))
        except Exception as e:                       # noqa: BLE001
            probleme.append("Müll %r wirft %s" % (str(muell)[:20], type(e).__name__))
    return probleme


def pruefe_schalter(base):
    """Wirkung des Schalters je Bereich, Prüfung und Rückweg immer frei."""
    probleme = []
    immer = ("pruefung", "verbindung", "hilfe", "sprache", "update", "lizenz", "beenden")
    with mock.patch.object(lizenz, "GESPERRT_OHNE_LIZENZ", ALLE_BEREICHE + immer):        # selbst wenn jemand sie sperren wollte: bleiben sie frei
        for a in ALLE_BEREICHE:
            if lizenz.frei(base, a):
                probleme.append("%s ist ohne Schlüssel nicht gesperrt" % a)
        for a in immer:
            if not lizenz.frei(base, a):
                probleme.append("%s ist gesperrt, muss aber immer frei sein" % a)
        for aid in ("restore_quarantine", "backup_now"):
            if not lizenz.frei(base, "aktionen", aid):
                probleme.append("Rückweg-Aktion %s ist gesperrt" % aid)
        if lizenz.frei(base, "aktionen", "core_update"):
            probleme.append("Aktion core_update ist ohne Schlüssel nicht gesperrt")
        lizenz.store(base, key())
        for a in ALLE_BEREICHE:
            if not lizenz.frei(base, a):
                probleme.append("%s bleibt trotz gültigem Schlüssel gesperrt" % a)
        lizenz.store(base, key(bereiche=["dashboard"]))
        if not lizenz.frei(base, "dashboard") or lizenz.frei(base, "aktionen"):
            probleme.append("Bereichsliste wirkt nicht (nur dashboard sollte frei sein)")
        lizenz.remove(base)
        if lizenz.frei(base, "dashboard"):
            probleme.append("nach dem Entfernen des Schlüssels ist dashboard frei")
        lizenz.store(base, key(bis=(date.today() - timedelta(days=3)).isoformat()))
        if lizenz.frei(base, "aktionen"):
            probleme.append("abgelaufener Schlüssel schaltet frei")
        lizenz.remove(base)
        if lizenz.store(base, "CL1.kaputt.kaputt")["valid"] or lizenz.load(base):
            probleme.append("ungültiger Schlüssel wird gespeichert")
    with mock.patch.object(lizenz, "GESPERRT_OHNE_LIZENZ", ()):
        if not all(lizenz.frei(base, a) for a in ALLE_BEREICHE):
            probleme.append("Standard (nichts gesperrt) wirkt nicht")
    return probleme


class Schluessel(unittest.TestCase):
    def test_pruefung_wirkt(self):
        with gut_keys():
            self.assertEqual(pruefe_schluessel(), [])

    def test_mutation_unterschrift_nicht_geprueft(self):
        with gut_keys(), mock.patch.object(lizenz, "_pubkey", lambda kid: mock.Mock(verify=lambda sig, body: None)):
            self.assertTrue(pruefe_schluessel(), "Test merkt nicht, dass die Unterschrift nichts mehr prüft")

    def test_mutation_ablauf_nicht_geprueft(self):
        with gut_keys():
            orig = lizenz.parse

            def ohne_ablauf(k, today=None):
                return orig(k, today=date(2000, 1, 1))
            with mock.patch.object(lizenz, "parse", ohne_ablauf):
                self.assertTrue(pruefe_schluessel(), "Test merkt nicht, dass der Ablauf nicht geprüft wird")

    def test_mutation_sperrliste_ignoriert(self):
        with gut_keys():
            orig = lizenz.parse

            def ohne_sperre(k, today=None):
                with mock.patch.object(lizenz, "REVOKED", ()):
                    return orig(k, today)
            with mock.patch.object(lizenz, "parse", ohne_sperre):
                self.assertTrue(pruefe_schluessel(), "Test merkt nicht, dass die Sperrliste ignoriert wird")

    def test_oeffentlicher_schluessel_im_programm_ist_gueltig(self):
        for kid, raw in lizenz.PUBLIC_KEYS.items():
            self.assertEqual(len(base64.b64decode(raw)), 32, kid)

    def test_kein_privater_schluessel_im_repo(self):
        import re
        pem = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----\s*[A-Za-z0-9+/=\s]{80,}-----END")
        gefunden = []
        for d, dirs, files in os.walk(ROOT):
            dirs[:] = [x for x in dirs if x not in (".git", "__pycache__", ".venv", "dist", "build", ".hypothesis")]
            for f in files:
                p = os.path.join(d, f)
                if f.endswith((".pem", ".key")) or f.startswith("lizenz_privat") or f == "lizenzen_ausgestellt.csv":
                    gefunden.append(p)
                elif f.endswith((".py", ".json", ".txt", ".md", ".js", ".html", ".yml", ".toml", ".cfg", ".bat", ".command", ".iss", ".ps1")):
                    try:
                        text = open(p, encoding="utf-8", errors="ignore").read()
                    except OSError:
                        continue
                    if pem.search(text):
                        gefunden.append(p)
        self.assertEqual(gefunden, [], "Hier liegt ein privater Schlüssel oder eine Schlüsseldatei")

    def test_standard_nichts_gesperrt(self):
        """Ausgelieferter Standard: kein Bereich ist ohne Lizenz gesperrt (Entscheidung des Autors, siehe Lizenz-Konzept)."""
        self.assertEqual(lizenz.GESPERRT_OHNE_LIZENZ, ())

    def test_gesperrte_bereiche_sind_bekannt(self):
        self.assertTrue(set(lizenz.GESPERRT_OHNE_LIZENZ) <= set(lizenz.BEREICHE))
        self.assertFalse(set(lizenz.IMMER_FREI) & set(lizenz.BEREICHE), "Ein immer freier Bereich darf nicht sperrbar sein")
        self.assertIn("pruefung", lizenz.IMMER_FREI)


class Schalter(unittest.TestCase):
    def setUp(self):
        self.base = tempfile.mkdtemp(prefix="claudia_lic_")

    def tearDown(self):
        shutil.rmtree(self.base, True)

    def test_schalter_wirkt(self):
        with gut_keys():
            self.assertEqual(pruefe_schalter(self.base), [])

    def test_mutation_frei_immer_ja(self):
        with gut_keys(), mock.patch.object(lizenz, "frei", lambda base, area, aid="": True):
            self.assertTrue(pruefe_schalter(self.base), "Test merkt nicht, dass der Schalter nichts mehr sperrt")

    def test_mutation_pruefung_sperrbar(self):
        with gut_keys(), mock.patch.object(lizenz, "IMMER_FREI", ()):
            self.assertTrue(pruefe_schalter(self.base), "Test merkt nicht, dass die Prüfung sperrbar geworden ist")

    def test_mutation_rueckweg_gesperrt(self):
        with gut_keys(), mock.patch.object(lizenz, "AKTIONEN_IMMER_FREI", ()):
            self.assertTrue(pruefe_schalter(self.base))


class ErzeugungsWerkzeug(unittest.TestCase):
    def test_privater_schluessel_ist_verschluesselt(self):
        self.assertIn(b"ENCRYPTED PRIVATE KEY", PEM)
        from cryptography.hazmat.primitives import serialization
        with self.assertRaises(Exception):
            serialization.load_pem_private_key(PEM, None)
        with self.assertRaises(Exception):
            serialization.load_pem_private_key(PEM, b"falsches-passwort")

    def test_kurzes_passwort_abgelehnt(self):
        with self.assertRaises(ValueError):
            tool.make_pair("kurz")

    def test_ausstellen_prueft_angaben(self):
        for kwargs in ({"art": "unbekannt"}, {"bis": "morgen"}, {"bis": "2027-13-45"}, {"name": ""}, {"bereiche": ["gibt_es_nicht"]}):
            args = dict(kid="k1", name="X", art="gewerblich", bis=MORGEN, bereiche="alle")
            args.update(kwargs)
            with self.assertRaises(ValueError, msg=str(kwargs)):
                tool.issue(PEM, PW, args["kid"], args["name"], args["art"], args["bis"], args["bereiche"])

    def test_falsches_passwort_beim_ausstellen(self):
        with self.assertRaises(Exception):
            tool.issue(PEM, "falsch-falsch-falsch", "k1", "X", "gewerblich", MORGEN)

    def test_schluesseldatei_nicht_im_repo(self):
        ns = mock.Mock(datei=os.path.join(tool.ROOT, "lizenz_privat.pem"), kid="k1")
        with mock.patch("getpass.getpass") as gp:
            self.assertEqual(tool.cmd_schluessel(ns), 2)
            gp.assert_not_called()
        self.assertFalse(os.path.exists(ns.datei))

    def test_schluesseldatei_wird_nie_ueberschrieben(self):
        d = tempfile.mkdtemp(prefix="claudia_lic_")
        try:
            f = os.path.join(d, "privat.pem")
            open(f, "w").write("vorhanden")
            self.assertEqual(tool.cmd_schluessel(mock.Mock(datei=f, kid="k1")), 2)
            self.assertEqual(open(f).read(), "vorhanden")
            neu = os.path.join(d, "neu.pem")
            with mock.patch("getpass.getpass", return_value=PW):
                self.assertEqual(tool.cmd_schluessel(mock.Mock(datei=neu, kid="k1")), 0)
            self.assertIn(b"ENCRYPTED PRIVATE KEY", open(neu, "rb").read())
            if os.name != "nt":
                self.assertEqual(os.stat(neu).st_mode & 0o077, 0, "private Schlüsseldatei darf nur dem Besitzer gehören")
        finally:
            shutil.rmtree(d, True)


class Server(unittest.TestCase):
    """Der Schalter im laufenden Programm: gesperrte Wege bekommen 403, alles andere (Prüfung, Verbindung, Rückweg) nie."""

    @classmethod
    def setUpClass(cls):
        cls.base = tempfile.mkdtemp(prefix="claudia_licsrv_")
        cls._env = mock.patch.dict(os.environ, {"CLAUDIA_NO_UPDATE_CHECK": "1", "CLAUDIA_NO_RESTART": "1"})
        cls._env.start()
        os.environ.pop("CLAUDIA_OFFLINE", None)
        cls.srv = server.make_server(directory=os.path.join(cls.base, "daten"))
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.sid = cls.srv.new_session()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls._env.stop()
        shutil.rmtree(cls.base, True)

    def call(self, method, path, body=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=15)
        try:
            h = {"Cookie": "claudia=" + self.sid, "X-Claudia": "1", "Content-Type": "application/json"}
            c.request(method, path, body=json.dumps(body if body is not None else {}) if method == "POST" else None, headers=h)
            r = c.getresponse()
            raw = r.read()
            try:
                return r.status, json.loads(raw)
            except ValueError:
                return r.status, {}
        finally:
            c.close()

    GESPERRT = (("POST", "/api/action-preview", {"id": "core_update"}), ("POST", "/api/action-run", {"id": "core_update"}), ("POST", "/api/logs-plan", {}),
                ("POST", "/api/logs-save", {}), ("GET", "/api/export", None), ("GET", "/api/zip", None), ("POST", "/api/handover", {}), ("GET", "/api/dashboard", None),
                ("POST", "/api/dashboard-delete", {}))
    FREI = (("GET", "/api/init", None), ("GET", "/api/state?since=0", None), ("POST", "/api/connect", {}), ("GET", "/api/connect-state", None), ("POST", "/api/run", {}),
            ("POST", "/api/cancel", {}), ("GET", "/api/docs", None), ("GET", "/api/license", None), ("GET", "/api/app-update", None), ("GET", "/api/ping", None),
            ("GET", "/api/action-state?since=0", None), ("POST", "/api/action-preview", {"id": "restore_quarantine"}), ("POST", "/api/action-preview", {"id": "backup_now"}),
            ("POST", "/api/disconnect", {}))

    def probleme(self):
        p = []
        with mock.patch.object(lizenz, "GESPERRT_OHNE_LIZENZ", ALLE_BEREICHE), gut_keys():
            lizenz.remove(self.srv.app.dir)
            for m, pf, b in self.GESPERRT:
                st, data = self.call(m, pf, b)
                if st != 403 or not data.get("lizenz"):
                    p.append("%s %s ist ohne Schlüssel nicht gesperrt (%s)" % (m, pf, st))
            for m, pf, b in self.FREI:
                st, data = self.call(m, pf, b)
                if data.get("lizenz"):
                    p.append("%s %s ist gesperrt, muss aber frei sein" % (m, pf))
            # ungültiger Schlüssel ändert nichts
            st, data = self.call("POST", "/api/license-set", {"key": "CL1.kaputt.kaputt"})
            if data.get("accepted") or lizenz.load(self.srv.app.dir):
                p.append("ungültiger Schlüssel wird angenommen oder gespeichert")
            # gültiger Schlüssel gibt alles frei
            st, data = self.call("POST", "/api/license-set", {"key": key()})
            if not data.get("accepted"):
                p.append("gültiger Schlüssel wird nicht angenommen: %s" % data.get("message"))
            for m, pf, b in self.GESPERRT:
                st, data = self.call(m, pf, b)
                if data.get("lizenz"):
                    p.append("%s %s bleibt trotz Schlüssel gesperrt" % (m, pf))
            st, data = self.call("POST", "/api/license-remove", {})
            st, data = self.call("POST", "/api/action-preview", {"id": "core_update"})
            if not data.get("lizenz"):
                p.append("nach dem Entfernen des Schlüssels ist die Sperre weg")
            lizenz.remove(self.srv.app.dir)
        return p

    def test_schalter_im_server(self):
        self.assertEqual(self.probleme(), [])

    def test_ohne_schalter_nichts_gesperrt(self):
        """Standard: nichts gesperrt, das Programm verhält sich wie vor der Lizenz-Technik."""
        st, data = self.call("POST", "/api/action-preview", {"id": "core_update"})
        self.assertFalse(data.get("lizenz"))

    def test_mutation_area_of(self):
        with mock.patch.object(server, "area_of", lambda path: ""):
            self.assertTrue(self.probleme(), "Test merkt nicht, dass die Sperre im Server fehlt")

    def test_mutation_frei(self):
        with mock.patch.object(lizenz, "frei", lambda *a, **k: True):
            self.assertTrue(self.probleme())

    def test_mutation_pruefung_gesperrt(self):
        with mock.patch.object(server, "AREA_OF", dict(server.AREA_OF, **{"/api/run": "aktionen"})):
            self.assertTrue(self.probleme(), "Test merkt nicht, dass /api/run gesperrt wurde")


if __name__ == "__main__":
    unittest.main()
