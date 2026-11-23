"""Stress und Robustheit (Code-Prüfung): große/seltsame Eingaben, Zufallseingaben, parallele Anfragen an den lokalen Server.

Alles lokal (127.0.0.1) und mit Zeit-, Größen- und Mengengrenzen. Erwartung: sauberer Fehler oder Begrenzung, kein Absturz, kein Hängen."""
import http.client
import json
import os
import random
import shutil
import socket
import sys
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from claudia import appupdate, db, server, util  # noqa: E402

try:
    from hypothesis import HealthCheck, given, settings, strategies as st
    HAS_HYP = True
except ImportError:                                       # pragma: no cover
    HAS_HYP = False

GEHEIM = "Geh3im-4711"


def zeit(f, *a):
    t = time.monotonic()
    r = f(*a)
    return r, time.monotonic() - t


class GrosseEingaben(unittest.TestCase):
    def test_maskierung_nicht_geschlossene_anfuehrungszeichen(self):
        """Früher quadratische Laufzeit (4000 Zeilen: ~7 s); jetzt linear begrenzt."""
        for text in ("public $password = 'a\n" * 20000, "define('DB_PASSWORD', 'a\n" * 20000):
            _, s = zeit(util.mask_secrets, text)
            self.assertLess(s, 8, "mask_secrets braucht %.1f s" % s)

    def test_maskierung_lange_zeile_und_viele_treffer(self):
        _, s = zeit(util.mask_secrets, "public $password = '" + "a" * 2_000_000)
        self.assertLess(s, 3)
        out, s = zeit(util.mask_secrets, ("public $secret = '%s';\n" % GEHEIM) * 50000)
        self.assertNotIn(GEHEIM, out)
        self.assertLess(s, 10)

    def test_maskierung_gewoehnliche_laengen(self):
        for n in (1, 100, 3000):
            v = GEHEIM + "x" * n
            self.assertNotIn(v, util.mask_secrets("public $password = '%s';" % v))
            self.assertNotIn(v, util.mask_secrets("define('AUTH_KEY', \"%s\");" % v))

    def test_hilfsfunktionen_mit_riesigen_eingaben(self):
        gross = {
            "mask_ip": lambda: util.mask_ip("1.2.3.4 " * 100000),
            "mask_ip6": lambda: util.mask_ip("a:" * 100000),
            "split_sections": lambda: util.split_sections("@@A\n" * 100000),
            "vtuple": lambda: util.vtuple("1." * 100000),
            "vcmp": lambda: util.vcmp("1." * 50000, "1." * 49999 + "2"),
            "sq": lambda: util.sq("a'" * 500000),
            "lines_of": lambda: util.lines_of("x\n" * 1_000_000),
            "parse_xml": lambda: util.parse_xml("<a>" + "<b/>" * 300000 + "</a>"),
            "parse_xml_tief": lambda: util.parse_xml("<a>" * 100000),
            "validate_vars": lambda: db.validate_vars("a" * 1_000_000, "p", "u", "h", ""),
        }
        for name, f in gross.items():
            _, s = zeit(f)
            self.assertLess(s, 10, "%s braucht %.1f s" % (name, s))

    def test_seltsame_zeichen(self):
        seltsam = ["", "\x00", "\x00" * 1000, "\udcff".encode("utf-8", "surrogatepass").decode("utf-8", "replace"), "\r\n" * 100, "\u202e", "ä" * 10000, "\x1b[31m", "\t" * 100]
        for s in seltsam:
            for f in (util.mask_secrets, util.mask_ip, util.vtuple, util.sq, util.lines_of, util.parse_xml, util.clean_line):
                try:
                    f(s)
                except Exception as e:                    # noqa: BLE001
                    self.fail("%s(%r) wirft %s" % (f.__name__, s[:20], e))
            self.assertIsInstance(db.validate_vars(s, "p", "u", "h", ""), str)


class Zufall(unittest.TestCase):
    """Zufallseingaben gegen reine Funktionen (feste Startzahl -> wiederholbar)."""

    def test_zufall_ohne_ausnahme(self):
        rnd = random.Random(20261123)
        alphabet = list("ab01.:/;'\"\\\n\t -_$@`<>&|~*%\x00ä²٣") + ["<!DOCTYPE", "<!ENTITY", "public $password", "define(", "@@", "..", "http://", "https://"]
        funcs = [util.mask_secrets, util.mask_ip, util.vtuple, util.sq, util.lines_of, util.parse_xml, util.clean_line, util.digits,
                 util.split_sections]
        for _ in range(1500):
            s = "".join(rnd.choice(alphabet) for _ in range(rnd.randint(0, 80)))
            for f in funcs:
                try:
                    f(s)
                except Exception as e:                    # noqa: BLE001
                    self.fail("%s(%r) wirft %s" % (f.__name__, s, e))
            self.assertIsInstance(db.validate_vars(s, s, s, s, s), str)

    def test_update_parser_zufall(self):
        rnd = random.Random(7)
        teile = ["v1.2.3", "2.16.0", "", None, 5, "SHA-256: " + "a" * 64, "x" * 64, "latest", "../..", "CLAUDIA_v1.2.3.zip", [], {}]
        for _ in range(800):
            d = {"tag_name": rnd.choice(teile), "body": rnd.choice(teile), "assets": rnd.choice([[], None, "x", [rnd.choice(teile)], [{"name": rnd.choice(teile), "browser_download_url": rnd.choice(teile), "digest": rnd.choice(teile)}]])}
            try:
                appupdate.parse_release(d, "2.16.0")
            except ValueError:
                pass
            except Exception as e:                        # noqa: BLE001
                self.fail("parse_release(%r) wirft %s" % (d, type(e).__name__))
        for n in ("a/../b", "..", "/x", "C:\\x", "a\\..\\b", "", "a//b", "./a", "a\x00b", "ä/ö", "../" * 100):
            r = appupdate._clean_name(n)
            self.assertTrue(r is None or (".." not in r.split("/") and not r.startswith("/")), n)


@unittest.skipUnless(HAS_HYP, "hypothesis nicht installiert")
class Eigenschaften(unittest.TestCase):
    """Invarianten mit hypothesis."""

    @settings(max_examples=300, deadline=2000, suppress_health_check=list(HealthCheck), database=None)
    @given(st.text())
    def test_clean_name_nie_unsicher(self, s):
        r = appupdate._clean_name(s)
        if r is not None:
            self.assertNotIn("..", r.replace("\\", "/").split("/"))
            self.assertFalse(r.startswith("/"))

    @settings(max_examples=300, deadline=2000, suppress_health_check=list(HealthCheck), database=None)
    @given(st.text(), st.text(), st.text())
    def test_validate_vars_erlaubt_nur_gewoehnliche_zeichen(self, a, b, c):
        if db.validate_vars(a, b, c, "h", "") == "":
            for v in (a, b, c):
                self.assertFalse(set(v) & set("'\"`;|&<>(){}\\ \n\r\t\x00"), repr(v))
                self.assertFalse(v.startswith("-"))

    @settings(max_examples=300, deadline=3000, suppress_health_check=list(HealthCheck), database=None)
    @given(st.text(alphabet=st.characters(blacklist_categories=("Cs",)), max_size=300))
    def test_mask_secrets_entfernt_geheimnis(self, wert):
        wert = wert.replace("'", "").replace("\\", "")
        if not wert.strip():
            return
        out = util.mask_secrets("public $password = '%s';" % wert)
        self.assertNotIn("'%s'" % wert, out)

    @settings(max_examples=200, deadline=2000, suppress_health_check=list(HealthCheck), database=None)
    @given(st.text(max_size=2000))
    def test_parse_xml_wirft_nie(self, s):
        r = util.parse_xml(s)
        self.assertTrue(r is None or hasattr(r, "tag"))


class ServerUnterLast(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base = tempfile.mkdtemp(prefix="claudia_last_")
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

    def get(self, pfad="/api/init", auth=True, timeout=15):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=timeout)
        try:
            h = {"Cookie": "claudia=" + self.sid, "X-Claudia": "1"} if auth else {}
            c.request("GET", pfad, headers=h)
            r = c.getresponse()
            r.read()
            return r.status
        except (OSError, http.client.HTTPException):
            return 0
        finally:
            c.close()

    def test_parallel_berechtigt_und_unberechtigt(self):
        """200 gleichzeitige Anfragen (je zur Hälfte mit/ohne Sitzung): richtige Antworten, schnell, Server danach ansprechbar."""
        threads_vorher = threading.active_count()
        with ThreadPoolExecutor(max_workers=40) as ex:
            t = time.monotonic()
            res = list(ex.map(lambda i: (i % 2 == 0, self.get(auth=(i % 2 == 0))), range(200)))
            dauer = time.monotonic() - t
        for mit, code in res:
            self.assertEqual(code, 200 if mit else 403)
        self.assertLess(dauer, 60)
        time.sleep(0.5)
        self.assertEqual(self.get(), 200)
        self.assertLess(threading.active_count(), threads_vorher + 10, "Threads bleiben hängen")

    def test_haengende_verbindungen_blockieren_nicht(self):
        """Halb gesendete Anfragen und stumme Verbindungen halten den Server nicht auf."""
        socks = []
        try:
            for i in range(30):
                s = socket.create_connection(("127.0.0.1", self.port), timeout=5)
                if i % 3 == 0:
                    s.sendall(b"GET /api/init HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n" % self.port)        # Kopf nie beendet
                elif i % 3 == 1:
                    s.sendall(b"POST /api/app-update-check HTTP/1.1\r\nContent-Length: 500000\r\n\r\n{")   # Inhalt fehlt
                socks.append(s)
            t = time.monotonic()
            self.assertEqual(self.get(), 200)
            self.assertLess(time.monotonic() - t, 5)
        finally:
            for s in socks:
                s.close()
        self.assertEqual(self.get(), 200)

    def test_muell_anfragen(self):
        """Ungültige Anfragen führen zu Fehlerantwort oder Verbindungsende, nie zum Absturz."""
        muell = [b"\x00" * 5000, b"GET\r\n\r\n", b"GET / HTTP/9.9\r\n\r\n", b"A" * 70000 + b"\r\n\r\n", b"GET /" + b"a" * 100000 + b" HTTP/1.1\r\n\r\n",
                 b"POST /api/x HTTP/1.1\r\nContent-Length: abc\r\n\r\n", b"GET /\xff\xfe HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
                 b"GET / HTTP/1.1\r\n" + b"X: y\r\n" * 5000 + b"\r\n"]
        for m in muell:
            try:
                s = socket.create_connection(("127.0.0.1", self.port), timeout=5)
                s.sendall(m)
                s.settimeout(5)
                try:
                    s.recv(1024)
                except OSError:
                    pass
                s.close()
            except OSError:
                pass
        self.assertEqual(self.get(), 200)

    def test_viele_grosse_post_werden_abgelehnt(self):
        for _ in range(5):
            c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
            try:
                c.putrequest("POST", "/api/app-update-check", skip_accept_encoding=True)
                c.putheader("Cookie", "claudia=" + self.sid)
                c.putheader("X-Claudia", "1")
                c.putheader("Content-Length", "50000000")
                c.endheaders()
                r = c.getresponse()
                self.assertEqual(r.status, 413)
            finally:
                c.close()
        self.assertEqual(self.get(), 200)


if __name__ == "__main__":
    unittest.main()
