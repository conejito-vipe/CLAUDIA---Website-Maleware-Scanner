"""Funktionstest der Sicherheitsfunktionen (Code-Prüfung): erlaubte Eingabe, Angriffsmuster und Wirksamkeitsbeweis.

Aufbau je Sicherheitsfunktion: eine Prüffunktion ``pruefe_*`` liefert die Liste der Probleme (leer = Schutz wirkt).
  1. Im Normalzustand muss die Liste leer sein.
  2. Wirksamkeitsbeweis (Mutationstest): Wird die Sicherheitsfunktion absichtlich entschärft (Monkeypatch, nie im Original), muss die Liste NICHT mehr leer sein.
     Bleibt sie leer, wäre der Test wertlos.
Es werden nur harmlose Marker verwendet (Befehle wie ``;touch ...`` werden nie ausgeführt, sondern nur auf Wirkungslosigkeit geprüft). Alles lokal, nie gegen fremde Systeme."""
import hashlib
import http.client
import io
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import zipfile
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from claudia import actions, appupdate, coreref, db, secure, server, util  # noqa: E402

HAS_BASH = shutil.which("bash") is not None


def _liste(*paare):
    return [text for ok, text in paare if not ok]


# ---------------------------------------------------------------- 1. Shell-Quoting (util.sq)
ANGRIFFE_SHELL = ["a b", "x; touch PWN", "$(touch PWN)", "`touch PWN`", "a'b\"c", "x && touch PWN", "x | touch PWN", "x\ntouch PWN", "-rf", "~", "*", "\\", "ä ö ü", "a\tb", "x > PWN", "", "'"]


def pruefe_sq():
    probleme = []
    wd = tempfile.mkdtemp(prefix="claudia_sq_")
    try:
        for s in ANGRIFFE_SHELL:
            r = subprocess.run(["bash", "-c", "printf '%%s' %s" % util.sq(s)], cwd=wd, capture_output=True, timeout=10)
            if r.stdout.decode("utf-8", "replace") != s:
                probleme.append("sq: %r wird nicht als ein einziges Wort gelesen" % s)
        if os.path.exists(os.path.join(wd, "PWN")):
            probleme.append("sq: eingeschleuster Befehl wurde ausgeführt")
    finally:
        shutil.rmtree(wd, True)
    return probleme


# ---------------------------------------------------------------- 2. XML (util.parse_xml)
def pruefe_xml():
    bombe = '<?xml version="1.0"?><!DOCTYPE l [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">]><l>&b;&b;&b;</l>'
    extern = '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x>&e;</x>'
    return _liste(
        (util.parse_xml("<a><b>1</b></a>") is not None, "gültiges XML wird abgelehnt"),
        (util.parse_xml(bombe) is None, "Entity-Bombe wird gelesen"),
        (util.parse_xml(extern) is None, "externe Entity wird gelesen"),
        (util.parse_xml("<!  DOCTYPE x><x/>") is None, "DOCTYPE mit Leerzeichen wird gelesen"),
        (util.parse_xml("<!doctype x><x/>") is None, "doctype klein wird gelesen"),
        (util.parse_xml("<a>" + "x" * 3_100_000 + "</a>") is None, "übergroße Eingabe wird gelesen"),
        (util.parse_xml(b"\xff\xfe<a/>") is None, "ungültiges UTF-8 wird gelesen"),
        (util.parse_xml(None) is None and util.parse_xml(5) is None and util.parse_xml("") is None, "Nicht-Text führt zu Ausnahme oder Treffer"),
        (util.parse_xml("<a><b></a>") is None, "kaputtes XML führt zu Ausnahme oder Treffer"),
        (util.parse_xml("<a>\x00</a>") is None, "Nullbyte wird gelesen"),
    )


def _naiv_xml(text, max_len=0):
    import xml.etree.ElementTree as ET
    try:
        return ET.fromstring(text)
    except Exception:
        return None


# ---------------------------------------------------------------- 3. Ziffernprüfung (util.digits)
def pruefe_digits():
    return _liste(
        (util.digits("123"), "echte Ziffern werden abgelehnt"),
        (not util.digits("²"), "hochgestellte Ziffer gilt als Zahl"),
        (not util.digits("٣"), "arabische Ziffer gilt als Zahl"),
        (not util.digits(""), "leerer Text gilt als Zahl"),
        (not util.digits(" 1"), "Leerzeichen gelten als Zahl"),
        (not util.digits("1.5") and not util.digits("-1"), "Dezimal-/Minuszeichen gelten als Zahl"),
        (not util.digits(None) and not util.digits(5), "Nicht-Text gilt als Zahl"),
    )


# ---------------------------------------------------------------- 4. Datenbank-Angaben (db.validate_vars)
def pruefe_validate_vars():
    gut = db.validate_vars("joomla_db", "jos_", "dbuser", "localhost", "")
    gut_sock = db.validate_vars("joomla_db", "jos_", "dbuser", "", "/var/run/mysqld/mysqld.sock")
    boese = ["x; touch PWN", "x' OR '1'='1", "x`id`", "$(id)", "-h evil", "x y", "x\ny", "x|y", "x&y", "x>y", "a" * 300, "x\x00y", "x\n", "0\n", "\n"]               # auch ein Zeilenumbruch am Ende (Regex-$ ließ ihn früher durch)
    probleme = _liste((gut == "", "normale Angaben werden abgelehnt"), (gut_sock == "", "normaler Socket wird abgelehnt"))
    for b in boese:
        for feld, args in (("Name", (b, "p_", "u", "h", "")), ("Präfix", ("n", b, "u", "h", "")), ("Benutzer", ("n", "p_", b, "h", "")), ("Host", ("n", "p_", "u", b, "")), ("Socket", ("n", "p_", "u", "h", b))):
            if db.validate_vars(*args) == "":
                probleme.append("validate_vars lässt %s=%r durch" % (feld, b))
    return probleme


# ---------------------------------------------------------------- 5. Pfadprüfung für Aktionen (actions._safe_path)
def pruefe_safe_path():
    return _liste(
        (actions._safe_path("./wp-content/plugins/x/a.php"), "normaler Pfad wird abgelehnt"),
        (not actions._safe_path("/etc/passwd"), "absoluter Pfad erlaubt"),
        (not actions._safe_path("./../../etc/passwd"), "../ am Anfang erlaubt"),
        (not actions._safe_path("./a/../../b"), "../ in der Mitte erlaubt"),
        (not actions._safe_path("./a/.."), "/.. am Ende erlaubt"),
        (not actions._safe_path("./a\nb"), "Zeilenumbruch erlaubt"),
        (not actions._safe_path("./a\0b"), "Nullbyte erlaubt"),
        (not actions._safe_path("./" + "a" * 500), "überlanger Pfad erlaubt"),
        (not actions._safe_path(None) and not actions._safe_path(5), "Nicht-Text erlaubt"),
    )


# ---------------------------------------------------------------- 6. URL-Regeln (secure)
def pruefe_url():
    return _liste(
        (secure.is_secure_url("https://example.org/x"), "https wird abgelehnt"),
        (secure.is_secure_url("http://127.0.0.1:8080/"), "lokales http wird abgelehnt"),
        (not secure.is_secure_url("http://example.org/"), "fremdes http gilt als sicher"),
        (not secure.is_secure_url("http://127.0.0.1.evil.example/"), "Lookalike-Host gilt als lokal"),
        (not secure.is_secure_url("http://localhost@evil.example/"), "Benutzerteil-Trick gilt als lokal"),
        (not secure.is_secure_url("ftp://example.org/"), "ftp gilt als sicher"),
        (not secure.is_secure_url("javascript:alert(1)") and not secure.is_secure_url(""), "javascript:/leer gilt als sicher"),
        (secure.to_https("http://example.org/a")[0] == "https://example.org/a", "http wird nicht auf https gehoben"),
        (secure.to_https("http://localhost/a")[0] == "http://localhost/a", "lokales http wird verändert"),
    )


# ---------------------------------------------------------------- 7. Geheimnisse maskieren (util.mask_secrets)
GEHEIM = "Geh3im-Wert-4711"


def pruefe_mask():
    joomla = "<?php class JConfig { public $password = '%s'; public $secret = \"%s\"; public $user = 'u'; }" % (GEHEIM, GEHEIM)
    wp = "define( 'DB_PASSWORD', '%s' );\ndefine('AUTH_KEY', \"%s\");\ndefine('MY_API_KEY','%s');" % (GEHEIM, GEHEIM, GEHEIM)
    return _liste((GEHEIM not in util.mask_secrets(joomla), "Joomla-Geheimnis bleibt im Text"),
                  (GEHEIM not in util.mask_secrets(wp), "WordPress-Geheimnis bleibt im Text"),
                  ("***" in util.mask_secrets(wp), "keine Maskierung erkennbar"))


# ---------------------------------------------------------------- 8. Programm-Update (appupdate)
def _zip(version="9.9.0", extra=None, init=None):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("CLAUDIA/claudia/__init__.py", init if init is not None else '__version__ = "%s"\n' % version)
        z.writestr("CLAUDIA/claudia/__main__.py", "#\n")
        for k, v in (extra or {}).items():
            z.writestr(k, v)
    return buf.getvalue()


def _verifiziert(data, version, sha):
    try:
        appupdate.verify_package(data, version, sha)
        return True
    except appupdate.UpdateError:
        return False


def pruefe_update_paket():
    gut = _zip()
    sha = hashlib.sha256(gut).hexdigest()
    kaputt = bytearray(gut)
    kaputt[len(kaputt) // 2] ^= 1                         # ein Byte verändert
    return _liste(
        (_verifiziert(gut, "9.9.0", sha), "korrektes Paket wird abgelehnt"),
        (not _verifiziert(bytes(kaputt), "9.9.0", sha), "verändertes Paket (ein Byte) wird angenommen"),
        (not _verifiziert(gut, "9.9.0", ""), "Paket ohne veröffentlichte Prüfsumme wird angenommen"),
        (not _verifiziert(gut, "9.9.0", "0" * 64), "falsche Prüfsumme wird angenommen"),
        (not _verifiziert(gut, "9.8.0", sha), "falsche Version im Paket wird angenommen"),
        (not _verifiziert(b"kein zip", "9.9.0", hashlib.sha256(b"kein zip").hexdigest()), "Nicht-ZIP wird angenommen"),
        *[(not _verifiziert(z, "9.9.0", hashlib.sha256(z).hexdigest()), "Zip-Slip %r wird angenommen" % name)
          for name in ("../evil.py", "CLAUDIA/../../evil.py", "/etc/evil.py", "C:/evil.py", "CLAUDIA\\..\\evil.py")
          for z in [_zip(extra={name: "x"})]],
    )


def pruefe_update_release():
    gut = {"tag_name": "v9.9.0", "body": "SHA-256: " + "ab" * 32,
           "assets": [{"name": "CLAUDIA_v9.9.0.zip", "browser_download_url": appupdate.DOWNLOAD_PREFIX + "v9.9.0/CLAUDIA_v9.9.0.zip"}]}
    fremd = json.loads(json.dumps(gut))
    fremd["assets"][0]["browser_download_url"] = "https://evil.example/CLAUDIA_v9.9.0.zip"
    http_url = json.loads(json.dumps(gut))
    http_url["assets"][0]["browser_download_url"] = appupdate.DOWNLOAD_PREFIX.replace("https://", "http://") + "v9.9.0/CLAUDIA_v9.9.0.zip"
    probleme = []
    try:
        a = appupdate.parse_release(gut, "2.16.0")
    except Exception as e:                                # noqa: BLE001
        return ["gültige Release-Angaben werden abgelehnt: %s" % e]
    if not a.get("url") or a.get("sha256") != "ab" * 32:
        probleme.append("gültige Release-Angaben werden nicht übernommen")
    for text, rel in (("Download von fremdem Host", fremd), ("Download per http", http_url)):
        try:
            b = appupdate.parse_release(rel, "2.16.0")
        except ValueError:
            continue
        if b.get("url"):
            probleme.append("%s wird übernommen" % text)
    for tag in ("latest", "v1.2", "v1.2.3-evil", "../x", "v1.2.3;rm", ""):
        try:
            appupdate.parse_release(dict(gut, tag_name=tag), "2.16.0")
            probleme.append("ungültige Version %r wird übernommen" % tag)
        except ValueError:
            pass
    return probleme


# ---------------------------------------------------------------- 9. Zugang zum lokalen Server (Host, Origin, Sitzung, Kopf, Größe)
class Roh:
    """Eigene HTTP-Anfragen mit frei wählbaren Köpfen (urllib würde manches nicht zulassen)."""

    def __init__(self, port):
        self.port = port

    def req(self, methode, pfad, host=None, kopf=None, body=None, rohkopf=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        h = {"Host": host if host is not None else "127.0.0.1:%d" % self.port}
        h.update(kopf or {})
        try:
            c.putrequest(methode, pfad, skip_host=True, skip_accept_encoding=True)
            for k, v in h.items():
                c.putheader(k, v)
            if body is not None:
                c.putheader("Content-Length", str(rohkopf if rohkopf is not None else len(body)))
            c.endheaders(body if body is not None else None)
            r = c.getresponse()
            return r.status, r.read()
        except (OSError, http.client.HTTPException):
            return 0, b""
        finally:
            c.close()


def pruefe_zugang(srv, sid):
    p = srv.server_address[1]
    r = Roh(p)
    ok = {"Cookie": "claudia=" + sid, "X-Claudia": "1"}
    jb = b"{}"
    st = lambda *a, **k: r.req(*a, **k)[0]                # noqa: E731
    probleme = _liste(
        (st("GET", "/api/init", kopf=ok) == 200, "berechtigte Anfrage wird abgelehnt"),
        (st("POST", "/api/app-update-check", kopf=dict(ok, **{"Content-Type": "application/json"}), body=jb) in (200, 400, 500) and st("POST", "/api/app-update-check", kopf=dict(ok), body=jb) != 403, "berechtigte POST-Anfrage wird als nicht autorisiert abgelehnt"),
        (st("GET", "/api/init", host="evil.example", kopf=ok) == 403, "fremder Host-Kopf (DNS-Rebinding) wird angenommen"),
        (st("GET", "/api/init", host="127.0.0.1:1", kopf=ok) == 403, "falscher Port im Host-Kopf wird angenommen"),
        (st("GET", "/api/init", kopf=dict(ok, Origin="https://evil.example")) == 403, "fremder Origin wird angenommen"),
        (st("GET", "/api/init", kopf=dict(ok, Origin="http://127.0.0.1.evil.example:%d" % p)) == 403, "Lookalike-Origin wird angenommen"),
        (st("GET", "/api/init", kopf={"X-Claudia": "1"}) == 403, "Anfrage ohne Sitzung wird angenommen"),
        (st("GET", "/api/init", kopf={"Cookie": "claudia=falsch", "X-Claudia": "1"}) == 403, "falsche Sitzung wird angenommen"),
        (st("GET", "/api/init", kopf={"Cookie": "claudia=", "X-Claudia": "1"}) == 403, "leere Sitzung wird angenommen"),
        (st("GET", "/api/init", kopf={"Cookie": "claudia=" + sid}) == 403, "Anfrage ohne X-Claudia-Kopf wird angenommen"),
        (st("GET", "/api/init", kopf=dict(ok, **{"X-Claudia": "0"})) == 403, "falscher X-Claudia-Kopf wird angenommen"),
        (st("POST", "/api/app-update-check", kopf={"Cookie": "claudia=falsch", "X-Claudia": "1"}, body=jb) == 403, "POST mit falscher Sitzung wird angenommen"),
        (st("POST", "/api/app-update-install", kopf={"X-Claudia": "1"}, body=jb) == 403, "Installation ohne Sitzung wird angenommen"),
        (st("POST", "/api/app-update-check", kopf=ok, body=jb, rohkopf=2_000_000) == 413, "zu große Anfrage wird gelesen"),
        (st("POST", "/api/app-update-check", kopf=ok, body=jb, rohkopf=-5) in (400, 413), "negative Länge wird angenommen"),
        (st("POST", "/api/app-update-check", kopf=ok, body=b"{kaputt") == 400, "kaputtes JSON wird angenommen"),
        (st("POST", "/api/app-update-check", kopf=ok, body=b"[1,2]") == 400, "JSON-Liste statt Objekt wird angenommen"),
    )
    # Dateizugriff nur aus der Liste der Seitendateien
    for pf in ("/../../etc/passwd", "/%2e%2e/%2e%2e/etc/passwd", "/..%2f..%2fetc/passwd", "/app.js/../../../etc/passwd", "/claudia/server.py", "/%00", "//etc/passwd"):
        code, body = r.req("GET", pf, kopf=ok)
        if code == 200 and (b"root:" in body or b"class Handler" in body):
            probleme.append("Dateizugriff außerhalb der Liste: %s" % pf)
    # Einmal-Schlüssel
    k = srv.new_key()
    s1 = srv.redeem(k)
    s2 = srv.redeem(k)
    probleme += _liste((bool(s1), "Einmal-Schlüssel wird nicht angenommen"), (s2 == "", "Einmal-Schlüssel gilt mehrfach"),
                       (srv.redeem("") == "" and srv.redeem("x" * 5000) == "", "leerer/erfundener Schlüssel wird angenommen"),
                       (not srv.session_valid("") and not srv.session_valid("erfunden"), "erfundene Sitzung gilt"))
    return probleme


class Sicherheitsfunktionen(unittest.TestCase):
    # --- Normalzustand: alle Schutzfunktionen wirken
    @unittest.skipUnless(HAS_BASH, "bash nötig")
    def test_sq_wirkt(self):
        self.assertEqual(pruefe_sq(), [])

    def test_xml_wirkt(self):
        self.assertEqual(pruefe_xml(), [])

    def test_digits_wirkt(self):
        self.assertEqual(pruefe_digits(), [])

    def test_validate_vars_wirkt(self):
        self.assertEqual(pruefe_validate_vars(), [])

    def test_safe_path_wirkt(self):
        self.assertEqual(pruefe_safe_path(), [])

    def test_url_wirkt(self):
        self.assertEqual(pruefe_url(), [])

    def test_mask_secrets_wirkt(self):
        self.assertEqual(pruefe_mask(), [])

    def test_update_paket_wirkt(self):
        self.assertEqual(pruefe_update_paket(), [])

    def test_update_release_wirkt(self):
        self.assertEqual(pruefe_update_release(), [])

    # --- Wirksamkeitsbeweis: entschärft -> der Test MUSS Probleme melden
    @unittest.skipUnless(HAS_BASH, "bash nötig")
    def test_mutation_sq(self):
        with mock.patch.object(util, "sq", lambda v: str(v)):
            self.assertTrue(pruefe_sq(), "Test merkt nicht, dass das Quoting ausgeschaltet ist")
        with mock.patch.object(util, "sq", lambda v: "'" + str(v) + "'"):          # naives Quoting ohne Behandlung von '
            self.assertTrue(pruefe_sq(), "Test merkt naives Quoting nicht")

    def test_mutation_xml(self):
        with mock.patch.object(util, "parse_xml", _naiv_xml):
            self.assertTrue(pruefe_xml(), "Test merkt nicht, dass DOCTYPE/ENTITY/Größe nicht mehr geprüft werden")

    def test_mutation_digits(self):
        with mock.patch.object(util, "digits", lambda v: isinstance(v, str) and v.isdigit()):
            self.assertTrue(pruefe_digits())

    def test_mutation_validate_vars(self):
        alle = re.compile(r".*", re.S)
        for attr in ("_NAME_RE", "_PREFIX_RE", "_USER_RE", "_HOST_RE", "_SOCK_RE"):
            with mock.patch.object(db, attr, alle):
                self.assertTrue(pruefe_validate_vars(), "Test merkt Entschärfung von %s nicht" % attr)

    def test_mutation_validate_vars_dollar(self):
        """Der alte Fehler: '$' statt '\\Z' am Ende lässt einen angehängten Zeilenumbruch durch."""
        alt = re.compile(r"^[A-Za-z0-9_$][A-Za-z0-9_$.-]{0,63}$")
        with mock.patch.object(db, "_NAME_RE", alt):
            self.assertTrue(pruefe_validate_vars(), "Test merkt den Zeilenumbruch am Ende nicht")

    def test_mutation_safe_path(self):
        with mock.patch.object(actions, "_safe_path", lambda f: isinstance(f, str) and f.startswith("./")):
            self.assertTrue(pruefe_safe_path())

    def test_mutation_url(self):
        with mock.patch.object(secure, "is_secure_url", lambda u: True):
            self.assertTrue(pruefe_url())
        with mock.patch.object(secure, "is_loopback", lambda h: str(h).startswith("127.") or str(h).startswith("localhost")):
            self.assertTrue(pruefe_url(), "Test merkt Lookalike-Host nicht")

    def test_mutation_mask(self):
        with mock.patch.object(util, "mask_secrets", lambda t: t):
            self.assertTrue(pruefe_mask())

    def test_mutation_update_paket(self):
        with mock.patch.object(coreref, "sha256_hex", lambda d: hashlib.sha256(b"").hexdigest()):
            self.assertTrue(pruefe_update_paket(), "Test merkt nicht, dass die Prüfsumme nichts mehr prüft")
        with mock.patch.object(appupdate, "_clean_name", lambda n: n):
            self.assertTrue(pruefe_update_paket(), "Test merkt Zip-Slip-Schutz nicht")

    def test_mutation_update_release(self):
        with mock.patch.object(appupdate, "DOWNLOAD_PREFIX", ""):
            self.assertTrue(pruefe_update_release(), "Test merkt nicht, dass fremde Download-Hosts erlaubt sind")
        with mock.patch.object(appupdate, "VERSION_RE", re.compile(r".*")):
            self.assertTrue(pruefe_update_release(), "Test merkt Versionsprüfung nicht")


class ZugangZumServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base = tempfile.mkdtemp(prefix="claudia_zugang_")
        cls._env = mock.patch.dict(os.environ, {"CLAUDIA_NO_UPDATE_CHECK": "1", "CLAUDIA_NO_RESTART": "1"})
        cls._env.start()
        os.environ.pop("CLAUDIA_OFFLINE", None)
        cls.srv = server.make_server(directory=os.path.join(cls.base, "daten"))
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.sid = cls.srv.new_session()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls._env.stop()
        shutil.rmtree(cls.base, True)

    def test_zugang_wirkt(self):
        self.assertEqual(pruefe_zugang(self.srv, self.sid), [])

    def test_mutation_guard(self):
        """Host-/Origin-Prüfung ausgeschaltet -> der Test muss es merken."""
        with mock.patch.object(server.Handler, "_guard", lambda self: True):
            self.assertTrue(pruefe_zugang(self.srv, self.sid), "Test merkt nicht, dass die Host-/Origin-Prüfung fehlt")

    def test_mutation_sitzung(self):
        with mock.patch.object(server.Handler, "_api_ok", lambda self: True):
            self.assertTrue(pruefe_zugang(self.srv, self.sid), "Test merkt nicht, dass die Sitzungsprüfung fehlt")

    def test_mutation_kopf(self):
        with mock.patch.object(server.Handler, "_api_ok", lambda self: self._session_ok()):   # X-Claudia nicht mehr verlangt
            self.assertTrue(pruefe_zugang(self.srv, self.sid), "Test merkt nicht, dass der X-Claudia-Kopf nicht mehr verlangt wird")

    def test_mutation_einmalschluessel(self):
        with mock.patch.object(server.Server, "redeem", lambda self, key: "sitzung" if key else ""):
            self.assertTrue(pruefe_zugang(self.srv, self.sid), "Test merkt nicht, dass Einmal-Schlüssel mehrfach gelten")


if __name__ == "__main__":
    unittest.main()
