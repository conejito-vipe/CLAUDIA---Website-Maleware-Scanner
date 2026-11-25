"""Vergleichsseite, Kauf und Rabattcodes (claudia/angebot.py): ausgeliefert AUS; Rabattcodes sind offline signiert (RB1) und von Lizenzschlüsseln (CL1) streng getrennt.

Schlüsselpaare entstehen zur Laufzeit im Test (nie ein echter privater Schlüssel im Repo); PUBLIC_KEYS und die Schalter werden nur per Monkeypatch gesetzt."""
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
from claudia import angebot, lizenz, server  # noqa: E402

_spec = importlib.util.spec_from_file_location("claudia_lizenz_tool2", os.path.join(ROOT, "tools", "lizenz.py"))
tool = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(tool)

PW = "Test-Passwort-nur-fuer-den-Test"
PEM, PUB = tool.make_pair(PW)
PEM2, PUB2 = tool.make_pair(PW)
HEUTE = date(2026, 11, 25)
SPAETER = (HEUTE + timedelta(days=100)).isoformat()
PAYPAL = "https://www.paypal.com/pay?amount={betrag}&cur={waehrung}&item={plan}&code={code}&lic={lizenz}"


def keys():
    return mock.patch.dict(lizenz.PUBLIC_KEYS, {"k1": PUB}, clear=True)


def rabatt(prozent=20, bis=SPAETER, fuer="alle", nur=False, pem=None, kid="k1", cid="", heute=HEUTE):
    with mock.patch.dict(lizenz.PUBLIC_KEYS, {kid: PUB}):
        return tool.issue_discount(pem or PEM, PW, kid, prozent, bis, fuer, nur, cid, heute=heute)


def flip(text, pos):
    return text[:pos] + ("B" if text[pos] != "B" else "C") + text[pos + 1:]


def pruefe_codes():
    """Probleme als Liste (leer = die Prüfung wirkt). Wird auch für den Wirksamkeitsbeweis benutzt."""
    p = []
    c = rabatt()
    r = angebot.parse_code(c, "", False, HEUTE)
    if not (r["valid"] and r["prozent"] == 20):
        p.append("gültiger Code wird abgelehnt: %s" % r)
    if not angebot.parse_code("  " + c[:15] + "\n" + c[15:] + " ", "", False, HEUTE)["valid"]:
        p.append("Zeilenumbruch aus einer E-Mail stört")
    teile = c.split(".")
    for i in (0, 6, len(teile[1]) - 2):
        if angebot.parse_code(".".join([teile[0], flip(teile[1], i), teile[2]]), "", False, HEUTE)["valid"]:
            p.append("veränderte Angaben (Stelle %d) werden angenommen" % i)
    for i in (0, 12, len(teile[2]) - 3):
        if angebot.parse_code(".".join([teile[0], teile[1], flip(teile[2], i)]), "", False, HEUTE)["valid"]:
            p.append("veränderte Unterschrift (Stelle %d) wird angenommen" % i)
    # Angaben austauschen (100 % statt 20 %) mit alter Unterschrift
    body = json.loads(lizenz._b64d(teile[1]))
    body["prozent"] = 100
    neu = lizenz.b64e(json.dumps(body, separators=(",", ":")).encode())
    if angebot.parse_code(".".join([teile[0], neu, teile[2]]), "", False, HEUTE)["valid"]:
        p.append("ausgetauschte Prozentzahl wird angenommen")
    if angebot.parse_code(rabatt(pem=PEM2), "", False, HEUTE)["valid"]:
        p.append("Code mit fremdem Schlüssel wird angenommen")
    if angebot.parse_code(rabatt(bis="2026-11-24", heute=date(2026, 1, 1)), "", False, HEUTE)["valid"]:
        p.append("abgelaufener Code wird angenommen")
    if angebot.parse_code(rabatt(fuer="abc"), "xyz", True, HEUTE)["valid"]:
        p.append("Code für eine andere Lizenz wird angenommen")
    if angebot.parse_code(rabatt(nur=True), "", False, HEUTE)["valid"]:
        p.append("Code nur für Verlängerung gilt beim Neukauf")
    return p


class Rabattcode(unittest.TestCase):
    def test_codes_work_and_attacks_fail(self):
        with keys():
            self.assertEqual(pruefe_codes(), [])

    def test_valid_variants(self):
        with keys():
            self.assertTrue(angebot.parse_code(rabatt(fuer="abc"), "abc", False, HEUTE)["valid"])
            self.assertTrue(angebot.parse_code(rabatt(nur=True), "abc", True, HEUTE)["valid"])
            self.assertTrue(angebot.parse_code(rabatt(bis=HEUTE.isoformat()), "", False, HEUTE)["valid"])       # am letzten Tag noch gültig

    def test_garbage_never_raises(self):
        with keys():
            for g in (None, 5, [], {}, "", " ", "RB1", "RB1..", "RB1.a.b", "RB1.%%%.%%%", "CL1.a.b", "x" * 5000, "RB1." + "A" * 900 + "." + "A" * 90, "\x00", "RB1.e30.e30",
                      "RB1." + lizenz.b64e(b"[1]") + ".AAAA", "RB1." + lizenz.b64e(b"\xff\xfe") + ".AAAA", "RB1." + lizenz.b64e(b"[" * 3000) + ".AAAA"):
                r = angebot.parse_code(g, "", False, HEUTE)
                self.assertFalse(r["valid"], g)
                self.assertEqual(r["prozent"], 0)

    def test_license_key_is_not_a_discount_code_and_vice_versa(self):
        with keys():
            with mock.patch.dict(lizenz.PUBLIC_KEYS, {"k1": PUB}):
                lic = tool.issue(PEM, PW, "k1", "Firma", "gewerblich", SPAETER, "alle", 0, "", heute=HEUTE)
            self.assertFalse(angebot.parse_code(lic, "", False, HEUTE)["valid"])
            code = rabatt()
            self.assertFalse(lizenz.parse(code, HEUTE)["valid"])
            # gleiche Angaben, aber als Lizenz unterschrieben (ohne Zweck-Präfix) darf als Code nicht gelten
            teile = code.split(".")
            body = lizenz._b64d(teile[1])
            from cryptography.hazmat.primitives import serialization
            priv = serialization.load_pem_private_key(PEM, PW.encode())
            falsch = ".".join([angebot.PREFIX, teile[1], lizenz.b64e(priv.sign(body))])
            self.assertFalse(angebot.parse_code(falsch, "", False, HEUTE)["valid"])

    def test_percent_bounds(self):
        with keys():
            for pct in (0, 101, -5):
                with self.assertRaises(ValueError):
                    rabatt(prozent=pct)
            self.assertTrue(angebot.parse_code(rabatt(prozent=100), "", False, HEUTE)["valid"])

    def test_mutation_proof_signature_check_matters(self):
        """Wird die Unterschriftsprüfung entschärft, MUSS die Prüfung Fehler melden (sonst wäre sie wertlos)."""
        class Egal:
            def verify(self, *a, **k):
                return None
        with keys():
            self.assertEqual(pruefe_codes(), [])
            with mock.patch.object(lizenz, "_pubkey", lambda kid: Egal()):
                self.assertTrue(pruefe_codes())

    def test_mutation_proof_expiry_and_scope_matter(self):
        with keys():
            orig = angebot.parse_code

            def lax(code, lizenz_id="", renewal=False, today=None):
                return orig(code, lizenz_id, True, date(2000, 1, 1))     # Ablauf und 'nur Verlängerung' ausgeschaltet
            with mock.patch.object(angebot, "parse_code", lax):
                self.assertTrue(pruefe_codes())


class Preis(unittest.TestCase):
    def test_discount_rounding(self):
        self.assertEqual(angebot.preis_nach_rabatt(4900, 20), 3920)
        self.assertEqual(angebot.preis_nach_rabatt(999, 33), 669)
        self.assertEqual(angebot.preis_nach_rabatt(4900, 0), 4900)
        self.assertEqual(angebot.preis_nach_rabatt(4900, 100), 0)
        self.assertEqual(angebot.preis_nach_rabatt(4900, 250), 0)
        self.assertEqual(angebot.preis_nach_rabatt(4900, -5), 4900)


class KaufUrl(unittest.TestCase):
    def url(self, tpl, **kw):
        with mock.patch.object(angebot, "PAYPAL_URL", tpl):
            return angebot.kauf_url("pro", kw.pop("cent", 3920), **kw)

    def test_empty_by_default(self):
        self.assertEqual(angebot.PAYPAL_URL, "")
        self.assertEqual(angebot.kauf_url("pro", 4900), "")

    def test_template_filled_and_encoded(self):
        u = self.url(PAYPAL, code="RB1.a-b_c.d", lizenz_id="ab12")
        self.assertEqual(u, "https://www.paypal.com/pay?amount=39.20&cur=EUR&item=pro&code=RB1.a-b_c.d&lic=ab12")
        u = self.url(PAYPAL, code="x&evil=1#frag y", lizenz_id="")
        self.assertNotIn("&evil=1", u)
        self.assertNotIn(" ", u)

    def test_only_paypal_https(self):
        for bad in ("http://www.paypal.com/x", "https://evil.example/x", "https://paypal.com.evil.example/x", "https://www.paypal.com@evil.example/x", "https://evil.example/https://www.paypal.com/",
                    "javascript:alert(1)", "https://www.paypal.com/x y", "//www.paypal.com/x", "ftp://www.paypal.com/x", "https://www.paypal.comevil.example/x"):
            self.assertEqual(self.url(bad), "", bad)
        self.assertTrue(self.url("https://www.paypal.me/autor/{betrag}"))
        self.assertTrue(self.url("https://paypal.com/x"))

    def test_zero_amount_and_overlong(self):
        self.assertEqual(self.url(PAYPAL, cent=0), "")
        self.assertEqual(self.url(PAYPAL + "&x=" + "a" * 400), "")


class Zustand(unittest.TestCase):
    def setUp(self):
        self.base = tempfile.mkdtemp(prefix="claudia_offer_")
        self.addCleanup(shutil.rmtree, self.base, True)

    def test_inactive_shows_nothing(self):
        self.assertFalse(angebot.AKTIV)
        self.assertEqual(angebot.state(self.base), {"aktiv": False})
        self.assertEqual(angebot.state(self.base, "RB1.x.y"), {"aktiv": False})

    def test_active_without_price_has_no_buy(self):
        with mock.patch.object(angebot, "AKTIV", True):
            st = angebot.state(self.base, today=HEUTE)
        self.assertTrue(st["aktiv"])
        self.assertFalse(st["kauf_moeglich"])
        self.assertEqual(st["laufzeit_tage"], 365)
        self.assertTrue(st["ngo"] and st["bedingungen"] and st["features"])
        self.assertFalse(st["verlaengerung"])

    def test_active_with_price_and_discount(self):
        with keys(), mock.patch.multiple(angebot, AKTIV=True, PREIS_CENT={"pro": 4900}, PAYPAL_URL=PAYPAL):
            st = angebot.state(self.base, rabatt(20), HEUTE)
            self.assertEqual((st["preis_cent"], st["zu_zahlen_cent"], st["kauf_moeglich"]), (4900, 3920, True))
            st = angebot.state(self.base, "RB1.kaputt.kaputt", HEUTE)
            self.assertEqual(st["zu_zahlen_cent"], 4900)
            self.assertFalse(st["rabatt"]["valid"])

    def test_renewal_when_license_exists(self):
        with keys(), mock.patch.multiple(angebot, AKTIV=True, PREIS_CENT={"pro": 4900}, PAYPAL_URL=PAYPAL):
            with mock.patch.dict(lizenz.PUBLIC_KEYS, {"k1": PUB}):
                k = tool.issue(PEM, PW, "k1", "Firma", "gewerblich", SPAETER, "alle", 0, "lic1", heute=HEUTE)
            self.assertTrue(lizenz.store(self.base, k)["valid"])
            st = angebot.state(self.base, rabatt(30, nur=True, fuer="lic1"), HEUTE)
            self.assertTrue(st["verlaengerung"])
            self.assertEqual(st["lizenz_id"], "lic1")
            self.assertEqual(st["zu_zahlen_cent"], 3430)
            self.assertEqual(st["lizenz_bis"], SPAETER)

    def test_default_content_has_no_prices_and_paypal_empty(self):
        self.assertEqual(angebot.PREIS_CENT, {})
        self.assertEqual(angebot.PAYPAL_URL, "")


class Server(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base = tempfile.mkdtemp(prefix="claudia_offersrv_")
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

    def call(self, method, path, body=None, headers=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=15)
        try:
            h = {"Cookie": "claudia=" + self.sid, "X-Claudia": "1", "Content-Type": "application/json"}
            h.update(headers or {})
            c.request(method, path, body=json.dumps(body if body is not None else {}) if method == "POST" else None, headers=h)
            r = c.getresponse()
            raw = r.read()
            try:
                return r.status, json.loads(raw)
            except ValueError:
                return r.status, {}
        finally:
            c.close()

    def test_inactive_by_default(self):
        st, data = self.call("POST", "/api/offer", {"code": "x"})
        self.assertEqual((st, data), (200, {"aktiv": False}))
        with mock.patch("webbrowser.open") as op:
            st, data = self.call("POST", "/api/offer-buy", {"code": "x"})
            self.assertNotEqual(st, 200)
            op.assert_not_called()
        st, init = self.call("GET", "/api/init")
        self.assertFalse(init["offer"])

    def test_buy_opens_only_server_built_url(self):
        with keys(), mock.patch.multiple(angebot, AKTIV=True, PREIS_CENT={"pro": 4900}, PAYPAL_URL=PAYPAL), mock.patch("webbrowser.open") as op:
            c = rabatt(20)
            st, data = self.call("POST", "/api/offer-buy", {"code": c, "url": "https://evil.example/", "betrag": 1})
            self.assertEqual((st, data.get("ok")), (200, True))
            opened = op.call_args[0][0]
            self.assertTrue(opened.startswith("https://www.paypal.com/pay?amount=39.20"), opened)
            self.assertNotIn("evil", opened)
            st, init = self.call("GET", "/api/init")
            self.assertTrue(init["offer"])
            op.reset_mock()
            st, data = self.call("POST", "/api/offer-buy", {"code": "RB1.kaputt.kaputt"})        # ungültiger Code: voller Preis, kein Rabatt
            self.assertEqual(st, 200)
            self.assertIn("amount=49.00", op.call_args[0][0])

    def test_no_buy_without_template(self):
        with mock.patch.multiple(angebot, AKTIV=True, PREIS_CENT={"pro": 4900}), mock.patch("webbrowser.open") as op:
            st, data = self.call("POST", "/api/offer-buy", {})
            self.assertNotEqual(st, 200)
            op.assert_not_called()

    def test_foreign_origin_rejected(self):
        with mock.patch.object(angebot, "AKTIV", True):
            st, data = self.call("POST", "/api/offer", {}, {"Origin": "https://evil.example"})
        self.assertIn(st, (400, 403))


class NichtOeffentlich(unittest.TestCase):
    """Keine Lizenz-, Preis- oder Zahlungsangaben in dem, was auf GitHub und in die Release-Texte kommt."""
    WORTE = ("PayPal", "Rabatt", "RB1", "Lizenzschlüssel", "licence key", "license key")

    def test_release_files_have_no_offer_info(self):
        for rel in (".github/workflows/release.yml", "tools/release_body.py", "RELEASE_NOTES.md"):
            text = open(os.path.join(ROOT, rel), encoding="utf-8").read()
            for w in self.WORTE:
                self.assertNotIn(w.lower(), text.lower(), "%s enthält '%s'" % (rel, w))


if __name__ == "__main__":
    unittest.main()
