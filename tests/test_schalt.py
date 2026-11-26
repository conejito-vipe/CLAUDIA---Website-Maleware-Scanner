import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import base64, json, os, sys, tempfile, unittest
from claudia import lizenz, schalt

def make(priv, kid="k1", aktiv=True, serial=1, gesperrt=(), purpose=schalt.PURPOSE, prefix="SW1"):
    body = json.dumps({"v": 1, "kid": kid, "aktiv": aktiv, "seit": "2026-11-26", "serial": serial, "gesperrt": list(gesperrt)}, separators=(",", ":")).encode()
    return "%s.%s.%s" % (prefix, lizenz.b64e(body), lizenz.b64e(priv.sign(purpose + body)))

class SchaltTests(unittest.TestCase):
    def setUp(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        self.priv = Ed25519PrivateKey.generate()
        lizenz.PUBLIC_KEYS = {"k1": base64.b64encode(self.priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()}
        self.base = tempfile.mkdtemp(); lizenz.SCHALT_AKTIV = False; lizenz.REVOKED_EXTRA = ()
    def tearDown(self): lizenz.PUBLIC_KEYS = {}; lizenz.SCHALT_AKTIV = False; lizenz.REVOKED_EXTRA = ()

    def test_annehmen_und_anwenden(self):
        self.assertEqual(schalt.accept(self.base, make(self.priv, gesperrt=["abc"])), "")
        self.assertTrue(lizenz.SCHALT_AKTIV); self.assertEqual(lizenz.REVOKED_EXTRA, ("abc",))
        schalt.apply(self.base); self.assertTrue(lizenz.SCHALT_AKTIV)

    def test_zurueckspielen_und_falsch(self):
        schalt.accept(self.base, make(self.priv, serial=5))
        self.assertNotEqual(schalt.accept(self.base, make(self.priv, aktiv=False, serial=4)), ""); self.assertTrue(lizenz.SCHALT_AKTIV)
        self.assertEqual(schalt.accept(self.base, make(self.priv, aktiv=False, serial=6)), ""); self.assertFalse(lizenz.SCHALT_AKTIV)
        for bad in (make(self.priv, purpose=b""), make(self.priv, kid="x"), make(self.priv, prefix="CL1"), "Müll", "", None, make(self.priv)[:-3] + "AAA"):
            self.assertIsNone(schalt.parse(bad))

    def test_kein_lizenzschluessel(self):
        self.assertFalse(lizenz.parse(make(self.priv))["valid"])

    def test_refresh(self):
        import io
        ok = lambda req, timeout: io.BytesIO(make(self.priv, serial=2).encode())
        self.assertTrue(schalt.refresh(self.base, "https://x.example/s.txt", ok)["ok"])
        self.assertFalse(schalt.refresh(self.base, "http://x.example/s.txt", ok)["ok"]); self.assertFalse(schalt.refresh(self.base, "")["ok"])
        def boom(req, timeout): raise OSError()
        self.assertFalse(schalt.refresh(self.base, "https://x.example/s.txt", boom)["ok"]); self.assertEqual(schalt.load(self.base)["serial"], 2)

    def test_server_nimmt_schaltdatei_ueber_lizenzfeld(self):
        from claudia.server import App
        app = App(self.base)
        self.assertFalse(lizenz.SCHALT_AKTIV)
        txt = make(self.priv, gesperrt=["xyz"])
        why = schalt.accept(app.dir, txt)
        self.assertEqual(why, "")
        st = lizenz.state(app.dir)
        self.assertEqual(set(st["gesperrt_ohne_lizenz"]), set(lizenz.BEREICHE))
        App(self.base)                                          # neuer Start liest die gespeicherte Datei
        self.assertTrue(lizenz.SCHALT_AKTIV)
        self.assertIn("xyz", lizenz.REVOKED_EXTRA)


if __name__ == "__main__":
    unittest.main()
