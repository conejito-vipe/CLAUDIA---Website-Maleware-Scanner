"""Sprachen: Satzzerlegung, Vorlagen, Sprachdatei, Bericht auf Englisch, Gleichlauf Python <-> JavaScript, Umschalten im Browser."""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, "tools"))

from claudia import i18n  # noqa: E402

GER_WORDS = set("der die das den dem des und oder nicht ist sind wird werden wurde kann können muss müssen für mit von zu auf bei nach über eine einen einem keine kein noch auch nur wenn dann aus bis haben gegen ohne zum zur beim vom bitte dass sich alle jede jeder hier dort dabei dafür damit weil aber sehr mehr gibt Zeile Datei Dateien Treffer Hinweis Kritisch Übersprungen Befunde Prüfung Prüfungen".split())


def looks_german(line: str) -> bool:
    ws = re.findall(r"[A-Za-zÄÖÜäöüß]+", line)
    return bool(re.search("[äöüÄÖÜß]", line)) or any(w in GER_WORDS for w in ws)


def _offen():
    """Bewusst noch nicht übersetzte Sätze (tests/uebersetzung_offen.json): sie zählen nicht als deutscher Rest."""
    import json
    try:
        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "uebersetzung_offen.json"), encoding="utf-8") as fh:
            return sorted(set(json.load(fh).get("fehlend") or []), key=len, reverse=True)
    except (OSError, ValueError):
        return []


def ohne_offene(text, offen):
    for s in offen:
        if s in text:
            text = text.replace(s, " ")
    return text


class Splitter(unittest.TestCase):
    def test_sentences(self):
        parts = i18n.split_sentences("Das ist gut. Das auch! Und z. B. das hier: Ja.")
        self.assertEqual([p for p in parts[::2]], ["Das ist gut.", "Das auch!", "Und z. B. das hier:", "Ja."])
        self.assertEqual("".join(parts), "Das ist gut. Das auch! Und z. B. das hier: Ja.")

    def test_newlines_kept(self):
        t = "Erste Zeile.\n\nZweite Zeile."
        self.assertEqual("".join(i18n.split_sentences(t)), t)

    def test_template_and_fill(self):
        c = i18n.Catalog({}, {"%d Datei(en) gefunden": "%d file(s) found", "%s von %s": "{2} of {1}", "Ja.": "Yes."})
        self.assertEqual(c.tr("3 Datei(en) gefunden"), "3 file(s) found")
        self.assertEqual(c.tr("a von b"), "b of a")
        self.assertEqual(c.tr("Ja. Unbekannt."), "Yes. Unbekannt.")           # Unübersetztes bleibt deutsch

    def test_label_and_arrow_and_period(self):
        c = i18n.Catalog({}, {"Beschriftung:": "Label:", "Erklärung": "Explanation", "Ende": "End", "A - B": "x"})
        self.assertEqual(c.tr("Beschriftung: Ende"), "Label: End")
        self.assertEqual(c.tr("Datei.php  ->  Erklärung"), "Datei.php  ->  Explanation")
        self.assertEqual(c.tr("Ende."), "End.")

    def test_number_after_colon_does_not_break_template(self):
        c = i18n.Catalog({}, {"Zeitraum: %s bis %s": "Period: %s to %s"})
        self.assertEqual(c.tr("Zeitraum: 2026-06-15 03:12 bis 2026-06-15 04:00"), "Period: 2026-06-15 03:12 to 2026-06-15 04:00")

    def test_obj_skips_technical_fields(self):
        c = i18n.Catalog({}, {"Ja.": "Yes."})
        o = c.obj({"title": "Ja.", "raw": {"x": "Ja."}, "cmd": "Ja.", "items": ["Ja."]})
        self.assertEqual(o, {"title": "Yes.", "raw": {"x": "Ja."}, "cmd": "Ja.", "items": ["Yes."]})


class LangFile(unittest.TestCase):
    def test_files_valid(self):
        langs = i18n.lang_files()
        self.assertIn("de", langs)
        self.assertIn("en", langs)
        for code in langs:
            d = i18n.read_file(code)
            m = d["_meta"]
            for k in ("code", "name", "flag", "html"):
                self.assertIn(k, m, code)
            self.assertTrue(m["flag"].startswith("<svg"), "Flagge als SVG, nicht als Emoji: " + code)
            self.assertNotIn("<script", m["flag"])

    def test_english_complete_and_placeholders(self):
        import i18n as tool
        keys = tool.extract()
        r = tool.check_lang("en", keys)
        self.assertEqual(r["bad"], [], "Platzhalter passen nicht")
        offen = set()                      # bewusst noch nicht übersetzte Texte (tests/uebersetzung_offen.json)
        p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uebersetzung_offen.json")
        if os.path.isfile(p):
            with open(p, encoding="utf-8") as fh:
                offen = set(json.load(fh).get("fehlend") or [])
        fehlt = [m for m in r["missing"] if m not in offen]
        self.assertLessEqual(len(fehlt), 5, fehlt[:10])
        self.assertEqual(r["unused"], [], "Einträge ohne Gegenstück im Quelltext")

    def test_client_payload_has_no_empty(self):
        p = i18n.client_payload("en")
        self.assertEqual(p["code"], "en")
        self.assertTrue(all(v for v in p["msg"].values()))
        self.assertGreater(len(p["msg"]), 2000)

    def test_german_is_identity(self):
        self.assertEqual(i18n.tr("Kritische Befunde gefunden", "de"), "Kritische Befunde gefunden")
        self.assertEqual(i18n.tr("Kritische Befunde gefunden", "en"), "Critical findings found")
        self.assertEqual(i18n.tr("Kritische Befunde gefunden", "xx"), "Kritische Befunde gefunden")


class EnglishReport(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import test_report
        from claudia import report
        cls.report = report
        cls.b, cls.w = test_report.make_bundle(True, True, "en")
        cls.files = report.all_files(cls.b)

    def test_language_in_meta_and_html(self):
        self.assertEqual(self.b["meta"]["sprache"], "en")
        self.assertIn("<html lang='en'>", self.files["bericht.html"])

    def test_static_texts_english(self):
        t = self.files["bericht.txt"]
        for s in ("Created:", "Recommendation:", "OVERALL RATING", "Critical:", "Duration"):
            self.assertIn(s, t)
        for s in ("Erstellt:", "Empfehlung:", "GESAMTBEWERTUNG", "Kritische Befunde"):
            self.assertNotIn(s, t)

    def test_few_german_leftovers_in_text_report(self):
        """Übrig bleiben darf nur, was aus den Daten der Seite stammt (Dateiinhalte, Namen, Pfade)."""
        bad = []
        offen = _offen()
        for line in self.files["bericht.txt"].split("\n"):
            core = line.strip()
            if not core or not looks_german(ohne_offene(core, offen)):
                continue
            if re.search(r"rohdaten/|Blockiert|Zähler|<script|<iframe|['\"]M_|die\(\)", core):        # Pfade, Dateiinhalte
                continue
            bad.append(core[:120])
        self.assertLessEqual(len(bad), 6, "\n".join(bad))

    def test_german_report_unchanged(self):
        import test_report
        b, _ = test_report.make_bundle(True, True, "de")
        self.assertIn("Erstellt:", self.report.render_txt(b))

    def test_no_secrets(self):
        import test_report
        for name, text in self.files.items():
            if isinstance(text, str):
                self.assertNotIn(test_report.PW, text, name)


@unittest.skipUnless(shutil.which("node"), "node nicht vorhanden")
class ParityPythonJs(unittest.TestCase):
    """Die Oberfläche übersetzt mit eigener JavaScript-Fassung; sie muss dasselbe Ergebnis liefern wie i18n.py."""

    SAMPLES = [
        "Kritische Befunde gefunden",
        "3 Datei(en) gefunden",
        "Zeitraum der Treffer: 2026-06-15 03:12 bis 2026-06-15 04:00.",
        "tmp: 1 Einträge, 12 KB, davon 1 PHP-Datei(en)",
        "Datei.php  ->  PHP-Ausführung für harmlose Endungen (.jpg) - Tarnung für Web-Shells",
        "Keine gespeicherten Prozeduren oder Funktionen vorhanden",
        "Zeitlimit: noch 45 s",
        "Empfehlung: Im Zweifel den Cache leeren.",
        "37 Tests ausgewählt",
        "Das gibt es nicht im Katalog.",
    ]

    def test_same_result(self):
        app = open(os.path.join(ROOT, "claudia", "web", "app.js"), encoding="utf-8").read()
        a = app.index("const L = {")
        b = app.index("/* Jeder Textknoten")
        code = app[a:b]
        payload = json.dumps(i18n.client_payload("en"), ensure_ascii=False)
        script = "const L_X=0;" + code + "\nsetCatalog(%s);\nconst S=%s;\nconsole.log(JSON.stringify(S.map(tr)));" % (payload, json.dumps(self.SAMPLES, ensure_ascii=False))
        fd, path = tempfile.mkstemp(suffix=".js")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(script)
        try:
            out = subprocess.run(["node", path], capture_output=True, text=True, timeout=60)
        finally:
            os.unlink(path)
        self.assertEqual(out.returncode, 0, out.stderr)
        js = json.loads(out.stdout)
        py = [i18n.tr(s, "en") for s in self.SAMPLES]
        self.assertEqual(js, py)
        self.assertEqual(py[0], "Critical findings found")
        self.assertNotEqual(py[2], self.SAMPLES[2])


class ServerLang(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import urllib.request
        from claudia.server import make_server
        cls.base = tempfile.mkdtemp(prefix="claudia_lang_")
        os.environ.pop("CLAUDIA_LANG", None)
        os.environ.pop("CLAUDIA_LANG_DEFAULT", None)  # setzt claudia.__main__ aus der PC-Sprache; darf aus anderen Tests nicht hereinwirken
        cls.srv = make_server(directory=cls.base)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.urllib = urllib.request

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    @property
    def sid(self):
        if not hasattr(self.__class__, "_sid"):
            self.__class__._sid = self.srv.new_session()
        return self._sid

    def call(self, path, data=None):
        url = self.srv.url.rstrip("/") + path
        req = self.urllib.Request(url, data=json.dumps(data).encode() if data is not None else None,
                                  headers={"Content-Type": "application/json", "X-Claudia": "1", "Cookie": "claudia=" + self.sid}, method="POST" if data is not None else "GET")
        with self.urllib.urlopen(req, timeout=30) as r:
            return json.loads(r.read().decode("utf-8"))

    def test_init_lists_languages_and_switch(self):
        init = self.call("/api/init")
        self.assertEqual(init.get("lang"), "de")
        codes = [l["code"] for l in init.get("langs", [])]
        self.assertIn("de", codes)
        self.assertIn("en", codes)
        cat = self.call("/api/lang")
        self.assertEqual(cat["code"], "de")
        r = self.call("/api/lang", {"lang": "en"})
        self.assertEqual(r.get("lang", r.get("code")), "en")
        self.assertEqual(self.call("/api/init")["lang"], "en")
        self.assertEqual(self.call("/api/lang")["code"], "en")
        self.assertIn("Kritische Befunde gefunden", self.call("/api/lang")["msg"])
        self.call("/api/lang", {"lang": "de"})
        self.assertEqual(self.call("/api/init")["lang"], "de")

    def test_unknown_language_rejected_or_ignored(self):
        try:
            self.call("/api/lang", {"lang": "../../etc/passwd"})
        except Exception:
            pass
        self.assertEqual(self.call("/api/init")["lang"], "de")

    def test_token_required(self):
        req = self.urllib.Request(self.srv.url.rstrip("/") + "/api/lang")
        with self.assertRaises(Exception):
            self.urllib.urlopen(req, timeout=10)


if __name__ == "__main__":
    unittest.main()
