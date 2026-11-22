#!/usr/bin/env python3
"""Hilfsprogramm für die Sprachdateien (claudia/lang/*.json).

  python tools/i18n.py extract            Alle deutschen Sätze aus dem Quelltext sammeln (gibt JSON aus)
  python tools/i18n.py neu fr "Français"  Neue Sprache anlegen (alle Sätze mit leerer Übersetzung, zum Ausfüllen)
  python tools/i18n.py sync [code]        Neue Sätze aus dem Quelltext in vorhandene Sprachdateien eintragen (leer), nichts Vorhandenes ändern
  python tools/i18n.py merge en datei.json  Geprüfte Übersetzungsdatei ({deutsch: englisch}) in die Sprachdatei einarbeiten
  python tools/i18n.py check [code]       Abdeckung, fehlende Texte, Platzhalter-Fehler und ungenutzte Einträge anzeigen (Exit-Code 1 bei Fehlern)

Es steht nur der abweichende Text in einer Sprachdatei. Deutsch ist die Quellsprache."""
from __future__ import annotations

import ast
import json
import os
import re
import sys
from typing import Dict, List, Set

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from claudia import i18n  # noqa: E402

PKG = os.path.join(ROOT, "claudia")
STOP = set("""der die das den dem des ein eine einer einen einem eines und oder nicht ist sind wird werden wurde wurden kann können muss müssen für mit von zu auf im in bei aus nach vor über unter
als wenn dann nur auch noch bitte dass wie wo was welche welcher dieser diese dieses diesen jede jeder jedes kein keine keinen alle alles schon sehr mehr weniger gibt gab hat haben hatte war waren sein
ihre ihr ihrer deine dein deiner dich dir du wir uns sie es man bis durch gegen ohne um zum zur beim vom ab seit weil damit sondern aber denn sowie sowohl weder noch jetzt später vorher danach
hier dort dabei dafür davon daran darauf darin dazu dadurch deshalb daher also etwa ob falls sofern""".split())
# Eindeutig deutsche Wortstämme (ohne Umlaut/Füllwort im Satz), damit auch kurze Befundtexte erkannt werden
STEMS = re.compile(r"(?i)\b(?:datei|dateien|zeile|zeilen|erweiterung|adresse|aktualisier\w*|fehlen|fehler|ordner|sicherung|prüf\w*|leeren|leere|einspielen|benutzer|tabelle|ereignis\w*|schutz|einstellung\w*|treffer|protokoll\w*|gefunden|bekannte?|unbekannte?r?|speicherplatz|kern\w*|einbindung\w*|anmeldung|konto|konten|suche|durchsuch\w*|ausgewertet\w*|abruf|aktive?|geplante?|registrierte?|weiterleitung\w*|umleitung\w*|vorhanden|erreichbar|auswerten|vergleiche?|ermitteln|erkennen|auflisten|ausblenden\w*|ausgeblendet|verwundbar\w*|fremde?|verdächtig\w*|ausschalten|kontrolle|kontrollieren|installieren|angelegt|einzelheiten|hersteller|bewertung\w*|kostenlos\w*|kostenpflichtig\w*|zeichen|abgelehnt|erreicht|server meldet|unerwartet\w*|baustein|umgebung|starten|beenden|kopieren|laufend\w*|geladen|einstellungs|befunde?|beschreibung|sichern|hinweis)\b|[a-zäöü]{4,}(?:ung|ungen|keit|lich)\b")
UMLAUT = re.compile("[äöüÄÖÜß]")
WORD = re.compile(r"[A-Za-zÄÖÜäöüß]+")
CODEY = re.compile(r"^[a-z0-9_.\-/:#\[\]=<>(){}*+?|\\^$%&@!~,;'\" ]*$")


CODE_START = re.compile(r"^(?:SELECT|UPDATE|DELETE|INSERT|SHOW|ALTER|CREATE|DROP|find |grep |cd |echo |sudo |chmod |chown |rm |mv |cp |tar |unzip |php |python|curl |wget |cat |head |tail |sed |awk |sha256sum|\[ |if |for |while |export |ls )")


def looks_german(s: str, single_ok: bool = False) -> bool:
    if len(s.strip()) < 3 or "\x00" in s:
        return False
    if CODE_START.match(s.strip()) or "&&" in s or "$(" in s or s.strip().startswith(("<?", "#!", "http://", "https://")):
        return False
    if re.search(r"\$[A-Za-z_{]", s):                    # Shell-Variablen sind Code - außer der Satz ist erkennbar deutsch ("... oder $_POST.")
        ws = [w.lower() for w in WORD.findall(_PH_STRIP(s))]
        if sum(1 for w in ws if w in STOP) < 2 and not UMLAUT.search(s):
            return False
    if UMLAUT.search(s):
        return True
    if STEMS.search(s) and not re.search(r"[<>{}\\|$]|--|&&|^%s [a-z]|Mozilla|^(?:application|text)/", s):
        return True
    words = [w.lower() for w in WORD.findall(_PH_STRIP(s))]
    if any(w in STOP for w in words):
        return True
    if single_ok and len(words) >= 1 and re.match(r"^[A-ZÄÖÜ][a-zäöüß]{3,}[ A-Za-zäöüß\-]*[.:!?]?$", s.strip()):
        return True
    return False


def _PH_STRIP(s: str) -> str:
    return i18n._PH.sub(" ", s)


def sentences(s: str) -> List[str]:
    out = []
    parts = i18n.split_sentences(s)
    for i, p in enumerate(parts):
        if i % 2:
            continue
        p = p.strip()
        if p and re.search(r"[A-Za-zÄÖÜäöüß]{2,}", _PH_STRIP(p)):
            out.append(p)
    return out


def py_strings(path: str) -> Set[str]:
    src = open(path, encoding="utf-8").read()
    tree = ast.parse(src)
    doc = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.ClassDef)) and node.body and isinstance(node.body[0], ast.Expr) and isinstance(getattr(node.body[0], "value", None), ast.Constant):
            doc.add(id(node.body[0].value))
    found: Set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
            fn = node.func
            name = fn.id if isinstance(fn, ast.Name) else getattr(fn, "attr", "")
            if name in ("T", "tr", "_tr", "L"):          # ausdrücklich zum Übersetzen markierte Texte, auch einzelne Wörter
                found.update(sentences(node.args[0].value))
        s = None
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in doc:
            s = node.value
        elif isinstance(node, ast.JoinedStr):
            s = "".join(v.value if isinstance(v, ast.Constant) else "%s" for v in node.values)
        if s and looks_german(s):
            found.update(sentences(s))                      # ganzer Text deutsch -> alle seine Sätze (auch kurze Beschriftungen)
    return found


JS_STR = re.compile(r"""(?P<q>["'`])(?P<s>(?:\\.|(?!(?P=q)).)*?)(?P=q)""")


def js_strings(path: str) -> Set[str]:
    src = open(path, encoding="utf-8").read()
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.S)
    src = re.sub(r"(?m)^\s*//.*$", "", src)
    found: Set[str] = set()
    for m in JS_STR.finditer(src):
        s = m.group("s")
        if "=>" in s or ") {" in s or "});" in s or s.lstrip().startswith(("+", ",", "}", ")")):
            continue
        s = re.sub(r"\\(.)", lambda k: {"n": "\n", "t": "\t"}.get(k.group(1), k.group(1)), s)
        s = re.sub(r"\$\{[^}]*\}", "%s", s)
        if "<" in s and ">" in s:
            s = re.sub(r"<[^>]+>", " ", s)
        if looks_german(s, single_ok=True):
            found.update(sentences(s))
    for m in re.finditer(r"""\btr\(\s*(["'])((?:\\.|(?!\1).)+?)\1""", src):
        found.update(sentences(re.sub(r"\\(.)", lambda k: {"n": "\n", "t": "\t"}.get(k.group(1), k.group(1)), m.group(2))))
    return found


def json_strings(path: str) -> Set[str]:
    """Texte aus den Datendateien (Hinweise, Beschreibungen) - nur Werte, die deutsch aussehen."""
    found: Set[str] = set()

    def walk(o):
        if isinstance(o, str):
            if looks_german(o, single_ok=False) and len(o) > 12:
                found.update(sentences(o))
        elif isinstance(o, dict):
            for k, v in o.items():
                if k in ("allow_hosts", "ioc_strings", "known_bad_filenames", "spam_words"):
                    continue
                walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)
    walk(json.load(open(path, encoding="utf-8")))
    return found


def html_strings(path: str) -> Set[str]:
    src = open(path, encoding="utf-8").read()
    src = re.sub(r"<script.*?</script>|<style.*?</style>", "", src, flags=re.S)
    found: Set[str] = set()
    for m in re.finditer(r"(?:title|placeholder|aria-label|alt)=\"([^\"]+)\"", src):
        found.update(sentences(m.group(1)))
    text = re.sub(r"<[^>]+>", "\n", src)
    for ln in text.splitlines():
        ln = re.sub(r"\s+", " ", ln).strip()
        if ln and looks_german(ln, single_ok=True):
            found.update(sentences(ln))
    return found


def extract() -> List[str]:
    found: Set[str] = set()
    for dp, dn, fn in os.walk(PKG):
        dn[:] = [d for d in dn if d not in ("__pycache__", "lang")]
        for f in fn:
            p = os.path.join(dp, f)
            if p in (os.path.join(PKG, "i18n.py"), os.path.join(PKG, "web", "docs.js")):   # docs.js bringt seine Texte zweisprachig selbst mit
                continue
            if f.endswith(".py"):
                found |= py_strings(p)
            elif f.endswith(".js"):
                found |= js_strings(p)
            elif f.endswith(".html"):
                found |= html_strings(p)
            elif f in ("security_tools.json", "backup_tools.json", "advisories.json"):
                found |= json_strings(p)
    found |= set(extra_keys())
    return sorted(k for k in found if not _noise(k))


_KEEP_WORDS = {"unbekannt", "abgebrochen"}
_SAME = {"CLAUDIA/2.0 (Sicherheitspruefung; https://github.com/)", "detail detail-in", "FS_METHOD = %s:", "CLAUDIA", "Joomla", "WordPress", "Server", "System", "Test", "Tests", "Updates", "Version", "Original", "Port", "Details", "Min.",
         "Content-Type", "Sprache / Language"}


def _noise(k: str) -> bool:
    """Kein zu übersetzender Text: Bezeichner, reguläre Ausdrücke, englische Eigennamen."""
    if k in _SAME or k.startswith("put your unique"):
        return True
    if re.search(r"[\\]|\S\|\S|\(\?|^-e |SELECT |#__|\bCLAUDIA_", k) and not re.search(r"\s[a-zäöüß]{3,}\s", k):
        return True
    if not re.search(r"\s", k.strip()):
        if k in _KEEP_WORDS:
            return False
        if re.fullmatch(r"[a-z0-9_.\-/]+", k) or "_" in k or k.isupper() and len(k) < 12 and k != "ABGEBROCHEN":
            return True
    return False


def extra_keys() -> List[str]:
    """Von Hand gepflegte Sätze, die der Quelltext nur zusammengesetzt erzeugt (tools/i18n_extra.json)."""
    p = os.path.join(ROOT, "tools", "i18n_extra.json")
    try:
        return list(json.load(open(p, encoding="utf-8")))
    except (OSError, ValueError):
        return []


def write_lang(code: str, d: Dict) -> None:
    path = os.path.join(i18n.LANG_DIR, code + ".json")
    os.makedirs(i18n.LANG_DIR, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        meta = json.dumps(d["_meta"], ensure_ascii=False)
        fh.write('{\n"_meta": %s,\n"msg": {\n' % meta)
        items = list(d["msg"].items())
        for i, (k, v) in enumerate(items):
            fh.write("%s: %s%s\n" % (json.dumps(k, ensure_ascii=False), json.dumps(v, ensure_ascii=False), "," if i < len(items) - 1 else ""))
        fh.write("}\n}\n")


def cmd_neu(code: str, name: str) -> int:
    if os.path.exists(os.path.join(i18n.LANG_DIR, code + ".json")):
        print("Die Sprache %s gibt es schon." % code)
        return 1
    write_lang(code, {"_meta": {"code": code, "name": name, "flag": "", "html": code}, "msg": {k: "" for k in extract()}})
    print("claudia/lang/%s.json angelegt. Eintragen: Übersetzungen (rechte Seite) und eine Flagge als <svg> im Feld flag (siehe en.json)." % code)
    return 0


def cmd_sync(only: str = "") -> int:
    keys = extract()
    for code in i18n.lang_files():
        if code == i18n.SOURCE or (only and code != only):
            continue
        d = i18n.read_file(code)
        n = 0
        for k in keys:
            if k not in d["msg"]:
                d["msg"][k] = ""
                n += 1
        write_lang(code, d)
        print("%s: %d neue Sätze eingetragen" % (code, n))
    return 0


def check_lang(code: str, keys: List[str], verbose: bool = True) -> Dict[str, List[str]]:
    d = i18n.read_file(code)
    msg = d.get("msg") or {}
    missing = [k for k in keys if not msg.get(k)]
    bad = [k for k, v in msg.items() if v and i18n.placeholders(k) != i18n.placeholders(v) and not re.search(r"\{\d+\}", v)]
    bad += [k for k, v in msg.items() if v and re.search(r"\{(\d+)\}", v) and max(int(x) for x in re.findall(r"\{(\d+)\}", v)) > len(i18n.placeholders(k))]
    unused = [k for k in msg if k not in set(keys)]
    return {"missing": missing, "bad": bad, "unused": unused}


def cmd_check(only: str = "") -> int:
    keys = extract()
    rc = 0
    for code in i18n.lang_files():
        if code == i18n.SOURCE or (only and code != only):
            continue
        r = check_lang(code, keys)
        done = len(keys) - len(r["missing"])
        print("%s: %d von %d Sätzen übersetzt (%.1f %%), %d Platzhalter-Fehler, %d ungenutzte Einträge" % (code, done, len(keys), 100.0 * done / max(1, len(keys)), len(r["bad"]), len(r["unused"])))
        for k in r["bad"][:20]:
            print("  Platzhalter passen nicht:", k)
            rc = 1
    return rc


def cmd_validate(path: str, keys_path: str = "") -> int:
    """Prüft eine Übersetzungsdatei ({deutsch: englisch}): Platzhalter, leere Werte, fehlende Schlüssel (wenn keys_path = Liste der Schlüssel)."""
    d = json.load(open(path, encoding="utf-8"))
    bad = 0
    for k, v in d.items():
        if not v:
            print("LEER:", k[:100]); bad += 1
        elif i18n.placeholders(k) != i18n.placeholders(v) and not re.search(r"\{\d+\}", v):
            print("PLATZHALTER:", k[:100], "=>", v[:100]); bad += 1
    if keys_path:
        keys = json.load(open(keys_path, encoding="utf-8"))
        miss = [k for k in keys if k not in d]
        for k in miss[:30]:
            print("FEHLT:", k[:100])
        print("%d von %d Schlüsseln vorhanden" % (len(keys) - len(miss), len(keys)))
        bad += len(miss)
    print("OK" if not bad else "%d Probleme" % bad)
    return 1 if bad else 0


def cmd_merge(code: str, path: str) -> int:
    """Übersetzungsdatei ({deutsch: übersetzt}) nach Prüfung in claudia/lang/<code>.json einarbeiten (nur Sätze, die dort fehlen oder leer sind)."""
    if cmd_validate(path):
        print("Nichts eingearbeitet.")
        return 1
    lang_path = os.path.join(PKG, "lang", code + ".json")
    d = json.load(open(lang_path, encoding="utf-8"))
    new = json.load(open(path, encoding="utf-8"))
    n = 0
    for k, v in new.items():
        if not d["msg"].get(k):
            d["msg"][k] = v
            n += 1
    write_lang(code, d)
    print("%d Sätze eingearbeitet." % n)
    return 0


def main(argv: List[str]) -> int:
    if len(argv) < 2 or argv[1] in ("-h", "--help"):
        print(__doc__)
        return 0
    c = argv[1]
    if c == "extract":
        print(json.dumps(extract(), ensure_ascii=False, indent=0))
        return 0
    if c == "neu" and len(argv) >= 4:
        return cmd_neu(argv[2], argv[3])
    if c == "sync":
        return cmd_sync(argv[2] if len(argv) > 2 else "")
    if c == "validate" and len(argv) >= 3:
        return cmd_validate(argv[2], argv[3] if len(argv) > 3 else "")
    if c == "merge" and len(argv) >= 4:
        return cmd_merge(argv[2], argv[3])
    if c == "check":
        return cmd_check(argv[2] if len(argv) > 2 else "")
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
