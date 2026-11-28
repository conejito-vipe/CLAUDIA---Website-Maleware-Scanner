"""Sprachen (Deutsch ist die Quellsprache, weitere Sprachen liegen als Textdateien in claudia/lang/).

Aufbau einer Sprachdatei (claudia/lang/<code>.json):
    {"_meta": {"code": "en", "name": "English", "flag": "<svg ...>"}, "msg": {"deutscher Satz": "englischer Satz", ...}}

Es steht nur der abweichende Text darin. Schlüssel ist immer ein deutscher SATZ (lange Texte werden satzweise übersetzt, damit zusammengesetzte
Meldungen funktionieren). Platzhalter (%s, %d, %.1f, {}, {name}) stehen im Schlüssel und in der Übersetzung; sie passen auf beliebigen Text.
In der Übersetzung kann die Reihenfolge mit {1}, {2}, ... geändert werden.
Ohne Eintrag bleibt der deutsche Text stehen (nie ein Fehler, nie ein leerer Text).
Eine neue Sprache anlegen: `python tools/i18n.py neu fr "Français"` - erzeugt claudia/lang/fr.json zum Ausfüllen.
"""
from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List, Optional, Tuple

SOURCE = "de"
LANG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "lang")

# Abkürzungen, nach denen kein neuer Satz beginnt
_ABBR = ("z. B.", "d. h.", "u. a.", "u. U.", "z. T.", "i. d. R.", "s. o.", "s. u.", "o. ä.", "v. a.", "ca.", "bzw.", "evtl.", "ggf.", "Nr.", "usw.", "etc.", "inkl.", "vgl.", "max.", "min.", "ggü.", "Dr.", "Abs.", "Std.", "Sek.")
_BOUNDARY = re.compile(r"(?<=[.!?:])(\s+)(?=[A-ZÄÖÜ0-9%{„\"'(\[])")
_PH = re.compile(r"%(?:\d+\$)?[-+ 0#]*\d*(?:\.\d+)?[sdifx]|\{\d*\}|\{[a-z_]+\}")
_ARROW = re.compile(r"(\s+(?:->|<-|\|)\s+)")
_DASH = re.compile(r"(\s+-\s+)")
_LABEL = re.compile(r"^([^:\n]{2,60}:)(\s+)(\S.*)$", re.S)
_NUM = re.compile(r"\{(\d+)\}")


def _after_abbr(before: str) -> bool:
    for a in _ABBR:
        if before.endswith(a) and (len(before) == len(a) or not before[-len(a) - 1].isalnum()):
            return True
    toks = before.split()
    return bool(toks) and re.fullmatch(r"[A-Za-zÄÖÜäöü]\.", toks[-1].lstrip("(\"'[")) is not None


def split_sentences(text: str) -> List[str]:
    """Zerlegt einen Text in [Satz, Trenner, Satz, Trenner, ..., Satz] (gerade Positionen = Text).
    Geteilt wird an Zeilenumbrüchen und nach . ! ? : vor einem Großbuchstaben (nicht nach Abkürzungen)."""
    out: List[str] = []
    for i, line in enumerate(re.split(r"(\n+)", text)):
        if i % 2:
            out.append(line)
            continue
        pos = 0
        for m in _BOUNDARY.finditer(line):
            if _after_abbr(line[pos:m.start()]):
                continue
            out.append(line[pos:m.start()])
            out.append(m.group(1))
            pos = m.end()
        out.append(line[pos:])
    return out


def _is_sep(s: str) -> bool:
    return bool(s) and not s.strip()


def _template(key: str) -> Optional[Tuple[re.Pattern, int]]:
    """Schlüssel mit Platzhaltern -> (Regex, Anzahl Platzhalter). Ohne Platzhalter: None."""
    pos, parts, n = 0, [], 0
    for m in _PH.finditer(key):
        parts.append(re.escape(key[pos:m.start()]))
        parts.append(r"([-+]?\d[\d.,]*)" if m.group(0)[-1] in "dif" and m.group(0).startswith("%") else "(.*?)")
        pos = m.end()
        n += 1
    if not n:
        return None
    parts.append(re.escape(key[pos:]))
    return re.compile("^" + "".join(parts) + "$", re.S), n


def _fill(trans: str, groups: Tuple[str, ...]) -> str:
    """Setzt die erfassten Texte in die Übersetzung ein (der Reihe nach, oder mit {1}, {2} ... in beliebiger Reihenfolge)."""
    if _NUM.search(trans):
        return _NUM.sub(lambda m: groups[int(m.group(1)) - 1] if 0 < int(m.group(1)) <= len(groups) else m.group(0), trans)
    it = iter(groups)
    return _PH.sub(lambda m: next(it, m.group(0)), trans)


class Catalog:
    def __init__(self, meta: Dict[str, Any], msg: Dict[str, str]):
        self.meta = meta
        self.exact: Dict[str, str] = {}
        self.templates: List[Tuple[re.Pattern, int, str, int]] = []
        for k, v in msg.items():
            if not v or k == v:
                continue
            t = _template(k)
            if t:
                lit = len(_PH.sub("", k))
                self.templates.append((t[0], t[1], v, lit))
                if not _NUM.search(v):
                    self.exact[k] = v                  # der Schlüssel selbst (Formatvorlage vor dem Einsetzen der Werte)
            else:
                self.exact[k] = v
        self.templates.sort(key=lambda x: -x[3])           # genauere (längere) Muster zuerst
        self._cache: Dict[str, str] = {}

    def _match(self, s: str) -> Optional[str]:
        if s in self.exact:
            return self.exact[s]
        for rx, n, v, _ in self.templates:
            m = rx.match(s)
            if m:
                return _fill(v, [self._group(g) for g in m.groups()])
        return None

    def _group(self, g: str, depth: int = 0) -> str:
        """Eingesetzte Textteile (z. B. 'gespeicherten Prozeduren') werden mitübersetzt, Zahlen und Namen bleiben.
        Auch eingesetzte Teile, die selbst einer Vorlage folgen ('tmp: 4 Datei(en), 12 KB'), mehrere davon mit '; ' getrennt."""
        if not g or len(g) > 200:
            return g
        if g in self.exact:
            return self.exact[g]
        if depth >= 2:
            return g
        parts = g.split("; ")
        out = []
        for part in parts:
            r = None
            for rx, n, v, _ in self.templates:
                m = rx.match(part)
                if m:
                    r = _fill(v, [self._group(x, depth + 1) for x in m.groups()])
                    break
            if r is None and ": " in part:                  # "tmp: 4 Datei(en), 12 KB": Name bleibt, der Wert wird übersetzt
                head, rest = part.split(": ", 1)
                r2 = self._group(rest, depth + 1)
                r = head + ": " + r2 if r2 != rest else None
            out.append(r if r is not None else part)
        return "; ".join(out)

    def _one(self, s: str) -> str:
        r = self._match(s)
        if r is not None:
            return r
        if _ARROW.search(s):                      # "Fundstelle  ->  Erklärung": beide Seiten einzeln
            return "".join(p if i % 2 else self._lead(p, self._one) for i, p in enumerate(_ARROW.split(s)))
        if _DASH.search(s):                       # "Name - Beschreibung"
            parts = _DASH.split(s)
            out = "".join(p if i % 2 else self._lead(p, self._one) for i, p in enumerate(parts))
            if out != s:
                return out
        m = _LABEL.match(s)                       # "Beschriftung: Wert" - nur die Beschriftung ist ein Schlüssel
        if m:
            lab = self._match(m.group(1))
            if lab is None and self._match(m.group(1)[:-1]) is not None:
                lab = self._match(m.group(1)[:-1]) + ":"
            if lab is not None:
                return lab + m.group(2) + self._one(m.group(3))
            val = self._match(m.group(3))                 # Beschriftung ist ein Name (z. B. Ordner "tmp"), der Wert eine bekannte Vorlage
            if val is not None:
                return m.group(1) + m.group(2) + val
        for end in (".", ":"):                    # Satzzeichen am Ende gehört nicht zum Schlüssel
            if s.endswith(end) and len(s) > 2:
                r = self._match(s[:-1])
                if r is not None:
                    return r + end
        return s

    def _sentences(self, parts: List[str]) -> str:
        """Satz für Satz; passt ein Satz allein nicht, werden bis zu 3 Nachbarsätze zusammen versucht
        (z. B. 'Zeitraum: 2026-06-15 03:12 bis ...' wird durch die Zahl nach dem Doppelpunkt zerteilt, der Schlüssel aber nicht)."""
        out: List[str] = []
        i, n = 0, len(parts)
        while i < n:
            used = 1
            res = None
            if parts[i].strip() and self._match(parts[i].strip()) is None:
                for span in (3, 2):
                    j = i + 2 * (span - 1)
                    if j < n:
                        joined = "".join(parts[i:j + 1])
                        r = self._match(joined.strip())
                        if r is not None:
                            res, used = self._lead(joined, lambda _x, r=r: r), 2 * span - 1
                            break
            out.append(res if res is not None else self._lead(parts[i], self._one))
            i += used
            if i < n:                              # Trenner hinter dem Satz
                out.append(parts[i])
                i += 1
        return "".join(out)

    def tr(self, text: str) -> str:
        if not text or not isinstance(text, str):
            return text
        c = self._cache.get(text)
        if c is not None:
            return c
        res = self.exact.get(text)
        if res is None:
            res = self._sentences(split_sentences(text))
        if len(self._cache) > 20000:
            self._cache.clear()
        self._cache[text] = res
        return res

    @staticmethod
    def _lead(piece: str, fn) -> str:
        """Übersetzt einen Satz, die umgebenden Leerzeichen bleiben erhalten."""
        core = piece.strip()
        if not core:
            return piece
        i = piece.index(core)
        return piece[:i] + fn(core) + piece[i + len(core):]

    def obj(self, o: Any, skip: Tuple[str, ...] = ("raw", "cmd", "commands", "path", "paths", "code")) -> Any:
        """Übersetzt alle Texte in einer JSON-artigen Struktur (Schlüssel bleiben, technische Felder bleiben unberührt)."""
        if isinstance(o, str):
            return self.tr(o)
        if isinstance(o, list):
            return [self.obj(x, skip) for x in o]
        if isinstance(o, dict):
            return {k: (v if k in skip else self.obj(v, skip)) for k, v in o.items()}
        return o


_CATS: Dict[str, Catalog] = {}


def lang_files() -> Dict[str, str]:
    out: Dict[str, str] = {}
    try:
        for n in sorted(os.listdir(LANG_DIR)):
            if n.endswith(".json"):
                out[n[:-5]] = os.path.join(LANG_DIR, n)
    except OSError:
        pass
    return out


def read_file(code: str) -> Dict[str, Any]:
    path = lang_files().get(code)
    if not path:
        return {"_meta": {"code": code, "name": code}, "msg": {}}
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def catalog(code: str) -> Optional[Catalog]:
    """Katalog einer Sprache (None für die Quellsprache Deutsch oder unbekannte Codes)."""
    if not code or code == SOURCE or code not in lang_files():
        return None
    if code not in _CATS:
        d = read_file(code)
        _CATS[code] = Catalog(d.get("_meta") or {}, d.get("msg") or {})
    return _CATS[code]


def reload() -> None:
    _CATS.clear()


def languages() -> List[Dict[str, str]]:
    """Alle verfügbaren Sprachen für den Umschalter im Seitenkopf: [{code, name, flag}], Deutsch zuerst."""
    out = []
    for code in lang_files():
        m = read_file(code).get("_meta") or {}
        out.append({"code": code, "name": str(m.get("name") or code), "flag": str(m.get("flag") or ""), "html": str(m.get("html") or code)})
    out.sort(key=lambda x: (x["code"] != SOURCE, x["code"]))
    return out


def valid(code: str) -> bool:
    return code in lang_files()


def tr(text: str, code: str) -> str:
    c = catalog(code)
    return c.tr(text) if c else text


def tr_obj(o: Any, code: str) -> Any:
    c = catalog(code)
    return c.obj(o) if c else o


def client_payload(code: str) -> Dict[str, Any]:
    """Für die Oberfläche: Katalog der Sprache (Schlüssel = deutscher Satz)."""
    d = read_file(code)
    return {"code": code, "meta": d.get("_meta") or {}, "msg": {k: v for k, v in (d.get("msg") or {}).items() if v and k != v}}


def placeholders(s: str) -> List[str]:
    return sorted(_PH.findall(s or ""))
