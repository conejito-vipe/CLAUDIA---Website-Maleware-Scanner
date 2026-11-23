"""Dokumentation im Programm und als eigene Datei: liest handbuch.<sprache>.txt und aenderungen.<sprache>.txt aus claudia/docs.

Format (reiner Text, leicht zu ergänzen):
  Handbuch:      '## kennung | Titel', danach Absätze und Listen ('- Punkt')
  Änderungen:    '## Version | Datum | Titel', darunter '### Funktion' mit den Zeilen 'Was:', 'Warum:', 'Wie:'
Fehlt eine Sprache, wird Deutsch gezeigt. Neue Sprache = neue Dateien mit gleichem Namensschema."""
from __future__ import annotations

import os
import re
from typing import Any, Dict, List

DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "docs")
SOURCE = "de"
_KEYS = {"was": "what", "warum": "why", "wie": "how", "what": "what", "why": "why", "how": "how",
         "qué": "what", "por qué": "why", "cómo": "how"}


def _read(kind: str, lang: str) -> str:
    for code in (lang, SOURCE):
        p = os.path.join(DIR, "%s.%s.txt" % (kind, code))
        if re.fullmatch(r"[a-z]{2,3}", code) and os.path.isfile(p):
            with open(p, encoding="utf-8") as fh:
                return fh.read()
    return ""


def _blocks(lines: List[str]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for ln in lines:
        ln = ln.rstrip()
        if not ln.strip():
            continue
        if ln.startswith("- "):
            if out and out[-1]["t"] == "ul":
                out[-1]["items"].append(ln[2:].strip())
            else:
                out.append({"t": "ul", "items": [ln[2:].strip()]})
        else:
            out.append({"t": "p", "text": ln.strip()})
    return out


def handbook(lang: str) -> List[Dict[str, Any]]:
    secs: List[Dict[str, Any]] = []
    for part in re.split(r"(?m)^## ", _read("handbuch", lang))[1:]:
        head, _, body = part.partition("\n")
        ident, _, title = head.partition("|")
        secs.append({"id": ident.strip(), "title": title.strip() or ident.strip(), "blocks": _blocks(body.split("\n"))})
    return secs


def changelog(lang: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for part in re.split(r"(?m)^## ", _read("aenderungen", lang))[1:]:
        head, _, body = part.partition("\n")
        bits = [x.strip() for x in head.split("|")]
        bits += [""] * (3 - len(bits))
        rel = {"version": bits[0], "date": bits[1], "title": bits[2], "items": []}
        for item in re.split(r"(?m)^### ", body)[1:]:
            ih, _, ib = item.partition("\n")
            it: Dict[str, Any] = {"title": ih.strip(), "what": "", "why": "", "how": ""}
            for ln in ib.split("\n"):
                m = re.match(r"^([^:\n]{2,12}):\s*(.*)\Z", ln.strip())
                if m and m.group(1).lower() in _KEYS:
                    it[_KEYS[m.group(1).lower()]] = m.group(2).strip()
            rel["items"].append(it)
        out.append(rel)
    return out


def available() -> List[str]:
    codes = set()
    try:
        for n in os.listdir(DIR):
            m = re.fullmatch(r"handbuch\.([a-z]{2,3})\.txt", n)
            if m:
                codes.add(m.group(1))
    except OSError:
        pass
    return sorted(codes)


def payload(lang: str, version: str = "", checks: List[Dict[str, Any]] | None = None, acts: List[Dict[str, Any]] | None = None) -> Dict[str, Any]:
    """Alles für die Anzeige: Handbuch, Änderungsverlauf, optional der Prüfkatalog und der Aktionskatalog (aus dem Programm selbst erzeugt)."""
    return {"lang": lang if lang in available() else SOURCE, "version": version, "handbook": handbook(lang),
            "changelog": changelog(lang), "checks": checks or [], "actions": acts or []}
