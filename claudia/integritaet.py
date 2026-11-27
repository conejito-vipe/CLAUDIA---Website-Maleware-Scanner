"""Installation prüfen: Fehlen Dateien des Originalpakets oder sind sie verändert? (nur lesend)

Grundlage ist PRUEFSUMMEN.txt, die beim Bauen des Pakets entsteht (SHA-256 jeder Datei). Fehlt eine Datei oder
weicht ihr Inhalt ab, meldet CLAUDIA das. Die Liste selbst fehlt: dann lässt sich nichts prüfen, und das wird gesagt.
"""
from __future__ import annotations

import hashlib
import os
import sys
from typing import Any, Dict, List, Optional

LISTE = "PRUEFSUMMEN.txt"


def _kandidaten() -> List[str]:
    """Mögliche Programmordner: über dem Paket (Python-Fassung) und neben der Programmdatei (Einzeldatei-Fassung)."""
    paket = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    out = [paket]
    if getattr(sys, "frozen", False):
        out.append(os.path.dirname(sys.executable))
    return out


def programmordner() -> str:
    for d in _kandidaten():
        if os.path.isfile(os.path.join(d, LISTE)):
            return d
    return _kandidaten()[0]


def _sha256(pfad: str) -> str:
    h = hashlib.sha256()
    with open(pfad, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def pruefen(ordner: Optional[str] = None) -> Dict[str, Any]:
    """Ergebnis: ok (bool), liste_da (bool), gesamt, fehlend (Liste der Pfade), geaendert (Liste der Pfade)."""
    base = ordner or programmordner()
    liste = os.path.join(base, LISTE)
    if not os.path.isfile(liste):
        return {"ok": False, "liste_da": False, "gesamt": 0, "fehlend": [], "geaendert": [], "ordner": base}
    fehlend: List[str] = []
    geaendert: List[str] = []
    gesamt = 0
    with open(liste, "r", encoding="utf-8", errors="replace") as f:
        for zeile in f:
            zeile = zeile.rstrip("\r\n")
            if not zeile or zeile.startswith("#"):
                continue
            teile = zeile.split("  ", 1)
            if len(teile) != 2 or len(teile[0]) != 64:
                continue
            want, rel = teile[0].lower(), teile[1].strip()
            if ".." in rel.replace("\\", "/").split("/") or rel.startswith(("/", "\\")):
                continue                                  # keine Pfade außerhalb des Programmordners
            gesamt += 1
            pfad = os.path.join(base, *rel.replace("\\", "/").split("/"))
            if not os.path.isfile(pfad):
                fehlend.append(rel)
                continue
            try:
                if _sha256(pfad) != want:
                    geaendert.append(rel)
            except OSError:
                fehlend.append(rel)
    return {"ok": not fehlend and not geaendert, "liste_da": True, "gesamt": gesamt,
            "fehlend": fehlend[:200], "fehlend_anzahl": len(fehlend), "geaendert": geaendert[:200], "geaendert_anzahl": len(geaendert), "ordner": base}
