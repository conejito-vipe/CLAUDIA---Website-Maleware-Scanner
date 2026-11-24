"""Wissensdaten (claudia/advisories.json) getrennt vom Programm aktualisieren, aber nur mit gültiger digitaler Unterschrift.

Fundmuster, Schwachstellenlisten und Versionsstände veralten schneller als das Programm. Der Autor kann eine neue Fassung veröffentlichen
(wissen/advisories.json mit Unterschrift wissen/advisories.json.sig im Repository). CLAUDIA übernimmt sie nur, wenn
- die Unterschriftsprüfung aktiv ist (öffentlicher Schlüssel in claudia/signatur.py) und die Unterschrift stimmt,
- die Datei gültiges JSON mit allen Abschnitten der mitgelieferten Fassung ist (es kann nichts wegfallen) und
- ihr Stand neuer ist als der der mitgelieferten Fassung.
Ist die Prüfung nicht aktiv, wird nichts geladen und eine abgelegte Datei nie benutzt. Beim Lesen wird die Unterschrift jedes Mal erneut geprüft."""
import json
import os
import re
from typing import Any, Callable, Dict, Optional

from . import coreref, signatur
from .util import atomic_write

REPO = "conejito-vipe/CLAUDIA---Website-Maleware-Scanner"
BASE_URL = "https://raw.githubusercontent.com/%s/main/wissen/" % REPO
NAME = "advisories.json"
MAX_BYTES = 3_000_000
STAND_RE = re.compile(r"^\d{4}-\d{2}-\d{2}\Z")
HERE = os.path.dirname(os.path.abspath(__file__))


def folder(base: str) -> str:
    return os.path.join(base, "wissen")


def bundled() -> Dict[str, Any]:
    with open(os.path.join(HERE, NAME), "r", encoding="utf-8") as fh:
        return json.load(fh)


def check(raw: bytes, ref: Dict[str, Any]) -> Dict[str, Any]:
    """Prüft Inhalt gegen die mitgelieferte Fassung. Wirft ValueError, wenn die Datei nicht brauchbar ist."""
    if len(raw) > MAX_BYTES:
        raise ValueError("zu groß")
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise ValueError("kein gültiges JSON")
    if not isinstance(data, dict):
        raise ValueError("kein Wörterbuch")
    stand = data.get("stand")
    if not isinstance(stand, str) or not STAND_RE.match(stand):
        raise ValueError("Stand fehlt")
    missing = [k for k in ref if k not in data]
    if missing:
        raise ValueError("Abschnitte fehlen: %s" % ", ".join(missing[:5]))
    if str(ref.get("stand") or "") >= stand:
        raise ValueError("nicht neuer als die mitgelieferte Fassung")
    return data


def load(base: str) -> Dict[str, Any]:
    """Die zu benutzenden Wissensdaten: die geprüfte, neuere Fassung aus dem Datenordner, sonst die mitgelieferte. Wirft nie (außer bei fehlender mitgelieferter Datei)."""
    ref = bundled()
    if not signatur.aktiv():
        return ref
    try:
        with open(os.path.join(folder(base), NAME), "rb") as fh:
            raw = fh.read(MAX_BYTES + 1)
        with open(os.path.join(folder(base), NAME + ".sig"), "rb") as fh:
            sig = fh.read(1024)
        if not signatur.verify("wissen", raw, sig):
            return ref
        return check(raw, ref)
    except (OSError, ValueError):
        return ref


def update(base: str, fetch: Optional[Callable[..., bytes]] = None) -> Dict[str, Any]:
    """Sucht eine neuere, unterschriebene Fassung und legt sie ab. Wirft nie. {'ok': bool, 'aktiv': bool, 'stand'?, 'error'?, 'neu'?: bool}"""
    if not signatur.aktiv():
        return {"ok": False, "aktiv": False}                      # nichts laden, nichts melden
    if os.environ.get("CLAUDIA_OFFLINE"):
        return {"ok": False, "aktiv": True, "error": "Offline-Modus"}
    f = fetch or coreref.fetch_bytes
    try:
        raw = f(BASE_URL + NAME, MAX_BYTES, 30)
        sig = f(BASE_URL + NAME + ".sig", 1024, 30)
    except coreref.RefError as e:
        return {"ok": False, "aktiv": True, "error": str(e)[:200]}
    if not signatur.verify("wissen", raw, sig):
        return {"ok": False, "aktiv": True, "error": "Die digitale Unterschrift der Wissensdaten stimmt nicht; sie werden nicht übernommen."}
    try:
        current = load(base)
        data = check(raw, bundled())
        if str(current.get("stand") or "") >= data["stand"]:
            return {"ok": True, "aktiv": True, "neu": False, "stand": str(current.get("stand") or "")}
        os.makedirs(folder(base), exist_ok=True)
        atomic_write(os.path.join(folder(base), NAME + ".sig"), bytes(sig).decode("ascii", "replace").strip())
        atomic_write(os.path.join(folder(base), NAME), raw.decode("utf-8"))
    except (ValueError, OSError) as e:
        return {"ok": False, "aktiv": True, "error": str(e)[:200]}
    return {"ok": True, "aktiv": True, "neu": True, "stand": data["stand"]}
