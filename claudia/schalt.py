"""Schaltdatei (SW1): schaltet die Lizenzpflicht ein/aus und liefert die Sperrliste, ohne neues Programm-Release.

Format:  SW1.<Angaben base64url>.<Unterschrift base64url>, signiert mit demselben privaten Schlüssel wie die Lizenzschlüssel, aber mit eigenem Zweck
(b"CONEJITO-SCHALT1\\n" + Angaben): Eine Schaltdatei ist nie ein Lizenzschlüssel und umgekehrt.
Angaben: {"v":1,"kid":..,"aktiv":bool,"seit":"JJJJ-MM-TT","serial":N,"gesperrt":[Lizenz-IDs]}
Die laufende Nummer darf nie sinken (Schutz gegen Zurückspielen alter Dateien). Ohne Netz, ohne Datei oder bei Fehlern gilt der zuletzt geprüfte Stand weiter;
eine ungültige Datei wird verworfen und ändert nichts. Der Abruf ist ein reines GET ohne Nutzerdaten, nur HTTPS, ohne Weiterleitung, mit Größengrenze."""
import json
import os
import re
import urllib.request
from datetime import date
from typing import Any, Dict, Optional

from . import lizenz
from .util import atomic_write

PREFIX = "SW1"
PURPOSE = b"CONEJITO-SCHALT1\n"
FILE = "schaltdatei.txt"
MAX_LEN = 60000
MAX_IDS = 5000
# Adresse der Schaltdatei, z. B. "https://claudia.beispiel.de/lizenz/schaltdatei.txt". Leer = kein Abruf (nur manuell/Datei).
SCHALT_URL = ""
_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,40}\Z")


def parse(text: Any, min_serial: int = 0) -> Optional[Dict[str, Any]]:
    """Prüft eine Schaltdatei. Gibt die Angaben zurück oder None (nie eine Ausnahme)."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    import base64
    if not isinstance(text, str):
        return None
    text = "".join(text.split())
    if not text or len(text) > MAX_LEN:
        return None
    try:
        parts = text.split(".")
        if len(parts) != 3 or parts[0] != PREFIX:
            return None
        body, sig = lizenz._b64d(parts[1]), lizenz._b64d(parts[2])
        data = json.loads(body.decode("utf-8"))
        kid = data.get("kid") if isinstance(data, dict) else None
        if not isinstance(kid, str) or kid not in lizenz.PUBLIC_KEYS:
            return None
        Ed25519PublicKey.from_public_bytes(base64.b64decode(lizenz.PUBLIC_KEYS[kid])).verify(sig, PURPOSE + body)
        g, serial = data.get("gesperrt"), data.get("serial")
        if (data.get("v") != 1 or not isinstance(data.get("aktiv"), bool) or isinstance(serial, bool) or not isinstance(serial, int) or serial < max(1, min_serial)
                or not isinstance(data.get("seit"), str) or not lizenz._DATE_RE.match(data["seit"]) or not isinstance(g, list) or len(g) > MAX_IDS
                or not all(isinstance(x, str) and _ID_RE.match(x) for x in g)):
            return None
        date.fromisoformat(data["seit"])
        return {"aktiv": data["aktiv"], "serial": serial, "seit": data["seit"], "gesperrt": tuple(g), "kid": kid}
    except Exception:  # noqa: BLE001  jede Abweichung heißt: ungültig
        return None


def _path(base: str) -> str:
    return os.path.join(base, FILE)


def load(base: str) -> Optional[Dict[str, Any]]:
    try:
        with open(_path(base), encoding="utf-8") as fh:
            return parse(fh.read(MAX_LEN + 10))
    except OSError:
        return None


def apply(base: str) -> Optional[Dict[str, Any]]:
    """Übernimmt den gespeicherten Stand in das Lizenzmodul (beim Start und nach jedem Abruf aufrufen)."""
    d = load(base)
    lizenz.SCHALT_AKTIV = bool(d and d["aktiv"])
    lizenz.REVOKED_EXTRA = tuple(d["gesperrt"]) if d else ()
    return d


def accept(base: str, text: Any) -> str:
    """Nimmt eine Schaltdatei an (Datei oder Abruf). Gibt '' bei Erfolg zurück, sonst den Grund. Ältere Nummer oder falsche Unterschrift: nichts ändert sich."""
    cur = load(base)
    d = parse(text, cur["serial"] if cur else 0)
    if not d:
        return "ungültig oder älter als der bekannte Stand"
    os.makedirs(base, exist_ok=True)
    atomic_write(_path(base), "".join(str(text).split()))
    apply(base)
    return ""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def refresh(base: str, url: str = "", opener=None) -> Dict[str, Any]:
    """Holt die Schaltdatei (GET, nur HTTPS, keine Weiterleitung). Nie eine Ausnahme; bei Fehlern bleibt der alte Stand."""
    url = url or SCHALT_URL
    if not url:
        return {"ok": False, "reason": "keine Adresse eingestellt"}
    if not url.lower().startswith("https://"):
        return {"ok": False, "reason": "nur https erlaubt"}
    try:
        op = opener or urllib.request.build_opener(_NoRedirect).open
        with op(urllib.request.Request(url, headers={"User-Agent": "CLAUDIA"}), timeout=10) as r:
            text = r.read(MAX_LEN + 1).decode("ascii", "strict")
    except Exception:  # noqa: BLE001
        return {"ok": False, "reason": "nicht erreichbar"}
    why = accept(base, text)
    return {"ok": not why, "reason": why}
