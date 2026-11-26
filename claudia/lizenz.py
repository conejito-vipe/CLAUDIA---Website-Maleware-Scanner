"""Lizenzschlüssel: offline prüfbar, digital signiert (Ed25519), ohne Rückfrage ins Netz und ohne Nutzerdaten.

Aufbau eines Schlüssels:  CL1.<Angaben als base64url>.<Unterschrift als base64url>
Die Angaben sind ein kurzer JSON-Text (Lizenznehmer, Art, gültig bis, Bereiche, Lizenz-ID, Schlüssel-ID). Erzeugen kann einen Schlüssel nur, wer den
PRIVATEN Schlüssel hat (liegt nur beim Autor, nie im Repo). Im Programm steht nur der ÖFFENTLICHE Schlüssel; er kann Unterschriften prüfen, aber keine erzeugen.

Der Schalter: BEREICHE nennt alle Bereiche, die sich sperren lassen, GESPERRT_OHNE_LIZENZ nennt die, die ohne gültigen Schlüssel gesperrt sind.
Ist die Liste leer (Standard), ist nichts gesperrt und das Programm verhält sich wie bisher. Die Prüfung ("Suche"), die Verbindung und der Rückweg
sind IMMER frei, unabhängig von jeder Einstellung (IMMER_FREI, siehe frei())."""
import base64
import binascii
import json
import os
import re
from datetime import date
from typing import Any, Dict, List, Optional, Tuple

from .util import atomic_write, clean_line

PREFIX = "CL1"
MAX_KEY_LEN = 4000
FILE = "lizenz.txt"
WARN_DAYS = 30

# Öffentliche Schlüssel (Schlüssel-ID -> 32 Byte, base64). Der Autor trägt hier den Wert aus "tools/lizenz.py schluessel" ein.
# Mehrere sind möglich: Geht ein privater Schlüssel verloren, kommt ein neuer dazu; alte Lizenzen laufen bis zu ihrem Ablauf weiter.
PUBLIC_KEYS: Dict[str, str] = {}

# Gesperrte Lizenz-IDs (z. B. weitergegebene Schlüssel). Kommt mit Programm-Updates, es gibt keine Rückfrage ins Netz.
REVOKED: Tuple[str, ...] = ()
# Kommt aus der signierten Schaltdatei (siehe schalt.py): zusätzliche Sperren und der Schalter "Lizenzpflicht an"
REVOKED_EXTRA: Tuple[str, ...] = ()
SCHALT_AKTIV = False

# Alle Bereiche, die sich sperren lassen (Name -> Anzeigetext). Nur Bereiche, die der Server wirklich durchsetzt (siehe AREA_OF in server.py); weitere kommen erst mit ihrer Durchsetzung dazu.
BEREICHE: Dict[str, str] = {
    "aktionen": "Lösungen auf Knopfdruck (Änderungen auf dem Server)",
    "dashboard": "Dashboard (Verlauf, Vergleich, Verwaltung)",
    "protokolle": "Zugriffsprotokolle sichern",
    "export": "Berichte und Übergabe exportieren",
}

# Der Schalter: diese Bereiche sind ohne gültigen Schlüssel gesperrt. Standard: keiner (nichts wird gesperrt).
GESPERRT_OHNE_LIZENZ: Tuple[str, ...] = ()

# Das ist nie sperrbar: die Prüfung (Suche), Verbindung, Sprache, Update, Hilfe, Beenden ...
IMMER_FREI = ("pruefung", "verbindung", "hilfe", "sprache", "update", "lizenz", "beenden")
# ... und der Rückweg: diese Aktionen bleiben auch dann erlaubt, wenn "aktionen" gesperrt ist
AKTIONEN_IMMER_FREI = ("restore_quarantine", "backup_now")

ARTEN = ("gewerblich", "gemeinnuetzig", "behoerde", "privat", "test")
_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,40}\Z")
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}\Z")


def _b64d(text: str) -> bytes:
    if not re.match(r"^[A-Za-z0-9_-]*\Z", text):
        raise ValueError("Zeichen")
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _pubkey(kid: str):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    raw = base64.b64decode(PUBLIC_KEYS[kid])
    if len(raw) != 32:
        raise ValueError("Länge")
    return Ed25519PublicKey.from_public_bytes(raw)


def _bad(reason: str) -> Dict[str, Any]:
    return {"valid": False, "reason": reason}


def parse(key: Any, today: Optional[date] = None) -> Dict[str, Any]:
    """Prüft einen Schlüssel. Gibt immer ein Wörterbuch zurück, nie eine Ausnahme.
    valid=True nur bei echter Unterschrift, bekannter Schlüssel-ID, nicht gesperrt, nicht abgelaufen und sauberen Angaben."""
    if not isinstance(key, str):
        return _bad("kein Text")
    key = "".join(key.split())                      # Zeilenumbrüche/Leerzeichen aus E-Mails stören nicht
    if not key or len(key) > MAX_KEY_LEN:
        return _bad("leer oder zu lang")
    parts = key.split(".")
    if len(parts) != 3 or parts[0] != PREFIX:
        return _bad("Format")
    try:
        body = _b64d(parts[1])
        sig = _b64d(parts[2])
        data = json.loads(body.decode("utf-8"))
    except (ValueError, binascii.Error, UnicodeDecodeError, RecursionError):
        return _bad("Format")
    if not isinstance(data, dict):
        return _bad("Format")
    kid = data.get("kid")
    if not isinstance(kid, str) or kid not in PUBLIC_KEYS:
        return _bad("unbekannter Schlüssel")
    try:
        _pubkey(kid).verify(sig, body)              # wirft bei jeder Abweichung, auch bei einem einzigen veränderten Byte
    except Exception:                               # noqa: BLE001  (InvalidSignature und jede Form-Ausnahme: gleich behandelt)
        return _bad("Unterschrift ungültig")
    lid, name, art, bis, bereiche = data.get("id"), data.get("name"), data.get("art"), data.get("bis"), data.get("bereiche", "alle")
    if not (isinstance(lid, str) and _ID_RE.match(lid) and isinstance(name, str) and 0 < len(name) <= 120 and art in ARTEN
            and isinstance(bis, str) and _DATE_RE.match(bis)):
        return _bad("Angaben unvollständig")
    if bereiche != "alle" and not (isinstance(bereiche, list) and all(isinstance(b, str) and b in BEREICHE for b in bereiche)):
        return _bad("Angaben unvollständig")
    try:
        until = date.fromisoformat(bis)
    except ValueError:
        return _bad("Angaben unvollständig")
    now = today or date.today()
    days_left = (until - now).days
    out = {"valid": True, "reason": "", "id": lid, "name": clean_line(name), "art": art, "until": bis, "days_left": days_left, "expired": days_left < 0,
           "areas": "alle" if bereiche == "alle" else list(bereiche), "seats": data.get("plaetze") if isinstance(data.get("plaetze"), int) else 0}
    if lid in REVOKED or lid in REVOKED_EXTRA:
        out.update(valid=False, reason="gesperrt")
    elif days_left < 0:
        out.update(valid=False, reason="abgelaufen")
    return out


def gesperrt_bereiche() -> Tuple[str, ...]:
    """Bereiche ohne Lizenz gesperrt: fest im Code oder, wenn die Schaltdatei die Lizenzpflicht einschaltet, alle sperrbaren Bereiche."""
    return tuple(BEREICHE) if SCHALT_AKTIV else GESPERRT_OHNE_LIZENZ


def path(base: str) -> str:
    return os.path.join(base, FILE)


def load(base: str) -> str:
    try:
        with open(path(base), encoding="utf-8") as fh:
            return fh.read(MAX_KEY_LEN + 10).strip()
    except OSError:
        return ""


def store(base: str, key: str) -> Dict[str, Any]:
    """Schlüssel prüfen und nur bei Erfolg speichern (Abgelaufene werden angezeigt, aber auch gespeichert, damit der Hinweis bleibt)."""
    res = parse(key)
    if res["valid"] or res.get("reason") == "abgelaufen":
        os.makedirs(base, exist_ok=True)
        atomic_write(path(base), "".join(str(key).split()))
    return res


def remove(base: str) -> bool:
    try:
        os.remove(path(base))
        return True
    except OSError:
        return False


def state(base: str, today: Optional[date] = None) -> Dict[str, Any]:
    """Zustand für die Oberfläche: Schlüssel, gesperrte Bereiche ohne Lizenz, Hinweis auf nahen Ablauf."""
    key = load(base)
    res = parse(key, today) if key else {"valid": False, "reason": ""}
    covered = BEREICHE.keys() if res.get("valid") and res.get("areas") == "alle" else (res.get("areas") or []) if res.get("valid") else []
    blocked = [b for b in gesperrt_bereiche() if b not in covered]
    warn = bool(res.get("valid") and res["days_left"] <= WARN_DAYS)
    return dict(res, has_key=bool(key), blocked=blocked, blocked_text=[BEREICHE.get(b, b) for b in blocked], warn_expiry=warn,
                public_key_set=bool(PUBLIC_KEYS), bereiche=BEREICHE, gesperrt_ohne_lizenz=list(gesperrt_bereiche()))


def frei(base: str, area: str, action_id: str = "") -> bool:
    """Darf dieser Bereich benutzt werden? Prüfung, Verbindung und Rückweg: immer ja."""
    if area in IMMER_FREI:
        return True
    if area == "aktionen" and action_id in AKTIONEN_IMMER_FREI:
        return True
    if area not in gesperrt_bereiche():
        return True
    return area not in state(base)["blocked"]
