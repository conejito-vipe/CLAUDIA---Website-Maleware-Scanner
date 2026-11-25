"""Vergleich Normal und Pro, Kauf (PayPal), Verlängerung und Rabattcodes: vorbereitet, aber AUS, bis der Autor es einschaltet.

Alles steht in diesem Modul als Einstellung (AKTIV, PREIS_CENT, PAYPAL_URL, FEATURES). Im Auslieferungszustand ist AKTIV falsch: Die Seite wird nirgends angezeigt, es gibt keinen Kauf-Knopf
und es werden keine Preise genannt. Das Programm prüft nichts online: Rabattcodes sind wie Lizenzschlüssel digital signiert (Ed25519) und werden offline geprüft; bezahlt wird bei PayPal im Browser,
danach stellt der Autor den Schlüssel aus (siehe tools/lizenz.py). Das Programm erfährt nichts von der Zahlung und speichert keine Zahlungsdaten.

Rabattcode: RB1.<Angaben als base64url>.<Unterschrift als base64url>, Angaben = {"v":1,"kid":..,"id":..,"prozent":1-100,"bis":"JJJJ-MM-TT","fuer":"alle"|<Lizenz-ID>,"nur_verlaengerung":bool}.
Unterschrieben wird "CLAUDIA-RABATT1" plus die Angaben; ein Schlüssel oder eine Unterschrift anderer Art gilt hier nie."""
import base64
import binascii
import json
import re
from datetime import date
from typing import Any, Dict, List, Optional
from urllib.parse import quote

from . import lizenz

PREFIX = "RB1"
MAX_CODE_LEN = 1200
AKTIV = False                                    # Seite und Kauf sichtbar? Der Autor schaltet sie ein, sobald Umfang, Preis und Schlüsselvergabe entschieden sind.
LAUFZEIT_TAGE = 365                              # Gültigkeit jeder Lizenz
WAEHRUNG = "EUR"
PREIS_CENT: Dict[str, int] = {}                  # z. B. {"pro": 4900}; leer = kein Preis genannt, kein Kauf
PAYPAL_URL = ""                                  # Vorlage mit {betrag}, {waehrung}, {plan}, {code}, {lizenz}; nur https://www.paypal.com/... oder https://www.paypal.me/...
PAYPAL_RE = re.compile(r"^https://(www\.)?paypal\.(com|me)/[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%{}-]{0,380}\Z")

# Zeile: (Schlüssel, Text, in Normal, in Pro). Der Autor legt gemeinsam mit der Schlüsselentscheidung fest, was wo steht.
FEATURES: List[Dict[str, Any]] = [
    {"id": "pruefung", "text": "Prüfung: Suche nach Spuren und Schwachstellen, Bericht", "normal": True, "pro": True},
    {"id": "rueckweg", "text": "Rückweg: Sicherung anlegen, Quarantäne zurückholen", "normal": True, "pro": True},
]
NGO_TEXT = ("Gemeinnützige Organisationen und Vereine bekommen einen Schlüssel kostenlos (wie in der Lizenz geregelt): "
            "Nachweis der Gemeinnützigkeit an den Autor senden, der Schlüssel kommt ohne Kosten.")
LIZENZ_HINWEIS = "Verbindlich sind die Lizenzbedingungen in der Datei LICENSE (deutsche Fassung)."
TERMS: List[str] = [
    "Kostenlos nutzbar: Privatpersonen (nicht kommerziell) sowie gemeinnützige Organisationen und Vereine für gemeinnützige Zwecke, jeweils auf eigenen Seiten.",
    "Keine Veränderung, keine Weitergabe der Software; Bezug nur vom Urheber.",
    "Parteien und Organisationen, die der Verfassungsschutz als rechtsextremistisch einstuft oder die verboten sind, sind von der Nutzung ausgeschlossen.",
    "Die Software wird ohne Gewährleistung bereitgestellt; Einsatz nur auf Seiten, die dir gehören oder für die du berechtigt bist.",
]
_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,40}\Z")
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}\Z")


def _b64d(text: str) -> bytes:
    if not re.match(r"^[A-Za-z0-9_-]*\Z", text):
        raise ValueError("Zeichen")
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def message(body: bytes) -> bytes:
    return b"CLAUDIA-RABATT1\n" + body


def _bad(reason: str) -> Dict[str, Any]:
    return {"valid": False, "reason": reason, "prozent": 0}


def parse_code(code: Any, lizenz_id: str = "", renewal: bool = False, today: Optional[date] = None) -> Dict[str, Any]:
    """Prüft einen Rabattcode (offline). Gibt immer ein Wörterbuch zurück, nie eine Ausnahme. valid=True nur bei echter Unterschrift, bekannter Schlüssel-ID,
    nicht abgelaufen und passend (Lizenz-ID bzw. nur Verlängerung)."""
    if not isinstance(code, str):
        return _bad("kein Text")
    code = "".join(code.split())
    if not code or len(code) > MAX_CODE_LEN:
        return _bad("leer oder zu lang")
    parts = code.split(".")
    if len(parts) != 3 or parts[0] != PREFIX:
        return _bad("Format")
    try:
        body, sig = _b64d(parts[1]), _b64d(parts[2])
        data = json.loads(body.decode("utf-8"))
    except (ValueError, binascii.Error, UnicodeDecodeError, RecursionError):
        return _bad("Format")
    if not isinstance(data, dict):
        return _bad("Format")
    kid = data.get("kid")
    if not isinstance(kid, str) or kid not in lizenz.PUBLIC_KEYS:
        return _bad("unbekannter Schlüssel")
    try:
        lizenz._pubkey(kid).verify(sig, message(body))
    except Exception:                                                # noqa: BLE001  (jede Abweichung: ungültig)
        return _bad("Unterschrift ungültig")
    cid, pct, bis, fuer, nur = data.get("id"), data.get("prozent"), data.get("bis"), data.get("fuer", "alle"), data.get("nur_verlaengerung", False)
    if not (isinstance(cid, str) and _ID_RE.match(cid) and isinstance(pct, int) and not isinstance(pct, bool) and 1 <= pct <= 100
            and isinstance(bis, str) and _DATE_RE.match(bis) and isinstance(fuer, str) and (fuer == "alle" or _ID_RE.match(fuer)) and isinstance(nur, bool)):
        return _bad("Angaben unvollständig")
    try:
        until = date.fromisoformat(bis)
    except ValueError:
        return _bad("Angaben unvollständig")
    if (until - (today or date.today())).days < 0:
        return dict(_bad("abgelaufen"), id=cid, until=bis)
    if fuer != "alle" and fuer != lizenz_id:
        return dict(_bad("gehört zu einer anderen Lizenz"), id=cid)
    if nur and not renewal:
        return dict(_bad("nur für Verlängerungen"), id=cid)
    return {"valid": True, "reason": "", "id": cid, "prozent": pct, "until": bis, "fuer": fuer, "nur_verlaengerung": nur}


def preis_nach_rabatt(cent: int, prozent: int) -> int:
    """Ganzzahlig auf den Cent abgerundet (zugunsten der Kundschaft ist der Rabatt immer mindestens der gerechnete Wert); nie unter 0."""
    p = max(0, min(100, int(prozent)))
    return max(0, (int(cent) * (100 - p)) // 100)


def kauf_url(plan: str, cent: int, code: str = "", lizenz_id: str = "") -> str:
    """PayPal-Adresse aus der Vorlage; leer, solange keine erlaubte Vorlage eingetragen ist. Alle Werte werden kodiert."""
    tpl = PAYPAL_URL.strip()
    if not tpl or not PAYPAL_RE.match(tpl) or cent <= 0:
        return ""
    amount = "%d.%02d" % (cent // 100, cent % 100)
    url = (tpl.replace("{betrag}", quote(amount, safe="")).replace("{waehrung}", quote(WAEHRUNG, safe="")).replace("{plan}", quote(str(plan)[:20], safe=""))
              .replace("{code}", quote(str(code)[:60], safe="")).replace("{lizenz}", quote(str(lizenz_id)[:40], safe="")))
    return url if PAYPAL_RE.match(url) and len(url) <= 400 else ""


def state(base: str, code: str = "", today: Optional[date] = None) -> Dict[str, Any]:
    """Alles für die Seite. Ist AKTIV falsch, kommt nur {"aktiv": False} zurück (nichts Sichtbares, keine Preise)."""
    if not AKTIV:
        return {"aktiv": False}
    lic = lizenz.state(base, today)
    renewal = bool(lic.get("has_key"))
    lid = str(lic.get("id") or "")
    cent = int(PREIS_CENT.get("pro", 0) or 0)
    disc = parse_code(code, lid, renewal, today) if code else {"valid": False, "reason": "", "prozent": 0}
    pay = preis_nach_rabatt(cent, disc["prozent"]) if disc["valid"] else cent
    return {"aktiv": True, "laufzeit_tage": LAUFZEIT_TAGE, "waehrung": WAEHRUNG, "features": FEATURES, "ngo": NGO_TEXT, "bedingungen": TERMS, "hinweis": LIZENZ_HINWEIS,
            "preis_cent": cent, "zu_zahlen_cent": pay, "rabatt": disc, "verlaengerung": renewal, "lizenz_bis": lic.get("until") or "", "tage_uebrig": lic.get("days_left") if lic.get("valid") else None,
            "kauf_moeglich": bool(kauf_url("pro", pay, code if disc["valid"] else "", lid)), "lizenz_id": lid}
