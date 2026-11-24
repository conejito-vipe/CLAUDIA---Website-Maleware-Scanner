"""Digitale Unterschrift (Ed25519) für heruntergeladene Dateien: Programm-Updates und Wissensdaten.

Das Programm kennt nur den ÖFFENTLICHEN Schlüssel (PUBLIC_KEYS). Damit kann es Unterschriften prüfen, aber keine erzeugen; der private
Schlüssel liegt nur beim Autor (tools/signieren.py). Solange kein öffentlicher Schlüssel eingetragen ist, ist die Prüfung NICHT aktiv:
Dann ändert sich nichts am bisherigen Verhalten (Prüfsumme wie bisher), und es wird nichts zusätzlich geladen.
Ist ein Schlüssel eingetragen, gilt: ohne gültige Unterschrift wird nichts installiert und nichts übernommen (im Zweifel nein).

Format einer Unterschrift (Text): CS1.<Schlüssel-ID>.<Unterschrift, base64url>. Unterschrieben wird "CLAUDIA-SIG1", der Zweck und die
Datei selbst; eine Unterschrift für den einen Zweck gilt nie für den anderen."""
import base64
import binascii
import re
from typing import Dict

PREFIX = "CS1"
ZWECKE = ("release", "wissen")
MAX_SIG_LEN = 400
PUBLIC_KEYS: Dict[str, str] = {}                  # Schlüssel-ID -> öffentlicher Schlüssel (32 Byte, base64); leer = Prüfung nicht aktiv
_KID_RE = re.compile(r"^[A-Za-z0-9_-]{1,20}\Z")


def aktiv() -> bool:
    """Ist die Unterschriftsprüfung eingeschaltet (öffentlicher Schlüssel eingetragen)?"""
    return bool(PUBLIC_KEYS)


def b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def message(zweck: str, data: bytes) -> bytes:
    """Das, was tatsächlich unterschrieben wird (mit Zweck, damit Unterschriften nicht für anderes missbraucht werden können)."""
    return b"CLAUDIA-SIG1\n" + zweck.encode("ascii") + b"\n" + data


def _pubkey(kid: str):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    raw = base64.b64decode(PUBLIC_KEYS[kid])
    if len(raw) != 32:
        raise ValueError("Länge")
    return Ed25519PublicKey.from_public_bytes(raw)


def verify(zweck: str, data: bytes, sig_text) -> bool:
    """True nur bei echter, zum Zweck und zu den Daten passender Unterschrift. Wirft nie; jede Abweichung ist False."""
    try:
        if zweck not in ZWECKE or not isinstance(data, (bytes, bytearray)) or isinstance(sig_text, bool):
            return False
        if isinstance(sig_text, (bytes, bytearray)):
            sig_text = bytes(sig_text).decode("ascii")
        if not isinstance(sig_text, str):
            return False
        sig_text = "".join(sig_text.split())
        if not sig_text or len(sig_text) > MAX_SIG_LEN:
            return False
        parts = sig_text.split(".")
        if len(parts) != 3 or parts[0] != PREFIX or not _KID_RE.match(parts[1]) or parts[1] not in PUBLIC_KEYS:
            return False
        sig = _b64d(parts[2])
        _pubkey(parts[1]).verify(sig, message(zweck, bytes(data)))        # wirft bei jeder Abweichung
        return True
    except (ValueError, binascii.Error, UnicodeError, TypeError, KeyError):
        return False
    except Exception:                                                     # noqa: BLE001  (InvalidSignature, fehlende Bibliothek u. a.: im Zweifel nein)
        return False
