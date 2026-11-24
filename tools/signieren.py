#!/usr/bin/env python3
"""Digitale Unterschriften für Release-Pakete und Wissensdaten (nur für den Autor, auf dem eigenen Rechner).

  python3 tools/signieren.py schluessel --datei ~/claudia_signatur_privat.pem --kid s1
      Erzeugt EIN Schlüsselpaar (privater Schlüssel verschlüsselt, Passwort wird abgefragt) und zeigt den öffentlichen Schlüssel an,
      der in claudia/signatur.py unter PUBLIC_KEYS eingetragen wird. Erst damit wird die Prüfung im Programm aktiv.
  python3 tools/signieren.py unterschreiben --privat ~/claudia_signatur_privat.pem --kid s1 --zweck release CLAUDIA_v2.18.0.zip
      Schreibt CLAUDIA_v2.18.0.zip.sig (als Datei neben das Paket legen und mit dem Release hochladen).
  python3 tools/signieren.py unterschreiben --privat ... --kid s1 --zweck wissen claudia/advisories.json --ausgabe wissen/advisories.json
      Kopiert die Wissensdaten nach wissen/advisories.json und schreibt wissen/advisories.json.sig daneben (beides ins Repository).
  python3 tools/signieren.py pruefen --zweck release DATEI.zip DATEI.zip.sig
      Prüft mit dem öffentlichen Schlüssel aus dem Programm.
Der private Schlüssel gehört nie ins Repository, in ein Paket oder in einen Chat. Das Passwort wird immer abgefragt."""
import argparse
import base64
import getpass
import os
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, ".."))
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)
from claudia import signatur  # noqa: E402
from lizenz import make_pair  # noqa: E402  (gleiche Schlüsselerzeugung wie bei den Lizenzschlüsseln)


def _inside_repo(p: str) -> bool:
    p = os.path.abspath(os.path.expanduser(p))
    return p == ROOT or p.startswith(ROOT + os.sep)


def sign(pem: bytes, password: str, kid: str, zweck: str, data: bytes) -> str:
    """Unterschrift als Text (CS1.<kid>.<Unterschrift>). Prüft sie sofort mit dem zum privaten Schlüssel gehörenden öffentlichen."""
    from cryptography.hazmat.primitives import serialization
    if zweck not in signatur.ZWECKE:
        raise ValueError("Zweck: %s" % ", ".join(signatur.ZWECKE))
    priv = serialization.load_pem_private_key(pem, password.encode("utf-8"))
    pub = base64.b64encode(priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode("ascii")
    text = "%s.%s.%s" % (signatur.PREFIX, kid, signatur.b64e(priv.sign(signatur.message(zweck, data))))
    old = dict(signatur.PUBLIC_KEYS)
    signatur.PUBLIC_KEYS[kid] = pub
    try:
        ok = signatur.verify(zweck, data, text)
    finally:
        signatur.PUBLIC_KEYS.clear()
        signatur.PUBLIC_KEYS.update(old)
    if not ok:
        raise ValueError("Die Selbstprüfung der Unterschrift ist fehlgeschlagen (Schlüssel-ID ungültig?).")
    return text


def cmd_schluessel(a) -> int:
    datei = os.path.abspath(os.path.expanduser(a.datei))
    if _inside_repo(datei):
        print("Abbruch: Die Schlüsseldatei darf nicht im Programmordner (Repo) liegen. Wähle einen Ort außerhalb.")
        return 2
    if os.path.exists(datei):
        print("Abbruch: Die Datei gibt es schon. Es wird nie etwas überschrieben.")
        return 2
    pw = getpass.getpass("Passwort für den privaten Schlüssel (mind. 10 Zeichen): ")
    if pw != getpass.getpass("Passwort wiederholen: "):
        print("Die Passwörter sind verschieden.")
        return 2
    pem, pub = make_pair(pw)
    fd = os.open(datei, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(pem)
    print("Privater Schlüssel gespeichert (verschlüsselt): %s" % datei)
    print("Sichere ihn zusätzlich offline. Geht er verloren, kannst du nichts mehr unterschreiben (dann muss ein neuer öffentlicher Schlüssel ins Programm).")
    print('\nÖffentlicher Schlüssel, in claudia/signatur.py eintragen:\n  PUBLIC_KEYS: Dict[str, str] = {"%s": "%s"}' % (a.kid, pub))
    return 0


def cmd_unterschreiben(a) -> int:
    with open(os.path.expanduser(a.privat), "rb") as fh:
        pem = fh.read()
    with open(a.datei, "rb") as fh:
        data = fh.read()
    pw = getpass.getpass("Passwort des privaten Schlüssels: ")
    text = sign(pem, pw, a.kid, a.zweck, data)
    ziel = a.ausgabe or a.datei
    if a.ausgabe and os.path.abspath(a.ausgabe) != os.path.abspath(a.datei):
        os.makedirs(os.path.dirname(os.path.abspath(a.ausgabe)), exist_ok=True)
        shutil.copyfile(a.datei, a.ausgabe)
    with open(ziel + ".sig", "w", encoding="ascii") as fh:
        fh.write(text + "\n")
    print("Unterschrift geschrieben: %s.sig" % ziel)
    return 0


def cmd_pruefen(a) -> int:
    with open(a.datei, "rb") as fh:
        data = fh.read()
    with open(a.sig, "rb") as fh:
        sig = fh.read(1024)
    if not signatur.aktiv():
        print("Im Programm ist noch kein öffentlicher Schlüssel eingetragen: nichts zu prüfen.")
        return 2
    ok = signatur.verify(a.zweck, data, sig)
    print("Unterschrift gültig." if ok else "Unterschrift UNGÜLTIG.")
    return 0 if ok else 1


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("schluessel")
    s.add_argument("--datei", required=True)
    s.add_argument("--kid", default="s1")
    s.set_defaults(f=cmd_schluessel)
    s = sub.add_parser("unterschreiben")
    s.add_argument("--privat", required=True)
    s.add_argument("--kid", default="s1")
    s.add_argument("--zweck", required=True, choices=signatur.ZWECKE)
    s.add_argument("--ausgabe", default="")
    s.add_argument("datei")
    s.set_defaults(f=cmd_unterschreiben)
    s = sub.add_parser("pruefen")
    s.add_argument("--zweck", required=True, choices=signatur.ZWECKE)
    s.add_argument("datei")
    s.add_argument("sig")
    s.set_defaults(f=cmd_pruefen)
    a = ap.parse_args(argv)
    try:
        return a.f(a)
    except (ValueError, OSError) as e:
        print("Fehler: %s" % e)
        return 2


if __name__ == "__main__":
    sys.exit(main())
