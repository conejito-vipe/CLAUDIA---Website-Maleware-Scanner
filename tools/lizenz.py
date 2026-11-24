#!/usr/bin/env python3
"""Lizenzschlüssel erzeugen (nur für den Autor, auf dem eigenen Rechner).

  python3 tools/lizenz.py schluessel --datei ~/claudia_lizenz_privat.pem --kid k1
      Erzeugt EIN Schlüsselpaar. Der PRIVATE Schlüssel kommt verschlüsselt (Passwort) in die Datei, der ÖFFENTLICHE wird angezeigt und
      in claudia/lizenz.py unter PUBLIC_KEYS eingetragen. Die Datei NIE ins Repo, in ein Zip oder in einen Chat legen.
  python3 tools/lizenz.py ausstellen --privat ~/claudia_lizenz_privat.pem --kid k1 --name "Firma Mustermann" --art gewerblich --bis 2027-11-30
      Stellt einen Schlüssel aus (Text für den Kunden) und trägt ihn in lizenzen_ausgestellt.csv neben der Schlüsseldatei ein.
  python3 tools/lizenz.py pruefen CL1....
      Prüft einen Schlüssel mit dem öffentlichen Schlüssel aus dem Programm.
Das Passwort wird immer abgefragt, nie als Parameter übergeben und nie gespeichert."""
import argparse
import getpass
import json
import os
import secrets
import sys
from datetime import date

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, ROOT)
from claudia import lizenz  # noqa: E402


def make_pair(password: str):
    """Gibt (privat_pem_verschluesselt, oeffentlich_base64) zurück."""
    import base64
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    if len(password) < 10:
        raise ValueError("Das Passwort muss mindestens 10 Zeichen haben.")
    priv = Ed25519PrivateKey.generate()
    pem = priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.BestAvailableEncryption(password.encode("utf-8")))
    pub = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return pem, base64.b64encode(pub).decode("ascii")


def issue(pem: bytes, password: str, kid: str, name: str, art: str, bis: str, bereiche="alle", plaetze: int = 0, lid: str = "", heute=None) -> str:
    """Stellt einen Schlüssel aus und prüft ihn sofort selbst. Wirft ValueError bei ungültigen Angaben."""
    import base64
    from cryptography.hazmat.primitives import serialization
    priv = serialization.load_pem_private_key(pem, password.encode("utf-8"))
    pub = base64.b64encode(priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode("ascii")
    data = {"v": 1, "kid": kid, "id": lid or secrets.token_hex(4), "name": name.strip(), "art": art, "bis": bis, "bereiche": bereiche}
    if plaetze:
        data["plaetze"] = int(plaetze)
    body = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    key = "%s.%s.%s" % (lizenz.PREFIX, lizenz.b64e(body), lizenz.b64e(priv.sign(body)))
    old = dict(lizenz.PUBLIC_KEYS)
    lizenz.PUBLIC_KEYS[kid] = pub                      # Selbstprüfung mit dem Schlüssel, der zu dieser Datei gehört
    try:
        res = lizenz.parse(key, heute)
    finally:
        lizenz.PUBLIC_KEYS.clear()
        lizenz.PUBLIC_KEYS.update(old)
    if not res["valid"]:
        raise ValueError("Die Angaben sind ungültig (%s). Art: %s; Datum: JJJJ-MM-TT; Bereiche: alle oder Liste aus %s." % (res["reason"], ", ".join(lizenz.ARTEN), ", ".join(lizenz.BEREICHE)))
    return key


def _inside_repo(p: str) -> bool:
    p = os.path.abspath(os.path.expanduser(p))
    return p == ROOT or p.startswith(ROOT + os.sep)


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
    print("Sichere ihn zusätzlich offline. Geht er verloren, kannst du keine Schlüssel mehr ausstellen.")
    print('\nÖffentlicher Schlüssel, in claudia/lizenz.py eintragen:\n  PUBLIC_KEYS = {"%s": "%s"}' % (a.kid, pub))
    return 0


def cmd_ausstellen(a) -> int:
    pem = open(os.path.expanduser(a.privat), "rb").read()
    pw = getpass.getpass("Passwort des privaten Schlüssels: ")
    bereiche = "alle" if a.bereiche == "alle" else [x.strip() for x in a.bereiche.split(",") if x.strip()]
    key = issue(pem, pw, a.kid, a.name, a.art, a.bis, bereiche, a.plaetze, a.id)
    lid = json.loads(lizenz._b64d(key.split(".")[1]))["id"]
    reg = os.path.join(os.path.dirname(os.path.abspath(os.path.expanduser(a.privat))), "lizenzen_ausgestellt.csv")
    with open(reg, "a", encoding="utf-8") as fh:
        fh.write("%s;%s;%s;%s;%s;%s\n" % (date.today().isoformat(), lid, a.name.replace(";", ","), a.art, a.bis, a.bereiche))
    print("Schlüssel für den Kunden:\n\n%s\n\nEingetragen in %s (zum Sperren später die Lizenz-ID in claudia/lizenz.py unter REVOKED aufnehmen)." % (key, reg))
    return 0


def cmd_pruefen(a) -> int:
    res = lizenz.parse(a.key)
    print(json.dumps(res, ensure_ascii=False, indent=2))
    return 0 if res["valid"] else 1


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("schluessel")
    s.add_argument("--datei", required=True)
    s.add_argument("--kid", default="k1")
    s.set_defaults(f=cmd_schluessel)
    s = sub.add_parser("ausstellen")
    s.add_argument("--privat", required=True)
    s.add_argument("--kid", default="k1")
    s.add_argument("--name", required=True)
    s.add_argument("--art", required=True, choices=lizenz.ARTEN)
    s.add_argument("--bis", required=True)
    s.add_argument("--bereiche", default="alle")
    s.add_argument("--plaetze", type=int, default=0)
    s.add_argument("--id", default="")
    s.set_defaults(f=cmd_ausstellen)
    s = sub.add_parser("pruefen")
    s.add_argument("key")
    s.set_defaults(f=cmd_pruefen)
    a = ap.parse_args(argv)
    try:
        return a.f(a)
    except (ValueError, OSError) as e:
        print("Fehler: %s" % e)
        return 2


if __name__ == "__main__":
    sys.exit(main())
