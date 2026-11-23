"""Umgebung des Server-Kontos und der Webseite (2.5.0): Klartext-Zugangsdaten, Alter der Sicherungen, TLS-Protokolle, Cookie-Flags, veraltete JavaScript-Bibliotheken.

Die Bewertung steckt in den reinen Funktionen von auswertung_umgebung.py (ausgelagert, mit Beispieldateien geprüft). Hier stehen die Skripte und die Anbindung. Alles nur lesend:
- Klartext-Zugangsdaten: nur Name, Rechte, Besitzer und Größe (find), der Inhalt wird nie geöffnet.
- Sicherungen: nur Name, Größe, Datum, Lesbarkeit (gzip -t bzw. unzip -t liest die Archivdatei, gibt aber nichts davon aus).
- TLS: je Protokoll ein Verbindungsversuch von diesem Rechner aus, es werden keine Daten gesendet.
- Cookies: die Kopfzeilen der Startseite; der Cookie-Wert wird sofort verworfen.
- JavaScript: Dateinamen und die erste Kopfzeile der Bibliothek (Versionskommentar)."""
from __future__ import annotations

import os
import re
import socket
import ssl
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from .. import secure
from ..model import CheckSkipped
from ..registry import check
from ..util import digits, sq
from . import auswertung_umgebung as au
from .web import UA_BROWSER, fetch

G = "grundlagen"
CRED_NAMES = (".my.cnf", ".netrc", ".git-credentials", ".env")
PRUNE = r"\( -path '*/node_modules' -o -path '*/.git' -o -path '*/.cache' -o -path '*/vendor' \) -prune"


def _emit(res, rows) -> None:
    for sev, title, text, items, hint in rows:
        res.add(sev, title, text, items, hint)


def _parse_sections(out: str) -> Dict[str, List[str]]:
    sec: Dict[str, List[str]] = {}
    cur = None
    for ln in (out or "").splitlines():
        if ln.startswith("@@"):
            cur = ln[2:].strip()
            sec[cur] = []
        elif cur is not None:
            sec[cur].append(ln)
    return sec


# ------------------------------------------------------------------ Klartext-Zugangsdaten
CRED_SCRIPT = r"""
echo '@@USER'; id -un 2>/dev/null
echo '@@ROOT'; pwd -P
echo '@@LIST'
find "$HOME" -maxdepth 4 """ + PRUNE + r""" -o -type f \( -name .my.cnf -o -name .netrc -o -name .git-credentials -o -name .env \) -printf '%m\t%u\t%s\t%p\n' 2>/dev/null | head -n 200
"""


def parse_creds(out: str) -> Tuple[str, List[Dict[str, Any]]]:
    sec = _parse_sections(out)
    user = (sec.get("USER") or [""])[0].strip()
    root = (sec.get("ROOT") or [""])[0].strip().rstrip("/")
    entries: List[Dict[str, Any]] = []
    for ln in sec.get("LIST", []):
        parts = ln.split("\t", 3)
        if len(parts) != 4 or os.path.basename(parts[3]) not in CRED_NAMES:
            continue
        mode, owner, size, path = parts
        try:
            sz = int(size)
        except ValueError:
            continue
        entries.append({"path": path, "name": os.path.basename(path), "mode": mode.strip(), "owner": owner.strip(), "size": sz,
                        "in_webroot": bool(root) and (path == root or path.startswith(root + "/"))})
    return user, entries


@check(
    "plaintext_creds", "konto", "Klartext-Zugangsdaten im Konto",
    "Liegen Dateien mit Zugangsdaten (.my.cnf, .netrc, .git-credentials, .env) mit zu offenen Rechten im Konto oder im Webverzeichnis?",
    what="Sucht im Server-Konto (bis vier Ordner tief, ohne node_modules, vendor, .git, .cache) nach den Dateien .my.cnf, .netrc, .git-credentials und .env und meldet nur Name, Rechte, Besitzer und Größe. "
         "Zu offene Rechte (Gruppe oder Andere dürfen zugreifen) und Dateien im Webverzeichnis werden gemeldet; im Webverzeichnis mit Lesezugriff für alle ist es kritisch.",
    why="In diesen Dateien stehen oft Passwörter im Klartext. Liegt eine davon im Webverzeichnis, kann sie unter Umständen jeder aus dem Internet abrufen. Zu offene Rechte erlauben anderen Konten auf dem Server das Mitlesen.",
    reads="Nur Dateinamen, Rechte, Besitzer und Größe. Der Inhalt dieser Dateien wird nie geöffnet und nie angezeigt. Es wird nichts verändert.",
    load="leicht", needs="ssh", presets=["schnell", "hack"],
)
def plaintext_creds(ctx, res):
    ctx.progress("Nach Dateien mit Zugangsdaten suchen (nur Namen und Rechte)")
    out = ctx.sh(CRED_SCRIPT, timeout=90).out
    user, entries = parse_creds(out)
    _emit(res, au.judge_plaintext_creds(entries, user))


# ------------------------------------------------------------------ Alter der Sicherungen
BACKUP_WORD = re.compile(r"backup|sicherung|akeeba|updraft|backwpup|duplicator|dump|\.bak|bak/|snapshot", re.I)
BACKUP_EXT = re.compile(r"\.(jpa|wpress|sql\.gz)$", re.I)
ARCHIVE_EXT = re.compile(r"\.(tar\.gz|tgz|gz|zip|jpa|wpress)$", re.I)
BACKUP_SCRIPT = r"""
echo '@@NOW'; date +%s
echo '@@LIST'
find "$HOME" -maxdepth 4 \( -path '*/node_modules' -o -path '*/.git' -o -path '*/.cache' -o -path '*/logs' -o -path '*/log' \) -prune -o -type f \( -iname '*.tar.gz' -o -iname '*.tgz' -o -iname '*.jpa' -o -iname '*.wpress' -o -iname '*.sql.gz' -o -iname '*.zip' \) -printf '%T@\t%s\t%p\n' 2>/dev/null | sort -rn | head -n 600
"""
MAX_BACKUPS = 40
TEST_NEWEST = 3


def parse_backups(out: str) -> Tuple[Optional[int], List[Dict[str, Any]]]:
    sec = _parse_sections(out)
    try:
        now = int((sec.get("NOW") or [""])[0].strip())
    except ValueError:
        now = None
    items: List[Dict[str, Any]] = []
    for ln in sec.get("LIST", []):
        parts = ln.split("\t", 2)
        if len(parts) != 3:
            continue
        try:
            mtime, size = int(float(parts[0])), int(parts[1])
        except ValueError:
            continue
        path = parts[2]
        if not (BACKUP_WORD.search(path) or BACKUP_EXT.search(path)):
            continue
        items.append({"path": path, "size": size, "mtime": mtime, "test_rc": None})
        if len(items) >= MAX_BACKUPS:
            break
    return now, items


def test_script(path: str) -> str:
    p = sq(path)
    if re.search(r"\.(tar\.gz|tgz|sql\.gz|gz)$", path, re.I):
        return "timeout 120 gzip -t %s >/dev/null 2>&1; echo $?" % p
    if path.lower().endswith(".zip"):
        return "command -v unzip >/dev/null 2>&1 && { timeout 120 unzip -tqq %s >/dev/null 2>&1; echo $?; } || echo X" % p
    return "echo X"


@check(
    "backup_age", "dateien", "Alter und Zustand der Sicherungen im Konto",
    "Gibt es im Konto eine aktuelle, lesbare Sicherung?",
    what="Sucht im Server-Konto nach Sicherungsdateien (Namen mit backup, sicherung, akeeba, updraft, dump u. ä. oder die Endungen .jpa, .wpress, .sql.gz) und bewertet die neueste: "
         "älter als 30 Tage, leer, auffällig klein im Vergleich zu den anderen oder beschädigt (die neuesten drei werden mit gzip -t bzw. unzip -t auf Lesbarkeit getestet). "
         "Sicherungen beim Hoster oder in fremdem Speicher sind von hier aus nicht sichtbar und werden nicht bewertet.",
    why="Eine Sicherung hilft nur, wenn sie aktuell und lesbar ist. Nach einem Einbruch ist sie oft der schnellste Weg zurück. Eine Datei, die sich nicht öffnen lässt, ist keine Sicherung.",
    reads="Nur Dateinamen, Größe und Datum; für die Lesbarkeit wird die Archivdatei einmal durchgelesen, ohne etwas auszugeben oder zu entpacken. Es wird nichts verändert.",
    load="mittel", needs="ssh", presets=["hack"],
)
def backup_age(ctx, res):
    ctx.progress("Nach Sicherungsdateien suchen")
    now, items = parse_backups(ctx.sh(BACKUP_SCRIPT, timeout=90).out)
    if now is None:
        raise CheckSkipped("Die Uhrzeit des Servers ist nicht lesbar.")
    for it in items[:TEST_NEWEST]:
        if "\n" in it["path"] or not ARCHIVE_EXT.search(it["path"]):
            continue
        ctx.progress("Lesbarkeit der neuesten Sicherungen testen")
        r = ctx.sh(test_script(it["path"]), timeout=150).out.strip().splitlines()
        last = r[-1].strip() if r else ""
        it["test_rc"] = int(last) if digits(last) else None
    _emit(res, au.judge_backup_age(items, now))


# ------------------------------------------------------------------ TLS-Protokolle
TLS_VERSIONS = (("TLSv1", "TLSv1"), ("TLSv1.1", "TLSv1_1"), ("TLSv1.2", "TLSv1_2"), ("TLSv1.3", "TLSv1_3"))
SERVER_ALERT = re.compile(r"ALERT_PROTOCOL_VERSION|ALERT_HANDSHAKE_FAILURE|alert protocol version|alert handshake failure|PROTOCOL_VERSION", re.I)


def classify_tls_error(exc: BaseException) -> str:
    """'refused' nur, wenn der Server das Protokoll ausdrücklich ablehnt (TLS-Alarm). Alles andere (eigenes OpenSSL kann das Protokoll nicht, Verbindung abgebrochen, Zeitüberschreitung) ist 'unknown'."""
    if isinstance(exc, ssl.SSLError) and SERVER_ALERT.search(str(exc)) and "UNSUPPORTED_PROTOCOL" not in str(exc).upper():
        return "refused"
    return "unknown"


def probe_tls(host: str, port: int, name: str, attr: str, timeout: float = 10.0) -> str:
    """Ein Verbindungsversuch mit genau einem Protokoll. Es wird kein Zertifikat geprüft (es geht nur um das Protokoll) und nichts gesendet."""
    try:
        ver = getattr(ssl.TLSVersion, attr)
        c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        c.check_hostname = False
        c.verify_mode = ssl.CERT_NONE
        if ver in (ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1):
            try:
                c.set_ciphers("ALL:@SECLEVEL=0")
            except ssl.SSLError:
                return "unknown"
        c.minimum_version = ver
        c.maximum_version = ver
    except (AttributeError, ValueError, ssl.SSLError):
        return "unknown"
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with c.wrap_socket(raw, server_hostname=host):
                return "accepted"
    except BaseException as e:      # noqa: BLE001 - jede Störung heißt hier nur 'nicht aussagekräftig'
        return classify_tls_error(e)


@check(
    "tls_protocols", "logs", "Verschlüsselungsprotokolle der Webseite (TLS)",
    "Akzeptiert der Server noch veraltete Verschlüsselung (TLS 1.0 oder 1.1)?",
    what="Baut vier kurze Verbindungen zur Webseite auf, je eine pro Protokoll (TLS 1.0, 1.1, 1.2, 1.3), und sieht nur, ob der Server das Protokoll annimmt. Es werden keine Daten gesendet. "
         "Alte Versionen anzunehmen ist 'bitte prüfen'. Kann das eigene Programm ein altes Protokoll nicht prüfen, steht es als 'nicht aussagekräftig' da und gilt nie als Beleg.",
    why="TLS 1.0 und 1.1 gelten seit Jahren als veraltet. Browser lehnen sie ab; wer sie noch anbietet, lässt Verbindungen mit schwacher Verschlüsselung zu.",
    reads="Nur das Ergebnis des Verbindungsaufbaus je Protokoll (angenommen oder abgelehnt). Es wird nichts gesendet und nichts verändert.",
    load="leicht", needs="web", presets=["schnell"],
)
def tls_protocols(ctx, res):
    url = (ctx.s.url or "").strip()
    if not url:
        raise CheckSkipped("Keine Adresse der Webseite angegeben (Feld 'Webseite' in den Verbindungsdaten).")
    url, _up = secure.to_https(url)
    p = urlparse(url)
    host = p.hostname or ""
    if not host or secure.is_loopback(host):
        raise CheckSkipped("Für den eigenen Rechner gibt es hier nichts zu prüfen.")
    hs = []
    for i, (name, attr) in enumerate(TLS_VERSIONS):
        ctx.progress("Protokoll %s ausprobieren" % name)
        hs.append({"protocol": name, "result": probe_tls(host, p.port or 443, name, attr)})
        ctx.check_cancel()
    _emit(res, au.judge_tls(hs))


# ------------------------------------------------------------------ Cookie-Flags
def parse_set_cookie(line: str) -> Optional[Dict[str, str]]:
    """Name und Attribute einer Set-Cookie-Zeile. Der Wert wird nie übernommen."""
    first, _, attrs = (line or "").partition(";")
    name = first.partition("=")[0].strip()
    if not name or len(name) > 200:
        return None
    return {"name": name, "attrs": attrs.strip()[:300]}


@check(
    "cookie_flags", "logs", "Sicherheits-Merkmale der Cookies",
    "Sind Sitzungs-Cookies gegen Abgreifen geschützt (Secure, HttpOnly, SameSite)?",
    what="Ruft die Startseite einmal ab und liest die Cookie-Kopfzeilen. Für Sitzungs-Cookies (Joomla, WordPress, PHP) wird geprüft, ob Secure und HttpOnly gesetzt sind, für alle Cookies, "
         "ob SameSite=None nur mit Secure vorkommt. Ein anonymer Besucher bekommt oft gar kein Sitzungs-Cookie; dann gibt es nichts zu bewerten.",
    why="Ohne HttpOnly kann Schadcode auf der Seite das Sitzungs-Cookie auslesen, ohne Secure wird es auch über unverschlüsselte Verbindungen gesendet. Beides erleichtert die Übernahme einer Sitzung.",
    reads="Nur die Cookie-Kopfzeilen der Startseite, so wie jeder Besucher sie bekommt. Die Werte der Cookies werden sofort verworfen. Es wird nichts verändert.",
    load="leicht", needs="web", presets=["schnell"],
)
def cookie_flags(ctx, res):
    url = (ctx.s.url or "").strip()
    if not url:
        raise CheckSkipped("Keine Adresse der Webseite angegeben (Feld 'Webseite' in den Verbindungsdaten).")
    url, _up = secure.to_https(url)
    ctx.progress("Cookies der Startseite lesen")
    f = fetch(url, UA_BROWSER, max_bytes=20_000)
    if f.error:
        raise CheckSkipped("Webseite nicht erreichbar: %s" % f.error)
    cookies = [c for c in (parse_set_cookie(x) for x in f.set_cookies) if c]
    https = urlparse(f.final or url).scheme == "https"
    _emit(res, au.judge_cookies(cookies, https))


# ------------------------------------------------------------------ JavaScript-Bibliotheken
LIB_FILE = {
    "jquery-ui": re.compile(r"^jquery[.-]ui([.-]\d[\d.]*)?(\.min)?\.js$", re.I),
    "jquery": re.compile(r"^jquery([.-]\d[\d.]*)?(\.min)?\.js$", re.I),
    "bootstrap": re.compile(r"^bootstrap(\.bundle)?([.-]\d[\d.]*)?(\.min)?\.js$", re.I),
    "moment": re.compile(r"^moment([.-]\d[\d.]*)?(\.min)?\.js$", re.I),
}
BANNER_NAME = {"jquery-ui": re.compile(r"jquery ui", re.I), "jquery": re.compile(r"^jquery(?! ui)", re.I), "bootstrap": re.compile(r"bootstrap", re.I), "moment": re.compile(r"version|moment", re.I)}
VERSION_RX = re.compile(r"\d+\.\d+(?:\.\d+)?")
JS_SCRIPT = r"""
find . -maxdepth 9 \( -path '*/node_modules' -o -path '*/.git' -o -path './tmp' -o -path './cache' -o -path './wp-content/cache' \) -prune -o -type f \( -iname 'jquery*.js' -o -iname 'bootstrap*.js' -o -iname 'moment*.js' \) -print 2>/dev/null | head -n 300 | while IFS= read -r f; do
  printf '@@F\t%s\n' "$f"
  head -c 3000 "$f" 2>/dev/null | tr -d '\000' | grep -a -m1 -oiE '(jquery( ui| javascript library)?|bootstrap|moment|version)[^0-9a-z]{0,24}v?[0-9]+\.[0-9]+(\.[0-9]+)?' | head -n 1
done
"""


def lib_of(path: str, banner: str) -> Optional[Dict[str, str]]:
    base = os.path.basename(path)
    for name in ("jquery-ui", "jquery", "bootstrap", "moment"):       # jquery-ui vor jquery: der engere Name zuerst
        if LIB_FILE[name].match(base):
            ver = ""
            if banner and BANNER_NAME[name].search(banner):
                m = VERSION_RX.search(banner)
                ver = m.group(0) if m else ""
            if not ver:
                m = VERSION_RX.search(base)
                ver = m.group(0) if m else ""
            return {"name": name, "version": ver, "path": path[2:] if path.startswith("./") else path}
    return None


def parse_js(out: str) -> List[Dict[str, str]]:
    libs: List[Dict[str, str]] = []
    path, banner = None, ""

    def flush():
        if path:
            lib = lib_of(path, banner)
            if lib:
                libs.append(lib)
    for ln in (out or "").splitlines():
        if ln.startswith("@@F\t"):
            flush()
            path, banner = ln[4:], ""
        elif path is not None and not banner:
            banner = ln.strip()
    flush()
    return libs


@check(
    "js_libs", "dateien", "Veraltete JavaScript-Bibliotheken auf dem Server",
    "Liegen alte Versionen von jQuery, jQuery UI, Bootstrap oder Moment.js im Verzeichnis?",
    what="Sucht im Seitenverzeichnis nach Dateien von jQuery, jQuery UI, Bootstrap und Moment.js, liest die Version aus dem Kommentar am Dateianfang und vergleicht sie mit einer kleinen Liste bekannter Lücken (jQuery bis 3.4, jQuery UI bis 1.13.1, "
         "Bootstrap 3 bis 3.4.0 und 4 bis 4.3.0, Moment.js 2.18.0 bis 2.29.3). Ob die Seite eine gefundene Datei auch lädt, wird hier nicht geprüft.",
    why="Alte Bibliotheken haben bekannte Lücken (Skripteinschleusung im Browser des Besuchers). Besonders alte Erweiterungen und Templates bringen sie mit.",
    reads="Nur Dateinamen und die ersten Zeilen (Versionskommentar) der Bibliotheksdateien. Es wird nichts verändert. Die Liste der Lücken ist klein und bewusst vorsichtig; sie ist keine vollständige Schwachstellen-Datenbank.",
    load="leicht", needs="ssh", presets=["schnell"],
)
def js_libs(ctx, res):
    ctx.progress("JavaScript-Bibliotheken suchen")
    libs = parse_js(ctx.sh(JS_SCRIPT, timeout=90).out)
    if not libs:
        res.add("info", "Keine der geprüften JavaScript-Bibliotheken gefunden", "Es wurden keine Dateien von jQuery, jQuery UI, Bootstrap oder Moment.js gefunden.")
        return
    _emit(res, au.judge_js_libs(libs))
