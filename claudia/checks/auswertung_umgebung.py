"""CLAUDIA: reine Auswertefunktionen für Server und Umgebung (Paket B).

Jede Funktion bekommt schon eingelesene Daten und gibt eine Liste von Befunden zurück:
    List[Tuple[sev, titel, text, items, hint]]
Es wird nichts gelesen, nichts verändert und keine Uhr benutzt (die Zeit kommt als now_epoch).
Die Funktionen stürzen nie ab: Bei unbrauchbarer Eingabe kommt genau ein Befund der Stufe "info".
"""
from __future__ import annotations

import calendar
import datetime
import re
import statistics
from typing import Any, Dict, List, Optional, Tuple

from .auswertung_joomla import Finding, _clean, _f, _np, _num, _to_flag  # gemeinsame Hilfsfunktionen (früher doppelt)

_DAY = 86400


# ---------------------------------------------------------------------------
# Hilfsfunktionen
# ---------------------------------------------------------------------------

def _size_text(size: float) -> str:
    if size < 1024:
        return "%d Byte" % size
    if size < 1048576:
        return "%d KB" % (size // 1024)
    return "%d MB" % (size // 1048576)


# ---------------------------------------------------------------------------
# 1. Klartext-Zugangsdaten
# ---------------------------------------------------------------------------

_CRED_NAMES = (".my.cnf", ".netrc", ".git-credentials", ".env")


def _octal(v: Any) -> Optional[int]:
    if isinstance(v, str) and re.fullmatch(r"\s*0?[0-7]{3,4}\s*", v):
        return int(v.strip(), 8)
    return None


def judge_plaintext_creds(entries, account_user):
    """Dateien mit Klartext-Zugangsdaten: nur Name, Rechte, Besitzer, Größe und Lage. Inhalte werden nie gelesen."""
    user = _clean(account_user, 60)
    if not isinstance(entries, list) or not user:
        return _np("Klartext-Zugangsdaten", "Die Dateiliste oder der Name des Server-Kontos fehlt oder ist unlesbar.")
    usable = 0
    crit: List[str] = []
    warn: List[str] = []
    info: List[str] = []
    for e in entries:
        if not isinstance(e, dict):
            continue
        path = _clean(e.get("path"), 200)
        name = _clean(e.get("name"), 60) or path.rsplit("/", 1)[-1]
        if not path and not name:
            continue
        usable += 1
        if name not in _CRED_NAMES:
            continue
        size = _num(e.get("size"))
        if size is not None and size <= 0:
            continue
        mode_txt = _clean(e.get("mode"), 8) if isinstance(e.get("mode"), str) else ""
        mode = _octal(e.get("mode"))
        web = _to_flag(e.get("in_webroot"))
        owner = _clean(e.get("owner"), 40)
        parts = ["Rechte %s" % mode_txt if mode is not None else "Rechte nicht lesbar"]
        if owner:
            parts.append("Besitzer %s" % owner + ("" if owner == user else " (nicht das Konto %s)" % user))
        if web is True:
            parts.append("im Webroot")
        item = "%s (%s)" % (path or name, ", ".join(parts))
        if mode is None:
            info.append(item)
        elif web is True and mode & 0o004:
            crit.append(item)
        elif web is True or mode & 0o077:
            warn.append(item)
        else:
            info.append(item)
    if entries and usable == 0:
        return _np("Klartext-Zugangsdaten", "In der Dateiliste wurde kein lesbarer Eintrag gefunden.")
    out: List[Finding] = []
    if crit:
        out.append(_f(
            "crit", "Zugangsdaten-Datei im Webroot ist für alle lesbar",
            "Solche Dateien enthalten Passwörter im Klartext. Diese liegt im Webroot (dem öffentlichen Ordner der Webseite) und darf von allen gelesen werden. "
            "Je nach Servereinstellung kann sie aus dem Internet abrufbar sein. Der Inhalt wurde nicht gelesen.",
            sorted(crit),
            "Datei aus dem Webroot entfernen, die darin stehenden Passwörter ändern und die Rechte auf 600 setzen (nur der Besitzer darf lesen und schreiben)."))
    if warn:
        out.append(_f(
            "warn", "Zugangsdaten-Datei mit offenen Rechten oder im Webroot",
            "Solche Dateien enthalten Passwörter im Klartext. Diese hier sind zu offen eingestellt oder liegen im Webroot (dem öffentlichen Ordner der Webseite). "
            "Der Inhalt wurde nicht gelesen.",
            sorted(warn),
            "Rechte auf 600 setzen (nur der Besitzer darf lesen und schreiben) und Dateien im Webroot nach außerhalb verschieben oder löschen."))
    if info:
        out.append(_f(
            "info", "Zugangsdaten-Datei mit strengen Rechten vorhanden",
            "Die Datei enthält vermutlich Passwörter im Klartext. Die Rechte sind streng und sie liegt nicht im Webroot. Der Inhalt wurde nicht gelesen.",
            sorted(info),
            "Löschen Sie die Datei, wenn Sie sie nicht mehr brauchen."))
    if not out:
        return [_f("ok", "Keine Datei mit Klartext-Zugangsdaten gefunden",
                   "Gesucht wurde nach .my.cnf, .netrc, .git-credentials und .env. Inhalte werden nie gelesen.")]
    return out


# ---------------------------------------------------------------------------
# 2. Alter der Sicherungen
# ---------------------------------------------------------------------------

def judge_backup_age(entries, now_epoch):
    """Sicherungen (Archive) im Konto: Alter, Lesbarkeit und Größe. Aussage nur über dieses Konto."""
    now = _num(now_epoch)
    if not isinstance(entries, list) or now is None or now <= 0:
        return _np("Sicherungen im Konto", "Die Liste der Sicherungen oder die Zeitangabe fehlt oder ist unlesbar.")
    valid = []
    for e in entries:
        if not isinstance(e, dict) or not isinstance(e.get("path"), str):
            continue
        size = _num(e.get("size"))
        mtime = _num(e.get("mtime"))
        if size is None or size < 0 or mtime is None or mtime <= 0:
            continue
        rc = e.get("test_rc")
        rc = rc if isinstance(rc, int) and not isinstance(rc, bool) else None
        valid.append((mtime, _clean(e["path"], 200), size, rc))
    if entries and not valid:
        return _np("Sicherungen im Konto", "In der Liste wurde kein lesbarer Eintrag gefunden.")
    if not valid:
        return [_f("info", "Keine Sicherung auf diesem Konto gefunden",
                   "Gesucht wurde nach Archiven wie .tar.gz, .tgz und .gz im Konto. Sicherungen, die Ihr Hoster selbst anlegt, sind hier nicht sichtbar.",
                   [],
                   "Prüfen Sie im Hosting-Paket, ob Ihr Anbieter Sicherungen anlegt. Wenn nicht, legen Sie regelmäßig eigene an.")]
    valid.sort(key=lambda v: (-v[0], v[1]))
    newest, others = valid[0], valid[1:]
    mtime, path, size, rc = newest
    age = max(0, int((now - mtime) // _DAY))
    desc = "%s (%s, %d Tage alt)" % (path, _size_text(size), age)
    scope = "Das sagt nichts über Sicherungen, die Ihr Hoster selbst anlegt."
    out: List[Finding] = []
    if age >= 31:
        out.append(_f(
            "warn", "Die neueste Sicherung auf diesem Konto ist %d Tage alt" % age,
            "Die neueste gefundene Sicherung ist älter als 30 Tage. Bei einem Schaden gingen die Änderungen seitdem verloren. %s" % scope,
            [desc],
            "Legen Sie eine frische Sicherung an und richten Sie eine regelmäßige ein."))
    if rc is not None and rc != 0:
        out.append(_f(
            "warn", "Die neueste Sicherung ist beschädigt",
            "Der Test, ob sich das Archiv lesen lässt, ist fehlgeschlagen. Eine beschädigte Sicherung hilft im Ernstfall nicht.",
            [desc],
            "Legen Sie eine neue Sicherung an und prüfen Sie, ob sie sich öffnen lässt."))
    elif size == 0:
        out.append(_f(
            "warn", "Die neueste Sicherung ist leer",
            "Die Datei hat die Größe null und enthält keine Daten.",
            [desc],
            "Legen Sie eine neue Sicherung an und prüfen Sie, ob sie Daten enthält."))
    else:
        sizes = [o[2] for o in others if o[2] > 0]
        if sizes and size * 10 < statistics.median(sizes):
            out.append(_f(
                "warn", "Die neueste Sicherung ist auffällig klein",
                "Sie ist weniger als ein Zehntel so groß wie die übrigen Sicherungen. Vielleicht fehlen Daten.",
                [desc],
                "Prüfen Sie den Inhalt der Sicherung und legen Sie bei Bedarf eine neue an."))
        if rc is None:
            out.append(_f(
                "info", "Die neueste Sicherung konnte nicht auf Lesbarkeit geprüft werden",
                "Der Test, ob sich das Archiv öffnen lässt, war nicht möglich. Ob die Sicherung brauchbar ist, ist unbekannt.",
                [desc]))
    broken = ["%s (%d Tage alt)" % (o[1], max(0, int((now - o[0]) // _DAY))) for o in others if o[3] is not None and o[3] != 0]
    if broken:
        out.append(_f(
            "info", "%d ältere Sicherung(en) sind beschädigt" % len(broken),
            "Ältere Archive lassen sich nicht lesen. Die neueste Sicherung ist davon nicht betroffen.",
            broken,
            "Beschädigte Archive können gelöscht werden."))
    if not out:
        return [_f("ok", "Die neueste Sicherung ist %d Tage alt und lesbar" % age,
                   "Gefunden wurde mindestens eine Sicherung auf diesem Konto. %s" % scope, [desc])]
    return out


# ---------------------------------------------------------------------------
# 3. TLS-Protokolle
# ---------------------------------------------------------------------------

_TLS_NAMES = {"tlsv1": "1.0", "tlsv1.0": "1.0", "tlsv1.1": "1.1", "tlsv1.2": "1.2", "tlsv1.3": "1.3"}


def judge_tls(handshakes):
    """TLS-Protokolle der Webseite, je Protokoll ein Verbindungsversuch."""
    if not isinstance(handshakes, list):
        return _np("TLS-Protokolle", "Die Ergebnisse der Verbindungsversuche fehlen oder sind unlesbar.")
    seen: Dict[str, set] = {}
    for h in handshakes:
        if not isinstance(h, dict) or not isinstance(h.get("protocol"), str):
            continue
        ver = _TLS_NAMES.get(h["protocol"].strip().lower().replace(" ", ""))
        if ver is None:
            continue
        res = h.get("result")
        res = res.strip().lower() if isinstance(res, str) else ""
        seen.setdefault(ver, set()).add(res if res in ("accepted", "refused") else "unknown")
    if not seen:
        return _np("TLS-Protokolle", "Es liegt kein lesbares Ergebnis eines Verbindungsversuchs vor.")
    state = {v: (next(iter(s)) if len(s) == 1 else "unknown") for v, s in seen.items()}

    def st(v: str) -> str:
        return state.get(v, "unknown")

    out: List[Finding] = []
    old_acc = [v for v in ("1.0", "1.1") if st(v) == "accepted"]
    if old_acc:
        out.append(_f(
            "warn", "Veraltete TLS-Version wird angenommen: %s" % ", ".join("TLS " + v for v in old_acc),
            "TLS ist die Verschlüsselung der Verbindung zu Ihrer Webseite. Die Versionen 1.0 und 1.1 gelten seit Jahren als überholt. "
            "Der Server sollte nur TLS 1.2 und 1.3 anbieten.",
            ["TLS %s: angenommen" % v for v in old_acc],
            "Bitten Sie Ihren Hoster, TLS 1.0 und 1.1 abzuschalten, oder stellen Sie es in der Servereinstellung ein."))
    if st("1.2") != "accepted" and st("1.3") != "accepted":
        if st("1.2") == "refused" and st("1.3") == "refused":
            out.append(_f(
                "warn", "Keine moderne TLS-Version bestätigt",
                "Der Server hat TLS 1.2 und TLS 1.3 abgelehnt. Moderne Browser können dann unter Umständen keine sichere Verbindung aufbauen.",
                ["TLS 1.2: abgelehnt", "TLS 1.3: abgelehnt"],
                "Bitten Sie Ihren Hoster, TLS 1.2 und 1.3 einzuschalten."))
        else:
            out.append(_f(
                "info", "TLS 1.2 und 1.3 konnten nicht sicher bestätigt werden",
                "Die Verbindungsversuche waren nicht aussagekräftig, zum Beispiel weil das Prüfwerkzeug ein Protokoll nicht kann. Eine Aussage ist nicht möglich."))
    else:
        if st("1.2") == "accepted" and st("1.3") != "accepted":
            if st("1.3") == "refused":
                out.append(_f(
                    "info", "TLS 1.3 wird nicht angeboten",
                    "Die Seite nutzt TLS 1.2. Das ist in Ordnung. TLS 1.3 ist die neuere Version und wäre zusätzlich wünschenswert.",
                    ["TLS 1.3: abgelehnt"],
                    "Fragen Sie Ihren Hoster, ob TLS 1.3 eingeschaltet werden kann."))
            else:
                out.append(_f(
                    "info", "TLS 1.3 nicht bestätigt",
                    "Die Seite nutzt TLS 1.2. Ob auch TLS 1.3 angeboten wird, ließ sich nicht klären."))
        unknown_old = [v for v in ("1.0", "1.1") if st(v) == "unknown"]
        if unknown_old:
            out.append(_f(
                "info", "Alte TLS-Versionen nicht prüfbar",
                "Für %s war der Verbindungsversuch nicht aussagekräftig. Es ist daher nicht belegt, dass sie abgeschaltet sind." % " und ".join("TLS " + v for v in unknown_old),
                ["TLS %s: unbekannt" % v for v in unknown_old]))
    if not out:
        return [_f("ok", "Nur moderne TLS-Versionen werden angeboten",
                   "TLS 1.2 und 1.3 werden angenommen, TLS 1.0 und 1.1 werden abgelehnt.")]
    return out


# ---------------------------------------------------------------------------
# 4. Cookie-Flags
# ---------------------------------------------------------------------------

def _cookie_kind(name: str) -> Tuple[str, str]:
    """-> (Art, Anzeigename). Art: 'sitzung' oder 'anderes'. Hex-Namen und Namenszusätze werden nie ausgegeben."""
    low = name.lower()
    if re.fullmatch(r"[0-9a-f]{32}", low):
        return "sitzung", "Joomla-Sitzungs-Cookie"
    if low == "phpsessid":
        return "sitzung", "Sitzungs-Cookie (PHPSESSID)"
    if low.startswith("wordpress_logged_in_"):
        return "sitzung", "WordPress-Anmelde-Cookie (wordpress_logged_in_*)"
    if low.startswith("wordpress_sec_"):
        return "sitzung", "WordPress-Sicherheits-Cookie (wordpress_sec_*)"
    return "anderes", "Cookie " + (_clean(name, 60) or "ohne Namen")


def judge_cookies(cookies, https):
    """Cookie-Flags aus den Set-Cookie-Kopfzeilen der Startseite. Cookie-Werte werden nie benutzt."""
    flag = _to_flag(https) if isinstance(https, (bool, int)) else None
    if not isinstance(cookies, list) or flag is None:
        return _np("Cookie-Einstellungen", "Die Cookie-Liste oder die Angabe, ob https benutzt wurde, fehlt oder ist unlesbar.")
    if flag is False:
        return [_f("info", "Cookie-Flags ohne https nicht bewertbar",
                   "Die Seite wurde nicht über https abgerufen. Das Flag Secure lässt sich dann nicht sinnvoll beurteilen.",
                   [], "Richten Sie https für die ganze Seite ein.")]
    sess_missing: Dict[str, List[str]] = {}
    samesite: List[str] = []
    other_missing: List[str] = []
    usable = 0
    for c in cookies:
        if not isinstance(c, dict) or not isinstance(c.get("name"), str) or not c["name"].strip():
            continue
        attrs = c.get("attrs")
        if attrs is None:
            attrs = ""
        if not isinstance(attrs, str):
            continue
        usable += 1
        kind, label = _cookie_kind(c["name"].strip())
        parts = [p.strip().lower() for p in attrs.split(";")]
        secure = "secure" in parts
        httponly = "httponly" in parts
        none_site = any(re.fullmatch(r"samesite\s*=\s*none", p) for p in parts)
        if kind == "sitzung":
            miss = [n for n, ok in (("Secure", secure), ("HttpOnly", httponly)) if not ok]
            if miss:
                sess_missing.setdefault(label, [])
                sess_missing[label] = sorted(set(sess_missing[label]) | set(miss))
        elif not secure:
            other_missing.append(label)
        if none_site and not secure:
            samesite.append(label)
    if cookies and usable == 0:
        return _np("Cookie-Einstellungen", "In der Cookie-Liste wurde kein lesbarer Eintrag gefunden.")
    if not cookies:
        return [_f("info", "Die Startseite setzt keine Cookies",
                   "Es gab keine Cookies zu bewerten. Cookies, die erst nach einer Anmeldung gesetzt werden, sind hier nicht erfasst.")]
    out: List[Finding] = []
    if sess_missing:
        out.append(_f(
            "warn", "Sitzungs-Cookies ohne Schutz-Flags",
            "Secure sorgt dafür, dass das Cookie nur über eine verschlüsselte Verbindung gesendet wird. HttpOnly verhindert, dass Skripte auf der Seite es lesen. "
            "Fehlt eines davon, lässt sich ein Sitzungs-Cookie leichter stehlen.",
            ["%s: %s fehlt" % (lab, " und ".join(m)) for lab, m in sorted(sess_missing.items())],
            "Stellen Sie in den PHP-Einstellungen session.cookie_secure und session.cookie_httponly auf 1 oder bitten Sie Ihren Hoster darum."))
    if samesite:
        out.append(_f(
            "warn", "SameSite=None ohne Secure",
            "Ein Cookie mit SameSite=None muss auch Secure tragen. Sonst lehnen Browser es ab oder es wird unsicher übertragen.",
            sorted(set(samesite)),
            "Setzen Sie bei diesen Cookies das Flag Secure oder wählen Sie SameSite=Lax."))
    if other_missing:
        out.append(_f(
            "info", "Weitere Cookies ohne Secure",
            "Diese Cookies könnten auch über eine unverschlüsselte Verbindung gesendet werden. Bei Cookies ohne Anmeldedaten ist das meist unkritisch.",
            sorted(set(other_missing)),
            "Wenn möglich, das Flag Secure setzen."))
    if not out:
        return [_f("ok", "Die Cookie-Flags sind in Ordnung",
                   "Es wurden %d Cookies der Startseite geprüft." % usable)]
    return out


# ---------------------------------------------------------------------------
# 5. JavaScript-Bibliotheken
# ---------------------------------------------------------------------------

# name, von (einschließlich), bis (ausschließlich), Grund, Stufe. Quellen: siehe ANNAHMEN.md
_JS_TABLE = (
    ("jquery", (0, 0, 0), (3, 5, 0), "XSS-Lücken (Schadcode über Eingaben), behoben ab 3.5.0", "warn"),
    ("jquery-ui", (0, 0, 0), (1, 13, 2), "XSS-Lücke (Schadcode über Eingaben), behoben ab 1.13.2", "warn"),
    ("bootstrap", (3, 0, 0), (3, 4, 1), "XSS-Lücke in Tooltip und Popover, behoben ab 3.4.1", "warn"),
    ("bootstrap", (4, 0, 0), (4, 3, 1), "XSS-Lücke in Tooltip und Popover, behoben ab 4.3.1", "warn"),
    ("moment", (2, 18, 0), (2, 29, 4), "ReDoS (sehr lange Eingaben können den Server ausbremsen), behoben ab 2.29.4", "info"),
)
_JS_KNOWN = frozenset(r[0] for r in _JS_TABLE)
_JS_NOTE = "Die Datei liegt auf dem Server; ob die Seite sie lädt, ist hier nicht geprüft."


def _version(v: Any) -> Optional[Tuple[str, Tuple[int, int, int]]]:
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        v = repr(v)
    if not isinstance(v, str):
        return None
    m = re.match(r"\s*v?(\d+(?:\.\d+){0,3})", v)
    if not m:
        return None
    nums = [int(x) for x in m.group(1).split(".")][:3]
    while len(nums) < 3:
        nums.append(0)
    return m.group(1), (nums[0], nums[1], nums[2])


def judge_js_libs(libs):
    """Veraltete JavaScript-Bibliotheken (Dateien auf dem Server)."""
    if not isinstance(libs, list):
        return _np("JavaScript-Bibliotheken", "Die Liste der Bibliotheken fehlt oder ist unlesbar.")
    groups: Dict[Tuple[str, str], Tuple[str, List[str]]] = {}
    unreadable: Dict[str, int] = {}
    valid = 0
    for lib in libs:
        if not isinstance(lib, dict) or not isinstance(lib.get("name"), str) or not lib["name"].strip():
            continue
        valid += 1
        name = lib["name"].strip().lower()
        if name not in _JS_KNOWN:
            continue
        path = _clean(lib.get("path"), 120) or "(Pfad unbekannt)"
        ver = _version(lib.get("version"))
        if ver is None:
            unreadable[name] = unreadable.get(name, 0) + 1
            continue
        text, tup = ver
        hit = next((r for r in _JS_TABLE if r[0] == name and r[1] <= tup < r[2]), None)
        if hit is None:
            continue
        key = (name, text)
        groups.setdefault(key, (hit[3] + "|" + hit[4], []))[1].append(path)
    if not libs:
        return _np("JavaScript-Bibliotheken", "Es wurde keine JavaScript-Bibliothek übergeben. Eine Aussage ist nicht möglich.")
    if valid == 0:
        return _np("JavaScript-Bibliotheken", "In der Liste wurde kein lesbarer Eintrag gefunden.")
    items = {"warn": [], "info": []}
    for (name, text), (meta, paths) in sorted(groups.items()):
        reason, sev = meta.split("|")
        paths = sorted(set(paths))
        where = "1 Datei: %s" % paths[0] if len(paths) == 1 else "%d Dateien, z. B. %s" % (len(paths), ", ".join(paths[:2]))
        items[sev].append("%s %s: %s (%s)" % (name, text, reason, where))
    out: List[Finding] = []
    if items["warn"]:
        out.append(_f(
            "warn", "Veraltete JavaScript-Bibliotheken auf dem Server (%d)" % len(items["warn"]),
            "Diese Bibliotheken sind in alten Versionen von bekannten Lücken betroffen. %s" % _JS_NOTE,
            items["warn"],
            "Aktualisieren Sie Joomla, WordPress und die Erweiterungen oder das Template, die diese Datei mitbringen. Ersetzen Sie die Datei nicht von Hand."))
    info_items = list(items["info"])
    if unreadable:
        info_items.append("Version nicht lesbar: %s (%d Datei(en))" % (", ".join(sorted(unreadable)), sum(unreadable.values())))
    if info_items:
        out.append(_f(
            "info", "Hinweise zu JavaScript-Bibliotheken",
            "Diese Bibliotheken sind veraltet oder ihre Version ließ sich nicht lesen. %s" % _JS_NOTE,
            info_items,
            "Prüfen Sie bei Gelegenheit, ob Erweiterungen oder das Template aktualisiert werden können."))
    if not out:
        return [_f("ok", "Keine veralteten JavaScript-Bibliotheken aus der Prüftabelle gefunden",
                   "Geprüft wurden jQuery, jQuery UI, Bootstrap und Moment. %s" % _JS_NOTE)]
    return out


# ---------------------------------------------------------------------------
# 6. Alter der Erweiterungen
# ---------------------------------------------------------------------------

_INFO_DAYS = 730
_WARN_DAYS = 1460


def _date_epoch(v: Any) -> Optional[int]:
    if not isinstance(v, str):
        return None
    m = re.match(r"\s*(\d{4})-(\d{2})-(\d{2})", v)
    if not m:
        return None
    try:
        d = datetime.date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
    except ValueError:
        return None
    return calendar.timegm(d.timetuple())


def judge_ext_age(exts, now_epoch):
    """Lange nicht aktualisierte Erweiterungen. Es wird nie behauptet, dass eine Lücke besteht."""
    now = _num(now_epoch)
    if not isinstance(exts, list) or now is None or now <= 0:
        return _np("Alter der Erweiterungen", "Die Liste der Erweiterungen oder die Zeitangabe fehlt oder ist unlesbar.")
    if not exts:
        return _np("Alter der Erweiterungen", "Es wurde keine Erweiterung übergeben. Eine Aussage ist nicht möglich.")
    valid = 0
    old_warn: List[Tuple[str, str]] = []
    old_info: List[Tuple[str, str]] = []
    unknown: List[str] = []
    for e in exts:
        if not isinstance(e, dict) or not _clean(e.get("name"), 80):
            continue
        valid += 1
        if _to_flag(e.get("core")) is True:
            continue
        name = _clean(e.get("name"), 80)
        typ = _clean(e.get("type"), 20)
        ver = e.get("version")
        ver = _clean(ver if isinstance(ver, str) else (repr(ver) if isinstance(ver, (int, float)) and not isinstance(ver, bool) else ""), 20)
        label = name + " (" + ", ".join(x for x in (typ, "Version " + ver if ver else "") if x) + ")" if (typ or ver) else name
        enabled = _to_flag(e.get("enabled")) is True
        ep = _date_epoch(e.get("last_update"))
        if ep is None:
            unknown.append(label)
            continue
        days = (now - ep) / _DAY
        if days <= _INFO_DAYS:
            continue
        line = "%s: zuletzt aktualisiert %s, vor %d Tagen" % (label, _clean(e.get("last_update"), 10), int(days))
        if days > _WARN_DAYS and enabled:
            old_warn.append((name, line))
        else:
            old_info.append((name, line + ("" if enabled else ", deaktiviert")))
    if valid == 0:
        return _np("Alter der Erweiterungen", "In der Liste wurde kein lesbarer Eintrag gefunden.")
    out: List[Finding] = []
    if old_warn:
        out.append(_f(
            "warn", "%d aktive Erweiterung(en) seit über vier Jahren nicht aktualisiert" % len(old_warn),
            "Diese Erweiterungen sind aktiviert und wurden lange nicht aktualisiert. Vermutlich wird sie der Hersteller nicht mehr pflegen.",
            [l for _, l in sorted(old_warn)],
            "Prüfen Sie, ob es eine neuere Version oder einen Nachfolger gibt. Erweiterungen, die Sie nicht brauchen, können Sie entfernen."))
    if old_info:
        out.append(_f(
            "info", "%d Erweiterung(en) lange nicht aktualisiert" % len(old_info),
            "Diese Erweiterungen wurden seit über zwei Jahren nicht aktualisiert oder sind abgeschaltet. Das ist nur ein Hinweis.",
            [l for _, l in sorted(old_info)],
            "Prüfen Sie bei Gelegenheit, ob es neuere Versionen gibt."))
    if unknown:
        out.append(_f(
            "info", "Bei %d Erweiterung(en) ist das Datum der letzten Aktualisierung unbekannt" % len(unknown),
            "Für diese Erweiterungen konnte kein Datum gelesen werden. Eine Aussage zum Alter ist nicht möglich.",
            sorted(unknown)))
    if not out:
        return [_f("ok", "Keine auffällig alten Erweiterungen",
                   "Alle geprüften Erweiterungen wurden in den letzten zwei Jahren aktualisiert oder gehören zum Kern.")]
    return out
