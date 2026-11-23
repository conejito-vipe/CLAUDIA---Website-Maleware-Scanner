"""Joomla-Einstellungen und Konten aus der Datenbank (2.5.0): Textfilter, Upload-Endungen, Registrierung, Zwei-Faktor, Admin-Anmeldungen, Alter der Erweiterungen; dazu Zwei-Faktor-Plugins bei WordPress.

Die Bewertung steckt in den reinen Funktionen von auswertung_joomla.py und auswertung_umgebung.py (ausgelagert, mit Beispieldateien geprüft). Hier stehen nur die Abfragen (nur SELECT) und die Anbindung.
Geheimnisse: Es werden nie Schlüsseldaten der Zwei-Faktor-Tabelle, Passwörter oder Tokens gelesen. Joomla-Feldnamen (com_config, com_media, com_users, user_mfa, action_logs) stammen aus der Kenntnis der Joomla-Quellen
und sind gegen eine echte Joomla-Installation noch NICHT geprüft; fehlt ein Feld, meldet die Prüfung 'nicht prüfbar' statt zu raten."""
from __future__ import annotations

import datetime
import json
import re
import time
from typing import Any, Dict, List, Optional, Tuple

from ..model import CheckSkipped
from ..registry import check
from . import auswertung_joomla as aj
from . import auswertung_umgebung as au
from .database import fetch, need_db
from .logs import geo_of
from ..util import digits

G = "datenbank"
Q_PARAMS = "SELECT params FROM #__extensions WHERE type = 'component' AND element = '%s' LIMIT 1"
Q_GROUPS = "SELECT id, parent_id, title FROM #__usergroups ORDER BY id"
Q_ROOT = "SELECT rules FROM #__assets WHERE name = 'root.1' LIMIT 1"
Q_MFA_PLUGINS = "SELECT element FROM #__extensions WHERE type = 'plugin' AND folder = 'multifactorauth' AND enabled = 1"
Q_MFA_ROWS = "SELECT user_id, method FROM #__user_mfa"
Q_ADMINS = ("SELECT DISTINCT u.id AS id, u.username AS username, u.block AS block FROM #__users u JOIN #__user_usergroup_map m ON m.user_id = u.id "
            "WHERE m.group_id IN (%s) ORDER BY u.id LIMIT 500")
Q_LOGINS = ("SELECT log_date, user_id, ip_address, message_language_key AS aktion, SUBSTRING(message, 1, 400) AS meldung FROM #__action_logs "
            "WHERE message_language_key IN ('PLG_ACTIONLOG_JOOMLA_USER_LOGGED_IN', 'PLG_ACTIONLOG_JOOMLA_USER_LOGIN_FAILED') ORDER BY id DESC LIMIT 2000")
Q_EXT = "SELECT name, type, element, folder, enabled, protected, manifest_cache FROM #__extensions LIMIT 3000"
DEFAULT_ADMIN_GROUPS = (6, 7, 8)


def _emit(res, rows) -> None:
    for sev, title, text, items, hint in rows:
        res.add(sev, title, text, items, hint)


def _json(text: Any) -> Any:
    try:
        return json.loads(text) if isinstance(text, str) and text.strip() else None
    except ValueError:
        return None


def component_params(db, element: str) -> Optional[Dict[str, Any]]:
    """Parameter einer Komponente als Wörterbuch (None: Tabelle oder Eintrag fehlt, Text ist kein JSON)."""
    rows = fetch(db, Q_PARAMS % element)
    if not rows:
        return None
    d = _json(rows[0].get("params"))
    return d if isinstance(d, dict) else None


def group_list(db) -> List[Dict[str, Any]]:
    out = []
    for r in fetch(db, Q_GROUPS) or []:
        try:
            out.append({"id": int(r.get("id")), "parent_id": int(r.get("parent_id") or 0), "title": str(r.get("title") or "")})
        except (TypeError, ValueError):
            continue
    return out


def _allowed(rules: Dict[str, Any], key: str, gid: int, parent: Dict[int, int]) -> Optional[bool]:
    """Nächster ausdrücklicher Eintrag auf dem Weg von der Gruppe nach oben (Joomla vererbt Rechte an Untergruppen). None = nirgends gesetzt."""
    entry = rules.get(key)
    if not isinstance(entry, dict):
        return None
    cur, steps = gid, 0
    while cur and steps < 30:
        v = entry.get(str(cur))
        if v in (1, "1", True):
            return True
        if v in (0, "0", False):
            return False
        cur = parent.get(cur, 0)
        steps += 1
    return None


def backend_map(db, groups: List[Dict[str, Any]]) -> Dict[int, Optional[bool]]:
    """Gruppen-ID -> darf sich im Backend anmelden (True/False) oder None, wenn die Rechte nicht lesbar sind.
    Gelesen wird nur die Wurzel der Rechte (root.1: core.login.admin und core.admin); Rechte, die an Komponenten oder Erweiterungen überschrieben werden, sind nicht erfasst."""
    rows = fetch(db, Q_ROOT)
    rules = _json(rows[0].get("rules")) if rows else None
    if not isinstance(rules, dict):
        return {g["id"]: None for g in groups}
    parent = {g["id"]: g["parent_id"] for g in groups}
    out: Dict[int, Optional[bool]] = {}
    for g in groups:
        a = _allowed(rules, "core.login.admin", g["id"], parent)
        b = _allowed(rules, "core.admin", g["id"], parent)
        out[g["id"]] = bool(a or b)
    return out


# ------------------------------------------------------------------ Textfilter
@check(
    "db_textfilter", G, "Textfilter der Benutzergruppen",
    "Dürfen Benutzergruppen beliebiges HTML oder Skripte in Texte schreiben?",
    what="Liest in der Joomla-Konfiguration (Komponente com_config) für jede Benutzergruppe die Einstellung 'Textfilter': Standard-Sperrliste, eigene Sperrliste, Positivliste, kein HTML oder kein Filter. "
         "Bewertet, ob eine Gruppe ohne Filter arbeitet (außer Super Users) oder in einer Positivliste Skripte, iframe, object oder embed erlaubt.",
    why="Der Textfilter entfernt gefährliches HTML aus Beiträgen. Ist er für eine Gruppe aus, kann ein Konto dieser Gruppe (oder ein Angreifer, der es übernimmt) Skripte in Beiträge schreiben, "
        "die Besucher infizieren oder deren Anmeldung stehlen.",
    reads="Nur die Textfilter-Einstellungen und die Namen der Benutzergruppen aus der Datenbank. Es wird nichts verändert.",
    load="leicht", needs="db", presets=["schnell", "hack"],
)
def db_textfilter(ctx, res):
    db = need_db(ctx, res, "Textfilter", [("Konfiguration", Q_PARAMS % "com_config"), ("Gruppen", Q_GROUPS)])
    params = component_params(db, "com_config")
    groups = group_list(db)
    titles = {g["id"]: g["title"] for g in groups}
    filters = (params or {}).get("filters")
    rows: List[Dict[str, Any]] = []
    if isinstance(filters, dict):
        for k, v in filters.items():
            if not (isinstance(v, dict) and digits(str(k))):
                continue
            rows.append({"group_id": int(k), "title": titles.get(int(k), "Gruppe %s" % k), "filter_type": str(v.get("filter_type", "")),
                         "filter_tags": str(v.get("filter_tags", "")), "filter_attributes": str(v.get("filter_attributes", ""))})
    rows.sort(key=lambda r: r["group_id"])
    _emit(res, aj.judge_textfilter(rows if rows else None))


# ------------------------------------------------------------------ Upload-Endungen
@check(
    "db_upload_ext", G, "Erlaubte Upload-Endungen der Medien",
    "Dürfen über die Medienverwaltung ausführbare Dateien hochgeladen werden?",
    what="Liest die Einstellungen der Medienverwaltung (com_media): erlaubte Endungen, ausgenommene Endungen, Einschränkung der Uploads und MIME-Prüfung. "
         "Meldet gefährliche Endungen (PHP und Verwandte, CGI, Skripte, Programme) als kritisch, aktiv ausführbare Webdateien (html, js, svg, xml) als 'bitte prüfen'.",
    why="Wer eine PHP-Datei hochladen kann, kann den Server übernehmen. Die Liste der erlaubten Endungen ist eine der wichtigsten Sperren der Medienverwaltung.",
    reads="Nur die Parameter der Komponente com_media aus der Datenbank. Es wird nichts verändert.",
    load="leicht", needs="db", presets=["schnell", "hack"],
)
def db_upload_ext(ctx, res):
    db = need_db(ctx, res, "Upload-Endungen", [("Medien-Einstellungen", Q_PARAMS % "com_media")])
    _emit(res, aj.judge_upload_ext(component_params(db, "com_media")))


# ------------------------------------------------------------------ Registrierung
@check(
    "db_registration", G, "Benutzer-Registrierung",
    "Kann sich jeder selbst registrieren, und in welche Gruppe kommt er?",
    what="Liest die Einstellungen der Benutzerverwaltung (com_users): ist die Selbstregistrierung offen, in welche Gruppe neue Konten kommen und wie sie aktiviert werden (gar nicht, per E-Mail, durch einen Administrator). "
         "Ob die Gruppe ins Backend darf, wird aus den Rechten der Wurzel (core.login.admin und core.admin) abgeleitet.",
    why="Offene Registrierung ist für viele Seiten unnötig. Landen neue Konten in einer Gruppe mit Bearbeitungsrechten oder Backend-Zugang, kann sich jeder Besucher selbst zum Redakteur oder Administrator machen.",
    reads="Nur Einstellungen der Komponente com_users, die Gruppen und die Rechte der Wurzel aus der Datenbank. Es wird nichts verändert. "
          "Rechte, die an einzelnen Komponenten überschrieben sind, werden nicht ausgewertet (dann steht der Backend-Zugang einer Gruppe als unbekannt).",
    load="leicht", needs="db", presets=["schnell", "hack"],
)
def db_registration(ctx, res):
    db = need_db(ctx, res, "Registrierung", [("Benutzer-Einstellungen", Q_PARAMS % "com_users"), ("Gruppen", Q_GROUPS), ("Rechte", Q_ROOT)])
    groups = group_list(db)
    bm = backend_map(db, groups)
    gl = [{"id": g["id"], "title": g["title"], "backend_login": bm.get(g["id"])} for g in groups]
    _emit(res, aj.judge_registration(component_params(db, "com_users"), gl if gl else None))


# ------------------------------------------------------------------ Zwei-Faktor (Joomla)
@check(
    "db_mfa", G, "Zwei-Faktor-Anmeldung der Backend-Konten",
    "Haben die Konten mit Backend-Zugang eine Zwei-Faktor-Anmeldung eingerichtet?",
    what="Prüft bei Joomla 4.2 und neuer, welche Zwei-Faktor-Methoden eingeschaltet sind und welche Konten mit Backend-Zugang mindestens eine Methode eingerichtet haben. "
         "Gesperrte Konten zählen nicht. Die Testmethode 'Festcode' (fixed) wird als 'bitte prüfen' gemeldet.",
    why="Ein gestohlenes oder erratenes Passwort reicht bei einem Konto ohne Zwei-Faktor für den vollen Zugriff auf das Backend. Mit Zwei-Faktor allein ist es nutzlos.",
    reads="Nur welche Methode ein Konto eingerichtet hat (Methodenname und Benutzer-Nummer). Schlüsseldaten und Codes werden nie gelesen. Es wird nichts verändert.",
    load="leicht", needs="db", presets=["schnell", "hack"],
)
def db_mfa(ctx, res):
    db = need_db(ctx, res, "Zwei-Faktor", [("Plugins", Q_MFA_PLUGINS), ("Methoden je Konto", Q_MFA_ROWS)])
    rows = fetch(db, Q_MFA_ROWS)
    if rows is None:
        _emit(res, aj.judge_mfa_joomla(False, [], [], []))
        return
    plugins = [str(r.get("element") or "") for r in fetch(db, Q_MFA_PLUGINS) or []]
    groups = group_list(db)
    bm = backend_map(db, groups)
    ids = sorted(g for g, v in bm.items() if v) or list(DEFAULT_ADMIN_GROUPS)
    admins = []
    for r in fetch(db, Q_ADMINS % ",".join(str(int(i)) for i in ids)) or []:
        try:
            admins.append({"id": int(r.get("id")), "username": str(r.get("username") or ""), "block": str(r.get("block")) == "1"})
        except (TypeError, ValueError):
            continue
    mrows = []
    for r in rows:
        try:
            mrows.append({"user_id": int(r.get("user_id")), "method": str(r.get("method") or "")})
        except (TypeError, ValueError):
            continue
    _emit(res, aj.judge_mfa_joomla(True, plugins, admins, mrows))


# ------------------------------------------------------------------ Admin-Anmeldungen
def local_offset_hours() -> float:
    """Abstand der Ortszeit dieses Rechners zu UTC in Stunden (für die Auswertung der Nachtzeit)."""
    try:
        return round(time.localtime().tm_gmtoff / 3600.0, 2)
    except Exception:
        return 0.0


def login_rows(ctx, raw: List[Dict[str, Optional[str]]]) -> Tuple[List[Dict[str, str]], Dict[str, Optional[str]]]:
    """Zeilen für die Auswertung. Die Land-Abfrage geht nur mit dem gekürzten Netz hinaus (siehe geoip) und je Netz einmal. Bei mehreren Ländern zum selben gekürzten Text gilt das Land als unbekannt."""
    geo = None if __import__("os").environ.get("CLAUDIA_OFFLINE") else geo_of(ctx)
    out: List[Dict[str, str]] = []
    cc_by_shown: Dict[str, Optional[str]] = {}
    seen: Dict[str, str] = {}
    for r in raw:
        key = (r.get("aktion") or "").replace("PLG_ACTIONLOG_JOOMLA_", "")
        meld = _json(r.get("meldung")) or {}
        name = str(meld.get("username") or "") if isinstance(meld, dict) else ""
        appk = str(meld.get("app") or "").upper() if isinstance(meld, dict) else ""
        app = "administrator" if "ADMINISTRATOR" in appk else ("site" if "SITE" in appk else "")
        ip = (r.get("ip_address") or "").strip()
        if ip.upper() == "COM_ACTIONLOGS_DISABLED":
            ip = ""
        shown = ctx.mask(ip) if ip else ""
        if ip and geo is not None and ip not in seen:
            try:
                seen[ip] = (geo.lookup(ip.replace(".x", ".0")) or {}).get("cc", "") or ""
            except Exception:
                seen[ip] = ""
        if shown:
            cc = seen.get(ip) or None
            if shown in cc_by_shown and cc_by_shown[shown] != cc:
                cc_by_shown[shown] = None
            else:
                cc_by_shown.setdefault(shown, cc)
        out.append({"log_date": str(r.get("log_date") or "")[:19], "username": name or "Benutzer %s" % (r.get("user_id") or "?"), "ip": shown, "app": app, "action": key})
    return out, cc_by_shown


@check(
    "db_admin_logins", G, "Auffällige Anmeldungen im Backend",
    "Gab es Backend-Anmeldungen aus einem anderen Land als sonst oder mitten in der Nacht?",
    what="Wertet die Anmeldungen im Joomla-Aktivitätsprotokoll aus: aus welchen Ländern wird sich im Backend angemeldet, und gibt es erfolgreiche Anmeldungen aus einem anderen Land als dem häufigsten? "
         "Anmeldungen zwischen 0 und 5 Uhr (Ortszeit dieses Rechners) werden nur als Hinweis genannt. Das Land kommt aus der Registrierung des Netzes (nur das gekürzte Netz wird abgefragt, nur online).",
    why="Ein Angreifer mit gestohlenem Passwort meldet sich oft von einem anderen Land aus an. Das Protokoll ist oft die einzige Spur davon.",
    reads="Zeit, Benutzername, App (Backend oder Seite) und gekürzte IP-Adresse der letzten 2000 Anmelde-Einträge. Es wird nichts verändert. "
          "Ist die Speicherung der IP-Adresse in Joomla ausgeschaltet oder das Protokoll leer, gibt es keine Länderauswertung. Das Land ist das des Netz-Anbieters, nicht der genaue Standort (VPN, Mobilfunk, Firmennetze).",
    load="leicht", needs="db", presets=["hack"],
)
def db_admin_logins(ctx, res):
    db = need_db(ctx, res, "Anmeldungen", [("Anmeldungen", Q_LOGINS)])
    raw = fetch(db, Q_LOGINS)
    if raw is None:
        raise CheckSkipped("Es gibt kein Aktivitätsprotokoll (Tabelle fehlt).")
    if not raw:
        res.add("info", "Keine Anmeldungen im Aktivitätsprotokoll", "Das Protokoll enthält keine Anmelde-Einträge (Plugin ausgeschaltet oder Einträge gelöscht). Nichts davon beweist, dass es keine fremden Anmeldungen gab.")
        return
    ctx.progress("Herkunft der Anmeldungen auswerten")
    rows, geo = login_rows(ctx, raw)
    _emit(res, aj.judge_admin_logins(rows, geo, local_offset_hours()))


# ------------------------------------------------------------------ Alter der Erweiterungen
_MONTHS = {"jan": 1, "feb": 2, "mar": 3, "mär": 3, "maer": 3, "apr": 4, "may": 5, "mai": 5, "jun": 6, "jul": 7, "aug": 8, "sep": 9, "oct": 10, "okt": 10, "nov": 11, "dec": 12, "dez": 12}


def parse_manifest_date(s: Any) -> Optional[str]:
    """Erstellungsdatum aus dem Manifest ('2024-05-01', '2024-05', '2024', '01.05.2024', 'May 2024', '1 May 2024') als JJJJ-MM-TT; None bei allem anderen. Fehlt der Tag, gilt der 1.; fehlt der Monat, der Januar."""
    t = str(s or "").strip()
    m = re.fullmatch(r"(\d{4})-(\d{1,2})-(\d{1,2})(?:[ T].*)?", t)
    d: Optional[Tuple[int, int, int]] = None
    if m:
        d = (int(m.group(1)), int(m.group(2)), int(m.group(3)))
    elif (m := re.fullmatch(r"(\d{4})-(\d{1,2})", t)):
        d = (int(m.group(1)), int(m.group(2)), 1)
    elif (m := re.fullmatch(r"(\d{4})", t)):
        d = (int(m.group(1)), 1, 1)
    elif (m := re.fullmatch(r"(\d{1,2})\.(\d{1,2})\.(\d{4})", t)):
        d = (int(m.group(3)), int(m.group(2)), int(m.group(1)))
    elif (m := re.fullmatch(r"(?:(\d{1,2})\.?\s+)?([A-Za-zäÄ]{3,9})\.?,?\s+(?:(\d{1,2}),?\s+)?(\d{4})", t)):
        mon = _MONTHS.get(m.group(2)[:3].lower().replace("ä", "ae")[:3]) or _MONTHS.get(m.group(2).lower()[:4])
        day = int(m.group(1) or m.group(3) or 1)
        if mon:
            d = (int(m.group(4)), mon, day)
    if not d:
        return None
    try:
        datetime.date(*d)
    except ValueError:
        return None
    return "%04d-%02d-%02d" % d


def ext_rows(rows: List[Dict[str, Optional[str]]]) -> List[Dict[str, Any]]:
    out = []
    for r in rows:
        man = _json(r.get("manifest_cache")) or {}
        if not isinstance(man, dict):
            man = {}
        author = str(man.get("author") or "")
        core = str(r.get("protected")) == "1" or bool(re.search(r"joomla!?\s*project", author, re.I))
        shown = str(man.get("name") or r.get("name") or r.get("element") or "")
        if r.get("type") == "plugin" and r.get("folder"):
            shown = "%s (%s/%s)" % (shown, r.get("folder"), r.get("element"))
        out.append({"name": shown[:120], "type": str(r.get("type") or ""), "version": str(man.get("version") or ""),
                    "last_update": parse_manifest_date(man.get("creationDate")), "source": "manifest", "core": core, "enabled": str(r.get("enabled")) == "1"})
    return out


@check(
    "db_ext_age", G, "Lange nicht aktualisierte Erweiterungen",
    "Gibt es Erweiterungen, deren Version schon sehr lange nicht erneuert wurde?",
    what="Liest für jede installierte Erweiterung das Datum, das ihr Hersteller in die Version eingetragen hat (creationDate im Manifest), und nennt Erweiterungen ab zwei Jahren Alter als Hinweis. "
         "Ab vier Jahren und aktiviert heißt es 'bitte prüfen' (vermutlich nicht mehr gepflegt). Erweiterungen von Joomla selbst werden nie gemeldet.",
    why="Nicht mehr gepflegte Erweiterungen bekommen keine Sicherheitskorrekturen mehr. Das Alter ist ein Hinweis, kein Beweis: Eine Erweiterung kann fertig und trotzdem sicher sein, und ein falsch gepflegtes Datum täuscht.",
    reads="Nur Name, Typ, Version, Aktiv-Status und das eingetragene Datum aus der Erweiterungstabelle. Es wird nichts verändert. Die Prüfung sagt nie, dass eine Sicherheitslücke besteht; dafür gibt es die Prüfungen gegen die Schwachstellenlisten.",
    load="leicht", needs="db", presets=["schnell"],
)
def db_ext_age(ctx, res):
    db = need_db(ctx, res, "Alter der Erweiterungen", [("Erweiterungen", Q_EXT)])
    raw = fetch(db, Q_EXT)
    if raw is None:
        raise CheckSkipped("Die Erweiterungstabelle ist nicht lesbar.")
    now = ctx.shared.get("_now_epoch")
    if now is None:
        now = int(time.time())
    _emit(res, au.judge_ext_age(ext_rows(raw), now))


# ------------------------------------------------------------------ Zwei-Faktor (WordPress)
Q_WP_ACTIVE = "SELECT option_value AS v FROM #__options WHERE option_name = 'active_plugins'"
Q_WP_ADMINS = "SELECT COUNT(*) AS n FROM #__usermeta WHERE meta_key = '#__capabilities' AND meta_value LIKE '%\"administrator\"%'"


@check(
    "wp_2fa", G, "Zwei-Faktor und Anmeldeschutz (WordPress)",
    "Ist ein Plugin für Zwei-Faktor-Anmeldung oder Anmeldeschutz installiert und aktiv?",
    what="Sucht unter den installierten Plugins nach Zwei-Faktor-Plugins (Two-Factor, WP 2FA) und nach Plugins mit Anmeldeschutz (Wordfence, iThemes Security) und prüft, ob sie aktiv sind. "
         "WordPress selbst hat keine Zwei-Faktor-Anmeldung. Ob einzelne Konten sie nutzen, ist von außen nicht erkennbar und wird nie behauptet.",
    why="Mit Zwei-Faktor ist ein gestohlenes Passwort allein nutzlos. Ohne ein solches Plugin schützt bei einem Administrator-Konto nur das Passwort.",
    reads="Die Ordnernamen unter wp-content/plugins, die Liste der aktiven Plugins und die Zahl der Administratoren aus der Datenbank. Es wird nichts verändert.",
    load="leicht", needs="db", presets=["schnell", "hack"], cms="wordpress",
)
def wp_2fa(ctx, res):
    db = need_db(ctx, res, "Zwei-Faktor", [("Aktive Plugins", Q_WP_ACTIVE), ("Administratoren", Q_WP_ADMINS)])
    out = ctx.sh("ls -1 wp-content/plugins 2>/dev/null | head -n 400", timeout=30).out
    slugs = [x.strip().lower() for x in out.splitlines() if re.fullmatch(r"[A-Za-z0-9._-]{1,100}", x.strip()) and not x.strip().startswith(".")]
    act_rows = fetch(db, Q_WP_ACTIVE) or []
    active = {a.split("/")[0].lower() for a in re.findall(r's:\d+:"([^"]+)";', (act_rows[0].get("v") or "") if act_rows else "")}
    n_rows = fetch(db, Q_WP_ADMINS)
    try:
        n = int((n_rows or [{}])[0].get("n"))
    except (TypeError, ValueError):
        n = None
    _emit(res, aj.judge_2fa_wp([{"slug": s, "active": s in active} for s in slugs] if slugs else None, n))
