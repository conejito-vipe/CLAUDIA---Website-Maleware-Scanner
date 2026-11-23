"""Datenbank-Prüfungen (nur lesende SELECT-Abfragen über das mysql-Programm auf dem Server)."""
from __future__ import annotations

import json
import re
import time
from collections import Counter
from typing import Dict, List, Optional, Tuple

from ..db import DbError, DbTableMissing
from ..model import CheckSkipped, Option
from ..registry import check
from ..util import clean_line, digits, extract_hosts, host_allowed, trunc
from .ext import get_ext_fs

G = "datenbank"
Query = Tuple[str, str]   # (Bezeichnung, SQL)


# ------------------------------------------------------------------ Hilfen
def need_db(ctx, res, title: str, queries: List[Query]):
    """Liefert die Datenbankverbindung oder überspringt den Test (mit SQL-Text für phpMyAdmin)."""
    db = ctx.db()
    if db.ok:
        return db
    txt = ["-- Test: %s" % title,
           "-- Im phpMyAdmin (Reiter SQL) jede Abfrage einzeln ausführen. Ergebnis als CSV exportieren oder Screenshot machen.", ""]
    for label, sql in queries:
        txt.append("-- %s\n%s;\n" % (label, db.sql(sql).strip()))
    ctx.add_raw("sql_manuell", "\n".join(txt))
    raise CheckSkipped("Kein Datenbankzugriff vom Server aus möglich (%s). Die Abfragen für phpMyAdmin liegen im Bericht unter 'sql_manuell'." % db.error)


def fetch(db, sql: str) -> Optional[List[Dict[str, Optional[str]]]]:
    """Abfrage ausführen; None, wenn die Tabelle nicht existiert."""
    try:
        return db.query(sql)
    except DbTableMissing:
        return None


def add_manual_sql(ctx, db, title: str, selects: List[Query]) -> None:
    """Ergänzt die Datei phpmyadmin_abfragen.sql um Abfragen zu den Funden (auch wenn der Datenbankzugriff vom Server aus klappt): damit lassen sich die Einträge von Hand ansehen und sichern."""
    if not selects:
        return
    txt = ["-- Fund: %s" % title,
           "-- Im phpMyAdmin (Reiter SQL) ausführen, um die betroffenen Einträge anzusehen. Vor jeder Änderung die Einträge exportieren (Export als SQL).", ""]
    for label, sql in selects[:60]:
        txt.append("-- %s\n%s;\n" % (label, db.sql(sql).strip()))
    ctx.add_raw("sql_manuell", "\n".join(txt))


def parse_dt(s: Optional[str]) -> Optional[float]:
    if not s or s.startswith("0000"):
        return None
    try:
        return time.mktime(time.strptime(s[:19], "%Y-%m-%d %H:%M:%S")) - time.timezone
    except ValueError:
        return None


def age_days(s: Optional[str]) -> Optional[float]:
    t = parse_dt(s)
    return None if t is None else max(0.0, (time.time() - t) / 86400.0)


def is_admin_group(groups: str) -> bool:
    return bool(re.search(r"super|admin", groups or "", re.IGNORECASE))


def fmt_date(s: Optional[str]) -> str:
    return (s or "nie")[:16] if s and not s.startswith("0000") else "nie"


# ------------------------------------------------------------------ Zugang
Q_ACCESS: List[Query] = [("Datenbank-Version", "SELECT VERSION() AS version, DATABASE() AS datenbank")]


@check(
    "db_access", G, "Datenbank-Zugang vom Server aus",
    "Kann das Programm die Joomla-Datenbank über den Server abfragen?",
    what="Liest Host, Benutzer und Datenbank aus der configuration.php und führt über das mysql-Programm des Servers eine harmlose Testabfrage aus. "
         "Das Passwort wird nicht in der Befehlszeile übergeben, sondern über einen verdeckten Kanal, und nie gespeichert oder exportiert.",
    why="Ohne diesen Zugang können die Datenbank-Tests nicht laufen. Der Test sagt dir früh, ob du die SQL-Abfragen sonst von Hand in phpMyAdmin ausführen musst.",
    reads="Nur eine Testabfrage (SELECT VERSION()). Es werden keine Daten verändert.",
    load="leicht", needs="db", presets=["schnell", "hack"],
)
def db_access(ctx, res):
    db = ctx.db()
    if not db.ok:
        need_db(ctx, res, "Datenbank-Zugang", Q_ACCESS)
    rows = db.query("SELECT VERSION() AS version, DATABASE() AS datenbank")
    r = rows[0] if rows else {}
    res.add("ok", "Datenbankzugriff funktioniert", "Alle Datenbank-Tests können laufen.",
            ["Server: %s" % (r.get("version") or "?"), "Datenbank: %s" % (r.get("datenbank") or db.name), "Tabellenpräfix: %s" % db.prefix])


# ------------------------------------------------------------------ Benutzer
Q_USERS: List[Query] = [
    ("Alle Benutzer mit Gruppen", "SELECT u.id, u.username, u.name, u.email, u.block, u.registerDate, u.lastvisitDate, u.requireReset, "
     "(SELECT GROUP_CONCAT(g.title) FROM #__user_usergroup_map m JOIN #__usergroups g ON g.id = m.group_id WHERE m.user_id = u.id) AS gruppen "
     "FROM #__users u ORDER BY u.registerDate DESC LIMIT 500"),
    ("API-Token (Dauerzugang)", "SELECT p.user_id, u.username, p.profile_key, p.profile_value FROM #__user_profiles p "
     "LEFT JOIN #__users u ON u.id = p.user_id WHERE p.profile_key LIKE 'joomlatoken.%'"),
]


def _idtag(uid) -> str:
    """Maschinenlesbare Marke am Zeilenende, damit Aktionen (Konto sperren, Token widerrufen) die Zeile zuordnen können."""
    return "  [ID %s]" % uid if digits(str(uid or "")) else ""


@check(
    "db_users", G, "Benutzer und Administratoren",
    "Wer darf sich anmelden - und wurden neue Administratoren oder API-Tokens angelegt, die du nicht kennst?",
    what="Listet alle Joomla-Benutzer mit Gruppen, Anmelde- und Registrierungsdatum. Hebt Administratoren und Super-User hervor, neu angelegte Admin-Konten, "
         "Konten ohne bisherige Anmeldung und aktive API-Tokens (Dauerzugänge, die ein Passwortwechsel nicht beendet).",
    why="Ein typischer Schritt nach dem Einbruch: ein zusätzliches Super-User-Konto oder ein API-Token anlegen, um jederzeit zurückzukehren.",
    reads="Benutzername, E-Mail, Gruppen und Datum aus den Benutzertabellen. Passwort-Hashes werden NICHT gelesen.",
    load="leicht", needs="db", presets=["hack"],
    options=[Option("days", "Als 'neu' zählen: letzte ... Tage", "int", 120, "Admin-Konten, die in diesem Zeitraum angelegt wurden, werden markiert.")],
)
def db_users(ctx, res):
    db = need_db(ctx, res, "Benutzer und Administratoren", Q_USERS)
    days = ctx.opt_int("days", 120)
    users = fetch(db, Q_USERS[0][1]) or []
    adm, newadm, never, blocked_adm = [], [], [], []
    for u in users:
        groups = (u.get("gruppen") or "")
        if not is_admin_group(groups):
            continue
        blocked = (u.get("block") or "0") == "1"
        reg_age = age_days(u.get("registerDate"))
        line = "%s  (%s, Gruppen: %s) - angelegt %s, letzte Anmeldung %s%s" % (
            clean_line(u.get("username") or "?"), clean_line(u.get("email") or "?"), clean_line(groups), fmt_date(u.get("registerDate")),
            fmt_date(u.get("lastvisitDate")), ", GESPERRT" if blocked else "") + _idtag(u.get("id"))
        (blocked_adm if blocked else adm).append(line)
        if not blocked:
            if reg_age is not None and reg_age <= days:
                newadm.append(line)
            if not u.get("lastvisitDate") or u.get("lastvisitDate", "").startswith("0000"):
                never.append(line)
    res.add("info", "%d aktive Administrator-Konten, %d gesperrte" % (len(adm), len(blocked_adm)),
            "Bitte prüfe jeden Eintrag: Kennst du den Benutzer? Jeder aktive Super-User kann die ganze Seite übernehmen.", adm + ["(gesperrt) " + x for x in blocked_adm])
    uid_re = re.compile(r"\[ID (\d+)\]")
    flagged_ids = sorted({int(m.group(1)) for l in newadm + never for m in [uid_re.search(l)] if m})
    if flagged_ids:
        add_manual_sql(ctx, db, "Auffällige Administrator-Konten", [("Konten ansehen (Passwort-Hashes nicht weitergeben)", "SELECT id, username, email, registerDate, lastvisitDate, block FROM #__users WHERE id IN (%s)" % ",".join(map(str, flagged_ids)))])
    if newadm:
        res.add("warn", "%d Administrator-Konto/Konten in den letzten %d Tagen angelegt" % (len(newadm), days),
                "Nach einem Hack ein typisches Zeichen. Wenn du das Konto nicht selbst angelegt hast: sperren und Passwörter ändern.", newadm,
                "Benutzer -> Verwalten: Konto sperren/löschen, danach alle Passwörter ändern.")
    if never:
        res.add("warn", "Aktive Administrator-Konten ohne jede Anmeldung", "Ungenutzte Admin-Konten sind unnötige Risiken.", never, "Löschen oder sperren, wenn nicht gebraucht.")
    recent_users = [u for u in users if (age_days(u.get("registerDate")) or 9999) <= 30 and not is_admin_group(u.get("gruppen") or "")]
    if recent_users:
        res.add("info", "%d normale Konten in den letzten 30 Tagen registriert" % len(recent_users),
                "Bei offener Registrierung sind Spam-Konten üblich.", ["%s (%s)" % (clean_line(u.get("username") or ""), fmt_date(u.get("registerDate"))) for u in recent_users[:20]])
    tokens = fetch(db, Q_USERS[1][1]) or []
    has_token = {t.get("user_id") for t in tokens if t.get("profile_key") == "joomlatoken.token" and (t.get("profile_value") or "").strip()}
    en = [t for t in tokens if t.get("profile_key") == "joomlatoken.enabled" and t.get("profile_value") == "1"
          and (not has_token or t.get("user_id") in has_token)]     # aktiviert UND ein Token wurde tatsächlich erzeugt
    if en:
        by_id = {u.get("id"): u for u in users}
        items = []
        for t in en:
            u = by_id.get(t.get("user_id")) or {}
            grp = u.get("gruppen") or ""
            items.append("%s%s%s" % (clean_line(t.get("username") or ("Benutzer-ID %s" % t.get("user_id"))),
                                     "  [%s]" % clean_line(grp) if grp else "", _idtag(t.get("user_id"))))
        res.add("warn", "%d Benutzer mit aktivem API-Token" % len(en),
                "Ein API-Token erlaubt Zugriff auf die Joomla-Programmierschnittstelle ohne Passwort. Ein Passwortwechsel beendet ihn nicht. "
                "Joomla speichert nicht, wann ein Token zuletzt benutzt wurde; im Zugriffsprotokoll tauchen Aufrufe unter /api/ auf.",
                items, "Nur behalten, wenn du den Token selbst eingerichtet hast (Benutzer bearbeiten -> Joomla API-Token). "
                       "Konten von Dienstleistern/Herstellern (z. B. Support-Zugänge) sperren, wenn sie nicht mehr gebraucht werden.")
    if not (newadm or never or en):
        res.add("ok", "Keine neu angelegten oder unbenutzten Administratoren, keine API-Tokens")


# ------------------------------------------------------------------ JCE
Q_JCE: List[Query] = [
    ("JCE-Profile", "SELECT id, name, published, area, device, ordering, plugins, LENGTH(params) AS params_len, "
     "(params LIKE '%php%') AS enthaelt_php, (params LIKE '%phtml%') AS enthaelt_phtml FROM #__wf_profiles ORDER BY id"),
    ("JCE: Ausschnitt um 'php'", "SELECT id, name, SUBSTRING(params, LOCATE('php', params), 160) AS ausschnitt FROM #__wf_profiles WHERE params LIKE '%php%'"),
]


@check(
    "db_jce", G, "JCE-Editor-Profile",
    "Wurden im JCE-Editor fremde Profile angelegt oder PHP-Uploads erlaubt?",
    what="Liest die Editor-Profile des JCE (Tabelle wf_profiles), listet sie auf und markiert Profile, in deren Einstellungen 'php' oder 'phtml' vorkommt "
         "(z. B. als erlaubter Upload-Dateityp).",
    why="Die JCE-Lücke CVE-2026-48907 wurde aktiv ausgenutzt, um ein fremdes Profil mit PHP-Upload-Recht anzulegen und darüber ein Web-Shell hochzuladen. "
        "Das Profil bleibt auch nach einem Update bestehen.",
    reads="Profilnamen und Einstellungen der JCE-Profile. Ist JCE nicht installiert, wird der Test sauber übersprungen.",
    load="leicht", needs="db", presets=["hack"],
)
def db_jce(ctx, res):
    db = need_db(ctx, res, "JCE-Editor-Profile", Q_JCE)
    rows = fetch(db, Q_JCE[0][1])
    if rows is None:
        res.add("ok", "JCE ist nicht installiert (keine Profiltabelle)", "Hier gibt es nichts zu prüfen.")
        return
    bad = [r for r in rows if r.get("enthaelt_php") == "1" or r.get("enthaelt_phtml") == "1"]
    names = ["#%s %s (%s)%s" % (r.get("id"), clean_line(r.get("name") or ""), "aktiv" if r.get("published") == "1" else "inaktiv",
                               "  <- enthält 'php'" if r in bad else "") for r in rows]
    res.add("info", "%d JCE-Profile" % len(rows), "Üblich sind 'Default' und 'Front End' plus eigene Profile.", names)
    if bad:
        snippets = fetch(db, Q_JCE[1][1]) or []
        items = ["#%s %s: ...%s" % (s.get("id"), clean_line(s.get("name") or ""), trunc(clean_line(s.get("ausschnitt") or ""), 150)) for s in snippets]
        add_manual_sql(ctx, db, "JCE-Profile mit 'php'", [("Profile ansehen/sichern", "SELECT * FROM #__wf_profiles WHERE id IN (%s)" % ",".join(str(int(b["id"])) for b in bad if digits(str(b.get("id") or ""))))]
                       if any(digits(str(b.get("id") or "")) for b in bad) else [])
        res.add("crit", "%d JCE-Profil(e) erwähnen 'php' in den Einstellungen" % len(bad),
                "Das ist das Muster des JCE-Angriffs: ein Profil, das den Upload von PHP-Dateien erlaubt.", items or [clean_line(b.get("name") or "") for b in bad],
                "Profil im Backend (Komponenten -> JCE Editor -> Profile) ansehen. Wenn du es nicht angelegt hast: löschen. JCE auf die aktuelle Version bringen.")
    else:
        res.add("ok", "Keine Profile mit PHP-Bezug")


# ------------------------------------------------------------------ eingeschleuster Code in Inhalten
INJ_PATTERNS = [("<script", "<script"), ("<iframe", "<iframe"), ("eval(", "eval("), ("fromCharCode", "fromCharCode"), ("document.write", "document.write"), ("atob(", "atob(")]


def _inj_query(table: str, idcol: str, titlecol: str, col: str) -> str:
    c = "`%s`" % col
    cases = " ".join("WHEN %s LIKE '%%%s%%' THEN SUBSTRING(%s, LOCATE('%s', %s), 300)" % (c, pat, c, pat, c) for pat, _ in INJ_PATTERNS)
    where = " OR ".join("%s LIKE '%%%s%%'" % (c, pat) for pat, _ in INJ_PATTERNS)
    return ("SELECT '%s' AS tabelle, %s AS id, %s AS titel, '%s' AS spalte, CASE %s END AS ausschnitt FROM #__%s WHERE %s LIMIT 100"
            % (table, idcol, titlecol, col, cases, table, where))


INJ_TARGETS = [("content", "id", "title", "introtext"), ("content", "id", "title", "fulltext"), ("modules", "id", "title", "content"),
               ("modules", "id", "title", "params"), ("template_styles", "id", "title", "params"), ("extensions", "extension_id", "name", "params"),
               ("menu", "id", "title", "params")]
Q_INJ: List[Query] = [("%s.%s" % (t, c), _inj_query(t, i, ti, c)) for t, i, ti, c in INJ_TARGETS]
HIDDEN_RE = re.compile(r"display\s*:\s*none|visibility\s*:\s*hidden|width\s*=\s*.?0|height\s*=\s*.?0|left\s*:\s*-\d{3,}", re.IGNORECASE)
OBF_RE = re.compile(r"_0x[0-9a-f]{3,}|fromCharCode|atob\(|unescape\(|eval\(|\\x[0-9a-f]{2}\\x[0-9a-f]{2}", re.IGNORECASE)
TAG_IDS = re.compile(r"\b(GTM-[A-Z0-9]{4,10}|G-[A-Z0-9]{8,12}|UA-\d{4,10}-\d+|AW-\d{6,12})\b")


@check(
    "db_content", G, "Eingeschleuster Code in Artikeln, Modulen und Template-Einstellungen",
    "Stehen in der Datenbank Skripte, versteckte Frames oder verschleierter Code?",
    what="Sucht in Artikeln, benutzerdefinierten Modulen, Template-Stilen (z. B. 'vor </head>' und 'nach <body>'), Erweiterungs- und Menü-Parametern nach "
         "<script>, <iframe>, eval(, fromCharCode, document.write und atob(. Die gefundenen Internetadressen werden mit deiner Liste bekannter Dienste verglichen. "
         "Außerdem werden Tag-Manager-/Analytics-IDs (GTM-..., G-...) aufgelistet.",
    why="Schadcode muss nicht in Dateien stehen: Ein Skript in einem Modul oder in den Template-Einstellungen wird auf jeder Seite ausgeliefert. "
        "Die Tag-Manager-ID zeigt, welcher Container eingebunden ist - dort kann ebenfalls Fremdcode hängen.",
    reads="Ausschnitte (300 Zeichen) der Stellen, an denen die Muster vorkommen - nicht ganze Inhalte.",
    load="mittel", needs="db", presets=["hack"],
)
def db_content(ctx, res):
    db = need_db(ctx, res, "Eingeschleuster Code in der Datenbank", Q_INJ)
    inject_scan(ctx, res, db, Q_INJ, ("Eintrag im Backend öffnen und den Code entfernen (vorher Kopie sichern). Danach prüfen, wie er hineinkam.",
                                      ("content", "modules")))


def inject_scan(ctx, res, db, queries, hints):
    """Gemeinsame Auswertung für Joomla und WordPress: Fundstellen mit Skripten/Frames bewerten und als Befunde ausgeben."""
    fix_hint, direct_tables = hints
    own, allow = ctx.own_host(), ctx.allow()
    crit, warn, info = [], [], []
    ids = Counter()
    scanned = 0
    sel: List[Query] = []
    for label, sql in queries:
        ctx.progress("Prüfe %s" % label)
        rows = fetch(db, sql)
        if rows is None:
            continue
        scanned += 1
        for r in rows:
            snip = r.get("ausschnitt") or ""
            where = "%s #%s '%s' (%s)" % (r.get("tabelle"), r.get("id"), clean_line(trunc(r.get("titel") or "", 40)), r.get("spalte"))
            for tid in TAG_IDS.findall(snip):
                ids[tid] += 1
            hosts = [h for h in extract_hosts(snip) if h != own]
            bad = [h for h in hosts if not host_allowed(h, allow)]
            text = "%s: %s" % (where, trunc(clean_line(snip), 200))
            mi = re.search(r"AS tabelle, (\w+) AS id", sql)
            flag_before = len(crit) + len(warn)
            if any(i.lower() in snip.lower() for i in ctx.adv.get("ioc_strings", []) if i):
                crit.append(text + "  -> BEKANNTER SCHADCODE aus dem Vorfall")
            elif OBF_RE.search(snip):
                crit.append(text + "  -> verschleierter Code")
            elif bad and "<iframe" in snip.lower() and HIDDEN_RE.search(snip):
                crit.append(text + "  -> unsichtbarer Frame auf fremde Adresse (%s)" % ", ".join(bad[:2]))
            elif bad:
                warn.append(text + "  -> unbekannte Adresse: %s" % ", ".join(bad[:3]))
            elif "<iframe" in snip.lower() and HIDDEN_RE.search(snip):
                warn.append(text + "  -> unsichtbarer Frame")
            elif hosts or re.search(r"googletagmanager|datalayer", snip, re.IGNORECASE):
                info.append(text + "  -> bekannter Dienst")
            elif r.get("tabelle") in direct_tables:
                warn.append(text + "  -> Skript direkt im Inhalt")
            else:
                info.append(text)
            if len(crit) + len(warn) > flag_before and mi and digits(str(r.get("id") or "")) and re.fullmatch(r"\w+", str(r.get("tabelle"))) and re.fullmatch(r"\w+", str(r.get("spalte"))):
                sel.append(("%s #%s (%s): kompletten Wert ansehen/sichern" % (r.get("tabelle"), r.get("id"), r.get("spalte")),
                            "SELECT `%s`, `%s` FROM #__%s WHERE `%s` = %s" % (mi.group(1), r.get("spalte"), r.get("tabelle"), mi.group(1), r.get("id"))))
    add_manual_sql(ctx, db, "Eingeschleuster Code in der Datenbank", sel)
    if crit:
        res.add("crit", "%d Fund(e) mit verdächtigem Code in der Datenbank" % len(crit), "Verschleierter Code oder unsichtbare Frames auf fremde Adressen.", crit[:40],
                fix_hint)
    if warn:
        res.add("warn", "%d Fund(e) mit Skripten/Frames, die geprüft werden sollten" % len(warn),
                "Adressen, die nicht in deiner Liste bekannter Dienste stehen, oder Skripte direkt in Artikeln/Modulen.", warn[:40],
                "Kennst du die Einbindung? Falls nicht, entfernen. Bekannte Dienste kannst du in den Einstellungen zur Liste hinzufügen.")
    if info:
        res.add("info", "%d bekannte Einbindung(en)" % len(info), "Z. B. Google Tag Manager, Elfsight, YouTube.", info[:25])
    if ids:
        res.add("info", "Tag-Manager-/Analytics-IDs in den Einstellungen",
                "Prüfe im jeweiligen Konto (tagmanager.google.com), dass der Container dir gehört, keine unbekannten benutzerdefinierten HTML-Tags enthält und nur bekannte Nutzer Zugriff haben.",
                ["%s (%dx gefunden)" % (k, v) for k, v in ids.most_common()])
    if not (crit or warn):
        res.add("ok", "Keine verdächtigen Skripte oder Frames in Artikeln, Modulen und Einstellungen",
                "%d Stellen durchsucht." % scanned)


# ------------------------------------------------------------------ Erweiterungen in der Datenbank
Q_EXT: List[Query] = [("Registrierte Erweiterungen", "SELECT extension_id, name, type, element, folder, client_id, enabled, "
                       "JSON_UNQUOTE(JSON_EXTRACT(manifest_cache, '$.version')) AS version, JSON_UNQUOTE(JSON_EXTRACT(manifest_cache, '$.author')) AS autor, "
                       "JSON_UNQUOTE(JSON_EXTRACT(manifest_cache, '$.creationDate')) AS datum FROM #__extensions ORDER BY type, folder, element")]


@check(
    "db_extensions", G, "Erweiterungen: Datenbank gegen Dateien abgleichen",
    "Gibt es Erweiterungs-Ordner auf dem Server, die in Joomla gar nicht registriert sind - oder umgekehrt?",
    what="Vergleicht die in der Datenbank registrierten Erweiterungen (Tabelle extensions) mit den tatsächlich vorhandenen Ordnern von Plugins, Komponenten, "
         "Modulen und Templates. Verwaiste Ordner (Dateien ohne Registrierung) und defekte Einträge (registriert, aber Dateien fehlen) werden gemeldet.",
    why="Registrierte Plugins werden geladen, nicht registrierte nicht - ihre PHP-Dateien liegen aber trotzdem im Web-Verzeichnis und sind per Adresse aufrufbar. "
        "Angreifer legen Hintertüren gern als 'Plugin' ab, das nie installiert wurde. Auch nach einer unvollständigen Deinstallation bleiben Reste.",
    reads="Die Liste der Erweiterungen aus der Datenbank (Name, Typ, Version) und die Ordnernamen auf dem Server.",
    load="leicht", needs="db", presets=["hack"],
)
def db_extensions(ctx, res):
    db = need_db(ctx, res, "Erweiterungen Datenbank vs. Dateien", Q_EXT)
    try:
        rows = fetch(db, Q_EXT[0][1]) or []
    except DbError:
        # Manche MySQL-Versionen verweigern JSON_EXTRACT bei leerem manifest_cache -> Rohdaten holen und selbst auswerten
        raw = fetch(db, "SELECT extension_id, name, type, element, folder, client_id, enabled, manifest_cache FROM #__extensions") or []
        rows = []
        for r in raw:
            try:
                mc = json.loads(r.get("manifest_cache") or "{}")
            except ValueError:
                mc = {}
            r["version"], r["autor"], r["datum"] = mc.get("version"), mc.get("author"), mc.get("creationDate")
            rows.append(r)
    fs = get_ext_fs(ctx)["dirs"]
    reg: Dict[str, set] = {"plugin": set(), "component": set(), "module": set(), "template": set()}
    for r in rows:
        t, el, fo = r.get("type") or "", r.get("element") or "", r.get("folder") or ""
        if t == "plugin":
            reg["plugin"].add("%s/%s" % (fo, el))
        elif t in reg:
            reg[t].add(el)
    orphan: List[str] = []
    for d in sorted(fs["plugin"]):
        parts = d.split("/")
        if len(parts) == 3 and "%s/%s" % (parts[1], parts[2]) not in reg["plugin"]:
            orphan.append("Plugin: %s" % d)
    for typ, label in (("component", "Komponente"), ("module", "Modul"), ("template", "Template")):
        seen = set()
        for d in sorted(fs[typ]):
            name = d.rstrip("/").split("/")[-1]
            if name in seen:
                continue
            seen.add(name)
            if name not in reg[typ] and name not in ("system",) and not (typ == "template" and name in ("system",)):
                if typ == "component" and name == "com_joomlaupdate":
                    continue
                orphan.append("%s: %s" % (label, d))
    missing: List[str] = []
    for r in rows:
        t, el, fo = r.get("type") or "", r.get("element") or "", r.get("folder") or ""
        if r.get("enabled") != "1":
            continue
        if t == "plugin" and "plugins/%s/%s" % (fo, el) not in fs["plugin"]:
            missing.append("Plugin %s/%s (%s) ist aktiv, aber der Ordner fehlt" % (fo, el, clean_line(r.get("name") or "")))
        elif t == "component" and not any(d.endswith("/" + el) for d in fs["component"]):
            missing.append("Komponente %s (%s) ist aktiv, aber der Ordner fehlt" % (el, clean_line(r.get("name") or "")))
        elif t == "module" and not any(d.endswith("/" + el) for d in fs["module"]):
            missing.append("Modul %s (%s) ist aktiv, aber der Ordner fehlt" % (el, clean_line(r.get("name") or "")))
        elif t == "template" and not any(d.endswith("/" + el) for d in fs["template"]):
            missing.append("Template %s ist aktiv, aber der Ordner fehlt" % el)
    if orphan:
        res.add("warn", "%d Ordner ohne Registrierung in Joomla (verwaist)" % len(orphan),
                "Diese Ordner liegen auf dem Server, sind aber in der Datenbank nicht als Erweiterung eingetragen.", orphan[:60],
                "Kennst du die Erweiterung? Wenn nicht: Inhalt prüfen (nicht ausführen), sichern und löschen. Reste alter Erweiterungen können ebenfalls weg.")
    if missing:
        res.add("info", "%d aktive Erweiterung(en) ohne Dateien" % len(missing),
                "Die Dateien wurden gelöscht, der Datenbankeintrag blieb. Das erzeugt Fehlermeldungen und sollte bereinigt werden.", missing[:40],
                "Eintrag über System -> Verwalten -> Datenbank bzw. Erweiterungen entfernen (Erweiterung deinstallieren oder neu installieren).")
    if not (orphan or missing):
        res.add("ok", "Datenbank und Ordner stimmen überein", "%d registrierte Erweiterungen verglichen." % len(rows))
    third_enabled = [r for r in rows if r.get("enabled") == "1" and "joomla! project" not in (r.get("autor") or "").lower() and r.get("type") in ("plugin", "component", "module", "template")]
    res.add("info", "%d aktive Erweiterungen nicht vom Joomla-Projekt" % len(third_enabled), "Zur Übersicht (Name, Version, Autor).",
            ["%s %s - %s" % (clean_line(r.get("name") or ""), r.get("version") or "?", clean_line(r.get("autor") or "?")) for r in third_enabled][:80])


# ------------------------------------------------------------------ Aktivitätsprotokoll
Q_LOG: List[Query] = [
    ("Umfang des Protokolls", "SELECT COUNT(*) AS anzahl, MIN(log_date) AS erstes, MAX(log_date) AS letztes FROM #__action_logs"),
    ("Letzte Ereignisse", "SELECT id, log_date, user_id, ip_address, message_language_key AS aktion, extension, SUBSTRING(message, 1, 200) AS meldung "
     "FROM #__action_logs ORDER BY id DESC LIMIT 500"),
]
INTERESTING = re.compile(r"INSTALL|UNINSTALL|USER_(REGISTERED|CREATED|DELETED|BLOCK|UNBLOCK|CHANGED|ADDED)|GROUP|CONFIG|PLUGIN|TEMPLATE|MODULE_(ADDED|DELETED)|CHECK_?IN|LOGIN_FAILED|PASSWORD|RESET|TOKEN", re.IGNORECASE)


@check(
    "db_actionlog", G, "Joomla-Aktivitätsprotokoll (Admin-Aktionen)",
    "Was wurde zuletzt im Backend gemacht: Installationen, neue Benutzer, Einstellungen, Anmeldungen?",
    what="Liest das Aktivitätsprotokoll von Joomla (Benutzer -> Aktivitätsprotokoll) und zeigt Installationen/Deinstallationen, neu angelegte oder geänderte Benutzer, "
         "Konfigurationsänderungen und Anmeldungen mit den verwendeten IP-Adressen.",
    why="Das Protokoll zeigt, was nach dem Einbruch im Backend passiert ist - falls der Angreifer sich angemeldet oder etwas installiert hat. "
        "Es ist oft die einzige Zeitleiste, die nicht von Dateizeiten abhängt. Ist das Protokoll leer oder deaktiviert, sagt das Programm das ebenfalls.",
    reads="Die letzten 500 Einträge des Aktivitätsprotokolls (Zeit, Aktion, IP-Adresse, kurzer Text).",
    load="leicht", needs="db", presets=["hack"],
)
def db_actionlog(ctx, res):
    db = need_db(ctx, res, "Aktivitätsprotokoll", Q_LOG)
    head = fetch(db, Q_LOG[0][1])
    if head is None:
        res.add("info", "Kein Aktivitätsprotokoll vorhanden", "Die Tabelle existiert nicht (Funktion deaktiviert oder sehr alte Joomla-Version).")
        return
    h = head[0] if head else {}
    n = int(h.get("anzahl") or 0)
    if n == 0:
        res.add("info", "Das Aktivitätsprotokoll ist leer",
                "Entweder ist das Plugin 'Aktionsprotokoll' deaktiviert, oder die Einträge wurden gelöscht (auch das kann ein Hinweis sein).",
                hint="Im Backend unter System -> Plugins das Protokoll-Plugin aktivieren, damit künftige Aktionen sichtbar sind.")
        return
    rows = fetch(db, Q_LOG[1][1]) or []
    for r in rows:                                   # Joomla schreibt diesen Platzhalter, wenn die IP-Speicherung abgeschaltet ist (Datenschutz-Einstellung)
        if (r.get("ip_address") or "").upper() == "COM_ACTIONLOGS_DISABLED":
            r["ip_address"] = ""
    no_ip = bool(rows) and not any(r.get("ip_address") for r in rows)
    res.add("info", "%d Einträge im Protokoll" % n, "Zeitraum: %s bis %s" % (fmt_date(h.get("erstes")), fmt_date(h.get("letztes"))))
    keys = Counter((r.get("aktion") or "").replace("PLG_ACTIONLOG_JOOMLA_", "") for r in rows)
    res.add("info", "Häufigste Aktionen (letzte %d Einträge)" % len(rows), "", ["%s: %d" % (k, v) for k, v in keys.most_common(12)])
    interesting = [r for r in rows if INTERESTING.search(r.get("aktion") or "") and "LOGGED_IN" not in (r.get("aktion") or "")
                   and "CHECKIN" not in (r.get("aktion") or "").replace("_", "").upper()]      # Check-ins (Sperre aufheben) sind Rauschen
    logins_ev = [r for r in rows if "LOGGED_IN" in (r.get("aktion") or "")]
    if no_ip:
        res.add("info", "Joomla speichert keine IP-Adressen im Aktivitätsprotokoll",
                "Die Einstellung 'IP-Adressen protokollieren' ist aus. Deshalb lässt sich nicht erkennen, von wo Admin-Aktionen kamen. Die Anmeldezeiten bleiben auswertbar.",
                hint="Optional: Benutzer -> Aktivitätsprotokoll -> Optionen -> 'IP-Adresse protokollieren' einschalten (datenschutzrechtlich abwägen).")
    usual_ips = {r.get("ip_address") for r in logins_ev if r.get("ip_address")}
    inst = [r for r in interesting if re.search(r"INSTALL|UNINSTALL", r.get("aktion") or "", re.IGNORECASE)]
    users_ev = [r for r in interesting if re.search(r"USER_|GROUP|PASSWORD|TOKEN", r.get("aktion") or "", re.IGNORECASE)]
    fmt = lambda r: "%s  %s%s  %s" % (fmt_date(r.get("log_date")), (r.get("aktion") or "").replace("PLG_ACTIONLOG_JOOMLA_", ""),
                                      ("  [%s]" % ctx.mask(r["ip_address"])) if r.get("ip_address") else "", trunc(clean_line(r.get("meldung") or ""), 120))
    foreign = [r for r in inst + users_ev if r.get("ip_address") and usual_ips and r.get("ip_address") not in usual_ips]
    if foreign:
        res.add("warn", "%d Admin-Aktion(en) von einer IP-Adresse, mit der sich nie jemand angemeldet hat" % len(foreign),
                "Installationen oder Benutzeränderungen von einer Adresse, die im Protokoll sonst nicht als Anmeldung auftaucht. Das passt zu einem Zugriff über eine Sicherheitslücke statt über das Login.",
                [fmt(r) for r in foreign[:30]], "Aktion prüfen: Hast du das selbst getan (z. B. mit anderer Internetverbindung)? Wenn nicht: Erweiterung/Benutzer entfernen, Passwörter ändern.")
    if inst:
        res.add("info", "%d Installation(en)/Deinstallation(en) im Protokoll" % len(inst),
                "Prüfe, ob alle von dir stammen (auch Updates erscheinen hier).", [fmt(r) for r in inst[:30]])
    if users_ev:
        res.add("info", "%d Benutzer-/Gruppen-Ereignis(se) im Protokoll" % len(users_ev),
                "Neue Konten, Gruppenänderungen und Passwortzurücksetzungen sollten zu deinen eigenen Aktionen passen.", [fmt(r) for r in users_ev[:30]])
    logins = logins_ev
    if logins and no_ip:
        res.add("info", "%d Anmeldungen im Protokoll" % len(logins), "Zeitraum der letzten Einträge: %s bis %s" % (fmt_date(logins[-1].get("log_date")), fmt_date(logins[0].get("log_date"))))
    elif logins:
        ips = Counter(r.get("ip_address") or "?" for r in logins)
        res.add("info", "%d Anmeldungen, von %d verschiedenen IP-Adressen" % (len(logins), len(ips)),
                "Kennst du alle? Eine fremde Adresse (anderes Land/Anbieter) kannst du in einem IP-Lookup nachsehen.",
                ["%s: %dx" % (ctx.mask(ip), c) for ip, c in ips.most_common(12)])
    others = [r for r in interesting if r not in inst and r not in users_ev]
    if others:
        res.add("info", "%d weitere Einstellungs-Ereignisse" % len(others), "Konfiguration, Plugins, Templates.", [fmt(r) for r in others[:20]])


# ------------------------------------------------------------------ Weiterleitungen und Aufgaben
Q_REDIR: List[Query] = [
    ("Weiterleitungen (Komponente Umleitungen)", "SELECT id, old_url, new_url, published, created_date FROM #__redirect_links WHERE new_url LIKE 'http%' ORDER BY created_date DESC LIMIT 200"),
    ("Menüpunkte mit externem Link", "SELECT id, title, link, published FROM #__menu WHERE type = 'url' AND link LIKE 'http%' LIMIT 200"),
    ("Geplante Aufgaben (Scheduler)", "SELECT id, title, type, state, last_execution, next_execution FROM #__scheduler_tasks ORDER BY id LIMIT 100"),
]


@check(
    "db_redirects", G, "Weiterleitungen, externe Menü-Links und geplante Aufgaben",
    "Gibt es Weiterleitungen auf fremde Seiten (SEO-Spam) oder unbekannte geplante Aufgaben?",
    what="Prüft die Joomla-Umleitungen und Menüpunkte vom Typ 'URL' auf fremde Zieladressen (und Spam-Wörter wie casino, viagra) und listet geplante Aufgaben auf.",
    why="SEO-Spam arbeitet oft mit Umleitungen: Suchmaschinen oder Besucher landen auf fremden Seiten, ohne dass du es merkst. Geplante Aufgaben können Code regelmäßig nachladen.",
    reads="Ziel-Adressen von Umleitungen und Menü-Links, Namen der geplanten Aufgaben.",
    load="leicht", needs="db", presets=["hack"],
)
def db_redirects(ctx, res):
    db = need_db(ctx, res, "Weiterleitungen und Aufgaben", Q_REDIR)
    own, allow = ctx.own_host(), ctx.allow()
    spam = [w.lower() for w in ctx.adv.get("spam_words", [])]
    bad, ext_ok = [], []
    bad_ids = {"Umleitung": [], "Menü": []}
    for label, col_url, col_title, sql in (("Umleitung", "new_url", "old_url", Q_REDIR[0][1]), ("Menü", "link", "title", Q_REDIR[1][1])):
        rows = fetch(db, sql)
        if rows is None:
            continue
        for r in rows:
            url = r.get(col_url) or ""
            hosts = [h for h in extract_hosts(url) if h != own]
            txt = "%s #%s: %s -> %s" % (label, r.get("id"), trunc(clean_line(r.get(col_title) or ""), 50), trunc(clean_line(url), 120))
            if any(w in url.lower() for w in spam):
                bad.append(txt + "  (Spam-Wort in der Adresse)")
                bad_ids[label].append(r.get("id"))
            elif any(not host_allowed(h, allow) for h in hosts):
                bad.append(txt)
                bad_ids[label].append(r.get("id"))
            else:
                ext_ok.append(txt)
    add_manual_sql(ctx, db, "Weiterleitungen/Links auf unbekannte Domains",
                   [(lab + "n ansehen" if lab == "Umleitung" else lab + "punkte ansehen", "SELECT * FROM #__%s WHERE id IN (%s)" % (tab, ",".join(str(int(i)) for i in ids if digits(str(i or "")))))
                    for lab, tab, ids in (("Umleitung", "redirect_links", bad_ids["Umleitung"]), ("Menü", "menu", bad_ids["Menü"])) if any(digits(str(i or "")) for i in ids)])
    if bad:
        res.add("warn", "%d Weiterleitung(en)/Link(s) auf unbekannte Domains" % len(bad),
                "Kann legitim sein (z. B. Partnerseite), ist aber auch das Muster von SEO-Spam.", bad[:40], "Kennst du das Ziel? Falls nicht, löschen.")
    if ext_ok:
        res.add("info", "%d externe Ziele auf bekannten Domains" % len(ext_ok), "", ext_ok[:20])
    tasks = fetch(db, Q_REDIR[2][1])
    if tasks:
        res.add("info", "%d geplante Aufgaben" % len(tasks), "Prüfe, ob du alle kennst.",
                ["#%s %s (%s) - %s" % (t.get("id"), clean_line(t.get("title") or ""), t.get("type"), "aktiv" if t.get("state") == "1" else "inaktiv") for t in tasks[:30]])
    if not bad:
        res.add("ok", "Keine Weiterleitungen oder externen Links auf unbekannte Domains")
