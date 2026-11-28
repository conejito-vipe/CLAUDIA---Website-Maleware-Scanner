"""Bereich 'Datenbank' (optional): Tests, die sich ausschließlich auf die Datenbank beziehen.

Verwendet die Zugangsdaten aus der Karte 'Datenbank-Verbindung' (sonst die der configuration.php). Alle Abfragen sind lesend (SELECT, SHOW).
"""
from __future__ import annotations

import json
import os
import re
import time
from typing import Any, Dict, List, Optional, Tuple

from .. import evidence
from ..db import DbError
from ..model import CheckSkipped
from ..registry import check
from ..util import clean_line, extract_hosts, host_allowed, trunc, vcmp
from .database import need_db, parse_dt
from .online import UA_BROWSER, VEL_URLS, fetch as http_fetch, parse_vel, vel_matches

G = "dbbereich"

# Muster werden auf LOWER(Spalte) angewendet. Nur Zeichen, die MySQL und MariaDB gleich verstehen (eckige Klammern statt Rückstrich).
STRONG_SQL = ("eval[ ]*[(]|base64_decode|gzinflate|str_rot13|fromcharcode|atob[(]|document[.]write[(]|unescape[(]|<[?]php|[$]_(get|post|request|cookie|server)|"
              "shell_exec|passthru|assert[(]|system[(]|proc_open|union[ ]+select")
WEAK_SQL = "<script|<iframe|javascript:|onerror[ ]*=|onload[ ]*=|<meta[^>]*refresh|<object|<embed|<base[ ]"
STRONG_RE = re.compile(STRONG_SQL.replace("[(]", r"\(").replace("[.]", r"\.").replace("[$]", r"\$").replace("[?]", r"\?").replace("[ ]", " "), re.IGNORECASE)
HIGH_RE = re.compile(r"base64_decode|gzinflate|str_rot13|fromcharcode|shell_exec|passthru|eval\s*\(|<\?php|proc_open|atob\(", re.IGNORECASE)
SKIP_COLS = {"password", "token", "secret", "otpKey", "otep", "authorisation", "session_id"}
Q_TEXTCOLS = ("SELECT c.table_name AS t, c.column_name AS c FROM information_schema.columns c WHERE c.table_schema = DATABASE() "
              "AND c.data_type IN ('char','varchar','tinytext','text','mediumtext','longtext') "
              "AND (c.character_maximum_length IS NULL OR c.character_maximum_length >= 40) ORDER BY c.table_name, c.ordinal_position")
Q_TABLES = ("SELECT table_name AS t, table_type AS typ, engine AS eng, table_rows AS zeilen, create_time AS erstellt, update_time AS geaendert, "
            "(data_length + index_length) AS bytes FROM information_schema.tables WHERE table_schema = DATABASE() ORDER BY table_name")


def _sqlstr(s: str) -> str:
    return "'" + s.replace("\\", "\\\\").replace("'", "''") + "'"


def _bt(name: str) -> str:
    return "`" + name.replace("`", "``") + "`"


def _int(v: Any) -> int:
    try:
        return int(str(v))
    except (TypeError, ValueError):
        return 0


def _tables(db) -> List[Dict[str, Optional[str]]]:
    try:
        return db.query(Q_TABLES)
    except DbError:
        return []


def _branch(version: str) -> Tuple[str, str]:
    """('mariadb'|'mysql', '10.6') aus 'VERSION()' wie '10.6.18-MariaDB-log' oder '8.0.36'."""
    low = (version or "").lower()
    engine = "mariadb" if "mariadb" in low else "mysql"
    m = re.search(r"(\d+)\.(\d+)", version or "")
    return engine, ("%s.%s" % (m.group(1), m.group(2)) if m else "")


# ------------------------------------------------------------------ 1) Server und Rechte
Q_VER = [("Version", "SELECT VERSION() AS version, @@version_comment AS kommentar, CURRENT_USER() AS benutzer")]
Q_GRANTS = [("Rechte", "SHOW GRANTS FOR CURRENT_USER()")]


@check(
    "dbx_server", G, "Datenbank-Server und Rechte des Zugangs",
    "Ist die Datenbank-Software noch gepflegt, und hat der Zugang nur die Rechte, die Joomla braucht?",
    what="Liest die Version des Datenbank-Servers und vergleicht sie mit den Support-Zeiträumen von MySQL und MariaDB. Liest außerdem die Rechte des Datenbank-Benutzers "
         "(SHOW GRANTS) und meldet Rechte, die Joomla nicht braucht: Dateien lesen/schreiben (FILE), Server-Verwaltung (SUPER, PROCESS), Rechte weitergeben (GRANT OPTION) "
         "oder Zugriff auf alle Datenbanken.",
    why="Ein Angreifer, der das Datenbank-Passwort kennt, kann mit zu großen Rechten Dateien auf den Server schreiben oder fremde Datenbanken lesen. "
        "Software ohne Support bekommt keine Sicherheits-Updates mehr.",
    reads="Nur SELECT VERSION(), einige Servereinstellungen und SHOW GRANTS. Es werden keine Daten verändert.",
    load="leicht", needs="db", presets=["komplett"],
)
def dbx_server(ctx, res):
    db = need_db(ctx, res, "Datenbank-Server und Rechte", Q_VER + Q_GRANTS)
    v = (db.query(Q_VER[0][1]) or [{}])[0]
    version = v.get("version") or ""
    engine, branch = _branch(version)
    items = ["Server: %s (%s)" % (version or "?", clean_line(v.get("kommentar") or "")), "Angemeldet als: %s" % clean_line(v.get("benutzer") or "?"),
             "Datenbank: %s, Tabellenpräfix: %s" % (db.name, db.prefix)]
    today = time.strftime("%Y-%m-%d")
    row = next((e for e in ctx.adv.get("database_eol", []) if e["engine"] == engine and e["branch"] == branch), None)
    if row and row["eol"] < today:
        res.add("warn", "Die Datenbank-Version %s %s wird nicht mehr mit Sicherheits-Updates versorgt" % ("MariaDB" if engine == "mariadb" else "MySQL", branch),
                "Das Support-Ende war am %s (Stand der Vergleichsliste: %s)." % (row["eol"], ctx.adv.get("stand", "?")), items,
                "Beim Hoster auf eine unterstützte Version umstellen lassen (Hosting-Paket oder Datenbank-Version wählen).")
    elif row:
        res.add("ok", "Datenbank-Version %s %s wird noch gepflegt" % ("MariaDB" if engine == "mariadb" else "MySQL", branch), "Support bis %s." % row["eol"], items)
    else:
        res.add("info", "Datenbank-Version %s %s: kein Eintrag in der Vergleichsliste" % ("MariaDB" if engine == "mariadb" else "MySQL", branch or "?"),
                "Entweder ist die Version neuer als die Liste (Stand %s) oder sie ist nicht bekannt. Prüfe den Support-Zeitraum auf der Seite des Herstellers." % ctx.adv.get("stand", "?"), items)
    # Rechte
    try:
        grants = [list(r.values())[0] or "" for r in db.query(Q_GRANTS[0][1])]
    except DbError as e:
        res.add("info", "Rechte konnten nicht gelesen werden", clean_line(str(e)))
        grants = []
    risky: List[str] = []
    for g in grants:
        m = re.match(r"GRANT (.*?) ON (.*?) TO", g, re.IGNORECASE | re.DOTALL)
        if not m:
            continue
        privs, scope = m.group(1).upper(), m.group(2).replace("`", "")
        glob = scope.startswith("*.*")
        flags = [p for p in ("FILE", "SUPER", "PROCESS", "SHUTDOWN", "CREATE USER", "RELOAD", "GRANT OPTION") if re.search(r"\b%s\b" % p, privs)]
        if "ALL PRIVILEGES" in privs and glob:
            flags.insert(0, "ALLE RECHTE auf alle Datenbanken")
        elif "ALL PRIVILEGES" in privs and "GRANT OPTION" in privs:
            flags.insert(0, "alle Rechte inkl. Weitergabe")
        if glob and flags:
            risky.append("%s ON %s" % (", ".join(flags), scope))
        elif flags and any(f in ("FILE", "SUPER", "GRANT OPTION") for f in flags):
            risky.append("%s ON %s" % (", ".join(flags), scope))
        elif scope.split(".")[0] not in (db.name, "%", "") and not glob and "USAGE" not in privs:
            risky.append("Zugriff auf weitere Datenbank: %s" % scope)
    if risky:
        res.add("warn", "Der Datenbank-Zugang hat mehr Rechte, als Joomla braucht", "Joomla braucht SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, INDEX, DROP und ähnliche Rechte nur auf der eigenen Datenbank.",
                [trunc(clean_line(r), 200) for r in risky][:12], "Beim Hoster einen eigenen Datenbank-Benutzer nur für diese Datenbank verwenden, ohne FILE/SUPER/GRANT OPTION.")
    elif grants:
        res.add("ok", "Die Rechte des Datenbank-Zugangs sind auf die eigene Datenbank beschränkt", "Keine Rechte wie FILE, SUPER oder Zugriff auf alle Datenbanken gefunden.",
                [trunc(clean_line(g), 160) for g in grants][:4])
    try:
        s = (db.query("SELECT @@local_infile AS li, @@secure_file_priv AS sfp") or [{}])[0]
        notes = []
        if str(s.get("li")) in ("1", "ON"):
            notes.append("local_infile ist AN (Dateien vom Client dürfen geladen werden)")
        if s.get("sfp") in ("", None) and any("FILE" in g.upper() for g in grants):
            notes.append("secure_file_priv ist leer und der Zugang hat das FILE-Recht: Dateien könnten an beliebigen Orten geschrieben werden")
        if notes:
            res.add("info", "Servereinstellungen, die du kennen solltest", "Das ist beim Hoster oft Standard und nicht zwingend ein Fehler.", notes, context=True)
    except DbError:
        pass


# ------------------------------------------------------------------ 2) Code in der Datenbank
LOG_COLUMNS = {"redirect_links": ("old_url", "new_url", "referer", "comment")}          # Protokoll der 404-Seiten: hier landen Angriffsadressen als Text


def is_log_column(table: str, col: str) -> bool:
    """Spalte, in der Joomla Adressen aus Anfragen speichert (die Weiterleitungs-Komponente protokolliert 404-Aufrufe samt Verweis)."""
    return any(table.lower().endswith("_" + t) and col.lower() in cols for t, cols in LOG_COLUMNS.items())

def _sample_query(table: str, col: str, pat: str) -> List[str]:
    c = _bt(col)
    return ["SELECT SUBSTRING(%s, GREATEST(1, REGEXP_INSTR(LOWER(%s), %s) - 70), 300) AS s, CHAR_LENGTH(%s) AS n FROM %s WHERE LOWER(%s) REGEXP %s LIMIT 5" % (c, c, _sqlstr(pat), c, _bt(table), c, _sqlstr(pat)),
            "SELECT LEFT(%s, 300) AS s, CHAR_LENGTH(%s) AS n FROM %s WHERE LOWER(%s) REGEXP %s LIMIT 5" % (c, c, _bt(table), c, _sqlstr(pat))]


def _samples(db, table: str, col: str, pat: str) -> List[Dict[str, Optional[str]]]:
    last: Optional[Exception] = None
    for q in _sample_query(table, col, pat):
        try:
            return db.query(q, timeout=60)
        except DbError as e:
            last = e
    if last:
        raise last
    return []


@check(
    "dbx_codescan", G, "Datenbank auf eingeschleusten Code durchsuchen",
    "Steckt in irgendeinem Textfeld irgendeiner Tabelle Schadcode?",
    what="Ermittelt alle Textspalten der Datenbank und sucht in jeder nach Merkmalen von Schadcode: verschleiertes JavaScript (eval, fromCharCode, atob), PHP-Code "
         "(base64_decode, gzinflate, <?php), Befehle zum Ausführen von Eingaben und eingebettete Fremdinhalte (<script>, <iframe>, Weiterleitungen). Gefundene Stellen werden "
         "mit Tabelle, Spalte und einem Ausschnitt gezeigt. Fremdinhalte von bekannten Diensten (z. B. YouTube) werden nur als Hinweis gezählt.",
    why="Angreifer legen Code gern in der Datenbank ab, weil Dateiscanner ihn dort nie finden: in Modulen, Template-Einstellungen, Artikeln und Tabellen fremder Erweiterungen. "
        "Er wird bei jedem Seitenaufruf ausgegeben und überlebt das Löschen aller Dateien.",
    reads="Nur SELECT-Abfragen auf die Textspalten. Passwörter und Schlüsselspalten werden nicht durchsucht. Auf großen Datenbanken kann das mehrere Minuten dauern.",
    load="hoch", needs="db", presets=["komplett"],
)
def dbx_codescan(ctx, res):
    db = need_db(ctx, res, "Datenbank auf Code durchsuchen", [("Textspalten", Q_TEXTCOLS)])
    cols = db.query(Q_TEXTCOLS, timeout=120)
    tabs = {t["t"]: t for t in _tables(db)}
    by_table: Dict[str, List[str]] = {}
    for r in cols:
        t, c = r["t"] or "", r["c"] or ""
        if not t or tabs.get(t, {}).get("typ") == "VIEW" or c.lower() in SKIP_COLS or re.search(r"(^|_)session$", t):
            continue
        by_table.setdefault(t, []).append(c)
    skipped_big, errors = [], []
    allow, own = ctx.allow(), ctx.own_host()
    hits_strong: List[Tuple[str, str, int, str, List[Dict[str, Any]]]] = []     # Tabelle, Spalte, Anzahl, Ausschnitt, Fundstellen mit Code
    hits_weak: List[Tuple[str, str, int, str, List[Dict[str, Any]]]] = []
    n_cols = scanned = 0
    names = sorted(by_table)
    for i, t in enumerate(names):
        ctx.progress("Tabelle %d von %d: %s" % (i + 1, len(names), t))
        if _int(tabs.get(t, {}).get("zeilen")) > 2_000_000:
            skipped_big.append("%s (ca. %s Zeilen)" % (t, tabs[t]["zeilen"]))
            continue
        cl = by_table[t][:40]
        n_cols += len(cl)
        parts = []
        for j, c in enumerate(cl):
            lc = "LOWER(%s)" % _bt(c)
            parts.append("COALESCE(SUM(%s REGEXP %s), 0) AS s%d, COALESCE(SUM(%s REGEXP %s), 0) AS w%d" % (lc, _sqlstr(STRONG_SQL), j, lc, _sqlstr(WEAK_SQL), j))
        try:
            row = (db.query("SELECT %s FROM %s" % (", ".join(parts), _bt(t)), timeout=120) or [{}])[0]
        except DbError as e:
            errors.append("%s: %s" % (t, trunc(clean_line(str(e)), 120)))
            continue
        scanned += 1
        for j, c in enumerate(cl):
            for kind, pat, store in (("s", STRONG_SQL, hits_strong), ("w", WEAK_SQL, hits_weak)):
                n = _int(row.get("%s%d" % (kind, j)))
                if not n:
                    continue
                try:
                    sm = _samples(db, t, c, pat)
                except DbError:
                    sm = []
                snips = [clean_line(x.get("s") or "") for x in sm[:2]]
                text = " ⟂ ".join(snips)
                code = [{"n": k + 1, "t": sn[:400], "hit": evidence.span(sn[:400], rx=pat)} for k, sn in enumerate(snips)]
                store.append((t, c, n, text, [{"file": "%s.%s" % (t, c), "line": 0, "kind": "db", "note": "%d Zeile(n) betroffen, Beispiele" % n, "code": code}] if code else []))
    raw = ["Geprüft: %d Tabellen, %d Textspalten" % (scanned, n_cols)]
    for kind, lst in (("STARK", hits_strong), ("SCHWACH", hits_weak)):
        for t, c, n, s, _ev in lst:
            raw.append("[%s] %s.%s: %d Treffer: %s" % (kind, t, c, n, s))
    ctx.add_raw("db_codescan.txt", "\n".join(raw))
    logs = [h for h in hits_strong if is_log_column(h[0], h[1])]
    hits_strong = [h for h in hits_strong if h not in logs]
    if logs:
        res.add("info", "%d Stelle(n) im Protokoll der Weiterleitungs-Komponente: Angriffsversuche, kein eingeschleuster Code" % len(logs),
                "Joomla schreibt hier die aufgerufenen Adressen und Verweise (Referer) von Seiten, die nicht gefunden wurden. Scanner und Angreifer probieren dabei Befehle in der Adresse aus. "
                "Der Text wird nur gespeichert und im Backend maskiert angezeigt, nicht ausgeführt: die Seite ist dadurch nicht infiziert. Er zeigt aber, dass die Seite angegriffen wird.",
                ["%s.%s: %d Zeile(n) | %s" % (h[0], h[1], h[2], trunc(h[3], 260)) for h in logs][:15],
                "Optional im Backend aufräumen: Komponenten -> Weiterleitungen -> Einträge löschen (die Tabelle wird bei jedem neuen 404 wieder befüllt).",
                [e for h in logs for e in h[4]][:6])
    if hits_strong:
        crit = [h for h in hits_strong if HIGH_RE.search(h[3])]
        def line(h):
            return "%s.%s: %d Zeile(n) | %s" % (h[0], h[1], h[2], trunc(h[3], 260))
        if crit:
            res.add("crit", "%d Stelle(n) in der Datenbank mit typischem Schadcode" % len(crit),
                    "Die Treffer enthalten verschleiernde oder ausführende Befehle (z. B. base64_decode, eval, fromCharCode), die in normalen Inhalten nicht vorkommen.", [line(h) for h in crit][:30],
                    "Den Inhalt im Joomla-Backend an der genannten Stelle öffnen und den Code entfernen (Tabelle verrät die Stelle: modules = Module, template_styles = Template-Einstellungen, content = Artikel). "
                    "Danach Passwörter erneuern und prüfen, wie der Code hineingelangt ist.", [e for h in crit for e in h[4]][:8])
        rest = [h for h in hits_strong if h not in crit]
        if rest:
            res.add("warn", "%d Stelle(n) mit auffälligen Programmbefehlen" % len(rest),
                    "Das kann harmlos sein (z. B. ein Code-Beispiel in einem Artikel oder ein Tracking-Skript), sollte aber angesehen werden.", [line(h) for h in rest][:30], "",
                    [e for h in rest for e in h[4]][:8])
    if hits_weak:
        bad, known = [], []
        bad_ev: List[Dict[str, Any]] = []
        for t, c, n, s, evs in hits_weak:
            hosts = extract_hosts(s)
            foreign = [h for h in hosts if not host_allowed(h, allow) and h != own]
            if foreign:
                bad_ev += evs
            (bad if foreign else known).append("%s.%s: %d Zeile(n) | %s%s" % (t, c, n, trunc(s, 200), ("  Fremde Adresse(n): " + ", ".join(foreign[:4])) if foreign else ""))
        if bad:
            res.add("warn", "%d Stelle(n) mit eingebettetem Fremdinhalt (script/iframe/Weiterleitung) von unbekannten Adressen" % len(bad),
                    "Eingebettete Inhalte von fremden Adressen können Besucher umleiten oder Schadcode laden. Kennst du die Adressen nicht, entferne sie.", bad[:30],
                    "Bekannte Dienste kannst du unter 'Weitere Einstellungen' -> 'Zusätzlich erlaubte Fremd-Domains' eintragen.", bad_ev[:8])
        if known:
            res.add("info", "%d Stelle(n) mit eingebetteten Inhalten bekannter Dienste oder der eigenen Seite" % len(known),
                    "Üblich (z. B. YouTube, Karten, Tracking). Der Test zählt sie nur, damit du siehst, wo sie liegen.", known[:15])
    if not hits_strong and not hits_weak and scanned:
        res.add("ok", "Kein eingeschleuster Code in den Textfeldern gefunden", "%d Tabellen mit %d Textspalten durchsucht." % (scanned, n_cols))
    elif scanned:
        res.add("info", "Umfang der Suche", "%d Tabellen mit %d Textspalten durchsucht. Details im Bericht (db_codescan.txt)." % (scanned, n_cols))
    if skipped_big:
        res.add("info", "Sehr große Tabellen wurden übersprungen", "Über 2 Millionen Zeilen würden den Server zu lange belasten.", skipped_big[:10])
    if errors:
        res.add("info", "%d Tabelle(n) konnten nicht durchsucht werden" % len(errors), "Meist fehlen Rechte oder die Tabelle ist beschädigt.", errors[:10])


# ------------------------------------------------------------------ 3) Auffälligkeiten
Q_TRIG = ("SELECT trigger_name AS n, event_object_table AS t, action_timing AS z, event_manipulation AS e, LEFT(action_statement, 300) AS st "
          "FROM information_schema.triggers WHERE trigger_schema = DATABASE()")
Q_EVENTS = "SELECT event_name AS n, status AS s, LEFT(event_definition, 300) AS st FROM information_schema.events WHERE event_schema = DATABASE()"
Q_ROUT = "SELECT routine_name AS n, routine_type AS typ, LEFT(routine_definition, 300) AS st FROM information_schema.routines WHERE routine_schema = DATABASE()"
Q_ADMSESS = ("SELECT s.username AS u, s.time AS t, s.client_id AS c FROM #__session s WHERE s.guest = 0 AND s.client_id = 1 ORDER BY s.time DESC LIMIT 20")
ODD_TABLE_RE = re.compile(r"^(wp_|tmp|temp|test|backup|bak|old|dump|copy)|(_bak|_old|_backup|_copy|_tmp|_dump)$|^[a-f0-9]{10,}\Z", re.IGNORECASE)


@check(
    "dbx_anomalies", G, "Auffälligkeiten im Aufbau der Datenbank",
    "Gibt es Tabellen, Trigger, Ereignisse oder Prozeduren, die in einer normalen Joomla-Datenbank nicht vorkommen?",
    what="Listet alle Tabellen und sucht fremde oder ungewöhnlich benannte Tabellen (wp_, tmp, backup, zufällige Namen), Ansichten (Views), frisch angelegte Tabellen, "
         "sowie Trigger, zeitgesteuerte Ereignisse und gespeicherte Prozeduren. Zeigt außerdem aktive Administrator-Sitzungen.",
    why="Trigger und Ereignisse sind Dauerhintertüren: Sie legen z. B. nach jedem Löschen wieder einen Admin-Zugang an oder fügen Code ein, ohne dass eine Datei verändert wird. "
        "Joomla selbst benutzt nichts davon. Fremde Tabellen verraten Spuren anderer Programme oder zurückgelassene Sicherungen.",
    reads="Nur Abfragen auf information_schema und die Sitzungstabelle (Benutzername und Zeit, keine Sitzungsdaten).",
    load="leicht", needs="db", presets=["komplett"],
)
def dbx_anomalies(ctx, res):
    db = need_db(ctx, res, "Auffälligkeiten in der Datenbank", [("Tabellen", Q_TABLES), ("Trigger", Q_TRIG), ("Ereignisse", Q_EVENTS), ("Prozeduren", Q_ROUT)])
    tabs = db.query(Q_TABLES, timeout=60)
    pre = db.prefix
    ctx.progress("Tabellen auswerten")
    mine = [t for t in tabs if (t["t"] or "").startswith(pre)]
    other = [t for t in tabs if not (t["t"] or "").startswith(pre)]
    views = [t for t in tabs if (t.get("typ") or "") == "VIEW"]
    res.add("info", "%d Tabellen in der Datenbank '%s'" % (len(tabs), db.name), "Davon %d mit dem Joomla-Präfix '%s'." % (len(mine), pre),
            ["Größte Tabellen: " + ", ".join("%s (%s MB)" % (t["t"], round(_int(t["bytes"]) / 1048576, 1)) for t in sorted(tabs, key=lambda x: -_int(x["bytes"]))[:5])], context=True)
    if other:
        odd = [t for t in other if ODD_TABLE_RE.search(t["t"] or "")]
        if odd:
            res.add("warn", "%d Tabelle(n) mit ungewöhnlichem Namen außerhalb des Joomla-Präfixes" % len(odd), "Namen wie wp_, tmp, backup oder zufällige Zeichenfolgen weisen auf fremde Programme oder Zurückgelassenes hin.",
                    [clean_line("%s (%s Zeilen, angelegt %s)" % (t["t"], t["zeilen"], (t.get("erstellt") or "?")[:10])) for t in odd][:30], "Kennst du die Tabelle nicht, sichere sie und prüfe, wozu sie gehört, bevor du sie löschst.")
        rest = [t for t in other if t not in odd]
        if rest:
            res.add("info", "%d weitere Tabelle(n) ohne Joomla-Präfix" % len(rest), "Das können Tabellen anderer Programme sein, die dieselbe Datenbank nutzen.",
                    [clean_line("%s (%s Zeilen)" % (t["t"], t["zeilen"])) for t in rest][:30])
    if views:
        res.add("warn", "%d Ansicht(en) (Views) in der Datenbank" % len(views), "Joomla legt keine Views an. Sie können Abfragen verbergen.", [clean_line(t["t"] or "") for t in views][:20])
    cutoff = time.time() - 30 * 86400
    recent = [t for t in mine if (parse_dt(t.get("erstellt")) or 0) > cutoff]
    if recent:
        res.add("info", "%d Joomla-Tabelle(n) in den letzten 30 Tagen angelegt" % len(recent), "Nach Updates und Installationen normal. Kennst du den Zeitpunkt nicht, sieh dir die Erweiterung dazu an.",
                [clean_line("%s (angelegt %s)" % (t["t"], (t.get("erstellt") or "?")[:16])) for t in sorted(recent, key=lambda x: x.get("erstellt") or "", reverse=True)][:20])
    # Trigger / Ereignisse / Prozeduren
    for label, q, kind, none_lbl in (("Trigger", Q_TRIG, "trig", "Trigger"), ("zeitgesteuerte Ereignisse", Q_EVENTS, "event", "zeitgesteuerten Ereignisse"),
                                     ("gespeicherte Prozeduren oder Funktionen", Q_ROUT, "rout", "gespeicherten Prozeduren oder Funktionen")):
        ctx.progress("Prüfe " + label)
        try:
            rows = db.query(q, timeout=40)
        except DbError as e:
            res.add("info", "%s konnten nicht abgefragt werden" % label.capitalize(), trunc(clean_line(str(e)), 200))
            continue
        if not rows:
            res.add("ok", "Keine %s vorhanden" % none_lbl, "In einer normalen Joomla-Datenbank gibt es keine.")
            continue
        items = []
        worst = "warn"
        for r in rows[:20]:
            st = clean_line(r.get("st") or "")
            if STRONG_RE.search(st) or re.search(r"insert\s+into|update\s+\S+\s+set|#__users|%susers" % re.escape(db.prefix), st, re.IGNORECASE):
                worst = "crit"
            head = r.get("n") or "?"
            if kind == "trig":
                head += " (%s %s auf %s)" % (r.get("z"), r.get("e"), r.get("t"))
            items.append("%s: %s" % (head, trunc(st, 220)))
        res.add(worst, "%d %s gefunden" % (len(rows), label), "Joomla selbst benutzt das nicht (%s). Es läuft unbemerkt bei jeder Änderung bzw. nach Zeitplan." % label, items,
                "Nur löschen, wenn du sicher weißt, dass sie nicht von einer Erweiterung stammen. Im Zweifel einen Spezialisten fragen (Sicherung zuerst).")
    # aktive Admin-Sitzungen
    try:
        rows = db.query(Q_ADMSESS, timeout=30)
        if rows:
            res.add("info", "%d Administrator-Sitzung(en) in der Sitzungstabelle" % len(rows), "Kennst du die Namen nicht oder passt die Uhrzeit nicht zu dir, ist jemand Fremdes angemeldet.",
                    ["%s (letzte Aktivität %s)" % (clean_line(r.get("u") or "?"), time.strftime("%Y-%m-%d %H:%M", time.localtime(_int(r.get("t")))) if _int(r.get("t")) else "?") for r in rows][:15])
        else:
            res.add("ok", "Keine angemeldeten Administratoren in der Sitzungstabelle")
    except DbError:
        pass


# ------------------------------------------------------------------ 4) Aktuelle Sicherheitslage
Q_EXTS = "SELECT type AS typ, element, folder AS gruppe, name, manifest_cache AS mc FROM #__extensions WHERE type IN ('component','plugin','module','template','library','package','file')"


def _manifests_from_db(rows: List[Dict[str, Optional[str]]]) -> List[Dict[str, str]]:
    out = []
    for r in rows:
        try:
            mc = json.loads(r.get("mc") or "{}")
        except ValueError:
            mc = {}
        out.append({"type": r.get("typ") or "", "group": r.get("gruppe") or "", "element": r.get("element") or "", "name": mc.get("name") or r.get("name") or "",
                    "version": str(mc.get("version") or ""), "author": str(mc.get("author") or ""), "date": str(mc.get("creationDate") or ""), "path": "Datenbank: %s" % (r.get("element") or "")})
    return out


@check(
    "dbx_incidents", G, "Aktuelle Sicherheitsvorfälle rund um die Datenbank",
    "Gibt es bekannte, aktuell ausgenutzte Lücken zu deiner Joomla-Version oder deinen Erweiterungen, die die Datenbank betreffen (SQL-Injection, Zugangsdaten)?",
    what="Liest die installierten Erweiterungen und die Joomla-Version aus der Datenbank. Prüft die Joomla-Version gegen bekannte Datenbank-Vorfälle (z. B. die Lücke, durch die Datenbank-Passwörter "
         "ohne Anmeldung ausgelesen werden konnten) und lädt von deinem PC aus die aktuelle Liste verwundbarer Erweiterungen von extensions.joomla.org. Treffer, die SQL-Injection betreffen, werden hervorgehoben.",
    why="SQL-Injection ist der direkteste Weg zu Benutzerlisten, Passwort-Hashes und Schreibzugriff auf die Datenbank. Neue Lücken in Erweiterungen werden laufend bekannt.",
    reads="Die Tabelle der Erweiterungen (Name und Version). Die Liste wird von deinem PC aus abgerufen wie von einem Browser; zum Server wird nichts gesendet.",
    load="leicht", needs="db", presets=["komplett"],
)
def dbx_incidents(ctx, res):
    db = need_db(ctx, res, "Aktuelle Sicherheitsvorfälle", [("Erweiterungen", Q_EXTS)])
    rows = db.query(Q_EXTS, timeout=60)
    ms = _manifests_from_db(rows)
    core = next((m for m in ms if m["type"] == "file" and m["element"] == "joomla"), None)
    jver = core["version"] if core else ""
    if jver:
        hit = [i for i in ctx.adv.get("database_incidents", []) if vcmp(jver, i["from"]) >= 0 and vcmp(jver, i["to"]) <= 0]
        if hit:
            for i in hit:
                res.add("crit", "Joomla %s ist von %s betroffen" % (jver, i["id"]), i["title"], [i["note"], "Behoben in Joomla %s" % i["fixed"]],
                        "Joomla aktualisieren und das Datenbank-Passwort erneuern. Benutzer und Administratoren prüfen.")
        else:
            res.add("ok", "Joomla %s ist von den bekannten Datenbank-Vorfällen nicht betroffen" % jver,
                    "Geprüft gegen: %s (Stand der Vergleichsliste %s)." % (", ".join(i["id"] for i in ctx.adv.get("database_incidents", [])), ctx.adv.get("stand", "?")))
    else:
        res.add("info", "Joomla-Version nicht in der Datenbank gefunden", "Der Abgleich mit bekannten Datenbank-Vorfällen konnte nicht laufen.")
    if os.environ.get("CLAUDIA_OFFLINE"):
        raise CheckSkipped("Offline-Modus (CLAUDIA_OFFLINE): Die Online-Liste wird nicht abgerufen.")
    items: List[Dict[str, Any]] = []
    errors: List[str] = []
    for u in VEL_URLS:
        ctx.progress("Lade Liste von %s" % u.split("/")[2])
        f = http_fetch(u, UA_BROWSER, max_bytes=20_000_000, timeout=20)
        if f.error:
            errors.append("%s: %s" % (u, f.error))
            continue
        items = parse_vel(f.body)
        if items:
            break
        errors.append("%s: keine lesbare Liste (HTTP %d)" % (u, f.status))
    if not items:
        res.add("info", "Die aktuelle Liste verwundbarer Erweiterungen konnte nicht geladen werden", "; ".join(errors)[:300])
        return
    hits = [h for h in vel_matches(items, [m for m in ms if m["version"]]) if h[2] in ("live", "behoben")]
    sql = [h for h in hits if re.search(r"\bsql\b|sql[ -]?injection|sqli", json.dumps(h[0], ensure_ascii=False).lower())]
    others = [h for h in hits if h not in sql]

    def line(h):
        it, m, kind = h
        cve = it.get("cve_id") or ""
        patch = it.get("patch_version") or ""
        return clean_line("%s %s - %s%s%s" % (m["name"] or m["element"], m["version"], trunc(str(it.get("title") or ""), 100), ("  [%s]" % cve) if cve else "",
                                            (" - behoben in %s" % patch) if patch else " - noch KEIN Update bekannt"))
    if sql:
        res.add("crit", "%d Erweiterung(en) mit bekannter SQL-Injection-Lücke installiert" % len(sql),
                "Über solche Lücken kann die Datenbank ohne Passwort ausgelesen oder verändert werden.", [line(h) for h in sql][:30],
                "Auf die genannte Version aktualisieren oder die Erweiterung deaktivieren. Danach Benutzer, Administratoren und Passwörter prüfen.")
    if others:
        res.add("warn", "%d weitere Erweiterung(en) auf der Joomla-Liste verwundbarer Erweiterungen" % len(others), "Keine SQL-Injection laut Listeneintrag, aber trotzdem bekannte Lücken.",
                [line(h) for h in others][:30], "Erweiterung aktualisieren.")
    if not hits:
        res.add("ok", "Keine deiner in der Datenbank eingetragenen Erweiterungen steht (mit passender Version) auf der Liste", "%d Einträge der Liste geprüft." % len(items))
