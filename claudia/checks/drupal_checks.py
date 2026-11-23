"""Drupal-Prüfungen (2.8.0): Kern, Einstellungen, abrufbare Dateien, Module, Konten, Datenbank-Einstellungen und Code in Inhalten. Nur Drupal 8 und neuer, nur lesend.

Die Bewertung steckt in auswertung_drupal.py (reine Funktionen, mit Beispieldaten geprüft). Hier stehen nur die Abfragen.
Noch NICHT gegen einen echten Drupal-Server geprüft: Antwortformat von updates.drupal.org, Tabellen- und Feldnamen (users_field_data, user__roles, config, node__body, ...).
Fehlt etwas, melden die Prüfungen 'nicht prüfbar' statt zu raten. Schlüssel, Passwörter und hash_salt werden nie ausgegeben."""
from __future__ import annotations

import os
import re
from typing import Any, Dict, List

from .. import coreref, drupal, drupalref
from ..model import CheckSkipped
from ..registry import check
from ..util import split_sections
from . import auswertung_drupal as ad
from . import web as webmod
from .database import fetch, need_db, parse_dt
from .joomla_core import parse_sums

RH = "https://updates.drupal.org/release-history/%s/current"
MAX_PROJECTS = 60           # so viele Module/Themes werden höchstens bei drupal.org nachgeschlagen (je ein Abruf)

Q_USERS = ("SELECT u.uid AS uid, u.name AS name, u.status AS status, u.created AS created, u.access AS access, "
           "(SELECT COUNT(*) FROM #__user__roles r WHERE r.entity_id = u.uid AND r.roles_target_id = 'administrator') AS adm "
           "FROM #__users_field_data u ORDER BY u.uid LIMIT 500")
Q_CFG = "SELECT name AS name, data AS v FROM #__config WHERE name IN ('system.logging', 'user.settings', 'core.extension', 'user.role.anonymous', 'user.role.authenticated')"
Q_CODE = {"node__body": "SELECT entity_id AS id, body_value AS text FROM #__node__body WHERE %s LIMIT 200",
          "block_content__body": "SELECT entity_id AS id, body_value AS text FROM #__block_content__body WHERE %s LIMIT 200",
          "comment__comment_body": "SELECT entity_id AS id, comment_body_value AS text FROM #__comment__comment_body WHERE %s LIMIT 200"}
LIKES = "body_value LIKE '%<script%' OR body_value LIKE '%<iframe%' OR body_value LIKE '%atob(%' OR body_value LIKE '%fromCharCode%' OR body_value LIKE '%eval(%' OR body_value LIKE '%javascript:%'"


def _emit(res, rows) -> None:
    for sev, title, text, items, hint in rows:
        res.add(sev, title, text, items, hint)


def drupal_version(ctx) -> str:
    if "drupal_version" not in ctx.shared:
        out = ctx.sh("head -c 6000 core/lib/Drupal.php 2>/dev/null; echo '@@M'; head -c 6000 includes/bootstrap.inc 2>/dev/null", timeout=30).out
        a, _, b = out.partition("@@M")
        ctx.shared["drupal_version"] = drupal.parse_drupal_version(a, b)
    return ctx.shared["drupal_version"]


def need_d8(ctx) -> str:
    v = drupal_version(ctx)
    if v and drupal.major(v) <= 7:
        raise CheckSkipped("Diese Prüfung gilt für Drupal 8 und neuer. Gefunden wurde Drupal %s (siehe die Kernprüfung)." % v)
    return v


def history(project: str):
    if os.environ.get("CLAUDIA_OFFLINE"):
        return None
    f = webmod.fetch(RH % project, webmod.UA_BROWSER, max_bytes=2_500_000, timeout=20)
    if f.error or f.status != 200:
        return None
    return ad.parse_release_history(f.body)


G_KONFIG, G_EXT, G_DB = "konfig", "erweiterungen", "datenbank"


@check(
    "drupal_core", G_KONFIG, "Drupal-Kern: Version und Originaldateien",
    "Ist Drupal aktuell und stimmen die Dateien im Ordner core mit dem Original überein?",
    what="Liest die Version aus core/lib/Drupal.php, fragt bei updates.drupal.org nach neueren und Sicherheitsversionen und vergleicht alle Dateien im Ordner core mit dem Original-Paket von ftp.drupal.org "
         "(Prüfsumme aus der Release-Liste). Auf dem Server werden nur Prüfsummen berechnet.",
    why="Veraltete Drupal-Versionen werden massenhaft automatisch angegriffen. Manipulierte Kerndateien sind ein häufiger Ort für Hintertüren, die keinem Schadcode-Muster entsprechen.",
    reads="Dateinamen und Prüfsummen im Ordner core des Servers sowie die Version; vom Internet die Release-Liste und das Original-Paket (nur https). Es wird nichts verändert.",
    load="mittel", needs="web", presets=["schnell", "hack", "komplett"], cms="drupal",
)
def drupal_core(ctx, res):
    ver = drupal_version(ctx)
    hist = None
    if ver and drupal.major(ver) >= 8:
        ctx.progress("Frage drupal.org nach Veröffentlichungen")
        hist = history("drupal")
    _emit(res, ad.judge_core(ver, hist))
    if not ver or drupal.major(ver) < 8:
        return
    if os.environ.get("CLAUDIA_OFFLINE"):
        res.add("info", "Dateivergleich übersprungen", "Offline-Modus (CLAUDIA_OFFLINE): Das Original-Paket wird nicht geladen.")
        return
    if not drupalref.VERSION_RE.match(ver):
        res.add("info", "Drupal %s ist eine Vorabversion" % ver, "Für Vorabversionen gibt es kein Paket zum Vergleich.")
        return
    out = ctx.sh(r"""H=""
if command -v sha256sum >/dev/null 2>&1; then H="sha256sum"; elif command -v shasum >/dev/null 2>&1; then H="shasum -a 256"; fi
echo '@@HASHER'; echo "${H:-none}"
echo '@@SUMS'
[ -n "$H" ] && [ -d core ] && find core -type f -print0 2>/dev/null | xargs -0 $H 2>/dev/null""", timeout=420, raw="pruefsummen", raw_cap=40_000).out
    sec = split_sections(out)
    if "none" in sec.get("HASHER", "none").split():
        res.add("info", "Dateivergleich nicht möglich", "Auf dem Server gibt es weder sha256sum noch shasum.")
        return
    server = parse_sums(sec.get("SUMS", ""))
    if len(server) < 200:
        res.add("info", "Dateivergleich nicht möglich", "Im Ordner core wurden nur %d Dateien gefunden. Das Verzeichnis ist vermutlich falsch." % len(server))
        return
    rel = next((r for r in (hist or {}).get("releases", []) if r["version"] == ver), {})
    ctx.progress("Lade das Original-Paket von Drupal %s" % ver)
    try:
        ref = drupalref.reference(ver, rel.get("mdhash", ""), rel.get("download", ""))
    except coreref.RefError as e:
        res.add("info", "Dateivergleich nicht möglich", "Original-Paket nicht verfügbar: %s" % e)
        return
    ctx.progress("Vergleiche %d Dateien" % len(server))
    refs = {p: h for p, h in ref["files"].items() if not re.search(r"(^|/)(node_modules|\.git)(/|$)", p)}
    changed = sorted(p for p, h in refs.items() if p in server and server[p] != h)
    missing = sorted(p for p in refs if p not in server)
    dirs = {p.rsplit("/", 1)[0] for p in refs}
    extra = sorted(p for p in server if p not in refs and p.rsplit("/", 1)[0] in dirs and not re.search(r"(^|/)(node_modules|\.git|\.htaccess)(/|$)", p) and not p.startswith("core/node_modules/"))
    src = "Original-Paket %s, %s." % (ref["package"], "Prüfsumme von drupal.org bestätigt" if ref["verified"] else "OHNE veröffentlichte Prüfsumme (nur https-Quelle)")
    _emit(res, ad.judge_core_files(len(refs), changed, missing, extra, src))


@check(
    "drupal_settings", G_KONFIG, "Drupal-Einstellungsdatei (settings.php)",
    "Steht in der settings.php Auffälliges, und sind die Rechte richtig gesetzt?",
    what="Liest die Datei sites/default/settings.php und prüft auffällige Befehle (eval, base64_decode), update_free_access, hash_salt, trusted_host_patterns und die Schreibrechte der Datei und des Ordners.",
    why="Die settings.php läuft bei jedem Aufruf und enthält die Zugangsdaten zur Datenbank. Sie ist ein beliebter Ort für Hintertüren, und fehlende Schutzeinstellungen erleichtern Angriffe über gefälschte Hostnamen.",
    reads="Die Datei settings.php (Passwörter werden nie angezeigt oder gespeichert) und die Dateirechte von Datei und Ordner. Es wird nichts verändert.",
    load="leicht", needs="ssh", presets=["schnell", "hack", "komplett"], cms="drupal",
)
def drupal_settings(ctx, res):
    cfg = ctx.config()
    modes: Dict[str, str] = {}
    out = ctx.sh("stat -c '%a %U %n' sites/default/settings.php sites/default 2>/dev/null", timeout=20).out
    for ln in out.splitlines():
        m = re.match(r"^(\d{3,4}) (\S+) (.+)\Z", ln.strip())
        if m:
            modes[m.group(3)] = "%s %s" % (m.group(1), m.group(2))
    _emit(res, ad.judge_settings(cfg, modes))


@check(
    "drupal_exposed", G_KONFIG, "Drupal: frei abrufbare Dateien und Schnittstellen",
    "Kann jeder Besucher Einstellungen, Nutzerdaten oder den Installations-Assistenten abrufen?",
    what="Ruft von DIESEM PC aus einzelne Adressen ohne Anmeldung auf: settings.php, composer.json und composer.lock, die JSON:API für Benutzer, die Installationsseite, die Ordnerliste von sites/default/files und die Versionsdatei. Es werden nur normale Seitenaufrufe gesendet.",
    why="Eine abrufbare Konfigurationsdatei, eine offene JSON:API oder eine erreichbare Installationsseite können zur Übernahme der Seite führen. Das lässt sich ohne Anmeldung von außen sehen.",
    reads="Öffentlich erreichbare Adressen Ihrer Domain, so wie jeder Besucher sie sieht. Inhalte werden nicht gespeichert. Es wird nichts verändert.",
    load="leicht", needs="web", presets=["schnell", "hack", "komplett"], cms="drupal",
)
def drupal_exposed(ctx, res):
    url = (ctx.s.url or "").strip()
    if not url:
        raise CheckSkipped("Keine Adresse der Webseite angegeben (Feld 'Webseite' in den Verbindungsdaten).")
    from .. import secure
    url, _ = secure.to_https(url)
    base = url.rstrip("/")
    targets = [("file", "Einstellungsdatei", "/sites/default/settings.php"), ("file", "Einstellungsdatei (Sicherung)", "/sites/default/settings.php.bak"),
               ("file", "Composer-Datei", "/composer.json"), ("file", "Composer-Sperrdatei", "/composer.lock"), ("file", "Umgebungsdatei", "/.env"),
               ("api", "JSON:API Benutzer", "/jsonapi/user/user"), ("install", "Installationsseite", "/core/install.php"),
               ("dir", "Ordner sites/default/files", "/sites/default/files/"), ("version", "Versionsdatei", "/core/CHANGELOG.txt")]
    web: List[Dict[str, Any]] = []
    for kind, label, path in targets:
        ctx.progress("Rufe %s ab" % path)
        f = webmod.fetch(base + path, webmod.UA_BROWSER, max_bytes=20000, timeout=15)
        if f.error:
            continue
        web.append({"kind": kind, "label": label, "url": base + path, "status": f.status, "body": f.body})
    _emit(res, ad.judge_exposed(web))


def _inventory(ctx) -> List[Dict[str, Any]]:
    out = ctx.sh("""for f in $(find modules themes profiles -maxdepth 4 -name '*.info.yml' -type f 2>/dev/null | head -400); do echo "@@F $f"; head -c 2000 "$f"; echo; done""", timeout=120, raw="info_yml", raw_cap=20000).out
    inv, seen = [], set()
    for blk in out.split("@@F ")[1:]:
        path, _, body = blk.partition("\n")
        info = drupal.parse_info_yml(body)
        proj = info.get("project") or drupal.project_of(path.rsplit("/", 1)[0] if "/" in path else path)
        folder = path.strip()
        # eine Erweiterung kann mehrere .info.yml haben (Untermodule): je Projekt nur die erste
        if not proj or proj in seen or info.get("hidden", "").lower() == "true":
            continue
        seen.add(proj)
        inv.append({"project": proj, "name": info.get("name") or proj, "version": info.get("version", ""), "type": info.get("type", ""),
                    "custom": "/custom/" in "/" + folder or folder.startswith("modules/custom") or not info.get("version")})
    return inv


@check(
    "drupal_modules", G_EXT, "Drupal-Module und Themes",
    "Welche Module und Themes laufen, und gibt es Sicherheitsupdates oder nicht mehr betreute Versionen?",
    what="Liest die *.info.yml-Dateien unter modules, themes und profiles (Name, Version) und fragt bei updates.drupal.org je Projekt nach Sicherheitsupdates, unsicheren und nicht mehr betreuten Versionen. "
         "Es werden höchstens 60 Projekte abgefragt. Eigene Module (Ordner custom) werden nur aufgelistet.",
    why="Die meisten Einbrüche bei Drupal laufen über veraltete Module. Drupal.org kennzeichnet unsichere und aufgegebene Versionen, das lässt sich automatisch vergleichen.",
    reads="Die Dateien *.info.yml (nur die ersten 2000 Zeichen) und je Projekt eine Abfrage bei updates.drupal.org. Es wird nichts verändert.",
    load="mittel", needs="web", presets=["schnell", "hack", "komplett"], cms="drupal",
)
def drupal_modules(ctx, res):
    inv = _inventory(ctx)
    states: Dict[str, Any] = {}
    todo = [m for m in inv if not m["custom"]][:MAX_PROJECTS]
    for i, m in enumerate(todo, 1):
        ctx.progress("Frage drupal.org nach %s (%d/%d)" % (m["project"], i, len(todo)))
        h = history(m["project"]) if re.fullmatch(r"[a-z0-9_]{2,60}", m["project"]) else None
        if h:
            states[m["project"]] = ad.release_state(m["version"], h)
    if len([m for m in inv if not m["custom"]]) > MAX_PROJECTS:
        res.add("info", "Nur %d von %d Projekten wurden abgefragt" % (MAX_PROJECTS, len([m for m in inv if not m["custom"]])), "Mehr Abfragen auf einmal werden bewusst nicht gestellt.")
    _emit(res, ad.judge_modules(inv, states))


@check(
    "drupal_users", G_DB, "Drupal-Konten und Administratoren",
    "Wer ist Administrator, und wurde kürzlich ein neues Konto mit Administratorrechten angelegt?",
    what="Liest aus der Datenbank Name, Status, Anlege- und Anmeldedatum der Benutzer und ob sie die Rolle 'administrator' haben. Gemeldet werden neue Administrator-Konten und nie benutzte Administrator-Konten.",
    why="Nach einem Einbruch legen Angreifer gern ein eigenes Administrator-Konto an, weil es auch nach einer Säuberung der Dateien bleibt.",
    reads="Benutzername, Status, Anlege- und Anmeldedatum und die Rollenzuordnung. Passwörter und E-Mail-Adressen werden nicht abgefragt. Es wird nichts verändert.",
    load="leicht", needs="db", presets=["schnell", "hack", "komplett"], cms="drupal",
)
def drupal_users(ctx, res):
    db = need_db(ctx, res, "Drupal-Konten", [("Benutzer", Q_USERS)])
    need_d8(ctx)
    rows = fetch(db, Q_USERS)
    if rows is None:
        _emit(res, ad.judge_users(None))
        return
    us = [{"uid": r.get("uid"), "name": r.get("name"), "status": r.get("status"), "created_ts": _ts(r.get("created")), "access_ts": _ts(r.get("access")), "admin": str(r.get("adm") or "0") not in ("0", "")} for r in rows]
    _emit(res, ad.judge_users(us))


def _ts(v):
    """Drupal speichert Zeitpunkte als Unix-Sekunden (Zahl); Datumstexte werden ebenfalls verstanden. 0 = nie."""
    try:
        n = int(str(v).strip())
        return float(n) if n > 0 else None
    except (TypeError, ValueError):
        return parse_dt(v)


@check(
    "drupal_config_db", G_DB, "Drupal-Einstellungen in der Datenbank",
    "Werden Fehlermeldungen angezeigt, ist die Registrierung offen, laufen Entwicklungsmodule, hat die Rolle der Besucher zu viele Rechte?",
    what="Liest aus der Tabelle config die Einstellungen für Protokollierung, Benutzerregistrierung, die Liste der eingeschalteten Module und die Rechte der Rollen 'anonymous' und 'authenticated' und bewertet sie.",
    why="Falsche Einstellungen öffnen Angreifern Türen, ohne dass eine Datei verändert wurde. Sie stehen nur in der Datenbank und fallen bei einer reinen Dateisuche nicht auf.",
    reads="Fünf Einträge der Tabelle config (Namen, Werte; keine Passwörter). Es wird nichts verändert.",
    load="leicht", needs="db", presets=["schnell", "hack", "komplett"], cms="drupal",
)
def drupal_config_db(ctx, res):
    db = need_db(ctx, res, "Drupal-Einstellungen", [("Einstellungen", Q_CFG)])
    need_d8(ctx)
    rows = fetch(db, Q_CFG)
    if rows is None:
        _emit(res, ad.judge_config(None))
        return
    m = {str(r.get("name")): r.get("v") or "" for r in rows}
    _emit(res, ad.judge_config({"logging": m.get("system.logging"), "user_settings": m.get("user.settings"), "core_extension": m.get("core.extension"),
                                "roles": {"anonymous": m.get("user.role.anonymous"), "authenticated": m.get("user.role.authenticated")}}))


@check(
    "drupal_db_code", G_DB, "Eingeschleuster Code in Drupal-Inhalten",
    "Stehen in Beiträgen, Blöcken oder Kommentaren Skripte, Iframes oder verschleierter Code?",
    what="Sucht in den Textfeldern von Beiträgen, Blöcken und Kommentaren nach <script>, <iframe>, javascript:, eval(, atob( und fromCharCode und zeigt die Stelle.",
    why="Angreifer schleusen Code gern in Inhalte ein, weil er in der Datenbank steht und bei einer Dateisuche nicht auftaucht. Besucher werden dann umgeleitet oder ihre Eingaben abgegriffen.",
    reads="Die Textfelder body_value und comment_body_value (nur Treffer, höchstens 200 je Tabelle). Es wird nichts verändert.",
    load="mittel", needs="db", presets=["hack", "komplett"], cms="drupal",
)
def drupal_db_code(ctx, res):
    db = need_db(ctx, res, "Code in Drupal-Inhalten", [("Beiträge", Q_CODE["node__body"] % LIKES)])
    need_d8(ctx)
    rows: List[Dict[str, Any]] = []
    got = False
    for tbl, q in Q_CODE.items():
        where = LIKES if tbl != "comment__comment_body" else LIKES.replace("body_value", "comment_body_value")
        r = fetch(db, q % where)
        if r is None:
            continue
        got = True
        rows += [{"table": tbl, "id": x.get("id"), "text": x.get("text")} for x in r]
    _emit(res, ad.judge_db_code(rows if got else None))
