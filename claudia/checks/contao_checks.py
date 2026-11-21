"""Contao-Prüfungen (2.11.0): Kern, Einstellungen, abrufbare Dateien, Pakete, Backend-Konten und Code in Inhalten. Nur lesend, Contao 4.13 und neuer (Composer).

Die Bewertung steckt in auswertung_contao.py (reine Funktionen, mit Beispieldaten geprüft). Hier stehen nur die Abfragen.
Noch NICHT gegen einen echten Contao-Server geprüft: Antwortformat von Packagist und GitHub-Archiv sowie die Tabellen- und Feldnamen (tl_user, tl_content, tl_module, tl_layout).
Fehlt etwas, melden die Prüfungen 'nicht prüfbar' statt zu raten. APP_SECRET, Passwörter und Mail-Zugangsdaten werden nie ausgegeben."""
from __future__ import annotations

import os
import re
from typing import Any, Dict, List, Tuple

from .. import contao, contaoref, coreref
from ..model import CheckSkipped
from ..registry import check
from ..util import split_sections
from . import auswertung_contao as ac
from . import web as webmod
from .database import fetch, need_db
from .joomla_core import parse_sums
from .typo3_checks import advisories, MAX_PACKAGES

RELEASE_URLS = ("https://repo.packagist.org/p2/contao/core-bundle.json", "https://packagist.org/packages/contao/core-bundle.json")

Q_USERS = ("SELECT id AS uid, username AS name, admin AS adm, disable AS dis, dateAdded AS created, lastLogin AS access, useTwoFactor AS tf FROM #__tl_user ORDER BY id LIMIT 500")
Q_USERS_MIN = ("SELECT id AS uid, username AS name, admin AS adm, disable AS dis, dateAdded AS created, lastLogin AS access FROM #__tl_user ORDER BY id LIMIT 500")
LIKE_TMPL = "(%(c)s LIKE '%%<script%%' OR %(c)s LIKE '%%<iframe%%' OR %(c)s LIKE '%%atob(%%' OR %(c)s LIKE '%%fromCharCode%%' OR %(c)s LIKE '%%eval(%%' OR %(c)s LIKE '%%javascript:%%')"
CODE_FIELDS = (("tl_content", "text"), ("tl_content", "html"), ("tl_module", "html"), ("tl_layout", "head"), ("tl_layout", "script"), ("tl_article", "teaser"))
Q_CODE = {"%s.%s" % (t, c): "SELECT id AS id, %s AS text FROM #__%s WHERE %s LIMIT 200" % (c, t, LIKE_TMPL % {"c": c}) for t, c in CODE_FIELDS}

G_KONFIG, G_EXT, G_DB = "konfig", "erweiterungen", "datenbank"


def _emit(res, rows) -> None:
    for sev, title, text, items, hint in rows:
        res.add(sev, title, text, items, hint)


def _q(s: str) -> str:
    return "'" + s.replace("'", "'\\''") + "'"


def layout(ctx) -> Dict[str, Any]:
    """Version, Pakete und Installationsart (einmal je Lauf lesen)."""
    if "contao_layout" not in ctx.shared:
        script = r"""R=.; if [ ! -d vendor/contao ] && [ -d ../vendor/contao ]; then R=..; fi
echo '@@ROOT'; echo "$R"
echo '@@LOCK'; if [ -f "$R/composer.lock" ]; then head -c 6000000 "$R/composer.lock"; fi
echo; echo '@@INST'; if [ -f "$R/vendor/composer/installed.php" ]; then head -c 3000000 "$R/vendor/composer/installed.php"; fi
echo; echo '@@LEGACY'; if [ -f system/modules/core/config/config.php ]; then head -c 20000 system/modules/core/config/config.php; fi
echo '@@MODE'; if [ -d "$R/vendor/contao" ]; then echo composer; elif [ -d system/modules/core ]; then echo legacy; else echo unknown; fi"""
        sec = split_sections(ctx.sh(script, timeout=60, raw="contao_lage", raw_cap=2000).out)
        lock = sec.get("LOCK", "")
        ctx.shared["contao_layout"] = {"version": contao.parse_core_version(lock, sec.get("INST", ""), sec.get("LEGACY", "")), "mode": (sec.get("MODE", "unknown").split() or ["unknown"])[0],
                                       "root": (sec.get("ROOT", ".").split() or ["."])[0], "packages": contao.parse_lock(lock)}
    return ctx.shared["contao_layout"]


def contao_version(ctx) -> str:
    return layout(ctx)["version"]


def releases(ctx) -> List[Dict[str, str]]:
    if "contao_releases" not in ctx.shared:
        out: List[Dict[str, str]] = []
        if not os.environ.get("CLAUDIA_OFFLINE"):
            for u in RELEASE_URLS:
                f = webmod.fetch(u, webmod.UA_BROWSER, max_bytes=8_000_000, timeout=25)
                if not f.error and f.status == 200:
                    out = contao.parse_release_list(f.body)
                    if out:
                        break
        ctx.shared["contao_releases"] = out
    return ctx.shared["contao_releases"]


@check(
    "contao_core", G_KONFIG, "Contao-Kern: Version, Sicherheitsmeldungen und Originaldateien",
    "Ist Contao aktuell und unterstützt, und stimmen die Dateien der Kern-Pakete mit dem Original überein?",
    what="Liest die Version aus composer.lock, prüft anhand einer Tabelle, ob die Version noch Sicherheitsupdates bekommt, fragt bei Packagist nach der neuesten Version und nach Sicherheitsmeldungen zu dieser Version "
         "und vergleicht die Dateien der Kern-Pakete (vendor/contao/core-bundle, manager-bundle, installation-bundle) mit dem Original von GitHub. Auf dem Server werden nur Prüfsummen berechnet.",
    why="Veraltete Contao-Versionen werden automatisch angegriffen. Manipulierte Kerndateien sind ein häufiger Ort für Hintertüren, die keinem Schadcode-Muster entsprechen.",
    reads="Dateinamen und Prüfsummen unter vendor/contao/* des Servers sowie composer.lock; vom Internet die Versionsliste, die Sicherheitsmeldungen und die Original-Pakete (nur https). Es wird nichts verändert.",
    load="mittel", needs="web", presets=["schnell", "hack", "komplett"], cms="contao",
)
def contao_core(ctx, res):
    lay = layout(ctx)
    ver = lay["version"]
    rel: List[Dict[str, str]] = []
    adv: Dict[str, List[Dict[str, str]]] = {}
    adv_ok = False
    modern = bool(ver) and not re.match(r"^[0-3]\.", ver)
    if modern:
        ctx.progress("Frage Packagist")
        rel = releases(ctx)
        adv, adv_ok = advisories(["contao/core-bundle"])
    _emit(res, ac.judge_core(ver, rel, contao.advisories_for(ver, adv, "contao/core-bundle") if ver else [], adv_ok=adv_ok if modern else True))
    if not modern or lay["mode"] != "composer":
        return
    if os.environ.get("CLAUDIA_OFFLINE"):
        res.add("info", "Dateivergleich übersprungen", "Offline-Modus (CLAUDIA_OFFLINE): Die Original-Pakete werden nicht geladen.")
        return
    versions = {p["name"]: p["version"] for p in lay["packages"] if p["name"] in contao.CORE_PACKAGES and contaoref.VERSION_RE.match(p["version"])}
    if not versions:
        res.add("info", "Dateivergleich nicht möglich", "Für die Kern-Pakete liegen keine stabilen Versionsnummern vor (Vorabversion?).")
        return
    out = ctx.sh(contaoref.server_hash_sh(sorted(versions)) + '; echo "@@HASHER"; command -v sha256sum >/dev/null 2>&1 && echo sha256sum || echo none', timeout=600, raw="pruefsummen", raw_cap=40_000).out
    tail = out.rsplit("@@HASHER", 1)
    if len(tail) == 2 and "none" in tail[1].split():
        res.add("info", "Dateivergleich nicht möglich", "Auf dem Server gibt es kein sha256sum.")
        return
    server = contaoref.parse_server_hashes(tail[0])
    for pkg, v in sorted(versions.items()):
        srv = server.get(pkg) or {}
        if len(srv) < 5:
            res.add("info", "%s: Dateivergleich nicht möglich" % pkg, "Unter vendor/%s wurden nur %d Dateien gefunden." % (pkg, len(srv)))
            continue
        ctx.progress("Lade das Original-Paket %s %s" % (pkg, v))
        try:
            ref = contaoref.reference(pkg, v)
        except coreref.RefError as e:
            res.add("info", "%s: Dateivergleich nicht möglich" % pkg, "Original-Paket nicht verfügbar: %s" % e)
            continue
        diff = contaoref.compare(ref["files"], srv)
        src = "Original-Paket %s von GitHub, OHNE veröffentlichte Prüfsumme (nur https-Quelle)." % ref["package"]
        _emit(res, ac.judge_core_files(pkg, len(ref["files"]), diff["changed"], diff["missing"], diff["extra"], src))


@check(
    "contao_settings", G_KONFIG, "Contao-Einstellungen (.env, parameters.yaml, localconfig.php)",
    "Steht in den Einstellungsdateien Auffälliges, läuft Contao im Produktivmodus, und sind die Rechte richtig gesetzt?",
    what="Liest .env, config/parameters.yaml, config/config.yaml und (ältere Versionen) system/config/localconfig.php. Geprüft werden auffällige Befehle, APP_ENV und APP_DEBUG, Länge und Beispielwert des APP_SECRET, "
         "TRUSTED_HOSTS, erlaubte Dateitypen beim Hochladen, erlaubte HTML-Tags, die Mindestlänge für Passwörter und die Dateirechte.",
    why="Die Einstellungsdateien laufen bzw. gelten bei jedem Aufruf und enthalten die Zugangsdaten zur Datenbank. Ein Entwicklungsmodus oder ein bekanntes APP_SECRET machen Angriffe einfacher.",
    reads="Die Einstellungsdateien (Passwörter, APP_SECRET und Mail-Zugangsdaten werden nie angezeigt oder gespeichert; vom APP_SECRET nur die Länge) und die Dateirechte. Es wird nichts verändert.",
    load="leicht", needs="ssh", presets=["schnell", "hack", "komplett"], cms="contao",
)
def contao_settings(ctx, res):
    cfg = ctx.config()
    modes: Dict[str, str] = {}
    paths = [p for p in (cfg.get("files") or []) if p]
    if paths:
        out = ctx.sh("stat -c '%%a %%U %%n' %s 2>/dev/null" % " ".join(_q(p) for p in paths[:12]), timeout=20).out
        for ln in out.splitlines():
            m = re.match(r"^(\d{3,4}) (\S+) (.+)$", ln.strip())
            if m:
                modes[m.group(3)] = "%s %s" % (m.group(1), m.group(2))
    _emit(res, ac.judge_settings(cfg, modes))


@check(
    "contao_exposed", G_KONFIG, "Contao: frei abrufbare Dateien und Seiten",
    "Kann jeder Besucher Einstellungen, Composer-Dateien, das Install-Tool oder einen Entwicklungs-Eingang abrufen?",
    what="Ruft von DIESEM PC aus einzelne Adressen ohne Anmeldung auf: .env, config/parameters.yaml, composer.json und composer.lock, localconfig.php, .git/config, Ordnerlisten von files und var, "
         "das Install-Tool, den Contao Manager, den Profiler/Entwicklungs-Eingang und die Backend-Anmeldung. Es werden nur normale Seitenaufrufe gesendet.",
    why="Eine abrufbare Konfigurationsdatei oder ein erreichbares Verwaltungswerkzeug können zur Übernahme der Seite führen. Das lässt sich ohne Anmeldung von außen sehen.",
    reads="Öffentlich erreichbare Adressen Ihrer Domain, so wie jeder Besucher sie sieht. Inhalte werden nicht gespeichert. Es wird nichts verändert.",
    load="leicht", needs="web", presets=["schnell", "hack", "komplett"], cms="contao",
)
def contao_exposed(ctx, res):
    url = (ctx.s.url or "").strip()
    if not url:
        raise CheckSkipped("Keine Adresse der Webseite angegeben (Feld 'Webseite' in den Verbindungsdaten).")
    from .. import secure
    url, _ = secure.to_https(url)
    base = url.rstrip("/")
    targets = [("file", "Umgebungsdatei", "/.env"), ("file", "Umgebungsdatei", "/.env.local"), ("file", "Einstellungsdatei", "/config/parameters.yaml"), ("file", "Einstellungsdatei", "/config/config.yaml"),
               ("file", "Einstellungsdatei", "/system/config/localconfig.php"), ("file", "Composer-Datei", "/composer.json"), ("file", "Composer-Sperrdatei", "/composer.lock"),
               ("file", "Git-Konfiguration", "/.git/config"), ("file", "Protokolle", "/var/logs/prod.log"),
               ("dir", "Ordner files", "/files/"), ("dir", "Ordner var", "/var/"),
               ("install", "Install-Tool", "/contao/install"), ("manager", "Contao Manager", "/contao-manager.phar.php"),
               ("profiler", "Profiler", "/_profiler/"), ("profiler", "Entwicklungs-Eingang", "/app_dev.php"),
               ("backend", "Backend-Anmeldung", "/contao")]
    web: List[Dict[str, Any]] = []
    for kind, label, path in targets:
        ctx.progress("Rufe %s ab" % path)
        f = webmod.fetch(base + path, webmod.UA_BROWSER, max_bytes=20000, timeout=15)
        if f.error:
            continue
        web.append({"kind": kind, "label": label, "url": base + path, "status": f.status, "body": f.body})
    _emit(res, ac.judge_exposed(web))


def _inventory(ctx) -> Tuple[List[Dict[str, Any]], Dict[str, str]]:
    """Pakete (Anzeige) und {Paketname: Version} zum Abfragen bei Packagist: zuerst contao/*, dann die übrigen (höchstens MAX_PACKAGES)."""
    pk = layout(ctx)["packages"]
    inv: List[Dict[str, Any]] = []
    pkgs: Dict[str, str] = {}
    first = sorted(pk, key=lambda p: (not p["name"].startswith(("contao/", "contao-")), p["name"]))
    for p in first:
        if not p["version"]:
            continue
        inv.append({"key": p["name"], "name": p["name"], "version": p["version"], "pkg": p["name"], "custom": p["custom"],
                    "ext": p["type"] in ("contao-bundle", "contao-module", "contao-component") or p["name"].startswith(("contao-community-alliance/", "codefog/", "terminal42/", "heimrichhannot/", "menatwork/", "netzmacht/", "inspiredminds/")) and not p["name"].startswith("contao/")})
        if not p["custom"]:
            pkgs[p["name"]] = p["version"]
    return inv, pkgs


@check(
    "contao_packages", G_EXT, "Contao-Pakete und Erweiterungen",
    "Welche Pakete und Erweiterungen laufen, und gibt es zu ihren Versionen bekannte Sicherheitsmeldungen?",
    what="Liest die Pakete aus composer.lock (Name, Version, Art) und fragt bei Packagist nach Sicherheitsmeldungen, die auf genau diese Versionen zutreffen (zuerst contao/*, dann die übrigen; höchstens 150 Pakete). "
         "Eigene Pakete (lokale Pfade) werden nur aufgelistet; Entwicklungs-Pakete auf dem Live-Server werden gemeldet.",
    why="Die meisten Einbrüche laufen über veraltete Erweiterungen und Bibliotheken. Packagist führt Sicherheitsmeldungen mit den betroffenen Versionen; das lässt sich automatisch vergleichen.",
    reads="composer.lock (Paketnamen und Versionen); im Internet Packagist (nur Paketnamen und Versionen werden gesendet). Es wird nichts verändert.",
    load="mittel", needs="web", presets=["schnell", "hack", "komplett"], cms="contao",
)
def contao_packages(ctx, res):
    inv, pkgs = _inventory(ctx)
    adv: Dict[str, List[Dict[str, str]]] = {}
    ok = False
    if pkgs:
        ctx.progress("Frage Packagist nach Sicherheitsmeldungen (%d Pakete)" % min(len(pkgs), MAX_PACKAGES))
        adv, ok = advisories(list(pkgs))
        if len(pkgs) > MAX_PACKAGES:
            res.add("info", "Nur %d von %d Paketen wurden abgefragt" % (MAX_PACKAGES, len(pkgs)), "Mehr Abfragen auf einmal werden bewusst nicht gestellt.")
    hits: Dict[str, List[Dict[str, str]]] = {}
    for m in inv:
        if m.get("pkg") and m.get("version") and not m.get("custom"):
            h = contao.advisories_for(m["version"], adv, m["pkg"])
            if h:
                hits[m["key"]] = h
    _emit(res, ac.judge_packages(inv, hits, checked=min(len(pkgs), MAX_PACKAGES), adv_ok=ok))


@check(
    "contao_users", G_DB, "Contao-Backend-Konten und Administratoren",
    "Wer ist Administrator, hat er Zwei-Faktor-Anmeldung, und wurde kürzlich ein neues Konto angelegt?",
    what="Liest aus der Tabelle tl_user Name, Status, Anlege- und Anmeldedatum, ob ein Konto Administrator ist und ob die Zwei-Faktor-Anmeldung eingeschaltet ist. Gemeldet werden neue Administrator-Konten, Administratoren ohne Zwei-Faktor, "
         "nie benutzte Konten, sehr viele Administratoren und leicht zu erratende Namen.",
    why="Nach einem Einbruch legen Angreifer gern ein eigenes Administrator-Konto an, weil es auch nach einer Säuberung der Dateien bleibt.",
    reads="Benutzername, Status, Anlege- und Anmeldedatum, Administrator-Merkmal und Zwei-Faktor-Merkmal. Passwörter und E-Mail-Adressen werden nicht abgefragt. Es wird nichts verändert.",
    load="leicht", needs="db", presets=["schnell", "hack", "komplett"], cms="contao",
)
def contao_users(ctx, res):
    db = need_db(ctx, res, "Contao-Konten", [("Backend-Benutzer", Q_USERS)])
    rows = fetch(db, Q_USERS)
    has_tf = rows is not None
    if rows is None:
        rows = fetch(db, Q_USERS_MIN)
    if rows is None:
        _emit(res, ac.judge_users(None))
        return
    us = [{"uid": r.get("uid"), "name": r.get("name"), "admin": str(r.get("adm") or "0") not in ("0", ""), "disabled": str(r.get("dis") or "0") not in ("0", ""),
           "created_ts": _ts(r.get("created")), "access_ts": _ts(r.get("access")),
           "tf": (str(r.get("tf") or "0") not in ("0", "")) if has_tf else None} for r in rows]
    _emit(res, ac.judge_users(us))


def _ts(v):
    """Contao speichert Zeitpunkte als Unix-Sekunden (Zahl); 0 oder leer = nie."""
    try:
        n = int(str(v).strip())
        return float(n) if n > 0 else None
    except (TypeError, ValueError):
        return None


@check(
    "contao_db_code", G_DB, "Eingeschleuster Code in Contao-Inhalten",
    "Stehen in Inhaltselementen, Modulen oder Seitenlayouts Skripte, Iframes oder verschleierter Code?",
    what="Sucht in den Textfeldern der Inhaltselemente (tl_content: Text, HTML), der Module (tl_module: HTML), der Seitenlayouts (tl_layout: Kopfbereich, Skripte) und der Artikel-Teaser nach <script>, <iframe>, javascript:, eval(, atob( und fromCharCode und zeigt die Stelle.",
    why="Angreifer schleusen Code gern in Inhalte ein, weil er in der Datenbank steht und bei einer Dateisuche nicht auftaucht. Besucher werden dann umgeleitet oder ihre Eingaben abgegriffen.",
    reads="Die genannten Textfelder (nur Treffer, höchstens 200 je Feld). Es wird nichts verändert.",
    load="mittel", needs="db", presets=["hack", "komplett"], cms="contao",
)
def contao_db_code(ctx, res):
    db = need_db(ctx, res, "Code in Contao-Inhalten", [("Inhaltselemente", Q_CODE["tl_content.text"])])
    rows: List[Dict[str, Any]] = []
    got = False
    for name, q in Q_CODE.items():
        r = fetch(db, q)
        if r is None:
            continue
        got = True
        rows += [{"table": name, "id": x.get("id"), "text": x.get("text")} for x in r]
    _emit(res, ac.judge_db_code(rows if got else None))
