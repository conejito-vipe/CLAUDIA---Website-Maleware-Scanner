"""PrestaShop-Prüfungen (2.12.0): Kern, Einstellungen, abrufbare Dateien, Module, Mitarbeiterkonten, Shop-Einstellungen und Code in Inhalten. Nur lesend, PrestaShop 1.7, 8 und 9 (1.6 eingeschränkt).

Die Bewertung steckt in auswertung_prestashop.py (reine Funktionen, mit Beispieldaten geprüft). Hier stehen nur die Abfragen.
Noch NICHT gegen einen echten PrestaShop-Server geprüft: Antwortformate von Packagist und GitHub sowie Tabellen- und Feldnamen (ps_employee, ps_configuration, ps_webservice_*, ps_cms_lang u. a.).
Fehlt etwas, melden die Prüfungen 'nicht prüfbar' statt zu raten. Passwörter, cookie_key und Webservice-Schlüssel werden nie ausgegeben."""
from __future__ import annotations

import os
import re
import time
from typing import Any, Dict, List, Tuple

from .. import coreref, prestashop, prestashopref, secure
from ..model import CheckSkipped
from ..registry import check
from . import auswertung_prestashop as ap
from . import web as webmod
from .database import fetch, need_db
from .typo3_checks import MAX_PACKAGES, advisories

RELEASE_URLS = ("https://repo.packagist.org/p2/prestashop/prestashop.json", "https://packagist.org/packages/prestashop/prestashop.json")
G_KONFIG, G_EXT, G_DB = "konfig", "erweiterungen", "datenbank"

Q_USERS = ("SELECT id_employee AS uid, firstname AS fn, lastname AS ln, id_profile AS prof, active AS act, date_add AS created, last_connection_date AS access FROM #__employee ORDER BY id_employee LIMIT 500")
Q_USERS_MIN = ("SELECT id_employee AS uid, firstname AS fn, lastname AS ln, id_profile AS prof, active AS act, date_add AS created FROM #__employee ORDER BY id_employee LIMIT 500")
CONF_NAMES = ("PS_WEBSERVICE", "PS_SSL_ENABLED", "PS_SSL_ENABLED_EVERYWHERE", "PS_DISABLE_OVERRIDES")
Q_CONF = "SELECT name AS name, value AS value FROM #__configuration WHERE name IN (%s)" % ", ".join("'%s'" % n for n in CONF_NAMES)
Q_KEYS = "SELECT id_webservice_account AS id, description AS descr, active AS act FROM #__webservice_account ORDER BY id_webservice_account LIMIT 100"
Q_PERMS = "SELECT id_webservice_account AS id, method AS m FROM #__webservice_permission WHERE method IN ('POST', 'PUT', 'DELETE') GROUP BY id_webservice_account, method LIMIT 500"
LIKE_TMPL = "(%(c)s LIKE '%%<script%%' OR %(c)s LIKE '%%<iframe%%' OR %(c)s LIKE '%%atob(%%' OR %(c)s LIKE '%%fromCharCode%%' OR %(c)s LIKE '%%eval(%%' OR %(c)s LIKE '%%javascript:%%')"
CODE_FIELDS = (("cms_lang", "content", "id_cms"), ("product_lang", "description", "id_product"), ("product_lang", "description_short", "id_product"), ("category_lang", "description", "id_category"),
               ("customtext_lang", "text", "id_customtext"), ("configuration", "value", "id_configuration"))
Q_CODE = {"%s.%s" % (t, c): "SELECT %s AS id, %s AS text FROM #__%s WHERE %s LIMIT 200" % (i, c, t, LIKE_TMPL % {"c": c}) for t, c, i in CODE_FIELDS}


def _emit(res, rows) -> None:
    for sev, title, text, items, hint in rows:
        res.add(sev, title, text, items, hint)


def _q(s: str) -> str:
    return "'" + s.replace("'", "'\\''") + "'"


def ps_version(ctx) -> str:
    cfg = ctx.config()
    return str(cfg.get("version") or "")


def releases(ctx) -> List[Dict[str, str]]:
    if "ps_releases" not in ctx.shared:
        out: List[Dict[str, str]] = []
        if not os.environ.get("CLAUDIA_OFFLINE"):
            for u in RELEASE_URLS:
                f = webmod.fetch(u, webmod.UA_BROWSER, max_bytes=8_000_000, timeout=25)
                if not f.error and f.status == 200:
                    out = prestashop.parse_release_list(f.body)
                    if out:
                        break
        ctx.shared["ps_releases"] = out
    return ctx.shared["ps_releases"]


@check(
    "prestashop_core", G_KONFIG, "PrestaShop-Kern: Version, Sicherheitsmeldungen und Originaldateien",
    "Ist PrestaShop aktuell und unterstützt, und stimmen die Programmdateien mit dem Original überein?",
    what="Liest die Version aus app/AppKernel.php, prüft anhand einer Tabelle, in welcher Support-Phase die Version steht, fragt bei Packagist nach der neuesten Version und nach Sicherheitsmeldungen zu dieser Version "
         "und vergleicht die Ordner classes, controllers und src mit dem Original von GitHub. Auf dem Server werden nur Prüfsummen berechnet.",
    why="Veraltete PrestaShop-Versionen werden automatisch angegriffen. Manipulierte Kerndateien sind ein häufiger Ort für Hintertüren und Zahlungsdaten-Abgreifer, die keinem Schadcode-Muster entsprechen.",
    reads="Dateinamen und Prüfsummen unter classes, controllers und src des Servers sowie app/AppKernel.php; vom Internet die Versionsliste, die Sicherheitsmeldungen und das Original-Paket (nur https). Es wird nichts verändert.",
    load="mittel", needs="web", presets=["schnell", "hack", "komplett"], cms="prestashop",
)
def prestashop_core(ctx, res):
    ver = ps_version(ctx)
    rel: List[Dict[str, str]] = []
    adv: Dict[str, List[Dict[str, str]]] = {}
    adv_ok = False
    if ver:
        ctx.progress("Frage Packagist")
        rel = releases(ctx)
        adv, adv_ok = advisories(["prestashop/prestashop"])
    _emit(res, ap.judge_core(ver, rel, prestashop.advisories_for(ver, adv, "prestashop/prestashop") if ver else [], adv_ok=adv_ok if ver else True))
    if not ver:
        return
    if os.environ.get("CLAUDIA_OFFLINE"):
        res.add("info", "Dateivergleich übersprungen", "Offline-Modus (CLAUDIA_OFFLINE): Das Original-Paket wird nicht geladen.")
        return
    if not prestashopref.VERSION_RE.match(ver):
        res.add("info", "Dateivergleich nicht möglich", "Für die Version '%s' liegt kein stabiles Paket zum Vergleich vor (Vorabversion?)." % ver)
        return
    out = ctx.sh(prestashopref.server_hash_sh() + '; echo "@@HASHER"; command -v sha256sum >/dev/null 2>&1 && echo sha256sum || echo none', timeout=600, raw="pruefsummen", raw_cap=40_000).out
    tail = out.rsplit("@@HASHER", 1)
    if len(tail) == 2 and "none" in tail[1].split():
        res.add("info", "Dateivergleich nicht möglich", "Auf dem Server gibt es kein sha256sum.")
        return
    srv = prestashopref.parse_server_hashes(tail[0])
    if len(srv) < 50:
        res.add("info", "Dateivergleich nicht möglich", "In classes, controllers und src wurden nur %d Dateien gefunden." % len(srv))
        return
    ctx.progress("Lade das Original-Paket PrestaShop %s" % ver)
    try:
        ref = prestashopref.reference(ver)
    except coreref.RefError as e:
        res.add("info", "Dateivergleich nicht möglich", "Original-Paket nicht verfügbar: %s" % e)
        return
    diff = prestashopref.compare(ref["files"], srv)
    src = "Original-Paket %s von GitHub (Quelltext), OHNE veröffentlichte Prüfsumme (nur https-Quelle)." % ref["package"]
    _emit(res, ap.judge_core_files("classes, controllers, src", len(ref["files"]), diff["changed"], diff["missing"], diff["extra"], src))


@check(
    "prestashop_settings", G_KONFIG, "PrestaShop-Einstellungen (parameters.php, Entwicklungsmodus, Ordner)",
    "Steht in den Einstellungsdateien Auffälliges, ist der Entwicklungsmodus aus, und liegen Installations- oder Verwaltungsordner unsicher?",
    what="Liest app/config/parameters.php, config/defines.inc.php und (PrestaShop 1.6) config/settings.inc.php. Geprüft werden auffällige Befehle, der Entwicklungsmodus, Länge des cookie_key, ein übrig gebliebener Installationsordner, "
         "ein leicht zu erratender Name des Verwaltungsordners und die Dateirechte.",
    why="Die Einstellungsdateien laufen bei jedem Aufruf mit und enthalten die Datenbank-Zugangsdaten; ein Installationsordner oder ein Standardname der Verwaltung erleichtern Angriffe.",
    reads="Die Einstellungsdateien (Passwörter und cookie_key werden nie angezeigt oder gespeichert; vom Schlüssel nur die Länge), die Ordnernamen admin* und install* sowie die Dateirechte. Es wird nichts verändert.",
    load="leicht", needs="ssh", presets=["schnell", "hack", "komplett"], cms="prestashop",
)
def prestashop_settings(ctx, res):
    cfg = ctx.config()
    modes: Dict[str, str] = {}
    paths = [p for p in (cfg.get("files") or []) if p]
    if paths:
        out = ctx.sh("stat -c '%%a %%U %%n' %s 2>/dev/null" % " ".join(_q(p) for p in paths[:6]), timeout=20).out
        for ln in out.splitlines():
            m = re.match(r"^(\d{3,4}) (\S+) (.+)\Z", ln.strip())
            if m:
                modes[m.group(3)] = "%s %s" % (m.group(1), m.group(2))
    _emit(res, ap.judge_settings(cfg, cfg.get("dirs") or [], modes))


@check(
    "prestashop_exposed", G_KONFIG, "PrestaShop: frei abrufbare Dateien und Seiten",
    "Kann jeder Besucher Einstellungen, Protokolle, den Installationsassistenten oder die Verwaltung unter dem Standardnamen abrufen?",
    what="Ruft von DIESEM PC aus einzelne Adressen ohne Anmeldung auf: parameters.php, settings.inc.php, composer.json, .git/config, Protokolle, Ordnerlisten (modules, upload, download), den Installationsordner, "
         "die Verwaltung unter den Namen admin und admin-dev und die Webservice-Schnittstelle /api. Es werden nur normale Seitenaufrufe gesendet.",
    why="Eine abrufbare Konfigurationsdatei oder ein erreichbarer Installationsassistent können zur Übernahme des Shops führen. Das lässt sich ohne Anmeldung von außen sehen.",
    reads="Öffentlich erreichbare Adressen Ihrer Domain, so wie jeder Besucher sie sieht. Inhalte werden nicht gespeichert. Es wird nichts verändert.",
    load="leicht", needs="web", presets=["schnell", "hack", "komplett"], cms="prestashop",
)
def prestashop_exposed(ctx, res):
    url = (ctx.s.url or "").strip()
    if not url:
        raise CheckSkipped("Keine Adresse der Webseite angegeben (Feld 'Webseite' in den Verbindungsdaten).")
    url, _ = secure.to_https(url)
    base = url.rstrip("/")
    targets = [("file", "Einstellungsdatei", "/app/config/parameters.php"), ("file", "Einstellungsdatei", "/config/settings.inc.php"), ("file", "Einstellungsdatei", "/config/defines.inc.php"),
               ("file", "Composer-Datei", "/composer.json"), ("file", "Git-Konfiguration", "/.git/config"), ("file", "Umgebungsdatei", "/.env"),
               ("dir", "Ordner var/logs", "/var/logs/"), ("dir", "Ordner modules", "/modules/"), ("dir", "Ordner upload", "/upload/"), ("dir", "Ordner download", "/download/"),
               ("install", "Installationsordner", "/install/"), ("install", "Installationsordner", "/install-dev/"),
               ("admin", "Verwaltung", "/admin/"), ("admin", "Verwaltung", "/admin-dev/"), ("api", "Webservice", "/api/")]
    web: List[Dict[str, Any]] = []
    for kind, label, path in targets:
        ctx.progress("Rufe %s ab" % path)
        f = webmod.fetch(base + path, webmod.UA_BROWSER, max_bytes=20000, timeout=15)
        if f.error:
            continue
        web.append({"kind": kind, "label": label, "url": base + path, "status": f.status, "body": f.body})
    _emit(res, ap.judge_exposed(web))


def _parse_modules(out: str) -> Tuple[List[Dict[str, Any]], List[str], bool]:
    """(Module, Override-Dateien, Ordner modules vorhanden). Ausgabe von read_modules_sh."""
    mods: List[Dict[str, Any]] = []
    overrides: List[str] = []
    ok = "@@MODDIR" in out
    for m in re.finditer(r"^@@M (\S+)\n(.*?)(?=^@@M |^@@O|\Z)", out, re.S | re.M):
        name, body = m.group(1), m.group(2)
        ver = re.search(r"<version><!\[CDATA\[([^\]]*)\]\]></version>", body)
        author = re.search(r"<author><!\[CDATA\[([^\]]*)\]\]></author>", body)
        pkg = re.search(r'"name"\s*:\s*"([a-z0-9_.\-]+/[a-z0-9_.\-]+)"', body)
        v = prestashop.norm_version(ver.group(1)) if ver else ""
        mods.append({"key": name, "name": name, "version": v, "pkg": pkg.group(1) if pkg and v else "", "core": bool(author and author.group(1).strip().lower() == "prestashop")})
    o = re.search(r"^@@O\n(.*)\Z", out, re.S | re.M)
    if o:
        overrides = [ln.strip() for ln in o.group(1).splitlines() if ln.strip() and not ln.strip().endswith("index.php")]
    return mods, overrides, ok


READ_MODULES_SH = r"""[ -d modules ] && echo '@@MODDIR'
for d in modules/*/; do n=${d#modules/}; n=${n%/}; echo "@@M $n"; [ -f "$d/config.xml" ] && head -c 3000 "$d/config.xml"; echo; [ -f "$d/composer.json" ] && head -c 2000 "$d/composer.json"; echo; done 2>/dev/null | head -c 3000000
echo '@@O'; find override -type f -name '*.php' 2>/dev/null | head -100"""


@check(
    "prestashop_modules", G_EXT, "PrestaShop-Module und Overrides",
    "Welche Module und Overrides laufen, und gibt es zu Modulversionen bekannte Sicherheitsmeldungen?",
    what="Liest je Modul Name, Version und Hersteller aus config.xml sowie den Composer-Namen aus composer.json (falls vorhanden) und fragt bei Packagist nach Sicherheitsmeldungen, die auf genau diese Versionen zutreffen (höchstens 150 Pakete). "
         "Listet außerdem die Dateien unter override/ auf. Die meisten Module sind nicht bei Packagist geführt; das wird offen gesagt.",
    why="Module von Dritten sind der häufigste Weg für Angriffe auf PrestaShop-Shops (SQL-Einschleusung, Datei-Upload, Zahlungsdaten-Abgreifer). Overrides ersetzen Programmklassen und sind ein beliebter Ort für versteckten Code.",
    reads="Die Dateien config.xml und composer.json je Modul (Name, Version, Hersteller) und die Dateinamen unter override/; im Internet Packagist (nur Paketnamen und Versionen werden gesendet). Es wird nichts verändert.",
    load="mittel", needs="web", presets=["schnell", "hack", "komplett"], cms="prestashop",
)
def prestashop_modules(ctx, res):
    mods, overrides, ok = _parse_modules(ctx.sh(READ_MODULES_SH, timeout=60, raw="module", raw_cap=4000).out)
    pk = {m["pkg"]: m["version"] for m in mods if m["pkg"]}
    adv: Dict[str, List[Dict[str, str]]] = {}
    adv_ok = False
    if pk:
        ctx.progress("Frage Packagist nach Sicherheitsmeldungen (%d Pakete)" % min(len(pk), MAX_PACKAGES))
        adv, adv_ok = advisories(list(pk))
    hits: Dict[str, List[Dict[str, str]]] = {}
    for m in mods:
        if m["pkg"]:
            h = prestashop.advisories_for(m["version"], adv, m["pkg"])
            if h:
                hits[m["key"]] = h
    _emit(res, ap.judge_modules(mods, hits, checked=min(len(pk), MAX_PACKAGES), adv_ok=adv_ok, overrides=overrides, modules_dir_ok=ok))


def _ts(v):
    """PrestaShop speichert Zeitpunkte als 'JJJJ-MM-TT hh:mm:ss' bzw. 'JJJJ-MM-TT'; '0000-00-00' oder leer = nie."""
    s = str(v or "").strip()
    if not s or s.startswith("0000"):
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return float(time.mktime(time.strptime(s[:19] if " " in s else s[:10], fmt)))
        except ValueError:
            continue
    return None


@check(
    "prestashop_users", G_DB, "PrestaShop-Mitarbeiterkonten und Super-Administratoren",
    "Wer ist Super-Administrator, wurde kürzlich ein neues Konto angelegt, und hat sich jemand nie angemeldet?",
    what="Liest aus der Tabelle ps_employee Name, Profil, Status, Anlege- und letztes Anmeldedatum. Gemeldet werden neue Super-Administrator-Konten, nie benutzte Konten, sehr viele Super-Administratoren und leicht zu erratende Namen.",
    why="Nach einem Einbruch legen Angreifer gern ein eigenes Konto mit voller Berechtigung an, weil es auch nach einer Säuberung der Dateien bleibt.",
    reads="Vor- und Nachname, Profil, Status, Anlege- und Anmeldedatum. Passwörter und E-Mail-Adressen werden nicht abgefragt. Es wird nichts verändert.",
    load="leicht", needs="db", presets=["schnell", "hack", "komplett"], cms="prestashop",
)
def prestashop_users(ctx, res):
    db = need_db(ctx, res, "PrestaShop-Konten", [("Mitarbeiter", Q_USERS)])
    rows = fetch(db, Q_USERS)
    if rows is None:
        rows = fetch(db, Q_USERS_MIN)
    if rows is None:
        _emit(res, ap.judge_users(None))
        return
    us = [{"uid": r.get("uid"), "name": ("%s %s" % (r.get("fn") or "", r.get("ln") or "")).strip(), "super": str(r.get("prof") or "") == "1",
           "active": str(r.get("act") or "0") not in ("0", ""), "created_ts": _ts(r.get("created")), "access_ts": _ts(r.get("access"))} for r in rows]
    _emit(res, ap.judge_users(us))


@check(
    "prestashop_shop", G_DB, "PrestaShop: HTTPS und Webservice-Schnittstelle",
    "Läuft der Shop überall über HTTPS, und gibt es offene Webservice-Schlüssel mit Schreibrechten?",
    what="Liest aus ps_configuration, ob HTTPS (überall) und die Webservice-Schnittstelle eingeschaltet sind, und aus ps_webservice_account und ps_webservice_permission, wie viele aktive Schlüssel es gibt und ob einer schreiben darf. "
         "Die Schlüssel selbst werden nicht gelesen.",
    why="Ohne HTTPS laufen Anmeldungen und Zahlungen unverschlüsselt; ein Webservice-Schlüssel mit Schreibrechten erlaubt, Shopdaten von außen zu ändern.",
    reads="Vier Einstellungen, Beschreibung und Status der Webservice-Schlüssel und deren Rechte-Art (nicht den Schlüssel). Es wird nichts verändert.",
    load="leicht", needs="db", presets=["schnell", "hack", "komplett"], cms="prestashop",
)
def prestashop_shop(ctx, res):
    db = need_db(ctx, res, "PrestaShop-Einstellungen", [("Konfiguration", Q_CONF)])
    rows = fetch(db, Q_CONF)
    if rows is None:
        _emit(res, ap.judge_shop(None, None))
        return
    conf = {str(r.get("name")): str(r.get("value") or "") for r in rows}
    keys = fetch(db, Q_KEYS) or []
    perms = fetch(db, Q_PERMS) or []
    wr = {str(p.get("id")) for p in perms}
    _emit(res, ap.judge_shop(conf, [{"id": k.get("id"), "descr": k.get("descr"), "active": str(k.get("act") or "0") not in ("0", ""), "write": str(k.get("id")) in wr} for k in keys]))


@check(
    "prestashop_db_code", G_DB, "Eingeschleuster Code in PrestaShop-Inhalten",
    "Stehen in Seiten, Produkttexten, Kategorien oder Einstellungen Skripte, Iframes oder verschleierter Code?",
    what="Sucht in den Textfeldern der CMS-Seiten, der Produkt- und Kategoriebeschreibungen, der Textblöcke (ps_customtext) und in den Werten von ps_configuration nach <script>, <iframe>, javascript:, eval(, atob( und fromCharCode und zeigt die Stelle.",
    why="Angreifer schleusen Code gern in Inhalte und Einstellungen ein, weil er in der Datenbank steht und bei einer Dateisuche nicht auftaucht. Damit werden Besucher umgeleitet oder Eingaben im Bezahlvorgang abgegriffen.",
    reads="Die genannten Textfelder (nur Treffer, höchstens 200 je Feld). Es wird nichts verändert.",
    load="mittel", needs="db", presets=["hack", "komplett"], cms="prestashop",
)
def prestashop_db_code(ctx, res):
    db = need_db(ctx, res, "Code in PrestaShop-Inhalten", [("CMS-Seiten", Q_CODE["cms_lang.content"])])
    rows: List[Dict[str, Any]] = []
    got = False
    for name, q in Q_CODE.items():
        r = fetch(db, q)
        if r is None:
            continue
        got = True
        rows += [{"table": name, "id": x.get("id"), "text": x.get("text")} for x in r]
    _emit(res, ap.judge_db_code(rows if got else None))
