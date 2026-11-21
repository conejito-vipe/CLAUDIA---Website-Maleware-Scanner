"""Shopware-Prüfungen (2.13.0): Kern, Einstellungen, abrufbare Dateien, Pakete und Plugins, Administratoren, Shop-Einstellungen und Code in Inhalten. Nur lesend, Shopware 6.5 und neuer (Composer).

Die Bewertung steckt in auswertung_shopware.py (reine Funktionen, mit Beispieldaten geprüft). Hier stehen nur die Abfragen.
Noch NICHT gegen einen echten Shopware-Server geprüft: Antwortformate von Packagist und GitHub-Archiv sowie Tabellen- und Feldnamen (user, integration, webhook, sales_channel_domain, cms_slot_translation u. a.).
Fehlt etwas, melden die Prüfungen 'nicht prüfbar' statt zu raten. APP_SECRET, Passwörter, Mail-Zugangsdaten und Integrations-Schlüssel werden nie ausgegeben."""
from __future__ import annotations

import os
import re
import time
from typing import Any, Dict, List, Tuple

from .. import coreref, secure, shopware, shopwareref
from ..model import CheckSkipped
from ..registry import check
from ..util import split_sections
from . import auswertung_shopware as ash
from . import web as webmod
from .database import fetch, need_db
from .typo3_checks import MAX_PACKAGES, advisories

RELEASE_URLS = ("https://repo.packagist.org/p2/shopware/core.json", "https://packagist.org/packages/shopware/core.json")
G_KONFIG, G_EXT, G_DB = "konfig", "erweiterungen", "datenbank"

Q_USERS = "SELECT LOWER(HEX(id)) AS uid, username AS name, admin AS adm, active AS act, created_at AS created FROM `#__user` ORDER BY created_at LIMIT 500"
Q_INTS = "SELECT label AS label, admin AS adm, created_at AS created, last_usage_at AS used FROM `#__integration` ORDER BY created_at LIMIT 200"
Q_INTS_MIN = "SELECT label AS label, admin AS adm, created_at AS created FROM `#__integration` ORDER BY created_at LIMIT 200"
Q_HOOKS = "SELECT name AS name, event_name AS event, url AS url, active AS act FROM `#__webhook` LIMIT 200"
Q_DOMAINS = "SELECT url AS url FROM `#__sales_channel_domain` LIMIT 200"
LIKE_TMPL = "(%(c)s LIKE '%%<script%%' OR %(c)s LIKE '%%<iframe%%' OR %(c)s LIKE '%%atob(%%' OR %(c)s LIKE '%%fromCharCode%%' OR %(c)s LIKE '%%eval(%%' OR %(c)s LIKE '%%javascript:%%')"
CODE_FIELDS = (("cms_slot_translation", "config", "cms_slot_id"), ("product_translation", "description", "product_id"), ("category_translation", "description", "category_id"),
               ("snippet", "value", "id"), ("system_config", "configuration_value", "id"))
Q_CODE = {"%s.%s" % (t, c): "SELECT LOWER(HEX(%s)) AS id, %s AS text FROM `#__%s` WHERE %s LIMIT 200" % (i, c, t, LIKE_TMPL % {"c": c}) for t, c, i in CODE_FIELDS}


def _emit(res, rows) -> None:
    for sev, title, text, items, hint in rows:
        res.add(sev, title, text, items, hint)


def _q(s: str) -> str:
    return "'" + s.replace("'", "'\\''") + "'"


def _ts(v):
    """Shopware speichert Zeitpunkte als 'JJJJ-MM-TT hh:mm:ss.mmm'; leer = nie."""
    s = str(v or "").strip()
    if not s or s.startswith("0000"):
        return None
    for fmt, n in (("%Y-%m-%d %H:%M:%S", 19), ("%Y-%m-%d", 10)):
        try:
            return float(time.mktime(time.strptime(s[:n], fmt)))
        except ValueError:
            continue
    return None


def _flag(v) -> bool:
    return str(v or "0").strip() not in ("0", "", "None")


READ_LAYOUT_SH = r"""R=.; if [ ! -d vendor/shopware ] && [ -d ../vendor/shopware ]; then R=..; fi
echo '@@ROOT'; echo "$R"
echo '@@LOCK'; if [ -f "$R/composer.lock" ]; then head -c 6000000 "$R/composer.lock"; fi
echo; echo '@@INST'; if [ -f "$R/vendor/composer/installed.php" ]; then head -c 3000000 "$R/vendor/composer/installed.php"; fi
echo; echo '@@MODE'; if [ -d "$R/vendor/shopware" ]; then echo composer; else echo unknown; fi
echo '@@PLUG'
for d in "$R"/custom/plugins/*/; do [ -d "$d" ] || continue; n=${d%/}; n=${n##*/}; echo "@@M plugin $n"; [ -f "$d/composer.json" ] && head -c 3000 "$d/composer.json"; echo; done 2>/dev/null | head -c 2000000
echo '@@APPS'
for d in "$R"/custom/apps/*/; do [ -d "$d" ] || continue; n=${d%/}; n=${n##*/}; echo "@@M app $n"; [ -f "$d/manifest.xml" ] && head -c 4000 "$d/manifest.xml"; echo; done 2>/dev/null | head -c 1000000"""


def parse_extensions(plug: str, apps: str) -> List[Dict[str, Any]]:
    """Plugins (custom/plugins) und Apps (custom/apps): [{'kind','name','version','pkg'}]; pkg = Composer-Name, wenn das Plugin einen hat."""
    out: List[Dict[str, Any]] = []
    for kind, text in (("plugin", plug), ("app", apps)):
        for m in re.finditer(r"^@@M %s (\S+)\n(.*?)(?=^@@M |\Z)" % kind, text or "", re.S | re.M):
            name, body = m.group(1), m.group(2)
            pkg = re.search(r'"name"\s*:\s*"([a-z0-9_.\-]+/[a-z0-9_.\-]+)"', body)
            ver = re.search(r'"version"\s*:\s*"v?([0-9][0-9A-Za-z.\-]*)"', body) or re.search(r"<version>\s*([0-9][0-9A-Za-z.\-]*)\s*</version>", body)
            out.append({"kind": kind, "name": name, "version": ver.group(1) if ver else "", "pkg": pkg.group(1) if (kind == "plugin" and pkg and ver) else ""})
    return out


def layout(ctx) -> Dict[str, Any]:
    """Version, Pakete, Plugins und Apps (einmal je Lauf lesen)."""
    if "shopware_layout" not in ctx.shared:
        sec = split_sections(ctx.sh(READ_LAYOUT_SH, timeout=60, raw="shopware_lage", raw_cap=2000).out)
        lock = sec.get("LOCK", "")
        ctx.shared["shopware_layout"] = {"version": shopware.parse_core_version(lock, sec.get("INST", "")), "mode": (sec.get("MODE", "unknown").split() or ["unknown"])[0],
                                         "root": (sec.get("ROOT", ".").split() or ["."])[0], "packages": shopware.parse_lock(lock),
                                         "extensions": parse_extensions(sec.get("PLUG", ""), sec.get("APPS", ""))}
    return ctx.shared["shopware_layout"]


def releases(ctx) -> List[Dict[str, str]]:
    if "shopware_releases" not in ctx.shared:
        out: List[Dict[str, str]] = []
        if not os.environ.get("CLAUDIA_OFFLINE"):
            for u in RELEASE_URLS:
                f = webmod.fetch(u, webmod.UA_BROWSER, max_bytes=8_000_000, timeout=25)
                if not f.error and f.status == 200:
                    out = shopware.parse_release_list(f.body)
                    if out:
                        break
        ctx.shared["shopware_releases"] = out
    return ctx.shared["shopware_releases"]


@check(
    "shopware_core", G_KONFIG, "Shopware-Kern: Version, Sicherheitsmeldungen und Originaldateien",
    "Ist Shopware aktuell und unterstützt, und stimmen die Dateien der Kern-Pakete mit dem Original überein?",
    what="Liest die Version aus composer.lock, prüft anhand einer Tabelle, ob die Version noch Sicherheitsupdates bekommt, fragt bei Packagist nach der neuesten Version und nach Sicherheitsmeldungen zu dieser Version "
         "und vergleicht die Dateien der Kern-Pakete (vendor/shopware/core, administration, storefront) mit dem Original von GitHub. Auf dem Server werden nur Prüfsummen berechnet.",
    why="Veraltete Shopware-Versionen werden automatisch angegriffen. Manipulierte Kerndateien sind ein häufiger Ort für Hintertüren und Zahlungsdaten-Abgreifer, die keinem Schadcode-Muster entsprechen.",
    reads="Dateinamen und Prüfsummen unter vendor/shopware/* des Servers sowie composer.lock; vom Internet die Versionsliste, die Sicherheitsmeldungen und die Original-Pakete (nur https). Es wird nichts verändert.",
    load="mittel", needs="web", presets=["schnell", "hack", "komplett"], cms="shopware",
)
def shopware_core(ctx, res):
    lay = layout(ctx)
    ver = lay["version"]
    rel: List[Dict[str, str]] = []
    adv: Dict[str, List[Dict[str, str]]] = {}
    adv_ok = False
    if ver:
        ctx.progress("Frage Packagist")
        rel = releases(ctx)
        adv, adv_ok = advisories(["shopware/core"])
    _emit(res, ash.judge_core(ver, rel, shopware.advisories_for(ver, adv, "shopware/core") if ver else [], adv_ok=adv_ok if ver else True))
    if not ver or lay["mode"] != "composer":
        return
    if os.environ.get("CLAUDIA_OFFLINE"):
        res.add("info", "Dateivergleich übersprungen", "Offline-Modus (CLAUDIA_OFFLINE): Die Original-Pakete werden nicht geladen.")
        return
    versions = {p["name"]: p["version"] for p in lay["packages"] if p["name"] in shopware.CORE_PACKAGES and shopwareref.VERSION_RE.match(p["version"])}
    if not versions:
        res.add("info", "Dateivergleich nicht möglich", "Für die Kern-Pakete liegen keine stabilen Versionsnummern vor (Vorabversion?).")
        return
    out = ctx.sh(shopwareref.server_hash_sh(sorted(versions)) + '; echo "@@HASHER"; command -v sha256sum >/dev/null 2>&1 && echo sha256sum || echo none', timeout=900, raw="pruefsummen", raw_cap=40_000).out
    tail = out.rsplit("@@HASHER", 1)
    if len(tail) == 2 and "none" in tail[1].split():
        res.add("info", "Dateivergleich nicht möglich", "Auf dem Server gibt es kein sha256sum.")
        return
    server = shopwareref.parse_server_hashes(tail[0])
    for pkg, v in sorted(versions.items()):
        srv = server.get(pkg) or {}
        if len(srv) < 5:
            res.add("info", "%s: Dateivergleich nicht möglich" % pkg, "Unter vendor/%s wurden nur %d Dateien gefunden." % (pkg, len(srv)))
            continue
        ctx.progress("Lade das Original-Paket %s %s" % (pkg, v))
        try:
            ref = shopwareref.reference(pkg, v)
        except coreref.RefError as e:
            res.add("info", "%s: Dateivergleich nicht möglich" % pkg, "Original-Paket nicht verfügbar: %s" % e)
            continue
        diff = shopwareref.compare(ref["files"], srv)
        src = "Original-Paket %s von GitHub, OHNE veröffentlichte Prüfsumme (nur https-Quelle)." % ref["package"]
        _emit(res, ash.judge_core_files(pkg, len(ref["files"]), diff["changed"], diff["missing"], diff["extra"], src))


@check(
    "shopware_settings", G_KONFIG, "Shopware-Einstellungen (.env, Schlüsseldateien)",
    "Steht in den Einstellungsdateien Auffälliges, läuft Shopware im Produktivmodus, und sind die Rechte richtig gesetzt?",
    what="Liest die .env-Dateien und prüft APP_ENV und APP_DEBUG, Länge und Beispielwert des APP_SECRET, die Adresse (APP_URL), TRUSTED_HOSTS und die Dateirechte der .env und des privaten Schlüssels config/jwt/private.pem.",
    why="Die .env enthält die Zugangsdaten zur Datenbank. Ein Entwicklungsmodus oder ein bekanntes APP_SECRET machen Angriffe einfacher; der private JWT-Schlüssel signiert die Anmeldungen an der Schnittstelle.",
    reads="Die .env-Dateien (Passwörter, APP_SECRET und Mail-Zugangsdaten werden nie angezeigt oder gespeichert; vom APP_SECRET nur die Länge) und die Dateirechte; der Inhalt der Schlüsseldateien wird nicht gelesen. Es wird nichts verändert.",
    load="leicht", needs="ssh", presets=["schnell", "hack", "komplett"], cms="shopware",
)
def shopware_settings(ctx, res):
    cfg = ctx.config()
    modes: Dict[str, str] = {}
    paths = [p for p in (cfg.get("files") or []) + (cfg.get("jwt") or []) if p]
    if paths:
        out = ctx.sh("stat -c '%%a %%U %%n' %s 2>/dev/null" % " ".join(_q(p) for p in paths[:12]), timeout=20).out
        for ln in out.splitlines():
            m = re.match(r"^(\d{3,4}) (\S+) (.+)$", ln.strip())
            if m:
                modes[m.group(3)] = "%s %s" % (m.group(1), m.group(2))
    _emit(res, ash.judge_settings(cfg, modes))


@check(
    "shopware_exposed", G_KONFIG, "Shopware: frei abrufbare Dateien und Seiten",
    "Kann jeder Besucher Einstellungen, Schlüssel, Composer-Dateien, den Installer oder einen Entwicklungs-Eingang abrufen?",
    what="Ruft von DIESEM PC aus einzelne Adressen ohne Anmeldung auf: .env, composer.json und composer.lock, .git/config, den privaten JWT-Schlüssel, Protokolle, Ordnerlisten (var, files), den Web-Installer, den Profiler, "
         "die Beschreibung der Schnittstelle und die Verwaltung. Es werden nur normale Seitenaufrufe gesendet.",
    why="Eine abrufbare Konfigurationsdatei oder ein erreichbares Verwaltungswerkzeug können zur Übernahme des Shops führen. Das lässt sich ohne Anmeldung von außen sehen.",
    reads="Öffentlich erreichbare Adressen Ihrer Domain, so wie jeder Besucher sie sieht. Inhalte werden nicht gespeichert. Es wird nichts verändert.",
    load="leicht", needs="web", presets=["schnell", "hack", "komplett"], cms="shopware",
)
def shopware_exposed(ctx, res):
    url = (ctx.s.url or "").strip()
    if not url:
        raise CheckSkipped("Keine Adresse der Webseite angegeben (Feld 'Webseite' in den Verbindungsdaten).")
    url, _ = secure.to_https(url)
    base = url.rstrip("/")
    targets = [("file", "Umgebungsdatei", "/.env"), ("file", "Umgebungsdatei", "/.env.local"), ("file", "Composer-Datei", "/composer.json"), ("file", "Composer-Sperrdatei", "/composer.lock"),
               ("file", "Git-Konfiguration", "/.git/config"), ("file", "Privater Schlüssel", "/config/jwt/private.pem"), ("file", "Protokolle", "/var/log/prod.log"),
               ("dir", "Ordner var", "/var/"), ("dir", "Ordner files", "/files/"),
               ("installer", "Web-Installer", "/shopware-installer.phar.php"), ("installer", "Installation", "/recovery/install/"),
               ("profiler", "Profiler", "/_profiler/"), ("api", "Schnittstellenbeschreibung", "/api/_info/openapi3.json"),
               ("admin", "Verwaltung", "/admin")]
    web: List[Dict[str, Any]] = []
    for kind, label, path in targets:
        ctx.progress("Rufe %s ab" % path)
        f = webmod.fetch(base + path, webmod.UA_BROWSER, max_bytes=20000, timeout=15)
        if f.error:
            continue
        web.append({"kind": kind, "label": label, "url": base + path, "status": f.status, "body": f.body})
    _emit(res, ash.judge_exposed(web))


def _inventory(ctx) -> Tuple[List[Dict[str, Any]], Dict[str, str]]:
    """Pakete (Anzeige) und {Paketname: Version} zum Abfragen bei Packagist: zuerst shopware/* und Plugins, dann die übrigen (höchstens MAX_PACKAGES)."""
    lay = layout(ctx)
    inv: List[Dict[str, Any]] = []
    pkgs: Dict[str, str] = {}
    for e in lay["extensions"]:
        key = "%s:%s" % (e["kind"], e["name"])
        inv.append({"key": key, "name": "%s %s" % ("Plugin" if e["kind"] == "plugin" else "App", e["name"]), "version": e["version"], "pkg": e["pkg"], "custom": False, "ext": True})
        if e["pkg"] and e["version"]:
            pkgs[e["pkg"]] = e["version"]
    first = sorted(lay["packages"], key=lambda p: (not p["name"].startswith("shopware/"), p["name"]))
    for p in first:
        if not p["version"] or p["name"] in pkgs:
            continue
        inv.append({"key": p["name"], "name": p["name"], "version": p["version"], "pkg": p["name"], "custom": p["custom"], "ext": p["type"] in ("shopware-platform-plugin", "shopware-app")})
        if not p["custom"]:
            pkgs[p["name"]] = p["version"]
    return inv, pkgs


@check(
    "shopware_packages", G_EXT, "Shopware-Pakete, Plugins und Apps",
    "Welche Pakete, Plugins und Apps laufen, und gibt es zu ihren Versionen bekannte Sicherheitsmeldungen?",
    what="Liest die Pakete aus composer.lock (Name, Version, Art) sowie die Plugins (custom/plugins) und Apps (custom/apps) und fragt bei Packagist nach Sicherheitsmeldungen, die auf genau diese Versionen zutreffen (zuerst Plugins und shopware/*, dann die übrigen; "
         "höchstens 150 Pakete). Eigene Pakete (lokale Pfade) werden nur aufgelistet; Entwicklungs-Pakete auf dem Live-Server werden gemeldet. Viele Store-Plugins sind nicht bei Packagist geführt; das wird offen gesagt.",
    why="Die meisten Einbrüche laufen über veraltete Plugins und Bibliotheken. Packagist führt Sicherheitsmeldungen mit den betroffenen Versionen; das lässt sich automatisch vergleichen.",
    reads="composer.lock, die Dateien composer.json je Plugin und manifest.xml je App (Name und Version); im Internet Packagist (nur Paketnamen und Versionen werden gesendet). Es wird nichts verändert.",
    load="mittel", needs="web", presets=["schnell", "hack", "komplett"], cms="shopware",
)
def shopware_packages(ctx, res):
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
            h = shopware.advisories_for(m["version"], adv, m["pkg"])
            if h:
                hits[m["key"]] = h
    _emit(res, ash.judge_packages(inv, hits, checked=min(len(pkgs), MAX_PACKAGES), adv_ok=ok))


@check(
    "shopware_users", G_DB, "Shopware-Administratoren",
    "Wer ist Administrator, und wurde kürzlich ein neues Konto angelegt?",
    what="Liest aus der Tabelle user Benutzername, Administrator-Merkmal, Status und Anlegedatum. Gemeldet werden neue Administrator-Konten, sehr viele Administratoren und leicht zu erratende Namen. "
         "Shopware speichert keinen Zeitpunkt der letzten Anmeldung; dazu gibt es deshalb keine Aussage.",
    why="Nach einem Einbruch legen Angreifer gern ein eigenes Administrator-Konto an, weil es auch nach einer Säuberung der Dateien bleibt.",
    reads="Benutzername, Administrator-Merkmal, Status und Anlegedatum. Passwörter und E-Mail-Adressen werden nicht abgefragt. Es wird nichts verändert.",
    load="leicht", needs="db", presets=["schnell", "hack", "komplett"], cms="shopware",
)
def shopware_users(ctx, res):
    db = need_db(ctx, res, "Shopware-Konten", [("Benutzer", Q_USERS)])
    rows = fetch(db, Q_USERS)
    if rows is None:
        _emit(res, ash.judge_users(None))
        return
    _emit(res, ash.judge_users([{"uid": r.get("uid"), "name": r.get("name"), "admin": _flag(r.get("adm")), "active": _flag(r.get("act")), "created_ts": _ts(r.get("created"))} for r in rows]))


@check(
    "shopware_shop", G_DB, "Shopware: HTTPS, Integrationen und Webhooks",
    "Laufen alle Shop-Adressen mit HTTPS, und gibt es Integrationen mit Administratorrechten oder Webhooks zu fremden Adressen?",
    what="Liest aus sales_channel_domain die Shop-Adressen, aus integration Name, Administrator-Merkmal und Anlegedatum (nie die Zugriffsschlüssel) und aus webhook Ereignis und Zieladresse (nur den Rechnernamen).",
    why="Ohne HTTPS laufen Anmeldungen und Zahlungen unverschlüsselt. Eine Integration mit Administratorrechten ist ein Dauerzugang; ein Webhook kann Bestell- und Kundendaten an fremde Adressen senden.",
    reads="Shop-Adressen, Integrations-Namen und -Merkmale, Webhook-Ereignisse und -Rechnernamen. Schlüssel und Geheimnisse werden nicht abgefragt. Es wird nichts verändert.",
    load="leicht", needs="db", presets=["schnell", "hack", "komplett"], cms="shopware",
)
def shopware_shop(ctx, res):
    db = need_db(ctx, res, "Shopware-Einstellungen", [("Verkaufskanal-Adressen", Q_DOMAINS)])
    dom = fetch(db, Q_DOMAINS)
    if dom is None:
        _emit(res, ash.judge_shop(None, None, None))
        return
    ints = fetch(db, Q_INTS)
    if ints is None:
        ints = fetch(db, Q_INTS_MIN) or []
    hooks = fetch(db, Q_HOOKS) or []
    _emit(res, ash.judge_shop([{"url": r.get("url")} for r in dom],
                              [{"label": r.get("label"), "admin": _flag(r.get("adm")), "created_ts": _ts(r.get("created")), "last_use_ts": _ts(r.get("used"))} for r in ints],
                              [{"name": r.get("name"), "event": r.get("event"), "url": r.get("url"), "active": _flag(r.get("act"))} for r in hooks]))


@check(
    "shopware_db_code", G_DB, "Eingeschleuster Code in Shopware-Inhalten",
    "Stehen in Erlebniswelten, Produkttexten, Kategorien, Textbausteinen oder Einstellungen Skripte, Iframes oder verschleierter Code?",
    what="Sucht in den Textfeldern der Erlebniswelt-Elemente (cms_slot_translation), der Produkt- und Kategoriebeschreibungen, der Textbausteine (snippet) und der Systemeinstellungen (system_config) nach <script>, <iframe>, javascript:, eval(, atob( und fromCharCode und zeigt die Stelle.",
    why="Angreifer schleusen Code gern in Inhalte und Einstellungen ein, weil er in der Datenbank steht und bei einer Dateisuche nicht auftaucht. Damit werden Besucher umgeleitet oder Eingaben im Bezahlvorgang abgegriffen.",
    reads="Die genannten Textfelder (nur Treffer, höchstens 200 je Feld). Es wird nichts verändert.",
    load="mittel", needs="db", presets=["hack", "komplett"], cms="shopware",
)
def shopware_db_code(ctx, res):
    db = need_db(ctx, res, "Code in Shopware-Inhalten", [("Erlebniswelt-Elemente", Q_CODE["cms_slot_translation.config"])])
    rows: List[Dict[str, Any]] = []
    got = False
    for name, q in Q_CODE.items():
        r = fetch(db, q)
        if r is None:
            continue
        got = True
        rows += [{"table": name, "id": x.get("id"), "text": x.get("text")} for x in r]
    _emit(res, ash.judge_db_code(rows if got else None))
