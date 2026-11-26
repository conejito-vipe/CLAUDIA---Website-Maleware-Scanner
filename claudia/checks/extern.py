"""Externer Modus: Prüfungen ausschließlich von außen (ohne SSH, ohne Serverzugang), für alle sieben Systeme.

Reine Funktionen (Erkennung, Versionsauswertung, Erweiterungsliste, Dateiprüfung) plus drei Tests:
  ext_fingerprint  Welches System und welche Version ist von außen erkennbar, und wie ist sie einzuordnen?
  ext_components   Welche Erweiterungen (Plugins, Module, Themes, Pakete) sind im Quelltext sichtbar?
  ext_files        Sind vergessene oder sensible Dateien abrufbar (Sicherungen, Konfigurationen, Protokolle, Schlüssel)?
Es werden nur normale GET-Aufrufe wie von einem Besucher gesendet. Nichts wird verändert oder gespeichert."""
from __future__ import annotations

import json
import os
import re
import secrets
from typing import Any, Dict, List, Optional, Tuple

from ..model import CheckResult, CheckSkipped
from ..registry import check
from . import web as webmod

G = "grundlagen"
G_WEB = "logs"
SYSTEMS = ("joomla", "wordpress", "drupal", "typo3", "contao", "prestashop", "shopware")
NAMES = {"joomla": "Joomla", "wordpress": "WordPress", "drupal": "Drupal", "typo3": "TYPO3", "contao": "Contao", "prestashop": "PrestaShop", "shopware": "Shopware"}

VER = r"(\d+(?:\.\d+){1,3})"


# ---------------------------------------------------------------- Erkennung
# (System, Gewicht, Beschriftung, Muster, Quelle) – Quelle: html | header | cookie | probe:<Pfad>
SIGNS: List[Tuple[str, int, str, "re.Pattern[str]", str]] = [
    ("wordpress", 3, "Generator-Angabe WordPress", re.compile(r"<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']WordPress", re.I), "html"),
    ("wordpress", 3, "Ordner wp-content im Quelltext", re.compile(r"/wp-content/(?:themes|plugins|uploads)/", re.I), "html"),
    ("wordpress", 2, "Ordner wp-includes im Quelltext", re.compile(r"/wp-includes/", re.I), "html"),
    ("wordpress", 2, "WordPress-Schnittstelle (wp-json)", re.compile(r"/wp-json/|rel=[\"']https://api\.w\.org/", re.I), "html"),
    ("wordpress", 2, "Kopfzeile Link zu wp-json", re.compile(r"api\.w\.org", re.I), "header"),
    ("joomla", 3, "Generator-Angabe Joomla", re.compile(r"<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']Joomla", re.I), "html"),
    ("joomla", 2, "Joomla-Ordner media/system", re.compile(r"/media/(?:system|vendor|templates|jui|com_[a-z0-9_]+)/", re.I), "html"),
    ("joomla", 2, "Joomla-Komponenten im Quelltext", re.compile(r"/(?:components/com_|modules/mod_|plugins/(?:system|content|editors)/)", re.I), "html"),
    ("joomla", 2, "Joomla-Konfigurationsobjekt", re.compile(r"joomla\.(?:optionsStorage|options)|\"csrf\.token\"", re.I), "html"),
    ("joomla", 3, "Verwaltungs-Anmeldung Joomla", re.compile(r"Joomla!?|com_login", re.I), "probe:/administrator/"),
    ("joomla", 4, "Joomla-Manifest", re.compile(r"<extension\b[^>]*type=[\"']file[\"'][^>]*>[\s\S]{0,400}?<name>\s*files_joomla", re.I), "probe:/administrator/manifests/files/joomla.xml"),
    ("drupal", 4, "Generator-Angabe Drupal", re.compile(r"<meta[^>]+name=[\"']Generator[\"'][^>]+content=[\"']Drupal", re.I), "html"),
    ("drupal", 4, "Kopfzeile X-Generator Drupal", re.compile(r"Drupal", re.I), "header:x-generator"),
    ("drupal", 3, "drupalSettings oder Drupal.settings", re.compile(r"drupalSettings|Drupal\.settings|data-drupal-", re.I), "html"),
    ("drupal", 2, "Drupal-Ordner im Quelltext", re.compile(r"/(?:core/(?:misc|themes|assets)|sites/(?:default|all)/(?:files|modules|themes))/", re.I), "html"),
    ("drupal", 3, "Kopfzeile X-Drupal-Cache", re.compile(r".+", re.S), "header:x-drupal-cache"),
    ("typo3", 4, "Generator-Angabe TYPO3", re.compile(r"<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']TYPO3", re.I), "html"),
    ("typo3", 3, "TYPO3-Ordner typo3conf oder typo3temp", re.compile(r"/(?:typo3conf/ext|typo3temp/|_assets/[0-9a-f]{32}/)", re.I), "html"),
    ("typo3", 2, "TYPO3-Kommentar im Quelltext", re.compile(r"This website is powered by TYPO3", re.I), "html"),
    ("typo3", 3, "TYPO3-Sitzungs-Cookie", re.compile(r"fe_typo_user", re.I), "cookie"),
    ("typo3", 3, "TYPO3-Anmeldung", re.compile(r"TYPO3\s+CMS|typo3-login|Typo3\.", re.I), "probe:/typo3/"),
    ("contao", 4, "Generator-Angabe Contao", re.compile(r"<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']Contao", re.I), "html"),
    ("contao", 3, "Contao-Ordner bundles/contao", re.compile(r"/(?:bundles/contao|assets/contao|system/themes/)", re.I), "html"),
    ("contao", 2, "Contao-Kommentar im Quelltext", re.compile(r"Contao Open Source CMS", re.I), "html"),
    ("contao", 3, "Contao-Anmeldung", re.compile(r"Contao(?:\s+Open\s+Source|\s+Backend|-Backend|\s+\d)", re.I), "probe:/contao"),
    ("prestashop", 4, "Generator-Angabe PrestaShop", re.compile(r"<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']PrestaShop", re.I), "html"),
    ("prestashop", 3, "PrestaShop-Objekt im Quelltext", re.compile(r"var\s+prestashop\s*=|prestashop\.(?:cart|customer|urls)|window\.prestashop", re.I), "html"),
    ("prestashop", 2, "PrestaShop-Module im Quelltext", re.compile(r"/modules/(?:ps_|blockcart|blocksearch)[a-z0-9_]*/", re.I), "html"),
    ("prestashop", 3, "Kopfzeile Powered-By PrestaShop", re.compile(r"PrestaShop", re.I), "header:powered-by"),
    ("prestashop", 2, "PrestaShop-Cookie", re.compile(r"PrestaShop-[0-9a-f]{16,}", re.I), "cookie"),
    ("shopware", 4, "Generator-Angabe Shopware", re.compile(r"<meta[^>]+(?:name=[\"'](?:generator|application-name)[\"'][^>]+content=[\"']Shopware|content=[\"']Shopware[^>]+name=[\"'](?:generator|application-name))", re.I), "html"),
    ("shopware", 3, "Shopware-Storefront-Ordner", re.compile(r"/(?:bundles/storefront|theme/[0-9a-f]{32})/", re.I), "html"),
    ("shopware", 3, "Shopware 5 Ordner themes/Frontend", re.compile(r"/themes/Frontend/|/engine/Shopware/", re.I), "html"),
    ("shopware", 3, "Shopware-Cookie", re.compile(r"sw-(?:cache-hash|states|context-token|currency)|session-\d|slbookmark", re.I), "cookie"),
    ("shopware", 3, "Kopfzeile sw-", re.compile(r".+", re.S), "header:sw-context-token"),
    ("shopware", 3, "Shopware-Verwaltung", re.compile(r"Shopware\s*(?:6)?\s*Administration|sw-admin|shopware", re.I), "probe:/admin"),
]


def _norm_headers(h: Optional[Dict[str, str]]) -> Dict[str, str]:
    return {str(k).lower(): str(v) for k, v in (h or {}).items()}


def detect(html: str, headers: Optional[Dict[str, str]] = None, cookies: Optional[List[str]] = None, probes: Optional[Dict[str, Tuple[int, str]]] = None) -> Dict[str, Any]:
    """Wertet die Merkmale aus. Rückgabe: {cms, score, scores, evidence} – cms leer, wenn kein System eindeutig ist (Mindestgewicht 3, und deutlicher Abstand zum Zweiten)."""
    headers = _norm_headers(headers)
    cook = " ; ".join(cookies or [])
    probes = probes or {}
    scores: Dict[str, int] = {s: 0 for s in SYSTEMS}
    ev: Dict[str, List[str]] = {s: [] for s in SYSTEMS}
    for cms, w, label, rx, src in SIGNS:
        hit = False
        if src == "html":
            hit = bool(rx.search(html or ""))
        elif src == "cookie":
            hit = bool(rx.search(cook))
        elif src.startswith("header:"):
            hit = src[7:] in headers and bool(rx.search(headers[src[7:]]))
        elif src == "header":
            hit = any(rx.search("%s: %s" % kv) for kv in headers.items())
        elif src.startswith("probe:"):
            st, body = probes.get(src[6:], (0, ""))
            hit = st == 200 and bool(rx.search(body or ""))
        if hit:
            scores[cms] += w
            ev[cms].append(label)
    ranked = sorted(scores.items(), key=lambda kv: -kv[1])
    top, second = ranked[0], ranked[1]
    cms = top[0] if top[1] >= 3 and top[1] - second[1] >= 2 else ""
    return {"cms": cms, "score": top[1], "scores": scores, "evidence": ev.get(cms, []) if cms else []}


# ---------------------------------------------------------------- Versionen
def _first(rx: str, text: str, flags: int = re.I) -> str:
    m = re.search(rx, text or "", flags)
    return m.group(1) if m else ""


def parse_version(cms: str, html: str, headers: Optional[Dict[str, str]] = None, probes: Optional[Dict[str, Tuple[int, str]]] = None) -> Tuple[str, str]:
    """(Version, Quelle) aus Quelltext, Kopfzeilen und Probe-Dateien. Leer, wenn von außen nicht lesbar (Contao, PrestaShop, TYPO3 meist so)."""
    headers = _norm_headers(headers)
    probes = probes or {}

    def probe(path: str) -> str:
        st, body = probes.get(path, (0, ""))
        return body if st == 200 else ""

    if cms == "wordpress":
        v = _first(r"<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']WordPress\s+" + VER, html)
        if v:
            return v, "Generator-Angabe"
        v = _first(r"<generator>[^<]*wordpress\.org/\?v=" + VER, probe("/feed/"))
        if v:
            return v, "Feed (/feed/)"
        v = _first(r"<br\s*/?>\s*Version\s+" + VER, probe("/readme.html"))
        if v:
            return v, "readme.html"
        return "", ""
    if cms == "joomla":
        v = _first(r"<version>\s*" + VER, probe("/administrator/manifests/files/joomla.xml"))
        if v:
            return v, "administrator/manifests/files/joomla.xml"
        v = _first(r"<version>\s*" + VER, probe("/language/en-GB/en-GB.xml")) or _first(r"<version>\s*" + VER, probe("/language/en-GB/langmetadata.xml"))
        if v:
            return v, "Sprachdatei en-GB"
        return "", ""
    if cms == "drupal":
        for p in ("/core/CHANGELOG.txt", "/CHANGELOG.txt"):
            v = _first(r"^\s*Drupal\s+(\d+(?:\.\d+){1,2})(?:[,\s]|-dev)", probe(p), re.I | re.M)
            if v:
                return v, p.lstrip("/")
        mj = _first(r"Drupal\s+(\d+)", headers.get("x-generator", "")) or _first(r"<meta[^>]+name=[\"']Generator[\"'][^>]+content=[\"']Drupal\s+(\d+)", html)
        return (mj, "Generator (nur Hauptversion)") if mj else ("", "")
    if cms == "typo3":
        v = _first(r"TYPO3\s+(?:CMS\s+)?(?:Version\s+)?(\d+(?:\.\d+){1,2})", probe("/typo3/"))
        return (v, "Anmeldeseite /typo3/") if v else ("", "")
    if cms == "shopware":
        try:
            d = json.loads(probe("/api/_info/version") or "{}")
            v = str(d.get("version", "")) if isinstance(d, dict) else ""
        except ValueError:
            v = ""
        v = v.lstrip("v")
        if re.fullmatch(r"\d+(?:\.\d+){1,3}", v or ""):
            return v, "/api/_info/version"
        return "", ""
    return "", ""        # contao, prestashop: nicht verlässlich lesbar


# ---------------------------------------------------------------- Erweiterungen aus dem Quelltext
_VER_Q = re.compile(r"[?&](?:ver|v|version)=(\d+(?:\.\d+){1,3})\b")
CONTAO_CORE = {"contao", "contaocore", "contaofrontend", "contaomanager", "contaoinstall", "contaocalendar", "contaonews", "contaocomments", "contaofaq", "contaolisting", "contaonewsletter", "contaotheme", "core", "contao-core"}
_PATTERNS: Dict[str, List[Tuple[str, "re.Pattern[str]"]]] = {
    "wordpress": [("Plugin", re.compile(r"/wp-content/plugins/([a-z0-9_.\-]+)/([^\"'\s)<>]*)", re.I)),
                  ("Theme", re.compile(r"/wp-content/themes/([a-z0-9_.\-]+)/([^\"'\s)<>]*)", re.I))],
    "joomla": [("Komponente", re.compile(r"/(?:components|media)/(com_[a-z0-9_]+)/([^\"'\s)<>]*)", re.I)),
               ("Modul", re.compile(r"/(?:modules|media)/(mod_[a-z0-9_]+)/([^\"'\s)<>]*)", re.I)),
               ("Plugin", re.compile(r"/(?:plugins|media)/((?:plg_)[a-z0-9_]+|(?:system|content|editors|editors-xtd|authentication|user|vmpayment|vmshipment|fields)/[a-z0-9_]+)/([^\"'\s)<>]*)", re.I)),
               ("Template", re.compile(r"/(?:templates|media/templates/site)/([a-z0-9_\-]+)/([^\"'\s)<>]*)", re.I))],
    "drupal": [("Modul", re.compile(r"/(?:sites/all/|sites/default/)?modules/(?:contrib/|custom/)?([a-z0-9_]+)/([^\"'\s)<>]*)", re.I)),
               ("Theme", re.compile(r"/(?:sites/all/|sites/default/)?themes/(?:contrib/|custom/)?([a-z0-9_]+)/([^\"'\s)<>]*)", re.I))],
    "typo3": [("Erweiterung", re.compile(r"/typo3conf/ext/([a-z0-9_]+)/([^\"'\s)<>]*)", re.I))],
    "contao": [("Paket", re.compile(r"/bundles/([a-z0-9_\-]+)/([^\"'\s)<>]*)", re.I))],
    "prestashop": [("Modul", re.compile(r"/modules/([a-z0-9_]+)/([^\"'\s)<>]*)", re.I)),
                   ("Theme", re.compile(r"/themes/([a-z0-9_\-]+)/([^\"'\s)<>]*)", re.I))],
    "shopware": [("Paket", re.compile(r"/bundles/([a-z0-9_\-]+)/([^\"'\s)<>]*)", re.I)),
                 ("Plugin", re.compile(r"/custom/plugins/([A-Za-z0-9_\-]+)/([^\"'\s)<>]*)", re.I)),
                 ("Theme", re.compile(r"/themes/(?:Frontend/)?([A-Za-z0-9_\-]+)/([^\"'\s)<>]*)", re.I))],
}
_CORE_SKIP = {
    "drupal": {"core", "system", "user", "node", "views", "block", "file", "image", "field", "filter", "claro", "olivero", "stable", "stable9", "bartik", "seven", "garland", "classy", "stark"},
    "joomla": {"com_ajax", "com_media", "com_users", "com_content", "com_config", "mod_menu", "mod_login", "system"},
    "shopware": {"storefront", "administration", "elasticsearch", "core", "responsive"},
    "prestashop": {"classic", "core", "ps_shoppingcart"},
}


def components(cms: str, html: str) -> List[Dict[str, str]]:
    """Im Quelltext sichtbare Erweiterungen: [{kind, slug, version}] (Version nur, wenn als ?ver=… im Adressbestandteil)."""
    out: Dict[Tuple[str, str], Dict[str, str]] = {}
    for kind, rx in _PATTERNS.get(cms, []):
        for m in rx.finditer(html or ""):
            slug = m.group(1).lower() if cms != "shopware" else m.group(1)
            if slug.lower() in _CORE_SKIP.get(cms, set()):
                continue
            if cms == "contao" and slug.lower() in CONTAO_CORE:
                continue
            if cms == "joomla" and kind == "Plugin" and "/" in slug:
                slug = slug.lower()
            v = _first(_VER_Q.pattern, m.group(2) or "", 0)
            key = (kind, slug)
            cur = out.get(key)
            if cur is None:
                out[key] = {"kind": kind, "slug": slug, "version": v}
            elif v and not cur["version"]:
                cur["version"] = v
    return sorted(out.values(), key=lambda c: (c["kind"], c["slug"]))[:200]


def readme_stable_tag(text: str) -> str:
    """Neueste Version laut WordPress-readme.txt ('Stable tag: 1.2.3')."""
    v = _first(r"^\s*Stable tag:\s*" + VER, text or "", re.I | re.M)
    return v


def wp_plugin_latest(text: str) -> str:
    try:
        d = json.loads(text)
    except ValueError:
        return ""
    return str(d.get("version", "")) if isinstance(d, dict) and d.get("version") else ""


# ---------------------------------------------------------------- vergessene Dateien
def _env(b: str) -> bool:
    return bool(re.search(r"^\s*[A-Z][A-Z0-9_]{2,}\s*=", b or "", re.M))


def _php_src(b: str) -> bool:
    return "<?php" in (b or "")[:400]


def _sql(b: str) -> bool:
    return bool(re.search(r"CREATE TABLE|INSERT INTO|DROP TABLE|-- MySQL dump|mysqldump", b or "", re.I))


def _log(b: str) -> bool:
    return bool(re.search(r"\[\d{2}-\w{3}-\d{4}|\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}|PHP (?:Warning|Notice|Fatal|Deprecated)|Stack trace|\.php on line", b or ""))


def _listing(b: str) -> bool:
    return bool(re.search(r"<title>\s*Index of /|<h1>\s*Index of /|Parent Directory", b or "", re.I))


def _zip(raw: bytes, b: str) -> bool:
    return raw[:2] == b"PK" or raw[:2] == b"\x1f\x8b"


# (Pfad, Beschriftung, Schwere, Prüfung(body, raw) -> bool, Systeme oder None für alle)
FILES: List[Tuple[str, str, str, Any, Optional[Tuple[str, ...]]]] = [
    (".env", "Umgebungsdatei mit Zugangsdaten", "crit", lambda b, r: _env(b), None),
    (".git/HEAD", "Git-Ordner (Quelltext abrufbar)", "crit", lambda b, r: (b or "").startswith("ref:"), None),
    (".git/config", "Git-Konfiguration", "crit", lambda b, r: "[core]" in (b or ""), None),
    (".svn/entries", "Subversion-Ordner", "crit", lambda b, r: bool(re.match(r"\s*\d+\s", b or "")) or "dir" in (b or "")[:50], None),
    (".DS_Store", "macOS-Verzeichnisdatei (verrät Dateinamen)", "warn", lambda b, r: r[:8] == b"\x00\x00\x00\x01Bud1", None),
    ("phpinfo.php", "phpinfo-Seite", "warn", lambda b, r: "phpinfo()" in (b or "") or "PHP Version" in (b or ""), None),
    ("info.php", "phpinfo-Seite", "warn", lambda b, r: "phpinfo()" in (b or "") or "PHP Version" in (b or ""), None),
    ("adminer.php", "Datenbank-Werkzeug Adminer", "crit", lambda b, r: "adminer" in (b or "").lower(), None),
    ("phpmyadmin/", "phpMyAdmin", "warn", lambda b, r: "phpmyadmin" in (b or "").lower(), None),
    ("error_log", "PHP-Fehlerprotokoll", "warn", lambda b, r: _log(b), None),
    ("backup.zip", "Sicherung (ZIP)", "crit", lambda b, r: _zip(r, b), None),
    ("backup.sql", "Datenbank-Sicherung", "crit", lambda b, r: _sql(b), None),
    ("dump.sql", "Datenbank-Sicherung", "crit", lambda b, r: _sql(b), None),
    ("database.sql", "Datenbank-Sicherung", "crit", lambda b, r: _sql(b), None),
    ("db.sql", "Datenbank-Sicherung", "crit", lambda b, r: _sql(b), None),
    ("site.zip", "Sicherung (ZIP)", "crit", lambda b, r: _zip(r, b), None),
    ("www.zip", "Sicherung (ZIP)", "crit", lambda b, r: _zip(r, b), None),
    ("public_html.zip", "Sicherung (ZIP)", "crit", lambda b, r: _zip(r, b), None),
    ("backup.tar.gz", "Sicherung (tar.gz)", "crit", lambda b, r: _zip(r, b), None),
    ("composer.lock", "Composer-Sperrdatei (verrät Paketversionen)", "warn", lambda b, r: '"packages"' in (b or ""), ("drupal", "typo3", "contao", "prestashop", "shopware")),
    ("composer.json", "Composer-Datei", "info", lambda b, r: '"require"' in (b or ""), ("drupal", "typo3", "contao", "prestashop", "shopware")),
    # WordPress
    ("wp-config.php.bak", "Sicherung der wp-config.php", "crit", lambda b, r: "DB_PASSWORD" in (b or "") or _php_src(b), ("wordpress",)),
    ("wp-config.php.old", "Sicherung der wp-config.php", "crit", lambda b, r: "DB_PASSWORD" in (b or "") or _php_src(b), ("wordpress",)),
    ("wp-config.php~", "Sicherung der wp-config.php", "crit", lambda b, r: "DB_PASSWORD" in (b or "") or _php_src(b), ("wordpress",)),
    ("wp-config.php.save", "Sicherung der wp-config.php", "crit", lambda b, r: "DB_PASSWORD" in (b or "") or _php_src(b), ("wordpress",)),
    ("wp-config.txt", "Kopie der wp-config", "crit", lambda b, r: "DB_PASSWORD" in (b or ""), ("wordpress",)),
    ("wp-content/debug.log", "WordPress-Debug-Protokoll", "warn", lambda b, r: _log(b), ("wordpress",)),
    ("wp-content/uploads/", "Verzeichnisliste von uploads", "warn", lambda b, r: _listing(b), ("wordpress",)),
    ("wp-content/plugins/", "Verzeichnisliste der Plugins", "warn", lambda b, r: _listing(b), ("wordpress",)),
    ("readme.html", "readme.html (verrät die Version)", "info", lambda b, r: "WordPress" in (b or ""), ("wordpress",)),
    ("wp-admin/install.php", "Installationsseite", "crit", lambda b, r: "Install" in (b or "") and "WordPress" in (b or "") and "already installed" not in (b or "").lower() and "bereits installiert" not in (b or "").lower(), ("wordpress",)),
    # Joomla
    ("configuration.php.bak", "Sicherung der configuration.php", "crit", lambda b, r: "JConfig" in (b or "") or _php_src(b), ("joomla",)),
    ("configuration.php.old", "Sicherung der configuration.php", "crit", lambda b, r: "JConfig" in (b or "") or _php_src(b), ("joomla",)),
    ("configuration.php~", "Sicherung der configuration.php", "crit", lambda b, r: "JConfig" in (b or "") or _php_src(b), ("joomla",)),
    ("configuration.php-dist", "Konfigurationsvorlage", "info", lambda b, r: "JConfig" in (b or ""), ("joomla",)),
    ("installation/index.php", "Installationsverzeichnis", "crit", lambda b, r: "Joomla" in (b or "") and ("install" in (b or "").lower()), ("joomla",)),
    ("administrator/logs/", "Protokollordner", "warn", lambda b, r: _listing(b), ("joomla",)),
    ("logs/", "Protokollordner", "warn", lambda b, r: _listing(b), ("joomla",)),
    ("htaccess.txt", "htaccess.txt (Vorlage)", "info", lambda b, r: "RewriteEngine" in (b or ""), ("joomla",)),
    ("administrator/manifests/files/joomla.xml", "Joomla-Manifest (verrät die Version)", "info", lambda b, r: "<version>" in (b or ""), ("joomla",)),
    # Drupal
    ("sites/default/settings.php.bak", "Sicherung der settings.php", "crit", lambda b, r: _php_src(b) or "databases" in (b or ""), ("drupal",)),
    ("sites/default/settings.php~", "Sicherung der settings.php", "crit", lambda b, r: _php_src(b) or "databases" in (b or ""), ("drupal",)),
    ("sites/default/settings.local.php", "Lokale Einstellungen", "crit", lambda b, r: _php_src(b), ("drupal",)),
    ("sites/default/files/", "Verzeichnisliste von sites/default/files", "warn", lambda b, r: _listing(b), ("drupal",)),
    ("core/install.php", "Installationsseite", "warn", lambda b, r: "Drupal" in (b or "") and "install" in (b or "").lower() and "already" not in (b or "").lower()[:4000], ("drupal",)),
    ("CHANGELOG.txt", "CHANGELOG.txt (verrät die Version)", "info", lambda b, r: bool(re.match(r"\s*Drupal\s+\d", b or "")), ("drupal",)),
    ("core/CHANGELOG.txt", "CHANGELOG.txt (verrät die Version)", "info", lambda b, r: bool(re.match(r"\s*Drupal\s+\d", b or "")), ("drupal",)),
    # TYPO3
    ("typo3conf/LocalConfiguration.php", "TYPO3-Konfiguration", "crit", lambda b, r: _php_src(b) or "'DB'" in (b or ""), ("typo3",)),
    ("typo3conf/LocalConfiguration.php.bak", "Sicherung der TYPO3-Konfiguration", "crit", lambda b, r: _php_src(b) or "'DB'" in (b or ""), ("typo3",)),
    ("typo3conf/localconf.php", "Alte TYPO3-Konfiguration", "crit", lambda b, r: _php_src(b), ("typo3",)),
    ("typo3conf/ENABLE_INSTALL_TOOL", "Install-Tool freigeschaltet", "crit", lambda b, r: True, ("typo3",)),
    ("typo3/install.php", "TYPO3-Install-Tool erreichbar", "warn", lambda b, r: "TYPO3" in (b or ""), ("typo3",)),
    ("fileadmin/_temp_/", "Verzeichnisliste fileadmin/_temp_", "warn", lambda b, r: _listing(b), ("typo3",)),
    ("fileadmin/", "Verzeichnisliste fileadmin", "warn", lambda b, r: _listing(b), ("typo3",)),
    ("var/log/", "Protokollordner", "warn", lambda b, r: _listing(b), ("typo3", "contao", "shopware", "prestashop")),
    # Contao
    ("system/config/localconfig.php", "Contao-Konfiguration (Contao 4.x/3.x)", "crit", lambda b, r: _php_src(b) or "dbPass" in (b or ""), ("contao",)),
    ("config/parameters.yaml", "Contao-Parameter", "crit", lambda b, r: "database_" in (b or "") or "parameters:" in (b or ""), ("contao",)),
    ("app/config/parameters.yml", "Parameterdatei", "crit", lambda b, r: "database_" in (b or "") or "parameters:" in (b or ""), ("contao", "prestashop")),
    ("contao-manager.phar.php", "Contao Manager erreichbar", "warn", lambda b, r: "contao" in (b or "").lower() or _php_src(b), ("contao",)),
    ("contao-manager/", "Contao-Manager-Ordner", "warn", lambda b, r: _listing(b), ("contao",)),
    ("files/", "Verzeichnisliste files", "warn", lambda b, r: _listing(b), ("contao",)),
    # PrestaShop
    ("install/index.php", "Installationsordner", "crit", lambda b, r: "PrestaShop" in (b or ""), ("prestashop",)),
    ("install-dev/index.php", "Installationsordner (Entwicklung)", "crit", lambda b, r: "PrestaShop" in (b or ""), ("prestashop",)),
    ("config/settings.inc.php.bak", "Sicherung der settings.inc.php", "crit", lambda b, r: _php_src(b) or "_DB_PASSWD_" in (b or ""), ("prestashop",)),
    ("app/config/parameters.php", "PrestaShop-Parameter", "crit", lambda b, r: _php_src(b) or "database_password" in (b or ""), ("prestashop",)),
    ("config/settings.inc.php", "PrestaShop-Konfiguration", "crit", lambda b, r: _php_src(b) or "_DB_PASSWD_" in (b or ""), ("prestashop",)),
    ("docs/CHANGELOG.txt", "CHANGELOG (verrät die Version)", "info", lambda b, r: "PrestaShop" in (b or "") or bool(re.search(r"Version\s+\d", b or "")), ("prestashop",)),
    ("log/", "Protokollordner", "warn", lambda b, r: _listing(b), ("prestashop",)),
    # Shopware
    ("config/jwt/private.pem", "Privater Schlüssel (JWT)", "crit", lambda b, r: "PRIVATE KEY" in (b or ""), ("shopware",)),
    (".env.local", "Lokale Umgebungsdatei", "crit", lambda b, r: _env(b), ("shopware",)),
    ("recovery/install/", "Installer erreichbar", "crit", lambda b, r: "shopware" in (b or "").lower() and "install" in (b or "").lower(), ("shopware",)),
    ("shopware.php", "Shopware-5-Startdatei", "info", lambda b, r: False, ("shopware",)),
    ("config.php", "Shopware-5-Konfiguration", "crit", lambda b, r: _php_src(b) or "'db'" in (b or ""), ("shopware",)),
]


def files_for(cms: str) -> List[Tuple[str, str, str, Any, Optional[Tuple[str, ...]]]]:
    return [f for f in FILES if f[4] is None or cms in f[4]]


def is_real_hit(path: str, status: int, body: str, raw: bytes, baseline: Optional[Tuple[int, str]]) -> bool:
    """Treffer nur bei Status 200 UND nicht der Fehlerseite der Webseite UND passendem Inhalt (Signatur je Datei), damit Weiterleitungen und 'weiche 404' nichts melden."""
    if status != 200:
        return False
    if baseline and baseline[0] == 200 and _same_page(body, baseline[1]):
        return False
    for p, _l, _s, test, _sys in FILES:
        if p == path:
            try:
                return bool(test(body, raw))
            except Exception:          # noqa: BLE001
                return False
    return False


def _same_page(a: str, b: str) -> bool:
    a, b = re.sub(r"\s+", " ", a or "")[:3000], re.sub(r"\s+", " ", b or "")[:3000]
    if not a or not b:
        return False
    if a == b:
        return True
    return abs(len(a) - len(b)) < 120 and a[:600] == b[:600]


# ---------------------------------------------------------------- Bewertung der Kernversion
def _fnd(res: CheckResult, sev: str, title: str, detail: str = "", items: Optional[List[str]] = None, hint: str = "") -> None:
    res.add(sev, title, detail, items or [], hint)


def judge_version(cms: str, version: str, ctx: Any = None) -> Tuple[str, str]:
    """(Schwere, Text) für die Kernversion – online (offizielle Quellen), sonst 'info'. Nie ein Fehler, wenn die Quelle fehlt."""
    from .. import util
    name = NAMES.get(cms, cms)
    if not version:
        return "info", "Die %s-Version ist von außen nicht lesbar; eine Aussage zur Aktualität ist ohne Serverzugang nicht möglich." % name
    if os.environ.get("CLAUDIA_OFFLINE"):
        return "info", "%s %s erkannt. Aktualität nicht geprüft (Offline-Modus)." % (name, version)
    try:
        if cms == "wordpress":
            f = webmod.fetch("https://api.wordpress.org/core/stable-check/1.0/", webmod.UA_BROWSER, max_bytes=400_000, timeout=20)
            from .wp import stable_check_status
            st = stable_check_status(f.body, version) if not f.error and f.status == 200 else ""
            if st == "insecure":
                return "crit", "WordPress %s wird von WordPress.org als UNSICHER eingestuft (bekannte Lücken)." % version
            if st == "outdated":
                return "warn", "WordPress %s ist veraltet (es gibt eine neuere Version desselben Zweigs oder neuer)." % version
            if st == "latest":
                return "ok", "WordPress %s ist die aktuelle Version." % version
            return "info", "WordPress %s erkannt; die Einstufung war online nicht abrufbar." % version
        if cms == "joomla":
            f = webmod.fetch("https://update.joomla.org/core/list.xml", webmod.UA_BROWSER, max_bytes=400_000, timeout=20)
            vs = re.findall(r"version=\"(\d+\.\d+\.\d+)\"", f.body) if not f.error and f.status == 200 else []
            major = version.split(".")[0]
            same = [v for v in vs if v.split(".")[0] == major]
            if major in ("1", "2", "3") and int(major) <= 3:
                return "crit", "Joomla %s wird nicht mehr mit Sicherheitsupdates versorgt (Joomla 3 und älter)." % version
            if not same:
                return "info", "Joomla %s erkannt; die Liste der Veröffentlichungen war online nicht abrufbar." % version
            newest = max(same, key=lambda v: tuple(int(x) for x in v.split(".")))
            if util.vcmp(version, newest) < 0:
                return "warn", "Joomla %s ist nicht die neueste Version (aktuell: %s). Neuere Versionen schließen Sicherheitslücken." % (version, newest)
            return "ok", "Joomla %s ist auf dem neuesten Stand." % version
        if cms == "drupal":
            from . import auswertung_drupal as ad, drupal_checks as dc
            if "." not in version:
                return "info", "Nur die Hauptversion %s ist sichtbar; die genaue Version ist von außen nicht lesbar." % version
            fs = ad.judge_core(version, dc.history("drupal"))
            worst = max(fs, key=lambda x: {"ok": 0, "info": 1, "warn": 2, "crit": 3}[x.sev]) if fs else None
            return (worst.sev, "%s %s" % (worst.title, worst.detail)) if worst else ("info", "Drupal %s erkannt." % version)
        if cms in ("typo3", "contao", "prestashop", "shopware") and ctx is not None:
            mod = {"typo3": ("typo3_checks", "auswertung_typo3", "typo3"), "contao": ("contao_checks", "auswertung_contao", "contao"),
                   "prestashop": ("prestashop_checks", "auswertung_prestashop", "prestashop"), "shopware": ("shopware_checks", "auswertung_shopware", "shopware")}[cms]
            import importlib
            chk = importlib.import_module("claudia.checks." + mod[0])
            aus = importlib.import_module("claudia.checks." + mod[1])
            lib = importlib.import_module("claudia." + mod[2])
            pkg = {"typo3": "typo3/cms-core", "contao": "contao/core-bundle", "prestashop": "prestashop/prestashop", "shopware": "shopware/core"}[cms]
            rel = chk.releases(ctx, lib.major(version)) if cms == "typo3" else chk.releases(ctx)
            adv, adv_ok = chk.advisories([pkg])
            fs = aus.judge_core(version, rel, lib.advisories_for(version, adv, pkg), adv_ok=adv_ok)
            worst = max(fs, key=lambda x: {"ok": 0, "info": 1, "warn": 2, "crit": 3}[x.sev]) if fs else None
            return (worst.sev, "%s %s" % (worst.title, worst.detail)) if worst else ("info", "%s %s erkannt." % (name, version))
    except Exception:          # noqa: BLE001  (fehlende Online-Daten dürfen nie zum Fehler werden)
        return "info", "%s %s erkannt; die Bewertung war nicht möglich." % (name, version)
    return "info", "%s %s erkannt." % (name, version)


# ---------------------------------------------------------------- Abruf (gemeinsam, einmal je Lauf)
PROBES = ["/administrator/", "/administrator/manifests/files/joomla.xml", "/language/en-GB/en-GB.xml", "/language/en-GB/langmetadata.xml",
          "/feed/", "/readme.html", "/core/CHANGELOG.txt", "/CHANGELOG.txt", "/typo3/", "/contao", "/admin", "/api/_info/version"]


def _base(ctx) -> str:
    url = (ctx.s.url or "").strip()
    if not url:
        raise CheckSkipped("Keine Adresse der Webseite angegeben.")
    from .. import secure
    url, _ = secure.to_https(url)
    return url.rstrip("/")


def gather(ctx) -> Dict[str, Any]:
    """Ruft Startseite und einige Standardadressen einmal ab (zwischengespeichert für alle externen Tests)."""
    if "extern" in ctx.shared:
        return ctx.shared["extern"]
    base = _base(ctx)
    ctx.progress("Rufe die Startseite ab")
    home = webmod.fetch(base + "/", webmod.UA_BROWSER, max_bytes=1_500_000, timeout=25)
    probes: Dict[str, Tuple[int, str]] = {}
    html = home.body or ""
    pre = detect(html, home.headers, home.set_cookies, {})
    bf = webmod.fetch(base + "/claudia-" + secrets.token_hex(6) + ".txt", webmod.UA_BROWSER, max_bytes=60_000, timeout=15)
    soft: Optional[Tuple[int, str]] = (bf.status, bf.body) if (not bf.error and bf.status == 200) else None
    for p in PROBES:
        f = webmod.fetch(base + p, webmod.UA_BROWSER, max_bytes=60_000, timeout=15)
        if not f.error and not (soft and f.status == 200 and _same_page(f.body, soft[1])):
            probes[p] = (f.status, f.body)
    d = detect(html, home.headers, home.set_cookies, probes)
    ver, src = parse_version(d["cms"], html, home.headers, probes) if d["cms"] else ("", "")
    data = {"soft": soft, "base": base, "home": home, "html": html, "probes": probes, "detect": d, "pre": pre, "version": ver, "version_src": src}
    ctx.shared["extern"] = data
    return data


@check(
    "ext_fingerprint", G, "Von außen: System und Version erkennen",
    "Welches System läuft, welche Version ist sichtbar, und ist sie aktuell?",
    what="Ruft die Startseite und einige öffentliche Standardadressen auf (zum Beispiel Verwaltungs-Anmeldung, Versions- und Änderungsdateien) und erkennt daran das System (Joomla, WordPress, Drupal, TYPO3, Contao, PrestaShop, Shopware) und, soweit sichtbar, die Version. Die Version wird online mit den offiziellen Quellen verglichen.",
    why="Veraltete Versionen sind das häufigste Einfallstor. Was von außen lesbar ist, sieht auch ein Angreifer - und scannt gezielt danach.",
    reads="Öffentlich erreichbare Adressen Ihrer Domain, so wie jeder Besucher sie sieht. Es wird nichts verändert und nichts gespeichert.",
    load="leicht", needs="web", presets=["schnell", "hack", "komplett"], cms="both", extern=True,
)
def ext_fingerprint(ctx, res):
    g = gather(ctx)
    home = g["home"]
    if home.error and not home.status:
        raise CheckSkipped("Die Webseite ist nicht erreichbar: %s" % home.error)
    cms = g["detect"]["cms"]
    if not cms:
        _fnd(res, "info", "Das System konnte von außen nicht eindeutig erkannt werden",
             "Es gibt keine ausreichend klaren Merkmale (oder sie sind bewusst entfernt). Das ist für Angreifer ein kleiner Hürdenvorteil, für diese Prüfung aber eine Grenze.",
             ["Bewertung der Merkmale: " + ", ".join("%s=%d" % (NAMES[k], v) for k, v in g["detect"]["scores"].items() if v)] if any(g["detect"]["scores"].values()) else [])
        return
    name = NAMES[cms]
    _fnd(res, "info", "Erkannt: %s" % name, "Merkmale: " + "; ".join(g["detect"]["evidence"]) + ".")
    if cms != ctx.cms:
        _fnd(res, "info", "Abweichung vom gewählten System", "Gewählt war %s, erkannt wurde %s. Die systemspezifischen Prüfungen folgen dem gewählten System." % (NAMES.get(ctx.cms, ctx.cms), name))
    ver = g["version"]
    sev, text = judge_version(cms, ver, ctx)
    if ver:
        res.add(sev, "%s %s (Quelle: %s)" % (name, ver, g["version_src"]), text, [],
                "Auf die neueste Version aktualisieren (vorher vollständige Sicherung)." if sev in ("warn", "crit") else "")
        _fnd(res, "info", "Die Version ist öffentlich lesbar", "Wer die Version kennt, sucht gezielt nach bekannten Lücken. Die Quelle sperren oder entfernen, wo möglich (Generator-Angabe, Änderungsdateien, Manifeste).")
    else:
        _fnd(res, "info", "%s-Version nicht ermittelbar" % name, text)


@check(
    "ext_components", G, "Von außen: sichtbare Erweiterungen",
    "Welche Plugins, Module, Themes oder Pakete verrät der Quelltext - und sind sie aktuell?",
    what="Liest aus dem Quelltext der Startseite, welche Erweiterungen eingebunden sind (Ordnernamen und, falls angegeben, Versionsnummern). Bei WordPress werden die Versionen zusätzlich über die öffentliche readme.txt der Plugins und das offizielle Verzeichnis (api.wordpress.org) verglichen; bei PrestaShop über die öffentlichen config.xml der Module.",
    why="Erweiterungen sind der häufigste Angriffsweg. Vom Besucher sichtbare Erweiterungen sind auch für Angreifer sichtbar; veraltete Versionen werden automatisiert gesucht.",
    reads="Den öffentlichen Quelltext der Startseite und einzelne öffentliche Dateien der Erweiterungen (readme.txt, config.xml). Nichts wird verändert oder gespeichert.",
    load="mittel", needs="web", presets=["schnell", "hack", "komplett"], cms="both", extern=True,
)
def ext_components(ctx, res):
    g = gather(ctx)
    cms = g["detect"]["cms"] or ctx.cms
    comps = components(cms, g["html"])
    if not comps:
        _fnd(res, "info", "Keine Erweiterungen im Quelltext sichtbar", "Die Startseite verrät keine Erweiterungsordner. Unsichtbare Erweiterungen (nur im Verwaltungsbereich) lassen sich von außen nicht erfassen.")
        return
    base = g["base"]
    online = not os.environ.get("CLAUDIA_OFFLINE")
    old: List[str] = []
    listed: List[str] = []
    checked = 0
    for c in comps:
        ver = c["version"]
        if cms == "wordpress" and c["kind"] == "Plugin" and checked < 25:
            checked += 1
            ctx.progress("Prüfe Plugin %s" % c["slug"])
            f = webmod.fetch("%s/wp-content/plugins/%s/readme.txt" % (base, c["slug"]), webmod.UA_BROWSER, max_bytes=30_000, timeout=12)
            if not f.error and f.status == 200:
                ver = readme_stable_tag(f.body) or ver
            if ver and online:
                from .. import util
                a = webmod.fetch("https://api.wordpress.org/plugins/info/1.0/%s.json" % c["slug"], webmod.UA_BROWSER, max_bytes=300_000, timeout=15)
                latest = wp_plugin_latest(a.body) if not a.error and a.status == 200 else ""
                if latest and util.vcmp(ver, latest) < 0:
                    old.append("%s %s (aktuell: %s)" % (c["slug"], ver, latest))
        if cms == "prestashop" and c["kind"] == "Modul" and checked < 25:
            checked += 1
            f = webmod.fetch("%s/modules/%s/config.xml" % (base, c["slug"]), webmod.UA_BROWSER, max_bytes=20_000, timeout=12)
            if not f.error and f.status == 200:
                ver = _first(r"<version><!\[CDATA\[\s*" + VER, f.body) or _first(r"<version>\s*" + VER, f.body) or ver
        listed.append("%s %s%s" % (c["kind"], c["slug"], (" " + ver) if ver else ""))
    _fnd(res, "info", "%d Erweiterung(en) sichtbar" % len(comps), "Diese Namen kann jeder Besucher aus dem Quelltext lesen." + (" Versionen stammen aus Quelltext, readme.txt oder config.xml." if any(" " in x.split(" ", 2)[-1] for x in listed) else ""), listed[:100])
    if old:
        _fnd(res, "warn", "%d Plugin(s) mit älterer Version als im Verzeichnis" % len(old), "Veraltete Plugins sind ein häufiger Einstieg für Angreifer.", old,
             "Plugins aktualisieren (vorher Sicherung) oder entfernen, wenn sie nicht gebraucht werden.")
    elif cms == "wordpress" and online and checked:
        _fnd(res, "ok", "Keine veralteten Plugins unter den lesbaren Versionen", "Verglichen wurden die Plugins, deren Version öffentlich lesbar war.")


@check(
    "ext_files", G_WEB, "Von außen: vergessene und sensible Dateien",
    "Sind Sicherungen, Konfigurationen, Protokolle, Schlüssel oder Installer frei abrufbar?",
    what="Ruft eine Liste typischer Fundorte ab (zum Beispiel .env, .git, Konfigurations-Sicherungen, Datenbank-Dumps, ZIP-Sicherungen, Protokolle, Installationsordner, Verzeichnislisten). Ein Treffer zählt nur bei Status 200, abweichender Fehlerseite UND passendem Inhalt, damit Weiterleitungen und Platzhalterseiten nichts melden.",
    why="Vergessene Sicherungen und Konfigurationen enthalten oft Zugangsdaten. Sie werden täglich automatisch gesucht und innerhalb von Minuten gefunden.",
    reads="Öffentliche Adressen Ihrer Domain. Der Inhalt wird nur kurz auf Merkmale geprüft und nicht gespeichert. Zugangsdaten werden nie angezeigt.",
    load="mittel", needs="web", presets=["schnell", "hack", "komplett"], cms="both", extern=True,
)
def ext_files(ctx, res):
    g = gather(ctx)
    cms = g["detect"]["cms"] or ctx.cms
    base = g["base"]
    baseline: Optional[Tuple[int, str]] = g.get("soft")
    hits: Dict[str, List[str]] = {"crit": [], "warn": [], "info": []}
    todo = files_for(cms)
    for i, (path, label, sev, _t, _s) in enumerate(todo):
        ctx.progress("Prüfe %s (%d/%d)" % (path, i + 1, len(todo)))
        f = webmod.fetch("%s/%s" % (base, path), webmod.UA_BROWSER, max_bytes=40_000, timeout=12, binary=path.endswith((".zip", ".gz", ".DS_Store")))
        if f.error:
            continue
        if is_real_hit(path, f.status, f.body, f.raw, baseline):
            hits[sev].append("/%s: %s" % (path, label))
    if hits["crit"]:
        _fnd(res, "crit", "%d kritische Datei(en) frei abrufbar" % len(hits["crit"]), "Diese Dateien enthalten typischerweise Zugangsdaten oder den kompletten Quelltext.", hits["crit"],
             "Sofort entfernen oder den Zugriff sperren, danach alle betroffenen Passwörter und Schlüssel erneuern (Datenbank, Salts, API-Schlüssel).")
    if hits["warn"]:
        _fnd(res, "warn", "%d Datei(en) oder Verzeichnislisten abrufbar" % len(hits["warn"]), "Sie verraten Aufbau, Dateinamen oder Fehlermeldungen.", hits["warn"],
             "Entfernen oder per Serverregel sperren; Verzeichnislisten abschalten (Options -Indexes).")
    if hits["info"]:
        _fnd(res, "info", "%d Datei(en) verraten Version oder Aufbau" % len(hits["info"]), "Kein Angriff, aber nützlich für gezielte Suche.", hits["info"])
    if not any(hits.values()):
        _fnd(res, "ok", "Keine vergessenen oder sensiblen Dateien gefunden", "Geprüft wurden %d typische Fundorte für %s." % (len(todo), NAMES.get(cms, cms)))


class _Mini:
    """Minimaler Ersatz für den Lauf-Kontext, damit die Erkennung auch beim Verbinden (vor dem Lauf) funktioniert."""

    def __init__(self, url: str) -> None:
        self.s = type("S", (), {"url": url})()
        self.shared: Dict[str, Any] = {}

    def progress(self, msg: str) -> None:
        pass


def detect_site(url: str) -> Dict[str, Any]:
    """Erkennt System und Version einer Adresse (für den Start im externen Modus). Rückgabe: {cms, name, version, evidence, reachable}."""
    try:
        g = gather(_Mini(url))
    except CheckSkipped as e:
        return {"cms": "", "name": "", "version": "", "evidence": [], "reachable": False, "error": str(e)}
    home = g["home"]
    cms = g["detect"]["cms"]
    return {"cms": cms, "name": NAMES.get(cms, ""), "version": g["version"], "evidence": g["detect"]["evidence"],
            "reachable": not (home.error and not home.status), "error": home.error or ""}
