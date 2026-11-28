"""WordPress-Prüfungen. Gleicher Aufbau wie bei Joomla (Grundlagen, Dateien, Konfiguration, Plugins/Themes, Datenbank, Protokolle),
aber auf WordPress zugeschnitten. Die dateibasierten Tests (Web-Shells, Uploads, Rechte, .htaccess ...) sind die gemeinsamen Tests der anderen Module."""
from __future__ import annotations

import csv
import io
import json
import os
import re
import time
from typing import Any, Dict, List, Optional
from urllib.parse import quote, urlparse

from .. import coreref, extsums, wordpress, wpsums
from ..model import CheckSkipped, Option
from ..registry import check
from ..util import clean_line, digits, extract_hosts, host_allowed, lines_of, split_sections, trunc, vcmp
from . import web as webmod
from .config import ENTRY_TOKENS
from .database import add_manual_sql, age_days, fetch, fmt_date, inject_scan, need_db, _inj_query
from .system import env_items
from ..probe import PHP_PROBE_SCRIPT

WPC = {"cms": "wordpress"}
API = "https://api.wordpress.org"


# ============================================================================ Grundlagen
@check(
    "wp_info", "grundlagen", "WordPress-Version und Umgebung",
    "Welche WordPress-Version läuft, unter welchem Benutzer und mit welchem PHP?",
    what="Liest die Versionsdatei von WordPress (wp-includes/version.php) und fragt Benutzernamen, Verzeichnis, PHP-Version der Kommandozeile und freien "
         "Speicherplatz ab. Vergleicht die Version mit der neuesten Version, die dem Programm bekannt ist, und meldet, wie weit die Reihe hinter der neuesten liegt (WordPress sichert ältere Reihen nur aus Kulanz).",
    why="Veraltete WordPress-Versionen und Plugins sind das häufigste Einfallstor. Die Prüfung zeigt außerdem sofort, ob das eingegebene Verzeichnis "
        "wirklich eine WordPress-Installation ist.",
    reads="Nur eine kleine Versionsdatei und einfache Systeminformationen. Nichts wird geändert.",
    load="leicht", presets=["schnell", "hack"], cms="wordpress",
)
def wp_info(ctx, res):
    out = ctx.sh(r"""
echo '@@VERSION'; head -c 6000 wp-includes/version.php 2>/dev/null
echo '@@WHO'; whoami 2>/dev/null; pwd
echo '@@DISK'; df -h . 2>/dev/null | tail -1
echo '@@CONFIG'; if test -f wp-config.php; then echo ja; elif test -f ../wp-config.php; then echo ja-oben; else echo nein; fi
echo '@@MULTI'; grep -c "MULTISITE'" wp-config.php 2>/dev/null
""" + PHP_PROBE_SCRIPT, timeout=60, raw="ausgabe").out
    sec = split_sections(out)
    ver = wordpress.parse_wp_version(sec.get("VERSION", ""))
    items = env_items(ctx, sec, out)
    if not ver["version"]:
        res.add("warn", "Keine WordPress-Installation erkannt",
                "Im angegebenen Verzeichnis wurde keine Datei wp-includes/version.php gefunden.", items,
                "Bitte das Verzeichnis prüfen (es muss die Ordner 'wp-admin', 'wp-content', 'wp-includes' und die Datei 'wp-config.php' enthalten).")
        return
    ctx.shared["wp_version"] = ver["version"]
    ctx.shared["wp_version_info"] = ver
    if ver["required_php"]:
        items.append("Diese WordPress-Version verlangt mindestens PHP %s" % ver["required_php"])
    if "ja-oben" in sec.get("CONFIG", ""):
        items.append("Die wp-config.php liegt eine Ebene über dem Webordner (gute Praxis)")
    res.add("info", "WordPress %s" % ver["version"], "Gefundene Version laut wp-includes/version.php.", items, context=True)
    latest = ctx.adv.get("wordpress", {}).get("latest_known", "")
    if latest and vcmp(ver["version"], latest) < 0:
        res.add("warn", "WordPress ist älter als die neueste bekannte Version (%s)" % latest,
                "Die Vergleichsliste stammt vom %s - neuere Versionen können inzwischen erschienen sein. Die Online-Prüfung 'Plugins und Themes online abgleichen' nennt die aktuelle Lage." % ctx.adv.get("stand", "?"),
                hint="WordPress im Dashboard unter Dashboard -> Aktualisierungen auf den neuesten Stand bringen.")
    from .system import cms_branch_finding
    eolf = cms_branch_finding("wordpress", ver["version"], ctx.adv)
    if eolf:
        res.add(eolf[0], eolf[1], eolf[2], hint=eolf[3])
    php = (ctx.shared.get("php_version") or "").replace("PHP ", "")
    if php and ver["required_php"] and vcmp(php, ver["required_php"]) < 0:
        res.add("crit", "PHP %s ist für diese WordPress-Version zu alt" % php,
                "WordPress %s verlangt mindestens PHP %s." % (ver["version"], ver["required_php"]), hint="Im Hosting-Panel eine neuere PHP-Version wählen.")
    if "nein" in sec.get("CONFIG", ""):
        res.add("warn", "wp-config.php fehlt", "Ohne diese Datei läuft WordPress nicht (oder das Verzeichnis ist falsch).")


# ============================================================================ Konfiguration
@check(
    "wp_config", "konfig", "WordPress-Konfiguration (wp-config.php)",
    "Steht in der wp-config.php eingeschleuster Code - oder sind unsichere Einstellungen aktiv?",
    what="Liest die wp-config.php (die Zugangsdaten werden nie angezeigt oder gespeichert) und prüft: eingefügten Code, Standard- oder fehlende Schlüssel (Salts), "
         "Debug-Einstellungen, Dateibearbeitung im Dashboard, Tabellenpräfix, fremde Adressen für WP_HOME/WP_SITEURL und Einstellungen, die automatische Updates blockieren.",
    why="Die wp-config.php wird bei jedem Seitenaufruf geladen: Eingefügter Code läuft immer mit. Schwache Schlüssel erleichtern das Übernehmen von Anmeldungen, "
        "und Debug-Ausgaben verraten Pfade und Datenbank-Fehler.",
    reads="Den Inhalt der wp-config.php, ausgewertet auf diesem PC. Passwörter und Schlüssel werden im Bericht durch *** ersetzt.",
    load="leicht", presets=["schnell", "hack"], cms="wordpress",
)
def wp_config(ctx, res):
    cfg = ctx.config()
    if cfg.get("missing"):
        res.add("warn", "wp-config.php nicht gefunden", "Weder im Seitenordner noch eine Ebene darüber.")
        return
    d = cfg["defines"]
    def on(k):
        return d.get(k) in (True, "true", "TRUE", 1, "1")
    items = ["Datenbank-Host: %s" % d.get("DB_HOST", "?"), "Datenbank: %s" % d.get("DB_NAME", "?"), "Tabellenpräfix: %s" % cfg["prefix"]]
    res.add("info", "Datenbank-Einstellungen", "Zugangsdaten werden nicht angezeigt.", items)
    if cfg["unexpected"]:
        res.add("crit", "Verdächtiger Code in der wp-config.php",
                "Zeilen mit eval, base64_decode, Zugriff auf Formulardaten oder Befehlsausführung gehören nicht in diese Datei.",
                ["Zeile %d: %s" % (n, trunc(clean_line(t), 170)) for n, t in cfg["unexpected"][:20]],
                "Datei sichern, Zeile entfernen und die Einfallslücke schließen. Danach Datenbank-Passwort und Schlüssel erneuern.")
    bad_keys, missing = [], []
    vals = {}
    for k in wordpress.SECRET_KEYS:
        v = d.get(k)
        if v in (None, ""):
            missing.append(k)
        elif re.search(r"put your unique phrase here|ändere diese|your unique|example", str(v), re.IGNORECASE) or len(str(v)) < 32:
            bad_keys.append(k)
        else:
            vals[k] = v
    if len(set(vals.values())) < len(vals):
        bad_keys.append("mehrere Schlüssel haben denselben Wert")
    if bad_keys or (missing and len(missing) == len(wordpress.SECRET_KEYS)):
        res.add("warn", "Schlüssel und Salts sind Standardwerte, zu kurz oder fehlen",
                "Die acht Schlüssel (AUTH_KEY ... NONCE_SALT) sichern Anmelde-Cookies. Mit Standardwerten lassen sich Cookies erraten oder fälschen.",
                bad_keys + (["fehlt: " + ", ".join(missing)] if missing else []),
                "Neue Schlüssel erzeugen (Lösung 'Schlüssel und Salts erneuern' bzw. api.wordpress.org/secret-key/1.1/salt/). Alle angemeldeten Benutzer müssen sich danach neu anmelden.")
    elif missing:
        res.add("info", "Nicht alle Schlüssel sind gesetzt", "", ["fehlt: " + ", ".join(missing)])
    if on("WP_DEBUG"):
        res.add("warn", "Debug-Modus ist eingeschaltet (WP_DEBUG)", "Auf einer Live-Seite zeigen Fehlermeldungen Pfade und können Zugangsdaten verraten.",
                ["WP_DEBUG_DISPLAY ist %s" % ("an" if on("WP_DEBUG_DISPLAY") else "nicht gesetzt oder aus"),
                 "WP_DEBUG_LOG ist %s" % ("an (debug.log wird geschrieben)" if d.get("WP_DEBUG_LOG") not in (None, False, "false") else "aus")],
                "WP_DEBUG auf false setzen.")
    elif d.get("WP_DEBUG_LOG") not in (None, False, "false"):
        res.add("info", "WP_DEBUG_LOG ist an", "Es wird eine Datei wp-content/debug.log geschrieben. Sie darf von außen nicht abrufbar sein (siehe Test 'Öffentlich abrufbare Dateien').")
    if not on("DISALLOW_FILE_EDIT"):
        res.add("info", "Dateien lassen sich im Dashboard bearbeiten", "Mit dem Theme-/Plugin-Editor kann jeder Administrator PHP-Dateien ändern - auch ein Angreifer mit gestohlenem Konto.",
                hint="define('DISALLOW_FILE_EDIT', true); in die wp-config.php setzen (Lösung 'Dateibearbeitung im Dashboard sperren').")
    if on("DISALLOW_FILE_MODS"):
        res.add("info", "Installation und Updates im Dashboard sind gesperrt (DISALLOW_FILE_MODS)",
                "Gut gegen Manipulation, aber WordPress kann sich dann nicht selbst aktualisieren. Updates müssen von Hand oder über wp-cli eingespielt werden.")
    if d.get("AUTOMATIC_UPDATER_DISABLED") in (True, "true") or d.get("WP_AUTO_UPDATE_CORE") in (False, "false"):
        res.add("info", "Automatische Updates sind abgeschaltet", "Sicherheits-Updates des Kerns kommen dann nicht von selbst.", hint="Nur abgeschaltet lassen, wenn du Updates regelmäßig von Hand einspielst.")
    if cfg["prefix"] == "wp_":
        res.add("info", "Tabellenpräfix ist der Standard 'wp_'", "Kein Sicherheitsgewinn durch Ändern, aber automatische Angriffe nehmen den Standardwert an. Ein Wechsel ist aufwendig und nur bei Neuinstallationen sinnvoll.")
    own = ctx.own_host()
    for k in ("WP_HOME", "WP_SITEURL"):
        v = d.get(k)
        if isinstance(v, str) and v.startswith("http"):
            h = (urlparse(v).hostname or "").lower()
            if own and h and h != own and h.lstrip("www.") != own.lstrip("www."):
                res.add("crit", "%s zeigt auf eine fremde Adresse (%s)" % (k, h), "Besucher könnten umgeleitet werden.", hint="Adresse prüfen und korrigieren.")
    if not on("FORCE_SSL_ADMIN"):
        res.add("info", "FORCE_SSL_ADMIN ist nicht gesetzt", "Die Anmeldung sollte nur verschlüsselt (https) erfolgen. Das erzwingt FORCE_SSL_ADMIN, falls die Seite nicht ohnehin überall auf https umleitet.")
    if cfg["size"] > 12_000:
        res.add("warn", "wp-config.php ist ungewöhnlich groß (%d Byte)" % cfg["size"], "Eine normale Datei hat 3 bis 6 KB. Eine große Datei enthält vermutlich zusätzlichen Code.")
    if not (cfg["unexpected"] or bad_keys):
        res.add("ok", "Keine eingeschleusten Zeilen in der wp-config.php")


# ----------------------------------------------------------------------------- Einstiegspunkte
@check(
    "wp_entry_points", "konfig", "Einstiegsdateien, Drop-ins und Must-Use-Plugins",
    "Läuft bei jedem Seitenaufruf Code mit, den du nicht kennst?",
    what="Prüft die Dateien, die WordPress bei JEDEM Aufruf lädt: index.php, wp-config.php, die Drop-ins in wp-content (advanced-cache.php, db.php, object-cache.php ...), "
         "alle Must-Use-Plugins (mu-plugins) und die Dateien header.php, footer.php und functions.php aller Themes. Sucht dort nach eval, base64_decode, fremden Skript-Adressen und Befehlsausführung.",
    why="Must-Use-Plugins und Drop-ins sind im Dashboard unsichtbar bzw. lassen sich dort nicht abschalten - ein beliebtes Versteck für Hintertüren. "
        "Die functions.php eines Themes ist die häufigste Stelle für eingeschleusten Spam- und Weiterleitungscode.",
    reads="Den Inhalt weniger Dateien (Einstiegs-, Drop-in-, mu-plugin- und Theme-Dateien). Bekannte Dienste (Google Tag Manager ...) gelten als bekannt.",
    load="leicht", presets=["schnell", "hack"], cms="wordpress",
)
def wp_entry_points(ctx, res):
    script = r"""
DROP="advanced-cache.php db.php object-cache.php sunrise.php maintenance.php install.php db-error.php php-error.php fatal-error-handler.php"
FILES="index.php wp-blog-header.php wp-load.php wp-content/index.php wp-content/plugins/index.php wp-content/themes/index.php wp-content/mu-plugins/*.php wp-content/mu-plugins/*/*.php wp-content/themes/*/functions.php wp-content/themes/*/header.php wp-content/themes/*/footer.php"
for d in $DROP; do FILES="$FILES wp-content/$d"; done
echo '@@FILES'
for f in $FILES; do [ -f "$f" ] && printf 'F\t%s\t%s\t%s\n' "$f" "$(stat -c %s "$f")" "$(stat -c %y "$f" | cut -c1-16)"; done
echo '@@HITS'
for f in $FILES; do [ -f "$f" ] && grep -nHiE -e '@TOKENS@' "$f" 2>/dev/null | cut -c1-300; done | head -400
echo '@@HEAD'
[ -f index.php ] && head -c 800 index.php
""".replace("@TOKENS@", ENTRY_TOKENS)
    out = ctx.sh(script, timeout=60, raw="treffer").out
    sec = split_sections(out)
    allow, own = ctx.allow(), ctx.own_host()
    sizes: Dict[str, int] = {}
    for ln in sec.get("FILES", "").splitlines():
        p = ln.split("\t")
        if len(p) >= 4 and p[0] == "F":
            sizes[p[1]] = int(p[2] or 0)
    crit, warn, info_hosts = [], [], []
    for ln in sec.get("HITS", "").splitlines():
        m = re.match(r"^(.*?):(\d+):(.*)\Z", ln)
        if not m:
            continue
        path, no, line = m.group(1), m.group(2), m.group(3)
        low = line.lower()
        hosts = [h for h in extract_hosts(line) if h != own]
        bad = [h for h in hosts if not host_allowed(h, allow)]
        desc = "%s Zeile %s: %s" % (clean_line(path), no, trunc(clean_line(line.strip()), 170))
        high = path in ("index.php", "wp-blog-header.php", "wp-load.php") or "/mu-plugins/" in path or re.search(r"wp-content/(advanced-cache|db|object-cache|sunrise)\.php$", path)
        dangerous = re.search(r"eval *\(|base64_decode|gzinflate|str_rot13|fromcharcode|shell_exec|passthru|system *\(|@include|@eval|@ini_set|atob\(|curl_exec|include(_once)? *\(? *.(/tmp|http|\$_)|document\.write", low)
        obf = bool(re.search(r"eval *\(.{0,120}fromcharcode|fromcharcode *\( *([0-9]+ *, *){25,}|eval *\( *base64_decode", low))
        if dangerous:
            (crit if (high or obf) else warn).append(desc + "  -> %s" % ("verschleierter Code: sehr wahrscheinlich Schadcode" if obf else "an dieser Stelle sehr ungewöhnlich" if high else "prüfen"))
        elif bad:
            warn.append(desc + "  -> unbekannte Adresse: %s" % ", ".join(bad[:3]))
        elif ("<script" in low or "<iframe" in low) and hosts:
            info_hosts.append(desc + "  -> bekannter Dienst: %s" % ", ".join(hosts[:3]))
    if crit:
        res.add("crit", "Verdächtiger Code in Einstiegsdateien", "Diese Dateien laufen bei jedem Seitenaufruf.", crit[:40],
                "Datei mit dem Original vergleichen (Kern: Test 'WordPress-Kern gegen Original prüfen'), bei Plugins/Themes neu installieren.")
    if warn:
        res.add("warn", "Auffälligkeiten in Theme-, Drop-in- oder Plugin-Dateien", "Skripte von unbekannten Adressen oder Funktionen, die dort selten vorkommen.", warn[:60],
                "Kennst du diese Einbindung? Falls nicht, entfernen (vorher Datei sichern).")
    if info_hosts:
        res.add("info", "Skripte/Frames von bekannten Diensten", "", info_hosts[:25])
    mu = sorted(f for f in sizes if "/mu-plugins/" in f)
    if mu:
        res.add("info", "%d Must-Use-Plugin-Datei(en) vorhanden" % len(mu),
                "Diese Plugins sind im Dashboard nur in einer eigenen Liste sichtbar und lassen sich nicht abschalten. Kennst du alle?", [clean_line(f) for f in mu[:30]])
    drops = sorted(f for f in sizes if re.match(r"wp-content/[^/]+\.php$", f) and not f.endswith("index.php"))
    if drops:
        res.add("info", "%d Drop-in(s) in wp-content" % len(drops),
                "Drop-ins ersetzen Teile von WordPress (Cache, Datenbank-Schicht). Sie gehören meist zu Cache-Plugins - ein unbekanntes Drop-in ist verdächtig.", [clean_line(f) for f in drops])
    if sizes.get("index.php", 0) > 2048:
        res.add("warn", "index.php ist ungewöhnlich groß (%d Byte)" % sizes["index.php"], "Die Standarddatei hat etwa 0,5 KB. Eine größere Datei enthält vermutlich zusätzlichen Code.",
                hint="Mit dem Original aus dem WordPress-Paket ersetzen.")
    if not (crit or warn):
        res.add("ok", "Einstiegs-, Drop-in- und Theme-Dateien unauffällig", "%d Dateien geprüft." % len(sizes))


# ----------------------------------------------------------------------------- Kern-Prüfsummen
CORE_SCRIPT = r"""
echo '@@SUMS'
{ find wp-admin wp-includes -type f -print0 2>/dev/null; for f in *.php *.html *.txt; do [ -f "$f" ] && printf '%s\0' "$f"; done; } | xargs -0 -r md5sum 2>/dev/null
echo '@@LOCALE'
grep -oE "wp_local_package *= *'[A-Za-z_]+'" wp-includes/version.php 2>/dev/null | head -1
"""


def parse_checksums(text: str) -> Dict[str, str]:
    try:
        data = json.loads(text)
    except ValueError:
        return {}
    c = data.get("checksums") if isinstance(data, dict) else None
    if isinstance(c, dict) and c and isinstance(next(iter(c.values())), dict):   # neuere Antworten: {version: {datei: md5}}
        c = next(iter(c.values()))
    return {k: str(v) for k, v in (c or {}).items() if isinstance(v, str)} if isinstance(c, dict) else {}


@check(
    "wp_core", "konfig", "WordPress-Kern gegen Original prüfen",
    "Stimmen alle Dateien in wp-admin und wp-includes mit dem offiziellen Original überein?",
    what="Berechnet auf dem Server die Prüfsumme (MD5) jeder Datei in wp-admin, wp-includes und im Hauptordner und vergleicht sie mit den offiziellen Prüfsummen von api.wordpress.org "
         "für genau diese Version. Veränderte Dateien, unbekannte zusätzliche Dateien im Kern und fehlende Kerndateien werden gemeldet.",
    why="Der Kern von WordPress wird nie von Hand geändert. Jede abweichende oder zusätzliche Datei in wp-admin/wp-includes ist ein starker Hinweis auf eine Manipulation - "
        "oder auf ein unvollständiges Update, an dem die automatische Aktualisierung scheitert.",
    reads="Nur Prüfsummen der Kerndateien (die Dateien werden nicht übertragen). Die Prüfsummen-Liste wird von DIESEM PC bei api.wordpress.org abgerufen (https).",
    load="mittel", presets=["hack"], cms="wordpress",
)
def wp_core(ctx, res):
    if os.environ.get("CLAUDIA_OFFLINE"):
        raise CheckSkipped("Offline-Modus (CLAUDIA_OFFLINE): Die Prüfsummen werden nicht abgerufen.")
    ver = ctx.shared.get("wp_version") or ""
    if not ver:
        r = ctx.sh("head -c 6000 wp-includes/version.php 2>/dev/null").out
        ver = wordpress.parse_wp_version(r)["version"]
    if not ver:
        raise CheckSkipped("WordPress-Version nicht erkannt.")
    out = ctx.sh(CORE_SCRIPT, timeout=240, raw="pruefsummen", raw_cap=60_000).out
    sec = split_sections(out)
    locale = (re.search(r"'([A-Za-z_]+)'", sec.get("LOCALE", "")) or [None, "en_US"])[1]
    sums: Dict[str, str] = {}
    for ln in sec.get("SUMS", "").splitlines():
        m = re.match(r"^([0-9a-f]{32})\s+\*?(.+)\Z", ln)
        if m:
            sums[m.group(2).lstrip("./")] = m.group(1)
    ctx.progress("Lade Prüfsummen für WordPress %s" % ver)
    ref: Dict[str, str] = {}
    for loc in (locale, "en_US"):
        f = webmod.fetch("%s/core/checksums/1.0/?version=%s&locale=%s" % (API, quote(ver), quote(loc)), webmod.UA_BROWSER, max_bytes=3_000_000, timeout=25)
        if f.error:
            raise CheckSkipped("Prüfsummen nicht abrufbar: %s" % f.error)
        ref = parse_checksums(f.body)
        if ref:
            break
    if not ref:
        res.add("info", "Für WordPress %s gibt es keine offiziellen Prüfsummen" % ver,
                "Eine Entwicklerversion, eine sehr neue oder eine angepasste Version. Ein Vergleich ist nicht möglich.")
        return
    core_ref = {k: v for k, v in ref.items() if not k.startswith("wp-content/")}
    changed = sorted(k for k, v in sums.items() if k in core_ref and core_ref[k] != v)
    extra = sorted(k for k in sums if "/" in k and k not in core_ref)
    missing = sorted(k for k in core_ref if "/" in k and k not in sums)
    root_missing = sorted(k for k in core_ref if "/" not in k and k not in sums)
    # Dateien, die Hoster und Betreiber üblicherweise ändern oder entfernen
    soft = {"readme.html", "license.txt", "wp-config-sample.php", "readme.txt"}
    if changed:
        crit = [k for k in changed if k not in soft]
        if crit:
            res.add("crit", "%d Kerndatei(en) weichen vom Original ab" % len(crit),
                    "Der Inhalt unterscheidet sich vom offiziellen WordPress %s. Entweder wurde die Datei manipuliert, oder ein Update ist unvollständig." % ver, crit[:60],
                    "Kern neu installieren (Dashboard -> Aktualisierungen -> Erneut installieren, oder Lösung 'Kerndateien neu installieren'). Die Seite und wp-content bleiben dabei erhalten.")
        if [k for k in changed if k in soft]:
            res.add("info", "Beschreibungsdateien weichen ab (üblich)", "readme.html und license.txt werden oft von Hostern oder Betreibern geändert.", [k for k in changed if k in soft])
    if extra:
        res.add("crit" if any(re.search(r"\.(php\d?|phtml|phar)$", k, re.I) for k in extra) else "warn",
                "%d unbekannte Datei(en) in wp-admin/wp-includes" % len(extra),
                "Diese Ordner enthalten nur Kerndateien. Zusätzliche Dateien dort sind ein klassisches Versteck für Hintertüren.", extra[:60],
                "Dateien ansehen (herunterladen, nicht ausführen) und löschen, wenn sie nicht zu einem bekannten Plugin gehören.")
    if missing:
        res.add("warn", "%d Kerndatei(en) fehlen in wp-admin/wp-includes" % len(missing),
                "Ein abgebrochenes Update hinterlässt fehlende Dateien. Die Seite kann Fehler zeigen, automatische Updates scheitern.", missing[:40],
                "Kern neu installieren.")
    if root_missing and not set(root_missing) <= soft:
        res.add("info", "Kerndateien im Hauptordner fehlen", "", [k for k in root_missing if k not in soft][:20])
    if not (changed or extra or missing):
        res.add("ok", "Alle %d Kerndateien stimmen mit dem Original von WordPress %s überein" % (len([k for k in sums if k in core_ref]), ver),
                "Prüfsummen von api.wordpress.org (Sprache: %s)." % locale)


# ============================================================================ Plugins & Themes
FS_SCRIPT = r"""
echo '@@PLUGINS'
for d in wp-content/plugins/*/; do
  [ -d "$d" ] || continue
  found=0
  for f in "$d"*.php; do
    [ -f "$f" ] || continue
    if head -c 4000 "$f" | grep -q 'Plugin Name:'; then printf '@@@P %s\n' "$f"; head -c 4000 "$f"; echo; found=1; break; fi
  done
  if [ $found = 0 ]; then n=$(find "$d" -maxdepth 2 -type f \( -name '*.php' -o -name '*.phtml' \) 2>/dev/null | head -50 | wc -l); printf '@@@NOHEAD %s\t%s\n' "$d" "$n"; fi
done
echo '@@SINGLE'
for f in wp-content/plugins/*.php; do [ -f "$f" ] || continue; printf '@@@S %s\t%s\n' "$f" "$(stat -c %s "$f")"; head -c 1500 "$f"; echo; done
echo '@@THEMES'
for d in wp-content/themes/*/; do
  [ -d "$d" ] || continue
  if [ -f "$d/style.css" ]; then printf '@@@T %s\n' "$d"; head -c 3000 "$d/style.css"; echo; else printf '@@@NOHEAD %s\t0\n' "$d"; fi
done
echo '@@MU'
ls -1 wp-content/mu-plugins 2>/dev/null | head -100
"""


def get_wp_fs(ctx) -> Dict[str, Any]:
    """Plugin- und Theme-Inventar aus dem Dateisystem (wird gecacht)."""
    if "wp_fs" in ctx.shared:
        return ctx.shared["wp_fs"]
    out = ctx.sh(FS_SCRIPT, timeout=120).out
    sec = split_sections(out)
    plugins: List[Dict[str, str]] = []
    nohead: List[Dict[str, str]] = []
    themes: List[Dict[str, str]] = []
    singles: List[Dict[str, str]] = []

    def blocks(text: str, tag: str):
        for chunk in text.split("@@@")[1:]:
            head, _, body = chunk.partition("\n")
            if head.startswith(tag + " ") or head == tag:
                yield head[len(tag):].strip(), body

    for sname, kind, store in (("PLUGINS", "P", plugins), ("THEMES", "T", themes)):
        text = sec.get(sname, "")
        for path, body in blocks("@@@" + text if not text.startswith("@@@") else text, kind):
            h = wordpress.parse_wp_header(body)
            if not h:
                continue
            parts = path.rstrip("/").split("/")
            slug = parts[2] if kind == "P" else parts[2]
            h.update({"slug": slug, "path": path.strip()})
            store.append(h)
        for path, body in blocks("@@@" + text if not text.startswith("@@@") else text, "NOHEAD"):
            p, _, n = path.partition("\t")
            nohead.append({"path": p.strip(), "php": (n or body or "0").strip(), "kind": "plugin" if sname == "PLUGINS" else "theme"})
    for path, body in blocks("@@@" + sec.get("SINGLE", "") if sec.get("SINGLE", "") else "", "S"):
        p, _, sz = path.partition("\t")
        h = wordpress.parse_wp_header(body)
        singles.append({"path": p.strip(), "size": sz.strip(), "name": h.get("name", ""), "version": h.get("version", "")})
    mu = lines_of(sec.get("MU", ""))
    data = {"plugins": plugins, "themes": themes, "nohead": nohead, "singles": singles, "mu": mu}
    ctx.shared["wp_fs"] = data
    return data


def _advisory_hits(advs: List[Dict[str, Any]], items: List[Dict[str, str]], kind: str):
    out = []
    by_slug = {i["slug"]: i for i in items}
    for a in advs:
        if a.get("kind", "plugin") != kind:
            continue
        it = by_slug.get(a["slug"])
        if not it or not it.get("version"):
            continue
        v = it["version"]
        if a.get("from") and vcmp(v, a["from"]) < 0:
            continue
        if vcmp(v, a["fixed_in"]) < 0:
            out.append((a, it))
    return out


@check(
    "wp_plugins", "erweiterungen", "Plugins und Themes inventarisieren und gegen Listen prüfen",
    "Welche Plugins und Themes sind installiert - und sind Versionen mit bekannten Sicherheitslücken dabei?",
    what="Liest den Kopf jeder Plugin-Hauptdatei und jeder style.css und erstellt eine Liste mit Name, Version und Autor. Gleicht sie mit einer Liste bekannter schwerer Lücken ab. "
         "Meldet Ordner ohne Plugin-Beschreibung, lose PHP-Dateien im Plugin-Ordner und nicht benutzte Themes.",
    why="Veraltete Plugins sind der häufigste Einbruchsweg bei WordPress, nicht der Kern. Ordner ohne Beschreibung und lose Dateien sind typische Verstecke für Hintertüren. "
        "Ungenutzte Themes und Plugins vergrößern die Angriffsfläche, ohne etwas zu nützen.",
    reads="Nur die ersten Zeilen der Plugin-Hauptdateien und style.css-Dateien (Kopfzeilen).",
    load="leicht", presets=["schnell", "hack"], cms="wordpress",
)
def wp_plugins(ctx, res):
    data = get_wp_fs(ctx)
    pl, th = data["plugins"], data["themes"]
    if not pl and not th and not data["nohead"]:
        res.add("warn", "Keine Plugins oder Themes gefunden", "Verzeichnis falsch oder wp-content ungewöhnlich aufgebaut.")
        return
    buf = io.StringIO()
    wr = csv.writer(buf, delimiter=";")
    wr.writerow(["art", "ordner", "name", "version", "autor", "pfad"])
    for kind, lst in (("plugin", pl), ("theme", th)):
        for i in sorted(lst, key=lambda x: x["slug"]):
            wr.writerow([kind, i["slug"], i.get("name", ""), i.get("version", ""), i.get("author", ""), i["path"]])
    ctx.add_raw("inventar_csv", buf.getvalue())
    res.add("info", "%d Plugin(s) und %d Theme(s) installiert" % (len(pl), len(th)),
            "Die vollständige Liste liegt im Bericht (Anhang 'inventar_csv'). Gilt für aktive und inaktive Plugins: auch ein ausgeschaltetes Plugin mit Lücke ist angreifbar, solange die Dateien da sind.",
            ["%s %s (%s)" % (clean_line(i.get("name", i["slug"])), i.get("version", "?"), clean_line(i.get("author", "ohne Autor"))) for i in sorted(pl, key=lambda x: x.get("name", ""))][:60])
    advs = ctx.adv.get("wp_plugins", [])
    for kind, lst in (("plugin", pl), ("theme", th)):
        hits = _advisory_hits(advs, lst, kind)
        crit = [h for h in hits if h[0]["severity"] == "crit"]
        rest = [h for h in hits if h[0]["severity"] != "crit"]
        for grp, sev in ((crit, "crit"), (rest, "warn")):
            if grp:
                res.add(sev, "%d %s mit bekannter Sicherheitslücke" % (len(grp), "Plugin(s)" if kind == "plugin" else "Theme(s)"),
                        "Die installierte Version ist älter als die Version, in der die Lücke behoben wurde.",
                        ["%s %s (%s), behoben in %s: %s%s" % (h[0]["title"], h[1].get("version", "?"), h[0]["cve"], h[0]["fixed_in"], h[0]["note"], ("  [Kennung: %s]" % h[1]["slug"]) if kind == "plugin" and h[1].get("slug") else "") for h in grp],
                        "Sofort aktualisieren (Dashboard -> Aktualisierungen, oder Lösung 'Plugins und Themes aktualisieren'). Wenn die Seite in der Zeit mit der alten Version lief: auf Hintertüren prüfen und Passwörter erneuern.")
    nohead = [n for n in data["nohead"] if n["kind"] == "plugin" and int(n["php"] or 0) > 0]
    if nohead:
        res.add("warn", "%d Ordner im Plugin-Verzeichnis ohne Plugin-Beschreibung, aber mit PHP-Dateien" % len(nohead),
                "Ein echtes Plugin trägt in seiner Hauptdatei den Kommentarkopf 'Plugin Name:'. Ohne ihn ist der Ordner im Dashboard unsichtbar - und läuft dennoch, wenn er geladen wird. Ein beliebtes Versteck.",
                ["%s  (%s PHP-Dateien)" % (clean_line(n["path"]), n["php"]) for n in nohead][:30], "Ordner ansehen und löschen, wenn du ihn nicht kennst.")
    loose = [s for s in data["singles"] if not s["path"].endswith(("/index.php", "/hello.php"))]
    if loose:
        res.add("warn", "%d lose PHP-Datei(en) direkt im Plugin-Ordner" % len(loose),
                "Außer index.php (Platzhalter) und hello.php (Hello Dolly) liegen dort normalerweise nur Ordner.",
                ["%s  (%s Byte%s)" % (clean_line(s["path"]), s["size"], (", Plugin: %s" % s["name"]) if s["name"] else ", ohne Plugin-Kopf") for s in loose][:30],
                "Datei prüfen. Eine Datei ohne Plugin-Kopf ist sehr verdächtig.")
    if any(s["path"].endswith("/hello.php") for s in data["singles"]):
        res.add("info", "Beispiel-Plugin 'Hello Dolly' ist installiert", "Es gehört zum WordPress-Paket, wird aber nicht gebraucht.", hint="Löschen, wenn nicht genutzt.")
    if len(th) > 3:
        res.add("info", "%d Themes installiert" % len(th), "Nur das aktive Theme (und bei Child-Themes das Eltern-Theme) wird gebraucht. Jedes weitere Theme kann veralten und angreifbar werden.",
                [clean_line("%s %s" % (t.get("name", t["slug"]), t.get("version", ""))) for t in th][:20], "Nicht benutzte Themes löschen.")
    bad_themes = [n for n in data["nohead"] if n["kind"] == "theme" and int(n["php"] or 0) >= 0 and not n["path"].endswith("/index/")]
    if bad_themes:
        res.add("warn", "%d Ordner im Theme-Verzeichnis ohne style.css" % len(bad_themes),
                "Jedes Theme braucht eine style.css mit Kopfzeilen. Ohne sie ist der Ordner kein gültiges Theme.", [clean_line(n["path"]) for n in bad_themes][:20], "Prüfen und löschen, wenn unbekannt.")
    if not (hits_any(advs, pl, th) or nohead or loose):
        res.add("ok", "Keine bekannten Sicherheitslücken in der eingebauten Liste, keine versteckten Plugin-Ordner",
                "Die eingebaute Liste ist nur eine Auswahl. Für die aktuelle Lage dient der Online-Test.")


def hits_any(advs, pl, th) -> bool:
    return bool(_advisory_hits(advs, pl, "plugin") or _advisory_hits(advs, th, "theme"))


def parse_plugin_info(text: str) -> Optional[Dict[str, Any]]:
    try:
        d = json.loads(text)
    except ValueError:
        return None
    if not isinstance(d, dict) or d.get("error") or not d.get("version"):
        return None
    return d


def stable_check_status(text: str, ver: str) -> str:
    """'insecure' | 'outdated' | 'latest' | '' laut api.wordpress.org/core/stable-check."""
    try:
        d = json.loads(text)
    except ValueError:
        return ""
    return str(d.get(ver, "")) if isinstance(d, dict) else ""


@check(
    "wp_plugins_online", "erweiterungen", "Plugins und Themes online abgleichen",
    "Ist der Kern als unsicher eingestuft - und sind Plugins veraltet oder im offiziellen Verzeichnis nicht mehr zu finden?",
    what="Fragt von DIESEM PC aus api.wordpress.org: Wie stuft WordPress die installierte Kern-Version ein (aktuell, veraltet, unsicher)? Für jedes Plugin und Theme: neueste Version, "
         "Datum der letzten Aktualisierung und ob es im Verzeichnis noch existiert.",
    why="Plugins, die seit Jahren nicht mehr gepflegt werden oder aus dem Verzeichnis entfernt wurden (oft wegen Sicherheitsproblemen), sind ein hohes Risiko. "
        "Nur die Online-Abfrage zeigt zuverlässig, was heute aktuell ist.",
    reads="Ruft öffentliche Adressen bei api.wordpress.org ab (https, wie ein Browser). Zum Server wird nichts gesendet; gesendet werden nur Plugin-Ordnernamen.",
    load="mittel", presets=["schnell", "hack"], cms="wordpress",
    options=[Option("max", "Höchstens so viele Plugins/Themes nachschlagen", "int", 80, "Jede Abfrage dauert etwa eine Sekunde.")],
)
def wp_plugins_online(ctx, res):
    if os.environ.get("CLAUDIA_OFFLINE"):
        raise CheckSkipped("Offline-Modus (CLAUDIA_OFFLINE): api.wordpress.org wird nicht abgefragt.")
    data = get_wp_fs(ctx)
    ver = ctx.shared.get("wp_version") or ""
    if ver:
        ctx.progress("Frage Einstufung des Kerns ab")
        f = webmod.fetch(API + "/core/stable-check/1.0/", webmod.UA_BROWSER, max_bytes=400_000, timeout=20)
        st = stable_check_status(f.body, ver) if not f.error else ""
        if st == "insecure":
            res.add("crit", "WordPress %s wird von WordPress.org als UNSICHER eingestuft" % ver,
                    "Für diese Version sind Sicherheitslücken bekannt, die in neueren Versionen behoben sind.", hint="Sofort aktualisieren.")
        elif st == "outdated":
            res.add("warn", "WordPress %s ist veraltet" % ver, "Es gibt eine neuere Version.", hint="Im Dashboard unter Aktualisierungen aktualisieren.")
        elif st == "latest":
            res.add("ok", "WordPress %s ist die aktuelle Version" % ver)
        elif f.error:
            res.add("info", "Kern-Einstufung nicht abrufbar", f.error)
    limit = max(1, ctx.opt_int("max", 80))
    old, missing, stale, closed_err = [], [], [], []
    now = time.time()
    n = 0
    for kind, lst in (("plugin", data["plugins"]), ("theme", data["themes"])):
        for it in lst:
            if n >= limit:
                break
            n += 1
            ctx.progress("Schlage %s nach" % it["slug"][:40])
            if kind == "plugin":
                url = "%s/plugins/info/1.0/%s.json" % (API, quote(it["slug"]))
            else:
                url = "%s/themes/info/1.2/?action=theme_information&request%%5Bslug%%5D=%s&request%%5Bfields%%5D%%5Bversions%%5D=0" % (API, quote(it["slug"]))
            f = webmod.fetch(url, webmod.UA_BROWSER, max_bytes=1_500_000, timeout=20)
            label = "%s %s" % (clean_line(it.get("name", it["slug"])), it.get("version", "?"))
            if f.error or f.status >= 500:
                closed_err.append(label)
                continue
            info = parse_plugin_info(f.body)
            if not info:
                missing.append("%s (%s)" % (label, kind))
                continue
            latest = str(info.get("version") or "")
            if latest and it.get("version") and vcmp(it["version"], latest) < 0:
                old.append("%s -> aktuell %s" % (label, latest))
            lu = str(info.get("last_updated") or "")[:10]
            try:
                t = time.mktime(time.strptime(lu, "%Y-%m-%d"))
                if (now - t) / 86400.0 > 730:
                    stale.append("%s - zuletzt aktualisiert am %s" % (label, lu))
            except ValueError:
                pass
    if old:
        res.add("warn", "%d Plugin(s)/Theme(s) haben eine neuere Version" % len(old), "Updates schließen oft Sicherheitslücken.", old[:60],
                "Aktualisieren (Dashboard -> Aktualisierungen oder Lösung 'Plugins und Themes aktualisieren').")
    if stale:
        res.add("warn", "%d Plugin(s)/Theme(s) seit über 2 Jahren nicht mehr aktualisiert" % len(stale),
                "Aufgegebene Plugins bekommen keine Sicherheitskorrekturen mehr.", stale[:40], "Durch eine gepflegte Alternative ersetzen.")
    if missing:
        res.add("info", "%d Plugin(s)/Theme(s) nicht im offiziellen Verzeichnis gefunden" % len(missing),
                "Das ist bei gekauften (Premium-)Plugins und Eigenbauten normal. Bei freien Plugins kann es heißen, dass das Plugin entfernt wurde - oft wegen Sicherheitsproblemen.", missing[:40],
                "Bei freien Plugins prüfen: Wurde es geschlossen (wordpress.org/plugins/<Name>)?")
    if closed_err:
        res.add("info", "%d Abfrage(n) nicht möglich" % len(closed_err), "api.wordpress.org antwortete nicht. Später erneut versuchen.", closed_err[:20])
    if not (old or stale or any(f.sev in ("crit", "warn") for f in res.findings)):
        res.add("ok", "Alle abgefragten Plugins und Themes sind aktuell und gepflegt", "%d abgefragt." % n)


# ============================================================================ Datenbank
Q_WP_USERS = [
    ("Alle Benutzer mit Rolle", "SELECT u.ID AS id, u.user_login AS login, u.user_email AS email, u.display_name AS name, u.user_registered AS registered, "
     "u.user_status AS status, m.meta_value AS caps FROM #__users u LEFT JOIN #__usermeta m ON m.user_id = u.ID AND m.meta_key = '#__capabilities' "
     "ORDER BY u.user_registered DESC LIMIT 500"),
    ("Anwendungs-Passwörter und Sitzungen", "SELECT user_id, meta_key, LENGTH(meta_value) AS len, SUBSTRING(meta_value, 1, 5000) AS v FROM #__usermeta "
     "WHERE meta_key IN ('_application_passwords', 'session_tokens') AND meta_value <> ''"),
]


PLUGIN_SUMS_SCRIPT = r"""
find wp-content/plugins -mindepth 2 -type f -size -2048k -print0 2>/dev/null | head -z -n 60000 | xargs -0 -r sha256sum 2>/dev/null
"""


@check(
    "wp_plugin_integrity", "erweiterungen", "Plugin-Dateien gegen das Original prüfen",
    "Stimmen die Dateien der Plugins mit den offiziellen Originalen von wordpress.org überein?",
    what="Berechnet auf dem Server die Prüfsumme (SHA-256) aller Plugin-Dateien und vergleicht sie mit den Prüfsummen, die wordpress.org für genau diese Plugin-Version veröffentlicht. "
         "Gemeldet werden geänderte Dateien, zusätzliche PHP-Dateien und fehlende PHP-Dateien. Plugins, die nicht im offiziellen Verzeichnis stehen (Premium, selbst entwickelt), können nicht geprüft werden und werden als solche aufgelistet.",
    why="Angreifer verstecken Hintertüren gern in bestehenden Plugin-Dateien: Der Code wirkt normal, die Datei ist aber verändert. Nur der Vergleich mit dem Original zeigt das zuverlässig, auch bei Code, den kein Suchmuster erkennt.",
    reads="Prüfsummen der Plugin-Dateien (Dateien werden nicht übertragen). Pro Plugin wird eine öffentliche Adresse bei downloads.wordpress.org abgerufen (https, einzeln nacheinander, nur für deine installierten Plugins, höchstens die eingestellte Anzahl).",
    load="mittel", presets=["hack"], cms="wordpress",
    options=[Option("max", "Höchstens so viele Plugins prüfen", "int", 60, "Jede Abfrage dauert etwa eine Sekunde.")],
)
def wp_plugin_integrity(ctx, res):
    if os.environ.get("CLAUDIA_OFFLINE"):
        raise CheckSkipped("Offline-Modus (CLAUDIA_OFFLINE): Die Prüfsummen werden nicht abgerufen.")
    data = get_wp_fs(ctx)
    plugins = [p for p in data["plugins"] if p.get("version")]
    if not plugins:
        raise CheckSkipped("Keine Plugins mit Versionsangabe gefunden.")
    ctx.progress("Prüfsummen der Plugin-Dateien berechnen")
    local = wpsums.parse_local(ctx.sh(PLUGIN_SUMS_SCRIPT, timeout=600).out)
    limit = max(1, ctx.opt_int("max", 60))
    bad_changed, bad_extra, bad_missing, no_ref, err, ok = [], [], [], [], [], []
    for i, pl in enumerate(plugins):
        if i >= limit:
            err.append("%d weitere Plugins wegen der Höchstzahl nicht geprüft" % (len(plugins) - limit))
            break
        slug = pl["slug"]
        label = "%s %s" % (clean_line(pl.get("name", slug)), pl["version"])
        if slug not in local:
            continue
        ctx.progress("Prüfe %s" % slug[:40])
        f = webmod.fetch(wpsums.url(slug, pl["version"]), webmod.UA_BROWSER, max_bytes=3_000_000, timeout=20)
        if f.error or f.status >= 500:
            err.append("%s (Abruf nicht möglich)" % label)
            continue
        ref = wpsums.parse_reference(f.body) if f.status == 200 else {}
        if not ref:
            no_ref.append(label)
            continue
        d = wpsums.compare(local[slug], ref)
        php_changed = [x for x in d["changed"] if wpsums.CODE_RE.search(x)]
        bad_changed += ["%s: %s" % (slug, x) for x in php_changed]
        bad_extra += ["%s: %s" % (slug, x) for x in d["extra"]]
        bad_missing += ["%s: %s" % (slug, x) for x in d["missing"]]
        if not (d["changed"] or d["extra"] or d["missing"]):
            ok.append(label)
    if bad_changed:
        res.add("crit", "%d Plugin-Datei(en) weichen vom Original ab" % len(bad_changed),
                "Der Inhalt unterscheidet sich vom offiziellen Plugin in genau dieser Version. Entweder wurde die Datei manipuliert, oder jemand hat das Plugin von Hand geändert.",
                bad_changed[:60], "Plugin neu installieren (Dashboard -> Plugins -> Löschen und neu installieren; Einstellungen liegen in der Datenbank). Bei selbst vorgenommenen Änderungen diese vorher sichern.")
    if bad_extra:
        res.add("warn", "%d zusätzliche PHP-Datei(en) in Plugin-Ordnern" % len(bad_extra),
                "Diese Dateien gehören nicht zum offiziellen Plugin. Manche Plugins erzeugen eigene Dateien, ein Versteck für Hintertüren ist es aber auch.", bad_extra[:60],
                "Dateien ansehen (nicht ausführen). Ohne bekannte Herkunft löschen.")
    if bad_missing:
        res.add("info", "%d PHP-Datei(en) des Originals fehlen" % len(bad_missing), "Oft ein abgebrochenes Update oder ein Hoster-Virenscanner, der Dateien entfernt hat.", bad_missing[:40])
    if no_ref:
        res.add("info", "%d Plugin(s) ohne Prüfsummen bei wordpress.org (nicht prüfbar)" % len(no_ref),
                "Premium-, selbst entwickelte oder aus dem Verzeichnis entfernte Plugins sowie sehr neue Versionen. Für sie gilt dieser Test nicht; die Suche nach Mustern prüft sie trotzdem.", no_ref[:60])
    if err:
        res.add("info", "Nicht alles konnte geprüft werden", "", err[:20])
    if ok and not (bad_changed or bad_extra):
        res.add("ok", "%d Plugin(s) stimmen mit dem Original überein" % len(ok), "Prüfsummen von downloads.wordpress.org.", ok[:60])


THEME_SUMS_SCRIPT = r"""
find wp-content/themes -mindepth 2 -type f -size -2048k -print0 2>/dev/null | head -z -n 60000 | xargs -0 -r sha256sum 2>/dev/null
"""
THEME_CODE_RE = re.compile(r"\.(php\d?|phtml|phar|inc|js)$|(^|/)\.htaccess$|(^|/)\.user\.ini$", re.I)


@check(
    "wp_theme_integrity", "erweiterungen", "Theme-Dateien gegen das Original prüfen",
    "Stimmen die Dateien der Themes mit den offiziellen Paketen von wordpress.org überein?",
    what="Lädt für jedes installierte Theme, das im offiziellen Verzeichnis steht, das Paket der installierten Version von downloads.wordpress.org (nur im Speicher gelesen, nie entpackt oder ausgeführt), "
         "berechnet daraus die Prüfsumme jeder Datei und vergleicht sie mit den Prüfsummen vom Server. Gemeldet werden geänderte PHP- und JavaScript-Dateien, zusätzliche PHP-Dateien und fehlende PHP-Dateien. "
         "Themes, die nicht im offiziellen Verzeichnis stehen (Premium, Kindthemes, selbst entwickelt), können nicht geprüft werden und werden als solche aufgelistet.",
    why="Für Themes gibt es keine veröffentlichten Prüfsummen wie bei Plugins; Angreifer verstecken Schadcode aber gern in der functions.php oder in Skripten eines Themes. Nur der Vergleich mit dem Originalpaket zeigt das auch bei Code, den kein Suchmuster erkennt.",
    reads="Prüfsummen der Theme-Dateien (Dateien werden nicht übertragen). Pro Theme wird ein Paket (höchstens 12 MB) bei downloads.wordpress.org abgerufen (https, einzeln nacheinander, nur für deine installierten Themes, höchstens die eingestellte Anzahl).",
    load="mittel", presets=["hack"], cms="wordpress",
    options=[Option("max", "Höchstens so viele Themes prüfen", "int", 10, "Jedes Paket wird einzeln geladen, das dauert einige Sekunden.")],
)
def wp_theme_integrity(ctx, res):
    if os.environ.get("CLAUDIA_OFFLINE"):
        raise CheckSkipped("Offline-Modus (CLAUDIA_OFFLINE): Die Theme-Pakete werden nicht abgerufen.")
    data = get_wp_fs(ctx)
    themes = [t for t in data["themes"] if t.get("version")]
    if not themes:
        raise CheckSkipped("Keine Themes mit Versionsangabe gefunden.")
    ctx.progress("Prüfsummen der Theme-Dateien berechnen")
    local = extsums.parse_local_themes(ctx.sh(THEME_SUMS_SCRIPT, timeout=600).out)
    limit = max(1, ctx.opt_int("max", 10))
    bad_changed, bad_extra, bad_missing, no_ref, err, ok = [], [], [], [], [], []
    for i, th in enumerate(themes):
        if i >= limit:
            err.append("%d weitere Themes wegen der Höchstzahl nicht geprüft" % (len(themes) - limit))
            break
        slug = th["slug"]
        label = "%s %s" % (clean_line(th.get("name", slug)), th["version"])
        if slug not in local or not re.match(r"^[A-Za-z0-9._-]{1,80}\Z", slug) or not re.match(r"^[A-Za-z0-9._+-]{1,40}\Z", th["version"]):
            continue
        ctx.progress("Prüfe Theme %s" % slug[:40])
        try:
            raw = coreref.fetch_bytes(extsums.theme_url(slug, th["version"]), extsums.MAX_ZIP_BYTES // 2, timeout=30)
        except coreref.RefError as e:
            msg = str(e)
            (no_ref if "HTTP 404" in msg else err).append(label if "HTTP 404" in msg else "%s (Abruf nicht möglich)" % label)
            continue
        try:
            ref = extsums.theme_reference(raw, slug)
        except extsums.ZipProblem as e:
            err.append("%s (%s)" % (label, e))
            continue
        if not ref:
            no_ref.append(label)
            continue
        d = wpsums.compare(local[slug], ref)
        code_changed = [x for x in d["changed"] if THEME_CODE_RE.search(x)]
        bad_changed += ["%s: %s" % (slug, x) for x in code_changed]
        bad_extra += ["%s: %s" % (slug, x) for x in d["extra"]]
        bad_missing += ["%s: %s" % (slug, x) for x in d["missing"]]
        if not (code_changed or d["extra"] or d["missing"]):
            ok.append(label)
    if bad_changed:
        res.add("crit", "%d Theme-Datei(en) weichen vom Original ab" % len(bad_changed),
                "Der Inhalt unterscheidet sich vom offiziellen Theme in genau dieser Version. Entweder wurde die Datei manipuliert, oder jemand hat das Theme von Hand geändert (bei eigenen Anpassungen nutze ein Kindtheme).",
                bad_changed[:60], "Theme neu installieren (Dashboard -> Design -> Themes; Einstellungen liegen in der Datenbank). Eigene Änderungen vorher sichern.")
    if bad_extra:
        res.add("warn", "%d zusätzliche PHP-Datei(en) in Theme-Ordnern" % len(bad_extra),
                "Diese Dateien gehören nicht zum offiziellen Theme. Ein Versteck für Hintertüren ist möglich.", bad_extra[:60], "Dateien ansehen (nicht ausführen). Ohne bekannte Herkunft löschen.")
    if bad_missing:
        res.add("info", "%d PHP-Datei(en) des Originals fehlen" % len(bad_missing), "Oft ein abgebrochenes Update oder ein Hoster-Virenscanner, der Dateien entfernt hat.", bad_missing[:40])
    if no_ref:
        res.add("info", "%d Theme(s) nicht im offiziellen Verzeichnis oder Version nicht mehr vorhanden (nicht prüfbar)" % len(no_ref),
                "Premium-, Kind- oder selbst entwickelte Themes sowie aus dem Verzeichnis entfernte Versionen. Für sie gilt dieser Test nicht; die Suche nach Mustern prüft sie trotzdem.", no_ref[:60])
    if err:
        res.add("info", "Nicht alles konnte geprüft werden", "", err[:20])
    if ok and not (bad_changed or bad_extra):
        res.add("ok", "%d Theme(s) stimmen mit dem Original überein" % len(ok), "Vergleich mit den Paketen von downloads.wordpress.org.", ok[:60])


def parse_app_passwords(v: str) -> List[Dict[str, Any]]:
    """Serialisierte Anwendungs-Passwörter -> Name, angelegt, zuletzt benutzt, letzte IP. Der Hash ('password') wird nie gelesen."""
    out: List[Dict[str, Any]] = []
    for blk in re.split(r's:4:"uuid";', v or "")[1:]:
        name = re.search(r's:4:"name";s:\d+:"([^"]*)";', blk)
        created = re.search(r's:7:"created";i:(\d+);', blk)
        used = re.search(r's:9:"last_used";(?:i:(\d+)|N);', blk)
        ip = re.search(r's:7:"last_ip";(?:s:\d+:"([^"]*)"|N);', blk)
        out.append({"name": name.group(1) if name else "?", "created": int(created.group(1)) if created else 0,
                    "last_used": int(used.group(1)) if used and used.group(1) else 0, "ip": (ip.group(1) if ip and ip.group(1) else "")})
    return out


def _is_wp_admin(caps: str) -> bool:
    return '"administrator"' in (caps or "") or "administrator" in (caps or "") and "a:" in (caps or "")


def _idtag(uid) -> str:
    """Maschinenlesbare Marke am Zeilenende, damit Aktionen (Konto sperren, Anwendungs-Passwörter widerrufen) die Zeile zuordnen können."""
    return "  [ID %s]" % uid if digits(str(uid or "")) else ""


@check(
    "wp_db_users", "datenbank", "Benutzer und Administratoren",
    "Wer darf sich anmelden - und wurden neue Administratoren oder Anwendungs-Passwörter angelegt, die du nicht kennst?",
    what="Listet alle WordPress-Benutzer mit Rolle und Registrierungsdatum. Hebt Administratoren hervor, kürzlich angelegte Administrator-Konten, Konten mit dem Namen 'admin' und "
         "Anwendungs-Passwörter (Dauerzugänge für die Programmierschnittstelle, die ein Passwortwechsel nicht beendet). Zeigt, wann sich ein Administrator zuletzt angemeldet hat, soweit WordPress es in den Sitzungen speichert.",
    why="Ein typischer Schritt nach dem Einbruch: ein zusätzliches Administrator-Konto anlegen, um jederzeit zurückzukehren. Anwendungs-Passwörter umgehen die Zwei-Faktor-Anmeldung.",
    reads="Benutzername, E-Mail, Rolle und Datum aus den Benutzertabellen. Passwort-Hashes werden NICHT gelesen.",
    load="leicht", needs="db", presets=["hack"], cms="wordpress",
    options=[Option("days", "Als 'neu' zählen: letzte ... Tage", "int", 120, "Administrator-Konten, die in diesem Zeitraum angelegt wurden, werden markiert.")],
)
def wp_db_users(ctx, res):
    db = need_db(ctx, res, "Benutzer und Administratoren", Q_WP_USERS)
    days = ctx.opt_int("days", 120)
    users = fetch(db, Q_WP_USERS[0][1]) or []
    adm, newadm, adm_named = [], [], []
    for u in users:
        if not _is_wp_admin(u.get("caps") or ""):
            continue
        line = "%s  (%s) - angelegt %s%s" % (clean_line(u.get("login") or "?"), clean_line(u.get("email") or "?"), fmt_date(u.get("registered")), _idtag(u.get("id")))
        adm.append(line)
        a = age_days(u.get("registered"))
        if a is not None and a <= days:
            newadm.append(line)
        if (u.get("login") or "").lower() == "admin":
            adm_named.append(line)
    res.add("info", "%d Administrator-Konto/Konten bei %d Benutzern" % (len(adm), len(users)),
            "Bitte prüfe jeden Eintrag: Kennst du den Benutzer? Jeder Administrator kann die ganze Seite übernehmen (auch PHP-Code über Plugins einschleusen).", adm)
    wp_ids = sorted({int(m.group(1)) for l in newadm + adm_named for m in [re.search(r"\[ID (\d+)\]", l)] if m})
    if wp_ids:
        add_manual_sql(ctx, db, "Auffällige Administrator-Konten", [("Konten ansehen (Passwort-Hashes nicht weitergeben)", "SELECT ID, user_login, user_email, user_registered FROM #__users WHERE ID IN (%s)" % ",".join(map(str, wp_ids)))])
    if newadm:
        res.add("warn", "%d Administrator-Konto/Konten in den letzten %d Tagen angelegt" % (len(newadm), days),
                "Nach einem Hack ein typisches Zeichen. Wenn du das Konto nicht selbst angelegt hast: löschen und alle Passwörter ändern.", newadm,
                "Dashboard -> Benutzer: Konto löschen, danach alle Passwörter und die Schlüssel in der wp-config.php erneuern.")
    if adm_named:
        res.add("info", "Ein Administrator heißt 'admin'", "Dieser Name wird von automatischen Anmeldeversuchen zuerst probiert.", adm_named,
                "Ein neues Konto mit eigenem Namen anlegen, die Inhalte zuweisen und 'admin' löschen.")
    rest = [u for u in users if not _is_wp_admin(u.get("caps") or "") and (age_days(u.get("registered")) or 9999) <= 30]
    if len(rest) >= 20:
        res.add("info", "%d normale Konten in den letzten 30 Tagen registriert" % len(rest), "Bei offener Registrierung sind Spam-Konten üblich.",
                ["%s (%s)" % (clean_line(u.get("login") or ""), fmt_date(u.get("registered"))) for u in rest[:20]])
    meta = fetch(db, Q_WP_USERS[1][1]) or []
    by_id = {u.get("id"): u for u in users}
    apw, apw_users, last_login = [], 0, {}
    for m in meta:
        uid = m.get("user_id")
        if m.get("meta_key") == "_application_passwords":
            entries = parse_app_passwords(m.get("v") or "")
            n = len(entries) or 1
            apw_users += 1
            u = by_id.get(uid) or {}
            apw.append("%s: %d Anwendungs-Passwort/-Passwörter%s%s" % (clean_line(u.get("login") or "Benutzer-ID %s" % uid), n, "  [Administrator]" if _is_wp_admin(u.get("caps") or "") else "", _idtag(uid)))
            for e in entries[:10]:
                apw.append("    Name '%s', angelegt %s, zuletzt benutzt %s%s" % (
                    trunc(clean_line(e["name"]), 60), time.strftime("%Y-%m-%d", time.localtime(e["created"])) if e["created"] else "?",
                    time.strftime("%Y-%m-%d", time.localtime(e["last_used"])) if e["last_used"] else "nie",
                    (" von " + ctx.mask(e["ip"])) if e["ip"] else ""))
        elif m.get("meta_key") == "session_tokens":
            ts = [int(x) for x in re.findall(r's:5:"login";i:(\d+);', m.get("v") or "")]
            if ts:
                last_login[uid] = max(ts)
    if apw:
        res.add("warn", "%d Benutzer mit Anwendungs-Passwörtern" % apw_users,
                "Ein Anwendungs-Passwort erlaubt Zugriff auf die Programmierschnittstelle ohne normales Passwort und ohne Zwei-Faktor-Anmeldung. Ein Passwortwechsel beendet es nicht.", apw,
                "Unter Benutzer -> Profil -> Anwendungs-Passwörter prüfen und unbekannte widerrufen.")
    shown = []
    for uid, t in sorted(last_login.items(), key=lambda kv: -kv[1])[:10]:
        u = by_id.get(uid) or {}
        if _is_wp_admin(u.get("caps") or ""):
            shown.append("%s: letzte gespeicherte Anmeldung %s" % (clean_line(u.get("login") or uid), time.strftime("%Y-%m-%d %H:%M", time.localtime(t))))
    if shown:
        res.add("info", "Zuletzt angemeldete Administratoren (laut gespeicherten Sitzungen)", "Passt das zu deinen eigenen Anmeldungen? Ein fremder Zeitpunkt deutet auf Fremdzugriff hin.", shown)
    if not (newadm or apw):
        res.add("ok", "Keine neu angelegten Administratoren, keine Anwendungs-Passwörter")


Q_WP_OPT = ("SELECT option_name AS name, SUBSTRING(option_value, 1, 3000) AS v FROM #__options WHERE option_name IN "
            "('siteurl','home','admin_email','users_can_register','default_role','active_plugins','template','stylesheet','permalink_structure')")
Q_WP_OPT_SCAN = ("SELECT option_name AS name, SUBSTRING(option_value, LOCATE('<', option_value), 300) AS v FROM #__options WHERE option_name <> 'cron' AND "
                 "(option_name LIKE 'widget%' OR option_name LIKE 'sidebars%' OR option_name LIKE 'theme_mods%') AND (option_value LIKE '%<script%' OR option_value LIKE '%<iframe%' OR option_value LIKE '%eval(%' OR option_value LIKE '%base64_decode%') LIMIT 60")


@check(
    "wp_db_options", "datenbank", "Einstellungen: Webadresse, Registrierung, aktive Plugins, Widgets",
    "Stimmen die wichtigsten Einstellungen in der Datenbank - und passt die Liste der aktiven Plugins zu den Dateien?",
    what="Liest die Optionen siteurl, home, users_can_register, default_role und active_plugins. Prüft, ob die Webadresse auf eine fremde Domain zeigt, ob sich jeder als Administrator registrieren kann, "
         "ob aktive Plugins fehlende oder ungewöhnliche Pfade haben, und durchsucht Widgets und Theme-Einstellungen nach Skripten und Frames.",
    why="Angreifer ändern gern die Webadresse (Umleitung aller Besucher), schalten die Registrierung mit Administrator-Rolle ein oder tragen ein Plugin ein, das nicht in der Plugin-Liste auftaucht.",
    reads="Wenige gezielte Einstellungen aus der Tabelle options (kurze Ausschnitte).",
    load="leicht", needs="db", presets=["hack"], cms="wordpress",
)
def wp_db_options(ctx, res):
    db = need_db(ctx, res, "Einstellungen in der Datenbank", [("Wichtige Optionen", Q_WP_OPT), ("Widgets", Q_WP_OPT_SCAN)])
    rows = fetch(db, Q_WP_OPT) or []
    o = {r.get("name"): (r.get("v") or "") for r in rows}
    own = ctx.own_host()
    hosts = {}
    for k in ("siteurl", "home"):
        h = (urlparse(o.get(k, "")).hostname or "").lower()
        hosts[k] = h
    res.add("info", "Webadresse und Grundeinstellungen", "", ["siteurl: %s" % clean_line(o.get("siteurl", "?")), "home: %s" % clean_line(o.get("home", "?")),
                                                              "Rolle neuer Benutzer: %s" % o.get("default_role", "?"), "Offene Registrierung: %s" % ("ja" if o.get("users_can_register") == "1" else "nein"),
                                                              "Aktives Theme: %s" % o.get("stylesheet", o.get("template", "?"))])
    for k, h in hosts.items():
        if h and own and h.replace("www.", "") != own.replace("www.", ""):
            res.add("crit", "%s zeigt auf eine andere Domain (%s)" % (k, h),
                    "Besucher oder die Seite selbst würden zu dieser Adresse geleitet. Das ist ein typisches Merkmal einer Übernahme (kann aber auch ein bewusster Umzug sein).",
                    hint="Dashboard -> Einstellungen -> Allgemein: Adresse prüfen.")
    if hosts.get("siteurl") and hosts.get("home") and hosts["siteurl"].replace("www.", "") != hosts["home"].replace("www.", ""):
        res.add("warn", "siteurl und home haben verschiedene Domains", "Das ist ungewöhnlich und kann auf eine Manipulation hinweisen.")
    if o.get("users_can_register") == "1":
        if o.get("default_role") == "administrator":
            res.add("crit", "Jeder darf sich als Administrator registrieren", "Offene Registrierung mit der Rolle 'administrator' gibt jedem Besucher die volle Kontrolle.",
                    hint="Einstellungen -> Allgemein: 'Jeder kann sich registrieren' ausschalten und die Standardrolle auf 'Abonnent' stellen.")
        elif o.get("default_role") not in ("subscriber", "customer", ""):
            res.add("warn", "Offene Registrierung mit der Rolle '%s'" % o.get("default_role"), "Neue Benutzer bekommen mehr als Leserechte.", hint="Standardrolle auf 'Abonnent' stellen.")
        else:
            res.add("info", "Die Registrierung ist offen", "Spam-Konten sind üblich. Aktiviere bei Bedarf eine Freigabe oder ein Anti-Spam-Plugin.")
    active = re.findall(r's:\d+:"([^"]+)";', o.get("active_plugins", ""))
    fs = get_wp_fs(ctx)
    present = {p["slug"] for p in fs["plugins"]} | {s["path"].split("/")[-1] for s in fs["singles"]}
    weird = [a for a in active if ".." in a or a.startswith("/") or not re.match(r"^[\w\-./]+\.php\Z", a)]
    nohead_dirs = {n["path"].rstrip("/").split("/")[-1] for n in fs["nohead"] if n["kind"] == "plugin"}
    hidden_active = [a for a in active if a not in weird and a.split("/")[0] in nohead_dirs]
    gone = [a for a in active if a not in weird and a not in hidden_active and a.split("/")[0] not in present and a not in present]
    if hidden_active:
        res.add("crit", "%d aktive(s) Plugin(s) ohne Plugin-Beschreibung" % len(hidden_active),
                "Der Ordner hat keinen Plugin-Kopf, ist aber in der Datenbank als aktiv eingetragen - so lädt WordPress Code, der im Dashboard nicht als Plugin erscheint.",
                [clean_line(a) for a in hidden_active], "Datei ansehen, Eintrag entfernen und Ordner löschen, wenn du ihn nicht kennst.")
    if weird:
        res.add("crit", "%d aktive(s) Plugin(s) mit ungewöhnlichem Pfad" % len(weird), "Ein Pfad mit '..' oder außerhalb des Plugin-Ordners lädt Code von anderswo.", [clean_line(a) for a in weird])
    if gone:
        res.add("warn", "%d aktive(s) Plugin(s) haben keine Dateien mehr" % len(gone),
                "Die Datenbank listet das Plugin als aktiv, im Ordner fehlt es. Meist ein Rest nach dem Löschen - kann aber ein Hinweis auf entfernten Schadcode sein.", [clean_line(a) for a in gone],
                "Im Dashboard unter Plugins prüfen und den Eintrag bereinigen.")
    if active:
        ctx.shared["wp_active_plugins"] = active
    scan = fetch(db, Q_WP_OPT_SCAN) or []
    allow = ctx.allow()
    bad = []
    for r in scan:
        snip = r.get("v") or ""
        hs = [h for h in extract_hosts(snip) if h != own and not host_allowed(h, allow)]
        if re.search(r"eval *\(|base64_decode|fromCharCode", snip) or hs:
            bad.append("%s: %s" % (clean_line(r.get("name") or ""), trunc(clean_line(snip), 180)))
    bad_names = [str(r.get("name")) for r in scan if re.fullmatch(r"[A-Za-z0-9_\-]{1,191}", str(r.get("name") or "")) and (re.search(r"eval *\(|base64_decode|fromCharCode", r.get("v") or "")
                 or [h for h in extract_hosts(r.get("v") or "") if h != own and not host_allowed(h, allow)])]
    if bad_names:
        add_manual_sql(ctx, db, "Widget-/Theme-Einstellungen mit Skripten", [("Einstellungen ansehen/sichern", "SELECT option_id, option_name, option_value FROM #__options WHERE option_name IN (%s)" % ",".join("'%s'" % n for n in bad_names[:30]))])
    if bad:
        res.add("warn", "%d Widget-/Theme-Einstellung(en) mit Skripten oder unbekannten Adressen" % len(bad), "Skripte in Widgets werden auf jeder Seite ausgeliefert.", bad[:30],
                "Dashboard -> Design -> Widgets bzw. Customizer prüfen und unbekannte Einbindungen entfernen.")
    if not (bad or weird or gone) and not any(f.sev in ("crit", "warn") for f in res.findings):
        res.add("ok", "Einstellungen unauffällig")


WP_INJ_TARGETS = [("posts", "ID", "post_title", "post_content"), ("posts", "ID", "post_title", "post_excerpt"), ("options", "option_id", "option_name", "option_value"),
                  ("postmeta", "meta_id", "meta_key", "meta_value"), ("comments", "comment_ID", "comment_author", "comment_content"), ("links", "link_id", "link_name", "link_url")]
Q_WP_INJ = [("%s.%s" % (t, c), _inj_query(t, i, ti, c)) for t, i, ti, c in WP_INJ_TARGETS]


@check(
    "wp_db_content", "datenbank", "Eingeschleuster Code in Beiträgen, Optionen und Kommentaren",
    "Stehen in der Datenbank Skripte, versteckte Frames oder verschleierter Code?",
    what="Sucht in Beiträgen und Seiten, Auszügen, Optionen, Beitrags-Metadaten, Kommentaren und Links nach <script>, <iframe>, eval(, fromCharCode, document.write und atob(. "
         "Die gefundenen Internetadressen werden mit deiner Liste bekannter Dienste verglichen. Tag-Manager-/Analytics-IDs werden aufgelistet.",
    why="Schadcode muss nicht in Dateien stehen: Ein Skript in einem Beitrag oder in einer Option wird auf der Seite ausgeliefert. Gerade bei WordPress ist die Tabelle options ein beliebtes Versteck, "
        "weil dort die Einstellungen aller Plugins liegen.",
    reads="Ausschnitte (300 Zeichen) der Stellen, an denen die Muster vorkommen - nicht ganze Inhalte.",
    load="mittel", needs="db", presets=["hack"], cms="wordpress",
)
def wp_db_content(ctx, res):
    db = need_db(ctx, res, "Eingeschleuster Code in der Datenbank", Q_WP_INJ)
    inject_scan(ctx, res, db, Q_WP_INJ, ("Beitrag bzw. Einstellung im Dashboard öffnen und den Code entfernen (vorher Kopie sichern). Danach prüfen, wie er hineinkam.", ("posts", "comments")))


@check(
    "wp_db_incidents", "dbbereich", "Aktuelle Sicherheitslage: aktive Plugins",
    "Sind aktive Plugins von bekannten Lücken betroffen, die die Datenbank gefährden (SQL-Injection, Rechteausweitung)?",
    what="Liest die Liste der aktiven Plugins aus der Datenbank und gleicht sie mit der Liste bekannter schwerer Lücken ab. Treffer, die SQL-Injection betreffen, werden hervorgehoben.",
    why="Eine SQL-Injection erlaubt das Auslesen und Ändern der gesamten Datenbank - auch der Passwort-Hashes. Bei aktiven Plugins ist das Risiko höher als bei ausgeschalteten.",
    reads="Nur die Option active_plugins und die Plugin-Köpfe.",
    load="leicht", needs="db", presets=[], cms="wordpress",
)
def wp_db_incidents(ctx, res):
    db = need_db(ctx, res, "Aktive Plugins", [("Aktive Plugins", "SELECT option_value AS v FROM #__options WHERE option_name = 'active_plugins'")])
    rows = fetch(db, "SELECT option_value AS v FROM #__options WHERE option_name = 'active_plugins'") or []
    active = {a.split("/")[0] for a in re.findall(r's:\d+:"([^"]+)";', rows[0].get("v") or "")} if rows else set()
    fs = get_wp_fs(ctx)
    items = [p for p in fs["plugins"] if p["slug"] in active]
    hits = _advisory_hits(ctx.adv.get("wp_plugins", []), items, "plugin")
    for a, it in hits:
        res.add("crit" if a.get("sqli") or a["severity"] == "crit" else "warn", "%s %s ist aktiv und von %s betroffen" % (a["title"], it.get("version", "?"), a["cve"]),
                a["note"], ["Behoben in %s" % a["fixed_in"]] + (["Betrifft die Datenbank (SQL-Injection)"] if a.get("sqli") else []),
                "Plugin aktualisieren, danach Administratoren und Passwörter prüfen." + (" Das Datenbank-Passwort erneuern." if a.get("sqli") else ""))
    if not hits:
        res.add("ok", "Keines der %d aktiven Plugins ist in der eingebauten Liste verzeichnet" % len(items), "Die Liste ist nur eine Auswahl. Die Online-Prüfung nennt die aktuelle Lage.")


# ============================================================================ Protokolle & Webseite
@check(
    "wp_logs", "logs", "WordPress- und PHP-Fehlerprotokolle",
    "Gibt es ein debug.log oder error_log - und was steht darin?",
    what="Sucht wp-content/debug.log und PHP-Fehlerprotokolle (error_log) in der Seite und wertet die letzten Zeilen aus: Anzahl schwerer Fehler (Fatal), betroffene Plugins, Datenbank-Fehler.",
    why="Fehlerprotokolle zeigen kaputte oder angegriffene Plugins. Eine große debug.log verrät außerdem Pfade und kann (bei falscher Rechtevergabe) von außen lesbar sein.",
    reads="Die letzten 2.000 Zeilen jedes Protokolls, ausgewertet auf dem Server; es wird nur zusammengefasst, nicht der Inhalt kopiert.",
    load="leicht", presets=["hack"], cms="wordpress",
)
def wp_logs(ctx, res):
    out = ctx.sh(r"""
echo '@@FILES'
find . \( -path ./node_modules -o -path ./wp-content/cache \) -prune -o -type f \( -name debug.log -o -name error_log -o -name php_errorlog -o -name php_errors.log \) -printf '%s\t%TY-%Tm-%Td\t%p\n' 2>/dev/null | head -40
echo '@@FATAL'
for f in wp-content/debug.log; do [ -f "$f" ] && tail -n 2000 "$f" | grep -E 'PHP Fatal|Uncaught|PHP Parse' | grep -oE 'wp-content/(plugins|themes)/[^/]+' | sort | uniq -c | sort -rn | head -10; done
echo '@@DBERR'
[ -f wp-content/debug.log ] && tail -n 2000 wp-content/debug.log | grep -ciE 'WordPress database error'
""", timeout=60, raw="treffer").out
    sec = split_sections(out)
    files = []
    for ln in lines_of(sec.get("FILES", "")):
        p = ln.split("\t")
        if len(p) >= 3:
            files.append((int(p[0] or 0), p[1], p[2]))
    if not files:
        res.add("ok", "Keine Fehlerprotokolle (debug.log, error_log) in der Seite gefunden")
        return
    big = [f for f in files if f[0] > 50 * 1024 * 1024]
    res.add("info", "%d Fehlerprotokoll(e) gefunden" % len(files), "Fehlerprotokolle von Plugins und PHP.", ["%s  (%.1f MB, zuletzt %s)" % (clean_line(p), s / 1048576.0, d) for s, d, p in files[:20]])
    if big:
        res.add("warn", "%d sehr große Protokolldatei(en)" % len(big), "Über 50 MB. Sie verbrauchen Platz und deuten auf wiederholte Fehler hin.", [clean_line(p) for _, _, p in big], "Ansehen, Ursache beheben, Datei löschen.")
    fatal = lines_of(sec.get("FATAL", ""))
    if fatal:
        res.add("warn", "Schwere PHP-Fehler in debug.log (letzte 2000 Zeilen)", "Die Zahl steht vor dem Plugin bzw. Theme. Ein ständig abstürzendes Plugin ist veraltet oder defekt.", [clean_line(x) for x in fatal])
    dberr = lines_of(sec.get("DBERR", ""))
    if dberr and digits(dberr[0]) and int(dberr[0]) > 0:
        res.add("warn", "%s Datenbank-Fehler in debug.log" % dberr[0], "Wiederholte Datenbank-Fehler können durch ein defektes Plugin oder durch Einschleusversuche (SQL-Injection) entstehen.")


@check(
    "wp_exposure", "logs", "Öffentlich abrufbare Dateien und Schnittstellen",
    "Kann jeder Besucher debug.log, Sicherungen, die Benutzerliste oder xmlrpc.php abrufen?",
    what="Ruft von DIESEM PC aus einige Adressen deiner Seite ab: wp-content/debug.log, wp-config-Sicherungen, .git, Ordnerlisten von uploads und plugins, die Benutzerliste der REST-Schnittstelle (/wp-json/wp/v2/users), "
         "?author=1 (Benutzernamen erraten) und xmlrpc.php. Es werden nur normale Seitenaufrufe gesendet.",
    why="Schon die Namen der Benutzer erleichtern Angriffe auf Passwörter. Ein abrufbares debug.log verrät Pfade und Fehler, eine abrufbare wp-config-Sicherung verrät das Datenbank-Passwort. "
        "xmlrpc.php wird für massenhafte Passwort-Versuche missbraucht.",
    reads="Öffentlich erreichbare Adressen deiner Domain, so wie jeder Besucher sie sieht. Es wird nichts verändert.",
    load="leicht", needs="web", presets=["schnell", "hack"], cms="wordpress",
)
def wp_exposure(ctx, res):
    url = (ctx.s.url or "").strip()
    if not url:
        raise CheckSkipped("Keine Adresse der Webseite angegeben (Feld 'Webseite' in den Verbindungsdaten).")
    from .. import secure
    url, _ = secure.to_https(url)
    base = url.rstrip("/")
    crit, warn, info = [], [], []
    def get(path, **kw):
        ctx.progress("Rufe %s ab" % path)
        return webmod.fetch(base + path, webmod.UA_BROWSER, max_bytes=kw.get("max", 20000), timeout=15)
    for path, label in (("/wp-content/debug.log", "debug.log"), ("/wp-config.php.bak", "wp-config.php.bak"), ("/wp-config.php.old", "wp-config.php.old"),
                        ("/wp-config.php~", "wp-config.php~"), ("/wp-config.txt", "wp-config.txt"), ("/.git/HEAD", ".git"), ("/.env", ".env"), ("/wp-content/backup-db/", "backup-db")):
        f = get(path)
        if f.error:
            continue
        if f.status == 200 and f.body.strip():
            if "wp-config" in path and "DB_" not in f.body:
                continue
            if path == "/.git/HEAD" and "ref:" not in f.body:
                continue
            if path == "/.env" and "=" not in f.body:
                continue
            (crit if ("wp-config" in path or path in ("/.env", "/.git/HEAD")) else warn).append("%s%s ist abrufbar (HTTP 200)" % (base, path))
    for path in ("/wp-content/uploads/", "/wp-content/plugins/", "/wp-includes/"):
        f = get(path)
        if not f.error and f.status == 200 and re.search(r"<title>Index of|Parent Directory", f.body):
            warn.append("Ordnerliste ist öffentlich: %s%s" % (base, path))
    f = get("/wp-json/wp/v2/users", max=60000)
    if not f.error and f.status == 200:
        try:
            users = [u.get("slug") for u in json.loads(f.body) if isinstance(u, dict)]
        except ValueError:
            users = []
        if users:
            warn.append("Die REST-Schnittstelle nennt Benutzernamen ohne Anmeldung: %s" % ", ".join(users[:6]))
    f = get("/?author=1")
    if not f.error and (f.chain or f.final) and re.search(r"/author/[^/]+", f.final or ""):
        info.append("?author=1 leitet auf %s weiter und verrät damit einen Benutzernamen" % (f.final or ""))
    f = get("/xmlrpc.php")
    if not f.error and f.status in (200, 405) and "XML-RPC server accepts POST" in f.body:
        info.append("xmlrpc.php ist aktiv. Wird für Massenversuche an Passwörtern missbraucht und ist nur bei Nutzung der WordPress-App oder von Jetpack nötig.")
    f = get("/readme.html")
    if not f.error and f.status == 200 and re.search(r"Version\s+\d", f.body):
        info.append("readme.html nennt die WordPress-Version (hilft Angreifern bei der Auswahl)")
    if crit:
        res.add("crit", "%d öffentlich abrufbare Datei(en) mit sensiblen Inhalten" % len(crit), "Jeder Besucher kann diese Dateien herunterladen.", crit,
                "Datei sofort löschen bzw. per .htaccess sperren; danach Datenbank-Passwort erneuern, wenn dort Zugangsdaten standen.")
    if warn:
        res.add("warn", "%d Datei(en)/Schnittstelle(n) geben Informationen preis" % len(warn), "", warn, "Sperren (z. B. per .htaccess) bzw. Benutzer-Schnittstelle einschränken.")
    if info:
        res.add("info", "%d Hinweis(e) zur Absicherung" % len(info), "", info)
    if not (crit or warn or info):
        res.add("ok", "Alle geprüften Adressen sind gesperrt oder nicht vorhanden")
