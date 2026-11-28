"""Konfiguration & Zugriffsregeln: .htaccess, PHP-Einstellungen, configuration.php, Einstiegsdateien."""
from __future__ import annotations

import re
import time
from typing import Dict, List, Tuple

from ..registry import check
from ..util import clean_line, extract_hosts, host_allowed, lines_of, split_sections, trunc

G = "konfig"
UPLOAD_DIRS = ("images", "media", "tmp", "cache", "files", "logs")


# ----------------------------------------------------------------------------- .htaccess
HT_PATTERN = (r"auto_(prepend|append)_file|php_(admin_)?(value|flag)|AddHandler|SetHandler|AddType|ExecCGI|"
              r"RewriteCond +%\{HTTP_(USER_AGENT|REFERER)\}|RewriteRule .*https?://|ErrorDocument +[0-9]+ +https?://|"
              r"base64|eval|<\?php|Redirect(Match)? .*https?://|Header +(set|add|always)|SecRule|allow_url_include")


def _classify_ht(line: str, path: str, own: str, allow: List[str], file_noexec: bool = False) -> Tuple[str, str]:
    """Bewertet eine einzelne .htaccess-Zeile. Rückgabe (Schweregrad, Begründung)."""
    low = line.lower()
    top = path.lstrip("./").split("/")[0]
    in_upload = top in UPLOAD_DIRS
    if re.search(r"auto_(prepend|append)_file", low):
        val = re.split(r"auto_(?:prepend|append)_file", low, maxsplit=1)[1].strip()
        if val in ("", "none", "\"\"", "''", "0") or val.endswith(("none", "\"\"", "'' ")):
            return "info", "Leere auto_prepend/append-Einstellung"
        return "crit", "Fremder Code wird vor/nach JEDER PHP-Seite geladen (auto_prepend_file) - klassischer Hack-Trick"
    if re.search(r"allow_url_include", low):
        return "crit", "Erlaubt das Nachladen von Code aus dem Internet"
    stripped = low.strip()
    if re.search(r"^options\b.*-execcgi", stripped):
        return "info", "Schaltet die CGI-/Skript-Ausführung ab (Schutzregel)"
    if re.match(r"rewritecond\s+%\{(query_string|request_uri|http_user_agent|the_request)\}", stripped) and re.search(r"base64|\beval\b|<\?php|<script", low):
        return "info", "Schutzregel: blockiert Anfragen mit base64/eval/Skript-Code (steht auch in Joomlas Standard-.htaccess)"
    if re.search(r"base64|\beval\b|<\?php", low):
        return "crit", "Code in einer .htaccess ist nie normal"
    if re.search(r"addhandler|sethandler|addtype|execcgi", low):
        exts = re.findall(r"\.([a-z0-9]+)", low)
        odd = [e for e in exts if e not in ("php", "phtml", "php5", "php7", "php8", "pht", "phps", "inc")]
        if re.search(r"x-httpd-php|application/x-php|proxy:fcgi|php-fpm|execcgi|cgi-script|application/x-httpd", low):
            if file_noexec and "cgi-script" in low:
                return "info", "Skript-Endungen werden einem Handler zugewiesen, die Ausführung ist aber in derselben Datei per 'Options -ExecCGI' abgeschaltet (Schutz gegen PHP in Cache-Ordnern)"
            if odd:
                return "crit", "PHP-Ausführung für harmlose Endungen (%s) - Tarnung für Web-Shells" % ", ".join("." + e for e in odd[:4])
            if in_upload:
                return "crit", "PHP-Ausführung in einem Upload-/Temp-Ordner"
            return "info", "PHP-Handler (bei vielen Hostern normal)"
        return "info", "Handler-/Typ-Zuweisung"
    if re.search(r"rewritecond +%\{http_(user_agent|referer)\}", low):
        if "%{http_host}" in low or "!" in low.split("}", 1)[-1][:6]:
            return "info", "Referer-/Browser-Bedingung (vermutlich Hotlink-Schutz)"
        if re.search(r"google|bing|yahoo|yandex|baidu|bot|crawl|spider|slurp|duckduck|android|iphone|mobile|msie", low):
            return "warn", "Regel, die nur für Suchmaschinen/Handys/Besucher von Google gilt - typisch für Cloaking und SEO-Spam-Weiterleitungen"
        return "info", "Referer-/Browser-Bedingung"
    if re.search(r"rewriterule .*https?://", low):
        if re.search(r"%\{http_host\}|%\{server_name\}|%\{http:|%1|\$1://", low):
            return "info", "Weiterleitung auf die eigene Domain (z. B. HTTPS/www)"
        hosts = extract_hosts(line)
        if own and any(h == own or h.endswith("." + own) or own.endswith("." + h) for h in hosts):
            return "info", "Weiterleitung auf die eigene Domain"
        return "warn", "Weiterleitung auf eine fremde Domain (%s)" % ", ".join(hosts[:3])
    if re.search(r"errordocument +[0-9]+ +https?://", low):
        return "warn", "Fehlerseite wird auf eine fremde Adresse umgeleitet"
    if re.search(r"redirect(match)? .*https?://", low):
        hosts = extract_hosts(line)
        if hosts and all(host_allowed(h, allow) or h == own for h in hosts):
            return "info", "Weiterleitung auf eine bekannte Domain"
        return "warn", "Weiterleitung auf eine fremde Domain (%s)" % ", ".join(hosts[:3])
    if re.search(r"php_(admin_)?(value|flag)", low):
        if re.search(r"disable_functions|open_basedir|display_errors\s+on|error_reporting", low):
            return "warn", "Änderung an Sicherheits-/Fehler-Einstellungen von PHP"
        return "info", "PHP-Einstellung"
    return "info", "Sicherheits-/Header-Regel"


# Blöcke, die Plugins/Programme in die .htaccess schreiben: "# BEGIN Name" ... "# END Name" (Kennung -> Anzeigename)
HT_BLOCKS = [
    (r"^wordfence( waf| code execution protection)?$|^wordfence", "Wordfence"),
    (r"^ithemes security|^solid security|^better wp security", "Solid Security (iThemes Security)"),
    (r"^(all in one wp security|aiowps)", "All In One WP Security"),
    (r"^sucuri", "Sucuri Security"),
    (r"^bulletproof", "BulletProof Security"),
    (r"^admin tools", "Admin Tools (Akeeba)"),
    (r"^wordpress$", "WordPress (Kern: Permalinks)"),
    (r"^litespeed|^w3 total cache|^wp super cache|^wp rocket|^supercache|^wpsupercache|^w3tc", "Cache-Plugin"),
    (r"^wps hide login", "WPS Hide Login"),
]
HT_MARK_RE = re.compile(r"^\s*#\s*(BEGIN|END)\s+(.+?)\s*\Z", re.IGNORECASE)


def _ht_block_name(name: str) -> str:
    """Bekannter Anzeigename eines Blocks oder '' (unbekannt)."""
    low = name.strip().lower()
    for pat, label in HT_BLOCKS:
        if re.search(pat, low):
            return label
    return ""


def _ht_blocks(marks: List[Tuple[str, int, str, str]]) -> Dict[str, List[Tuple[int, int, str]]]:
    """Aus (Datei, Zeile, BEGIN|END, Name) je Datei die geschlossenen Blöcke (von, bis, Name) bilden. Offene Blöcke ohne END werden ignoriert."""
    out: Dict[str, List[Tuple[int, int, str]]] = {}
    open_: Dict[Tuple[str, str], int] = {}
    for path, no, kind, name in sorted(marks, key=lambda m: (m[0], m[1])):
        key = (path, name.lower())
        if kind == "BEGIN":
            open_[key] = no
        elif key in open_:
            out.setdefault(path, []).append((open_.pop(key), no, name))
    return out


@check(
    "htaccess", G, ".htaccess-Dateien auf Manipulation prüfen",
    "Enthalten die .htaccess-Dateien Weiterleitungen, Cloaking-Regeln oder Code, der nicht hineingehört?",
    what="Liest ALLE .htaccess-Dateien der Seite und markiert Zeilen mit auto_prepend_file, ungewöhnlichen Handlern (PHP in Bildern), "
         "Weiterleitungen auf fremde Domains, Regeln nur für Suchmaschinen/Mobilgeräte (Cloaking) und eingebettetem Code. "
         "Normale Regeln (HTTPS-Weiterleitung, Sperren für PHP in Upload-Ordnern) werden als harmlos eingestuft.",
    why="Die .htaccess ist ein Lieblingsziel: Eine Zeile reicht, um Besucher auf Spam-Seiten umzuleiten oder jede PHP-Seite mit fremdem Code zu "
        "versehen - ohne dass eine einzige Joomla-Datei verändert wird.",
    reads="Den Inhalt der .htaccess-Dateien. Nichts wird verändert.",
    load="leicht", presets=["schnell", "hack"],
)
def htaccess(ctx, res):
    script = r"""
echo '@@LIST'
find . -name .htaccess -not -path './node_modules/*' -printf 'L\t%TY-%Tm-%Td %TH:%TM\t%s\t%p\n' 2>/dev/null | head -300
echo '@@HITS'
find . -name .htaccess -not -path './node_modules/*' -print0 2>/dev/null | xargs -0 -r grep -nHiE -e '@PATTERN@' 2>/dev/null | cut -c1-300 | head -500
echo '@@MARK'
find . -name .htaccess -not -path './node_modules/*' -print0 2>/dev/null | xargs -0 -r grep -nHiE -e '^[[:space:]]*#[[:space:]]*(BEGIN|END)[[:space:]]' 2>/dev/null | cut -c1-200 | head -400
echo '@@NOW'; date +%s
""".replace("@PATTERN@", HT_PATTERN)
    out = ctx.sh(script, timeout=120, raw="treffer").out
    sec = split_sections(out)
    files = []
    for ln in sec.get("LIST", "").splitlines():
        p = ln.split("\t")
        if len(p) >= 4 and p[0] == "L":
            files.append((p[3], p[1], int(p[2] or 0)))
    own, allow = ctx.own_host(), ctx.allow()
    buckets: Dict[str, List[str]] = {"crit": [], "warn": [], "info": []}
    per_file: Dict[str, List[str]] = {}
    hits = []
    noexec_files = set()
    for ln in sec.get("HITS", "").splitlines():
        m = re.match(r"^(.*?):(\d+):(.*)\Z", ln)
        if not m:
            continue
        hits.append((m.group(1), m.group(2), m.group(3)))
        if re.match(r"^\s*options\b.*-execcgi", m.group(3), re.IGNORECASE):
            noexec_files.add(m.group(1))
    marks = []
    for ln in sec.get("MARK", "").splitlines():
        m = re.match(r"^(.*?):(\d+):(.*)\Z", ln)
        mm = HT_MARK_RE.match(m.group(3)) if m else None
        if m and mm:
            marks.append((m.group(1), int(m.group(2)), mm.group(1).upper(), mm.group(2)))
    blocks = _ht_blocks(marks)
    for path, no, line in hits:
        sev, why = _classify_ht(line, path, own, allow, path in noexec_files)
        inside = [b for b in blocks.get(path, []) if b[0] < int(no) < b[1]]
        if inside:
            label = _ht_block_name(inside[-1][2])
            why += "  [Block '%s' %s]" % (clean_line(inside[-1][2]), ("von " + label) if label else "unbekannter Herkunft")
        desc = "%s Zeile %s: %s  -> %s" % (clean_line(path), no, trunc(clean_line(line.strip()), 150), why)
        buckets[sev].append(desc)
        per_file.setdefault(path, []).append(sev)
    # Cloaking-Kombination: Bedingung + fremde Weiterleitung in derselben Datei
    combo = [f for f, sv in per_file.items() if sv.count("warn") >= 2]
    if buckets["crit"]:
        res.add("crit", "%d gefährliche Zeile(n) in .htaccess-Dateien" % len(buckets["crit"]),
                "Diese Regeln sind typisch für Manipulation und gehören nicht in eine normale Joomla-Installation.", buckets["crit"][:60],
                "Datei sichern, Zeile entfernen (bzw. durch die Joomla-Standarddatei htaccess.txt ersetzen) und die Einfallslücke schließen.")
    if buckets["warn"]:
        res.add("warn", "%d auffällige Zeile(n) in .htaccess-Dateien" % len(buckets["warn"]),
                "Kann legitim sein (z. B. Domain-Umzug), ist aber auch das Muster für SEO-Spam und Weiterleitungen.", buckets["warn"][:60],
                "Prüfen, ob du diese Regeln selbst oder dein Hoster/Plugin angelegt hat.")
    if combo:
        res.add("crit", "Cloaking-Verdacht in %d Datei(en)" % len(combo),
                "Bedingungen für Suchmaschinen/Besucher UND Weiterleitungen in derselben Datei: Du selbst siehst nichts, Google oder Besucher werden umgeleitet.",
                [clean_line(c) for c in combo], "Die Regeln genau lesen. Im Zweifel durch die Joomla-Standarddatei ersetzen.")
    recent = [f for f in files if _recent(f[1], 45)]
    res.add("info", "%d .htaccess-Datei(en) gefunden" % len(files),
            "Jüngst geänderte (letzte 45 Tage) sind mit * markiert.",
            ["%s%s  (%s, %d Byte)" % ("* " if f in recent else "", clean_line(f[0]), f[1], f[2]) for f in files][:80], context=True)
    known = [(p, b) for p, bl in blocks.items() for b in bl if _ht_block_name(b[2])]
    unknown = [(p, b) for p, bl in blocks.items() for b in bl if not _ht_block_name(b[2])]
    if known:
        res.add("info", "%d Regel-Block/Blöcke von bekannten Programmen" % len(known),
                "Plugins und Programme schreiben ihre Regeln zwischen '# BEGIN Name' und '# END Name'. Das ist normal. Der Inhalt wird trotzdem geprüft: "
                "Auch ein Angreifer kann seine Regeln in einen solchen Block schreiben, deshalb mildert ein Block-Name keine Bewertung.",
                ["%s Zeilen %d-%d: %s -> %s" % (clean_line(p), b[0], b[1], clean_line(b[2]), _ht_block_name(b[2])) for p, b in known][:40])
    if unknown:
        res.add("info", "%d Regel-Block/Blöcke unbekannter Herkunft" % len(unknown),
                "Diese Blöcke sind keinem bekannten Plugin zuzuordnen. Meist stammen sie von einem Hoster-Tool oder einer Erweiterung, die das Programm nicht kennt.",
                ["%s Zeilen %d-%d: %s" % (clean_line(p), b[0], b[1], clean_line(b[2])) for p, b in unknown][:40],
                "Prüfen, ob du das zugehörige Plugin/Programm kennst. Wenn nicht, den Inhalt des Blocks genau lesen.")
    if buckets["info"]:
        res.add("info", "%d harmlose/übliche Regel(n) erkannt" % len(buckets["info"]), "Zur Vollständigkeit.", buckets["info"][:25], context=True)
    if not (buckets["crit"] or buckets["warn"] or combo):
        res.add("ok", "Keine verdächtigen Regeln in den .htaccess-Dateien gefunden")


def _recent(date_str: str, days: int) -> bool:
    try:
        t = time.mktime(time.strptime(date_str[:10], "%Y-%m-%d"))
        return (time.time() - t) / 86400.0 <= days
    except ValueError:
        return False


# ----------------------------------------------------------------------------- PHP-Einstellungsdateien
@check(
    "php_ini", G, "PHP-Einstellungsdateien (.user.ini, php.ini)",
    "Lädt eine PHP-Einstellungsdatei Fremdcode vor jede Seite oder lockert Sicherheitseinstellungen?",
    what="Liest alle .user.ini- und php.ini-Dateien in der Seite und markiert auto_prepend_file/auto_append_file, allow_url_include, disable_functions und Fehleranzeige.",
    why="Mit auto_prepend_file in einer .user.ini kann ein Angreifer eine Datei vor jede PHP-Seite schalten - ohne eine Joomla-Datei zu ändern. "
        "Das ist schwerer zu entdecken als eine .htaccess-Zeile.",
    reads="Den Inhalt dieser kleinen Einstellungsdateien.",
    load="leicht", presets=["schnell", "hack"],
)
def php_ini(ctx, res):
    out = ctx.sh(r"""
find . \( -name '.user.ini' -o -name 'php.ini' -o -name '.php.ini' -o -name 'php5.ini' \) -not -path './node_modules/*' -not -path '*/vendor/*' -print0 2>/dev/null \
  | xargs -0 -r grep -nHvE '^[[:space:]]*(;|#|$)' 2>/dev/null | cut -c1-250 | head -300
""", timeout=60, raw="inhalt").out
    crit, warn, info = [], [], []
    seen_files = set()
    for ln in lines_of(out):
        m = re.match(r"^(.*?):(\d+):(.*)\Z", ln)
        if not m:
            continue
        path, no, line = m.group(1), m.group(2), m.group(3).strip()
        seen_files.add(path)
        low = line.lower().replace(" ", "")
        desc = "%s Zeile %s: %s" % (clean_line(path), no, trunc(clean_line(line), 160))
        if re.match(r"auto_(prepend|append)_file=", low):
            val = low.split("=", 1)[1].strip("\"'")
            if val and val != "none":
                crit.append(desc + "  -> lädt Fremdcode vor/nach jeder PHP-Seite")
            else:
                info.append(desc)
        elif low.startswith("allow_url_include=") and low.split("=", 1)[1].strip("\"'") in ("1", "on", "true", "yes"):
            crit.append(desc + "  -> erlaubt Nachladen von Code aus dem Internet")
        elif re.match(r"(display_errors|display_startup_errors)=(1|on|true)", low):
            warn.append(desc + "  -> zeigt Fehlermeldungen (mit Pfaden) für Besucher an")
        elif low.startswith("disable_functions=") and not low.split("=", 1)[1].strip("\"'"):
            warn.append(desc + "  -> alle PHP-Funktionen freigegeben")
        else:
            info.append(desc)
    if crit:
        res.add("crit", "Gefährliche PHP-Einstellung", "", crit, "Zeile entfernen und prüfen, welche Datei dort eingebunden wurde.")
    if warn:
        res.add("warn", "Auffällige PHP-Einstellung", "", warn)
    if info:
        res.add("info", "Weitere Einstellungen in %d Datei(en)" % len(seen_files), "Zur Kontrolle.", info[:40])
    if not (crit or warn or info):
        res.add("ok", "Keine PHP-Einstellungsdateien gefunden")
    elif not (crit or warn):
        res.add("ok", "Keine gefährlichen PHP-Einstellungen gefunden")


# ----------------------------------------------------------------------------- configuration.php
@check(
    "configuration", G, "Joomla-Konfiguration (configuration.php)",
    "Ist die configuration.php unverändert, ohne eingeschleuste Zeilen und mit sinnvollen Einstellungen?",
    what="Liest die configuration.php und prüft: Stehen dort nur die üblichen Einstellungen (keine zusätzlichen Code-Zeilen)? Ist Debug aus? "
         "Haben tmp- und log-Pfad einen Schrägstrich am Ende (verursacht Update-Prüfsummenfehler)? Ist das Geheimwort (secret) vorhanden? "
         "Sind lange Sitzungszeiten oder der FTP-Layer aktiv? Passwörter werden dabei NICHT angezeigt oder exportiert.",
    why="Die configuration.php enthält die Datenbank-Zugangsdaten und ist ein Ziel für eingeschleuste Zeilen (@include, eval). "
        "Außerdem zeigt sie Fehleinstellungen, die Updates blockieren oder Informationen preisgeben.",
    reads="Den Inhalt der configuration.php. Im Bericht werden Passwörter und Geheimnisse durch *** ersetzt.",
    load="leicht", presets=["schnell", "hack"],
)
def configuration(ctx, res):
    cfg = ctx.config()
    if cfg.get("missing"):
        res.add("warn", "configuration.php nicht gefunden", "Das Verzeichnis ist vermutlich falsch.")
        return
    v = cfg["vars"]
    ctx.add_raw("configuration_maskiert", cfg["text"])
    if cfg["unexpected"]:
        res.add("crit", "Unerwartete Zeilen in der configuration.php (%d)" % len(cfg["unexpected"]),
                "Die Datei darf nur die üblichen 'public $name = ...;'-Zeilen enthalten. Alles andere ist eingeschleuster Code.",
                ["Zeile %d: %s" % (n, clean_line(t)) for n, t in cfg["unexpected"][:20]],
                "Zeile sofort entfernen (vorher sichern), danach Datenbank-Passwort ändern und herausfinden, wie der Code hineinkam.")
    else:
        res.add("ok", "Aufbau der configuration.php ist unverändert", "%d Einstellungen, %d Byte, keine zusätzlichen Zeilen." % (len(v), cfg["size"]))
    if v.get("debug") is True or str(v.get("debug")) == "1":
        res.add("warn", "Debug-Modus ist an", "Zeigt Besuchern Fehler und interne Pfade.", hint="Globale Konfiguration -> System -> Debug-System: Nein.")
    if str(v.get("error_reporting", "default")).lower() in ("maximum", "development", "e_all"):
        res.add("warn", "Fehlerberichte stehen auf '%s'" % v.get("error_reporting"), "Gibt auf einer Live-Seite zu viele Informationen preis.",
                hint="Globale Konfiguration -> Server -> Fehlerberichterstattung: Standard/Keine.")
    for key, label in (("tmp_path", "tmp-Pfad"), ("log_path", "log-Pfad")):
        p = str(v.get(key, ""))
        if len(p) > 1 and p.endswith("/"):
            res.add("warn", "%s endet mit einem Schrägstrich (%s)" % (label, p),
                    "Das führt bei Joomla zu falschen Pfaden und kann z. B. die Prüfsummenprüfung beim Update zum Scheitern bringen.",
                    hint="In der Globalen Konfiguration (Server) den Schrägstrich am Ende entfernen.")
    if not v.get("secret") or len(str(v.get("secret"))) < 16:
        res.add("warn", "Das 'secret' fehlt oder ist sehr kurz", "Wird für Sitzungen und Token benutzt.")
    if v.get("password") in ("", None):
        res.add("crit", "Datenbank ohne Passwort", "Das Datenbankkonto hat laut configuration.php kein Passwort.")
    if str(v.get("ftp_enable")) in ("1", "True", "true"):
        res.add("warn", "FTP-Layer ist aktiv", "Dann stehen FTP-Zugangsdaten in der configuration.php.", hint="Deaktivieren, wenn nicht gebraucht.")
    try:
        life = int(v.get("lifetime", 15))
        if life > 180:
            res.add("warn", "Sitzungsdauer sehr lang (%d Minuten)" % life,
                    "Gestohlene Anmelde-Sitzungen bleiben dann lange gültig.", hint="Auf 15 bis 60 Minuten stellen.")
    except (TypeError, ValueError):
        pass
    dbhost = str(v.get("host", "localhost"))
    res.add("info", "Datenbank-Einstellungen", "Zugangsdaten werden nicht angezeigt.",
            ["Typ: %s" % v.get("dbtype", "?"), "Host: %s" % dbhost, "Datenbank: %s" % v.get("db", "?"), "Tabellenpräfix: %s" % v.get("dbprefix", "?"),
             "Sitzungsverwaltung: %s" % v.get("session_handler", "?"), "Mailer: %s" % v.get("mailer", "?")], context=True)


# ----------------------------------------------------------------------------- Einstiegsdateien
ENTRY_TOKENS = (r"eval *\(|base64_decode|gzinflate|str_rot13|fromCharCode|file_get_contents *\( *.https?|curl_exec|shell_exec|passthru|"
                r"system *\(|@include|@eval|@ini_set|<script|<iframe|document\.write|atob\(|include(_once)? *\(? *.(/tmp|http|\$_)")
KNOWN_INCLUDES = {"app.php", "defines.php", "framework.php", "incompatible.php", "index.html"}


@check(
    "entry_points", G, "Einstiegsdateien und Template-Dateien",
    "Sind index.php, Template-Dateien und includes/ sauber - oder wurde Code eingefügt?",
    what="Liest die Einstiegsdateien von Joomla (index.php, administrator/index.php, api/index.php, includes/*.php) und alle Template-Dateien "
         "(index.php, error.php, component.php) und sucht nach eingefügtem Code, Skript-Einbindungen und fremden Adressen.",
    why="Ein Angreifer, der Code in jede Seite ausliefern will, ändert häufig die index.php des Templates (z. B. um ein Skript in den <head> zu setzen). "
        "Genau das passierte bei dem Vorfall, der dieses Programm ausgelöst hat.",
    reads="Den Inhalt weniger Dateien (Einstiegs- und Template-Dateien). Bekannte Dienste (Google Tag Manager, Elfsight ...) gelten als bekannt.",
    load="leicht", presets=["schnell", "hack"],
)
def entry_points(ctx, res):
    files_expr = ("index.php administrator/index.php api/index.php includes/*.php templates/*/index.php templates/*/error.php templates/*/component.php "
                  "administrator/templates/*/index.php administrator/templates/*/login.php")
    script = r"""
FILES="@FILES@"
echo '@@FILES'
for f in $FILES; do [ -f "$f" ] && printf 'F\t%s\t%s\t%s\n' "$f" "$(stat -c %s "$f")" "$(stat -c %y "$f" | cut -c1-16)"; done
echo '@@HITS'
for f in $FILES; do [ -f "$f" ] && grep -nHiE -e '@TOKENS@' "$f" 2>/dev/null | cut -c1-300; done | head -400
echo '@@HEAD'
for f in index.php administrator/index.php; do [ -f "$f" ] && { echo "== $f"; head -c 1500 "$f"; echo; }; done
""".replace("@FILES@", files_expr).replace("@TOKENS@", ENTRY_TOKENS)
    out = ctx.sh(script, timeout=60, raw="treffer").out
    sec = split_sections(out)
    allow, own = ctx.allow(), ctx.own_host()
    sizes: Dict[str, int] = {}
    n_files = 0
    for ln in sec.get("FILES", "").splitlines():
        p = ln.split("\t")
        if len(p) >= 4 and p[0] == "F":
            n_files += 1
            sizes[p[1]] = int(p[2] or 0)
    crit, warn, info_hosts, unknown_hosts = [], [], [], []
    inline_scripts = 0
    for ln in sec.get("HITS", "").splitlines():
        m = re.match(r"^(.*?):(\d+):(.*)\Z", ln)
        if not m:
            continue
        path, no, line = m.group(1), m.group(2), m.group(3)
        is_entry = path in ("index.php", "administrator/index.php", "api/index.php") or path.startswith("includes/")
        low = line.lower()
        hosts = [h for h in extract_hosts(line) if h != own]
        bad_hosts = [h for h in hosts if not host_allowed(h, allow)]
        desc = "%s Zeile %s: %s" % (clean_line(path), no, trunc(clean_line(line.strip()), 170))
        dangerous = re.search(r"eval *\(|base64_decode|gzinflate|str_rot13|fromcharcode|shell_exec|passthru|system *\(|@include|@eval|@ini_set|atob\(|curl_exec|include(_once)? *\(? *.(/tmp|http|\$_)|document\.write", low)
        obfuscated = bool(re.search(r"eval *\(.{0,120}fromcharcode|fromcharcode *\( *([0-9]+ *, *){25,}", low))
        if dangerous:
            (crit if (is_entry or obfuscated) else warn).append(desc + "  -> %s" % (
                "in einer Einstiegsdatei sehr ungewöhnlich" if is_entry else "verschleierter Code (eval + fromCharCode): sehr wahrscheinlich Schadcode" if obfuscated else "prüfen"))
        elif bad_hosts:
            warn.append(desc + "  -> unbekannte Adresse: %s" % ", ".join(bad_hosts[:3]))
            unknown_hosts += bad_hosts
        elif "<script" in low or "<iframe" in low:
            inline_scripts += 1
            if hosts:
                info_hosts.append(desc + "  -> bekannter Dienst: %s" % ", ".join(hosts[:3]))
    if crit:
        res.add("crit", "Verdächtiger Code in Einstiegsdateien", "Diese Dateien sollten nur aus wenigen Standardzeilen bestehen.", crit[:40],
                "Datei mit dem Original aus dem Joomla-Paket vergleichen bzw. Core neu installieren.")
    if warn:
        res.add("warn", "Auffälligkeiten in Template-Dateien", "Skripte von unbekannten Adressen oder Funktionen, die dort selten vorkommen.", warn[:60],
                "Kennst du diese Einbindung? Falls nicht, entfernen (vorher Datei sichern).")
    if info_hosts:
        res.add("info", "Skripte/Frames von bekannten Diensten", "Z. B. Google Tag Manager oder Elfsight. Bitte prüfen, ob du sie selbst eingebaut hast.", info_hosts[:25])
    for f in ("index.php", "administrator/index.php", "api/index.php"):
        if sizes.get(f, 0) > 4096:
            res.add("warn", "%s ist ungewöhnlich groß (%d Byte)" % (f, sizes[f]),
                    "Die Standarddatei hat etwa 1,5 KB. Eine deutlich größere Datei enthält vermutlich zusätzlichen Code.",
                    hint="Mit Joomla-Core neu installieren ersetzen.")
    unknown_inc = []
    for f in sizes:
        if f.startswith("includes/") and f.split("/", 1)[1] not in KNOWN_INCLUDES:
            unknown_inc.append(f)
    if unknown_inc:
        res.add("warn", "Unbekannte Dateien in includes/", "Joomla liefert dort nur app.php, defines.php, framework.php und incompatible.php.",
                [clean_line(f) for f in unknown_inc], "Prüfen und im Zweifel löschen.")
    if not (crit or warn):
        res.add("ok", "Einstiegs- und Template-Dateien unauffällig",
                "%d Dateien geprüft%s." % (n_files, (", %d Skript-/Frame-Einbindungen bekannter Dienste" % inline_scripts) if inline_scripts else ""))
