"""Kritische PHP-Einstellungen und Integrität der configuration.php. Rein lesend (php -l und ini_get lesen nur)."""
from __future__ import annotations

import datetime
import re
from typing import Any, Dict, List, Optional, Tuple

from .. import phppick
from ..model import CheckSkipped
from ..registry import check
from ..util import clean_line, digits, lines_of, mask_secrets, split_sections
from .config import ENTRY_TOKENS

G = "konfig"
Row = Tuple[str, str, str, List[str], str]            # (sev, title, detail, items, hint)

SETTINGS = ["allow_url_include", "allow_url_fopen", "expose_php", "disable_functions", "open_basedir", "auto_prepend_file", "auto_append_file",
            "enable_dl", "error_log", "log_errors", "memory_limit", "session.use_only_cookies", "session.use_trans_sid", "zend.assertions",
            "short_open_tag", "file_uploads", "disable_classes"]
DANGEROUS_FUNCS = ["exec", "passthru", "shell_exec", "system", "proc_open", "popen", "pcntl_exec"]
KNOWN_PREPEND = ("wordfence-waf.php", "sucuri", "ithemes")           # Firewalls laden sich bewusst vor jede Seite

PHP_SCRIPT = r"""
@PICK@echo '@@BIN'; echo "$P"
if [ -n "$P" ]; then
  echo '@@SET'
  timeout 15 "$P" -r '$k=explode(",","@KEYS@"); foreach($k as $x){ echo $x,"\t",str_replace(array("\r","\n","\t")," ",(string)ini_get($x)),"\n"; } echo "VER\t",PHP_VERSION,"\n";' </dev/null 2>/dev/null
  INIS="$(timeout 15 "$P" -r 'echo php_ini_loaded_file(),"\n",php_ini_scanned_files();' </dev/null 2>/dev/null | tr ',' '\n' | sed 's/^[ \t]*//' | grep -v '^$')"
  echo '@@INIFILES'; echo "$INIS"
  echo '@@DISPLAY'
  for f in $INIS; do [ -r "$f" ] && grep -HiE '^[[:space:]]*display_errors[[:space:]]*=' "$f" 2>/dev/null; done | tail -3
fi
"""


FUNC_RX = r"(^|[^A-Za-z0-9_>:$.])(%s)[[:space:]]*\("
FUNC_SCAN = {
    "joomla": "plugins components modules templates administrator/components administrator/modules administrator/templates libraries",
    "wordpress": "wp-content/plugins wp-content/themes wp-content/mu-plugins",
}
FUNC_SCRIPT = r"""
echo '@@USERS'
for d in @DIRS@; do [ -d "$d" ] && echo "$d"; done | while IFS= read -r d; do
  find "$d" \( -path 'libraries/vendor' -o -path 'libraries/src' -o -path '*/node_modules' \) -prune -o -type f -name '*.php' -print0 2>/dev/null
done | xargs -0 -r timeout 60 grep -HoE '@RX@' 2>/dev/null | head -n 4000
"""
FUNC_USER_RX = re.compile(r"^(?P<path>[^:]+):[^A-Za-z0-9_]?(?P<fn>exec|passthru|shell_exec|system|proc_open|popen|pcntl_exec)\s*\($")


def ext_key(path: str, cms: str) -> str:
    """Kurzname der Erweiterung zu einem Dateipfad (Plugin, Komponente, Modul, Template, Bibliothek bzw. WordPress-Plugin oder -Theme)."""
    parts = [x for x in path.replace("\\", "/").split("/") if x and x != "."]
    if cms == "wordpress":
        if len(parts) >= 3 and parts[0] == "wp-content":
            return parts[2] if parts[1] in ("plugins", "themes", "mu-plugins") else "/".join(parts[:3])
        return "/".join(parts[:2])
    if parts and parts[0] == "administrator":
        parts = parts[1:]
    if len(parts) >= 3 and parts[0] == "plugins":
        return "%s/%s (Plugin)" % (parts[1], parts[2])
    if len(parts) >= 2 and parts[0] in ("components", "modules", "templates", "libraries"):
        return parts[1]
    return "/".join(parts[:2])


def parse_func_users(out: str, cms: str) -> Dict[str, Dict[str, int]]:
    """Aus 'Datei:Treffer'-Zeilen: Funktion -> {Erweiterung: Zahl der Treffer}."""
    res: Dict[str, Dict[str, int]] = {}
    body = out.split("@@USERS", 1)[-1]
    for ln in body.splitlines():
        m = FUNC_USER_RX.match(ln.strip())
        if not m:
            continue
        k = ext_key(m.group("path"), cms)
        d = res.setdefault(m.group("fn"), {})
        d[k] = d.get(k, 0) + 1
    return res


def apply_func_users(rows: List[Row], users: Optional[Dict[str, Dict[str, int]]]) -> List[Row]:
    """Ergänzt die Zeile 'gefährliche Funktionen nicht gesperrt' um die Antwort auf die Frage: Braucht eine Erweiterung diese Funktionen? None = nicht gesucht."""
    if users is None:
        return rows
    out: List[Row] = []
    for sev, title, detail, items, hint in rows:
        if "gefährlichen Funktionen sind nicht gesperrt" in title:
            open_f = [x.split(": ", 1)[-1] for x in items if x.startswith("nicht gesperrt: ")]
            names = [n.strip() for n in (open_f[0].split(",") if open_f else [])]
            unused = [n for n in names if n not in users]
            used = [(n, users[n]) for n in names if n in users]
            lines = []
            for n, who in used:
                lines.append("%s wird gefunden in: %s" % (n, ", ".join("%s (%dx)" % (k, v) for k, v in sorted(who.items(), key=lambda kv: -kv[1])[:6])))
            if unused:
                lines.append("Von keiner gefundenen Erweiterung genutzt, ohne Risiko für sie sperrbar: " + ", ".join(unused))
            detail += (" Die Suche in den Dateien der Erweiterungen zeigt, wer diese Funktionen aufruft. Ein Treffer ist ein Hinweis, kein Beweis, dass die Funktion wirklich gebraucht wird "
                       "(auch Kommentare und Prüfungen zählen).")
            if used:
                hint = ("Sperre zuerst nur die Funktionen, die niemand nutzt. Bei den übrigen bei der genannten Erweiterung nachlesen, ob sie die Funktion braucht "
                        "(Sicherungs-Erweiterungen nutzen sie zum Packen, Mail- und Bildprogramme zum Aufruf externer Programme). Sperren beim Hoster eintragen lassen und danach die Erweiterungen ausprobieren.")
            else:
                hint = "Keine gefundene Erweiterung ruft diese Funktionen auf. Du kannst alle beim Hoster sperren lassen (disable_functions) und danach die Seite kurz ausprobieren."
            items = list(items) + lines
        out.append((sev, title, detail, items, hint))
    return out


def truthy(v: str) -> bool:
    return str(v).strip().lower() in ("1", "on", "true", "yes")


def parse_settings(text: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for ln in text.splitlines():
        k, sep, v = ln.partition("\t")
        if sep:
            out[k.strip()] = v.strip()
    return out


def evaluate(s: Dict[str, str], display_lines: List[str], web_version: str, eol_rows: List[Dict[str, str]], today: Optional[datetime.date] = None) -> List[Row]:
    """Bewertet die Einstellungen. Reine Funktion (testbar)."""
    today = today or datetime.date.today()
    rows: List[Row] = []
    if truthy(s.get("allow_url_include", "0")):
        rows.append(("crit", "allow_url_include ist eingeschaltet", "Damit kann PHP Code von fremden Adressen laden und ausführen. Das macht jede Datei-Einbindungs-Lücke zum Totalschaden. Joomla und WordPress brauchen das nicht.", [],
                     "Beim Hoster (PHP-Einstellungen) auf 'Off' stellen oder in einer .user.ini: allow_url_include = Off"))
    if truthy(s.get("allow_url_fopen", "0")):
        rows.append(("info", "allow_url_fopen ist eingeschaltet", "Skripte können Webadressen wie Dateien lesen. Das ist auf vielen Servern üblich und wird von manchen Erweiterungen gebraucht, erleichtert aber Angreifern das Nachladen von Schadcode.", [],
                     "Wenn keine Erweiterung es braucht: auf 'Off' stellen."))
    pre = [(k, s.get(k, "").strip()) for k in ("auto_prepend_file", "auto_append_file")]
    pre = [(k, v) for k, v in pre if v]
    if pre:
        known = all(any(x in v.lower() for x in KNOWN_PREPEND) for _, v in pre)
        rows.append(("info" if known else "crit", "%s lädt automatisch eine Datei" % pre[0][0] if len(pre) == 1 else "auto_prepend_file/auto_append_file laden automatisch Dateien",
                     "Diese Datei wird vor bzw. nach JEDER PHP-Seite ausgeführt. %s" % ("Das passt zu einer Firewall (z. B. Wordfence)." if known else "Das ist ein klassischer Hack-Trick, um Schadcode ohne Änderung einer Joomla-/WordPress-Datei auszuführen."),
                     ["%s = %s" % (k, clean_line(v)) for k, v in pre], "" if known else "Datei ansehen. Gehört sie nicht zu einer bekannten Firewall: Einstellung und Datei entfernen."))
    funcs = {f.strip().lower() for f in s.get("disable_functions", "").split(",") if f.strip()}
    open_f = [f for f in DANGEROUS_FUNCS if f not in funcs]
    if open_f:
        rows.append(("info", "%d von %d gefährlichen Funktionen sind nicht gesperrt" % (len(open_f), len(DANGEROUS_FUNCS)),
                     "Web-Shells brauchen meist exec, system, shell_exec, passthru, proc_open oder popen, um Befehle auf dem Server auszuführen. Joomla selbst braucht sie nicht; manche Backup-Erweiterungen schon.",
                     ["nicht gesperrt: " + ", ".join(open_f)], "Beim Hoster in disable_functions eintragen lassen (testen, ob alle Erweiterungen weiterlaufen)."))
    else:
        rows.append(("ok", "Gefährliche Funktionen sind gesperrt", "exec, system, shell_exec, passthru, proc_open, popen und pcntl_exec stehen in disable_functions.", [], ""))
    if truthy(s.get("expose_php", "0")):
        rows.append(("info", "expose_php ist eingeschaltet", "Der Server verrät in den Kopfzeilen die genaue PHP-Version. Angreifer suchen damit gezielt nach Lücken.", [], "expose_php = Off"))
    if not s.get("open_basedir", "").strip():
        rows.append(("info", "open_basedir ist nicht gesetzt", "PHP darf überall lesen, wo das Konto Rechte hat. Auf Shared Hosting sorgt meist eine andere Trennung für Schutz; wo nicht, ist das ein Risiko.", [], ""))
    if truthy(s.get("enable_dl", "0")):
        rows.append(("warn", "enable_dl ist eingeschaltet", "Skripte dürfen PHP-Erweiterungen zur Laufzeit nachladen. Das wird für Angriffe auf den Server genutzt und von keiner Seite gebraucht.", [], "enable_dl = Off"))
    last = display_lines[-1] if display_lines else ""
    m = re.search(r"display_errors\s*=\s*\"?([A-Za-z0-9_]+)", last, re.I)
    if m and m.group(1).lower() in ("1", "on", "true", "yes", "stdout"):
        rows.append(("warn", "display_errors ist in der PHP-Einstellung eingeschaltet", "Fehlermeldungen mit Dateipfaden und Datenbank-Angaben erscheinen auf der Webseite. Das hilft Angreifern.", [clean_line(last)], "display_errors = Off"))
    if s.get("session.use_only_cookies", "1").strip() in ("0", "Off", "off", ""):
        rows.append(("warn", "Sitzungen dürfen auch über die Adresse laufen (session.use_only_cookies aus)", "Gestohlene oder untergeschobene Sitzungs-IDs in Links werden akzeptiert (Session Fixation).", [], "session.use_only_cookies = 1"))
    if truthy(s.get("session.use_trans_sid", "0")):
        rows.append(("warn", "session.use_trans_sid ist eingeschaltet", "Die Sitzungs-ID wird in Links eingefügt und kann über Verweise und Protokolle abfließen.", [], "session.use_trans_sid = 0"))
    el = s.get("error_log", "").strip()
    if el and re.search(r"(^|/)(public_html|htdocs|www|html|httpdocs|web)/", el) and "/logs" not in el:
        rows.append(("info", "error_log liegt vermutlich im öffentlichen Webverzeichnis", "Fehlerprotokolle mit Pfaden und Teilen von Anfragen sollten nicht von außen lesbar sein.", [clean_line(el)], "Datei außerhalb des Webverzeichnisses ablegen oder per .htaccess sperren."))
    ver = (web_version or s.get("VER", "")).strip()
    mm = re.match(r"(\d+\.\d+)", ver)
    if mm:
        row = next((r for r in eol_rows if r["branch"] == mm.group(1)), None)
        if row:
            eol = datetime.date.fromisoformat(row["eol"])
            if eol < today:
                years = (today - eol).days / 365.0
                rows.append(("crit" if years > 2 else "warn", "PHP %s wird nicht mehr mit Sicherheitsupdates versorgt" % mm.group(1),
                             "Das Support-Ende war am %s. Bekannte Lücken werden nicht mehr geschlossen; viele Angriffe richten sich gezielt gegen alte PHP-Versionen." % row["eol"], ["PHP-Version: " + ver],
                             "Beim Hoster auf eine aktuelle PHP-Version umstellen (vorher prüfen, ob alle Erweiterungen sie unterstützen)."))
            elif (eol - today).days < 120:
                rows.append(("info", "PHP %s läuft bald aus (Support-Ende %s)" % (mm.group(1), row["eol"]), "Plane die Umstellung auf eine neuere PHP-Version.", ["PHP-Version: " + ver], ""))
            else:
                rows.append(("ok", "PHP %s wird noch mit Sicherheitsupdates versorgt" % mm.group(1), "Support bis %s." % row["eol"], [], ""))
    return rows


@check(
    "php_settings", "konfig", "Kritische PHP-Einstellungen",
    "Sind PHP-Einstellungen gesetzt, die Angriffe erleichtern (allow_url_include, gesperrte Funktionen, auto_prepend_file, veraltete PHP-Version)?",
    what="Liest mit dem PHP-Programm des Servers die wirksamen Einstellungen (ini_get) und die Einstellungsdateien: allow_url_include, allow_url_fopen, auto_prepend_file/auto_append_file, disable_functions, expose_php, "
         "open_basedir, enable_dl, display_errors, Sitzungs-Einstellungen und ob die PHP-Version noch Sicherheitsupdates erhält. Es wird nichts geändert und kein Skript der Seite ausgeführt.",
    why="Einige PHP-Einstellungen entscheiden darüber, wie viel Schaden eine einzelne Lücke anrichtet: Mit allow_url_include wird jede Einbindungs-Lücke zur Fernsteuerung, mit offenen Funktionen wie system() "
        "laufen Web-Shells voll, und eine PHP-Version ohne Support bekommt keine Lücken mehr geschlossen.",
    reads="Nur die PHP-Einstellungen (php -r mit ini_get) und die gefundenen php.ini-Dateien (nur die Zeile display_errors). Hinweis: Gelesen werden die Werte der Kommandozeile; auf vielen Hostern sind sie mit denen der Webseite identisch, nicht auf allen.",
    load="leicht", presets=["schnell", "hack"],
)
def php_settings(ctx, res):
    web = ctx.shared.get("php_web") or {}
    wv = str(web.get("version") or "").strip()
    script = PHP_SCRIPT.replace("@PICK@", ctx.php_pick()).replace("@KEYS@", ",".join(SETTINGS))
    out = ctx.sh(script, timeout=90, raw="php_einstellungen").out
    sec = split_sections(out)
    if not (sec.get("BIN") or "").strip():
        raise CheckSkipped("Auf dem Server wurde kein PHP-Programm für die Kommandozeile gefunden. Die Einstellungen sind so nicht lesbar.")
    s = parse_settings(sec.get("SET", ""))
    if not s:
        raise CheckSkipped("Das PHP-Programm lieferte keine Einstellungen (gesperrt?).")
    rows = evaluate(s, lines_of(sec.get("DISPLAY", "")), wv, ctx.adv.get("php_eol", []))
    if any("gefährlichen Funktionen sind nicht gesperrt" in r[1] for r in rows):
        ctx.progress("Prüfe, welche Erweiterungen die gesperrten Funktionen aufrufen")
        dirs = FUNC_SCAN.get(ctx.cms, FUNC_SCAN["joomla"])
        fsc = FUNC_SCRIPT.replace("@DIRS@", dirs).replace("@RX@", FUNC_RX % "|".join(DANGEROUS_FUNCS))
        fo = ctx.sh(fsc, timeout=120)
        rows = apply_func_users(rows, None if (fo.timed_out or fo.rc not in (0, 1, 123)) else parse_func_users(fo.out, ctx.cms))
    note = "Gelesen mit %s (Kommandozeile%s)." % (sec["BIN"].strip(), ", PHP " + s["VER"] if s.get("VER") else "")
    if wv and s.get("VER") and not s["VER"].startswith(wv):
        note += " Die Webseite läuft laut Erkennung mit PHP %s; die Werte können abweichen." % wv
    shown = False
    for sev, title, detail, items, hint in rows:
        res.add(sev, title, detail, items, hint)
        shown = shown or sev in ("warn", "crit")
    res.add("info", "Quelle der Einstellungen", note, [x.strip() for x in lines_of(sec.get("INIFILES", ""))][:6], context=True)


# ============================================================================ configuration.php
JCONFIG_KNOWN = set("""offline offline_message display_offline_message offline_image sitename editor captcha list_limit access debug debug_lang debug_lang_const dbtype host user password db dbprefix
dbencryption dbsslverifyservercert dbsslkey dbsslcert dbsslca dbsslcipher force_ssl live_site secret gzip error_reporting helpurl offset mailonline mailer mailfrom fromname sendmail smtpauth smtpuser smtppass
smtphost smtpsecure smtpport caching cache_handler cachetime cache_platformprefix MetaDesc MetaAuthor MetaVersion MetaRights robots sef sef_rewrite sef_suffix unicodeslugs feed_limit feed_email log_path tmp_path
lifetime session_handler shared_session session_metadata session_filesystem_path ftp_host ftp_port ftp_user ftp_pass ftp_root ftp_enable proxy_enable proxy_host proxy_port proxy_user proxy_pass massmailoff
replyto replytoname sitename_pagetitles log_categories log_category_mode log_everything log_deprecated log_priorities behind_loadbalancer cors cors_allow_origin cors_allow_headers cors_allow_methods
session_memcached_server_host session_memcached_server_port session_redis_server_host session_redis_server_port session_redis_server_auth session_redis_server_db memcached_persist memcached_compress
memcached_server_host memcached_server_port redis_persist redis_server_host redis_server_port redis_server_auth redis_server_db asset_id api_cors frontediting site_name mailfrom_name""".split())

STR_LIT = r"'(?:[^'\\]|\\.)*'|\"(?:[^\"\\$]|\\.)*\""
SCALAR = r"(?:%s|-?\d+(?:\.\d+)?|true|false|null)" % STR_LIT
LITERAL_RE = re.compile(r"^(?:%s|(?:array\s*\(|\[)\s*(?:%s(?:\s*=>\s*%s)?(?:\s*,\s*%s(?:\s*=>\s*%s)?)*\s*,?\s*)?(?:\)|\]))\Z" % (SCALAR, SCALAR, SCALAR, SCALAR, SCALAR), re.I)
PROP_LINE_RE = re.compile(r"^\s*public\s+(?:\?\w+\s+|\w+\s+)?\$(\w+)\s*=\s*(.*?)\s*;\s*(?://.*|#.*)?\Z")

CFG_SCRIPT = r"""
echo '@@STAT'; stat -c '%a %U %Y %s' configuration.php 2>/dev/null
echo '@@ME'; id -un 2>/dev/null
echo '@@NOW'; date +%s
echo '@@LINT'
@PICK@if [ -n "$P" ]; then timeout 20 "$P" -l configuration.php </dev/null 2>&1 | head -4; else echo NOPHP; fi
echo '@@COPIES'
find . -maxdepth 3 -type f \( -iname 'configuration.php?*' -o -iname '*.configuration.php' -o -iname 'configuration.*.php' -o -iname 'configuration_*' -o -iname 'configuration-*' -o -iname 'configuration.bak*' -o -iname '.configuration*' \) \
  ! -path './configuration.php' ! -path './administrator/cache/*' ! -path './cache/*' 2>/dev/null | head -20 | while IFS= read -r f; do
  if grep -qE 'class JConfig|public \$password' "$f" 2>/dev/null; then echo "PW	$f"; else echo "OTHER	$f"; fi
done
"""


def literal_problems(text: str) -> List[Tuple[int, str, str]]:
    """Eigenschaften der JConfig-Klasse, deren Wert kein einfaches Literal ist (Zeichenkette, Zahl, true/false/null, einfaches Feld).
    Dahinter steckt oft angehängter Code in derselben Zeile (public $x = 'a'; eval(...);)."""
    bad = []
    for no, ln in enumerate(text.splitlines(), 1):
        m = PROP_LINE_RE.match(ln)
        if m and not LITERAL_RE.match(m.group(2).strip()):
            bad.append((no, m.group(1), m.group(2).strip()[:200]))
    return bad


LINT_ERR_RE = re.compile(r"(?:PHP\s+)?(?:Parse|Fatal) error\s*:\s*(.+?)\s+in\s+\S+\s+on\s+line\s+(\d+)", re.I)
LINT_VALID = "public $offline = false;   |   public $sitename = 'Meine Seite';   (Text in Anführungszeichen, jede Zeile endet mit Semikolon)"


def lint_explain(msg: str) -> str:
    low = msg.lower()
    if "end of file" in low:
        return "Die Datei endet zu früh: Eine Klammer oder ein Anführungszeichen wurde geöffnet und nie geschlossen (oder der Rest der Datei fehlt)."
    if "unexpected" in low:
        return "An dieser Stelle steht ein Zeichen oder Wort, das PHP dort nicht erwartet. Meist fehlt davor ein Semikolon oder ein Anführungszeichen, oder ein Text enthält ein nicht maskiertes Anführungszeichen."
    return "PHP kann die Datei an dieser Stelle nicht lesen."


def lint_row(ls: str, text: str) -> Row:
    """Auswertung von 'php -l'. Nur eine echte PHP-Fehlermeldung ist ein Befund; alles andere (z. B. die Ausgabe eines Auswahlprogramms) wird nicht als Fehler der Datei gewertet."""
    m = LINT_ERR_RE.search(ls)
    if not m:
        why = ("Das PHP-Programm der Kommandozeile ist ein Auswahlprogramm und führt nichts aus. " if phppick.is_wrapper(ls) else "")
        return ("info", "Syntaxprüfung nicht auswertbar",
                why + "Die Ausgabe von php -l enthielt keine PHP-Fehlermeldung. Daraus lässt sich weder ein Fehler noch Fehlerfreiheit ableiten.",
                [clean_line(x) for x in ls.splitlines()[:3]], "")
    msg, line = m.group(1).strip(), int(m.group(2))
    lines = text.splitlines()
    items = ["PHP-Meldung: %s (Zeile %d)" % (clean_line(msg)[:200], line)]
    if 1 <= line <= len(lines):
        items.append("Zeile %d: %s" % (line, clean_line(mask_secrets(lines[line - 1]))[:200]))
    items.append("So sieht eine gültige Zeile aus: " + LINT_VALID)
    return ("crit", "Die configuration.php hat einen Syntaxfehler (Zeile %d)" % line,
            "%s Die Seite kann so nicht laufen. Ursache sind meist eine Handänderung oder Schadcode." % lint_explain(msg), items,
            "Zeile mit der Meldung vergleichen und korrigieren, oder die zuletzt gesicherte Fassung zurückspielen.")


def evaluate_config(text: str, vars_: Dict[str, Any], stat: str, me: str, now: int, lint: str, own_host: str) -> List[Row]:
    rows: List[Row] = []
    bad = literal_problems(text)
    if bad:
        rows.append(("crit", "Einstellungen in der configuration.php enthalten Code (%d)" % len(bad),
                     "Ein Wert besteht nicht nur aus einer Zeichenkette oder Zahl. Hinter einer normalen Zeile versteckt sich oft angehängter Code, der bei jedem Seitenaufruf läuft.",
                     ["Zeile %d: $%s = %s" % (n, k, clean_line(v)) for n, k, v in bad[:15]], "Zeile sofort prüfen und bereinigen (vorher sichern), danach Datenbank-Passwort ändern."))
    risky = [(k, v) for k, v in vars_.items() if isinstance(v, str) and k not in ("password", "smtppass", "ftp_pass", "secret", "proxy_pass") and re.search(ENTRY_TOKENS, v, re.I)]
    if risky and not bad:
        rows.append(("crit", "Verdächtiger Inhalt in Einstellungswerten", "Diese Werte enthalten Befehle oder Skript-Code, der dort nicht hingehört.",
                     ["$%s = %s" % (k, clean_line(v)[:160]) for k, v in risky[:10]], "Wert prüfen und bereinigen."))
    unknown = sorted(k for k in vars_ if k not in JCONFIG_KNOWN)
    if unknown:
        rows.append(("info", "%d unbekannte Einstellung(en) in der configuration.php" % len(unknown),
                     "Joomla kennt diese Namen nicht. Sie stammen von Erweiterungen oder von neueren Joomla-Versionen, können aber auch eingeschleust sein.", ["$" + k for k in unknown[:20]], "Namen nachschlagen; unbekannte, nicht benötigte Einstellungen entfernen."))
    live = str(vars_.get("live_site") or "").strip()
    if live:
        m = re.match(r"^(?:https?://)?([^/:]+)", live, re.I)
        host = (m.group(1) if m else "").lower()
        if own_host and host and host.removeprefix("www.") != own_host.removeprefix("www."):
            rows.append(("warn", "live_site zeigt auf eine fremde Adresse", "Alle von Joomla erzeugten Links und Weiterleitungen führen auf %s statt auf die eigene Seite. Das ist ein bekannter Umleitungs-Trick." % host,
                         ["$live_site = " + live], "Feld in der Globalen Konfiguration leeren oder korrigieren."))
        else:
            rows.append(("info", "live_site ist gesetzt", "Joomla benutzt diese Adresse statt der automatisch erkannten.", ["$live_site = " + live], ""))
    ls = lint.strip()
    if "NOPHP" in ls:
        rows.append(("info", "Syntaxprüfung nicht möglich", "Auf dem Server wurde kein PHP-Programm für die Kommandozeile gefunden. Der Aufbau wurde nur über den Text geprüft.", [], ""))
    elif re.search(r"No syntax errors detected", ls):
        rows.append(("ok", "Syntaxprüfung der configuration.php bestanden", "php -l meldet keine Fehler. Die Datei wird dabei nicht ausgeführt.", [], ""))
    elif ls:
        rows.append(lint_row(ls, text))
    p = stat.split()
    if len(p) >= 4 and digits(p[0]) and digits(p[2]) and digits(p[3]):
        mode, owner, mt, size = int(p[0], 8), p[1], int(p[2]), int(p[3])
        if mode & 0o002:
            rows.append(("crit", "configuration.php ist für alle beschreibbar (%s)" % p[0], "Jedes Konto auf dem Server kann die Datei verändern.", [], "chmod 640 (oder 644) setzen."))
        elif mode & 0o020:
            rows.append(("warn", "configuration.php ist für die Gruppe beschreibbar (%s)" % p[0], "Andere Konten in derselben Gruppe könnten die Datei verändern.", [], "chmod 640 (oder 644) setzen."))
        elif mode & 0o004:
            rows.append(("info", "configuration.php ist für alle lesbar (%s)" % p[0], "Auf vielen Hostern nötig, weil der Webserver unter einem anderen Konto läuft. Wo möglich, 640 oder 600 benutzen.", [], ""))
        if size > 20_000:
            rows.append(("warn", "configuration.php ist ungewöhnlich groß (%d KB)" % (size // 1024), "Üblich sind 2 bis 6 KB. Eine große Datei kann angehängten Code enthalten.", [], "Inhalt ansehen."))
        age = (now - mt) / 86400.0
        if now and age < 14:
            rows.append(("info", "configuration.php wurde vor %d Tag(en) geändert" % max(0, int(age)), "Eine Änderung ist normal, wenn du die Globale Konfiguration gespeichert hast. Sonst ist sie ein Warnzeichen.", [], ""))
        if me and owner and owner != me:
            rows.append(("info", "configuration.php gehört dem Konto '%s' (angemeldet: '%s')" % (owner, me), "Auf manchen Hostern ist das üblich, sonst deutet es auf ein fremdes Konto hin.", [], ""))
    return rows


@check(
    "config_integrity", "konfig", "Integrität der configuration.php",
    "Ist die configuration.php syntaktisch in Ordnung, ohne eingeschleusten Code in den Werten und ohne ungeschützte Kopien?",
    what="Prüft die configuration.php mit php -l (Syntax, ohne Ausführung), sucht in jedem Wert nach angehängtem Code, vergleicht die Einstellungsnamen mit den von Joomla bekannten, prüft live_site, Dateirechte, Größe und Änderungsdatum "
         "und sucht nach liegengebliebenen Kopien (configuration.php.bak, configuration.php~, ...), die das Datenbank-Passwort lesbar ausliefern. Passwörter werden nicht angezeigt.",
    why="Die configuration.php läuft bei jedem Seitenaufruf und enthält das Datenbank-Passwort. Ein angehängter Code in einer scheinbar normalen Zeile oder eine Kopie als .bak (wird als Text ausgeliefert) sind zwei der häufigsten Wege, "
        "über die eine Seite übernommen wird.",
    reads="Den Text der configuration.php, ihre Rechte und eine Liste ähnlich benannter Dateien. Im Bericht werden Passwörter durch *** ersetzt.",
    load="leicht", presets=["schnell", "hack"],
)
def config_integrity(ctx, res):
    cfg = ctx.config()
    if cfg.get("missing"):
        raise CheckSkipped("configuration.php nicht gefunden.")
    sec = split_sections(ctx.sh(CFG_SCRIPT.replace("@PICK@", ctx.php_pick()), timeout=90, raw="config_pruefung").out)
    now_s = (lines_of(sec.get("NOW", "")) or ["0"])[0].strip()
    now = int(now_s) if digits(now_s) else 0
    rows = evaluate_config(cfg["text"], cfg["vars"], (lines_of(sec.get("STAT", "")) or [""])[0], (lines_of(sec.get("ME", "")) or [""])[0].strip(), now,
                           sec.get("LINT", ""), ctx.own_host())
    copies = [l.split("\t", 1) for l in lines_of(sec.get("COPIES", "")) if "\t" in l]
    pw = [c[1] for c in copies if c[0] == "PW"]
    other = [c[1] for c in copies if c[0] == "OTHER"]
    if pw:
        rows.append(("crit", "%d Kopie(n) der configuration.php im Webverzeichnis" % len(pw),
                     "Dateien wie configuration.php.bak oder configuration.php~ werden vom Webserver als Text ausgeliefert. Jeder Besucher kann das Datenbank-Passwort lesen.", pw, "Sofort löschen (vorher herunterladen) und das Datenbank-Passwort ändern."))
    if other:
        rows.append(("warn", "%d ähnlich benannte Datei(en)" % len(other), "Dateien mit 'configuration' im Namen sind oft Reste von Sicherungen oder Umbenennungen.", other, "Ansehen und löschen, wenn nicht gebraucht."))
    bad = [r for r in rows if r[0] in ("warn", "crit")]
    for sev, title, detail, items, hint in rows:
        res.add(sev, title, detail, items, hint)
    if not bad:
        res.add("ok", "configuration.php ist unauffällig", "Keine Syntaxfehler, keine Code-Anhängsel in Werten, keine Kopien im Webverzeichnis.")
