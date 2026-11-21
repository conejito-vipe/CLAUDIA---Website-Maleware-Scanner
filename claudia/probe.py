"""Verbindungstest: Joomla-Ordner, Version, Datenbank-Programm und PHP-Version ermitteln.

Jeder Schritt ist einzeln und mit eigener Zeitgrenze abgesichert. Ein hängender Befehl (auf manchen
Hostern antwortet 'php -v' auf der Kommandozeile nicht) darf weder die anderen Angaben verhindern
noch den Test minutenlang blockieren.
"""
from __future__ import annotations

import re
import time
from typing import Any, Callable, Dict, Optional

from . import contao, drupal, joomla, phppick, typo3, wordpress
from .runner import Runner, RunnerError
from .util import lines_of, split_sections

# Hilfsfunktion: Befehl mit Zeitgrenze (falls das Programm 'timeout' vorhanden ist), ohne Eingabe
SHELL_TIMEOUT_FN = r"""to() { if command -v timeout >/dev/null 2>&1; then timeout -k 1 "$@"; else shift; "$@"; fi; }"""

# PHP-Kommandozeile: erst 'php', dann versionierte Programme (php8.3 ...). Alles mit Zeitgrenze.
PHP_PROBE_SCRIPT = SHELL_TIMEOUT_FN + r"""
echo '@@PHPBIN'; command -v php 2>/dev/null | head -1
echo '@@PHPVER'; p=$(command -v php 2>/dev/null); [ -n "$p" ] && to 5 "$p" -v </dev/null 2>&1 | head -2
echo '@@PHPCAND'
n=0
for v in 8.5 8.4 8.3 8.2 8.1 8.0 7.4; do
  for name in php$v php-$v php${v%.*}${v#*.}; do
    b=$(command -v "$name" 2>/dev/null) || continue
    [ -n "$b" ] || continue
    n=$((n+1)); [ $n -le 3 ] || continue
    printf 'CAND\t%s\t%s\t' "$name" "$b"; to 4 "$b" -v </dev/null 2>&1 | head -1 | tr '\t\r' '  '; echo
  done
done
ls -d /usr/local/php* /opt/php* /opt/plesk/php/* 2>/dev/null | head -6 | sed 's/^/DIR\t/'
echo '@@PHPHT'
grep -hiE 'x-httpd-php|php-?[0-9]\.?[0-9]|proxy:unix|fcgi' .htaccess ../.htaccess 2>/dev/null | head -4 | cut -c1-160
echo '@@PHPPS'
ps -u "$(id -u)" -o args= 2>/dev/null | grep -i php | grep -v grep | cut -c1-200 | sort -u | head -8
echo '@@PHPLINK'
p=$(command -v php 2>/dev/null); [ -n "$p" ] && readlink -f "$p" 2>/dev/null
echo '@@END'
"""

_PHP_RE = re.compile(r"\bPHP\s+(\d+\.\d+(?:\.\d+)?[^\s]*)")


def parse_php_probe(text: str) -> Dict[str, Any]:
    """Wertet die Ausgabe von PHP_PROBE_SCRIPT aus."""
    sec = split_sections(text)
    out: Dict[str, Any] = {"php": "", "php_source": "", "php_note": "", "php_bin": "", "php_candidates": [], "php_installed": [], "php_hint": "",
                           "php_ps": "", "php_link": "", "php_wrapper": False}
    binp = lines_of(sec.get("PHPBIN", ""))
    out["php_bin"] = binp[0] if binp else ""
    m = _PHP_RE.search(sec.get("PHPVER", ""))
    out["php_wrapper"] = phppick.is_wrapper(sec.get("PHPVER", ""))
    if m:
        out["php"] = "PHP " + m.group(1)
        out["php_source"] = "php"
    cands = []
    for ln in sec.get("PHPCAND", "").splitlines():
        p = ln.split("\t")
        if p[0] == "CAND" and len(p) >= 3:
            ver = _PHP_RE.search(p[3]) if len(p) > 3 else None
            cands.append({"name": p[1], "path": p[2], "version": ("PHP " + ver.group(1)) if ver else ""})
        elif p[0] == "DIR" and len(p) >= 2:
            cands.append({"name": p[1], "path": p[1], "version": ""})
    out["php_candidates"] = cands
    versions = []
    for c in cands:
        if c["version"] and c["version"] not in versions:
            versions.append(c["version"])
    out["php_installed"] = versions
    if not out["php"] and len(versions) == 1:
        # nur eine Version installiert: eindeutig
        for c in cands:
            if c["version"]:
                out["php"], out["php_source"] = c["version"], c["name"]
                break
    out["php_ps"] = "\n".join(lines_of(sec.get("PHPPS", ""))[:8])
    out["php_link"] = "\n".join(lines_of(sec.get("PHPLINK", ""))[:1])
    hints = lines_of(sec.get("PHPHT", ""))
    out["php_hint"] = "; ".join(h.strip() for h in hints[:2])
    if not out["php"] and len(versions) > 1:
        out["php_note"] = ("Auf dem Server sind mehrere PHP-Versionen installiert (%s). Das Standard-Programm 'php' %s, "
                           "deshalb ist die Version der Kommandozeile nicht erkennbar." % (", ".join(v.replace("PHP ", "") for v in versions),
                           "ist nur ein Auswahlprogramm und führt nichts aus" if out["php_wrapper"] else "hat nicht geantwortet"))
    elif not out["php"]:
        if out["php_bin"]:
            out["php_note"] = ("Das Programm 'php' (%s) hat auf 'php -v' nicht innerhalb von 5 Sekunden geantwortet. "
                               "Das betrifft nur die Anzeige der Version." % out["php_bin"])
        elif not cands:
            out["php_note"] = "Auf der Kommandozeile des Servers gibt es kein PHP-Programm."
        else:
            out["php_note"] = "Die gefundenen PHP-Programme haben nicht geantwortet."
    return out


STEPS = [("connect", "Mit dem Server verbinden"), ("folder", "Ordner auflisten"), ("joomla", "Joomla/WordPress erkennen"),
         ("db", "Datenbank-Programm suchen"), ("php", "PHP-Version ermitteln")]


def probe(runner: Runner, site_dir: str, progress: Optional[Callable[[str, str], None]] = None,
          deadline: Optional[float] = None) -> Dict[str, Any]:
    """Liefert ein Dict mit allen Angaben. 'progress(step_id, text)' meldet den jeweils laufenden Schritt."""
    info: Dict[str, Any] = {"site_dir": site_dir, "site_found": False, "joomla": "", "php": "", "php_source": "",
                            "php_note": "", "php_hint": "", "php_candidates": [], "mysql": False, "mysql_path": "",
                            "config": False, "cms": "joomla", "wordpress": "", "drupal": "", "drupal_config": False, "typo3": "", "typo3_config": False, "typo3_mode": "", "contao": "", "contao_config": False, "wp_config": False, "who": "", "pwd": "", "folders": [], "warnings": []}

    def step(sid: str, text: str) -> None:
        if progress:
            progress(sid, text)

    def left(default: float) -> float:
        if deadline is None:
            return default
        return max(2.0, min(default, deadline - time.monotonic()))

    try:
        step("folder", "Ordner im Login-Verzeichnis auflisten ...")
        home = runner.run("ls -1Ap 2>/dev/null | grep '/$' | head -60", left(10))
        info["folders"] = [x.rstrip("/") for x in lines_of(home.out)]

        step("joomla", "Joomla, WordPress, Drupal, TYPO3 oder Contao erkennen ...")
        res = runner.sh(site_dir, r"""
echo '@@VERSION'; head -c 8000 libraries/src/Version.php 2>/dev/null
echo '@@MANIFEST'; head -c 4000 administrator/manifests/files/joomla.xml 2>/dev/null
echo '@@CONFIG'; test -f configuration.php && echo ja || echo nein
echo '@@WPVER'; head -c 4000 wp-includes/version.php 2>/dev/null
echo '@@WPCONF'; if test -f wp-config.php; then echo ja; elif test -f ../wp-config.php; then echo ja-oben; else echo nein; fi
echo '@@DRUPAL'; head -c 6000 core/lib/Drupal.php 2>/dev/null
echo '@@DRUPAL7'; head -c 6000 includes/bootstrap.inc 2>/dev/null
echo '@@DRUPALCONF'; test -f sites/default/settings.php && echo ja || echo nein
echo '@@TYPO3VER'; for f in %s; do if [ -f "$f" ]; then head -c 6000 "$f"; break; fi; done
echo '@@TYPO3OLD'; grep -hm1 "TYPO3_version'" %s 2>/dev/null
echo '@@TYPO3CONF'; for f in %s; do if [ -f "$f" ]; then echo ja; break; fi; done
echo '@@TYPO3MODE'; if [ -d vendor/typo3 ] || [ -d ../vendor/typo3 ]; then echo composer; else echo classic; fi
echo '@@CONTAOCONF'; if [ -d vendor/contao/core-bundle ] || [ -d ../vendor/contao/core-bundle ]; then echo ja; fi
echo '@@CONTAOVER'; for f in composer.lock ../composer.lock; do if [ -f "$f" ]; then grep -m1 -A12 '"name": "contao/core-bundle"' "$f"; break; fi; done
echo '@@CONTAOLEG'; head -c 6000 system/modules/core/config/config.php 2>/dev/null
echo '@@WHO'; whoami; pwd
""" % (" ".join(typo3.VERSION_FILES), typo3.OLD_VERSION_FILE, " ".join(typo3.CONFIG_FILES)), left(12))
        if res.rc == 97:
            info["error"] = "Das Verzeichnis '%s' existiert nicht im Login-Verzeichnis des Servers." % site_dir
        else:
            sec = split_sections(res.out)
            info["site_found"] = True
            info["joomla"] = joomla.parse_joomla_version(sec.get("VERSION", ""), sec.get("MANIFEST", ""))
            info["config"] = "ja" in sec.get("CONFIG", "")
            wpv = wordpress.parse_wp_version(sec.get("WPVER", ""))
            wpconf = "ja" in sec.get("WPCONF", "")
            info["wordpress"] = wpv["version"]
            info["wp_config"] = wpconf
            dv = drupal.parse_drupal_version(sec.get("DRUPAL", ""), sec.get("DRUPAL7", ""))
            info["drupal"] = dv
            info["drupal_config"] = "ja" in sec.get("DRUPALCONF", "")
            tv = typo3.parse_typo3_version(sec.get("TYPO3VER", ""), sec.get("TYPO3OLD", ""))
            info["typo3"] = tv
            info["typo3_config"] = "ja" in sec.get("TYPO3CONF", "")
            info["typo3_mode"] = (sec.get("TYPO3MODE", "").split() or [""])[0] if (tv or info["typo3_config"]) else ""
            info["contao_config"] = "ja" in sec.get("CONTAOCONF", "")
            info["contao"] = contao.parse_core_version(sec.get("CONTAOVER", ""), "", sec.get("CONTAOLEG", ""))
            if info["joomla"]:
                info["cms"] = "joomla"
            elif wpv["version"] or wpconf:
                info["cms"] = "wordpress"
            elif dv or info["drupal_config"]:
                info["cms"] = "drupal"
            elif tv or info["typo3_config"]:
                info["cms"] = "typo3"
            elif info["contao"] or info["contao_config"]:
                info["cms"] = "contao"
            else:
                info["cms"] = "joomla"    # unbekannt: Standardbereich anzeigen
            who = lines_of(sec.get("WHO", ""))
            info["who"] = who[0] if who else ""
            info["pwd"] = who[1] if len(who) > 1 else ""

        step("db", "Datenbank-Programm (mysql/mariadb) suchen ...")
        dbr = runner.run("command -v mysql || command -v mariadb", left(10))
        paths = lines_of(dbr.out)
        info["mysql"] = bool(paths)
        info["mysql_path"] = paths[0] if paths else ""

        step("php", "PHP-Version ermitteln (höchstens 15 Sekunden) ...")
        pr = runner.sh(site_dir if info["site_found"] else ".", PHP_PROBE_SCRIPT, left(25))
        info.update(parse_php_probe(pr.out))
        if pr.timed_out and not info["php"]:
            info["php_note"] = "Die Abfrage der PHP-Version hat zu lange gedauert und wurde abgebrochen."
    except RunnerError as e:
        info["error"] = str(e)
    return info
