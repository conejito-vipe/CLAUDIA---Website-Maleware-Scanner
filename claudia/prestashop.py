"""PrestaShop (seit 2.12.0): Version, Einstellungsdateien und Support-Stand lesen. Reine Funktionen ohne Serverzugriff (mit Beispieltexten prüfbar).

Unterstützt werden PrestaShop 1.7, 8 und 9 (app/config/parameters.php) sowie 1.6 (config/settings.inc.php). Maßgeblich für die Datenbank-Anbindung sind diese Dateien; sie werden nur als Text gelesen, nie ausgeführt.
Passwörter, cookie_key und secret werden nie ausgegeben (vom Schlüssel nur die Länge)."""
from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple

from . import drupal
from .contao import parse_release_list  # gleiche Packagist-Antwort (Liste stabiler x.y.z-Versionen)
from .typo3 import DANGEROUS, advisories_for, affected, cycle, norm_version, parse_advisories, parse_php_array, strip_comments, version_key, Expr

__all__ = ["advisories_for", "affected", "parse_advisories", "norm_version", "parse_release_list"]

PARAMS_FILE = "app/config/parameters.php"
DEFINES_FILE = "config/defines.inc.php"
SETTINGS16_FILE = "config/settings.inc.php"
KERNEL_FILE = "app/AppKernel.php"
INSTALL_VERSION_FILE = "install/install_version.php"
CORE_DIRS = ("classes", "controllers", "src")                     # werden mit dem Original verglichen
VERSION_RE = re.compile(r"\b(?:const\s+VERSION|_PS_VERSION_|_PS_INSTALL_VERSION_)\b['\"]?\s*[,=]\s*['\"]([0-9][0-9A-Za-z.\-]*)['\"]")

# Phasen je Version "Haupt.Neben". Das Projekt nennt keine festen Daten, sondern Regeln (Stand 2026-11, prestashop-project.org):
# aktuell: Fehlerkorrekturen und Sicherheitsupdates; 'security': nur noch kritische Fehler und Sicherheitsupdates (erweiterte Unterstützung, endet mit dem Erscheinen der nächsten Hauptversion); 'ended': keine Updates.
LIFECYCLE: Dict[str, str] = {"9.1": "supported", "9.0": "security", "8.2": "security", "8.1": "ended", "8.0": "ended"}
LIFECYCLE_ASOF = "2026-11"

major = drupal.major


def lifecycle(version: str) -> Dict[str, str]:
    """state: 'supported', 'security' (nur noch kritische Fehler und Sicherheit), 'ended', 'unknown'."""
    c = cycle(version)
    key = "%d.%d" % c
    if c == (0, 0):
        return {"state": "unknown", "cycle": ""}
    if key in LIFECYCLE:
        return {"state": LIFECYCLE[key], "cycle": key}
    return {"state": "ended" if c < (8, 0) else "unknown", "cycle": key}


def parse_core_version(kernel_php: str = "", install_php: str = "", settings16: str = "") -> str:
    """Version aus app/AppKernel.php (const VERSION), install/install_version.php oder (1.6) config/settings.inc.php; leer, wenn nicht erkannt."""
    for t in (kernel_php, settings16, install_php):
        m = VERSION_RE.search(t or "")
        if m:
            return m.group(1)
    return ""


def _define(text: str, name: str) -> str:
    m = re.search(r"define\(\s*['\"]%s['\"]\s*,\s*(?:'([^']*)'|\"([^\"]*)\"|([A-Za-z0-9_]+))\s*\)" % re.escape(name), strip_comments(text or ""))
    return (m.group(1) or m.group(2) or m.group(3) or "") if m else ""


def parse_settings(params_php: str, defines_php: str = "", settings16: str = "", extra: str = "") -> Dict[str, Any]:
    """Datenbank-Angaben und wichtige Einstellungen. Rückgabe passt zur Datenbank-Anbindung (vars wie bei den anderen Systemen).
    'extra': weitere Konfigurationsdateien, die nur auf auffällige Befehle gelesen werden."""
    arr = parse_php_array(params_php) or {}
    p = arr.get("parameters") if isinstance(arr.get("parameters"), dict) else {}

    def sv(k: str) -> str:
        v = p.get(k)
        return "" if v is None or isinstance(v, (dict, Expr)) else str(v)

    host = sv("database_host")
    port = sv("database_port")
    user, pw, db, prefix = sv("database_user"), sv("database_password"), sv("database_name"), sv("database_prefix")
    cookie = sv("cookie_key")
    secret = sv("secret")
    if not db and settings16:
        host, user, pw, db = _define(settings16, "_DB_SERVER_"), _define(settings16, "_DB_USER_"), _define(settings16, "_DB_PASSWD_"), _define(settings16, "_DB_NAME_")
        prefix = _define(settings16, "_DB_PREFIX_")
        cookie = _define(settings16, "_COOKIE_KEY_")
        port = ""
    if host and port and ":" not in host and port not in ("", "0"):
        host = "%s:%s" % (host, port)
    host = host or ("localhost" if db else "")
    dev = _define(defines_php, "_PS_MODE_DEV_").lower()
    unexpected: List[Tuple[int, str]] = []
    for label, body in (("parameters.php: ", params_php), ("defines.inc.php: ", defines_php), ("settings.inc.php: ", settings16), ("", extra)):
        for no, line in enumerate(strip_comments(body or "").splitlines(), 1):
            s = line.strip()
            if s and DANGEROUS.search(s):
                unexpected.append((no, label + s[:300]))
    parsed = bool(arr) or bool(db)
    return {"vars": {"host": host, "user": user, "password": pw, "db": db, "dbprefix": prefix or "ps_", "dbtype": "mysqli"},
            "prestashop": {"dev_mode": dev in ("true", "1"), "dev_known": bool(dev), "cookie_len": len(cookie), "has_cookie": bool(cookie), "secret_len": len(secret), "has_secret": bool(secret),
                           "caching": sv("ps_caching"), "legacy": bool(settings16 and not arr)},
            "prefix": prefix or "ps_", "unexpected": unexpected, "parsed": parsed,
            "files": [f for f, t in ((PARAMS_FILE, params_php), (DEFINES_FILE, defines_php), (SETTINGS16_FILE, settings16)) if (t or "").strip()],
            "size": len((params_php or "").encode("utf-8", "replace")) + len((settings16 or "").encode("utf-8", "replace")), "lines": 0}


def read_config_sh() -> str:
    """Shell-Text: gibt die Dateien mit Kopfzeilen '@@F <Pfad>' aus (Parameter, Defines, 1.6-Einstellungen, AppKernel, Installer-Version) und danach '@@DIRS <Ordnernamen>' der Ebene (admin*, install*)."""
    files = (PARAMS_FILE, DEFINES_FILE, SETTINGS16_FILE, KERNEL_FILE, INSTALL_VERSION_FILE)
    return (" ".join('if [ -f %s ]; then echo "@@F %s"; head -c 60000 %s; echo; fi;' % (f, f, f) for f in files)
            + ' echo "@@DIRS"; ls -d admin* install* 2>/dev/null | head -20')


def split_config_output(out: str) -> Dict[str, Any]:
    """{'files': {Pfad: Text}, 'dirs': [Ordnernamen]}."""
    res: Dict[str, Any] = {"files": {}, "dirs": []}
    head, _, dirs = ("\n" + (out or "")).partition("\n@@DIRS")
    res["dirs"] = [d.strip().rstrip("/") for d in dirs.splitlines() if d.strip()]
    marks = list(re.finditer(r"^@@F (.+)$", head, re.M))
    for i, m in enumerate(marks):
        end = marks[i + 1].start() if i + 1 < len(marks) else len(head)
        res["files"][m.group(1).strip()] = head[m.end() + 1:end]
    return res
