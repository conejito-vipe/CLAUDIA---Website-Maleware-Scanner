"""WordPress-spezifisches Parsen: wp-config.php, Versionsdatei, Plugin- und Theme-Köpfe."""
from __future__ import annotations

import re
from typing import Any, Dict, List

_DEFINE_RE = re.compile(r"""define\s*\(\s*(['"])(\w+)\1\s*,\s*(.*?)\s*\)\s*;""")
_PREFIX_RE = re.compile(r"""^\s*\$table_prefix\s*=\s*(['"])(.*?)\1\s*;""", re.MULTILINE)
SECRET_KEYS = ("AUTH_KEY", "SECURE_AUTH_KEY", "LOGGED_IN_KEY", "NONCE_KEY",
               "AUTH_SALT", "SECURE_AUTH_SALT", "LOGGED_IN_SALT", "NONCE_SALT")
SUSPICIOUS_RE = re.compile(r"eval\s*\(|base64_decode|gzinflate|str_rot13|assert\s*\(|\$_(GET|POST|REQUEST|COOKIE|SERVER)\b|"
                           r"(file_get_contents|curl_exec|fsockopen)\s*\(|preg_replace\s*\(.*/e|\bsystem\s*\(|passthru|shell_exec|popen\s*\(", re.IGNORECASE)


def _val(raw: str) -> Any:
    raw = raw.strip()
    if len(raw) >= 2 and raw[0] in "'\"" and raw[-1] == raw[0]:
        return raw[1:-1].replace("\\'", "'").replace('\\"', '"').replace("\\\\", "\\")
    low = raw.lower()
    if low == "true":
        return True
    if low == "false":
        return False
    if re.fullmatch(r"-?\d+", raw):
        return int(raw)
    return raw


def parse_wp_config(text: str) -> Dict[str, Any]:
    """Liest define()-Zeilen und $table_prefix. Rückgabe wie joomla.parse_config, damit die Datenbank-Anbindung gleich bleibt."""
    defines: Dict[str, Any] = {}
    for m in _DEFINE_RE.finditer(text):
        defines.setdefault(m.group(2), _val(m.group(3)))
    pm = _PREFIX_RE.search(text)
    prefix = pm.group(2) if pm else "wp_"
    vars_ = {"host": defines.get("DB_HOST", "localhost"), "user": defines.get("DB_USER", ""),
             "password": defines.get("DB_PASSWORD", ""), "db": defines.get("DB_NAME", ""),
             "dbprefix": prefix, "dbtype": "mysqli"}
    unexpected = []
    in_block = False
    for no, line in enumerate(text.splitlines(), 1):
        s = line.strip()
        if in_block:
            in_block = "*/" not in s
            continue
        if s.startswith("/*"):
            in_block = "*/" not in s
            continue
        if not s or s.startswith(("//", "#", "*")):
            continue
        if SUSPICIOUS_RE.search(s) and not _DEFINE_RE.search(s):
            unexpected.append((no, s[:300]))
    return {"vars": vars_, "defines": defines, "prefix": prefix, "unexpected": unexpected,
            "size": len(text.encode("utf-8", "replace")), "lines": len(text.splitlines())}


def parse_wp_version(version_php: str) -> Dict[str, str]:
    out = {"version": "", "db_version": "", "required_php": "", "required_mysql": ""}
    for key, name in (("version", "wp_version"), ("db_version", "wp_db_version"),
                      ("required_php", "required_php_version"), ("required_mysql", "required_mysql_version")):
        m = re.search(r"\$%s\s*=\s*['\"]?([\w.\-]+)['\"]?\s*;" % name, version_php)
        if m:
            out[key] = m.group(1)
    return out


_HEAD_KEYS = {"plugin name": "name", "theme name": "name", "version": "version", "author": "author", "plugin uri": "uri",
              "theme uri": "uri", "requires php": "requires_php", "requires at least": "requires_wp", "text domain": "domain",
              "update uri": "update_uri", "template": "template"}


def parse_wp_header(text: str) -> Dict[str, str]:
    """Liest den Kommentarkopf einer Plugin-Hauptdatei oder einer style.css. Leer = kein Kopf (kein Plugin/Theme)."""
    out: Dict[str, str] = {}
    head = text[:8192]
    for line in head.splitlines():
        m = re.match(r"^[\s*#/@]*([A-Za-z][A-Za-z ]{2,20}):\s*(.+?)\s*(?:\*/)?\s*\Z", line)
        if m:
            key = _HEAD_KEYS.get(m.group(1).strip().lower())
            if key and key not in out:
                out[key] = m.group(2).strip()
    return out if out.get("name") else {}


def version_tuple(v: str) -> List[int]:
    return [int(x) for x in re.findall(r"\d+", v or "")][:4]
