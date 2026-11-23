"""Drupal: Version, settings.php und Erweiterungs-Kennzeichen lesen. Reine Funktionen ohne Serverzugriff (mit Beispieltexten prüfbar).

Unterstützt wird Drupal 8 und neuer (Datei core/lib/Drupal.php). Drupal 7 (includes/bootstrap.inc) wird nur erkannt."""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

VERSION_D8 = re.compile(r"const\s+VERSION\s*=\s*['\"]([0-9][0-9A-Za-z.\-]*)['\"]")
VERSION_D7 = re.compile(r"define\(\s*['\"]VERSION['\"]\s*,\s*['\"]([0-9][0-9A-Za-z.\-]*)['\"]")


def parse_drupal_version(drupal_php: str, bootstrap_inc: str = "") -> str:
    """Version aus core/lib/Drupal.php (ab Drupal 8) oder includes/bootstrap.inc (Drupal 7); leer, wenn nicht erkannt."""
    m = VERSION_D8.search(drupal_php or "")
    if m:
        return m.group(1)
    m = VERSION_D7.search(bootstrap_inc or "")
    return m.group(1) if m else ""


def major(version: str) -> int:
    m = re.match(r"(\d+)", version or "")
    return int(m.group(1)) if m else 0


def version_key(version: str) -> Tuple[int, ...]:
    """Sortierbarer Schlüssel ('10.3.1' -> (10, 3, 1)); Vorabversionen (-rc1, -dev) zählen kleiner als die Hauptversion."""
    m = re.match(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?(-[A-Za-z0-9.]+)?", version or "")
    if not m:
        return (0, 0, 0, 0)
    return (int(m.group(1)), int(m.group(2) or 0), int(m.group(3) or 0), 0 if m.group(4) else 1)


# ------------------------------------------------------------------ settings.php
_DB_FIELDS = ("database", "username", "password", "host", "port", "driver", "prefix", "unix_socket")


def _unq(v: str) -> str:
    v = v.strip().rstrip(",").strip()
    if len(v) >= 2 and v[0] in "'\"" and v[-1] == v[0]:
        return v[1:-1].replace("\\'", "'").replace('\\"', '"').replace("\\\\", "\\")
    return v


def _strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", lambda m: "\n" * m.group(0).count("\n"), text, flags=re.S)
    return "\n".join(l for l in text.splitlines() if not l.lstrip().startswith(("//", "#")))


def parse_settings(text: str) -> Dict[str, Any]:
    """Liest die Datenbank-Angaben und wichtige Einstellungen aus settings.php. Rückgabe wie joomla.parse_config, damit die Datenbank-Anbindung gleich bleibt.

    Gelesen werden nur einfache Zuweisungen ($databases['default']['default'] = [...]; $settings['x'] = ...). Alles andere (Umgebungsvariablen, include-Dateien)
    bleibt unbekannt; dann fehlen die Felder, und die Datenbank-Prüfungen melden das, statt zu raten."""
    code = _strip_comments(text or "")
    db: Dict[str, str] = {}
    m = re.search(r"\$databases\s*\[\s*['\"]default['\"]\s*\]\s*\[\s*['\"]default['\"]\s*\]\s*=\s*(?:array\s*\(|\[)(.*?)\n\s*(?:\)|\])\s*;", code, re.S)
    if m:
        for k, v in re.findall(r"['\"](\w+)['\"]\s*=>\s*((?:'(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\"|[^,\n]+))", m.group(1)):
            if k in _DB_FIELDS:
                db[k] = _unq(v)
    else:      # Schreibweise $databases['default']['default']['host'] = 'x';
        for k, v in re.findall(r"\$databases\s*\[\s*['\"]default['\"]\s*\]\s*\[\s*['\"]default['\"]\s*\]\s*\[\s*['\"](\w+)['\"]\s*\]\s*=\s*((?:'(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\"|[^;\n]+))\s*;", code):
            if k in _DB_FIELDS:
                db[k] = _unq(v)
    host = db.get("host", "localhost")
    if db.get("port"):
        host = "%s:%s" % (host, db["port"])
    elif db.get("unix_socket"):
        host = "%s:%s" % (host or "localhost", db["unix_socket"])
    drv = db.get("driver", "mysql")
    vars_ = {"host": host, "user": db.get("username", ""), "password": db.get("password", ""), "db": db.get("database", ""),
             "dbprefix": db.get("prefix", "") if isinstance(db.get("prefix", ""), str) else "", "dbtype": "mysqli" if "mysql" in drv else drv}
    settings: Dict[str, str] = {}
    for k, v in re.findall(r"\$settings\s*\[\s*['\"](\w+)['\"]\s*\]\s*=\s*((?:'(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\"|[^;\n]+))\s*;", code):
        settings[k] = _unq(v)
    unexpected: List[Tuple[int, str]] = []
    for no, line in enumerate((text or "").splitlines(), 1):
        s = line.strip()
        if s and not s.startswith(("//", "#", "*", "/*")) and re.search(r"\b(eval|base64_decode|gzinflate|str_rot13|assert|system|shell_exec|passthru|exec)\s*\(", s):
            unexpected.append((no, s[:300]))
    return {"vars": vars_, "settings": settings, "prefix": vars_["dbprefix"], "unexpected": unexpected, "trusted_hosts": "trusted_host_patterns" in code,
            "size": len((text or "").encode("utf-8", "replace")), "lines": len((text or "").splitlines())}


# ------------------------------------------------------------------ .info.yml
def parse_info_yml(text: str) -> Dict[str, str]:
    """Liest die einfachen Schlüssel einer *.info.yml (name, type, version, core_version_requirement, project, package)."""
    out: Dict[str, str] = {}
    for line in (text or "").splitlines():
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.*?)\s*\Z", line)
        if m and m.group(1) in ("name", "type", "version", "core_version_requirement", "core", "project", "package", "description", "lifecycle", "hidden"):
            out.setdefault(m.group(1), _unq(re.sub(r"\s+#.*$", "", m.group(2))))
    return out


def project_of(folder: str) -> Optional[str]:
    """Projektname aus dem Ordnerpfad (modules/contrib/pathauto -> pathauto)."""
    m = re.match(r"^\.?/?(?:modules|themes|profiles)/(?:(?:contrib|custom)/)?([^/]+)", folder.strip())
    return m.group(1) if m else None
