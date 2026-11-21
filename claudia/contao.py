"""Contao (seit 2.11.0): Version, Umgebungs- und Einstellungsdateien, Pakete und Sicherheitsmeldungen lesen. Reine Funktionen ohne Serverzugriff (mit Beispieltexten prüfbar).

Unterstützt werden Contao 4.13 und neuer (Composer-Installation mit vendor/contao/core-bundle). Ältere Versionen (Contao 3) werden erkannt und als nicht mehr unterstützt gemeldet.
Zugangsdaten, APP_SECRET, Mail-DSN und Passwörter werden nie ausgegeben; die Dateien werden nur als Text gelesen und nie ausgeführt."""
from __future__ import annotations

import json
import re
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import unquote, urlsplit

from . import drupal
from .typo3 import DANGEROUS, advisories_for, affected, norm_version, parse_advisories, strip_comments  # gleiche Composer- und Packagist-Regeln wie bei TYPO3

__all__ = ["advisories_for", "affected", "parse_advisories", "norm_version"]

CORE_PACKAGES = ("contao/core-bundle", "contao/manager-bundle", "contao/installation-bundle")      # werden mit dem Original verglichen
ENV_FILES = (".env", ".env.local", ".env.prod", ".env.prod.local")                                   # spätere Dateien überschreiben frühere (Symfony-Reihenfolge)
YAML_FILES = ("config/parameters.yaml", "config/config.yaml", "config/parameters.yml", "config/config.yml", "app/config/parameters.yml", "app/config/config.yml")
LOCAL_FILES = ("system/config/localconfig.php",)
LEGACY_VERSION_FILE = "system/modules/core/config/config.php"       # Contao 3: define('VERSION', '3.5'); define('BUILD', '40');

# Laufzeiten je Version "Haupt.Neben": (Ende der Fehlerkorrekturen, Ende der Sicherheitsupdates). Stand: 2026-11, Quelle: endoflife.date/contao (contao.org war nicht abrufbar).
# Eine Version unterhalb von 5.3 gilt als beendet; eine Version, die hier fehlt und neuer ist, ist unbekannt (keine Aussage).
LIFECYCLE: Dict[str, Tuple[str, str]] = {
    "4.13": ("2025-02-14", "2026-02-14"),
    "5.3": ("2027-02-14", "2028-02-14"),
    "5.6": ("2026-02-14", "2026-02-14"),
    "5.7": ("2029-02-14", "2030-02-14"),
    "6.0": ("2027-02-14", "2027-02-14"),
}
LIFECYCLE_ASOF = "2026-11"
LIFECYCLE_MIN = (5, 3)

major = drupal.major
version_key = drupal.version_key


def cycle(version: str) -> Tuple[int, int]:
    m = re.match(r"^(\d+)\.(\d+)", norm_version(version))
    return (int(m.group(1)), int(m.group(2))) if m else (0, 0)


def _day(s: str) -> float:
    return time.mktime(time.strptime(s, "%Y-%m-%d"))


def lifecycle(version: str, now: Optional[float] = None) -> Dict[str, Any]:
    """Stand der Unterstützung. state: 'supported' (Fehlerkorrekturen und Sicherheitsupdates), 'security' (nur noch Sicherheitsupdates), 'ended', 'unknown'."""
    now = now or time.time()
    c = cycle(version)
    key = "%d.%d" % c
    if c == (0, 0):
        return {"state": "unknown", "cycle": "", "bugfix_until": "", "security_until": "", "days_left": None}
    if key not in LIFECYCLE:
        return {"state": "ended" if c < LIFECYCLE_MIN and c[0] >= 3 else "unknown", "cycle": key, "bugfix_until": "", "security_until": "", "days_left": None}
    bug, sec = LIFECYCLE[key]
    end_sec = _day(sec) + 86400
    if now > end_sec:
        st = "ended"
    elif now > _day(bug) + 86400:
        st = "security"
    else:
        st = "supported"
    return {"state": st, "cycle": key, "bugfix_until": bug, "security_until": sec, "days_left": int((end_sec - now) // 86400) if st != "ended" else None}


# ------------------------------------------------------------------ Version und Pakete (composer.lock, installed.php)
def parse_core_version(lock_text: str, installed_php: str = "", legacy_php: str = "") -> str:
    """Version von contao/core-bundle aus composer.lock oder vendor/composer/installed.php; leer, wenn nicht erkannt. legacy_php: Contao 3 (define VERSION/BUILD)."""
    m = re.search(r'"name"\s*:\s*"contao/core-bundle"\s*,(?:(?!"name").){0,1500}?"version"\s*:\s*"v?([0-9][0-9A-Za-z.\-]*)"', lock_text or "", re.S)
    if m:
        return m.group(1)
    m = re.search(r"'contao/core-bundle'\s*=>\s*(?:array\s*)?\(?\s*\[?\s*'pretty_version'\s*=>\s*'v?([0-9][0-9A-Za-z.\-]*)'", installed_php or "", re.S)
    if m:
        return m.group(1)
    v = re.search(r"define\(\s*['\"]VERSION['\"]\s*,\s*['\"]([0-9][0-9.]*)['\"]", legacy_php or "")
    b = re.search(r"define\(\s*['\"]BUILD['\"]\s*,\s*['\"]([0-9]+)['\"]", legacy_php or "")
    if v:
        return "%s.%s" % (v.group(1), b.group(1)) if b else v.group(1)
    return ""


def parse_lock(text: str) -> List[Dict[str, Any]]:
    """Pakete aus composer.lock (nur 'packages', nicht 'packages-dev'): [{'name','version','type','custom'(bool),'ref'}]. Leer bei unlesbarem Text."""
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return []
    out: List[Dict[str, Any]] = []
    for p in (data.get("packages") if isinstance(data, dict) else None) or []:
        if isinstance(p, dict) and isinstance(p.get("name"), str):
            dist = p.get("dist") if isinstance(p.get("dist"), dict) else {}
            out.append({"name": p["name"], "version": norm_version(str(p.get("version") or "")), "type": str(p.get("type") or ""),
                        "custom": dist.get("type") == "path", "ref": str(dist.get("reference") or "")[:60]})
    return out


# ------------------------------------------------------------------ Umgebungsdateien (.env) und YAML
SAFE_ENV = ("APP_ENV", "APP_DEBUG", "TRUSTED_HOSTS", "TRUSTED_PROXIES")     # nur diese Werte werden weitergegeben


def parse_env(text: str) -> Dict[str, str]:
    """KEY=Wert-Zeilen einer .env-Datei (Kommentare, 'export ', Anführungszeichen). Rückgabe enthält ALLE Schlüssel; Geheimnisse gehören nicht in Ergebnisse (siehe parse_settings)."""
    out: Dict[str, str] = {}
    for line in (text or "").splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        s = re.sub(r"^export\s+", "", s)
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$", s)
        if not m:
            continue
        v = m.group(2).strip()
        if v and v[0] in "'\"" and v.find(v[0], 1) > 0:
            v = v[1:v.find(v[0], 1)]
        else:
            v = re.split(r"\s+#", v, maxsplit=1)[0].strip()
        out[m.group(1)] = v
    return out


def parse_yaml_flat(text: str) -> Dict[str, str]:
    """Einfaches YAML (verschachtelte Schlüssel, Werte als Text) -> {'a.b.c': 'wert'}. Listen, Anker und mehrzeilige Werte werden übersprungen. Kein vollständiger YAML-Leser."""
    out: Dict[str, str] = {}
    stack: List[Tuple[int, str]] = []
    for raw in (text or "").splitlines()[:5000]:
        if not raw.strip() or raw.lstrip().startswith(("#", "-", "---")):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        m = re.match(r"^\s*([^:#\s][^:]*?)\s*:(?:\s+(.*))?$", raw)
        if not m:
            continue
        while stack and stack[-1][0] >= indent:
            stack.pop()
        key = m.group(1).strip().strip("'\"")
        val = (m.group(2) or "").strip()
        if val and val[0] in "'\"" and val.find(val[0], 1) > 0:
            val = val[1:val.find(val[0], 1)]
        else:
            val = re.split(r"\s+#", val, maxsplit=1)[0].strip()
        path = ".".join([k for _, k in stack] + [key])
        if val == "" or val in ("|", ">"):
            stack.append((indent, key))
        else:
            out[path] = val
    return out


def parse_database_url(url: str) -> Dict[str, str]:
    """mysql://benutzer:passwort@host:3306/datenbank?... -> host, user, password, db. Leer, wenn die Angabe ein Platzhalter (%env(...)%) oder unlesbar ist."""
    u = (url or "").strip()
    if not re.match(r"^[a-z0-9+]+://", u, re.I) or "%env(" in u or "${" in u:
        return {}
    try:
        p = urlsplit(u)
        host = p.hostname or ""
        port = p.port
    except ValueError:
        return {}
    q = dict(x.split("=", 1) for x in (p.query or "").split("&") if "=" in x)
    sock = unquote(q.get("unix_socket", ""))
    h = "%s:%s" % (host or "localhost", port) if port else (host or "localhost")
    if sock:
        h = "%s:%s" % (host or "localhost", sock)
    return {"host": h, "user": unquote(p.username or ""), "password": unquote(p.password or ""), "db": unquote((p.path or "").lstrip("/")), "driver": p.scheme.lower()}


PLACEHOLDER_SECRETS = ("ThisTokenIsNotSoSecretChangeIt", "ThisTokenIsNotSoSecret", "changeme", "change_me", "secret", "ChangeThisToken")
SECRET_KEY_RE = re.compile(r"(pass|secret|dsn|url|token|key)", re.I)


def parse_localconfig(text: str) -> Dict[str, str]:
    """$GLOBALS['TL_CONFIG']['name'] = Wert; (einfache Werte) aus system/config/localconfig.php."""
    out: Dict[str, str] = {}
    for m in re.finditer(r"\$GLOBALS\[\s*['\"]TL_CONFIG['\"]\s*\]\[\s*['\"]([A-Za-z0-9_]+)['\"]\s*\]\s*=\s*(.+?);\s*$", strip_comments(text or ""), re.M):
        v = m.group(2).strip()
        if v and v[0] in "'\"" and v.rfind(v[0]) > 0:
            out[m.group(1)] = v[1:v.rfind(v[0])]
        elif re.fullmatch(r"-?\d+|true|false|TRUE|FALSE", v):
            out[m.group(1)] = v.lower()
    return {k: v for k, v in out.items() if not SECRET_KEY_RE.search(k) or k.endswith("Length")}


def parse_settings(env_files: List[Tuple[str, str]], yaml_files: List[Tuple[str, str]], local_files: List[Tuple[str, str]]) -> Dict[str, Any]:
    """Liest Datenbank-Angaben und die wichtigen Einstellungen. Rückgabe passt zur Datenbank-Anbindung (vars wie bei den anderen Systemen).

    Ergebnis ohne Geheimnisse: Passwörter und APP_SECRET stehen nur in 'vars' (für die Datenbank-Anbindung, wird nie angezeigt) bzw. als Länge."""
    env: Dict[str, str] = {}
    for _, t in env_files:
        env.update(parse_env(t))
    flat: Dict[str, str] = {}
    for _, t in yaml_files:
        flat.update(parse_yaml_flat(t))
    dbu = env.get("DATABASE_URL") or flat.get("parameters.env(DATABASE_URL)") or flat.get("parameters.database_url") or ""
    db = parse_database_url(dbu)
    if not db and flat.get("parameters.database_name"):
        host = flat.get("parameters.database_host") or "localhost"
        if flat.get("parameters.database_port") and flat["parameters.database_port"] != "null":
            host = "%s:%s" % (host, flat["parameters.database_port"])
        db = {"host": host, "user": flat.get("parameters.database_user", ""), "password": flat.get("parameters.database_password", ""), "db": flat["parameters.database_name"], "driver": "mysql"}
    secret = env.get("APP_SECRET") or flat.get("parameters.env(APP_SECRET)") or flat.get("parameters.secret") or ""
    local: Dict[str, str] = {}
    unexpected: List[Tuple[int, str]] = []
    for path, t in local_files:
        local.update(parse_localconfig(t))
        for no, line in enumerate(strip_comments(t).splitlines(), 1):
            s = line.strip()
            if s and DANGEROUS.search(s):
                unexpected.append((no, "%s: %s" % (path.rsplit("/", 1)[-1], s[:300])))
    safe_yaml = {k: v for k, v in flat.items() if not SECRET_KEY_RE.search(k)}
    return {"vars": {"host": db.get("host", ""), "user": db.get("user", ""), "password": db.get("password", ""), "db": db.get("db", ""), "dbprefix": "",
                     "dbtype": "mysqli" if "mysql" in db.get("driver", "mysql") else db.get("driver", "")},
            "contao": {"env": {k: env[k] for k in SAFE_ENV if k in env}, "yaml": safe_yaml, "local": local,
                       "has_secret": bool(secret), "secret_len": len(secret), "secret_placeholder": any(p.lower() in secret.lower() for p in PLACEHOLDER_SECRETS) if secret else False},
            "prefix": "", "unexpected": unexpected, "parsed": bool(env or flat or local_files),
            "files": [p for p, _ in list(env_files) + list(yaml_files) + list(local_files)],
            "size": sum(len(t) for _, t in list(env_files) + list(yaml_files) + list(local_files)), "lines": 0}


# ------------------------------------------------------------------ Veröffentlichte Versionen (Packagist)
def parse_release_list(text: Any) -> List[Dict[str, str]]:
    """Alle stabilen Versionen (x.y.z) aus der Packagist-Antwort zu contao/core-bundle (beide Aufbauten: 'packages' als Liste oder 'package.versions' als Wörterbuch). Noch nicht gegen die echte Antwort geprüft."""
    if not isinstance(text, str) or not text.strip() or len(text) > 8_000_000:
        return []
    try:
        data = json.loads(text)
    except ValueError:
        return []
    out: Dict[str, Dict[str, str]] = {}

    def walk(o: Any, depth: int = 0) -> None:
        if depth > 8:
            return
        if isinstance(o, dict):
            v = o.get("version")
            if isinstance(v, str) and re.fullmatch(r"v?\d+\.\d+\.\d+", v):
                n = norm_version(v)
                out.setdefault(n, {"version": n, "date": str(o.get("time") or "")[:10]})
            for k, x in o.items():
                if isinstance(x, (dict, list)):
                    walk(x, depth + 1)
                elif isinstance(k, str) and re.fullmatch(r"v?\d+\.\d+\.\d+", k):
                    out.setdefault(norm_version(k), {"version": norm_version(k), "date": ""})
        elif isinstance(o, list):
            for x in o:
                walk(x, depth + 1)

    walk(data)
    return sorted(out.values(), key=lambda r: version_key(r["version"]))


# ------------------------------------------------------------------ Dateien auf dem Server lesen
def read_config_sh() -> str:
    """Shell-Text: findet das Projektverzeichnis (Seitenordner oder eine Ebene darüber, falls public/ gewählt wurde) und gibt .env-, YAML- und localconfig-Dateien
    mit Kopfzeilen '@@ENV <Pfad>', '@@YAML <Pfad>', '@@LOCAL <Pfad>' aus."""
    return ('R=.; if [ ! -d vendor/contao ] && [ -d ../vendor/contao ]; then R=..; fi; echo "@@ROOT $R"; '
            'for f in %s; do if [ -f "$R/$f" ]; then echo "@@ENV $R/$f"; head -c 20000 "$R/$f"; echo; fi; done; '
            'for f in %s; do if [ -f "$R/$f" ]; then echo "@@YAML $R/$f"; head -c 60000 "$R/$f"; echo; fi; done; '
            'for f in %s; do if [ -f "$R/$f" ]; then echo "@@LOCAL $R/$f"; head -c 100000 "$R/$f"; echo; fi; done'
            % (" ".join(ENV_FILES), " ".join(YAML_FILES), " ".join(LOCAL_FILES)))


def split_config_output(out: str) -> Dict[str, Any]:
    """Zerlegt die Ausgabe von read_config_sh in {'root','env':[(Pfad,Text)],'yaml':[...],'local':[...]}; Pfade ohne führendes './'."""
    res: Dict[str, Any] = {"root": ".", "env": [], "yaml": [], "local": []}
    marks = list(re.finditer(r"^@@(ROOT|ENV|YAML|LOCAL) ?(.*)$", out or "", re.M))
    for i, m in enumerate(marks):
        end = marks[i + 1].start() if i + 1 < len(marks) else len(out)
        kind, arg = m.group(1), m.group(2).strip()
        if kind == "ROOT":
            res["root"] = arg or "."
        else:
            res[kind.lower()].append((re.sub(r"^\./", "", arg), out[m.end() + 1:end]))
    return res
