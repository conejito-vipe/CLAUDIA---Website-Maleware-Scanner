"""Shopware 6 (seit 2.13.0): Version, Umgebungsdateien, Pakete und Support-Stand lesen. Reine Funktionen ohne Serverzugriff (mit Beispieltexten prüfbar).

Unterstützt wird Shopware 6.5 und neuer (Composer-Installation mit vendor/shopware/core). Shopware 5 wird erkannt und als nicht mehr unterstützt gemeldet.
Zugangsdaten, APP_SECRET, Mail-DSN und Passwörter werden nie ausgegeben; die Dateien werden nur als Text gelesen und nie ausgeführt."""
from __future__ import annotations

import re
import time
from typing import Any, Dict, List, Optional, Tuple

from .contao import parse_database_url, parse_env, parse_lock, parse_release_list, split_config_output as _split, PLACEHOLDER_SECRETS
from .typo3 import advisories_for, affected, cycle, norm_version, parse_advisories, version_key

__all__ = ["advisories_for", "affected", "parse_advisories", "norm_version", "parse_release_list", "parse_lock", "version_key"]

CORE_PACKAGES = ("shopware/core", "shopware/administration", "shopware/storefront")      # werden mit dem Original verglichen
ENV_FILES = (".env", ".env.local", ".env.prod", ".env.prod.local")
JWT_FILES = ("config/jwt/private.pem", "config/jwt/public.pem")
SAFE_ENV = ("APP_ENV", "APP_DEBUG", "TRUSTED_HOSTS", "TRUSTED_PROXIES", "APP_URL", "SHOPWARE_HTTP_CACHE_ENABLED", "SHOPWARE_ES_ENABLED", "BLUE_GREEN_DEPLOYMENT")

# Laufzeiten je Version "Haupt.Neben": (Ende der Fehlerkorrekturen, Ende der Sicherheitsupdates). Stand: 2026-11, Quelle: endoflife.date/shopware (die Seite von Shopware nennt keine festen Daten).
# Bei 6.7 nennt die Quelle noch kein Ende der Fehlerkorrekturen; hier steht deshalb das Ende der Sicherheitsupdates. Eine Version unterhalb von 6.5 gilt als beendet; neuere, hier fehlende Versionen sind unbekannt.
LIFECYCLE: Dict[str, Tuple[str, str]] = {
    "6.5": ("2024-03-28", "2027-02-28"),
    "6.6": ("2025-06-17", "2028-02-28"),
    "6.7": ("2028-02-28", "2028-02-28"),
}
LIFECYCLE_ASOF = "2026-11"
LIFECYCLE_MIN = (6, 5)


def _day(s: str) -> float:
    return time.mktime(time.strptime(s, "%Y-%m-%d"))


def lifecycle(version: str, now: Optional[float] = None) -> Dict[str, Any]:
    """state: 'supported', 'security' (nur noch Sicherheitsupdates), 'ended', 'unknown'."""
    now = now or time.time()
    c = cycle(version)
    key = "%d.%d" % c
    empty = {"cycle": key, "bugfix_until": "", "security_until": "", "days_left": None}
    if c == (0, 0):
        return dict(empty, state="unknown", cycle="")
    if key not in LIFECYCLE:
        return dict(empty, state="ended" if c < LIFECYCLE_MIN else "unknown")
    bug, sec = LIFECYCLE[key]
    end_sec = _day(sec) + 86400
    if now > end_sec:
        st = "ended"
    elif now > _day(bug) + 86400:
        st = "security"
    else:
        st = "supported"
    return {"state": st, "cycle": key, "bugfix_until": bug, "security_until": sec, "days_left": int((end_sec - now) // 86400) if st != "ended" else None}


def parse_core_version(lock_text: str, installed_php: str = "") -> str:
    """Version von shopware/core (oder shopware/platform) aus composer.lock bzw. vendor/composer/installed.php; leer, wenn nicht erkannt."""
    for name in ("shopware/core", "shopware/platform"):
        m = re.search(r'"name"\s*:\s*"%s"\s*,(?:(?!"name").){0,1500}?"version"\s*:\s*"v?([0-9][0-9A-Za-z.\-]*)"' % re.escape(name), lock_text or "", re.S)
        if m:
            return m.group(1)
        m = re.search(r"'%s'\s*=>\s*(?:array\s*)?\(?\s*\[?\s*'pretty_version'\s*=>\s*'v?([0-9][0-9A-Za-z.\-]*)'" % re.escape(name), installed_php or "", re.S)
        if m:
            return m.group(1)
    return ""


def parse_settings(env_files: List[Tuple[str, str]]) -> Dict[str, Any]:
    """Datenbank-Angaben und wichtige Einstellungen aus den .env-Dateien (spätere überschreiben frühere). Rückgabe passt zur Datenbank-Anbindung (vars wie bei den anderen Systemen).
    Passwörter, APP_SECRET und Mail-DSN stehen nur in 'vars' (nie angezeigt) bzw. als Länge."""
    env: Dict[str, str] = {}
    for _, t in env_files:
        env.update(parse_env(t))
    db = parse_database_url(env.get("DATABASE_URL", ""))
    secret = env.get("APP_SECRET", "")
    return {"vars": {"host": db.get("host", ""), "user": db.get("user", ""), "password": db.get("password", ""), "db": db.get("db", ""), "dbprefix": "",
                     "dbtype": "mysqli" if "mysql" in db.get("driver", "mysql") else db.get("driver", "")},
            "shopware": {"env": {k: env[k] for k in SAFE_ENV if k in env}, "has_secret": bool(secret), "secret_len": len(secret),
                         "secret_placeholder": any(p.lower() in secret.lower() for p in PLACEHOLDER_SECRETS) if secret else False,
                         "has_mailer": bool(env.get("MAILER_DSN") or env.get("MAILER_URL"))},
            "prefix": "", "unexpected": [], "parsed": bool(env),
            "files": [p for p, _ in env_files], "size": sum(len(t) for _, t in env_files), "lines": 0}


def read_config_sh() -> str:
    """Shell-Text: findet das Projektverzeichnis (Seitenordner oder eine Ebene darüber, falls public/ gewählt wurde) und gibt .env-Dateien mit Kopfzeilen '@@ENV <Pfad>' aus;
    danach '@@JWT <Pfad>' für vorhandene JWT-Schlüsseldateien (nur der Pfad, nie der Inhalt)."""
    return ('R=.; if [ ! -d vendor/shopware ] && [ -d ../vendor/shopware ]; then R=..; fi; echo "@@ROOT $R"; '
            'for f in %s; do if [ -f "$R/$f" ]; then echo "@@ENV $R/$f"; head -c 20000 "$R/$f"; echo; fi; done; '
            'for f in %s; do if [ -f "$R/$f" ]; then echo "@@JWT $R/$f"; fi; done' % (" ".join(ENV_FILES), " ".join(JWT_FILES)))


def split_config_output(out: str) -> Dict[str, Any]:
    """{'root', 'env': [(Pfad, Text)], 'jwt': [Pfad]}."""
    res = _split(re.sub(r"^@@JWT (.*)$", "", out or "", flags=re.M))
    res["jwt"] = [re.sub(r"^\./", "", m.strip()) for m in re.findall(r"^@@JWT (.+)$", out or "", re.M)]
    return res
