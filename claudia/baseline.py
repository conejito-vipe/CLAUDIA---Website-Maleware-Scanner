"""Vergleichsbasis (B9, 2.4.0): Pro Verbindung (Server, Benutzer, Seitenordner) wird auf DIESEM Computer eine Liste von Prüfsummen gespeichert
(PHP-, JS- und .htaccess-Dateien) plus die Dateiliste der Upload-Ordner. Es werden keine Dateiinhalte, keine Zugangsdaten und keine Passwörter gespeichert."""
from __future__ import annotations

import hashlib
import json
import os
import re
import time
from typing import Any, Dict, List, Optional, Tuple

from .util import atomic_write, digits

VERSION = 1
MAX_FILES = 30000
KEY_RE = re.compile(r"^[0-9a-f]{16}\Z")


def make_key(host: str, user: str, site_dir: str) -> str:
    """Kurze Kennung der Verbindung. Der Klartext steht nur als Beschriftung in der Datei (Server und Ordner, ohne Benutzername)."""
    raw = "\n".join([(host or "").strip().lower(), (user or "").strip(), (site_dir or "").strip().strip("/")])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def _path(base_dir: str, key: str) -> str:
    if not KEY_RE.match(key or ""):
        raise ValueError("ungültige Kennung")
    return os.path.join(base_dir, key + ".json")


def load(base_dir: str, key: str) -> Optional[Dict[str, Any]]:
    try:
        with open(_path(base_dir, key), encoding="utf-8") as fh:
            d = json.load(fh)
        return d if isinstance(d, dict) and d.get("version") == VERSION and isinstance(d.get("files"), dict) else None
    except (OSError, ValueError):
        return None


def save(base_dir: str, key: str, label: str, files: Dict[str, str], uploads: Dict[str, int]) -> Dict[str, Any]:
    d = {"version": VERSION, "saved": time.strftime("%Y-%m-%d %H:%M:%S"), "label": label[:120], "files": files, "uploads": uploads}
    os.makedirs(base_dir, exist_ok=True)
    atomic_write(_path(base_dir, key), json.dumps(d, ensure_ascii=False, separators=(",", ":")))
    return d


def mark_compared(base_dir: str, key: str) -> bool:
    """Vermerkt in der lokalen Basis-Datei, wann zuletzt verglichen wurde (nur Zeitpunkt, auf diesem Computer). Für die Erinnerung in der Oberfläche."""
    d = load(base_dir, key)
    if not d:
        return False
    d["compared"] = time.strftime("%Y-%m-%d %H:%M:%S")
    try:
        atomic_write(_path(base_dir, key), json.dumps(d, ensure_ascii=False, separators=(",", ":")))
        return True
    except OSError:
        return False


REMIND_DAYS = 14


def _days_since(stamp: str, now: Optional[float] = None) -> Optional[int]:
    try:
        t = time.mktime(time.strptime(stamp, "%Y-%m-%d %H:%M:%S"))
    except (ValueError, TypeError, OverflowError):
        return None
    return max(0, int(((time.time() if now is None else now) - t) // 86400))


def reminder(info: Dict[str, Any], now: Optional[float] = None, days: int = REMIND_DAYS) -> Dict[str, str]:
    """Erinnerung für die Oberfläche (kein Hintergrunddienst, nur Anzeige beim Öffnen). -> {'level': 'first'|'due'|'ok', 'text': ...}"""
    if not info.get("exists"):
        return {"level": "first", "text": "Für diese Verbindung gibt es noch keine Vergleichsbasis. Speichere eine, wenn die Seite nach deiner Einschätzung sauber ist; dann fallen spätere Änderungen an Code-Dateien auf."}
    stamp = info.get("compared") or info.get("saved") or ""
    n = _days_since(stamp, now)
    what = "Letzter Vergleich" if info.get("compared") else "Basis gespeichert, seither nicht verglichen"
    if n is None:
        return {"level": "ok", "text": "Vergleichsbasis vorhanden."}
    ago = "heute" if n == 0 else ("vor 1 Tag" if n == 1 else "vor %d Tagen" % n)
    if n >= days:
        return {"level": "due", "text": "%s: %s (%s). Ein Vergleich etwa alle %d Tage macht Änderungen früh sichtbar. Nach Updates, die du selbst eingespielt hast, danach eine neue Basis speichern." % (what, ago, stamp[:10], days)}
    return {"level": "ok", "text": "%s: %s (%s)." % (what, ago, stamp[:10])}


def delete(base_dir: str, key: str) -> bool:
    gone = False
    for fn in (_path, _dns_path):
        try:
            os.remove(fn(base_dir, key))
            gone = True
        except (OSError, ValueError):
            pass
    return gone


# ---- DNS-Basis (2.5.0 / 2.13): eigene Datei neben der Prüfsummen-Basis, nur öffentliche DNS-Einträge (kein Geheimnis, keine Zugangsdaten)
def _dns_path(base_dir: str, key: str) -> str:
    if not KEY_RE.match(key or ""):
        raise ValueError("ungültige Kennung")
    return os.path.join(base_dir, key + ".dns.json")


def load_dns(base_dir: str, key: str) -> Optional[Dict[str, Any]]:
    try:
        with open(_dns_path(base_dir, key), encoding="utf-8") as fh:
            d = json.load(fh)
        ok = isinstance(d, dict) and d.get("version") == VERSION and isinstance(d.get("records"), dict)
        return d if ok and all(isinstance(v, list) for v in d["records"].values()) else None
    except (OSError, ValueError):
        return None


def save_dns(base_dir: str, key: str, domain: str, records: Dict[str, List[str]]) -> Dict[str, Any]:
    d = {"version": VERSION, "saved": time.strftime("%Y-%m-%d %H:%M:%S"), "domain": domain[:253], "records": {k: sorted(set(v))[:50] for k, v in records.items()}}
    os.makedirs(base_dir, exist_ok=True)
    atomic_write(_dns_path(base_dir, key), json.dumps(d, ensure_ascii=False, separators=(",", ":")))
    return d


def info(base_dir: str, key: str) -> Dict[str, Any]:
    d = load(base_dir, key)
    if not d:
        return {"exists": False, "reminder": reminder({"exists": False})}
    out = {"exists": True, "saved": d.get("saved", ""), "compared": d.get("compared", ""), "label": d.get("label", ""), "files": len(d["files"]), "uploads": len(d.get("uploads") or {})}
    out["reminder"] = reminder(out)
    return out


def parse_scan(out: str) -> Tuple[Dict[str, str], Dict[str, int], bool]:
    """Ausgabe des Server-Skripts: 'H\\t<sha256>\\t<Pfad>' und 'U\\t<Größe>\\t<Pfad>'. Rückgabe: (Prüfsummen, Upload-Liste, gekürzt?)."""
    files: Dict[str, str] = {}
    uploads: Dict[str, int] = {}
    cut = "@@CUT" in out and bool(out.split("@@CUT", 1)[1].strip())
    for ln in out.splitlines():
        p = ln.split("\t", 2)
        if len(p) == 3 and p[0] == "H" and re.fullmatch(r"[0-9a-f]{64}", p[1]):
            files[p[2]] = p[1]
        elif len(p) == 3 and p[0] == "U" and digits(p[1]):
            uploads[p[2]] = int(p[1])
    return files, uploads, cut


def compare(base: Dict[str, Any], files: Dict[str, str], uploads: Dict[str, int]) -> Dict[str, List[str]]:
    bf, bu = base.get("files") or {}, base.get("uploads") or {}
    return {
        "new": sorted(p for p in files if p not in bf), "changed": sorted(p for p in files if p in bf and files[p] != bf[p]), "deleted": sorted(p for p in bf if p not in files),
        "up_new": sorted(p for p in uploads if p not in bu), "up_deleted": sorted(p for p in bu if p not in uploads),
    }
