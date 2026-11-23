"""Plugin-Prüfsummen von wordpress.org (A10, 2.4.0): Antwort lesen und mit den Prüfsummen vom Server vergleichen.

Quelle: https://downloads.wordpress.org/plugin-checksums/<slug>/<version>.json  Aufbau: {"files": {"<Pfad>": {"md5": "...", "sha256": "..." | ["...", ...]}}}.
Aufbau und Adresse sind am Quelltext von WP-CLI (checksum-command, WpOrgApi) abgeglichen, NICHT gegen die Live-Antwort getestet (siehe Dokumentation); der Leser ist deshalb tolerant und gibt bei unbekanntem Aufbau ein leeres Ergebnis zurück."""
from __future__ import annotations

import json
import re
from typing import Dict, List, Set

CODE_RE = re.compile(r"\.(php\d?|phtml|phar|inc)$|(^|/)\.htaccess$|(^|/)\.user\.ini$", re.I)
HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX32 = re.compile(r"^[0-9a-f]{32}$")


def url(slug: str, version: str) -> str:
    from urllib.parse import quote
    return "https://downloads.wordpress.org/plugin-checksums/%s/%s.json" % (quote(slug, safe=""), quote(version, safe=""))


def parse_reference(text: str) -> Dict[str, Dict[str, Set[str]]]:
    """-> {Pfad: {"sha256": {...}, "md5": {...}}}. Leer, wenn die Antwort nicht lesbar ist."""
    try:
        data = json.loads(text)
    except ValueError:
        return {}
    files = data.get("files") if isinstance(data, dict) else None
    out: Dict[str, Dict[str, Set[str]]] = {}
    if not isinstance(files, dict):
        return out
    for path, v in files.items():
        if not isinstance(path, str):
            continue
        row: Dict[str, Set[str]] = {"sha256": set(), "md5": set()}
        if isinstance(v, dict):
            for k in ("sha256", "md5"):
                x = v.get(k)
                for s in ([x] if isinstance(x, str) else list(x) if isinstance(x, list) else []):
                    if isinstance(s, str):
                        row[k].add(s.lower())
        elif isinstance(v, str):
            row["md5" if HEX32.match(v.lower()) else "sha256"].add(v.lower())
        out[path[2:] if path.startswith("./") else path] = row
    return out


def parse_local(out: str) -> Dict[str, Dict[str, str]]:
    """Ausgabe von sha256sum für wp-content/plugins/<slug>/<Pfad> -> {slug: {Pfad: sha256}}."""
    res: Dict[str, Dict[str, str]] = {}
    for ln in out.splitlines():
        m = re.match(r"^([0-9a-f]{64})  \*?(?:\./)?wp-content/plugins/([^/]+)/(.+)\Z", ln)
        if m:
            res.setdefault(m.group(2), {})[m.group(3)] = m.group(1)
    return res


def compare(local: Dict[str, str], ref: Dict[str, Dict[str, Set[str]]]) -> Dict[str, List[str]]:
    changed: List[str] = []
    extra: List[str] = []
    for p, h in local.items():
        r = ref.get(p)
        if r is None:
            if CODE_RE.search(p):
                extra.append(p)
        elif r["sha256"] and h not in r["sha256"]:
            changed.append(p)
        elif not r["sha256"] and not r["md5"]:
            continue
    missing = [p for p in ref if p not in local and CODE_RE.search(p)]
    return {"changed": sorted(changed), "extra": sorted(extra), "missing": sorted(missing)}
