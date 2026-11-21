"""Original von PrestaShop als Vergleich für die Programmordner classes, controllers und src. Nur https, nur github.com/PrestaShop.

Es gibt keine veröffentlichte Prüfsumme je Version; das Archiv gilt als 'nicht gegen eine Prüfsumme bestätigt' (verified=False). Es wird nichts entpackt: das Zip wird im Speicher gelesen und nur gehasht.
Verglichen werden nur die Ordner, die bei der Veröffentlichung unverändert aus dem Quelltext übernommen werden."""
from __future__ import annotations

import hashlib
import re
from typing import Any, Dict, List

from . import contaoref, coreref
from .prestashop import CORE_DIRS

MAX_ZIP = 220 * 1024 * 1024
VERSION_RE = re.compile(r"^\d+\.\d+\.\d+(\.\d+)?$")
ARCHIVE = "https://github.com/PrestaShop/PrestaShop/archive/refs/tags/%s.zip"


class RefError(coreref.RefError):
    pass


def only_core(files: Dict[str, str]) -> Dict[str, str]:
    return {k: v for k, v in files.items() if k.split("/", 1)[0] in CORE_DIRS}


def reference(version: str) -> Dict[str, Any]:
    if not VERSION_RE.match(version or ""):
        raise RefError("Für die Version '%s' gibt es kein veröffentlichtes Paket zum Vergleich." % version)
    try:
        data = coreref.fetch_bytes(ARCHIVE % version, MAX_ZIP, 300.0)
        files = only_core(contaoref.hash_zip(data))
    except coreref.RefError as e:
        raise RefError(str(e))
    if len(files) < 200:
        raise RefError("Im Paket wurden nur %d Dateien in classes, controllers und src gefunden." % len(files))
    return {"files": files, "package": "PrestaShop-%s.zip" % version, "sha256": hashlib.sha256(data).hexdigest(), "verified": False}


def server_hash_sh() -> str:
    """Shell-Text: sha256 aller Dateien unter classes, controllers und src (Ausgabe 'hash  ./Pfad')."""
    return "for d in %s; do [ -d \"$d\" ] && find -L \"$d\" -type f -print0 | xargs -0 sha256sum 2>/dev/null; done" % " ".join(CORE_DIRS)


def parse_server_hashes(out: str) -> Dict[str, str]:
    res: Dict[str, str] = {}
    for line in (out or "").splitlines():
        m = re.match(r"^([0-9a-f]{64})\s+\*?(?:\./)?(.+)$", line)
        if m:
            res[m.group(2)] = m.group(1)
    return res


def compare(ref: Dict[str, str], server: Dict[str, str]) -> Dict[str, List[str]]:
    return contaoref.compare(ref, server, ignore_re=r"^(\.git|tests?/|\.github/)")
