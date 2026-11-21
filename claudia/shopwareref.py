"""Originalpakete von Shopware als Vergleich für die Kern-Pakete (vendor/shopware/core, administration, storefront). Nur https, nur github.com/shopware.

Es gibt keine veröffentlichte Prüfsumme je Paket; das Archiv wird deshalb als 'nicht gegen eine Prüfsumme bestätigt' (verified=False) gekennzeichnet. Es wird nichts entpackt: das Zip wird im Speicher gelesen."""
from __future__ import annotations

import hashlib
import re
from typing import Any, Dict, List

from . import coreref
from .contaoref import compare, hash_zip, parse_server_hashes, MAX_ZIP  # noqa: F401  (gleiche Regeln wie bei Contao)

VERSION_RE = re.compile(r"^\d+\.\d+\.\d+(?:\.\d+)?$")
PACKAGE_RE = re.compile(r"^shopware/(core|administration|storefront)$")
ARCHIVE = "https://github.com/shopware/%s/archive/refs/tags/v%s.zip"


class RefError(coreref.RefError):
    pass


def reference(package: str, version: str) -> Dict[str, Any]:
    """Vergleichsdateien eines Pakets (z. B. 'shopware/core') in einer Version."""
    if not PACKAGE_RE.match(package or "") or not VERSION_RE.match(version or ""):
        raise RefError("Für '%s' in Version '%s' gibt es kein veröffentlichtes Paket zum Vergleich." % (package, version))
    repo = package.split("/", 1)[1]
    try:
        data = coreref.fetch_bytes(ARCHIVE % (repo, version), MAX_ZIP, 300.0)
    except coreref.RefError as e:
        raise RefError(str(e))
    files = hash_zip(data)
    if len(files) < 5:
        raise RefError("Im Paket %s wurden nur %d Dateien gefunden." % (package, len(files)))
    return {"files": files, "package": "%s-%s.zip" % (repo, version), "sha256": hashlib.sha256(data).hexdigest(), "verified": False}


def server_hash_sh(packages: List[str]) -> str:
    """Shell-Text: sha256 aller Dateien unter vendor/shopware/<Paket> (Ausgabe '@@PKG <Paket>' gefolgt von 'hash  Pfad'-Zeilen, Pfad relativ zum Paket)."""
    pk = [p.split("/", 1)[1] for p in packages[:3] if PACKAGE_RE.match(p)]
    return ('R=.; if [ ! -d vendor/shopware ] && [ -d ../vendor/shopware ]; then R=..; fi; '
            'for p in %s; do echo "@@PKG shopware/$p"; d="$R/vendor/shopware/$p"; '
            '[ -d "$d" ] && (cd "$d" && find -L . -type f -not -path "./.git/*" -not -path "*/node_modules/*" -print0 | xargs -0 sha256sum 2>/dev/null); done' % " ".join(pk))
