"""Originalpakete von Contao als Vergleich für die Kern-Bundles (vendor/contao/*). Nur https, nur github.com/contao.

Es gibt keine veröffentlichte Prüfsumme je Paket; das Archiv wird deshalb als 'nicht gegen eine Prüfsumme bestätigt' (verified=False) gekennzeichnet. Es wird nichts entpackt: das Zip wird im Speicher gelesen und nur gehasht."""
from __future__ import annotations

import hashlib
import io
import re
import zipfile
from typing import Any, Dict, List

from . import coreref

MAX_ZIP = 120 * 1024 * 1024
VERSION_RE = re.compile(r"^\d+\.\d+\.\d+\Z")
PACKAGE_RE = re.compile(r"^contao/[a-z0-9\-]+\Z")
ARCHIVE = "https://github.com/contao/%s/archive/refs/tags/%s.zip"
MAX_PACKAGES = 6


class RefError(coreref.RefError):
    pass


def hash_zip(data: bytes) -> Dict[str, str]:
    """sha256 aller regulären Dateien des GitHub-Archivs (oberster Ordner entfernt). Pfade mit '..' oder absolute werden ignoriert."""
    out: Dict[str, str] = {}
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                name = info.filename
                parts = name.split("/")
                if len(parts) < 2 or ".." in parts or name.startswith("/"):
                    continue
                rel = "/".join(parts[1:])
                out[rel] = hashlib.sha256(zf.read(info)).hexdigest()
    except (zipfile.BadZipFile, OSError, EOFError, RuntimeError) as e:
        raise RefError("Das Paket ist kein lesbares Archiv: %s" % e)
    return out


def reference(package: str, version: str) -> Dict[str, Any]:
    """Vergleichsdateien eines Pakets (z. B. 'contao/core-bundle') in einer Version."""
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
    """Shell-Text: sha256 aller Dateien unter vendor/contao/<Paket> (Ausgabe '@@PKG <Paket>' gefolgt von 'hash  Pfad'-Zeilen, Pfad relativ zum Paket)."""
    pk = [p.split("/", 1)[1] for p in packages[:MAX_PACKAGES] if PACKAGE_RE.match(p)]
    return ('R=.; if [ ! -d vendor/contao ] && [ -d ../vendor/contao ]; then R=..; fi; '
            'for p in %s; do echo "@@PKG contao/$p"; d="$R/vendor/contao/$p"; '
            '[ -d "$d" ] && (cd "$d" && find -L . -type f -not -path "./.git/*" -print0 | xargs -0 sha256sum 2>/dev/null); done' % " ".join(pk))


def parse_server_hashes(out: str) -> Dict[str, Dict[str, str]]:
    """{'contao/core-bundle': {'src/x.php': hash, ...}}."""
    res: Dict[str, Dict[str, str]] = {}
    cur = ""
    for line in (out or "").splitlines():
        if line.startswith("@@PKG "):
            cur = line[6:].strip()
            res[cur] = {}
        elif cur:
            m = re.match(r"^([0-9a-f]{64})\s+\*?(?:\./)?(.+)\Z", line)
            if m:
                res[cur][m.group(2)] = m.group(1)
    return res


def compare(ref: Dict[str, str], server: Dict[str, str], ignore_re: str = r"^(\.git|tests?/|\.github/)") -> Dict[str, List[str]]:
    """Unterschiede: changed (anderer Inhalt), missing (im Original, fehlt auf dem Server), extra (nur auf dem Server)."""
    ig = re.compile(ignore_re)
    r = {k: v for k, v in ref.items() if not ig.search(k)}
    s = {k: v for k, v in server.items() if not ig.search(k)}
    return {"changed": sorted(k for k in s if k in r and r[k] != s[k]),
            "missing": sorted(k for k in r if k not in s),
            "extra": sorted(k for k in s if k not in r)}
