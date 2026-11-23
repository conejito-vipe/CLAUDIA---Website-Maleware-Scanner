"""Original-Paket von TYPO3 als Vergleich für die Systemerweiterungen (typo3/sysext). Nur https, nur get.typo3.org, Prüfsumme (sha256) von der Release-Seite.

Es wird nichts entpackt: das Archiv wird im Speicher gelesen und nur gehasht (kein Schreiben auf die Festplatte, keine Pfade aus dem Archiv)."""
from __future__ import annotations

import hashlib
import io
import re
import tarfile
from typing import Any, Dict

from . import coreref

MAX_TAR = 220 * 1024 * 1024
VERSION_RE = re.compile(r"^\d+\.\d+\.\d+\Z")
PAGE = "https://get.typo3.org/version/%s"
PACKAGE = "https://get.typo3.org/%s/tar.gz"


class RefError(coreref.RefError):
    pass


def hash_tar(data: bytes, version: str) -> Dict[str, str]:
    """sha256 aller Dateien unter typo3_src-<Version>/typo3/sysext/ (Schlüssel: 'typo3/sysext/...'). Nur reguläre Dateien, Pfade mit '..' oder absolute werden ignoriert."""
    out: Dict[str, str] = {}
    prefix = "typo3_src-%s/" % version
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
            for m in tf:
                if not m.isreg() or not m.name.startswith(prefix + "typo3/sysext/"):
                    continue
                rel = m.name[len(prefix):]
                if ".." in rel.split("/") or rel.startswith("/"):
                    continue
                f = tf.extractfile(m)
                if f is not None:
                    out[rel] = hashlib.sha256(f.read()).hexdigest()
    except (tarfile.TarError, OSError, EOFError) as e:
        raise RefError("Das Paket ist kein lesbares Archiv: %s" % e)
    return out


def reference(version: str, expected_sha256: str = "") -> Dict[str, Any]:
    if not VERSION_RE.match(version or ""):
        raise RefError("Für die Version '%s' gibt es kein veröffentlichtes Paket zum Vergleich." % version)
    url = PACKAGE % version
    try:
        data = coreref.fetch_bytes(url, MAX_TAR, 300.0)
    except coreref.RefError as e:
        raise RefError(str(e))
    sha = hashlib.sha256(data).hexdigest()
    verified = bool(expected_sha256) and re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is not None
    if verified and sha != expected_sha256:
        raise RefError("Die Prüfsumme des Pakets stimmt nicht mit der Angabe von get.typo3.org überein. Das Paket wird nicht benutzt.")
    files = hash_tar(data, version)
    if len(files) < 500:
        raise RefError("Im Paket wurden nur %d Dateien unter typo3/sysext gefunden." % len(files))
    return {"files": files, "package": "typo3_src-%s.tar.gz" % version, "sha256": sha, "verified": verified}
