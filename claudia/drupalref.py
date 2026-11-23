"""Original-Paket von Drupal als Vergleich für den Ordner core/ (Prüfsummen). Nur https, nur ftp.drupal.org, Prüfsumme (md5) aus der Release-Liste von updates.drupal.org.

Es wird nichts entpackt: das Archiv wird im Speicher gelesen und nur gehasht (kein Schreiben auf die Festplatte, keine Pfade aus dem Archiv)."""
from __future__ import annotations

import hashlib
import io
import re
import tarfile
from typing import Any, Dict
from urllib.parse import urlparse

from . import coreref

MAX_TAR = 60 * 1024 * 1024
HOSTS = ("ftp.drupal.org",)
VERSION_RE = re.compile(r"^\d+\.\d+\.\d+\Z")


class RefError(coreref.RefError):
    pass


def package_url(version: str, download: str = "") -> str:
    """Adresse des Pakets: die aus der Release-Liste, wenn sie auf ftp.drupal.org zeigt, sonst die übliche."""
    if download:
        u = urlparse(download)
        if u.scheme == "https" and u.hostname in HOSTS and re.search(r"/drupal-[\d.]+\.tar\.gz$", u.path):
            return download
    return "https://ftp.drupal.org/files/projects/drupal-%s.tar.gz" % version


def hash_tar(data: bytes, version: str) -> Dict[str, str]:
    """sha256 aller Dateien unter drupal-<Version>/core/ (Schlüssel: 'core/...'). Nur reguläre Dateien, Pfade mit '..' oder absolute werden ignoriert."""
    out: Dict[str, str] = {}
    prefix = "drupal-%s/" % version
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
            for m in tf:
                if not m.isreg() or not m.name.startswith(prefix + "core/"):
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


def reference(version: str, mdhash: str = "", download: str = "") -> Dict[str, Any]:
    if not VERSION_RE.match(version or ""):
        raise RefError("Für die Version '%s' gibt es kein veröffentlichtes Paket zum Vergleich." % version)
    url = package_url(version, download)
    try:
        data = coreref.fetch_bytes(url, MAX_TAR, 120.0)
    except coreref.RefError as e:
        raise RefError(str(e))
    md5 = hashlib.md5(data).hexdigest()
    verified = bool(mdhash) and re.fullmatch(r"[0-9a-f]{32}", mdhash) is not None
    if verified and md5 != mdhash:
        raise RefError("Die Prüfsumme des Pakets stimmt nicht mit der Angabe von drupal.org überein. Das Paket wird nicht benutzt.")
    files = hash_tar(data, version)
    if len(files) < 200:
        raise RefError("Im Paket wurden nur %d Dateien unter core/ gefunden." % len(files))
    return {"files": files, "package": url.rsplit("/", 1)[-1], "md5": md5, "verified": verified}
