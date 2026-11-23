"""Offizielle Referenzdaten für den Kernvergleich (Joomla).

Ablauf: Die Prüfsumme des Original-Pakets kommt von der Release-Seite des Joomla-Projekts (GitHub-API, https). Das Paket wird von DIESEM Computer geladen,
gegen diese Prüfsumme (und, wenn vorhanden, gegen die des Joomla-Update-Servers) geprüft und Datei für Datei in Prüfsummen umgerechnet.
Im Cache liegt nur die Liste der Prüfsummen (klein). Das ZIP selbst wird nur für die Aktion 'Kerndateien neu einspielen' gebraucht und liegt dann vorübergehend im Cache.
Alles läuft über https; unverschlüsselte Adressen werden nicht abgerufen."""
from __future__ import annotations

import hashlib
import io
import json
import os
import re
import ssl
import time
import urllib.error
import urllib.request
import zipfile
from typing import Any, Dict, Tuple

from . import secure
from .util import atomic_write, parse_xml

GITHUB_API = "https://api.github.com/repos/joomla/joomla-cms/releases/tags/%s"
GITHUB_DL = "https://github.com/joomla/joomla-cms/releases/download/%s/%s"
UPDATE_LIST = "https://update.joomla.org/core/list.xml"
MAX_ZIP = 120 * 1024 * 1024
UA = "CLAUDIA/2.0 (Sicherheitspruefung; https://github.com/)"
VERSION_RE = re.compile(r"^\d+\.\d+\.\d+\Z")
# Pfade, die nie aus einem Paket zurückgespielt werden und beim Vergleich ausgenommen sind (Inhalt gehört der Seite, nicht dem Kern)
SKIP_PREFIXES = ("installation/", "images/", "tmp/", "cache/", "logs/", "administrator/cache/", "administrator/logs/")
SKIP_FILES = {"configuration.php", ".htaccess", "robots.txt", "web.config", "php.ini", ".user.ini", "htaccess.txt", "web.config.txt", "robots.txt.dist",
              "readme.txt", "license.txt", "readme.md", "favicon.ico"}


class RefError(Exception):
    pass


def cache_dir() -> str:
    env = os.environ.get("CLAUDIA_CACHE")
    if env:
        return env
    from .server import data_dir          # späte Einfuhr: server.py führt dieses Modul über die Prüfungen ein
    return os.path.join(data_dir(), "cache")


class _Https(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not secure.is_secure_url(newurl):
            raise urllib.error.URLError("Weiterleitung auf eine unverschlüsselte Adresse (http) wird nicht befolgt: %s" % newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch_bytes(url: str, max_bytes: int = 5_000_000, timeout: float = 30.0) -> bytes:
    """Lädt eine https-Adresse. Wirft RefError bei Fehlern; mehr als max_bytes gelten als Fehler (kein stilles Abschneiden)."""
    if not secure.is_secure_url(url):
        raise RefError("Unverschlüsselte Adresse (http) wird nicht abgerufen: %s" % url)
    opener = urllib.request.build_opener(_Https(), urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
    try:
        with opener.open(req, timeout=timeout) as r:
            data = r.read(max_bytes + 1)
    except urllib.error.HTTPError as e:
        raise RefError("%s: HTTP %s" % (url, e.code))
    except (urllib.error.URLError, OSError, ValueError) as e:
        raise RefError("%s: %s" % (url, getattr(e, "reason", e)))
    if len(data) > max_bytes:
        raise RefError("%s: Datei ist größer als erlaubt (%d MB)" % (url, max_bytes // 1_048_576))
    return data


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ----------------------------------------------------------------------------- Veröffentlichte Prüfsummen
def release_asset(version: str) -> Dict[str, str]:
    """Das Full-Package einer Version laut Release-Seite: {name, url, sha256}. sha256 kann leer sein, wenn die Seite keine veröffentlicht."""
    if not VERSION_RE.match(version or ""):
        raise RefError("Keine Standard-Versionsnummer (%s): Entwicklerversionen werden nicht verglichen." % (version or "?"))
    raw = fetch_bytes(GITHUB_API % version, 2_000_000)
    try:
        data = json.loads(raw.decode("utf-8", "replace"))
    except ValueError:
        raise RefError("Die Release-Seite des Joomla-Projekts lieferte keine lesbare Antwort.")
    want = "Joomla_%s-Stable-Full_Package.zip" % version
    url, sha = "", ""
    for a in data.get("assets") or []:
        if a.get("name") == want:
            url = str(a.get("browser_download_url") or "")
            d = str(a.get("digest") or "")
            if d.startswith("sha256:") and re.fullmatch(r"[0-9a-f]{64}", d[7:]):
                sha = d[7:]
    if not sha:
        m = re.search(re.escape(want) + r"[^0-9a-f]{0,40}([0-9a-f]{64})", str(data.get("body") or ""), re.I)
        if m:
            sha = m.group(1).lower()
    if not url:
        url = GITHUB_DL % (version, want)
    if not secure.is_secure_url(url) or not url.startswith("https://github.com/joomla/joomla-cms/"):
        raise RefError("Unerwartete Download-Adresse in der Release-Antwort.")
    return {"name": want, "url": url, "sha256": sha}


def update_server_hashes(version: str) -> Dict[str, str]:
    """sha256-Werte, die der Joomla-Update-Server für diese Version nennt ({Dateiname: sha256}). Leer, wenn die Version dort nicht (mehr) geführt wird."""
    out: Dict[str, str] = {}
    try:
        lst = parse_xml(fetch_bytes(UPDATE_LIST, 500_000))
    except RefError:
        return out
    if lst is None:
        return out
    urls = []
    for e in lst.iter("extension"):
        u = e.get("detailsurl") or ""
        if u.startswith("https://update.joomla.org/") and u not in urls:
            urls.append(u)
    for u in urls[:8]:
        try:
            root = parse_xml(fetch_bytes(u, 500_000))
        except RefError:
            continue
        if root is None:
            continue
        for up in root.iter("update"):
            if (up.findtext("version") or "").strip() != version:
                continue
            sha = (up.findtext("sha256") or "").strip().lower()
            for d in up.iter("downloadurl"):
                name = (d.text or "").strip().rsplit("/", 1)[-1]
                if name and re.fullmatch(r"[0-9a-f]{64}", sha):
                    out[name] = sha
    return out


# ----------------------------------------------------------------------------- Paket -> Prüfsummen
def hash_zip(data: bytes) -> Dict[str, str]:
    """{relativer Pfad: sha256} aller Dateien im Paket (ohne Ordner, ohne unsichere Pfade)."""
    files: Dict[str, str] = {}
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        raise RefError("Das heruntergeladene Paket ist kein gültiges ZIP.")
    with zf:
        for i in zf.infolist():
            n = i.filename.replace("\\", "/")
            if n.endswith("/") or n.startswith("/") or ".." in n.split("/"):
                continue
            files[n] = hashlib.sha256(zf.read(i)).hexdigest()
    return files


def is_compared(path: str) -> bool:
    p = path[2:] if path.startswith("./") else path
    return not p.startswith(SKIP_PREFIXES) and p.lower() not in SKIP_FILES


def reference(version: str, force: bool = False) -> Dict[str, Any]:
    """Referenz für eine Joomla-Version: {version, files, verified, cross, source, package, sha256, url}. Wirft RefError.

    verified = Die Prüfsumme des geladenen Pakets stimmt mit der veröffentlichten überein.
    cross = Der Update-Server des Projekts nennt dieselbe Prüfsumme (zweite, unabhängige Bestätigung; nicht für alle Versionen verfügbar)."""
    cdir = cache_dir()
    cfile = os.path.join(cdir, "joomla-%s.json" % version)
    if not force and VERSION_RE.match(version or ""):
        try:
            with open(cfile, encoding="utf-8") as fh:
                c = json.load(fh)
            if c.get("version") == version and c.get("files"):
                return c
        except (OSError, ValueError):
            pass
    asset = release_asset(version)
    data = fetch_bytes(asset["url"], MAX_ZIP, timeout=180)
    got = sha256_hex(data)
    pub = asset["sha256"]
    verified = bool(pub) and got == pub
    if pub and got != pub:
        raise RefError("Die Prüfsumme des geladenen Pakets (%s...) weicht von der veröffentlichten ab (%s...). Das Paket wird NICHT benutzt." % (got[:12], pub[:12]))
    cross = False
    other = update_server_hashes(version) if not os.environ.get("CLAUDIA_NO_UPDATE_SERVER") else {}
    for n, h in other.items():
        if h == got:
            cross = True
    ref = {"version": version, "files": hash_zip(data), "verified": verified, "cross": cross, "source": "github.com/joomla/joomla-cms (Release %s)" % version,
           "package": asset["name"], "sha256": got, "url": asset["url"], "stand": time.strftime("%Y-%m-%d")}
    try:
        os.makedirs(cdir, exist_ok=True)
        atomic_write(cfile, json.dumps(ref))
        zpath = os.path.join(cdir, asset["name"])
        with open(zpath, "wb") as fh:
            fh.write(data)
        _trim_cache(cdir, keep=zpath)
    except OSError:
        pass
    return ref


def _trim_cache(cdir: str, keep: str) -> None:
    """Pakete im Cache: nur das aktuell benutzte bleibt liegen (Platz sparen)."""
    try:
        for n in os.listdir(cdir):
            if n.startswith("Joomla_") and n.endswith(".zip") and os.path.join(cdir, n) != keep:
                os.remove(os.path.join(cdir, n))
    except OSError:
        pass


def package_path(ref: Dict[str, Any]) -> Tuple[str, str]:
    """Pfad des Pakets im Cache (lädt es bei Bedarf neu und prüft die Prüfsumme). Rückgabe: (Pfad, sha256)."""
    cdir = cache_dir()
    path = os.path.join(cdir, ref["package"])
    try:
        with open(path, "rb") as fh:
            data = fh.read()
        if sha256_hex(data) == ref["sha256"]:
            return path, ref["sha256"]
    except OSError:
        pass
    data = fetch_bytes(ref["url"], MAX_ZIP, timeout=180)
    if sha256_hex(data) != ref["sha256"]:
        raise RefError("Das Paket weicht von der geprüften Referenz ab. Es wird nicht benutzt.")
    os.makedirs(cdir, exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(data)
    _trim_cache(cdir, keep=path)
    return path, ref["sha256"]
