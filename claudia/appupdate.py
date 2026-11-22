"""Programm-Update: neue Version auf GitHub suchen, Paket laden, prüfen, sichern, einspielen, bei Fehler zurückrollen.

Grundsätze:
- Gesucht wird mit einer einzigen https-Anfrage an die Release-Seite des Projekts; ohne Netz passiert nichts (kein Fehlerfenster).
- Installiert wird nur auf ausdrücklichen Wunsch. Das Paket muss zur veröffentlichten Prüfsumme (SHA-256) passen und die erwartete Version enthalten.
- Vor dem Einspielen wird der Programmordner gesichert (ohne .venv). Schlägt etwas fehl, wird alles zurückgespielt und ein Fehlerprotokoll geschrieben.
- Persönliche Daten (Verbindungen, Einstellungen, Berichte) liegen außerhalb des Programmordners und werden nie angefasst.
- Startdateien im Hauptordner (start.bat, start.command, install.command) werden erst nach dem Beenden ersetzt, weil die laufende Startdatei sonst
  mitten im Lauf ihren Inhalt ändern würde.
"""
from __future__ import annotations

import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile
from typing import Any, Callable, Dict, List, Optional, Tuple

from . import __version__, coreref
from .util import atomic_write, vcmp

REPO = "conejito-vipe/CLAUDIA---Website-Maleware-Scanner"
API_LATEST = "https://api.github.com/repos/%s/releases/latest" % REPO
DOWNLOAD_PREFIX = "https://github.com/%s/releases/download/" % REPO
MAX_ZIP = 80_000_000
MAX_NOTES = 8000
VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")
SHA_RE = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{64}(?![0-9A-Fa-f])")
SKIP_TOP = (".venv", "__pycache__", ".git", "dist", "Output")                  # nie sichern und nie überschreiben
LATE_FILES = ("start.bat", "start.command", "install.command")                   # erst nach dem Beenden ersetzen
STATE_FILE = "update.json"
LOG_FILE = "update.log"


def root_dir() -> str:
    """Programmordner (der Ordner, in dem das Paket 'claudia' liegt)."""
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def update_dir(data_dir: str) -> str:
    return os.path.join(data_dir, "update")


# ------------------------------------------------------------------------------------------------ Suche
def parse_release(data: Dict[str, Any], current: str) -> Dict[str, Any]:
    """Macht aus der Antwort der Release-Seite die Angaben für die Anzeige. Wirft ValueError, wenn sie nicht brauchbar ist."""
    tag = str(data.get("tag_name") or "").strip()
    version = tag[1:] if tag[:1] in ("v", "V") else tag
    if not VERSION_RE.match(version):
        raise ValueError("Keine Standard-Versionsnummer: %s" % (tag or "?"))
    name_re = re.compile(r"^claudia_v%s\.zip$" % re.escape(version), re.I)
    asset: Dict[str, Any] = {}
    for a in data.get("assets") or []:
        if isinstance(a, dict) and name_re.match(str(a.get("name") or "")):
            asset = a
            break
    url = str(asset.get("browser_download_url") or "")
    if url and not url.startswith(DOWNLOAD_PREFIX):
        url = ""                                                                  # nur Downloads aus diesem Projekt
    notes = str(data.get("body") or "")
    sha = ""
    digest = str(asset.get("digest") or "")
    if digest.lower().startswith("sha256:") and SHA_RE.fullmatch(digest[7:]):
        sha = digest[7:].lower()
    if not sha:
        for line in notes.splitlines():                                           # Zeile mit Dateiname oder "SHA-256" und einer 64-stelligen Prüfsumme
            if re.search(r"sha-?256|claudia_v", line, re.I):
                m = SHA_RE.search(line)
                if m:
                    sha = m.group(0).lower()
                    break
    return {
        "version": version, "newer": vcmp(version, current) > 0, "notes": notes[:MAX_NOTES], "page": str(data.get("html_url") or ""),
        "name": str(asset.get("name") or ""), "url": url, "size": int(asset.get("size") or 0), "sha256": sha,
        "published": str(data.get("published_at") or "")[:10],
    }


def check(current: str = __version__, fetch: Optional[Callable[..., bytes]] = None) -> Dict[str, Any]:
    """Sucht die neueste Version. Wirft nie: {'ok': True, 'info': {...}} oder {'ok': False, 'error': '...'}."""
    if os.environ.get("CLAUDIA_OFFLINE"):
        return {"ok": False, "error": "Offline-Modus"}
    try:
        raw = (fetch or coreref.fetch_bytes)(API_LATEST, 2_000_000, 15)
        return {"ok": True, "info": parse_release(json.loads(raw.decode("utf-8", "replace")), current)}
    except (coreref.RefError, ValueError, TypeError, AttributeError) as e:
        return {"ok": False, "error": str(e)[:300]}


# ------------------------------------------------------------------------------------------------ Zustand (übersprungene Version)
def load_state(data_dir: str) -> Dict[str, Any]:
    try:
        with open(os.path.join(data_dir, STATE_FILE), encoding="utf-8") as fh:
            d = json.load(fh)
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def save_state(data_dir: str, **changes: Any) -> None:
    d = load_state(data_dir)
    d.update(changes)
    try:
        os.makedirs(data_dir, exist_ok=True)
        atomic_write(os.path.join(data_dir, STATE_FILE), json.dumps(d))
    except OSError:
        pass


def skipped(data_dir: str, version: str) -> bool:
    return str(load_state(data_dir).get("skip") or "") == version


# ------------------------------------------------------------------------------------------------ Paket prüfen
class UpdateError(Exception):
    pass


def _clean_name(name: str) -> Optional[str]:
    """Pfad im Paket ohne das oberste Verzeichnis; None, wenn unzulässig (absolut, '..', Laufwerk)."""
    n = name.replace("\\", "/")
    if n.startswith("/") or re.match(r"^[A-Za-z]:", n):
        return None
    parts = [p for p in n.split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts):
        return None
    return "/".join(parts)


def members(z: zipfile.ZipFile) -> List[Tuple[str, zipfile.ZipInfo]]:
    """Alle Dateien des Pakets mit dem Pfad relativ zum Programmordner. Wirft UpdateError bei unzulässigen Pfaden."""
    raw = [(i, _clean_name(i.filename)) for i in z.infolist() if not i.filename.endswith("/")]
    if any(n is None for _, n in raw):
        raise UpdateError("Das Paket enthält unzulässige Pfade.")
    names = [n for _, n in raw if n]
    top = {n.split("/", 1)[0] for n in names}
    strip = len(top) == 1 and all("/" in n for n in names)                        # alles liegt in einem Ordner (CLAUDIA/...)
    out: List[Tuple[str, zipfile.ZipInfo]] = []
    for info, n in raw:
        rel = n.split("/", 1)[1] if strip else n
        if rel.split("/", 1)[0] in SKIP_TOP:
            continue
        out.append((rel, info))
    return out


def verify_package(data: bytes, expected_version: str, expected_sha: str) -> List[Tuple[str, zipfile.ZipInfo]]:
    """Prüft Prüfsumme, Aufbau und Version des Pakets. Rückgabe: die Dateiliste. Wirft UpdateError."""
    if not expected_sha:
        raise UpdateError("Für diese Version ist keine Prüfsumme veröffentlicht. Bitte das Paket von Hand von der Release-Seite laden.")
    got = coreref.sha256_hex(data)
    if got != expected_sha.lower():
        raise UpdateError("Die Prüfsumme des Downloads stimmt nicht (erwartet %s, erhalten %s). Es wurde nichts verändert." % (expected_sha[:16] + "…", got[:16] + "…"))
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        raise UpdateError("Der Download ist keine gültige ZIP-Datei.")
    if z.testzip() is not None:
        raise UpdateError("Die ZIP-Datei ist beschädigt.")
    mem = members(z)
    by = dict(mem)
    for need in ("claudia/__init__.py", "claudia/__main__.py"):
        if need not in by:
            raise UpdateError("Im Paket fehlt %s." % need)
    m = re.search(r'__version__\s*=\s*"([^"]+)"', z.read(by["claudia/__init__.py"]).decode("utf-8", "replace"))
    if not m or m.group(1) != expected_version:
        raise UpdateError("Das Paket enthält die Version %s statt %s." % (m.group(1) if m else "?", expected_version))
    if sum(i.file_size for _, i in mem) > 400_000_000:
        raise UpdateError("Das Paket ist ungewöhnlich groß entpackt.")
    return mem


# ------------------------------------------------------------------------------------------------ Sicherung und Rückweg
def backup(root: str, data_dir: str, version: str) -> str:
    """Sichert den Programmordner (ohne .venv und Zwischendateien) als ZIP. Frühere Sicherungen werden ersetzt."""
    d = update_dir(data_dir)
    os.makedirs(d, exist_ok=True)
    for old in os.listdir(d):
        if old.startswith("sicherung_") and old.endswith(".zip"):
            try:
                os.remove(os.path.join(d, old))
            except OSError:
                pass
    path = os.path.join(d, "sicherung_%s.zip" % version)
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        for base, dirs, files in os.walk(root):
            rel_base = os.path.relpath(base, root)
            dirs[:] = [x for x in dirs if not (rel_base == "." and x in SKIP_TOP) and x != "__pycache__"]
            for f in files:
                if f.endswith(".pyc"):
                    continue
                full = os.path.join(base, f)
                rel = os.path.normpath(os.path.join(rel_base, f)).replace("\\", "/")
                try:
                    z.write(full, rel)
                except OSError:
                    continue
    return path


def restore(root: str, backup_zip: str, created: List[str]) -> None:
    """Spielt die Sicherung zurück und entfernt Dateien, die das Update neu angelegt hat."""
    with zipfile.ZipFile(backup_zip) as z:
        have = set()
        for i in z.infolist():
            rel = _clean_name(i.filename)
            if not rel or i.filename.endswith("/"):
                continue
            have.add(rel)
            _write(root, rel, z.read(i), (i.external_attr >> 16) & 0o777)
    for rel in created:
        if rel not in have:
            try:
                os.remove(os.path.join(root, rel))
            except OSError:
                pass


def _write(root: str, rel: str, data: bytes, mode: int = 0) -> None:
    target = os.path.normpath(os.path.join(root, rel))
    if os.path.commonpath([os.path.abspath(root), os.path.abspath(target)]) != os.path.abspath(root):
        raise UpdateError("Unzulässiger Zielpfad: %s" % rel)
    os.makedirs(os.path.dirname(target), exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".upd-", dir=os.path.dirname(target))
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        if mode & 0o111:
            os.chmod(tmp, 0o755)
        os.replace(tmp, target)
    except BaseException:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise


# ------------------------------------------------------------------------------------------------ Einspielen
def log_line(data_dir: str, text: str) -> None:
    try:
        os.makedirs(data_dir, exist_ok=True)
        with open(os.path.join(data_dir, LOG_FILE), "a", encoding="utf-8") as fh:
            fh.write("%s  %s\n" % (time.strftime("%Y-%m-%d %H:%M:%S"), text))
    except OSError:
        pass


def install(info: Dict[str, Any], root: str, data_dir: str, progress: Optional[Callable[[int, str], None]] = None,
            fetch: Optional[Callable[..., bytes]] = None, current: str = __version__) -> Dict[str, Any]:
    """Lädt, prüft, sichert und spielt das Update ein. Wirft nie; Rückgabe {'ok': bool, 'error'?, 'late'?: [...], 'staging'?: pfad, 'log': pfad}.

    Nach Erfolg müssen die Dateien aus 'late' noch nach dem Beenden ersetzt werden (siehe finish_command)."""
    def step(p: int, t: str) -> None:
        log_line(data_dir, "[%3d %%] %s" % (p, t))
        if progress:
            progress(p, t)
    logp = os.path.join(data_dir, LOG_FILE)
    created: List[str] = []
    bak = ""
    try:
        version = str(info.get("version") or "")
        if not VERSION_RE.match(version) or vcmp(version, current) <= 0:
            raise UpdateError("Keine neuere Version.")
        url = str(info.get("url") or "")
        if not url.startswith(DOWNLOAD_PREFIX):
            raise UpdateError("Für diese Version gibt es kein Paket zum automatischen Laden. Bitte von der Release-Seite laden.")
        step(5, "Lade %s (%s)" % (info.get("name") or "Paket", version))
        data = (fetch or coreref.fetch_bytes)(url, MAX_ZIP, 180)
        step(40, "Prüfe Prüfsumme und Aufbau")
        mem = verify_package(data, version, str(info.get("sha256") or ""))
        z = zipfile.ZipFile(io.BytesIO(data))
        step(55, "Sichere den bisherigen Stand")
        bak = backup(root, data_dir, current)
        step(70, "Spiele %d Dateien ein" % len(mem))
        staging = os.path.join(update_dir(data_dir), "neu")
        shutil.rmtree(staging, ignore_errors=True)
        late: List[str] = []
        for rel, i in mem:
            blob, mode = z.read(i), (i.external_attr >> 16) & 0o777
            if rel in LATE_FILES:
                _write(staging, rel, blob, mode)
                late.append(rel)
                continue
            if not os.path.exists(os.path.join(root, rel)):
                created.append(rel)
            _write(root, rel, blob, mode)
        step(95, "Fertig, Neustart steht an")
        return {"ok": True, "late": late, "staging": staging if late else "", "log": logp, "backup": bak, "version": version}
    except (UpdateError, coreref.RefError, OSError, zipfile.BadZipFile, ValueError) as e:
        msg = str(e)
        log_line(data_dir, "FEHLER: %s" % msg)
        if bak:
            try:
                restore(root, bak, created)
                log_line(data_dir, "Der bisherige Stand wurde aus der Sicherung wiederhergestellt: %s" % bak)
                msg += " Der bisherige Stand wurde wiederhergestellt."
            except (OSError, zipfile.BadZipFile) as e2:
                log_line(data_dir, "RÜCKWEG GESCHEITERT: %s" % e2)
                msg += " Die Wiederherstellung ist gescheitert; die Sicherung liegt unter %s." % bak
        return {"ok": False, "error": msg, "log": logp}


# ------------------------------------------------------------------------------------------------ Neustart
def finish_code() -> str:
    """Kleines Skript, das nach dem Beenden die späten Dateien ersetzt und das Programm neu startet (läuft in einem eigenen Prozess)."""
    return (
        "import os,shutil,subprocess,sys,time\n"
        "root,staging,pid=sys.argv[1],sys.argv[2],int(sys.argv[3])\n"
        "for _ in range(60):\n"
        "    if os.name=='nt':\n"
        "        break\n"
        "    try:\n"
        "        os.kill(pid,0)\n"
        "    except OSError:\n"
        "        break\n"
        "    time.sleep(0.5)\n"
        "time.sleep(2.5)\n"
        "if staging and os.path.isdir(staging):\n"
        "    for base,_,files in os.walk(staging):\n"
        "        for f in files:\n"
        "            rel=os.path.relpath(os.path.join(base,f),staging)\n"
        "            for _ in range(10):\n"
        "                try:\n"
        "                    shutil.copy2(os.path.join(base,f),os.path.join(root,rel));break\n"
        "                except OSError:\n"
        "                    time.sleep(1)\n"
        "    shutil.rmtree(staging,ignore_errors=True)\n"
        "os.chdir(root)\n"
        "if os.name=='nt':\n"
        "    subprocess.Popen(['cmd','/c','start','','start.bat'],cwd=root)\n"
        "else:\n"
        "    subprocess.Popen(['/bin/sh','./start.command'],cwd=root,start_new_session=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)\n"
    )


def restart(root: str, staging: str, python: Optional[str] = None) -> Optional[int]:
    """Startet den Neustart-Helfer losgelöst vom Programm. Rückgabe: Prozessnummer (oder None bei Fehler)."""
    py = python or sys.executable
    args = [py, "-c", finish_code(), root, staging or "", str(os.getpid())]
    try:
        if os.name == "nt":
            flags = 0x00000008 | 0x00000200 | 0x08000000                           # DETACHED_PROCESS | NEW_PROCESS_GROUP | NO_WINDOW
            p = subprocess.Popen(args, cwd=root, creationflags=flags, close_fds=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            p = subprocess.Popen(args, cwd=root, start_new_session=True, close_fds=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return p.pid
    except OSError:
        return None
