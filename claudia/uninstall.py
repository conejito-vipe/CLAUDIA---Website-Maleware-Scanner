"""Deinstallation: entfernt, was das Programm auf diesem PC angelegt hat.

Ablauf: Die Liste (plan) wird aus festen, selbst berechneten Pfaden gebildet. Nichts davon kommt aus einer Eingabe der Oberfläche.
Die Oberfläche schickt nur die Kennungen der angehakten Einträge. Gelöscht wird nach dem Beenden des Programms durch ein kleines, sichtbares
Skript (Windows: .cmd, sonst .sh), weil die laufende Python-Umgebung unter Windows nicht gelöscht werden kann, solange sie in Benutzung ist.
Persönliche Daten (gespeicherte Verbindungen, Berichte) und der Programmordner werden nie ohne ausdrückliches Anhaken entfernt.
"""
from __future__ import annotations

import os
import sys
import re
import tempfile
from typing import Any, Dict, List, Optional

from .util import sq

PY_MARKER_ORG = "python_von_claudia_pyorg.txt"     # legt start.bat an, wenn es Python von python.org installiert hat
PY_MARKER = "python_von_claudia.txt"          # legt start.bat an, nachdem es Python selbst installiert hat
PY_WINGET_ID = "Python.Python.3.12"
MAX_WALK = 50_000


def _size(path: str) -> Dict[str, int]:
    files = size = 0
    if os.path.isfile(path):
        try:
            return {"files": 1, "bytes": os.path.getsize(path)}
        except OSError:
            return {"files": 1, "bytes": 0}
    for base, _dirs, names in os.walk(path):
        for n in names:
            files += 1
            if files > MAX_WALK:
                return {"files": files, "bytes": size}
            try:
                size += os.path.getsize(os.path.join(base, n))
            except OSError:
                pass
    return {"files": files, "bytes": size}


def _is_plain(path: str) -> bool:
    """Kein Verweis (Symlink/Junction): so kann kein Eintrag unbemerkt auf einen fremden Ordner zeigen."""
    return os.path.normcase(os.path.realpath(path)) == os.path.normcase(os.path.abspath(path))


def _safe_root(root: str) -> bool:
    r = os.path.abspath(root)
    return (os.path.isfile(os.path.join(r, "start.bat")) or os.path.isfile(os.path.join(r, "start.command")) or os.path.isfile(os.path.join(r, "claudia", "__init__.py"))) \
        and os.path.dirname(r) != r and r != os.path.expanduser("~")


def python_org_hint(data_dir: str) -> str:
    """Hat start.bat Python von python.org installiert, entfernt CLAUDIA es nicht selbst: Hinweis auf den Windows-Weg."""
    if os.name == "nt" and os.path.isfile(os.path.join(data_dir, PY_MARKER_ORG)):
        return (" Das Python selbst hat start.bat von python.org installiert; CLAUDIA entfernt es nicht. Wenn du es sonst nicht brauchst, entferne es in Windows unter "
                "Einstellungen > Apps > Installierte Apps > Python 3.12.")
    if sys.platform == "darwin" and os.path.isfile(os.path.join(data_dir, PY_MARKER_ORG)):
        return (" Das Python selbst hat start.command von python.org installiert; CLAUDIA entfernt es nicht. Wenn du es sonst nicht brauchst, lege auf dem Mac die Ordner "
                "/Library/Frameworks/Python.framework und /Applications/Python 3.12 in den Papierkorb (Administratorpasswort nötig).")
    return ""


def installed_by_setup(root: str) -> bool:
    """True, wenn der Programmordner vom Windows-Installer (Inno Setup) stammt: dort liegt dessen Deinstaller (unins000.exe)."""
    try:
        return any(n.lower().startswith("unins") and n.lower().endswith(".exe") for n in os.listdir(root))
    except OSError:
        return False


def plan(root: str, data_dir: str, reports_dir: str) -> List[Dict[str, Any]]:
    """Alle möglichen Einträge mit Pfad, Größe, Erklärung und Vorbelegung. 'exists' False = nichts zu tun."""
    root, data_dir, reports_dir = os.path.abspath(root), os.path.abspath(data_dir), os.path.abspath(reports_dir)
    items: List[Dict[str, Any]] = []

    def add(iid: str, label: str, path: str, why: str, default: bool, kind: str = "dir", personal: bool = False) -> None:
        ex = os.path.exists(path)
        it = {"id": iid, "label": label, "path": path, "why": why, "default": default and ex, "exists": ex, "personal": personal, "kind": kind}
        it.update(_size(path) if ex else {"files": 0, "bytes": 0})
        items.append(it)

    add("venv", "Eigene Python-Umgebung mit SSH-Baustein (paramiko) und Fenster-Baustein (pywebview)", os.path.join(root, ".venv"),
        "Wurde beim ersten Start im Programmordner angelegt (Ordner .venv). Sie enthält nur Python-Bausteine für dieses Programm; sonst auf dem PC nichts." + python_org_hint(data_dir), True)
    add("cache", "Zwischenspeicher (heruntergeladene Joomla-Referenzpakete)", os.path.join(data_dir, "cache"),
        "Offizielle Joomla-Pakete für den Dateivergleich. Sie werden bei Bedarf neu geladen.", True)
    add("log", "Startprotokoll", os.path.join(data_dir, "launcher.log"), "Protokoll der Startschritte.", True, "file")
    for iid, name, label in (("profiles", "profile.json", "Gespeicherte Verbindungen (ohne Passwörter)"),
                             ("hosts", "bekannte_server.json", "Gemerkte Server-Fingerabdrücke"),
                             ("prefs", "einstellungen.json", "Programmeinstellungen")):
        add(iid, label, os.path.join(data_dir, name), "Deine Daten. Nur entfernen, wenn du das Programm nicht mehr nutzen willst.", False, "file", True)
    if os.path.basename(reports_dir).lower() == "berichte":
        add("reports", "Berichte und Exporte", reports_dir, "Deine gespeicherten Prüfberichte. Sie lassen sich nicht neu erzeugen.", False, "dir", True)
    if os.path.isfile(os.path.join(data_dir, PY_MARKER)) and os.name == "nt":
        items.append({"id": "python", "label": "Python (von start.bat per winget installiert)", "path": "winget uninstall %s" % PY_WINGET_ID,
                      "why": "Python wurde auf diesem PC nur für dieses Programm installiert. Bitte nur entfernen, wenn du es sonst nicht brauchst.",
                      "default": False, "exists": True, "personal": False, "kind": "winget", "files": 0, "bytes": 0})
    if _safe_root(root) and not installed_by_setup(root):
        add("program", "Programmordner dieser Version", root, "Der Ordner mit start.bat bzw. start.command und dem Programmcode. Wird zuletzt gelöscht.", False, "dir", False)
    return items


def validate(items: List[Dict[str, Any]], ids: List[str], root: str, data_dir: str) -> List[Dict[str, Any]]:
    """Wählt aus dem Plan genau die angeforderten Einträge aus. Wirft ValueError bei unbekannten Kennungen oder unsicheren Pfaden."""
    by_id = {i["id"]: i for i in items}
    chosen = []
    for iid in ids:
        it = by_id.get(str(iid))
        if not it:
            raise ValueError("Unbekannter Eintrag: %s" % str(iid)[:40])
        if it["kind"] != "winget":
            p = it["path"]
            if re.search(r'["\n\r\x00]', p) or len(p) < 8 or os.path.dirname(p) == p:
                raise ValueError("Unsicherer Pfad: %s" % p[:80])
            if it["exists"] and not _is_plain(p):
                raise ValueError("Der Pfad ist ein Verweis und wird nicht gelöscht: %s" % p)
            inside = [os.path.abspath(root), os.path.abspath(data_dir)]
            if it["id"] == "reports":
                inside.append(os.path.dirname(p))
            if not any(os.path.normcase(os.path.abspath(p)).startswith(os.path.normcase(b) + os.sep) or os.path.normcase(os.path.abspath(p)) == os.path.normcase(b) for b in inside):
                raise ValueError("Pfad liegt außerhalb der erlaubten Ordner: %s" % p[:80])
        if it["exists"]:
            chosen.append(it)
    # Programmordner zuletzt (alles andere kann darin liegen)
    chosen.sort(key=lambda i: (i["id"] == "program", i["id"] == "python"))
    return chosen


def _cmd_path(p: str) -> str:
    return p.replace("%", "%%")


def build_script(items: List[Dict[str, Any]], pids: List[int], data_dir: str, windows: Optional[bool] = None) -> str:
    """Text des Löschskripts. Es wartet, bis die genannten Prozesse beendet sind, meldet jeden Schritt und prüft das Ergebnis."""
    win = (os.name == "nt") if windows is None else windows
    pids = [int(p) for p in pids if int(p) > 0]
    if win:
        L = ["@echo off", "chcp 65001 >nul", "title CLAUDIA deinstallieren", 'cd /d "%TEMP%"', "echo.", "echo  CLAUDIA wird deinstalliert. Dieses Fenster zeigt jeden Schritt.", "echo."]
        for p in pids:
            L += [":w%d" % p, 'tasklist /fi "PID eq %d" 2>nul | find "%d" >nul' % (p, p), "if not errorlevel 1 (timeout /t 1 /nobreak >nul & goto w%d)" % p]
        for i in items:
            if i["kind"] == "winget":
                L += ["echo  Entferne Python (winget) ...", "winget uninstall -e --id %s" % PY_WINGET_ID,
                      'del "%s" 2>nul' % _cmd_path(os.path.join(data_dir, PY_MARKER))]
                continue
            q = '"%s"' % _cmd_path(i["path"])
            L.append("echo  Entferne: %s" % re.sub(r"[&|<>^%]", "", i["label"]))
            L.append(("del /f /q %s 2>nul" % q) if i["kind"] == "file" else ("rmdir /s /q %s 2>nul" % q))
            L.append("if exist %s (echo    FEHLER: nicht vollstaendig entfernt, bitte von Hand loeschen: %s) else (echo    erledigt)" % (q, _cmd_path(i["path"])))
        L += ['rmdir "%s" 2>nul' % _cmd_path(data_dir), "echo.", "echo  Fertig. Mit einer beliebigen Taste schliessen.", "pause >nul", '(goto) 2>nul & del "%~f0"']
        return "\r\n".join(L) + "\r\n"
    L = ["#!/bin/sh", 'cd "${TMPDIR:-/tmp}"', "echo 'CLAUDIA wird deinstalliert.'"]
    for p in pids:
        L.append("while kill -0 %d 2>/dev/null; do sleep 1; done" % p)
    for i in items:
        if i["kind"] == "winget":
            continue
        L.append("echo %s" % sq("Entferne: " + i["label"]))
        L.append("rm -rf -- %s" % sq(i["path"]))
        L.append("if [ -e %s ]; then echo %s; else echo erledigt; fi" % (sq(i["path"]), sq("FEHLER: nicht vollstaendig entfernt: " + i["path"])))
    L += ["rmdir %s 2>/dev/null" % sq(data_dir), 'rm -f -- "$0"']
    return "\n".join(L) + "\n"


def write_script(items: List[Dict[str, Any]], pids: List[int], data_dir: str) -> str:
    win = os.name == "nt"
    fd, path = tempfile.mkstemp(prefix="claudia-deinstallation-", suffix=".cmd" if win else ".sh")
    with os.fdopen(fd, "w", encoding="utf-8", newline="") as fh:
        fh.write(build_script(items, pids, data_dir))
    if not win:
        os.chmod(path, 0o700)
    return path


def window_available() -> bool:
    """Das Deinstallations-Fenster braucht PySide6 (Python-Umgebung des Programms) oder ersatzweise tkinter."""
    if qt_python():
        return True
    try:
        import tkinter  # noqa: F401
        return True
    except Exception:
        return False


def qt_python() -> str:
    """Python der Programm-Umgebung (.venv), wenn dort PySide6 installiert wurde (Marke qt.ok); sonst leer. Unter Windows pythonw (ohne Konsole)."""
    if getattr(sys, "base_prefix", sys.prefix) == sys.prefix or not os.path.isfile(os.path.join(sys.prefix, "qt.ok")):
        return ""
    exe = sys.executable
    if os.name == "nt" and os.path.isfile(os.path.join(os.path.dirname(exe), "pythonw.exe")):
        exe = os.path.join(os.path.dirname(exe), "pythonw.exe")
    return exe if os.path.isfile(exe) else ""


def base_python() -> str:
    """Python außerhalb der Programm-Umgebung (.venv), damit es beim Löschen des Programmordners weiterlaufen kann; unter Windows pythonw (ohne Konsole)."""
    exe = getattr(sys, "_base_executable", "") or sys.executable
    if os.name == "nt":
        w = os.path.join(os.path.dirname(exe), "pythonw.exe")
        if os.path.isfile(w):
            return w
    return exe


def launch_window(items: List[Dict[str, Any]], pids: List[int], data_dir: str) -> str:
    """Startet das Deinstallations-Fenster als eigenen Prozess. Plan, Fenster-Dateien und Logos liegen im Temp-Ordner (werden am Ende gelöscht)."""
    import json
    import shutil
    import subprocess
    tmp = tempfile.mkdtemp(prefix="claudia-deinstallation-")
    here = os.path.dirname(os.path.abspath(__file__))
    dst = os.path.join(tmp, "uninstall_window.py")
    shutil.copyfile(os.path.join(here, "uninstall_window.py"), dst)
    shutil.copyfile(os.path.join(here, "tkskin.py"), os.path.join(tmp, "tkskin.py"))
    qt = qt_python()
    if qt:                                                                          # PySide6-Fenster: Code und Logo mitnehmen
        shutil.copyfile(os.path.join(here, "splash_qt.py"), os.path.join(tmp, "splash_qt.py"))
        os.makedirs(os.path.join(tmp, "assets"), exist_ok=True)
        shutil.copyfile(os.path.join(here, "assets", "claudia_logo.png"), os.path.join(tmp, "assets", "claudia_logo.png"))
    for w in (200, 300, 400):
        src_logo = os.path.join(here, "assets", "claudia_logo_tk_%d.png" % w)
        if os.path.isfile(src_logo):
            shutil.copyfile(src_logo, os.path.join(tmp, "claudia_logo_tk_%d.png" % w))
    plan_path = os.path.join(tmp, "plan.json")
    with open(plan_path, "w", encoding="utf-8") as fh:
        json.dump({"items": [{k: i.get(k) for k in ("id", "label", "path", "kind")} for i in items], "pids": [int(p) for p in pids], "data_dir": data_dir, "winget_id": PY_WINGET_ID}, fh)
    flags = 0x08000000 if os.name == "nt" else 0                                    # CREATE_NO_WINDOW: nur das Fenster, keine Konsole
    subprocess.Popen([qt or base_python(), dst, plan_path], cwd=tmp, close_fds=True, creationflags=flags,
                     **({} if os.name == "nt" else {"start_new_session": True, "stdin": subprocess.DEVNULL, "stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL}))
    return plan_path


def launch(script: str) -> None:
    """Startet das Skript unabhängig vom Programm (sichtbares Fenster unter Windows)."""
    import subprocess
    if os.name == "nt":
        subprocess.Popen(["cmd", "/c", script], creationflags=0x00000010, cwd=tempfile.gettempdir(), close_fds=True)        # CREATE_NEW_CONSOLE
    else:
        subprocess.Popen(["/bin/sh", script], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True, cwd=tempfile.gettempdir())
