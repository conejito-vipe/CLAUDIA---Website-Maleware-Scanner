#!/usr/bin/env python3
"""Baut die einzelne Programmdatei ohne Python-Einrichtung mit PyInstaller.

  python tools/build_exe.py [Zielordner]         Standard: ./dist-exe
  python tools/build_exe.py --check              nur Voraussetzungen prüfen (PyInstaller, Bausteine), nichts bauen

Ergebnis je nach System (immer ein ZIP mit dem Namen CLAUDIA_v<Version>_<System>.zip im Zielordner):
  Windows   CLAUDIA\\CLAUDIA.exe (Ordner mit Programmdatei und Bausteinen; "onedir", damit der Start schnell ist und Virenscanner weniger anschlagen)
  Mac       CLAUDIA.app (Programmpaket; ungesigniert: beim ersten Start Rechtsklick > Öffnen)
  Linux     nur zum Testen der Verpackung (CLAUDIA-Ordner)

Windows und Mac lassen sich nur auf dem jeweiligen System bauen; dafür gibt es den Workflow .github/workflows/release.yml.
Die Programmdaten (Oberfläche, Hilfetexte, Sprachdateien, Listen) liegen im Paket unter claudia/..., genau wie im Quellordner."""
from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
import zipfile
from typing import List

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from claudia import __version__  # noqa: E402

NAME = "CLAUDIA"
HIDDEN = ["paramiko", "cryptography", "cryptography.hazmat.primitives.asymmetric.ed25519"]      # Bausteine, die PyInstaller nicht immer von selbst findet
SKIP_NAMES = {"__pycache__", ".pytest_cache"}


def system_label() -> str:
    return {"win32": "Windows", "darwin": "Mac"}.get(sys.platform, "Linux")


def stage_package(dst: str) -> str:
    """Kopie des Pakets 'claudia' (ohne Zwischendateien) für die Programmdaten. Die .py-Dateien gehören dazu: das Kapitel 'Technik' liest den echten Quelltext."""
    shutil.rmtree(dst, ignore_errors=True)
    shutil.copytree(os.path.join(ROOT, "claudia"), os.path.join(dst, "claudia"), ignore=shutil.ignore_patterns(*SKIP_NAMES, "*.pyc"))
    return os.path.join(dst, "claudia")


def pyinstaller_args(workdir: str, staged: str) -> List[str]:
    sep = os.pathsep
    args = [sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean", "--name", NAME, "--onedir",
            "--distpath", os.path.join(workdir, "dist"), "--workpath", os.path.join(workdir, "build"), "--specpath", workdir,
            "--add-data", "%s%sclaudia" % (staged, sep), "--collect-submodules", "claudia"]
    if sys.platform != "linux":
        args.append("--windowed")                                   # ohne Konsolenfenster
    for h in HIDDEN:
        args += ["--hidden-import", h]
    if sys.platform in ("win32", "darwin"):
        args += ["--collect-submodules", "webview"]                 # Fenster-Baustein (pywebview) samt Plattformteilen
    icon = os.path.join(ROOT, "claudia", "assets", "claudia.ico")
    if sys.platform == "win32" and os.path.isfile(icon):
        args += ["--icon", icon]
    if sys.platform == "darwin":
        args += ["--osx-bundle-identifier", "io.github.conejito-vipe.claudia"]
    args.append(os.path.join(ROOT, "installer", "exe_main.py"))
    return args


def zip_dir(src: str, zpath: str, top: str) -> None:
    with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as z:
        for base, dirs, names in os.walk(src):
            dirs.sort()
            for n in sorted(names):
                full = os.path.join(base, n)
                arc = os.path.join(top, os.path.relpath(full, src)).replace(os.sep, "/")
                info = zipfile.ZipInfo.from_file(full, arc)             # behält Ausführungsrechte (wichtig auf dem Mac)
                info.compress_type = zipfile.ZIP_DEFLATED
                with open(full, "rb") as fh:
                    z.writestr(info, fh.read())


def check() -> int:
    ok = True
    try:
        import PyInstaller  # noqa: F401
        print("PyInstaller: %s" % PyInstaller.__version__)
    except ImportError:
        print("PyInstaller: FEHLT (pip install pyinstaller)")
        ok = False
    for mod in ("paramiko", "cryptography"):
        try:
            __import__(mod)
            print("%-12s vorhanden" % (mod + ":"))
        except ImportError:
            print("%-12s FEHLT (pip install -r requirements.txt)" % (mod + ":"))
            ok = False
    if sys.platform in ("win32", "darwin"):
        try:
            import webview  # noqa: F401
            print("webview:     vorhanden")
        except ImportError:
            print("webview:     FEHLT (pip install pywebview)")
            ok = False
    return 0 if ok else 1


def main(argv: List[str]) -> int:
    if "--check" in argv:
        return check()
    target = os.path.abspath(next((a for a in argv[1:] if not a.startswith("-")), os.path.join(ROOT, "dist-exe")))
    if check() != 0:
        return 1
    work = os.path.join(target, "_work")
    os.makedirs(target, exist_ok=True)
    staged = stage_package(os.path.join(work, "data"))
    cmd = pyinstaller_args(work, staged)
    print("Starte: " + " ".join(cmd[2:6]) + " ...")
    if subprocess.call(cmd, cwd=ROOT) != 0:
        print("PyInstaller ist fehlgeschlagen.")
        return 1
    dist = os.path.join(work, "dist")
    if sys.platform == "darwin":
        src, top = os.path.join(dist, NAME + ".app"), NAME + ".app"
    else:
        src, top = os.path.join(dist, NAME), NAME
    if not os.path.exists(src):
        print("Erwartetes Ergebnis fehlt: " + src)
        return 1
    zpath = os.path.join(target, "CLAUDIA_v%s_%s.zip" % (__version__, system_label()))
    if sys.platform == "darwin":
        subprocess.call(["ditto", "-c", "-k", "--keepParent", src, zpath])      # ditto erhält Rechte und Paketaufbau des Mac-Programms
    else:
        zip_dir(src, zpath, top)
    print("Fertig: %s" % zpath)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
