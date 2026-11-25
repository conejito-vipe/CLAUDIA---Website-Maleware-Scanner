"""Startet das Programm: lokaler Server plus eigenes Programmfenster (siehe window.py).

    python -m claudia               normal starten (öffnet das Programmfenster)
    python -m claudia --port 8765   festen Port verwenden

Gedacht ist der Start über start.bat. Es gibt absichtlich keine Option, die den Zugangsschlüssel ausgibt oder das Programm ohne Fenster bedienbar macht.
"""
from __future__ import annotations

import argparse
import os
import json
import sys
import threading
from typing import Any, Callable, Optional

from . import APP_NAME, __version__
from .server import make_server
from . import window


RESOURCES = ("web/index.html", "web/app.js", "lang/de.json", "lang/en.json", "docs/handbuch.de.txt", "docs/handbuch.en.txt", "docs/technik.de.txt",
             "docs/aenderungen.en.txt", "advisories.json", "icons.json", "loc.json", "security_tools.json", "backup_tools.json", "known_tools.json", "assets/claudia.ico")


def resources_ok():
    """Liegen alle Programmdaten (Oberfläche, Hilfetexte, Sprachen, Listen) neben dem Programmcode? Wichtig für die einzelne Programmdatei: fehlt hier etwas, fehlt es im Paket.
    Das Kapitel 'Technik' liest außerdem den echten Quelltext; auch das wird geprüft."""
    here = os.path.dirname(os.path.abspath(__file__))
    missing = [r for r in RESOURCES if not os.path.isfile(os.path.join(here, *r.split("/")))]
    try:
        from . import techdoc
        if not techdoc.payload("de"):
            missing.append("Technik-Kapitel")
    except Exception as e:                                          # noqa: BLE001  (Selbsttest soll melden, nicht abstürzen)
        missing.append("Technik-Kapitel (%s)" % type(e).__name__)
    return not missing, missing


def selftest() -> int:
    import os
    import platform
    from .registry import load_all, ordered
    from .server import data_dir, reports_dir
    ok = True
    print("%s %s" % (APP_NAME, __version__))
    print("Python:      %s (%s)" % (platform.python_version(), platform.system()))
    try:
        import paramiko  # type: ignore
        print("paramiko:    %s" % getattr(paramiko, "__version__", "vorhanden"))
    except ImportError:
        print("paramiko:    FEHLT (bitte start.bat bzw. start.command ausführen oder: pip install paramiko)")
        ok = False
    load_all()
    n = len(ordered())
    print("Tests:       %d geladen" % n)
    ok = ok and n > 0
    if getattr(sys, "frozen", False):
        print("Fassung:     einzelne Programmdatei (ohne Python-Einrichtung)")
    res_ok, missing = resources_ok()
    print("Programmdaten: %s" % ("vollständig" if res_ok else "FEHLEN: " + ", ".join(missing)))
    ok = ok and res_ok
    for label, d in (("Profile", data_dir()), ("Berichte", reports_dir())):
        try:
            os.makedirs(d, exist_ok=True)
            probe = os.path.join(d, ".schreibtest")
            with open(probe, "w") as fh:
                fh.write("x")
            os.remove(probe)
            print("%-12s %s (beschreibbar)" % (label + ":", d))
        except OSError as e:
            print("%-12s %s NICHT beschreibbar: %s" % (label + ":", d, e))
            ok = False
    print("Ergebnis:    %s" % ("alles in Ordnung" if ok else "Es gibt Probleme (siehe oben)"))
    return 0 if ok else 1


def pid_alive(pid: int) -> bool:
    """Läuft der Prozess mit dieser Nummer noch? (Windows und Linux)"""
    import os
    if pid <= 0:
        return False
    if os.name == "nt":
        try:
            import ctypes
            k = ctypes.windll.kernel32            # type: ignore[attr-defined]
            h = k.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
            if not h:
                return False
            code = ctypes.c_ulong()
            ok = k.GetExitCodeProcess(h, ctypes.byref(code))
            k.CloseHandle(h)
            return bool(ok) and code.value == 259   # STILL_ACTIVE
        except Exception:
            return True
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def watch_parent(pid: int, stop, interval: float = 1.5, cancel: Optional[threading.Event] = None) -> threading.Thread:
    """Beendet das Programm, sobald das Startfenster (Elternprozess) vor der Übergabe wegfällt - kein verwaister Hintergrundprozess.
    Nach der Übergabe (cancel gesetzt) ist das Programmfenster selbst das Programm."""
    import time

    def run() -> None:
        while pid_alive(pid):
            if cancel is not None and cancel.is_set():
                return
            time.sleep(interval)
        if cancel is None or not cancel.is_set():
            stop()
    t = threading.Thread(target=run, daemon=True)
    t.start()
    return t


def main(argv=None, show: Optional[Callable[[Any], str]] = None) -> int:
    """show: ersetzt das Programmfenster (nur für Tests): bekommt den Server, gibt den benutzten Weg zurück."""
    ap = argparse.ArgumentParser(prog="claudia", description=APP_NAME)
    ap.add_argument("--port", type=int, default=0, help="Port (Standard: zufällig)")
    ap.add_argument("--lang", metavar="CODE", help="Sprache der Oberfläche und Berichte (z. B. de, en); Standard: gespeicherte Auswahl bzw. Sprache des PCs")
    ap.add_argument("--parent-pid", type=int, default=0, help="(vom Startfenster benutzt) beenden, wenn dieser Prozess vor der Übergabe an das Programmfenster endet")
    ap.add_argument("--selftest", action="store_true", help="Umgebung prüfen (Python, paramiko, Ordner) und beenden")
    ap.add_argument("--dev-demo", metavar="WORLD_JSON", help="(Entwicklung) lokale Testwelt statt SSH verwenden")
    args = ap.parse_args(argv)

    if args.selftest:
        return selftest()

    if args.lang:
        os.environ["CLAUDIA_LANG"] = args.lang
    else:
        try:
            import locale
            os.environ.setdefault("CLAUDIA_LANG_DEFAULT", (locale.getlocale()[0] or os.environ.get("LANG", "") or "")[:2].lower())
        except (ValueError, TypeError):
            pass
    world = None
    if args.dev_demo:
        with open(args.dev_demo, "r", encoding="utf-8") as fh:
            world = json.load(fh)
    try:
        srv = make_server(port=args.port, demo_world=world)
    except OSError as e:
        print("Der Port ist nicht verfügbar: %s" % e)
        return 1
    print("%s %s" % (APP_NAME, __version__))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    if not os.environ.get("CLAUDIA_NO_UPDATE_CHECK"):
        srv.app.selfupd_check_async()               # sucht im Hintergrund nach einer neuen Version; installiert wird nur nach Rückfrage im Fenster
    print("CLAUDIA_READY")                            # Stichwort für das Startfenster: der Server steht
    sys.stdout.flush()

    handed_over = threading.Event()
    if args.parent_pid:
        srv.app.parent_pid = args.parent_pid
        watch_parent(args.parent_pid, srv.stop, cancel=handed_over)

    def announce() -> None:
        """Die Seite ist im Programmfenster geladen: das Startfenster darf sich schließen."""
        handed_over.set()
        print("CLAUDIA_WINDOW")
        sys.stdout.flush()
        if args.parent_pid:
            window.silence_output()

    win = window.Window(srv, announce)
    try:
        show(srv) if show else win.show()
    except KeyboardInterrupt:
        pass
    finally:
        srv.app.disconnect()
        srv.shutdown_and_close()
    if not args.parent_pid:
        print("Beendet.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
