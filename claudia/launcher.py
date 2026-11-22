"""Startprogramm mit Startbildschirm (ohne Konsolenfenster).

Was beim Start passiert, steht Schritt für Schritt im Startfenster, mit Prozentanzeige:
  1. Python prüfen             2. Programmordner prüfen
  3. Eigene Python-Umgebung (.venv) anlegen   (nur beim ersten Start)
  4. SSH-Baustein 'paramiko' installieren      (nur beim ersten Start, Download von pypi.org)
  5. Selbsttest               6. Programm starten (lokaler Server nur für diesen PC)
  7. Programmfenster öffnen
Das Startfenster gibt es nur beim Start. Sobald das Programmfenster da ist, schließt es sich: danach ist das Programmfenster das Programm.
Nichts davon läuft heimlich: jeder Schritt und jede Ausgabe erscheint im Fenster und in launcher.log.

Gestartet wird mit start.bat (der einzigen Startdatei; sie öffnet dieses Fenster ohne Konsole).
"""
from __future__ import annotations

import os
import queue
import subprocess
import sys
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from . import APP_NAME, __version__

CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0
NEW_GROUP = 0x00000200 if os.name == "nt" else 0           # eigener Prozessgruppen-Kontext: das Programm überlebt das Startfenster
DETACH: dict = {} if os.name == "nt" else {"start_new_session": True}   # Mac/Linux: eigene Sitzung, das Programm überlebt Terminal und Startfenster
MIN_PY = (3, 9)


READY = "CLAUDIA_READY"                # Der Server steht (Stichwort aus __main__)
WINDOW = "CLAUDIA_WINDOW"              # Das Programmfenster hat die Seite geladen


def child_env() -> Dict[str, str]:
    """Umgebung für Unterprozesse: Ausgabe immer als UTF-8, damit Umlaute im Startfenster stimmen."""
    env = dict(os.environ)
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"
    return env


class LaunchError(Exception):
    def __init__(self, title: str, text: str, details: str = ""):
        super().__init__(title)
        self.title, self.text, self.details = title, text, details


def console_python() -> str:
    """Python mit Konsole für Unterprozesse (venv anlegen, pip): unter 'pythonw' liegt 'python.exe' direkt daneben."""
    exe = sys.executable
    base = os.path.basename(exe).lower()
    if base in ("pythonw.exe", "pythonw"):
        cand = os.path.join(os.path.dirname(exe), "python.exe" if base.endswith(".exe") else "python")
        if os.path.isfile(cand):
            return cand
    return exe


def _as_str(text: str) -> str:
    """Text als AppleScript-Zeichenkette (für das Fehlerfenster auf dem Mac)."""
    return '"' + '" & return & "'.join(p.replace("\\", "\\\\").replace('"', '\\"') for p in text.split("\n")) + '"'


def venv_python(root: str) -> str:
    if os.name == "nt":
        return os.path.join(root, ".venv", "Scripts", "python.exe")
    return os.path.join(root, ".venv", "bin", "python")


def log_path() -> str:
    try:
        from .server import data_dir
        d = data_dir()
        os.makedirs(d, exist_ok=True)
        return os.path.join(d, "launcher.log")
    except Exception:
        return os.path.join(os.path.expanduser("~"), "claudia-launcher.log")


class Launcher:
    """Führt die Startschritte aus und meldet Fortschritt an die Oberfläche (ui)."""

    def __init__(self, root: str, ui: Any, python: Optional[str] = None,
                 popen: Callable[..., Any] = subprocess.Popen, extra_args: Optional[List[str]] = None, log_file: Optional[str] = None):
        self.root = root
        self.ui = ui
        self.python = python or console_python()
        self.popen = popen
        self.extra_args = extra_args or []
        self.log_file = log_file or log_path()
        self.child: Any = None
        self.handed_over = False
        self._plan: List[Tuple[str, str, float]] = []
        self._done_weight = 0.0
        self._cur = ("", 0.0)
        self._total = 100.0
        self._log_fh = None
        self.bootstrap = False            # True: nur Python, Ordner, Umgebung und PySide6 einrichten (Konsole, siehe --bootstrap), dann zurück

    # ---------------------------------------------------------------- Protokoll und Fortschritt
    def log(self, line: str) -> None:
        line = line.rstrip()
        stamp = time.strftime("%H:%M:%S")
        try:
            if self._log_fh is None:
                self._log_fh = open(self.log_file, "a", encoding="utf-8")
                self._log_fh.write("\n=== %s %s, %s ===\n" % (APP_NAME, __version__, time.strftime("%Y-%m-%d %H:%M:%S")))
            self._log_fh.write("%s  %s\n" % (stamp, line))
            self._log_fh.flush()
        except OSError:
            pass
        self.ui.log(line)

    def _begin(self, key: str, title: str, detail: str = "") -> None:
        w = dict((k, wt) for k, _t, wt in self._plan).get(key, 0.0)
        self._cur = (key, w)
        self.ui.update(self._pct(0.0), title, detail)
        self.log("%s %s" % (title, detail))

    def _sub(self, frac: float, title: str, detail: str = "") -> None:
        self.ui.update(self._pct(max(0.0, min(1.0, frac))), title, detail)

    def _end(self) -> None:
        self._done_weight += self._cur[1]
        self.ui.update(self._pct(0.0), "", "")

    def _pct(self, frac: float) -> int:
        return int(min(100, round(100.0 * (self._done_weight + self._cur[1] * frac) / self._total)))

    # ---------------------------------------------------------------- Plan
    def make_plan(self) -> List[Tuple[str, str, float]]:
        vpy = venv_python(self.root)
        need_venv = not os.path.isfile(vpy)
        need_pip = need_venv or not os.path.isfile(os.path.join(self.root, ".venv", "paramiko.ok"))
        self.need_window_pkg = need_venv or not os.path.isfile(os.path.join(self.root, ".venv", "webview.ok"))
        steps = [("py", "Python prüfen", 3.0), ("dir", "Programmordner prüfen", 3.0)]
        if need_venv:
            steps.append(("venv", "Eigene Python-Umgebung anlegen (einmalig)", 20.0))
        self.need_qt_pkg = need_venv or not os.path.isfile(os.path.join(self.root, ".venv", "qt.ok"))
        if self.need_qt_pkg:           # gleich nach der Umgebung: ab dann läuft der Startbildschirm mit PySide6
            steps.append(("pyqt", "Startbildschirm einrichten (einmalig, Download)", 25.0))
        if not self.bootstrap:
            if need_pip:
                steps.append(("pip", "SSH-Baustein 'paramiko' installieren (einmalig, Download)", 35.0))
            if self.need_window_pkg:
                steps.append(("pipwin", "Fenster-Baustein 'pywebview' installieren (einmalig, Download)", 25.0))
            steps += [("self", "Programm prüfen (Selbsttest)", 8.0), ("start", "Programm starten", 12.0), ("window", "Programmfenster öffnen", 6.0)]
        total = sum(w for _k, _t, w in steps)
        self._total = total
        self._plan = steps
        return steps

    # ---------------------------------------------------------------- Hilfen
    def _run(self, args: List[str], timeout: float, on_line: Optional[Callable[[str], None]] = None) -> Tuple[int, str]:
        self.log("Befehl: " + " ".join(args))
        try:
            p = self.popen(args, cwd=self.root, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                           encoding="utf-8", errors="replace", creationflags=CREATE_NO_WINDOW, env=child_env())
        except OSError as e:
            return 127, str(e)
        q: "queue.Queue[Optional[str]]" = queue.Queue()

        def reader() -> None:
            try:
                for ln in p.stdout:                    # type: ignore[union-attr]
                    q.put(ln)
            finally:
                q.put(None)
        threading.Thread(target=reader, daemon=True).start()
        out: List[str] = []
        start = time.monotonic()
        while True:
            try:
                ln = q.get(timeout=0.2)
            except queue.Empty:
                if time.monotonic() - start > timeout:
                    p.kill()
                    return 124, "".join(out) + "\nZeitüberschreitung nach %d Sekunden." % timeout
                continue
            if ln is None:
                break
            out.append(ln)
            self.log(ln)
            if on_line:
                on_line(ln)
        return p.wait(), "".join(out)

    # ---------------------------------------------------------------- Ablauf
    def run(self) -> None:
        """Führt alle Schritte aus, bis das Programmfenster geöffnet ist. Wirft LaunchError."""
        self.make_plan()
        vpy = venv_python(self.root)

        self._begin("py", "Python prüfen", "Version %s" % sys.version.split()[0])
        if sys.version_info[:2] < MIN_PY:
            raise LaunchError("Python ist zu alt", "Dieses Programm braucht Python %d.%d oder neuer. Gefunden: %s." % (MIN_PY + (sys.version.split()[0],)))
        self._end()

        self._begin("dir", "Programmordner prüfen", self.root)
        for need in ("claudia", "requirements.txt"):
            if not os.path.exists(os.path.join(self.root, need)):
                raise LaunchError("Programmdateien fehlen", "Im Ordner '%s' fehlt '%s'. Bitte die ZIP-Datei vollständig entpacken." % (self.root, need))
        try:
            probe = os.path.join(self.root, ".schreibtest")
            with open(probe, "w") as fh:
                fh.write("x")
            os.remove(probe)
        except OSError:
            raise LaunchError("Der Programmordner ist schreibgeschützt",
                              "Bitte den Ordner an einen normalen Ort verschieben, z. B. auf den Desktop oder nach C:\\CLAUDIA, und erneut starten.")
        self._end()

        if "venv" in [k for k, _t, _w in self._plan]:
            self._begin("venv", "Eigene Python-Umgebung anlegen", "Ordner .venv (ändert nichts am restlichen System)")
            rc, out = self._run([self.python, "-m", "venv", os.path.join(self.root, ".venv")], 300)
            if rc != 0 or not os.path.isfile(vpy):
                raise LaunchError("Die Python-Umgebung konnte nicht angelegt werden", "Ist der Ordner schreibgeschützt? Details stehen unten und in launcher.log.", out[-1500:])
            self._end()

        if "pyqt" in [k for k, _t, _w in self._plan]:
            self._begin("pyqt", "Startbildschirm einrichten", "Installiert 'PySide6-Essentials' von pypi.org (einmalig, ca. 80 MB)")
            rc, out = self._run([vpy, "-m", "pip", "install", "--disable-pip-version-check", "--progress-bar", "off", "-r", "requirements-splash.txt"], 900,
                                lambda ln: self._sub(0.5, "Startbildschirm einrichten", ln.strip()[:90]))
            if rc == 0:
                try:
                    with open(os.path.join(self.root, ".venv", "qt.ok"), "w") as fh:
                        fh.write("ok")
                except OSError:
                    pass
            else:       # kein Abbruch: der Startbildschirm bleibt dann der einfache aus tkinter
                self.log("PySide6 konnte nicht installiert werden. Es wird der einfache Ersatz-Startbildschirm (tkinter) benutzt.")
            self._end()
            if self.bootstrap:
                return

        if "pip" in [k for k, _t, _w in self._plan]:
            self._begin("pip", "SSH-Baustein 'paramiko' installieren", "Lädt das Paket von pypi.org (einmalig)")
            state = {"f": 0.05}

            def on_line(ln: str) -> None:
                low = ln.lower()
                if low.startswith("collecting"):
                    state["f"] = min(0.4, state["f"] + 0.1)
                elif low.startswith("downloading") or "using cached" in low:
                    state["f"] = min(0.7, state["f"] + 0.1)
                elif low.startswith("installing collected"):
                    state["f"] = 0.85
                elif low.startswith("successfully installed"):
                    state["f"] = 1.0
                self._sub(state["f"], "SSH-Baustein 'paramiko' installieren", ln.strip()[:90])
            rc, out = self._run([vpy, "-m", "pip", "install", "--disable-pip-version-check", "--progress-bar", "off", "-r", "requirements.txt"], 900, on_line)
            if rc != 0:
                raise LaunchError("Die Installation von paramiko ist fehlgeschlagen",
                                  "Ist der PC mit dem Internet verbunden? Eine Firmen-Firewall kann pip blockieren.", out[-1500:])
            try:
                with open(os.path.join(self.root, ".venv", "paramiko.ok"), "w") as fh:
                    fh.write("ok")
            except OSError:
                pass
            self._end()

        if "pipwin" in [k for k, _t, _w in self._plan]:
            self._begin("pipwin", "Fenster-Baustein 'pywebview' installieren", "Eigenes Programmfenster statt Browser (einmalig, optional)")
            rc, out = self._run([vpy, "-m", "pip", "install", "--disable-pip-version-check", "--progress-bar", "off", "-r", "requirements-window.txt"], 900,
                                lambda ln: self._sub(0.5, "Fenster-Baustein 'pywebview' installieren", ln.strip()[:90]))
            if rc == 0:
                try:
                    with open(os.path.join(self.root, ".venv", "webview.ok"), "w") as fh:
                        fh.write("ok")
                except OSError:
                    pass
            else:       # kein Abbruch: das Programm öffnet dann ein App-Fenster von Edge/Chrome
                self.log("pywebview konnte nicht installiert werden. Das Programm nutzt stattdessen ein App-Fenster von Edge oder Chrome.")
            self._end()

        self._begin("self", "Programm prüfen (Selbsttest)", "python -m claudia --selftest")
        rc, out = self._run([vpy if os.path.isfile(vpy) else self.python, "-m", "claudia", "--selftest"], 120)
        if rc != 0:
            raise LaunchError("Der Selbsttest hat Probleme gemeldet", "Details stehen unten und in launcher.log.", out[-1500:])
        self._end()

        self._begin("start", "Programm starten", "Lokaler Server, nur von diesem PC aus erreichbar (127.0.0.1)")
        args = [vpy if os.path.isfile(vpy) else self.python, "-m", "claudia", "--parent-pid", str(os.getpid())] + self.extra_args
        self.log("Befehl: " + " ".join(args))
        try:
            self.child = self.popen(args, cwd=self.root, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    text=True, encoding="utf-8", errors="replace", creationflags=CREATE_NO_WINDOW | NEW_GROUP, env=child_env(), **DETACH)
        except OSError as e:
            raise LaunchError("Das Programm konnte nicht gestartet werden", str(e))
        q: "queue.Queue[Optional[str]]" = queue.Queue()

        def drain() -> None:
            try:
                for ln in self.child.stdout:
                    q.put(ln)
                    self.log(ln)
            except (OSError, ValueError):
                pass
            finally:
                q.put(None)
        threading.Thread(target=drain, daemon=True).start()
        seen: List[str] = []

        def wait_for(word: str, limit: float, title: str, detail: str, what: str) -> None:
            t0 = time.monotonic()
            while True:
                try:
                    ln = q.get(timeout=0.2)
                except queue.Empty:
                    if time.monotonic() - t0 > limit:
                        self.stop()
                        raise LaunchError("Das Programm antwortet nicht", "%s ist nach %d Sekunden nicht bereit." % (what, limit), "".join(seen)[-1500:])
                    self._sub(min(0.9, (time.monotonic() - t0) / (limit / 2.0)), title, detail)
                    continue
                if ln is None:
                    raise LaunchError("Das Programm wurde sofort beendet", "Details stehen unten und in launcher.log.", "".join(seen)[-1500:])
                seen.append(ln)
                if word in ln:
                    return
        wait_for(READY, 45, "Programm starten", "Warte auf den lokalen Server ...", "Der lokale Server")
        self._end()

        self._begin("window", "Programmfenster öffnen", "Das Startfenster schließt sich, sobald das Programmfenster da ist")
        wait_for(WINDOW, 60, "Programmfenster öffnen", "Warte auf das Programmfenster ...", "Das Programmfenster")
        self._end()
        self.handed_over = True
        self.ui.update(100, "Fertig", "Das Programmfenster ist geöffnet.")
        self.log("Übergabe an das Programmfenster. Das Startfenster schließt sich.")

    def release(self) -> None:
        """Nach der Übergabe: das Programm läuft eigenständig weiter, hier wird nur noch aufgeräumt (der Server wird NICHT beendet)."""
        self.close_log()

    def alive(self) -> bool:
        return bool(self.child and self.child.poll() is None)

    def stop(self) -> None:
        c = self.child
        if c is not None and c.poll() is None:
            try:
                c.terminate()
                c.wait(5)
            except Exception:
                try:
                    c.kill()
                except Exception:
                    pass
        if c is not None:
            try:
                if c.stdout:
                    c.stdout.close()
            except Exception:
                pass
        self.close_log()

    def close_log(self) -> None:
        fh, self._log_fh = self._log_fh, None
        if fh is not None:
            try:
                fh.close()
            except OSError:
                pass


# ------------------------------------------------------------------------------------------------ Oberflächen
class ConsoleUi:
    """Ohne Fenster (wenn tkinter fehlt): Ausgabe nur ins Protokoll, Fehler als Windows-Meldung."""

    def __init__(self) -> None:
        self.lines: List[str] = []
        self.done = threading.Event()
        self.failed = False

    def update(self, pct: int, title: str, detail: str) -> None:
        pass

    def log(self, line: str) -> None:
        self.lines.append(line)

    def error(self, title: str, text: str, details: str, path: str) -> None:
        self.failed = True
        self.done.set()
        msg = "%s\n\n%s\n\nProtokoll: %s" % (title, text, path)
        if os.name == "nt":
            try:
                import ctypes
                ctypes.windll.user32.MessageBoxW(0, msg, APP_NAME, 0x10)      # type: ignore[attr-defined]
                return
            except Exception:
                pass
        elif sys.platform == "darwin":
            try:
                subprocess.run(["osascript", "-e", 'display dialog %s with title %s buttons {"OK"} default button "OK" with icon stop' % (_as_str(msg), _as_str(APP_NAME))],
                               timeout=600, check=False, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                return
            except Exception:
                pass
        sys.stderr.write(msg + "\n" + details + "\n")

    def finished(self) -> None:
        self.done.set()

    def mainloop(self, launcher: Launcher) -> None:
        self.done.wait()


MONO_PREFERENCE = ("Consolas", "Cascadia Mono", "Lucida Console", "DejaVu Sans Mono", "Courier New")
BG, FG, DIM, ACCENT = "#0d1418", "#e6f1f6", "#9fb4c0", "#2bb3c9"         # dunkel wie ein Befehlsfenster, hoher Kontrast


def pick_mono(families) -> str:
    have = {f.lower(): f for f in families}
    for name in MONO_PREFERENCE:
        if name.lower() in have:
            return have[name.lower()]
    return "TkFixedFont"


def _tk_ui():
    """Tk-Oberfläche. Liefert None, wenn tkinter nicht verfügbar ist.
    Alles in derselben Schrift wie im Befehlsfenster (Konsolenschrift), hell auf dunkel: gut lesbar und einheitlich."""
    try:
        import tkinter as tk
        from . import tkskin
    except Exception:
        return None

    class TkUi:
        W, H = 765, 560            # Grundgröße bei 100 % Skalierung; wird an Bildschirm und Windows-Skalierung angepasst

        def __init__(self) -> None:
            if os.name == "nt":
                try:                 # scharfe Schrift auf Bildschirmen mit Skalierung
                    import ctypes
                    ctypes.windll.shcore.SetProcessDpiAwareness(1)      # type: ignore[attr-defined]
                except Exception:
                    pass
            self.q: "queue.Queue[Tuple[str, Any]]" = queue.Queue()
            self.root = tk.Tk()
            self.root.title(APP_NAME)
            try:
                self.scale = max(1.0, self.root.winfo_fpixels("1i") / 96.0)
            except Exception:
                self.scale = 1.0
            self.root.minsize(int(620 * self.scale), int(460 * self.scale))
            self.center(self.W, self.H)
            self.root.protocol("WM_DELETE_WINDOW", self._on_close)
            self.skin = tkskin.Skin(self.root, self.scale, os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets"), True, "Starte ...")
            self.buttons = self.skin.buttons
            self.skin.button(self.buttons, "Abbrechen und beenden", self._on_close, width=26).pack(side="right")
            self.root.after(80, self._poll)

        def center(self, w: int, h: int) -> None:
            """Fenstergröße setzen und mittig auf dem Bildschirm platzieren (passt sich kleinen Bildschirmen an)."""
            self.root.update_idletasks()
            sw, sh = self.root.winfo_screenwidth(), self.root.winfo_screenheight()
            w, h = min(int(w * self.scale), sw - 60), min(int(h * self.scale), sh - 100)
            x, y = max(0, (sw - w) // 2), max(0, (sh - h) // 2 - 20)
            self.root.geometry("%dx%d+%d+%d" % (w, h, x, y))

        # --- Aufrufe aus dem Arbeits-Thread: nur in die Warteschlange legen
        def update(self, pct: int, title: str, detail: str) -> None:
            self.q.put(("update", (pct, title, detail)))

        def log(self, line: str) -> None:
            self.q.put(("log", line))

        def error(self, title: str, text: str, details: str, path: str) -> None:
            self.q.put(("error", (title, text, details, path)))

        def finished(self) -> None:
            self.q.put(("close", None))

        # --- im Haupt-Thread
        def _poll(self) -> None:
            try:
                while True:
                    kind, data = self.q.get_nowait()
                    if kind == "update":
                        pct, title, detail = data
                        self.skin.set_pct(pct)
                        if title:
                            self.skin.title_var.set(title)
                            self.skin.detail_var.set(detail)
                    elif kind == "log":
                        self.skin.add_log(data)
                    elif kind == "error":
                        self._show_error(*data)
                    elif kind == "close":
                        self.root.destroy()
                        return
            except queue.Empty:
                pass
            self.root.after(80, self._poll)

        def _show_error(self, title: str, text: str, details: str, path: str) -> None:
            self.skin.title_var.set(title)
            if details:
                self.skin.add_log("\n--- Ausgabe ---\n" + details, "bad")
            self.skin.detail_var.set(text + "\nProtokoll: " + path)
            for w in self.buttons.winfo_children():
                w.destroy()
            self.skin.button(self.buttons, "Schließen", self.root.destroy, width=14).pack(side="right")

        def _on_close(self) -> None:
            self.root.destroy()

        def mainloop(self, launcher: Launcher) -> None:
            self.root.mainloop()

    return TkUi()


class BootstrapUi:
    """Einmalige Einrichtung im Konsolenfenster von start.bat (Python-Umgebung und PySide6), solange es noch keinen schönen Startbildschirm geben kann."""

    def __init__(self) -> None:
        self.done = threading.Event()
        self.failed = False
        self._last = -1

    def _say(self, text: str) -> None:
        try:
            sys.stdout.write(text + "\n")
            sys.stdout.flush()
        except (OSError, UnicodeError, ValueError):
            pass

    def update(self, pct: int, title: str, detail: str) -> None:
        if title and pct != self._last:
            self._last = pct
            self._say("  [%3d %%] %s" % (pct, title.encode("ascii", "replace").decode("ascii")))

    def log(self, line: str) -> None:
        pass

    def error(self, title: str, text: str, details: str, path: str) -> None:
        self.failed = True
        self._say("  Hinweis: %s. Der einfache Startbildschirm wird benutzt. Protokoll: %s" % (title.encode("ascii", "replace").decode("ascii"), path))
        self.done.set()

    def finished(self) -> None:
        self.done.set()

    def mainloop(self, launcher: Launcher) -> None:
        self.done.wait()


def _qt_ui():
    """Startbildschirm mit PySide6 (siehe splash_qt.py). None, wenn PySide6 hier nicht verfügbar ist (dann tkinter)."""
    if os.environ.get("CLAUDIA_NO_QT"):
        return None
    try:
        from .splash_qt import QtUi
        return QtUi()
    except Exception:
        return None


def _reexec_in_venv(root: str) -> bool:
    """Ab dem zweiten Start liegt PySide6 in der eigenen Umgebung (.venv). Dann dort neu starten, damit der schöne Startbildschirm laufen kann.
    True = es wurde neu gestartet, dieser Prozess soll enden. Nur einmal (CLAUDIA_NO_REEXEC) und nur, wenn die Marke qt.ok vorhanden ist."""
    if os.environ.get("CLAUDIA_NO_REEXEC") or os.environ.get("CLAUDIA_NO_QT"):
        return False
    venv = os.path.join(root, ".venv")
    if not os.path.isfile(os.path.join(venv, "qt.ok")):
        return False
    if os.path.normcase(os.path.abspath(sys.prefix)) == os.path.normcase(os.path.abspath(venv)):
        return False
    vpy = venv_python(root)
    if os.name == "nt":
        w = os.path.join(venv, "Scripts", "pythonw.exe")           # ohne Konsolenfenster
        vpy = w if os.path.isfile(w) else vpy
    if not os.path.isfile(vpy):
        return False
    env = child_env()
    env["CLAUDIA_NO_REEXEC"] = "1"
    try:
        subprocess.Popen([vpy, "-m", "claudia.launcher"], cwd=root, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         creationflags=CREATE_NO_WINDOW | NEW_GROUP, **DETACH)
    except OSError:
        return False
    return True


def main(root: Optional[str] = None, argv: Optional[List[str]] = None) -> int:
    root = root or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    boot = "--bootstrap" in (sys.argv[1:] if argv is None else argv)
    if not boot and _reexec_in_venv(root):
        return 0
    ui = BootstrapUi() if boot else (_qt_ui() or _tk_ui() or ConsoleUi())
    launcher = Launcher(root, ui)
    launcher.bootstrap = boot

    def work() -> None:
        try:
            launcher.run()
            time.sleep(0.4)
            ui.finished()                        # Startfenster zu: ab jetzt gibt es nur noch das Programmfenster
        except LaunchError as e:
            launcher.log("FEHLER: %s - %s" % (e.title, e.text))
            launcher.stop()
            ui.error(e.title, e.text, e.details, launcher.log_file)
        except Exception as e:  # pragma: no cover
            launcher.log("FEHLER: %s: %s" % (type(e).__name__, e))
            launcher.stop()
            ui.error("Unerwarteter Fehler", "%s: %s" % (type(e).__name__, e), "", launcher.log_file)

    threading.Thread(target=work, daemon=True).start()
    ui.mainloop(launcher)
    if launcher.handed_over:
        launcher.release()                       # Programm läuft eigenständig weiter
    else:
        launcher.stop()                          # Abbruch oder Fehler: nichts im Hintergrund zurücklassen
    return 1 if boot and getattr(ui, "failed", False) else 0


if __name__ == "__main__":
    sys.exit(main())
