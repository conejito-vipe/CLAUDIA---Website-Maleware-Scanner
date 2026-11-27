"""Das Programmfenster: CLAUDIA läuft in einem eigenen Fenster, nicht in einem Browser-Tab.

Reihenfolge (jeweils der nächste Weg, wenn der vorige nicht geht):
  1. Eigenes Fenster mit 'pywebview' (nutzt die Edge-Engine von Windows, kein Browser-Tab, keine Adressleiste).
  2. Edge oder Chrome im App-Modus (ein Fenster nur für CLAUDIA, ohne Tabs und Adressleiste, eigenes Profil).
  3. Notfall: normaler Browser. Dann endet das Programm, wenn der Browser keine Lebenszeichen mehr schickt.

Der Zugang läuft über einen Einmal-Startschlüssel, der nur an das eigene Fenster geht (siehe server.Server.entry_url).
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import webbrowser
from typing import Any, Callable, List, Optional

from . import APP_NAME, __version__, i18n

WIDTH, HEIGHT = 1360, 900
MIN_W, MIN_H = 960, 640
MAX_SIZE = 10000
PING_TIMEOUT = 90.0


def app_browser() -> Optional[str]:
    """Edge oder Chrome (für den App-Modus). None, wenn keiner gefunden wird."""
    cands: List[str] = []
    if os.name == "nt":
        roots = [os.environ.get(k, "") for k in ("ProgramFiles(x86)", "ProgramFiles", "LOCALAPPDATA")]
        for r in roots:
            if r:
                cands += [os.path.join(r, "Microsoft", "Edge", "Application", "msedge.exe"), os.path.join(r, "Google", "Chrome", "Application", "chrome.exe")]
    if sys.platform == "darwin":                                       # macOS: Programme im Ordner Programme (auch im Benutzerordner)
        home = os.path.expanduser("~")
        for base in ("/Applications", os.path.join(home, "Applications")):
            for app, exe in (("Google Chrome", "Google Chrome"), ("Microsoft Edge", "Microsoft Edge"), ("Chromium", "Chromium"), ("Brave Browser", "Brave Browser")):
                cands.append(os.path.join(base, app + ".app", "Contents", "MacOS", exe))
    for n in ("msedge", "microsoft-edge", "google-chrome", "chrome", "chromium", "chromium-browser"):
        w = shutil.which(n)
        if w:
            cands.append(w)
    for c in cands:
        if c and os.path.isfile(c):
            return c
    return None


def _mac_dock_icon() -> None:
    """Auf dem Mac das CLAUDIA-Symbol im Dock zeigen (sonst das Python-Symbol). Nur ein Versuch, Fehler sind unkritisch."""
    if sys.platform != "darwin":
        return
    try:
        from AppKit import NSApplication, NSImage          # type: ignore  # kommt mit pywebview (pyobjc)
        png = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets", "claudia_logo.png")
        img = NSImage.alloc().initWithContentsOfFile_(png)
        if img is not None:
            NSApplication.sharedApplication().setApplicationIconImage_(img)
    except Exception:
        pass


def _win_app_id() -> None:
    """Windows: eigene Programm-Kennung, damit die Taskleiste CLAUDIA statt Python zeigt und das Symbol nicht mit anderen Python-Programmen gruppiert wird."""
    if os.name != "nt":
        return
    try:
        import ctypes
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("conejito-vipe.CLAUDIA")
    except Exception:
        pass


def _win_icon(win: Any) -> None:
    """Windows: CLAUDIA-Symbol als Fenstersymbol (Taskleiste, Alt+Tab). Nur ein Versuch, Fehler sind unkritisch."""
    if os.name != "nt":
        return
    try:
        from System.Drawing import Icon                    # type: ignore  # kommt mit pywebview (pythonnet)
        ico = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets", "claudia.ico")
        win.native.Icon = Icon(ico)
    except Exception:
        pass


def start_geometry(screens: Any) -> dict:
    """Größe und Position des Programmfensters: so groß wie möglich bis WIDTH x HEIGHT, aber nie größer als der Hauptbildschirm, mittig darauf.
    screens: Liste der Bildschirme von pywebview (Hauptbildschirm zuerst) oder None. Ohne Angaben bleibt es bei der Grundgröße und pywebview zentriert selbst."""
    try:
        scr = screens[0]
        sx, sy, sw, sh = int(scr.x), int(scr.y), int(scr.width), int(scr.height)
        if sw < 300 or sh < 300:
            raise ValueError("unplausibel")
    except Exception:
        return {"width": WIDTH, "height": HEIGHT}
    w, h = min(WIDTH, max(MIN_W, sw - 80)), min(HEIGHT, max(MIN_H, sh - 110))
    return {"width": w, "height": h, "x": sx + max(0, (sw - w) // 2), "y": sy + max(0, (sh - h) // 2 - 20)}


def app_mode_args(exe: str, url: str, profile: str) -> List[str]:
    return [exe, "--app=" + url, "--user-data-" + "dir=" + profile, "--no-first-run", "--no-default-browser-check", "--disable-extensions",
            "--window-size=%d,%d" % (WIDTH, HEIGHT)]


class WindowApi:
    """Was die Seite im Programmfenster tun darf: nur die eigene Titelleiste bedienen (Minimieren, Maximieren, Schließen). Sonst nichts."""

    def __init__(self, owner: "Window", frameless: bool):
        self._owner = owner
        self._frameless = frameless

    def is_custom_frame(self) -> bool:
        return bool(self._frameless)

    def minimize(self) -> None:
        w = self._owner._win
        if w is not None:
            w.minimize()

    def is_maximized(self) -> bool:
        return bool(self._owner._maximized)

    def toggle_maximize(self) -> None:
        w = self._owner._win
        if w is None:
            return
        self._owner._maximized = not self._owner._maximized
        (w.maximize if self._owner._maximized else w.restore)()

    def close(self) -> None:
        w = self._owner._win
        if w is not None and self._owner._on_closing():                    # gleiche Nachfrage wie beim normalen Schließen
            self._owner._confirmed = True                                  # destroy() löst das Schließen-Ereignis aus: nicht ein zweites Mal fragen
            w.destroy()

    def get_size(self) -> list:
        """Aktuelle Fenstergröße (für die Ziehgriffe am Rand)."""
        w = self._owner._win
        try:
            return [int(w.width), int(w.height)]
        except Exception:
            return [WIDTH, HEIGHT]

    def get_rect(self) -> list:
        """Position und Größe des Fensters [x, y, Breite, Höhe] (Start eines Ziehvorgangs am Rand)."""
        w = self._owner._win
        try:
            return [int(w.x), int(w.y), int(w.width), int(w.height)]
        except Exception:
            return [0, 0, WIDTH, HEIGHT]

    def resize_by(self, x0: Any, y0: Any, w0: Any, h0: Any, dx: Any, dy: Any, edges: Any) -> bool:
        """Fenster am Rand ziehen: Ausgangslage (x0, y0, w0, h0) plus Mausweg (dx, dy). 'l', 'r', 'b' in edges wählen die Ränder; beim linken Rand bleibt die rechte Kante stehen."""
        w = self._owner._win
        if w is None or self._owner._maximized:
            return False
        try:
            x0, y0, w0, h0, dx, dy = (int(float(v)) for v in (x0, y0, w0, h0, dx, dy))
            edges = str(edges)
        except (TypeError, ValueError):
            return False
        nw, nh = w0, h0
        if "r" in edges:
            nw = w0 + dx
        if "l" in edges:
            nw = w0 - dx
        if "b" in edges:
            nh = h0 + dy
        nw, nh = max(MIN_W, min(nw, MAX_SIZE)), max(MIN_H, min(nh, MAX_SIZE))
        try:
            w.resize(nw, nh)
            if "l" in edges:
                w.move(x0 + (w0 - nw), y0)
        except Exception:
            return False
        return True

    def set_size(self, width: Any, height: Any) -> bool:
        """Fenstergröße ändern (nur mit eigener Titelleiste, nicht im maximierten Zustand); begrenzt auf sinnvolle Werte. Die linke obere Ecke bleibt stehen."""
        w = self._owner._win
        if w is None or self._owner._maximized:
            return False
        try:
            width, height = int(float(width)), int(float(height))
        except (TypeError, ValueError):
            return False
        width, height = max(MIN_W, min(width, MAX_SIZE)), max(MIN_H, min(height, MAX_SIZE))
        try:
            w.resize(width, height)
        except Exception:
            return False
        return True


class Window:
    """Zeigt das Programmfenster und blockiert, bis es geschlossen wird. Rückgabe von show(): benutzter Weg."""

    def __init__(self, srv: Any, announce: Callable[[], None], webview_module: Any = None, popen: Callable[..., Any] = subprocess.Popen,
                 opener: Callable[[str], Any] = webbrowser.open, browser_finder: Callable[[], Optional[str]] = app_browser):
        self.srv = srv
        self.announce = announce
        self._webview = webview_module
        self.popen = popen
        self.opener = opener
        self.find = browser_finder
        self.mode = ""
        self._win: Any = None
        self._proc: Any = None
        self._stopping = threading.Event()
        self._maximized = False
        self._confirmed = False
        srv.on_stop.append(self.close)

    # ------------------------------------------------------------------ gemeinsam
    def title(self) -> str:
        return "%s %s" % (APP_NAME, __version__)

    def close(self) -> None:
        self._stopping.set()
        try:
            if self._win is not None:
                self._win.destroy()
        except Exception:
            pass
        p = self._proc
        if p is not None and p.poll() is None:
            try:
                p.terminate()
            except Exception:
                pass

    def _watch_loaded(self) -> None:
        """Meldet dem Startfenster, sobald die Seite im Programmfenster wirklich geladen wurde (dann darf es sich schließen)."""
        def run() -> None:
            if self.srv.page_loaded.wait(40):
                self.announce()
        threading.Thread(target=run, daemon=True).start()

    # ------------------------------------------------------------------ Wege
    def _try_webview(self) -> bool:
        wv = self._webview
        if wv is None:
            try:
                import webview as wv  # type: ignore
            except Exception:
                return False
        try:
            try:
                wv.settings["ALLOW_DOWNLOADS"] = True
            except Exception:
                pass
            win = None
            try:
                geo = start_geometry(getattr(wv, "screens", None))
            except Exception:
                geo = {"width": WIDTH, "height": HEIGHT}
            if not os.environ.get("CLAUDIA_NO_FRAMELESS") and sys.platform != "darwin":      # auf dem Mac: normaler Fensterrahmen (Ampelknöpfe, Verschieben und Größe wie gewohnt)
                try:        # eigene Titelleiste im Stil des Startbildschirms (Chip, Minimieren, Schließen); die Seite zeichnet sie
                    win = wv.create_window(self.title(), self.srv.entry_url(), min_size=(MIN_W, MIN_H), text_select=True, **geo,
                                           frameless=True, easy_drag=False, shadow=True, js_api=WindowApi(self, True))
                except TypeError:        # ältere pywebview-Version ohne diese Angaben: Fenster mit normalem Rahmen
                    win = None
            if win is None:
                win = wv.create_window(self.title(), self.srv.entry_url(), min_size=(MIN_W, MIN_H), text_select=True, **geo)
            self._win = win
            _mac_dock_icon()
            _win_app_id()
            try:
                win.events.shown += lambda: _win_icon(win)
            except Exception:
                pass
            try:
                win.events.closing += self._on_closing
            except Exception:
                pass
            for ereignis, wert in (("maximized", True), ("restored", False)):        # Zustand auch dann richtig, wenn per Tastatur oder Systemmenü maximiert wird
                try:
                    ev = getattr(win.events, ereignis)
                    ev += (lambda w=wert: setattr(self, "_maximized", w))
                except Exception:
                    pass
            self._watch_loaded()
            started = time.monotonic()
            wv.start(debug=False)
        except Exception:
            self._win = None
            return False
        # Kehrt start() sofort ohne geladene Seite zurück, hat das Fenster nicht funktioniert: nächster Weg
        return self.srv.page_loaded.is_set() or time.monotonic() - started > 5

    def _on_closing(self) -> bool:
        """Beim Schließen während einer Prüfung nachfragen. False = nicht schließen."""
        app = self.srv.app
        if self._confirmed or self._stopping.is_set() or not (getattr(app, "running", False) or getattr(app, "job", None)):
            return True
        try:
            lang = getattr(app, "lang", i18n.SOURCE)
            msg = i18n.tr("Das Programm jetzt beenden?\n\nLaufende Prüfungen werden abgebrochen.", lang) if lang != i18n.SOURCE else \
                "Das Programm jetzt beenden?\n\nLaufende Prüfungen werden abgebrochen."
            return bool(self._win.create_confirmation_dialog(self.title(), msg))
        except Exception:
            return True

    def _try_app_mode(self) -> bool:
        exe = self.find()
        if not exe:
            return False
        profile = tempfile.mkdtemp(prefix="claudia-fenster-")
        try:
            self._proc = self.popen(app_mode_args(exe, self.srv.entry_url(), profile), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except OSError:
            shutil.rmtree(profile, ignore_errors=True)
            return False
        self._watch_loaded()
        try:
            while self._proc.poll() is None and not self._stopping.is_set():
                time.sleep(0.4)
        finally:
            shutil.rmtree(profile, ignore_errors=True)
        return True

    def _browser_fallback(self) -> None:
        self.opener(self.srv.entry_url())
        self._watch_loaded()
        last = time.monotonic()
        while not self._stopping.is_set():
            time.sleep(1.0)
            if self.srv.page_loaded.is_set():
                last = max(last, self.srv.last_ping)
                if getattr(self.srv.app, "running", False):
                    last = time.monotonic()
                if time.monotonic() - last > PING_TIMEOUT:
                    return

    def _simulated(self) -> None:
        """Nur für automatische Tests (Umgebungsvariable): meldet 'Seite geladen' und wartet auf das Ende. Gibt keinen Zugang frei."""
        self.srv.note_page_load()
        self._watch_loaded()
        self._stopping.wait()

    def show(self) -> str:
        if os.environ.get("CLAUDIA_TEST_NO_WINDOW"):
            self.mode = "test"
            self._simulated()
        elif self._try_webview():
            self.mode = "webview"
        elif self._try_app_mode():
            self.mode = "app"
        else:
            self.mode = "browser"
            self._browser_fallback()
        return self.mode


def silence_output() -> None:
    """Nach dem Start hängt niemand mehr an der Ausgabe (das Startfenster ist weg): Ausgaben verwerfen statt ins Leere zu schreiben."""
    for name in ("stdout", "stderr"):
        try:
            setattr(sys, name, open(os.devnull, "w", encoding="utf-8"))
        except OSError:
            pass
