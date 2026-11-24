"""Lokaler Webserver für die Oberfläche (nur auf diesem Rechner erreichbar).

Schutzmaßnahmen:
  * lauscht ausschließlich auf 127.0.0.1 (zufälliger Port)
  * jede Anfrage an /api braucht ein zufälliges Token (steht nur in der ausgelieferten Seite)
  * Host- und Origin-Kopf werden geprüft (Schutz vor fremden Webseiten im Browser)
  * Passwörter bleiben im Arbeitsspeicher und werden nie gespeichert oder exportiert
"""
from __future__ import annotations

import json
import os
import shutil
import re
import secrets
import sys
import socket
import threading
import time
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse

from . import appupdate, lizenz, support, verlauf, wissen, cms as cmsmod, contao, drupal, prestashop, shopware, typo3, APP_NAME, __version__, actionplan, actions, baseline, hoster, joomla, logsave, phpdetect, probe as probe_mod, report, snippets, uninstall, wordpress
from .db import DbError
from .engine import Ctx, Engine, Settings
from . import helpdocs, i18n
from .icons import all_icons
from .registry import PRESETS, cluster_map, cluster_title_defs, groups_for, load_all, ordered
from .runner import (WeakCrypto, AuthFailed, ConnectFailed, HostKeyChanged, HostKeyUnknown, KnownHosts, LocalRunner,
                     MissingDependency, Runner, RunnerError, SSHRunner)
from .summary import summarize
from .util import atomic_write, digits, split_allow

HERE = os.path.dirname(os.path.abspath(__file__))
WEB = os.path.join(HERE, "web")
COOKIE = "claudia"
STATIC = {"/app.css": ("app.css", "text/css; charset=utf-8"),
          "/docs.css": ("docs.css", "text/css; charset=utf-8"),
          "/app.js": ("app.js", "application/javascript; charset=utf-8"),
          "/docs.js": ("docs.js", "application/javascript; charset=utf-8"),
          "/radar.js": ("radar.js", "application/javascript; charset=utf-8"),
          "/logo.png": ("logo.png", "image/png"),
          "/favicon-64.png": ("favicon-64.png", "image/png"),
          "/favicon-192.png": ("favicon-192.png", "image/png"),
          "/favicon.ico": ("favicon.ico", "image/x-icon"),
          "/TwemojiCountryFlags.woff2": ("TwemojiCountryFlags.woff2", "font/woff2")}


def locked_page(lang: str) -> bytes:
    """Hinweisseite für Aufrufe ohne gültigen Zugang (normaler Browser, Skript)."""
    t = lambda x: i18n.tr(x, lang) if lang != i18n.SOURCE else x       # noqa: E731
    return ("<!doctype html><meta charset=utf-8><title>%s</title><body style=\"font:16px/1.5 Consolas,monospace;background:#0d1418;color:#d3e2ea;padding:40px\">"
            "<h1>%s</h1><p>%s</p><p>%s</p></body>" % (APP_NAME, APP_NAME, t("Dieses Programm lässt sich nur über sein eigenes Fenster bedienen."),
                                                      t("Bitte CLAUDIA über start.bat (Windows) bzw. start.command (Mac) starten. Zum Schutz vor Missbrauch ist der Zugriff aus einem normalen Browser oder per Skript nicht vorgesehen."))).encode("utf-8")


def split_secret_opts(opts: Dict[str, Dict[str, Any]]) -> Tuple[Dict[str, Dict[str, Any]], List[str]]:
    """Trennt Test-Optionen vom Typ 'secret' (z. B. API-Schlüssel) ab: Sie gehen nur an den Test, nie in Berichte oder Einstellungen.
    Rückgabe: (Optionen ohne Geheimnisse, Liste der Geheimnisse zum Schwärzen)."""
    from .registry import REGISTRY
    secret_keys = {(cid, o.key) for cid, c in REGISTRY.items() for o in c.options if o.kind == "secret"}
    public: Dict[str, Dict[str, Any]] = {}
    secrets_: List[str] = []
    for cid, d in (opts or {}).items():
        keep = {}
        for k, v in d.items():
            if (cid, k) in secret_keys:
                if str(v or "").strip():
                    secrets_.append(str(v).strip())
            else:
                keep[k] = v
        public[cid] = keep
    return public, secrets_


def python_lines() -> int:
    """Zeilen reinen Python-Codes (wird beim Bau des Releases in claudia/loc.json geschrieben, siehe tools/count_loc.py); 0 = unbekannt."""
    try:
        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "loc.json"), encoding="utf-8") as fh:
            return max(0, int(json.load(fh).get("python_lines", 0)))
    except (OSError, ValueError, TypeError, AttributeError):
        return 0


def _legacy(*parts: str) -> str:
    """Ordnername früherer Versionen. Wird zusammengesetzt, damit er nirgends als Text im Programm oder in der Dokumentation steht."""
    return "".join(parts)


def _tree_stats(path: str) -> tuple:
    n = size = 0
    for root, _dirs, files in os.walk(path):
        for f in files:
            n += 1
            try:
                size += os.path.getsize(os.path.join(root, f))
            except OSError:
                pass
    return n, size


def adopt_folder(old: str, new: str) -> str:
    """Daten früherer Versionen übernehmen: Gibt es den alten Ordner, aber noch nicht den neuen, wird er umbenannt (derselbe Elternordner, nichts wird kopiert oder gelöscht).
    Klappt das Umbenennen nicht (Rechte, gesperrte Datei, Explorer hat den Ordner offen), wird der alte Ordner in den neuen KOPIERT und die Kopie auf gleiche Dateizahl und Größe geprüft;
    erst dann gilt der neue Ordner. Der alte Ordner bleibt dabei unberührt und kann später von Hand gelöscht werden. Misslingt auch das, wird der alte weiter benutzt, damit nichts verloren geht."""
    if os.path.isdir(old) and not os.path.isdir(new):
        try:
            os.rename(old, new)
            return new
        except OSError:
            pass
        try:
            shutil.copytree(old, new)
            if _tree_stats(old) == _tree_stats(new):
                return new
        except (OSError, shutil.Error):
            pass
        shutil.rmtree(new, ignore_errors=True)
        return old
    return new


def data_dir() -> str:
    env = os.environ.get("CLAUDIA_HOME")
    if env:
        return env
    if os.name == "nt":
        base = os.environ.get("APPDATA") or os.path.expanduser("~")
        return adopt_folder(os.path.join(base, _legacy("Joomla", "Sicher", "heitscheck")), os.path.join(base, "CLAUDIA"))
    home = os.path.expanduser("~")
    if sys.platform == "darwin":                                       # macOS: übliche Programmdaten unter Library/Application Support
        return os.path.join(home, "Library", "Application Support", "CLAUDIA")
    return adopt_folder(os.path.join(home, _legacy(".joomla-", "sicher", "heitscheck")), os.path.join(home, ".claudia"))


def documents_dir() -> str:
    """Ordner 'Dokumente' (unter Windows auch bei Umleitung, z. B. OneDrive; auf dem Mac ~/Documents); sonst leer."""
    if os.name == "nt":
        try:
            import ctypes
            buf = ctypes.create_unicode_buffer(520)
            if ctypes.windll.shell32.SHGetFolderPathW(None, 5, None, 0, buf) == 0 and buf.value:   # type: ignore[attr-defined]
                return buf.value
        except Exception:
            pass
        for c in ("Documents", "Dokumente"):
            p = os.path.join(os.path.expanduser("~"), c)
            if os.path.isdir(p):
                return p
    elif sys.platform == "darwin":
        p = os.path.join(os.path.expanduser("~"), "Documents")
        if os.path.isdir(p):
            return p
    return ""


def reports_dir() -> str:
    env = os.environ.get("CLAUDIA_REPORTS")
    if env:
        return env
    docs = documents_dir()
    if docs:
        new = os.path.join(docs, "CLAUDIA")
        if not os.path.isdir(new) and os.path.isdir(os.path.join(docs, "Claudia")):
            new = os.path.join(docs, "Claudia")                      # Windows unterscheidet Groß und Klein nicht; unter anderen Systemen bleibt ein vorhandener Ordner erhalten
        return os.path.join(adopt_folder(os.path.join(docs, _legacy("Joomla", "Sicher", "heitscheck")), new), "Berichte")
    return os.path.join(data_dir(), "Berichte")


PROFILE_FIELDS = ("host", "port", "user", "auth", "key_file", "site_dir", "url", "log_dir", "local_log",
                  "allow_hosts", "mask_ips")   # bewusst ohne Passwörter


class ProfileStore:
    def __init__(self, path: str):
        self.path = path
        self.lock = threading.Lock()

    def load(self) -> Dict[str, Dict[str, Any]]:
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                d = json.load(fh)
            return d if isinstance(d, dict) else {}
        except (OSError, ValueError):
            return {}

    def save(self, name: str, data: Dict[str, Any]) -> None:
        clean = {k: data.get(k) for k in PROFILE_FIELDS if k in data}
        with self.lock:
            all_ = self.load()
            all_[name] = clean
            self._write(all_)

    def delete(self, name: str) -> None:
        with self.lock:
            all_ = self.load()
            all_.pop(name, None)
            self._write(all_)

    def _write(self, d: Dict[str, Any]) -> None:
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        atomic_write(self.path, json.dumps(d, indent=2, ensure_ascii=False))


class ApiError(Exception):
    def __init__(self, message: str, status: int = 400, **extra: Any):
        super().__init__(message)
        self.status, self.extra = status, extra


def public_result(r: Dict[str, Any]) -> Dict[str, Any]:
    """Ergebnis für die Oberfläche: Rohdaten nur als Namen und Größe (die gehören in den Export)."""
    out = {k: v for k, v in r.items() if k != "raw"}
    out["raw_files"] = [{"name": k, "size": len(v)} for k, v in (r.get("raw") or {}).items()]
    return out


# Welche Wege zu welchem sperrbaren Bereich gehören (siehe lizenz.py). Alles, was hier nicht steht, ist immer frei: Prüfung, Verbindung, Hilfe, Update, Rückweg.
AREA_OF = {"/api/action-preview": "aktionen", "/api/action-run": "aktionen",
           "/api/logs-plan": "protokolle", "/api/logs-save": "protokolle", "/api/logs-open": "protokolle",
           "/api/zip": "export", "/api/export": "export", "/api/handover": "export", "/api/open-folder": "export"}


def _lizenz_msg(res: Dict[str, Any]) -> str:
    if res.get("valid"):
        return "Lizenz angenommen: %s, gültig bis %s." % (res["name"], res["until"])
    return {"abgelaufen": "Dieser Schlüssel ist abgelaufen.", "gesperrt": "Dieser Schlüssel wurde gesperrt.", "Unterschrift ungültig": "Der Schlüssel ist ungültig (Unterschrift stimmt nicht).",
            "unbekannter Schlüssel": "Dieser Schlüssel gehört nicht zu dieser Programmversion."}.get(str(res.get("reason")), "Das ist kein gültiger Lizenzschlüssel.")


def area_of(path: str) -> str:
    return "dashboard" if path.startswith("/api/dashboard") else AREA_OF.get(path, "")


CONNECT_LIMIT = 45      # Sekunden, die ein Verbindungstest höchstens dauern darf


class ConnectJob:
    """Ein laufender Verbindungstest mit Zeitgrenze und Fortschritt."""

    def __init__(self, limit: float):
        self.id = secrets.token_hex(4)
        self.limit = float(limit)
        self.started = time.monotonic()
        self.deadline = self.started + self.limit
        self.step = "connect"
        self.msg = "Verbinde mit dem Server ..."
        self.done = False
        self.abandoned = False
        self.result: Optional[Dict[str, Any]] = None
        self.error: Optional[Dict[str, Any]] = None

    def set(self, step: str, msg: str) -> None:
        self.step, self.msg = step, msg

    def remaining(self) -> float:
        return max(0.0, self.deadline - time.monotonic())

    def to_dict(self) -> Dict[str, Any]:
        order = [s[0] for s in probe_mod.STEPS]
        cur = order.index(self.step) if self.step in order else 0
        ok = self.done and self.result is not None and self.result.get("ok")
        steps = []
        for i, (sid, label) in enumerate(probe_mod.STEPS):
            state = "done" if (ok or i < cur) else ("run" if (i == cur and not self.done) else "todo")
            steps.append({"id": sid, "label": label, "state": state})
        return {"job": self.id, "done": self.done, "limit": self.limit, "remaining": round(self.remaining(), 1),
                "elapsed": round(time.monotonic() - self.started, 1), "step": self.step, "msg": self.msg,
                "steps": steps, "result": self.result if self.done else None, "error": self.error if self.done else None}


class ActionJob:
    """Eine Aktion läuft in einem eigenen Thread; das Statusfenster der Oberfläche fragt Befehle und Antworten laufend ab."""

    def __init__(self, app: "App", action: Dict[str, Any], params: Dict[str, Any]):
        self.app, self.action, self.params = app, action, params
        self.events: List[Dict[str, Any]] = []
        self.finished = False
        self.result: Dict[str, Any] = {}
        self.error = ""
        self.silent = False            # stille Hintergrundsuche: kein Protokoll im Berichtsordner
        self.started = time.monotonic()
        self.thread = threading.Thread(target=self._work, daemon=True)
        self._lock = threading.Lock()

    def start(self) -> None:
        self.thread.start()

    def emit(self, kind: str, text: str) -> None:
        with self._lock:
            self.events.append({"t": kind, "text": text, "at": round(time.monotonic() - self.started, 1)})

    def state(self, since: int) -> Dict[str, Any]:
        with self._lock:
            evs = self.events[since:]
            n = len(self.events)
        return {"id": self.action["id"], "title": self.action["title"], "events": evs, "next": n, "done": self.finished,
                "ok": bool(self.result.get("ok")) if self.finished else None, "result": self._public() if self.finished else None,
                "elapsed": round(time.monotonic() - self.started, 1), "error": self.error}

    def _public(self) -> Dict[str, Any]:
        r = dict(self.result)
        r["id"], r["title"] = self.action["id"], self.action["title"]
        return r

    def _work(self) -> None:
        app, a = self.app, self.action
        try:
            ctx = {"ext_updates": app.update_state.get("ext_updates") or [], "joomla": str((app.info or {}).get("joomla") or ""), "befund": app.befund_text(), "url": str(app.run_settings.get("url") or "")}
            pw = app.conn.get("password", "")
            res = actions.run_action(app.runner, (app.run_settings.get("site_dir") or app.conn.get("site_dir") or "html"), a["id"], self.params,
                                     a.get("php_choices", []), allowed_files=a["params"].get("files"), emit=self.emit,
                                     secrets=[pw] if pw else [], context=ctx)
            if pw:
                for st in res["steps"]:
                    st["output"] = (st.get("output") or "").replace(pw, "***")
            if a["id"] == "check_updates":
                asm = res.get("assess") or {}
                if res.get("ok") and asm:
                    app.update_state = {"checked": True, "has_update": asm["has_update"], "latest": asm["latest"], "ext_updates": res.get("ext_updates") or [],
                                        "reliable": asm["reliable"], "confirmed": asm["confirmed"], "reasons": asm["reasons"], "live_extra": asm["live_extra"],
                                        "message": res.get("message", "")}
                else:
                    app.update_state = {"checked": False, "failed": True, "error": res.get("error") or "Die Update-Suche ist fehlgeschlagen.", "ext_updates": []}
            elif a["id"] == "update_extensions" and res.get("updated"):
                app.update_state["ext_updates"] = [u for u in app.update_state.get("ext_updates", []) if u.get("name") not in res["updated"]]
            elif a["id"] == "core_update" and res.get("ok"):
                app.update_state["has_update"] = False
            res["ext_updates"] = len(res.get("ext_updates") or []) if "ext_updates" in res else 0
            if res.get("ok") and not self.silent:
                res["recheck"] = self._recheck(a["id"])
            self.result = res
            if not self.silent:
                self._write_log(res)
        except actions.ActionError as e:
            self.error = str(e)
            self.emit("fail", str(e))
            self.result = {"ok": False, "steps": [], "error": str(e)}
        except Exception as e:  # pragma: no cover
            self.error = "%s: %s" % (type(e).__name__, e)
            self.emit("fail", self.error)
            self.result = {"ok": False, "steps": [], "error": self.error}
        finally:
            if self.action["id"] == "check_updates" and not self.app.update_state.get("checked") and not self.app.update_state.get("failed"):
                self.app.update_state = {"checked": False, "failed": True, "error": self.error or "Die Update-Suche ist fehlgeschlagen.", "ext_updates": []}
            self.app.scan_cache = None            # Zustand auf dem Server hat sich evtl. geändert: beim nächsten Mal neu lesen
            if not self.silent and self.action["id"] != "check_updates":
                try:
                    key, label = self.app._site()
                    verlauf.record_action(self.app.dir, key, label, self.action["id"], self.action["title"], bool(self.result.get("ok")))
                except Exception:                  # noqa: BLE001
                    pass
            self.finished = True

    def _recheck(self, aid: str) -> List[Dict[str, Any]]:
        """Kontrolle nach der Aktion: die dazugehörigen Prüfungen (nur lesend) noch einmal ausführen und mit dem Stand vor der Aktion vergleichen.
        Der gespeicherte Prüfbericht bleibt unverändert. Scheitert die Kontrolle, bleibt die Aktion trotzdem gültig."""
        app = self.app
        try:
            ids = list(actions.RECHECK.get(aid, {}).get(app.cms(), []))
            st = app.last_settings
            if not ids or st is None or app.runner is None:
                return []
            before = {}
            for r in list(app.results):
                rid, fnd = (r.get("id"), r.get("findings")) if isinstance(r, dict) else (getattr(r, "id", ""), getattr(r, "findings", []))
                if rid in ids:
                    before[rid] = actions.count_sev(fnd)
            ids = [i for i in ids if i in before]
            if not ids:
                return []
            self.emit("info", "Kontrolle nach der Aktion: Die zugehörigen Prüfungen werden noch einmal ausgeführt (nur lesend).")
            out: List[Dict[str, Any]] = []
            engine = Engine(app.runner, st, app.advisories)
            for r in engine.run(ids, lambda e: None, threading.Event()):
                if r.status in ("error", "skipped"):
                    continue
                b, n = before.get(r.id, (0, 0)), actions.count_sev(r.findings)
                better = n[0] < b[0] or (n[0] == b[0] and n[1] <= b[1])
                out.append({"id": r.id, "title": r.title, "before": actions.recheck_line("before", b), "after": actions.recheck_line("after", n), "better": better})
                self.emit("ok" if better else "err", "%s: %s %s" % (r.title, actions.recheck_line("before", b), actions.recheck_line("after", n)))
            return out
        except Exception as e:  # noqa: BLE001  (die Kontrolle darf die Aktion nie verfälschen)
            self.emit("info", "Die Kontrolle nach der Aktion war nicht möglich: %s" % e)
            return []

    def _write_log(self, res: Dict[str, Any]) -> None:
        app, a = self.app, self.action
        try:
            os.makedirs(app.reports, exist_ok=True)
            path = os.path.join(app.reports, "aktion_%s_%s.txt" % (a["id"], time.strftime("%Y%m%d-%H%M%S")))
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("%s\nServer: %s\nErgebnis: %s\nSicherung auf dem Server: %s\n\n" % (a["title"], app.conn.get("host", ""), "OK" if res["ok"] else "FEHLER", res.get("backup_dir") or "-"))
                for ev in self.events:
                    fh.write("[%6.1fs] %-4s %s\n" % (ev["at"], ev["t"], ev["text"].replace("\n", "\n               ")))
            res["log"] = path
        except OSError:
            pass


class App:
    """Zustand einer Sitzung (eine Verbindung, ein Lauf)."""

    def __init__(self, directory: str, demo_world: Optional[Dict[str, str]] = None):
        self.dir = directory
        os.makedirs(self.dir, exist_ok=True)
        self.profiles = ProfileStore(os.path.join(self.dir, "profile.json"))
        self.known = KnownHosts(os.path.join(self.dir, "bekannte_server.json"))
        self.demo_world = demo_world
        self.reports = reports_dir()
        self.logs_base = os.environ.get("CLAUDIA_LOGS") or os.path.join(os.path.dirname(self.reports), "Protokolle")
        self.logjob: Optional[logsave.SaveJob] = None
        self.actjob: Optional["ActionJob"] = None
        self.update_state: Dict[str, Any] = {}
        self.updjob: Optional["ActionJob"] = None
        self.scan_cache: Optional[Dict[str, Any]] = None
        self.last_settings: Optional[Settings] = None
        self.auto_update = True              # Updates beim Öffnen der Lösungen automatisch suchen (Tests schalten es aus)
        self.selfupd_fetch: Any = None       # nur für Tests: ersetzt den Abruf der Release-Seite und des Pakets
        self.selfupd_root = ""               # nur für Tests: anderer Programmordner
        self.selfupd_lock = threading.Lock()
        self.selfupd: Dict[str, Any] = {"checked": False, "checking": False, "ok": None, "info": None, "error": "", "last": 0.0,
                                        "install": {"running": False, "pct": 0, "step": "", "error": "", "done": False}}
        self.selfupd_pending: Dict[str, Any] = {}
        self.last_export = ""
        self.settings_file = os.path.join(self.dir, "einstellungen.json")
        self.lang = self._load_lang()
        self.advisories = wissen.load(self.dir)       # mitgelieferte Fassung; eine neuere, unterschriebene nur bei aktiver Unterschriftsprüfung
        self.wissen_fetch: Any = None                 # nur für Tests: ersetzt den Abruf der Wissensdaten
        load_all()
        self.lock = threading.Lock()
        self.runner: Optional[Runner] = None
        self.conn: Dict[str, Any] = {}          # Verbindungsdaten (inkl. Passwort, nur im Speicher)
        self.info: Dict[str, Any] = {}          # Ergebnis der Verbindungsprüfung
        self.job: Optional[ConnectJob] = None
        self.reset_run()
        self.running = False
        self.thread: Optional[threading.Thread] = None
        self.cancel = threading.Event()

    # ------------------------------------------------------------ Lauf-Zustand
    def reset_run(self) -> None:
        self.update_state = {}
        self.scan_cache = None
        self.manage = False                      # Dashboard-Verwaltung geöffnet: Aufräum-Aktionen auch ohne vorherige Prüfung anbieten
        self.update_checked = False
        self.results: List[Dict[str, Any]] = []     # vollständige Ergebnisse (mit Rohdaten)
        self.current: Dict[str, Any] = {}
        self.plan: List[str] = []
        self.started = 0.0
        self.finished_at = 0.0
        self.run_settings: Dict[str, Any] = {}
        self.db_password = ""
        self.secret_opts: List[str] = []
        self.run_error = ""
        self.cancelled = False

    # ------------------------------------------------------------ Verbindung
    def make_runner(self, c: Dict[str, Any]) -> Runner:
        if c.get("host") == "__demo__" and self.demo_world:
            return LocalRunner(self.demo_world["home"], extra_path=self.demo_world["bin"])
        return SSHRunner(c["host"], int(c.get("port") or 22), c["user"],
                         password=c.get("password", "") if c.get("auth") != "key" else "",
                         key_file=c.get("key_file", "") if c.get("auth") == "key" else "",
                         key_pass=c.get("password", "") if c.get("auth") == "key" else "",
                         known_hosts=self.known, trusted_fp=c.get("trust_fp", ""), allow_weak=c.get("allow_weak") is True)

    # ------------------------------------------------------------ Verbindungstest (mit Zeitgrenze)
    LOGIN_MAX_FAILS = 5
    LOGIN_WINDOW = 600.0
    LOGIN_MIN_GAP = 1.5

    def _login_gate(self) -> None:
        """Bremse gegen Missbrauch als Passwort-Rater: Verbindungsversuche nur einzeln und mit Pause, nach mehreren Fehlschlägen eine Sperre."""
        now = time.monotonic()
        fails = [t for t in getattr(self, "_fails", []) if now - t < self.LOGIN_WINDOW]
        self._fails = fails
        if len(fails) >= self.LOGIN_MAX_FAILS:
            wait = int(self.LOGIN_WINDOW - (now - fails[0])) + 1
            raise ApiError("Zu viele fehlgeschlagene Anmeldungen. Zum Schutz vor Missbrauch (Passwort-Raten) ist für %d Minute(n) keine neue Verbindung möglich. "
                           "Bitte Zugangsdaten beim Hoster prüfen." % max(1, (wait + 59) // 60), 429, kind="locked")
        gap = now - getattr(self, "_last_connect", 0.0)
        if gap < self.LOGIN_MIN_GAP:
            time.sleep(self.LOGIN_MIN_GAP - gap)
        self._last_connect = time.monotonic()

    def _login_failed(self) -> None:
        self._fails = getattr(self, "_fails", []) + [time.monotonic()]

    def _validate_conn(self, c: Dict[str, Any]) -> None:
        c["host"] = (c.get("host") or "").strip()
        c["user"] = (c.get("user") or "").strip()
        if not c["host"] or not c["user"]:
            raise ApiError("Bitte Server und Benutzername eingeben.")
        if c.get("auth") == "key" and not (c.get("key_file") or "").strip():
            raise ApiError("Bitte den Pfad zur Schlüsseldatei angeben.")
        if c.get("auth") != "key" and not c.get("password"):
            raise ApiError("Bitte das Passwort eingeben.")
        try:
            port = int(c.get("port") or 22)
            if not 1 <= port <= 65535:
                raise ValueError
        except ValueError:
            raise ApiError("Der Port muss eine Zahl zwischen 1 und 65535 sein.")
        c["port"] = port

    def connect(self, c: Dict[str, Any], job: Optional["ConnectJob"] = None) -> Dict[str, Any]:
        """Verbindung herstellen und prüfen (blockierend). Mit 'job' werden Fortschritt und Zeitgrenze gemeldet."""
        if c.get("mode") == "none":
            self.disconnect()
            self.conn, self.info = {"mode": "none"}, {"mode": "none"}
            return {"ok": True, "mode": "none"}
        self._validate_conn(c)
        self._login_gate()
        job = job or ConnectJob(CONNECT_LIMIT)
        self.disconnect()
        job.set("connect", "Verbinde mit %s ..." % c["host"])
        runner = self.make_runner(c)
        try:
            if isinstance(runner, SSHRunner):
                runner.timeout = 15.0
                runner.connect()
        except HostKeyUnknown as e:
            return {"ok": False, "need_trust": True, "fingerprint": e.fingerprint, "key_type": e.key_type,
                    "host_id": "%s:%d" % (c["host"], c["port"])}
        except WeakCrypto as e:
            return {"ok": False, "need_weak": True, "detail": str(e)}
        except HostKeyChanged as e:
            raise ApiError("Der Schlüssel dieses Servers hat sich seit dem letzten Mal geändert. Das kann nach einem "
                           "Serverumzug normal sein, kann aber auch bedeuten, dass jemand die Verbindung abfängt. "
                           "Frage im Zweifel beim Hoster nach dem aktuellen Fingerabdruck.", 409,
                           kind="hostkey_changed", known=e.known, seen=e.seen)
        except MissingDependency as e:
            raise ApiError(str(e), 500, kind="dependency")
        except AuthFailed as e:
            self._login_failed()
            raise ApiError(str(e), 401, kind="auth")
        except ConnectFailed as e:
            raise ApiError(str(e), 502, kind="connect")
        if job.abandoned:                     # Zeitgrenze war schon abgelaufen: nichts mehr übernehmen
            runner.close()
            raise ApiError("Abgebrochen.", 408, kind="timeout")
        info = probe_mod.probe(runner, (c.get("site_dir") or "").strip() or ".", job.set, job.deadline)
        if getattr(runner, "label", "") == "ssh":
            try:
                info["security"] = runner.security_info()
            except Exception:
                info["security"] = {"encrypted": True, "protocol": "SSH-2", "fingerprint": getattr(runner, "fp", "")}
        else:
            info["security"] = {"encrypted": False, "local": True}       # nur Test/Demo auf diesem Rechner, kein Netzwerk
        info["host"], info["user"] = c["host"], c["user"]
        job.set("php", "PHP-Version der Webseite erkennen ...")
        web = phpdetect.decide(info, (c.get("url") or "").strip())
        info["php_web"], info["php_web_source"], info["php_web_note"] = web["version"], web["source"], web["note"]
        with self.lock:
            if job.abandoned:
                runner.close()
                raise ApiError("Abgebrochen.", 408, kind="timeout")
            self.runner, self.conn, self.info = runner, dict(c), info
        return {"ok": True, "info": info}

    def connect_start(self, c: Dict[str, Any]) -> Dict[str, Any]:
        if c.get("mode") == "none":
            return self.connect(c)
        self._validate_conn(c)
        old = self.job
        if old and not old.done:
            old.abandoned = True
        job = self.job = ConnectJob(CONNECT_LIMIT)

        def work() -> None:
            try:
                job.result = self.connect(dict(c), job)
            except ApiError as e:
                job.error = dict({"error": str(e), "status": e.status}, **e.extra)
            except Exception as e:  # pragma: no cover
                sys.stderr.write(traceback.format_exc())
                job.error = {"error": "Interner Fehler: %s" % e, "status": 500}
            finally:
                job.done = True
        threading.Thread(target=work, daemon=True).start()
        return {"job": job.id, "limit": CONNECT_LIMIT}

    def connect_state(self) -> Dict[str, Any]:
        job = self.job
        if job is None:
            return {"done": True, "error": {"error": "Kein Verbindungstest aktiv."}}
        if not job.done and job.remaining() <= 0:
            job.abandoned = True
            job.done = True
            job.error = {"error": "Zeitüberschreitung: Der Verbindungstest hat nach %d Sekunden nicht geantwortet. "
                                  "Prüfe Servername, Port und ob SSH beim Hoster aktiviert ist." % CONNECT_LIMIT,
                         "kind": "timeout", "status": 504}
        return job.to_dict()

    def connect_cancel(self) -> None:
        job = self.job
        if job and not job.done:
            job.abandoned = True
            job.done = True
            job.error = {"error": "Der Verbindungstest wurde abgebrochen.", "kind": "cancelled", "status": 499}

    def disconnect(self) -> None:
        if self.runner is not None:
            try:
                self.runner.close()
            except Exception:
                pass
        self.runner = None
        self.conn, self.info = {}, {}
        self.update_state, self.scan_cache = {}, None
        self.manage = False

    def ensure_connected(self) -> None:
        """Verbindung vor dem Lauf prüfen, bei Abbruch (z. B. Leerlauf) neu aufbauen."""
        r = self.runner
        if r is None or not isinstance(r, SSHRunner):
            return
        try:
            tr = r.client.get_transport() if r.client else None
            if tr is not None and tr.is_active():
                return
        except Exception:
            pass
        c = dict(self.conn)
        fresh = self.make_runner(c)
        try:
            fresh.connect()
        except RunnerError as e:
            raise ApiError("Die Verbindung wurde getrennt und konnte nicht neu aufgebaut werden: %s" % e, 502)
        self.runner = fresh

    # ------------------------------------------------------------ Vergleichsbasis (B9)
    def baseline_dir(self) -> str:
        return os.path.join(self.dir, "baselines")

    def _bl_site(self, site_dir: Any = None) -> str:
        return (str(site_dir or "").strip() or self.conn.get("site_dir") or ".").strip() or "."

    def baseline_key(self, site_dir: Any = None) -> str:
        return baseline.make_key(str(self.conn.get("host", "")), str(self.conn.get("user", "")), self._bl_site(site_dir))

    def baseline_label(self, site_dir: Any = None) -> str:
        return "%s : %s" % (self.conn.get("host", ""), self._bl_site(site_dir))

    def baseline_info(self, site_dir: Any = None) -> Dict[str, Any]:
        if not self.conn:
            return {"exists": False}
        return baseline.info(self.baseline_dir(), self.baseline_key(site_dir))

    def baseline_delete(self, site_dir: Any = None) -> Dict[str, Any]:
        if not self.conn:
            raise ApiError("Bitte zuerst eine Verbindung herstellen.", 409)
        return {"deleted": baseline.delete(self.baseline_dir(), self.baseline_key(site_dir))}

    # ------------------------------------------------------------ Lauf
    def start(self, ids: List[str], s: Dict[str, Any]) -> None:
        with self.lock:
            if self.running:
                raise ApiError("Es läuft bereits eine Prüfung.", 409)
            if not self.conn:
                raise ApiError("Bitte zuerst eine Verbindung herstellen.", 409)
            valid = {c.id for c in ordered(self.cms())}
            ids = [i for i in ids if i in valid]
            if not ids:
                raise ApiError("Bitte mindestens einen Test auswählen.")
            self.ensure_connected()
            settings = Settings(
                site_dir=(s.get("site_dir") or self.conn.get("site_dir") or ".").strip() or ".",
                url=(s.get("url") or "").strip(), log_dir=(s.get("log_dir") or "").strip(),
                local_log=(s.get("local_log") or "").strip(),
                allow_hosts=split_allow(s.get("allow_hosts") or "") if isinstance(s.get("allow_hosts"), str)
                else list(s.get("allow_hosts") or []),
                mask_ips=bool(s.get("mask_ips", True)),
                opts={k: v for k, v in (s.get("opts") or {}).items() if isinstance(v, dict)},
                php_web={"version": self.info.get("php_web", ""), "source": self.info.get("php_web_source", ""), "note": self.info.get("php_web_note", "")},
                db=self._clean_db(s.get("db")), cms=self.cms(), php_cands=list(self.info.get("php_candidates") or []),
                baseline_dir=self.baseline_dir(), baseline_key=self.baseline_key(s.get("site_dir")), baseline_label=self.baseline_label(s.get("site_dir")),
            )
            self.db_password = settings.db.get("password", "")
            self.last_settings = settings
            public_opts, self.secret_opts = split_secret_opts(settings.opts)
            self.reset_run()
            self.plan = ids
            self.started = time.time()
            self.run_settings = {
                "site_dir": settings.site_dir, "url": settings.url, "log_dir": settings.log_dir,
                "local_log": settings.local_log, "allow_hosts": settings.allow_hosts,
                "mask_ips": settings.mask_ips, "opts": public_opts,
                "eigene_datenbankverbindung": bool(settings.db),
            }
            self.cancel = threading.Event()
            self.running = True
            engine = Engine(self.runner, settings, self.advisories)
            cancel = self.cancel
            self.thread = threading.Thread(target=self._work, args=(engine, ids, cancel), daemon=True)
            self.thread.start()

    def _emit(self, ev: Dict[str, Any]) -> None:
        t = ev.get("type")
        if t == "start":
            self.current = {"id": ev["id"], "msg": "", "since": time.time()}
        elif t == "progress":
            if self.current.get("id") == ev.get("id"):
                self.current["msg"] = ev.get("msg", "")
        elif t == "done":
            self.results.append(ev["result"])
            self.current = {}

    def _work(self, engine: Engine, ids: List[str], cancel: threading.Event) -> None:
        try:
            engine.run(ids, self._emit, cancel)
        except Exception as e:  # pragma: no cover - Engine fängt Testfehler selbst ab
            self.run_error = "%s: %s" % (type(e).__name__, e)
            sys.stderr.write(traceback.format_exc())
        finally:
            self.cancelled = cancel.is_set()
            self.finished_at = time.time()
            self.current = {}
            self.running = False
            if not self.cancelled and not self.run_error:
                self._verlauf_run()

    def _site(self) -> Tuple[str, str]:
        """Kennung und Anzeigename der verbundenen Seite für den Verlauf ('' wenn keine Verbindung besteht)."""
        try:
            return (self.baseline_key(), self.baseline_label()) if self.conn and self.conn.get("host") else ("", "")
        except Exception:                                  # noqa: BLE001  (Zusatzfunktion darf nie stören)
            return ("", "")

    def _verlauf_run(self) -> None:
        try:
            key, label = self._site()
            if key:
                cms = str((self.info or {}).get("cms") or "")
                verlauf.record_run(self.dir, verlauf.run_entry(key, label, cms, str((self.info or {}).get(cms) or ""), [r if isinstance(r, dict) else r.to_dict() for r in self.results]))
        except Exception:                                  # noqa: BLE001
            pass

    def state(self, since: int) -> Dict[str, Any]:
        res = list(self.results)
        return {
            "running": self.running, "plan": self.plan, "total": len(self.plan),
            "current": dict(self.current), "since": since, "next": len(res),
            "results": [public_result(r) for r in res[since:]],
            "elapsed": round((self.finished_at or time.time()) - self.started, 1) if self.started else 0,
            "cancelled": self.cancelled, "error": self.run_error,
            "summary": summarize(res) if not self.running and self.started else None,
            "hoster": self._hoster(res) if not self.running and self.started and res else None,
        }

    def _hoster(self, res: List[Any]) -> Dict[str, Any]:
        """Befunde, die nur der Hoster ändern kann, samt fertiger E-Mail (nur Anzeige, nichts wird gesendet)."""
        try:
            return hoster.build([r if isinstance(r, dict) else (r.to_dict() if hasattr(r, "to_dict") else {}) for r in res],
                                str((self.run_settings or {}).get("url") or ""), str((self.info or {}).get("host") or ""))
        except Exception:                                  # noqa: BLE001  (Zusatzanzeige darf den Zustand nie verhindern)
            return {"items": [], "mail": {"subject": "", "body": ""}}

    # ------------------------------------------------------------ Dashboard (Verlauf, siehe verlauf.py)
    def dashboard(self) -> Dict[str, Any]:
        out = verlauf.dashboard(self.dir)
        out["current"] = self._site()[0]
        out["connected"] = bool(self.runner)
        return out

    def dashboard_delete(self, body: Dict[str, Any]) -> Dict[str, Any]:
        site = str(body.get("site", ""))
        if not site:
            raise ApiError("Welche Seite?")
        return {"deleted": verlauf.delete_site(self.dir, site)}

    def dashboard_server(self) -> Dict[str, Any]:
        """Sicherungen und Quarantäne der verbundenen Seite (nur lesend). Öffnet die Verwaltung: die Aufräum-Aktionen stehen danach zur Verfügung."""
        if not self.runner:
            return {"connected": False}
        self.manage = True
        sc = self._scan()
        return {"connected": True, "label": self._site()[1],
                "backups": [{"name": b["name"], "mtime": b["mtime"], "kb": b["kb"], "kind": b["kind"]} for b in sc.get("backups") or []][:60],
                "quarantines": [{"name": q["name"], "mtime": q["mtime"], "count": q["count"], "kb": q["kb"], "files": [e["origin"] for e in q["entries"]][:20]}
                                for q in sc.get("quarantines") or []][:30]}

    def dashboard_export(self, body: Dict[str, Any]) -> Dict[str, Any]:
        """Verlauf als CSV (alle Seiten oder eine) oder als Bericht über eine Seite (HTML) in den Berichte-Ordner schreiben."""
        fmt, site = str(body.get("fmt", "")), str(body.get("site", ""))
        stamp = time.strftime("%Y%m%d-%H%M%S")
        if fmt == "csv":
            name, text = "verlauf.csv", verlauf.export_csv(self.dir, site)
        elif fmt == "html":
            text = verlauf.export_html(self.dir, site)
            if not text:
                raise ApiError("Zu dieser Seite gibt es keinen Verlauf.", 404)
            name = "bericht.html"
        else:
            raise ApiError("Unbekanntes Format.")
        outdir = os.path.join(self.reports, "verlauf_" + stamp)
        try:
            os.makedirs(outdir, exist_ok=True)
            with open(os.path.join(outdir, name), "w", encoding="utf-8", newline="") as fh:
                fh.write(text)
        except OSError as e:
            raise ApiError("Die Datei konnte nicht gespeichert werden (%s). Ordner: %s" % (e.strerror or e, self.reports), 500)
        return {"ok": True, "dir": outdir, "file": os.path.join(outdir, name)}

    def dashboard_verify(self, body: Dict[str, Any]) -> Dict[str, Any]:
        """Eine Sicherung auf dem Server prüfen (nur lesend: lesbar und vollständig?). Nur Sicherungen aus der Liste des Programms."""
        if not self.runner:
            raise ApiError("Bitte zuerst eine Verbindung herstellen.", 409)
        if self.actjob and not self.actjob.finished:
            raise ApiError("Es läuft gerade eine Aktion.", 409)
        name = str(body.get("name", ""))
        if name not in [b["name"] for b in self._scan().get("backups") or []]:
            raise ApiError("Diese Sicherung gibt es nicht (mehr). Bitte die Liste neu laden.", 404)
        try:
            self.ensure_connected()
            return actions.verify_backup(self.runner, self._log_site(), name)
        except (actions.ActionError, RunnerError, ApiError) as e:
            raise ApiError(str(e) or "Nicht möglich.", 502)

    def support_package(self) -> Dict[str, Any]:
        """Support-Paket (Textdatei ohne Zugangsdaten und Serveradresse) erstellen und im Berichte-Ordner ablegen."""
        c = self.conn or {}
        hide = [c.get("password", ""), getattr(self, "db_password", ""), c.get("host", ""), c.get("user", ""), c.get("site_dir", ""), (self.info or {}).get("host", ""),
                (self.info or {}).get("user", "")] + list(getattr(self, "secret_opts", []))
        res = [r if isinstance(r, dict) else (r.to_dict() if hasattr(r, "to_dict") else {}) for r in self.results]
        log = ""
        try:
            with open(os.path.join(appupdate.update_dir(self.dir), appupdate.LOG_FILE), "r", encoding="utf-8", errors="replace") as fh:
                log = fh.read()[-20000:]
        except OSError:
            pass
        key = self._site()[0]
        acts = [a for a in verlauf.load(self.dir)["actions"] if not key or a["site"] == key]
        text = support.build(__version__, self.info or {}, res, acts, log, str(self.advisories.get("stand", "")), [str(x) for x in hide])
        path = os.path.join(self.reports, "support_%s.txt" % time.strftime("%Y%m%d-%H%M%S"))
        try:
            os.makedirs(self.reports, exist_ok=True)
            with open(path, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(text)
        except OSError as e:
            raise ApiError("Die Datei konnte nicht gespeichert werden (%s). Ordner: %s" % (e.strerror or e, self.reports), 500)
        return {"ok": True, "file": path, "text": text}

    # ------------------------------------------------------------ Programm-Update (siehe appupdate.py)
    def selfupd_state(self) -> Dict[str, Any]:
        with self.selfupd_lock:
            u = dict(self.selfupd)
            u["install"] = dict(u["install"])
        info = u.get("info") or {}
        newer = bool(info.get("newer"))
        return {"current": __version__, "checked": u["checked"], "checking": u["checking"], "ok": u["ok"], "error": u["error"],
                "info": info if newer else None, "newer": newer,
                "skipped": bool(newer and appupdate.skipped(self.dir, str(info.get("version") or ""))),
                "installable": bool(newer and info.get("url") and info.get("sha256")), "install": u["install"]}

    def selfupd_check(self) -> Dict[str, Any]:
        with self.selfupd_lock:
            busy = self.selfupd["checking"] or self.selfupd["install"]["running"]
            if not busy:
                self.selfupd["checking"] = True
        if busy:
            return self.selfupd_state()
        r = appupdate.check(__version__, self.selfupd_fetch)
        with self.selfupd_lock:
            self.selfupd.update(checking=False, checked=True, ok=bool(r.get("ok")), info=r.get("info"), error=str(r.get("error") or ""), last=time.time())
        return self.selfupd_state()

    def selfupd_check_async(self) -> None:
        threading.Thread(target=self.selfupd_check, daemon=True).start()
        threading.Thread(target=self.wissen_update, daemon=True).start()

    def wissen_update(self) -> Dict[str, Any]:
        """Neuere, unterschriebene Wissensdaten holen (nur bei aktiver Unterschriftsprüfung; sonst passiert nichts). Gilt ab dem nächsten Lauf."""
        res = wissen.update(self.dir, self.wissen_fetch)
        if res.get("neu"):
            self.advisories = wissen.load(self.dir)
        return res

    def selfupd_skip(self, version: str) -> Dict[str, Any]:
        if not re.match(r"^\d+\.\d+\.\d+\Z", version or ""):
            raise ApiError("Ungültige Versionsnummer.", 400)
        appupdate.save_state(self.dir, skip=version)
        return self.selfupd_state()

    def selfupd_install(self, version: str) -> Dict[str, Any]:
        if self.running:
            raise ApiError("Bitte warten, bis die Prüfung beendet ist.", 409)
        with self.selfupd_lock:
            info = self.selfupd.get("info") or {}
            if not info.get("newer") or str(info.get("version")) != version:
                raise ApiError("Diese Version wurde nicht gefunden. Bitte erneut nach Updates suchen.", 409)
            if not (info.get("url") and info.get("sha256")):
                raise ApiError("Für diese Version gibt es kein Paket mit veröffentlichter Prüfsumme. Bitte von der Release-Seite laden.", 409)
            if self.selfupd["install"]["running"]:
                raise ApiError("Das Update läuft bereits.", 409)
            self.selfupd["install"] = {"running": True, "pct": 1, "step": "Start", "error": "", "done": False}
        threading.Thread(target=self._selfupd_run, args=(dict(info),), daemon=True).start()
        return self.selfupd_state()

    def _selfupd_run(self, info: Dict[str, Any]) -> None:
        def prog(p: int, t: str) -> None:
            with self.selfupd_lock:
                self.selfupd["install"].update(pct=p, step=t)
        r = appupdate.install(info, self.selfupd_root or appupdate.root_dir(), self.dir, prog, self.selfupd_fetch)
        with self.selfupd_lock:
            if r.get("ok"):
                self.selfupd_pending = {"staging": r.get("staging") or ""}
                self.selfupd["install"] = {"running": False, "pct": 100, "step": "Fertig", "error": "", "done": True}
            else:
                self.selfupd["install"] = {"running": False, "pct": 0, "step": "", "error": str(r.get("error") or "Fehler"), "done": False, "log": r.get("log") or ""}

    def selfupd_restart(self) -> Dict[str, Any]:
        with self.selfupd_lock:
            if not self.selfupd["install"].get("done"):
                raise ApiError("Es liegt kein fertiges Update vor.", 409)
            staging = str(self.selfupd_pending.get("staging") or "")
        self.disconnect()
        if os.environ.get("CLAUDIA_NO_RESTART"):
            return {"ok": True, "started": False}
        pid = appupdate.restart(self.selfupd_root or appupdate.root_dir(), staging)
        return {"ok": True, "started": pid is not None}

    # ------------------------------------------------------------ Sprache
    def _load_lang(self) -> str:
        """Gewählte Sprache: Umgebungsvariable CLAUDIA_LANG, sonst gespeicherte Auswahl, sonst Sprache des PCs (wenn vorhanden), sonst Deutsch."""
        env = os.environ.get("CLAUDIA_LANG", "").strip().lower()
        if env and i18n.valid(env):
            return env
        try:
            with open(self.settings_file, encoding="utf-8") as fh:
                saved = str(json.load(fh).get("lang", ""))
            if i18n.valid(saved):
                return saved
        except (OSError, ValueError, AttributeError):
            pass
        dflt = os.environ.get("CLAUDIA_LANG_DEFAULT", "").strip().lower()       # vom Start (__main__) aus der PC-Sprache gesetzt; Tests setzen nichts
        if dflt and i18n.valid(dflt):
            return dflt
        return i18n.SOURCE

    def set_lang(self, code: str) -> Dict[str, Any]:
        code = (code or "").strip().lower()
        if not i18n.valid(code):
            raise ApiError("Diese Sprache gibt es nicht.", 400)
        self.lang = code
        try:
            atomic_write(self.settings_file, json.dumps({"lang": code}))
        except OSError:
            pass
        return {"ok": True, "lang": code}

    # ------------------------------------------------------------ Export
    def bundle(self) -> Dict[str, Any]:
        if self.running:
            raise ApiError("Bitte warten, bis die Prüfung beendet ist.", 409)
        if not self.results:
            raise ApiError("Es gibt noch keine Ergebnisse zum Speichern.", 409)
        secrets = [self.conn.get("password", ""), getattr(self, "db_password", "")] + list(getattr(self, "secret_opts", []))
        return report.build_bundle(list(self.results), self.plan, self.run_settings, self.info,
                                   (self.finished_at or time.time()) - self.started, self.cancelled,
                                   self.advisories.get("stand", ""), secrets, self.lang)

    def export(self) -> Dict[str, Any]:
        b = self.bundle()
        try:
            outdir, files = report.write_all(b, self.reports)
        except OSError as e:
            raise ApiError("Die Dateien konnten nicht gespeichert werden (%s). Ordner: %s" % (e.strerror or e, self.reports), 500)
        self.last_export = outdir
        return {"ok": True, "dir": outdir, "files": files}

    # ------------------------------------------------------------ Lösungen auf Knopfdruck
    def _php_manual(self) -> str:
        """Erkannte PHP-Version der Webseite (nur zur Vorauswahl des PHP-Programms)."""
        return (self.info.get("php_web") or "").strip()

    def _scan(self) -> Dict[str, Any]:
        """Zustand des Servers für Aufräum-Aktionen (nur lesend, kurz zwischengespeichert)."""
        sc = self.scan_cache
        if sc is not None and time.monotonic() - sc.get("_at", 0) < 60:
            return sc
        try:
            self.ensure_connected()
            sc = actions.scan_server(self.runner, self._log_site())
        except (RunnerError, ApiError):
            sc = {}
        sc = dict(sc)
        sc["_at"] = time.monotonic()
        self.scan_cache = sc
        return sc

    def _default_php(self) -> str:
        ch = actions.php_choices(self.info, self._php_manual())
        for c in ch:
            if c.get("default"):
                return c["name"]
        return ch[0]["name"] if ch else ""

    def ensure_update_check(self, force: bool = False) -> None:
        """Sucht Updates automatisch (Joomla und Erweiterungen), sobald die Lösungen angezeigt werden."""
        if not self.runner or self.running or not cmsmod.profile(self.cms())["update_cli"]:
            return    # z. B. WordPress: keine Joomla-Kommandozeile; Updates kommen aus den Befunden (wp_update)
        st = self.update_state
        if st.get("checking") or (self.updjob and not self.updjob.finished):
            return
        if not force and (st.get("checked") or st.get("failed")):
            return
        php = self._default_php()
        if not php:
            self.update_state = {"checked": False, "failed": True, "error": "Es wurde kein funktionierendes PHP-Programm gefunden. Updates bitte im Joomla-Backend suchen "
                                 "(System -> Aktualisieren).", "ext_updates": []}
            return
        meta = actions.ACTIONS["check_updates"]
        act = {"id": "check_updates", "title": meta["title"], "php_choices": actions.php_choices(self.info, self._php_manual()), "params": {}}
        self.update_state = {"checking": True, "checked": False, "ext_updates": []}
        self.updjob = ActionJob(self, act, {"php": php})
        self.updjob.silent = True
        self.updjob.start()

    @staticmethod
    def _clean_db(d: Any) -> Dict[str, str]:
        """Eigene Datenbank-Zugangsdaten aus der Oberfläche (Bereich 'Datenbank'). Nur bekannte Felder, nur Text, leer = aus configuration.php."""
        if not isinstance(d, dict) or not d.get("custom"):
            return {}
        out = {k: str(d.get(k) or "").strip()[:200] for k in ("host", "port", "user", "name", "prefix")}
        out["password"] = str(d.get("password") or "")[:300]
        if out["port"] and not digits(out["port"]):
            raise ApiError("Der Port der Datenbank muss eine Zahl sein.")
        if out["prefix"] and not re.match(r"^[A-Za-z0-9_]{1,40}\Z", out["prefix"]):
            raise ApiError("Das Tabellenpräfix darf nur Buchstaben, Ziffern und _ enthalten.")
        return {k: v for k, v in out.items() if v}

    def db_prefill(self, body: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Zugangsdaten aus der configuration.php des Servers (OHNE Passwort) zum Vorausfüllen der Karte."""
        if not self.runner:
            raise ApiError("Bitte zuerst eine Verbindung herstellen.", 409)
        self.ensure_connected()
        try:
            site = str((body or {}).get("site_dir") or "").strip() or self._log_site()
            r = self.runner.sh(site, "test -f configuration.php && head -c 300000 configuration.php", 30)
            wp = None
            if not r.out.strip():
                wp = self.runner.sh(site, "if test -f wp-config.php; then head -c 300000 wp-config.php; elif test -f ../wp-config.php; then head -c 300000 ../wp-config.php; fi", 30)
        except RunnerError as e:
            raise ApiError(str(e), 502)
        if not r.out.strip() and not (wp and wp.out.strip()):
            try:
                dr = self.runner.sh(site, "head -c 300000 sites/default/settings.php 2>/dev/null", 30)
            except RunnerError as e:
                raise ApiError(str(e), 502)
            if dr.out.strip():
                v = drupal.parse_settings(dr.out).get("vars", {})
                host, port, sock = joomla.split_db_host(str(v.get("host", "")))
                return {"found": True, "host": host + (":" + sock if sock else ""), "port": str(port or ""), "user": str(v.get("user", "")), "name": str(v.get("db", "")),
                        "prefix": str(v.get("dbprefix", "")), "has_password": bool(v.get("password"))}
        if not r.out.strip() and not (wp and wp.out.strip()):
            try:
                tr = self.runner.sh(site, typo3.read_config_sh(), 30)
            except RunnerError as e:
                raise ApiError(str(e), 502)
            parts = typo3.split_config_output(tr.out)
            if parts["text"].strip():
                v = typo3.parse_settings(parts["text"]).get("vars", {})
                host, port, sock = joomla.split_db_host(str(v.get("host", "")))
                return {"found": True, "host": host + (":" + sock if sock else ""), "port": str(port or ""), "user": str(v.get("user", "")), "name": str(v.get("db", "")),
                        "prefix": "", "has_password": bool(v.get("password"))}
        if not r.out.strip() and not (wp and wp.out.strip()):
            try:
                cr = self.runner.sh(site, contao.read_config_sh(), 30)
            except RunnerError as e:
                raise ApiError(str(e), 502)
            cparts = contao.split_config_output(cr.out)
            if cparts["env"] or cparts["yaml"] or cparts["local"]:
                v = contao.parse_settings(cparts["env"], cparts["yaml"], cparts["local"]).get("vars", {})
                if v.get("db"):
                    host, port, sock = joomla.split_db_host(str(v.get("host", "")))
                    return {"found": True, "host": host + (":" + sock if sock else ""), "port": str(port or ""), "user": str(v.get("user", "")), "name": str(v.get("db", "")),
                            "prefix": "", "has_password": bool(v.get("password"))}
        if not r.out.strip() and not (wp and wp.out.strip()):
            try:
                sr = self.runner.sh(site, shopware.read_config_sh(), 30)
            except RunnerError as e:
                raise ApiError(str(e), 502)
            sp = shopware.split_config_output(sr.out)["env"]
            if any((t or "").strip() for _, t in sp):
                v = shopware.parse_settings(sp).get("vars", {})
                if v.get("db"):
                    host, port, sock = joomla.split_db_host(str(v.get("host", "")))
                    return {"found": True, "host": host + (":" + sock if sock else ""), "port": str(port or ""), "user": str(v.get("user", "")), "name": str(v.get("db", "")),
                            "prefix": "", "has_password": bool(v.get("password"))}
            try:
                pr = self.runner.sh(site, prestashop.read_config_sh(), 30)
            except RunnerError as e:
                raise ApiError(str(e), 502)
            pf = prestashop.split_config_output(pr.out)["files"]
            if (pf.get(prestashop.PARAMS_FILE) or "").strip() or (pf.get(prestashop.SETTINGS16_FILE) or "").strip():
                pc = prestashop.parse_settings(pf.get(prestashop.PARAMS_FILE, ""), "", pf.get(prestashop.SETTINGS16_FILE, ""))
                v = pc.get("vars", {})
                if v.get("db"):
                    host, port, sock = joomla.split_db_host(str(v.get("host", "")))
                    return {"found": True, "host": host + (":" + sock if sock else ""), "port": str(port or ""), "user": str(v.get("user", "")), "name": str(v.get("db", "")),
                            "prefix": str(pc.get("prefix") or ""), "has_password": bool(v.get("password"))}
        if not r.out.strip() and not (wp and wp.out.strip()):
            return {"found": False}
        v = joomla.parse_config(r.out).get("vars", {}) if r.out.strip() else wordpress.parse_wp_config(wp.out).get("vars", {})
        host, port, sock = joomla.split_db_host(str(v.get("host", "")))
        return {"found": True, "host": host + (":" + sock if sock else ""), "port": str(port or ""), "user": str(v.get("user", "")), "name": str(v.get("db", "")),
                "prefix": str(v.get("dbprefix", "")), "has_password": bool(v.get("password"))}

    def db_test(self, body: Dict[str, Any]) -> Dict[str, Any]:
        if not self.runner:
            raise ApiError("Bitte zuerst eine Verbindung herstellen.", 409)
        self.ensure_connected()
        db_settings = self._clean_db(body.get("db"))
        st = Settings(site_dir=str(body.get("site_dir") or "").strip() or self._log_site(), db=db_settings, cms=self.cms())
        ctx = Ctx(self.runner, st, self.advisories, lambda e: None, threading.Event())
        db = ctx.db()
        if not db.ok:
            return {"ok": False, "error": db.error}
        try:
            row = (db.query("SELECT VERSION() AS v, DATABASE() AS d") or [{}])[0]
        except DbError as e:
            return {"ok": False, "error": str(e)}
        return {"ok": True, "version": row.get("v", ""), "database": row.get("d", ""), "prefix": db.prefix, "user": db.user, "custom": bool(db_settings)}

    def actions_list(self) -> Dict[str, Any]:
        if not self.runner:
            return {"actions": [], "connected": False}
        scan: Dict[str, Any] = {}
        if not self.running and not (self.actjob and not self.actjob.finished):
            if self.auto_update and self.results:
                self.ensure_update_check()
            scan = self._scan() if (self.results or self.manage) else {}
        scan = dict(scan)
        scan["manage"] = self.manage
        scan["local_logs"] = actions.list_local_logs(self.reports)
        scan["log_dir"] = self.reports
        lst = actions.available(list(self.results) if not self.running else [], self.info, self._php_manual(), self.update_state, scan)
        us = self.update_state
        upd = {"checking": bool(us.get("checking") or (self.updjob and not self.updjob.finished)), "checked": bool(us.get("checked")), "failed": bool(us.get("failed")),
               "error": us.get("error", ""), "has_update": us.get("has_update"), "latest": us.get("latest", ""), "ext_count": len(us.get("ext_updates") or []),
               "reliable": bool(us.get("reliable")), "confirmed": bool(us.get("confirmed")), "reasons": us.get("reasons") or [],
               "live_extra": us.get("live_extra") or [], "message": us.get("message", "")}
        return {"actions": lst, "connected": True, "update_checked": bool(us.get("checked")), "update": upd,
                "busy": bool((self.actjob and not self.actjob.finished) or upd["checking"]), "plan": actions.build_plan(lst, self.results),
                "action_plan": actionplan.build_plan(list(self.results) if not self.running else [], [a for a in lst if not a.get("hidden")], self.cms(), cluster_map(self.cms())),
                "manual": snippets.manual_targets(list(self.results)) if not self.running else []}

    def cms_logo(self) -> Dict[str, Any]:
        from . import store
        return store.cms_logo(self.cms())

    def store_info(self, body: Dict[str, Any]) -> Dict[str, Any]:
        """Kurzbeschreibung, Bild und Store-Link einer Sicherheits-Erweiterung aus der festen Liste (die Kennung wird nur nachgeschlagen, nie als Adresse benutzt)."""
        from . import store
        from .checks.security_ext import load_tools
        cms = self.cms()
        tid = str(body.get("id") or "")
        for t in load_tools("backup" if str(body.get("kind")) == "backup" else "security").get(cms, []):
            if t["id"] == tid and not t.get("background"):
                return store.lookup(t, cms)
        raise ApiError("Unbekannte Erweiterung.", 404)

    def snippet(self, body: Dict[str, Any]) -> Dict[str, Any]:
        """Ausschnitt einer verdächtigen Datei (nur lesend). Erlaubt sind nur Fundstellen, die die Prüfung selbst gemeldet hat."""
        if not self.runner:
            raise ApiError("Bitte zuerst eine Verbindung herstellen.", 409)
        try:
            file, line = str(body.get("file", "")), int(body.get("line"))
        except (TypeError, ValueError):
            raise ApiError("Ungültige Anfrage.", 400)
        if not any(t["file"] == file and t["line"] == line for t in snippets.manual_targets(list(self.results))):
            raise ApiError("Diese Fundstelle gehört nicht zu den Befunden.", 404)
        self.ensure_connected()
        try:
            r = self.runner.sh(self._log_site(), snippets.read_script(file, line), 60)
        except RunnerError as e:
            raise ApiError(str(e), 502)
        got = snippets.parse_read(r.out, line)
        if got is None:
            raise ApiError("Die Datei gibt es nicht mehr (oder sie ist ein Verweis). Vermutlich wurde sie schon entfernt oder ersetzt.", 404)
        lines, first, total = got
        if not lines or first + len(lines) - 1 < line:
            raise ApiError("Die Datei hat keine Zeile %d mehr. Vermutlich wurde sie schon geändert." % line, 404)
        ex = snippets.build_excerpt(lines, first, line, total)
        ex["file"] = file
        ex["original"] = self._original(file, lines, first, line, ex.get("fixed_line", ""))
        return ex

    def _original(self, file: str, lines: List[str], first: int, target: int, fixed: str) -> Dict[str, Any]:
        """Abgleich mit dem offiziellen Joomla-Original dieser Version (von diesem PC aus, nur lesend). Immer ein Ergebnis, nie ein Fehler."""
        wp = self.cms() == "wordpress"
        name = cmsmod.name_of(self.cms())
        ver = str((self.info or {}).get(cmsmod.profile(self.cms())["version_key"]) or "").strip()
        if self.cms() == "drupal":
            return {"status": "kein_original", "note": "Für Drupal gibt es noch keinen Abgleich einzelner Zeilen mit dem Original. Der Dateivergleich des Kerns steht in der Prüfung 'Drupal-Kern: Version und Originaldateien'."}
        if self.cms() == "contao":
            return {"status": "kein_original", "note": "Für Contao gibt es noch keinen Abgleich einzelner Zeilen mit dem Original. Der Dateivergleich der Kern-Pakete steht in der Prüfung 'Contao-Kern: Version, Sicherheitsmeldungen und Originaldateien'."}
        if self.cms() == "shopware":
            return {"status": "kein_original", "note": "Für Shopware gibt es noch keinen Abgleich einzelner Zeilen mit dem Original. Der Dateivergleich des Kerns steht in der Prüfung 'Shopware-Kern: Version, Sicherheitsmeldungen und Originaldateien'."}
        if self.cms() == "prestashop":
            return {"status": "kein_original", "note": "Für PrestaShop gibt es noch keinen Abgleich einzelner Zeilen mit dem Original. Der Dateivergleich des Kerns steht in der Prüfung 'PrestaShop-Kern: Version, Sicherheitsmeldungen und Originaldateien'."}
        if self.cms() == "typo3":
            return {"status": "kein_original", "note": "Für TYPO3 gibt es noch keinen Abgleich einzelner Zeilen mit dem Original. Der Dateivergleich der Systemerweiterungen steht in der Prüfung 'TYPO3-Kern: Version, Sicherheitsmeldungen und Originaldateien'."}
        if not (snippets.core_candidate_wp(file) if wp else snippets.core_candidate(file)):
            return {"status": "kein_original", "note": "Das ist keine Datei des offiziellen %s (Theme oder Plugin eines Drittanbieters), deshalb gibt es kein Original zum Vergleichen. "
                                                       "Die grüne Zeile ist aus der Zeile selbst abgeleitet: nur die rot markierte Stelle fehlt." % name}
        if not re.match(r"^\d+(\.\d+){1,3}\Z", ver):
            return {"status": "kein_original", "note": "Die %s-Version ist nicht bekannt, ein Vergleich mit dem Original ist nicht möglich." % name}
        if os.environ.get("CLAUDIA_OFFLINE"):
            return {"status": "kein_original", "note": "Offline-Modus: der Vergleich mit dem Original wird nicht abgerufen."}
        key = (name, ver, file)
        cache = self.__dict__.setdefault("_orig_cache", {})
        if key not in cache:
            from .checks.web import UA_BROWSER, fetch
            base = os.environ.get("CLAUDIA_ORIGINAL_BASE") or (snippets.ORIGINAL_BASE_WP if wp else snippets.ORIGINAL_BASE)
            f = fetch(snippets.original_url(ver, file, base), UA_BROWSER, max_bytes=3_000_000, timeout=20)
            cache[key] = (f.status, f.error, f.body)
        status, err, body = cache[key]
        if err:
            return {"status": "kein_original", "note": "Das Original konnte nicht abgerufen werden (%s). Die grüne Zeile ist aus der Zeile selbst abgeleitet." % err[:120]}
        if status != 200:
            return {"status": "kein_original", "note": "Zu dieser Datei gibt es in %s %s kein Original (HTTP %d). Vermutlich gehört sie nicht zu %s selbst. "
                                                       "Die grüne Zeile ist aus der Zeile selbst abgeleitet." % (name, ver, status, name)}
        res = snippets.compare_original(lines, first, target, body.splitlines(), fixed)
        res["source"] = "%s %s (offizielles Original auf GitHub)" % (name, ver)
        return res

    def update_check(self) -> Dict[str, Any]:
        if not self.runner:
            raise ApiError("Bitte zuerst eine Verbindung herstellen.", 409)
        if self.actjob and not self.actjob.finished:
            raise ApiError("Es läuft gerade eine Aktion.", 409)
        self.ensure_update_check(force=True)
        return {"started": True}

    def _find_action(self, aid: str) -> Dict[str, Any]:
        for a in self.actions_list()["actions"]:
            if a["id"] == aid:
                return a
        raise ApiError("Diese Aktion ist gerade nicht verfügbar.", 404)

    def action_preview(self, body: Dict[str, Any]) -> Dict[str, Any]:
        a = self._find_action(str(body.get("id", "")))
        params = dict(a["params"], php=body.get("php", ""), selected=self._selected(a, body), **self._extra(a, body))
        try:
            cmds = actions.commands_preview(a["id"], params, a.get("php_choices", []))
            extra = {}
            if a["id"] == "remove_db_code":
                if not self.runner:
                    raise ApiError("Bitte zuerst eine Verbindung herstellen.", 409)
                extra["dbcode"] = actions.dbcode_preview(self.runner, (self.run_settings.get("site_dir") or self.conn.get("site_dir") or "html"), params)
            if a["id"] == "reset_htaccess":
                if not self.runner:
                    raise ApiError("Bitte zuerst eine Verbindung herstellen.", 409)
                extra["htaccess"] = actions.htaccess_preview(self.runner, (self.run_settings.get("site_dir") or self.conn.get("site_dir") or "html"), params)
        except actions.ActionError as e:
            raise ApiError(str(e))
        return dict({"id": a["id"], "commands": cmds}, **extra)

    def _extra(self, a: Dict[str, Any], body: Dict[str, Any]) -> Dict[str, Any]:
        """Zusätzliche, geprüfte Parameter einzelner Aktionen."""
        out: Dict[str, Any] = {}
        if a["id"] == "delete_old_backups":
            out["selected_backups"] = [str(x) for x in (body.get("backups") or []) if isinstance(x, str)][:60]
            out["selected_logs"] = [str(x) for x in (body.get("logs") or []) if isinstance(x, str)][:500]
        if a["id"] in ("install_security", "install_backup"):
            ok = {t["id"] for t in a["params"].get("tools", []) if t.get("installable")}
            tid = str(body.get("tool") or "")
            if tid not in ok:
                raise ApiError("Bitte eine Erweiterung aus der Liste wählen, die das Programm installieren darf.", 400)
            out["tool"] = tid
        if a["id"] in actions.PICK_ACTIONS and (a["id"] != "remove_shells" or a["params"].get("pick")):
            valid = [str(x.get("key")) for x in a["params"].get("pick", [])]
            chosen = [k for k in dict.fromkeys(str(x) for x in (body.get("pick") or []) if isinstance(x, str)) if k in valid]
            if not chosen:
                raise ApiError("Bitte mindestens einen Eintrag auswählen.", 400)
            out["selected_pick"] = chosen
        if a["id"] == "remove_db_code":
            try:
                from urllib.parse import urlparse
                out["own_host"] = (urlparse(str(self.run_settings.get("url") or "")).hostname or "").lower()
            except ValueError:
                out["own_host"] = ""
            ah = self.run_settings.get("allow_hosts") or []
            ah = split_allow(ah) if isinstance(ah, str) else list(ah)
            out["allow"] = list(self.advisories.get("allow_hosts", [])) + ah
            out["ioc"] = list(self.advisories.get("ioc_strings", []))
        if a["id"] == "reset_htaccess":
            out["keep_own"] = body.get("keep_own") is not False
            try:
                from urllib.parse import urlparse
                out["own_host"] = (urlparse(str(self.run_settings.get("url") or "")).hostname or "").lower()
            except ValueError:
                out["own_host"] = ""
        if a.get("can_skip_backup") and body.get("no_backup") is True:
            out["no_backup"] = True
        return out

    def _selected(self, a: Dict[str, Any], body: Dict[str, Any]) -> List[int]:
        if a["id"] != "update_extensions":
            return []
        ok = {int(u["uid"]) for u in a["params"].get("updates", [])}
        out = []
        for i in body.get("selected") or []:
            try:
                if int(i) in ok and int(i) not in out:
                    out.append(int(i))
            except (TypeError, ValueError):
                pass
        return out

    def action_start(self, body: Dict[str, Any]) -> Dict[str, Any]:
        """Prüft alles und startet die Aktion im Hintergrund. Der Fortschritt (Befehle, Antworten des Servers) kommt über action_state()."""
        if body.get("confirm") is not True:
            raise ApiError("Bitte die Warnung bestätigen.", 400)
        if self.running:
            raise ApiError("Es läuft gerade eine Prüfung.", 409)
        a = self._find_action(str(body.get("id", "")))
        if a["reason"]:
            raise ApiError(a["reason"], 409)
        if a["id"] == "core_update" and not self.update_state.get("checked") and not self._older_known():
            raise ApiError("Bitte zuerst 'Nach Updates suchen' ausführen und das Ergebnis lesen.", 409)
        if a["id"] == "update_extensions" and not self._selected(a, body):
            raise ApiError("Bitte mindestens ein Update auswählen.", 400)
        extra = self._extra(a, body)
        if a["id"] == "delete_old_backups" and not extra.get("selected_backups") and not extra.get("selected_logs"):
            raise ApiError("Bitte mindestens eine Sicherung oder ein Protokoll auswählen.", 400)
        if a.get("irreversible") and body.get("confirm_irreversible") is not True:
            raise ApiError("Diese Aktion lässt sich nicht vollständig rückgängig machen. Bitte den Hinweis ausdrücklich bestätigen.", 400)
        if extra.get("no_backup") and body.get("confirm_no_backup") is not True:
            raise ApiError("Bitte bestätigen, dass du die Profile ohne Sicherung löschen willst.", 400)
        if self.updjob and not self.updjob.finished:
            raise ApiError("Die Update-Suche läuft noch. Bitte einen Moment warten.", 409)
        self.ensure_connected()
        params = dict(a["params"], php=body.get("php", ""), selected=self._selected(a, body), **extra)
        with self.lock:
            if self.actjob and not self.actjob.finished:
                raise ApiError("Es läuft bereits eine Aktion.", 409)
            self.actjob = ActionJob(self, a, params)
        self.actjob.start()
        return {"started": True}

    def _older_known(self) -> bool:
        for r in self.results:
            for f in r.get("findings", []):
                if f.get("title", "").startswith("Joomla ist älter als die neueste bekannte Version"):
                    return True
        return False

    def action_state(self, since: int = 0) -> Dict[str, Any]:
        j = self.actjob
        if not j:
            return {"none": True, "done": True, "events": [], "next": 0}
        return j.state(since)

    def action_run(self, body: Dict[str, Any]) -> Dict[str, Any]:
        """Wie action_start, wartet aber auf das Ende und liefert das Ergebnis (für Tests und einfache Aufrufer)."""
        self.action_start(body)
        j = self.actjob
        j.thread.join()
        if j.error:
            raise ApiError(j.error)
        return j.result

    # ------------------------------------------------------------ Protokolle auf den PC sichern (auf dem Server nur lesend)
    def _log_site(self) -> str:
        return (self.run_settings.get("site_dir") or self.conn.get("site_dir") or "html")

    def logs_plan(self, body: Dict[str, Any]) -> Dict[str, Any]:
        if not self.runner:
            raise ApiError("Bitte zuerst eine Verbindung herstellen.", 409)
        if self.running:
            raise ApiError("Es läuft gerade eine Prüfung.", 409)
        self.ensure_connected()
        try:
            items = logsave.list_remote(self.runner, self._log_site(), str(body.get("log_dir") or "").strip(),
                                        include_joomla=body.get("joomla") is not False)
        except (logsave.LogSaveError, RunnerError) as e:
            raise ApiError(str(e), 502)
        arch = logsave.Archive(self.logs_base, self.conn.get("host", "server"))
        pl = logsave.plan(arch, items)
        pl["todo"] = [{"rel": x["rel"], "size": x["size"], "mtime": x["mtime"], "state": x["state"]} for x in pl["todo"]]
        return pl

    def logs_save(self, body: Dict[str, Any]) -> Dict[str, Any]:
        if body.get("confirm") is not True:
            raise ApiError("Bitte bestätigen.", 400)
        if self.logjob and not self.logjob.finished:
            raise ApiError("Es läuft bereits eine Sicherung.", 409)
        if not self.runner:
            raise ApiError("Bitte zuerst eine Verbindung herstellen.", 409)
        if self.running:
            raise ApiError("Es läuft gerade eine Prüfung.", 409)
        self.ensure_connected()
        try:
            items = logsave.list_remote(self.runner, self._log_site(), str(body.get("log_dir") or "").strip(),
                                        include_joomla=body.get("joomla") is not False)
        except (logsave.LogSaveError, RunnerError) as e:
            raise ApiError(str(e), 502)
        arch = logsave.Archive(self.logs_base, self.conn.get("host", "server"))
        pl = logsave.plan(arch, items)
        if not pl["todo"]:
            return {"started": False, "message": "Alle gefundenen Protokolle sind bereits gesichert.", "dir": arch.dir}
        if not pl["fits"]:
            raise ApiError("Auf dem PC ist nicht genug Platz frei (benötigt %d MB, frei %d MB)." % (pl["bytes"] // 1048576, pl["free"] // 1048576), 507)
        self.logjob = logsave.SaveJob(self.runner, self._log_site(), arch, pl["todo"])
        self.logjob.start()
        return {"started": True, "dir": arch.dir}

    def logs_state(self) -> Dict[str, Any]:
        return self.logjob.state() if self.logjob else {"done": True, "none": True}

    def logs_cancel(self) -> None:
        if self.logjob:
            self.logjob.cancel.set()

    def logs_open(self) -> None:
        d = self.logjob.archive.dir if self.logjob else os.path.join(self.logs_base, logsave.host_slug(self.conn.get("host", "server")))
        if not os.path.isdir(d):
            raise ApiError("Es wurde noch nichts gesichert.", 409)
        self._reveal(d)

    def handover_prompt(self) -> str:
        """Fertiger Text für den Chat mit Claude (ohne Zugangsdaten)."""
        sm = summarize([r.to_dict() if hasattr(r, "to_dict") else r for r in self.results])
        c = sm.get("counts", {})
        joomla = (self.info or {}).get("joomla") or "unbekannt"
        return ("Hallo Claude, ich habe meine Joomla-Seite mit CLAUDIA (Version %s) geprüft. Joomla %s. "
                "Im Anhang liegt fuer_claude.zip (bericht.txt, ergebnisse.json, Rohdaten; ohne Passwörter).\n\n"
                "Ergebnis laut Programm: %d kritisch, %d Warnung(en), %d Hinweis(e), %d in Ordnung.\n\n"
                "Bitte: 1) gehe die Befunde der Reihe nach durch, 2) trenne echte Probleme von Fehlalarmen und begründe es, "
                "3) nenne die wichtigsten nächsten Schritte in sinnvoller Reihenfolge, 4) sag mir, ob am Programm selbst etwas "
                "falsch erkannt wurde, damit es verbessert werden kann."
                % (__version__, joomla, c.get("crit", 0), c.get("warn", 0), c.get("info", 0), c.get("ok", 0)))

    def handover(self) -> Dict[str, Any]:
        """Bericht speichern, Ordner mit markierter ZIP öffnen und den Chat-Text liefern. Hochladen kann das Programm nicht selbst."""
        out = self.export()
        zip_path = os.path.join(out["dir"], "fuer_claude.zip")
        try:
            self._reveal(zip_path if os.path.isfile(zip_path) else out["dir"])
        except Exception:
            pass
        return {"ok": True, "dir": out["dir"], "files": out["files"], "zip": zip_path, "prompt": self.handover_prompt(), "url": "https://claude.ai/new"}

    @staticmethod
    def _reveal(path: str) -> None:
        import subprocess
        if os.name == "nt":
            if os.path.isfile(path):
                subprocess.Popen(["explorer", "/select,", path])
            else:
                os.startfile(path)                   # type: ignore[attr-defined]
        elif sys.platform == "darwin":
            subprocess.Popen(["open", "-R", path] if os.path.isfile(path) else ["open", path])
        else:
            subprocess.Popen(["xdg-open", os.path.dirname(path) if os.path.isfile(path) else path])

    def open_folder(self) -> None:
        if not self.last_export or not os.path.isdir(self.last_export):
            raise ApiError("Es wurde noch nichts gespeichert.", 409)
        try:
            if os.name == "nt":
                os.startfile(self.last_export)      # type: ignore[attr-defined]
            elif sys.platform == "darwin":
                import subprocess
                subprocess.Popen(["open", self.last_export])
            else:
                import subprocess
                subprocess.Popen(["xdg-open", self.last_export])
        except Exception as e:
            raise ApiError("Der Ordner konnte nicht geöffnet werden: %s" % e, 500)

    def cms(self) -> str:
        """Erkanntes System der verbundenen Seite: 'joomla' oder 'wordpress' (Standard: joomla)."""
        return cmsmod.known(str((self.info or {}).get("cms") or "joomla"))

    def docs_payload(self) -> Dict[str, Any]:
        """Handbuch, Änderungsverlauf und Prüfkatalog in der gewählten Sprache (Dokumentation im Programm)."""
        load_all()
        checks: List[Dict[str, Any]] = []
        for cms in cmsmod.PROFILES:
            for c in ordered(cms):
                d = c.public(cms)
                checks.append({"cms": cms, "id": d["id"], "title": d["title"], "summary": d["summary"], "what": d["what"], "why": d["why"],
                               "reads": d["reads"], "load": d.get("load", "")})
        acts = actions.catalog()
        if self.lang != i18n.SOURCE:
            checks, acts = i18n.tr_obj(checks, self.lang), i18n.tr_obj(acts, self.lang)
        return helpdocs.payload(self.lang, __version__, checks, acts)

    def befund_text(self) -> str:
        """Kurzfassung der letzten Prüfung für die MANIFEST.txt einer Sicherung (nur Anzahlen, keine Inhalte)."""
        cnt: Dict[str, int] = {}
        for r in list(self.results):
            for f in (r.get("findings", []) if isinstance(r, dict) else []):
                cnt[f.get("sev", "info")] = cnt.get(f.get("sev", "info"), 0) + 1
        if not cnt:
            return ""
        names = {"crit": "kritisch", "warn": "Warnung", "info": "Hinweis", "ok": "in Ordnung"}
        return ", ".join("%s: %d" % (names.get(k, k), cnt[k]) for k in ("crit", "warn", "info", "ok") if k in cnt)

    def techdoc_payload(self) -> Dict[str, Any]:
        """Kapitel 'Technik': Befehle, SQL und Programmablauf aus dem echten Quelltext (claudia/techdoc.py)."""
        from . import techdoc
        return techdoc.payload(self.lang)

    def uninstall_plan(self) -> Dict[str, Any]:
        root = os.path.dirname(HERE)
        return {"items": uninstall.plan(root, self.dir, self.reports), "windows": os.name == "nt"}

    def uninstall_run(self, ids: List[Any], confirm: bool) -> Dict[str, Any]:
        """Löscht erst nach dem Beenden des Programms (Skript). Nur Einträge aus dem eigenen Plan, nur mit ausdrücklicher Bestätigung."""
        if confirm is not True:
            raise ValueError("Bitte die Bestätigung ankreuzen.")
        root = os.path.dirname(HERE)
        chosen = uninstall.validate(uninstall.plan(root, self.dir, self.reports), [str(i) for i in ids][:12], root, self.dir)
        if not chosen:
            raise ValueError("Nichts ausgewählt oder nichts mehr vorhanden.")
        pids = [os.getpid()]
        if getattr(self, "parent_pid", 0):
            pids.append(int(self.parent_pid))
        if uninstall.window_available():
            script = uninstall.launch_window(chosen, pids, self.dir)
        else:                                                      # ohne tkinter: Konsolen-Skript wie bisher
            script = uninstall.write_script(chosen, pids, self.dir)
            uninstall.launch(script)
        return {"ok": True, "count": len(chosen), "script": script}

    def init_payload(self) -> Dict[str, Any]:
        cms = self.cms()
        return {
            "app": APP_NAME, "version": __version__, "stand": self.advisories.get("stand", ""), "cms": cms, "loc": python_lines(),
            "cms_name": cmsmod.name_of(cms), "license": lizenz.state(self.dir),
            "groups": [{"id": g[0], "title": g[1], "text": g[2]} for g in groups_for(cms)],
            "presets": [{"id": p[0], "title": p[1], "text": p[2]} for p in PRESETS],
            "clusters": cluster_title_defs(cms),
            "checks": [c.public(cms) for c in ordered(cms)],
            "profiles": self.profiles.load(),
            "data_dir": self.dir, "reports_dir": self.reports, "demo": bool(self.demo_world),
            "connected": bool(self.conn), "info": self.info,
            "running": self.running, "icons": all_icons(), "lang": self.lang, "langs": i18n.languages(),
        }


# ======================================================================= HTTP
class Handler(BaseHTTPRequestHandler):
    server_version = "CLAUDIA"
    protocol_version = "HTTP/1.0"
    timeout = 60                                  # hängende Verbindungen (z. B. halb gesendete Anfragen) werden beendet

    @property
    def app(self) -> App:
        return self.server.app          # type: ignore[attr-defined]

    def log_message(self, fmt: str, *args: Any) -> None:   # leise
        pass

    # --------------------------------------------------- Schutz
    def _guard(self) -> bool:
        port = self.server.server_address[1]
        allowed = {"127.0.0.1:%d" % port, "localhost:%d" % port}
        if (self.headers.get("Host") or "").lower() not in allowed:
            self._send(403, b"Forbidden", "text/plain")
            return False
        origin = self.headers.get("Origin")
        if origin and origin.lower() not in {"http://" + a for a in allowed}:
            self._send(403, b"Forbidden", "text/plain")
            return False
        return True

    def _session_ok(self) -> bool:
        """Gültige Sitzung = Cookie aus dem Startschlüssel-Tausch. Jede Anfrage braucht zusätzlich den Kopf X-Claudia (kann fremde Seiten nicht setzen)."""
        return self.server.session_valid(self._cookie())          # type: ignore[attr-defined]

    def _cookie(self) -> str:
        for part in (self.headers.get("Cookie") or "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == COOKIE:
                return v
        return ""

    def _api_ok(self) -> bool:
        return self._session_ok() and self.headers.get("X-Claudia") == "1"

    def _send(self, code: int, body: bytes, ctype: str, extra: Optional[Dict[str, str]] = None) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj: Any, code: int = 200, translate: bool = True) -> None:
        lang = getattr(self.app, "lang", i18n.SOURCE)
        if translate and lang != i18n.SOURCE:
            obj = i18n.tr_obj(obj, lang)                  # alle Texte in der gewählten Sprache (Quelle: claudia/lang/<code>.json)
        self._send(code, json.dumps(obj, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8")

    # --------------------------------------------------- Routen
    def do_GET(self) -> None:  # noqa: N802
        if not self._guard():
            return
        u = urlparse(self.path)
        if u.path in ("/", "/index.html"):
            key = (parse_qs(u.query).get("k") or [""])[0]
            if key:                                    # Einmal-Startschlüssel gegen Sitzungs-Cookie tauschen, danach sauberer Aufruf ohne Schlüssel
                sid = self.server.redeem(key)          # type: ignore[attr-defined]
                if not sid:
                    return self._send(403, locked_page(getattr(self.app, "lang", i18n.SOURCE)), "text/html; charset=utf-8")
                return self._send(302, b"", "text/plain", {"Location": "/", "Set-Cookie": "%s=%s; Path=/; HttpOnly; SameSite=Strict" % (COOKIE, sid)})
            if not self._session_ok():
                return self._send(403, locked_page(getattr(self.app, "lang", i18n.SOURCE)), "text/html; charset=utf-8")
            with open(os.path.join(WEB, "index.html"), "r", encoding="utf-8") as fh:
                page = fh.read()
            self.server.note_page_load()               # type: ignore[attr-defined]
            return self._send(200, page.encode("utf-8"), "text/html; charset=utf-8")
        if u.path in STATIC:
            name, ctype = STATIC[u.path]
            with open(os.path.join(WEB, name), "rb") as fh:
                return self._send(200, fh.read(), ctype)
        if u.path.startswith("/api/"):
            return self._api("GET", u.path, parse_qs(u.query), {})
        self._send(404, b"Not found", "text/plain")

    def do_POST(self) -> None:  # noqa: N802
        if not self._guard():
            return
        u = urlparse(self.path)
        if not self._api_ok():                        # zuerst prüfen, dann erst den Inhalt lesen
            return self._json({"error": "Nicht autorisiert. Dieses Programm lässt sich nur über sein eigenes Fenster bedienen."}, 403)
        try:
            n = int(self.headers.get("Content-Length") or 0)
            if n < 0 or n > 1_000_000:
                return self._json({"error": "Anfrage zu groß."}, 413)
            body = json.loads(self.rfile.read(n).decode("utf-8") or "{}")
            if not isinstance(body, dict):
                raise ValueError
        except (ValueError, OSError):
            return self._json({"error": "Ungültige Anfrage."}, 400)
        self._api("POST", u.path, {}, body)

    def _api(self, method: str, path: str, q: Dict[str, List[str]], body: Dict[str, Any]) -> None:
        if not self._api_ok():
            return self._json({"error": "Nicht autorisiert. Dieses Programm lässt sich nur über sein eigenes Fenster bedienen."}, 403)
        app = self.app
        area = area_of(path)
        if area and not lizenz.frei(app.dir, area, str(body.get("id", "")) if area == "aktionen" else ""):
            return self._json({"error": "Dieser Bereich (%s) ist nur mit gültigem Lizenzschlüssel nutzbar. Die Prüfung bleibt immer frei. Den Schlüssel trägst du unter „Lizenz“ ein."
                               % lizenz.BEREICHE.get(area, area), "lizenz": True, "area": area}, 403)
        try:
            if method == "GET" and path == "/api/init":
                return self._json(app.init_payload())
            if method == "GET" and path == "/api/docs":
                return self._json(app.docs_payload(), translate=False)
            if method == "GET" and path == "/api/techdoc":
                return self._json(app.techdoc_payload(), translate=False)
            if method == "GET" and path == "/api/lang":
                return self._json(i18n.client_payload(app.lang), translate=False)
            if method == "POST" and path == "/api/lang":
                return self._json(app.set_lang(str(body.get("lang", ""))), translate=False)
            if method == "GET" and path == "/api/zip":
                data = report.claude_zip(app.bundle())
                return self._send(200, data, "application/zip",
                                  {"Content-Disposition": 'attachment; filename="fuer_claude.zip"'})
            if method == "POST" and path == "/api/export":
                return self._json(app.export())
            if method == "GET" and path == "/api/actions":
                return self._json(app.actions_list())
            if method == "POST" and path == "/api/snippet":
                return self._json(app.snippet(body))
            if method == "POST" and path == "/api/db-prefill":
                return self._json(app.db_prefill(body))
            if method == "POST" and path == "/api/db-test":
                return self._json(app.db_test(body))
            if method == "GET" and path == "/api/cms-logo":
                return self._json(app.cms_logo(), translate=False)
            if method == "POST" and path == "/api/store-info":
                return self._json(app.store_info(body))
            if method == "GET" and path == "/api/dashboard":
                return self._json(app.dashboard())
            if method == "POST" and path == "/api/dashboard-delete":
                return self._json(app.dashboard_delete(body))
            if method == "GET" and path == "/api/dashboard-server":
                return self._json(app.dashboard_server())
            if method == "POST" and path == "/api/dashboard-export":
                return self._json(app.dashboard_export(body))
            if method == "POST" and path == "/api/dashboard-verify":
                return self._json(app.dashboard_verify(body))
            if method == "POST" and path == "/api/support-package":
                return self._json(app.support_package())
            if method == "GET" and path == "/api/license":
                return self._json(lizenz.state(app.dir))
            if method == "POST" and path == "/api/license-set":
                res = lizenz.store(app.dir, str(body.get("key", ""))[:lizenz.MAX_KEY_LEN + 1])
                return self._json(dict(lizenz.state(app.dir), accepted=bool(res["valid"]), message=_lizenz_msg(res)))
            if method == "POST" and path == "/api/license-remove":
                lizenz.remove(app.dir)
                return self._json(dict(lizenz.state(app.dir), removed=True))
            if method == "GET" and path == "/api/app-update":
                return self._json(app.selfupd_state())
            if method == "POST" and path == "/api/app-update-check":
                return self._json(app.selfupd_check())
            if method == "POST" and path == "/api/app-update-skip":
                return self._json(app.selfupd_skip(str(body.get("version", ""))))
            if method == "POST" and path == "/api/app-update-install":
                return self._json(app.selfupd_install(str(body.get("version", ""))))
            if method == "POST" and path == "/api/app-update-restart":
                res = app.selfupd_restart()
                self._json(res)
                threading.Thread(target=self.server.stop, daemon=True).start()
                return
            if method == "POST" and path == "/api/update-check":
                return self._json(app.update_check())
            if method == "POST" and path == "/api/action-preview":
                return self._json(app.action_preview(body))
            if method == "POST" and path == "/api/action-run":
                return self._json(app.action_start(body))
            if method == "GET" and path == "/api/action-state":
                return self._json(app.action_state(int((q.get("since") or ["0"])[0])))
            if method == "POST" and path == "/api/logs-plan":
                return self._json(app.logs_plan(body))
            if method == "POST" and path == "/api/logs-save":
                return self._json(app.logs_save(body))
            if method == "GET" and path == "/api/logs-state":
                return self._json(app.logs_state())
            if method == "POST" and path == "/api/logs-cancel":
                app.logs_cancel()
                return self._json({"ok": True})
            if method == "POST" and path == "/api/logs-open":
                app.logs_open()
                return self._json({"ok": True})
            if method == "POST" and path == "/api/handover":
                return self._json(self.app.handover())
            if method == "POST" and path == "/api/open-folder":
                app.open_folder()
                return self._json({"ok": True})
            if method == "GET" and path == "/api/state":
                return self._json(app.state(int((q.get("since") or ["0"])[0])))
            if method == "POST" and path == "/api/connect":
                return self._json(app.connect_start(body))
            if method == "GET" and path == "/api/connect-state":
                return self._json(app.connect_state())
            if method == "POST" and path == "/api/connect-cancel":
                app.connect_cancel()
                return self._json({"ok": True})
            if method == "POST" and path == "/api/disconnect":
                app.disconnect()
                return self._json({"ok": True})
            if method == "GET" and path == "/api/uninstall-plan":
                return self._json(app.uninstall_plan())
            if method == "POST" and path == "/api/uninstall-run":
                try:
                    res = app.uninstall_run(list(body.get("ids") or []), body.get("confirm"))
                except ValueError as e:
                    return self._json({"error": str(e)}, 400)
                app.disconnect()
                self._json(res)
                threading.Thread(target=self.server.stop, daemon=True).start()
                return
            if method == "GET" and path == "/api/ping":
                self.server.ping()                     # type: ignore[attr-defined]
                return self._json({"ok": True})
            if method == "POST" and path == "/api/open-url":
                url = str(body.get("url", ""))
                if not re.match(r"^https://[A-Za-z0-9.-]+(:\d+)?(/[^\s\x00-\x1f]*)?\Z", url) or len(url) > 400:
                    raise ApiError("Nur https-Adressen werden im Browser geöffnet.")
                import webbrowser
                webbrowser.open(url)
                return self._json({"ok": True})
            if method == "POST" and path == "/api/quit":
                app.disconnect()
                self._json({"ok": True})
                threading.Thread(target=self.server.stop, daemon=True).start()
                return
            if method == "POST" and path == "/api/run":
                app.start(list(body.get("ids") or []), dict(body.get("settings") or {}))
                return self._json({"ok": True})
            if method == "POST" and path == "/api/baseline-info":
                return self._json(app.baseline_info(body.get("site_dir")))
            if method == "POST" and path == "/api/baseline-delete":
                return self._json(app.baseline_delete(body.get("site_dir")))
            if method == "POST" and path == "/api/cancel":
                app.cancel.set()
                return self._json({"ok": True})
            if method == "POST" and path == "/api/profile/save":
                name = (body.get("name") or "").strip()
                if not name:
                    raise ApiError("Bitte einen Profilnamen angeben.")
                app.profiles.save(name[:60], body.get("data") or {})
                return self._json({"ok": True, "profiles": app.profiles.load()})
            if method == "POST" and path == "/api/profile/delete":
                app.profiles.delete((body.get("name") or "").strip())
                return self._json({"ok": True, "profiles": app.profiles.load()})
            return self._json({"error": "Unbekannte Funktion."}, 404)
        except ApiError as e:
            return self._json(dict({"error": str(e)}, **e.extra), e.status)
        except Exception as e:  # pragma: no cover
            sys.stderr.write(traceback.format_exc())
            return self._json({"error": "Interner Fehler: %s" % e}, 500)


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, app: App, port: int = 0):
        super().__init__(("127.0.0.1", port), Handler)
        self.app = app
        self._keys: Dict[str, float] = {}
        self._sessions: List[str] = []
        self._lock = threading.Lock()
        self.last_ping = time.monotonic()
        self.page_loaded = threading.Event()
        self.on_stop: List[Any] = []

    # --- Zugang: Einmal-Startschlüssel -> Sitzungs-Cookie. Der Schlüssel liegt nur im Speicher und wird nie in einer Seite oder Datei ausgegeben.
    def handle_error(self, request: Any, client_address: Any) -> None:
        """Abgebrochene Verbindungen (Browser zu, halbe Anfrage) sind normal und brauchen keine Fehlerausgabe mit Stacktrace; echte Fehler bleiben sichtbar."""
        if isinstance(sys.exc_info()[1], (ConnectionError, TimeoutError, socket.timeout)):
            return
        super().handle_error(request, client_address)

    def new_key(self) -> str:
        key = secrets.token_urlsafe(24)
        with self._lock:
            now = time.monotonic()
            self._keys = {k: t for k, t in self._keys.items() if now - t < 120}
            self._keys[key] = now
        return key

    def entry_url(self) -> str:
        """Adresse mit frischem Einmal-Schlüssel. Nur für das eigene Programmfenster (und Tests) gedacht."""
        return self.url + "?k=" + self.new_key()

    def redeem(self, key: str) -> str:
        with self._lock:
            t = self._keys.pop(key, None)
            if t is None or time.monotonic() - t > 120:
                return ""
            sid = secrets.token_urlsafe(24)
            self._sessions = (self._sessions + [sid])[-4:]
            return sid

    def session_valid(self, sid: str) -> bool:
        with self._lock:
            return any(secrets.compare_digest(sid, s) for s in self._sessions) if sid else False

    def new_session(self) -> str:
        """Direkt eine Sitzung anlegen (Tests, die ohne Fenster arbeiten)."""
        return self.redeem(self.new_key())

    def note_page_load(self) -> None:
        self.page_loaded.set()

    def ping(self) -> None:
        self.last_ping = time.monotonic()

    def shutdown_and_close(self) -> None:
        """Beenden vom Haupt-Thread aus (nach dem Schließen des Fensters)."""
        self._closing = True
        for cb in list(self.on_stop):
            try:
                cb()
            except Exception:
                pass
        try:
            self.shutdown()
        except Exception:
            pass
        self.server_close()

    def stop(self) -> None:
        for cb in list(self.on_stop):
            try:
                cb()
            except Exception:
                pass
        self.shutdown()

    @property
    def url(self) -> str:
        return "http://127.0.0.1:%d/" % self.server_address[1]


def make_server(directory: Optional[str] = None, port: int = 0, demo_world: Optional[Dict[str, str]] = None) -> Server:
    return Server(App(directory or data_dir(), demo_world), port)
