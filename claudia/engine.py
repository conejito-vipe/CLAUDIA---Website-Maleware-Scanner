"""Ausführung der Tests: Kontext, Fortschritt, Abbruch, Fehlerbehandlung."""
from __future__ import annotations

import threading
import time
import traceback
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from . import cms as cmsmod, contao, drupal, joomla, phppick, typo3, wordpress
from .model import Cancelled, CheckResult, CheckSkipped
from .registry import REGISTRY, load_all
from .runner import Runner, RunnerError, ShResult
from .util import mask_ip, mask_secrets

RAW_CAP = 400_000   # maximale Rohdaten pro Anhang (Zeichen), damit Berichte handlich bleiben


@dataclass
class Settings:
    site_dir: str = "html"
    url: str = ""
    log_dir: str = ""
    local_log: str = ""
    allow_hosts: List[str] = field(default_factory=list)
    mask_ips: bool = True
    opts: Dict[str, Dict[str, Any]] = field(default_factory=dict)   # {check_id: {option_key: value}}
    php_web: Dict[str, str] = field(default_factory=dict)            # erkannte PHP-Version der Webseite (aus dem Verbindungstest)
    db: Dict[str, str] = field(default_factory=dict)                 # optionale eigene Datenbank-Zugangsdaten (Bereich 'Datenbank')
    cms: str = "joomla"                                              # joomla | wordpress | drupal | typo3 | contao (erkannt beim Verbinden)
    php_cands: List[Dict[str, Any]] = field(default_factory=list)    # gefundene PHP-Programme (aus dem Verbindungstest)
    baseline_dir: str = ""                                           # Ordner für Vergleichsbasen (B9); leer = Vergleich nicht verfügbar
    baseline_key: str = ""                                           # Kennung der Verbindung (Server, Benutzer, Seitenordner)
    baseline_label: str = ""                                         # Beschriftung (Server und Seitenordner, ohne Zugangsdaten)


class Ctx:
    """Alles, was ein Test braucht. Wird pro Lauf einmal erzeugt."""

    def __init__(self, runner: Optional[Runner], settings: Settings, advisories: Dict[str, Any],
                 emit: Callable[[Dict[str, Any]], None], cancel: threading.Event):
        self.runner = runner
        self.s = settings
        self.adv = advisories
        self._emit = emit
        self._cancel = cancel
        self.shared: Dict[str, Any] = {"php_web": dict(settings.php_web or {})}
        self.current: Optional[CheckResult] = None
        self.current_id: str = ""
        self.cms: str = settings.cms if settings.cms in cmsmod.PROFILES else "joomla"
        self.prof = cmsmod.profile(self.cms)
        self.cms_name: str = self.prof["name"]

    def php_pick(self) -> str:
        """Shell-Code, der P auf ein funktionierendes PHP-Programm setzt (siehe phppick)."""
        return phppick.snippet(str((self.shared.get("php_web") or {}).get("version") or ""), self.s.php_cands)

    # ---------- Steuerung
    def check_cancel(self) -> None:
        if self._cancel.is_set():
            raise Cancelled()

    def progress(self, msg: str) -> None:
        self.check_cancel()
        self._emit({"type": "progress", "id": self.current_id, "msg": msg})

    # ---------- Optionen
    def opt(self, key: str, default: Any = None) -> Any:
        v = self.s.opts.get(self.current_id, {}).get(key)
        return default if v in (None, "") else v

    def opt_int(self, key: str, default: int) -> int:
        try:
            return int(self.opt(key, default))
        except (TypeError, ValueError):
            return default

    # ---------- Befehle auf dem Server
    def sh(self, script: str, timeout: float = 120.0, raw: str = "", raw_cap: int = RAW_CAP,
           stdin: Optional[str] = None, ips: bool = False) -> ShResult:
        """Skript im Joomla-Verzeichnis ausführen. 'raw' = Name, unter dem die Ausgabe im Bericht landet."""
        self.check_cancel()
        if self.runner is None:
            raise CheckSkipped("Kein Serverzugriff.")
        try:
            res = self.runner.sh(self.s.site_dir, script, timeout, stdin)
        except RunnerError as e:
            raise CheckSkipped(str(e))
        if res.rc == 97 and "CLAUDIA_NO_SITE_DIR" in res.err:
            raise CheckSkipped("Das %s-Verzeichnis '%s' existiert nicht." % (self.cms_name, self.s.site_dir))
        if raw:
            self.add_raw(raw, res.out + (("\n--- stderr ---\n" + res.err) if res.err.strip() else ""), raw_cap, ips)
        self.check_cancel()
        return res

    def mask(self, text: str) -> str:
        """IP-Adressen kürzen (nur anwenden, wenn der Text IP-Adressen enthalten kann)."""
        return mask_ip(text) if self.s.mask_ips else text

    def add_raw(self, name: str, text: str, cap: int = RAW_CAP, ips: bool = False) -> None:
        if self.current is None:
            return
        text = mask_secrets(text)
        if ips:
            text = self.mask(text)
        if len(text) > cap:
            text = text[:cap] + "\n[... gekürzt, %d Zeichen weggelassen ...]" % (len(text) - cap)
        self.current.raw[name] = text

    def allow(self) -> List[str]:
        """Bekannte/erlaubte Hostnamen: Voreinstellung plus eigene Ergänzungen aus der Oberfläche."""
        return list(self.adv.get("allow_hosts", [])) + list(self.s.allow_hosts or [])

    def own_host(self) -> str:
        from urllib.parse import urlparse
        u = (self.s.url or "").strip()
        if u and "//" not in u:
            u = "https://" + u
        return (urlparse(u).hostname or "").lower()

    # ---------- gemeinsame Daten (einmal laden, mehrfach nutzen)
    def config(self) -> Dict[str, Any]:
        if "config" not in self.shared and self.cms == "drupal":
            res = self.sh("head -c 300000 sites/default/settings.php 2>/dev/null", timeout=30)
            if not res.out.strip():
                self.shared["config"] = {"vars": {}, "settings": {}, "prefix": "", "unexpected": [], "trusted_hosts": False, "size": 0, "lines": 0, "missing": True, "text": ""}
            else:
                cfg = drupal.parse_settings(res.out)
                cfg["text"] = res.out
                cfg["missing"] = False
                self.shared["config"] = cfg
        if "config" not in self.shared and self.cms == "typo3":
            res = self.sh(typo3.read_config_sh(), timeout=30)
            parts = typo3.split_config_output(res.out)
            if not parts["text"].strip():
                self.shared["config"] = {"vars": {}, "typo3": {}, "prefix": "", "unexpected": [], "parsed": False, "has_additional": False, "has_key": False, "key_len": 0, "size": 0, "lines": 0,
                                         "missing": True, "text": "", "path": ""}
            else:
                cfg = typo3.parse_settings(parts["text"], parts["add_text"])
                cfg["text"] = parts["text"]
                cfg["path"] = parts["path"]
                cfg["missing"] = False
                self.shared["config"] = cfg
        if "config" not in self.shared and self.cms == "contao":
            res = self.sh(contao.read_config_sh(), timeout=30)
            parts = contao.split_config_output(res.out)
            if not (parts["env"] or parts["yaml"] or parts["local"]):
                self.shared["config"] = {"vars": {}, "contao": {}, "prefix": "", "unexpected": [], "parsed": False, "size": 0, "lines": 0, "missing": True, "text": "", "path": "", "files": []}
            else:
                cfg = contao.parse_settings(parts["env"], parts["yaml"], parts["local"])
                cfg["text"] = res.out
                cfg["path"] = (parts["env"] or parts["yaml"] or parts["local"])[0][0]
                cfg["missing"] = False
                self.shared["config"] = cfg
        if "config" not in self.shared and self.cms == "wordpress":
            # wp-config.php liegt im Seitenordner, WordPress erlaubt sie auch eine Ebene darüber
            res = self.sh("if test -f wp-config.php; then head -c 300000 wp-config.php; elif test -f ../wp-config.php; then head -c 300000 ../wp-config.php; fi", timeout=30)
            if not res.out.strip():
                self.shared["config"] = {"vars": {}, "defines": {}, "prefix": "wp_", "unexpected": [], "size": 0, "lines": 0, "missing": True, "text": ""}
            else:
                cfg = wordpress.parse_wp_config(res.out)
                cfg["text"] = res.out
                cfg["missing"] = False
                self.shared["config"] = cfg
        if "config" not in self.shared:
            res = self.sh("test -f configuration.php && head -c 300000 configuration.php", timeout=30)
            if not res.out.strip():
                self.shared["config"] = {"vars": {}, "unexpected": [], "size": 0, "lines": 0, "missing": True, "text": ""}
            else:
                cfg = joomla.parse_config(res.out)
                cfg["text"] = res.out
                cfg["missing"] = False
                self.shared["config"] = cfg
        return self.shared["config"]

    def db(self):
        """Datenbankzugriff über das mysql-Programm auf dem Server (oder None)."""
        if "db" not in self.shared:
            from .db import DbAccess
            self.shared["db"] = DbAccess.from_ctx(self)
        return self.shared["db"]


# Gemeinsame Tests formulieren ihre Befunde einmal für Joomla. Für WordPress werden die Bezeichnungen hier angepasst.
_WP_SUBST = [
    ("(Tabelle verrät die Stelle: modules = Module, template_styles = Template-Einstellungen, content = Artikel)",
     "(Tabelle verrät die Stelle: posts = Beiträge und Seiten, options = Einstellungen und Widgets, comments = Kommentare, postmeta = Zusatzfelder)"),
    ("im Joomla-Backend", "im WordPress-Dashboard"),
    ("configuration.php", "wp-config.php"), ("die Joomla-Standarddatei htaccess.txt", "die WordPress-Standard-.htaccess"),
    ("Joomla-Standarddatei", "WordPress-Standarddatei"), ("im Joomla-Backend", "im WordPress-Dashboard"),
    ("Joomla-Hauptverzeichnis", "WordPress-Hauptverzeichnis"), ("Joomla-Core neu installieren", "den WordPress-Kern neu installieren (Dashboard -> Updates -> Erneut installieren)"),
    ("Joomla-Datenbank", "WordPress-Datenbank"), ("Joomla-Präfix", "WordPress-Präfix"), ("Joomla-Tabelle", "WordPress-Tabelle"),
    ("Joomla", "WordPress"), ("Erweiterungen", "Plugins"), ("Erweiterung", "Plugin"),
    ("images, media, files, tmp", "wp-content/uploads, upgrade, cache"), ("images, media oder files", "wp-content/uploads"),
    ("images/files/tmp", "wp-content/uploads, upgrade, cache"),
]


def wp_text(s: str) -> str:
    for a, b in _WP_SUBST:
        s = s.replace(a, b)
    return s


def localize_wp(res: CheckResult) -> None:
    """Bezeichnungen der gemeinsamen Tests auf WordPress umstellen (Titel stehen schon richtig)."""
    for f in res.findings:
        f.title, f.detail, f.hint = wp_text(f.title), wp_text(f.detail), wp_text(f.hint)
        f.items = [wp_text(i) for i in f.items]
    res.message = wp_text(res.message)


class Engine:
    def __init__(self, runner: Optional[Runner], settings: Settings, advisories: Dict[str, Any]):
        self.runner = runner
        self.settings = settings
        self.advisories = advisories
        load_all()

    def run(self, ids: List[str], emit: Callable[[Dict[str, Any]], None], cancel: threading.Event) -> List[CheckResult]:
        ctx = Ctx(self.runner, self.settings, self.advisories, emit, cancel)
        results: List[CheckResult] = []
        if any(i in ids for i in ("threat_intel", "access_logs", "local_logs")) and "intel" not in ctx.shared:
            emit({"type": "progress", "id": ids[0], "msg": "Lade die aktuelle Bedrohungslage (NVD/CVE, Joomla-VEL)"})
            try:
                from .checks.threat import load_intel
                load_intel(ctx)
            except Exception:                                  # noqa: BLE001  (fehlende Online-Daten dürfen den Lauf nie verhindern)
                ctx.shared["intel"] = {"cves": [], "vel": [], "errors": ["Abruf fehlgeschlagen"]}
        for cid in ids:
            if cancel.is_set():
                break
            cdef = REGISTRY.get(cid)
            if cdef is None or cdef.cms not in (ctx.cms, "both"):
                continue
            res = CheckResult(id=cdef.id, title=cdef.view(ctx.cms)["title"], group=cdef.group)
            ctx.current, ctx.current_id = res, cid
            emit({"type": "start", "id": cid})
            t0 = time.monotonic()
            try:
                if cdef.needs in ("ssh", "db") and self.runner is None:
                    raise CheckSkipped("Dafür ist eine SSH-Verbindung nötig.")
                cdef.fn(ctx, res)
            except Cancelled:
                res.status, res.message = "skipped", "Abgebrochen."
                res.seconds = time.monotonic() - t0
                results.append(res)
                emit({"type": "done", "result": res.to_dict()})
                break
            except CheckSkipped as e:
                res.status, res.message = "skipped", str(e)
            except Exception as e:  # ein fehlerhafter Test darf den Lauf nicht beenden
                res.status = "error"
                res.message = "%s: %s" % (type(e).__name__, e)
                res.raw["fehler_details"] = traceback.format_exc()[-4000:]
            res.seconds = time.monotonic() - t0
            if ctx.cms == "wordpress":
                localize_wp(res)
            res.finalize()
            results.append(res)
            emit({"type": "done", "result": res.to_dict()})
        ctx.current = None
        return results
