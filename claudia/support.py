"""Support-Paket: eine kurze Textdatei zum Anhängen an ein GitHub-Issue, wenn etwas nicht klappt.

Enthält: Programm- und Systemversion, erkanntes System und PHP, Ergebnis jeder Prüfung (Status, Dauer, Fehlertext), die letzten Zeilen des
Update-Protokolls und die letzten Aktionen (Name und Erfolg). Enthält NICHT: Passwörter, Zugangsdaten, Serveradresse, Benutzername,
Seitenordner, Dateiinhalte oder die Texte der Funde. Zugangsdaten und Adressen werden zusätzlich aus allen Texten herausgenommen."""
import os
import platform
import sys
import time
from typing import Any, Dict, List

from .util import clean_line, mask_secrets

MAX_LINES = 60
MAX_TEXT = 300


def scrub(text: str, hide: List[str]) -> str:
    """Nimmt Geheimnisse und bekannte Adressen/Namen aus einem Text."""
    t = mask_secrets(clean_line(str(text or ""))[:MAX_TEXT * 3])
    for h in sorted({x for x in hide if x and len(x) >= 3}, key=len, reverse=True):
        t = t.replace(h, "<verborgen>")
    return t[:MAX_TEXT]


def programm_protokoll() -> str:
    """Programmprotokoll der Programmdatei (schreibt installer/exe_main.py): Windows %APPDATA%\\CLAUDIA\\protokoll\\claudia.log,
    Mac ~/Library/Logs/CLAUDIA/claudia.log."""
    import os
    base = os.environ.get("CLAUDIA_LOG_DIR")
    if not base:
        if os.name == "nt":
            base = os.path.join(os.environ.get("APPDATA") or os.path.expanduser("~"), "CLAUDIA", "protokoll")
        elif sys.platform == "darwin":
            base = os.path.join(os.path.expanduser("~"), "Library", "Logs", "CLAUDIA")
        else:
            base = os.path.join(os.path.expanduser("~"), ".claudia", "protokoll")
    return os.path.join(base, "claudia.log")


def build(version: str, info: Dict[str, Any], results: List[Dict[str, Any]], actions: List[Dict[str, Any]], update_log: str, wissen_stand: str,
          hide: List[str], now: float = 0.0, prog_log: str = "") -> str:
    """Setzt das Paket zusammen. hide: Texte, die nie erscheinen dürfen (Passwort, Host, Benutzer, Ordner)."""
    cms = str((info or {}).get("cms") or "?")
    out = ["CLAUDIA Support-Paket", "Erstellt: %s" % time.strftime("%Y-%m-%d %H:%M", time.localtime(now or time.time())), "",
           "Programm: CLAUDIA %s" % version, "Wissensdaten: %s" % (wissen_stand or "?"),
           "Computer: %s, Python %s" % (platform.platform(), sys.version.split()[0]),
           "Seite: %s %s, PHP %s" % (cms, scrub(str((info or {}).get(cms) or "?"), hide), scrub(str((info or {}).get("php") or "?"), hide)), ""]
    out.append("Prüfergebnisse (%d):" % len(results))
    for r in results[:200]:
        line = "- %s: %s, %.1f s" % (scrub(r.get("id", "?"), []), r.get("status", "?"), float(r.get("seconds") or 0))
        if r.get("status") in ("error", "skipped") and r.get("message"):
            line += " (%s)" % scrub(r["message"], hide)
        else:
            c = {"crit": 0, "warn": 0}
            for f in r.get("findings") or []:
                if isinstance(f, dict) and f.get("sev") in c:
                    c[f["sev"]] += 1
            if c["crit"] or c["warn"]:
                line += " (%d kritisch, %d Warnungen)" % (c["crit"], c["warn"])
        out.append(line)
    if not results:
        out.append("- noch keine Prüfung in dieser Sitzung")
    out += ["", "Letzte Aktionen:"]
    for a in actions[-10:]:
        out.append("- %s: %s" % (scrub(a.get("id", "?"), []), "erfolgreich" if a.get("ok") else "nicht erfolgreich"))
    if not actions:
        out.append("- keine")
    lines = [scrub(x, hide) for x in (update_log or "").splitlines()[-MAX_LINES:] if x.strip()]
    out += ["", "Update-Protokoll (letzte Zeilen):"] + (["  " + x for x in lines] or ["  (leer)"])
    plines = [scrub(x, hide) for x in (prog_log or "").splitlines()[-MAX_LINES:] if x.strip()]
    out += ["", "Programmprotokoll (letzte Zeilen):"] + (["  " + x for x in plines] or ["  (leer)"])
    out += ["", "Hinweis: Dieses Paket enthält keine Passwörter, keine Serveradresse und keine Dateiinhalte. Bitte trotzdem kurz durchsehen, bevor du es weitergibst."]
    return "\n".join(out) + "\n"
