"""Befunde, die sich nur beim Hoster ändern lassen, gesammelt, mit fertigem Text für eine E-Mail an den Hoster.

Reine Funktionen ohne Netz und ohne Dateizugriff. Gesammelt wird nur aus den Befunden der Prüfung (Stufe Hinweis, Bitte prüfen, Kritisch);
welcher Befund hierher gehört, steht in RULES (Prüfung, Anfang des Titels, Formulierung der Bitte an den Hoster)."""
from __future__ import annotations

import re
from typing import Any, Callable, Dict, List, Tuple

SEV_ORDER = {"crit": 0, "warn": 1, "info": 2}
SKIP_SEV = ("ok",)

Ask = Callable[[Dict[str, Any]], str]


def _funcs(f: Dict[str, Any]) -> str:
    for it in f.get("items") or []:
        if str(it).startswith("nicht gesperrt: "):
            names = str(it).split(": ", 1)[1].strip()
            return "In der PHP-Einstellung disable_functions bitte ergänzen: %s. Vorher bitte bestätigen oder mir sagen, wie ich meine Seite danach testen kann." % names
    return "In der PHP-Einstellung disable_functions bitte die Funktionen exec, passthru, shell_exec, system, proc_open, popen und pcntl_exec sperren."


def _spf(f: Dict[str, Any]) -> str:
    cur = next((str(i) for i in (f.get("items") or []) if str(i).lower().startswith("v=spf1")), "")
    base = "Den SPF-Eintrag (TXT-Eintrag) meiner Domain anpassen. "
    if "?all" in str(f.get("title", "")):
        return base + "Am Ende bitte ~all (oder -all) statt ?all setzen%s." % ((" (derzeit: %s)" % cur) if cur else "")
    if "Kein SPF" in str(f.get("title", "")):
        return base + "Es gibt keinen Eintrag. Bitte einen SPF-Eintrag anlegen, der Ihre Mailserver und die Server meiner Seite erlaubt und mit ~all endet."
    if "Mehrere" in str(f.get("title", "")):
        return base + "Es gibt mehrere SPF-Einträge; bitte zu einem einzigen zusammenfassen."
    return base + "Bitte den Eintrag auf Fehler prüfen (%s)." % str(f.get("title", ""))[:80]


def _fixed(text: str) -> Ask:
    return lambda f: text


# (Prüfung, Anfang des Befund-Titels, Bitte an den Hoster)
RULES: List[Tuple[str, str, Ask]] = [
    ("php_settings", "allow_url_include", _fixed("In der PHP-Einstellung allow_url_include bitte auf Off stellen.")),
    ("php_settings", "allow_url_fopen", _fixed("In der PHP-Einstellung allow_url_fopen bitte auf Off stellen, falls das für mein Konto möglich ist.")),
    ("php_settings", "enable_dl", _fixed("In der PHP-Einstellung enable_dl bitte auf Off stellen.")),
    ("php_settings", "expose_php", _fixed("In der PHP-Einstellung expose_php bitte auf Off stellen, damit der Server die PHP-Version nicht in den Kopfzeilen nennt.")),
    ("php_settings", "open_basedir", _fixed("Bitte mitteilen, ob open_basedir für mein Konto gesetzt ist, oder es auf mein Konto-Verzeichnis begrenzen.")),
    ("php_settings", "PHP ", lambda f: "Meine Webseite läuft mit einer PHP-Version, die keine Sicherheitsupdates mehr bekommt oder bald nicht mehr bekommt. Bitte die Umstellung auf eine unterstützte Version ermöglichen." if re.search(r"nicht mehr|läuft bald aus", str(f.get("title", ""))) else ""),
    ("php_settings", "", lambda f: _funcs(f) if "gefährlichen Funktionen" in str(f.get("title", "")) else ""),
    ("mail_dns", "SPF", _spf),
    ("mail_dns", "Kein SPF", _spf),
    ("mail_dns", "Mehrere SPF", _spf),
    ("mail_dns", "DMARC", _fixed("Für meine Domain bitte einen DMARC-Eintrag (TXT-Eintrag bei _dmarc) anlegen, zunächst im Beobachtungsmodus: v=DMARC1; p=none.")),
    ("mail_dns", "Kein DMARC", _fixed("Für meine Domain bitte einen DMARC-Eintrag (TXT-Eintrag bei _dmarc) anlegen, zunächst im Beobachtungsmodus: v=DMARC1; p=none.")),
    ("mail_dns", "Kein DKIM", _fixed("Bitte DKIM für den Mailversand meiner Domain einrichten und den Namen (Selektor) des Eintrags mitteilen.")),
    ("access_logs", "Kein Zugriffsprotokoll", _fixed("Bitte die Zugriffsprotokolle (Access-Logs) der letzten Monate bereitstellen oder den Zugriff darauf freischalten.")),
    ("tls_protocols", "", _fixed("Bitte die veralteten Verschlüsselungsprotokolle TLS 1.0 und TLS 1.1 für meine Domain abschalten (mindestens TLS 1.2).")),
    ("mail_send", "sendmail_path", _fixed("Bitte erklären, warum die PHP-Einstellung sendmail_path auf ein ungewöhnliches Programm zeigt, und sie auf den Standard zurücksetzen.")),
    ("mail_send", "Mail-Warteschlange", _fixed("Die Mail-Warteschlange meines Kontos ist sehr voll. Bitte nachsehen, woher die Mails stammen.")),
]


def _norm(t: str) -> str:
    return re.sub(r"\s+", " ", str(t or "")).strip()


def collect(results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Einträge {check, title, sev, ask} in der Reihenfolge Kritisch, Bitte prüfen, Hinweis. Gleiche Bitten werden nur einmal aufgeführt."""
    out: List[Dict[str, Any]] = []
    seen = set()
    for r in results or []:
        rid = str(r.get("id", ""))
        for f in r.get("findings") or []:
            sev = f.get("sev")
            if sev in SKIP_SEV or sev not in SEV_ORDER:
                continue
            title = str(f.get("title", ""))
            for cid, prefix, ask in RULES:
                if cid != rid or not title.startswith(prefix):
                    continue
                text = ask(f)
                if not text or text in seen:
                    continue
                seen.add(text)
                out.append({"check": rid, "title": title, "sev": sev, "ask": text})
                break
    out.sort(key=lambda x: SEV_ORDER[x["sev"]])
    return out


def mail(items: List[Dict[str, Any]], site: str = "", server: str = "") -> Dict[str, str]:
    """Fertiger Text für die E-Mail an den Hoster (Betreff und Inhalt). Leer, wenn nichts zu bitten ist."""
    if not items:
        return {"subject": "", "body": ""}
    what = _norm(site) or "meine Webseite"
    subject = "Bitte um Änderung von Server-Einstellungen (%s)" % what
    lines = ["Guten Tag,", "",
             "bei einer Sicherheitsprüfung meiner Webseite %s%s mit dem Programm CLAUDIA wurden Punkte gefunden, die ich selbst nicht ändern kann. "
             "Ich bitte Sie, sie umzusetzen oder mir kurz mitzuteilen, falls etwas bei Ihnen nicht möglich ist:" % (what, (" (Server: %s)" % _norm(server)) if server else ""), ""]
    for i, it in enumerate(items, 1):
        lines.append("%d. %s" % (i, it["ask"]))
    lines += ["", "Falls eine Änderung Auswirkungen auf meine Seite haben kann, nennen Sie mir bitte vorher, wie ich sie testen kann. Vielen Dank für Ihre Hilfe.", "", "Mit freundlichen Grüßen"]
    return {"subject": subject, "body": "\n".join(lines)}


def build(results: List[Dict[str, Any]], site: str = "", server: str = "") -> Dict[str, Any]:
    items = collect(results)
    return {"items": items, "mail": mail(items, site, server)}
