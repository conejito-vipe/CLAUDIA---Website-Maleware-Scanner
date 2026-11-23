"""Bewertung der Drupal-Prüfungen (2.8.0): reine Funktionen ohne Server-, Datenbank- oder Netzzugriff, mit Beispieldaten prüfbar.

Jede Funktion bekommt einfache Wörterbücher/Listen und liefert Funde als (Stufe, Titel, Text, Einträge, Hinweis). Unbrauchbare Eingaben ergeben genau einen Info-Fund 'nicht prüfbar'.
Geheimnisse (Passwörter, hash_salt, Schlüssel) werden nie gelesen oder ausgegeben; es zählen Namen, Rechte, Zeiten, Versionen und Adressen."""
from __future__ import annotations

import re
import time
from typing import Any, Dict, List, Optional, Tuple

from .. import drupal
from ..util import parse_xml
from .auswertung_joomla import _clean, _f, _np, _to_int
from .auswertung_woo import BAD_MARKUP, php_strings, php_value

Finding = Tuple[str, str, str, List[str], str]

DEV_MODULES = {"devel", "devel_generate", "webprofiler", "kint", "stage_file_proxy", "devel_php", "web_profiler", "examples", "field_ui_devel", "reroute_email"}
RISKY_PERMS = ("administer permissions", "administer users", "administer modules", "administer software updates", "bypass node access", "import configuration", "administer site configuration",
               "use text format full_html", "access devel information", "administer themes", "administer account settings", "synchronize configuration", "administer filters",
               "administer text formats and filters", "view the administration theme", "access site reports")
OBFUSCATED = re.compile(r"atob\s*\(|fromCharCode|eval\s*\(|document\.write\s*\(\s*unescape|String\.fromCharCode|\\x[0-9a-f]{2}\\x[0-9a-f]{2}", re.I)


# ------------------------------------------------------------------ Verlaufsdatei von updates.drupal.org
def parse_release_history(text: Any) -> Dict[str, Any]:
    """Liest die Release-Daten eines Projekts (XML von updates.drupal.org). Rückgabe {'ok': bool, 'status': str, 'supported': [Zweige], 'releases': [...]}.

    Unbrauchbare oder verdächtige Eingaben (DOCTYPE/ENTITY, kein XML) ergeben ok=False. Die Elementnamen folgen der Beschreibung der Update-Schnittstelle von Drupal
    (version, status, release_link, terms/term 'Release type' mit 'Security update', 'Insecure', 'Unsupported'); sie sind noch nicht gegen die echte Antwort des Servers geprüft."""
    bad = {"ok": False, "status": "", "supported": [], "releases": []}
    root = parse_xml(text)
    if root is None or root.tag != "project":
        return bad
    rels: List[Dict[str, Any]] = []
    for r in root.iter("release"):
        ver = (r.findtext("version") or "").strip()
        if not ver:
            continue
        types = set()
        for t in r.iter("term"):
            if (t.findtext("name") or "").strip() == "Release type":
                types.add((t.findtext("value") or "").strip())
        rels.append({"version": ver, "status": (r.findtext("status") or "published").strip(), "types": types, "mdhash": (r.findtext("mdhash") or "").strip().lower(),
                     "download": (r.findtext("download_link") or "").strip(), "date": _to_int(r.findtext("date"))})
    sup = [x.strip() for x in (root.findtext("supported_branches") or "").split(",") if x.strip()]
    return {"ok": True, "status": (root.findtext("project_status") or "").strip(), "supported": sup, "releases": rels}


def _branch(version: str) -> str:
    m = re.match(r"(\d+)\.(\d+)", version or "")
    return "%s.%s." % (m.group(1), m.group(2)) if m else ""


def release_state(installed: str, hist: Any) -> Dict[str, Any]:
    """Stand einer installierten Version gegenüber den veröffentlichten Releases.

    state: 'unknown' (keine/unbrauchbare Daten oder Entwicklerversion), 'current', 'update' (neuere Version vorhanden), 'security' (neuere Sicherheitsversion),
    'insecure' (die installierte Version ist als unsicher markiert). Zusätzlich 'unsupported' (Projekt/Zweig nicht mehr betreut) und 'latest'."""
    out: Dict[str, Any] = {"state": "unknown", "latest": "", "security": [], "unsupported": False}
    if not isinstance(hist, dict) or not hist.get("ok") or not installed or re.search(r"dev|\+", installed):
        return out
    cur = drupal.version_key(installed)
    pub = [r for r in hist["releases"] if r["status"] != "unpublished"]
    same_major = [r for r in pub if drupal.version_key(r["version"])[0] == cur[0] and not re.search(r"-(dev|alpha|beta|rc)", r["version"])]
    newer = [r for r in same_major if drupal.version_key(r["version"]) > cur]
    out["latest"] = max((r["version"] for r in same_major), key=drupal.version_key, default="")
    out["security"] = sorted({r["version"] for r in newer if "Security update" in r["types"]}, key=drupal.version_key)
    mine = next((r for r in hist["releases"] if r["version"] == installed), None)
    out["unsupported"] = bool((hist.get("status") or "").lower() in ("unsupported", "revoked")
                              or (mine and "Unsupported" in mine["types"])
                              or (hist.get("supported") and _branch(installed) and _branch(installed) not in hist["supported"] and drupal.major(installed) >= 8))
    if mine and "Insecure" in mine["types"]:
        out["state"] = "insecure"
    elif out["security"]:
        out["state"] = "security"
    elif newer:
        out["state"] = "update"
    else:
        out["state"] = "current"
    return out


# ------------------------------------------------------------------ Kern
def judge_core(version: str, hist: Any) -> List[Finding]:
    if not version:
        return _np("Drupal-Version", "Die Version konnte nicht aus core/lib/Drupal.php gelesen werden.")
    ver = _clean(version, 30)
    mj = drupal.major(version)
    out: List[Finding] = []
    if mj and mj <= 7:
        return [_f("crit", "Drupal %s wird nicht mehr mit Sicherheitsupdates versorgt" % mj,
                   "Für Drupal 7 und älter gibt es keine kostenlosen Sicherheitsupdates mehr. Neue Lücken bleiben offen und werden gezielt ausgenutzt.", [],
                   "Auf eine unterstützte Version (Drupal 10 oder 11) umziehen. Bis dahin Zugriff auf Verwaltung und Formulare einschränken und regelmäßig sichern.")]
    if mj in (8, 9):
        out.append(_f("crit", "Drupal %d wird nicht mehr mit Sicherheitsupdates versorgt" % mj,
                      "Drupal 8 und 9 haben das Ende der Unterstützung erreicht. Neue Sicherheitslücken werden nicht mehr behoben.", [ver],
                      "Auf Drupal 10 oder 11 aktualisieren (vorher vollständige Sicherung)."))
        return out
    st = release_state(version, hist)
    if st["state"] == "unknown":
        out.append(_f("info", "Drupal %s: Aktualität nicht prüfbar" % ver, "Die Liste der Veröffentlichungen von drupal.org war nicht erreichbar oder nicht lesbar, oder es ist eine Entwicklerversion."))
        return out
    if st["state"] == "insecure":
        out.append(_f("crit", "Die installierte Drupal-Version %s ist als unsicher markiert" % ver, "Drupal.org führt diese Version als unsicher. Bekannte Lücken werden ausgenutzt.", [ver],
                      "Sofort auf %s oder neuer aktualisieren (vorher Sicherung)." % (st["latest"] or "die neueste Version")))
    elif st["state"] == "security":
        out.append(_f("crit", "Für Drupal %s gibt es Sicherheitsupdates" % ver, "Neuere Versionen schließen Sicherheitslücken.", ["Sicherheitsversionen: " + ", ".join(st["security"][-5:])],
                      "Auf %s aktualisieren (vorher Sicherung)." % (st["latest"] or st["security"][-1])))
    elif st["state"] == "update":
        out.append(_f("warn", "Drupal %s ist nicht die neueste Version" % ver, "Neueste Version: %s." % st["latest"], [], "Beim nächsten Wartungsfenster aktualisieren (vorher Sicherung)."))
    else:
        out.append(_f("ok", "Drupal %s ist auf dem neuesten Stand" % ver, "Neueste bekannte Version dieser Hauptversion: %s." % (st["latest"] or ver)))
    if st["unsupported"]:
        out.append(_f("crit", "Der Zweig von Drupal %s erhält keine Sicherheitsupdates mehr" % ver, "Der Zweig ist nicht mehr in der Liste der unterstützten Zweige von drupal.org.", [],
                      "Auf einen unterstützten Zweig wechseln."))
    return out


def judge_core_files(ref_count: int, changed: List[str], missing: List[str], extra: List[str], source: str = "") -> List[Finding]:
    """Ergebnis des Dateivergleichs mit dem Original-Paket (nur Ordner core/). Abweichende Dateien sind nicht zwingend ein Angriff (Patches, Composer), eingeschleuste PHP-Dateien schon eher."""
    out: List[Finding] = []
    total = max(1, ref_count)
    if (len(changed) + len(missing)) / total > 0.35:
        return [_f("warn", "Sehr viele Kerndateien weichen ab (%d von %d)" % (len(changed) + len(missing), total),
                   "Das spricht für eine angepasste Version, einen Fork oder ein unvollständiges Paket als Vergleich, nicht für einen Einzelangriff. " + source, [], "Vergleichsweise prüfen, welche Version wirklich installiert ist.")]
    php_extra = [p for p in extra if re.search(r"\.(php\d?|phtml|pht|phar|inc)$", p, re.I)]
    other_extra = [p for p in extra if p not in php_extra]
    if php_extra:
        out.append(_f("crit", "%d unbekannte PHP-Datei(en) im Ordner core" % len(php_extra), "Im Drupal-Kern liegen PHP-Dateien, die nicht zum Original gehören. Das ist ein typischer Ablageort für Hintertüren. " + source,
                      php_extra, "Datei ansehen; wenn sie nicht von Ihnen oder einem bekannten Patch stammt, sichern und entfernen und die Zugangsdaten erneuern."))
    if changed:
        out.append(_f("warn", "%d Kerndatei(en) weichen vom Original ab" % len(changed), "Das kann ein bewusster Patch (Composer-Patches) sein oder eine Manipulation. " + source, changed,
                      "Ist kein Patch bekannt: Datei gegen das Original vergleichen und Drupal-Kern neu einspielen (composer install bzw. Paket von drupal.org)."))
    if missing:
        out.append(_f("warn", "%d Kerndatei(en) fehlen" % len(missing), "Fehlende Kerndateien deuten auf ein unvollständiges Update oder auf entfernte Dateien hin.", missing, "Kern neu einspielen."))
    if other_extra:
        out.append(_f("info", "%d zusätzliche Datei(en) im Ordner core (ohne Programmcode)" % len(other_extra), "Sie können nichts ausführen und sind meist harmlos.", other_extra))
    if not out:
        out.append(_f("ok", "Alle Kerndateien stimmen mit dem Original überein", "%d Dateien verglichen. %s" % (ref_count, source)))
    return out


# ------------------------------------------------------------------ Module
def judge_modules(inventory: Any, states: Any, abandoned_online: bool = True) -> List[Finding]:
    """inventory: [{'project','name','version','type','custom'(bool)}]; states: {projekt: release_state(...)} (fehlt ein Projekt = nicht abgefragt)."""
    if not isinstance(inventory, list):
        return _np("Drupal-Module", "Die Liste der Module fehlt oder ist unlesbar.")
    inv = [m for m in inventory if isinstance(m, dict) and m.get("project")]
    if not inv:
        return [_f("info", "Keine Module oder Themes gefunden", "Unter modules, themes und profiles wurden keine .info.yml-Dateien gelesen.")]
    states = states if isinstance(states, dict) else {}
    out: List[Finding] = []
    sec, insecure, update, unsup, unknown, custom = [], [], [], [], [], []

    def lab(m, extra=""):
        return "%s %s%s" % (_clean(m.get("name") or m["project"], 60), _clean(m.get("version") or "?", 30), extra)

    for m in inv:
        if m.get("custom"):
            custom.append(lab(m))
            continue
        st = states.get(m["project"])
        if not st or st["state"] == "unknown":
            unknown.append(lab(m))
            continue
        if st["state"] == "insecure":
            insecure.append(lab(m, " (als unsicher markiert)"))
        elif st["state"] == "security":
            sec.append(lab(m, " -> %s" % st["security"][-1]))
        elif st["state"] == "update":
            update.append(lab(m, " -> %s" % st["latest"]))
        if st["unsupported"]:
            unsup.append(lab(m))
    if insecure:
        out.append(_f("crit", "%d Modul(e)/Theme(s) in einer als unsicher markierten Version" % len(insecure), "Drupal.org führt diese Versionen als unsicher.", insecure, "Sofort aktualisieren oder entfernen."))
    if sec:
        out.append(_f("crit", "Für %d Modul(e)/Theme(s) gibt es Sicherheitsupdates" % len(sec), "Neuere Versionen schließen Sicherheitslücken.", sec, "Aktualisieren (vorher Sicherung), mit composer update oder über die Update-Funktion."))
    if unsup:
        out.append(_f("warn", "%d Modul(e)/Theme(s) werden nicht mehr betreut" % len(unsup), "Für sie gibt es keine Sicherheitsupdates mehr.", unsup, "Ersatz suchen oder entfernen."))
    if update:
        out.append(_f("warn" if len(update) > 5 else "info", "%d Modul(e)/Theme(s) haben neuere Versionen" % len(update), "", update, "Beim nächsten Wartungsfenster aktualisieren."))
    if unknown:
        out.append(_f("info", "%d Modul(e)/Theme(s): Aktualität nicht prüfbar" % len(unknown), "drupal.org war für diese Projekte nicht erreichbar oder lieferte nichts (Entwicklerversionen, Kopien, nicht gelistete Projekte).", unknown))
    if custom:
        out.append(_f("info", "%d eigene Module/Themes (Ordner custom)" % len(custom), "Eigene Programme werden nicht gegen drupal.org verglichen; sie wurden nur von den Dateisuchen geprüft.", custom))
    if not (insecure or sec or unsup or update):
        out.append(_f("ok", "Keine veralteten oder unsicheren Module gefunden", "%d Projekte geprüft." % len([m for m in inv if not m.get("custom")])))
    dev = sorted({m["project"] for m in inv if m["project"] in DEV_MODULES})
    if dev:
        out.append(_f("warn", "%d Entwicklungs-Modul(e) liegen auf dem Server" % len(dev), "Module wie devel oder webprofiler zeigen Interna und gehören nicht auf eine Live-Seite.", dev,
                      "Entfernen (composer remove) oder zumindest abschalten."))
    return out


# ------------------------------------------------------------------ Konten
def judge_users(rows: Any, now: Optional[float] = None) -> List[Finding]:
    """rows: [{'uid','name','status'(0/1),'created_ts','access_ts','admin'(bool)}]"""
    if not isinstance(rows, list):
        return _np("Drupal-Konten", "Die Benutzerliste fehlt oder ist unlesbar.")
    now = now or time.time()
    us = [r for r in rows if isinstance(r, dict)]
    admins = [r for r in us if r.get("admin") and str(r.get("status")) == "1"]
    out: List[Finding] = []
    if not admins:
        out.append(_f("info", "Keine aktiven Administrator-Konten gefunden", "Entweder gibt es keine Rolle 'administrator' oder die Abfrage lieferte nichts."))
    else:
        out.append(_f("info", "%d aktive(s) Administrator-Konto/Konten" % len(admins), "Administratoren dürfen Module, Rechte und Inhalte ändern.", ["%s (uid %s)" % (_clean(str(r.get("name") or "?"), 60), r.get("uid")) for r in admins],
                      "Nicht mehr gebrauchte Konten sperren."))
    fresh = [r for r in admins if isinstance(r.get("created_ts"), (int, float)) and now - r["created_ts"] < 14 * 86400]
    if fresh:
        out.append(_f("warn", "%d Administrator-Konto/Konten wurden in den letzten 14 Tagen angelegt" % len(fresh), "Nach einem Einbruch legen Angreifer gern ein neues Konto mit Administratorrechten an.",
                      [_clean(str(r.get("name") or "?"), 60) for r in fresh], "Prüfen, ob Sie oder Ihr Team das Konto angelegt haben. Wenn nicht: sperren und alle Passwörter ändern."))
    never = [r for r in admins if not r.get("access_ts") and r.get("uid") not in (1, "1")]
    if never:
        out.append(_f("info", "%d Administrator-Konto/Konten haben sich nie angemeldet" % len(never), "Ein nie benutztes Konto mit Administratorrechten ist unnötiges Risiko.", [_clean(str(r.get("name") or "?"), 60) for r in never], "Sperren oder Rolle entziehen."))
    u1 = next((r for r in us if str(r.get("uid")) == "1"), None)
    if u1 and str(u1.get("status")) == "1" and not admins:
        out.append(_f("info", "Das Konto mit der Nummer 1 ist aktiv", "Es hat in Drupal immer alle Rechte, auch ohne Rolle.", [_clean(str(u1.get("name") or "?"), 60)]))
    return out


# ------------------------------------------------------------------ Einstellungen in der Datenbank (Tabelle config)
def judge_config(cfg: Any) -> List[Finding]:
    """cfg: {'logging': Text, 'user_settings': Text, 'core_extension': Text, 'roles': {'anonymous': Text, 'authenticated': Text}} (Rohtexte aus der Tabelle config, serialisiert)."""
    if not isinstance(cfg, dict) or not any(cfg.get(k) for k in ("logging", "user_settings", "core_extension", "roles")):
        return _np("Drupal-Einstellungen in der Datenbank", "Die Tabelle config lieferte keine lesbaren Angaben.")
    out: List[Finding] = []
    lvl = php_value(cfg.get("logging"), "error_level")
    if lvl in ("verbose", "all"):
        out.append(_f("warn", "Fehlermeldungen werden den Besuchern angezeigt (Stufe %s)" % lvl, "Meldungen verraten Pfade, Datenbank-Namen und Programmteile.", [],
                      "Unter Konfiguration > Entwicklung > Protokollierung auf 'Keine' stellen."))
    elif lvl:
        out.append(_f("ok", "Fehlermeldungen werden Besuchern nicht angezeigt", "Stufe: %s." % _clean(lvl, 20)))
    reg = php_value(cfg.get("user_settings"), "register")
    if reg == "visitors":
        out.append(_f("warn", "Jeder Besucher kann sich ohne Freigabe registrieren", "Konten ohne Prüfung sind ein Einstieg für Spam und Missbrauch.", [],
                      "Unter Konfiguration > Personen > Kontoeinstellungen auf 'Nur Administratoren' oder 'Besucher, aber Freigabe nötig' stellen."))
    elif reg:
        out.append(_f("ok", "Registrierung: %s" % ("nur Administratoren" if reg == "admin_only" else "mit Freigabe" if reg == "visitors_admin_approval" else _clean(reg, 40)), ""))
    ext = cfg.get("core_extension") or ""
    mods = {m for m in php_strings(ext)} if ext else set()
    dev = sorted(mods & DEV_MODULES)
    if dev:
        out.append(_f("warn", "%d Entwicklungs-Modul(e) sind eingeschaltet" % len(dev), "Module wie devel oder webprofiler zeigen Interna und gehören nicht auf eine Live-Seite.", dev,
                      "Unter Erweitern ausschalten und entfernen."))
    for role, label in (("anonymous", "anonyme Besucher"), ("authenticated", "angemeldete Benutzer")):
        perms = [p for p in php_strings((cfg.get("roles") or {}).get(role) or "") if p in RISKY_PERMS or p.startswith("administer ")]
        if perms:
            out.append(_f("crit" if role == "anonymous" else "warn", "Die Rolle '%s' hat weitreichende Rechte" % label, "Diese Rechte gehören nur Administratoren.", sorted(set(perms)),
                          "Unter Personen > Rechte entziehen."))
    if not out:
        out.append(_f("ok", "Keine Auffälligkeiten in den Einstellungen", ""))
    return out


# ------------------------------------------------------------------ settings.php
def judge_settings(cfg: Any, modes: Optional[Dict[str, str]] = None) -> List[Finding]:
    """cfg: Ergebnis von drupal.parse_settings (+ 'missing'); modes: {'settings.php': '444 user', 'sites/default': '755 user'} (stat-Ausgabe)."""
    if not isinstance(cfg, dict) or cfg.get("missing"):
        return _np("Drupal-Einstellungsdatei", "Die Datei sites/default/settings.php wurde nicht gefunden.")
    st = cfg.get("settings") or {}
    out: List[Finding] = []
    if cfg.get("unexpected"):
        out.append(_f("crit", "In der settings.php stehen auffällige Befehle", "Dort gehören nur Einstellungen hin. Befehle wie eval oder base64_decode sind ein typisches Zeichen für eine Manipulation.",
                      ["Zeile %s: %s" % (n, _clean(t, 160)) for n, t in cfg["unexpected"][:20]], "Datei mit einer Sicherung vergleichen, Zugangsdaten und hash_salt erneuern."))
    if str(st.get("update_free_access", "")).strip().upper() == "TRUE":
        out.append(_f("crit", "update_free_access ist eingeschaltet", "Damit darf jeder Besucher update.php ausführen.", [], "In der settings.php auf FALSE setzen."))
    if "hash_salt" not in st or not str(st.get("hash_salt", "")).strip().strip("'\""):
        out.append(_f("warn", "hash_salt ist in der settings.php nicht gesetzt oder leer", "Der Wert schützt Formulare und Einmal-Links. Er kann auch über eine Datei oder Umgebungsvariable gesetzt sein; dann ist diese Meldung unbegründet.", [],
                      "Prüfen, wo hash_salt gesetzt wird."))
    if not cfg.get("trusted_hosts"):
        out.append(_f("warn", "trusted_host_patterns ist nicht gesetzt", "Ohne diese Einstellung akzeptiert Drupal Anfragen unter jedem Hostnamen (Host-Header-Angriffe, gefälschte Links in E-Mails).", [],
                      "In der settings.php $settings['trusted_host_patterns'] auf die eigene Domain setzen."))
    if str(st.get("skip_permissions_hardening", "")).strip().upper() == "TRUE":
        out.append(_f("warn", "Die automatische Rechte-Härtung ist abgeschaltet", "skip_permissions_hardening lässt Drupal die Rechte von settings.php nicht mehr absichern.", [], "Einstellung entfernen."))
    for name, mode in (modes or {}).items():
        m = re.match(r"^(\d{3,4})\b", mode or "")
        if not m:
            continue
        octal = m.group(1)[-3:]
        if int(octal[2]) & 2:
            out.append(_f("crit", "%s ist für alle beschreibbar (%s)" % (name, octal), "Jeder Benutzer des Servers kann sie ändern.", [], "Rechte auf 444 (Datei) bzw. 755 (Ordner) setzen."))
        elif name.endswith("settings.php") and int(octal[1]) & 2:
            out.append(_f("warn", "%s ist für die Gruppe beschreibbar (%s)" % (name, octal), "", [], "Rechte auf 444 setzen."))
        elif name.endswith("settings.php") and int(octal[0]) & 2:
            out.append(_f("info", "%s ist für den Besitzer beschreibbar (%s)" % (name, octal), "Drupal setzt sie im Normalbetrieb auf 444, damit ein Einbrecher sie nicht ändern kann.", [], "Mit chmod 444 sperren."))
    if not out:
        out.append(_f("ok", "Die settings.php ist unauffällig", "Keine auffälligen Befehle, update_free_access aus, trusted_host_patterns gesetzt."))
    return out


# ------------------------------------------------------------------ Eingeschleuster Code in Inhalten
def judge_db_code(rows: Any, system: str = "Drupal") -> List[Finding]:
    """rows: [{'table','id','text'}] Inhalte, die ein Skript-, Iframe- oder Verschleierungsmuster enthalten (Vorauswahl in SQL)."""
    if not isinstance(rows, list):
        return _np("Code in %s-Inhalten" % system, "Die Inhalte konnten nicht gelesen werden.")
    crit, warn = [], []
    for r in rows:
        if not isinstance(r, dict):
            continue
        text = str(r.get("text") or "")
        m = OBFUSCATED.search(text) or re.search(r"<\s*script|<\s*iframe|javascript\s*:", text, re.I)
        if not m:
            continue
        snip = _clean(text[max(0, m.start() - 40): m.end() + 120], 200)
        label = "%s %s: %s" % (_clean(str(r.get("table") or "?"), 40), _clean(str(r.get("id") or "?"), 20), snip)
        (crit if OBFUSCATED.search(text) or BAD_MARKUP.search(text) and re.search(r"https?://", text) and not re.search(r"youtube|vimeo|google|twitter|facebook", text, re.I) else warn).append(label)
    out: List[Finding] = []
    if crit:
        out.append(_f("crit", "%d Inhalt(e) enthalten verschleierten oder fremden Code" % len(crit), "Verschleierter Code (atob, eval, fromCharCode) oder Skripte mit fremder Adresse in Inhalten sind ein typischer Weg, Besucher umzuleiten oder Daten abzugreifen.",
                      crit, "Inhalt im Backend öffnen und den Code entfernen; danach Konten und Zugänge prüfen (wie kam der Code hinein?)."))
    if warn:
        out.append(_f("warn", "%d Inhalt(e) enthalten Skript- oder Iframe-Tags" % len(warn), "Das kann gewollt sein (Einbettungen, Statistik). Prüfen Sie, ob Sie es kennen.", warn, "Unbekannte Einbettungen entfernen."))
    if not (crit or warn):
        out.append(_f("ok", "In Inhalten wurde kein auffälliger Code gefunden", ""))
    return out


# ------------------------------------------------------------------ Abrufbare Dateien und Schnittstellen
def judge_exposed(web: Any) -> List[Finding]:
    """web: [{'kind','label','url','status','body'}]; kind: file (darf nicht abrufbar sein), api (darf ohne Anmeldung nichts liefern), dir (keine Ordnerliste), install (Installationsseite)."""
    if not isinstance(web, list):
        return _np("Abrufbare Drupal-Dateien", "Die Abruf-Ergebnisse fehlen.")
    crit, warn, info = [], [], []
    for r in web:
        if not isinstance(r, dict) or r.get("status") != 200:
            continue
        body = str(r.get("body") or "")
        lab = "%s: %s" % (_clean(str(r.get("label") or "?"), 70), _clean(str(r.get("url") or ""), 160))
        k = r.get("kind")
        if k == "file":
            if body.strip() and not body.lstrip().startswith("<!") and not body.lstrip().lower().startswith("<html"):
                crit.append(lab + " ist abrufbar")
        elif k == "api":
            if re.search(r'"(data|users|attributes)"\s*:', body) and not re.search(r'"errors"\s*:', body):
                crit.append(lab + " liefert Daten ohne Anmeldung")
        elif k == "dir":
            if re.search(r"<title>Index of|Parent Directory", body):
                warn.append(lab + " zeigt eine öffentliche Ordnerliste")
        elif k == "install":
            if re.search(r"Choose language|Select an installation profile|Set up database", body, re.I):
                crit.append(lab + " zeigt den Installations-Assistenten")
        elif k == "version":
            m = re.search(r"Drupal\s+(\d+\.\d+\.\d+)", body)
            if m:
                info.append(lab + " verrät die Version %s" % m.group(1))
    out: List[Finding] = []
    if crit:
        out.append(_f("crit", "%d Datei(en) oder Schnittstelle(n) sind frei abrufbar" % len(crit), "Einstellungen, Zugangsdaten oder Nutzerdaten dürfen von außen nicht zu lesen sein.", crit,
                      "Zugriff im Webserver sperren (Require all denied / Regel für die Datei) und Zugriffe in den Protokollen prüfen."))
    if warn:
        out.append(_f("warn", "%d Ordner zeigen eine öffentliche Ordnerliste" % len(warn), "Besucher sehen, welche Dateien dort liegen.", warn, "Ordnerlisten abschalten (Options -Indexes)."))
    if info:
        out.append(_f("info", "Die Drupal-Version ist von außen lesbar", "Angreifer suchen gezielt nach Seiten mit alter Version. Die Datei lässt sich sperren; das ersetzt aber keine Updates.", info,
                      "Datei CHANGELOG.txt im Webserver sperren."))
    if not (crit or warn):
        out.append(_f("ok", "Keine der geprüften Dateien und Schnittstellen ist frei abrufbar", "%d Adresse(n) geprüft." % len([r for r in web if isinstance(r, dict)])))
    return out
