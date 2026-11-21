"""Bewertung der PrestaShop-Prüfungen (2.12.0): reine Funktionen ohne Server-, Datenbank- oder Netzzugriff, mit Beispieldaten prüfbar.

Jede Funktion liefert Funde als (Stufe, Titel, Text, Einträge, Hinweis). Unbrauchbare Eingaben ergeben genau einen Info-Fund 'nicht prüfbar'.
Geheimnisse (Passwörter, cookie_key, API-Schlüssel) werden nie ausgegeben; es zählen Namen, Rechte, Zeiten, Versionen und Adressen."""
from __future__ import annotations

import re
import time
from typing import Any, Dict, List, Optional, Tuple

from .. import prestashop
from .auswertung_contao import judge_core_files  # gleicher Dateivergleich wie bei Contao
from .auswertung_drupal import judge_db_code as _judge_db_code
from .auswertung_joomla import _clean, _f, _np

Finding = Tuple[str, str, str, List[str], str]
__all__ = ["judge_core", "judge_core_files", "judge_settings", "judge_modules", "judge_users", "judge_shop", "judge_db_code", "judge_exposed"]

DEFAULT_ADMIN = re.compile(r"^(admin|admin-dev|administration|backoffice|bo|prestashop)$", re.I)


def judge_core(version: str, releases: Any, adv: Any, adv_ok: bool = True) -> List[Finding]:
    """version: installierte Version; releases: Liste von parse_release_list (leer = nicht erreichbar); adv: zutreffende Sicherheitsmeldungen."""
    if not version:
        return _np("PrestaShop-Version", "Die Version konnte nicht aus app/AppKernel.php, install/install_version.php oder config/settings.inc.php gelesen werden.")
    ver = _clean(version, 30)
    life = prestashop.lifecycle(version)
    out: List[Finding] = []
    if life["state"] == "ended":
        out.append(_f("crit", "PrestaShop %s wird nicht mehr mit Sicherheitsupdates versorgt" % (life["cycle"] or ver), "Diese Version hat das Ende der Unterstützung erreicht. Neue Sicherheitslücken werden nicht mehr behoben.", [ver],
                      "Auf eine unterstützte Version umziehen (vorher vollständige Sicherung und Test mit einer Kopie des Shops; Hilfe bietet der Update-Assistent des Projekts)."))
    elif life["state"] == "security":
        out.append(_f("warn", "PrestaShop %s ist nur noch in der erweiterten Unterstützung" % life["cycle"], "Es erscheinen nur noch Korrekturen für kritische Fehler und Sicherheitslücken; die Phase endet, wenn die nächste Hauptversion erscheint.", [ver],
                      "Den Umzug auf die aktuelle Version 9.x planen."))
    elif life["state"] == "unknown":
        out.append(_f("info", "PrestaShop %s: Laufzeit der Version unbekannt" % ver, "Für diese Version enthält das Programm keine Angaben zum Support-Ende (Stand der Tabelle: %s)." % prestashop.LIFECYCLE_ASOF))
    hits = [a for a in (adv or []) if isinstance(a, dict)]
    if hits:
        out.append(_f("crit", "Für PrestaShop %s sind %d Sicherheitsmeldung(en) bekannt" % (ver, len(hits)), "Die Version liegt im betroffenen Bereich dieser Meldungen (Quelle: Packagist). Sie ist dort als verwundbar geführt.",
                      ["%s %s%s" % (_clean(a.get("id") or "?", 40), _clean(a.get("title") or "", 90), (" (%s)" % _clean(a["cve"], 30)) if a.get("cve") else "") for a in hits[:15]]
                      + (["... und %d weitere" % (len(hits) - 15)] if len(hits) > 15 else []), "Auf die neueste Version dieser Linie aktualisieren (vorher Sicherung)."))
    rel = [r for r in (releases or []) if isinstance(r, dict) and prestashop.cycle(r["version"]) == prestashop.cycle(version)]
    if rel:
        latest = max((r["version"] for r in rel), key=prestashop.version_key)
        if prestashop.version_key(latest) > prestashop.version_key(version):
            out.append(_f("crit" if hits else "warn", "PrestaShop %s ist nicht die neueste Version" % ver, "Neueste Version dieser Linie: %s." % _clean(latest, 30), [],
                          "Sofort aktualisieren (vorher Sicherung)." if hits else "Beim nächsten Wartungsfenster aktualisieren (vorher Sicherung)."))
        elif not hits and life["state"] in ("supported", "security"):
            out.append(_f("ok", "PrestaShop %s ist auf dem neuesten Stand" % ver, "Neueste bekannte Version dieser Linie: %s." % _clean(latest, 30)))
    elif not hits and life["state"] != "ended":
        out.append(_f("info", "PrestaShop %s: Aktualität nicht prüfbar" % ver, "Die Liste der Veröffentlichungen von Packagist war nicht erreichbar oder nicht lesbar."))
    if not adv_ok:
        out.append(_f("info", "Sicherheitsmeldungen nicht prüfbar", "Packagist war nicht erreichbar oder lieferte nichts Lesbares. Ob für diese Version Meldungen vorliegen, ist offen.", [],
                      "Auf build.prestashop-project.org/news nachsehen."))
    return out


def judge_settings(cfg: Any, dirs: Optional[List[str]] = None, modes: Optional[Dict[str, str]] = None) -> List[Finding]:
    """cfg: Ergebnis von prestashop.parse_settings (+ 'missing'); dirs: Ordner der obersten Ebene (admin*, install*); modes: {'Pfad': '644 user'}."""
    if not isinstance(cfg, dict) or cfg.get("missing"):
        return _np("PrestaShop-Einstellungen", "Weder app/config/parameters.php noch config/settings.inc.php wurde gefunden.")
    if not cfg.get("parsed"):
        return _np("PrestaShop-Einstellungen", "Die Dateien ließen sich nicht lesen (andere Schreibweise oder beschädigt). Die Werte wurden nicht bewertet.")
    c = cfg.get("prestashop") or {}
    out: List[Finding] = []
    if cfg.get("unexpected"):
        out.append(_f("crit", "In den Einstellungsdateien stehen auffällige Befehle", "Dort gehören nur Einstellungen hin. Befehle wie eval oder base64_decode sind ein typisches Zeichen für eine Manipulation.",
                      ["Zeile %s: %s" % (n, _clean(x, 160)) for n, x in cfg["unexpected"][:20]], "Datei mit einer Sicherung vergleichen, Datenbank-Passwort und cookie_key erneuern."))
    if c.get("dev_mode"):
        out.append(_f("crit", "Der Entwicklungsmodus ist eingeschaltet (_PS_MODE_DEV_)", "Fehlermeldungen mit Pfaden und Programmdetails werden den Besuchern angezeigt.", [], "In config/defines.inc.php _PS_MODE_DEV_ auf false setzen."))
    if not c.get("has_cookie"):
        out.append(_f("warn", "Der cookie_key fehlt oder ist leer", "Der Schlüssel schützt Anmelde-Cookies. Ohne ihn sind sie nicht sicher.", [], "Die Datei mit einer Sicherung vergleichen; ein neuer Schlüssel meldet alle Nutzer ab."))
    elif c.get("cookie_len", 0) < 32:
        out.append(_f("warn", "Der cookie_key ist kurz (%d Zeichen)" % c.get("cookie_len", 0), "Kurze Schlüssel sind leichter zu erraten.", [], "Einen zufälligen Schlüssel mit mindestens 32 Zeichen verwenden."))
    if c.get("legacy"):
        out.append(_f("info", "Alte Einstellungsdatei (PrestaShop 1.6)", "Diese Version wird seit Jahren nicht mehr gepflegt.", [], "Auf eine unterstützte Version umziehen."))
    names = list(dirs or [])
    inst = [d for d in names if d.lower().startswith("install")]
    if inst:
        out.append(_f("crit", "Der Installationsordner liegt noch auf dem Server", "Ein erreichbarer Installationsordner erlaubt im schlimmsten Fall, den Shop neu aufzusetzen oder zu übernehmen.", inst, "Ordner nach der Einrichtung entfernen (vorher Sicherung)."))
    adm = [d for d in names if d.lower().startswith("admin")]
    weak = [d for d in adm if DEFAULT_ADMIN.match(d)]
    if weak:
        out.append(_f("warn", "Der Ordner der Verwaltung hat einen leicht zu erratenden Namen", "PrestaShop vergibt bei der Installation einen zufälligen Namen (admin + Zeichenfolge). Namen wie 'admin' werden bei Angriffen als Erstes probiert.", weak, "Ordner umbenennen (vorher Sicherung; das Back-Office ist danach unter der neuen Adresse erreichbar)."))
    for name, mode in (modes or {}).items():
        m = re.match(r"^(\d{3,4})\b", mode or "")
        if not m:
            continue
        octal = m.group(1)[-3:]
        if int(octal[2]) & 2:
            out.append(_f("crit", "%s ist für alle beschreibbar (%s)" % (name, octal), "Jeder Benutzer des Servers kann sie ändern.", [], "Rechte auf 644 (Datei) bzw. 755 (Ordner) setzen."))
        elif int(octal[2]) & 4 and name.endswith("parameters.php"):
            out.append(_f("info", "%s ist für alle lesbar (%s)" % (name, octal), "Die Datei enthält das Datenbank-Passwort. Auf Shared Hosting ist das oft nicht anders einstellbar.", [], "Wenn möglich Rechte auf 640 setzen."))
    if not out:
        out.append(_f("ok", "Die Einstellungen sind unauffällig", "Keine auffälligen Befehle, Entwicklungsmodus aus, Schlüssel gesetzt, kein Installationsordner."))
    return out


def judge_modules(inventory: Any, adv_hits: Any, checked: int = 0, adv_ok: bool = True, overrides: Optional[List[str]] = None, modules_dir_ok: bool = True) -> List[Finding]:
    """inventory: [{'key','name','version','pkg'(Composer-Name oder ''),'core'(bool)}]; adv_hits: {Schlüssel: [Meldungen]}; overrides: Dateien unter override/ (ohne index.php)."""
    if not isinstance(inventory, list):
        return _np("PrestaShop-Module", "Die Modulliste fehlt oder ist unlesbar.")
    inv = [m for m in inventory if isinstance(m, dict) and m.get("key")]
    hits = adv_hits if isinstance(adv_hits, dict) else {}
    out: List[Finding] = []

    def lab(m: Dict[str, Any]) -> str:
        return "%s %s" % (_clean(m.get("name") or m["key"], 70), _clean(m.get("version") or "?", 30))

    vuln = [m for m in inv if hits.get(m["key"])]
    if vuln:
        items: List[str] = []
        for m in vuln:
            for a in hits[m["key"]][:3]:
                items.append("%s: %s %s%s" % (lab(m), _clean(a.get("id") or "?", 40), _clean(a.get("title") or "", 80), (" (%s)" % _clean(a["cve"], 30)) if a.get("cve") else ""))
        out.append(_f("crit", "%d Modul(e) in einer Version mit bekannter Sicherheitslücke" % len(vuln), "Die installierten Versionen liegen im betroffenen Bereich veröffentlichter Sicherheitsmeldungen (Packagist).", items[:25],
                      "Auf die in der Meldung genannte Version aktualisieren oder das Modul entfernen (vorher Sicherung)."))
    third = [m for m in inv if not m.get("core")]
    if inv:
        out.append(_f("info", "%d Modul(e) installiert, davon %d von Dritten" % (len(inv), len(third)), "Module von Dritten sind der häufigste Weg für Angriffe auf PrestaShop-Shops; halten Sie sie aktuell und entfernen Sie nicht benutzte.",
                      [lab(m) for m in third][:40]))
    if overrides:
        out.append(_f("info", "%d Override-Datei(en) vorhanden" % len(overrides), "Overrides ersetzen Programmklassen des Kerns. Sie sind legitim, aber auch ein beliebter Ort für versteckten Code.", [_clean(o, 120) for o in overrides[:40]],
                      "Prüfen, ob jede Datei von einem Modul oder Ihrer Agentur stammt."))
    if not modules_dir_ok:
        out.append(_f("info", "Der Ordner modules wurde nicht gefunden", "Es konnten keine Module gelesen werden.", []))
    if not vuln:
        out.append(_f("ok" if checked and adv_ok else "info", "Kein Modul mit bekannter Sicherheitslücke gefunden" if checked and adv_ok else "Es wurde kein Modul gegen Sicherheitsmeldungen geprüft",
                      "%d Modul(e) mit Composer-Namen abgeglichen." % checked if checked else "Die meisten Module sind nicht bei Packagist geführt; nur Module mit eigener composer.json lassen sich so abgleichen.", []))
    if not adv_ok and checked:
        out.append(_f("info", "Sicherheitsmeldungen nicht prüfbar", "Packagist war nicht erreichbar oder lieferte nichts Lesbares.", [], "Später erneut prüfen."))
    return out


def judge_users(rows: Any, now: Optional[float] = None) -> List[Finding]:
    """rows: [{'uid','name','super'(bool),'active'(bool),'created_ts','access_ts'}] aus ps_employee (super = Profil 'SuperAdmin')."""
    if not isinstance(rows, list):
        return _np("PrestaShop-Mitarbeiterkonten", "Die Mitarbeiterliste fehlt oder ist unlesbar.")
    now = now or time.time()
    us = [r for r in rows if isinstance(r, dict)]
    sup = [r for r in us if r.get("super") and r.get("active")]
    out: List[Finding] = []
    if not sup:
        out.append(_f("info", "Keine aktiven Super-Administrator-Konten gefunden", "Die Abfrage lieferte keine aktiven Mitarbeiter mit dem Profil SuperAdmin."))
    else:
        out.append(_f("info", "%d aktive(s) Super-Administrator-Konto/Konten" % len(sup), "Super-Administratoren dürfen Module, Rechte, Zahlungsarten und alle Daten ändern.",
                      ["%s (id %s)" % (_clean(str(r.get("name") or "?"), 60), r.get("uid")) for r in sup[:30]], "Nicht mehr gebrauchte Konten sperren."))
        if len(sup) > 3:
            out.append(_f("warn", "Auffällig viele Super-Administrator-Konten (%d)" % len(sup), "Je mehr Administratoren, desto mehr Zugänge.", [], "Die meisten auf ein eingeschränktes Profil zurückstufen."))
    fresh = [r for r in sup if isinstance(r.get("created_ts"), (int, float)) and now - r["created_ts"] < 14 * 86400]
    if fresh:
        out.append(_f("warn", "%d Super-Administrator-Konto/Konten wurden in den letzten 14 Tagen angelegt" % len(fresh), "Nach einem Einbruch legen Angreifer gern ein neues Konto mit voller Berechtigung an.",
                      [_clean(str(r.get("name") or "?"), 60) for r in fresh], "Prüfen, ob Sie oder Ihr Team das Konto angelegt haben. Wenn nicht: sperren und alle Passwörter ändern."))
    never = [r for r in sup if not r.get("access_ts")]
    if never:
        out.append(_f("info", "%d Super-Administrator-Konto/Konten haben sich nie angemeldet" % len(never), "Ein nie benutztes Konto mit voller Berechtigung ist unnötiges Risiko.", [_clean(str(r.get("name") or "?"), 60) for r in never], "Sperren oder Profil ändern."))
    _def = ("admin", "administrator", "prestashop", "demo", "test")
    default = [r for r in sup if str(r.get("name") or "").strip().lower() in _def or (str(r.get("name") or "").split() and all(t.lower() in _def for t in str(r.get("name")).split()))]
    if default:
        out.append(_f("warn", "Super-Administrator-Konto mit einem leicht zu erratenden Namen", "Namen wie admin werden bei Angriffen als Erstes durchprobiert.", [_clean(str(r.get("name") or "?"), 60) for r in default], "Konto umbenennen oder ein neues anlegen und das alte sperren."))
    return out


def judge_shop(conf: Any, keys: Any) -> List[Finding]:
    """conf: {Konfigurationsname: Wert} aus ps_configuration; keys: [{'id','descr','active'(bool),'write'(bool)}] (Webservice-Schlüssel ohne den Schlüssel selbst)."""
    if not isinstance(conf, dict):
        return _np("PrestaShop-Shop-Einstellungen", "Die Konfiguration fehlt oder ist unlesbar.")
    out: List[Finding] = []
    ws = str(conf.get("PS_WEBSERVICE") or "0") in ("1", "true")
    ks = [k for k in (keys or []) if isinstance(k, dict)]
    act = [k for k in ks if k.get("active")]
    if ws and act:
        wr = [k for k in act if k.get("write")]
        out.append(_f("warn" if wr else "info", "Die Webservice-Schnittstelle ist an (%d aktive(r) Schlüssel)" % len(act), "Über die Schnittstelle (/api) lassen sich Shopdaten lesen%s." % (" und ändern" if wr else ""),
                      ["%s%s" % (_clean(str(k.get("descr") or "ohne Beschreibung"), 60), " (darf schreiben)" if k.get("write") else "") for k in act][:20],
                      "Nicht benutzte Schlüssel löschen; nur die nötigen Rechte vergeben; die Schnittstelle abschalten, wenn kein Dienst sie braucht."))
    elif ws:
        out.append(_f("info", "Die Webservice-Schnittstelle ist an, aber ohne aktiven Schlüssel", "Ohne Schlüssel kann niemand etwas abrufen.", [], "Abschalten, wenn nicht gebraucht."))
    ssl = str(conf.get("PS_SSL_ENABLED") or "0") in ("1", "true")
    ssl_all = str(conf.get("PS_SSL_ENABLED_EVERYWHERE") or "0") in ("1", "true")
    if not ssl:
        out.append(_f("crit", "Der Shop läuft nicht über HTTPS (PS_SSL_ENABLED)", "Anmeldungen, Warenkörbe und Zahlungen laufen unverschlüsselt.", [], "Im Back-Office unter Shop-Parameter > Allgemein > SSL einschalten (Zertifikat vorher beim Hoster einrichten)."))
    elif not ssl_all:
        out.append(_f("warn", "HTTPS wird nicht für alle Seiten erzwungen", "Nur ein Teil der Seiten ist verschlüsselt.", [], "Die Einstellung 'SSL auf allen Seiten' einschalten."))
    if str(conf.get("PS_DISABLE_OVERRIDES") or "0") not in ("1", "true"):
        out.append(_f("info", "Overrides sind erlaubt", "Overrides können Programmklassen des Kerns ersetzen. Das ist normal, solange nur bekannte Module sie anlegen.", []))
    if not out:
        out.append(_f("ok", "Die Shop-Einstellungen sind unauffällig", "HTTPS überall, keine offene Webservice-Schnittstelle."))
    return out


def judge_db_code(rows: Any) -> List[Finding]:
    """rows: [{'table','id','text'}]: gleiche Bewertung wie bei Drupal, mit PrestaShop-Bezeichnung."""
    return _judge_db_code(rows, "PrestaShop")


def judge_exposed(web: Any) -> List[Finding]:
    """web: [{'kind','label','url','status','body'}]; kind: file (darf nicht lesbar sein), dir (Ordnerliste), install (Installationsordner), admin (Verwaltung unter Standardname), api (Webservice)."""
    if not isinstance(web, list):
        return _np("Abrufbare PrestaShop-Dateien", "Die Abruf-Ergebnisse fehlen.")
    crit, warn, info = [], [], []
    for r in web:
        if not isinstance(r, dict) or r.get("status") not in (200, 401):
            continue
        body = str(r.get("body") or "")
        lab = "%s: %s" % (_clean(str(r.get("label") or "?"), 70), _clean(str(r.get("url") or ""), 160))
        k = r.get("kind")
        low = body.lstrip().lower()
        if r.get("status") == 401:
            if k == "api":
                info.append(lab + " ist erreichbar (verlangt einen Schlüssel)")
            continue
        if k == "file":
            if body.strip() and not low.startswith(("<!", "<html")) and re.search(r"<\?php|database_password|_DB_PASSWD_|cookie_key|\"require\"|\[core\]|ERROR|Stack trace", body):
                crit.append(lab + " ist abrufbar")
        elif k == "dir":
            if re.search(r"<title>Index of|Parent Directory", body):
                warn.append(lab + " zeigt eine öffentliche Ordnerliste")
        elif k == "install":
            if re.search(r"PrestaShop.{0,40}(Installation|Installer|Installations)|install_version|Install Assistant", body, re.I):
                crit.append(lab + " ist erreichbar (Installationsassistent)")
        elif k == "admin":
            if re.search(r"PrestaShop|id=\"login\"|admin-dev|Back ?office|Anmeldung", body, re.I):
                warn.append(lab + " ist unter dem Standardnamen erreichbar")
        elif k == "api":
            info.append(lab + " ist erreichbar")
    out: List[Finding] = []
    if crit:
        out.append(_f("crit", "%d Datei(en) oder Seite(n) sind frei abrufbar" % len(crit), "Einstellungen, Protokolle oder der Installationsassistent dürfen von außen nicht zu erreichen sein.", crit,
                      "Zugriff im Webserver sperren bzw. den Ordner entfernen und Zugriffe in den Protokollen prüfen."))
    if warn:
        out.append(_f("warn", "%d Adresse(n) sollten von außen nicht offen sein" % len(warn), "Ordnerlisten zeigen, welche Dateien dort liegen; ein Standardname der Verwaltung wird bei Angriffen zuerst probiert.", warn,
                      "Ordnerlisten abschalten (Options -Indexes); den Ordner der Verwaltung umbenennen."))
    if info:
        out.append(_f("info", "Die Webservice-Schnittstelle ist öffentlich erreichbar", "Sie verlangt einen Schlüssel. Wenn kein Dienst sie braucht, sollte sie abgeschaltet sein.", info))
    if not (crit or warn):
        out.append(_f("ok", "Keine der geprüften Dateien und Seiten ist frei abrufbar", "%d Adresse(n) geprüft." % len([r for r in web if isinstance(r, dict)])))
    return out
