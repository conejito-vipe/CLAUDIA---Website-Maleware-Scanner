"""Bewertung der Shopware-Prüfungen (2.13.0): reine Funktionen ohne Server-, Datenbank- oder Netzzugriff, mit Beispieldaten prüfbar.

Jede Funktion liefert Funde als (Stufe, Titel, Text, Einträge, Hinweis). Unbrauchbare Eingaben ergeben genau einen Info-Fund 'nicht prüfbar'.
Geheimnisse (Passwörter, APP_SECRET, Mail-DSN, Zugriffsschlüssel von Integrationen) werden nie ausgegeben; es zählen Namen, Rechte, Zeiten, Versionen und Adressen."""
from __future__ import annotations

import re
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

from .. import shopware
from .auswertung_contao import judge_core_files  # noqa: F401  (gleicher Dateivergleich wie bei Contao)
from .auswertung_drupal import judge_db_code as _judge_db_code
from .auswertung_joomla import _clean, _f, _np

Finding = Tuple[str, str, str, List[str], str]

DEV_PACKAGES = {"symfony/web-profiler-bundle", "symfony/debug-bundle", "shopware/dev-tools", "phpunit/phpunit", "friendsofphp/php-cs-fixer", "roave/security-advisories"}


def judge_core(version: str, releases: Any, adv: Any, now: Optional[float] = None, adv_ok: bool = True) -> List[Finding]:
    """version: installierte Version von shopware/core; releases: Liste von shopware.parse_release_list (leer = nicht erreichbar); adv: zutreffende Sicherheitsmeldungen."""
    if not version:
        return _np("Shopware-Version", "Die Version konnte nicht aus composer.lock oder vendor/composer/installed.php gelesen werden.")
    ver = _clean(version, 30)
    life = shopware.lifecycle(version, now)
    cy = life["cycle"] or ver
    out: List[Finding] = []
    if life["state"] == "ended":
        out.append(_f("crit", "Shopware %s wird nicht mehr mit Sicherheitsupdates versorgt" % cy, "Diese Version hat das Ende der Unterstützung erreicht%s. Neue Sicherheitslücken werden nicht mehr behoben." % (" (am %s)" % life["security_until"] if life["security_until"] else ""),
                      [ver], "Auf eine unterstützte Version umziehen (vorher vollständige Sicherung und Test mit einer Kopie des Shops)."))
    elif life["state"] == "security":
        out.append(_f("warn", "Shopware %s bekommt nur noch Sicherheitsupdates" % cy, "Fehlerkorrekturen endeten am %s; Sicherheitsupdates gibt es bis %s." % (life["bugfix_until"], life["security_until"]), [ver],
                      "Den Umzug auf eine Version mit voller Unterstützung planen."))
    elif life["state"] == "supported" and life["days_left"] is not None and life["days_left"] < 180:
        out.append(_f("warn", "Shopware %s: Die Unterstützung endet in %d Tagen" % (cy, life["days_left"]), "Ende der Sicherheitsupdates am %s." % life["security_until"], [ver], "Den Umzug auf die nächste Hauptversion jetzt planen."))
    elif life["state"] == "unknown":
        out.append(_f("info", "Shopware %s: Laufzeit der Version unbekannt" % ver, "Für diese Version enthält das Programm keine Angaben zum Support-Ende (Stand der Tabelle: %s)." % shopware.LIFECYCLE_ASOF))
    if cy == "6.5" and shopware.version_key(version) < shopware.version_key("6.5.8.0"):
        out.append(_f("warn", "Shopware %s liegt vor 6.5.8" % ver, "Für Versionen vor 6.5.8 gibt es Sicherheitskorrekturen nur noch über das Sicherheits-Plugin von Shopware, nicht mehr als direkte Updates.", [ver],
                      "Auf die letzte 6.5-Version oder eine neuere Hauptversion aktualisieren."))
    hits = [a for a in (adv or []) if isinstance(a, dict)]
    if hits:
        out.append(_f("crit", "Für Shopware %s sind %d Sicherheitsmeldung(en) bekannt" % (ver, len(hits)),
                      "Die Version liegt im betroffenen Bereich dieser Meldungen (Quelle: Packagist). Sie ist dort als verwundbar geführt.",
                      ["%s %s%s" % (_clean(a.get("id") or "?", 40), _clean(a.get("title") or "", 90), (" (%s)" % _clean(a["cve"], 30)) if a.get("cve") else "") for a in hits[:15]]
                      + (["... und %d weitere" % (len(hits) - 15)] if len(hits) > 15 else []), "Auf die neueste Version dieser Linie aktualisieren (vorher Sicherung)."))
    rel = [r for r in (releases or []) if isinstance(r, dict) and shopware.cycle(r["version"]) == shopware.cycle(version)]
    if rel:
        latest = max((r["version"] for r in rel), key=shopware.version_key)
        if shopware.version_key(latest) > shopware.version_key(version) and "-" not in version:
            out.append(_f("crit" if hits else "warn", "Shopware %s ist nicht die neueste Version" % ver, "Neueste Version dieser Linie: %s." % _clean(latest, 30), [],
                          "Sofort aktualisieren (vorher Sicherung)." if hits else "Beim nächsten Wartungsfenster aktualisieren (vorher Sicherung)."))
        elif not hits and life["state"] in ("supported", "security"):
            out.append(_f("ok", "Shopware %s ist auf dem neuesten Stand" % ver, "Neueste bekannte Version dieser Linie: %s." % _clean(latest, 30)))
    elif not hits and life["state"] != "ended":
        out.append(_f("info", "Shopware %s: Aktualität nicht prüfbar" % ver, "Die Liste der Veröffentlichungen von Packagist war nicht erreichbar oder nicht lesbar."))
    if not adv_ok:
        out.append(_f("info", "Sicherheitsmeldungen nicht prüfbar", "Packagist war nicht erreichbar oder lieferte nichts Lesbares. Ob für diese Version Meldungen vorliegen, ist offen.", [], "Die Sicherheitshinweise auf docs.shopware.com nachlesen."))
    return out


def judge_settings(cfg: Any, modes: Optional[Dict[str, str]] = None) -> List[Finding]:
    """cfg: Ergebnis von shopware.parse_settings (+ 'missing'); modes: {'Pfad': '644 user'} (stat-Ausgabe, auch für die JWT-Schlüssel)."""
    if not isinstance(cfg, dict) or cfg.get("missing"):
        return _np("Shopware-Einstellungen", "Es wurde keine .env-Datei gefunden.")
    if not cfg.get("parsed"):
        return _np("Shopware-Einstellungen", "Die Dateien ließen sich nicht lesen (andere Schreibweise oder beschädigt). Die Werte wurden nicht bewertet.")
    c = cfg.get("shopware") or {}
    env = c.get("env") or {}
    out: List[Finding] = []
    app_env = str(env.get("APP_ENV") or "").lower()
    if app_env in ("dev", "test"):
        out.append(_f("crit", "Shopware läuft im Entwicklungsmodus (APP_ENV=%s)" % _clean(app_env, 20), "Im Entwicklungsmodus zeigt Shopware Fehlerdetails, Profiler und Debug-Leiste; das verrät Pfade und Einstellungen.", [], "In der .env APP_ENV=prod setzen und den Cache leeren."))
    elif app_env and app_env != "prod":
        out.append(_f("warn", "APP_ENV ist nicht 'prod' (%s)" % _clean(app_env, 20), "Nur 'prod' ist der Betriebsmodus für Live-Shops.", [], "APP_ENV=prod setzen."))
    elif not app_env:
        out.append(_f("info", "APP_ENV ist in den Dateien nicht gesetzt", "Es gilt dann der Wert der Server-Umgebung. Prüfen Sie, ob 'prod' gilt.", []))
    if str(env.get("APP_DEBUG") or "").lower() in ("1", "true"):
        out.append(_f("warn", "APP_DEBUG ist eingeschaltet", "Der Debug-Modus zeigt Interna und Fehlerdetails.", [], "APP_DEBUG=0 setzen."))
    if not c.get("has_secret"):
        out.append(_f("crit", "APP_SECRET fehlt oder ist leer", "Der Schlüssel schützt Sitzungen, Formulare und Links. Ohne ihn ist die Installation nicht sicher.", [], "Einen langen Zufallswert in der .env als APP_SECRET eintragen."))
    elif c.get("secret_placeholder"):
        out.append(_f("crit", "APP_SECRET ist ein bekannter Beispielwert", "Beispielwerte aus Anleitungen kennt jeder Angreifer.", [], "Einen neuen Zufallswert erzeugen (z. B. 32 Bytes, hexadezimal) und eintragen."))
    elif c.get("secret_len", 0) < 32:
        out.append(_f("warn", "APP_SECRET ist kurz (%d Zeichen)" % c.get("secret_len", 0), "Kurze Schlüssel sind leichter zu erraten.", [], "Einen Zufallswert mit mindestens 32 Zeichen verwenden."))
    if re.match(r"^http://", str(env.get("APP_URL") or ""), re.I):
        out.append(_f("warn", "APP_URL beginnt mit http://", "Der Shop erzeugt dann Links ohne Verschlüsselung.", [], "APP_URL auf die https-Adresse des Shops setzen."))
    if str(env.get("TRUSTED_HOSTS") or "").strip() in (".*", "^.*$", "*"):
        out.append(_f("warn", "TRUSTED_HOSTS erlaubt jeden Hostnamen", "Der Wert schränkt nichts ein.", [], "Auf die eigene Domain setzen."))
    for name, mode in (modes or {}).items():
        m = re.match(r"^(\d{3,4})\b", mode or "")
        if not m:
            continue
        octal = m.group(1)[-3:]
        if int(octal[2]) & 2:
            out.append(_f("crit", "%s ist für alle beschreibbar (%s)" % (name, octal), "Jeder Benutzer des Servers kann sie ändern.", [], "Rechte auf 640 bzw. 644 (Datei) und 755 (Ordner) setzen."))
        elif int(octal[2]) & 4 and re.search(r"(^|/)(\.env[^/]*|private\.pem)$", name):
            out.append(_f("warn", "%s ist für alle lesbar (%s)" % (name, octal), "Die Datei enthält Zugangsdaten bzw. den privaten Schlüssel für die Anmeldung an der Schnittstelle.", [], "Rechte auf 600 oder 640 setzen."))
    if not out:
        out.append(_f("ok", "Die Einstellungen sind unauffällig", "Produktivmodus, Schlüssel gesetzt, keine zu offenen Rechte."))
    return out


def judge_packages(inventory: Any, adv_hits: Any, checked: int = 0, adv_ok: bool = True) -> List[Finding]:
    """inventory: [{'key','name','version','pkg','custom'(bool),'ext'(bool)}] (Erweiterungen = Plugins und Apps); adv_hits: {Schlüssel: [Meldungen]}; checked: so viele Pakete wurden abgefragt."""
    if not isinstance(inventory, list):
        return _np("Shopware-Erweiterungen", "Die Liste der Pakete fehlt oder ist unlesbar.")
    inv = [m for m in inventory if isinstance(m, dict) and m.get("key")]
    if not inv:
        return [_f("info", "Keine Pakete gefunden", "In composer.lock und custom/plugins wurden keine Pakete gelesen.")]
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
        out.append(_f("crit", "%d Paket(e) in einer Version mit bekannter Sicherheitslücke" % len(vuln), "Die installierten Versionen liegen im betroffenen Bereich veröffentlichter Sicherheitsmeldungen (Packagist).",
                      items[:25], "Auf die in der Meldung genannte Version aktualisieren (composer update <Paket>) oder das Paket entfernen (vorher Sicherung)."))
    dev = [m for m in inv if m["key"] in DEV_PACKAGES]
    if dev:
        out.append(_f("warn", "%d Entwicklungs-Paket(e) liegen auf dem Live-Server" % len(dev), "Werkzeuge für Entwickler (Profiler, Tests) gehören nicht auf einen Live-Shop.", [lab(m) for m in dev], "Mit 'composer install --no-dev' neu installieren."))
    custom = [m for m in inv if m.get("custom")]
    if custom:
        out.append(_f("info", "%d eigene Paket(e) (lokale Pfade)" % len(custom), "Eigene Programme werden nicht mit Sicherheitsmeldungen verglichen.", [lab(m) for m in custom][:40]))
    ext = [m for m in inv if m.get("ext")]
    if ext:
        out.append(_f("info", "%d Shopware-Erweiterung(en) installiert" % len(ext), "Plugins und Apps von Drittanbietern sind der häufigste Weg für Angriffe auf Shops; halten Sie sie aktuell. Viele Store-Plugins sind nicht bei Packagist geführt und werden hier nicht gegen Meldungen geprüft.",
                      [lab(m) for m in ext][:40]))
    if not adv_ok and checked:
        out.append(_f("info", "Sicherheitsmeldungen nicht prüfbar", "Packagist war nicht erreichbar oder lieferte nichts Lesbares.", [], "Später erneut prüfen."))
    if not (vuln or dev):
        out.append(_f("ok" if checked and adv_ok else "info", "Kein Paket mit bekannter Sicherheitslücke gefunden" if checked and adv_ok else "Es wurde kein Paket gegen Sicherheitsmeldungen geprüft",
                      "%d Paket(e) abgeglichen." % checked if checked else "Es lagen keine Paketnamen vor.", []))
    return out


def judge_users(rows: Any, now: Optional[float] = None) -> List[Finding]:
    """rows: [{'uid','name','admin'(bool),'active'(bool),'created_ts'}] aus der Tabelle user (Shopware speichert keinen Zeitpunkt der letzten Anmeldung)."""
    if not isinstance(rows, list):
        return _np("Shopware-Administratoren", "Die Benutzerliste fehlt oder ist unlesbar.")
    now = now or time.time()
    us = [r for r in rows if isinstance(r, dict)]
    admins = [r for r in us if r.get("admin") and r.get("active")]
    out: List[Finding] = []
    if not admins:
        out.append(_f("info", "Keine aktiven Administrator-Konten gefunden", "Die Abfrage lieferte keine aktiven Benutzer mit dem Administrator-Merkmal."))
    else:
        out.append(_f("info", "%d aktive(s) Administrator-Konto/Konten" % len(admins), "Administratoren dürfen Plugins, Rechte, Zahlungsarten und alle Daten ändern.",
                      ["%s (id %s)" % (_clean(str(r.get("name") or "?"), 60), _clean(str(r.get("uid") or "?"), 12)) for r in admins[:30]], "Nicht mehr gebrauchte Konten sperren."))
        if len(admins) > 5:
            out.append(_f("warn", "Auffällig viele Administrator-Konten (%d)" % len(admins), "Je mehr Administratoren, desto mehr Zugänge.", [], "Die meisten auf eine Rolle mit eingeschränkten Rechten umstellen."))
    fresh = [r for r in admins if isinstance(r.get("created_ts"), (int, float)) and now - r["created_ts"] < 14 * 86400]
    if fresh:
        out.append(_f("warn", "%d Administrator-Konto/Konten wurden in den letzten 14 Tagen angelegt" % len(fresh), "Nach einem Einbruch legen Angreifer gern ein neues Konto mit Administratorrechten an.",
                      [_clean(str(r.get("name") or "?"), 60) for r in fresh], "Prüfen, ob Sie oder Ihr Team das Konto angelegt haben. Wenn nicht: sperren und alle Passwörter ändern."))
    default = [r for r in admins if str(r.get("name") or "").lower() in ("admin", "administrator", "shopware", "root", "test")]
    if default:
        out.append(_f("warn", "Administrator-Konto mit einem leicht zu erratenden Namen", "Namen wie admin werden bei Angriffen als Erstes durchprobiert.", [_clean(str(r.get("name") or "?"), 60) for r in default], "Konto umbenennen oder ein neues mit anderem Namen anlegen und das alte sperren."))
    return out


def judge_shop(domains: Any, integrations: Any, webhooks: Any) -> List[Finding]:
    """domains: [{'url'}] aus sales_channel_domain; integrations: [{'label','admin'(bool),'last_use_ts','created_ts'}] (ohne Schlüssel); webhooks: [{'name','event','url','active'(bool)}]."""
    if not isinstance(domains, list):
        return _np("Shopware-Shop-Einstellungen", "Die Verkaufskanal-Adressen fehlen oder sind unlesbar.")
    out: List[Finding] = []
    plain = [d for d in domains if isinstance(d, dict) and re.match(r"^http://", str(d.get("url") or ""), re.I)]
    if plain:
        out.append(_f("crit", "%d Shop-Adresse(n) laufen ohne HTTPS" % len(plain), "Anmeldungen, Warenkörbe und Zahlungen laufen dort unverschlüsselt.", [_clean(str(d.get("url")), 120) for d in plain][:20],
                      "In der Verwaltung unter Verkaufskanäle > Domains auf https umstellen."))
    ints = [i for i in (integrations or []) if isinstance(i, dict)]
    adm = [i for i in ints if i.get("admin")]
    if adm:
        out.append(_f("warn", "%d Integration(en) mit vollen Administratorrechten" % len(adm), "Über die Zugriffsschlüssel dieser Integrationen lassen sich alle Shopdaten lesen und ändern. Ein vergessener Schlüssel ist ein Dauerzugang.",
                      [_clean(str(i.get("label") or "?"), 70) for i in adm][:20], "Nicht benötigte Integrationen löschen; für den Rest eine eingeschränkte Rolle vergeben."))
    elif ints:
        out.append(_f("info", "%d Integration(en) vorhanden" % len(ints), "Integrationen greifen mit eigenen Zugriffsschlüsseln auf die Schnittstelle zu.", [_clean(str(i.get("label") or "?"), 70) for i in ints][:20]))
    fresh = [i for i in ints if isinstance(i.get("created_ts"), (int, float)) and (time.time() - i["created_ts"]) < 14 * 86400]
    if fresh:
        out.append(_f("warn", "%d Integration(en) wurden in den letzten 14 Tagen angelegt" % len(fresh), "Angreifer legen gern eine Integration an, um auch nach einer Säuberung Zugriff zu behalten.", [_clean(str(i.get("label") or "?"), 70) for i in fresh], "Prüfen, ob Sie sie angelegt haben; sonst löschen."))
    hooks = [w for w in (webhooks or []) if isinstance(w, dict) and w.get("active") is not False]
    if hooks:
        items = []
        plain_hooks = []
        for w in hooks[:50]:
            try:
                host = urlsplit(str(w.get("url") or "")).hostname or "?"
            except ValueError:
                host = "?"
            items.append("%s -> %s" % (_clean(str(w.get("event") or w.get("name") or "?"), 60), _clean(host, 80)))
            if re.match(r"^http://", str(w.get("url") or ""), re.I):
                plain_hooks.append(_clean(host, 80))
        out.append(_f("info", "%d aktive(r) Webhook(s)" % len(hooks), "Webhooks senden Ereignisse (z. B. neue Bestellungen) an fremde Adressen. Ein unbekannter Empfänger kann Kundendaten abgreifen.", items[:30], "Empfänger prüfen und Unbekannte entfernen."))
        if plain_hooks:
            out.append(_f("warn", "%d Webhook(s) senden ohne Verschlüsselung (http)" % len(plain_hooks), "Die Daten gehen unverschlüsselt durchs Netz.", plain_hooks[:20], "Auf https umstellen lassen oder entfernen."))
    if not out:
        out.append(_f("ok", "Die Shop-Einstellungen sind unauffällig", "Alle Adressen mit HTTPS, keine Integration mit Administratorrechten, keine Webhooks."))
    return out


def judge_db_code(rows: Any) -> List[Finding]:
    """rows: [{'table','id','text'}]: gleiche Bewertung wie bei Drupal, mit Shopware-Bezeichnung."""
    return _judge_db_code(rows, "Shopware")


def judge_exposed(web: Any) -> List[Finding]:
    """web: [{'kind','label','url','status','body'}]; kind: file (darf nicht lesbar sein), dir, installer (Web-Installer), profiler (Entwicklungs-Eingang), api (offene Schnittstellenbeschreibung), admin (nur Hinweis)."""
    if not isinstance(web, list):
        return _np("Abrufbare Shopware-Dateien", "Die Abruf-Ergebnisse fehlen.")
    crit, warn, info = [], [], []
    for r in web:
        if not isinstance(r, dict) or r.get("status") != 200:
            continue
        body = str(r.get("body") or "")
        lab = "%s: %s" % (_clean(str(r.get("label") or "?"), 70), _clean(str(r.get("url") or ""), 160))
        k = r.get("kind")
        low = body.lstrip().lower()
        if k == "file":
            if body.strip() and not low.startswith(("<!", "<html")) and re.search(r"<\?php|APP_SECRET|DATABASE_URL|\"require\"|\"packages\"|APP_ENV|BEGIN (RSA )?PRIVATE KEY|\[core\]|Stack trace", body):
                crit.append(lab + " ist abrufbar")
        elif k == "dir":
            if re.search(r"<title>Index of|Parent Directory", body):
                warn.append(lab + " zeigt eine öffentliche Ordnerliste")
        elif k == "installer":
            if re.search(r"Shopware.{0,60}(Installer|Installation)|shopware-installer", body, re.I):
                warn.append(lab + " ist erreichbar (Installationsprogramm)")
        elif k == "profiler":
            if re.search(r"Symfony Profiler|sf-toolbar|Web Debug", body, re.I):
                crit.append(lab + " ist erreichbar (Entwicklungs-Eingang)")
        elif k == "api":
            if re.search(r"\"openapi\"|swagger", body, re.I):
                warn.append(lab + " ist ohne Anmeldung abrufbar (Beschreibung der Schnittstelle)")
        elif k == "admin":
            info.append(lab + " ist erreichbar")
    out: List[Finding] = []
    if crit:
        out.append(_f("crit", "%d Datei(en) oder Seite(n) sind frei abrufbar" % len(crit), "Einstellungen, Zugangsdaten, Schlüssel oder Entwicklungs-Werkzeuge dürfen von außen nicht zu erreichen sein.", crit,
                      "Zugriff im Webserver sperren (nur der Ordner public/ gehört ins Web) und Zugriffe in den Protokollen prüfen."))
    if warn:
        out.append(_f("warn", "%d Adresse(n) sollten von außen nicht offen sein" % len(warn), "Installationsprogramm und Schnittstellenbeschreibung helfen Angreifern; Ordnerlisten zeigen, welche Dateien dort liegen.", warn,
                      "Nach der Arbeit die Datei bzw. den Zugang entfernen oder auf eigene Adressen beschränken; Ordnerlisten abschalten (Options -Indexes)."))
    if info:
        out.append(_f("info", "Die Verwaltung (/admin) ist öffentlich erreichbar", "Das ist normal. Zusätzlicher Schutz (Zugriff nur von bestimmten Adressen, Zwei-Faktor-Anmeldung) senkt das Risiko von Passwort-Versuchen.", info))
    if not (crit or warn):
        out.append(_f("ok", "Keine der geprüften Dateien und Seiten ist frei abrufbar", "%d Adresse(n) geprüft." % len([r for r in web if isinstance(r, dict)])))
    return out
