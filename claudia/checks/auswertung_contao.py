"""Bewertung der Contao-Prüfungen (2.11.0): reine Funktionen ohne Server-, Datenbank- oder Netzzugriff, mit Beispieldaten prüfbar.

Jede Funktion liefert Funde als (Stufe, Titel, Text, Einträge, Hinweis). Unbrauchbare Eingaben ergeben genau einen Info-Fund 'nicht prüfbar'.
Geheimnisse (Passwörter, APP_SECRET, Mail-DSN) werden nie ausgegeben; es zählen Namen, Rechte, Zeiten, Versionen und Adressen."""
from __future__ import annotations

import re
import time
from typing import Any, Dict, List, Optional, Tuple

from .. import contao
from .auswertung_drupal import judge_db_code as _judge_db_code
from .auswertung_joomla import _clean, _f, _np

Finding = Tuple[str, str, str, List[str], str]

DEV_PACKAGES = {"symfony/web-profiler-bundle", "symfony/debug-bundle", "contao/manager-plugin-dev", "phpunit/phpunit", "friendsofphp/php-cs-fixer", "roave/security-advisories"}
BAD_UPLOAD = re.compile(r"^(php\d?|phtml|pht|phar|inc|htaccess|htpasswd|sh|cgi|pl|py|exe)$", re.I)
BAD_TAG = re.compile(r"<(script|iframe|object|embed)\b", re.I)


def judge_core(version: str, releases: Any, adv: Any, now: Optional[float] = None, adv_ok: bool = True) -> List[Finding]:
    """version: installierte Version von contao/core-bundle; releases: Liste von contao.parse_release_list (leer = nicht erreichbar); adv: zutreffende Sicherheitsmeldungen."""
    if not version:
        return _np("Contao-Version", "Die Version konnte nicht aus composer.lock oder vendor/composer/installed.php gelesen werden.")
    ver = _clean(version, 30)
    life = contao.lifecycle(version, now)
    cy = life["cycle"] or ver
    out: List[Finding] = []
    if re.match(r"^[0-3]\.", version):
        out.append(_f("crit", "Contao %s ist uralt und wird nicht mehr gepflegt" % ver, "Diese Hauptversion bekommt seit Jahren keine Sicherheitsupdates mehr; die Prüfungen dieses Programms gelten für Contao ab 4.13.", [ver],
                      "Auf eine unterstützte Version umziehen (vorher vollständige Sicherung und Test mit einer Kopie der Seite)."))
        return out
    if life["state"] == "ended":
        out.append(_f("crit", "Contao %s wird nicht mehr mit Sicherheitsupdates versorgt" % cy, "Diese Version hat das Ende der Unterstützung erreicht%s. Neue Sicherheitslücken werden nicht mehr behoben." % (" (am %s)" % life["security_until"] if life["security_until"] else ""),
                      [ver], "Auf eine unterstützte Version (LTS) umziehen (vorher vollständige Sicherung und Test mit einer Kopie der Seite)."))
    elif life["state"] == "security":
        out.append(_f("warn", "Contao %s bekommt nur noch Sicherheitsupdates" % cy, "Fehlerkorrekturen endeten am %s; Sicherheitsupdates gibt es bis %s." % (life["bugfix_until"], life["security_until"]), [ver],
                      "Den Umzug auf eine Version mit voller Unterstützung planen."))
    elif life["state"] == "supported" and life["days_left"] is not None and life["days_left"] < 180:
        out.append(_f("warn", "Contao %s: Die Unterstützung endet in %d Tagen" % (cy, life["days_left"]), "Ende der Sicherheitsupdates am %s." % life["security_until"], [ver], "Den Umzug auf die nächste LTS-Version jetzt planen."))
    elif life["state"] == "unknown":
        out.append(_f("info", "Contao %s: Laufzeit der Version unbekannt" % ver, "Für diese Version enthält das Programm keine Angaben zum Support-Ende (Stand der Tabelle: %s)." % contao.LIFECYCLE_ASOF))
    hits = [a for a in (adv or []) if isinstance(a, dict)]
    if hits:
        out.append(_f("crit", "Für Contao %s sind %d Sicherheitsmeldung(en) bekannt" % (ver, len(hits)),
                      "Die Version liegt im betroffenen Bereich dieser Meldungen (Quelle: Packagist). Sie ist dort als verwundbar geführt.",
                      ["%s %s%s" % (_clean(a.get("id") or "?", 40), _clean(a.get("title") or "", 90), (" (%s)" % _clean(a["cve"], 30)) if a.get("cve") else "") for a in hits[:15]]
                      + (["... und %d weitere" % (len(hits) - 15)] if len(hits) > 15 else []), "Auf die neueste Version dieser Linie aktualisieren (vorher Sicherung)."))
    rel = [r for r in (releases or []) if isinstance(r, dict) and contao.cycle(r["version"]) == contao.cycle(version)]
    if rel:
        latest = max((r["version"] for r in rel), key=contao.version_key)
        if contao.version_key(latest) > contao.version_key(version) and "-" not in version:
            out.append(_f("crit" if hits else "warn", "Contao %s ist nicht die neueste Version" % ver, "Neueste Version dieser Linie: %s." % _clean(latest, 30), [],
                          "Sofort aktualisieren (vorher Sicherung)." if hits else "Beim nächsten Wartungsfenster aktualisieren (vorher Sicherung)."))
        elif not hits and life["state"] in ("supported", "security"):
            out.append(_f("ok", "Contao %s ist auf dem neuesten Stand" % ver, "Neueste bekannte Version dieser Linie: %s." % _clean(latest, 30)))
    elif not hits and life["state"] != "ended":
        out.append(_f("info", "Contao %s: Aktualität nicht prüfbar" % ver, "Die Liste der Veröffentlichungen von Packagist war nicht erreichbar oder nicht lesbar."))
    if not adv_ok:
        out.append(_f("info", "Sicherheitsmeldungen nicht prüfbar", "Packagist war nicht erreichbar oder lieferte nichts Lesbares. Ob für diese Version Meldungen vorliegen, ist offen.", [], "Auf contao.org/de/sicherheitshinweise.html nachsehen."))
    return out


def judge_core_files(label: str, ref_count: int, changed: List[str], missing: List[str], extra: List[str], source: str = "") -> List[Finding]:
    """Ergebnis des Dateivergleichs eines Kern-Bundles (z. B. contao/core-bundle) mit dem Original."""
    out: List[Finding] = []
    total = max(1, ref_count)
    if (len(changed) + len(missing)) / total > 0.35:
        return [_f("warn", "%s: sehr viele Dateien weichen ab (%d von %d)" % (label, len(changed) + len(missing), total),
                   "Das spricht für eine angepasste Version, einen Fork oder ein unpassendes Paket als Vergleich, nicht für einen Einzelangriff. " + source, [], "Prüfen, welche Version wirklich installiert ist.")]
    php_extra = [p for p in extra if re.search(r"\.(php\d?|phtml|pht|phar|inc)$", p, re.I)]
    if php_extra:
        out.append(_f("crit", "%s: %d unbekannte PHP-Datei(en)" % (label, len(php_extra)), "Im Paket liegen PHP-Dateien, die nicht zum Original gehören. Das ist ein typischer Ablageort für Hintertüren. " + source,
                      php_extra[:40], "Datei ansehen; wenn sie nicht von Ihnen oder einem bekannten Patch stammt, sichern und entfernen und die Zugangsdaten erneuern."))
    if changed:
        out.append(_f("warn", "%s: %d Datei(en) weichen vom Original ab" % (label, len(changed)), "Das kann ein bewusster Patch sein oder eine Manipulation. " + source, changed[:40],
                      "Ist kein Patch bekannt: Datei gegen das Original vergleichen und das Paket neu einspielen (composer install)."))
    if missing:
        out.append(_f("warn", "%s: %d Datei(en) fehlen" % (label, len(missing)), "Fehlende Dateien deuten auf ein unvollständiges Update oder auf entfernte Dateien hin.", missing[:40], "Paket neu einspielen."))
    if not out:
        out.append(_f("ok", "%s: alle Dateien stimmen mit dem Original überein" % label, "%d Dateien verglichen. %s" % (ref_count, source)))
    return out


def judge_settings(cfg: Any, modes: Optional[Dict[str, str]] = None) -> List[Finding]:
    """cfg: Ergebnis von contao.parse_settings (+ 'missing'); modes: {'Pfad': '644 user'} (stat-Ausgabe)."""
    if not isinstance(cfg, dict) or cfg.get("missing"):
        return _np("Contao-Einstellungen", "Weder .env, config/parameters.yaml noch system/config/localconfig.php wurden gefunden.")
    if not cfg.get("parsed"):
        return _np("Contao-Einstellungen", "Die Dateien ließen sich nicht lesen (andere Schreibweise oder beschädigt). Die Werte wurden nicht bewertet.")
    c = cfg.get("contao") or {}
    env, loc, yml = c.get("env") or {}, c.get("local") or {}, c.get("yaml") or {}
    out: List[Finding] = []
    if cfg.get("unexpected"):
        out.append(_f("crit", "In den Einstellungsdateien stehen auffällige Befehle", "Dort gehören nur Einstellungen hin. Befehle wie eval oder base64_decode sind ein typisches Zeichen für eine Manipulation.",
                      ["Zeile %s: %s" % (n, _clean(x, 160)) for n, x in cfg["unexpected"][:20]], "Datei mit einer Sicherung vergleichen, Zugangsdaten und APP_SECRET erneuern."))
    app_env = str(env.get("APP_ENV") or "").lower()
    if app_env in ("dev", "test"):
        out.append(_f("crit", "Contao läuft im Entwicklungsmodus (APP_ENV=%s)" % _clean(app_env, 20), "Im Entwicklungsmodus zeigt Contao Fehlerdetails, Profiler und Debug-Leiste; das verrät Pfade und Einstellungen.", [], "In der .env APP_ENV=prod setzen und den Cache leeren."))
    elif app_env and app_env != "prod":
        out.append(_f("warn", "APP_ENV ist nicht 'prod' (%s)" % _clean(app_env, 20), "Nur 'prod' ist der Betriebsmodus für Live-Seiten.", [], "APP_ENV=prod setzen."))
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
    if not str(env.get("TRUSTED_HOSTS") or "").strip() and not any("trusted_hosts" in k.lower() for k in yml):
        out.append(_f("info", "TRUSTED_HOSTS ist nicht gesetzt", "Ohne Einschränkung nimmt Contao Anfragen unter jedem Hostnamen an (gefälschte Links in E-Mails).", [], "TRUSTED_HOSTS in der .env auf die eigene Domain setzen."))
    elif str(env.get("TRUSTED_HOSTS") or "").strip() in (".*", "^.*$", "*"):
        out.append(_f("warn", "TRUSTED_HOSTS erlaubt jeden Hostnamen", "Der Wert schränkt nichts ein.", [], "Auf die eigene Domain setzen."))
    ut = [t.strip().lower() for t in re.split(r"[,\s]+", str(loc.get("uploadTypes") or "")) if t.strip()]
    badu = [t for t in ut if BAD_UPLOAD.match(t)]
    if badu:
        out.append(_f("crit", "Hochladen ausführbarer Dateitypen ist erlaubt", "In 'uploadTypes' stehen Typen, die auf dem Server ausgeführt werden können.", badu, "Diese Typen unter System > Einstellungen > Dateien aus der Liste der erlaubten Dateitypen entfernen."))
    at = str(loc.get("allowedTags") or "")
    if BAD_TAG.search(at):
        out.append(_f("warn", "In den erlaubten HTML-Tags stehen Skript-Elemente", "Redakteure (und übernommene Konten) können dann Skripte in Inhalte einbauen.", [], "script, iframe, object und embed aus 'allowedTags' entfernen."))
    try:
        mpl = int(str(loc.get("minPasswordLength") or "0"))
    except ValueError:
        mpl = 0
    if mpl and mpl < 8:
        out.append(_f("warn", "Die Mindestlänge für Passwörter ist zu kurz (%d)" % mpl, "Kurze Passwörter lassen sich leicht erraten.", [], "Mindestens 12 einstellen (minPasswordLength)."))
    if str(loc.get("displayErrors") or "").lower() in ("1", "true"):
        out.append(_f("warn", "Fehlermeldungen werden den Besuchern angezeigt (displayErrors)", "Meldungen verraten Pfade und Programmteile.", [], "displayErrors auf false setzen."))
    for name, mode in (modes or {}).items():
        m = re.match(r"^(\d{3,4})\b", mode or "")
        if not m:
            continue
        octal = m.group(1)[-3:]
        if int(octal[2]) & 2:
            out.append(_f("crit", "%s ist für alle beschreibbar (%s)" % (name, octal), "Jeder Benutzer des Servers kann sie ändern.", [], "Rechte auf 640 bzw. 644 (Datei) und 755 (Ordner) setzen."))
        elif int(octal[2]) & 4 and re.search(r"(^|/)\.env[^/]*$", name):
            out.append(_f("warn", "%s ist für alle lesbar (%s)" % (name, octal), "Die Datei enthält Zugangsdaten.", [], "Rechte auf 600 oder 640 setzen."))
    if not out:
        out.append(_f("ok", "Die Einstellungen sind unauffällig", "Keine auffälligen Befehle, Produktivmodus, Schlüssel gesetzt, keine riskanten Dateitypen."))
    return out


def judge_packages(inventory: Any, adv_hits: Any, checked: int = 0, adv_ok: bool = True) -> List[Finding]:
    """inventory: [{'key','name','version','pkg','custom'(bool),'dev'(bool)}] (Erweiterungen = alle Pakete außer contao/*, symfony/* usw. werden von der Prüfung vorsortiert);
    adv_hits: {Schlüssel: [Meldungen]} (nur zutreffende); checked: so viele Pakete wurden abgefragt."""
    if not isinstance(inventory, list):
        return _np("Contao-Erweiterungen", "Die Liste der Pakete fehlt oder ist unlesbar.")
    inv = [m for m in inventory if isinstance(m, dict) and m.get("key")]
    if not inv:
        return [_f("info", "Keine Pakete gefunden", "In composer.lock wurden keine Pakete gelesen.")]
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
        out.append(_f("warn", "%d Entwicklungs-Paket(e) liegen auf dem Live-Server" % len(dev), "Werkzeuge für Entwickler (Profiler, Tests) gehören nicht auf eine Live-Seite.", [lab(m) for m in dev], "Mit 'composer install --no-dev' neu installieren."))
    custom = [m for m in inv if m.get("custom")]
    if custom:
        out.append(_f("info", "%d eigene Paket(e) (lokale Pfade)" % len(custom), "Eigene Programme werden nicht mit Sicherheitsmeldungen verglichen.", [lab(m) for m in custom][:40]))
    ext = [m for m in inv if m.get("ext")]
    if ext:
        out.append(_f("info", "%d Contao-Erweiterung(en) installiert" % len(ext), "Erweiterungen sind der häufigste Weg für Angriffe; halten Sie sie aktuell.", [lab(m) for m in ext][:40]))
    if not adv_ok and checked:
        out.append(_f("info", "Sicherheitsmeldungen nicht prüfbar", "Packagist war nicht erreichbar oder lieferte nichts Lesbares.", [], "Später erneut prüfen."))
    if not (vuln or dev):
        out.append(_f("ok" if checked and adv_ok else "info", "Kein Paket mit bekannter Sicherheitslücke gefunden" if checked and adv_ok else "Es wurde kein Paket gegen Sicherheitsmeldungen geprüft",
                      "%d Paket(e) abgeglichen." % checked if checked else "Es lagen keine Paketnamen vor.", []))
    return out


def judge_users(rows: Any, now: Optional[float] = None) -> List[Finding]:
    """rows: [{'uid','name','admin'(bool),'disabled'(bool),'created_ts','access_ts','tf'(bool oder None)}] aus tl_user."""
    if not isinstance(rows, list):
        return _np("Contao-Backend-Konten", "Die Benutzerliste fehlt oder ist unlesbar.")
    now = now or time.time()
    us = [r for r in rows if isinstance(r, dict)]
    admins = [r for r in us if r.get("admin") and not r.get("disabled")]
    out: List[Finding] = []
    if not admins:
        out.append(_f("info", "Keine aktiven Administrator-Konten gefunden", "Die Abfrage lieferte keine Benutzer mit dem Administrator-Merkmal."))
    else:
        out.append(_f("info", "%d aktive(s) Administrator-Konto/Konten im Backend" % len(admins), "Administratoren dürfen Erweiterungen, Rechte und Inhalte ändern.",
                      ["%s (id %s)" % (_clean(str(r.get("name") or "?"), 60), r.get("uid")) for r in admins[:30]], "Nicht mehr gebrauchte Konten sperren."))
        if len(admins) > 5:
            out.append(_f("warn", "Auffällig viele Administrator-Konten (%d)" % len(admins), "Je mehr Administratoren, desto mehr Zugänge.", [], "Die meisten auf normale Redakteurs-Rechte zurückstufen."))
    fresh = [r for r in admins if isinstance(r.get("created_ts"), (int, float)) and now - r["created_ts"] < 14 * 86400]
    if fresh:
        out.append(_f("warn", "%d Administrator-Konto/Konten wurden in den letzten 14 Tagen angelegt" % len(fresh), "Nach einem Einbruch legen Angreifer gern ein neues Konto mit Administratorrechten an.",
                      [_clean(str(r.get("name") or "?"), 60) for r in fresh], "Prüfen, ob Sie oder Ihr Team das Konto angelegt haben. Wenn nicht: sperren und alle Passwörter ändern."))
    never = [r for r in admins if not r.get("access_ts")]
    if never:
        out.append(_f("info", "%d Administrator-Konto/Konten haben sich nie angemeldet" % len(never), "Ein nie benutztes Konto mit Administratorrechten ist unnötiges Risiko.", [_clean(str(r.get("name") or "?"), 60) for r in never], "Sperren oder Rechte entziehen."))
    notf = [r for r in admins if r.get("tf") is False]
    if notf:
        out.append(_f("warn", "%d Administrator-Konto/Konten ohne Zwei-Faktor-Anmeldung" % len(notf), "Mit Zwei-Faktor-Anmeldung hilft ein gestohlenes Passwort allein nicht.", [_clean(str(r.get("name") or "?"), 60) for r in notf][:30],
                      "Im Backend unter 'Mein Konto' die Zwei-Faktor-Anmeldung einschalten."))
    default = [r for r in admins if str(r.get("name") or "").lower() in ("admin", "administrator", "contao", "root", "test")]
    if default:
        out.append(_f("warn", "Administrator-Konto mit einem leicht zu erratenden Namen", "Namen wie admin werden bei Angriffen als Erstes durchprobiert.", [_clean(str(r.get("name") or "?"), 60) for r in default], "Konto umbenennen oder ein neues mit anderem Namen anlegen und das alte sperren."))
    return out


def judge_db_code(rows: Any) -> List[Finding]:
    """rows: [{'table','id','text'}]: gleiche Bewertung wie bei Drupal, mit Contao-Bezeichnung."""
    return _judge_db_code(rows, "Contao")


def judge_exposed(web: Any) -> List[Finding]:
    """web: [{'kind','label','url','status','body'}]; kind: file (darf nicht lesbar sein), dir, install (Install-Tool), manager (Contao Manager), profiler (Entwicklungs-Eingang), backend (nur Hinweis)."""
    if not isinstance(web, list):
        return _np("Abrufbare Contao-Dateien", "Die Abruf-Ergebnisse fehlen.")
    crit, warn, info = [], [], []
    for r in web:
        if not isinstance(r, dict) or r.get("status") != 200:
            continue
        body = str(r.get("body") or "")
        lab = "%s: %s" % (_clean(str(r.get("label") or "?"), 70), _clean(str(r.get("url") or ""), 160))
        k = r.get("kind")
        low = body.lstrip().lower()
        if k == "file":
            if body.strip() and not low.startswith(("<!", "<html")) and re.search(r"<\?php|APP_SECRET|DATABASE_URL|TL_CONFIG|\"require\"|\"packages\"|APP_ENV|database_password|\[core\]", body):
                crit.append(lab + " ist abrufbar")
        elif k == "dir":
            if re.search(r"<title>Index of|Parent Directory", body):
                warn.append(lab + " zeigt eine öffentliche Ordnerliste")
        elif k == "install":
            if re.search(r"Contao Install Tool|install tool|Installations-Tool", body, re.I):
                warn.append(lab + " ist erreichbar (Install-Tool)")
        elif k == "manager":
            if re.search(r"Contao Manager|contao-manager", body, re.I):
                warn.append(lab + " ist erreichbar (Contao Manager)")
        elif k == "profiler":
            if re.search(r"Symfony Profiler|sf-toolbar|app_dev|Web Debug|Contao.*(dev|debug)", body, re.I):
                crit.append(lab + " ist erreichbar (Entwicklungs-Eingang)")
        elif k == "backend":
            info.append(lab + " ist erreichbar")
    out: List[Finding] = []
    if crit:
        out.append(_f("crit", "%d Datei(en) oder Seite(n) sind frei abrufbar" % len(crit), "Einstellungen, Zugangsdaten oder Entwicklungs-Werkzeuge dürfen von außen nicht zu erreichen sein.", crit,
                      "Zugriff im Webserver sperren (nur der Ordner public/ gehört ins Web) und Zugriffe in den Protokollen prüfen."))
    if warn:
        out.append(_f("warn", "%d Adresse(n) sollten von außen nicht offen sein" % len(warn), "Install-Tool und Contao Manager sind Verwaltungswerkzeuge; Ordnerlisten zeigen, welche Dateien dort liegen.", warn,
                      "Nach der Arbeit die Datei bzw. den Zugang entfernen oder auf eigene Adressen beschränken; Ordnerlisten abschalten (Options -Indexes)."))
    if info:
        out.append(_f("info", "Die Backend-Anmeldung ist öffentlich erreichbar", "Das ist normal. Zusätzlicher Schutz (Zugriff nur von bestimmten Adressen, Zwei-Faktor-Anmeldung) senkt das Risiko von Passwort-Versuchen.", info))
    if not (crit or warn):
        out.append(_f("ok", "Keine der geprüften Dateien und Seiten ist frei abrufbar", "%d Adresse(n) geprüft." % len([r for r in web if isinstance(r, dict)])))
    return out
