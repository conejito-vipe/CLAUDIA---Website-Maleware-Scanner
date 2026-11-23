"""Bewertung der WooCommerce-Prüfungen (2.7.0): reine Funktionen ohne Server- oder Datenbankzugriff, mit Beispieldaten prüfbar.

Jede Funktion bekommt einfache Wörterbücher/Listen und liefert Funde als (Stufe, Titel, Text, Einträge, Hinweis). Unbrauchbare Eingaben ergeben genau einen Info-Fund 'nicht prüfbar', nie eine geratene Aussage.
Geheimnisse: Schlüssel, Geheimwörter und Zugangsdaten der Zahlungsanbieter werden hier nie gelesen und nie ausgegeben; es zählen nur Namen, Rechte, Zeiten und Adressen."""
from __future__ import annotations

import re
import time
from typing import Any, List, Optional, Tuple
from urllib.parse import urlparse

from ..util import host_allowed
from .auswertung_joomla import _clean, _f, _np, _to_int  # gleiche Säuberung und Form wie die übrigen Bewertungen

Finding = Tuple[str, str, str, List[str], str]

# Adressen, die zum Auffangen von Daten dienen (Test-Dienste, Tunnel); an solche gehören keine Bestell- oder Kundendaten
CATCHER_HOSTS = ["webhook.site", "requestbin.com", "requestbin.net", "pipedream.net", "ngrok.io", "ngrok-free.app", "ngrok.app", "trycloudflare.com", "interact.sh", "oast.fun", "oast.pro",
                 "oast.live", "oast.site", "oast.online", "burpcollaborator.net", "requestcatcher.com", "beeceptor.com", "hookbin.com", "mockbin.org", "serveo.net", "localhost.run", "loca.lt"]
# Automatisierungsdienste, an die Shops Bestelldaten schicken dürfen. Nur Adressen, deren Aufbau in der offiziellen Dokumentation des Anbieters steht (geprüft 17.11.2026):
#   Zapier: hooks.zapier.com (help.zapier.com), Slack: hooks.slack.com (docs.slack.dev), Make: hook.make.com (apps.make.com/gateway; regionale Adressen hook.<region>.make.com sind dort nicht beschrieben, werden aber wegen des gleichen Aufbaus mitgenommen).
# Wichtig: Diese Adressen sind Sammelstellen vieler Kunden. Dass ein Webhook dort hingeht, sagt nicht, dass das Konto Ihnen gehört; deshalb gibt es dafür nur einen Hinweis, kein stilles 'in Ordnung'.
SERVICE_HOSTS = {"hooks.zapier.com": "Zapier", "hooks.slack.com": "Slack", "hook.make.com": "Make"}
# Themen, bei denen Kunden- oder Bestelldaten gesendet werden
SENSITIVE_TOPIC = re.compile(r"^(order|customer|coupon)\.", re.I)
KNOWN_GATEWAYS = {"bacs", "cheque", "cod", "paypal", "ppcp-gateway", "stripe", "stripe_sepa", "stripe_ideal", "stripe_sofort", "stripe_klarna", "stripe_giropay", "klarna_payments",
                  "mollie_wc_gateway_creditcard", "mollie_wc_gateway_ideal", "mollie_wc_gateway_paypal", "mollie_wc_gateway_banktransfer", "germanized_direct_debit", "woocommerce_payments",
                  "square_credit_card", "amazon_payments_advanced", "payone", "ppec_paypal", "eway", "authorize_net_cim_credit_card", "braintree_credit_card", "wc_gateway_payone", "sumup",
                  "invoice", "germanized_invoice", "sepa", "wc_sepa", "applepay", "googlepay", "ppcp", "ppcp-credit-card-gateway", "ppcp-card-button-gateway", "paypal_plus", "sofort", "giropay"}
TEST_KEYS = ("testmode", "test_mode", "sandbox", "test", "is_test", "testmodus", "sandbox_mode", "enable_test_mode")
BAD_MARKUP = re.compile(r"<\s*script|javascript\s*:|onerror\s*=|onload\s*=|eval\s*\(|atob\s*\(|fromCharCode|document\.write", re.I)
PHP_STR = r's:\d+:"%s";s:\d+:"((?:[^"\\]|\\.)*)";'


def php_value(text: Any, key: str) -> Optional[str]:
    """Text-Wert zu einem Schlüssel aus einem serialisierten PHP-Feld (a:..:{s:7:"enabled";s:3:"yes";}); None, wenn nicht vorhanden."""
    if not isinstance(text, str):
        return None
    m = re.search(PHP_STR % re.escape(key), text)
    return m.group(1) if m else None


def php_strings(text: Any) -> List[str]:
    """Alle Text-Werte (jeder zweite Text) eines serialisierten PHP-Feldes, für die Suche nach eingeschleustem Code."""
    if not isinstance(text, str):
        return []
    return [m.group(1) for m in re.finditer(r's:\d+:"((?:[^"\\]|\\.)*)";', text)]


def _ver(v: Any) -> Optional[Tuple[int, ...]]:
    if not isinstance(v, str):
        return None
    m = re.match(r"\s*(\d+)(?:\.(\d+))?(?:\.(\d+))?", v)
    if not m:
        return None
    return tuple(int(x) if x else 0 for x in m.groups())


def _yes(v: Any) -> bool:
    return isinstance(v, str) and v.strip().lower() in ("yes", "1", "true", "on")


# ------------------------------------------------------------------ Überblick
def judge_overview(info: Any) -> List[Finding]:
    """info: {'installed': bool, 'active': bool, 'version': str, 'db_version': str, 'ordner': str}."""
    if not isinstance(info, dict):
        return _np("WooCommerce-Überblick", "Es liegen keine lesbaren Angaben vor.")
    if not info.get("installed"):
        return []
    out: List[Finding] = []
    ver = _clean(str(info.get("version") or ""), 30) or "unbekannt"
    if not info.get("active"):
        out.append(_f("info", "WooCommerce ist installiert, aber nicht aktiv",
                      "Version %s. Ein ausgeschaltetes Plugin liefert keinen Shop aus, bleibt aber auf dem Server und kann eine alte Sicherheitslücke behalten." % ver, [],
                      "Wird der Shop nicht mehr gebraucht, das Plugin im Backend löschen (vorher Sicherung anlegen)."))
        return out
    out.append(_f("ok", "WooCommerce ist aktiv", "Version %s." % ver))
    pv, dv = _ver(info.get("version")), _ver(info.get("db_version"))
    if pv and dv and dv[:2] < pv[:2]:
        out.append(_f("warn", "Das Datenbank-Update von WooCommerce steht aus",
                      "Das Plugin hat Version %s, die Datenbank meldet erst %s. Ein angefangenes oder abgebrochenes Update lässt Fehler und Sicherheitsfunktionen unvollständig." % (ver, _clean(str(info.get("db_version")), 30)),
                      [], "Im Backend unter WooCommerce > Status das Datenbank-Update ausführen (vorher Sicherung anlegen)."))
    elif not dv:
        out.append(_f("info", "Datenbank-Version von WooCommerce nicht lesbar", "Der Eintrag woocommerce_db_version fehlt. Das ist bei frischen oder halb eingerichteten Shops möglich."))
    return out


# ------------------------------------------------------------------ Benutzer mit Shop-Rechten
def judge_shop_managers(rows: Any, now: Optional[float] = None) -> List[Finding]:
    """rows: [{'login','registered_ts'(Sekunden oder None),'role'}], Rollen shop_manager und customer-fremde Rollen."""
    if not isinstance(rows, list):
        return _np("Shop-Manager", "Die Benutzerliste fehlt oder ist unlesbar.")
    now = now or time.time()
    mans = [r for r in rows if isinstance(r, dict) and r.get("role") == "shop_manager"]
    if not mans:
        return [_f("ok", "Keine Konten mit der Rolle Shop-Manager", "Nur Administratoren verwalten den Shop.")]
    out: List[Finding] = []
    fresh = [r for r in mans if isinstance(r.get("registered_ts"), (int, float)) and now - r["registered_ts"] < 14 * 86400]
    names = [_clean(str(r.get("login") or "?"), 60) for r in mans]
    out.append(_f("info", "%d Konto/Konten mit der Rolle Shop-Manager" % len(mans),
                  "Shop-Manager dürfen Bestellungen, Kundendaten, Produkte und Zahlungseinstellungen ändern und andere Konten verwalten.", names,
                  "Nicht mehr gebrauchte Konten entfernen. Jedes Konto braucht ein eigenes, langes Passwort."))
    if fresh:
        out.append(_f("warn", "%d Shop-Manager-Konto/Konten wurden in den letzten 14 Tagen angelegt" % len(fresh),
                      "Nach einem Einbruch legen Angreifer gern ein neues Konto mit weitreichenden Rechten an.",
                      [_clean(str(r.get("login") or "?"), 60) for r in fresh], "Prüfen, ob Sie oder jemand aus Ihrem Team diese Konten angelegt haben. Wenn nicht: sperren und Passwörter ändern."))
    return out


# ------------------------------------------------------------------ API-Schlüssel
def judge_api_keys(rows: Any, now: Optional[float] = None) -> List[Finding]:
    """rows: [{'description','permissions','last_access_ts' (Sekunden oder None),'owner' (Anmeldename oder None)}]. Schlüssel und Geheimwörter werden nie gelesen."""
    if not isinstance(rows, list):
        return _np("WooCommerce-API-Schlüssel", "Die Liste der Schlüssel fehlt oder ist unlesbar.")
    now = now or time.time()
    keys = [r for r in rows if isinstance(r, dict)]
    if not keys:
        return [_f("ok", "Keine API-Schlüssel angelegt", "Es kann sich keine fremde Anwendung per WooCommerce-Schnittstelle anmelden.")]
    out: List[Finding] = []

    def name(r) -> str:
        return "%s (%s)" % (_clean(str(r.get("description") or "ohne Namen"), 70), _clean(str(r.get("permissions") or "?"), 20))

    write = [r for r in keys if str(r.get("permissions") or "").lower() in ("read_write", "write")]
    never = [r for r in keys if not isinstance(r.get("last_access_ts"), (int, float))]
    old = [r for r in keys if isinstance(r.get("last_access_ts"), (int, float)) and now - r["last_access_ts"] > 180 * 86400]
    orphan = [r for r in keys if r.get("owner") in (None, "") and "owner" in r]
    recent_w = [r for r in write if isinstance(r.get("last_access_ts"), (int, float)) and now - r["last_access_ts"] <= 180 * 86400]
    if orphan:
        out.append(_f("warn", "%d API-Schlüssel gehören zu einem Konto, das es nicht mehr gibt" % len(orphan),
                      "Ein Schlüssel ohne Besitzer ist verwaist und wird von niemandem mehr betreut.", [name(r) for r in orphan],
                      "Im Backend unter WooCommerce > Einstellungen > Erweitert > REST-API widerrufen."))
    if never:
        out.append(_f("warn", "%d API-Schlüssel wurden nie benutzt" % len(never),
                      "Nie benutzte Schlüssel sind Ballast; werden sie später entwendet, fällt der Missbrauch nicht auf.", [name(r) for r in never],
                      "Widerrufen, was Sie nicht kennen oder nicht brauchen."))
    if old:
        out.append(_f("warn", "%d API-Schlüssel sind seit mehr als 180 Tagen unbenutzt" % len(old), "", [name(r) for r in old], "Widerrufen, wenn die Anwendung nicht mehr genutzt wird."))
    if recent_w:
        out.append(_f("info", "%d API-Schlüssel mit Schreibrecht sind in Benutzung" % len(recent_w),
                      "Mit einem Schlüssel mit Schreibrecht lassen sich Bestellungen, Produkte und Preise verändern.", [name(r) for r in recent_w],
                      "Nur dort Schreibrecht lassen, wo es die Anwendung wirklich braucht; sonst auf 'Lesen' stellen (neuen Schlüssel anlegen, alten widerrufen)."))
    if not (orphan or never or old or recent_w):
        out.append(_f("ok", "%d API-Schlüssel, alle in jüngerer Zeit benutzt und nur lesend" % len(keys), "", [name(r) for r in keys]))
    return out


# ------------------------------------------------------------------ Webhooks
def service_of(host: str) -> str:
    """Name des Automatisierungsdienstes zu einer Adresse, sonst ''. Make: hook.make.com und hook.<region>.make.com."""
    if host in SERVICE_HOSTS:
        return SERVICE_HOSTS[host]
    if re.fullmatch(r"hook\.[a-z0-9-]+\.make\.com", host):
        return "Make"
    return ""


def _host_of(url: Any) -> str:
    try:
        return (urlparse(str(url or "").strip()).hostname or "").lower()
    except ValueError:
        return ""


def judge_webhooks(rows: Any, own_host: str = "", allow: Optional[List[str]] = None) -> List[Finding]:
    """rows: [{'name','status','topic','url','failure_count'}]. Meldet aktive Webhooks, die Bestell- oder Kundendaten an fremde Adressen senden."""
    if not isinstance(rows, list):
        return _np("WooCommerce-Webhooks", "Die Liste der Webhooks fehlt oder ist unlesbar.")
    hooks = [r for r in rows if isinstance(r, dict)]
    if not hooks:
        return [_f("ok", "Keine Webhooks eingerichtet", "WooCommerce schickt keine Bestell- oder Kundendaten automatisch an andere Adressen.")]
    allow_l = list(allow or []) + ([own_host] if own_host else [])
    out: List[Finding] = []
    crit, warn, plain, quiet, svc = [], [], [], [], []
    for r in hooks:
        host = _host_of(r.get("url"))
        topic = str(r.get("topic") or "")
        label = "%s: %s -> %s" % (_clean(str(r.get("name") or "ohne Namen"), 50), _clean(topic, 40) or "?", _clean(host or str(r.get("url") or "?"), 80))
        if str(r.get("status") or "").lower() != "active":
            quiet.append(label)
            continue
        scheme = str(r.get("url") or "").strip().lower()[:8]
        sv = service_of(host)
        if sv and not host_allowed(host, allow_l):
            if scheme.startswith("http:") and SENSITIVE_TOPIC.match(topic):
                plain.append(label)
            elif SENSITIVE_TOPIC.match(topic):
                svc.append("%s (%s)" % (label, sv))
            continue
        if host and (host_allowed(host, CATCHER_HOSTS) or re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host)):
            crit.append(label)
        elif not host:
            warn.append(label + " (Adresse unlesbar)")
        elif SENSITIVE_TOPIC.match(topic) and not host_allowed(host, allow_l):
            warn.append(label)
        elif scheme.startswith("http:") and SENSITIVE_TOPIC.match(topic):
            plain.append(label)
    if crit:
        out.append(_f("crit", "%d aktive(r) Webhook(s) senden an eine Auffang-Adresse oder eine reine IP-Adresse" % len(crit),
                      "Das sind Adressen von Test- und Tunneldiensten oder ohne Namen. An solche gehören keine Kundendaten; so lassen sich Bestellungen unbemerkt abgreifen.", crit,
                      "Webhook sofort deaktivieren (WooCommerce > Einstellungen > Erweitert > Webhooks) und prüfen, wer ihn angelegt hat. Dann Zugänge und API-Schlüssel erneuern."))
    if warn:
        out.append(_f("warn", "%d aktive(r) Webhook(s) senden Bestell- oder Kundendaten an fremde Adressen" % len(warn),
                      "Das kann gewollt sein (Buchhaltung, Versand). Prüfen Sie, ob Sie den Empfänger kennen.", warn,
                      "Unbekannte Empfänger entfernen. Bekannte Empfänger in den erlaubten Adressen von CLAUDIA eintragen, dann erscheint die Meldung nicht mehr."))
    if plain:
        out.append(_f("warn", "%d Webhook(s) senden unverschlüsselt (http)" % len(plain), "Bestell- und Kundendaten laufen im Klartext durchs Netz.", plain, "Adresse auf https umstellen."))
    if svc:
        out.append(_f("info", "%d aktive(r) Webhook(s) senden Bestell- oder Kundendaten an einen Automatisierungsdienst" % len(svc),
                      "Zapier, Make und Slack sind bekannte Dienste, aber ihre Adressen gehören vielen Kunden. Prüfen Sie, ob das Konto dort Ihnen oder Ihrem Dienstleister gehört.", svc,
                      "Unbekannte Webhooks entfernen. Gehört das Konto Ihnen, tragen Sie die Adresse unter den erlaubten Adressen ein, dann erscheint der Hinweis nicht mehr."))
    if quiet:
        out.append(_f("info", "%d Webhook(s) sind ausgeschaltet oder pausiert" % len(quiet), "", quiet, "Nicht mehr gebrauchte löschen."))
    if not (crit or warn or plain or svc):
        out.append(_f("ok", "Alle aktiven Webhooks gehen an bekannte Adressen", "%d Webhook(s) geprüft." % len(hooks)))
    return out


# ------------------------------------------------------------------ Zahlungsarten
def judge_gateways(gateways: Any) -> List[Finding]:
    """gateways: [{'id','enabled'(Text),'raw'(serialisierter Text der Einstellungen)}]; Geheimwörter werden nur im Rohtext nach Schadcode durchsucht, nicht ausgegeben."""
    if not isinstance(gateways, list):
        return _np("Zahlungsarten", "Die Einstellungen der Zahlungsarten fehlen oder sind unlesbar.")
    gw = [g for g in gateways if isinstance(g, dict) and isinstance(g.get("id"), str)]
    if not gw:
        return [_f("info", "Keine Einstellungen von Zahlungsarten gefunden", "Entweder ist noch keine Zahlungsart eingerichtet oder die Einträge heißen anders.")]
    out: List[Finding] = []
    bad, test, unknown, on = [], [], [], []
    for g in gw:
        gid = _clean(g["id"], 60)
        raw = g.get("raw") or ""
        enabled = _yes(g.get("enabled")) or _yes(php_value(raw, "enabled"))
        if BAD_MARKUP.search("\n".join(php_strings(raw))):
            bad.append(gid)
        if enabled:
            on.append(gid)
            if any(_yes(php_value(raw, k)) for k in TEST_KEYS):
                test.append(gid)
            if gid not in KNOWN_GATEWAYS and not gid.startswith(("stripe", "mollie", "ppcp", "paypal", "klarna", "wc_", "germanized")):
                unknown.append(gid)
    if bad:
        out.append(_f("crit", "In den Einstellungen von %d Zahlungsart(en) steht Programmcode" % len(bad),
                      "Titel, Beschreibung oder Hinweistexte einer Zahlungsart enthalten <script>, javascript: oder ähnlichen Code. Das ist ein bekannter Weg, Kartendaten im Bezahlvorgang abzugreifen.", bad,
                      "Eintrag im Backend (WooCommerce > Einstellungen > Zahlungen) bereinigen, danach alle Passwörter und Schlüssel erneuern und den Bezahlvorgang auf fremde Skripte prüfen (siehe Skimmer-Prüfung)."))
    if test:
        out.append(_f("warn", "%d eingeschaltete Zahlungsart(en) laufen im Testmodus" % len(test),
                      "Im Testmodus wird nicht gezahlt: Kunden bekommen Ware ohne Zahlungseingang, oder Zahlungen verfallen.", test, "Testmodus beim Anbieter-Plugin ausschalten, sobald der Shop Kunden bedient."))
    if unknown:
        out.append(_f("info", "%d eingeschaltete Zahlungsart(en) sind CLAUDIA nicht bekannt" % len(unknown),
                      "Das ist bei Plugins kleiner Anbieter normal. Prüfen Sie, ob Sie das Plugin selbst eingerichtet haben.", unknown))
    if on and not (bad or test):
        out.append(_f("ok", "%d Zahlungsart(en) eingeschaltet, keine Auffälligkeiten" % len(on), "", on))
    elif not on and not bad:
        out.append(_f("info", "Keine Zahlungsart eingeschaltet", "Der Shop kann derzeit keine Zahlungen annehmen."))
    return out


# ------------------------------------------------------------------ Abrufbare Daten
def judge_exposed(web: Any, logs_listed: Any = None) -> List[Finding]:
    """web: [{'label','url','status','body'}] Ergebnis der Web-Abrufe; logs_listed: Anzahl Protokolldateien im Ordner wc-logs (oder None)."""
    if not isinstance(web, list):
        return _np("Abrufbare Shop-Daten", "Die Abruf-Ergebnisse fehlen.")
    crit, warn = [], []
    for r in web:
        if not isinstance(r, dict) or r.get("status") != 200:
            continue
        body = str(r.get("body") or "")
        lab = "%s: %s" % (_clean(str(r.get("label") or "?"), 80), _clean(str(r.get("url") or ""), 160))
        kind = r.get("kind")
        if kind == "api":     # Schnittstelle liefert Daten ohne Anmeldung
            if body.lstrip().startswith("[") and len(body.strip()) > 4:
                crit.append(lab + " liefert Daten ohne Anmeldung")
        elif kind == "dir":
            if re.search(r"<title>Index of|Parent Directory", body):
                warn.append(lab + " zeigt eine öffentliche Ordnerliste")
        elif kind == "file":
            if body.strip() and not body.lstrip().startswith("<"):     # eine Fehlerseite mit Status 200 ist keine Datei
                crit.append(lab + " ist abrufbar")
    out: List[Finding] = []
    if crit:
        out.append(_f("crit", "%d Shop-Datei(en) oder Schnittstelle(n) sind ohne Anmeldung abrufbar" % len(crit),
                      "Protokolle und Schnittstellen eines Shops enthalten Namen, Adressen, E-Mail-Adressen und Bestelldaten Ihrer Kunden. Das ist auch ein Datenschutzvorfall.", crit,
                      "Datei oder Ordner sofort sperren (.htaccess mit 'Require all denied' bzw. Regel im Webserver) und die Zugriffe in den Protokollen auf fremde Abrufe prüfen."))
    if warn:
        out.append(_f("warn", "%d Shop-Ordner zeigen eine öffentliche Ordnerliste" % len(warn), "Besucher sehen, welche Dateien dort liegen.", warn,
                      "Ordnerlisten abschalten (Options -Indexes in der .htaccess) bzw. Ordner sperren."))
    if not (crit or warn):
        out.append(_f("ok", "Protokolle und Schnittstellen des Shops sind nicht frei abrufbar", "%d Adresse(n) geprüft." % len([r for r in web if isinstance(r, dict)])))
    n = _to_int(logs_listed)
    if n is not None and n > 200:
        out.append(_f("info", "Im Ordner wc-logs liegen %d Protokolle" % n, "Alte Protokolle enthalten oft Kundendaten und sollten nicht ewig liegen bleiben.", [],
                      "Im Backend unter WooCommerce > Status > Protokolle aufräumen und die Aufbewahrung kürzen."))
    return out
