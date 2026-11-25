"""Laufen die automatischen Updates wirklich? (Joomla ab 5.4, WordPress)

Rein lesend. Die Prüfung 'Lässt sich die Seite automatisch aktualisieren?' (update_ready) beantwortet, ob ein Update im Backend gelingt: Rechte, Platz, PHP.
Das sagt nichts darüber, ob die AUTOMATIK läuft. Bei Joomla 5.4 und neuer meldet sich die Seite beim Update-Dienst von joomla.org an, und dieser Dienst stößt die
Updates über die Programmierschnittstelle (API) der Seite an. Dafür müssen Einstellung, API-Plugins, Update-Quelle und Erreichbarkeit von außen stimmen; eine Firewall,
die Anfragen ohne Browser-Kennung oder den Ordner /api sperrt, verhindert die Automatik, ohne dass ein Update im Backend gestört wäre.
Bei WordPress hängt die Automatik am WP-Cron (Zeitplan der Seite): er muss laufen, und wp-cron.php darf nicht gesperrt sein.
Alles hier ist nur lesend; die einzigen Abfragen von außen sind einzelne Aufrufe der eigenen Seite (nur Statuscode und Kopfzeilen)."""
from __future__ import annotations

import json
import os
import re
import time
from typing import Any, Dict, List, Optional, Tuple

from .. import joomla
from ..registry import check
from ..util import clean_line, digits, lines_of, split_sections, sq, trunc, vcmp
from .database import fetch
from .security_ext import detect_tools, load_tools

G = "grundlagen"
MIN_JOOMLA = "5.4.0"
BROWSER_UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
SECRET_KEY = re.compile(r"(?i)token|secret|passw|pass$|salt|licen[sc]e|apikey|api_key|private|credential|download_?id|dlid|key$")
RELEVANT_KEY = re.compile(r"(?i)api|updat|webservice|bot|agent|user_?agent|country|geo|block|ban|white|allow|black|deny|rate|limit|rest|header|firewall|waf|request")
HOST_RE = re.compile(r"^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?\Z")
IDENT_RE = re.compile(r"^[A-Za-z0-9_]{1,64}\Z")
STABLE = {"4", "stable"}

Q_JOOMLAUPDATE = ("Einstellungen von Joomla-Update", "SELECT LEFT(params, 4000) AS p FROM #__extensions WHERE type = 'component' AND element = 'com_joomlaupdate'")
Q_API = ("API-Plugins", "SELECT folder, element, enabled FROM #__extensions WHERE type = 'plugin' AND (folder = 'webservices' OR folder = 'api-authentication' OR (folder = 'user' AND element = 'token')) ORDER BY folder, element")
Q_SITES = ("Update-Quellen", "SELECT name, location, enabled, last_check_timestamp AS ts FROM #__update_sites WHERE location LIKE '%update.joomla.org%' OR name LIKE 'Joomla%' LIMIT 10")
Q_CORE = ("Bereitliegendes Kern-Update", "SELECT version FROM #__updates WHERE element = 'joomla' AND type = 'file' LIMIT 20")
Q_LOG = ("Zuletzt protokollierte Updates", "SELECT log_date AS d, LEFT(message, 220) AS m FROM #__action_logs WHERE extension = 'com_joomlaupdate' ORDER BY id DESC LIMIT 5")


def parse_params(text: str) -> Dict[str, Any]:
    try:
        v = json.loads(text) if text and text.strip() else {}
    except ValueError:
        return {}
    return v if isinstance(v, dict) else {}


def curl_block(label: str, host: str, path: str, ua: str = "") -> str:
    """Ein Aufruf der eigenen Seite (nur Statuscode und Kopfzeilen, kein Inhalt)."""
    url = "https://%s%s" % (host, path)
    uas = ("-A %s " % sq(ua)) if ua else ""
    return ("echo '@@%s'\ncurl -s -m 12 -o /dev/null -D - %s%s 2>/dev/null | tr -d '\\r' | grep -iE '^(HTTP/|content-type:|server:|cf-ray:|www-authenticate:|x-sucuri|x-firewall|x-waf)' | head -8\n"
            % (label, uas, sq(url)))


def parse_probe(text: str) -> Dict[str, str]:
    code, ctype, server, cf = "", "", "", ""
    for ln in lines_of(text):
        low = ln.lower()
        m = re.match(r"^http/\S+\s+(\d{3})", low)
        if m:
            code = m.group(1)
        elif low.startswith("content-type:"):
            ctype = low.split(":", 1)[1].strip()
        elif low.startswith("server:"):
            server = ln.split(":", 1)[1].strip()
        elif low.startswith("cf-ray:"):
            cf = "ja"
    return {"code": code or "000", "ctype": ctype, "server": server, "cloudflare": cf or ("ja" if "cloudflare" in server.lower() else "")}


def probe_blocked(p: Dict[str, str]) -> bool:
    """True, wenn die Antwort NICHT von Joomla selbst kommt, sondern von etwas davor (Firewall, Webserver-Regel): Fehlercode mit HTML statt JSON."""
    if p["code"] in ("000", ""):
        return False                                   # nicht erreichbar ist etwas anderes als gesperrt
    if "json" in p["ctype"]:
        return False
    return p["code"] in ("401", "403", "406", "418", "429", "451", "503") or p["code"].startswith("5")


def api_state(plugs: List[Dict[str, Any]]) -> Dict[str, Any]:
    on = {"%s/%s" % (p.get("folder"), p.get("element")): str(p.get("enabled")) == "1" for p in plugs}
    web = [k for k, v in on.items() if k.startswith("webservices/") and v]
    updplug = on.get("webservices/joomlaupdate")
    auth = [k for k, v in on.items() if k.startswith("api-authentication/") and v]
    return {"items": ["%s: %s" % (k, "an" if v else "aus") for k, v in sorted(on.items())], "web_on": web, "update_plugin": updplug, "auth_on": auth, "any": bool(plugs)}


def fw_params(rows: List[Dict[str, Any]]) -> List[str]:
    """Einstellungen von Firewall-Erweiterungen, die für den Update-Dienst wichtig sein können. Geheimnisse werden nicht gezeigt."""
    out: List[str] = []
    for r in rows:
        data = parse_params(str(r.get("p") or ""))
        flat: List[Tuple[str, str]] = []

        def walk(prefix: str, v: Any, depth: int = 0) -> None:
            if depth > 3 or len(flat) > 400:
                return
            if isinstance(v, dict):
                for k, x in v.items():
                    walk(prefix + "." + str(k) if prefix else str(k), x, depth + 1)
            elif isinstance(v, list):
                flat.append((prefix, ", ".join(str(x) for x in v[:12])))
            else:
                flat.append((prefix, str(v)))
        walk("", data)
        for k, v in flat:
            if not RELEVANT_KEY.search(k):
                continue
            if SECRET_KEY.search(k):
                v = "(nicht angezeigt)"
            out.append("%s (%s): %s = %s" % (clean_line(str(r.get("element"))), clean_line(str(r.get("type"))), clean_line(k)[:70], clean_line(v)[:90]))
            if len(out) >= 60:
                return out
    return out


def fw_log_hits(ctx, db, patterns: List[str]) -> List[str]:
    """Sucht in den Protokoll-Tabellen der Firewall-Erweiterungen Zeilen, die /api oder den Update-Dienst nennen. Nur Zählung und wenige Beispiele (IP-Adressen maskiert)."""
    pats = [p for p in patterns if IDENT_RE.match(p)]
    if not pats:
        return []
    cond = " OR ".join("table_name LIKE '%%%s%%'" % p for p in pats)
    tabs = fetch(db, "SELECT table_name AS t FROM information_schema.tables WHERE table_schema = DATABASE() AND (%s) LIMIT 40" % cond) or []
    names = [str(t.get("t")) for t in tabs if IDENT_RE.match(str(t.get("t")))]
    logs = [n for n in names if re.search(r"(?i)log|block|ban|event|request|hit|attack|incident", n)]
    out: List[str] = []
    for t in logs[:6]:
        cols = fetch(db, "SELECT column_name AS c FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = '%s' AND data_type IN ('varchar','char','text','tinytext','mediumtext','longtext') LIMIT 8" % t) or []
        cn = [str(c.get("c")) for c in cols if IDENT_RE.match(str(c.get("c")))]
        if not cn:
            continue
        where = " OR ".join("`%s` LIKE '%%/api/%%' OR `%s` LIKE '%%api/index.php%%' OR `%s` LIKE '%%autoupdate%%' OR `%s` LIKE '%%joomlaupdate%%'" % (c, c, c, c) for c in cn)
        try:
            n = fetch(db, "SELECT COUNT(*) AS n FROM `%s` WHERE %s" % (t, where)) or []
            cnt = int(n[0].get("n") or 0) if n else 0
            if not cnt:
                out.append("%s: keine Einträge, die /api oder den Update-Dienst nennen" % t)
                continue
            smp = fetch(db, "SELECT LEFT(CONCAT_WS(' | ', %s), 220) AS s FROM `%s` WHERE %s LIMIT 4" % (", ".join("`%s`" % c for c in cn[:5]), t, where)) or []
            out.append("%s: %d Eintrag/Einträge nennen /api oder den Update-Dienst" % (t, cnt))
            out += ["    Beispiel: " + trunc(ctx.mask(clean_line(str(s.get("s")))), 200) for s in smp]
        except Exception as e:                                       # noqa: BLE001  (fremde Tabelle mit unerwartetem Aufbau: überspringen)
            out.append("%s: nicht lesbar (%s)" % (t, type(e).__name__))
    return out


@check(
    "auto_updates", G, "Laufen die automatischen Updates wirklich?",
    "Ist die Update-Automatik eingeschaltet, erreichbar und durch nichts gebremst (Joomla: API, Update-Quelle, Firewall; WordPress: Cron)?",
    what="Joomla ab 5.4: liest die Einstellung 'Automatische Updates' und die Update-Quelle, prüft die API-Plugins, die der Update-Dienst von joomla.org braucht, ob die Update-Quelle eingeschaltet ist, "
         "ob ein Kern-Update bereitliegt, das nicht installiert wurde, und ruft den Ordner /api der eigenen Seite einmal mit und einmal ohne Browser-Kennung auf (nur Statuscode und Art der Antwort). "
         "Erkennt eine Firewall-Erweiterung (z. B. HTProtect, Admin Tools) und zeigt deren Einstellungen und Protokoll-Einträge zu /api. WordPress: prüft den WP-Cron (läuft er? ist wp-cron.php erreichbar?) und "
         "Versionsverwaltung im Ordner, die Updates unterbindet.",
    why="Eine Seite kann sich im Backend problemlos aktualisieren lassen und trotzdem nie von selbst aktualisiert werden: Der Update-Dienst von Joomla erreicht die API nicht, eine Firewall sperrt ihn, "
        "die API-Plugins sind aus (zum Beispiel nach 'API abschalten') oder die Update-Quelle ist umgestellt. Dann bleibt die Seite wochenlang auf einem verwundbaren Stand, ohne dass etwas auffällt. "
        "Bei WordPress laufen Hintergrund-Updates nur, wenn der WP-Cron läuft.",
    reads="Nur Einstellungen und Status aus der Datenbank (bei Firewall-Erweiterungen nur Einstellungsnamen mit Bezug zu API und Updates, nie Schlüssel) und einzelne Aufrufe der eigenen Seite "
          "(Statuscode, Art der Antwort, Server-Kennung). Nichts wird verändert. Nicht prüfbar von hier: ob joomla.org die Seite erreicht und ob die Anmeldung beim Update-Dienst gültig ist.",
    load="leicht", presets=["schnell", "hack"],
    wp={"title": "Laufen die automatischen Updates wirklich? (WordPress-Cron)",
        "summary": "Läuft der WP-Cron, der die Hintergrund-Updates auslöst, und ist wp-cron.php erreichbar?"},
)
def auto_updates(ctx, res):
    if ctx.cms == "wordpress":
        return _wordpress(ctx, res)
    return _joomla(ctx, res)


# ------------------------------------------------------------------------------------------------ Joomla
def _joomla(ctx, res):
    version = ctx.shared.get("joomla_version") or ""
    if not version:
        out = ctx.sh("head -c 8000 libraries/src/Version.php 2>/dev/null; echo '@@M'; head -c 4000 administrator/manifests/files/joomla.xml 2>/dev/null", timeout=30).out
        a, _, b = out.partition("@@M")
        version = joomla.parse_joomla_version(a, b) or ""
    if version and vcmp(version, MIN_JOOMLA) < 0:
        res.add("info", "Joomla %s hat keine automatischen Core-Updates" % version,
                "Die Update-Automatik (Update-Dienst von joomla.org) gibt es erst ab Joomla %s. Diese Seite wird im Backend oder von Hand aktualisiert; ob das gelingt, zeigt die Prüfung "
                "'Lässt sich die Seite automatisch aktualisieren?'." % MIN_JOOMLA, [], "Auf Joomla %s oder neuer aktualisieren, um die Automatik nutzen zu können." % MIN_JOOMLA)
        return
    problems: List[str] = []
    checked: List[str] = []
    notes: List[str] = []
    host = ctx.own_host()
    db = ctx.db()
    cfg = ctx.config()
    vars_ = (cfg.get("vars") or {}) if isinstance(cfg, dict) else {}

    api: Dict[str, Any] = {"any": False, "items": [], "web_on": [], "update_plugin": None, "auth_on": []}
    prm: Dict[str, Any] = {}
    have_db = bool(db and db.ok)
    if have_db:
        try:
            r = fetch(db, Q_JOOMLAUPDATE[1]) or []
            prm = parse_params(str(r[0].get("p") or "")) if r else {}
            api = api_state(fetch(db, Q_API[1]) or [])
        except Exception as e:                                       # noqa: BLE001
            have_db = False
            notes.append("Datenbankabfrage (%s)" % type(e).__name__)
    else:
        notes.append("Einstellungen aus der Datenbank (kein Datenbankzugriff vom Server aus)")

    # ---- Einstellung
    auto = str(prm.get("autoupdate", "")).strip() if have_db else ""
    enabled: Optional[bool] = None
    if have_db:
        if auto == "0":
            enabled = False
            problems.append("aus")
            res.add("warn", "Automatische Updates sind in Joomla ausgeschaltet",
                    "Die Einstellung 'Automatische Updates' der Komponente Joomla-Update steht auf Nein (autoupdate = 0). Der Update-Dienst von joomla.org darf dann keine Updates anstoßen. "
                    "Bei Seiten, die von einer älteren Version auf 5.4 oder neuer aktualisiert wurden, ist sie nach Joomla-Angaben zunächst aus.",
                    ["autoupdate = 0"], "Backend -> System -> Joomla-Aktualisierung -> Optionen -> Reiter 'Automatische Updates' -> Ja. Das Programm ändert diese Einstellung nicht.")
        elif auto == "1":
            enabled = True
            checked.append("Einstellung 'Automatische Updates' ist an")
        else:
            enabled = True
            notes.append("Einstellung 'Automatische Updates' ist nicht gespeichert (es gilt der Standard der Joomla-Version: bei neuen Installationen an, nach einem Versionssprung oft aus)")
        src = str(prm.get("updatesource", "default")).strip().lower() or "default"
        stab = str(prm.get("minimum_stability", "4")).strip().lower() or "4"
        if src != "default":
            problems.append("quelle")
            res.add("warn", "Joomla holt Updates nicht aus der Standard-Update-Quelle (%s)" % src,
                    "Der Update-Dienst von joomla.org arbeitet nur mit der Standard-Quelle ('Default'). 'Joomla Next', 'Testing' oder eine eigene Adresse stoppen die Automatik.",
                    ["updatesource = %s" % src], "Backend -> System -> Joomla-Aktualisierung -> Optionen -> Update-Kanal auf 'Standard' stellen.")
        else:
            checked.append("Update-Quelle ist 'Standard'")
        if stab not in STABLE:
            problems.append("stabilitaet")
            res.add("warn", "Die Mindeststabilität für Updates ist nicht 'Stabil' (%s)" % stab,
                    "Automatische Updates werden nur für stabile Versionen eingespielt.", ["minimum_stability = %s" % stab], "Backend -> System -> Joomla-Aktualisierung -> Optionen -> Minimale Stabilität: Stabil.")
        else:
            checked.append("Mindeststabilität 'Stabil'")

        # ---- API-Plugins
        if not api["any"]:
            notes.append("API-Plugins (keine gefunden)")
        elif not api["web_on"] or not api["auth_on"] or api["update_plugin"] is False:
            if enabled is not False:
                problems.append("api")
                miss = []
                if not api["web_on"]:
                    miss.append("kein Web-Services-Plugin ist eingeschaltet")
                elif api["update_plugin"] is False:
                    miss.append("das Plugin 'Web Services - Joomla-Update' ist aus")
                if not api["auth_on"]:
                    miss.append("keine API-Authentifizierung ist eingeschaltet")
                res.add("crit", "Die Joomla-API ist (teilweise) ausgeschaltet: automatische Updates können nicht laufen",
                        "Der Update-Dienst von joomla.org stößt die Updates über die API deiner Seite an. Ohne die zugehörigen Plugins kommt keine Anfrage an. Häufige Ursache: die API wurde aus Sicherheitsgründen "
                        "abgeschaltet (auch durch die Aktion 'Joomla-API (Web-Services) abschalten' in diesem Programm oder durch eine Sicherheits-Erweiterung). Joomla-Update im Backend funktioniert trotzdem, daher fällt es nicht auf. "
                        "Festgestellt: " + "; ".join(miss) + ".",
                        api["items"], "Die Plugins wieder einschalten: Backend -> System -> Plugins -> Filter 'webservices' bzw. 'api-authentication' -> einschalten. "
                                      "Das Programm kann es mit der Aktion 'API für automatische Joomla-Updates einschalten' tun (Sicherung und Rückweg inklusive).")
        else:
            checked.append("API-Plugins für den Update-Dienst sind eingeschaltet")

        # ---- Update-Quelle eingeschaltet / zuletzt geprüft
        sites = fetch(db, Q_SITES[1]) or []
        off = [s for s in sites if str(s.get("enabled")) == "0"]
        if off:
            problems.append("quellaus")
            res.add("crit", "Eine Update-Quelle von Joomla ist ausgeschaltet",
                    "Ohne sie findet Joomla keine Kern-Updates; also auch keine automatischen.", ["%s (%s)" % (clean_line(str(s.get("name"))), clean_line(str(s.get("location")))) for s in off],
                    "Backend -> System -> Update-Seiten -> die Quelle 'Joomla Core' einschalten.")
        elif sites:
            checked.append("Update-Quelle von joomla.org ist eingeschaltet")
        latest = ""
        for r in fetch(db, Q_CORE[1]) or []:
            v = str(r.get("version") or "").strip()
            if re.match(r"^\d+\.\d+\.\d+", v) and (not latest or vcmp(v, latest) > 0):
                latest = v
        if latest and version and vcmp(latest, version) > 0 and enabled is not False and not problems:
            problems.append("liegt")
            res.add("warn", "Ein Kern-Update (%s) liegt bereit, ist aber nicht installiert (installiert: %s)" % (latest, version),
                    "Alle Voraussetzungen, die sich von hier prüfen lassen, stimmen. Trotzdem hat die Automatik das Update nicht eingespielt. Mögliche Gründe: Der Update-Dienst von joomla.org erreicht die Seite nicht "
                    "(Firewall, Cloudflare, Passwortschutz), die Anmeldung der Seite beim Update-Dienst ist abgelaufen, oder es ist eine neue Hauptversion (die Automatik spielt nur Sicherheits- und Fehlerbehebungs-Updates ein).",
                    ["installiert: " + version, "bereit: " + latest], "Update im Backend einspielen und die Hinweise zu Firewall und Erreichbarkeit unten prüfen.")
        elif latest and version and vcmp(latest, version) > 0:
            notes.append("Kern-Update %s liegt bereit (installiert: %s)" % (latest, version))
        for r in (fetch(db, Q_LOG[1]) or [])[:5]:
            notes.append("Protokoll: %s %s" % (clean_line(str(r.get("d")))[:19], re.sub(r"\s+", " ", clean_line(str(r.get("m"))))[:140]))

    # ---- Konfiguration: Offline, Mail
    if vars_:
        if str(vars_.get("offline", "")).strip().lower() in ("1", "true"):
            problems.append("offline")
            res.add("warn", "Die Seite steht im Offline-Modus", "Der Update-Dienst von joomla.org kann eine Seite im Offline-Modus nicht als erreichbar ansehen.", ["offline = 1"], "Offline-Modus in der Globalen Konfiguration ausschalten.")
        if str(vars_.get("mailonline", "1")).strip().lower() in ("0", "false") or not str(vars_.get("mailfrom", "")).strip():
            problems.append("mail")
            res.add("warn", "Der Mailversand ist nicht eingerichtet", "Das Ergebnis jedes automatischen Updates kommt per E-Mail an die Super-Benutzer. Ohne Mailversand merkst du nicht, ob es geklappt hat.",
                    ["mailonline = %s" % vars_.get("mailonline", "?"), "mailfrom = %s" % (vars_.get("mailfrom") or "leer")], "Globale Konfiguration -> Server -> Mail: Mailversand 'Ja', Absender-Adresse eintragen.")
        else:
            checked.append("Mailversand ist eingerichtet")

    # ---- Aufrufe von außen
    probes: Dict[str, Dict[str, str]] = {}
    if os.environ.get("CLAUDIA_OFFLINE"):
        notes.append("Aufrufe der eigenen Seite (Offline-Modus)")
    elif not host or not HOST_RE.match(host):
        notes.append("Aufrufe der eigenen Seite (keine Webadresse angegeben)")
    else:
        script = ("command -v curl >/dev/null 2>&1 || { echo '@@NOCURL'; exit 0; }\n" + curl_block("API_CURL", host, "/api/index.php/v1/") + curl_block("API_BROWSER", host, "/api/index.php/v1/", BROWSER_UA)
                  + curl_block("HOME", host, "/", BROWSER_UA))
        out = ctx.sh(script, timeout=90, raw="auto_updates_aufrufe").out
        if "@@NOCURL" in out:
            notes.append("Aufrufe der eigenen Seite (auf dem Server fehlt curl)")
        else:
            sec = split_sections(out)
            probes = {k: parse_probe(sec.get(k, "")) for k in ("API_CURL", "API_BROWSER", "HOME")}
    if probes:
        a1, a2, home = probes["API_CURL"], probes["API_BROWSER"], probes["HOME"]
        items = ["/api ohne Browser-Kennung: HTTP %s (%s)" % (a1["code"], a1["ctype"] or "ohne Art"), "/api mit Browser-Kennung: HTTP %s (%s)" % (a2["code"], a2["ctype"] or "ohne Art"),
                 "Startseite: HTTP %s" % home["code"]]
        cf = a1["cloudflare"] or a2["cloudflare"] or home["cloudflare"]
        if cf:
            items.append("Die Antworten kommen über Cloudflare")
        if home["code"] in ("401", "403"):
            problems.append("geschuetzt")
            res.add("warn", "Die Startseite ist von außen nicht frei abrufbar (HTTP %s)" % home["code"],
                    "Passwortschutz, IP-Sperre oder eine Firewall-Regel verhindert, dass der Update-Dienst von joomla.org die Seite erreicht. Joomla gibt an, dass die Seite öffentlich erreichbar sein muss.", items,
                    "Schutz für /api (und die Startseite) aufheben oder den Update-Dienst von joomla.org zulassen.")
        if probe_blocked(a1) and not probe_blocked(a2):
            problems.append("ua")
            res.add("crit", "Eine Firewall sperrt Anfragen ohne Browser-Kennung an /api (HTTP %s)" % a1["code"],
                    "Mit Browser-Kennung kommt die Antwort von Joomla (JSON), ohne sie wird sie von etwas VOR Joomla abgewiesen. Der Update-Dienst von joomla.org meldet sich nicht wie ein Browser. "
                    "Das ist ein typisches Verhalten von Bot-Filtern in Firewall-Erweiterungen und Webserver-Regeln und blockiert die Update-Automatik, ohne dass Backend-Updates betroffen sind.",
                    items, "In der Firewall (Erweiterung, .htaccess, Hoster) Anfragen an /api/index.php nicht nach Browser-Kennung filtern bzw. den Update-Dienst von joomla.org zulassen; danach diese Prüfung wiederholen.")
        elif probe_blocked(a1) and probe_blocked(a2):
            problems.append("apiblock")
            res.add("crit", "/api wird abgewiesen, bevor Joomla antwortet (HTTP %s)" % a2["code"],
                    "Weder mit noch ohne Browser-Kennung antwortet Joomla. Eine Firewall-Erweiterung, eine Webserver-Regel (.htaccess) oder ein vorgeschalteter Dienst (z. B. Cloudflare Bot-Schutz) sperrt den Ordner /api. "
                    "Damit erreicht der Update-Dienst die Seite nicht.", items,
                    "Sperre für /api aufheben (siehe Hinweise zu Firewall-Einstellungen unten), danach diese Prüfung wiederholen.")
        elif a1["code"] == "000" and a2["code"] == "000":
            notes.append("Erreichbarkeit von /api (der Server erreicht seine eigene Adresse nicht; das kommt bei manchen Hostern vor)")
        else:
            checked.append("/api antwortet von Joomla selbst (HTTP %s/%s)" % (a1["code"], a2["code"]))
        if cf and "ua" not in problems and "apiblock" not in problems:
            notes.append("Cloudflare erkannt: der Bot-Schutz ('Bot Fight Mode') kann den Update-Dienst von joomla.org mit HTTP 403 abweisen, ohne dass es sich von hier zeigt")

    # ---- Zugriffsregeln in .htaccess
    ht = ctx.sh("for f in .htaccess api/.htaccess; do [ -f \"$f\" ] && grep -nHiE 'api' \"$f\" 2>/dev/null | grep -iE 'deny|forbid|\\[F|R=40|require|errordocument|rewritecond.*(user_agent|remote_addr)' ; done | head -20", timeout=30).out
    hl = [clean_line(x)[:200] for x in lines_of(ht)]
    if hl:
        problems.append("htaccess")
        res.add("warn", "Zugriffsregeln in der .htaccess nennen /api und sperren oder filtern",
                "Diese Zeilen können den Update-Dienst von joomla.org aussperren. Ob sie wirken, zeigen die Aufrufe oben.", hl, "Zeilen prüfen; /api/index.php darf für den Update-Dienst nicht gesperrt sein.")

    # ---- Firewall-Erweiterungen (Wechselwirkung)
    present: Dict[str, List[str]] = {}
    try:
        tools = load_tools().get("joomla", [])
        stored = ctx.shared.get("security_tools") or {}
        present = stored.get("present") or detect_tools(ctx, tools, "auto_updates_sicherheitserweiterungen")[0]
        byid = {t["id"]: t for t in tools}
        fws = [byid[i] for i in present if i in byid and not byid[i].get("background")]
    except Exception:                                                # noqa: BLE001  (Liste fehlt o. ä.: ohne diesen Teil weiter)
        fws = []
    if fws and have_db:
        els = sorted({p.replace("com_", "").lower() for t in fws for p in t["paths"] if IDENT_RE.match(p)} | {p.lower() for t in fws for p in t["paths"] if IDENT_RE.match(p)})
        cond = " OR ".join("element LIKE '%%%s%%'" % e for e in els)
        try:
            prm_rows = fetch(db, "SELECT element, type, LEFT(params, 30000) AS p FROM #__extensions WHERE %s LIMIT 20" % cond) or []
            fp = fw_params(prm_rows)
            logs = fw_log_hits(ctx, db, els)
        except Exception as e:                                       # noqa: BLE001
            fp, logs = [], ["nicht lesbar (%s)" % type(e).__name__]
        names = ", ".join(t["name"].split(" - ")[0] for t in fws)
        detail = ("Auf dieser Seite arbeitet eine Firewall-Erweiterung (%s). Sie wird NICHT automatisch als Ursache gewertet, ist aber die häufigste Stelle, an der der Update-Dienst von joomla.org hängen bleibt: "
                  "Bot- und Browser-Kennungsfilter, Länder- oder IP-Sperren, Ratenbegrenzung und gesperrte API-Pfade. Bei Firewalls mit eigener Update-Funktion kann diese zusätzlich Joomlas eigene Automatik verdrängen." % names)
        items = (["Einstellungen mit Bezug zu API, Updates, Bots, Sperren (Werte, die Geheimnisse sein könnten, sind ausgeblendet):"] + fp[:40] if fp else ["Keine Einstellungen mit Bezug zu API oder Updates gefunden."])
        if logs:
            items += ["Firewall-Protokoll:"] + logs[:20]
        res.add("info" if not (probe_blocked(probes.get("API_CURL", {"code": "", "ctype": ""})) if probes else False) else "warn",
                "Firewall-Erweiterung erkannt (%s): Wechselwirkung mit den automatischen Updates prüfen" % names, detail, items,
                "In den Einstellungen der Firewall: 1) /api (Web Services) nicht sperren, 2) keine Filter nach Browser-Kennung oder Land für /api, 3) falls sie eigene automatische Updates anbietet: nur eine der beiden Automatiken benutzen, "
                "4) im Firewall-Protokoll nach Einträgen zu /api oder joomla.org suchen und die Quelle freigeben.")
    elif fws:
        notes.append("Einstellungen der Firewall-Erweiterung (kein Datenbankzugriff)")

    ctx.shared["auto_updates_problems"] = problems
    if problems:
        return
    items = ["geprüft: " + c for c in checked] + ["nicht prüfbar: " + n for n in notes] + ["nicht prüfbar: ob joomla.org die Seite erreicht und die Anmeldung beim Update-Dienst gültig ist"]
    res.add("ok", "Die Voraussetzungen für automatische Joomla-Updates sind erfüllt",
            "Alles, was sich von hier prüfen lässt, stimmt. Die Anmeldung beim Update-Dienst von joomla.org und dessen Zugriff von außen sind von hier nicht sichtbar; zeigt Joomla trotzdem keine automatischen Updates, "
            "helfen die Protokolle des Update-Dienstes (Backend -> Benutzeraktionen-Protokoll) und der Zugriffsprotokolle des Webservers (Anfragen an /api).", items)


# ------------------------------------------------------------------------------------------------ WordPress
CRON_HOOKS = ("wp_version_check", "wp_maybe_auto_update", "wp_update_plugins", "wp_update_themes")


def cron_times(serialized: str) -> Dict[str, int]:
    """Nächste geplante Zeit je Hook aus der Option 'cron' (serialisiertes PHP-Feld, nur gelesen, nie ausgeführt)."""
    out: Dict[str, int] = {}
    for m in re.finditer(r"i:(\d{9,11});a:\d+:\{s:\d+:\"(%s)\";" % "|".join(CRON_HOOKS), serialized or ""):
        t, h = int(m.group(1)), m.group(2)
        if h not in out or t < out[h]:
            out[h] = t
    return out


def _wordpress(ctx, res):
    problems: List[str] = []
    checked: List[str] = []
    notes: List[str] = []
    host = ctx.own_host()
    cfg = ctx.config()
    d = (cfg.get("defines") or {}) if isinstance(cfg, dict) else {}

    def on(k: str) -> bool:
        return str(d.get(k, "")).strip().lower() in ("true", "1")
    cron_off = on("DISABLE_WP_CRON")
    script = ("echo '@@VCS'\nfor d in . .. ../..; do for v in .git .svn .hg .bzr; do [ -d \"$d/$v\" ] && echo \"$d/$v\"; done; done\n"
              "echo '@@CRONTAB'\ncrontab -l 2>/dev/null | grep -iE 'wp-cron|wp cron|cron event run' | head -5\n")
    if host and HOST_RE.match(host) and not os.environ.get("CLAUDIA_OFFLINE"):
        script += ("command -v curl >/dev/null 2>&1 || echo '@@NOCURL'\n" + curl_block("CRON_CURL", host, "/wp-cron.php") + curl_block("CRON_BROWSER", host, "/wp-cron.php", BROWSER_UA))
    out = ctx.sh(script, timeout=90, raw="auto_updates_aufrufe").out
    sec = split_sections(out)
    vcs = [clean_line(x) for x in lines_of(sec.get("VCS", ""))]
    if vcs:
        problems.append("vcs")
        res.add("warn", "Im WordPress-Ordner liegt eine Versionsverwaltung (%s): WordPress schaltet die automatischen Updates dann ab" % ", ".join(v.rsplit("/", 1)[-1] for v in vcs),
                "WordPress erkennt .git, .svn, .hg oder .bzr im Ordner oder darüber und hält die Seite für eine Entwicklungsumgebung. Hintergrund-Updates laufen dort nicht. Auf einem Live-Server hat so ein Ordner außerdem nichts zu suchen.",
                vcs, "Den Ordner entfernen (das Programm meldet ihn auch in der Prüfung der Hauptordner), oder Updates über das Deployment einspielen.")
    else:
        checked.append("keine Versionsverwaltung im Ordner")
    cronlines = [clean_line(x)[:160] for x in lines_of(sec.get("CRONTAB", ""))]
    if cron_off:
        if cronlines:
            checked.append("DISABLE_WP_CRON ist an, ein Cronjob des Servers löst wp-cron aus")
        else:
            problems.append("cronoff")
            res.add("warn", "DISABLE_WP_CRON ist an, aber kein Cronjob ruft den Zeitplan auf",
                    "Mit DISABLE_WP_CRON löst WordPress seine geplanten Aufgaben nicht mehr bei Seitenaufrufen aus; ein Cronjob des Servers muss es tun. Im Konto ist keiner sichtbar (Cronjobs im Hosting-Paneel sieht das Programm nicht). "
                    "Ohne ihn laufen weder Hintergrund-Updates noch Prüfungen auf neue Versionen.", ["define('DISABLE_WP_CRON', true)"],
                    "Im Hosting-Paneel einen Cronjob einrichten (z. B. alle 5-15 Minuten: wget -q -O - https://deine-seite/wp-cron.php?doing_wp_cron), oder DISABLE_WP_CRON entfernen.")
    if "NOCURL" in out or not (host and HOST_RE.match(host)) or os.environ.get("CLAUDIA_OFFLINE"):
        notes.append("Aufruf von wp-cron.php (kein curl, keine Webadresse oder Offline-Modus)")
    else:
        p1, p2 = parse_probe(sec.get("CRON_CURL", "")), parse_probe(sec.get("CRON_BROWSER", ""))
        items = ["wp-cron.php ohne Browser-Kennung: HTTP %s" % p1["code"], "wp-cron.php mit Browser-Kennung: HTTP %s" % p2["code"]]

        def bad(p: Dict[str, str]) -> bool:
            return p["code"] in ("401", "403", "406", "429", "451") or p["code"].startswith("5")
        if bad(p1) or bad(p2):
            problems.append("cronblock")
            res.add("crit", "wp-cron.php wird abgewiesen (HTTP %s)" % (p1["code"] if bad(p1) else p2["code"]),
                    "Eine Firewall-Regel, ein Passwortschutz oder ein Sicherheits-Plugin sperrt die Datei, die den WordPress-Zeitplan auslöst. Dann laufen Hintergrund-Updates nicht, und Plugin-Updates bleiben liegen.", items,
                    "Sperre für wp-cron.php aufheben (Firewall, .htaccess, Sicherheits-Plugin) oder den Zeitplan über einen Cronjob des Servers laufen lassen.")
        elif p1["code"] == "000" and p2["code"] == "000":
            notes.append("Erreichbarkeit von wp-cron.php (der Server erreicht seine eigene Adresse nicht)")
        else:
            checked.append("wp-cron.php antwortet (HTTP %s)" % p2["code"])
    db = ctx.db()
    if db and db.ok:
        try:
            rows = fetch(db, "SELECT LEFT(option_value, 150000) AS v FROM #__options WHERE option_name = 'cron'") or []
            times = cron_times(rows[0].get("v") or "") if rows else {}
            now = time.time()
            if not times:
                notes.append("Zeitplan: keine Hooks für Versions- und Update-Prüfung gefunden")
            else:
                overdue = {h: t for h, t in times.items() if now - t > 36 * 3600}
                if overdue:
                    problems.append("cronstehen")
                    res.add("crit", "Der WordPress-Zeitplan steht: Update-Aufgaben sind seit über 36 Stunden überfällig",
                            "Die Aufgaben für Versions- und Update-Prüfung hätten längst laufen müssen. Meist wird der WP-Cron nicht ausgelöst (wenig Besuch bei aktivem DISABLE_WP_CRON, gesperrte wp-cron.php, Fehler in einem Plugin).",
                            ["%s: geplant für %s" % (h, time.strftime("%Y-%m-%d %H:%M", time.gmtime(t))) for h, t in sorted(overdue.items())], "wp-cron.php erreichbar machen oder einen Cronjob einrichten; Fehlerprotokoll der Seite ansehen.")
                else:
                    checked.append("Zeitplan der Update-Aufgaben ist aktuell")
        except Exception as e:                                       # noqa: BLE001
            notes.append("Zeitplan aus der Datenbank (%s)" % type(e).__name__)
    else:
        notes.append("Zeitplan aus der Datenbank (kein Datenbankzugriff vom Server aus)")
    ctx.shared["auto_updates_problems"] = problems
    if problems:
        return
    res.add("ok", "Die Voraussetzungen für automatische WordPress-Updates sind erfüllt",
            "Der WP-Cron läuft und ist erreichbar. Welche Updates WordPress selbst einspielt, steht in der Prüfung 'Lässt sich WordPress automatisch aktualisieren?' (Einstellungen WP_AUTO_UPDATE_CORE und Auto-Update je Plugin).",
            ["geprüft: " + c for c in checked] + ["nicht prüfbar: " + n for n in notes])
