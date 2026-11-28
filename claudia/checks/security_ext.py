"""Ist eine Sicherheits-Erweiterung (Firewall/Scanner) installiert und aktiv? Mit Empfehlung und Bewertungen. Rein lesend."""
from __future__ import annotations

import json
import os
import re
import time
from typing import Any, Dict, List, Optional

from .. import BACKUP_TOOLS_FILE, SECURITY_TOOLS_FILE
from ..model import CheckSkipped
from ..registry import check
from ..util import clean_line, lines_of
from .database import fetch

G = "erweiterungen"
FAMILY = {"securitycheckpro": "securitycheck"}      # Free und Pro derselben Entwickler zählen als eine


def load_tools(kind: str = "security") -> Dict[str, Any]:
    """Feste Liste der Erweiterungen: kind='security' (Firewall/Scanner) oder 'backup' (Sicherung)."""
    try:
        with open(BACKUP_TOOLS_FILE if kind == "backup" else SECURITY_TOOLS_FILE, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {"stand": "", "joomla": [], "wordpress": []}


def stars_text(t: Dict[str, Any]) -> str:
    if t.get("reviews"):
        return "%d von 5 Sternen (JED, gerundet), %s Bewertungen%s" % (t.get("stars", 0), t.get("reviews"), (" [%s]" % t["reviews_note"]) if t.get("reviews_note") else "")
    return "noch keine Bewertung auf der JED"


def price_group(t: Dict[str, Any]) -> int:
    """0 = kostenlos (auch mit Pro-Aufpreis), 1 = Preis nicht angegeben, 2 = kostenpflichtig. WordPress-Einträge ohne Preisfeld liegen im Verzeichnis kostenlos vor."""
    price = str(t.get("price") or "").lower()
    if price.startswith("kostenlos"):
        return 0
    if "kostenpflichtig" in price or "€" in price or "$" in price:
        return 2
    return 0 if t.get("price") is None else 1


GROUP_TITLES = {0: "Kostenlos:", 1: "Preis im Verzeichnis nachsehen:", 2: "Kostenpflichtig:"}


def grouped(tools: List[Dict[str, Any]], line) -> List[str]:
    """Empfehlungsliste: erst die kostenlosen, dann (unter eigener Überschrift) die kostenpflichtigen. Innerhalb einer Gruppe bleibt die Reihenfolge der Liste."""
    out: List[str] = []
    shown = [t for t in tools if not t.get("background")]
    for g in (0, 1, 2):
        part = [t for t in shown if price_group(t) == g]
        if not part:
            continue
        if len({price_group(t) for t in shown}) > 1:
            out.append(GROUP_TITLES[g])
        out.extend(line(t) for t in part)
    return out


def joomla_line(t: Dict[str, Any]) -> str:
    return "%s - %s | %s%s | %s\n   %s\n   %s" % (
        t["name"], stars_text(t), t.get("price") or "Preis siehe JED", (" | " + t["developer"]) if t.get("developer") else "", t["jed"], t["text"], "")


def _wp_rating(slug: str, ctx) -> Optional[Dict[str, Any]]:
    """Live-Bewertung aus api.wordpress.org (nur wenn online)."""
    from . import web as webmod
    from urllib.parse import quote
    f = webmod.fetch("https://api.wordpress.org/plugins/info/1.0/%s.json" % quote(slug), webmod.UA_BROWSER, max_bytes=1_500_000, timeout=20)
    if f.error or f.status != 200:
        return None
    try:
        d = json.loads(f.body)
    except ValueError:
        return None
    if not isinstance(d, dict) or not d.get("rating"):
        return None
    return {"rating": float(d.get("rating", 0)) / 20.0, "num": int(d.get("num_ratings", 0) or 0), "installs": d.get("active_installs")}


HOST_MARKERS = [
    (re.compile(r"(?i)SecRuleEngine|security2_module"), "ModSecurity (Web-Firewall des Servers, im Hosting enthalten)"),
    (re.compile(r"(?i)imunify|\bi360\b"), "Imunify360 (Schutz auf Server-Ebene, vom Hoster betrieben)"),
    (re.compile(r"(?i)AuthUserFile"), "Passwortschutz per .htpasswd (Verzeichnisschutz)"),
]


def host_protection(ctx) -> List[str]:
    """Hinweise auf Schutz, der nicht als Plugin installiert ist, aus der .htaccess im Hauptordner (nur lesend). Leere Liste, wenn nichts gefunden wurde."""
    out = ctx.sh("[ -f .htaccess ] && grep -ohiE 'SecRuleEngine|security2_module|imunify[0-9a-z]*|i360|AuthUserFile' .htaccess 2>/dev/null | sort -u | head -20", timeout=30).out
    return [label for rx, label in HOST_MARKERS if rx.search(out)]


def detect_tools(ctx, tools: List[Dict[str, Any]], raw: str):
    """Welche Erweiterungen der Liste liegen im Dateisystem, und sind sie eingeschaltet (nur mit Datenbank)? -> (present, active).
    present: Kennung -> Pfade; active: Kennung -> True/False/None (None = nicht feststellbar)."""
    cms = ctx.cms
    names = sorted({p for t in tools for p in t["paths"]})
    pred = " -o ".join("-iname '%s'" % n for n in names)
    base = ctx.prof["sec_base"]
    depth = ctx.prof["sec_depth"]
    out = ctx.sh("echo '# Gesucht in: %s'; for d in %s; do [ -d \"$d\" ] && find \"$d\" -maxdepth %d -type d \\( %s \\) -printf 'FOUND\\t%%p\\n' 2>/dev/null; done | head -80" % (base, base, depth, pred),
                 timeout=60, raw=raw).out
    found_paths = [l.split("\t", 1)[1] for l in lines_of(out) if l.startswith("FOUND\t")]
    present: Dict[str, List[str]] = {}
    for t in tools:
        for fp in found_paths:
            if os.path.basename(fp.rstrip("/")).lower() in t["paths"]:
                present.setdefault(t["id"], []).append(fp)
    # eingeschaltet? (nur mit Datenbank)
    active: Dict[str, Optional[bool]] = {tid: None for tid in present}
    db = ctx.db()
    if present and db.ok:
        try:
            if cms == "wordpress":
                rows = fetch(db, "SELECT option_value AS v FROM #__options WHERE option_name = 'active_plugins'") or []
                act = {a.split("/")[0].lower() for a in re.findall(r's:\d+:"([^"]+)";', rows[0].get("v") or "")} if rows else set()
                for t in tools:
                    if t["id"] in present:
                        active[t["id"]] = any(p in act for p in t["paths"])
            else:
                rows = fetch(db, "SELECT element, type, enabled FROM #__extensions WHERE type IN ('plugin','component')") or []
                en = {}
                for r in rows:
                    en.setdefault((r.get("element") or "").lower().replace("com_", ""), []).append(str(r.get("enabled")) == "1")
                for t in tools:
                    if t["id"] in present:
                        vals = [v for p in t["paths"] for v in en.get(p.replace("com_", "").lower(), [])]
                        active[t["id"]] = any(vals) if vals else None
        except Exception:
            pass
    return present, active


@check(
    "security_ext", G, "Schutz durch eine Sicherheits-Erweiterung",
    "Ist eine Firewall oder ein Scanner installiert und eingeschaltet - und welche wird empfohlen?",
    what="Sucht nach bekannten Sicherheits-Erweiterungen (Firewall, Schadcode-Scanner, Anmeldeschutz) und prüft, ob sie eingeschaltet sind. Fehlt eine, erklärt der Test, warum sich eine lohnt, "
         "und zeigt Empfehlungen mit den Bewertungen im Verzeichnis (JED bei Joomla, wordpress.org bei WordPress).",
    why="Joomla und WordPress bringen weder eine Web-Firewall noch einen Schadcode-Scanner mit. Eine Sicherheits-Erweiterung blockiert typische Angriffe, bevor sie die Seite erreichen, "
        "meldet Dateiänderungen und sperrt Angreifer bei der Anmeldung. Sie ersetzt keine Updates und keine Sicherungen, ist aber die wichtigste Ergänzung dazu.",
    reads="Nur Ordnernamen der Erweiterungen und - falls möglich - ob sie in der Datenbank eingeschaltet sind. Bei WordPress eine öffentliche Abfrage der Bewertungen bei api.wordpress.org (https).",
    load="leicht", presets=["schnell", "hack"],
    wp={"title": "Schutz durch ein Sicherheits-Plugin", "summary": "Ist eine Firewall oder ein Scanner installiert und eingeschaltet - und welches wird empfohlen?"},
)
def security_ext(ctx, res):
    cms = ctx.cms
    name = ctx.prof["name"]
    data = load_tools()
    tools: List[Dict[str, Any]] = data.get(cms, [])
    if not tools:
        raise CheckSkipped("Die Liste der Sicherheits-Erweiterungen fehlt.")
    present, active = detect_tools(ctx, tools, "sicherheitserweiterungen")
    host = host_protection(ctx)
    ctx.shared["security_tools"] = {"present": present, "active": active, "host": host}       # für andere Prüfungen (z. B. .htaccess-Blöcke zuordnen)
    by_id = {t["id"]: t for t in tools}
    main_present = [by_id[i] for i in present if not by_id[i].get("background")]
    helper_present = [by_id[i] for i in present if by_id[i].get("background")]
    stand = data.get("stand", "")
    why_lines = [
        "Eine Firewall erkennt und blockiert typische Angriffe (SQL-Injection, Einschleusen von Dateien, Ausnutzen von Lücken), bevor sie die Seite erreichen - auch in der Zeit zwischen dem Bekanntwerden einer Lücke und deinem Update.",
        "Ein Scanner vergleicht Dateien mit dem Original und meldet Änderungen sofort, nicht erst nach Wochen.",
        "Der Anmeldeschutz sperrt Angreifer, die Passwörter durchprobieren.",
        "Sie ersetzt keine Updates, keine Sicherungen und keine sicheren Passwörter. Installiere nur EINE Firewall; zwei Firewalls stören sich gegenseitig.",
    ]

    def comparison() -> List[str]:
        items: List[str] = []
        if cms == "wordpress":
            for t in tools:
                if t.get("background"):
                    continue
                line = "%s - %s" % (t["name"], t["text"])
                r = None if os.environ.get("CLAUDIA_OFFLINE") else _wp_rating(t["slug"], ctx)
                if r:
                    line = "%s - %.1f von 5 Sternen, %d Bewertungen (wordpress.org)%s - %s" % (
                        t["name"], r["rating"], r["num"], (", %s+ aktive Installationen" % r["installs"]) if r.get("installs") else "", t["text"])
                items.append(line)
        else:
            items = grouped(tools, lambda t: "%s - %s | %s%s - %s [%s]" % (t["name"], stars_text(t), t.get("price") or "Preis siehe JED",
                                                                       (" | " + t["developer"]) if t.get("developer") else "", t["text"], t["jed"]))
        return items

    if main_present:
        on = [t for t in main_present if active.get(t["id"]) is True]
        off = [t for t in main_present if active.get(t["id"]) is False]
        unknown = [t for t in main_present if active.get(t["id"]) is None]
        if off and not on:
            res.add("warn", "Sicherheits-Erweiterung ist installiert, aber ausgeschaltet", "%s ist vorhanden, aber nicht aktiv. Dann schützt sie nichts." % ", ".join(t["name"] for t in off),
                    ["Pfad: %s" % clean_line(p) for t in off for p in present[t["id"]]][:10],
                    ctx.prof["enable_hint"])
        elif len({FAMILY.get(t["id"], t["id"]) for t in on + unknown}) > 1:
            res.add("info", "Mehrere Sicherheits-Erweiterungen sind installiert", "Zwei Firewalls können sich gegenseitig blockieren oder Seiten verlangsamen.",
                    [t["name"] for t in on + unknown], "Nur eine Firewall aktiv lassen.")
        else:
            label = ", ".join(t["name"] for t in main_present)
            state = "eingeschaltet" if on else "installiert (ob sie eingeschaltet ist, ließ sich nicht prüfen)"
            res.add("ok", "Sicherheits-Erweiterung vorhanden: %s (%s)" % (label, state),
                    "Halte sie aktuell und prüfe gelegentlich ihre Meldungen. Regeln und Signaturen veralten ohne Updates.",
                    ["Pfad: %s" % clean_line(p) for t in main_present for p in present[t["id"]]][:6])
    elif helper_present:
        res.add("info", "Nur ein Teilschutz ist installiert: %s" % ", ".join(t["name"] for t in helper_present),
                "Diese Erweiterung schützt einen Teil (z. B. die Anmeldung), ersetzt aber keine Firewall mit Scanner.",
                [t["text"] for t in helper_present], "Zusätzlich eine vollwertige Sicherheits-Erweiterung einsetzen (siehe Empfehlungen).")
    if host:
        res.add("info", "Schutz auf Server-Ebene erkannt", "In der .htaccess stehen Hinweise auf Schutz, der nicht als Plugin läuft. Das ergänzt ein Sicherheits-Plugin, ersetzt es aber nicht: "
                "Server-Regeln kennen weder deine Dateien noch deine Benutzer.", host)
    if not main_present:
        res.add("info", ctx.prof["no_sec_title"],
                "Auf dieser %s-Seite läuft keine bekannte Web-Firewall und kein Schadcode-Scanner. Angriffe auf Lücken werden dann nicht abgefangen." % name,
                why_lines, ctx.prof["install_hint"] + " (Empfehlungen und Bewertungen siehe nächster Befund).", context=True)
    items = comparison()
    head = (data.get("hinweis_joomla", "") if cms != "wordpress" else
            "Bewertungen von wordpress.org werden bei der Prüfung live abgefragt (nur online). Ohne Verbindung fehlen die Zahlen.")
    res.add("info", "Empfehlungen und Bewertungen%s" % (" (Stand %s)" % stand if cms != "wordpress" and stand else ""), head, items,
            "So wählst du: Für den Einstieg reicht eine kostenlose Version. Kostenpflichtige haben meist festen Support und schnellere Regel-Updates. "
            "Achte auf Pflege (letztes Update), Verbreitung (Zahl der Bewertungen) und darauf, dass sie zu deiner %s-Version passt." % name)


# ============================================================================ Sicherungs-Erweiterung
BACKUP_FILE_FIND = r"\( -iname '*.jpa' -o -iname '*.jps' -o -iname '*.zip' -o -iname '*.tar' -o -iname '*.tar.gz' -o -iname '*.tgz' -o -iname '*.gz' -o -iname '*.wpress' -o -iname '*.sql' -o -iname '*.sql.gz' -o -iname '*.7z' \)"
DIR_RE = re.compile(r"^[A-Za-z0-9_./*-]{1,120}\Z")


def backup_scan_script(dirs: List[str]) -> str:
    """Nur lesend: je Speicherordner die drei neuesten Sicherungsdateien (Zeit, Größe, Name) und ob der Ordner einen Zugriffsschutz (.htaccess, index.html) hat."""
    good = [d for d in dirs if DIR_RE.match(d) and ".." not in d and not d.startswith("/")]
    lines = ["echo '@@NOW'; date +%s"]
    for d in good:
        lines.append("for D in %s; do [ -d \"$D\" ] || continue; echo \"@@DIR $D\"; [ -f \"$D/.htaccess\" ] && echo '@@HT'; [ -f \"$D/index.html\" ] && echo '@@IDX'; "
                     "find \"$D\" -maxdepth 2 -type f %s -printf '%%T@ %%s %%p\\n' 2>/dev/null | sort -rn | head -3; done" % (d, BACKUP_FILE_FIND))
    return "\n".join(lines)


def parse_backup_scan(out: str) -> Dict[str, Any]:
    """Aus der Ausgabe: {'now': Sekunden, 'dirs': [{'dir', 'htaccess', 'index', 'files': [(zeit, größe, name)]}]}."""
    res: Dict[str, Any] = {"now": 0, "dirs": []}
    cur: Optional[Dict[str, Any]] = None
    for ln in out.splitlines():
        ln = ln.rstrip()
        if ln == "@@NOW":
            continue
        if ln.startswith("@@DIR "):
            cur = {"dir": ln[6:].strip(), "htaccess": False, "index": False, "files": []}
            res["dirs"].append(cur)
        elif ln == "@@HT" and cur is not None:
            cur["htaccess"] = True
        elif ln == "@@IDX" and cur is not None:
            cur["index"] = True
        elif cur is not None:
            m = re.match(r"^(\d+)(?:\.\d+)?\s+(\d+)\s+(.+)\Z", ln)
            if m:
                cur["files"].append((int(m.group(1)), int(m.group(2)), m.group(3)))
        elif re.match(r"^\d{9,}\Z", ln):
            res["now"] = int(ln)
    return res


def _size_text(n: int) -> str:
    return "%.1f MB" % (n / 1048576.0) if n >= 1048576 else "%d KB" % max(1, n // 1024)
def _backup_age_and_place(ctx, res, on) -> None:
    """Letzte Sicherung (Alter) und Speicherort der eingeschalteten Erweiterungen. Nur lesend; Cloud-Ziele und Hoster-Sicherungen sind nicht sichtbar."""
    dirs = [d for t in on for d in t.get("dirs", [])]
    if not dirs:
        return
    out = ctx.sh(backup_scan_script(dirs), timeout=60).out
    sc = parse_backup_scan(out)
    now = sc["now"] or int(time.time())
    files = [(f, d) for d in sc["dirs"] for f in d["files"]]
    names = ", ".join(t["name"] for t in on)
    if not files:
        res.add("warn", "Keine Sicherungsdatei am üblichen Speicherort gefunden",
                "%s ist installiert, aber im Standardordner liegt kein Archiv (gesucht in %s). Entweder wurde noch nie gesichert, oder die Archive liegen woanders (eigener Ordner, Cloud-Speicher, FTP). "
                "Das Programm sieht Cloud-Ziele und Sicherungen des Hosters nicht." % (names, ", ".join(dirs[:4])),
                [], "In %s nachsehen, ob und wohin gesichert wird, und eine Sicherung anlegen." % names)
        return
    newest = max(files, key=lambda x: x[0][0])
    (ts, size, name), d = newest
    age = max(0, (now - ts) // 86400)
    when = time.strftime("%Y-%m-%d", time.gmtime(ts))
    items = ["%s  (%s, %s)" % (clean_line(f[2]), time.strftime("%Y-%m-%d %H:%M", time.gmtime(f[0])), _size_text(f[1])) for f, _d in sorted(files, key=lambda x: -x[0][0])[:4]]
    if age <= 14:
        res.add("ok", "Letzte Sicherung vor %d Tag(en) (%s)" % (age, when), "Die neueste Sicherungsdatei am üblichen Speicherort ist %d Tag(e) alt." % age, items)
    else:
        res.add("warn", "Letzte Sicherung ist %d Tage alt (%s)" % (age, when),
                "Die neueste Sicherungsdatei am üblichen Speicherort ist älter als zwei Wochen. Entweder läuft der Zeitplan nicht, oder neuere Sicherungen liegen woanders (z. B. in der Cloud).",
                items, "Zeitplan der Erweiterung prüfen und eine neue Sicherung anlegen.")
    places = []
    for dd in sc["dirs"]:
        if dd["files"]:
            places.append("%s  (innerhalb der Seite, %s)" % (clean_line(dd["dir"]), "mit Zugriffsschutz" if dd["htaccess"] or dd["index"] else "OHNE Zugriffsschutz"))
    open_ = [dd for dd in sc["dirs"] if dd["files"] and not (dd["htaccess"] or dd["index"])]
    if open_:
        res.add("warn", "Sicherungen liegen im Web-Ordner ohne Zugriffsschutz",
                "Der Ordner liegt im öffentlich erreichbaren Bereich der Seite und enthält weder .htaccess noch index.html. Ist der Dateiname erratbar, kann ihn jeder aus dem Internet laden. Sicherungen enthalten Datenbank und Zugangsdaten. "
                "Ob die Dateien wirklich abrufbar sind, zeigt die Prüfung 'Webseite aus Besuchersicht' (sofern sie gelaufen ist).", places,
                "In den Einstellungen der Erweiterung ein Ausgabe-Verzeichnis außerhalb des Webspaces wählen (z. B. oberhalb von public_html) oder eine .htaccess mit 'Require all denied' in den Ordner legen.")
    else:
        res.add("info", "Speicherort der Sicherungen: innerhalb der Seite", "Die Archive liegen im Seitenordner, durch .htaccess oder index.html gegen Auflisten geschützt. Besser ist ein Ordner außerhalb des Webspaces: "
                "Bei nginx wirkt .htaccess nicht.", places, "Ausgabe-Verzeichnis in der Erweiterung außerhalb des Webspaces wählen.")
    _backup_web_test(ctx, res, sc)


MAX_BACKUP_WEB_TESTS = 3           # höchstens drei Abrufe je Lauf (je Speicherordner einer, nur die neueste Datei): keine Massenabfrage


def archive_reachable(f) -> bool:
    """True, wenn die Antwort wie eine ausgelieferte Datei aussieht (200/206, kein HTML). Eine Fehler- oder Startseite mit Status 200 zählt nicht."""
    if f.error or f.status not in (200, 206) or f.size <= 0:
        return False
    ctype = (f.headers or {}).get("content-type", "").lower()
    head = (f.body or "")[:200].lstrip().lower()
    return not (ctype.startswith("text/html") or head.startswith(("<!doctype", "<html", "<?xml")))


def _backup_web_test(ctx, res, sc) -> None:
    """D7 (2.4.0): Sicherungen anderer Tools von außen abrufbar? Je Speicherordner ein einzelner Abruf der neuesten Datei (nur die ersten Bytes, Inhalt wird nie gezeigt)
    und der Hinweis, dass Sicherungen den Befall enthalten können."""
    from . import web as webmod
    from .. import secure
    from urllib.parse import quote
    res.add("info", "Sicherungen können den Befall enthalten",
            "Ein Archiv aus der Zeit nach dem Einbruch enthält auch die Hintertüren und manipulierten Dateien. Vor dem Zurückspielen nach einem Hack das Datum der Sicherung mit dem "
            "Zeitpunkt des Befalls vergleichen und eine Sicherung davor wählen; nach dem Zurückspielen erneut prüfen.")
    url = (getattr(ctx.s, "url", "") or "").strip()
    cand = [(dd, max(dd["files"], key=lambda x: x[0])) for dd in sc["dirs"] if dd["files"]][:MAX_BACKUP_WEB_TESTS]
    if not url or not cand:
        if cand:
            res.add("info", "Abrufbarkeit der Sicherungen nicht getestet", "Es ist keine Adresse der Webseite angegeben (Feld 'Webseite' in den Verbindungsdaten).")
        return
    base, _ = secure.to_https(url)
    base = base.rstrip("/")
    bad, good, wafs, unclear = [], [], [], []
    for dd, (ts, size, name) in cand:
        path = name[2:] if name.startswith("./") else name
        ctx.progress("Rufe eine Sicherungsdatei von außen ab (nur die ersten Bytes)")
        f = webmod.fetch("%s/%s" % (base, quote(path)), webmod.UA_BROWSER, max_bytes=512, timeout=15)
        who = webmod.waf_block(f)
        if f.error:
            unclear.append("%s: nicht erreichbar (%s)" % (clean_line(path), f.error))
        elif who:
            wafs.append("%s: Firewall (%s)" % (clean_line(path), who))
        elif archive_reachable(f):
            bad.append("%s  (HTTP %d)" % (clean_line(path), f.status))
        else:
            good.append("%s: HTTP %d, wird nicht ausgeliefert" % (clean_line(path), f.status))
    if bad:
        res.add("crit", "%d Sicherungsdatei(en) sind von außen abrufbar" % len(bad),
                "Jeder Besucher, der den Dateinamen kennt oder errät, kann das Archiv herunterladen. Es enthält Datenbank, Benutzer und Passwort-Hashes. Es wurden nur die ersten Bytes abgerufen und nicht gespeichert.",
                bad, "Archive sofort aus dem Web-Bereich entfernen oder den Ordner sperren ('Require all denied' in der .htaccess, bei nginx in der Serverkonfiguration); danach das Ausgabe-Verzeichnis außerhalb des Webspaces wählen und Passwörter erneuern, wenn die Datei offen war.")
    if good:
        res.add("ok", "Sicherungsdateien sind von außen nicht abrufbar (%d getestet)" % len(good), "Getestet wurde je Ordner die neueste Datei mit einem einzelnen Abruf.", good)
    if wafs:
        res.add("info", "Von einer Firewall blockiert, Abrufbarkeit nicht geklärt", "Die Firewall hat den Abruf abgefangen; ob der Server die Datei sonst ausliefern würde, ist damit offen.", wafs)
    if unclear:
        res.add("info", "Abrufbarkeit nicht getestet", "", unclear)


def restore_hint(res, tool_found: bool) -> None:
    """2.4.1 Punkt 8: reiner Hinweis (kein Befund). CLAUDIA kann weder eine Wiederherstellung prüfen noch Sicherungen übertragen oder den Ort außerhalb des Servers sehen."""
    res.add("info", "Sicherung nützt nur, wenn sich zurückspielen lässt und eine Kopie woanders liegt",
            "Zwei Dinge sieht CLAUDIA nicht und prüft sie nicht: ob sich eine Sicherung wirklich zurückspielen lässt, und ob eine Kopie außerhalb dieses Servers liegt. "
            "Eine Sicherung nur auf demselben Server geht bei einem Hack, Serverausfall oder einer gelöschten Kundenkonto-Verbindung mit verloren.",
            ["Wiederherstellung einmal auf einer Testkopie (Unterverzeichnis oder lokale Umgebung) ausprobieren, bevor sie im Ernstfall gebraucht wird",
             "Eine Kopie an einem anderen Ort ablegen: Cloud-Speicher, anderer Anbieter oder eigener Rechner (CLAUDIA überträgt selbst nichts)",
             "Mehrere ältere Stände aufheben, nicht nur den neuesten: Ein Befall wird oft erst Wochen später bemerkt"
             ] + ([] if tool_found else ["Auch wenn der Hoster sichert: im Kundenbereich nachsehen, wie lange aufbewahrt wird und wie man zurückspielt"]),
            "Termin für einen Wiederherstellungstest und für die Kopie außerhalb des Servers festlegen.")


@check(
    "backup_tool", G, "Sicherungs-Erweiterung",
    "Gibt es eine Erweiterung, die die Seite regelmäßig sichert - und wenn nicht: welche passt?",
    what="Sucht nach bekannten Sicherungs-Erweiterungen (Joomla: Akeeba Backup; WordPress: Akeeba Backup, UpdraftPlus, Duplicator, BackWPup, WPvivid, All-in-One WP Migration) und prüft, ob sie eingeschaltet sind. "
         "Fehlt eine, zeigt der Test eine kleine Auswahl mit Beschreibung. Das Programm kann sie auf Wunsch installieren (WordPress mit WP-CLI; bei Joomla nur, wenn der Hersteller eine geprüfte öffentliche Update-Adresse hat, sonst Link und Anleitung).",
    why="Ohne Sicherung bleibt nach einem Hack oder einem fehlgeschlagenen Update nur Neuaufbau. Eine Sicherung ist die einzige Versicherung, die auch dann hilft, wenn alles andere versagt hat. "
        "Viele Hoster legen Sicherungen an, du hast aber oft keinen Einfluss darauf, wie lange sie aufbewahrt werden und ob sie sich zurückspielen lassen.",
    reads="Nur Ordnernamen der Erweiterungen und - falls möglich - ob sie in der Datenbank eingeschaltet sind. Zusätzlich werden die Standard-Speicherordner der Erweiterungen gelesen (Dateiname, Datum, Größe der drei neuesten Archive, Zugriffsschutz). Cloud-Ziele und eigene Ordner sieht das Programm nicht. "
          "Sicherungen des Hosters (Kundenbereich) sind von hier aus nicht sichtbar.",
    load="leicht", presets=["schnell", "hack"],
    wp={"title": "Sicherungs-Plugin"},
)
def backup_tool(ctx, res):
    cms = ctx.cms
    data = load_tools("backup")
    tools: List[Dict[str, Any]] = data.get(cms, [])
    if not tools:
        raise CheckSkipped("Die Liste der Sicherungs-Erweiterungen fehlt.")
    present, active = detect_tools(ctx, tools, "")
    ctx.shared["backup_tools"] = {"present": present, "active": active}
    by_id = {t["id"]: t for t in tools}
    found = [by_id[i] for i in present]
    if found:
        off = [t for t in found if active.get(t["id"]) is False]
        on = [t for t in found if active.get(t["id"]) is not False]
        paths = ["Pfad: %s" % clean_line(p) for t in found for p in present[t["id"]]][:6]
        if on:
            res.add("ok", "Sicherungs-Erweiterung vorhanden: %s" % ", ".join(t["name"] for t in on),
                    ("Das Programm sieht, dass sie installiert und eingeschaltet ist. " if any(active.get(t["id"]) is True for t in on) else "Das Programm sieht, dass sie installiert ist. ")
                    + "Wann zuletzt gesichert wurde und wo die Archive liegen, steht in den folgenden Zeilen, soweit sie am üblichen Speicherort der Erweiterung liegen. "
                    "Ob sich eine Sicherung zurückspielen lässt, prüft es nicht: Probiere die Wiederherstellung einmal aus.", paths)
            _backup_age_and_place(ctx, res, on)
            restore_hint(res, True)
        else:
            res.add("warn", "Sicherungs-Erweiterung ist installiert, aber ausgeschaltet", "%s ist vorhanden, aber nicht aktiv. Dann entstehen keine Sicherungen." % ", ".join(t["name"] for t in off), paths,
                    ctx.prof["enable_hint"])
        return
    if cms == "wordpress":
        items = ["%s - %s" % (t["name"], t["text"]) for t in tools if not t.get("background")]
    else:
        items = grouped(tools, lambda t: "%s | %s%s - %s [%s]" % (t["name"], t.get("price") or "Preis siehe JED", (" | " + t["developer"]) if t.get("developer") else "", t["text"], t["jed"]))
    res.add("info", "Kein Sicherungs-Tool (Erweiterung) gefunden",
            "Auf dieser Seite läuft keine bekannte Sicherungs-Erweiterung. Vielleicht sichert dein Hoster (Kundenbereich ansehen). Dann solltest du wissen, wie lange er aufbewahrt und wie man zurückspielt. "
            "Sonst ist eine eigene Sicherung der wichtigste Schutz nach Updates.", items,
            "Eine der Erweiterungen installieren. Das Programm bietet das bei den Aktionen an (Auswahl mit Beschreibung und Link zur Store-Seite). Stand der Liste: %s." % data.get("stand", "?"))
    restore_hint(res, False)
