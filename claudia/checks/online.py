"""Abgleich mit Online-Quellen: Joomla-Liste verwundbarer Erweiterungen (VEL) und Erweiterungsverzeichnis (JED).

Beide Tests laufen von DIESEM PC aus (normale Seitenaufrufe, nichts wird gesendet außer Erweiterungsnamen im Suchaufruf)
und nutzen das Inventar aus den Manifest-Dateien des Servers.
"""
from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List, Optional, Tuple

from ..model import CheckSkipped, Option
from ..registry import check
from ..util import clean_line, digits, trunc, vcmp
from .ext import get_ext_fs
from .web import UA_BROWSER, fetch

G = "erweiterungen"
VEL_URLS = ["https://extensions.joomla.org/vel-feed", "https://extensions.joomla.org/index.php?option=com_vel&format=json"]


def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", (s or "").lower())


def _as_dict(v: Any) -> Dict[str, Any]:
    if isinstance(v, dict):
        return v
    if isinstance(v, str):
        try:
            d = json.loads(v)
            return d if isinstance(d, dict) else {}
        except ValueError:
            return {}
    return {}


def parse_vel(text: str) -> List[Dict[str, Any]]:
    """Liest die Einträge aus der JSON-Antwort der VEL. Leere Liste, wenn das Format nicht passt."""
    try:
        data = json.loads(text)
    except ValueError:
        return []
    if isinstance(data, dict) and "data" in data and isinstance(data["data"], dict):
        data = data["data"]
    items = data.get("items") if isinstance(data, dict) else data
    return [i for i in (items or []) if isinstance(i, dict)]


def vel_matches(items: List[Dict[str, Any]], manifests: List[Dict[str, str]]) -> List[Tuple[Dict[str, Any], Dict[str, str], str]]:
    """(Eintrag, Manifest, Einstufung) für jede installierte Erweiterung, die laut VEL betroffen ist."""
    out = []
    for it in items:
        inst = _as_dict(it.get("install_data"))
        names = {_norm(inst.get("name", "")), _norm(inst.get("element", ""))} - {""}
        if not names:
            continue
        start, vuln, patch = (str(it.get(k) or "").strip() for k in ("start_version", "vulnerable_version", "patch_version"))
        for m in manifests:
            if m["type"] in ("file", "package") or not m["version"]:
                continue
            if not (names & {_norm(m["name"]), _norm(m["element"])}):
                continue
            ver = m["version"]
            if start and vcmp(ver, start) < 0:
                continue
            if vuln and vcmp(ver, vuln) > 0:
                continue
            if patch and vcmp(ver, patch) >= 0:
                continue
            live = str(it.get("status")) == "1"
            out.append((it, m, "live" if live else "behoben" if not _scheme_mismatch(ver, patch or vuln) else "schema"))
    return out


def _scheme_mismatch(installed: str, listed: str) -> bool:
    """Zusatz-Plugins tragen oft die Platzhalter-Version '1.0' (z. B. die Convert-Forms-Plugins) und werden nur wegen eines ähnlichen Namens
    mit einem Eintrag wie 'AcyMailing 5.9.5' verwechselt. Dann sagt der Versionsvergleich nichts aus."""
    if not (installed.startswith("1.0") and re.match(r"^1\.0(\.0)*\Z", installed)):
        return False
    m = re.match(r"^(\d+)", listed or "")
    return bool(m) and int(m.group(1)) >= 3


@check(
    "vel_feed", G, "Aktuelle Joomla-Liste verwundbarer Erweiterungen (online)",
    "Gibt es zu deinen Erweiterungen aktuelle Sicherheitsmeldungen auf der offiziellen Joomla-Liste?",
    what="Lädt die öffentliche Liste verwundbarer Erweiterungen (Vulnerable Extensions List, VEL) von extensions.joomla.org und vergleicht sie mit den "
         "installierten Erweiterungen und deren Versionen. Die Liste ist immer aktuell; die eingebaute Liste im Programm hat dagegen nur einen Stand.",
    why="Neue Lücken werden täglich bekannt. Nur der Abgleich mit der offiziellen Liste zeigt sie, bevor sie ausgenutzt werden.",
    reads="Ruft die öffentliche Adresse der Liste von deinem PC aus ab (wie ein Browser). Zum Server wird nichts gesendet, es werden nur die Manifest-Dateien gelesen.",
    load="leicht", presets=["schnell", "hack"],
    options=[Option("feed_url", "Adresse der Liste (nur ändern, wenn sich die Adresse geändert hat)", "text", "", "Leer = offizielle Adresse von extensions.joomla.org.")],
)
def vel_feed(ctx, res):
    if os.environ.get("CLAUDIA_OFFLINE"):
        raise CheckSkipped("Offline-Modus (CLAUDIA_OFFLINE): Die Online-Liste wird nicht abgerufen.")
    data = get_ext_fs(ctx)
    custom = str(ctx.opt("feed_url", "") or "").strip()
    urls = [custom] if custom else VEL_URLS
    items: List[Dict[str, Any]] = []
    errors: List[str] = []
    used = ""
    pre = (ctx.shared.get("intel") or {}).get("vel") if not custom else None
    if pre:
        items, used, urls = pre, "Joomla-VEL, zu Beginn des Laufs geladen", []
    for u in urls:
        ctx.progress("Lade Liste von %s" % u.split("/")[2])
        f = fetch(u, UA_BROWSER, max_bytes=20_000_000, timeout=20)
        if f.error:
            errors.append("%s: %s" % (u, f.error))
            continue
        items = parse_vel(f.body)
        if items:
            used = u
            break
        errors.append("%s: keine lesbare Liste (HTTP %d)" % (u, f.status))
    if not items:
        raise CheckSkipped("Die Liste konnte nicht geladen werden (%s). Ohne Internet oder bei geänderter Adresse bleibt der eingebaute Abgleich "
                           "aus dem Test 'Erweiterungen und bekannte Sicherheitslücken' aktiv." % "; ".join(errors))
    hits = vel_matches(items, data["manifests"])
    live = [h for h in hits if h[2] == "live"]
    old = [h for h in hits if h[2] == "behoben"]
    schema = [h for h in hits if h[2] == "schema"]

    def line(h):
        it, m, _ = h
        cve = it.get("cve_id") or ""
        patch = it.get("patch_version") or ""
        return clean_line("%s %s (%s) - %s%s%s" % (m["name"] or m["element"], m["version"], m["path"], trunc(str(it.get("title") or ""), 90),
                                                 ("  [%s]" % cve) if cve else "",
                                                 (" - behoben in %s" % patch) if patch else " - noch KEIN Update bekannt"))
    if live:
        res.add("crit", "%d installierte Erweiterung(en) stehen auf der Joomla-Liste verwundbarer Erweiterungen" % len(live),
                "Die Liste nennt für diese Versionen eine bekannte, noch offene oder nur in neueren Versionen behobene Lücke.", [line(h) for h in live][:40],
                "Auf die genannte Version oder neuer aktualisieren. Gibt es noch kein Update, die Erweiterung deaktivieren oder entfernen, bis es eines gibt.")
    if old:
        res.add("warn", "%d Erweiterung(en) mit bereits behobener Lücke in deiner (alten) Version" % len(old),
                "Die Lücke ist in einer neueren Version behoben, deine Version ist älter.", [line(h) for h in old][:40], "Erweiterung aktualisieren.")
    if schema:
        res.add("info", "%d mögliche Verwechslung(en) wegen Platzhalter-Version nicht gewertet" % len(schema),
                "Zusatz-Plugins haben oft die Version 1.0 und tragen den Namen einer anderen Erweiterung (z. B. AcyMailing). Der Versionsvergleich wäre sinnlos; "
                "maßgeblich ist die Hauptkomponente (Convert Forms o. ä.).", [line(h) for h in schema][:20], context=True)
    if not (live or old):
        res.add("ok", "Keine deiner Erweiterungen steht (mit passender Version) auf der Joomla-Liste",
                "%d Einträge der Liste geprüft (Quelle: %s). Der Abgleich läuft über Namen und Versionen, kleine Abweichungen in der Schreibweise können Treffer verpassen." % (len(items), used))
    if live or old:
        res.add("info", "Umfang des Abgleichs", "%d Einträge der Liste geprüft (Quelle: %s)." % (len(items), used))


# ----------------------------------------------------------------------------- JED
JED_BASE = "https://extensions.joomla.org/extension/"
_REV = re.compile(r"(\d[\d.,]*)\s+reviews?", re.IGNORECASE)


def _slug(name: str) -> str:
    return re.sub(r"-+", "-", re.sub(r"[^a-z0-9]+", "-", (name or "").lower())).strip("-")


_PREFIX_RE = re.compile(r"^(system|content|plugin|editors?|authentication|quickicon|user|search|component|module|template|finder|fields|captcha)\s*-\s*", re.I)
_GENERIC_TAIL = re.compile(r"\s+(framework|component|plugin|module|extension|pro|free|for joomla!?|library)$", re.I)


def _short(m: Dict[str, str]) -> str:
    return _norm(re.sub(r"^(plg|com|mod|tpl)_", "", m.get("element", ""), flags=re.I))


def jed_candidates(m: Dict[str, str], known: Optional[Dict[str, str]] = None) -> List[str]:
    """Wahrscheinliche Adress-Namen im Verzeichnis (JED) für eine Erweiterung. Geprüfte Adressen aus der Liste kommen zuerst."""
    out: List[str] = []
    short = _short(m)
    if known and short in known:
        out.append(known[short])
    name = m.get("name", "")
    if name and not re.match(r"^(COM|MOD|PLG|TPL)_", name):        # Sprachschlüssel wie COM_JCE sind kein Anzeigename
        clean = _PREFIX_RE.sub("", name).strip()
        out.append(_slug(clean))
        trimmed = clean
        while _GENERIC_TAIL.search(trimmed):
            trimmed = _GENERIC_TAIL.sub("", trimmed).strip()
            out.append(_slug(trimmed))
    out.append(_slug(re.sub(r"^(plg|com|mod|tpl)_", "", m.get("element", ""), flags=re.I)))
    uniq: List[str] = []
    for x in out:
        if x and not digits(x) and x not in uniq:
            uniq.append(x)
    return uniq[:4]


def classify_third(manifests: List[Dict[str, str]], jed: Dict[str, Any]) -> Tuple[List[Dict[str, str]], List[str], List[str]]:
    """Trennt: (einzeln nachzuschlagen, zu einer Hauptkomponente gehörig, mit Joomla mitgeliefert)."""
    family = jed.get("family", {})
    bundled = set(jed.get("bundled", []))
    comps = [x for x in manifests if x["type"] == "component"]
    comp_keys = {_short(c) for c in comps if len(_short(c)) >= 5}
    main, parts, core = [], [], []
    seen = set()
    for m in manifests:
        if m["type"] not in ("component", "template", "plugin", "module"):
            continue
        a = (m["author"] or "").lower()
        if "joomla" in a and "project" in a:
            continue
        label = "%s %s" % (m["name"] or m["element"], m["version"])
        short = _short(m)
        if m["type"] == "plugin" and short in bundled and m.get("group") in ("editors", "editors-xtd"):
            core.append(label)
            continue
        if m["type"] in ("plugin", "module", "template"):
            grp = _norm(m.get("group", ""))
            fam = family.get(short, "")
            if (fam and fam in comp_keys) or any(k in grp or (k in short and m["type"] != "template") for k in comp_keys):
                parts.append(label)
                continue
        key = re.sub(r"^shaper", "", short) if m["type"] in ("template", "plugin") else short
        if key in seen:
            parts.append(label)                 # z. B. Helix Ultimate als Plugin und Template: nur einmal nachschlagen
            continue
        seen.add(key)
        main.append(m)
    return main, parts, core


def parse_jed_page(body: str) -> Optional[Dict[str, str]]:
    """Titel, Hersteller, Bewertungsanzahl aus einer JED-Seite. None, wenn es keine Erweiterungsseite ist."""
    t = re.search(r"<title>(.*?)</title>", body, re.I | re.S)
    title = clean_line(re.sub(r"\s+", " ", t.group(1))) if t else ""
    if not re.search(r"Developer:|Reviews?\s*\(\d|Compatibility:", body):
        return None
    dev = re.search(r"Developer:\s*(?:</[^>]+>\s*)*(?:<[^>]+>\s*)*([^<\n]{2,60})", body)
    rev = _REV.search(body)
    return {"title": title, "developer": clean_line(dev.group(1)).strip() if dev else "", "reviews": rev.group(1) if rev else ""}


@check(
    "jed_listing", G, "Erweiterungen im offiziellen Joomla-Verzeichnis (JED) nachschlagen",
    "Ist jede Erweiterung von Drittanbietern im offiziellen Verzeichnis gelistet - und was sagen die Nutzer?",
    what="Sucht zu den Erweiterungen von Drittanbietern die Seite im Joomla Extensions Directory (extensions.joomla.org) und zeigt Hersteller und Anzahl der Nutzerbewertungen. "
         "Das Verzeichnis hat keine öffentliche Such-Schnittstelle: Das Programm rät die Adresse aus dem Erweiterungsnamen. Nicht gefundene Erweiterungen werden gesondert aufgeführt.",
    why="Erweiterungen im Verzeichnis werden vom Joomla-Team geprüft. Eine Erweiterung ohne Eintrag ist nicht automatisch schlecht (Eigenbau, Kauf-Erweiterungen), "
        "verdient aber einen zweiten Blick. Bewertungen ersetzen keine Sicherheitsprüfung.",
    reads="Ruft für jede Erweiterung höchstens zwei Seiten bei extensions.joomla.org ab (von deinem PC, wie ein Browser). Dauert je nach Anzahl einige Minuten.",
    load="mittel", presets=[],
    options=[Option("max", "Höchstens so viele Erweiterungen nachschlagen", "int", 30, "Jede Abfrage dauert etwa eine Sekunde."),
             ],
)
def jed_listing(ctx, res):
    if os.environ.get("CLAUDIA_OFFLINE"):
        raise CheckSkipped("Offline-Modus (CLAUDIA_OFFLINE): Das Verzeichnis wird nicht abgefragt.")
    data = get_ext_fs(ctx)
    jed = ctx.adv.get("jed", {})
    third, parts, core = classify_third(data["manifests"], jed)
    limit = max(1, ctx.opt_int("max", 30))
    found, missing, unreachable = [], [], []
    for m in third[:limit]:
        ctx.progress("Schlage %s nach" % (m["name"] or m["element"])[:40])
        page, errs = None, 0
        for slug in jed_candidates(m, jed.get("slugs")):
            f = fetch(JED_BASE + slug + "/", UA_BROWSER, max_bytes=600_000, timeout=20)
            if f.error or f.status in (0, 403, 429) or f.status >= 500:
                errs += 1
                continue
            if f.status == 200:
                page = parse_jed_page(f.body)
                if page:
                    page["url"] = JED_BASE + slug + "/"
                    break
        label = "%s %s (%s)" % (m["name"] or m["element"], m["version"], m["author"] or "ohne Autor")
        if page:
            found.append(clean_line("%s - JED: %s, Hersteller laut JED: %s, %s Bewertung(en)  %s" % (label, trunc(page["title"], 50), page["developer"] or "?", page["reviews"] or "?", page["url"])))
        elif errs:
            unreachable.append(label)
        else:
            q = re.sub(r"[^A-Za-z0-9]+", "+", _PREFIX_RE.sub("", m["name"] or m["element"])).strip("+")
            missing.append("%s - Suche im Verzeichnis: https://extensions.joomla.org/extensions/?searchall=%s" % (label, q))
    if not third:
        res.add("info", "Keine Erweiterungen von Drittanbietern gefunden")
        return
    if found:
        res.add("info", "%d Erweiterung(en) im Joomla-Verzeichnis gefunden" % len(found),
                "Prüfe, ob der Hersteller im Verzeichnis zu dem in deiner Erweiterung passt. Viele positive Bewertungen sind ein gutes Zeichen, aber kein Beweis.", found)
    if unreachable:
        res.add("info", "%d Erweiterung(en): Das Verzeichnis war nicht abrufbar" % len(unreachable),
                "Die Seite antwortete nicht oder wurde gesperrt (z. B. Schutz vor automatischen Abrufen). Das sagt nichts über die Erweiterung. Später erneut versuchen.", unreachable[:40])
    if missing:
        res.add("info", "%d Erweiterung(en) nicht automatisch zugeordnet" % len(missing),
                "Das Programm hat die Adresse im Verzeichnis nicht erraten. Das bedeutet NICHT, dass die Erweiterung dort fehlt oder unseriös ist: "
                "Namen im Verzeichnis weichen oft von den Namen in der Installation ab. Über den Link siehst du die Suche im Verzeichnis.", missing[:40])
    if parts:
        res.add("info", "%d Plugins/Module gehören zu einer Hauptkomponente" % len(parts),
                "Sie werden nicht einzeln nachgeschlagen: Im Verzeichnis ist nur das Gesamtpaket gelistet (z. B. Convert Forms mit seinen Zusatz-Plugins).", parts[:40])
    if core:
        res.add("info", "%d Erweiterung(en) werden mit Joomla selbst mitgeliefert" % len(core),
                "Der Editor TinyMCE und CodeMirror gehören zum Joomla-Paket und stehen deshalb nicht einzeln im Verzeichnis.", core)
    if len(third) > limit:
        res.add("info", "Nur die ersten %d von %d Erweiterungen wurden nachgeschlagen" % (limit, len(third)), "Erhöhe die Zahl in den Optionen des Tests.")
