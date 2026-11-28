"""Aktuelle Bedrohungslage: neue CVEs (NVD) und VEL-Einträge gegen Version und installierte Erweiterungen abgleichen. Rein lesend."""
from __future__ import annotations

import os
import re
from typing import Any, Dict, List

from .. import cms as cmsmod, intel as intelmod, joomla, wordpress
from ..model import CheckSkipped
from ..registry import check
from ..util import clean_line, trunc

G = "grundlagen"
# Plugin-Gruppen von Joomla selbst; andere Gruppen gehören zu einer Erweiterung (z. B. convertforms, acf, j2store)
JOOMLA_PLUGIN_GROUPS = {"actionlog", "api-authentication", "authentication", "behaviour", "captcha", "content", "editors", "editors-xtd", "extension", "fields",
                        "filesystem", "finder", "installer", "media-action", "multifactorauth", "privacy", "quickicon", "sampledata", "schemaorg", "system", "task",
                        "twofactorauth", "user", "webservices", "workflow", "search", "console"}


def load_intel(ctx) -> Dict[str, Any]:
    if "intel" not in ctx.shared:
        ctx.shared["intel"] = intelmod.load(ctx.cms, offline=bool(os.environ.get("CLAUDIA_OFFLINE")))
    return ctx.shared["intel"]


def inventory(ctx) -> List[Dict[str, str]]:
    """[{key, names[], version, kind, label}] der installierten Erweiterungen (Joomla) bzw. Plugins und Themes (WordPress)."""
    out: List[Dict[str, str]] = []
    if ctx.cms == "wordpress":
        from .wp import get_wp_fs
        d = get_wp_fs(ctx)
        for kind, lst in (("plugin", d["plugins"]), ("theme", d["themes"])):
            for x in lst:
                out.append({"key": x["slug"], "names": [x["slug"], x.get("name", "")], "version": x.get("version", ""), "kind": kind, "label": x.get("name") or x["slug"]})
        return out
    from .ext import get_ext_fs
    for m in get_ext_fs(ctx)["manifests"]:
        if m["type"] in ("file", "package", "library") or not m.get("version"):
            continue
        if "joomla" in (m.get("author") or "").lower() and "project" in (m.get("author") or "").lower():
            continue
        el = re.sub(r"^(plg|com|mod|tpl)_", "", m.get("element", ""), flags=re.I)
        group = (m.get("group") or "").lower()
        if m["type"] == "plugin" and group and group not in JOOMLA_PLUGIN_GROUPS:
            # Zusatz-Plugin einer anderen Erweiterung (z. B. convertforms/acymailing = ConvertForms-Anbindung AN AcyMailing): das Element nennt das Ziel,
            # nicht das Produkt. Allein würde "acymailing" fälschlich Lücken in AcyMailing selbst zuordnen.
            el = "%s_%s" % (group, el)
        names = [m.get("name", ""), el]
        out.append({"key": m.get("element") or m.get("name"), "names": [n for n in names if n and not re.match(r"^(COM|MOD|PLG|TPL)_", n) and intelmod._norm(n) not in intelmod.GENERIC_NAMES], "version": m["version"],
                    "kind": m["type"], "label": m.get("name") or m.get("element")})
    return out


def evaluate(intel: Dict[str, Any], core_version: str, inv: List[Dict[str, str]], cms: str) -> Dict[str, Any]:
    """Treffer des Kerns und der Erweiterungen. Reine Funktion (testbar)."""
    core = intelmod.core_hits(intel, cmsmod.known(cms), core_version) if core_version else []
    ext: List[Dict[str, Any]] = []
    for e in inv:
        hits = intelmod.extension_hits(intel, e["names"], e["version"])
        merged: Dict[str, Dict[str, Any]] = {}
        for lst in hits.values():
            for c in lst:
                cur = merged.get(c["id"])
                if not cur or (cur["match"] == "name" and c["match"] == "confirmed"):
                    merged[c["id"]] = c
        if merged:
            ext.append({"inv": e, "cves": sorted(merged.values(), key=lambda c: (c["match"] != "confirmed", -c["score"]))})
    return {"core": core, "ext": ext}


def sev_for(score: float) -> str:
    return "crit" if score >= 9.0 else "warn" if score >= 4.0 else "info"


def cve_line(c: Dict[str, Any]) -> str:
    return clean_line("%s (CVSS %s, %s) - %s" % (c["id"], c["score"] or "?", c["pub"], trunc(c["text"], 110)))


def watch_patterns(ctx) -> List[Dict[str, str]]:
    """Zusätzliche Suchmuster für die Zugriffsprotokolle: POST-Aufrufe auf Erweiterungen, für die aktuell eine passende Lücke gemeldet ist."""
    intel = ctx.shared.get("intel")
    if not intel or not (intel.get("cves")):
        return []
    try:
        res = evaluate(intel, "", inventory(ctx), ctx.cms)
    except Exception:                                              # noqa: BLE001  (Zusatzsuche darf Protokollprüfung nie verhindern)
        return []
    pats = []
    for h in res["ext"]:
        conf = [c for c in h["cves"] if c["match"] == "confirmed"]
        if not conf:
            continue
        e = h["inv"]
        key = re.escape(e["key"] if ctx.cms == "wordpress" else re.sub(r"^plg_[a-z]+_", "", e["key"]))
        rx = ('POST [^"]*/wp-content/%ss/%s/' % (e["kind"], key)) if ctx.cms == "wordpress" else ('POST [^"]*(option=%s|plugin=%s)([&" ]|$)' % (key, key))
        pats.append({"id": "intel_" + re.sub(r"\W+", "_", e["key"]), "title": "Schreibende Aufrufe von %s (aktuelle Meldung %s)" % (e["label"], conf[0]["id"]), "regex": rx, "severity": "warn"})
    return pats[:15]


@check(
    "threat_intel", G, "Aktuelle Bedrohungslage (NVD/CVE und Joomla-VEL)",
    "Gibt es neue Sicherheitsmeldungen zu deiner Version oder deinen Erweiterungen?",
    what="Lädt vor jedem Lauf die neuesten Meldungen aus der Schwachstellen-Datenbank NVD (CVE) und die Joomla-Liste verwundbarer Erweiterungen (VEL), gleicht sie mit der installierten Version "
         "und den installierten Erweiterungen ab und zeigt die aktuellen Vorfälle. Für betroffene Erweiterungen sucht der Protokoll-Test zusätzlich gezielt nach schreibenden Aufrufen.",
    why="Neue Lücken werden täglich bekannt und sofort ausgenutzt. Die eingebauten Listen im Programm haben nur einen Stand; nur der Blick in die Datenbanken zeigt, was seit dem letzten Update dazugekommen ist.",
    reads="Ruft von diesem PC aus services.nvd.nist.gov und extensions.joomla.org ab (https, nur die öffentliche Suche). Zum Server geht dabei nichts; dort werden nur die Versionsdateien gelesen.",
    load="leicht", needs="web", presets=["schnell", "hack"],
)
def threat_intel(ctx, res):
    intel = load_intel(ctx)
    if not (intel.get("cves") or intel.get("vel")):
        raise CheckSkipped("Die Online-Quellen waren nicht erreichbar (%s). Es gilt der eingebaute Stand vom %s." % ("; ".join(intel.get("errors") or ["keine Angabe"]), ctx.adv.get("stand", "?")))
    wp = ctx.cms == "wordpress"
    ver = ctx.shared.get("wp_version" if wp else "joomla_version") or ""
    if not ver:
        if wp:
            ver = wordpress.parse_wp_version(ctx.sh("head -c 6000 wp-includes/version.php 2>/dev/null").out)["version"]
        else:
            r = ctx.sh("head -c 8000 libraries/src/Version.php 2>/dev/null; echo '@@M'; head -c 4000 administrator/manifests/files/joomla.xml 2>/dev/null").out
            a, _, b = r.partition("@@M")
            ver = joomla.parse_joomla_version(a, b)
    hits = evaluate(intel, ver, inventory(ctx), ctx.cms)
    cves = intel.get("cves", [])
    src = "NVD%s%s" % (" (%d Meldungen der letzten %d Tage)" % (len(cves), intelmod.WINDOW_DAYS[ctx.cms]) if intel.get("nvd_ok") or cves else " (nicht erreichbar)",
                       (", Joomla-VEL (%d Einträge)" % len(intel["vel"])) if intel.get("vel") else "")
    note = " Die Daten stammen aus dem Zwischenspeicher (%s)." % intel.get("stand") if intel.get("cached") else ""
    if intel.get("stale"):
        note = " Die Online-Quellen waren nicht erreichbar; es werden ältere Daten vom %s benutzt." % intel.get("stand")
    shown = hits["core"] or hits["ext"]
    for c in hits["core"][:12]:
        res.add(sev_for(c["score"]), "%s: aktuelle Meldung für deine Version %s" % (c["id"], ver), "%s Veröffentlicht am %s, CVSS %s. %s" % (trunc(c["text"], 400), c["pub"], c["score"] or "?", ""),
                ["https://nvd.nist.gov/vuln/detail/" + c["id"]], "Auf die aktuelle Version aktualisieren (Joomla-Aktualisierung bzw. WordPress-Dashboard) und danach den Test noch einmal laufen lassen.")
    for h in hits["ext"][:25]:
        e = h["inv"]
        conf = [c for c in h["cves"] if c["match"] == "confirmed"]
        name_only = [c for c in h["cves"] if c["match"] == "name"]
        if conf:
            top = max(c["score"] for c in conf)
            res.add(sev_for(top), "%s %s: %d aktuelle Meldung(en) zu dieser Version" % (e["label"], e["version"], len(conf)),
                    "Die NVD nennt für diese Version eine Schwachstelle. Gibt es ein Update, schließt es sie meist.", [cve_line(c) for c in conf[:6]],
                    "Erweiterung aktualisieren. Gibt es noch keines, deaktivieren oder ersetzen, bis eine behobene Version erscheint.")
        elif name_only:
            res.add("info", "%s: Erwähnung in %d aktuellen Meldung(en)" % (e["label"], len(name_only)),
                    "Der Name steht in der Beschreibung, die betroffene Version ließ sich aber nicht eindeutig zuordnen. Bitte von Hand nachlesen.", [cve_line(c) for c in name_only[:5]],
                    "Meldung lesen und die genannte Version mit deiner vergleichen.")
    if not shown:
        res.add("ok", "Keine aktuelle Meldung betrifft deine Version oder deine Erweiterungen",
                "Abgeglichen mit %s. %d Erweiterungen/Plugins mit Version wurden berücksichtigt. Angezeigt wird nur, was zu etwas passt, das auf diesem Server installiert ist.%s" % (src, len(inventory(ctx)), note))
    ctx.add_raw("bedrohungslage", "\n".join("%s %s %s" % (c["id"], c["score"], c["pub"]) for c in cves[:500]))
