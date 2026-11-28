"""Erweiterungen: Inventar aus den Manifest-Dateien und Abgleich mit bekannten Sicherheitslücken."""
from __future__ import annotations

import csv
import io
import re
from typing import Any, Dict, List

from .. import joomla
from ..registry import check
from ..util import clean_line, vcmp

G = "erweiterungen"

LIST_SCRIPT = r"""
LST=$( { find administrator/components -maxdepth 3 -name '*.xml' -type f 2>/dev/null
         find plugins -maxdepth 3 -name '*.xml' -type f 2>/dev/null
         find modules administrator/modules -maxdepth 2 -name '*.xml' -type f 2>/dev/null
         find templates administrator/templates -maxdepth 2 -name 'templateDetails.xml' -type f 2>/dev/null
         find administrator/manifests -maxdepth 2 -name '*.xml' -type f 2>/dev/null; } | sort -u )
echo '@@MANIFESTS'
printf '%s\n' "$LST" | while IFS= read -r f; do
  [ -f "$f" ] || continue
  head -c 3500 "$f" | grep -qE '<(extension|install)[ >]' || continue
  printf '@@@FILE %s\n' "$f"; head -c 3500 "$f"; echo
done
echo '@@DIRS'
for d in plugins/*/*; do [ -d "$d" ] && echo "plugin	$d"; done
for d in administrator/components/com_* components/com_*; do [ -d "$d" ] && echo "component	$d"; done
for d in modules/mod_* administrator/modules/mod_*; do [ -d "$d" ] && echo "module	$d"; done
for d in templates/* administrator/templates/*; do [ -d "$d" ] && echo "template	$d"; done
"""


def get_ext_fs(ctx) -> Dict[str, Any]:
    """Erweiterungs-Inventar aus dem Dateisystem (wird gecacht)."""
    if "ext_fs" in ctx.shared:
        return ctx.shared["ext_fs"]
    out = ctx.sh(LIST_SCRIPT, timeout=120).out
    head, _, tail = out.partition("@@DIRS")
    body = head.split("@@MANIFESTS", 1)[-1]
    manifests: List[Dict[str, str]] = []
    for chunk in body.split("@@@FILE ")[1:]:
        path, _, text = chunk.partition("\n")
        m = joomla.parse_manifest(path.strip(), text)
        if m:
            manifests.append(m)
    dirs: Dict[str, set] = {"plugin": set(), "component": set(), "module": set(), "template": set()}
    for ln in tail.splitlines():
        p = ln.split("\t")
        if len(p) == 2 and p[0] in dirs:
            dirs[p[0]].add(p[1])
    data = {"manifests": manifests, "dirs": dirs}
    ctx.shared["ext_fs"] = data
    return data


@check(
    "extensions_fs", G, "Erweiterungen und bekannte Sicherheitslücken",
    "Welche Erweiterungen sind installiert - und sind darunter Versionen mit bekannten Sicherheitslücken?",
    what="Liest die Beschreibungsdateien (Manifeste) aller Komponenten, Plugins, Module, Templates und Bibliotheken und erstellt eine Liste mit Name, "
         "Version, Hersteller und Datum. Diese wird mit einer Liste von Erweiterungen abgeglichen, für die Sicherheitslücken bekannt sind "
         "(JCE, Tassos Framework, Convert Forms, Helix Ultimate, SP Page Builder, T4 Page Builder).",
    why="Veraltete Erweiterungen sind der häufigste Einbruchsweg, nicht Joomla selbst. Bei dem Vorfall waren JCE und das Tassos Framework die "
        "wahrscheinlichsten Einfallstore. Die Liste lässt sich in der Datei claudia/advisories.json erweitern.",
    reads="Nur die kleinen XML-Beschreibungsdateien der Erweiterungen (kein Code).",
    load="leicht", presets=["schnell", "hack"],
)
def extensions_fs(ctx, res):
    data = get_ext_fs(ctx)
    ms = data["manifests"]
    if not ms:
        res.add("warn", "Keine Erweiterungs-Manifeste gefunden", "Verzeichnis falsch oder Joomla-Struktur ungewöhnlich.")
        return
    # Inventar als CSV in den Bericht
    buf = io.StringIO()
    wr = csv.writer(buf, delimiter=";")
    wr.writerow(["typ", "gruppe", "element", "name", "version", "autor", "datum", "pfad"])
    for m in sorted(ms, key=lambda x: (x["type"], x["group"], x["element"])):
        wr.writerow([m["type"], m["group"], m["element"], m["name"], m["version"], m["author"], m["date"], m["path"]])
    ctx.add_raw("erweiterungen.csv", buf.getvalue())

    adv = ctx.adv.get("extensions", [])
    vulnerable, current, sub_info = [], [], []
    for a in adv:
        el_re = re.compile(a.get("element_regex", "(?!x)x"), re.IGNORECASE)
        nm_re = re.compile(a.get("name_regex", "(?!x)x"), re.IGNORECASE)
        matched = []
        for m in ms:
            if m["type"] in ("file", "package"):
                continue
            if el_re.search(m["element"] or "") or nm_re.search(m["name"] or ""):
                matched.append(m)
        # Hauptteil (Komponente) und Untererweiterungen (Plugins/Module mit eigener Versionsnummer, z. B. 1.0) trennen:
        # Verglichen wird die Komponente. Nur wenn es keine gibt (z. B. reines Plugin wie nrframework), zählen die übrigen.
        primary = [m for m in matched if m["type"] == "component"]
        subs = [m for m in matched if m not in primary] if primary else []
        for m in (primary or matched):
            ver = m["version"]
            fixed = a.get("fixed_in", "")
            label = "%s %s (%s)" % (a["title"], ver or "?", m["path"])
            tag = "  [Kennung: %s/%s/%s]" % (m["type"], m["group"] or "-", m["element"]) if m.get("element") else ""
            cve = ("  [%s]" % a["cve"]) if a.get("cve") else ""
            if fixed and ver and vcmp(ver, fixed) >= 0:
                rec = a.get("recommended") or fixed
                current.append("%s - Version in Ordnung (behoben ab %s)%s" % (label, fixed, cve))
                if rec and vcmp(ver, rec) < 0:
                    current[-1] += ", empfohlen wird mindestens %s" % rec
            elif fixed:
                vulnerable.append((a, "%s - VERALTET, behoben ab %s (empfohlen %s)%s%s" % (label, fixed, a.get("recommended") or fixed, cve, tag)))
            else:
                vulnerable.append((a, "%s - bekannte Schwachstelle, behobene Version unklar%s%s" % (label, cve, tag)))
        if subs:
            sub_info.append("%s: %d zugehörige Plugins/Module mit eigener Versionsnummer (nicht verglichen, maßgeblich ist die Komponente)" % (a["title"], len(subs)))
    for sev in ("crit", "warn"):
        group = [(a, d) for a, d in vulnerable if a.get("severity", "warn") == sev]
        if not group:
            continue
        items: List[str] = []
        seen_adv = set()
        for a, d in group:
            items.append(d)
            if a["id"] not in seen_adv and a.get("note"):
                seen_adv.add(a["id"])
                items.append("    Hinweis zu %s: %s" % (a["title"], a["note"]))
        n = len(group)
        res.add(sev, "%d Erweiterung(en) mit bekannter Sicherheitslücke" % n,
                "Der Vergleich stammt aus einer Liste vom %s und ist nicht vollständig." % ctx.adv.get("stand", "?"), items,
                "Sofort auf die genannte Version oder neuer aktualisieren (System -> Aktualisieren). Nicht benötigte Erweiterungen deinstallieren.")
    if current:
        res.add("ok" if not vulnerable else "info", "Erweiterungen auf bekannt sicherem Stand", "Laut der Vergleichsliste vom %s." % ctx.adv.get("stand", "?"), current)
    if sub_info:
        res.add("info", "Zugehörige Plugins und Module wurden nicht einzeln verglichen",
                "Untererweiterungen tragen oft eine eigene, niedrige Versionsnummer (z. B. 1.0), die nichts über die Sicherheit aussagt.", sub_info, context=True)
    if not vulnerable and not current:
        res.add("ok", "Keine der bekannten verwundbaren Erweiterungen installiert",
                "Geprüft gegen: %s." % ", ".join(a["title"] for a in adv))
    # Inventar-Übersicht
    third = [m for m in ms if m["type"] not in ("file", "package") and "joomla! project" not in (m["author"] or "").lower()
             and "joomla project" not in (m["author"] or "").lower()]
    authors: Dict[str, int] = {}
    for m in third:
        authors[m["author"] or "(kein Autor)"] = authors.get(m["author"] or "(kein Autor)", 0) + 1
    res.add("info", "%d Erweiterungen insgesamt, davon %d nicht vom Joomla-Projekt" % (len(ms), len(third)),
            "Die vollständige Liste liegt im Bericht (erweiterungen.csv). Prüfe, ob du alle Hersteller kennst.",
            ["%s: %d" % (k, v) for k, v in sorted(authors.items(), key=lambda kv: (-kv[1], kv[0]))][:40], context=True)
    unnamed = [m for m in third if not m["author"] or not m["version"]]
    if unnamed:
        res.add("warn", "%d Erweiterung(en) ohne Autor oder Version" % len(unnamed),
                "Echte Erweiterungen geben beides an. Selbstgebaute Plugins sind aber auch möglich (z. B. dein eigenes renderfix).",
                [clean_line("%s %s (%s)" % (m["name"], m["version"], m["path"])) for m in unnamed][:30],
                "Prüfen, ob du die Erweiterung kennst.")
