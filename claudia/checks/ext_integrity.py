"""Erweiterungen: Dateien gegen das Paket des Herstellers vergleichen (2.4.1). Eigenes Modul, weil es die Datenbank-Hilfen braucht."""
from __future__ import annotations

import difflib
import os
import re
import time
from typing import Any, Dict, List, Tuple

from .. import coreref, extsums, joomla, secure, updcheck, wpsums
from ..model import CheckSkipped, Option
from ..registry import check
from ..util import clean_line, sq
from .database import fetch, need_db

G = "erweiterungen"


INSTALL_ONLY = re.compile(r"(^|/)(packages/|script\.install[^/]*\.php$|[^/]*installer[^/]*\.php$|install\.[^/]*$|uninstall\.[^/]*$)"
                          r"|\.j3(_[a-z]+)?\.php$|(^|/)j3/", re.I)      # .j3.php: Joomla-3-Fassung, die das Installationsskript unter Joomla 4+ entfernt
MAX_DIFFS = 12           # so viele geänderte Dateien bekommen eine Gegenüberstellung (Codefenster)
DIFF_LINES = 160


def split_missing(missing):
    """Fehlende Dateien (Form 'Erweiterung: Ordner/Datei') in normale und reine Installationsdateien trennen. Installationsdateien (Zusatz-Pakete unter packages/, script.install*.php, *installer*.php) löscht das Installationsprogramm nach der Installation selbst."""
    normal, inst = [], []
    for m in missing:
        path = m.split(": ", 1)[-1]
        (inst if INSTALL_ONLY.search(path) else normal).append(m)
    return normal, inst


def count_by_ext(entries):
    """Eine Zeile je Erweiterung mit der Zahl der Dateien (statt tausender Einzelzeilen)."""
    cnt = {}
    for m in entries:
        k = m.split(": ", 1)[0]
        cnt[k] = cnt.get(k, 0) + 1
    return ["%s: %d Datei(en)" % (k, v) for k, v in sorted(cnt.items(), key=lambda kv: -kv[1])[:30]]



@check(
    "ext_integrity", G, "Erweiterungen gegen das Paket des Herstellers prüfen",
    "Stimmen die Dateien von Erweiterungen mit dem Paket überein, das der Hersteller ausliefert?",
    what="Liest aus der Datenbank, welche Erweiterungen eine öffentliche Update-Adresse haben, und ruft dort die Update-Datei ab. Bietet der Update-Server GENAU die installierte Version an, "
         "wird deren Paket einmal geladen (nur im Speicher gelesen, nie entpackt oder ausgeführt) und die Prüfsumme jeder Datei mit der auf dem Server verglichen. "
         "Gemeldet werden geänderte, zusätzliche und fehlende PHP-Dateien. Erweiterungen ohne Update-Adresse, mit Lizenzschlüssel, mit älterer Version als auf dem Update-Server oder als Paket-Sammlung werden als nicht prüfbar aufgelistet.",
    why="Hintertüren stecken oft in Dateien echter Erweiterungen, ohne dass ein Suchmuster anschlägt. Nur der Vergleich mit dem Original zeigt, dass eine Datei nicht mehr dem entspricht, was der Hersteller ausliefert. "
        "Der Vergleich beweist die Übereinstimmung mit dem Paket, das der Hersteller aktuell ausliefert; er kann nicht beweisen, dass dieses Paket selbst sauber ist.",
    reads="Prüfsummen der Erweiterungs-Dateien (Dateien werden nicht übertragen) und die Update-Adressen aus der Datenbank. Von diesem PC aus wird je Erweiterung eine Update-Datei und ein Paket (höchstens 25 MB) vom Update-Server des Herstellers geladen (https, nacheinander, mit Pause, höchstens die eingestellte Anzahl).",
    load="mittel", presets=["hack"], cms="joomla",
    options=[Option("max", "Höchstens so viele Erweiterungen prüfen", "int", 12, "Jedes Paket wird einzeln geladen, das dauert einige Sekunden.")],
)
def ext_integrity(ctx, res):
    if os.environ.get("CLAUDIA_OFFLINE"):
        raise CheckSkipped("Offline-Modus (CLAUDIA_OFFLINE): Die Pakete werden nicht abgerufen.")
    db = need_db(ctx, res, "Erweiterungen gegen das Paket des Herstellers prüfen", [("Update-Server der Erweiterungen", updcheck.SITES_SQL)])
    rows = fetch(db, updcheck.SITES_SQL)
    sites = extsums.sites_from_rows(rows or [])
    ver = ctx.shared.get("joomla_version") or ""
    if not ver:
        r = ctx.sh("head -c 8000 libraries/src/Version.php 2>/dev/null; echo '@@M'; head -c 4000 administrator/manifests/files/joomla.xml 2>/dev/null").out
        a, _, b = r.partition("@@M")
        ver = joomla.parse_joomla_version(a, b)
    if not ver:
        raise CheckSkipped("Joomla-Version nicht erkannt.")
    cands = [x for x in sites if x["type"] in ("component", "module", "plugin", "template") and x["version"]]
    skipped_other = [x for x in sites if x not in cands and x["type"] == "package"]
    no_ref: List[str] = []
    err: List[str] = []
    jobs = []      # (Erweiterung, [(Ordner im ZIP, Ordner auf dem Server)], Dateien im ZIP)
    limit = max(1, ctx.opt_int("max", 12))
    cache_xml: Dict[str, Any] = {}
    checked = 0
    seen_eid = set()
    for x in cands:
        if x["eid"] in seen_eid:
            continue
        label = "%s %s" % (clean_line(x["name"]), x["version"])
        if re.match(r"^https?://([a-z0-9-]+\.)*joomla\.org/", x["location"], re.I):
            continue                                       # Joomla-eigene Erweiterung: gehört zum Kern, den der Kernvergleich prüft
        if x["needs_key"]:
            no_ref.append("%s (braucht einen Lizenzschlüssel)" % label)
            continue
        if x["location"].startswith("http://"):
            x = dict(x, location="https://" + x["location"][7:])         # viele Hersteller liefern dieselbe Adresse auch per https
            if not secure.is_secure_url(x["location"]) or updcheck._get(x["location"]) is None:
                no_ref.append("%s (Update-Adresse nur ohne https erreichbar)" % label)
                continue
        if not x["location"].startswith("https://") or not secure.is_secure_url(x["location"]):
            no_ref.append("%s (Update-Adresse ohne https)" % label)
            continue
        if checked >= limit:
            err.append("Weitere Erweiterungen wegen der Höchstzahl nicht geprüft")
            break
        seen_eid.add(x["eid"])
        checked += 1
        ctx.progress("Update-Server: %s" % re.sub(r"^https://([^/]+).*$", r"\1", x["location"])[:60])
        if x["location"] not in cache_xml:
            time.sleep(updcheck.PAUSE)
            cache_xml[x["location"]] = updcheck._get(x["location"])
        body = cache_xml[x["location"]]
        if body is None:
            err.append("%s (Update-Server nicht erreichbar)" % label)
            continue
        entries = extsums.entries_with_downloads(body, ver)
        sets = updcheck.parse_set(body)
        for ref in sets[:updcheck.MAX_FOLLOW] if not entries else []:
            if ref["url"] and updcheck._matches({"element": ref["element"], "type": ref["type"], "folder": ref["folder"], "client": int(ref["client"])}, x):
                time.sleep(updcheck.PAUSE)
                sub = updcheck._get(ref["url"])
                if sub:
                    entries += extsums.entries_with_downloads(sub, ver)
        hit = [u for u in entries if updcheck._matches(u, x) and u["version"] == x["version"] and u["urls"]]
        if not hit:
            no_ref.append("%s (der Update-Server bietet diese Version nicht an)" % label)
            continue
        try:
            time.sleep(updcheck.PAUSE)
            raw = coreref.fetch_bytes(hit[0]["urls"][0], extsums.MAX_ZIP_BYTES, timeout=40)
            files, manifest, zbytes, top = extsums.resolve_package(raw, x)     # auch Paket-Sammlungen mit eingebettetem ZIP
        except (coreref.RefError, extsums.ZipProblem) as e:
            err.append("%s (%s)" % (label, str(e)[:120]))
            continue
        tdirs = extsums.target_entries(manifest, x)
        if not tdirs:
            no_ref.append("%s (Paketaufbau nicht unterstützt)" % label)
            continue
        jobs.append((x, label, tdirs, files, zbytes, top))
    changed, extra, missing, ok = [], [], [], []
    cand: List[Tuple[Any, str, str, str]] = []          # (Auftrag, Erweiterung, Serverpfad, Paketpfad) geänderter Dateien
    if jobs:
        dirs = sorted({s for _, _, td, _, _, _ in jobs for _, s in td})
        ctx.progress("Prüfsummen auf dem Server berechnen")
        local = extsums.parse_local(ctx.sh(extsums.find_script(dirs), timeout=600).out, dirs)
        for job in jobs:
            x, label, tdirs, files, _, _ = job
            bad = 0
            zdirs = [z for z, _ in tdirs]
            for (zdir, sdir), entries in tdirs.items():
                rel = extsums.only_entries(extsums.strip_prefix(files, zdir), entries,
                                           [z[len(zdir) + 1:] if zdir else z for z in zdirs if z != zdir and (not zdir or z.startswith(zdir + "/"))])
                ref = extsums.as_reference(rel)
                if not ref or sdir not in local:
                    continue
                d = wpsums.compare(local[sdir], ref)
                tag = x["element"]
                code_chg = [f for f in d["changed"] if wpsums.CODE_RE.search(f)]
                if x["type"] != "template":
                    cand += [(job, tag, "%s/%s" % (sdir, f), ("%s/%s" % (zdir, f)) if zdir else f) for f in code_chg]
                else:
                    extra += ["%s: %s/%s" % (tag, sdir, f) for f in code_chg]
                extra += ["%s: %s/%s" % (tag, sdir, f) for f in d["extra"]]
                missing += ["%s: %s/%s" % (tag, sdir, f) for f in d["missing"]]
                bad += len(code_chg) + len(d["extra"]) + len(d["missing"])
            if not bad:
                ok.append(label)
        # Gemeinsame Bibliotheken: Manche Hersteller (z. B. Joomlashack: OSMap, OSMeta, osmylicensesmanager) bringen dieselbe Bibliothek in mehreren
        # Paketen mit; bei jeder Installation wird sie mit der neuesten Fassung überschrieben. Ist die Datei identisch mit der aus einem anderen geprüften Paket, ist sie echt.
        known: Dict[str, str] = {}
        for job in jobs:
            for _p, h in job[3].items():
                known.setdefault(h, job[0]["element"])
        shared, harmless, real = [], [], []
        for job, tag, spath, zpath in cand:
            sdir = next((d for d in sorted(local, key=len, reverse=True) if spath.startswith(d + "/")), "")
            h = local.get(sdir, {}).get(spath[len(sdir) + 1:], "")
            src = known.get(h)
            if h and src and src != tag:
                shared.append("%s: %s (identisch mit der Datei aus dem Paket von %s)" % (tag, spath, src))
            else:
                real.append((job, tag, spath, zpath))
        diffs: Dict[str, Dict[str, Any]] = {}
        if real:
            ctx.progress("Geänderte Dateien gegenüberstellen")
            todo = [r for r in real if extsums.SAFE_REL.match(r[2])][:MAX_DIFFS]
            script = "".join("printf '@@DATEI %%s\\n' %s; head -c 120000 -- %s 2>/dev/null; printf '\\n@@ENDE\\n'; " % (sq(r[2]), sq(r[2])) for r in todo)
            out = ctx.sh(script, timeout=120).out if todo else ""
            texts = dict(re.findall(r"@@DATEI ([^\n]+)\n(.*?)\n@@ENDE", out, re.S))
            for job, tag, spath, zpath in todo:
                if spath not in texts:
                    continue
                try:
                    pkg = extsums.zip_member(job[4], zpath, strip_top=job[5])
                except Exception:
                    continue
                srv = texts[spath].encode("utf-8", "surrogateescape") if isinstance(texts[spath], str) else texts[spath]
                if extsums.normalized_equal(pkg, srv):
                    harmless.append("%s: %s" % (tag, spath))
                    continue
                a = pkg.decode("utf-8", "replace").splitlines()
                b = texts[spath].splitlines()
                rows = list(difflib.unified_diff(a, b, "Paket des Herstellers", "Datei auf dem Server", n=2, lineterm=""))[2:DIFF_LINES + 2]
                diffs[spath] = {"file": spath, "kind": "diff", "note": "- = Paket des Herstellers, + = Datei auf dem Server",
                                "code": [{"n": k + 1, "t": t[:300], **({"hit": [0, min(len(t), 300)]} if t[:1] in "+-" else {})} for k, t in enumerate(rows)]}
        harmless_set = set(harmless)
        changed = ["%s: %s" % (tag, spath) for _job, tag, spath, _z in real if "%s: %s" % (tag, spath) not in harmless_set]
        evidence = [diffs[c.split(": ", 1)[1]] for c in changed if c.split(": ", 1)[1] in diffs]
        if shared:
            res.add("ok", "%d Datei(en) aus einer gemeinsamen Bibliothek (identisch mit einem anderen Paket)" % len(shared),
                    "Diese Dateien weichen vom eigenen Paket ab, sind aber Byte für Byte identisch mit derselben Datei im Paket einer anderen geprüften Erweiterung. "
                    "Das ist bei gemeinsam genutzten Bibliotheken normal (die zuletzt installierte Erweiterung bringt die neueste Fassung mit). Kein Handlungsbedarf.", shared[:60])
        if harmless:
            res.add("ok", "%d Datei(en) unterscheiden sich nur in Zeilenenden oder Leerzeichen" % len(harmless),
                    "Der Code ist identisch mit dem Paket des Herstellers; nur Zeilenumbrüche (Windows/Linux) oder Leerzeichen am Zeilenende sind anders. Kein Handlungsbedarf.", harmless[:60])
    if changed:
        res.add("crit", "%d Erweiterungs-Datei(en) weichen vom Paket des Herstellers ab" % len(changed),
                "Der Inhalt unterscheidet sich vom Paket, das der Update-Server für genau diese Version ausliefert. Entweder wurde die Datei manipuliert, oder jemand hat sie von Hand geändert. "
                "Was genau anders ist, zeigt das Codefenster je Datei (- = Paket des Herstellers, + = Datei auf dem Server).",
                changed[:60], "Erweiterung über Joomla neu installieren (Erweiterungen -> Verwalten -> Update bzw. gleiches Paket erneut installieren). Eigene Änderungen vorher sichern.",
                evidence=evidence[:MAX_DIFFS])
    if extra:
        res.add("warn", "%d zusätzliche oder (bei Templates) geänderte PHP-Datei(en) in Erweiterungs-Ordnern" % len(extra),
                "Diese Dateien gehören nicht zum Paket des Herstellers oder wurden an einem Template geändert (Anpassungen sind dort üblich). Ein Versteck für Hintertüren ist möglich.",
                extra[:60], "Dateien ansehen (nicht ausführen). Ohne bekannte Herkunft löschen.")
    if missing:
        normal, inst = split_missing(missing)
        if inst:
            res.add("ok", "%d Installationsdatei(en) des Pakets fehlen (normal)" % len(inst),
                    "Diese Dateien dienen nur der Installation: Das Installationsprogramm der Erweiterung entpackt sie, installiert damit mitgelieferte Zusatz-Erweiterungen und löscht sie danach wieder. "
                    "Dass sie auf dem Server fehlen, ist der Normalfall. Es muss nichts nachgeladen werden.", count_by_ext(inst))
        if normal:
            res.add("info", "%d PHP-Datei(en) des Pakets fehlen auf dem Server" % len(normal),
                    "Das Paket des Herstellers enthält diese Dateien, auf deinem Server liegen sie nicht. Die Erweiterung kann dann Fehler zeigen oder einzelne Funktionen verlieren. "
                    "Ursachen: ein abgebrochenes Update, ein Virenscanner des Hosters, der Dateien entfernt hat, oder jemand hat sie gelöscht.",
                    count_by_ext(normal) + normal[:30],
                    "Erweiterung über Joomla neu installieren (Erweiterungen -> Verwalten -> Aktualisieren, oder das gleiche Paket noch einmal installieren). Das stellt die fehlenden Dateien wieder her; Einstellungen und Daten bleiben erhalten.")
    if no_ref:                     # Paket-Sammlungen sind nicht "nicht prüfbar": ihr Inhalt wird einzeln geprüft
        res.add("info", "%d Erweiterung(en) nicht prüfbar" % len(no_ref), "Ohne öffentliche Update-Adresse, mit Lizenzschlüssel oder wenn der Update-Server die installierte Version nicht mehr anbietet, gibt es nichts zum Vergleichen.", no_ref[:60])
    if err:
        res.add("info", "Nicht alles konnte geprüft werden", "", err[:20])
    if ok and not (changed or extra):
        res.add("ok", "%d Erweiterung(en) stimmen mit dem Paket des Herstellers überein" % len(ok), "Vergleich mit dem Paket des Update-Servers.", ok[:60])
