"""Joomla-Kern gegen das offizielle Original prüfen (Prüfsummen). Rein lesend: Auf dem Server werden nur Prüfsummen berechnet."""
from __future__ import annotations

import os
import re
from typing import Dict, List

from .. import coreref, evidence, joomla
from ..model import CheckSkipped
from ..registry import check
from ..util import split_sections, sq

G = "konfig"
TITLE_OK = "Alle Kerndateien stimmen mit dem Original überein"
TITLE_CHANGED = "Kerndatei(en) weichen vom Original ab"
TITLE_MISSING = "Kerndatei(en) fehlen"
TITLE_EXTRA = "unbekannte Datei(en) in Kernordnern"
TITLE_FIX = "Kerndateien lassen sich aus dem Original neu einspielen"
TITLE_NOFIX = "Kerndateien werden nicht automatisch neu eingespielt"
MAX_SHARE = 0.35            # weichen mehr als so viele Dateien ab, passt die Referenz vermutlich nicht (Fork, angepasste Version)
MIN_FILES = 200             # weniger Dateien auf dem Server: das Verzeichnis ist vermutlich falsch
MAX_FIX = 600               # so viele Dateien werden höchstens in einem Schritt ersetzt

SUMS_SCRIPT = r"""
H=""
if command -v sha256sum >/dev/null 2>&1; then H="sha256sum"; elif command -v shasum >/dev/null 2>&1; then H="shasum -a 256"; fi
echo '@@HASHER'; echo "${H:-none}"
echo '@@SUMS'
if [ -n "$H" ]; then
{ for d in administrator api cli components includes language layouts libraries media modules plugins templates; do [ -d "$d" ] && find "$d" -type f -print0 2>/dev/null; done; find . -maxdepth 1 -type f -print0 2>/dev/null; } | xargs -0 -r $H 2>/dev/null
fi
"""

SOFT_DIRS = ("language/", "administrator/language/")                 # Sprachdateien werden gern angepasst
EXTRA_SKIP_NAMES = {".htaccess", "user.css", "user.js", "web.config", ".user.ini", "error_log", "php_error.log", "php_errorlog"}
EXEC_RE = re.compile(r"\.(php\d?|phtml|pht|phps|phar|inc)$", re.I)


ELEM_SCRIPT = r"""
for d in administrator/components components administrator/modules modules templates administrator/templates libraries media; do
  [ -d "$d" ] && find "$d" -mindepth 1 -maxdepth 1 -printf '%f\n' 2>/dev/null
done
[ -d plugins ] && find plugins -mindepth 2 -maxdepth 2 -printf '%f\n' 2>/dev/null
"""
MANIFEST_DIR = "administrator/manifests/"          # Joomla legt hier bei jeder Installation das Manifest von Paketen, Bibliotheken und Dateisätzen ab: normal


def element_names(text: str) -> set:
    out = set()
    for ln in (text or "").splitlines():
        n = re.sub(r"^(com|mod|plg|tpl|lib|pkg)_", "", ln.strip().lower())
        if len(n) >= 4:
            out.add(n)
    return out


# Entwicklungsdateien, die Bibliotheken im Ordner libraries/vendor/ mitbringen (Beispiele, Format-Einstellungen). Sie stehen nicht im Joomla-Paket, liegen aber nach
# Updates und Composer-Läufen oft dort. Ein Fund gilt nur dann als unkritisch, wenn Name UND Ort passen und der Inhalt keine der geprüften Befehle enthält.
VENDOR_DEV = re.compile(r"^libraries/vendor/[^/]+/[^/]+/(\.php[-_]cs[-_]fixer(\.dist)?\.php|\.php_cs(\.dist)?|demo\.php|get_oauth_token\.php|examples?/[^/]+\.php)$", re.I)
DANGER_ERE = (r"(eval|assert|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec|create_function|base64_decode|gzinflate|gzuncompress|str_rot13|file_put_contents|fwrite|fputs|move_uploaded_file)"
              r"[[:space:]]*\(|php://input|data://|\$\{?[[:space:]]*['\"]?GLOBALS|\$_(POST|REQUEST|COOKIE)\[[^]]*\][[:space:]]*\(|(include|require)(_once)?[[:space:]]*\(?[[:space:]]*\$_")


def is_vendor_dev(path: str) -> bool:
    return bool(VENDOR_DEV.match(path))


def dev_scan_script(paths: List[str]) -> str:
    """Nur lesend: Namen der Dateien, die einen der gefährlichen Ausdrücke enthalten (grep -l)."""
    return "grep -liIE -e %s -- %s 2>/dev/null; true" % (sq(DANGER_ERE), " ".join(sq(p) for p in paths))


def scan_hits(ctx, paths: List[str]) -> Dict[str, List[int]]:
    """Welche der Dateien enthalten gefährliche Ausdrücke, und in welcher Zeile? Nur lesend (grep -n), höchstens drei Zeilen je Datei."""
    if not paths:
        return {}
    cmd = "grep -HnIiE -m3 -e %s -- %s 2>/dev/null; true" % (sq(DANGER_ERE), " ".join(sq(p) for p in paths))
    out: Dict[str, List[int]] = {}
    try:
        text = ctx.sh(cmd, timeout=120).out
    except CheckSkipped:
        return {p: [1] for p in paths}                                  # nicht prüfbar: nichts herabstufen
    for ln in text.splitlines():
        m = re.match(r"^(.+?):(\d+):", ln)
        if m:
            f = m.group(1)
            f = f[2:] if f.startswith("./") else f
            out.setdefault(f, []).append(int(m.group(2)))
    return out


def in_own_folder(path: str, stem: str) -> bool:
    """Liegt die Datei im Ordner der Erweiterung (Ordnername = Name oder Name mit Präfix com_, mod_, plg_, tpl_, lib_)?"""
    p = "/" + path
    return any("/%s%s/" % (pre, stem) in p for pre in ("", "com_", "mod_", "plg_", "tpl_", "lib_"))


def stem_of(path: str) -> str:
    return path.rsplit("/", 1)[-1].split(".")[0].lower()


def classify_extra(extra: List[str], elements: set) -> Dict[str, object]:
    """Unbekannte Dateien in Kernordnern sortieren: Manifeste (normal), ausführbare Dateien (prüfen) und Dateien ohne Programmcode (Dokumentation, Hilfsdateien).
    Eine Datei gilt als 'zugeordnet', wenn ihr Name (vor dem ersten Punkt) einer installierten Erweiterung gleicht, z. B. jaupdater.com_tags.xml -> Erweiterung jaupdater."""
    manifest = [p for p in extra if p.startswith(MANIFEST_DIR)]
    execs = [p for p in extra if not p.startswith(MANIFEST_DIR) and EXEC_RE.search(p)]
    other = [p for p in extra if not p.startswith(MANIFEST_DIR) and not EXEC_RE.search(p)]
    owned = {p: stem_of(p) for p in execs if len(stem_of(p)) >= 5 and stem_of(p) in elements}
    groups: Dict[str, List[str]] = {}
    for p in other:
        base = p.rsplit("/", 1)[-1]
        stem = stem_of(p)
        ext = base.rsplit(".", 1)[-1].lower() if "." in base else ""
        key = ("%s.*.%s" % (stem, ext)) if base.count(".") >= 2 else base
        groups.setdefault(key, []).append(p)
    rows = []
    for key, ps in sorted(groups.items(), key=lambda kv: (-len(kv[1]), kv[0])):
        stem = stem_of(ps[0])
        who = "  [gehört zur installierten Erweiterung: %s]" % stem if len(stem) >= 5 and stem in elements else ""
        rows.append("%s  (%d Datei(en), z. B. %s)%s" % (key, len(ps), ps[0], who))
    return {"manifest": manifest, "exec": execs, "owned": owned, "other": other, "other_rows": rows}


def parse_sums(text: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for ln in text.splitlines():
        m = re.match(r"^([0-9a-f]{64})\s+\*?(.+)\Z", ln.rstrip("\r"))
        if m:
            n = m.group(2)
            out[n[2:] if n.startswith("./") else n] = m.group(1)
    return out


def compare(ref: Dict[str, str], server: Dict[str, str]) -> Dict[str, List[str]]:
    """Vergleicht die Prüfsummen des Servers mit dem Original. Rückgabe: changed, missing, extra, soft (abweichende Sprachdateien), noindex (fehlende index.html)."""
    refc = {p: h for p, h in ref.items() if coreref.is_compared(p)}
    changed, missing, soft, noindex = [], [], [], []
    for p, h in sorted(refc.items()):
        if p not in server:
            (noindex if p.endswith("/index.html") else missing).append(p)
        elif server[p] != h:
            (soft if p.startswith(SOFT_DIRS) else changed).append(p)
    dirs = {p.rsplit("/", 1)[0] for p in refc if "/" in p}
    extra = []
    for p in sorted(server):
        if p in refc or "/" not in p or not coreref.is_compared(p) or p.startswith(SOFT_DIRS) or "/html/" in p:
            continue
        if p.rsplit("/", 1)[-1].lower() in EXTRA_SKIP_NAMES:
            continue
        if p.rsplit("/", 1)[0] in dirs:
            extra.append(p)
    return {"changed": changed, "missing": missing, "extra": extra, "soft": soft, "noindex": noindex, "compared": [p for p in refc if p in server]}


@check(
    "joomla_core", "konfig", "Joomla-Kern gegen Original prüfen",
    "Stimmen alle Joomla-Dateien mit dem offiziellen Original dieser Version überein?",
    what="Lädt das offizielle Joomla-Paket der installierten Version auf DIESEM Computer (https, Quelle: Release-Seite des Joomla-Projekts), prüft es gegen die dort veröffentlichte Prüfsumme "
         "(und, wenn vorhanden, gegen die des Joomla-Update-Servers) und berechnet daraus die Prüfsumme jeder Datei. Auf dem Server werden nur die Prüfsummen der Kerndateien berechnet und verglichen. "
         "Gemeldet werden veränderte Kerndateien, fehlende Kerndateien und unbekannte zusätzliche Dateien in Kernordnern. Wenn es sicher geht, bietet das Programm an, die Kerndateien neu einzuspielen.",
    why="Der Joomla-Kern wird nie von Hand geändert. Jede abweichende oder zusätzliche Datei in den Kernordnern ist ein starker Hinweis auf eine Manipulation - oder auf ein unvollständiges Update. "
        "Das fängt auch Hintertüren, die in gewöhnliche Joomla-Dateien eingebaut wurden und deshalb keinem Schadcode-Muster entsprechen.",
    reads="Nur Prüfsummen der Kerndateien (die Dateien werden nicht übertragen). Das Original-Paket wird von diesem PC bei github.com/joomla (https) geladen.",
    load="mittel", presets=["hack"],
)
def joomla_core(ctx, res):
    if os.environ.get("CLAUDIA_OFFLINE"):
        raise CheckSkipped("Offline-Modus (CLAUDIA_OFFLINE): Das Original-Paket wird nicht geladen.")
    ver = ctx.shared.get("joomla_version") or ""
    if not ver:
        r = ctx.sh("head -c 8000 libraries/src/Version.php 2>/dev/null; echo '@@M'; head -c 4000 administrator/manifests/files/joomla.xml 2>/dev/null").out
        a, _, b = r.partition("@@M")
        ver = joomla.parse_joomla_version(a, b)
    if not ver:
        raise CheckSkipped("Joomla-Version nicht erkannt.")
    if not coreref.VERSION_RE.match(ver):
        res.add("info", "Joomla %s ist eine Vorabversion" % ver, "Für Entwickler- und Vorabversionen gibt es kein offizielles Paket zum Vergleich.")
        return
    out = ctx.sh(SUMS_SCRIPT, timeout=420, raw="pruefsummen", raw_cap=40_000).out
    sec = split_sections(out)
    if "none" in sec.get("HASHER", "none").split():
        raise CheckSkipped("Auf dem Server gibt es weder sha256sum noch shasum. Der Vergleich ist dort nicht möglich.")
    server = parse_sums(sec.get("SUMS", ""))
    if len(server) < MIN_FILES:
        raise CheckSkipped("Auf dem Server wurden nur %d Dateien gefunden. Das Verzeichnis ist vermutlich falsch." % len(server))
    ctx.progress("Lade das Original-Paket von Joomla %s" % ver)
    try:
        ref = coreref.reference(ver)
    except coreref.RefError as e:
        raise CheckSkipped("Original-Paket nicht verfügbar: %s" % e)
    ctx.progress("Vergleiche %d Dateien" % len(server))
    d = compare(ref["files"], server)
    ctx.shared["joomla_core"] = {"version": ver, "ref": {k: v for k, v in ref.items() if k != "files"}, **d}
    src = "Original-Paket %s, Prüfsumme %s... %s" % (ref["package"], ref["sha256"][:16], "bestätigt von Release-Seite und Update-Server" if ref.get("cross")
                                                      else ("bestätigt von der Release-Seite des Projekts" if ref.get("verified") else "OHNE veröffentlichte Prüfsumme (nur https-Quelle)"))
    changed, missing, extra = d["changed"], d["missing"], d["extra"]
    total = max(1, len(d["compared"]) + len(missing))
    wrong_ref = (len(changed) + len(missing)) / total > MAX_SHARE
    if wrong_ref:
        res.add("warn", "Sehr viele Kerndateien weichen ab (%d von %d)" % (len(changed) + len(missing), total),
                "Das spricht eher für eine angepasste Version, einen Fork oder einen unvollständigen Upload als für einen Einzelangriff. Die Dateien werden deshalb nicht automatisch ersetzt. " + src,
                (changed + missing)[:40], "Joomla über Komponenten -> Joomla-Aktualisierung neu installieren (Update erneut einspielen) oder den Hoster fragen.")
    else:
        if changed:
            res.add("crit", "%d %s" % (len(changed), TITLE_CHANGED),
                    "Der Inhalt unterscheidet sich vom offiziellen Joomla %s. Entweder wurde die Datei manipuliert, oder ein Update ist unvollständig. %s" % (ver, src), changed[:80],
                    "Datei ansehen (Fundstelle), danach Kern neu einspielen (Lösung 'Kerndateien neu einspielen').")
        if missing:
            res.add("warn", "%d %s" % (len(missing), TITLE_MISSING), "Ein abgebrochenes Update oder ein Aufräum-Skript hinterlässt fehlende Dateien. Die Seite kann Fehler zeigen, Updates scheitern.", missing[:60],
                    "Kern neu einspielen.")
    ex = {"manifest": [], "exec": [], "owned": {}, "other": [], "other_rows": []}
    if extra:
        try:
            elements = element_names(ctx.sh(ELEM_SCRIPT, timeout=60).out)
        except CheckSkipped:
            elements = set()
        ex = classify_extra(extra, elements)
        ex["vendor_dev"] = []
        cands = [p for p in ex["exec"] if is_vendor_dev(p)][:60]
        if cands:
            try:
                flagged = {ln.strip().lstrip("./") if ln.startswith("./") else ln.strip() for ln in ctx.sh(dev_scan_script(cands), timeout=120).out.splitlines() if ln.strip()}
            except CheckSkipped:
                flagged = set(cands)                                         # nicht prüfbar: nichts herabstufen
            ex["vendor_dev"] = [p for p in cands if p not in flagged]
            ex["exec"] = [p for p in ex["exec"] if p not in ex["vendor_dev"]]
        if ex["vendor_dev"]:
            res.add("info", "%d Entwicklungsdatei(en) von Bibliotheken im Ordner vendor" % len(ex["vendor_dev"]),
                    "Name und Ort passen zu Beispiel- und Einstellungsdateien, die Bibliotheken von Haus aus mitbringen (z. B. .php-cs-fixer.dist.php, demo.php), und der Inhalt enthält keinen der geprüften "
                    "Befehle (eval, base64_decode, Systemaufrufe, Schreiben von Dateien, Formulardaten als Funktion). Das beweist nicht, dass die Datei unverändert ist, aber sie wird hier nicht als Hinweis auf "
                    "einen Einbruch gewertet. Sie wird für den Betrieb nicht gebraucht und kann gelöscht werden.", ex["vendor_dev"][:40])
        if ex["exec"]:
            hits = scan_hits(ctx, ex["exec"][:60])
            clean_owned = [p for p in ex["exec"] if p in ex["owned"] and p not in hits and in_own_folder(p, ex["owned"][p])]
            attention = [p for p in ex["exec"] if p not in clean_owned]
            if clean_owned:
                want = [("./" + p, 1) for p in clean_owned[:3]]
                ctxl = evidence.fetch(ctx, want, before=0, after=7)
                evs = [evidence.build(path, 1, ctxl[(path, 1)], note="geprüft: kein gefährlicher Ausdruck gefunden") for path, _ in want if (path, 1) in ctxl]
                res.add("info", "%d Programmdatei(en) gehören zu installierten Erweiterungen" % len(clean_owned),
                        "Diese Dateien liegen in einem Kernordner, tragen aber den Namen einer installierten Erweiterung und liegen in deren eigenem Ordner (zum Beispiel das Installationsskript eines Plugins). "
                        "Ihr Inhalt wurde auf gefährliche Ausdrücke geprüft (eval, base64_decode, Systemaufrufe, Schreiben von Dateien, Formulardaten als Funktion); es wurde keiner gefunden. "
                        "Das ist das normale Bild einer Erweiterung, die in einem Kernordner installiert ist. Es beweist nicht, dass die Datei unverändert ist.",
                        ["%s  [gehört zur Erweiterung %s]" % (p, ex["owned"][p]) for p in clean_owned[:40]],
                        "Nichts zu tun. Wird die Erweiterung nicht mehr gebraucht, kann sie in Joomla deinstalliert werden.", evs)
            if attention:
                want = [("./" + p, (hits[p][0] if p in hits else 1)) for p in attention[:6]]
                ctxl = evidence.fetch(ctx, want, before=1 if hits else 0, after=3 if hits else 7)
                evs = []
                for path, no in want:
                    if (path, no) in ctxl:
                        marked = path[2:] in hits
                        evs.append(evidence.build(path, no, ctxl[(path, no)], rx=DANGER_ERE if marked else "",
                                                  note="rot markiert: gefährlicher Ausdruck" if marked else "Anfang der Datei, kein gefährlicher Ausdruck gefunden: Herkunft ungeklärt"))
                items = []
                for p in attention[:80]:
                    tag = []
                    if p in ex["owned"]:
                        tag.append("Name gleicht der installierten Erweiterung %s" % ex["owned"][p])
                    if p in hits:
                        tag.append("enthält gefährlichen Ausdruck, Zeile %s" % ", ".join(str(n) for n in hits[p][:3]))
                    items.append("%s  [%s]" % (p, "; ".join(tag)) if tag else p)
                danger = [p for p in attention if p in hits]
                unclear = [p for p in attention if p not in hits]
                if danger:
                    text = ("In diesen Ordnern liegen nur Joomla-Dateien. Diese zusätzliche Programmdatei enthält Ausdrücke, wie sie Hintertüren benutzen (rot markiert). Das kann auch eine Erweiterung sein, "
                            "die selbst Befehle ausführt; ohne bekannte Herkunft ist es ein Verdachtsfall.")
                    hint = "Datei ansehen (herunterladen, nicht ausführen). Gehört sie nicht zu einer bekannten Erweiterung, löschen und die Prüfung wiederholen."
                else:
                    text = ("In diesen Ordnern liegen nur Joomla-Dateien. Eine zusätzliche Programmdatei (PHP) dort kann ein Rest eines Plugins sein, ist aber auch ein klassisches Versteck für Hintertüren. "
                            "Im Inhalt wurde kein gefährlicher Ausdruck gefunden (deshalb keine rote Zeile im Code); die Herkunft ist trotzdem ungeklärt, und genau das macht sie kritisch.")
                    hint = "Datei ansehen (herunterladen, nicht ausführen) und löschen, wenn sie nicht zu einer bekannten Erweiterung gehört."
                res.add("crit", "%d %s" % (len(attention), TITLE_EXTRA), text, items, hint, evs)   # eine ungeklärte Programmdatei im Kern bleibt kritisch (Hintertüren verstecken sich dort)
        if ex["other"]:
            res.add("info", "%d zusätzliche Datei(en) ohne Programmcode in Kernordnern" % len(ex["other"]),
                    "Das sind Dokumentation (README, CHANGELOG), Konfigurations- und Hilfsdateien, die Erweiterungen oder Werkzeuge neben die Joomla-Dateien legen (z. B. JA Updater legt je Komponente eine jaupdater.*.xml an). "
                    "Sie können auf dem Server nichts ausführen, deshalb ist das kein Einbruchszeichen. Der Test meldet sie, damit du siehst, was zusätzlich im Kern liegt.", ex["other_rows"][:60])
    if d["soft"]:
        res.add("info", "%d Sprachdatei(en) weichen ab (üblich)" % len(d["soft"]), "Sprachdateien werden oft angepasst. Eigene Texte gehören besser in language/overrides.", d["soft"][:20])
    if d["noindex"]:
        res.add("info", "%d index.html fehlen" % len(d["noindex"]), "Diese leeren Dateien verhindern nur die Ordner-Auflistung. Kein Einbruchszeichen, aber ein Zeichen für ein Aufräum-Skript.", d["noindex"][:20])
    if not (changed or missing or ex["exec"]) and not wrong_ref:
        res.add("ok", "%s (%d Dateien, Joomla %s)" % (TITLE_OK, len(d["compared"]), ver), src)
        return
    fixable = sorted(set(changed + missing))
    why_not = ""
    if wrong_ref:
        why_not = "Es weichen zu viele Dateien ab; das Original passt vermutlich nicht zu dieser Installation."
    elif not ref.get("verified"):
        why_not = "Die Prüfsumme des Original-Pakets konnte nicht bestätigt werden. Ohne bestätigte Herkunft wird nichts überschrieben."
    elif not fixable:
        return
    elif len(fixable) > MAX_FIX:
        why_not = "Mehr als %d Dateien müssten ersetzt werden." % MAX_FIX
    if why_not:
        res.add("info", TITLE_NOFIX, why_not + " Sicherer Weg: Joomla-Backend -> Komponenten -> Joomla-Aktualisierung -> 'Update erneut installieren'.")
    else:
        res.add("info", TITLE_FIX, "Bestätigtes Original-Paket vorhanden (%s). Es werden nur die %d abweichenden bzw. fehlenden Dateien ersetzt, vorher entsteht eine Sicherung. "
                                   "Unbekannte zusätzliche Dateien werden nicht angefasst, die configuration.php, images und Erweiterungen bleiben unberührt." % (ref["package"], len(fixable)), fixable[:MAX_FIX],
                "Lösung 'Joomla-Kerndateien neu einspielen' ausführen. Danach den Test noch einmal laufen lassen.")
