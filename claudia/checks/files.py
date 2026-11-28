"""Schadcode im Dateisystem: node_modules, JavaScript, PHP in Upload-Ordnern, Web-Shells, Namen, Änderungen, Backups."""
from __future__ import annotations

import re
import time
from collections import Counter, defaultdict
from typing import Dict, List, Tuple

from ..model import Option
from ..registry import check
from ..util import clean_line, human_size, lines_of, mask_secrets, sq, split_sections, trunc

G = "dateien"
# D4 (2.4.0): Positivliste bekannter Sicherheits-/Backup-Erweiterungen (known_tools.json, mit Stand-Datum). Früher genügte ein Stichwort irgendwo im Pfad (z. B. "akeeba.php" im Bilder-Ordner).
# Jetzt gilt eine Datei nur als bekannt, wenn der Pfad im Ordner der Erweiterung liegt UND der Inhalt deren Kennung enthält.
def load_known_tools() -> Dict:
    import json
    from .. import KNOWN_TOOLS_FILE
    try:
        with open(KNOWN_TOOLS_FILE, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {"stand": "", "tools": []}


def known_tool_split(ctx, paths: List[str]) -> Dict[str, str]:
    """{Pfad: Name der Erweiterung} für die Pfade, die Pfad UND Inhalt einer bekannten Erweiterung erfüllen. Der Inhalt wird nur lesend mit grep geprüft (höchstens 200 Dateien)."""
    data = load_known_tools()
    cand: List[Tuple[str, Dict]] = []
    for pth in dict.fromkeys(paths):
        if re.search(r"[\x00-\x1f]", pth):
            continue
        for t in data.get("tools", []):
            if re.match(t["path"], pth):
                cand.append((pth, t))
                break
    if not cand:
        return {}
    script = "".join("grep -qiE -e %s -- %s 2>/dev/null && printf 'K\\t%%s\\n' %s\n" % (sq(t["content"]), sq(pth), sq(pth)) for pth, t in cand[:200])
    out = ctx.sh(script, timeout=60, raw="known_tools").out
    ok = {ln.split("\t", 1)[1] for ln in out.splitlines() if ln.startswith("K\t") and "\t" in ln}
    return {pth: t["name"] for pth, t in cand[:200] if pth in ok}


def _path_of(entry: str) -> str:
    m = re.match(r"^(\./.*?)(?::\d+:|:\d+$|\s+-\s|:\s|\s{2,}|$)", entry)
    return m.group(1) if m else entry


EXEC_EXT_FIND = r"\( -iname '*.php' -o -iname '*.phtml' -o -iname '*.pht' -o -iname '*.phps' -o -iname '*.php[0-9]' -o -iname '*.phar' -o -iname '*.shtml' \)"


_EXT_ROOT = re.compile(r"^(\./plugins/[^/]+/[^/]+|\./(?:administrator/)?(?:components|modules|templates)/[^/]+)(?:/|$)")


def ext_root(path: str, cms: str = "joomla"):
    """Hauptordner der Erweiterung (Plugin/Theme), zu der eine Datei gehört (oder None)."""
    from ..cms import ext_root as _er
    return _er(cms, path)


def _epoch_now(sec: Dict[str, str]) -> float:
    try:
        return float(lines_of(sec.get("NOW", ""))[0])
    except (IndexError, ValueError):
        return time.time()


def _age_days(date_str: str, now: float) -> float:
    try:
        t = time.mktime(time.strptime(date_str[:10], "%Y-%m-%d"))
        return max(0.0, (now - t) / 86400.0)
    except ValueError:
        return 9999.0


# ----------------------------------------------------------------------------- node_modules
@check(
    "node_modules", G, "Ordner node_modules (Versteck für Schadcode)",
    "Liegt ein Node.js-Entwicklungsordner auf dem Server - und wann wurde darin zuletzt etwas geändert?",
    what="Sucht überall in der Seite nach Ordnern namens node_modules und meldet Größe, Dateianzahl und das letzte Änderungsdatum. "
         "Die Inhalte werden vom Test 'JavaScript-Dateien auf Schadcode prüfen' untersucht.",
    why="Bei dem Vorfall, der diese Prüfung ausgelöst hat, steckte der Schadcode in node_modules/jquery/dist/jquery.min.js. "
        "Ein solcher Ordner enthält Hunderte Unterordner, in denen eine manipulierte Datei kaum auffällt, und wird auf einem Live-Server nie gebraucht.",
    reads="Nur Ordnernamen, Größe, Anzahl und Datum. Keine Dateiinhalte.",
    load="leicht", presets=["schnell", "hack"],
)
def node_modules(ctx, res):
    out = ctx.sh(r"""
n=0
find . -type d -name node_modules -prune -print0 2>/dev/null | while IFS= read -r -d '' d; do
  n=$((n+1)); [ "$n" -gt 20 ] && break
  echo "ND|$d|$(du -sk "$d" 2>/dev/null | cut -f1)|$(find "$d" -type f 2>/dev/null | wc -l)|$(find "$d" -type f -printf '%TY-%Tm-%Td\n' 2>/dev/null | sort | tail -1)"
done
echo '@@NOW'; date +%s
""", timeout=120, raw="gefunden").out
    sec = split_sections(out)
    now = _epoch_now(sec)
    found = []
    recent = []
    for ln in lines_of(out.split("@@NOW")[0]):
        p = ln.split("|")
        if len(p) < 5 or p[0] != "ND":
            continue
        path, kb, files, last = p[1], p[2], p[3], p[4]
        desc = "%s - %s, %s Dateien, zuletzt geändert %s" % (path, human_size(int(kb or 0) * 1024), files, last or "?")
        found.append(desc)
        if last and _age_days(last, now) <= 365:
            recent.append(desc)
    if not found:
        res.add("ok", "Kein node_modules-Ordner gefunden")
        return
    res.add("warn", "%d node_modules-Ordner auf dem Server" % len(found),
            "Entwicklungsordner gehören nicht auf einen Live-Server.", found,
            "Ordner herunterladen (als Beweis), dann löschen. Vorher mit dem JavaScript-Test prüfen lassen.")
    if recent:
        res.add("crit", "node_modules wurde im letzten Jahr verändert",
                "Ein Ordner, der seit der Einrichtung unverändert sein sollte, hat neue oder geänderte Dateien. Das ist bei einem Hack typisch.",
                recent, "Inhalt genau ansehen: JavaScript-Test ausführen und die neuesten Dateien prüfen.")


# ----------------------------------------------------------------------------- JavaScript
NOCONFLICT_RE = re.compile(r"^(?:var\s+|window\.)?\$\s*=\s*(?:window\.)?jQuery\.noConflict\(\)\s*;?\s*\Z")
JQ_CORE_RE = re.compile(r"^jquery(?:[-.]\d+(?:\.\d+)*)?(?:\.slim)?(?:\.min)?\.js$|^jquery[-.](?:migrate|ui)[-.\d]*(?:\.min)?\.js\Z")


def jquery_kind(path: str) -> str:
    """core (jQuery selbst, Migrate, UI) | wrapper (jquery-noconflict) | plugin (alles andere, z. B. jquery.cookie.js)."""
    base = path.rsplit("/", 1)[-1].lower()
    if "noconflict" in base:
        return "wrapper"
    return "core" if JQ_CORE_RE.match(base) else "plugin"


@check(
    "js_scan", G, "JavaScript-Dateien auf Schadcode prüfen",
    "Sind JavaScript-, HTML- oder PHP-Dateien mit bekanntem oder verschleiertem Schadcode versehen?",
    what="Durchsucht alle .js-, .html- und .php-Dateien nach (1) bekannten Schadcode-Merkmalen aus dem Vorfall, (2) typischer "
         "Code-Verschleierung (Namen wie _0x1a2b), (3) gepackten eval(function(p,a,c,k,e,...)-Skripten. Bei jQuery-Dateien wird "
         "zusätzlich geprüft, ob die Datei mit dem üblichen Kommentar-Kopf beginnt und die Version zur package.json passt.",
    why="Bei dem Vorfall wurde verschleierter Code VOR den eigentlichen jQuery-Code gesetzt, sodass jeder Besucher einen "
        "Fremd-Server kontaktierte. Der Kopf der Datei behauptete eine andere Version als die mitgelieferte package.json.",
    reads="Durchsucht den Inhalt aller JS/HTML/PHP-Dateien auf dem Server (nur lesend, auf dem Server, nichts wird heruntergeladen). Das kann einige Minuten dauern.",
    load="hoch", presets=["schnell", "hack"],
)
def js_scan(ctx, res):
    ioc = [s for s in ctx.adv.get("ioc_strings", []) if s]
    ioc_args = " ".join("-e %s" % sq(s) for s in ioc) or "-e __kein_ioc__"
    script = r"""
echo '@@JQ'
find . -type f \( -iname 'jquery*.js' \) -not -path './cache/*' -print0 2>/dev/null | head -z -n 400 | while IFS= read -r -d '' f; do
  head80=$(head -c 80 "$f" | tr '\n\t\r' '   ')
  hv=$(head -c 600 "$f" | grep -oE 'jQuery v[0-9]+\.[0-9]+\.[0-9]+' | head -1)
  pj="$(dirname "$f")/../package.json"; pv=""
  [ -f "$pj" ] && pv=$(grep -m1 '"version"' "$pj" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
  printf 'JQ\t%s\t%s\t%s\t%s\t%s\n' "$f" "$(stat -c %s "$f")" "$hv" "$pv" "$head80"
done
echo '@@IOC'
grep -rIlF @IOC@ --include='*.js' --include='*.html' --include='*.htm' --include='*.php' --include='*.css' . 2>/dev/null | head -100
echo '@@OBF'
grep -rIlE '_0x[0-9a-f]{4,6}.{0,400}_0x[0-9a-f]{4,6}.{0,400}_0x[0-9a-f]{4,6}' --include='*.js' --include='*.html' --include='*.htm' --include='*.php' . 2>/dev/null | head -100
echo '@@PACK'
grep -rIlE 'eval\(function\(p,a,c,k,e,[dr]\)' --include='*.js' --include='*.html' --include='*.php' . 2>/dev/null | head -50
echo '@@FCC'
grep -rInE 'eval *\( *[A-Za-z0-9_$.]+ *\. *fromCharCode *\(|fromCharCode *\( *([0-9]+ *, *){25,}' --include='*.js' --include='*.html' --include='*.htm' --include='*.php' --include='*.phtml' . 2>/dev/null | head -40 | cut -c1-400
echo '@@NOW'; date +%s
""".replace("@IOC@", ioc_args)
    out = ctx.sh(script, timeout=420, raw="treffer").out
    sec = split_sections(out)
    crit_items: List[str] = []
    warn_items: List[str] = []
    jq_total = 0
    plugins = 0
    for ln in sec.get("JQ", "").splitlines():
        p = ln.split("\t")
        if len(p) < 6 or p[0] != "JQ":
            continue
        jq_total += 1
        path, size, hv, pv, head = p[1], p[2], p[3], p[4], p[5]
        h = head.lstrip()
        kind = jquery_kind(path)
        if kind == "wrapper" and NOCONFLICT_RE.match(h) and int(size or 0) <= 200:
            continue            # Joomlas eigene Mini-Datei (window.$ = jQuery.noConflict()) - harmlos
        if kind == "plugin" and "_0x" not in head:
            plugins += 1
            continue            # jQuery-Plugin einer Erweiterung: hat keinen festen Kopf, wird nur auf Verschleierung geprüft
        if "_0x" in head or (h and not h.startswith("/*") and not h.startswith("//") and re.search(r"[A-Za-z]{3}", h[:20] or "") and h.startswith(("var ", "function", "(function", "eval", "document"))):
            crit_items.append("%s - beginnt nicht mit dem üblichen Kommentar-Kopf, sondern mit Code: \"%s\" (%s Byte)" % (path, trunc(clean_line(head), 60), size))
        elif h and not h.startswith("/*") and not h.startswith("!function") and not h.startswith("//"):
            warn_items.append("%s - ungewöhnlicher Dateianfang: \"%s\"" % (path, trunc(clean_line(head), 60)))
        if hv and pv and hv.split("v")[-1] != pv:
            crit_items.append("%s - Datei behauptet %s, die daneben liegende package.json sagt %s (Versionen passen nicht zusammen)" % (path, hv, pv))
    ioc_hits = lines_of(sec.get("IOC", ""))
    obf_hits = lines_of(sec.get("OBF", ""))
    pack_hits = lines_of(sec.get("PACK", ""))
    fcc_items: List[str] = []
    for x in lines_of(sec.get("FCC", "")):
        m = re.match(r"^(\./[^:]+):(\d+):(.*)\Z", x)
        if m:
            fcc_items.append("%s Zeile %s: %s" % (m.group(1)[2:], m.group(2), trunc(clean_line(m.group(3)), 140)))
    if fcc_items:
        res.add("crit", "Verschleiertes Skript (eval + fromCharCode) in %d Datei(en)" % len(fcc_items),
                "Das Skript baut seinen Code aus einer langen Zahlenliste zusammen und führt ihn mit eval aus. Normale Seiten und Bibliotheken tun das nicht. "
                "Genau so wird Besuchern oft Werbe-, Weiterleitungs- oder Betrugscode untergeschoben.",
                fcc_items[:30],
                "Zeile von Hand entfernen (vorher Datei sichern). Unter 'Lösungen' zeigt das Programm Ausschnitt, Schadstelle und Zeilennummern. Danach Passwörter ändern.")
    if ioc_hits:
        res.add("crit", "Bekannte Schadcode-Merkmale gefunden (%d Datei(en))" % len(ioc_hits),
                "Diese Dateien enthalten Zeichenfolgen, die zum Schadcode aus dem Vorfall gehören.",
                [clean_line(x) for x in ioc_hits],
                "Datei herunterladen (Beweis), dann löschen oder durch das saubere Original ersetzen. Danach Passwörter ändern.")
    if obf_hits:
        known = known_tool_split(ctx, obf_hits)
        scanner = [x for x in obf_hits if x in known]
        real = [x for x in obf_hits if x not in known]
        if real:
            res.add("crit", "Verschleierter Code im Stil von obfuscator.io (%d Datei(en))" % len(real),
                    "Normale Bibliotheken enthalten selten Variablen wie _0x1a2b. Genau diese Verschleierung benutzte der Schadcode im Vorfall.",
                    [clean_line(x) for x in real], "Datei prüfen und mit dem Original aus dem Herstellerpaket vergleichen.")
        if scanner:
            res.add("info", "Verschleierter Code in Sicherheits-/Backup-Erweiterungen", "Üblich bei kommerziellen Erweiterungen. Als bekannt gilt eine Datei nur, wenn sie im Ordner der Erweiterung liegt UND deren Kennung enthält (Liste vom %s)." % load_known_tools().get("stand", "?"),
                    ["%s  (%s)" % (clean_line(x), known[x]) for x in scanner])
    if crit_items:
        res.add("crit", "jQuery-Datei(en) mit Auffälligkeiten", "Manipulierte Bibliotheksdateien sind der häufigste Weg, Besucher anzugreifen.", crit_items,
                "Datei durch das Original ersetzen (Joomla-Core neu installieren bzw. Erweiterung neu installieren).")
    if warn_items:
        res.add("warn", "jQuery-Datei mit ungewöhnlichem Anfang", "", warn_items)
    if pack_hits:
        res.add("warn", "Gepackte Skripte (eval(function(p,a,c,k,e,...)", "Manche alte Bibliotheken sind so gepackt, aber auch Schadcode.",
                [clean_line(x) for x in pack_hits], "Prüfen, ob die Datei zu einer bekannten Erweiterung gehört.")
    if not (ioc_hits or obf_hits or crit_items or warn_items or pack_hits or fcc_items):
        res.add("ok", "Keine Schadcode-Merkmale in JavaScript-, HTML- und PHP-Dateien gefunden",
                "%d jQuery-Datei(en) geprüft, davon %d jQuery-Plugin(s) von Erweiterungen." % (jq_total, plugins))
    else:
        res.add("info", "Umfang der Prüfung", "%d jQuery-Datei(en) gefunden, davon %d jQuery-Plugin(s) von Erweiterungen (nur auf Verschleierung geprüft)." % (jq_total, plugins))


# ----------------------------------------------------------------------------- PHP in Upload-Ordnern
DANGER_RE = r"eval ?\(|base64_decode|gzinflate|gzuncompress|str_rot13|assert ?\(|\$_(GET|POST|REQUEST|COOKIE|FILES)|shell_exec|passthru|proc_open|popen|\bsystem ?\("
DIS_CODE_RE = (r"<\?php[[:space:]]|<\?=.{0,300}(eval|base64_decode|gzinflate|gzuncompress|str_rot13|system|exec|passthru|shell_exec|assert|proc_open|popen|"
               r"\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER)|file_put_contents|move_uploaded_file|fwrite|curl_exec|include|require)")
DIS_EXCLUDE = ("--exclude='*.php' --exclude='*.phtml' --exclude='*.pht' --exclude='*.phps' --exclude='*.phar' "
               "--exclude='*.php[0-9]' --exclude='*.js' --exclude='*.map'")


@check(
    "php_in_uploads", G, "PHP-Dateien in Upload- und Temp-Ordnern",
    "Liegen ausführbare Dateien dort, wo nur Bilder, Cache und Temp-Dateien sein sollten?",
    what="Sucht in images, media, files, tmp, cache und den Log-Ordnern nach PHP-Dateien (.php, .phtml, .phar ...), "
         "nach versteckten Dateien (z. B. .cache.ico) und nach Dateien mit harmloser Endung (z. B. .jpg), die PHP-Code enthalten.",
    why="Die Lücken in JCE und Convert Forms (siehe Erweiterungs-Test) dienen dazu, genau dort Web-Shells abzulegen. "
        "In diesen Ordnern hat PHP-Code nichts zu suchen. Das ist die wirksamste Einzelprüfung.",
    reads="Dateinamen und - nur bei Verdacht - der Anfang von Dateien in diesen Ordnern. Nichts wird verändert.",
    load="mittel", presets=["schnell", "hack"],
)
def php_in_uploads(ctx, res):
    script = r"""
echo '@@PHP'
for d in @UPL@; do
  [ -d "$d" ] && find "$d" -type f @EXT@ -printf 'P\t%TY-%Tm-%Td %TH:%TM\t%s\t%p\n' 2>/dev/null
done | head -300
echo '@@STUB'
for d in @UPL@; do
  [ -d "$d" ] && find "$d" -type f -iname 'index.php' -size -201c -print0 2>/dev/null | xargs -0 -r grep -LiE 'eval|base64|\$_|system|exec|passthru|shell|include|require|file_put|fwrite|curl|assert|popen' 2>/dev/null
done | head -300
echo '@@CACHEBAD'
for d in @CACHE@; do
  [ -d "$d" ] && find "$d" -type f @EXT@ -print0 2>/dev/null | xargs -0 -r grep -lE '@DANGER@' 2>/dev/null
done | head -100 | while IFS= read -r f; do
  printf 'CB\t%s\t%s\n' "$f" "$(grep -aoE '.{0,40}(@DANGER@).{0,40}' "$f" 2>/dev/null | head -1 | tr '\t\r\n' '   ' | cut -c1-170)"
done
echo '@@CACHEUNK'
for d in @CACHE@; do
  [ -d "$d" ] || continue
  find "$d" -type f @EXT@ -print0 2>/dev/null | head -z -n 4000 | while IFS= read -r -d '' f; do
    grep -qE 'die ?\(.(Access Denied|Forbidden)' "$f" 2>/dev/null && continue
    h=$(head -c 100 "$f" 2>/dev/null | tr '\n\r\t' '   ')
    case "$h" in "<?php return"*|"<?php  return"*) continue;; esac
    printf 'CU\t%s\t%s\n' "$f" "$h"
  done
done | head -150
echo '@@HIDDEN'
find @UPL@ @CACHE@ -type f -name '.*' -not -name '.htaccess' -not -name '.gitkeep' -not -name '.gitignore' -printf '%TY-%Tm-%Td %TH:%TM\t%s\t%p\n' 2>/dev/null | head -100
echo '@@DISGUISED'
grep -rlazE '@DISCODE@' @UPL@ 2>/dev/null @DISEX@ | head -100
echo '@@NOW'; date +%s
""".replace("@EXT@", EXEC_EXT_FIND).replace("@DANGER@", DANGER_RE).replace("@DISCODE@", DIS_CODE_RE).replace("@DISEX@", DIS_EXCLUDE).replace("@UPL@", ctx.prof["upload_dirs"]).replace("@CACHE@", ctx.prof["cache_dirs"])
    out = ctx.sh(script, timeout=300, raw="treffer").out
    sec = split_sections(out)
    stubs = {clean_line(x).lstrip("./") for x in lines_of(sec.get("STUB", ""))}
    crit: List[str] = []
    warn: List[str] = []
    stub_list: List[str] = []
    for ln in sec.get("PHP", "").splitlines():
        p = ln.split("\t")
        if p[0] == "P" and len(p) >= 4:
            path = p[3]
            if path.lstrip("./") in stubs:
                stub_list.append("%s  (%s Byte)" % (clean_line(path), p[2]))
                continue
            desc = "%s  (%s, %s Byte)" % (clean_line(path), p[1], p[2])
            top = path.split("/")[0]
            (warn if top == "media" and ctx.cms == "joomla" else crit).append(desc)
    bad_cache, lang_cache, unk_cache, unk_heads = [], [], [], []
    for ln in sec.get("CACHEBAD", "").splitlines():
        p = ln.split("\t")
        if len(p) >= 2 and p[0] == "CB":
            snip = clean_line(p[2]) if len(p) > 2 else ""
            entry = "%s  ->  \"%s\"" % (clean_line(p[1]), trunc(snip.strip(), 110))
            # Sprach-Cache enthält Beschreibungstexte (z. B. einer Sicherheitserweiterung, die 'base64_decode' nur erwähnt)
            (lang_cache if re.search(r"/language/.*\.ini\.\d+\.php$|\.ini\.\d+\.php$", p[1]) else bad_cache).append(entry)
    for ln in sec.get("CACHEUNK", "").splitlines():
        p = ln.split("\t")
        if len(p) >= 2 and p[0] == "CU":
            unk_cache.append(clean_line(p[1]))
            if len(unk_heads) < 5:
                unk_heads.append("%s  beginnt mit: \"%s\"" % (clean_line(p[1]), trunc(clean_line(p[2]) if len(p) > 2 else "", 70)))
    if crit:
        res.add("crit", "%d PHP-Datei(en) in images/files/tmp" % len(crit),
                "In diesen Ordnern dürfen keine ausführbaren Dateien liegen. Das ist das typische Merkmal eines Web-Shells.", crit[:80],
                "Dateien NICHT im Browser öffnen. Herunterladen (Beweis), dann löschen, und die Einfallslücke schließen (Erweiterungen aktualisieren).")
    if warn:
        res.add("warn", "%d PHP-Datei(en) in media" % len(warn),
                "Manche Erweiterungen legen dort Dateien ab, normalerweise sind es aber keine PHP-Dateien.", warn[:80], "Prüfen, ob die Dateien zu einer bekannten Erweiterung gehören.")
    if stub_list:
        res.add("info", "%d leere Platzhalter-Datei(en) index.php" % len(stub_list),
                "Kleine index.php-Dateien ohne Code verhindern das Auflisten eines Ordners. Das legen Joomla und viele Erweiterungen selbst an.", stub_list[:15])
    if bad_cache:
        res.add("crit", "%d PHP-Datei(en) in Cache/Logs mit Hintertür-Merkmalen" % len(bad_cache),
                "Echte Cache- und Log-Dateien enthalten nur Daten. Diese Dateien enthalten Befehle wie eval, base64_decode oder $_POST.", bad_cache[:60],
                "Datei herunterladen (Beweis), Inhalt prüfen und löschen.")
    if lang_cache:
        res.add("warn", "%d Sprach-Cache-Datei(en) enthalten Wörter wie eval/base64_decode" % len(lang_cache),
                "Der Sprach-Cache speichert die Beschreibungstexte der Erweiterungen. Bei Sicherheitserweiterungen (z. B. htprotect) stehen dort Begriffe wie "
                "'base64_decode', weil sie diese Angriffe beschreiben. Die Textstelle steht jeweils dahinter. Steht dort ein Satz, ist es harmlos.",
                lang_cache[:20], "Stelle lesen: Beschreibung = harmlos. Im Zweifel den Cache leeren (System -> Cache löschen), Joomla baut ihn neu auf.")
    if unk_cache and not (bad_cache or lang_cache):
        res.add("info", "%d PHP-Datei(en) im Cache ohne die()-Schutzzeile" % len(unk_cache),
                "Joomla 4 bis 6 speichert Sprach- und Klassen-Zwischenspeicher als PHP-Datei. Es wurden keine Befehle wie eval, base64_decode oder $_POST darin gefunden.",
                unk_heads)
    elif unk_cache:
        res.add("info", "%d weitere PHP-Datei(en) im Cache ohne die()-Schutzzeile (ohne Befehle)" % len(unk_cache), "", unk_heads)
    hid = []
    for ln in lines_of(sec.get("HIDDEN", "")):
        p = ln.split("\t")
        if len(p) >= 3:
            hid.append("%s  (%s, %s Byte)" % (clean_line(p[2]), p[0], p[1]))
    if hid:
        res.add("warn", "%d versteckte Datei(en) in Upload-/Temp-Ordnern" % len(hid),
                "Dateien, deren Name mit einem Punkt beginnt, werden im Datei-Manager oft nicht angezeigt und sind ein beliebtes Versteck.", hid[:60],
                "Inhalt prüfen und löschen, wenn unbekannt.")
    dis = [clean_line(x) for x in lines_of(sec.get("DISGUISED", ""))]
    if dis:
        res.add("crit", "%d Datei(en) mit harmloser Endung enthalten PHP-Code" % len(dis),
                "Eine Datei wie logo.jpg oder .ico, die '<?php ' enthält, ist fast immer eine Tarnung. (Die bloße Zeichenfolge '<?=' wird nur mit Befehlen gewertet, weil sie in Bilddaten zufällig vorkommt.)", dis[:60],
                "Datei herunterladen (Beweis) und löschen. Prüfen, ob in dem Ordner eine .htaccess PHP-Ausführung erlaubt.")
    if not (crit or warn or bad_cache or lang_cache or unk_cache or hid or dis):
        res.add("ok", "Keine PHP-Dateien in Upload-, Temp- und Cache-Ordnern",
                "Geprüft: images, media, files, tmp, cache, logs (inkl. versteckter Dateien und getarnter Dateien).")


# A8 (2.4.0): Code, der Bild-/Textdateien als PHP einbindet, und PHP-Dateien mit Bildkopf. Ohne Anführungszeichen, damit die Muster in einfache Shell-Anführungszeichen passen.
# [^;?] begrenzt auf eine Anweisung (kein Treffer über ';' oder '?>' hinweg).
A8_IMG = r"(include|require)(_once)?[[:space:]]*\(?[^;?]{0,200}\.(ico|png|jpe?g|gif|bmp|webp)[^A-Za-z0-9_]"
A8_TXT = r"(include|require)(_once)?[[:space:]]*\(?[^;?]{0,200}\.(txt|log|dat|tmp)[^A-Za-z0-9_]"
A8_FGC = r"(eval|assert|create_function|include|require)(_once)?[[:space:]]*\(?[^;?]{0,80}file_get_contents[^;?]{0,200}\.(ico|png|jpe?g|gif|bmp|webp|txt|log|dat)[^A-Za-z0-9_]"
A8_MAXKB = 2048          # größere Dateien werden für A8 nicht gelesen (Schutz vor Last)


# ----------------------------------------------------------------------------- Web-Shell-Signaturen
R1 = r"eval\s*\(\s*(base64_decode|gzinflate|gzuncompress|str_rot13|rawurldecode|strrev)\s*\("
R2 = r"(assert|eval|system|passthru|shell_exec|exec|popen|proc_open|pcntl_exec)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)"
R3 = r"preg_replace\s*\(\s*.[^,]{0,60}/e.\s*,"
R4 = r"FilesMan|c99shell|r57shell|b374k|IndoXploit|Mini Shell|ALFA TEAM|Tryag|0byt3m1n1|WSO [0-9]\.[0-9]"
R5 = r"base64_decode\s*\(\s*.[A-Za-z0-9+/=]{300,}"


@check(
    "webshells", G, "Hintertüren (Web-Shells) in PHP-Dateien suchen",
    "Enthalten PHP-Dateien typische Hintertür-Muster wie eval(base64_decode(...)) oder Befehle aus Formulardaten?",
    what="Durchsucht alle PHP-Dateien in vier Stufen: (1) eindeutige Hintertür-Muster, (2) Dateien mit base64/eval, die in den letzten Tagen "
         "geändert wurden, (3) Dateien mit extrem langen Zeilen (verschleierter Code), (4) Tarnung als Bild: PHP-Dateien mit GIF-/PNG-/JPEG-Kopf und PHP-Code, "
         "der Bild- oder Textdateien einbindet (include/require/file_get_contents auf .ico, .png, .jpg, .txt ...; Dateien über 2 MB werden dafür nicht gelesen). Bekannte Bibliotheken (vendor, libraries) werden dabei geschont.",
    why="Web-Shells erlauben dem Angreifer, jederzeit Befehle auszuführen, auch nach einem Passwortwechsel. Ohne sie zu finden und zu entfernen, "
        "kommt der Angreifer zurück.",
    reads="Durchsucht den Inhalt aller PHP-Dateien auf dem Server (nur lesend). Dauert bei großen Seiten einige Minuten und belastet den Server kurz.",
    load="hoch", presets=["hack"],
    options=[Option("days", "Als 'neu' zählen: letzte ... Tage", "int", 90, "Dateien mit base64/eval, die in diesem Zeitraum geändert wurden, werden hervorgehoben.")],
)
def webshells(ctx, res):
    days = ctx.opt_int("days", 90)
    script = r"""
R1='@R1@'; R2='@R2@'; R3='@R3@'; R4='@R4@'; R5='@R5@'
INC="--include=*.php --include=*.phtml --include=*.php5 --include=*.php7 --include=*.phar --include=*.inc --include=*.pht"
echo '@@T1'
grep -rIlE $INC -e "$R1" -e "$R2" -e "$R3" -e "$R4" -e "$R5" . 2>/dev/null | head -200 | while IFS= read -r f; do
  grep -noE -e "$R1" -e "$R2" -e "$R3" -e "$R4" -e "$R5" "$f" 2>/dev/null | head -3 | cut -c1-220 | while IFS= read -r m; do printf 'HIT\t%s\t%s\n' "$f" "$m"; done
done
echo '@@T2'
grep -rIlE $INC -e 'base64_decode|gzinflate|str_rot13|eval *\(|create_function' . 2>/dev/null | grep -viE '@LIBEX2@' | head -3000 | while IFS= read -r f; do
  printf 'T2\t%s\t%s\n' "$(stat -c %Y "$f" 2>/dev/null)" "$f"
done
echo '@@LL'
grep -rIlE $INC -e '.{4000}' . 2>/dev/null | grep -viE '@LIBEX@' | head -100 | while IFS= read -r f; do
  sus=0; grep -qE 'eval *\(|base64_decode|gzinflate|str_rot13|assert *\(|\$_(GET|POST|REQUEST|COOKIE)' "$f" 2>/dev/null && sus=1
  printf 'LL\t%s\t%s\t%s\t%s\n' "$(stat -c %Y "$f" 2>/dev/null)" "$(stat -c %s "$f" 2>/dev/null)" "$f" "$sus"
done
echo '@@A8I'
find . -type f \( -iname '*.php' -o -iname '*.phtml' -o -iname '*.php5' -o -iname '*.php7' -o -iname '*.pht' -o -iname '*.inc' \) -size -@A8KB@k -print0 2>/dev/null | xargs -0 -r grep -HnoE -e "@A8IMG@" -e "@A8FGC@" 2>/dev/null | grep -viE '@LIBEX2@' | head -150 | while IFS= read -r m; do printf 'IM\tI\t%s\n' "$m"; done
find . -type f \( -iname '*.php' -o -iname '*.phtml' -o -iname '*.php5' -o -iname '*.php7' -o -iname '*.pht' -o -iname '*.inc' \) -size -@A8KB@k -print0 2>/dev/null | xargs -0 -r grep -HnoE -e "@A8TXT@" 2>/dev/null | grep -viE '@LIBEX2@' | head -150 | while IFS= read -r m; do printf 'IM\tT\t%s\n' "$m"; done
echo '@@A8H'
LC_ALL=C grep -rlaE -m1 -e '^GIF8[79]a' -e '^.PNG' -e $'^\xff\xd8\xff' $INC . 2>/dev/null | head -300 | while IFS= read -r f; do
  [ "$(stat -c %s "$f" 2>/dev/null || echo 0)" -le @A8BYTES@ ] || continue
  h=$(head -c 4 "$f" 2>/dev/null | od -An -tx1 | tr -d ' \n')
  case "$h" in 47494638|89504e47|ffd8ff*) grep -qaE '<\?(php|=)' "$f" 2>/dev/null && printf 'IH\t%s\t%s\n' "$f" "$h";; esac
done | head -100
echo '@@MFT'
@MFT@
echo '@@NOW'; date +%s
""".replace("@A8KB@", str(A8_MAXKB)).replace("@A8BYTES@", str(A8_MAXKB * 1024)).replace("@A8IMG@", A8_IMG).replace("@A8TXT@", A8_TXT).replace("@A8FGC@", A8_FGC).replace("@MFT@", ctx.prof["manifest_find"]).replace("@LIBEX@", ctx.prof["lib_exclude"]).replace("@LIBEX2@", ctx.prof["lib_exclude2"]).replace("@R1@", R1).replace("@R2@", R2).replace("@R3@", R3).replace("@R4@", R4).replace("@R5@", R5)
    out = ctx.sh(script, timeout=480, raw="treffer").out
    sec = split_sections(out)
    now = _epoch_now(sec)
    by_file: Dict[str, List[str]] = defaultdict(list)
    for ln in sec.get("T1", "").splitlines():
        p = ln.split("\t")
        if len(p) >= 3 and p[0] == "HIT":
            by_file[p[1]].append(trunc(clean_line(p[2]), 140))
    real, scanner = [], []
    known = known_tool_split(ctx, list(by_file))
    for f, ms in by_file.items():
        entry = "%s - %s" % (clean_line(f), "; ".join(ms[:2]))
        if f in known:
            scanner.append("%s  [%s]" % (entry, known[f]))
        else:
            real.append(entry)
    if real:
        res.add("crit", "%d Datei(en) mit typischen Hintertür-Mustern" % len(real),
                "Gefunden wurden Muster wie eval(base64_decode(...)), Befehle aus $_POST/$_GET oder bekannte Shell-Namen.", real[:80],
                "Dateien nicht ausführen. Herunterladen (Beweis), löschen und prüfen, wie sie auf den Server kamen.")
    if scanner:
        res.add("info", "Muster in Sicherheits-/Backup-Erweiterungen (üblich)",
                "Virenscanner und ähnliche Erweiterungen enthalten Listen solcher Muster, um sie zu erkennen. Als bekannt gilt eine Datei nur, wenn sie im Ordner der Erweiterung liegt UND deren Kennung enthält "
                "(Liste vom %s). Dateien, die nur so heißen oder woanders liegen, werden oben als Hintertür gemeldet." % load_known_tools().get("stand", "?"), scanner[:20])
    t2: List[Tuple[float, str]] = []
    old2 = 0
    for ln in sec.get("T2", "").splitlines():
        p = ln.split("\t")
        if len(p) >= 3 and p[0] == "T2":
            try:
                mt = float(p[1])
            except ValueError:
                mt = 0.0
            age = (now - mt) / 86400.0 if mt else 9999
            if age <= days and p[2] not in by_file:
                t2.append((mt, p[2]))
            else:
                old2 += 1
    # Update-Erkennung 1: Viele Dateien in derselben Stunde geändert (Joomla-Kern, große Updates)
    per_hour = Counter(int(mt // 3600) for mt, _ in t2)
    waves = {h for h, n in per_hour.items() if n >= 10}
    # Update-Erkennung 2: Die Datei wurde zusammen mit der Beschreibungsdatei (Manifest) ihrer Erweiterung geändert
    manifest_mt: Dict[str, float] = {}
    for ln in sec.get("MFT", "").splitlines():
        p = ln.split("\t")
        if len(p) >= 3 and p[0] == "MF":
            try:
                manifest_mt["./" + p[2].lstrip("./")] = max(manifest_mt.get("./" + p[2].lstrip("./"), 0.0), float(p[1]))
            except ValueError:
                pass
    recent2: List[str] = []
    wave_items: List[str] = []
    ext_updates: Dict[str, List[str]] = defaultdict(list)
    for mt, path in sorted(t2, reverse=True):
        desc = "%s  (vor %d Tagen geändert)" % (clean_line(path), (now - mt) / 86400.0)
        root = ext_root(path, ctx.cms)
        mm = manifest_mt.get(root or "")
        if int(mt // 3600) in waves:
            wave_items.append(desc)
        elif root and mm and abs(mt - mm) <= 3 * 86400:
            ext_updates[root].append(path)
        else:
            recent2.append(desc)
    if recent2:
        res.add("warn", "%d kürzlich geänderte Datei(en) mit base64/eval" % len(recent2),
                "Diese Funktionen nutzen auch viele legitime Erweiterungen. Verdächtig ist aber, wenn die Datei neu ist und du keine Änderung kennst.",
                recent2[:60], "Dateien ansehen: Gehört die Datei zu einer Erweiterung, die du kürzlich aktualisiert hast?")
    if ext_updates:
        res.add("info", "%d Erweiterung(en) mit base64/eval-Dateien wurden zusammen mit ihrer Beschreibungsdatei geändert (Update)" % len(ext_updates),
                "Wird eine Erweiterung aktualisiert, ändern sich ihre Dateien und die Beschreibungsdatei (xml) gleichzeitig. Das spricht für ein normales Update. "
                "Ein Angreifer ändert meist nur eine einzelne Datei und lässt die Beschreibungsdatei unberührt.",
                ["%s: %d Datei(en), Update am %s" % (r, len(f), time.strftime("%Y-%m-%d", time.localtime(manifest_mt[r]))) for r, f in sorted(ext_updates.items())][:25], context=True)
    if wave_items:
        res.add("info", "%d Datei(en) mit base64/eval wurden gemeinsam mit vielen anderen geändert (vermutlich Update)" % len(wave_items),
                "Mindestens 10 Dateien wurden innerhalb derselben Stunde geändert. Das passiert bei Joomla- und Erweiterungs-Updates. "
                "Falls du zu dem Zeitpunkt nichts aktualisiert hast, bitte genauer prüfen (Test 'Kürzlich geänderte Dateien').",
                wave_items[:15], context=True)
    if old2:
        res.add("info", "%d ältere Datei(en) mit base64/eval (außerhalb von vendor/libraries)" % old2,
                "Meist legitim (Erweiterungen). Wird nur zur Vollständigkeit gezählt.")
    a8_img: List[str] = []
    a8_txt: List[str] = []
    a8_rows = []
    for ln in sec.get("A8I", "").splitlines():
        p = ln.split("\t", 2)
        if len(p) == 3 and p[0] == "IM":
            m = re.match(r"^(.*?):(\d+):(.*)\Z", p[2])
            if m:
                a8_rows.append((p[1], m))
    a8_known = known_tool_split(ctx, [m.group(1) for _, m in a8_rows])
    for kind, m in a8_rows:
        if m.group(1) in a8_known:
            continue
        entry = "%s, Zeile %s: %s" % (clean_line(m.group(1)), m.group(2), trunc(clean_line(m.group(3)), 110))
        (a8_img if kind == "I" else a8_txt).append(entry)
    a8_head: List[str] = []
    for ln in sec.get("A8H", "").splitlines():
        p = ln.split("\t")
        if len(p) >= 3 and p[0] == "IH":
            a8_head.append("%s  (beginnt mit %s-Kopf)" % (clean_line(p[1]), {"47494638": "GIF", "89504e47": "PNG"}.get(p[2], "JPEG")))
    if a8_head:
        res.add("crit", "%d PHP-Datei(en) mit Bildkopf (GIF/PNG/JPEG) und PHP-Code" % len(a8_head),
                "Eine Datei, die wie ein Bild beginnt, aber PHP-Code enthält, soll Upload-Filter täuschen, die nur den Dateianfang prüfen. In normalen Erweiterungen kommt das nicht vor.",
                a8_head[:60], "Datei herunterladen (Beweis), nicht im Browser öffnen, in Quarantäne verschieben und prüfen, wie sie auf den Server kam.")
    if a8_img:
        res.add("crit", "%d PHP-Datei(en) binden Bilddateien oder Bildinhalte als Code ein" % len(a8_img),
                "Ein include/require auf .ico, .png, .jpg oder .gif (oder eval/include von file_get_contents darauf) versteckt Schadcode in einer Bilddatei, die bei der Suche nach PHP-Dateien übersehen wird.",
                a8_img[:60], "Die genannte Zeile und die eingebundene Datei ansehen (nicht im Browser öffnen). Enthält die Bilddatei PHP-Code, beide in Quarantäne verschieben.")
    if a8_txt:
        res.add("warn", "%d PHP-Datei(en) binden Text-/Datendateien (.txt, .log, .dat, .tmp) als Code ein" % len(a8_txt),
                "Das ist ungewöhnlich und wird als Versteck für Schadcode genutzt. Selten ist es harmlos (z. B. eine Vorlage).",
                a8_txt[:60], "Zeile und eingebundene Datei ansehen: Enthält sie PHP-Code, den du nicht kennst?")
    long_recent, long_old, long_data = [], [], []
    for ln in sec.get("LL", "").splitlines():
        p = ln.split("\t")
        if len(p) >= 4 and p[0] == "LL":
            try:
                age = (now - float(p[1])) / 86400.0
            except ValueError:
                age = 9999
            desc = "%s  (%s Byte, vor %d Tagen)" % (clean_line(p[3]), p[2], age)
            sus = len(p) < 5 or p[4].strip() != "0"
            if not sus:
                long_data.append(desc)         # lange Zeilen, aber keine Befehle: Datentabellen (Icons, Geräteliste)
            else:
                (long_recent if age <= days else long_old).append(desc)
    if long_recent:
        res.add("warn", "%d kürzlich geänderte PHP-Datei(en) mit extrem langen Zeilen und Befehlen" % len(long_recent),
                "Verschleierter Code besteht oft aus einer einzigen sehr langen Zeile.", long_recent[:40], "Inhalt prüfen.")
    if long_old:
        res.add("info", "%d ältere PHP-Datei(en) mit extrem langen Zeilen" % len(long_old), "Meist Übersetzungs- oder Datendateien.", long_old[:15])
    if long_data:
        res.add("info", "%d PHP-Datei(en) mit langen Zeilen, aber ohne Befehle (Datentabellen)" % len(long_data),
                "Lange Zeilen allein sind kein Hinweis auf Schadcode. Hier fehlen eval, base64_decode, $_POST usw. Üblich bei Icon-Listen und Geräte-Erkennung.",
                long_data[:15], context=True)
    if not (real or recent2 or long_recent or a8_head or a8_img or a8_txt):
        res.add("ok", "Keine Hintertür-Muster in PHP-Dateien gefunden",
                "Hinweis: Eine saubere Suche beweist nicht, dass nichts da ist - gut versteckter Code kann durch Muster rutschen.")


# ----------------------------------------------------------------------------- auffällige Dateinamen
STRONG_NAME_RE = re.compile(r"^(wp-[a-z-]+|adminer[^/]*|phpinfo|shell[^/]*|cmd|c99|r57|wso|b374k|alfa|uploader|bypass|lock360|leaf)\.php\Z")
ODD_EXT_RE = re.compile(r"\.(phtml|pht|phar|suspected|php[0-9])$|\.php\.[^/]+$")
WEAK_NAME_RE = re.compile(r"^(radio|index2|up|info|xmlrpc|[a-z0-9]|\.[^/]+)\.php\Z")
KNOWN_DOTFILES = {".php-cs-fixer.dist.php", ".php-cs-fixer.php", ".phpstorm.meta.php"}
CODE_DIR_RE = re.compile(r"^\./(administrator/)?(components|modules|plugins|templates|layouts|libraries|language)/|^\./(layouts|libraries|api|includes|cli)/")
WP_CODE_DIR_RE = re.compile(r"^\./wp-content/(plugins|themes|mu-plugins|languages)/|^\./(wp-includes|wp-admin)/")


@check(
    "suspicious_names", G, "Auffällige Dateinamen",
    "Gibt es Dateien mit typischen Hintertür-Namen, Doppelendungen oder vergessenen Entwickler-Dateien?",
    what="Sucht nach Dateien wie wp-login.php (auf einer Joomla-Seite!), adminer.php, phpinfo.php, shell.php, Dateien mit Doppelendung "
         "(z. B. bild.php.jpg), .phtml/.phar-Dateien, ungewöhnlich kurzen PHP-Namen (a.php), sowie .git, .env, error_log und Sicherungskopien von PHP-Dateien (.php.bak).",
    why="Angreifer wählen oft unauffällige Namen. Sicherungskopien wie configuration.php.bak können Passwörter im Klartext ausliefern.",
    reads="Nur Dateinamen, Größe und Datum.",
    load="leicht", presets=["schnell", "hack"],
)
def suspicious_names(ctx, res):
    bad = [n.lower() for n in ctx.adv.get("known_bad_filenames", [])]
    out = ctx.sh(r"""
echo '@@NAMES'
find . \( @PRUNE@ \) -prune -o -regextype posix-extended -type f \( \
  -iname '*.php.*' -o -iname '*.phtml' -o -iname '*.pht' -o -iname '*.phar' -o -iname '*.php[0-9]' -o -iname '*.suspected' \
  @WPROOT@ \
  -o -iregex '.*/(@WPNAME@adminer[^/]*|phpinfo|info|shell[^/]*|cmd|c99|r57|wso|b374k|alfa|uploader|bypass|xmlrpc|leaf|lock360|radio|index2|up)\.php' \
  -o -iregex '.*/\.[^/]+\.php' -o -iregex '.*/[a-z0-9]\.php' \) -printf '%TY-%Tm-%Td\t%s\t%p\n' 2>/dev/null | head -300
echo '@@DEV'
find . \( @PRUNE2@ \) -prune -o \( -name .git -o -name .svn -o -name .env -o -name .DS_Store -o -name error_log -o -name php_errorlog -o -name php_errors.log \) -printf '%TY-%Tm-%Td\t%y\t%p\n' 2>/dev/null | head -100
""".replace("@PRUNE@", ctx.prof["prune_find"]).replace("@PRUNE2@", "-path ./node_modules -o -path ./cache" if ctx.cms == "joomla" else "-path ./node_modules -o -path ./wp-content/cache")
       .replace("@WPNAME@", "wp-[a-z-]+|" if ctx.cms == "joomla" else "")
       .replace("@WPROOT@", "" if ctx.cms == "joomla" else "-o -iregex './wp-[a-z-]+\\.php'"), timeout=120, raw="treffer").out
    sec = split_sections(out)
    crit, warn, common = [], [], []
    for ln in sec.get("NAMES", "").splitlines():
        p = ln.split("\t")
        if len(p) < 3:
            continue
        path = p[2]
        base = path.rsplit("/", 1)[-1].lower()
        desc = "%s  (%s, %s Byte)" % (clean_line(path), p[0], p[1])
        if ctx.cms == "wordpress" and path.count("/") == 1 and base in ctx.prof["core_files"]:
            continue                      # Kerndatei von WordPress im Hauptordner (z. B. wp-login.php, xmlrpc.php)
        if base in bad and base not in ("xmlrpc.php",):
            crit.append(desc)
        elif STRONG_NAME_RE.match(base) or ODD_EXT_RE.search(base):
            warn.append(desc)
        elif base in KNOWN_DOTFILES or (WEAK_NAME_RE.match(base) and (WP_CODE_DIR_RE if ctx.cms == "wordpress" else CODE_DIR_RE).match(path)):
            common.append(desc)        # z. B. layouts/.../radio.php oder .php-cs-fixer.dist.php: gehört zu Joomla bzw. Erweiterungen
        else:
            warn.append(desc)
    if crit:
        res.add("crit", "%d Datei(en) mit typischen Hintertür-Namen" % len(crit), "", crit[:60], "Inhalt prüfen (nicht öffnen/ausführen) und löschen.")
    if warn:
        res.add("warn", "%d Datei(en) mit auffälligem Namen" % len(warn),
                "Doppelendungen, .phtml/.phar, ungewöhnlich kurze Namen oder Sicherungskopien von PHP-Dateien.", warn[:80], "Jede Datei kurz prüfen: Kennst du sie?")
    if common:
        res.add("info", "%d Datei(en) mit Namen, die in Joomla und Erweiterungen üblich sind" % len(common),
                "Namen wie radio.php stehen auch in Joomlas Formularfeldern und Layouts; Entwicklerdateien wie .php-cs-fixer.dist.php gehören zum Joomla-Paket. "
                "Verdächtig wären sie nur in images, media, tmp oder im Hauptverzeichnis.", common[:20], context=True)
    dev = []
    for ln in sec.get("DEV", "").splitlines():
        p = ln.split("\t")
        if len(p) >= 3:
            dev.append("%s  (%s)" % (clean_line(p[2]), p[0]))
    if dev:
        res.add("warn", "%d Entwickler-/Fehlerdatei(en) gefunden" % len(dev),
                ".git, .env und error_log können Quellcode, Zugangsdaten und Angriffsspuren verraten.", dev[:60],
                "Aufheben (error_log ansehen: Angriffsspuren!), sonst löschen oder per .htaccess sperren.")
    if not (crit or warn or dev):
        res.add("ok", "Keine auffälligen Dateinamen gefunden")


# ----------------------------------------------------------------------------- kürzliche Änderungen
def _ctime_findings(ctx, res, section: str, days: int) -> None:
    """A9 (2.4.0): Dateien, deren Änderungsdatum (mtime) alt ist, deren Eintrag (ctime) aber kürzlich geändert wurde. Das Änderungsdatum lässt sich mit touch beliebig zurückstellen,
    die ctime nicht (ohne Administratorrechte). Ursachen sind Rechteänderung, Besitzerwechsel, Kopieren oder Wiederherstellen, aber auch ein zurückgestelltes Datum. Darum höchstens Hinweis oder Warnung, nie kritisch."""
    rows = []
    for ln in section.splitlines():
        p = ln.split("\t")
        if len(p) >= 5 and p[0] == "C":
            rows.append((p[1], int(p[2] or 0), p[3], p[4]))
    if not rows:
        return
    per_hour = Counter(r[0][:13] for r in rows)
    bulk_hours = {h for h, n in per_hour.items() if n >= 30}
    # Warnung nur für PHP-artige Dateien in Ordnern, in denen normalerweise nur Daten liegen (Bilder, Cache, Logs, Uploads, tmp). Alles andere (.htaccess, JS, Entwicklungsdateien,
    # entpackte Archive mit altem Änderungsdatum) bleibt ein Hinweis, damit ein Upload oder eine Wiederherstellung keinen Fehlalarm auslöst.
    php_rx = re.compile(r"\.(php\d?|phtml|phar)$", re.IGNORECASE)
    data_rx = re.compile(r"^\./(images|tmp|cache|logs|administrator/cache|administrator/logs|wp-content/(uploads|cache|upgrade))/")

    def is_outside(r):
        if r[3].rsplit("/", 1)[-1].lower() == "index.php" and r[1] <= 100:
            return False        # die winzige 'Silence is golden'-Datei, die WordPress und Joomla in Daten-Ordner legen
        return bool(php_rx.search(r[3])) and bool(data_rx.match(r[3]))
    # Solche Dateien werden auch in einer Massenänderung einzeln genannt (sonst ließen sie sich darin verstecken)
    outside = [r for r in rows if is_outside(r)]
    single = [r for r in rows if r[0][:13] not in bulk_hours or r in outside]
    bulk = len(rows) - len(single)
    note = ("Das Änderungsdatum (mtime) lässt sich mit 'touch' zurückstellen, die ctime nicht. Eine neue ctime bei altem Änderungsdatum entsteht durch Rechte- oder Besitzeränderung, Kopieren oder Wiederherstellen "
            "(auch durch die Aktion 'Schreibrechte für alle entfernen' dieses Programms), kann aber auch ein zurückgestelltes Datum verraten.")
    if outside:
        res.add("warn", "%d PHP-Datei(en) in Daten-Ordnern: Eintrag kürzlich geändert, Änderungsdatum alt" % len(outside), note,
                ["%s  (ctime %s, mtime %s, %d Byte)" % (clean_line(r[3]), r[0], r[2], r[1]) for r in outside[:50]],
                "Prüfen, ob du (oder ein Update, eine Rechte-Aktion, eine Wiederherstellung) die Dateien angefasst hast. Sonst Inhalt ansehen.")
    other = [r for r in single if r not in outside]
    if other:
        res.add("info", "%d weitere Datei(en): Eintrag kürzlich geändert, Änderungsdatum alt (ctime)" % len(other), note,
                ["%s  (ctime %s, mtime %s)" % (clean_line(r[3]), r[0], r[2]) for r in other[:25]])
    if bulk:
        res.add("info", "%d Datei(en) in einer Massenänderung (ctime, jeweils 30 und mehr in derselben Stunde)" % bulk,
                "Üblich nach Rechte-Änderungen, Kopieren, Wiederherstellen aus einer Sicherung oder einem Update. Einzeln werden sie nicht aufgelistet.",
                ["%s Uhr: %d Dateien" % (h, n) for h, n in sorted(per_hour.items(), reverse=True) if h in bulk_hours][:15])


@check(
    "recent_changes", G, "Kürzlich geänderte Dateien",
    "Welche Dateien wurden im gewählten Zeitraum verändert - und wann?",
    what="Listet alle Dateien, die in den letzten Tagen geändert wurden (ohne Cache, tmp und Logs), gruppiert nach Tag und Ordner, "
         "und hebt ausführbare Dateien (PHP, JS, .htaccess) hervor. Zusätzlich (ctime): Dateien, deren Änderungsdatum alt ist, deren Eintrag aber kürzlich geändert wurde, "
         "denn das Änderungsdatum lässt sich zurückstellen, die ctime nicht.",
    why="Angreifer ändern Dateien und hinterlassen Spuren in der Zeitleiste. Häufungen an einem Tag zeigen oft den Zeitpunkt des Einbruchs. "
        "Du kannst die Liste mit deinen eigenen Arbeiten (Updates, Uploads) abgleichen.",
    reads="Nur Pfade, Größen und Änderungsdaten.",
    load="mittel", presets=["hack"],
    options=[Option("days", "Zeitraum in Tagen", "int", 30, "Wie weit soll zurückgeschaut werden? Für die Aufklärung eines Hacks z. B. 120.")],
)
def recent_changes(ctx, res):
    days = max(1, ctx.opt_int("days", 30))
    out = ctx.sh(r"""
find . -type f -mtime -@D@ @SKIP@ \
  -printf 'R\t%TY-%Tm-%Td %TH:%TM\t%s\t%p\n' 2>/dev/null | sort -r | head -4000
echo '@@CT'
find . -type f -ctime -@D@ ! -mtime -@D@ @SKIP@ \
  -printf 'C\t%CY-%Cm-%Cd %CH:%CM\t%s\t%TY-%Tm-%Td\t%p\n' 2>/dev/null | sort -r | head -2000
echo '@@NOW'; date +%s
""".replace("@D@", str(days)).replace("@SKIP@", ctx.prof["recent_skip"]), timeout=150, raw="liste", raw_cap=250_000).out
    entries = []
    head_part, _, ct_part = out.split("@@NOW")[0].partition("@@CT")
    for ln in head_part.splitlines():
        p = ln.split("\t")
        if len(p) >= 4 and p[0] == "R":
            entries.append((p[1], int(p[2] or 0), p[3]))
    _ctime_findings(ctx, res, ct_part, days)
    if not entries:
        res.add("info", "Keine Dateiänderungen in den letzten %d Tagen" % days)
        return
    per_day = Counter(e[0][:10] for e in entries)
    per_dir = Counter("/".join(e[2].split("/")[:3]) if e[2].count("/") > 2 else e[2].rsplit("/", 1)[0] for e in entries)
    busy = ["%s: %d Dateien" % (d, n) for d, n in sorted(per_day.items(), reverse=True)[:25]]
    res.add("info", ("Mindestens %d Dateien in den letzten %d Tagen geändert (Liste bei %d gekürzt)" % (len(entries), days, len(entries))) if len(entries) >= 4000
            else "%d Dateien in den letzten %d Tagen geändert" % (len(entries), days),
            "Tage mit vielen Änderungen sind meist Updates oder Uploads. Gleiche sie mit deinen eigenen Arbeiten ab.", busy)
    res.add("info", "Am stärksten betroffene Ordner", "", ["%s: %d" % (d, n) for d, n in per_dir.most_common(15)])
    risky = [e for e in entries if re.search(r"\.(php\d?|phtml|phar|js|htaccess|ini)$", e[2], re.IGNORECASE) or e[2].endswith(".htaccess")]
    root_ok = ctx.prof["root_ok"]
    outside = [e for e in risky if e[2] not in root_ok and not re.match(ctx.prof["ext_dir_re"], e[2])]
    if outside:
        res.add("warn", "%d ausführbare Datei(en) außerhalb der üblichen Erweiterungs-Ordner geändert" % len(outside),
                "Z. B. im Hauptverzeichnis (außer den Kerndateien), in %s. Dort ändert sich normalerweise nichts." % ctx.prof["outside_dir"],
                ["%s  %s (%s Byte)" % (clean_line(e[2]), e[0], e[1]) for e in outside[:60]], "Prüfen, ob du diese Änderungen selbst gemacht hast.")
    if risky:
        res.add("info", "%d ausführbare Datei(en) geändert (PHP/JS/.htaccess)" % len(risky), "Die jüngsten zuerst.",
                ["%s  %s" % (clean_line(e[2]), e[0]) for e in risky[:40]])


# ----------------------------------------------------------------------------- Backups im Web-Verzeichnis
INSTALLER_SQL_RE = re.compile(r"^\./(administrator/)?(components|modules|plugins|templates)/.+/sql/.*\.sql$|^\./installation/.*\.sql\Z", re.IGNORECASE)

# Installationsskripte legen nur Tabellen und Voreinstellungen an. Auffällig ist, was dort nichts verloren hat: Konten, Rechte, Code, Dateizugriffe.
SQL_SUSPECT = [
    (r"<\?php|\beval\s*\(|base64_decode|from_base64|gzinflate|\bsystem\s*\(|shell_exec",
     "enthält PHP-Code oder Verschleierung. In einem Tabellen-Skript hat das keinen Zweck; so werden Hintertüren eingeschleust."),
    (r"into\s+(out|dump)file|load_file\s*\(|load\s+data\s+(local\s+)?infile",
     "schreibt oder liest Dateien auf dem Server. Ein Installationsskript braucht das nicht; so lässt sich Schadcode ablegen."),
    (r"\bcreate\s+user\b|\bgrant\s+|\bdrop\s+(database|schema)\b|\balter\s+user\b",
     "legt Datenbank-Konten oder Rechte an bzw. löscht die Datenbank. Das gehört nicht in ein Erweiterungs-Skript."),
    (r"(insert\s+into|update|replace\s+into)\s+[`'\"]?(#__|[a-z0-9]+_)(users|user_usergroup_map|usergroups|user_keys)\b",
     "legt Benutzer an oder ändert sie bzw. ihre Gruppen. So entstehen unbemerkt Administrator-Konten."),
    (r"(insert\s+into|update|replace\s+into)\s+[`'\"]?(#__|[a-z0-9]+_)(options|extensions|template_styles)\b.*(siteurl|home|admin_email|users_can_register|default_role|enabled|\bparams\b)",
     "ändert zentrale Seiteneinstellungen (Adressen, Registrierung, Rollen). Das ist bei Erweiterungs-Skripten ungewöhnlich."),
]
SQL_SUSPECT_GREP = "|".join("(%s)" % a for a, _ in SQL_SUSPECT)


def sql_reason(line: str) -> str:
    """Begründung, warum eine Zeile eines Installations-SQL-Skripts auffällt ('' = unauffällig)."""
    for rx, why in SQL_SUSPECT:
        if re.search(rx, line or "", re.IGNORECASE):
            return why
    return ""


@check(
    "backups_in_webroot", G, "Backups und Dumps im Web-Verzeichnis",
    "Liegen Sicherungsdateien (.jpa, .zip, .sql ...) dort, wo sie jeder per Browser herunterladen könnte?",
    what="Sucht nach Archiven und Datenbank-Dumps in der Seite und prüft, ob der jeweilige Ordner durch eine .htaccess mit Zugriffssperre geschützt ist.",
    why="Ein frei abrufbares Backup enthält Datenbank, Benutzer und Passwort-Hashes. Angreifer suchen gezielt nach Akeeba-Ordnern und .sql-Dateien.",
    reads="Nur Dateinamen, Größe, Datum und - zur Schutzprüfung - die .htaccess im selben Ordner.",
    load="leicht", presets=["schnell", "hack"],
)
def backups_in_webroot(ctx, res):
    out = ctx.sh(r"""
bk() { find . \( -path ./node_modules -o -path ./libraries -o -path ./wp-admin -o -path ./wp-includes -o -path '*/vendor' -o -path '*/tests' \) -prune -o -type f \
  \( -iname '*.jpa' -o -iname '*.zip' -o -iname '*.sql' -o -iname '*.sql.gz' -o -iname '*.tar' -o -iname '*.tar.gz' -o -iname '*.tgz' -o -iname '*.bak' -o -iname '*.7z' -o -iname '*.rar' -o -iname '*.wpress' \) "$@" 2>/dev/null; }
declare -A PC
prot_of() {
  local d="$1" p="$1"; RES=nein
  if [ -n "${PC[$d]}" ]; then RES="${PC[$d]}"; return; fi
  while [ -n "$p" ] && [ "$p" != "." ] && [ "$p" != "/" ]; do
    if [ -f "$p/.htaccess" ] && grep -qiE 'require +all +denied|deny +from +all' "$p/.htaccess" 2>/dev/null; then RES=ja; break; fi
    p=$(dirname "$p")
  done
  PC[$d]=$RES
}
echo '@@FILES'
bk -printf '%s\t%TY-%Tm-%Td\t%p\n' | head -600 | while IFS=$'\t' read -r sz dt path; do
  prot_of "$(dirname "$path")"
  printf 'F\t%s\t%s\t%s\t%s\n' "$sz" "$dt" "$RES" "$path"
done
""", timeout=150, raw="treffer").out
    sec = split_sections(out)
    crit, warn, safe, installer = [], [], [], []
    for ln in sec.get("FILES", "").splitlines():
        p = ln.split("\t")
        if len(p) < 5 or p[0] != "F":
            continue
        size, date, prot, path = int(p[1] or 0), p[2], p[3], p[4]
        desc = "%s  (%s, %s)" % (clean_line(path), human_size(size), date)
        if re.match(ctx.prof["installer_sql_re"], path, re.IGNORECASE) and size < 500_000:
            installer.append((path, desc))
        elif prot == "ja":
            safe.append(desc)
        elif re.search(r"\.(jpa|sql|sql\.gz|wpress)$", path, re.IGNORECASE) or (size > 100_000 and path.lower().endswith((".zip", ".tar.gz", ".tgz", ".7z", ".rar"))):
            crit.append(desc)
        else:
            warn.append(desc)
    if crit:
        res.add("crit", "%d Backup-/Dump-Datei(en) ohne Zugriffssperre" % len(crit),
                "Diese Dateien könnten per Browser heruntergeladen werden, wenn jemand den Dateinamen errät oder findet.", crit[:60],
                "In einen geschützten Ordner außerhalb des Web-Verzeichnisses verschieben oder eine .htaccess mit 'Require all denied' in den Ordner legen. "
                "Danach die Adresse im privaten Browserfenster testen (muss 403 liefern).")
    if warn:
        res.add("warn", "%d weitere Archiv-/Sicherungsdatei(en) ohne Zugriffssperre" % len(warn), "", warn[:60], "Prüfen und aufräumen.")
    if safe:
        res.add("info", "%d Datei(en) in geschützten Ordnern" % len(safe),
                "Der Ordner (oder ein übergeordneter Ordner) enthält eine .htaccess mit Sperrregel. Ob sie wirkt, prüft der Test 'Webseite aus Besuchersicht' automatisch per Abruf.", safe[:20])
    odd = []
    if installer:
        files = [p for p, _ in installer]
        odd = [(p, "Der Dateiname enthält Steuerzeichen. Das kommt bei echten Erweiterungen nicht vor.", "") for p in files if re.search(r"[\x00-\x1f]", p)]
        todo = [p for p in files if not re.search(r"[\x00-\x1f]", p)][:300]
        if todo:
            pat = SQL_SUSPECT_GREP.replace("'", "'\\''")
            scan = ctx.sh("PAT='%s'\nfor f in %s; do m=$(grep -ianE -m1 -e \"$PAT\" -- \"$f\" 2>/dev/null | head -c 240); [ -n \"$m\" ] && printf 'S\\t%%s\\t%%s\\n' \"$f\" \"$m\"; done"
                          % (pat, " ".join(sq(p) for p in todo)), timeout=60, raw="installer_sql_scan").out
            for ln in scan.splitlines():
                c = ln.split("\t", 2)
                if len(c) == 3 and c[0] == "S":
                    why = sql_reason(c[2])
                    if why:
                        odd.append((c[1], why, c[2]))
    if odd:
        res.add("warn", "%d SQL-Skript(e) von Erweiterungen mit auffälligem Inhalt" % len(odd),
                "Normale Installationsskripte legen nur Tabellen und Voreinstellungen an. Diese enthalten etwas, das dort nicht hingehört. Was genau, steht je Datei darunter.",
                ["%s: %s%s" % (clean_line(p), why, (" Fundstelle: " + mask_secrets(clean_line(txt))[:160]) if txt else "") for p, why, txt in odd[:20]],
                "Datei mit dem Original der Erweiterung vergleichen (Erweiterung neu installieren). Weicht sie ab, die Seite als möglicherweise manipuliert behandeln und Passwörter ändern.")
    if not (crit or warn or safe or odd):
        res.add("ok", "Keine Backups oder Dumps im Web-Verzeichnis gefunden",
                ("%d Installationsskript(e) bekannter Erweiterungen wurden geprüft und sind unauffällig." % len(installer)) if installer else "")
