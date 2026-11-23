"""Erweiterte Malware-/Backdoor-Muster, versteckte Dateien und auffällige Dateistrukturen, vertiefte .htaccess-Untersuchung. Rein lesend."""
from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple

from .. import evidence
from ..registry import check
from ..util import clean_line, lines_of, split_sections, trunc

G = "dateien"
S = r"[[:space:]]"
REQ = r"\$_(GET|POST|REQUEST|COOKIE|SERVER)"

# (id, Titel, Schweregrad, ERE für grep -E, Erklärung). Muster für PHP-Dateien.
PHP_SIGS: List[Tuple[str, str, str, str, str]] = [
    ("cb_request", "Funktion wird mit Formulardaten als Rückruf ausgeführt", "crit",
     r"(array_map|array_filter|array_walk|usort|uasort|uksort|call_user_func(_array)?|register_shutdown_function|register_tick_function|preg_replace_callback|forward_static_call(_array)?)" + S + r"*\(" + S + "*" + REQ,
     "Typischer Weg, Befehle aus der Anfrage auszuführen, ohne das Wort eval zu benutzen."),
    ("cb_danger", "Gefährliche Funktion als Zeichenkette in einem Rückruf", "crit",
     r"(array_map|array_filter|array_walk|usort|uasort|call_user_func(_array)?|register_shutdown_function)" + S + r"*\(" + S + r"*['\"](assert|system|exec|passthru|shell_exec|eval|popen|proc_open)['\"]",
     "Wird benutzt, um Filter nach eval/assert zu umgehen."),
    ("dyn_call", "Funktionsname kommt aus der Anfrage", "crit", REQ + r"\[[^]]*\]" + S + r"*\(",
     "$_POST['f']($_POST['x']) führt jede beliebige PHP-Funktion mit Daten des Besuchers aus."),
    ("eval_var", "eval/assert mit verschachteltem Funktionsaufruf", "crit", r"(eval|assert)" + S + r"*\(" + S + r"*\$[A-Za-z_][A-Za-z0-9_]*" + S + r"*\(",
     "eval($a($b)): Funktionsname und Inhalt stehen in Variablen, damit Suchmuster nichts finden."),
    ("concat_name", "Funktionsname aus Teilstücken zusammengesetzt", "crit",
     r"['\"](ba|bas|base|ass|ev|syst|she|pass|gzin|str_r)['\"]" + S + r"*\." + S + r"*['\"](se64_decode|e64_decode|ert|al|em|ll_exec|thru|flate|ot13)['\"]",
     "Der Name base64_decode/assert/system wird zerlegt, damit er nicht als Ganzes im Code steht."),
    ("input_wrap", "Code aus php://input wird eingebunden", "crit", r"(eval|include|require)(_once)?" + S + r"*\(?" + S + r"*(file_get_contents" + S + r"*\(" + S + r"*)?['\"]php://input",
     "Der Angreifer schickt den Code im Anfragetext; nichts davon steht in Adresse oder Protokoll."),
    ("wrapper_inc", "include mit data://, phar://, zip:// oder expect://", "crit", r"(include|require)(_once)?" + S + r"*\(?" + S + r"*['\"](data|expect|phar|zip)://",
     "Führt Code aus Datenströmen aus; normaler Joomla-/WordPress-Code tut das nicht."),
    ("mailer", "mail() mit Formulardaten als Empfänger", "crit", r"mail" + S + r"*\(" + S + r"*\$_(POST|REQUEST|GET)",
     "Spam-Versender: Die Seite verschickt Mails im Auftrag des Angreifers."),
    ("dropper", "Datei wird mit Formulardaten geschrieben", "warn", r"(file_put_contents|fwrite|fputs)" + S + r"*\([^;]{0,120}" + REQ,
     "Damit kann ein Angreifer weitere Dateien auf dem Server ablegen."),
    ("shell_head", "Typischer Kopf einer Web-Shell (Zeitlimit aus, Fehler aus)", "warn",
     r"@?(set_time_limit|ignore_user_abort)" + S + r"*\(" + S + r"*(0|true|1)" + S + r"*\)" + S + r"*;[^;]{0,80}error_reporting" + S + r"*\(" + S + r"*0",
     "Shells schalten Zeitlimit und Fehlermeldungen ab, damit sie lange und unbemerkt laufen."),
    ("chr_chain", "Text aus vielen chr()-Aufrufen zusammengesetzt", "warn", r"(chr" + S + r"*\(" + S + r"*[0-9]+" + S + r"*\)" + S + r"*\." + S + r"*){5,}",
     "Verschleierung von Funktionsnamen."),
    ("globals_call", "Funktionsaufruf über $GLOBALS", "warn", r"\$GLOBALS\[[^]]{1,40}\]" + S + r"*\(|\$\{" + S + "*[\"']GLOBALS[\"']",
     "Variable Funktionsaufrufe über $GLOBALS sind ein Verschleierungs-Trick."),
    ("hex_escapes", "Lange Folge von Hex-Zeichen (\\x..) in einer Zeichenkette", "warn", r"(\\x[0-9a-fA-F]{2}){8,}",
     "Funktionsnamen und Befehle werden als Hex-Code geschrieben."),
    ("create_func", "create_function()", "warn", r"create_function" + S + r"*\(",
     "Entfernt seit PHP 8; wird von alter Schadsoftware und sehr alten Bibliotheken benutzt."),
]
JS_SIGS: List[Tuple[str, str, str, str, str]] = [
    ("miner", "Kryptowährungs-Miner im Code", "crit", r"coinhive|cryptonight|coin-hive|webminepool|authedmine|minero\.cc|crypto-loot|coinimp|deepminer",
     "Die Besucher-Rechner schürfen unbemerkt Geld für den Angreifer."),
    ("eval_unescape", "eval/document.write mit unescape oder langem base64", "crit",
     r"(eval|document\.write)" + S + r"*\(" + S + r"*(unescape|atob)" + S + r"*\(",
     "Klassische Verschleierung für nachgeladenen Schadcode."),
]
FILE_SCRIPT = r"""
echo '@@PHP'
find . \( @PRUNE@ \) -prune -o -type f \( -iname '*.php' -o -iname '*.phtml' -o -iname '*.inc' -o -iname '*.php[0-9]' -o -iname '*.pht' \) -size -3000k -print0 2>/dev/null \
  | xargs -0 -r grep -HnoiIE -e '@PHPRX@' 2>/dev/null | cut -c1-260 | head -600
echo '@@JS'
find . \( @PRUNE@ \) -prune -o -type f \( -iname '*.js' -o -iname '*.html' -o -iname '*.htm' \) -size -3000k -print0 2>/dev/null \
  | xargs -0 -r grep -HnoiIE -e '@JSRX@' 2>/dev/null | cut -c1-260 | head -300
"""


def classify(text: str, sigs) -> List[Tuple[str, str, str, str, str]]:
    """Ordnet eine Trefferzeile 'Datei:Zeile:Treffer' dem ersten passenden Muster zu: (id, sev, Datei, Zeile, Ausschnitt)."""
    m = re.match(r"^(.*?):(\d+):(.*)\Z", text)
    if not m:
        return []
    path, no, frag = m.groups()
    for sid, _t, sev, rx, _w in sigs:
        if re.search(rx.replace("[[:space:]]", r"\s"), frag, re.I):
            return [(sid, sev, path, no, frag)]
    return []


def lib_path(path: str) -> bool:
    return bool(re.search(r"/(vendor|libraries)/", path))


def vendor_tests(path: str) -> bool:
    """Testdateien von Bibliotheken (z. B. PHP_CodeSniffer-Tests mit Absicht veralteten Funktionen): werden nie ausgeliefert-ausgeführt."""
    return bool(re.search(r"/(vendor|libraries)/.+/(tests?|Tests?|testdata|fixtures?)/", path))


# --- Hex-Zeichenfolgen: erst entschlüsseln, dann bewerten (Binärdaten in Krypto-Bibliotheken sind kein Schadcode)
HEX_BYTE = re.compile(r"\\x([0-9a-fA-F]{2})")
HEX_DANGER = re.compile(r"eval|assert|system|exec|passthru|popen|proc_open|base64|gzinflate|gzuncompress|str_rot13|file_put_contents|fwrite|fopen|include|require|curl|"
                        r"\$_(get|post|request|cookie|server)|<\?|https?:|create_function|preg_replace|move_uploaded|unlink|chmod", re.I)


def hex_decode(frag: str) -> Tuple[str, float]:
    """Entschlüsselter Text und Anteil der druckbaren ASCII-Zeichen."""
    raw = bytes(int(h, 16) for h in HEX_BYTE.findall(frag))
    if not raw:
        return "", 0.0
    txt = raw.decode("latin-1")
    good = sum(1 for b in raw if 32 <= b < 127 or b in (9, 10, 13))
    return txt, good / len(raw)


def hex_verdict(frag: str) -> str:
    """'danger' = entschlüsselt steht ein Befehl/Funktionsname darin; 'text' = lesbarer Text ohne Befehl; 'binary' = Binärdaten (Prüfsummen, Schlüssel, Tabellen)."""
    txt, share = hex_decode(frag)
    if txt and HEX_DANGER.search(txt):
        return "danger"
    return "text" if share >= 0.85 else "binary"


# --- zusammengesetzte Funktionsnamen: reine Liste (kann nichts ausführen) oder echter Code
_LIT = r"(?:'[^'\\]*'|\"[^\"\\]*\")"
_ITEM = r"%s(?:\s*\.\s*%s)*" % (_LIT, _LIT)
_OPEN = r"(?:array\s*\(|\[)"
LIST_LINE = re.compile(r"^\s*(?:(?:[A-Za-z_$][\w$\[\]'\"]*\s*(?:=>?|\.=)\s*%s)|%s)?\s*(?:%s\s*(?:=>\s*%s\s*)?,?\s*)+(?:\)|\])?\s*[,;]?\s*(?://.*|#.*)?$" % (_OPEN, _OPEN, _ITEM, _ITEM))


_ASSIGN_VAL = r"(?:%s|%s\s*(?:%s\s*(?:=>\s*%s\s*)?,?\s*)+(?:\)|\]))" % (_ITEM, _OPEN, _ITEM, _ITEM)
ASSIGN_LINE = re.compile(r"^\s*(?:\$[A-Za-z_]\w*\s*(?:=|\.=)\s*%s\s*;\s*)+(?://.*|#.*)?$" % _ASSIGN_VAL)


def concat_kind(line_text: str) -> str:
    """'list' = die Zeile besteht nur aus Textstücken (Liste von Namen, z. B. in der Signaturdatei einer Firewall); 'code' = alles andere."""
    t = (line_text or "").strip()
    if t and "(" not in re.sub(r"array\s*\(", "", t, flags=re.I) and LIST_LINE.match(t):
        return "list"
    if t and "(" not in re.sub(r"array\s*\(", "", t, flags=re.I) and ASSIGN_LINE.match(t):
        return "assign"                                         # nur Zuweisungen von Textstücken an Variablen ($ev = 'e' . 'val';), kein Aufruf in dieser Zeile
    return "code"


def tool_of(path: str) -> str:
    """Name der bekannten Sicherheits-/Sicherungs-Erweiterung (aus den Listen von JED/wordpress.org), in deren Ordner die Datei liegt; sonst ''."""
    from .security_ext import load_tools
    segs = [x.lower() for x in path.split("/") if x]
    for kind in ("security", "backup"):
        data = load_tools(kind)
        for cms in ("joomla", "wordpress"):
            for t in data.get(cms, []):
                for p in t.get("paths", []):
                    p = p.lower()
                    if any(sg == p or (len(p) >= 6 and sg.startswith(p)) for sg in segs):
                        return t.get("name") or t.get("id") or ""
    return ""


@check(
    "malware_patterns", G, "Bekannte Malware-Muster (erweitert)",
    "Enthält Code Muster bekannter Hintertüren, Spam-Versender und Miner, die einfache Suchen übersehen?",
    what="Sucht in PHP-, JavaScript- und HTML-Dateien nach Mustern, die klassische Hintertür-Suchen umgehen: Funktionen, die über Rückrufe oder $_POST-Namen aufgerufen werden, zusammengesetzte Funktionsnamen, "
         "php://input, data://-Einbindung, Spam-Mailer, Datei-Dropper, Hex- und chr()-Verschleierung und Krypto-Miner. Jede Fundstelle wird mit Datei, Zeile und dem Code der Umgebung angezeigt, die Treffer-Stelle rot markiert. "
         "Hex-Zeichenfolgen werden entschlüsselt: Nur wenn ein Befehl darin steht, wird gemeldet (Binärdaten in Krypto-Bibliotheken sind harmlos). Reine Namenslisten in Dateien bekannter Sicherheits-Erweiterungen werden als Hinweis gezeigt. "
         "Ergänzt den Test 'Hintertüren (Web-Shells) in PHP-Dateien suchen'.",
    why="Moderne Schadsoftware vermeidet das Wort eval und bekannte Namen. Die Muster hier beschreiben, WIE Code ausgeführt wird, nicht wie die Datei heißt. Sicherheits-Erweiterungen enthalten dieselben Wörter, weil sie die Angriffe erkennen sollen: "
        "deshalb entscheidet nicht das Wort allein, sondern die Form (Liste oder Aufruf) und der Ort.",
    reads="Durchsucht den Text der PHP-/JS-/HTML-Dateien auf dem Server (nur lesend, nur Trefferstellen werden übertragen). Zu den Fundstellen werden je 2 Zeilen davor und danach gelesen (höchstens 30 Stellen, 300 Zeichen pro Zeile). Dauert bei großen Seiten einige Minuten.",
    load="hoch", presets=["hack"],
)
def malware_patterns(ctx, res):
    phprx = "|".join("(%s)" % s[3] for s in PHP_SIGS)
    jsrx = "|".join("(%s)" % s[3] for s in JS_SIGS)
    out = ctx.sh(FILE_SCRIPT.replace("@PRUNE@", "-path ./node_modules -o -path ./cache -o -path ./administrator/cache").replace("@PHPRX@", phprx.replace("'", "'\"'\"'")).replace("@JSRX@", jsrx.replace("'", "'\"'\"'")),
                 timeout=900, raw="treffer", raw_cap=120_000).out
    sec = split_sections(out)
    meta: Dict[str, Tuple[str, str, str]] = {s[0]: (s[1], s[2], s[4]) for s in PHP_SIGS + JS_SIGS}
    rxs: Dict[str, str] = {s[0]: s[3] for s in PHP_SIGS + JS_SIGS}
    hits: Dict[str, List[Tuple[str, int, str]]] = {}          # Muster-ID -> (Datei, Zeile, Treffer)
    for part, sigs in (("PHP", PHP_SIGS), ("JS", JS_SIGS)):
        for ln in lines_of(sec.get(part, "")):
            for sid, _sev, path, no, frag in classify(ln, sigs):
                if sid == "create_func" and vendor_tests(path):
                    continue
                hits.setdefault(sid, []).append((path, int(no), frag))
    # Umgebung (Code) zu allen Stellen holen, die später bewertet oder angezeigt werden: Zusammengesetzte Namen immer (Liste oder Aufruf?)
    want: List[Tuple[str, int]] = []
    for sid in sorted(hits, key=lambda k: 0 if k == "concat_name" else 1):
        want += [(p, n) for p, n, f in hits[sid] if sid != "hex_escapes" or hex_verdict(f) == "danger"][:12]
    context = evidence.fetch(ctx, want[: evidence.MAX_HITS]) if want else {}
    groups: Dict[Tuple[str, str], Dict[str, Any]] = {}          # (Titel-ID, Schwere) -> items/evidence/count

    def put(key, sev, path, no, frag, note="", title_override=""):
        g = groups.setdefault((key, sev), {"items": [], "ev": [], "n": 0, "title": title_override})
        g["n"] += 1
        g["items"].append("%s Zeile %s: %s" % (clean_line(path), no, trunc(clean_line(frag), 110)))
        if (path, no) in context and len(g["ev"]) < 8:
            g["ev"].append(evidence.build(path, no, context[(path, no)], hit=frag, rx=rxs.get(key.split(":")[0], ""), note=note))

    hex_stats = {"danger": 0, "text": 0, "binary": 0}
    crit_paths = {p for sid, rows in hits.items() if sid != "concat_name" and meta[sid][1] == "crit" for p, _n, _f in rows}
    for sid, rows in hits.items():
        for path, no, frag in rows:
            sev = meta[sid][1]
            if sid == "create_func" and lib_path(path):
                sev = "info"
            if sid == "hex_escapes":
                v = hex_verdict(frag)
                hex_stats[v] += 1
                if v == "danger":
                    put("hex_escapes", "crit", path, no, frag, note="entschlüsselt steht ein Befehl darin: %s" % trunc(hex_decode(frag)[0], 60))
                continue
            if sid == "concat_name":
                lines = context.get((path, no)) or []
                text = next((c["t"] for c in lines if c["n"] == no), "")
                kind = concat_kind(text) if text else "code"
                if kind in ("list", "assign"):
                    tool = tool_of(path)
                    calm = bool(tool) and path not in crit_paths             # nur ruhig, wenn die Datei sonst nichts Kritisches enthält
                    if kind == "list" or calm:
                        sv = "info" if calm else "warn"
                        put("concat_list", sv, path, no, frag, note=("%s, Datei gehört zu %s" % ("Namensliste" if kind == "list" else "Zuweisung von Namensteilen", tool)) if tool else "Namensliste")
                        groups[("concat_list", sv)]["tool"] = tool if calm else ""
                        continue
            put(sid, sev, path, no, frag)
    any_bad = False
    order = {"crit": 0, "warn": 1, "info": 2}
    for (sid, sev), g in sorted(groups.items(), key=lambda kv: (order[kv[0][1]], kv[0][0])):
        any_bad = any_bad or sev in ("crit", "warn")
        if sid == "concat_list":
            tool = g.get("tool", "")
            title = "Liste zerlegter Funktionsnamen (%d Fundstelle(n))" % g["n"]
            detail = ("Die Zeilen bestehen nur aus Textstücken (Liste oder Zuweisung an Variablen) und führen in dieser Zeile nichts aus. Sicherheits-Werkzeuge führen solche Listen, um genau diese Tricks bei Angreifern zu erkennen. "
                      + ("Die Dateien liegen im Ordner von %s (im Erweiterungsverzeichnis gelistet). Das Programm kann nicht prüfen, ob die Datei unverändert ist: Im Zweifel die Erweiterung über die Joomla-/WordPress-Aktualisierung neu installieren." % tool
                         if tool else
                         "Die Datei gehört aber zu keiner bekannten Sicherheits-Erweiterung: Prüfe, wozu die Liste dient."))
            hint = "" if sev == "info" else "Datei ansehen (nicht ausführen). Gehört sie zu keiner Erweiterung, die du kennst: sichern und löschen."
        elif sid == "hex_escapes":
            title = "Hex-Zeichenfolge mit Befehl im Klartext (%d Fundstelle(n))" % g["n"]
            detail = "Die Zeichenfolge \\x.. wurde entschlüsselt und enthält einen Befehl oder Funktionsnamen: So wird Schadcode vor einfachen Suchen versteckt."
            hint = "Datei ansehen (nicht ausführen). Gehört sie nicht zu einer Erweiterung, die du kennst: sichern und löschen, danach die Einfallslücke suchen."
        else:
            title, _s, detail = meta[sid]
            title = "%s (%d Fundstelle(n))" % (title, g["n"])
            hint = "Datei ansehen (nicht ausführen). Gehört sie nicht zu einer bekannten Erweiterung: sichern und löschen, danach die Einfallslücke suchen." if sev != "info" else ""
        res.add(sev, title, detail, g["items"][:40], hint, g["ev"])
    if hits.get("hex_escapes") and not hex_stats["danger"]:
        res.add("ok", "%d Hex-Zeichenfolgen geprüft: keine enthält einen Befehl" % sum(hex_stats.values()),
                "Die Folgen \\x.. wurden entschlüsselt: %d Binärdaten (z. B. Prüfsummen und Tabellen in Krypto-Bibliotheken wie sodium_compat oder web-auth), %d lesbarer Text ohne Befehl. Das ist normaler Programmcode, kein Schadcode." % (hex_stats["binary"], hex_stats["text"]),
                [("%s Zeile %s" % (clean_line(p), n)) for p, n, _ in hits["hex_escapes"][:8]])
    if not hits:
        res.add("ok", "Keine erweiterten Malware-Muster gefunden", "Geprüft: %d PHP-Muster und %d JavaScript-Muster." % (len(PHP_SIGS), len(JS_SIGS)))


# ============================================================================ versteckte Dateien und Strukturen
STRUCT_SCRIPT = r"""
echo '@@ROOT'; pwd -P
echo '@@DOTDIR'
find . \( @PRUNE@ \) -prune -o -type d -name '.*' ! -name . ! -name .well-known ! -name .git ! -name .svn ! -name .github -printf '%TY-%Tm-%Td\t%p\n' 2>/dev/null | head -80
echo '@@ODD'
LC_ALL=C find . \( @PRUNE@ \) -prune -o ! -name . \( -name '* *' -o -name '*[![:print:]]*' -o -name '*.' \) \( -type d -o -iname '*.php*' -o -iname '*.phtml' -o -iname '*.phar' -o -iname '*.js' -o -iname '.htaccess*' -o -iname '*.sh' -o -iname '*.pl' -o -iname '*.cgi' \) -printf '%TY-%Tm-%Td\t%y\t%p\n' 2>/dev/null \
  | grep -v -E '^[^\t]+\t[^\t]+\t\./(images|media|wp-content/uploads|templates|language)/' | head -80
echo '@@LINKS'
find . \( @PRUNE@ \) -prune -o -type l -printf '%p\t%l\n' 2>/dev/null | head -100
echo '@@SUID'
find . \( @PRUNE@ \) -prune -o -type f -perm /6000 -printf '%m\t%p\n' 2>/dev/null | head -30
echo '@@EXEC'
find . \( @PRUNE@ \) -prune -o -type f -perm /111 ! -path './cli/*' ! -path './node_modules/*' ! -path '*/bin/*' -print 2>/dev/null | head -400 | while IFS= read -r f; do
  if head -c 4 "$f" 2>/dev/null | grep -qa 'ELF'; then echo "ELF	$f"; else echo "X	$f"; fi
done | head -400
echo '@@CGI'
find . \( @PRUNE@ \) -prune -o \( -type d -name cgi-bin -o -type f \( -iname '*.pl' -o -iname '*.cgi' -o -iname '*.py' -o -iname '*.sh' -o -iname '*.rb' \) \) ! -path './cli/*' ! -path '*/vendor/*' ! -path '*/node_modules/*' ! -path './build/*' -printf '%TY-%Tm-%Td\t%y\t%p\n' 2>/dev/null | head -80
echo '@@FUTURE'
find . \( @PRUNE@ \) -prune -o -type f -newermt "@$(( $(date +%s) + 172800 ))" -printf '%TY-%Tm-%Td\t%p\n' 2>/dev/null | head -40
echo '@@ANCIENT'
find . \( @PRUNE@ \) -prune -o -type f \( -iname '*.php' -o -iname '*.phtml' \) ! -newermt '2005-01-01' -printf '%TY-%Tm-%Td\t%p\n' 2>/dev/null | head -60
"""
SAFE_LINK_TARGETS = ("/usr/", "/opt/", "/var/lib/", "/etc/alternatives")
SYSTEM_TARGET = re.compile(r"^/(etc|proc|root|sys|dev|var/log|var/run|boot)(/|$)|^/$")


def evaluate_struct(sec: Dict[str, str]) -> List[Tuple[str, str, str, List[str], str]]:
    rows: List[Tuple[str, str, str, List[str], str]] = []
    root = (lines_of(sec.get("ROOT", "")) or [""])[0].strip()

    def pairs(name, n):
        return [l.split("\t") for l in lines_of(sec.get(name, "")) if len(l.split("\t")) >= n]
    dd = pairs("DOTDIR", 2)
    if dd:
        rows.append(("warn", "%d versteckte(r) Ordner (Name beginnt mit Punkt)" % len(dd),
                     "Ordner wie .cache oder .tmp werden im Datei-Manager oft nicht angezeigt und sind ein beliebtes Versteck für Schadcode.", ["%s  (%s)" % (clean_line(p[1]), p[0]) for p in dd[:40]],
                     "Inhalt ansehen. Gehört der Ordner nicht zu einer bekannten Erweiterung: sichern und löschen."))
    odd = pairs("ODD", 3)
    if odd:
        rows.append(("warn", "%d Name(n) mit Leerzeichen, Sonderzeichen oder Punkt am Ende" % len(odd),
                     "Ordner oder Skripte wie 'images ' oder 'x.php.' sehen im Datei-Manager aus wie normale Einträge, sind es aber nicht.", ["%s  (%s)" % (clean_line(p[2]), p[0]) for p in odd[:40]],
                     "Datei/Ordner ansehen und bei Verdacht löschen."))
    bad_links, other_links = [], []
    for p in pairs("LINKS", 2):
        tgt = p[1]
        if SYSTEM_TARGET.match(tgt):
            bad_links.append("%s -> %s" % (clean_line(p[0]), clean_line(tgt)))
        elif tgt.startswith("/") and root and not tgt.startswith(root) and not tgt.startswith(SAFE_LINK_TARGETS):
            other_links.append("%s -> %s" % (clean_line(p[0]), clean_line(tgt)))
        elif tgt.count("../") >= 3:
            other_links.append("%s -> %s" % (clean_line(p[0]), clean_line(tgt)))
    if bad_links:
        rows.append(("crit", "%d symbolische Verknüpfung(en) auf Systemordner" % len(bad_links),
                     "Verknüpfungen auf /etc, /proc oder / werden für Angriffe auf andere Konten desselben Servers benutzt (Symlink-Angriff).", bad_links[:30], "Verknüpfung löschen (nur den Verweis, nicht das Ziel)."))
    if other_links:
        rows.append(("warn", "%d symbolische Verknüpfung(en) aus dem Seitenordner hinaus" % len(other_links), "Das Ziel liegt außerhalb dieser Installation. Manche Hoster und Deployments legen so etwas an, Angreifer auch.",
                     other_links[:30], "Prüfen, ob du die Verknüpfung selbst angelegt hast."))
    suid = pairs("SUID", 2)
    if suid:
        rows.append(("crit", "%d Datei(en) mit setuid/setgid-Recht" % len(suid), "Solche Dateien laufen mit den Rechten ihres Besitzers. In einem Webverzeichnis hat das nie einen guten Grund.",
                     ["%s  (Modus %s)" % (clean_line(p[1]), p[0]) for p in suid[:30]], "Recht entfernen (chmod 644) und Datei prüfen."))
    elf = [l.split("\t", 1)[1] for l in lines_of(sec.get("EXEC", "")) if l.startswith("ELF\t")]
    exe = [l.split("\t", 1)[1] for l in lines_of(sec.get("EXEC", "")) if l.startswith("X\t")]
    if elf:
        rows.append(("crit", "%d ausführbare Programme (ELF) im Webverzeichnis" % len(elf), "Kompilierte Programme gehören nicht in eine Joomla-/WordPress-Installation. Typisch sind Hintertüren, Scanner und Miner.",
                     [clean_line(x) for x in elf[:30]], "Nicht ausführen. Datei als Beweis sichern, dann löschen, und die Einfallslücke suchen."))
    if exe:
        rows.append(("info", "%d Datei(en) mit Ausführungsrecht" % len(exe), "Skripte und Webdateien brauchen kein Ausführungsrecht (755 statt 644). Das kommt von FTP-Programmen und Hostern, ist aber auch ein Merkmal abgelegter Skripte.",
                     [clean_line(x) for x in exe[:25]], "Bei Dateien, die du nicht kennst, genauer hinsehen."))
    cgi = pairs("CGI", 3)
    if cgi:
        rows.append(("warn", "%d Skript(e)/Ordner für CGI (Perl, Python, Shell)" % len(cgi), "In Joomla und WordPress gibt es keine solchen Skripte. Perl- und Shell-Hintertüren und ein 'cgi-bin' sind eine häufige Tarnung.",
                     ["%s  (%s)" % (clean_line(p[2]), p[0]) for p in cgi[:30]], "Inhalt ansehen und bei Unbekanntem löschen."))
    fut = pairs("FUTURE", 2)
    if fut:
        rows.append(("warn", "%d Datei(en) mit Änderungsdatum in der Zukunft" % len(fut), "Angreifer setzen Zeitstempel, damit Dateien nicht in der Liste 'zuletzt geändert' auftauchen. Eine falsche Uhr kommt selten vor.",
                     ["%s  (%s)" % (clean_line(p[1]), p[0]) for p in fut[:30]], "Dateien genau prüfen."))
    anc = pairs("ANCIENT", 2)
    if len(anc) >= 1:
        rows.append(("info", "%d PHP-Datei(en) mit Datum vor 2005" % len(anc), "Das kann von Archiven kommen (Datum 1980/2000). Es ist aber auch ein Trick, Hintertüren zwischen alten Dateien zu verstecken.",
                     ["%s  (%s)" % (clean_line(p[1]), p[0]) for p in anc[:25]], "Nur stichprobenartig prüfen; wichtiger ist der Abgleich mit dem Original (Kernvergleich)."))
    return rows


@check(
    "hidden_structure", G, "Versteckte Dateien und auffällige Dateistrukturen",
    "Gibt es versteckte Ordner, Verknüpfungen, ausführbare Programme, CGI-Skripte oder gefälschte Zeitstempel?",
    what="Sucht Ordner mit Punkt am Namensanfang, Namen mit Leerzeichen oder Sonderzeichen, symbolische Verknüpfungen auf Systemordner oder aus dem Seitenordner heraus, Dateien mit setuid-Recht, "
         "kompilierte Programme (ELF) und Ausführungsrechte, Perl-/Python-/Shell-/CGI-Skripte, Änderungsdaten in der Zukunft und PHP-Dateien mit sehr altem Datum.",
    why="Angreifer verstecken ihre Werkzeuge dort, wo ein Betreiber im Datei-Manager nicht hinsieht, und tarnen sie mit unauffälligen Namen und Zeitstempeln. Die Struktur verrät sie auch dann, wenn der Code selbst unauffällig aussieht.",
    reads="Nur Dateinamen, Rechte, Zeitstempel und die ersten 4 Byte ausführbarer Dateien (um Programme zu erkennen). Nichts wird verändert oder ausgeführt.",
    load="mittel", presets=["schnell", "hack"],
)
def hidden_structure(ctx, res):
    out = ctx.sh(STRUCT_SCRIPT.replace("@PRUNE@", ctx.prof["prune_find"]), timeout=300, raw="treffer").out
    rows = evaluate_struct(split_sections(out))
    for sev, title, detail, items, hint in rows:
        res.add(sev, title, detail, items, hint)
    if not [r for r in rows if r[0] in ("warn", "crit")]:
        res.add("ok", "Keine versteckten Ordner, Verknüpfungen oder auffälligen Strukturen gefunden")


# ============================================================================ .htaccess vertieft
HT_SCRIPT = r"""
echo '@@META'
find . -name .htaccess -type f -not -path './node_modules/*' 2>/dev/null | head -200 | while IFS= read -r f; do
  awk -v F="$f" 'BEGIN{b=0;mb=0;ml=0;hid=0}{ if(length($0)>ml)ml=length($0); if($0 ~ /^[ \t\r]*$/){b++; if(b>mb)mb=b}else{ if(b>=40) hid=1; b=0 } } END{printf "M\t%s\t%d\t%d\t%d\n",F,ml,mb,hid}' "$f"
  if grep -qiE 'deny from all|require all denied' "$f" 2>/dev/null; then echo "D	$f"; fi
  if grep -qiE '<files(match)?[^>]*php' "$f" 2>/dev/null && grep -qiE 'allow from all|require all granted' "$f" 2>/dev/null; then echo "A	$f"; fi
  grep -nHiE '^[[:space:]]*rewriterule[[:space:]]+[^[:space:]]+[[:space:]]+/?[^[:space:]\[]+\.php' "$f" 2>/dev/null | head -5 | sed 's/^/T	/'
  grep -nHiE '^[[:space:]]*rewritecond[[:space:]]+%\{(HTTP_COOKIE|HTTP_ACCEPT_LANGUAGE|REMOTE_ADDR)\}' "$f" 2>/dev/null | head -5 | sed 's/^/C	/'
done
"""
CODE_TOP = ("components", "plugins", "modules", "libraries", "includes", "layouts", "language", "templates", "api", "cli", "wp-admin", "wp-includes")
INDEX_TARGETS = ("index.php", "administrator/index.php", "api/index.php", "wp-app.php")


def evaluate_ht(sec: Dict[str, str]) -> List[Tuple[str, str, str, List[str], str]]:
    rows: List[Tuple[str, str, str, List[str], str]] = []
    metas, deny, allow, targets, conds = [], set(), [], [], []
    for ln in lines_of(sec.get("META", "")):
        p = ln.split("\t")
        if p[0] == "M" and len(p) >= 5:
            metas.append((p[1], int(p[2] or 0), int(p[3] or 0), p[4] == "1"))
        elif p[0] == "D" and len(p) >= 2:
            deny.add(p[1])
        elif p[0] == "A" and len(p) >= 2:
            allow.append(p[1])
        elif p[0] == "T" and len(p) >= 2:
            targets.append(p[1])
        elif p[0] == "C" and len(p) >= 2:
            conds.append(p[1])
    long_ = ["%s  (längste Zeile %d Zeichen)" % (clean_line(f), ml) for f, ml, _, _ in metas if ml > 800]
    if long_:
        rows.append(("warn", "%d .htaccess mit extrem langer Zeile" % len(long_), "Normale Regeln sind kurz. Sehr lange Zeilen verstecken Code oder Adresslisten rechts außerhalb des sichtbaren Bereichs.", long_[:20], "Datei ganz lesen (Zeilenumbruch einschalten)."))
    hid = ["%s  (bis zu %d Leerzeilen am Stück)" % (clean_line(f), mb) for f, _, mb, h in metas if h]
    if hid:
        rows.append(("crit", "%d .htaccess mit versteckten Regeln hinter Leerzeilen" % len(hid), "Nach vielen Leerzeilen folgen weitere Regeln. Im Editor scheint die Datei zu Ende zu sein, der eigentliche Schadcode steht weit unten.", hid[:20],
                     "Datei bis zum Ende lesen; im Zweifel durch die Standarddatei ersetzen."))
    where = []
    for f, *_ in metas:
        top = f.lstrip("./").split("/")[0] if "/" in f.lstrip("./") else ""
        if top in CODE_TOP and f not in deny:
            where.append(clean_line(f))
    if where:
        rows.append(("warn", "%d .htaccess in Programmordnern ohne Sperrregel" % len(where), "In components, plugins, libraries und ähnlichen Ordnern liegt normalerweise keine .htaccess, oder sie sperrt nur den Zugriff. Andere Regeln dort sind ein Warnzeichen.", where[:30],
                     "Inhalt ansehen; unbekannte Dateien löschen."))
    if allow:
        rows.append(("warn", "%d .htaccess erlauben PHP-Dateien gezielt (Allow from all)" % len(allow), "Eine Regel, die einzelne PHP-Dateien wieder freigibt, hebt oft eine Sperre auf, damit eine Hintertür erreichbar bleibt.",
                     [clean_line(x) for x in allow[:20]], "Datei ansehen; Freigabe nur behalten, wenn du sie selbst gesetzt hast."))
    tg = []
    for t in targets:
        m = re.match(r"^(.*?):(\d+):\s*rewriterule\s+\S+\s+/?([^\s\[]+\.php)", t, re.I)
        if m and m.group(3).lstrip("/") not in INDEX_TARGETS and not m.group(3).lower().startswith(("http", "%{")) and "$" not in m.group(3).split("/")[-1]:
            tg.append("%s Zeile %s: Ziel %s" % (clean_line(m.group(1)), m.group(2), clean_line(m.group(3))))
    if tg:
        rows.append(("warn", "%d Umschreibung(en) auf eine andere PHP-Datei als index.php" % len(tg), "Joomla und WordPress leiten alles an index.php. Eine Regel, die Anfragen an eine andere PHP-Datei schickt, kann eine Hintertür oder Spam-Weiche sein.", tg[:20],
                     "Zieldatei ansehen: Kennst du sie nicht, ist sie verdächtig."))
    if conds:
        rows.append(("info", "%d Bedingung(en) nach Cookie, Browsersprache oder Besucher-IP" % len(conds), "Mit solchen Bedingungen zeigen Angreifer ihren Spam nur Fremden und nie dem Betreiber (Cloaking). Es gibt auch harmlose Gründe, etwa Sprachweichen.",
                     [trunc(clean_line(c), 150) for c in conds[:15]], "Prüfen, ob du die Regel kennst."))
    return rows


@check(
    "htaccess_structure", "konfig", ".htaccess-Dateien: Aufbau und Verstecke",
    "Verstecken sich Regeln hinter Leerzeilen, in Programmordnern oder in sehr langen Zeilen?",
    what="Untersucht den Aufbau aller .htaccess-Dateien: sehr lange Zeilen, Regeln hinter vielen Leerzeilen, .htaccess in Programmordnern ohne Sperrregel, Freigaben für einzelne PHP-Dateien, Umschreibungen auf andere PHP-Dateien als index.php "
         "und Bedingungen nach Cookie, Sprache oder IP. Ergänzt den Test '.htaccess-Dateien auf Manipulation prüfen', der die einzelnen Regeln bewertet.",
    why="Eine .htaccess ist unauffällig und wird bei jedem Aufruf gelesen. Angreifer verstecken Regeln, indem sie sie weit unter dem sichtbaren Teil anhängen oder in Ordner legen, in denen niemand nachsieht.",
    reads="Nur die .htaccess-Dateien (Längen, Leerzeilen und einzelne Regelzeilen). Nichts wird verändert.",
    load="leicht", presets=["schnell", "hack"],
)
def htaccess_structure(ctx, res):
    out = ctx.sh(HT_SCRIPT, timeout=120, raw="treffer").out
    rows = evaluate_ht(split_sections(out))
    for sev, title, detail, items, hint in rows:
        res.add(sev, title, detail, items, hint)
    if not [r for r in rows if r[0] in ("warn", "crit")]:
        res.add("ok", "Keine versteckten Regeln oder auffälligen Strukturen in den .htaccess-Dateien gefunden")
