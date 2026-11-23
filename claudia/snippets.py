"""Schadcode, den man von Hand entfernen muss: Ausschnitt mit Zeilennummern, Schadstelle markiert, Orientierungszeilen drumherum.

Alles hier ist rein lesend. Das Programm entfernt solchen Code NICHT selbst, weil er mitten in sonst normalen Dateien steht
(z. B. in der index.php einer Vorlage). Es zeigt genau, WO er steht und WIE die Zeile danach aussehen soll.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

MANUAL_ITEM_RE = re.compile(r"^(?P<file>[\w@./+-]+\.(?:php\d?|phtml|inc|js|html?))\s+Zeile\s+(?P<line>\d+):")
MANUAL_CHECKS = ("entry_points", "wp_entry_points", "webshells", "js_scan", "web_source")
CONTEXT = 5                  # Orientierungszeilen davor und danach
HEAD, TAIL = 110, 90         # Anzeige langer Zeilen: Anfang und Ende bleiben sichtbar
BAD_MAX = 420                # längere Schadstellen werden in der Mitte gekürzt

MAX_SCAN = 400_000           # längere Zeilen werden nur bis hierher durchsucht (Schutz vor absichtlich gebauten Dateien)

# (Bezeichnung, Anfang, Ende). Reihenfolge = Priorität. Der Anfang ist ein einfaches Muster, das Ende wird danach mit einer einzelnen Suche gefunden.
# Das vermeidet verschachtelte Suchmuster, die bei gezielt gebauten Dateien extrem langsam werden könnten ("ReDoS").
_RX = lambda p: re.compile(p, re.I | re.S)          # noqa: E731
BAD_PATTERNS: List[Tuple[str, "re.Pattern[str]", Optional["re.Pattern[str]"]]] = [
    ("verschleiertes JavaScript (eval + fromCharCode)", _RX(r"<script[^>]{0,300}>\s{0,50}(?:var\s+\w+\s*=\s*String\s*;\s*)?[^<]{0,200}?eval\s*\("), _RX(r"</script>")),
    ("JavaScript mit fromCharCode", _RX(r"<script[^>]{0,300}>[^<]{0,200}?fromCharCode"), _RX(r"</script>")),
    ("eval auf entschlüsselten Text", _RX(r"(?:@\s*)?eval\s*\(\s*(?:base64_decode|gzinflate|gzuncompress|str_rot13|rawurldecode|urldecode)\s*\("), _RX(r"\)\s*\)\s*;?")),
    ("PHP-eval/assert", _RX(r"<\?php\s*@?\s*(?:eval|assert)\s*\("), _RX(r"\?>")),
    ("document.write(unescape(...))", _RX(r"document\s*\.\s*write\s*\(\s*unescape\s*\("), _RX(r"\)\s*\)\s*;?")),
    ("unsichtbares iframe", _RX(r"<iframe[^>]{0,300}?(?:width|height)\s*=\s*[\"']?[01]\b[^>]{0,300}>"), _RX(r"</iframe>")),
    ("fremdes Skript von außen eingebunden", _RX(r"<script[^>]{0,300}\ssrc\s*=\s*[\"']?(?:https?:)?//[^\"'\s>]{1,2000}[\"']?[^>]{0,300}>\s{0,50}</script>"), None),
    ("fremdes iframe von außen eingebunden", _RX(r"<iframe[^>]{0,300}\ssrc\s*=\s*[\"']?(?:https?:)?//[^\"'\s>]{1,2000}[\"']?[^>]{0,300}>\s{0,50}</iframe>"), None),
    ("eval(", _RX(r"\beval\s*\(.{0,600}?\)\s*;?"), None),
]


def find_bad_spans(text: str) -> List[Tuple[int, int, str]]:
    """Die verdächtigen Bereiche in 'text' (Anfang, Ende, Bezeichnung), ohne Überlappungen."""
    text = text[:MAX_SCAN]
    spans: List[Tuple[int, int, str]] = []
    for label, start_rx, end_rx in BAD_PATTERNS:
        pos = 0
        while pos <= len(text):
            m = start_rx.search(text, pos)
            if not m:
                break
            s, e = m.start(), m.end()
            if end_rx is not None:
                c = end_rx.search(text, e)
                if not c:
                    break                       # kein Ende hinter diesem Anfang: auch hinter späteren Anfängen gibt es keines
                e = c.end()
            pos = max(e, s + 1)
            if any(s < b and a < e for a, b, _ in spans):
                continue
            spans.append((s, e, label))
    spans.sort()
    return spans


def remove_spans(text: str, spans: List[Tuple[int, int, str]]) -> str:
    out, pos = [], 0
    for s, e, _ in spans:
        out.append(text[pos:s])
        pos = e
    out.append(text[pos:])
    return "".join(out)


def _clip(t: str, keep_head: int, keep_tail: int) -> List[Dict[str, Any]]:
    if len(t) <= keep_head + keep_tail + 20:
        return [{"k": "ok", "s": t}] if t else []
    return [{"k": "ok", "s": t[:keep_head]}, {"k": "gap", "s": " … [%d Zeichen ausgeblendet] … " % (len(t) - keep_head - keep_tail)}, {"k": "ok", "s": t[-keep_tail:]}]


def segments(line: str, spans: List[Tuple[int, int, str]]) -> List[Dict[str, Any]]:
    """Zeile in Anzeige-Stücke: normal (ok), Schadstelle (bad), ausgeblendet (gap). Lange Zeilen werden gekürzt, die Schadstelle bleibt erkennbar."""
    if len(line) <= 260 and not spans:
        return [{"k": "ok", "s": line}]
    segs: List[Dict[str, Any]] = []
    pos = 0
    for i, (s, e, label) in enumerate(spans):
        before = line[pos:s]
        segs += _clip(before, HEAD if i == 0 else 40, 40 if i < len(spans) else TAIL)
        bad = line[s:e]
        if len(bad) > BAD_MAX:
            segs += [{"k": "bad", "s": bad[:300], "label": label}, {"k": "gap", "s": " … [%d Zeichen der Schadstelle ausgeblendet] … " % (len(bad) - 360), "bad": True},
                     {"k": "bad", "s": bad[-60:], "label": label}]
        else:
            segs.append({"k": "bad", "s": bad, "label": label})
        pos = e
    segs += _clip(line[pos:], 40, TAIL) if spans else _clip(line, HEAD * 2, TAIL)
    return segs


def build_excerpt(lines: List[str], first_no: int, target: int, total: int = 0) -> Dict[str, Any]:
    """lines = die gelesenen Zeilen ab Zeilennummer first_no. Rückgabe: Anzeigedaten für die Oberfläche."""
    rows: List[Dict[str, Any]] = []
    fixed_line = ""
    spans_found: List[Tuple[int, int, str]] = []
    for i, ln in enumerate(lines):
        n = first_no + i
        if n == target:
            spans_found = find_bad_spans(ln)
            fixed_line = remove_spans(ln, spans_found) if spans_found else ""
            rows.append({"n": n, "role": "ziel", "segs": segments(ln, spans_found if spans_found else [(0, len(ln), "ganze Zeile verdächtig")]), "len": len(ln)})
        else:
            rows.append({"n": n, "role": "kontext", "segs": segments(ln, []), "len": len(ln)})
    found = bool(spans_found)
    how = ""
    if found:
        labels = ", ".join(dict.fromkeys(l for _, _, l in spans_found))
        how = ("In Zeile %d den rot markierten Teil löschen (%s). Alles andere in der Zeile bleibt stehen. Darunter steht in Grün, wie die Zeile danach aussehen soll. "
               "Die Zeilen davor und danach (grau) bleiben unverändert und dienen zur Orientierung." % (target, labels))
        if "fremdes" in labels:
            how += " Achtung: Löschen darfst du nur Adressen, die du nicht kennst. Ein selbst eingebundener Dienst (z. B. Statistik, Karte) gehört dir und bleibt stehen."
    else:
        how = ("Das Programm konnte die Schadstelle in Zeile %d nicht genau eingrenzen. Die ganze Zeile ist markiert. Sieh sie dir im Editor an und frage im Zweifel "
               "Claude oder einen Spezialisten." % target)
    return {"rows": rows, "line": target, "found": found, "total": total, "how": how, "fixed_line": fixed_line,
            "fixed_segs": segments(fixed_line, []) if found else [], "removed_chars": sum(e - s for s, e, _ in spans_found)}


def manual_targets(results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Fundstellen aus den Befunden, die von Hand bereinigt werden müssen: [{file, line, check, title}]"""
    out: List[Dict[str, Any]] = []
    seen = set()
    for r in results or []:
        if r.get("id") not in MANUAL_CHECKS:
            continue
        for f in r.get("findings", []):
            if f.get("sev") not in ("warn", "crit"):
                continue
            for it in f.get("items", []) or []:
                m = MANUAL_ITEM_RE.match(it) if isinstance(it, str) else None
                if not m:
                    continue
                path = m.group("file").lstrip("./")
                key = (path, int(m.group("line")))
                if key in seen or ".." in path.split("/") or path.startswith("/") or path.startswith(("tmp/", "images/tmp/")):
                    continue          # Temp-Ordner räumt die Aktion 'Temp-Ordner leeren' ab
                seen.add(key)
                out.append({"file": path, "line": int(m.group("line")), "check": r.get("id"), "title": f.get("title", "")})
    return out[:20]


def read_script(path: str, target: int) -> str:
    """Shell-Skript: liest die Zeilen um 'target' herum (nur lesend). Gibt '@@TOTAL' und '@@LINES' aus."""
    from .util import sq
    a, b = max(1, target - CONTEXT), target + CONTEXT
    return ("[ -f %s ] && [ ! -L %s ] || { echo 'CLAUDIA_NO_FILE'; exit 3; }\n"
            "echo '@@TOTAL'; wc -l < %s\n"
            "echo '@@LINES'; sed -n '%d,%dp' -- %s | head -c 600000\n" % (sq(path), sq(path), sq(path), a, b, sq(path)))


def parse_read(out: str, target: int) -> Optional[Tuple[List[str], int, int]]:
    from .util import split_sections
    if "CLAUDIA_NO_FILE" in out:
        return None
    sec = split_sections(out)
    try:
        total = int((sec.get("TOTAL", "0") or "0").strip().split()[0])
    except (ValueError, IndexError):
        total = 0
    body = sec.get("LINES", "")
    lines = body.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    return lines, max(1, target - CONTEXT), total


# ------------------------------------------------------------------ Abgleich mit dem Original
ORIGINAL_BASE = "https://raw.githubusercontent.com/joomla/joomla-cms"
_CORE_ROOTS = ("administrator/", "api/", "cli/", "components/", "includes/", "language/", "layouts/", "libraries/", "modules/", "plugins/", "templates/", "media/")
_CORE_TEMPLATES = ("templates/cassiopeia/", "templates/system/")


def core_candidate(path: str) -> bool:
    """Kann diese Datei zum offiziellen Joomla gehören? (Dateien von Drittanbietern haben kein Original auf GitHub.)"""
    p = path.lstrip("./")
    if p in ("index.php", "htaccess.txt", "web.config.txt", "robots.txt.dist"):
        return True
    if p.startswith("templates/") and not p.startswith(_CORE_TEMPLATES):
        return False
    return p.startswith(_CORE_ROOTS) and p.split(".")[-1].lower() in ("php", "js", "html", "xml", "ini", "css")


ORIGINAL_BASE_WP = "https://raw.githubusercontent.com/WordPress/WordPress"


def core_candidate_wp(path: str) -> bool:
    """Kann diese Datei zum offiziellen WordPress gehören? (wp-content mit Plugins und Themes hat kein Original, außer den mitgelieferten.)"""
    p = path.lstrip("./")
    if p.startswith(("wp-admin/", "wp-includes/")):
        return p.split(".")[-1].lower() in ("php", "js", "css", "html", "json")
    if "/" not in p:
        return bool(re.match(r"^(wp-[\w-]+|index|xmlrpc)\.php\Z", p))
    return bool(re.match(r"^wp-content/themes/twenty[\w-]+/", p) or p.startswith("wp-content/plugins/akismet/"))


def original_url(version: str, path: str, base: str = ORIGINAL_BASE) -> str:
    return "%s/%s/%s" % (base.rstrip("/"), version.strip(), path.lstrip("./"))


def compare_original(window: List[str], first_no: int, target: int, orig_lines: List[str], fixed_line: str) -> Dict[str, Any]:
    """Ordnet die gelesenen Zeilen (window ab first_no) dem Original zu und liefert die Originalzeile zu 'target'.

    status: identisch (Zeile nach dem Entfernen == Original) | abweichend (Originalzeile siehe 'line') | eingefuegt (im Original gibt es die Zeile nicht)
    | nicht_zuordenbar (zu wenig Übereinstimmung, Datei wohl eine andere Version oder stark verändert)."""
    idx: Dict[str, List[int]] = {}
    for i, ln in enumerate(orig_lines):
        t = ln.strip()
        if len(t) >= 4:
            idx.setdefault(t, []).append(i)

    def offset(side: str) -> Tuple[Optional[int], int]:
        votes: Dict[int, int] = {}
        for k, ln in enumerate(window):
            n = first_no + k
            if n == target or (side == "before" and n > target) or (side == "after" and n < target):
                continue
            for oi in idx.get(ln.strip(), [])[:60]:
                votes[oi - (n - 1)] = votes.get(oi - (n - 1), 0) + 1
        if not votes:
            return None, 0
        off, v = max(votes.items(), key=lambda kv: kv[1])
        return off, v

    off_b, vb = offset("before")
    off_a, va = offset("after")
    if (off_b is None or vb < 1) and (off_a is None or va < 1):
        return {"status": "nicht_zuordenbar"}
    if off_b is not None and off_a is not None and vb >= 1 and va >= 1 and off_a < off_b:
        return {"status": "eingefuegt", "count": off_b - off_a}
    off = off_b if (off_b is not None and vb >= 1 and (va < 1 or vb >= va)) else off_a
    oi = target - 1 + (off or 0)
    if off is None or oi < 0 or oi >= len(orig_lines):
        return {"status": "nicht_zuordenbar"}
    line = orig_lines[oi]
    same = bool(fixed_line) and fixed_line.strip() == line.strip()
    return {"status": "identisch" if same else "abweichend", "line": line, "n": oi + 1}
