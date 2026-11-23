"""Fundstellen mit Code: liest zu Treffern ein paar Zeilen Umgebung (nur lesend) und markiert die Treffer-Stelle für die Anzeige."""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

from .util import clean_line, digits

MAX_HITS = 30           # so viele Fundstellen werden höchstens mit Code gezeigt
WIDTH = 300             # Zeichen pro Codezeile
SCRIPT = r"""
while IFS="$(printf '\t')" read -r l f; do
  case "$f" in ./*) ;; *) continue;; esac
  [ -f "$f" ] && [ ! -L "$f" ] || continue
  a=$((l-@B@)); [ "$a" -lt 1 ] && a=1; b=$((l+@A@))
  printf '@@HIT\t%s\t%s\n' "$l" "$f"
  sed -n "${a},${b}p;${b}q" -- "$f" 2>/dev/null | awk -v o="$a" '{printf "%d\t%s\n", o+NR-1, substr($0,1,@W@)}'
done
"""


def safe_hit(path: str, line: Any) -> bool:
    return isinstance(path, str) and path.startswith("./") and "\n" not in path and "\0" not in path and "\t" not in path and len(path) < 400 and digits(str(line)) and 0 < int(line) < 10_000_000


def fetch(ctx, hits: List[Tuple[str, int]], before: int = 2, after: int = 2, width: int = WIDTH) -> Dict[Tuple[str, int], List[Dict[str, Any]]]:
    """hits = [(./Datei, Zeile)]. Rückgabe: {(Datei, Zeile): [{n, t}]}. Ein einziger Server-Aufruf; nichts wird verändert."""
    todo = [(p, int(n)) for p, n in dict.fromkeys(hits) if safe_hit(p, n)][:MAX_HITS]
    if not todo:
        return {}
    payload = "".join("%d\t%s\n" % (n, p) for p, n in todo)
    script = SCRIPT.replace("@B@", str(before)).replace("@A@", str(after)).replace("@W@", str(width))
    out = ctx.sh(script, timeout=90, stdin=payload).out
    res: Dict[Tuple[str, int], List[Dict[str, Any]]] = {}
    cur: Optional[Tuple[str, int]] = None
    for ln in out.split("\n"):
        if ln.startswith("@@HIT\t"):
            parts = ln.split("\t", 2)
            if len(parts) == 3 and digits(parts[1]):
                cur = (parts[2], int(parts[1]))
                res[cur] = []
            continue
        if cur is not None and "\t" in ln:
            n, t = ln.split("\t", 1)
            if digits(n):
                res[cur].append({"n": int(n), "t": clean_line(t.rstrip("\r"))})
    return res


def span(text: str, hit: str = "", rx: str = "") -> Optional[List[int]]:
    """Stelle des Treffers in der Zeile: erst als Text, dann als Muster."""
    if hit:
        i = text.find(hit)
        if i >= 0:
            return [i, i + len(hit)]
    if rx:
        try:
            m = re.search(rx.replace("[[:space:]]", r"\s"), text, re.I)
        except re.error:
            m = None
        if m and m.end() > m.start():
            return [m.start(), m.end()]
    return None


def build(path: str, line: int, ctx_lines: List[Dict[str, Any]], hit: str = "", rx: str = "", note: str = "") -> Dict[str, Any]:
    """Eine Fundstelle: Datei, Zeile, Code der Umgebung; in der Treffer-Zeile ist die Stelle markiert (hit = [von, bis])."""
    code = []
    for c in ctx_lines:
        sp = span(c["t"], hit, rx) if c["n"] == line else None
        code.append({"n": c["n"], "t": c["t"], "hit": sp})
    if not code:
        code = [{"n": line, "t": hit, "hit": [0, len(hit)] if hit else None}]
    return {"file": clean_line(path), "line": line, "note": note, "code": code}


def render_txt(ev: Dict[str, Any]) -> List[str]:
    """Textform für den Bericht: Treffer-Zeile mit '>>' und der Stelle zwischen '[[' und ']]'."""
    head = ("%s, Zeile %s" % (ev["file"], ev["line"])) if ev.get("line") else ev["file"]
    out = ["%s%s" % (head, ("  (%s)" % ev["note"]) if ev.get("note") else "")]
    for c in ev["code"]:
        t = c["t"]
        if c.get("hit"):
            a, b = c["hit"]
            t = t[:a] + "[[" + t[a:b] + "]]" + t[b:]
        out.append("%s %5d | %s" % (">>" if c.get("hit") else "  ", c["n"], t))
    return out
