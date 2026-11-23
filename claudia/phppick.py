"""Auswahl eines funktionierenden PHP-Programms auf dem Server.

Auf manchen Hostern ist 'php' nur ein Auswahlprogramm ("Multiple PHP versions found: ..."), das nichts ausführt.
Deshalb wird jeder Kandidat zuerst mit "php -v" geprüft; nur eine echte Versionszeile ("PHP 8.3.6 ...") zählt.
"""
from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List

from .util import sq, vtuple

WRAPPER_RE = re.compile(r"multiple php versions|select.*php version|choose.*php version", re.I)


def is_wrapper(text: str) -> bool:
    return bool(WRAPPER_RE.search(text or ""))


def candidate_names(web_version: str, cands: Iterable[Dict[str, Any]]) -> List[str]:
    """Reihenfolge: passend zur Webseiten-Version, dann 'php', dann alle bekannten Programme mit Version (neueste zuerst)."""
    names: List[str] = []
    m = re.match(r"(\d+)\.(\d+)", str(web_version or ""))
    if m:
        a, b = m.groups()
        names += ["php%s.%s" % (a, b), "php-%s.%s" % (a, b), "php%s%s" % (a, b)]
    names.append("php")
    known = [c for c in cands if c.get("version") and re.match(r"^[A-Za-z0-9._/+-]+\Z", str(c.get("name", "")))]
    known.sort(key=lambda c: vtuple(str(c["version"]).replace("PHP ", "")), reverse=True)
    names += [c["name"] for c in known]
    return list(dict.fromkeys(names))


def snippet(web_version: str, cands: Iterable[Dict[str, Any]]) -> str:
    """Shell-Code, der P auf das erste Programm setzt, das eine echte PHP-Version meldet (sonst bleibt P leer)."""
    names = " ".join(sq(n) for n in candidate_names(web_version, cands))
    return ('P=""\n'
            'for n in %s; do\n'
            '  b=$(command -v "$n" 2>/dev/null); [ -n "$b" ] || continue\n'
            '  v=$(timeout 10 "$b" -v </dev/null 2>/dev/null | head -1)\n'
            '  case "$v" in "PHP "[0-9]*.[0-9]*) P="$b"; break;; esac\n'
            'done\n' % names)
