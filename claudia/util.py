"""Kleine Hilfsfunktionen (Quoting, Versionen, Maskierung, Hosts)."""
from __future__ import annotations

import re
import shlex
import xml.etree.ElementTree as ET
from typing import Iterable, List, Optional, Tuple


def sq(value: str) -> str:
    """Shell-sicheres Quoting für Linux-Befehle auf dem Server."""
    return shlex.quote(value)


def parse_xml(text, max_len: int = 3_000_000) -> Optional[ET.Element]:
    """Fremdes XML (Update-Listen, Manifeste) sicher lesen: einheitlich für alle Stellen.
    Kein Text, zu lang, mit DOCTYPE/ENTITY (Entity-Bombe) oder kaputt -> None, nie eine Ausnahme."""
    if isinstance(text, (bytes, bytearray)):
        try:
            text = bytes(text).decode("utf-8")
        except UnicodeDecodeError:
            return None
    if not isinstance(text, str) or not text.strip() or len(text) > max_len:
        return None
    if re.search(r"<!\s*(DOCTYPE|ENTITY)", text, re.I):
        return None
    try:
        return ET.fromstring(text)
    except (ET.ParseError, ValueError, RecursionError):
        return None


def digits(value) -> bool:
    """True nur für echte ASCII-Ziffern (str.isdigit() lässt auch '²' oder arabische Ziffern durch, int() scheitert dann)."""
    return isinstance(value, str) and bool(value) and value.isascii() and value.isdigit()


# ---------------------------------------------------------------- Versionen
def vtuple(version: str) -> Tuple[int, ...]:
    """'2.9.99.7' -> (2, 9, 99, 7). Nicht-numerische Zusätze werden ignoriert."""
    if not version:
        return tuple()
    m = re.match(r"\s*[vV]?(\d+(?:\.\d+)*)", str(version))
    if not m:
        return tuple()
    return tuple(int(p) for p in m.group(1).split(".")[:6])


def vcmp(a: str, b: str) -> int:
    """-1 / 0 / 1 wie cmp. Fehlende Stellen zählen als 0."""
    ta, tb = vtuple(a), vtuple(b)
    n = max(len(ta), len(tb))
    ta = ta + (0,) * (n - len(ta))
    tb = tb + (0,) * (n - len(tb))
    return (ta > tb) - (ta < tb)


# ---------------------------------------------------------------- Maskierung
# Der Wert ist auf 4096 Zeichen begrenzt: Ohne Grenze braucht eine Datei mit vielen nicht geschlossenen Anführungszeichen quadratische Zeit (Stress-Fund der Code-Prüfung).
_SECRET_KEYS = (
    "password", "secret", "smtppass", "ftp_pass", "proxy_pass",
    "user", "smtpuser", "ftp_user", "proxy_user", "ftp_root",
)
_SECRET_RE = re.compile(
    r"(public\s+\$(?:%s)\s*=\s*)(['\"])(.{0,4096}?)\2(\s*;)" % "|".join(_SECRET_KEYS),
    re.IGNORECASE | re.DOTALL,
)


_WP_SECRET_RE = re.compile(
    r"""(define\s*\(\s*['"](?:DB_PASSWORD|DB_USER|DB_HOST|AUTH_KEY|SECURE_AUTH_KEY|LOGGED_IN_KEY|NONCE_KEY|AUTH_SALT|SECURE_AUTH_SALT|"""
    r"""LOGGED_IN_SALT|NONCE_SALT|[A-Z_]*(?:PASSWORD|SECRET|API_KEY|TOKEN)[A-Z_]*)['"]\s*,\s*)(['"])(.{0,4096}?)\2(\s*\))""",
    re.IGNORECASE | re.DOTALL,
)


def mask_secrets(text: str) -> str:
    """Ersetzt Passwörter/Geheimnisse in einer configuration.php (Joomla) bzw. wp-config.php (WordPress) durch ***."""
    def repl(m):
        val = m.group(3)
        return "%s%s%s%s%s" % (m.group(1), m.group(2), "***" if val else "", m.group(2), m.group(4))
    return _WP_SECRET_RE.sub(repl, _SECRET_RE.sub(repl, text))


_IPV4_RE = re.compile(r"(?<![\d.])(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?![\d.])")
_IPV6_CAND = re.compile(r"(?<![0-9A-Fa-f:])[0-9A-Fa-f:]{3,39}(?![0-9A-Fa-f:])")


def mask_ip(text: str) -> str:
    """Kürzt IP-Adressen (a.b.c.x) - NUR auf Text anwenden, der IP-Adressen enthält (Logs, Aktivitätsprotokoll).

    Versionsnummern wie 2.9.99.7 sehen wie IPv4-Adressen aus und würden sonst verfälscht.
    """
    import ipaddress

    def v4(m):
        if all(int(g) <= 255 for g in m.groups()):
            return "%s.%s.%s.x" % (m.group(1), m.group(2), m.group(3))
        return m.group(0)

    text = _IPV4_RE.sub(v4, text)

    def v6(m):
        cand = m.group(0)
        if ":" not in cand or cand.count(":") < 2:
            return cand
        try:
            ipaddress.IPv6Address(cand)
        except ValueError:
            return cand
        if "::" not in cand and cand.count(":") != 7:
            return cand
        parts = [p for p in cand.split(":") if p != ""]
        return ":".join(parts[:3]) + "::x"
    return _IPV6_CAND.sub(v6, text)


# ---------------------------------------------------------------- Hosts / URLs
_URL_RE = re.compile(r"""(?:https?:)?//([A-Za-z0-9][A-Za-z0-9.\-]{1,100}\.[A-Za-z]{2,24})(?::\d+)?(?=[/\s"'<>)\\?#]|$)""")


def extract_hosts(text: str) -> List[str]:
    """Alle Hostnamen aus URLs im Text (klein geschrieben, ohne Duplikate, Reihenfolge erhalten)."""
    seen, out = set(), []
    for m in _URL_RE.finditer(text or ""):
        h = m.group(1).lower().rstrip(".")
        if h not in seen:
            seen.add(h)
            out.append(h)
    return out


def host_allowed(host: str, allow: Iterable[str]) -> bool:
    host = host.lower()
    for a in allow:
        a = a.strip().lower().lstrip("*.")
        if a and (host == a or host.endswith("." + a)):
            return True
    return False


def split_allow(text: str) -> List[str]:
    return [x.strip().lower() for x in re.split(r"[\s,;]+", text or "") if x.strip()]


# ---------------------------------------------------------------- Formatierung
def human_size(n: float) -> str:
    n = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return ("%d %s" % (n, unit)) if unit == "B" else ("%.1f %s" % (n, unit))
        n /= 1024.0
    return "%.1f GB" % n


def trunc(text: str, n: int = 200) -> str:
    text = (text or "").replace("\r", " ")
    return text if len(text) <= n else text[: n - 1] + "…"


def clean_line(text: str) -> str:
    """Steuerzeichen entfernen, damit nichts die Berichte verfälscht."""
    return re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "?", text or "")


def safe_name(text: str, fallback: str = "seite") -> str:
    s = re.sub(r"[^A-Za-z0-9._-]+", "_", text or "").strip("._")
    return s[:60] or fallback


# ---------------------------------------------------------------- mysql --batch
def mysql_unescape(field: str) -> Optional[str]:
    """mysql --batch maskiert \\n \\t \\\\ \\0 und gibt NULL als 'NULL' aus."""
    if field == "NULL":
        return None
    if "\\" not in field:
        return field
    out, i = [], 0
    mapping = {"n": "\n", "t": "\t", "\\": "\\", "0": "\0", "r": "\r"}
    while i < len(field):
        c = field[i]
        if c == "\\" and i + 1 < len(field):
            out.append(mapping.get(field[i + 1], field[i + 1]))
            i += 2
        else:
            out.append(c)
            i += 1
    return "".join(out)


# ---------------------------------------------------------------- Ausgabe in Abschnitte teilen
def split_sections(text: str, marker: str = "@@") -> dict:
    """Teilt eine Ausgabe in Abschnitte, die mit '@@NAME' beginnen. Liefert {name: text}."""
    sections: dict = {}
    cur, buf = None, []
    for line in (text or "").splitlines():
        if line.startswith(marker) and re.match(r"^@@[A-Z0-9_]+\s*\Z", line):
            if cur is not None:
                sections[cur] = "\n".join(buf)
            cur, buf = line[2:].strip(), []
        elif cur is not None:
            buf.append(line)
    if cur is not None:
        sections[cur] = "\n".join(buf)
    return sections


def lines_of(section: str) -> List[str]:
    return [l for l in (section or "").splitlines() if l.strip()]


def atomic_write(path: str, text: str) -> None:
    """Schreibt erst in eine Nebendatei im selben Ordner und ersetzt dann die Zieldatei in einem Schritt: ein Abbruch mitten im Schreiben lässt keine halbe Datei zurück."""
    import os
    import tempfile
    d = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=d)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
        os.replace(tmp, path)
    except OSError:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise
