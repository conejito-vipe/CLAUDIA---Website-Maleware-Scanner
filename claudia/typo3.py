"""TYPO3 (seit 2.10.0): Version, Einstellungsdatei, Erweiterungs-Kennzeichen und Sicherheitsmeldungen lesen. Reine Funktionen ohne Serverzugriff (mit Beispieltexten prüfbar).

Unterstützt werden klassische Installationen (Ordner typo3, typo3conf) und Composer-Installationen (Ordner config, vendor, public). Maßgeblich ist TYPO3 11 und neuer;
ältere Versionen werden erkannt und als nicht mehr unterstützt gemeldet.
Es werden nie Passwörter, Schlüssel oder Hashes ausgegeben; die Einstellungsdatei wird nur gelesen und nie ausgeführt (kein PHP, nur Textauswertung)."""
from __future__ import annotations

import json
import re
import time
from typing import Any, Dict, List, Optional, Tuple

from . import drupal

# ------------------------------------------------------------------ Orte (relativ zum Ordner der Seite; bei public/ als Ordner eine Ebene höher)
VERSION_FILES = ("vendor/typo3/cms-core/Classes/Information/Typo3Version.php", "../vendor/typo3/cms-core/Classes/Information/Typo3Version.php",
                 "typo3/sysext/core/Classes/Information/Typo3Version.php", "typo3_src/typo3/sysext/core/Classes/Information/Typo3Version.php")
OLD_VERSION_FILE = "typo3/sysext/core/Classes/Core/SystemEnvironmentBuilder.php"       # TYPO3 6.2 bis 8.7: define('TYPO3_version', ...)
CONFIG_FILES = ("config/system/settings.php", "../config/system/settings.php", "typo3conf/system/settings.php", "typo3conf/LocalConfiguration.php")
ADDITIONAL_FILES = ("config/system/additional.php", "../config/system/additional.php", "typo3conf/system/additional.php", "typo3conf/AdditionalConfiguration.php")
INSTALL_TOOL_FILES = ("var/transient/ENABLE_INSTALL_TOOL", "../var/transient/ENABLE_INSTALL_TOOL", "typo3conf/ENABLE_INSTALL_TOOL", "../typo3conf/ENABLE_INSTALL_TOOL")

VERSION_NEW = re.compile(r"\bVERSION\s*=\s*['\"]([0-9][0-9A-Za-z.\-]*)['\"]")
VERSION_OLD = re.compile(r"define\(\s*['\"]TYPO3_version['\"]\s*,\s*['\"]([0-9][0-9A-Za-z.\-]*)['\"]")

# Laufzeiten der Hauptversionen (Ende der kostenlosen Sicherheitsupdates, Ende des kostenpflichtigen ELTS-Zusatzes). Stand: 2026-11, Quelle: TYPO3-Support-Übersicht.
# Fehlt eine Hauptversion hier und ist sie älter als die älteste, gilt sie als beendet; ist sie neuer, ist sie unbekannt (keine Aussage).
LIFECYCLE: Dict[int, Tuple[str, str]] = {
    11: ("2024-10-31", "2027-10-31"),
    12: ("2026-04-30", "2029-04-30"),
    13: ("2027-12-31", "2030-12-31"),
    14: ("2029-06-30", "2032-06-30"),
}
LIFECYCLE_ASOF = "2026-11"


def parse_typo3_version(new_php: str, old_php: str = "") -> str:
    """Version aus Typo3Version.php (ab TYPO3 9/10) oder aus der Konstante TYPO3_version (ältere Versionen); leer, wenn nicht erkannt."""
    m = VERSION_NEW.search(new_php or "")
    if m:
        return m.group(1)
    m = VERSION_OLD.search(old_php or "") or VERSION_OLD.search(new_php or "")
    return m.group(1) if m else ""


major = drupal.major


def version_key(version: str) -> Tuple[int, ...]:
    """Sortierschlüssel mit bis zu vier Zahlen ('6.6.10.0' -> (6, 6, 10, 0, 1)); Vorabversionen (-rc1) zählen kleiner. Für Shopware und PrestaShop (vierteilige Versionen)."""
    m = re.match(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.(\d+))?(-[A-Za-z0-9.]+)?", norm_version(version))
    if not m:
        return (0, 0, 0, 0, 0)
    return (int(m.group(1)), int(m.group(2) or 0), int(m.group(3) or 0), int(m.group(4) or 0), 0 if m.group(5) else 1)


def _day(s: str) -> float:
    return time.mktime(time.strptime(s, "%Y-%m-%d"))


def lifecycle(version: str, now: Optional[float] = None) -> Dict[str, Any]:
    """Stand der Unterstützung einer Hauptversion. state: 'supported' (kostenlose Sicherheitsupdates), 'elts' (nur noch kostenpflichtig), 'ended' (gar nicht mehr), 'unknown'."""
    now = now or time.time()
    mj = major(version)
    if not mj:
        return {"state": "unknown", "major": 0, "free_until": "", "elts_until": "", "days_left": None}
    if mj not in LIFECYCLE:
        return {"state": "ended" if mj < min(LIFECYCLE) else "unknown", "major": mj, "free_until": "", "elts_until": "", "days_left": None}
    free, elts = LIFECYCLE[mj]
    if now <= _day(free) + 86400:
        return {"state": "supported", "major": mj, "free_until": free, "elts_until": elts, "days_left": int((_day(free) + 86400 - now) // 86400)}
    if now <= _day(elts) + 86400:
        return {"state": "elts", "major": mj, "free_until": free, "elts_until": elts, "days_left": None}
    return {"state": "ended", "major": mj, "free_until": free, "elts_until": elts, "days_left": None}


# ------------------------------------------------------------------ PHP-Arrays (Einstellungsdatei, ext_emconf.php) als Text lesen
class Expr(str):
    """Ein Ausdruck, der kein einfacher Wert ist (Funktionsaufruf, Konstante ...). Er wird nie ausgewertet."""


class _Reader:
    MAX_DEPTH = 40

    def __init__(self, text: str) -> None:
        self.s = text
        self.i = 0
        self.n = len(text)

    def ws(self) -> None:
        while self.i < self.n and self.s[self.i] in " \t\r\n":
            self.i += 1

    def string(self) -> str:
        q = self.s[self.i]
        self.i += 1
        out: List[str] = []
        while self.i < self.n:
            c = self.s[self.i]
            if c == "\\" and self.i + 1 < self.n:
                nxt = self.s[self.i + 1]
                if q == "'":
                    out.append(nxt if nxt in "\\'" else "\\" + nxt)
                else:
                    out.append({"n": "\n", "t": "\t", "r": "\r"}.get(nxt, nxt))
                self.i += 2
                continue
            if c == q:
                self.i += 1
                return "".join(out)
            out.append(c)
            self.i += 1
        return "".join(out)

    def skip_expr(self) -> Expr:
        """Bis zum nächsten Komma oder zur schließenden Klammer dieser Ebene lesen (Zeichenketten und Klammern werden beachtet)."""
        start = self.i
        depth = 0
        while self.i < self.n:
            c = self.s[self.i]
            if c in "'\"":
                self.string()
                continue
            if c in "([{":
                depth += 1
            elif c in ")]}":
                if depth == 0:
                    break
                depth -= 1
            elif c == "," and depth == 0:
                break
            self.i += 1
        return Expr(self.s[start:self.i].strip()[:200])

    def value(self, depth: int = 0) -> Any:
        self.ws()
        if self.i >= self.n or depth > self.MAX_DEPTH:
            return Expr("")
        c = self.s[self.i]
        if c in "'\"":
            v = self.string()
            self.ws()
            if self.s.startswith(".", self.i):          # Verkettung ('a' . $b): kein einfacher Wert
                return Expr(v + self.skip_expr())
            return v
        if c == "[":
            self.i += 1
            return self.array("]", depth + 1)
        m = re.match(r"array\s*\(", self.s[self.i:self.i + 12], re.I)
        if m:
            self.i += m.end()
            return self.array(")", depth + 1)
        m = re.match(r"-?\d+(?:\.\d+)?(?![\w.])", self.s[self.i:self.i + 40])
        if m:
            self.i += m.end()
            t = m.group(0)
            return float(t) if "." in t else int(t)
        m = re.match(r"(true|false|null)(?![\w(])", self.s[self.i:self.i + 8], re.I)
        if m:
            self.i += m.end()
            return {"true": True, "false": False, "null": None}[m.group(1).lower()]
        return self.skip_expr()

    def array(self, close: str, depth: int) -> Dict[Any, Any]:
        out: Dict[Any, Any] = {}
        auto = 0
        while True:
            self.ws()
            if self.i >= self.n:
                return out
            if self.s[self.i] == close:
                self.i += 1
                return out
            if self.s[self.i] == ",":
                self.i += 1
                continue
            first = self.value(depth)
            self.ws()
            if self.s.startswith("=>", self.i):
                self.i += 2
                val = self.value(depth)
                key = first if isinstance(first, (str, int)) else str(first)
            else:
                val, key = first, auto
            if isinstance(key, int):
                auto = max(auto, key + 1)
            out[key] = val
            self.ws()
            if self.i < self.n and self.s[self.i] not in ",)]":
                self.skip_expr()                      # Unbekanntes hinter dem Wert überspringen, damit die Ebene nicht verrutscht


def strip_comments(text: str) -> str:
    """Kommentare entfernen, ohne Zeichenketten anzutasten (die Auswertung kennt keine Kommentare)."""
    out: List[str] = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c in "'\"":
            j = i + 1
            while j < n and text[j] != c:
                j += 2 if text[j] == "\\" else 1
            out.append(text[i:j + 1])
            i = j + 1
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            out.append("\n" * text.count("\n", i, j))
            i = j
        elif text.startswith("//", i) or c == "#" and not text.startswith("#[", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
        else:
            out.append(c)
            i += 1
    return "".join(out)


def parse_php_array(text: str, after: str = r"\breturn\b") -> Optional[Dict[Any, Any]]:
    """Das erste Array hinter 'return' (oder hinter dem Muster 'after') lesen; None, wenn keines gefunden wird."""
    code = strip_comments((text or "")[:400_000])
    m = re.search(after, code)
    if not m:
        return None
    r = _Reader(code)
    r.i = m.end()
    r.ws()
    if r.i < r.n and code[r.i] == "=":
        r.i += 1
    v = r.value()
    return v if isinstance(v, dict) else None


# ------------------------------------------------------------------ Einstellungsdatei (settings.php / LocalConfiguration.php)
DANGEROUS = re.compile(r"\b(eval|base64_decode|gzinflate|gzuncompress|str_rot13|assert|system|shell_exec|passthru|exec|proc_open|popen|file_put_contents|curl_exec)\s*\(")


SECRET_KEYS = ("encryptionKey", "installToolPassword")          # werden nur auf Vorhandensein und Länge ausgewertet, nie weitergegeben


def _g(d: Any, *path: str) -> Any:
    for k in path:
        if not isinstance(d, dict):
            return None
        d = d.get(k)
    return d


def parse_settings(text: str, extra: str = "") -> Dict[str, Any]:
    """Liest die Datenbank-Angaben und die wichtigen Einstellungen. Rückgabe wie drupal.parse_settings, damit die Datenbank-Anbindung gleich bleibt.

    Nur einfache Werte werden gelesen. Was als Ausdruck gebaut ist (Umgebungsvariable, Funktionsaufruf), bleibt unbekannt; dann fehlen die Felder
    und die Datenbank-Prüfungen melden das, statt zu raten. 'extra' ist der Text der additional.php (wird nur auf auffällige Befehle gelesen)."""
    arr = parse_php_array(text) or {}
    db = _g(arr, "DB", "Connections", "Default") or {}
    if not isinstance(db, dict):
        db = {}

    def sv(k: str) -> str:
        v = db.get(k)
        return "" if v is None or isinstance(v, (dict, Expr)) else str(v)

    host = sv("host") or "localhost"
    if sv("port") and sv("port") != "0":
        host = "%s:%s" % (host, sv("port"))
    elif sv("unix_socket"):
        host = "%s:%s" % (host or "localhost", sv("unix_socket"))
    drv = sv("driver") or "mysqli"
    vars_ = {"host": host, "user": sv("user"), "password": sv("password"), "db": sv("dbname"), "dbprefix": "", "dbtype": "mysqli" if "mysql" in drv else drv}
    unexpected: List[Tuple[int, str]] = []
    for label, body in (("", text or ""), ("additional.php: ", extra or "")):
        for no, line in enumerate(strip_comments(body).splitlines(), 1):
            s = line.strip()
            if s and DANGEROUS.search(s):
                unexpected.append((no, label + s[:300]))
    simple = {}
    for sect in ("SYS", "BE", "FE"):
        d = arr.get(sect)
        if isinstance(d, dict):
            simple[sect] = {k: v for k, v in d.items() if (not isinstance(v, dict) or k == "passwordHashing") and k not in SECRET_KEYS}
    return {"vars": vars_, "typo3": simple, "prefix": "", "unexpected": unexpected, "parsed": bool(arr), "has_additional": bool((extra or "").strip()),
            "size": len((text or "").encode("utf-8", "replace")), "lines": len((text or "").splitlines()),
            "has_key": isinstance(_g(arr, "SYS", "encryptionKey"), str) and bool(_g(arr, "SYS", "encryptionKey")),
            "key_len": len(_g(arr, "SYS", "encryptionKey") or "") if isinstance(_g(arr, "SYS", "encryptionKey"), str) else 0}


# ------------------------------------------------------------------ Erweiterungen
def parse_ext_emconf(text: str) -> Dict[str, str]:
    """Liest title, version, state und category aus ext_emconf.php."""
    arr = parse_php_array(text, r"\$EM_CONF\s*\[[^\]]*\]\s*=") or {}
    out: Dict[str, str] = {}
    for k in ("title", "version", "state", "category"):
        v = arr.get(k)
        if isinstance(v, (str, int, float)) and not isinstance(v, Expr):
            out[k] = str(v)
    return out


def parse_installed_json(text: str) -> List[Dict[str, str]]:
    """Pakete aus vendor/composer/installed.json (Composer 1 und 2): [{'name','version','type','path'(bool)}]. Leer bei unlesbarem Text."""
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return []
    pk = data.get("packages") if isinstance(data, dict) else data
    out: List[Dict[str, str]] = []
    for p in pk if isinstance(pk, list) else []:
        if isinstance(p, dict) and isinstance(p.get("name"), str):
            dist = p.get("dist") if isinstance(p.get("dist"), dict) else {}
            out.append({"name": p["name"], "version": norm_version(str(p.get("version") or "")), "type": str(p.get("type") or ""),
                        "path": "1" if dist.get("type") == "path" else ""})
    return out


def norm_version(v: str) -> str:
    """'v12.4.8' -> '12.4.8'; Entwicklungsversionen (dev-main) bleiben unverändert."""
    return re.sub(r"^[vV](?=\d)", "", (v or "").strip())


def ext_key_of(path: str) -> Optional[str]:
    m = re.match(r"^\.?/?(?:public/)?(?:typo3conf/ext|packages)/([^/]+)", path.strip())
    return m.group(1) if m else None


def composer_name_of(text: str) -> str:
    """Name (vendor/paket) aus der composer.json einer Erweiterung; leer, wenn nicht lesbar."""
    try:
        d = json.loads(text)
    except (ValueError, TypeError):
        return ""
    n = d.get("name") if isinstance(d, dict) else ""
    return n if isinstance(n, str) and re.fullmatch(r"[a-z0-9_.\-]+/[a-z0-9_.\-]+", n) else ""


def sysext_package(name: str) -> str:
    """Ordner einer Systemerweiterung (typo3/sysext/<name>) -> Composer-Paket (typo3/cms-<name mit Bindestrichen>)."""
    return "typo3/cms-" + name.replace("_", "-")


def package_sysext(pkg: str) -> str:
    return pkg[len("typo3/cms-"):].replace("-", "_") if pkg.startswith("typo3/cms-") else ""


# ------------------------------------------------------------------ Veröffentlichte Versionen (get.typo3.org)
def parse_release_list(text: Any) -> List[Dict[str, str]]:
    """Liest alle Versionen aus der Antwort von get.typo3.org (Aufbau je nach Abruf verschieden: es werden alle Einträge mit einem Feld 'version' gesammelt).
    ELTS-Versionen (kostenpflichtig) und Vorabversionen werden ausgelassen. Noch nicht gegen die echte Antwort des Servers geprüft."""
    if not isinstance(text, str) or not text.strip() or len(text) > 6_000_000:
        return []
    try:
        data = json.loads(text)
    except ValueError:
        return []
    out: Dict[str, Dict[str, str]] = {}

    def walk(o: Any, depth: int = 0) -> None:
        if depth > 8:
            return
        if isinstance(o, dict):
            v = o.get("version")
            if isinstance(v, str) and re.fullmatch(r"\d+\.\d+\.\d+", v) and not o.get("elts") and str(o.get("type") or "").lower() not in ("development", "snapshot"):
                out.setdefault(v, {"version": v, "type": str(o.get("type") or ""), "date": str(o.get("date") or "")})
            for k, x in o.items():
                if isinstance(x, (dict, list)):
                    walk(x, depth + 1)
                elif isinstance(k, str) and re.fullmatch(r"\d+\.\d+\.\d+", k):
                    out.setdefault(k, {"version": k, "type": "", "date": ""})
        elif isinstance(o, list):
            for x in o:
                walk(x, depth + 1)

    walk(data)
    return sorted(out.values(), key=lambda r: version_key(r["version"]))


def sha256_from_version_page(html: str, version: str) -> str:
    """Prüfsumme des Quellpakets aus der Release-Seite von get.typo3.org (Zeile '<sha256>  typo3_src-<Version>.tar.gz'); leer, wenn nicht gefunden."""
    m = re.search(r"\b([0-9a-f]{64})\s+typo3_src-%s\.tar\.gz\b" % re.escape(version), html or "")
    return m.group(1) if m else ""


# ------------------------------------------------------------------ Sicherheitsmeldungen (Packagist)
def parse_advisories(text: Any) -> Dict[str, List[Dict[str, str]]]:
    """Antwort von packagist.org/api/security-advisories: {Paket: [{'id','title','link','cve','affected','reported'}]}. Leer bei unlesbarem Text."""
    if not isinstance(text, str) or not text.strip() or len(text) > 8_000_000:
        return {}
    try:
        data = json.loads(text)
    except ValueError:
        return {}
    adv = data.get("advisories") if isinstance(data, dict) else None
    out: Dict[str, List[Dict[str, str]]] = {}
    if not isinstance(adv, dict):
        return out
    for pkg, lst in adv.items():
        rows = lst.values() if isinstance(lst, dict) else lst
        if not isinstance(rows, (list, type({}.values()))):
            continue
        for a in rows:
            if not isinstance(a, dict) or not isinstance(a.get("affectedVersions"), str):
                continue
            out.setdefault(str(pkg), []).append({"id": str(a.get("advisoryId") or a.get("remoteId") or "")[:60], "title": str(a.get("title") or "")[:200],
                                                 "link": str(a.get("link") or "")[:300], "cve": str(a.get("cve") or "")[:40], "affected": a["affectedVersions"],
                                                 "reported": str(a.get("reportedAt") or "")[:10]})
    return out


_OPS = ("<=", ">=", "==", "!=", "<", ">", "=")


def _one(version: str, cons: str) -> bool:
    cons = cons.strip()
    if not cons or cons == "*":
        return True
    op = next((o for o in _OPS if cons.startswith(o)), "")
    ref = cons[len(op):].strip()
    ref = norm_version(ref)
    if "*" in ref:                                   # 1.2.* -> >=1.2.0,<1.3.0
        parts = ref.split(".")
        pre = [p for p in parts if p != "*"]
        return version_key(version)[:len(pre)] == version_key(ref.replace("*", "0"))[:len(pre)]
    a, b = version_key(version), version_key(ref)
    if op in ("", "=", "=="):
        return a == b
    return {"<=": a <= b, ">=": a >= b, "<": a < b, ">": a > b, "!=": a != b}[op]


def affected(version: str, constraint: str) -> bool:
    """Liegt 'version' im Bereich 'constraint' (Composer-Schreibweise: ODER mit '|' oder '||', UND mit ',' oder Leerzeichen, z. B. '>=12.0.0,<12.4.8|>=13.0.0,<13.1.1')?
    Entwicklungs- und Vorabversionen (dev-main, -rc1) ergeben False: ihr Stand ist nicht beurteilbar."""
    v = norm_version(version)
    if not re.match(r"^\d+(\.\d+){0,3}$", v):
        return False
    for alt in re.split(r"\s*\|\|?\s*", constraint or ""):
        parts = [p for p in re.split(r"\s*,\s*|\s+(?=[<>=!])", alt.strip()) if p]
        if parts and all(_one(v, p) for p in parts):
            return True
    return False


def advisories_for(version: str, adv: Dict[str, List[Dict[str, str]]], pkg: str) -> List[Dict[str, str]]:
    return [a for a in adv.get(pkg, []) if affected(version, a["affected"])]


# ------------------------------------------------------------------ Einstellungsdateien auf dem Server lesen
def read_config_sh() -> str:
    """Shell-Text, der die Einstellungsdatei und (getrennt) die additional.php ausgibt, jeweils mit Kopfzeile '@@CONF <Pfad>' bzw. '@@ADD <Pfad>'."""
    return ('for f in %s; do if [ -f "$f" ]; then echo "@@CONF $f"; head -c 300000 "$f"; echo; break; fi; done; '
            'for f in %s; do if [ -f "$f" ]; then echo "@@ADD $f"; head -c 100000 "$f"; echo; break; fi; done' % (" ".join(CONFIG_FILES), " ".join(ADDITIONAL_FILES)))


def split_config_output(out: str) -> Dict[str, str]:
    """Zerlegt die Ausgabe von read_config_sh in {'path','text','add_path','add_text'}."""
    res = {"path": "", "text": "", "add_path": "", "add_text": ""}
    m = re.search(r"^@@CONF (.+)$", out or "", re.M)
    a = re.search(r"^@@ADD (.+)$", out or "", re.M)
    if m:
        end = a.start() if a and a.start() > m.end() else len(out)
        res["path"], res["text"] = m.group(1).strip(), out[m.end() + 1:end]
    if a:
        res["add_path"], res["add_text"] = a.group(1).strip(), out[a.end() + 1:]
    return res
