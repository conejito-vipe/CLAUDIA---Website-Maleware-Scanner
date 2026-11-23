"""Joomla-spezifisches Parsen: configuration.php, Manifeste, Versionsdateien."""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from .util import digits

_PROP_RE = re.compile(r"^\s*public\s+\$(\w+)\s*=\s*(.*?)\s*;\s*(?://.*|#.*)?\Z")


def _parse_value(raw: str) -> Any:
    raw = raw.strip()
    if len(raw) >= 2 and raw[0] in "'\"" and raw[-1] == raw[0]:
        inner = raw[1:-1]
        return inner.replace("\\'", "'").replace('\\"', '"').replace("\\\\", "\\")
    low = raw.lower()
    if low == "true":
        return True
    if low == "false":
        return False
    if low == "null":
        return None
    if re.fullmatch(r"-?\d+", raw):
        return int(raw)
    return raw


def parse_config(text: str) -> Dict[str, Any]:
    """Liest die Eigenschaften der JConfig-Klasse und meldet unerwartete Zeilen.

    Rückgabe: {"vars": {...}, "unexpected": [(zeilennr, text), ...], "size": n, "lines": n}
    """
    vars_: Dict[str, Any] = {}
    unexpected: List[tuple] = []
    in_block_comment = False
    lines = text.splitlines()
    for no, line in enumerate(lines, 1):
        s = line.strip()
        if not s:
            continue
        if in_block_comment:
            if "*/" in s:
                in_block_comment = False
            continue
        if s.startswith("/*"):
            if "*/" not in s:
                in_block_comment = True
            continue
        if s.startswith(("//", "#", "*")):
            continue
        if s in ("<?php", "<?", "?>", "{", "}") or re.match(r"^(final\s+)?class\s+JConfig\s*\{?\Z", s):
            continue
        if re.match(r"^(declare\s*\(strict_types=1\)\s*;|namespace\s+[\w\\]+\s*;)\Z", s):
            continue
        m = _PROP_RE.match(line)
        if m:
            vars_[m.group(1)] = _parse_value(m.group(2))
            continue
        unexpected.append((no, s[:300]))
    return {"vars": vars_, "unexpected": unexpected, "size": len(text.encode("utf-8", "replace")), "lines": len(lines)}


def split_db_host(host: str):
    """'host:3306' oder 'localhost:/pfad/zum/socket' -> (host, port, socket)."""
    host = (host or "localhost").strip()
    if ":" in host and not host.startswith("["):
        h, rest = host.rsplit(":", 1)
        if digits(rest):
            return h, int(rest), ""
        if rest.startswith("/"):
            return h, 0, rest
    return host, 0, ""


# ----------------------------------------------------------------- Manifeste
_EXT_ROOT_RE = re.compile(r"<(extension|install)\b([^>]*)>", re.IGNORECASE)


def _tag(text: str, name: str) -> str:
    m = re.search(r"<%s>\s*(.*?)\s*</%s>" % (name, name), text, re.IGNORECASE | re.DOTALL)
    if not m:
        return ""
    val = m.group(1)
    val = re.sub(r"<!\[CDATA\[(.*?)\]\]>", r"\1", val, flags=re.DOTALL)
    return val.strip()


def parse_manifest(path: str, text: str) -> Optional[Dict[str, str]]:
    """Liest Name, Version, Autor usw. aus einem Joomla-Erweiterungs-Manifest. None = kein Manifest."""
    m = _EXT_ROOT_RE.search(text)
    if not m:
        return None
    attrs = m.group(2)
    tm = re.search(r'type\s*=\s*"([^"]*)"', attrs)
    gm = re.search(r'group\s*=\s*"([^"]*)"', attrs)
    ext_type = tm.group(1).lower() if tm else ""
    name = _tag(text, "name")
    version = _tag(text, "version")
    return {
        "path": path,
        "type": ext_type,
        "group": gm.group(1) if gm else "",
        "name": name,
        "version": version,
        "author": _tag(text, "author"),
        "date": _tag(text, "creationDate"),
        "element": _manifest_element(path, ext_type, gm.group(1) if gm else ""),
    }


def _manifest_element(path: str, ext_type: str, group: str) -> str:
    """Element-Name aus dem Pfad ableiten (wie in #__extensions.element)."""
    parts = [p for p in path.replace("\\", "/").split("/") if p and p != "."]
    if ext_type == "plugin" and len(parts) >= 3 and parts[0] == "plugins":
        return parts[2]
    if ext_type == "component":
        for p in parts:
            if p.startswith("com_"):
                return p
    if ext_type == "module":
        for p in parts:
            if p.startswith("mod_"):
                return p
    if ext_type == "template" and len(parts) >= 2 and parts[0] in ("templates", "administrator"):
        return parts[-2]
    if ext_type in ("library", "package", "file") and parts:
        return parts[-1].rsplit(".", 1)[0]
    return parts[-2] if len(parts) >= 2 else ""


def parse_joomla_version(version_php: str, manifest_xml: str = "") -> str:
    vals = {}
    for key in ("MAJOR_VERSION", "MINOR_VERSION", "PATCH_VERSION"):
        m = re.search(r"\b%s\s*=\s*(\d+)" % key, version_php)
        if m:
            vals[key] = m.group(1)
    if len(vals) == 3:
        extra = re.search(r"EXTRA_VERSION\s*=\s*'([^']*)'", version_php)
        v = "%s.%s.%s" % (vals["MAJOR_VERSION"], vals["MINOR_VERSION"], vals["PATCH_VERSION"])
        if extra and extra.group(1):
            v += "-" + extra.group(1)
        return v
    m = re.search(r"<version>\s*([\d.]+[^<]*)</version>", manifest_xml)
    return m.group(1).strip() if m else ""
