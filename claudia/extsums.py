"""Integrität von Erweiterungen (2.4.1, Stufe 2 Punkt 5): Pakete des Herstellers lesen und mit den Dateien auf dem Server vergleichen.

Zwei Wege, beide nur lesend und mit einer einzelnen https-Anfrage je Paket:
- WordPress-Themes: ZIP von downloads.wordpress.org/theme/<slug>.<version>.zip (wordpress.org gilt als verifizierte Quelle).
- Joomla-Erweiterungen mit öffentlicher Update-Adresse: Die Adresse steht in der Datenbank der Seite (#__update_sites). Das Paket wird nur geladen,
  wenn der Update-Server GENAU die installierte Version anbietet; sonst gilt die Erweiterung als nicht prüfbar.
Das ZIP wird nur im Speicher gelesen (nie entpackt, nie ausgeführt) und mit Grenzen für Größe und Dateizahl gegen ZIP-Bomben geschützt.
Aufbau und Verzeichniszuordnung sind nur mit nachgebildeten Paketen getestet, NICHT gegen echte Hersteller-Server."""
from __future__ import annotations

import hashlib
import io
import re
import zipfile
from typing import Any, Dict, List, Set, Tuple
from urllib.parse import quote
from xml.etree import ElementTree as ET

from .util import parse_xml

MAX_ZIP_BYTES = 25_000_000
MAX_UNPACKED = 200_000_000
MAX_FILES = 20_000
MAX_ONE_FILE = 20_000_000
SAFE_REL = re.compile(r"^[A-Za-z0-9_./-]{1,200}$")


class ZipProblem(Exception):
    pass


def theme_url(slug: str, version: str) -> str:
    return "https://downloads.wordpress.org/theme/%s.%s.zip" % (quote(slug, safe=""), quote(version, safe=""))


def read_zip_full(data: bytes, strip_top: bool = False) -> Tuple[Dict[str, str], str, Dict[str, bytes]]:
    """-> ({Pfad: sha256}, Manifest-Text, {Pfad: Inhalt eingebetteter ZIPs}). strip_top: liegt alles in EINEM Oberordner
    (z. B. paket-1.2/...), wird er entfernt. Wirft ZipProblem bei defektem oder zu großem Paket."""
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        raise ZipProblem("Das Paket ist kein gültiges ZIP.")
    files: Dict[str, str] = {}
    xmls: Dict[str, bytes] = {}
    nested: Dict[str, bytes] = {}
    total = 0
    with zf:
        infos = zf.infolist()
        if len(infos) > MAX_FILES:
            raise ZipProblem("Das Paket enthält zu viele Dateien.")
        for i in infos:
            n = i.filename.replace("\\", "/")
            if n.endswith("/") or n.startswith("/") or ".." in n.split("/") or n.startswith("__MACOSX/"):
                continue
            total += i.file_size
            if i.file_size > MAX_ONE_FILE or total > MAX_UNPACKED:
                raise ZipProblem("Das Paket ist entpackt zu groß.")
            raw = zf.read(i)
            files[n] = hashlib.sha256(raw).hexdigest()
            low = n.lower()
            if low.endswith(".xml") and n.count("/") <= 1 and len(raw) < 200_000 and re.search(rb"<(extension|install)[\s>]", raw[:3500]):
                xmls[n] = raw
            elif low.endswith(".zip") and len(raw) <= MAX_ZIP_BYTES:
                nested[n] = raw
    tops = {n.split("/", 1)[0] for n in files}
    if strip_top and len(tops) == 1 and all("/" in n for n in files):     # alles in einem Oberordner
        top = tops.pop() + "/"
        files = {n[len(top):]: h for n, h in files.items()}
        xmls = {n[len(top):]: v for n, v in xmls.items() if n.startswith(top)}
        nested = {n[len(top):]: v for n, v in nested.items() if n.startswith(top)}
    manifest = ""
    for n in sorted(xmls):
        if "/" not in n:
            manifest = xmls[n].decode("utf-8", "replace")
            break
    return files, manifest, nested


def read_zip(data: bytes) -> Tuple[Dict[str, str], str]:
    """-> ({Pfad im ZIP: sha256}, Text des Manifests im Hauptordner des ZIP oder ""). Wirft ZipProblem bei defektem oder zu großem Paket."""
    files, manifest, _ = read_zip_full(data)
    return files, manifest


def zip_member(data: bytes, rel: str, strip_top: bool = False) -> bytes:
    """Inhalt einer Datei aus dem Paket (für die Anzeige der Unterschiede); strip_top wie bei read_zip_full."""
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        names = [i.filename for i in zf.infolist() if not i.filename.endswith("/")]
        tops = {n.split("/", 1)[0] for n in names}
        pre = (tops.pop() + "/") if strip_top and len(tops) == 1 and all("/" in n for n in names) else ""
        info = zf.getinfo(pre + rel)
        if info.file_size > MAX_ONE_FILE:
            raise ZipProblem("Datei zu groß.")
        return zf.read(info)


def _read_any(data: bytes) -> Tuple[Dict[str, str], str, Dict[str, bytes], bool]:
    """Erst wie geliefert lesen; steht kein Manifest im Hauptordner, mit entferntem Oberordner."""
    files, manifest, nested = read_zip_full(data)
    if manifest:
        return files, manifest, nested, False
    f2, m2, n2 = read_zip_full(data, strip_top=True)
    return (f2, m2, n2, True) if m2 else (files, manifest, nested, False)


def resolve_package(data: bytes, ext: Dict[str, Any]) -> Tuple[Dict[str, str], str, bytes, bool]:
    """Das richtige Paket für die Erweiterung finden. Viele Hersteller liefern eine Paket-Sammlung (type="package"),
    in der die eigentliche Erweiterung als eigenes ZIP steckt (z. B. packages/plg_system_acf.zip). -> (Dateien, Manifest, ZIP-Bytes, Oberordner entfernt)."""
    files, manifest, nested, top = _read_any(data)
    root = parse_xml(manifest)
    kind = str(ext.get("type") or "").lower()
    if root is None or (root.get("type") or "").lower() == kind or not nested:
        return files, manifest, data, top
    element = str(ext.get("element") or "").lower()
    group = str(ext.get("folder") or "").lower()
    order: List[str] = []
    if (root.get("type") or "").lower() == "package":
        for fe in root.findall("files"):
            folder = (fe.get("folder") or "").strip().strip("/")
            for f in fe.findall("file"):
                fid = (f.get("id") or "").strip().lower()
                ftype = (f.get("type") or "").strip().lower()
                fgroup = (f.get("group") or "").strip().lower()
                if ftype == kind and fid in (element, element.replace("com_", "", 1), "%s_%s" % (group, element)) and (kind != "plugin" or not fgroup or fgroup == group):
                    order.append(((folder + "/") if folder else "") + (f.text or "").strip())
    order += sorted(n for n in nested if element and element.replace("com_", "") in n.lower().rsplit("/", 1)[-1])
    for name in dict.fromkeys(order):
        sub = nested.get(name)
        if sub is None:
            continue
        try:
            f2, m2, _, t2 = _read_any(sub)
        except ZipProblem:
            continue
        r2 = parse_xml(m2)
        if r2 is not None and (r2.get("type") or "").lower() == kind:
            return f2, m2, sub, t2
    return files, manifest, data, top


def strip_prefix(files: Dict[str, str], prefix: str) -> Dict[str, str]:
    """Dateien unter einem Ordner im ZIP -> relative Pfade ('' = alle)."""
    prefix = prefix.strip("/")
    out: Dict[str, str] = {}
    for n, h in files.items():
        if not prefix:
            out[n] = h
        elif n.startswith(prefix + "/"):
            out[n[len(prefix) + 1:]] = h
    return out


def as_reference(files: Dict[str, str]) -> Dict[str, Dict[str, Set[str]]]:
    return {p: {"sha256": {h}, "md5": set()} for p, h in files.items()}


# ---------------------------------------------------------------- WordPress-Themes
def parse_local_themes(out: str) -> Dict[str, Dict[str, str]]:
    """Ausgabe von sha256sum für wp-content/themes/<slug>/<Pfad> -> {slug: {Pfad: sha256}}."""
    res: Dict[str, Dict[str, str]] = {}
    for ln in out.splitlines():
        m = re.match(r"^([0-9a-f]{64})  \*?(?:\./)?wp-content/themes/([^/]+)/(.+)\Z", ln)
        if m:
            res.setdefault(m.group(2), {})[m.group(3)] = m.group(1)
    return res


def theme_reference(data: bytes, slug: str) -> Dict[str, Dict[str, Set[str]]]:
    files, _ = read_zip(data)
    return as_reference(strip_prefix(files, slug))


# ---------------------------------------------------------------- Joomla: Update-Server und Zuordnung zu Ordnern
def sites_from_rows(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Zeilen der Abfrage updcheck.SITES_SQL -> Liste wie updcheck.parse_sites."""
    out = []
    for r in rows or []:
        d = dict(r)
        try:
            d["sid"], d["eid"], d["client"] = int(d["sid"]), int(d["eid"]), int(d.get("client") or 0)
        except (KeyError, TypeError, ValueError):
            continue
        d["needs_key"] = str(d.get("needs_key")) == "1"
        d["location"] = d.get("location") or ""
        d["version"] = d.get("version") or ""
        d["folder"] = d.get("folder") or ""
        out.append(d)
    return out


def entries_with_downloads(xml_text: str, joomla: str) -> List[Dict[str, Any]]:
    """Einträge einer Update-Datei (stabil, passend zur Joomla-Version) samt Download-Adressen."""
    from . import updcheck
    root = updcheck._safe_xml(xml_text or "")
    if root is None:
        return []
    out = []
    for up in root.iter("update"):
        g = lambda tag: (up.findtext(tag) or "").strip()          # noqa: E731
        tp = up.find("targetplatform")
        if tp is not None and (tp.get("name") or "").lower() == "joomla" and tp.get("version"):
            try:
                if not re.search(tp.get("version"), joomla or ""):
                    continue
            except re.error:
                continue
        tags = [(t.text or "").strip().lower() for t in up.iterfind("tags/tag")]
        if tags and "stable" not in tags:
            continue
        urls = []
        for dl in up.iter("downloadurl"):
            u = (dl.text or "").strip()
            if re.match(r"^https://[A-Za-z0-9.-]+(:\d+)?/\S*\Z", u):
                urls.append((dl.get("type", "full") or "full", u))
        urls.sort(key=lambda t: 0 if t[0] == "full" else 1)
        out.append({"element": g("element").lower(), "type": g("type").lower(), "folder": g("folder").lower(),
                    "client": updcheck._client(g("client") or g("client_id") or "0"), "version": g("version"), "urls": [u for _, u in urls]})
    return out


def _files_folders(root: ET.Element, xpath: str) -> List[str]:
    out = []
    for fe in root.findall(xpath):
        out.append((fe.get("folder") or "").strip().strip("/"))
    return out


def target_entries(manifest: str, ext: Dict[str, Any]) -> Dict[Tuple[str, str], List[str]]:
    """Wie target_dirs, zusätzlich die im Manifest aufgezählten Dateien und Ordner je Zuordnung (<filename>, <folder>, <file>).
    Nur diese installiert Joomla; alles andere im ZIP (Installationsskripte, Unterpakete, der admin-Ordner unter dem Seitenteil) gehört nicht in den Ordner."""
    out: Dict[Tuple[str, str], List[str]] = {}
    root = parse_xml(manifest)
    if root is None:
        return out
    pairs = target_dirs(manifest, ext)
    kind = str(ext.get("type") or "").lower()
    groups = {"administrator/": root.findall("administration/files")}
    site = root.findall("files")
    for z, s in pairs:
        cand = groups["administrator/"] if (kind == "component" and s.startswith("administrator/")) else site
        names: List[str] = []
        for fe in cand:
            if (fe.get("folder") or "").strip().strip("/") != z:
                continue
            for c in fe:
                if c.tag in ("filename", "folder", "file") and (c.text or "").strip():
                    t = (c.text or "").strip().strip("/")
                    if SAFE_REL.match(t) and ".." not in t.split("/"):
                        names.append(t)
        out[(z, s)] = names
    return out


def only_entries(files: Dict[str, str], entries: List[str], exclude: List[str]) -> Dict[str, str]:
    """Relative Pfade auf die Manifest-Einträge beschränken; ohne Einträge alles außer den Ordnern anderer Zuordnungen (z. B. admin/)."""
    if entries:
        return {p: h for p, h in files.items() if any(p == e or p.startswith(e + "/") for e in entries)}
    return {p: h for p, h in files.items() if not any(x and (p == x or p.startswith(x + "/")) for x in exclude)}


def normalized_equal(a: bytes, b: bytes) -> bool:
    """Gleich bis auf Zeilenenden, Leerzeichen am Zeilenende und eine fehlende Leerzeile am Dateiende."""
    na = [ln.rstrip() for ln in a.replace(b"\r\n", b"\n").replace(b"\r", b"\n").split(b"\n")]
    nb = [ln.rstrip() for ln in b.replace(b"\r\n", b"\n").replace(b"\r", b"\n").split(b"\n")]
    while na and not na[-1]:
        na.pop()
    while nb and not nb[-1]:
        nb.pop()
    return na == nb


def target_dirs(manifest: str, ext: Dict[str, Any]) -> List[Tuple[str, str]]:
    """[(Ordner im ZIP, Ordner auf dem Server)] für eine Erweiterung. Leer, wenn die Art nicht unterstützt ist oder das Manifest nicht passt."""
    root = parse_xml(manifest)
    if root is None:
        return []
    kind = str(ext.get("type") or "").lower()
    if (root.get("type") or "").lower() != kind:
        return []
    element = str(ext.get("element") or "")
    if not re.match(r"^[a-z0-9_]{2,60}\Z", element, re.I):
        return []
    out: List[Tuple[str, str]] = []
    if kind == "component":
        for f in _files_folders(root, "files") or [""]:
            out.append((f, "components/%s" % element))
        for f in _files_folders(root, "administration/files") or ([] if root.find("administration") is None else [""]):
            out.append((f, "administrator/components/%s" % element))
    elif kind == "plugin":
        group = re.sub(r"[^a-z0-9_]", "", str(ext.get("folder") or "").lower())
        if not group:
            return []
        for f in _files_folders(root, "files") or [""]:
            out.append((f, "plugins/%s/%s" % (group, element)))
    elif kind in ("module", "template"):
        admin = int(ext.get("client") or 0) == 1
        base = ("administrator/modules" if admin else "modules") if kind == "module" else ("administrator/templates" if admin else "templates")
        for f in _files_folders(root, "files") or [""]:
            out.append((f, "%s/%s" % (base, element)))
    # doppelte Zuordnungen (gleiches Ziel) entfernen, unsichere Pfade verwerfen
    seen, clean = set(), []
    for z, s in out:
        if (z, s) in seen or not SAFE_REL.match(s) or ".." in s or (z and not SAFE_REL.match(z)):
            continue
        seen.add((z, s))
        clean.append((z, s))
    return clean


def parse_local(out: str, dirs: List[str]) -> Dict[str, Dict[str, str]]:
    """Ausgabe von sha256sum -> {Serverordner: {relativer Pfad: sha256}}; die Zuordnung erfolgt über den längsten passenden Ordner."""
    res: Dict[str, Dict[str, str]] = {d: {} for d in dirs}
    order = sorted(dirs, key=len, reverse=True)
    for ln in out.splitlines():
        m = re.match(r"^([0-9a-f]{64})  \*?(?:\./)?(.+)\Z", ln)
        if not m:
            continue
        path = m.group(2)
        for d in order:
            if path.startswith(d + "/"):
                res[d][path[len(d) + 1:]] = m.group(1)
                break
    return res


def find_script(dirs: List[str]) -> str:
    """Shell-Skript, das die Prüfsummen aller Dateien in den Ordnern liefert (nur lesend)."""
    from .util import sq
    return "for d in %s; do [ -d \"$d\" ] && find \"$d\" -type f -size -2048k -print0 2>/dev/null | head -z -n 20000 | xargs -0 -r sha256sum 2>/dev/null; done" % " ".join(sq(d) for d in dirs)
