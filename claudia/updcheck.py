"""Update-Suche: Bewertung des Ergebnisses und unabhängige Gegenprobe über die Update-Server.

Grundsatz: "keine Updates" wird nur gemeldet, wenn die Suche nachweislich funktioniert hat.
Die Joomla-Kommandozeile kann still scheitern (falsches PHP, nicht erreichte Update-Quellen, leere Tabelle #__updates).
Deshalb wird jedes Ergebnis geprüft und zusätzlich von diesem PC aus gegen die Update-Server der Erweiterungen verglichen
(je Server eine einzelne https-Anfrage, nacheinander).
"""
from __future__ import annotations

import os
import re
import time
import xml.etree.ElementTree as ET
from typing import Any, Callable, Dict, List, Optional, Tuple

from . import coreref, secure
from .util import parse_xml, vcmp

MAX_SITES = 60
MAX_FOLLOW = 40
PAUSE = 0.25                     # Sekunden zwischen zwei Anfragen
FRESH_SECONDS = 1800

SITES_SQL = ("SELECT s.update_site_id AS sid, s.location AS location, s.type AS stype, IF(IFNULL(s.extra_query,'')='',0,1) AS needs_key, "
             "e.extension_id AS eid, e.name AS name, e.element AS element, e.type AS type, IFNULL(e.folder,'') AS folder, e.client_id AS client, "
             "IFNULL(JSON_UNQUOTE(JSON_EXTRACT(e.manifest_cache,'$.version')),'') AS version, UNIX_TIMESTAMP()-IFNULL(s.last_check_timestamp,0) AS age "
             "FROM #__update_sites s JOIN #__update_sites_extensions x ON x.update_site_id=s.update_site_id "
             "JOIN #__extensions e ON e.extension_id=x.extension_id WHERE s.enabled=1 AND NOT (e.element='joomla' AND e.type='file') "
             "ORDER BY s.update_site_id, e.extension_id LIMIT 600")


def parse_sites(out: str) -> List[Dict[str, Any]]:
    lines = [l for l in (out or "").split("\n") if l.strip()]
    if len(lines) < 2:
        return []
    head = lines[0].split("\t")
    rows = []
    for ln in lines[1:]:
        cells = ln.split("\t")
        if len(cells) < len(head):
            continue
        d = dict(zip(head, cells))
        try:
            d["sid"], d["eid"], d["client"] = int(d["sid"]), int(d["eid"]), int(d.get("client") or 0)
            d["age"] = int(float(d.get("age") or 0))
        except ValueError:
            continue
        d["needs_key"] = d.get("needs_key") == "1"
        rows.append(d)
    return rows


def _safe_xml(text: str) -> Optional[ET.Element]:
    return parse_xml(text)


def _client(v: str) -> int:
    return 1 if str(v).strip().lower() in ("1", "administrator", "admin") else 0


def parse_updates(text: str, joomla: str) -> List[Dict[str, Any]]:
    """Einträge einer Update-Datei, die zur Joomla-Version passen und stabil sind."""
    root = _safe_xml(text)
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
        out.append({"element": g("element").lower(), "type": g("type").lower(), "folder": g("folder").lower(),
                    "client": _client(g("client") or g("client_id") or "0"), "version": g("version")})
    return out


def parse_set(text: str) -> List[Dict[str, str]]:
    """Einträge einer Sammlung (<extensionset>): Verweise auf weitere Update-Dateien."""
    root = _safe_xml(text)
    if root is None or root.tag != "extensionset":
        return []
    return [{"element": (e.get("element") or "").lower(), "type": (e.get("type") or "").lower(), "folder": (e.get("folder") or "").lower(),
             "client": str(_client(e.get("client") or "0")), "url": e.get("detailsurl") or ""} for e in root.iter("extension")]


def _get(url: str) -> Optional[str]:
    url, _ = secure.to_https(url)
    if not secure.is_secure_url(url):
        return None
    try:
        data = coreref.fetch_bytes(url, 1_500_000, timeout=20)
    except coreref.RefError:
        return None
    return data.decode("utf-8", "replace")


def _matches(upd: Dict[str, Any], ext: Dict[str, Any]) -> bool:
    if upd["element"] != str(ext["element"]).lower() or upd["type"] != str(ext["type"]).lower():
        return False
    if upd["folder"] and ext.get("folder") and upd["folder"] != str(ext["folder"]).lower():
        return False
    return upd["client"] == int(ext.get("client") or 0) or ext["type"] in ("plugin", "library", "package", "file")


def live_extensions(sites: List[Dict[str, Any]], joomla: str, tick: Optional[Callable[[str], None]] = None) -> Dict[str, Any]:
    """Vergleicht die installierten Versionen mit den Update-Servern. Rückgabe: {ran, found[], unreachable[], sites, reason}."""
    if os.environ.get("CLAUDIA_OFFLINE"):
        return {"ran": False, "found": [], "unreachable": [], "sites": 0, "reason": "Offline-Modus"}
    by_loc: Dict[str, List[Dict[str, Any]]] = {}
    for s in sites:
        if s["location"].startswith(("http://", "https://")):
            by_loc.setdefault(s["location"], []).append(s)
    found: List[Dict[str, Any]] = []
    unreachable: List[str] = []
    follow = 0
    for n, (loc, exts) in enumerate(list(by_loc.items())[:MAX_SITES]):
        if n:
            time.sleep(PAUSE)
        host = re.sub(r"^https?://([^/]+).*$", r"\1", loc)
        if tick:
            tick("Update-Server %d/%d: %s" % (n + 1, min(len(by_loc), MAX_SITES), host))
        body = _get(loc)
        if body is None:
            unreachable.append(host)
            continue
        entries = parse_updates(body, joomla)
        sets = parse_set(body)
        if sets:
            for ext in exts:
                for ref in sets:
                    if follow >= MAX_FOLLOW or not ref["url"] or not _matches({"element": ref["element"], "type": ref["type"], "folder": ref["folder"], "client": int(ref["client"])}, ext):
                        continue
                    follow += 1
                    time.sleep(PAUSE)
                    sub = _get(ref["url"])
                    if sub is None:
                        unreachable.append(re.sub(r"^https?://([^/]+).*$", r"\1", ref["url"]))
                        continue
                    entries += parse_updates(sub, joomla)
        for ext in exts:
            cands = [u["version"] for u in entries if _matches(u, ext) and u["version"]]
            if not cands or not ext["version"]:
                continue
            best = cands[0]
            for v in cands:
                if vcmp(v, best) > 0:
                    best = v
            if vcmp(best, ext["version"]) > 0:
                found.append({"eid": ext["eid"], "name": ext["name"], "old": ext["version"], "new": best, "source": host, "needs_key": ext["needs_key"]})
    return {"ran": True, "found": found, "unreachable": sorted(set(unreachable)), "sites": min(len(by_loc), MAX_SITES), "reason": ""}


def live_core(current: str) -> Optional[str]:
    """Neueste zur Version passende Joomla-Version laut Update-Server (None = nicht ermittelbar)."""
    if os.environ.get("CLAUDIA_OFFLINE") or not current:
        return None
    body = _get(coreref.UPDATE_LIST)
    root = _safe_xml(body) if body else None
    if root is None:
        return None
    urls = []
    for e in root.iter("extension"):
        u = e.get("detailsurl") or ""
        if u.startswith("https://update.joomla.org/") and u not in urls:
            urls.append(u)
    best = ""
    got = False
    for i, u in enumerate(urls[:8]):
        if i:
            time.sleep(PAUSE)
        sub = _get(u)
        if sub is None:
            continue
        got = True
        for up in parse_updates(sub, current):
            if up["element"] == "joomla" and up["type"] == "file" and re.match(r"^\d+\.\d+\.\d+\Z", up["version"]) and (not best or vcmp(up["version"], best) > 0):
                best = up["version"]
    return best if got and best else None


def assess(core_cli: Optional[Dict[str, Any]], cli_ok: bool, ext_rows: Optional[List[Dict[str, Any]]], stale: Optional[Tuple[int, int]],
           live: Dict[str, Any], live_core_latest: Optional[str], current: str) -> Dict[str, Any]:
    """Bewertet alle Quellen gemeinsam.

    core_cli: Ergebnis von parse_core_check (None = Ausgabe nicht verstanden). ext_rows: Liste aus #__updates (None = nicht lesbar).
    stale: (Update-Quellen mit zu altem Zeitstempel, Quellen insgesamt) oder None. Rückgabe: has_update True/False/None, reliable, reasons, live_extra."""
    reasons: List[str] = []
    if not cli_ok:
        reasons.append("Die Joomla-Kommandozeile hat die Suche nicht sauber abgeschlossen.")
    if ext_rows is None:
        reasons.append("Die Liste der Erweiterungs-Updates (Tabelle #__updates) war nicht lesbar.")
    if core_cli is None:
        reasons.append("Die Antwort zur Joomla-Version wurde nicht verstanden.")
    if stale and stale[0]:
        reasons.append("%d von %d Update-Quellen wurden von Joomla beim letzten Lauf nicht erreicht oder nicht aktualisiert." % stale)
    has_update: Optional[bool] = core_cli.get("has_update") if core_cli else None
    latest = (core_cli or {}).get("latest", "") if has_update else (current if core_cli else "")
    if live_core_latest and current and vcmp(live_core_latest, current) > 0 and has_update is not True:
        reasons.append("Der Update-Server nennt Joomla %s, die Kommandozeile meldete das nicht." % live_core_latest)
        has_update, latest = True, live_core_latest
    cli_ids = {int(u["eid"]) for u in (ext_rows or [])}
    extra = [u for u in live.get("found", []) if u["eid"] not in cli_ids]
    if extra:
        reasons.append("Die Update-Server nennen %d Update(s) für Erweiterungen, die Joomla nicht gemeldet hat." % len(extra))
    if live.get("ran") and live.get("unreachable"):
        reasons.append("Gegenprobe unvollständig: %d Update-Server von diesem PC aus nicht erreichbar (%s)." % (len(live["unreachable"]), ", ".join(live["unreachable"][:4])))
    confirmed = bool(live.get("ran")) and not live.get("unreachable")
    return {"has_update": has_update, "latest": latest, "reliable": not reasons, "confirmed": confirmed, "reasons": reasons,
            "live_extra": extra, "live_ran": bool(live.get("ran")), "stale": list(stale) if stale else []}


def message(a: Dict[str, Any], n_cli: int) -> str:
    """Kurztext zum Ergebnis. 'aktuell' und 'keine Updates' stehen nur bei einem verlässlichen Ergebnis."""
    if a["reliable"]:
        core = ("Update auf %s verfügbar" % a["latest"]) if a["has_update"] else "aktuell"
        ext = ("%d Update(s) verfügbar" % n_cli) if n_cli else "keine Updates"
        tail = " (bestätigt durch die Update-Server)" if a.get("confirmed") else " (Gegenprobe über die Update-Server war nicht möglich)"
        return "Joomla: %s. Erweiterungen: %s%s." % (core, ext, tail)
    return "Ergebnis nicht verlässlich: %s Bitte im Joomla-Backend unter System > Aktualisieren nachsehen." % " ".join(a["reasons"])
