"""Aktuelle Bedrohungslage: neue Schwachstellen-Meldungen aus der NVD (CVE) und der Joomla-Liste verwundbarer Erweiterungen (VEL).

Wird vor jedem Lauf einmal geladen (Zwischenspeicher: höchstens eine Stunde alt), damit neue Vorfälle sofort in die Prüfung einfließen.
Alle Abrufe laufen von diesem PC über https; zu den Quellen geht nichts außer der Suchanfrage. Ohne Internet bleibt der eingebaute Stand aktiv."""
from __future__ import annotations

import json
import os
import re
import time
from typing import Any, Dict, List, Optional
from urllib.parse import quote

from . import cms as cmsmod, coreref
from .util import atomic_write, vcmp

NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"
WINDOW_DAYS = {"joomla": 120, "wordpress": 30}          # NVD erlaubt höchstens 120 Tage je Anfrage
KEYWORD = {"joomla": "joomla", "wordpress": "wordpress"}
MAX_CVES = 4000
TTL = 3600


def _iso(t: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S.000", time.gmtime(t))


_SPLIT = re.compile(r"(?<!\\):")


def parse_cpe(s: str) -> Dict[str, str]:
    p = [x.replace("\\", "") for x in _SPLIT.split(s or "")]
    if len(p) < 6 or p[0] != "cpe":
        return {}
    return {"v": p[3].lower(), "p": p[4].lower(), "ver": p[5]}


def compact_cve(item: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    c = item.get("cve") or item
    cid = str(c.get("id") or "")
    if not re.match(r"^CVE-\d{4}-\d+\Z", cid):
        return None
    desc = next((str(d.get("value") or "") for d in c.get("descriptions") or [] if d.get("lang") == "en"), "")
    score, sev = 0.0, ""
    m = c.get("metrics") or {}
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if m.get(key):
            first = m[key][0]
            d = first.get("cvssData") or {}
            try:
                score = float(d.get("baseScore") or 0)
            except (TypeError, ValueError):
                score = 0.0
            sev = str(d.get("baseSeverity") or first.get("baseSeverity") or "").upper()
            break
    cpes = []
    for conf in c.get("configurations") or []:
        for node in conf.get("nodes") or []:
            for cm in node.get("cpeMatch") or []:
                if cm.get("vulnerable", True) is False:
                    continue
                cp = parse_cpe(str(cm.get("criteria") or ""))
                if cp:
                    for k, src in (("s", "versionStartIncluding"), ("si", "versionStartExcluding"), ("e", "versionEndExcluding"), ("ei", "versionEndIncluding")):
                        if cm.get(src):
                            cp[k] = str(cm[src])
                    cpes.append(cp)
    return {"id": cid, "pub": str(c.get("published") or "")[:10], "score": score, "sev": sev, "text": desc[:600], "cpes": cpes[:30]}


def version_affected(version: str, cp: Dict[str, str]) -> bool:
    """Liegt die Version im betroffenen Bereich dieses CPE-Eintrags? Ohne Versionsangaben gelten alle Versionen als betroffen."""
    if not version:
        return False
    ver = cp.get("ver", "*")
    if ver not in ("*", "-", ""):
        return vcmp(version, ver) == 0
    if cp.get("s") and vcmp(version, cp["s"]) < 0:
        return False
    if cp.get("si") and vcmp(version, cp["si"]) <= 0:
        return False
    if cp.get("e") and vcmp(version, cp["e"]) >= 0:
        return False
    if cp.get("ei") and vcmp(version, cp["ei"]) > 0:
        return False
    return True


def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", (s or "").lower())


def fetch_nvd(cms: str, now: Optional[float] = None) -> List[Dict[str, Any]]:
    now = now or time.time()
    start = now - WINDOW_DAYS[cms] * 86400
    out: List[Dict[str, Any]] = []
    index = 0
    while len(out) < MAX_CVES:
        url = "%s?keywordSearch=%s&pubStartDate=%s&pubEndDate=%s&resultsPerPage=2000&startIndex=%d" % (NVD, KEYWORD[cms], quote(_iso(start)), quote(_iso(now)), index)
        raw = coreref.fetch_bytes(url, 40_000_000, timeout=60)
        try:
            data = json.loads(raw.decode("utf-8", "replace"))
        except ValueError:
            raise coreref.RefError("Die NVD lieferte keine lesbare Antwort.")
        vulns = data.get("vulnerabilities") or []
        for v in vulns:
            c = compact_cve(v)
            if c:
                out.append(c)
        index += len(vulns)
        if not vulns or index >= int(data.get("totalResults") or 0):
            break
    return out


def fetch_vel() -> List[Dict[str, Any]]:
    from .checks import online
    for u in online.VEL_URLS:
        try:
            items = online.parse_vel(coreref.fetch_bytes(u, 20_000_000, timeout=25).decode("utf-8", "replace"))
        except coreref.RefError:
            continue
        if items:
            keep = ("title", "cve_id", "install_data", "start_version", "vulnerable_version", "patch_version", "status")
            return [{k: i.get(k) for k in keep} for i in items]
    return []


def load(cms: str, offline: bool = False, now: Optional[float] = None) -> Dict[str, Any]:
    """Bedrohungslage laden. Rückgabe: {stand, cms, cves, vel, nvd_ok, vel_ok, errors, cached}. Fehler werden gemeldet, nie geworfen."""
    now = now or time.time()
    cfile = os.path.join(coreref.cache_dir(), "intel-%s.json" % cms)
    cached: Optional[Dict[str, Any]] = None
    try:
        with open(cfile, encoding="utf-8") as fh:
            cached = json.load(fh)
    except (OSError, ValueError):
        pass
    ttl = int(os.environ.get("CLAUDIA_INTEL_TTL", TTL))
    if cached and now - float(cached.get("fetched") or 0) < ttl:
        cached["cached"] = True
        return cached
    base = {"stand": time.strftime("%Y-%m-%d %H:%M", time.localtime(now)), "fetched": now, "cms": cms, "cves": [], "vel": [], "nvd_ok": False, "vel_ok": False, "errors": [], "cached": False}
    if offline:
        base["errors"].append("Offline-Modus: keine Online-Quellen abgefragt.")
        return cached_or(base, cached)
    try:
        base["cves"] = fetch_nvd(cms, now)
        base["nvd_ok"] = True
    except coreref.RefError as e:
        base["errors"].append("NVD: %s" % e)
    if cmsmod.profile(cms)["vel"]:
        try:
            base["vel"] = fetch_vel()
            base["vel_ok"] = bool(base["vel"])
            if not base["vel_ok"]:
                base["errors"].append("VEL: keine lesbare Liste.")
        except Exception as e:                                    # noqa: BLE001  (Quelle darf den Lauf nie stoppen)
            base["errors"].append("VEL: %s" % e)
    if not (base["nvd_ok"] or base["vel_ok"]):
        return cached_or(base, cached)
    try:
        os.makedirs(os.path.dirname(cfile), exist_ok=True)
        atomic_write(cfile, json.dumps(base))
    except OSError:
        pass
    return base


def cached_or(base: Dict[str, Any], cached: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Quellen nicht erreichbar: ältere Daten benutzen, falls vorhanden (gekennzeichnet)."""
    if cached and (cached.get("cves") or cached.get("vel")):
        cached = dict(cached)
        cached["cached"] = True
        cached["stale"] = True
        cached["errors"] = base["errors"]
        return cached
    return base


# Allgemeine Wörter, die als Erweiterungsname nie ausreichen (würden Meldungen zum Kern oder zu fremden Produkten treffen)
GENERIC_NAMES = {"joomla", "wordpress", "plugin", "plugins", "system", "content", "user", "editor", "search", "extension", "module", "component",
                 "template", "theme", "installer", "authentication", "captcha", "fields", "finder", "cache", "mail", "menu", "admin", "site", "core"}


def core_hits(intel: Dict[str, Any], product: str, version: str) -> List[Dict[str, Any]]:
    """CVEs, deren betroffener Bereich die installierte Version des Kerns (Produkt joomla/wordpress) enthält."""
    out = []
    for c in intel.get("cves", []):
        if any(cp["p"].replace("!", "") == product and version_affected(version, cp) for cp in c["cpes"]):
            out.append(c)
    return sorted(out, key=lambda c: -c["score"])


def extension_hits(intel: Dict[str, Any], names: List[str], version: str) -> Dict[str, List[Dict[str, Any]]]:
    """Je Name (Anzeigename, Element, Slug): CVEs, bei denen das CPE-Produkt zum Namen passt UND die Version im betroffenen Bereich liegt (match=confirmed),
    oder bei denen der Name in der Beschreibung steht (match=name, nur als Hinweis). Passt das Produkt, aber die Version ist schon behoben, gibt es keinen Treffer."""
    keys = {_norm(n): n for n in names if len(_norm(n)) >= 3 and _norm(n) not in GENERIC_NAMES}
    out: Dict[str, List[Dict[str, Any]]] = {}
    for c in intel.get("cves", []):
        low = c["text"].lower()
        for k, n in keys.items():
            prods = [cp for cp in c["cpes"] if _norm(cp["p"]) == k]
            if prods:
                if any(version_affected(version, cp) for cp in prods):
                    out.setdefault(n, []).append({**c, "match": "confirmed"})
            elif len(k) >= 6 and re.search(r"(?<![a-z0-9])%s(?![a-z0-9])" % re.escape(n.lower()), low):
                out.setdefault(n, []).append({**c, "match": "name"})
    return out
