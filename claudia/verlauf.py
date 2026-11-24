"""Verlauf für das Dashboard: was wurde wann geprüft, was hat sich geändert, was wurde erledigt.

Gespeichert wird nur lokal (verlauf.json im Datenordner) und nur das Nötigste: Zeit, Seite (Host und Ordner), CMS, Version, Zählstände,
die Kurzbezeichnungen der Warnungen und kritischen Funde sowie ausgeführte Aktionen mit Ergebnis. Keine Passwörter, keine Dateiinhalte,
keine Übertragung nach außen. Alles lässt sich im Dashboard je Seite löschen. Eine kaputte oder fremde Datei führt nie zu einer Ausnahme."""
import json
import os
import threading
import time
from typing import Any, Dict, List, Optional

from .util import atomic_write, clean_line

_LOCK = threading.Lock()          # Prüfung und Aktion können gleichzeitig enden: Lesen-Ändern-Schreiben nur einer nach dem anderen
FILE = "verlauf.json"
MAX_RUNS = 400                 # Prüfungen insgesamt
MAX_ACTIONS = 600              # Aktionen insgesamt
KEEP_DETAIL = 12               # je Seite so viele letzte Prüfungen behalten ihre Fundliste, ältere nur die Zählstände
MAX_FINDINGS = 150             # Funde je Prüfung
STALE_DAYS = 30
SEVS = ("warn", "crit")
NACHKONTROLL_TAGE = 3          # so viele Tage nach einer Bereinigung soll die Seite noch einmal geprüft werden (Schadsoftware kommt oft zurück)
# Aktionen, die Schadcode entfernen oder dem Angreifer den Zugang nehmen: danach ist eine Nachkontrolle sinnvoll
BEREINIGUNG = ("remove_shells", "remove_db_code", "remove_jce_profiles", "reset_htaccess", "joomla_core_reinstall", "wp_core_reinstall",
               "block_users", "revoke_tokens", "end_sessions", "wp_salts", "deactivate_extension", "wp_deactivate_plugin", "clean_tmp")
EXEC_STATUS = ("ok", "info", "warn", "crit")       # Prüfung ist wirklich gelaufen (nicht übersprungen oder fehlgeschlagen)


def path(base: str) -> str:
    return os.path.join(base, FILE)


def _empty() -> Dict[str, Any]:
    return {"v": 1, "runs": [], "actions": []}


def load(base: str) -> Dict[str, Any]:
    try:
        with open(path(base), encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return _empty()
    if not isinstance(data, dict) or not isinstance(data.get("runs"), list) or not isinstance(data.get("actions"), list):
        return _empty()
    data["runs"] = [r for r in data["runs"] if isinstance(r, dict) and isinstance(r.get("site"), str) and isinstance(r.get("ts"), (int, float))]
    data["actions"] = [a for a in data["actions"] if isinstance(a, dict) and isinstance(a.get("site"), str) and isinstance(a.get("ts"), (int, float))]
    return data


def save(base: str, data: Dict[str, Any]) -> None:
    data["runs"] = data["runs"][-MAX_RUNS:]
    data["actions"] = data["actions"][-MAX_ACTIONS:]
    # ältere Prüfungen derselben Seite behalten nur die Zählstände
    seen: Dict[str, int] = {}
    for r in reversed(data["runs"]):
        n = seen.get(r["site"], 0) + 1
        seen[r["site"]] = n
        if n > KEEP_DETAIL:
            r.pop("findings", None)
            r.pop("ran", None)
    try:
        os.makedirs(base, exist_ok=True)
        atomic_write(path(base), json.dumps(data, ensure_ascii=False, separators=(",", ":")))
    except OSError:
        pass                                        # Verlauf ist Zusatz: nie die eigentliche Arbeit stören


def _txt(value: Any, n: int) -> str:
    return clean_line(str(value if value is not None else ""))[:n]


def run_entry(site: str, label: str, cms: str, version: str, results: List[Dict[str, Any]], ts: Optional[float] = None) -> Dict[str, Any]:
    """Eine Prüfung als kurzer Eintrag. 'ran' = Prüfungen, die wirklich gelaufen sind (nur dort kann ein Fund als behoben gelten)."""
    counts = {"crit": 0, "warn": 0, "ok": 0, "info": 0, "error": 0, "skipped": 0}
    finds: List[List[str]] = []
    ran: List[str] = []
    for r in results or []:
        if not isinstance(r, dict):
            continue
        st = str(r.get("status") or "")
        counts[st] = counts.get(st, 0) + 1
        cid = _txt(r.get("id"), 60)
        if st in EXEC_STATUS and cid:
            ran.append(cid)
        for f in r.get("findings") or []:
            if isinstance(f, dict) and f.get("sev") in SEVS and len(finds) < MAX_FINDINGS:
                finds.append([cid, str(f["sev"]), _txt(f.get("title"), 90)])
    return {"ts": int(ts if ts is not None else time.time()), "site": _txt(site, 80), "label": _txt(label, 120), "cms": _txt(cms, 20),
            "version": _txt(version, 30), "counts": counts, "findings": finds, "ran": ran}


def record_run(base: str, entry: Dict[str, Any]) -> None:
    if not entry.get("site") or not (entry["counts"].get("ok", 0) + entry["counts"].get("crit", 0) + entry["counts"].get("warn", 0) + entry["counts"].get("info", 0)):
        return                                      # leerer oder abgebrochener Lauf ohne ein einziges Ergebnis
    with _LOCK:
        data = load(base)
        data["runs"].append(entry)
        save(base, data)


def record_action(base: str, site: str, label: str, aid: str, title: str, ok: bool, ts: Optional[float] = None) -> None:
    if not site:
        return
    with _LOCK:
        _record_action(base, site, label, aid, title, ok, ts)


def _record_action(base: str, site: str, label: str, aid: str, title: str, ok: bool, ts: Optional[float]) -> None:
    data = load(base)
    data["actions"].append({"ts": int(ts if ts is not None else time.time()), "site": _txt(site, 80), "label": _txt(label, 120), "id": _txt(aid, 40),
                            "title": _txt(title, 120), "ok": bool(ok)})
    save(base, data)


def compare(prev: Dict[str, Any], cur: Dict[str, Any]) -> Dict[str, Any]:
    """Zwei Prüfungen vergleichen: neu, behoben, unverändert. Behoben zählt nur, wenn die Prüfung beim zweiten Mal wirklich gelaufen ist."""
    a = {tuple(x) for x in prev.get("findings") or [] if isinstance(x, list) and len(x) == 3}
    b = {tuple(x) for x in cur.get("findings") or [] if isinstance(x, list) and len(x) == 3}
    ran = set(cur.get("ran") or [])
    fixed = sorted(x for x in a - b if x[0] in ran)
    unknown = sorted(x for x in a - b if x[0] not in ran)       # nicht mehr gemeldet, weil nicht geprüft
    new = sorted(b - a)
    return {"new": new, "fixed": fixed, "not_checked": unknown, "same": len(a & b), "prev_ts": prev.get("ts"), "cur_ts": cur.get("ts")}


def _level(counts: Dict[str, Any]) -> str:
    return "crit" if counts.get("crit") else "warn" if counts.get("warn") else "ok"


def _runs_of(data: Dict[str, Any], site: str) -> List[Dict[str, Any]]:
    return sorted([r for r in data["runs"] if r["site"] == site], key=lambda r: r["ts"])


def fixed_total(runs: List[Dict[str, Any]]) -> int:
    n = 0
    with_detail = [r for r in runs if "findings" in r and "ran" in r]
    for p, c in zip(with_detail, with_detail[1:]):
        n += len(compare(p, c)["fixed"])
    return n


def nachkontrolle(runs: List[Dict[str, Any]], acts: List[Dict[str, Any]], now: float) -> Optional[Dict[str, Any]]:
    """Stand der Nachkontrolle nach der letzten erfolgreichen Bereinigung: 'wartet' (zu früh), 'faellig' oder 'erledigt'.
    Eine Prüfung zählt als Nachkontrolle erst ab NACHKONTROLL_TAGE nach der Bereinigung; die Prüfung direkt danach ist die Erfolgskontrolle."""
    cl = [a for a in acts if a.get("ok") and a.get("id") in BEREINIGUNG]
    if not cl:
        return None
    ts = cl[-1]["ts"]
    due = ts + NACHKONTROLL_TAGE * 86400
    out: Dict[str, Any] = {"cleanup_ts": ts, "due_ts": due, "action": cl[-1].get("title", ""), "state": "wartet", "new": 0, "text": ""}
    after = [r for r in runs if r["ts"] >= due]
    if after:
        first = after[0]
        before = [r for r in runs if r["ts"] < ts]
        out.update(state="erledigt", check_ts=first["ts"])
        if before and "findings" in before[-1] and "findings" in first:
            out["new"] = len(compare(before[-1], first)["new"])
        out["text"] = ("Nachkontrolle am %s: seit vor der Bereinigung sind %d neue Funde dazugekommen." % (_day(first["ts"]), out["new"])) if out["new"] else \
                      "Nachkontrolle am %s: seit vor der Bereinigung ist nichts Neues aufgefallen." % _day(first["ts"])
    elif now >= due:
        out.update(state="faellig", text="Nachkontrolle fällig: Die Bereinigung (%s) war am %s. Prüfe die Seite jetzt noch einmal, damit auffällt, falls etwas zurückkommt." % (out["action"], _day(ts)))
    else:
        out["text"] = "Nachkontrolle ab %s empfohlen (%d Tage nach der Bereinigung)." % (_day(due), NACHKONTROLL_TAGE)
    return out


def _day(ts: float) -> str:
    return time.strftime("%d.%m.%Y", time.localtime(ts))


def dashboard(base: str, now: Optional[float] = None) -> Dict[str, Any]:
    """Alles, was das Dashboard anzeigt (nur lesend)."""
    now = float(now if now is not None else time.time())
    data = load(base)
    sites: List[Dict[str, Any]] = []
    for site in sorted({r["site"] for r in data["runs"] if r.get("site")}):
        runs = _runs_of(data, site)
        last = runs[-1]
        acts = sorted([a for a in data["actions"] if a["site"] == site], key=lambda a: a["ts"])
        backups = [a for a in acts if a["id"] == "backup_now" and a["ok"]]
        age_days = int((now - last["ts"]) // 86400)
        hints: List[str] = []
        if age_days >= STALE_DAYS:
            hints.append("Die letzte Prüfung ist %d Tage her." % age_days)
        if not backups:
            hints.append("Mit CLAUDIA wurde noch keine Sicherung angelegt.")
        elif (now - backups[-1]["ts"]) // 86400 >= STALE_DAYS:
            hints.append("Die letzte Sicherung mit CLAUDIA ist %d Tage alt." % int((now - backups[-1]["ts"]) // 86400))
        nk = nachkontrolle(runs, acts, now)
        if nk and nk["state"] == "faellig":
            hints.append(nk["text"])
        cmp_last = compare(runs[-2], runs[-1]) if len(runs) >= 2 and "findings" in runs[-2] and "findings" in runs[-1] else None
        sites.append({"site": site, "label": last.get("label") or site, "cms": last.get("cms", ""), "version": last.get("version", ""),
                      "last_ts": last["ts"], "age_days": age_days, "level": _level(last["counts"]), "counts": last["counts"], "runs": len(runs),
                      "trend": [{"ts": r["ts"], "crit": r["counts"].get("crit", 0), "warn": r["counts"].get("warn", 0)} for r in runs[-20:]],
                      "fixed": fixed_total(runs), "compare": cmp_last,
                      "actions_ok": len([a for a in acts if a["ok"]]), "actions_failed": len([a for a in acts if not a["ok"]]),
                      "last_backup": backups[-1]["ts"] if backups else 0, "hints": hints, "nachkontrolle": nk})
    sites.sort(key=lambda s: ({"crit": 0, "warn": 1, "ok": 2}.get(s["level"], 3), -s["last_ts"]))
    recent = sorted(data["actions"], key=lambda a: a["ts"], reverse=True)[:40]
    return {"sites": sites, "recent_actions": recent,
            "totals": {"sites": len(sites), "runs": len(data["runs"]), "fixed": sum(s["fixed"] for s in sites),
                       "actions_ok": len([a for a in data["actions"] if a["ok"]])}}


def delete_site(base: str, site: str) -> int:
    """Verlauf einer Seite löschen. Gibt die Anzahl gelöschter Einträge zurück."""
    with _LOCK:
        data = load(base)
        n = len(data["runs"]) + len(data["actions"])
        data["runs"] = [r for r in data["runs"] if r["site"] != site]
        data["actions"] = [a for a in data["actions"] if a["site"] != site]
        removed = n - len(data["runs"]) - len(data["actions"])
        if removed:
            save(base, data)
        return removed


# ------------------------------------------------------------------------------------------------ Export (CSV und Bericht)
def _cell(value: Any) -> str:
    """Eine CSV-Zelle. Texte stammen teils vom Server der Seite: Zeichen, mit denen Tabellenprogramme eine Formel beginnen, werden entschärft."""
    t = clean_line(str(value if value is not None else "")).replace('"', '""')
    if t[:1] in ("=", "+", "-", "@", "\t", "\r"):
        t = "'" + t
    return '"%s"' % t


def _stamp(ts: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(ts))


def export_csv(base: str, site: str = "") -> str:
    """Alle Prüfungen und Aktionen (oder nur die einer Seite) als CSV mit Semikolon, UTF-8."""
    data = load(base)
    rows = [";".join(_cell(x) for x in ("Art", "Zeit", "Seite", "CMS", "Version", "Kritisch", "Warnungen", "In Ordnung", "Aktion", "Ergebnis"))]
    items: List[Any] = [("p", r) for r in data["runs"] if not site or r["site"] == site] + [("a", a) for a in data["actions"] if not site or a["site"] == site]
    items.sort(key=lambda x: x[1]["ts"])
    for kind, r in items:
        if kind == "p":
            c = r.get("counts") or {}
            rows.append(";".join(_cell(x) for x in ("Prüfung", _stamp(r["ts"]), r.get("label") or r["site"], r.get("cms", ""), r.get("version", ""), c.get("crit", 0), c.get("warn", 0), c.get("ok", 0), "", "")))
        else:
            rows.append(";".join(_cell(x) for x in ("Aktion", _stamp(r["ts"]), r.get("label") or r["site"], "", "", "", "", "", r.get("title", ""), "erfolgreich" if r.get("ok") else "nicht erfolgreich")))
    return "﻿" + "\r\n".join(rows) + "\r\n"


def export_html(base: str, site: str, now: Optional[float] = None) -> str:
    """Bericht über eine Seite (für Kunden oder zur Ablage): Stand, Verlauf, Funde der letzten Prüfung, Aktionen, Nachkontrolle. Alles Maskierte ist HTML-sicher."""
    from html import escape as e
    d = dashboard(base, now)
    s = next((x for x in d["sites"] if x["site"] == site), None)
    if not s:
        return ""
    data = load(base)
    runs = _runs_of(data, site)
    acts = sorted([a for a in data["actions"] if a["site"] == site], key=lambda a: a["ts"])
    lvl = {"crit": "Kritische Funde", "warn": "Hinweise", "ok": "Keine Auffälligkeiten"}.get(s["level"], "")
    out = ["<!doctype html><html lang=\"de\"><head><meta charset=\"utf-8\"><title>%s</title>" % e("Bericht: " + s["label"]),
           "<style>body{font:15px/1.5 system-ui,sans-serif;max-width:860px;margin:2em auto;padding:0 1em;color:#222}table{border-collapse:collapse;width:100%}"
           "td,th{border:1px solid #ccc;padding:4px 8px;text-align:left}th{background:#f3f3f3}.crit{color:#b00020}.warn{color:#8a5a00}small{color:#666}</style></head><body>",
           "<h1>%s</h1><p><strong>%s</strong> · %s %s · letzte Prüfung %s</p>" % (e(s["label"]), e(lvl), e(s["cms"]), e(s["version"]), e(_stamp(s["last_ts"]))),
           "<p>%d Prüfungen, %d Funde behoben, %d Aktionen ausgeführt.</p>" % (s["runs"], s["fixed"], s["actions_ok"])]
    if s["hints"]:
        out.append("<h2>Hinweise</h2><ul>%s</ul>" % "".join("<li>%s</li>" % e(h) for h in s["hints"]))
    if s.get("nachkontrolle"):
        out.append("<p><strong>Nachkontrolle:</strong> %s</p>" % e(s["nachkontrolle"]["text"]))
    out.append("<h2>Verlauf der Prüfungen</h2><table><tr><th>Zeit</th><th>Kritisch</th><th>Warnungen</th><th>In Ordnung</th></tr>")
    for r in runs[-30:]:
        c = r.get("counts") or {}
        out.append("<tr><td>%s</td><td>%d</td><td>%d</td><td>%d</td></tr>" % (e(_stamp(r["ts"])), c.get("crit", 0), c.get("warn", 0), c.get("ok", 0)))
    out.append("</table>")
    finds = runs[-1].get("findings") or []
    if finds:
        out.append("<h2>Funde der letzten Prüfung</h2><ul>%s</ul>" % "".join('<li class="%s">%s</li>' % (e(f[1]) if f[1] in SEVS else "", e(f[2])) for f in finds[:100]))
    if acts:
        out.append("<h2>Ausgeführte Aktionen</h2><table><tr><th>Zeit</th><th>Aktion</th><th>Ergebnis</th></tr>")
        for a in acts[-40:]:
            out.append("<tr><td>%s</td><td>%s</td><td>%s</td></tr>" % (e(_stamp(a["ts"])), e(a.get("title", "")), "erfolgreich" if a.get("ok") else "nicht erfolgreich"))
        out.append("</table>")
    out.append("<p><small>Erstellt von CLAUDIA am %s aus dem lokal notierten Verlauf. Enthält keine Passwörter und keine Dateiinhalte.</small></p></body></html>" % e(_stamp(now if now is not None else time.time())))
    return "".join(out)
