"""Berichte und Export: HTML, Text, JSON, Rohdaten, phpMyAdmin-Abfragen und ZIP für die Auswertung.

Die Ergebnisse sind bereits beim Sammeln bereinigt (Zugangsdaten aus der configuration.php unkenntlich,
IP-Adressen auf Wunsch gekürzt). Hier wird zusätzlich alles, was dem Programm als Passwort bekannt ist,
noch einmal entfernt (Sicherheitsnetz), bevor etwas auf die Festplatte kommt.
"""
from __future__ import annotations

import html
import io
import json
import os
import re
import time
import zipfile
from datetime import datetime
from typing import Any, Dict, List, Tuple

from . import cms as cmsmod, evidence

from . import APP_NAME, __version__
from .icons import svg as icon_svg
from . import i18n
from .model import SEV_LABEL
from . import actionplan, hoster
from .registry import REGISTRY, cluster_map, groups_for, load_all
from .summary import summarize
from .util import safe_name

SEV_RANK = {"crit": 0, "warn": 1, "error": 2, "info": 3, "skipped": 4, "ok": 5}


# ----------------------------------------------------------------------------- Zusammenstellung
def build_bundle(results: List[Dict[str, Any]], plan: List[str], settings: Dict[str, Any], info: Dict[str, Any],
                 elapsed: float, cancelled: bool, advisories_stand: str, secrets: List[str], lang: str = "de") -> Dict[str, Any]:
    load_all()
    now = datetime.now().astimezone()
    cleaned = [_scrub_obj(r, secrets) for r in results]
    lang = lang if i18n.valid(lang) else "de"
    summary = summarize(cleaned)
    cms = cmsmod.known(str(info.get("cms") or ""))
    action_plan = actionplan.build_plan(cleaned, [], cms, cluster_map(cms))          # nur noch als Daten (Reihenfolge der Bereiche); im Bericht wird kein Maßnahmenplan mehr angezeigt
    hoster_part = hoster.build(cleaned, str(settings.get("url", "")), str(info.get("host", "")))
    if lang != i18n.SOURCE:
        cleaned = i18n.tr_obj(cleaned, lang)                 # Texte der Befunde in die gewählte Sprache (Rohdaten bleiben unberührt)
        summary = i18n.tr_obj(summary, lang)
        action_plan = i18n.tr_obj(action_plan, lang)
        hoster_part = i18n.tr_obj(hoster_part, lang)
    return {
        "meta": {
            "sprache": lang,
            "programm": "%s %s" % (APP_NAME, __version__),
            "erstellt": now.strftime("%Y-%m-%d %H:%M:%S %z"),
            "dauer_sekunden": round(elapsed, 1),
            "abgebrochen": bool(cancelled),
            "vergleichsdaten_stand": advisories_stand,
            "server": info.get("host", ""),
            "system": cmsmod.name_of(cms),
            "joomla_verzeichnis": settings.get("site_dir", ""),
            "joomla_version": info.get(cmsmod.profile(cms)["version_key"]) or "",
            "php_kommandozeile": info.get("php", ""),
            "datenbank_programm_vorhanden": bool(info.get("mysql")),
            "webadresse": settings.get("url", ""),
            "ips_gekuerzt": bool(settings.get("mask_ips", True)),
            "eigene_erlaubte_domains": settings.get("allow_hosts", []),
            "test_optionen": settings.get("opts", {}),
            "geplante_tests": plan,
        },
        "summary": summary,
        "massnahmenplan": action_plan,
        "hoster": hoster_part,
        "results": cleaned,
    }


def _tr(b: Dict[str, Any]):
    lang = (b.get("meta") or {}).get("sprache", "de")
    return lambda text: i18n.tr(text, lang)


def _scrub_text(text: str, secrets: List[str]) -> str:
    for s in secrets:
        if s and len(s) >= 3:
            text = text.replace(s, "***")
    return text


def _scrub_obj(obj: Any, secrets: List[str]) -> Any:
    if isinstance(obj, str):
        return _scrub_text(obj, secrets)
    if isinstance(obj, list):
        return [_scrub_obj(x, secrets) for x in obj]
    if isinstance(obj, dict):
        return {k: _scrub_obj(v, secrets) for k, v in obj.items()}
    return obj


def _sorted(results: List[Dict[str, Any]], plan: List[str]) -> List[Dict[str, Any]]:
    idx = {i: n for n, i in enumerate(plan)}
    return sorted(results, key=lambda r: (SEV_RANK.get(r["status"], 9), idx.get(r["id"], 999)))


def _group_title(gid: str, cms: str = "joomla") -> str:
    return next((g[1] for g in groups_for(cms) if g[0] == gid), gid)


# ----------------------------------------------------------------------------- JSON
def render_json(b: Dict[str, Any]) -> str:
    slim = dict(b)
    slim["results"] = []
    for r in b["results"]:
        x = {k: v for k, v in r.items() if k != "raw"}
        x["rohdaten_dateien"] = [raw_path(r["id"], n) for n in (r.get("raw") or {})]
        slim["results"].append(x)
    return json.dumps(slim, ensure_ascii=False, indent=2)


# ----------------------------------------------------------------------------- Text
def render_txt(b: Dict[str, Any]) -> str:
    m, s = b["meta"], b["summary"]
    T = _tr(b)
    sysn = m.get("system", "Joomla")
    out: List[str] = []
    add = out.append
    add("%s - %s" % (APP_NAME, T("Bericht")))
    add("=" * 64)
    add("%-20s%s" % (T("Erstellt") + ":", m["erstellt"]))
    add("%-20s%s" % (T("Programm") + ":", T("%s (Vergleichsdaten vom %s)") % (m["programm"], m["vergleichsdaten_stand"])))
    add("%-20s%s" % ("Server:", m["server"] or T("(ohne Serverzugang)")))
    add("%-20s%s" % (T("%s-Verzeichnis") % sysn + ":", m["joomla_verzeichnis"]))
    add("%-20s%s" % (T("%s-Version") % sysn + ":", m["joomla_version"] or T("unbekannt")))
    add("%-20s%s" % (T("Webseite") + ":", m["webadresse"] or "-"))
    add("%-20s%s s%s" % (T("Laufzeit") + ":", m["dauer_sekunden"], "  (%s)" % T("ABGEBROCHEN") if m["abgebrochen"] else ""))
    add("%-20s%s" % (T("IP-Adressen") + ":", T("gekürzt") if m["ips_gekuerzt"] else T("vollständig")))
    add("")
    add("%s: %s" % (T("GESAMTBEWERTUNG"), s["headline"]))
    add(s["text"])
    c = s["counts"]
    add(T("Kritisch: %d | Bitte prüfen: %d | Hinweis: %d | In Ordnung: %d | Übersprungen: %d | Fehlgeschlagen: %d") % (
        c["crit"], c["warn"], c["info"], c["ok"], c["skipped"], c["error"]))
    add(s["caveat"])
    add("")
    ho = b.get("hoster") or {}
    if ho.get("items"):
        add(T("NUR BEIM HOSTER ÄNDERBAR"))
        add(T("Diese Punkte kann nur dein Hoster ändern. Unten steht ein fertiger Text für eine E-Mail an ihn."))
        for i, it in enumerate(ho["items"], 1):
            add("%d. [%s] %s" % (i, T(SEV_LABEL.get(it["sev"], it["sev"])), it["title"]))
            add("   %s" % it["ask"])
        add("")
        add(T("E-Mail an den Hoster") + ":")
        add("%s: %s" % (T("Betreff"), ho["mail"]["subject"]))
        for ln in ho["mail"]["body"].split("\n"):
            add("   " + ln if ln else "")
        add("")
    for r in _sorted(b["results"], m["geplante_tests"]):
        add("-" * 64)
        add("[%s] %s" % (T(SEV_LABEL.get(r["status"], r["status"])).upper(), r["title"]))
        add("    %s: %s | %s: %s | %s: %s s" % (T("Gruppe"), T(_group_title(r["group"], cmsmod.by_name(m.get("system", "")))), T("Test-ID"), r["id"], T("Dauer"), r["seconds"]))
        if r.get("message"):
            add("    %s: %s" % (T("Hinweis zum Test"), r["message"]))
        for f in r["findings"]:
            add("  * [%s] %s" % (T("Erläuterung" if f.get("context") else SEV_LABEL[f["sev"]]), f["title"]))
            if f.get("detail"):
                add("      %s" % f["detail"])
            for it in f.get("items", []):
                add("        - %s" % it)
            for ev in f.get("evidence", []):
                add("      %s:" % T("Code"))
                for ln in evidence.render_txt(ev):
                    add("        | %s" % ln)
            if f.get("hint"):
                add("      %s: %s" % (T("Empfehlung"), f["hint"]))
        raws = list((r.get("raw") or {}).keys())
        if raws:
            add("    %s: " % T("Rohdaten") + ", ".join(raw_path(r["id"], n) for n in raws))
    add("-" * 64)
    return "\n".join(out) + "\n"


# ----------------------------------------------------------------------------- HTML
def flag_font_css() -> str:
    """Die Flaggen-Schrift (Twemoji Country Flags, CC BY 4.0) einbetten, damit der Bericht ohne weitere Dateien lesbar bleibt."""
    import base64
    try:
        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "web", "TwemojiCountryFlags.woff2"), "rb") as fh:
            b64 = base64.b64encode(fh.read()).decode("ascii")
    except OSError:
        return ""
    return ("@font-face{font-family:'Twemoji Country Flags';src:url(data:font/woff2;base64,%s) format('woff2');unicode-range:U+1F1E6-1F1FF}"
            "body{font-family:'Twemoji Country Flags','Segoe UI',system-ui,sans-serif}" % b64)


def ev_html(ev: Dict[str, Any], esc) -> str:
    """Fundstelle als schwarzes Codefenster mit grünem Code; die Treffer-Stelle ist rot markiert."""
    head = ("%s, Zeile %s" % (ev["file"], ev["line"])) if ev.get("line") else ev["file"]
    if ev.get("note"):
        head += "  (%s)" % ev["note"]
    rows = []
    for c in ev["code"]:
        t = c["t"]
        if c.get("hit"):
            a, b = c["hit"]
            t = esc(t[:a]) + "<mark>" + esc(t[a:b]) + "</mark>" + esc(t[b:])
        else:
            t = esc(t)
        rows.append("<span class='ln'>%s</span>%s" % ("" if ev.get("kind") == "db" else c["n"], t))
    return "<details class='code' open><summary>%s</summary><pre>%s</pre></details>" % (esc(head), "\n".join(rows))


_CSS = """
:root{--ink:#11212e;--muted:#536576;--line:#cdd8de;--bg:#eef2f4;--ok:#2b8a58;--info:#3a6db0;--warn:#d28a00;--crit:#c53a2b;--skip:#8896a3}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 "Segoe UI",system-ui,sans-serif}
main{max-width:980px;margin:0 auto;padding:28px 20px 60px}h1{font:600 30px/1.2 Bahnschrift,"Segoe UI",sans-serif;margin:0 0 6px}
h2{font:600 18px Bahnschrift,"Segoe UI",sans-serif;margin:0}.muted{color:var(--muted)}
.card{background:#fff;border:1px solid var(--line);border-radius:12px;padding:18px 20px;margin-top:16px}
.strip{display:flex;gap:4px;padding:8px 10px;background:#f1f5f7;border:1px solid var(--line);border-radius:999px;margin-top:14px}
.pad{flex:1;max-width:30px;height:28px;border-radius:5px;background:var(--line)}
.pad.ok{background:var(--ok)}.pad.info{background:var(--info)}.pad.warn{background:var(--warn)}.pad.crit{background:var(--crit)}.pad.error,.pad.skipped{background:var(--skip)}
table.meta{border-collapse:collapse;width:100%}table.meta td{padding:4px 12px 4px 0;vertical-align:top}table.meta td:first-child{color:var(--muted);white-space:nowrap}
.res{border-left:6px solid var(--line)}.res.ok{border-left-color:var(--ok)}.res.info{border-left-color:var(--info)}.res.warn{border-left-color:var(--warn)}.res.crit{border-left-color:var(--crit)}.res.error,.res.skipped{border-left-color:var(--skip)}
.ic{width:14px;height:14px;vertical-align:-2px;margin-right:5px;fill:none;stroke:currentColor;stroke-width:2;stroke-linecap:round;stroke-linejoin:round}
.badge{display:inline-block;font-size:12px;font-weight:600;padding:2px 9px;border-radius:999px;background:#e9eef1;margin-right:8px}
.badge.crit{background:#fbe2de;color:#8f2418}.badge.warn{background:#fbefd2;color:#7d5200}.badge.info{background:#e1ebf8;color:#264f86}.badge.ok{background:#dff2e7;color:#17623a}
.f{padding-left:12px;border-left:3px solid var(--line);margin-top:12px}.f.crit{border-color:var(--crit)}.f.warn{border-color:var(--warn)}.f.info{border-color:var(--info)}.f.ok{border-color:var(--ok)}
.f h3{margin:0;font-size:15px}.f p{margin:3px 0 0;color:var(--muted)}
ul.items{margin:8px 0 0;padding:8px 12px;list-style:none;background:#f1f5f7;border-radius:8px;font:12px/1.5 Consolas,"Cascadia Mono",monospace}
ul.items li{word-break:break-all}details.code{margin:8px 0;border-radius:8px;background:#0a0d0b;border:1px solid #1f2a22}details.code summary{cursor:pointer;color:#9fe3b3;padding:6px 12px;font:12px Consolas,monospace}details.code pre{margin:0;padding:8px 12px 10px;color:#3ddc84;font:12px/1.5 Consolas,"Cascadia Mono",monospace;white-space:pre-wrap;word-break:break-all}details.code mark{background:#c62828;color:#fff;border-radius:3px;padding:0 2px}details.code .ln{color:#5d7a66;display:inline-block;min-width:44px;margin-right:10px;text-align:right;user-select:none}.stars{display:inline-block;margin:0 6px 0 4px;font-size:16px;line-height:1;letter-spacing:1px;color:transparent;background:linear-gradient(90deg,#f2a900 var(--v),#cfd8dc var(--v));-webkit-background-clip:text;background-clip:text}.rnum{margin-right:6px}.adv{margin-top:8px;padding:8px 12px;background:#dcf0f3;border-radius:8px}
details.what{margin-top:12px}details.what summary{cursor:pointer;color:#0b6e7f}.caveat{border-left:3px solid var(--line);padding:8px 14px;color:var(--muted);margin-top:14px}
@media print{body{background:#fff}.card{break-inside:avoid}}
"""


def render_html(b: Dict[str, Any]) -> str:
    load_all()
    e = html.escape
    m, s = b["meta"], b["summary"]
    T = _tr(b)
    sysn = m.get("system", "Joomla")
    cms = cmsmod.by_name(sysn)
    lang = m.get("sprache", "de")
    parts: List[str] = []
    add = parts.append
    add("<!doctype html><html lang='%s'>" % e(lang) + "<head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>")
    add("<title>%s - %s</title><style>%s</style></head><body><main>" % (e(APP_NAME), e(T("Bericht")), _CSS))
    add("<h1>%s</h1><p class='muted'>%s</p>" % (e(s["headline"]), e(s["text"])))
    plan = m["geplante_tests"]
    by_id = {r["id"]: r for r in b["results"]}
    add("<div class='strip' role='img' aria-label='%s'>" % e(T("Prüfstreifen")))
    for i in plan:
        r = by_id.get(i)
        title = T(REGISTRY[i].view(cms)["title"] if i in REGISTRY else i)
        add("<span class='pad %s' title='%s'></span>" % (e(r["status"]) if r else "", e(title)))
    add("</div><p class='caveat'>%s</p>" % e(s["caveat"]))
    rows = [(T("Erstellt"), m["erstellt"]), (T("Programm"), T("%s (Vergleichsdaten vom %s)") % (m["programm"], m["vergleichsdaten_stand"])),
            ("Server", m["server"] or T("(ohne Serverzugang)")), (T("%s-Verzeichnis") % sysn, m["joomla_verzeichnis"]),
            (T("%s-Version") % sysn, m["joomla_version"] or T("unbekannt")), (T("Webseite"), m["webadresse"] or "-"),
            (T("Laufzeit"), "%s s%s" % (m["dauer_sekunden"], " (%s)" % T("abgebrochen") if m["abgebrochen"] else "")),
            (T("IP-Adressen"), T("gekürzt") if m["ips_gekuerzt"] else T("vollständig"))]
    add("<div class='card'><table class='meta'>%s</table></div>" % "".join("<tr><td>%s</td><td>%s</td></tr>" % (e(k), e(str(v))) for k, v in rows))
    c = s["counts"]
    add("<div class='card'><b>%s:</b> %s</div>" % (e(T("Übersicht")), e(T("%d kritisch, %d bitte prüfen, %d Hinweis, %d in Ordnung, %d übersprungen, %d fehlgeschlagen") % (
        c["crit"], c["warn"], c["info"], c["ok"], c["skipped"], c["error"]))))
    ho = b.get("hoster") or {}
    if ho.get("items"):
        add("<div class='card'><h2>%s</h2><p class='muted'>%s</p><ol class='items'>" % (e(T("Nur beim Hoster änderbar")), e(T("Diese Punkte kann nur dein Hoster ändern. Unten steht ein fertiger Text für eine E-Mail an ihn."))))
        for it in ho["items"]:
            add("<li><b>%s:</b> %s<br>%s</li>" % (e(T(SEV_LABEL.get(it["sev"], it["sev"]))), e(it["title"]), e(it["ask"])))
        add("</ol><h3>%s</h3><p><b>%s:</b> %s</p><pre>%s</pre></div>" % (e(T("E-Mail an den Hoster")), e(T("Betreff")), e(ho["mail"]["subject"]), e(ho["mail"]["body"])))
    for r in _sorted(b["results"], plan):
        d = REGISTRY.get(r["id"])
        add("<section class='card res %s'><h2><span class='badge %s'>%s%s</span>%s</h2><div class='muted'>%s%s</div>" % (
            e(r["status"]), e(r["status"]), icon_svg(r["status"]), e(T(SEV_LABEL.get(r["status"], r["status"]))), e(r["title"]), icon_svg(r["group"]), e(T(_group_title(r["group"], cms)))))
        if r.get("message"):
            add("<p><b>%s:</b> %s</p>" % (e(T("Zum Test")), e(r["message"])))
        for f in r["findings"]:
            add("<div class='f %s'><h3><span class='badge %s'>%s%s</span>%s</h3>" % (e(f["sev"]), e(f["sev"]), icon_svg(f["sev"]), e(T("Erläuterung" if f.get("context") else SEV_LABEL[f["sev"]])), e(f["title"])))
            if f.get("detail"):
                add("<p>%s</p>" % e(f["detail"]))
            if f.get("items"):
                add("<ul class='items'>%s</ul>" % "".join("<li>%s</li>" % rated(x) for x in f["items"]))
            for ev in f.get("evidence", []):
                add(ev_html(ev, e))
            if f.get("hint"):
                add("<div class='adv'><b>%s:</b> %s</div>" % (e(T("Empfehlung")), e(f["hint"])))
            add("</div>")
        if d:
            add("<details class='what'><summary>%s</summary><p><b>%s:</b> %s</p><p><b>%s:</b> %s</p><p><b>%s:</b> %s</p></details>" % (
                e(T("Was macht dieser Test?")), e(T("Was passiert")), e(T(d.what)), e(T("Warum")), e(T(d.why)), e(T("Was wird gelesen")), e(T(d.reads))))
        add("<p class='muted' style='font-size:12.5px'>%s</p></section>" % e(T("Test-ID %s, Dauer %s s") % (r["id"], r["seconds"])))
    add("</main></body></html>")
    out = "".join(parts)
    if re.search("[\U0001F1E6-\U0001F1FF]", out):
        out = out.replace("</style>", flag_font_css() + "</style>", 1)         # Windows zeigt Flaggen-Emoji sonst nur als Buchstaben
    return out


# ----------------------------------------------------------------------------- Rohdaten, SQL, Dateien
def raw_path(check_id: str, name: str) -> str:
    return "rohdaten/%s__%s.txt" % (safe_name(check_id), safe_name(name))


def raw_files(b: Dict[str, Any]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for r in b["results"]:
        for name, text in (r.get("raw") or {}).items():
            if name == "sql_manuell":
                continue        # kommt als fertige .sql-Datei
            out[raw_path(r["id"], name)] = text
    return out


RATING_RE = re.compile(r"(\d+(?:[.,]\d+)?) (?:von|of) 5 (?:Sternen|stars)")


def rated(text: str) -> str:
    """Zeile mit Bewertung: die Zahl der Sterne wird als Sternreihe gezeichnet, der Rest bleibt (maskierter) Text."""
    e = html.escape
    m = RATING_RE.search(text)
    if not m:
        return e(text)
    v = max(0.0, min(5.0, float(m.group(1).replace(",", "."))))
    return "%s<span class='stars' style='--v:%d%%' title='%s / 5'>&#9733;&#9733;&#9733;&#9733;&#9733;</span><b class='rnum'>%s/5</b>%s" % (
        e(text[:m.start()]), round(v * 20), e(m.group(1)), e(m.group(1)), e(text[m.end():]))


def sql_file(b: Dict[str, Any]) -> str:
    chunks = [text for r in b["results"] for name, text in (r.get("raw") or {}).items() if name == "sql_manuell"]
    if not chunks:
        return ""
    seen, uniq = set(), []
    for t in chunks:
        if t not in seen:
            seen.add(t)
            uniq.append(t)
    return "\n\n".join(uniq) + "\n"


def claude_readme(b: Dict[str, Any]) -> str:
    m = b["meta"]
    T = _tr(b)
    return T(
        "Ergebnisse des %s (%s)\n"
        "Erstellt: %s | Server: %s | %s: %s\n\n"
        "Inhalt:\n"
        "  bericht.txt        lesbare Zusammenfassung aller Tests mit Befunden und Empfehlungen\n"
        "  ergebnisse.json    dieselben Ergebnisse maschinenlesbar\n"
        "  rohdaten/          Rohausgaben einzelner Tests (z. B. Trefferzeilen, Dateilisten)\n"
        "  phpmyadmin_abfragen.sql (falls vorhanden)  Abfragen, die von Hand im phpMyAdmin laufen müssen\n\n"
        "Datenschutz: Es sind keine Passwörter enthalten. Zugangsdaten aus der configuration.php bzw. wp-config.php sind unkenntlich "
        "gemacht, IP-Adressen sind %s.\n\n"
        "Bitte auswerten: Welche Befunde sind echte Hinweise auf eine Kompromittierung, welche sind harmlos? "
        "Was ist die Reihenfolge der nächsten Schritte? Was fehlt noch (z. B. Zugriffsprotokolle des Hosters)?\n"
    ) % (APP_NAME, m["programm"], m["erstellt"], m["server"] or "-", m.get("system", "Joomla"), m["joomla_version"] or T("unbekannt"),
         T("gekürzt") if m["ips_gekuerzt"] else T("NICHT gekürzt"))


def all_files(b: Dict[str, Any]) -> Dict[str, str]:
    files = {"bericht.html": render_html(b), "bericht.txt": render_txt(b), "ergebnisse.json": render_json(b)}
    files.update(raw_files(b))
    sql = sql_file(b)
    if sql:
        files["phpmyadmin_abfragen.sql"] = sql
    return files


def claude_zip(b: Dict[str, Any]) -> bytes:
    files = all_files(b)
    files.pop("bericht.html", None)      # der Text reicht für die Auswertung; HTML ist für dich zum Lesen
    files["LIES_MICH.txt"] = claude_readme(b)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, text in files.items():
            z.writestr(name, text.encode("utf-8"))
    return buf.getvalue()


def write_all(b: Dict[str, Any], base_dir: str) -> Tuple[str, List[Dict[str, Any]]]:
    """Schreibt alle Dateien in einen neuen Unterordner und liefert (Ordner, Dateiliste)."""
    host = safe_name(b["meta"]["server"] or "ohne-server", "bericht")
    stamp = time.strftime("%Y%m%d-%H%M%S")
    outdir = os.path.join(base_dir, "%s_%s" % (host, stamp))
    os.makedirs(outdir, exist_ok=True)
    listing: List[Dict[str, Any]] = []
    for rel, text in all_files(b).items():
        path = os.path.join(outdir, *rel.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
        listing.append({"name": rel, "size": len(text.encode("utf-8"))})
    zpath = os.path.join(outdir, "fuer_claude.zip")
    data = claude_zip(b)
    with open(zpath, "wb") as fh:
        fh.write(data)
    listing.append({"name": "fuer_claude.zip", "size": len(data)})
    return outdir, listing
