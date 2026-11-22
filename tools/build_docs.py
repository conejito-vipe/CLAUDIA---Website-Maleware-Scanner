#!/usr/bin/env python3
"""Erzeugt die eigenständige Dokumentation als EINE HTML-Datei (ohne Internet nutzbar): Handbuch, Änderungsverlauf, Prüfkatalog,
Suche und Sprachumschaltung. Gleiche Quellen und gleicher Anzeigecode wie das Hilfe-Fenster im Programm.

  python tools/build_docs.py [Ausgabedatei]      Standard: CLAUDIA_Dokumentation.html im Hauptordner"""
from __future__ import annotations

import json
import os
import sys
from typing import Any, Dict, List

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from claudia import __version__, actions, helpdocs, i18n, techdoc  # noqa: E402
from claudia import cms as cmsmod
from claudia.registry import load_all, ordered  # noqa: E402

PAGE = """<!doctype html>
<html lang="%(lang)s"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark"><title>CLAUDIA - %(title)s %(version)s</title>
<style>
:root{--line:#cdd8de;--muted:#536576;--accent:#0b6e7f;--bg:#eef2f4;--card:#fff;--ink:#11212e}
@media (prefers-color-scheme:dark){:root{--line:#2c3b47;--muted:#9fb0bd;--accent:#4cc3d6;--bg:#0f1a22;--card:#16232d;--ink:#e6eef3}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 "Segoe UI",system-ui,sans-serif}
.wrap{max-width:1180px;margin:0 auto;padding:18px 16px 40px}.bar{display:flex;align-items:center;gap:12px;margin-bottom:12px}
.bar b{font:600 22px Bahnschrift,"Segoe UI",sans-serif;flex:1}.lang{border:1px solid var(--line);background:var(--card);border-radius:8px;padding:4px 6px;cursor:pointer;display:flex}
.lang.on{outline:2px solid var(--accent)}.lang svg{width:30px;height:20px;display:block}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;overflow:hidden;min-height:70vh;display:flex;flex-direction:column}
.docs{flex:1;height:auto}
.foot{margin-top:14px;font-size:12.5px;color:var(--muted)}
%(docscss)s
@media print{.bar .lang,.docs-q,.docs-tabs{display:none}.card{border:0}}
</style></head><body><div class="wrap">
<div class="bar"><b>CLAUDIA %(version)s</b><span id="flags"></span></div>
<div class="card"><div id="host"></div></div>
<p class="foot">%(foot)s</p></div>
<script>%(docsjs)s</script>
<script>
const DATA=%(data)s, FLAGS=%(flags)s;
let cur=%(cur)s;
function show(code){cur=code;document.documentElement.lang=code;
  const f=document.getElementById("flags");f.replaceChildren();
  for(const c of Object.keys(DATA)){const b=document.createElement("button");b.className="lang"+(c===code?" on":"");b.type="button";b.title=FLAGS[c].name;b.setAttribute("aria-label",FLAGS[c].name);b.innerHTML=FLAGS[c].flag||c.toUpperCase();b.onclick=()=>show(c);f.append(b);}
  window.ClaudiaDocs.mount(document.getElementById("host"),DATA[code],{});}
show(cur);
</script></body></html>
"""


def checks_for(lang: str) -> List[Dict[str, Any]]:
    load_all()
    out: List[Dict[str, Any]] = []
    for cms in cmsmod.PROFILES:
        for c in ordered(cms):
            d = c.public(cms)
            out.append({"cms": cms, "id": d["id"], "title": d["title"], "summary": d["summary"], "what": d["what"], "why": d["why"], "reads": d["reads"], "load": d.get("load", "")})
    return out if lang == i18n.SOURCE else i18n.tr_obj(out, lang)


def actions_for(lang: str) -> List[Dict[str, Any]]:
    out = actions.catalog()
    return out if lang == i18n.SOURCE else i18n.tr_obj(out, lang)


def build(out_path: str) -> str:
    langs = helpdocs.available()
    data = {code: dict(helpdocs.payload(code, __version__, checks_for(code), actions_for(code)), tech=techdoc.payload(code)) for code in langs}
    flags = {code: {"name": (i18n.read_file(code).get("_meta") or {}).get("name", code), "flag": (i18n.read_file(code).get("_meta") or {}).get("flag", "")} for code in langs}
    docscss = open(os.path.join(ROOT, "claudia", "web", "docs.css"), encoding="utf-8").read()
    docsjs = open(os.path.join(ROOT, "claudia", "web", "docs.js"), encoding="utf-8").read().replace("</script", "<\\/script")
    default = "de" if "de" in langs else langs[0]
    page = PAGE % {
        "lang": default, "title": "Dokumentation / Documentation", "version": __version__,
        "foot": "Freeware, kostenlos und ohne jegliche Gewährleistung oder Erfolgsgarantie. / Freeware, free of charge and without any warranty or guarantee of success.",
        "docscss": docscss, "docsjs": docsjs, "data": json.dumps(data, ensure_ascii=False).replace("</", "<\\/"),
        "flags": json.dumps(flags, ensure_ascii=False).replace("</", "<\\/"), "cur": json.dumps(default),
    }
    with open(out_path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(page)
    return out_path


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "CLAUDIA_Dokumentation.html")
    print(build(target))
