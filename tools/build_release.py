#!/usr/bin/env python3
"""Baut das Release: CHANGELOG.md und RELEASE_NOTES.md aus claudia/docs/aenderungen.*.txt, PRUEFSUMMEN.txt, CLAUDIA_Dokumentation.html
und die ZIP-Datei CLAUDIA_v<Version>.zip (ohne Tests-Zwischendateien).

  python tools/build_release.py [Zielordner]        Standard: Ordner über dem Projekt
  python tools/build_release.py --check             nur prüfen (Version, CHANGELOG.md aktuell), nichts schreiben"""
from __future__ import annotations

import hashlib
import os
import sys
import zipfile
from typing import List

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tools"))
from claudia import __version__, helpdocs  # noqa: E402

SKIP_DIRS = {"__pycache__", ".venv", ".git", "dist", "build", "Output", ".hypothesis", ".pytest_cache", ".ruff_cache", ".mypy_cache"}
SKIP_FILES = {"PRUEFSUMMEN.txt"}


def changelog_md(lang: str = "en") -> str:
    out = ["# Changelog" if lang == "en" else "# Änderungsverlauf", "",
           "Generated from `claudia/docs/aenderungen.%s.txt` (do not edit by hand)." % lang if lang == "en" else
           "Erzeugt aus `claudia/docs/aenderungen.%s.txt` (nicht von Hand ändern)." % lang, ""]
    labels = {"what": "What", "why": "Why", "how": "How"} if lang == "en" else {"what": "Was", "why": "Warum", "how": "Wie"}
    for r in helpdocs.changelog(lang):
        out.append("## %s%s%s" % (r["version"], " (%s)" % r["date"] if r["date"] else "", " - " + r["title"] if r["title"] else ""))
        for i in r["items"]:
            out += ["", "### " + i["title"]]
            out += ["- **%s:** %s" % (labels[k], i[k]) for k in ("what", "why", "how") if i[k]]
        out.append("")
    return "\n".join(out) + "\n"


def release_notes(lang: str = "en") -> str:
    rel = helpdocs.changelog(lang)[0]
    head = "# CLAUDIA %s" % rel["version"] + (" - " + rel["title"] if rel["title"] else "")
    return head + "\n\n" + "\n".join("- **%s**: %s" % (i["title"], i["what"]) for i in rel["items"]) + "\n"


def files() -> List[str]:
    out = []
    for d, dirs, fs in os.walk(ROOT):
        dirs[:] = [x for x in dirs if x not in SKIP_DIRS]
        for f in fs:
            if f.endswith(".pyc") or f in SKIP_FILES or f.startswith("CLAUDIA_v"):
                continue
            out.append(os.path.relpath(os.path.join(d, f), ROOT).replace(os.sep, "/"))
    return sorted(out)


def add_file(z: zipfile.ZipFile, src: str, arc: str) -> None:
    """Datei ins Paket legen. Startdatei und Shell-Skripte bekommen das Ausführrecht (der Mac braucht es für den Doppelklick auf start.command)."""
    zi = zipfile.ZipInfo.from_file(src, arc)
    zi.compress_type = zipfile.ZIP_DEFLATED
    zi.external_attr = (0o100000 | (0o755 if arc.endswith((".command", ".sh")) else 0o644)) << 16
    with open(src, "rb") as fh:
        z.writestr(zi, fh.read())


def write(path: str, text: str) -> None:
    with open(os.path.join(ROOT, path), "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)


def main(argv: List[str]) -> int:
    if "--check" in argv:
        cur = open(os.path.join(ROOT, "CHANGELOG.md"), encoding="utf-8").read() if os.path.exists(os.path.join(ROOT, "CHANGELOG.md")) else ""
        ok = cur == changelog_md("en") and helpdocs.changelog("de")[0]["version"] == __version__
        print("OK" if ok else "CHANGELOG.md veraltet oder Version passt nicht: python tools/build_release.py")
        return 0 if ok else 1
    target = next((a for a in argv[1:] if not a.startswith("-")), os.path.dirname(ROOT))
    import count_loc
    count_loc.main(["--write"])                      # Zeilen reinen Python-Codes für die Fußzeile (claudia/loc.json)
    write("CHANGELOG.md", changelog_md("en"))
    write("CHANGELOG.de.md", changelog_md("de"))
    write("RELEASE_NOTES.md", release_notes("en"))
    import build_docs
    build_docs.build(os.path.join(ROOT, "CLAUDIA_Dokumentation.html"))
    names = files()
    lines = ["# SHA-256-Pruefsummen aller Dateien (pruefen.bat vergleicht sie). Erstellt zusammen mit dem Paket."]
    for n in names:
        lines.append("%s  %s" % (hashlib.sha256(open(os.path.join(ROOT, n), "rb").read()).hexdigest(), n))
    write("PRUEFSUMMEN.txt", "\n".join(lines) + "\n")
    out = os.path.join(target, "CLAUDIA_v%s.zip" % __version__)
    if os.path.exists(out):
        os.remove(out)
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for n in names + ["PRUEFSUMMEN.txt"]:
            add_file(z, os.path.join(ROOT, n), "CLAUDIA/" + n)
    print(out)
    print(hashlib.sha256(open(out, "rb").read()).hexdigest())
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
