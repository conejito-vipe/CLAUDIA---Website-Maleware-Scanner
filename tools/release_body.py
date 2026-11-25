#!/usr/bin/env python3
"""Stellt aus einem Ordner mit den fertigen Release-Dateien den GitHub-Release-Text und SHA256SUMS.txt zusammen (vom Workflow release.yml benutzt).

  python tools/release_body.py <Ordner mit den Dateien> [--notes RELEASE_NOTES.md] [--out release_body.md]

Der Ordner muss CLAUDIA_v<Version>.zip enthalten (das Paket, das die Aktualisierung im Programm lädt). Der Text besteht aus
  1. den Release Notes (Englisch, Deutsch als umschaltbarer Block), unverändert aus RELEASE_NOTES.md,
  2. der Liste der Dateien dieses Releases (was jede Datei ist),
  3. der Zeile "SHA-256: <Prüfsumme von CLAUDIA_v<Version>.zip>". Daran erkennt die Aktualisierung im Programm die Prüfsumme, falls GitHub keine liefert.
Prüfsummen weiterer Dateien stehen nur in SHA256SUMS.txt (Anhang), nicht im Text: sonst könnte eine falsche Zeile als Prüfsumme des Pakets gelesen werden."""
from __future__ import annotations

import hashlib
import os
import re
import sys
from typing import Dict, List, Optional

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from claudia import __version__  # noqa: E402

SUMS = "SHA256SUMS.txt"
# Dateiname (mit {v} für die Version) -> kurze, technische Beschreibung
KINDS = [
    ("CLAUDIA-Setup-{v}.exe", "Windows installer, single file, no Python needed (per-user, no administrator rights)"),
    ("CLAUDIA_v{v}_Windows.zip", "Windows, portable folder with CLAUDIA.exe, no Python needed"),
    ("CLAUDIA_v{v}_Mac.zip", "macOS (Apple silicon), CLAUDIA.app, no Python needed; not notarized: first start via right click > Open"),
    ("CLAUDIA_v{v}.zip", "Source package for the Python version (start.bat / start.command, Python 3.9+); this is the file the in-program update downloads"),
    (SUMS, "SHA-256 of every file of this release"),
]


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def write_sums(folder: str) -> str:
    """SHA256SUMS.txt im Format 'sha256sum' (Prüfen mit: sha256sum -c SHA256SUMS.txt)."""
    names = sorted(n for n in os.listdir(folder) if n != SUMS and os.path.isfile(os.path.join(folder, n)))
    path = os.path.join(folder, SUMS)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        for n in names:
            fh.write("%s  %s\n" % (sha256_file(os.path.join(folder, n)), n))
    return path


def notes_version(text: str) -> str:
    m = re.match(r"#\s*CLAUDIA\s+(\d+\.\d+\.\d+)\b", text)
    return m.group(1) if m else ""


def body(folder: str, notes_text: str, version: str = __version__) -> str:
    if notes_version(notes_text) != version:
        raise ValueError("RELEASE_NOTES.md gehört nicht zur Version %s." % version)
    zip_name = "CLAUDIA_v%s.zip" % version
    zpath = os.path.join(folder, zip_name)
    if not os.path.isfile(zpath):
        raise ValueError("%s fehlt im Ordner." % zip_name)
    present = set(os.listdir(folder))
    rows: List[str] = []
    for pattern, what in KINDS:
        name = pattern.format(v=version)
        if name in present or name == SUMS:
            rows.append("- `%s`: %s" % (name, what))
    return (notes_text.rstrip() + "\n\n## Files\n\n" + "\n".join(rows) + "\n\nSHA-256: %s\n" % sha256_file(zpath))


def main(argv: List[str]) -> int:
    args = [a for a in argv[1:] if not a.startswith("--")]
    opts: Dict[str, str] = {}
    for i, a in enumerate(argv[1:], 1):
        if a in ("--notes", "--out") and i + 1 < len(argv):
            opts[a] = argv[i + 1]
    skip = set(opts.values())
    args = [a for a in args if a not in skip]
    if len(args) != 1:
        print(__doc__)
        return 2
    folder = args[0]
    notes_path = opts.get("--notes", os.path.join(ROOT, "RELEASE_NOTES.md"))
    out: Optional[str] = opts.get("--out")
    with open(notes_path, encoding="utf-8") as fh:
        notes = fh.read()
    write_sums(folder)
    text = body(folder, notes)
    if out:
        with open(out, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
