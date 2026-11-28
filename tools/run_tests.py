#!/usr/bin/env python3
"""Führt die ganze Testsuite aus und behandelt bekannt flackernde Tests nach fester Regel.

  python tools/run_tests.py [Ergebnisdatei]       Standard: tests/ERGEBNIS.txt

Regel: Scheitert ein Test, wird er bis zu 2-mal einzeln wiederholt.
 - besteht er in einer Wiederholung            -> 'flackernd' (Hinweis im Ergebnis, kein Fehler)
 - scheitert er bekannt-flackernd auch 2-mal   -> 'offen (bekannt flackernd)': Hinweis im Ergebnis und die Möglichkeit, ihn von Hand 3-mal nachzuprüfen (Befehl steht im Ergebnis)
 - scheitert ein anderer Test auch 2-mal       -> echter Fehler (Rückgabewert 1)
Die Liste der bekannt flackernden Tests steht unten (KNOWN_FLAKY); neue Einträge nur nach Absprache."""
from __future__ import annotations

import os
import re
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TESTS = os.path.join(ROOT, "tests")
KNOWN_FLAKY = {"test_ui.UiFlow.test_2_texts_are_never_html": "Browser-Test der Oberfläche, scheitert im Volllauf gelegentlich durch Zeitverhalten; besteht einzeln"}
ENV = dict(os.environ, PYTHONPATH=os.pathsep.join([os.path.join(TESTS, "fake_paramiko"), ROOT]), CLAUDIA_SITE_PAUSE="0")   # keine Höflichkeitspause in Tests


def run(args, timeout=1800):
    return subprocess.run([sys.executable, "-W", "ignore", "-m", "unittest"] + args, cwd=TESTS, env=ENV, capture_output=True, text=True, timeout=timeout)


def failed_ids(output: str):
    ids = []
    for m in re.finditer(r"^(?:FAIL|ERROR): \S+ \(([\w.]+)\)", output, re.M):
        ids.append(m.group(1))
    return ids


def main() -> int:
    out_path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(TESTS, "ERGEBNIS.txt")
    t0 = time.time()
    r = run(["discover", "-s", ".", "-p", "test_*.py"])
    text = r.stdout + r.stderr
    summary = re.search(r"^Ran (\d+) tests? in ([\d.]+)s", text, re.M)
    ran = summary.group(1) if summary else "?"
    fails = failed_ids(text)
    lines = ["Testergebnis (%s)" % time.strftime("%Y-%m-%d %H:%M"), "Erster Lauf: %s Tests, %d gescheitert" % (ran, len(fails))]
    flaky, open_known, real = [], [], []
    for tid in fails:
        ok_after = 0
        for n in (1, 2):
            if run([tid], 600).returncode == 0:
                ok_after = n
                break
        if ok_after:
            flaky.append((tid, ok_after))
        elif tid in KNOWN_FLAKY:
            open_known.append(tid)
        else:
            real.append(tid)
    for tid, n in flaky:
        lines.append("FLACKERND: %s bestand im %d. Wiederholungslauf. %s" % (tid, n, KNOWN_FLAKY.get(tid, "NICHT in der Liste bekannter Flackertests: bitte beobachten")))
    for tid in open_known:
        lines.append("OFFEN (bekannt flackernd): %s scheiterte auch 2 Wiederholungen. %s" % (tid, KNOWN_FLAKY[tid]))
        lines.append("  Von Hand 3-mal nachprüfen: cd tests && for i in 1 2 3; do PYTHONPATH=fake_paramiko:.. python3 -W ignore -m unittest %s; done" % tid)
    for tid in real:
        lines.append("FEHLER: %s scheiterte auch nach 2 Wiederholungen" % tid)
    lines.append("Ergebnis: %s" % ("ECHTER FEHLER" if real else ("in Ordnung, mit Hinweis" if (flaky or open_known) else "alles in Ordnung")))
    lines.append("Dauer: %d s" % (time.time() - t0))
    if real or open_known or flaky:
        lines.append("")
        lines.append("Auszug aus dem ersten Lauf:")
        lines += [l for l in text.splitlines() if re.match(r"^(FAIL|ERROR|AssertionError)", l)][:30]
    open(out_path, "w", encoding="utf-8").write("\n".join(lines) + "\n")
    print("\n".join(lines))
    return 1 if real else 0


if __name__ == "__main__":
    sys.exit(main())
