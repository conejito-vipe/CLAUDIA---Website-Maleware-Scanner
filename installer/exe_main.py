"""Einstiegspunkt der einzelnen Programmdatei (.exe unter Windows, .app auf dem Mac), gebaut mit PyInstaller (tools/build_exe.py).

Die Programmdatei bringt Python und alle Bausteine mit. Es gibt keinen Startbildschirm für die Einrichtung, keine .venv und keinen Download
beim ersten Start: Der Start ruft direkt das Programm auf (lokaler Server nur für diesen PC plus eigenes Fenster).
Ohne Konsole (--windowed) gibt es keine Standardausgabe; sie wird dann ins Leere gelenkt, damit nichts beim Schreiben abstürzt."""
import multiprocessing
import os
import sys


def _streams() -> None:
    out = os.environ.get("CLAUDIA_SELFTEST_OUT")                   # nur für den Selbsttest im Build-Workflow: ohne Konsole die Ausgabe in eine Datei schreiben
    if out and "--selftest" in sys.argv:
        try:
            sys.stdout = sys.stderr = open(out, "w", encoding="utf-8")
            return
        except OSError:
            pass
    for name in ("stdout", "stderr"):
        if getattr(sys, name, None) is None:
            try:
                setattr(sys, name, open(os.devnull, "w", encoding="utf-8"))
            except OSError:
                pass


def run(argv=None) -> int:
    _streams()
    from claudia.__main__ import main
    return main(argv)


if __name__ == "__main__":
    multiprocessing.freeze_support()
    sys.exit(run())
