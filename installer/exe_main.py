"""Einstiegspunkt der einzelnen Programmdatei (.exe unter Windows, .app auf dem Mac), gebaut mit PyInstaller (tools/build_exe.py).

Die Programmdatei bringt Python und alle Bausteine mit. Es gibt keinen Startbildschirm für die Einrichtung, keine .venv und keinen Download
beim ersten Start: Der Start ruft direkt das Programm auf (lokaler Server nur für diesen PC plus eigenes Fenster).
Ohne Konsole (--windowed) gibt es keine Standardausgabe; sie wird dann ins Leere gelenkt, damit nichts beim Schreiben abstürzt."""
import multiprocessing
import os
import sys


MAX_LOG = 2 * 1024 * 1024


def protokoll_datei() -> str:
    """Pfad des Programmprotokolls (eine Quelle: claudia.support.programm_protokoll)."""
    from claudia.support import programm_protokoll
    return programm_protokoll()


def _log_oeffnen():
    """Protokolldatei zum Anhängen öffnen; über 2 MB wird sie zu claudia.alt.log (die vorige alte wird ersetzt)."""
    pfad = protokoll_datei()
    os.makedirs(os.path.dirname(pfad), exist_ok=True)
    try:
        if os.path.getsize(pfad) > MAX_LOG:
            os.replace(pfad, pfad[:-4] + ".alt.log")
    except OSError:
        pass
    f = open(pfad, "a", encoding="utf-8", errors="replace", buffering=1)
    import datetime
    import platform
    f.write("\n===== Start %s | %s | Python %s | %s =====\n" % (
        datetime.datetime.now().isoformat(timespec="seconds"), platform.platform(), platform.python_version(), " ".join(sys.argv[1:]) or "-"))
    return f


def _streams() -> None:
    out = os.environ.get("CLAUDIA_SELFTEST_OUT")                   # nur für den Selbsttest im Build-Workflow: ohne Konsole die Ausgabe in eine Datei schreiben
    if out and "--selftest" in sys.argv:
        try:
            sys.stdout = sys.stderr = open(out, "w", encoding="utf-8")
            return
        except OSError:
            pass
    if getattr(sys, "stdout", None) is not None and getattr(sys, "stderr", None) is not None:
        return
    # Ohne Konsole: Ausgaben, Warnungen und Abstürze ins Programmprotokoll schreiben (für die Fehlersuche), sonst ins Leere
    try:
        log = _log_oeffnen()
    except OSError:
        log = None
    for name in ("stdout", "stderr"):
        if getattr(sys, name, None) is None:
            try:
                setattr(sys, name, log or open(os.devnull, "w", encoding="utf-8"))
            except OSError:
                pass
    if log is not None:
        try:
            import faulthandler
            faulthandler.enable(log)                                   # auch harte Abstürze (z. B. im Fensterbaustein) landen im Protokoll
        except Exception:
            pass
        try:
            import logging
            logging.basicConfig(level=logging.WARNING, stream=log, format="%(asctime)s %(name)s %(levelname)s: %(message)s")
        except Exception:
            pass


def run(argv=None) -> int:
    _streams()
    from claudia.__main__ import main
    rc = main(argv)
    if getattr(sys, "frozen", False):
        # Fenster ist zu: Prozess sicher beenden, auch wenn noch ein Hintergrundfaden hängt (sonst bleibt CLAUDIA.exe
        # unsichtbar im Speicher und ein neuer Start kann hängen)
        for st in (sys.stdout, sys.stderr):
            try:
                st.flush()
            except Exception:
                pass
        os._exit(rc or 0)
    return rc


if __name__ == "__main__":
    multiprocessing.freeze_support()
    sys.exit(run())
