"""Protokolle: Zugriffsprotokoll (Server und eigener PC) und Joomla-/PHP-Protokolle."""
from __future__ import annotations

import gzip
import os
import re
from collections import Counter
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .. import geoip
from ..model import CheckSkipped, Option
from ..registry import check
from ..util import clean_line, lines_of, split_sections, sq, trunc

G = "logs"
LOG_RE = re.compile(r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<req>[^"]*)" (?P<code>\d{3}) ')


def _parse(line: str) -> Tuple[str, str, str, str]:
    """(ip, zeit_iso, anfrage, statuscode) aus einer Zeile im Apache/Nginx-Format."""
    m = LOG_RE.match(line)
    if not m:
        ip = line.split(" ", 1)[0] if line else "?"
        return ip, "", line[:120], ""
    ts = m.group("ts")
    try:
        iso = datetime.strptime(ts, "%d/%b/%Y:%H:%M:%S %z").strftime("%Y-%m-%d %H:%M")
    except ValueError:
        iso = ts
    return m.group("ip"), iso, m.group("req"), m.group("code")


class Stat:
    def __init__(self, pat: Dict[str, Any]):
        self.pat = pat
        self.rx = re.compile(pat["regex"], re.IGNORECASE)
        self.count = 0
        self.ok200 = 0
        self.err5 = 0
        self.paths: Counter = Counter()
        self.first = ""
        self.last = ""
        self.ips: Counter = Counter()
        self.samples: List[str] = []
        self.tail: List[str] = []

    def add(self, line: str) -> None:
        ip, ts, req, code = _parse(line)
        self.count += 1
        if code.startswith("2"):
            self.ok200 += 1
        elif code.startswith("5"):
            self.err5 += 1
        parts = req.split(" ")
        if len(parts) >= 2:
            self.paths[parts[1].split("?")[0][:100]] += 1
        if ts:
            if not self.first or ts < self.first:
                self.first = ts
            if not self.last or ts > self.last:
                self.last = ts
        self.ips[ip] += 1
        entry = "%s  %s  %s -> %s" % (ts or "?", ip, trunc(clean_line(req), 110), code or "?")
        if len(self.samples) < 5:
            self.samples.append(entry)
        else:
            self.tail.append(entry)
            if len(self.tail) > 3:
                self.tail.pop(0)


def geo_of(ctx) -> "geoip.Geo":
    return ctx.shared.setdefault("_geo", geoip.Geo())


def senders(ctx, counter: Counter, n: int = 5) -> Tuple[str, List[str]]:
    """Häufigste Absender mit Flagge vor der (gekürzten) Adresse; dazu je eine Zeile mit Land und Netzname. Gefragt wird nur das gekürzte Netz."""
    geo = geo_of(ctx)
    parts: List[str] = []
    rows: List[str] = []
    for ip, c in counter.most_common(n):
        raw = ip.replace(".x", ".0") if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){2}\.x", ip) else ip
        info = geo.lookup(raw)
        cc = info.get("cc", "")
        shown = ctx.mask(ip)
        parts.append(("%s %s (%dx)" % (geoip.flag(cc) if cc else "", shown, c)).strip())
        if cc or info.get("name"):
            who = ", ".join(x for x in (info.get("name"), info.get("org")) if x)
            rows.append("%s %s: %s%s  [%s]" % (geoip.flag(cc), shown, geoip.label(cc) or "Land unbekannt", (", Netz " + who) if who else "", info.get("registry", "")))
    return ", ".join(parts), rows


def _render(ctx, res, stats: List[Stat], source: str, files_info: List[str], total_lines: Optional[int] = None) -> None:
    hits = [s for s in stats if s.count]
    sev_rank = {"crit": 0, "warn": 1, "info": 2, "ok": 3}
    def eff(st: Stat) -> str:
        """Eine Regel für alle Angriffsmuster: Wurde keine einzige Anfrage mit 2xx beantwortet (alles abgewehrt, umgeleitet oder nicht gefunden), ist der Befund grün (ok).
        Mit mindestens einer 2xx-Antwort wird er rot (kritisch) - bei den Mustern, die im normalen Betrieb nie vorkommen (Web-Shell-Aufrufe, bekannte Angriffe, SQL-Injection, Traversal, Code-Ausführung).
        Bei Mustern, die auch ein echter Besucher oder Administrator auslösen kann (schreibende Aufrufe einer Erweiterung mit aktueller Meldung), bleibt es bei 'bitte prüfen'."""
        sv = st.pat.get("severity", "info")
        if sv not in ("crit", "warn"):
            return sv
        if st.ok200 == 0:
            return "ok"
        return "warn" if str(st.pat.get("id", "")).startswith("intel_") else "crit"

    for s in sorted(hits, key=lambda x: sev_rank.get(eff(x), 3)):
        sev = eff(s)
        top, origin = senders(ctx, s.ips)
        paths = ", ".join("%s (%dx)" % (pt, c) for pt, c in s.paths.most_common(3))
        if s.ok200:
            outcome = "Davon %d mit Antwortcode 2xx (Anfrage vermutlich ERFOLGREICH)." % s.ok200
        else:
            outcome = "Keine einzige Anfrage wurde mit 2xx beantwortet (alle abgewehrt oder nicht gefunden)"
            outcome += ", %d mit Serverfehler 5xx." % s.err5 if s.err5 else "."
        detail = "Zeitraum der Treffer: %s bis %s. %s Häufigste Absender: %s. Häufigste Adressen: %s." % (
            s.first or "?", s.last or "?", outcome, top, paths or "?")
        items = [ctx.mask(x) for x in s.samples] + ([ctx.mask("...")] if s.tail else []) + [ctx.mask(x) for x in s.tail]
        origin_note = ("Herkunft der Absender (Land laut Registrierung des Netzes bei der Regional-Registry, nicht der genaue Standort):",) if origin else ()
        items = list(origin_note) + origin + items
        hint = ""
        if sev == "crit":
            hint = ("Der früheste Treffer (%s) ist ein möglicher Einbruchszeitpunkt. Vergleiche ihn mit dem Änderungsdatum verdächtiger Dateien. "
                    "Antworten mit Code 200 bedeuten meist, dass der Angriff funktioniert hat." % (s.first or "?"))
        elif s.pat.get("severity") in ("crit", "warn") and not s.ok200:
            hint = ("Angriffsversuch, der abgewehrt wurde. Das ist normaler Internet-Lärm, solange die Erweiterung aktuell ist. "
                    "Prüfe nur, ob später am selben Tag Dateien neu angelegt wurden (Test 'Kürzlich geänderte Dateien').")
        title = "%s: %d Treffer" % (s.pat["title"], s.count)
        if s.pat.get("severity") in ("crit", "warn") and not s.ok200:
            title += ", keiner erfolgreich"
        res.add(sev, title, detail, items, hint)
    crit_hits = [s for s in hits if eff(s) == "crit"]
    if crit_hits:
        earliest = min((s.first for s in crit_hits if s.first), default="")
        if earliest:
            res.add("info", "Frühester erfolgreicher Treffer: %s" % earliest,
                    "Alles davor ist laut diesem Protokoll unauffällig. Datum mit der Datei-Zeitleiste (Test 'Kürzlich geänderte Dateien') abgleichen.")
    if not [s for s in hits if eff(s) in ("crit", "warn")]:
        res.add("ok", "Keine bekannten Angriffsmuster im Zugriffsprotokoll gefunden",
                "Geprüft wurde auf: " + "; ".join(s.pat["title"] for s in stats if s.pat.get("severity") in ("crit", "warn")) + ".")
    if files_info:
        res.add("info", "Ausgewertete Protokolldateien (%s)" % source, "" if total_lines is None else "%d Zeilen insgesamt." % total_lines, files_info[:40], context=True)


# ----------------------------------------------------------------------------- Zugriffsprotokoll auf dem Server
@check(
    "access_logs", G, "Zugriffsprotokoll auf dem Server nach Angriffsspuren durchsuchen",
    "Finden sich im Zugriffsprotokoll Aufrufe, die zu den bekannten Angriffen passen (JCE, Tassos, Web-Shells ...)?",
    what="Sucht im Log-Ordner deines Hosters (z. B. ~/logs) nach Aufrufen wie 'com_jce ... profiles.import', 'plugin=nrframework ... task=include', Zugriffen auf PHP-Dateien "
         "in tmp/ und images/, SQL-Injection- und Traversal-Versuchen. Zeigt Zeitraum, Absender-IPs und Beispiele.",
    why="Nur das Zugriffsprotokoll verrät, WANN und WIE der Angreifer hereinkam. Das entscheidet, ob die Schwachstelle wirklich geschlossen ist.",
    reads="Durchsucht die Protokolldateien auf dem Server (auch .gz) nur lesend. Es werden nur die Trefferzeilen übertragen. Das kann bei großen Protokollen einige Minuten dauern.",
    load="hoch", presets=["hack"],
)
def access_logs(ctx, res):
    from .threat import watch_patterns
    patterns = [p for p in list(ctx.adv.get("log_patterns", [])) + watch_patterns(ctx) if p.get("severity") in ("crit", "warn")]
    rx = "|".join("(%s)" % p["regex"] for p in patterns)
    d = ctx.s.log_dir.strip()
    cands = [d] if d else ["logs", "log", "access-logs", "access_log", "../logs", "../log"]
    script = r"""
echo '@@FILES'
for d in @CANDS@; do
  case "$d" in /*) p="$d";; "~"/*) p="$HOME/${d#\~/}";; *) p="$HOME/$d";; esac
  [ -d "$p" ] && find "$p" -maxdepth 3 -type f \( -iname '*access*' -o -iname '*.log' -o -iname '*.log.*' -o -iname '*.gz' \) ! -iname '*error*' -printf 'LF\t%s\t%TY-%Tm-%Td\t%p\n' 2>/dev/null
done | head -500
echo '@@DIR'
for d in @CANDS@; do
  case "$d" in /*) p="$d";; "~"/*) p="$HOME/${d#\~/}";; *) p="$HOME/$d";; esac
  [ -d "$p" ] && echo "$p"
done | head -3
""".replace("@CANDS@", " ".join(sq(c) for c in cands))
    out = ctx.sh(script, timeout=90).out
    sec = split_sections(out)
    files = []
    for ln in sec.get("FILES", "").splitlines():
        p = ln.split("\t")
        if len(p) >= 4 and p[0] == "LF":
            files.append((p[3], int(p[1] or 0), p[2]))
    dirs = lines_of(sec.get("DIR", ""))
    if not dirs or not files:
        res.add("info", "Kein Zugriffsprotokoll auf dem Server gefunden",
                "Gesucht in: %s." % ", ".join(cands),
                hint="Viele Hoster legen Protokolle nicht im Konto ab. Lade sie im Kundenmenü herunter (Zugriffsprotokoll/Logfiles, möglichst ab Juni) "
                     "und werte sie mit dem Test 'Zugriffsprotokoll von diesem PC auswerten' aus. Oder gib in den Einstellungen den Log-Ordner an.")
        return
    ctx.progress("Durchsuche %d Protokolldatei(en) ..." % len(files))
    search = r"""
find @DIRS@ -maxdepth 3 -type f \( -iname '*access*' -o -iname '*.log' -o -iname '*.log.*' -o -iname '*.gz' \) ! -iname '*error*' -print0 2>/dev/null \
  | xargs -0 -r zcat -f -- 2>/dev/null | grep -aE -e @RX@ | head -6000
""".replace("@DIRS@", " ".join(sq(x) for x in dirs)).replace("@RX@", sq(rx))
    hits = ctx.sh(search, timeout=900, raw="trefferzeilen", raw_cap=200_000, ips=True)
    stats = [Stat(p) for p in patterns]
    for line in hits.out.splitlines():
        for s in stats:
            if s.rx.search(line):
                s.add(line)
    oldest = min((f[2] for f in files), default="?")
    newest = max((f[2] for f in files), default="?")
    info = ["%s  (%d KB, geändert %s)" % (clean_line(f[0]), f[1] // 1024, f[2]) for f in sorted(files, key=lambda x: x[2])]
    _render(ctx, res, stats, "Server", info)
    res.add("info", "Abdeckung der Protokolle", "Die ältesten gefundenen Dateien stammen von %s, die neuesten von %s. "
            "Liegt der vermutete Einbruch davor, enthält das Protokoll ihn nicht mehr - dann beim Hoster ältere Protokolle anfragen." % (oldest, newest), context=True)
    if hits.truncated or len(hits.out.splitlines()) >= 6000:
        res.add("warn", "Sehr viele Treffer - Ausgabe gekürzt", "Es wurden nur die ersten 6000 Trefferzeilen ausgewertet.")


# ----------------------------------------------------------------------------- Zugriffsprotokoll vom eigenen PC
def _iter_files(path: str) -> List[str]:
    path = os.path.expanduser(path.strip().strip('"'))
    if os.path.isfile(path):
        return [path]
    out = []
    if os.path.isdir(path):
        for root, _dirs, names in os.walk(path):
            for n in sorted(names):
                if "error" in n.lower() or n.startswith("SICHERUNG_") or n.endswith(".teil"):
                    continue
                out.append(os.path.join(root, n))
                if len(out) >= 400:
                    return out
    return out


def _open_lines(path: str) -> Iterable[str]:
    opener = gzip.open if path.lower().endswith(".gz") else open
    with opener(path, "rt", encoding="utf-8", errors="replace") as fh:  # type: ignore[arg-type]
        for line in fh:
            yield line.rstrip("\n")


@check(
    "local_logs", G, "Zugriffsprotokoll von diesem PC auswerten",
    "Du hast Protokolle vom Hoster heruntergeladen? Dann werden sie hier direkt auf deinem PC ausgewertet.",
    what="Liest eine Protokolldatei (.log oder .gz) oder einen ganzen Ordner auf DEINEM Computer und sucht dieselben Angriffsmuster wie der Server-Test. "
         "Zusätzlich werden Scans (wp-login, xmlrpc) und Anmeldeversuche am Admin-Bereich gezählt. Dafür ist keine SSH-Verbindung nötig.",
    why="Viele Hoster (auch hosting.de) bieten die Zugriffsprotokolle nur zum Download im Kundenmenü an. Damit lässt sich ermitteln, wie der Angreifer hereinkam, "
        "ohne dass die Daten die Rechner verlassen.",
    reads="Nur die von dir angegebene Datei/den Ordner auf deinem PC. Nichts wird hochgeladen, in den Bericht kommen nur Trefferzeilen (IPs auf Wunsch gekürzt).",
    load="mittel", needs="local", presets=[],
    options=[Option("path", "Pfad zur Protokolldatei oder zum Ordner auf deinem PC", "text", "",
                    "Beispiel: C:\\Users\\Dennis\\Downloads\\logs   (Rechtsklick auf Ordner -> 'Als Pfad kopieren')")],
)
def local_logs(ctx, res):
    path = str(ctx.opt("path", "") or "")
    if not path:
        raise CheckSkipped("Kein Pfad angegeben. Trage bei diesem Test den Pfad zu deiner Protokolldatei oder deinem Ordner ein.")
    files = _iter_files(path)
    if not files:
        raise CheckSkipped("Unter '%s' wurde keine Protokolldatei gefunden." % path)
    from .threat import watch_patterns
    stats = [Stat(p) for p in list(ctx.adv.get("log_patterns", [])) + watch_patterns(ctx)]
    total = 0
    days: Counter = Counter()
    day_rx = re.compile(r"\[(\d{2}/[A-Za-z]{3}/\d{4}):")
    info: List[str] = []
    for f in files:
        n = 0
        try:
            for line in _open_lines(f):
                n += 1
                total += 1
                if total % 200_000 == 0:
                    ctx.progress("%d Zeilen ausgewertet ..." % total)
                for s in stats:
                    if s.rx.search(line):
                        s.add(line)
                dm = day_rx.search(line, 0, 80)
                if dm:
                    days[dm.group(1)] += 1
        except (OSError, EOFError) as e:
            info.append("%s  - FEHLER beim Lesen: %s" % (f, e))
            continue
        info.append("%s  (%d Zeilen)" % (clean_line(f), n))
    ctx.add_raw("zeilen_auszug", "\n".join(x for s in stats if s.count for x in (s.samples + s.tail)), ips=True)
    _render(ctx, res, stats, "dein PC", info, total)
    if days:
        iso = {}
        for d, c in days.items():
            try:
                iso[datetime.strptime(d, "%d/%b/%Y").strftime("%Y-%m-%d")] = c
            except ValueError:
                pass
        if iso:
            ks = sorted(iso)
            res.add("info", "Zeitraum der Protokolle: %s bis %s (%d Tage)" % (ks[0], ks[-1], len(ks)),
                    "Liegt der vermutete Einbruch außerhalb dieses Zeitraums, fehlen die entscheidenden Tage - beim Hoster ältere Protokolle anfragen.",
                    ["%s: %d Anfragen" % (k, iso[k]) for k in sorted(iso, key=lambda k: -iso[k])[:8]] and
                    ["Tage mit den meisten Anfragen: " + ", ".join("%s (%d)" % (k, iso[k]) for k in sorted(iso, key=lambda k: -iso[k])[:6])])


# ----------------------------------------------------------------------------- Joomla- und PHP-Protokolle
STRONG_LOG = r"\.\./\.\./|<\?php|base64_decode|eval\(|union +select|system\(|shell_exec|passthru|php://input|allow_url_include|/tmp/[A-Za-z0-9_.-]+\.php"
FAIL_LOG = r"Username and password do not match|login failed|Login denied|Invalid Token|JAuthentication"


@check(
    "joomla_logs", G, "Joomla- und PHP-Fehlerprotokolle",
    "Stehen in den Fehlerprotokollen Angriffsspuren, Fehlversuche bei Anmeldungen oder auffällige Eingaben?",
    what="Liest die Protokolle in administrator/logs (bzw. im log-Pfad der Konfiguration) und eventuelle PHP-Fehlerprotokolle (error_log) und sucht nach Angriffs-Eingaben "
         "(../../, <?php, base64_decode, SQL-Injection), PHP-Fehlern durch eingeschleusten Code und zählt fehlgeschlagene Anmeldungen.",
    why="Protokolle von Formularen (z. B. Convert Forms) und PHP-Fehlerprotokolle halten oft Angriffsversuche fest, auch erfolglose. "
        "Viele Fehlanmeldungen zeigen Passwort-Raten.",
    reads="Joomla-Protokolle (kleine Textdateien) und der Schwanz der PHP-Fehlerprotokolle. Nichts wird verändert.",
    load="leicht", presets=["schnell", "hack"],
)
def joomla_logs(ctx, res):
    cfg = ctx.config()
    logpath = str(cfg.get("vars", {}).get("log_path", "")) if not cfg.get("missing") else ""
    dirs = ["administrator/logs", "logs"] + ([logpath] if logpath.startswith("/") else [])
    dl = " ".join(sq(d) for d in dirs)
    script = r"""
echo '@@LIST'
for d in @DIRS@; do [ -d "$d" ] && find "$d" -maxdepth 1 -type f -printf 'L\t%s\t%TY-%Tm-%Td\t%p\n' 2>/dev/null; done | head -120
echo '@@STRONG'
for d in @DIRS@; do [ -d "$d" ] && find "$d" -maxdepth 1 -type f -print0 2>/dev/null | xargs -0 -r grep -nHaiE -e @STRONG@ 2>/dev/null | cut -c1-260; done | head -300
echo '@@FAILS'
for d in @DIRS@; do [ -d "$d" ] && find "$d" -maxdepth 1 -type f -print0 2>/dev/null | xargs -0 -r grep -ciE -e @FAIL@ 2>/dev/null; done | grep -v ':0$' | head -50
echo '@@PHPERR'
find . -maxdepth 3 -type f \( -name error_log -o -name php_errorlog -o -name php_errors.log \) -not -path './node_modules/*' 2>/dev/null | head -6 | while IFS= read -r f; do
  echo "== $f ($(stat -c %s "$f") Byte)"
  tail -n 500 "$f" | grep -aE "eval\(\)'d code|Failed opening|base64|/tmp/[A-Za-z0-9_.-]+\.php|allow_url|Permission denied|shell|exploit" | cut -c1-260 | tail -25
done
""".replace("@DIRS@", dl).replace("@STRONG@", sq(STRONG_LOG)).replace("@FAIL@", sq(FAIL_LOG))
    out = ctx.sh(script, timeout=120, raw="treffer", ips=True).out
    sec = split_sections(out)
    files = []
    seen_files = set()
    for ln in sec.get("LIST", "").splitlines():
        p = ln.split("\t")
        if len(p) >= 4 and p[0] == "L":
            key = (p[3].rsplit("/", 1)[-1], p[1], p[2])
            if key in seen_files:
                continue            # derselbe Ordner einmal relativ und einmal absolut angegeben
            seen_files.add(key)
            files.append("%s  (%d KB, %s)" % (clean_line(p[3]), int(p[1] or 0) // 1024, p[2]))
    strong_crit, strong_warn, scanner = [], [], []
    for ln in sec.get("STRONG", "").splitlines():
        m = re.match(r"^(.*?):(\d+):(.*)\Z", ln)
        if not m:
            continue
        if m.group(3).lstrip().startswith("#"):
            continue   # Joomla-Kopfzeile "#<?php die('Forbidden.'); ?>"
        text = "%s Zeile %s: %s" % (clean_line(m.group(1)), m.group(2), trunc(clean_line(m.group(3).strip()), 170))
        if re.search(r"Page not found \(404\)|\bclient-error\b", m.group(3)):
            scanner.append(ctx.mask(text))    # Joomla hat die Seite nicht gefunden: Scanner-Anfrage, nichts wurde ausgeführt
            continue
        (strong_crit if re.search(r"<\?php|system\(|shell_exec|passthru|eval\(", m.group(3), re.IGNORECASE) else strong_warn).append(ctx.mask(text))
    if strong_crit:
        res.add("crit", "%d Protokollzeile(n) mit Programmcode-Eingaben" % len(strong_crit),
                "Jemand hat versucht, PHP-Code über ein Formular oder eine Adresse einzuschleusen (oft in Convert-Forms- und Joomla-Fehlerprotokollen sichtbar).",
                strong_crit[:40], "Zeitpunkt notieren und mit dem Zugriffsprotokoll abgleichen. Erweiterung des betroffenen Formulars auf dem neuesten Stand halten.")
    if strong_warn:
        res.add("warn", "%d Protokollzeile(n) mit Angriffsmustern" % len(strong_warn), "Z. B. ../../, SQL-Injection oder base64_decode.", strong_warn[:40])
    if scanner:
        ips = Counter()
        for x in scanner:
            mi = re.search(r"\t(\d{1,3}(?:\.\d{1,3}){2}\.[\dx]+|[0-9a-f:]{6,}[:x]+\S*)\t", x)
            if mi:
                ips[mi.group(1)] += 1
        shown, origin = senders(ctx, ips, 3) if ips else ("", [])
        top = (" Häufigste Absender: " + shown + ".") if ips else ""
        res.add("info", "%d Scanner-Anfrage(n) auf nicht vorhandene Seiten (Fehler 404)" % len(scanner),
                "Automatische Scanner probieren Adressen wie ../../ aus. Joomla meldet 'Seite nicht gefunden', es wurde nichts ausgeführt.%s" % top,
                origin + scanner[:8])
    fails = lines_of(sec.get("FAILS", ""))
    total_fail = 0
    items = []
    for ln in fails:
        m = re.match(r"^(.*):(\d+)\Z", ln)
        if m:
            total_fail += int(m.group(2))
            items.append("%s: %s" % (clean_line(m.group(1)), m.group(2)))
    if total_fail:
        res.add("info" if total_fail < 200 else "warn", "%d Fehlanmeldungen/Token-Fehler in den Protokollen" % total_fail,
                "Viele Fehlversuche deuten auf Passwort-Raten hin." if total_fail >= 200 else "", items[:15],
                "Bei vielen Versuchen: Zwei-Faktor-Anmeldung für alle Admins aktivieren." if total_fail >= 200 else "")
    perr = sec.get("PHPERR", "").strip()
    if perr:
        res.add("warn", "Auffällige Zeilen in PHP-Fehlerprotokoll(en)", "Meldungen wie \"eval()'d code\" oder fehlgeschlagene Includes stammen oft von eingeschleustem Code.",
                [ctx.mask(clean_line(x)) for x in perr.splitlines()[:40]], "Datei ansehen: Welche Datei wird in den Meldungen genannt?")
    if not (strong_crit or strong_warn or perr):
        res.add("ok", "Keine Angriffsspuren in Joomla- und PHP-Protokollen gefunden", "%d Protokolldatei(en) geprüft." % len(files))
    if files:
        res.add("info", "Protokolldateien", "", files[:30], context=True)
