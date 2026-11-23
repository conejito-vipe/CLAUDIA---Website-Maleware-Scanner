"""Dauerzugänge im Server-Konto: Cronjobs, SSH-Schlüssel, laufende Prozesse, Start-Dateien der Shell, angemeldete Sitzungen, WP-Cron.

Nach einem Einbruch bleibt ein Angreifer oft nicht in den Dateien der Seite, sondern im Konto: ein Cronjob lädt die Hintertür jede Stunde neu,
ein fremder SSH-Schlüssel erlaubt die Rückkehr, ein Prozess läuft weiter. Alle Prüfungen hier sind rein lesend. Ausgaben, die Geheimnisse
enthalten können (Cronzeilen, Shell-Dateien), werden nicht im Rohbericht gespeichert und in der Anzeige maskiert; Schlüsseltext wird nie gelesen
(nur der Fingerabdruck)."""
from __future__ import annotations

import re
import time
from typing import Dict, List, Optional, Tuple

from ..registry import check
from ..util import clean_line, digits, lines_of, split_sections, trunc
from .database import fetch, need_db

G = "konto"
RECENT_DAYS = 30

# Muster in Befehlszeilen (Cron, Shell-Dateien). Bewusst eng: 'eval "$(dircolors -b)"' steht in jeder Standard-.bashrc und ist harmlos.
CRIT_CMD = [
    (re.compile(r"\b(?:curl|wget|fetch|lwp-download)\b[^|;&\n]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b", re.I), "lädt etwas aus dem Netz und führt es sofort in der Shell aus"),
    (re.compile(r"\b(?:curl|wget)\b[^|;&\n]*\|\s*(?:php|python\d?|perl|ruby)\b", re.I), "lädt etwas aus dem Netz und führt es sofort aus"),
    (re.compile(r"base64\s+(?:-d\b|--decode\b|-D\b)", re.I), "entschlüsselt base64-Text (verbreitete Tarnung für Schadcode)"),
    (re.compile(r"\beval\b[^\n]*(?:base64|gzinflate|str_rot13|\bcurl\b|\bwget\b)", re.I), "führt verschleierten oder aus dem Netz geladenen Code aus"),
    (re.compile(r"\bphp\d?(?:\.\d+)?\s+-r\b", re.I), "führt PHP-Code direkt aus der Befehlszeile aus (php -r)"),
    (re.compile(r"\bpython\d?\s+-c\b", re.I), "führt Python-Code direkt aus der Befehlszeile aus (python -c)"),
    (re.compile(r"\bperl\s+-e\b", re.I), "führt Perl-Code direkt aus der Befehlszeile aus (perl -e)"),
    (re.compile(r"/dev/(?:tcp|udp)/|\bbash\s+-i\b|\b(?:nc|ncat|netcat)\b[^\n]*\s-e\b|\bsocat\b[^\n]*\bexec:", re.I), "baut eine Fernsteuerung (Reverse-Shell) auf"),
    (re.compile(r"\b(?:xmrig|minerd|cpuminer|kdevtmpfsi|kinsing|stratum\+tcp)\b", re.I), "nennt ein bekanntes Mining-Programm"),
]
WARN_CMD = [
    (re.compile(r"(?:^|[\s;&|(=])(?:/tmp/|/var/tmp/|/dev/shm/)\S+", re.I), "führt etwas aus einem Temp-Ordner aus oder legt es dort ab"),
    (re.compile(r"(?:^|[\s;&|(=])(?:\S*/)?(?:uploads|images|cache|media)/\S+\.(?:php|sh|pl|py)\b", re.I), "führt ein Skript aus einem Upload-, Bild- oder Cache-Ordner aus"),
    (re.compile(r"/\.[A-Za-z0-9_][^\s/]*/\S*\.(?:php|sh|pl|py)\b"), "führt ein Skript aus einem versteckten Ordner aus"),
    (re.compile(r"\bchmod\s+(?:[0-7]?[0-7][0-7][157]|\+x|a\+x|u\+x)\b"), "macht eine Datei ausführbar"),
    (re.compile(r"\b(?:curl|wget)\b[^\n]*\s(?:-o|-O|--output|--output-document)[ =]?\S*(?:/tmp/|/var/tmp/|/dev/shm/|uploads/|images/|cache/)", re.I), "lädt eine Datei in einen Temp-, Upload- oder Cache-Ordner"),
    (re.compile(r"\b(?:nohup|setsid|disown)\b[^\n]*&\s*$"), "startet etwas dauerhaft im Hintergrund"),
]
_SECRET_ARG = re.compile(r"""(?i)((?:--?p(?:ass(?:word|wd)?)?|--password|password|passwd|pwd|pass|token|secret|api[_-]?key|key|auth)(?:=|\s+|(?<=-p)))(?:"[^"]*"|'[^']*'|[^\s"';&|]+)""")
_URL_AUTH = re.compile(r"(://[^/\s:@]+:)[^@\s/]+@")
_URL_KEY = re.compile(r"(?i)([?&](?:key|token|pass|password|secret|api_?key|auth|k)=)[^&\s\"']+")


def mask_cmd(text: str) -> str:
    """Passwörter, Schlüssel und Tokens in einer Befehlszeile durch *** ersetzen (Cronzeilen enthalten sie oft)."""
    t = _URL_AUTH.sub(r"\1***@", text or "")
    t = _URL_KEY.sub(r"\1***", t)
    t = _SECRET_ARG.sub(lambda m: m.group(1) + "***", t)
    return clean_line(t)


def judge_cmd(line: str) -> Tuple[str, List[str]]:
    """Bewertung einer Befehlszeile: ('crit'|'warn'|'', Gründe)."""
    crit = [why for rx, why in CRIT_CMD if rx.search(line)]
    warn = [why for rx, why in WARN_CMD if rx.search(line)]
    if crit:
        return "crit", crit + warn
    if warn:
        return "warn", warn
    return "", []


# ============================================================================ A1 Cronjobs
@check(
    "crontab", G, "Cronjobs des Server-Kontos",
    "Läuft im Konto ein zeitgesteuerter Befehl, der Schadcode lädt oder startet?",
    what="Liest die Cron-Tabelle des Kontos (crontab -l) und bewertet jede Zeile: Download mit sofortiger Ausführung (curl ... | sh), base64-Entschlüsselung, "
         "php -r / python -c / perl -e, Fernsteuerung (Reverse-Shell), Mining-Programme sowie Befehle, die aus Temp-, Upload-, Cache- oder versteckten Ordnern laufen. "
         "Normale Zeilen (Joomla- und WordPress-Cron, Datensicherung) werden nur aufgelistet. Passwörter und Schlüssel in den Zeilen werden mit *** ersetzt.",
    why="Ein Cronjob lädt die Hintertür jede Stunde neu. Wer nur die Dateien säubert, hat nach kurzer Zeit wieder den gleichen Befall. Auf Hostings ist das ein häufiger "
        "Dauerzugang, den kein Datei-Scan findet.",
    reads="Nur die Cron-Tabelle des eigenen Kontos. Der Rohtext wird nicht im Bericht gespeichert, weil er Passwörter enthalten kann. Nichts wird geändert. "
          "Verbietet der Hoster crontab, meldet die Prüfung 'nicht prüfbar'.",
    load="leicht", presets=["schnell", "hack"],
)
def crontab_check(ctx, res):
    out = ctx.sh("crontab -l 2>&1; echo \"@@RC=$?\"", timeout=30).out
    m = re.search(r"@@RC=(\d+)", out)
    rc = int(m.group(1)) if m else 1
    body = re.sub(r"@@RC=\d+\s*", "", out)
    low = body.lower()
    if rc != 0:
        if "no crontab" in low:
            res.add("ok", "Das Konto hat keine Cronjobs", "crontab -l meldet: keine Cron-Tabelle für dieses Konto.")
        else:
            res.add("info", "Cronjobs nicht prüfbar", "Der Hoster erlaubt crontab auf diesem Konto nicht oder das Programm fehlt. Cronjobs, die der Hoster im Kundenbereich "
                    "(Plesk, cPanel, KIS) verwaltet, sind von hier aus nicht zu sehen.", [trunc(clean_line(body), 160)] if body.strip() else [],
                    "Im Kundenbereich des Hosters die Cronjobs ansehen und unbekannte entfernen.")
        return
    jobs = [ln.strip() for ln in body.splitlines() if ln.strip() and not ln.strip().startswith("#") and not re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", ln.strip())]
    if not jobs:
        res.add("ok", "Das Konto hat keine Cronjobs", "Die Cron-Tabelle enthält nur Kommentare oder Einstellungen.")
        return
    crit, warn = [], []
    for j in jobs:
        sev, why = judge_cmd(j)
        row = "%s   <- %s" % (trunc(mask_cmd(j), 220), "; ".join(why[:2]))
        if sev == "crit":
            crit.append(row)
        elif sev == "warn":
            warn.append(row)
    if crit:
        res.add("crit", "%d verdächtige(r) Cronjob(s)" % len(crit), "Diese Zeilen laden oder starten Code auf eine Art, die bei Schadsoftware üblich ist und bei normalen Aufgaben selten vorkommt.",
                crit, "Wenn du den Eintrag nicht selbst angelegt hast: mit crontab -e entfernen (oder im Kundenbereich des Hosters), danach Passwörter und SSH-Schlüssel erneuern.")
    if warn:
        res.add("warn", "%d Cronjob(s) mit auffälligem Ziel" % len(warn), "Die Zeilen führen etwas aus Orten aus, an denen normale Aufgaben selten liegen. Kennst du sie?", warn,
                "Unbekannte Einträge mit crontab -e entfernen und die genannte Datei prüfen.")
    shown = [trunc(mask_cmd(j), 200) for j in jobs[:15]]
    res.add("info" if (crit or warn) else "ok", "%d Cronjob(s) im Konto" % len(jobs),
            "Alle eingetragenen Zeiten und Befehle (Passwörter maskiert). Prüfe, ob du jede Zeile kennst." if (crit or warn) else "Keine Zeile fällt auf. Prüfe trotzdem, ob du jede kennst.",
            shown + (["... und %d weitere" % (len(jobs) - 15)] if len(jobs) > 15 else []))


# ============================================================================ A3 SSH-Schlüssel
KEYS_SCRIPT = r"""
D="$HOME/.ssh"
echo '@@DIR'; [ -d "$D" ] && stat -c '%a %U %Y' "$D" 2>/dev/null || echo FEHLT
for f in authorized_keys authorized_keys2; do
  p="$D/$f"
  echo "@@FILE $f"
  if [ -f "$p" ]; then
    stat -c '%a %U %Y %s' "$p" 2>/dev/null
    echo '@@LIST'
    ssh-keygen -l -f "$p" 2>&1 | head -60
    echo '@@OPT'
    # Nur die Optionen vor dem Schlüsseltyp, nie der Schlüssel selbst
    grep -v '^[[:space:]]*#' "$p" 2>/dev/null | grep -v '^[[:space:]]*$' | head -60 | awk '{ i=index($0,"ssh-"); j=index($0,"ecdsa-"); k=index($0,"sk-"); m=0; if(i>0)m=i; if(j>0&&(m==0||j<m))m=j; if(k>0&&(m==0||k<m))m=k; if(m>1) print substr($0,1,m-1); else print "-" }'
    echo '@@COUNT'; grep -c -v -e '^[[:space:]]*#' -e '^[[:space:]]*$' "$p" 2>/dev/null
  else
    echo FEHLT
  fi
done
echo '@@END'
"""


def parse_keys(out: str) -> Dict[str, object]:
    """Ausgabe von KEYS_SCRIPT -> Verzeichnisrechte und je Datei Rechte, Schlüsselliste (nur Fingerabdrücke), Optionen."""
    res: Dict[str, object] = {"dir": None, "files": {}}
    parts = re.split(r"(?m)^@@FILE (\S+)\n", out)
    head = parts[0]
    sec = split_sections(head)
    d = lines_of(sec.get("DIR", ""))
    if d and d[0].strip() != "FEHLT":
        p = d[0].split()
        if len(p) >= 3 and digits(p[2]):
            res["dir"] = {"mode": p[0], "owner": p[1], "mtime": int(p[2])}
    for i in range(1, len(parts) - 1, 2):
        name, body = parts[i], parts[i + 1]
        s = split_sections(body.split("@@END")[0])
        first = body.strip().splitlines()[0] if body.strip() else ""
        if first.strip() == "FEHLT":
            continue
        meta = first.split()
        info: Dict[str, object] = {"mode": "", "owner": "", "mtime": 0, "keys": [], "options": [], "count": 0}
        pre = body.split("@@LIST")[0].strip().split()
        if len(pre) >= 3 and digits(pre[2]):
            info["mode"], info["owner"], info["mtime"] = pre[0], pre[1], int(pre[2])
        keys = []
        for ln in lines_of(s.get("LIST", "")):
            m = re.match(r"^(\d+)\s+(SHA256:\S+|MD5:\S+)\s*(.*?)\s*\(([A-Za-z0-9-]+)\)\s*\Z", ln.strip())
            if m:
                keys.append({"bits": int(m.group(1)), "fp": m.group(2), "comment": m.group(3), "type": m.group(4)})
        info["keys"] = keys
        info["listing_failed"] = bool(lines_of(s.get("LIST", ""))) and not keys
        info["options"] = [ln.strip() for ln in (s.get("OPT", "") or "").splitlines() if ln.strip() and ln.strip() != "-"]
        c = lines_of(s.get("COUNT", ""))
        info["count"] = int(c[0]) if c and digits(c[0].strip()) else len(keys)
        res["files"][name] = info
    return res


@check(
    "authorized_keys", G, "SSH-Schlüssel mit Zugang zum Konto",
    "Gibt es SSH-Schlüssel, mit denen sich jemand ohne Passwort auf dem Konto anmelden kann?",
    what="Liest ~/.ssh/authorized_keys (und authorized_keys2): Anzahl, Schlüsselart, Fingerabdruck und Kommentar jedes Schlüssels, Optionen wie command= oder from=, "
         "Rechte des Ordners ~/.ssh und der Datei sowie das Änderungsdatum. Der Schlüsseltext selbst wird nie gelesen oder gespeichert, nur der Fingerabdruck.",
    why="Ein eingeschleuster SSH-Schlüssel erlaubt die Rückkehr, auch nach Passwortwechsel und nach dem Säubern der Seite. Nach einem Hack ist er einer der ersten Orte, "
        "an denen Angreifer sich festsetzen.",
    reads="Die Datei authorized_keys wird zeilenweise vom Programm ssh-keygen in Fingerabdrücke umgerechnet. Ausgegeben werden Länge, Art, Fingerabdruck, Kommentar und Optionen. Nichts wird geändert.",
    load="leicht", presets=["schnell", "hack"],
)
def authorized_keys_check(ctx, res):
    info = parse_keys(ctx.sh(KEYS_SCRIPT, timeout=45).out)
    files = info["files"]
    d = info["dir"]
    if not files:
        res.add("ok", "Keine SSH-Schlüssel für die Anmeldung hinterlegt", "Es gibt keine Datei ~/.ssh/authorized_keys. Es kann sich also niemand mit einem Schlüssel anmelden.")
        return
    days = RECENT_DAYS
    now = time.time()
    total = 0
    for name, f in files.items():
        keys, opts = f["keys"], f["options"]
        count = int(f["count"])
        total += count
        rows = ["%s  %d Bit  %s  %s" % (k["type"], k["bits"], k["fp"], ("(" + trunc(clean_line(k["comment"]), 60) + ")") if k["comment"] else "(ohne Kommentar)") for k in keys]
        if f.get("listing_failed") or (count and not keys):
            rows.append("Die Fingerabdrücke konnten nicht berechnet werden (ssh-keygen fehlt oder meldet einen Fehler). Es gibt %d Eintrag/Einträge." % count)
        res.add("info", "%s: %d Schlüssel" % (name, count), "Jeder Eintrag erlaubt die Anmeldung ohne Passwort. Der Fingerabdruck lässt sich mit dem deiner eigenen Schlüssel vergleichen "
                "(ssh-keygen -l -f ~/.ssh/id_ed25519.pub auf deinem Computer). Unbekannte Einträge entfernen.", rows)
        mt = int(f["mtime"] or 0)
        if mt and now - mt <= days * 86400:
            res.add("warn", "%s wurde in den letzten %d Tagen geändert" % (name, days), "Zuletzt geändert: %s. Hast du selbst einen Schlüssel hinzugefügt (oder dein Hoster)? "
                    "Wenn nicht, ist das ein Zeichen für Fremdzugriff." % time.strftime("%Y-%m-%d %H:%M", time.localtime(mt)), [],
                    "Unbekannte Schlüssel entfernen, danach Passwörter ändern und die Schlüssel der Seite erneuern.")
        forced = [o for o in opts if re.search(r"(?i)\bcommand\s*=", o)]
        if forced:
            res.add("warn", "%s: Schlüssel mit erzwungenem Befehl" % name, "Mit command= läuft bei jeder Anmeldung ein festgelegter Befehl. Das nutzen manche Sicherungsprogramme, aber auch Angreifer.",
                    [trunc(mask_cmd(o), 200) for o in forced[:10]], "Nur behalten, wenn du den Zweck kennst.")
        weak = [k for k in keys if k["type"] in ("DSA",) or (k["type"] == "RSA" and k["bits"] < 2048)]
        if weak:
            res.add("warn", "%s: schwache Schlüssel" % name, "DSA-Schlüssel und RSA-Schlüssel unter 2048 Bit gelten als unsicher.",
                    ["%s %d Bit %s" % (k["type"], k["bits"], k["fp"]) for k in weak])
        mode = str(f["mode"] or "")
        if mode and (int(mode[-2]) & 2 or int(mode[-1]) & 2):
            res.add("warn", "%s ist für Gruppe oder alle beschreibbar (%s)" % (name, mode), "Andere Konten könnten Schlüssel einfügen. Die Rechte sollten 600 oder 644 sein.", [],
                    "chmod 600 ~/.ssh/authorized_keys")
    if d and str(d["mode"]) and (int(str(d["mode"])[-2]) & 2 or int(str(d["mode"])[-1]) & 2):
        res.add("warn", "Der Ordner ~/.ssh ist für Gruppe oder alle beschreibbar (%s)" % d["mode"], "Andere Konten könnten dort Dateien ersetzen. Die Rechte sollten 700 sein.", [], "chmod 700 ~/.ssh")
    if not any(f.sev in ("warn", "crit") for f in res.findings):
        res.add("ok", "%d SSH-Schlüssel, keine Auffälligkeit bei Rechten, Optionen und Änderungsdatum" % total, "Das Programm kann nicht wissen, welche Schlüssel deine sind. Vergleiche die Fingerabdrücke.")


# ============================================================================ A6 Prozesse
PROC_SCRIPT = r"""
ME=$(id -un 2>/dev/null)
echo '@@PS'
ps -u "$ME" -o pid=,ppid=,etime=,args= 2>/dev/null | head -400
echo '@@EXE'
for p in $(ps -u "$ME" -o pid= 2>/dev/null | head -400); do
  e=$(readlink "/proc/$p/exe" 2>/dev/null)
  case "$e" in *"(deleted)"*) echo "$p $e";; esac
done
echo '@@SHM'
ipcs -m 2>/dev/null | awk -v me="$ME" 'NR>3 && $3==me {printf "%s %s %s\n", $1, $5, $6}' | head -n 50
echo '@@END'
"""
MINERS = re.compile(r"(?i)\b(?:xmrig|minerd|cpuminer|kdevtmpfsi|kinsing|kthreaddi|ld-linux-x86|stratum\+tcp|cryptonight)\b")
INTERP = re.compile(r"(?:^|/)(?:php(?:\d[\d.]*)?|perl|python\d?(?:\.\d+)?|ruby|node|nodejs|lua)$")
HOST_MANAGED = re.compile(r"(?i)(?:php-fpm|lsphp|php-cgi|lsphp\d|fcgi|lscgid|litespeed|apache|httpd|nginx)")
SELF_NOISE = re.compile(r"(?:readlink /proc|ps -u|@@EXE|@@PS|\bsshd:|sftp-server|-bash$|^bash$|^-?sh$|^-?zsh$|\bpsprobe\b)")


def etime_seconds(s: str) -> int:
    """ps-Laufzeit '[[dd-]hh:]mm:ss' in Sekunden."""
    m = re.match(r"^(?:(\d+)-)?(?:(\d+):)?(\d+):(\d+)\Z", (s or "").strip())
    if not m:
        return 0
    d, h, mi, se = (int(x or 0) for x in m.groups())
    return ((d * 24 + h) * 60 + mi) * 60 + se


def parse_procs(out: str) -> Dict[str, object]:
    sec = split_sections(out)
    procs = []
    for ln in (sec.get("PS", "") or "").splitlines():
        m = re.match(r"^\s*(\d+)\s+(\d+)\s+(\S+)\s+(.*)\Z", ln)
        if m:
            procs.append({"pid": int(m.group(1)), "ppid": int(m.group(2)), "etime": m.group(3), "secs": etime_seconds(m.group(3)), "args": m.group(4).strip()})
    deleted = {}
    for ln in lines_of(sec.get("EXE", "")):
        m = re.match(r"^(\d+)\s+(.*)\Z", ln.strip())
        if m:
            deleted[int(m.group(1))] = m.group(2)
    shm = []
    for ln in lines_of(sec.get("SHM", "")):
        p = ln.split()
        if len(p) >= 3 and digits(p[1]):
            shm.append({"key": p[0], "bytes": int(p[1]), "attached": p[2]})
    return {"procs": procs, "deleted": deleted, "ok": "PS" in sec, "shm": shm}


@check(
    "processes", G, "Laufende Prozesse des Kontos",
    "Läuft im Konto ein Programm, das dort nicht hingehört (Miner, Fernsteuerung, gelöschte Datei)?",
    what="Listet die Prozesse des Server-Kontos (ps) und sucht nach Mining-Programmen, Interpretern (PHP, Perl, Python), die seit Tagen laufen oder aus Temp-, Upload- oder "
         "versteckten Ordnern gestartet wurden, nach Prozessen, deren Programmdatei gelöscht wurde, und nach Fernsteuerungen. Die eigene Verbindung dieses Programms wird ausgeblendet.",
    why="Schadsoftware läuft oft als Prozess weiter, auch wenn die Datei längst gelöscht ist. Miner und Spam-Versender fallen sonst nur durch eine langsame Seite auf.",
    reads="Nur die Prozessliste des eigenen Kontos (Nummer, Laufzeit, Befehl) und für jeden Prozess, ob seine Programmdatei noch existiert. Befehlszeilen werden von Passwörtern bereinigt. Nichts wird beendet.",
    load="leicht", presets=["hack"],
)
def processes_check(ctx, res):
    r = ctx.sh(PROC_SCRIPT, timeout=45)
    info = parse_procs(r.out)
    procs = [p for p in info["procs"] if not SELF_NOISE.search(p["args"])]
    if not info["ok"] or not info["procs"]:
        res.add("info", "Prozesse nicht prüfbar", "ps liefert auf diesem Hosting keine Liste (oft aus Sicherheitsgründen gesperrt). Laufende Prozesse sind von hier aus nicht zu sehen.", [],
                "Im Kundenbereich des Hosters die Prozess- oder Ressourcenanzeige ansehen (CPU-Spitzen ohne Besucher sind verdächtig).")
        return
    crit, warn = [], []
    for p in procs:
        args = p["args"]
        exe = args.split()[0] if args else ""
        row = "PID %d, läuft seit %s: %s" % (p["pid"], p["etime"], trunc(mask_cmd(args), 200))
        why = []
        if MINERS.search(args):
            why.append("Mining-Programm")
        if p["pid"] in info["deleted"]:
            why.append("Programmdatei wurde gelöscht, der Prozess läuft weiter")
        sev, w = judge_cmd(args)
        if sev == "crit":
            why += w
        if why:
            crit.append(row + "   <- " + "; ".join(why[:2]))
            continue
        managed = bool(HOST_MANAGED.search(args))
        if INTERP.search(exe) and not managed:
            reasons = []
            if p["secs"] >= 86400:
                reasons.append("Interpreter läuft seit mehr als einem Tag")
            if sev == "warn":
                reasons += w
            if reasons:
                warn.append(row + "   <- " + "; ".join(reasons[:2]))
    if crit:
        res.add("crit", "%d verdächtige(r) Prozess(e)" % len(crit), "Diese Prozesse sind typisch für Schadsoftware (Miner, Fernsteuerung, gelöschte Programmdatei).", crit,
                "Prozess beenden (kill <PID>), die Quelle suchen (Cronjobs, SSH-Schlüssel, Web-Shells) und Passwörter erneuern. Im Zweifel den Hoster einschalten.")
    if warn:
        res.add("warn", "%d lang laufende(r) Skript-Prozess(e)" % len(warn), "PHP, Perl oder Python laufen sonst nur kurz. Ein Dauerläufer kann ein Hintergrund-Skript sein, das du nicht kennst.", warn,
                "Prüfen, ob du das Skript kennst. Sonst beenden und die Datei suchen.")
    shm = info.get("shm") or []
    if shm:
        res.add("warn", "%d Shared-Memory-Segment(e) des Kontos" % len(shm),
                "Selbstheilende WordPress-Schadsoftware (2026) legt ihren Code in einem System-V-Shared-Memory-Segment ab, damit er nach dem Löschen aller Dateien weiterlebt. "
                "PHP-Anwendungen nutzen diese Segmente normalerweise nicht.",
                ["Schlüssel %s, %d Byte, %s Anbindung(en)" % (s["key"], s["bytes"], s["attached"]) for s in shm[:20]],
                "Mit 'ipcs -m' ansehen. Gehört das Segment zu keiner Anwendung, die du kennst, vom Hoster entfernen lassen (ipcrm) und die Quelle suchen.")
    if not (crit or warn or shm):
        res.add("ok", "Keine verdächtigen Prozesse", "%d Prozess(e) des Kontos geprüft (ohne die eigene Verbindung)." % len(procs))
    else:
        res.add("info", "%d Prozess(e) des Kontos insgesamt" % len(procs), "Anzahl der Prozesse, die das Programm angesehen hat.")


# ============================================================================ A7 Start-Dateien der Shell
STARTUP = (".bashrc", ".bash_profile", ".profile", ".bash_login", ".bash_logout", ".zshrc", ".zprofile", ".zshenv", ".ssh/rc")
STARTUP_SCRIPT = (r"""
cd "$HOME" 2>/dev/null || exit 0
for f in """ + " ".join(STARTUP) + r"""; do
  if [ -f "$f" ] && [ ! -L "$f" ]; then
    echo "@@FILE $f"
    stat -c '%a %Y %s' "$f" 2>/dev/null
    echo '@@BODY'
    head -c 40000 "$f" 2>/dev/null
    echo
    echo '@@ENDFILE'
  fi
done
echo '@@END'
""")
STARTUP_EXTRA = [
    (re.compile(r"^\s*alias\s+(?:ls|ps|top|netstat|ss|who|w|last|find|ssh|sudo|su|cat|crontab|kill)\s*="), "ersetzt einen Systembefehl durch einen anderen (versteckt Spuren)"),
    (re.compile(r"\bPROMPT_COMMAND\s*=.*(?:curl|wget|base64|nc\b|bash -i)", re.I), "führt bei jeder Eingabe fremden Code aus (PROMPT_COMMAND)"),
    (re.compile(r"\bHISTFILE\s*=\s*(?:/dev/null|\"\")|\bunset\s+HISTFILE|\bHISTSIZE\s*=\s*0\b"), "schaltet das Befehlsprotokoll ab (versteckt Spuren)"),
]


def parse_startup(out: str) -> List[Dict[str, object]]:
    files = []
    for blk in re.split(r"(?m)^@@FILE ", out)[1:]:
        name, _, rest = blk.partition("\n")
        meta, _, body = rest.partition("@@BODY\n")
        p = meta.split()
        mt = int(p[1]) if len(p) >= 2 and digits(p[1]) else 0
        files.append({"name": name.strip(), "mode": p[0] if p else "", "mtime": mt, "body": body.split("@@ENDFILE")[0]})
    return files


@check(
    "shell_startup", G, "Start-Dateien der Shell (.bashrc, .profile ...)",
    "Startet eine Datei, die bei jeder Anmeldung läuft, etwas, das dort nicht hingehört?",
    what="Liest die Dateien, die bei jeder SSH-Anmeldung laufen (.bashrc, .bash_profile, .profile, .zshrc, ~/.ssh/rc u. a.), und sucht Zeilen, die Code aus dem Netz laden, "
         "verschleierten Code ausführen, Systembefehle ersetzen (alias ls=...), das Befehlsprotokoll abschalten oder etwas im Hintergrund starten. "
         "Die übliche Standardausstattung (z. B. eval \"$(dircolors -b)\") wird nicht gemeldet.",
    why="Ein Angreifer mit Dateizugriff, aber ohne Root, setzt Dauerzugänge gern in Start-Dateien: Bei jeder Anmeldung des Besitzers läuft sein Code. Das sieht kein Scan der Webseite.",
    reads="Nur diese wenigen Dateien im Home-Verzeichnis (höchstens 40 KB je Datei). Der Text wird nicht im Bericht gespeichert; auffällige Zeilen werden mit *** für Passwörter gezeigt. Nichts wird geändert.",
    load="leicht", presets=["hack"],
)
def shell_startup_check(ctx, res):
    files = parse_startup(ctx.sh(STARTUP_SCRIPT, timeout=45).out)
    if not files:
        res.add("ok", "Keine Start-Dateien der Shell gefunden", "Im Home-Verzeichnis liegt keine der geprüften Dateien (%s)." % ", ".join(STARTUP[:5]) + " ...")
        return
    now = time.time()
    bad = 0
    for f in files:
        rows, sev = [], ""
        for i, ln in enumerate(str(f["body"]).splitlines(), 1):
            s = ln.strip()
            if not s or s.startswith("#"):
                continue
            sv, why = judge_cmd(s)
            for rx, w in STARTUP_EXTRA:
                if rx.search(s):
                    why.append(w)
                    sv = sv or "warn"
            if why:
                rows.append("Zeile %d: %s   <- %s" % (i, trunc(mask_cmd(s), 200), "; ".join(why[:2])))
                if sv == "crit" or sev == "crit":
                    sev = "crit"
                else:
                    sev = "warn"
        recent = bool(f["mtime"]) and now - int(f["mtime"]) <= RECENT_DAYS * 86400
        if rows:
            bad += 1
            res.add("crit" if sev == "crit" else "warn", "%s enthält auffällige Zeilen" % f["name"], "Diese Datei läuft bei jeder Anmeldung. Zuletzt geändert: %s%s." % (
                time.strftime("%Y-%m-%d %H:%M", time.localtime(int(f["mtime"]))) if f["mtime"] else "unbekannt", " (kürzlich!)" if recent else ""), rows,
                "Wenn du die Zeilen nicht selbst eingetragen hast: entfernen (die Datei gehört dir, vorher eine Kopie ziehen) und alle Passwörter und SSH-Schlüssel erneuern.")
        elif recent:
            res.add("info", "%s wurde in den letzten %d Tagen geändert" % (f["name"], RECENT_DAYS), "Keine auffällige Zeile, aber die Datei läuft bei jeder Anmeldung. Hast du sie geändert?")
    if not bad:
        res.add("ok", "%d Start-Datei(en) geprüft, keine auffällige Zeile" % len(files), ", ".join(str(f["name"]) for f in files))


# ============================================================================ A5 Angemeldete Sitzungen
Q_WP_SESS = [("Gespeicherte Sitzungen", "SELECT m.user_id AS uid, u.user_login AS login, c.meta_value AS caps, SUBSTRING(m.meta_value, 1, 6000) AS v FROM #__usermeta m "
              "JOIN #__users u ON u.ID = m.user_id LEFT JOIN #__usermeta c ON c.user_id = m.user_id AND c.meta_key = '#__capabilities' "
              "WHERE m.meta_key = 'session_tokens' AND m.meta_value <> '' LIMIT 300")]
Q_J_SESS = [("Angemeldete Sitzungen", "SELECT s.userid AS uid, s.username AS login, s.client_id AS client, s.time AS t FROM #__session s WHERE s.guest = 0 ORDER BY s.time DESC LIMIT 300")]
SESS_RE = re.compile(r's:64:"[0-9a-f]{64}";a:\d+:\{(.*?)\}(?=s:64:"|\}$|$)', re.S)


def parse_wp_sessions(v: str) -> List[Dict[str, object]]:
    """Serialisierte WordPress-Sitzungen -> Ablaufzeit, IP, Browser, Anmeldezeit (kein Token)."""
    out = []
    for blk in SESS_RE.findall(v or ""):
        exp = re.search(r's:10:"expiration";i:(\d+);', blk)
        ip = re.search(r's:2:"ip";s:\d+:"([^"]*)";', blk)
        ua = re.search(r's:2:"ua";s:\d+:"([^"]*)";', blk)
        lg = re.search(r's:5:"login";i:(\d+);', blk)
        out.append({"exp": int(exp.group(1)) if exp else 0, "ip": ip.group(1) if ip else "", "ua": ua.group(1) if ua else "", "login": int(lg.group(1)) if lg else 0})
    return out


def _wp_admin(caps: Optional[str]) -> bool:
    return "administrator" in (caps or "")


@check(
    "sessions", G, "Angemeldete Sitzungen im Admin-Bereich",
    "Wer ist gerade (oder noch) als Administrator angemeldet, und von wo?",
    what="WordPress: liest die gespeicherten Sitzungen jedes Benutzers (Anzahl, Anmeldezeit, Ablauf, IP-Adresse, Browser; nie die Sitzungsschlüssel) und meldet Administratoren mit "
         "mehreren Sitzungen oder mehreren verschiedenen IP-Adressen. Joomla: liest die Sitzungstabelle der Datenbank, falls Joomla Sitzungen dort speichert; "
         "liegen sie im Dateisystem (Standard bei vielen Installationen), nennt die Prüfung die Grenze.",
    why="Ein Angreifer, der ein Passwort erbeutet hat, bleibt über seine Sitzung angemeldet, auch wenn du das Passwort änderst. Mehrere Sitzungen von verschiedenen Orten sind ein Warnzeichen.",
    reads="Nur Benutzername, Rolle, Zeiten, IP-Adresse (gekürzt) und Browserkennung. Sitzungsschlüssel und Passwörter werden nicht gelesen. Nichts wird geändert.",
    load="leicht", needs="db", presets=["hack"],
)
def sessions_check(ctx, res):
    if ctx.cms_name == "WordPress":
        db = need_db(ctx, res, "Angemeldete Sitzungen", Q_WP_SESS)
        rows = fetch(db, Q_WP_SESS[0][1]) or []
        now = time.time()
        shown, warn = [], []
        for r in rows:
            sess = [s for s in parse_wp_sessions(r.get("v") or "") if s["exp"] > now]
            if not sess:
                continue
            ips = sorted({ctx.mask(s["ip"]) for s in sess if s["ip"]})
            admin = _wp_admin(r.get("caps"))
            latest = max(s["login"] for s in sess)
            line = "%s%s: %d Sitzung(en), %d IP-Adresse(n)%s, jüngste Anmeldung %s" % (clean_line(r.get("login") or "?"), " [Administrator]" if admin else "", len(sess), len(ips),
                                                                                 (" (" + ", ".join(ips[:4]) + ")") if ips else "", time.strftime("%Y-%m-%d %H:%M", time.localtime(latest)) if latest else "?")
            if admin:
                shown.append(line)
                if len(sess) > 3 or len(ips) > 2:
                    warn.append(line)
        if warn:
            res.add("warn", "%d Administrator(en) mit auffällig vielen Sitzungen oder IP-Adressen" % len(warn),
                    "Mehr als drei gleichzeitige Sitzungen oder mehr als zwei IP-Adressen sind bei einer einzelnen Person selten (Handy, Büro und Zuhause ausgenommen). Das Programm kann nicht erkennen, ob es deine sind.", warn,
                    "Alle Sitzungen beenden: Benutzer -> Profil -> 'Von allen Geräten abmelden'; danach Passwort ändern. Die Aktion 'Neue Schlüssel in der wp-config.php' meldet alle ab.")
        if shown:
            res.add("info" if warn else "ok", "%d Administrator(en) mit gültiger Sitzung" % len(shown), "Gespeicherte, noch nicht abgelaufene Sitzungen. Passt das zu deinen eigenen Anmeldungen?", shown[:15])
        else:
            res.add("ok", "Keine Administrator-Sitzung gespeichert", "Keine noch gültige Sitzung eines Administrators in der Datenbank.")
        return
    # Joomla
    handler = ""
    cfg = ctx.sh("grep -E 'session_handler' configuration.php 2>/dev/null | head -1", timeout=20).out
    m = re.search(r"session_handler\s*=\s*['\"]([A-Za-z0-9_]+)['\"]", cfg)
    handler = m.group(1).lower() if m else ""
    if handler and handler != "database":
        res.add("info", "Sitzungen liegen nicht in der Datenbank (Speicherort: %s)" % handler,
                "Joomla speichert die angemeldeten Sitzungen hier in Dateien oder im Arbeitsspeicher. Von hier aus ist nicht zu sehen, wer angemeldet ist. Das ist eine Grenze der Prüfung, kein Fund.", [],
                "Im Backend unter System -> Benutzer -> 'Angemeldete Benutzer' (Globale Konfiguration -> Sitzung) ansehen, falls verfügbar.")
        return
    db = need_db(ctx, res, "Angemeldete Sitzungen", Q_J_SESS)
    rows = fetch(db, Q_J_SESS[0][1])
    if rows is None:
        res.add("info", "Sitzungstabelle nicht vorhanden", "Die Tabelle der Sitzungen fehlt oder ist leer.")
        return
    adm = [r for r in rows if str(r.get("client")) == "1"]
    lines = []
    for r in adm[:15]:
        t = int(r["t"]) if digits(str(r.get("t") or "")) else 0
        lines.append("%s: Backend-Sitzung, zuletzt aktiv %s" % (clean_line(r.get("login") or "?"), time.strftime("%Y-%m-%d %H:%M", time.localtime(t)) if t else "?"))
    names = {r.get("login") for r in adm}
    if len(adm) > 3 or len(names) > 2:
        res.add("warn", "%d Backend-Sitzungen von %d Benutzer(n)" % (len(adm), len(names)), "Viele gleichzeitige Backend-Sitzungen sind bei einer kleinen Seite ungewöhnlich.", lines,
                "Im Backend unter System -> 'Angemeldete Benutzer' abmelden bzw. in den Joomla-Einstellungen die Sitzungen beenden, danach Passwörter ändern.")
    elif adm:
        res.add("info", "%d Backend-Sitzung(en)" % len(adm), "Zurzeit gespeicherte Anmeldungen im Administrationsbereich. Passt das zu dir?", lines)
    else:
        res.add("ok", "Keine Backend-Sitzung in der Datenbank", "Zurzeit ist niemand im Administrationsbereich angemeldet (soweit Joomla es in der Datenbank speichert).")


# ============================================================================ A2 WP-Cron
Q_WP_CRON = [("WP-Cron-Plan", "SELECT SUBSTRING(option_value, 1, 60000) AS v, LENGTH(option_value) AS len FROM #__options WHERE option_name = 'cron'")]
CRON_ENTRY = re.compile(r's:(\d+):"([^"]+)";a:\d+:\{s:32:"[0-9a-f]{32}";a:')
CORE_HOOKS = {
    "wp_version_check", "wp_update_plugins", "wp_update_themes", "wp_scheduled_delete", "wp_scheduled_auto_draft_delete", "delete_expired_transients",
    "wp_privacy_delete_old_export_files", "wp_site_health_scheduled_check", "recovery_mode_clean_expired_keys", "wp_delete_temp_updater_backups",
    "wp_https_detection", "wp_update_user_counts", "publish_future_post", "importer_scheduled_cleanup", "wp_split_shared_term_batch", "wp_cron_maintenance",
    "wp_maybe_auto_update", "wp_delete_old_unattached_media", "wp_scheduled_cleanup_old_revisions", "wp_media_cleanup",
}
BAD_HOOK = re.compile(r"(?i)eval|base64|shell|backdoor|passthru|wp[_-]?vcd|wp[_-]?feed|c99|r57|exec_|_exec|system_|cmd_|payload|dropper|updater_?[0-9a-f]{4,}|^[a-z0-9]{24,}$")


def parse_cron_hooks(v: str) -> List[str]:
    """Hook-Namen aus der serialisierten Option 'cron' (nur Namen; Argumente werden nicht gelesen)."""
    seen: List[str] = []
    for m in CRON_ENTRY.finditer(v or ""):
        n = m.group(2)
        if len(n.encode("utf-8")) == int(m.group(1)) and n not in seen and not re.fullmatch(r"\d+", n):
            seen.append(n)
    return seen


@check(
    "wp_cron", G, "WordPress-Cron (geplante Aufgaben)",
    "Sind in WordPress geplante Aufgaben eingetragen, die zu keinem Plugin gehören?",
    what="Liest den Aufgabenplan von WordPress (Option 'cron' in der Datenbank), listet die Namen der Aufgaben und vergleicht sie mit denen des WordPress-Kerns. Für jede unbekannte Aufgabe wird im Programmcode "
         "(wp-content, wp-includes) gesucht, ob irgendein Plugin oder Theme sie überhaupt kennt. Aufgaben ohne Programmcode und Aufgaben mit Tarnnamen (eval, shell, wp-vcd ...) werden gemeldet.",
    why="Schadsoftware trägt sich gern in den WordPress-Cron ein: Jede Stunde läuft ihr Code, auch wenn du die Datei gelöscht hast und sie sich selbst neu anlegt. Der Plan steht in der Datenbank, "
        "wo ein Datei-Scan ihn nicht sieht.",
    reads="Nur die Namen der geplanten Aufgaben (keine Argumente) und eine Suche nach diesen Namen in den PHP-Dateien. Nichts wird geändert.",
    load="mittel", needs="db", presets=["hack"], cms="wordpress",
)
def wp_cron_check(ctx, res):
    db = need_db(ctx, res, "WordPress-Cron", Q_WP_CRON)
    rows = fetch(db, Q_WP_CRON[0][1]) or []
    if not rows or not (rows[0].get("v") or "").strip():
        res.add("info", "Kein Aufgabenplan gespeichert", "Die Option 'cron' ist leer. WordPress legt sie beim nächsten Seitenaufruf neu an.")
        return
    if digits(str(rows[0].get("len") or "0")) and int(rows[0]["len"]) > 60000:
        res.add("info", "Der Aufgabenplan ist sehr groß", "Es wurden nur die ersten 60.000 Zeichen gelesen (%s insgesamt)." % rows[0]["len"])
    hooks = parse_cron_hooks(rows[0].get("v") or "")
    unknown = [h for h in hooks if h not in CORE_HOOKS]
    bad = [h for h in unknown if BAD_HOOK.search(h)]
    orphans: List[str] = []
    check = [h for h in unknown if h not in bad][:40]
    for h in check:
        if len(h) > 200:
            bad.append(h[:60] + "...")
            continue
        r = ctx.sh("grep -rlsF --include='*.php' -e %s wp-content wp-includes 2>/dev/null | head -1" % _q(h), timeout=60)
        if not r.out.strip():
            orphans.append(h)
    if bad:
        res.add("crit", "%d geplante Aufgabe(n) mit verdächtigem Namen" % len(bad), "Die Namen ähneln Tarnnamen oder Befehlen. Ein normales Plugin benennt Aufgaben nach sich selbst.", bad[:30],
                "Prüfen, welche Datei die Aufgabe ausführt (WP Crontrol zeigt es), und entfernen: wp cron event delete <name>.")
    if orphans:
        res.add("warn", "%d geplante Aufgabe(n) ohne Programmcode" % len(orphans), "Zu diesen Namen findet sich in wp-content und wp-includes keine PHP-Datei. Meist sind es Reste gelöschter Plugins (harmlos). "
                "Schadsoftware nutzt aber dasselbe, wenn sie ihre Funktion erst zur Laufzeit aus der Datenbank nachlädt.", orphans[:30],
                "Plugin-Reste mit WP Crontrol oder 'wp cron event delete <name>' entfernen. Bei einem Namen, den du nicht zuordnen kannst, die Option 'cron' und die Datenbank nach eingeschleustem Code durchsuchen.")
    res.add("ok" if not (bad or orphans) else "info", "%d geplante Aufgabe(n), davon %d aus dem WordPress-Kern" % (len(hooks), len([h for h in hooks if h in CORE_HOOKS])),
            "Aufgaben von Plugins und Themes: %d%s." % (len(unknown), (" (davon %d geprüft)" % len(check)) if len(unknown) > len(check) else ""), unknown[:20])


def _q(v: str) -> str:
    from ..util import sq
    return sq(v)


# ============================================================================ A4 Joomla API-Zugang
Q_J_API = [("Web-Services- und Token-Plugins", "SELECT folder, element, enabled FROM #__extensions WHERE type = 'plugin' AND ((folder = 'webservices') OR (folder = 'user' AND element = 'token') OR (folder = 'api-authentication')) ORDER BY folder, element"),
           ("Benutzer mit API-Token (nur Anzahl)", "SELECT COUNT(*) AS n FROM #__user_profiles WHERE profile_key = 'joomlatoken.token'"),
           ("Abweichende Token-Schlüssel (Gegenprobe)", "SELECT profile_key, COUNT(*) AS n FROM #__user_profiles WHERE profile_key LIKE '%token%' AND profile_key NOT LIKE 'joomlatoken.%' GROUP BY profile_key LIMIT 10")]


@check(
    "joomla_api", G, "API-Zugang (Web-Services und Tokens)",
    "Ist die Programmierschnittstelle von Joomla eingeschaltet, und gibt es API-Tokens?",
    what="Fragt ab, welche Web-Services-Plugins, das API-Token-Plugin und die API-Authentifizierung aktiv sind, und zählt, wie viele Benutzer ein API-Token haben (nur die Anzahl, nie das Token).",
    why="Die API von Joomla (seit Version 4) erlaubt Lesen und Ändern von Inhalten und Benutzern mit einem Token statt Passwort. Ein vergessenes oder eingeschleustes Token ist ein Dauerzugang, den ein Passwortwechsel nicht beendet.",
    reads="Nur Plugin-Name und Status aus der Erweiterungstabelle und eine Anzahl aus den Benutzerprofilen. Tokens werden nicht gelesen. Nichts wird geändert. "
          "Der Speicherort der Tokens (Tabelle user_profiles, Schlüssel-Präfix joomlatoken) ist durch die API-Dokumentation von Joomla 4.2 belegt; Joomla 5 und 6 wurden nicht einzeln gegen den Quelltext geprüft. "
          "Als Gegenprobe meldet die Prüfung Profil-Schlüssel mit 'token' in anderer Schreibweise.",
    load="leicht", needs="db", presets=["hack"],
)
def joomla_api_check(ctx, res):
    db = need_db(ctx, res, "API-Zugang", Q_J_API)
    plugs = fetch(db, Q_J_API[0][1]) or []
    on = [p for p in plugs if str(p.get("enabled")) == "1"]
    cnt_rows = fetch(db, Q_J_API[1][1])
    n = int((cnt_rows or [{}])[0].get("n") or 0) if cnt_rows else 0
    web_on = [p for p in on if p.get("folder") == "webservices"]
    tok_on = [p for p in on if p.get("folder") == "user" and p.get("element") == "token"]
    items = ["%s/%s: %s" % (p.get("folder"), p.get("element"), "aktiv" if str(p.get("enabled")) == "1" else "aus") for p in plugs]
    odd = fetch(db, Q_J_API[2][1]) or []
    if odd:
        res.add("info", "%d Profil-Schlüssel mit 'token' in anderer Schreibweise" % len(odd),
                "Das Programm sucht die Joomla-Tokens unter 'joomlatoken.*' (Joomla 4.2 bestätigt). Diese Schlüssel haben einen anderen Aufbau: Entweder gehören sie zu einer Erweiterung, "
                "oder eine Joomla-Version speichert Tokens anders. Dann wäre die Zahl oben zu niedrig.",
                ["%s (%s Einträge)" % (clean_line(str(o.get("profile_key"))), o.get("n")) for o in odd],
                "Schlüssel prüfen: Gehören sie zu einer dir bekannten Erweiterung? Wenn nicht, im Backend unter Benutzer die Token-Felder ansehen.")
    if not plugs:
        res.add("info", "Keine Web-Services-Plugins gefunden", "Diese Joomla-Version kennt die API vermutlich nicht (vor Joomla 4).")
        return
    if tok_on and n:
        res.add("warn", "%d Benutzer mit API-Token, API-Zugang aktiv" % n, "Mit dem Token erreicht man die Schnittstelle ohne Passwort. Unbekannte Tokens sind ein Dauerzugang.", items,
                "Backend -> Benutzer -> Benutzer bearbeiten -> Reiter 'Joomla API Token': Token neu erzeugen oder das Plugin 'Benutzer - Joomla API-Token' ausschalten, wenn du die API nicht brauchst.")
    elif web_on:
        res.add("info", "Web-Services aktiv, aber kein API-Token gefunden", "Die Schnittstelle ist an. Ohne Token ist sie nur mit Anmeldedaten nutzbar. Wenn du sie nicht brauchst, die Plugins ausschalten.", items)
    else:
        res.add("ok", "Keine aktive API mit Token", "Es sind keine Web-Services-Plugins aktiv oder kein Benutzer hat ein Token.", items)
