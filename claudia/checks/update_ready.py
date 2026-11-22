"""Lässt sich die Seite automatisch aktualisieren? (Joomla und WordPress)

Rein lesend. Geprüft wird alles, woran ein Update im Dashboard/Backend in der Praxis scheitert: Schreibrechte der Kernordner,
Besitzer der Dateien, Reste abgebrochener Updates, freier Speicher, PHP-Module, Erreichbarkeit der Update-Server und
Einstellungen, die Updates sperren. Nur wenn alles in Ordnung ist, steht am Ende die Erfolgsmeldung. Sonst gibt es nur die Befunde
mit der passenden Lösung (soweit das Programm sie sicher selbst ausführen kann)."""
from __future__ import annotations

import os
import re
from typing import List

from ..registry import check
from ..util import clean_line, lines_of, split_sections

G = "grundlagen"

# Ordner, die bei einem Kern-Update überschrieben werden (ohne Uploads, Cache, tmp)
CORE_DIRS = {
    "joomla": "administrator api cli components includes language layouts libraries media modules plugins templates",
    "wordpress": "wp-admin wp-includes wp-content/plugins wp-content/themes wp-content/mu-plugins wp-content/languages",
}
# Verzeichnisse selbst, die Schreibrecht brauchen, damit Pakete entpackt werden können
WRITE_DIRS = {
    "joomla": ". tmp administrator/components/com_joomlaupdate",
    "wordpress": ". wp-content wp-content/upgrade",
}
MODULE_WHY = {
    "zlib": "komprimiert und entpackt Daten (gzip); nötig für Update-Pakete",
    "zip": "entpackt ZIP-Dateien, also Update- und Erweiterungspakete (zlib ist der Ersatz)",
    "json": "Datenformat für Einstellungen und Schnittstellen; ab PHP 8.0 fest eingebaut",
    "mbstring": "kürzt, sucht und wandelt Text mit Umlauten und Sonderzeichen (UTF-8) richtig",
    "xml": "liest XML: Update-Server-Listen und Erweiterungs-Beschreibungen",
    "openssl": "verschlüsselte Verbindungen aus PHP heraus (https-Downloads, SMTP mit TLS, Verschlüsselung)",
    "mysqli": "Verbindung zur MySQL-/MariaDB-Datenbank",
}
UPDATE_SERVER = {
    "joomla": "https://update.joomla.org/core/list.xml",
    "wordpress": "https://api.wordpress.org/core/version-check/1.7/",
}

SCRIPT = r"""
ME=$(id -un); echo '@@ME'; echo "$ME"; id -Gn | tr ' ' ','
echo '@@FREE'; df -Pk . 2>/dev/null | awk 'NR==2{print $4}'
echo '@@CORESIZE'; du -sk @CORE@ 2>/dev/null | awk '{s+=$1} END{print s+0}'
echo '@@LOCKED_OWN'
# Dateien/Ordner im Kern, die dem eigenen Konto gehören, aber kein Schreibrecht für den Besitzer haben (Update scheitert dort)
for d in @CORE@; do [ -d "$d" ] && find "$d" -xdev \( -type f -o -type d \) -user "$ME" ! -perm -u+w -printf '%m\t%y\t./%p\n' 2>/dev/null; done | head -120
for d in @WRITE@; do [ -d "$d" ] && [ "$d" != "." ] && find "$d" -maxdepth 0 -user "$ME" ! -perm -u+w -printf '%m\t%y\t./%p\n' 2>/dev/null; done | head -20
find . -maxdepth 1 -type f \( @ROOTFILES@ \) -user "$ME" ! -perm -u+w -printf '%m\t%y\t./%p\n' 2>/dev/null | head -20
[ -d . ] && find . -maxdepth 0 -user "$ME" ! -perm -u+w -printf '%m\t%y\t.\n' 2>/dev/null
echo '@@LOCKED_OTHER'
# Gehört einem anderen Konto und weder für alle noch für die Gruppe beschreibbar
for d in @CORE@; do [ -d "$d" ] && find "$d" -xdev \( -type f -o -type d \) ! -user "$ME" ! -perm -0002 ! -perm -0020 -printf '%u\t%m\t%y\t./%p\n' 2>/dev/null; done | head -120
echo '@@WORLDW'
for d in @CORE@; do [ -d "$d" ] && find "$d" -xdev \( -type f -o -type d \) -perm -0002 ! -type l -printf '%m\t./%p\n' 2>/dev/null; done | head -120
echo '@@WEBOWNER'
# Welcher Benutzer legt Dateien an, wenn die Webseite läuft? (Besitzer von Zwischenspeicher-Dateien)
for d in @SPOOL@; do [ -d "$d" ] && find "$d" -maxdepth 2 -type f ! -name index.html ! -name .htaccess -printf '%u\n' 2>/dev/null | head -20; done | sort | uniq -c | sort -rn | head -3
echo '@@LEFT'
@LEFT@
echo '@@PHP'
@PICK@if [ -n "$P" ]; then
  echo "BIN $P"
  timeout 10 "$P" -r 'echo "VER ".PHP_VERSION."\nMEM ".ini_get("memory_limit")."\nURLFOPEN ".ini_get("allow_url_fopen")."\nEXEC ".ini_get("max_execution_time")."\n";' </dev/null 2>/dev/null
  timeout 10 "$P" -m </dev/null 2>/dev/null | tr 'A-Z' 'a-z' | grep -E '^(zip|zlib|curl|openssl|json|mbstring|xml|dom|simplexml|mysqli|mysqlnd|pdo_mysql|hash)$' | sed 's/^/MOD /'
fi
echo '@@NET'
if command -v curl >/dev/null 2>&1; then
  c=$(curl -s -m 10 -o /dev/null -w '%{http_code}' -A 'CLAUDIA-Check' @URL@ 2>/dev/null); echo "${c:-000}"
else echo 'KEIN_CURL'; fi
echo '@@END'
"""

LEFT = {
    "joomla": r"""
for p in tmp/joomla_update* tmp/jupdate* tmp/*.zip tmp/*.tar.gz administrator/components/com_joomlaupdate/restoration.php administrator/components/com_joomlaupdate/update.php; do
  [ -e "$p" ] && printf 'LEFT\t%s\t%s\n' "$(stat -c '%Y' "$p" 2>/dev/null)" "$p"
done | head -30
""",
    "wordpress": r"""
[ -f .maintenance ] && printf 'MAINT\t%s\t%s\n' "$(stat -c '%Y' .maintenance 2>/dev/null)" "$(head -c 200 .maintenance | tr -d '\n\r')"
for p in wp-content/upgrade/* wp-content/upgrade-temp-backup; do
  [ -e "$p" ] && printf 'LEFT\t%s\t%s\n' "$(stat -c '%Y' "$p" 2>/dev/null)" "$p"
done | head -30
""",
}


def _to_kb(txt: str) -> int:
    return int(txt) if txt.strip().isdigit() else 0


def _mem_mb(v: str) -> int:
    """memory_limit in MB (-1 = unbegrenzt)."""
    v = (v or "").strip().lower()
    if v in ("-1", "unlimited"):
        return 10 ** 6
    m = re.match(r"^(\d+)\s*([kmg]?)", v)
    if not m:
        return 0
    n = int(m.group(1))
    return {"": n // 1048576, "k": n // 1024, "m": n, "g": n * 1024}[m.group(2)]


@check(
    "update_ready", G, "Lässt sich die Seite automatisch aktualisieren?",
    "Sind Rechte, Speicher, PHP und Update-Server so, dass ein Update im Backend gelingt?",
    what="Prüft alles, woran ein automatisches Update in der Praxis scheitert: Schreibrechte der Kernordner und wer sie besitzt, falsch gesetzte Rechte, "
         "Reste abgebrochener Updates, freien Speicherplatz, PHP-Module (zip, curl, openssl ...), den PHP-Speicher, die Erreichbarkeit des Update-Servers und "
         "Einstellungen, die Updates sperren. Meldet nur dann 'in Ordnung', wenn nichts im Weg steht.",
    why="Ein Update, das mittendrin abbricht, hinterlässt eine halb aktualisierte Seite. Fehlende Schreibrechte sind der häufigste Grund, warum Seiten nicht "
        "aktualisiert werden - und damit lange auf einem verwundbaren Stand bleiben. Falsch gesetzte Rechte (z. B. 777) sind außerdem selbst ein Sicherheitsrisiko.",
    reads="Nur Rechte, Besitzer, Dateinamen, freien Platz und PHP-Einstellungen. Eine einzige Abfrage der Update-Adresse (nur Statuscode, verschlüsselt). Nichts wird verändert.",
    load="leicht", presets=["schnell", "hack"],
    wp={"title": "Lässt sich WordPress automatisch aktualisieren?",
        "summary": "Sind Rechte, Speicher, PHP und Update-Server so, dass ein Update im Dashboard gelingt?"},
)
def update_ready(ctx, res):
    cms = ctx.cms
    name = ctx.prof["name"]
    cfg = ctx.config()
    core = CORE_DIRS[cms]
    spool = ctx.prof["spool"]
    rootfiles = ctx.prof["root_find"]
    script = (SCRIPT.replace("@CORE@", core).replace("@WRITE@", WRITE_DIRS[cms]).replace("@ROOTFILES@", rootfiles).replace("@SPOOL@", spool)
              .replace("@LEFT@", LEFT[cms]).replace("@PICK@", ctx.php_pick()).replace("@URL@", UPDATE_SERVER[cms]))
    out = ctx.sh(script, timeout=150, raw="updatebereitschaft").out
    sec = split_sections(out)
    me_l = lines_of(sec.get("ME", ""))
    me = me_l[0] if me_l else ""
    problems: List[str] = []        # kurze Titel der gefundenen Probleme (für die Zusammenfassung)
    checked: List[str] = []         # was geprüft wurde und in Ordnung ist
    notes: List[str] = []           # was sich nicht prüfen ließ

    # ---- Schreibrechte
    own = []
    for ln in lines_of(sec.get("LOCKED_OWN", "")):
        p = ln.split("\t")
        if len(p) >= 3:
            own.append("%s  %s" % (p[0].zfill(3), clean_line(p[2])))
    if own:
        problems.append("rechte")
        res.add("crit", "%d Datei(en)/Ordner ohne Schreibrecht für den Besitzer - ein Update scheitert dort" % len(own),
                "Diese Einträge gehören dem Konto '%s', haben aber kein Schreibrecht (z. B. 444 oder 555). %s kann sie beim Update nicht ersetzen. "
                "Das Update bricht dann mitten im Kopieren ab oder verlangt FTP-Zugangsdaten." % (me, name),
                own[:80], "Schreibrecht für den Besitzer wiederherstellen (Dateien 644, Ordner 755). Das kann das Programm für dich erledigen.")
    else:
        checked.append("Schreibrechte der Kernordner")
    other = []
    for ln in lines_of(sec.get("LOCKED_OTHER", "")):
        p = ln.split("\t")
        if len(p) >= 4:
            other.append("%s  %s:  %s" % (p[1].zfill(3), p[0], clean_line(p[3])))
    if other:
        problems.append("fremd")
        res.add("crit", "%d Datei(en)/Ordner gehören einem anderen Konto und sind für dich gesperrt" % len(other),
                "Sie wurden von einem anderen Benutzer angelegt (oft 'root', durch einen früheren Server-Wechsel oder ein Skript mit Administratorrechten). "
                "Du und %s können sie nicht ändern, ein Update scheitert." % name,
                other[:80], "Das lässt sich nur mit höheren Rechten ändern: Wende dich an den Hoster (Besitzer auf dein Konto setzen) oder lösche und lade die Dateien neu hoch.")
    world = []
    for ln in lines_of(sec.get("WORLDW", "")):
        p = ln.split("\t", 1)
        if len(p) == 2:
            world.append("%s  %s" % (p[0].zfill(3), clean_line(p[1])))
    if world:
        problems.append("falsche Rechte")
        res.add("warn", "%d Datei(en)/Ordner im %s-Kern für alle beschreibbar (falsch gesetzte Rechte)" % (len(world), name),
                "Rechte wie 777 oder 666 sind nie nötig. Jedes andere Konto auf dem Server kann dort Code ablegen. Außerdem verweigern manche Server "
                "(und %s selbst) bei so gesetzten Rechten Updates oder melden einen Fehler." % name,
                world[:80], "Schreibrecht für 'alle' entfernen (Dateien 644, Ordner 755). Das kann das Programm für dich erledigen.")
    else:
        checked.append("keine falsch gesetzten Rechte (777/666) im Kern")

    # ---- Webserver-Benutzer
    wo = [l.split() for l in lines_of(sec.get("WEBOWNER", ""))]
    owners = {w[1]: int(w[0]) for w in wo if len(w) >= 2 and w[0].isdigit()}
    if me and owners:
        foreign = {u: n for u, n in owners.items() if u != me}
        if foreign and me not in owners:
            problems.append("webbenutzer")
            u = max(foreign, key=foreign.get)
            res.add("warn", "Der Webserver läuft vermutlich unter einem anderen Benutzer als dein Konto ('%s' statt '%s')" % (u, me),
                    "Dateien, die die Webseite selbst anlegt (Zwischenspeicher, Uploads), gehören '%s'. Deine Kerndateien gehören '%s'. Ein Update im %s kann sie dann "
                    "nicht überschreiben; %s fragt stattdessen nach FTP-Zugangsdaten oder bricht ab." % (u, me, ctx.prof["admin_word"], name),
                    ["Besitzer der von der Seite angelegten Dateien: %s" % u, "Besitzer der Kerndateien: %s" % me],
                    "Aktualisiere über die Kommandozeile (das macht das Programm im Bereich 'Updates' mit dem Konto '%s'), oder frage den Hoster nach 'Dateien als Konto-Benutzer ausführen' (suPHP/PHP-FPM)." % me)
        else:
            checked.append("Benutzer von Webserver und Dateien stimmen überein")
    else:
        notes.append("Benutzer des Webservers (noch keine von der Seite angelegten Dateien gefunden)")

    # ---- Reste alter Updates
    left, has_maint = [], False
    for ln in lines_of(sec.get("LEFT", "")):
        p = ln.split("\t", 2)
        if p[0] == "MAINT":
            has_maint = True
        elif p[0] == "LEFT" and len(p) >= 3:
            left.append(clean_line(p[2]))
    if has_maint:
        problems.append("maintenance")
        res.add("crit", ".maintenance liegt im Hauptordner (Wartungsmodus hängt)",
                "WordPress legt diese Datei während eines Updates an und löscht sie danach. Bleibt sie liegen, zeigt die Seite 'Kurz nicht verfügbar wegen Wartungsarbeiten' "
                "und weitere Updates werden verweigert. Das passiert, wenn ein Update abbricht.",
                [".maintenance"], "Datei .maintenance löschen. Das kann das Programm für dich erledigen (die Datei enthält nur einen Zeitstempel).")
    if left:
        problems.append("reste")
        in_comp = [x for x in left if "com_joomlaupdate/" in x]
        in_tmp = [x for x in left if x not in in_comp]
        text = ("Liegengebliebene Update-Pakete und Entpack-Ordner können das nächste Update stören und belegen Platz. Sie sind außerdem ein beliebter Ablageort für Schadcode.")
        if in_comp:
            text += (" Die Dateien update.php und restoration.php im Ordner com_joomlaupdate legt Joomla nur während eines Updates an und löscht sie danach. "
                     "Liegen sie noch dort, ist das letzte Update nicht sauber zu Ende gelaufen. Die Datei extract.php gehört dagegen zum Joomla-Kern und wird hier nicht gemeldet.")
        hint = ("Temp-Ordner leeren (das Programm sichert den Inhalt vorher und kann es für dich erledigen)." if in_tmp else
                "Läuft gerade kein Update, die genannte(n) Datei(en) per SFTP herunterladen (als Sicherung) und dann auf dem Server löschen. Danach Prüfung wiederholen.")
        if in_tmp and in_comp:
            hint += " Die Dateien in com_joomlaupdate löschst du, wenn kein Update läuft, per SFTP (vorher herunterladen)."
        res.add("warn", "%d Rest(e) abgebrochener oder alter Updates" % len(left), text, left[:30], hint)
    if not (has_maint or left):
        checked.append("keine Reste abgebrochener Updates")

    # ---- Speicherplatz
    free, size = _to_kb((lines_of(sec.get("FREE", "")) or [""])[0]), _to_kb((lines_of(sec.get("CORESIZE", "")) or [""])[0])
    if free:
        need = max(150_000, size * 3 + 50_000)      # Entpacken + Sicherungskopie + Reserve
        if free < 60_000:
            problems.append("platz")
            res.add("crit", "Fast kein freier Speicherplatz (%d MB)" % (free // 1024),
                    "Ein Update braucht Platz für das Paket, das Entpacken und eine Sicherungskopie. Mit so wenig Platz bricht es ab und kann Dateien halb geschrieben zurücklassen.",
                    ["frei: %d MB" % (free // 1024), "empfohlen: mindestens %d MB" % (need // 1024)],
                    "Platz schaffen (alte Sicherungen und Protokolle löschen, siehe 'Lösungen auf Knopfdruck') oder beim Hoster mehr Speicher buchen.")
        elif free < need:
            problems.append("platz")
            res.add("warn", "Wenig freier Speicherplatz (%d MB)" % (free // 1024),
                    "Für ein Update werden etwa %d MB empfohlen (Paket, Entpacken, Sicherungskopie)." % (need // 1024),
                    ["frei: %d MB" % (free // 1024), "Kern: %d MB" % (size // 1024)],
                    "Alte Sicherungen und Protokolle löschen (siehe 'Lösungen auf Knopfdruck').")
        else:
            checked.append("freier Speicherplatz (%d MB)" % (free // 1024))
    else:
        notes.append("freier Speicherplatz (der Server gibt ihn nicht an; Kontingente des Hosters sind so nicht sichtbar)")

    # ---- PHP
    php = {"mods": set()}
    for ln in lines_of(sec.get("PHP", "")):
        k, _, v = ln.partition(" ")
        if k == "MOD":
            php["mods"].add(v.strip())
        elif k in ("BIN", "VER", "MEM", "URLFOPEN", "EXEC"):
            php[k] = v.strip()
    if php.get("BIN") and not php["mods"]:
        notes.append("PHP-Module (die Modulliste war leer: 'php -m' ist auf diesem Server vermutlich gesperrt; es wurde nichts bewertet)")
    elif php.get("BIN"):
        mods = php["mods"]
        wv = str((ctx.shared.get("php_web") or {}).get("version") or "")
        sure = bool(wv) and str(php.get("VER", "")).startswith(wv)
        sev = "crit" if sure else "warn"
        src = ["gemessen mit %s (PHP %s, Kommandozeile)" % (php["BIN"], php.get("VER", "?")),
               "Der Webserver nutzt %s." % (("PHP " + wv) if wv else "eine nicht erkannte PHP-Version; sie kann andere Module haben")]
        miss = []
        need_mods = ctx.prof["need_mods"]
        for mod in need_mods:
            if mod not in mods and not (mod == "mysqli" and "mysqlnd" in mods and "pdo_mysql" in mods):
                miss.append(mod)
        if miss:
            problems.append("module")
            res.add(sev, "PHP-Modul(e) fehlen: %s" % ", ".join(miss),
                    "Ohne diese Module kann %s das Update-Paket nicht lesen oder entpacken. %s" % (name, "" if sure else "Gemessen wurde aber nicht zwingend das PHP der Webseite."),
                    ["%s: %s" % (m_, MODULE_WHY.get(m_, "")) for m_ in miss] + src,
                    "Im Hosting-Paneel unter 'PHP-Einstellungen' das Modul aktivieren oder den Hoster bitten.")
        if "zip" not in mods and "zlib" not in mods:
            problems.append("zip")
            res.add(sev, "Weder PHP-Modul 'zip' noch 'zlib' vorhanden",
                    "Update-Pakete sind ZIP-Dateien und können so nicht entpackt werden.", ["zip/zlib: " + MODULE_WHY["zip"]] + src, "Im Hosting-Paneel unter 'PHP-Einstellungen' 'zip' oder 'zlib' aktivieren.")
        elif "zip" not in mods and ctx.prof["zip_note"]:
            notes.append(ctx.prof["zip_note"])
        if "openssl" not in mods or ("curl" not in mods and php.get("URLFOPEN", "") in ("", "0", "Off", "off")):
            if "openssl" not in mods:
                problems.append("ssl")
                res.add(sev, "PHP-Modul 'openssl' fehlt",
                        "PHP-Skripte können dann keine verschlüsselten Verbindungen aufbauen (Update-Downloads über https, SMTP mit TLS). Das Zertifikat deiner Seite (z. B. von Let's Encrypt) ist davon unabhängig: "
                        "es wird vom Webserver bzw. Hoster verwaltet und braucht dieses Modul nicht.",
                        ["openssl: " + MODULE_WHY["openssl"]] + src, "Im Hosting-Paneel unter 'PHP-Einstellungen' 'openssl' aktivieren.")
            if "curl" not in mods and php.get("URLFOPEN", "") in ("", "0", "Off", "off"):
                problems.append("download")
                res.add(sev, "Der Server kann keine Update-Pakete laden (weder curl noch allow_url_fopen)",
                        "%s braucht eines von beiden, um das Paket vom Update-Server zu holen." % name,
                        ["curl: %s" % ("ja" if "curl" in mods else "nein"), "allow_url_fopen: %s" % (php.get("URLFOPEN") or "aus")] + src,
                        "Im Hosting-Paneel unter 'PHP-Einstellungen' 'curl' oder 'allow_url_fopen' aktivieren.")
        if not (miss or "openssl" not in mods):
            checked.append("PHP-Module (zlib/zip, openssl, curl bzw. allow_url_fopen)")
        mem = _mem_mb(php.get("MEM", ""))
        if mem and mem < 128:
            problems.append("memory")
            res.add("warn", "PHP-Speicherlimit ist niedrig (%s)" % php.get("MEM"),
                    "Beim Entpacken großer Update-Pakete reichen weniger als 128 MB oft nicht; das Update bricht dann mit einem leeren oder weißen Bildschirm ab.",
                    ["memory_limit: %s" % php.get("MEM"), "PHP der Kommandozeile: %s" % php.get("VER", "?")],
                    "Im Hosting-Paneel 'memory_limit' auf mindestens 128M (besser 256M) erhöhen.")
        elif mem:
            checked.append("PHP-Speicherlimit (%s)" % php.get("MEM"))
    else:
        notes.append("PHP-Module und -Limits (auf der Kommandozeile wurde kein PHP gefunden; der Webserver kann trotzdem eines haben)")

    # ---- Update-Server
    net = [l.strip() for l in lines_of(sec.get("NET", ""))]
    code = net[0] if net else ""
    if os.environ.get("CLAUDIA_OFFLINE"):
        notes.append("Erreichbarkeit des Update-Servers (Offline-Modus)")
    elif code == "KEIN_CURL":
        notes.append("Erreichbarkeit des Update-Servers (auf dem Server fehlt das Programm curl)")
    elif re.match(r"^\d{3}$", code) and code.startswith("2"):
        checked.append("Update-Server erreichbar (%s)" % re.sub(r"^https://([^/]+)/.*$", r"\1", UPDATE_SERVER[cms]))
    elif code and code != "000":
        problems.append("updateserver")
        res.add("warn", "Der Update-Server antwortet mit einem Fehler (HTTP %s)" % code,
                "Das kann kurzfristig sein. Bleibt es, scheitern Updates.", [UPDATE_SERVER[cms]], "Später erneut prüfen. Bleibt es dabei: Hoster fragen, ob ausgehende Verbindungen gesperrt sind.")
    else:
        problems.append("updateserver")
        res.add("warn", "Der Server erreicht den Update-Server nicht",
                "Ausgehende Verbindungen sind blockiert oder DNS/Zertifikate sind kaputt. Dann findet %s keine Updates und kann keine laden." % name,
                [UPDATE_SERVER[cms]],
                "Beim Hoster nachfragen, ob ausgehende HTTPS-Verbindungen erlaubt sind und die Zertifikate aktuell sind.")

    # ---- Einstellungen, die Updates sperren (WordPress)
    if cms == "wordpress":
        d = (cfg.get("defines") or {})
        def on(k):
            return str(d.get(k, "")).strip().lower() in ("true", "1")
        blockers = []
        if on("DISALLOW_FILE_MODS"):
            blockers.append("DISALLOW_FILE_MODS ist an: Installieren und Aktualisieren ist im Dashboard komplett gesperrt")
        if on("AUTOMATIC_UPDATER_DISABLED"):
            blockers.append("AUTOMATIC_UPDATER_DISABLED ist an: Hintergrund-Updates sind aus")
        if str(d.get("WP_AUTO_UPDATE_CORE", "")).strip().lower() in ("false", "0"):
            blockers.append("WP_AUTO_UPDATE_CORE ist aus: Sicherheits-Updates des Kerns kommen nicht von selbst")
        fs = str(d.get("FS_METHOD", "")).strip("'\" ").lower()
        if fs and fs != "direct":
            blockers.append("FS_METHOD = %s: WordPress verlangt bei jedem Update FTP-/SSH-Zugangsdaten" % fs)
        if blockers:
            problems.append("sperre")
            res.add("warn", "In der wp-config.php sind Updates eingeschränkt oder gesperrt", "Das ist manchmal Absicht (z. B. bei Updates per Deployment), sonst eine Update-Bremse.",
                    blockers, "Zeile in der wp-config.php entfernen oder auf 'false' setzen, wenn du Updates im Dashboard willst. Das Programm ändert diese Zeilen nicht selbst.")
        else:
            checked.append("keine Update-Sperren in der wp-config.php")

    ctx.shared["update_ready_problems"] = problems
    if problems:
        return          # nur Befunde, keine Erfolgsmeldung
    items = ["geprüft: " + c for c in checked]
    items += ["nicht prüfbar: " + n for n in notes]
    res.add("ok", "%s lässt sich automatisch aktualisieren - es steht nichts im Weg" % name,
            "Alle Voraussetzungen, die sich von hier aus prüfen lassen, sind erfüllt.", items)
