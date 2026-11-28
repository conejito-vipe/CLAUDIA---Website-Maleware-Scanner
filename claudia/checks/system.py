"""Grundlagen & Umfeld: Joomla-Version, Hauptverzeichnis, Dateirechte, weitere Installationen."""
from __future__ import annotations

import re
from typing import List, Optional

from .. import joomla
from ..model import CheckSkipped, Option
from ..registry import check
from ..probe import PHP_PROBE_SCRIPT, parse_php_probe
from ..util import clean_line, lines_of, split_sections, sq, trunc, vcmp

G = "grundlagen"


def env_items(ctx, sec, out):
    """Umgebungsangaben (Benutzer, Verzeichnis, PHP, Speicher) als Liste für die Anzeige; gemeinsam für Joomla und WordPress."""
    phpinfo = parse_php_probe(out)
    who = lines_of(sec.get("WHO", ""))
    items = []
    if who:
        items.append("Server-Benutzer: %s" % who[0])
    if len(who) > 1:
        items.append("Verzeichnis: %s" % who[1])
    web = ctx.shared.get("php_web") or {}
    if web.get("version"):
        items.append("PHP der Webseite: %s (erkannt über: %s)" % (web["version"], web["source"]))
        ctx.shared["php_version"] = "PHP " + web["version"]
    else:
        items.append("PHP der Webseite: nicht erkannt%s" % ((" (" + web["note"] + ")") if web.get("note") else ""))
    if phpinfo["php"]:
        via = "" if phpinfo["php_source"] == "php" else " (über %s)" % phpinfo["php_source"]
        items.append("PHP (Kommandozeile, kann von der Webseite abweichen): %s%s" % (phpinfo["php"], via))
        ctx.shared.setdefault("php_version", phpinfo["php"])
    else:
        items.append("PHP (Kommandozeile): nicht erkannt. %s" % phpinfo["php_note"])
    if phpinfo["php_hint"]:
        items.append("Hinweis aus der .htaccess: %s" % trunc(phpinfo["php_hint"], 140))
    if phpinfo.get("php_installed") and not phpinfo["php"]:
        items.append("Auf dem Server installierte PHP-Versionen: %s" % ", ".join(
            v.replace("PHP ", "") for v in phpinfo["php_installed"]))
    if phpinfo["php_candidates"]:
        items.append("Gefundene PHP-Programme: " + ", ".join(
            "%s%s" % (c["name"], (" = " + c["version"]) if c["version"] else "") for c in phpinfo["php_candidates"][:4]))
    disk = lines_of(sec.get("DISK", ""))
    if disk:
        items.append("Speicher: %s" % trunc(re.sub(r"\s+", " ", disk[0]), 100))
    return items


def cms_branch_finding(cms: str, version: str, adv: dict, today: Optional[float] = None):
    """Lebensende der CMS-Reihe. Liefert (Stufe, Titel, Text, Hinweis) oder None, wenn nichts zu melden ist.

    Joomla hat feste Termine (Liste cms_eol in advisories.json). WordPress hat keine: nur die neueste Hauptversion gilt als unterstützt,
    ältere Reihen bekommen Sicherheitsfixes nur aus Kulanz; gemeldet wird, wie viele Reihen die Seite hinter der neuesten liegt."""
    import time as _t
    now = _t.time() if today is None else today
    eol = adv.get("cms_eol", {}) or {}
    stand = eol.get("stand", "?")

    def ts(d: str) -> float:
        return _t.mktime(_t.strptime(d, "%Y-%m-%d"))
    if cms == "joomla":
        major = (version or "").split(".")[0]
        for b in eol.get("joomla", []):
            if b.get("branch") != major:
                continue
            end, act = ts(b["eol"]), ts(b["active_end"])
            note = "Quelle: endoflife.date, Stand der Liste %s. Das Projekt kann Termine ändern." % stand
            if now > end:
                return ("crit", "Joomla %s wird nicht mehr gepflegt (Ende der Sicherheitsfixes am %s)" % (major, b["eol"]),
                        "Neue Sicherheitslücken werden in dieser Reihe nicht mehr geschlossen. Jede neu bekannt werdende Lücke bleibt offen. " + note,
                        "Auf die aktuelle Joomla-Hauptversion wechseln (vorher Erweiterungen und Template auf Kompatibilität prüfen, Sicherung anlegen).")
            if now > end - 180 * 86400:
                return ("warn", "Joomla %s bekommt nur noch bis %s Sicherheitsfixes" % (major, b["eol"]),
                        "In weniger als einem halben Jahr endet die Pflege dieser Reihe. " + note, "Den Wechsel auf die aktuelle Hauptversion jetzt planen.")
            if now > act:
                return ("info", "Joomla %s: nur noch Sicherheitsfixes bis %s" % (major, b["eol"]),
                        "Die aktive Weiterentwicklung dieser Reihe endete am %s; es kommen nur noch Sicherheitskorrekturen. %s" % (b["active_end"], note),
                        "Den Wechsel auf die neueste Hauptversion einplanen.")
        return None
    if cms == "wordpress":
        latest = (adv.get("wordpress", {}) or {}).get("latest_known", "")
        m1 = re.match(r"^(\d+)\.(\d+)", version or "")
        m2 = re.match(r"^(\d+)\.(\d+)", latest or "")
        if not (m1 and m2):
            return None
        behind = (int(m2.group(1)) * 10 + int(m2.group(2))) - (int(m1.group(1)) * 10 + int(m1.group(2)))
        note = "WordPress nennt nur die neueste Hauptversion offiziell unterstützt; ältere Reihen bekommen Sicherheitsfixes nur aus Kulanz, ohne Zusage und ohne Frist (wordpress.org, Supported Versions). Vergleich mit der Liste vom %s." % stand
        if behind >= 2:
            return ("warn", "WordPress %s.%s liegt %d Reihen hinter der neuesten (%s.%s)" % (m1.group(1), m1.group(2), behind, m2.group(1), m2.group(2)),
                    "Diese Reihe ist nicht mehr offiziell unterstützt. " + note, "Auf die neueste WordPress-Version aktualisieren.")
        if behind == 1:
            return ("info", "WordPress %s.%s ist nicht mehr die neueste Reihe" % (m1.group(1), m1.group(2)),
                    "Die Vorgänger-Reihe bekommt Sicherheitsfixes nur aus Kulanz. " + note, "Auf die neueste Reihe aktualisieren.")
    return None


# ----------------------------------------------------------------------------- Joomla-Version
@check(
    "joomla_info", G, "Joomla-Version und Umgebung",
    "Welche Joomla-Version läuft, unter welchem Benutzer und mit welchem PHP?",
    what="Liest die Versionsdatei von Joomla (libraries/src/Version.php) und fragt Benutzernamen, Verzeichnis, "
         "PHP-Version der Kommandozeile und freien Speicherplatz ab. Vergleicht die Joomla-Version mit der neuesten "
         "Version, die dem Programm bekannt ist, und meldet, wenn die Joomla-Reihe (z. B. 4.x) keine Sicherheitsfixes mehr bekommt oder bald nicht mehr bekommt.",
    why="Veraltete Joomla-Versionen sind das häufigste Einfallstor. Die Prüfung zeigt außerdem sofort, ob das "
        "eingegebene Verzeichnis wirklich eine Joomla-Installation ist.",
    reads="Nur eine kleine Versionsdatei und einfache Systeminformationen. Nichts wird geändert.",
    load="leicht", presets=["schnell", "hack"],
)
def joomla_info(ctx, res):
    out = ctx.sh(r"""
echo '@@VERSION'; head -c 8000 libraries/src/Version.php 2>/dev/null
echo '@@MANIFEST'; head -c 4000 administrator/manifests/files/joomla.xml 2>/dev/null
echo '@@WHO'; whoami 2>/dev/null; pwd
echo '@@DISK'; df -h . 2>/dev/null | tail -1
echo '@@CONFIG'; test -f configuration.php && echo ja || echo nein
""" + PHP_PROBE_SCRIPT, timeout=60, raw="ausgabe").out
    sec = split_sections(out)
    version = joomla.parse_joomla_version(sec.get("VERSION", ""), sec.get("MANIFEST", ""))
    items = env_items(ctx, sec, out)
    if not version:
        res.add("warn", "Keine Joomla-Installation erkannt",
                "Im angegebenen Verzeichnis wurde keine Joomla-Versionsdatei gefunden.",
                items, "Bitte das Verzeichnis prüfen (es muss den Ordner 'administrator' und die Datei 'configuration.php' enthalten).")
    else:
        ctx.shared["joomla_version"] = version
        latest = ctx.adv.get("joomla", {}).get("latest_known", "")
        res.add("info", "Joomla %s" % version, "Gefundene Version laut libraries/src/Version.php.", items, context=True)    # Angabe, kein Hinweis
        if latest and vcmp(version, latest) < 0:
            res.add("warn", "Joomla ist älter als die neueste bekannte Version (%s)" % latest,
                    "Die Vergleichsliste stammt vom %s - neuere Versionen können inzwischen erschienen sein." % ctx.adv.get("stand", "?"),
                    hint="Joomla über Komponenten -> Joomla-Aktualisierung auf den neuesten Stand bringen.")
        eolf = cms_branch_finding("joomla", version, ctx.adv)
        if eolf:
            res.add(eolf[0], eolf[1], eolf[2], hint=eolf[3])
    if "nein" in sec.get("CONFIG", ""):
        res.add("warn", "configuration.php fehlt", "Ohne diese Datei läuft Joomla nicht (oder das Verzeichnis ist falsch).")


# ----------------------------------------------------------------------------- Hauptverzeichnis
CORE_DIRS = {"administrator", "api", "cache", "cli", "components", "images", "includes", "language", "layouts",
             "libraries", "media", "modules", "plugins", "templates", "tmp", ".well-known"}
CORE_FILES = {"index.php", "configuration.php", "htaccess.txt", "license.txt", "readme.txt", "robots.txt.dist",
              "robots.txt", "web.config.txt", ".htaccess", ".user.ini", "favicon.ico", "php.ini"}
DEV_NAMES = {".appveyor.yml", ".drone.yml", ".editorconfig", ".github", ".gitignore", ".gitattributes", ".phan",
             ".php-cs-fixer.dist.php", "code_of_conduct.md", "codeception.yml", "composer.json", "composer.lock",
             "package.json", "package-lock.json", "phpunit.xml.dist", "phpunit-pgsql.xml.dist", "renovate.json",
             "ruleset.xml", "build", "tests", "build.js", "jsconfig.json", "tsconfig.json", ".eslintrc.json",
             ".eslintignore", ".npmrc", "babel.config.js", ".stylelintrc.json", ".prettierrc.json", "cypress.config.dist.js",
             "cypress.config.js", ".php_cs.dist", ".travis.yml", "contributing.md", "security.md", ".babelrc", ".nvmrc"}
EXEC_EXT = re.compile(r"\.(php\d?|phtml|pht|phps|phar|shtml)$", re.IGNORECASE)


@check(
    "root_files", G, "Hauptverzeichnis auf fremde Dateien prüfen",
    "Liegt im obersten Ordner etwas, das dort nicht hingehört (fremde PHP-Dateien, .git, Altlasten)?",
    what="Listet alle Dateien und Ordner direkt im Joomla-Hauptverzeichnis auf und vergleicht sie mit dem, was "
         "Joomla dort normalerweise ablegt. Unbekannte PHP-Dateien, versteckte Ordner wie .git, ein node_modules-Ordner "
         "oder alte Kopien der .htaccess werden gesondert gemeldet.",
    why="Angreifer legen Hintertüren gern direkt im Hauptverzeichnis ab, weil sie dort leicht aufrufbar sind. "
        "Entwickler-Altlasten (z. B. composer.json, .drone.yml) gehören nicht auf einen Live-Server.",
    reads="Nur Namen, Größe, Änderungsdatum und Rechte der Einträge im obersten Ordner. Keine Dateiinhalte.",
    load="leicht", presets=["schnell", "hack"],
)
def root_files(ctx, res):
    out = ctx.sh(r"find . -maxdepth 1 -mindepth 1 -printf '%y\t%TY-%Tm-%Td %TH:%TM\t%m\t%s\t%f\n' 2>/dev/null | sort -t$'\t' -k5",
                 timeout=40, raw="verzeichnisliste").out
    bad_names = {n.lower() for n in ctx.adv.get("known_bad_filenames", [])}
    unknown_php: List[str] = []
    unknown_other: List[str] = []
    dev: List[str] = []
    oldcopies: List[str] = []
    hidden_risk: List[str] = []
    nodemod: List[str] = []
    knownbad: List[str] = []
    n = 0
    for ln in lines_of(out):
        parts = ln.split("\t")
        if len(parts) < 5:
            continue
        n += 1
        typ, mtime, size, name = parts[0], parts[1], parts[3], "\t".join(parts[4:])
        low = name.lower()
        desc = "%s  (%s, %s)" % (clean_line(name) + ("/" if typ == "d" else ""), mtime, "Ordner" if typ == "d" else size + " Byte")
        if ctx.cms == "wordpress" and typ != "d" and low in ctx.prof["core_files"]:
            continue                      # Kerndatei von WordPress (wp-login.php, xmlrpc.php ...)
        if name == "node_modules":
            nodemod.append(desc)
        elif low in bad_names:
            knownbad.append(desc)
        elif name in (".git", ".svn", ".hg", ".env", ".DS_Store") or low in (".env.local", ".env.production"):
            hidden_risk.append(desc)
        elif typ == "d" and (name in ctx.prof["core_dirs"] or (ctx.prof.get("core_dir_re") and re.match(ctx.prof["core_dir_re"], name))):
            continue
        elif typ != "d" and low in ctx.prof["core_files"]:
            continue
        elif low in DEV_NAMES:
            dev.append(desc)
        elif "htaccess" in low or re.search(r"\.(bak|old|orig|swp|save)$", low) or low.endswith("~"):
            oldcopies.append(desc)
        elif typ != "d" and EXEC_EXT.search(name) or re.search(r"\.php\.", low):
            unknown_php.append(desc)
        else:
            unknown_other.append(desc)
    if knownbad:
        res.add("crit", "Datei mit typischem Hintertür-Namen im Hauptverzeichnis", "Diese Namen werden oft von Web-Shells benutzt.",
                knownbad, "Inhalt ansehen (herunterladen, nicht öffnen/ausführen) und im Zweifel löschen.")
    if unknown_php:
        res.add("warn", "Unbekannte PHP-Datei(en) im Hauptverzeichnis",
                ctx.prof["root_text"] + "Alles andere stammt vom Betreiber, einem Plugin - oder von einem Angreifer.",
                unknown_php, "Dateien einzeln prüfen: Kennst du sie? Falls nicht, sichern und löschen.")
    if nodemod:
        res.add("warn", "Ordner node_modules liegt im Web-Verzeichnis",
                "Das ist ein Entwicklungsordner (Node.js), der auf einem Live-Server nichts zu suchen hat und mit Hunderten Unterordnern ein ideales Versteck bietet.",
                nodemod, "Auf den eigenen PC herunterladen (Beweissicherung), dann vom Server löschen. Ein Joomla läuft ohne ihn.")
    if hidden_risk:
        res.add("warn", "Versteckte Entwickler-/Konfigurationsdateien im Web-Verzeichnis", "Können Quellcode oder Zugangsdaten preisgeben, wenn sie per Browser abrufbar sind.",
                hidden_risk, "Entfernen oder per .htaccess sperren.")
    if oldcopies:
        res.add("info", "Alte Kopien (.htaccess usw.)", "Alte Sicherungskopien können Regeln oder Pfade verraten und sind meist überflüssig.",
                oldcopies, "Nach einem Backup löschen.")
    if dev:
        res.add("info", "Entwickler-Dateien aus dem Joomla-Paket", "Gehören nicht auf einen Live-Server, sind aber harmlos.", dev, "Kann nach einem Backup gelöscht werden.")
    if unknown_other:
        res.add("info", "Weitere Einträge, die nicht zum Joomla-Kern gehören",
                "Das sind oft eigene Ordner (z. B. files, Backups). Bitte kurz prüfen, ob du sie kennst.", unknown_other, context=True)
    if not (knownbad or unknown_php or nodemod or hidden_risk):
        res.add("ok", "Keine auffälligen Einträge im Hauptverzeichnis", "%d Einträge geprüft." % n)


# ----------------------------------------------------------------------------- Dateirechte
@check(
    "perms", G, "Dateirechte (schreibbar für alle?)",
    "Gibt es Dateien oder Ordner, die jeder Server-Benutzer verändern darf?",
    what="Sucht nach Dateien und Ordnern mit Schreibrecht für 'alle' (z. B. 777/666) und prüft die Rechte der configuration.php.",
    why="Auf geteilten Servern können andere Konten oder eingeschleuste Skripte solche Dateien manipulieren. "
        "Die configuration.php enthält Datenbank-Passwort und Geheimnisse.",
    reads="Nur Rechte und Pfade (keine Inhalte).",
    load="leicht", presets=["hack"],
)
def perms(ctx, res):
    out = ctx.sh(r"""
echo '@@CONFIG'; stat -c '%a %U:%G' @CFG@ 2>/dev/null
echo '@@FILES'; find . -xdev -type f -perm -0002 -not -path './node_modules/*' -printf '%m\t%p\n' 2>/dev/null | head -300
echo '@@DIRS'; find . -xdev -type d -perm -0002 -printf '%m\t%p\n' 2>/dev/null | head -300
echo '@@GROUP'; find . -xdev \( -type f -o -type d \) -perm -0020 ! -perm -0002 -not -path './node_modules/*' -printf '%m\t%p\n' 2>/dev/null | head -300
""".replace("@CFG@", ctx.prof["config_file"]), timeout=90, raw="rechte").out
    sec = split_sections(out)
    cfg = lines_of(sec.get("CONFIG", ""))
    if cfg:
        mode = cfg[0].split()[0]
        try:
            m = int(mode, 8)
        except ValueError:
            m = 0
        if m & 0o022:
            res.add("crit", "%s ist beschreibbar (%s)" % (ctx.prof["config_file"], mode),
                    "Datei mit Datenbank-Passwort darf von Gruppe oder allen verändert werden.", hint="Rechte auf 440 oder 444 setzen.")
        elif m & 0o004:
            res.add("info", "%s ist für alle lesbar (%s)" % (ctx.prof["config_file"], mode),
                    "Auf geteilten Servern können andere Konten die Datei theoretisch lesen.", ["%s  ./%s" % (mode, ctx.prof["config_file"].lstrip("./"))],
                    hint="Optional auf 440 setzen. Bei Fehlern zurück auf den alten Wert. Die Aktion 'Dateirechte auf Sollwerte setzen' macht das mit Test und Rückweg.")
        else:
            res.add("ok", "%s hat strenge Rechte (%s)" % (ctx.prof["config_file"], mode))
    wfiles = [l.split("\t", 1) for l in lines_of(sec.get("FILES", ""))]
    wdirs = [l.split("\t", 1) for l in lines_of(sec.get("DIRS", ""))]
    risky = [("%s  %s" % (a, clean_line(b))) for a, b in (x for x in wfiles if len(x) == 2)
             if re.search(r"\.(php\d?|phtml|js|htaccess|ini)$", b, re.IGNORECASE) or b.endswith(".htaccess")]
    other = [("%s  %s" % (a, clean_line(b))) for a, b in (x for x in wfiles if len(x) == 2)]
    if risky:
        res.add("crit", "%d ausführbare Datei(en) für alle beschreibbar" % len(risky),
                "PHP-/JS-/.htaccess-Dateien mit Schreibrecht für alle können unbemerkt verändert werden.", risky[:60],
                "Rechte korrigieren (Dateien 644, Ordner 755).")
    elif other:
        res.add("warn", "%d Datei(en) für alle beschreibbar" % len(other), "", other[:60], "Rechte auf 644 setzen.")
    if wdirs:
        res.add("warn", "%d Ordner für alle beschreibbar (777)" % len(wdirs),
                "Das ist auf manchen Servern üblich, aber riskant, weil dort jeder Dateien ablegen kann.",
                ["%s  %s" % (a, clean_line(b)) for a, b in (x for x in wdirs if len(x) == 2)][:60], "Ordnerrechte auf 755 setzen.")
    group = [("%s  %s" % (a, clean_line(b))) for a, b in (x.split("\t", 1) for x in lines_of(sec.get("GROUP", "")) if "\t" in x)]
    if group:
        res.add("info", "%d Datei(en)/Ordner für die Gruppe beschreibbar" % len(group),
                "Sollwerte sind 644 für Dateien und 755 für Ordner. Schreibrecht für die Gruppe ist auf manchen Servern üblich, auf geteilten Servern aber unnötig.",
                group[:60], "Rechte auf 644 (Dateien) bzw. 755 (Ordner) setzen; die Aktion 'Dateirechte auf Sollwerte setzen' macht das mit Test und Rückweg.")
    if not (risky or other or wdirs) and not any(f.sev == "crit" for f in res.findings):
        res.add("ok", "Keine für alle beschreibbaren Dateien oder Ordner gefunden")


# ----------------------------------------------------------------------------- weitere Installationen
@check(
    "other_installs", G, "Weitere Webseiten auf demselben Webspace",
    "Laufen im selben Hosting-Konto noch andere Joomla- oder WordPress-Seiten?",
    what="Sucht im gesamten Home-Verzeichnis nach weiteren Installationen (Joomla, WordPress, Drupal, TYPO3, Contao, PrestaShop, Shopware) und liest bei Joomla die Version.",
    why="Liegen mehrere Seiten im selben Konto, kann ein Angreifer von einer gehackten Seite auf die anderen überspringen. "
        "Alle müssen geprüft werden - sonst kehrt der Schadcode zurück.",
    reads="Nur Dateinamen und die Versionsdatei von Joomla. Das Programm durchsucht keine Inhalte anderer Seiten. "
          "Nur wenn du den Schnellscan einschaltest: Je gewählter Installation werden Upload-Ordner und PHP-Dateien einmal lesend durchsucht (zeitbegrenzt, höchstens 10 Installationen).",
    load="mittel", presets=["schnell", "hack"],
    options=[Option("scan", "Schnellscan je weiterer Installation (PHP in Upload-Ordnern, Hintertür-Muster, Version)", "bool", False,
                    "Nur lesend und nur in diesem Hosting-Konto. Ersetzt keine vollständige Prüfung der jeweiligen Seite."),
             Option("names", "Nur diese Installationen scannen (Teile des Ordnernamens, mit Komma getrennt; leer = alle gefundenen)", "text", "", "Die Liste der gefundenen Installationen steht nach dem ersten Lauf im Bericht."),
             Option("minutes", "Zeitgrenze je Installation in Minuten", "int", 2, "Danach wird der Scan dieser Installation abgebrochen und als unvollständig gemeldet.")],
)
def other_installs(ctx, res):
    out = ctx.sh(r"""
find "$HOME" -maxdepth 6 \( -name node_modules -o -name vendor -o -name cache -o -name .git -o -name tmp -o -name images \) -prune -o -type f \
  \( -name wp-config.php -o -path '*/libraries/src/Version.php' -o -path '*/sites/default/settings.php' -o -path '*/config/system/settings.php' -o -path '*/typo3conf/LocalConfiguration.php' -o -path '*/typo3conf/system/settings.php' \) -print 2>/dev/null | head -60 | while IFS= read -r f; do
  case "$f" in
    */libraries/src/Version.php) d="${f%/libraries/src/Version.php}"; v=$(grep -hE '(MAJOR|MINOR|PATCH)_VERSION *=' "$f" | grep -oE '[0-9]+' | paste -sd. -); echo "JOOMLA|$d|$v";;
    */wp-config.php) echo "WORDPRESS|${f%/wp-config.php}|";;
    */sites/default/settings.php) echo "DRUPAL|${f%/sites/default/settings.php}|";;
    */config/system/settings.php) echo "TYPO3|${f%/config/system/settings.php}|";;
    */typo3conf/LocalConfiguration.php) echo "TYPO3|${f%/typo3conf/LocalConfiguration.php}|";;
    */typo3conf/system/settings.php) echo "TYPO3|${f%/typo3conf/system/settings.php}|";;
  esac
done
find "$HOME" -maxdepth 7 \( -name node_modules -o -name cache -o -name .git -o -name tmp \) -prune -o -type f -path '*/vendor/contao/core-bundle/composer.json' -print 2>/dev/null | head -20 | while IFS= read -r f; do
  echo "CONTAO|${f%/vendor/contao/core-bundle/composer.json}|"
done
find "$HOME" -maxdepth 7 \( -name node_modules -o -name cache -o -name .git -o -name tmp -o -name vendor \) -prune -o -type f \( -path '*/app/AppKernel.php' -o -path '*/config/settings.inc.php' \) -print 2>/dev/null | head -40 | while IFS= read -r f; do
  d=${f%/app/AppKernel.php}; [ "$d" = "$f" ] && d=${f%/config/settings.inc.php}
  [ -d "$d/classes" ] && echo "PRESTASHOP|$d|"
done
find "$HOME" -maxdepth 7 \( -name node_modules -o -name cache -o -name .git -o -name tmp \) -prune -o -type f -path '*/vendor/shopware/core/composer.json' -print 2>/dev/null | head -40 | while IFS= read -r f; do
  echo "SHOPWARE|${f%/vendor/shopware/core/composer.json}|"
done
echo "@@HOME"; echo "$HOME"; pwd
""", timeout=90, raw="fundliste").out
    sec = split_sections(out)
    home_lines = lines_of(sec.get("HOME", ""))
    home = home_lines[0] if home_lines else ""
    here = home_lines[1] if len(home_lines) > 1 else ""
    head = out.split("@@HOME")[0]
    others, same = [], []
    latest = ctx.adv.get("joomla", {}).get("latest_known", "")
    outdated = []
    for ln in lines_of(head):
        p = ln.split("|")
        if len(p) < 3:
            continue
        kind, path, ver = p[0], p[1], p[2]
        rel = path[len(home) + 1:] if home and path.startswith(home + "/") else path
        label = "%s: %s%s" % ({"JOOMLA": "Joomla", "WORDPRESS": "WordPress", "DRUPAL": "Drupal", "TYPO3": "TYPO3", "CONTAO": "Contao", "PRESTASHOP": "PrestaShop", "SHOPWARE": "Shopware"}.get(kind, kind), rel, (" (Version %s)" % ver) if ver else "")
        if here and path.rstrip("/") == here.rstrip("/"):
            same.append(label)
            continue
        others.append(label)
        if kind == "JOOMLA" and ver and latest and vcmp(ver, latest) < 0:
            outdated.append(label)
    if others:
        res.add("warn", "%d weitere Installation(en) im selben Konto gefunden" % len(others),
                "Jede dieser Seiten kann dieselbe Schwachstelle haben oder als Sprungbrett dienen.", others,
                "Dieses Programm mit demselben Zugang für jede Seite einzeln ausführen (anderes Verzeichnis eingeben).")
    else:
        res.add("ok", "Keine weiteren Installationen im Konto gefunden",
                "Gesucht bis 6 Ordnerebenen tief unter dem Home-Verzeichnis.")
    if outdated:
        res.add("warn", "Veraltete Joomla-Version bei einer weiteren Seite", "", outdated, "Auf die neueste Version aktualisieren.")
    if same:
        res.add("info", "Diese Seite", "", same)
    if str(ctx.opt("scan", "")).lower() in ("1", "true", "yes", "ja", "on"):
        quick_scan(ctx, res, head, home, here)



# ----------------------------------------------------------------------------- A12: Schnellscan weiterer Installationen
QS_UP = {"JOOMLA": "images media tmp", "WORDPRESS": "wp-content/uploads", "DRUPAL": "sites/default/files", "TYPO3": "fileadmin public/fileadmin uploads", "CONTAO": "files public/files", "PRESTASHOP": "img upload download", "SHOPWARE": "public/media files"}
QS_MAX = 10


def qs_script(path: str, kind: str) -> str:
    from .files import R1, R2, R3, R4
    rx = "|".join("(%s)" % x for x in (R1, R2, R3, R4)).replace("'", "'\"'\"'")
    return ("cd %s 2>/dev/null || exit 3\n"
            "echo '@@UP'; for d in %s; do test -d \"$d\" && find \"$d\" -type f \\( -iname '*.php' -o -iname '*.phtml' -o -iname '*.phar' -o -iname '*.php[0-9]' \\) "
            "! \\( -name index.php -size -101c \\) -print 2>/dev/null | head -n 30; done\n"
            "echo '@@SH'; find . -type f -iname '*.php' -size -1024k -not -path '*/vendor/*' -not -path '*/node_modules/*' -print0 2>/dev/null | head -z -n 6000 "
            "| xargs -0 -r grep -lE '%s' 2>/dev/null | head -n 30\n"
            "echo '@@WPV'; grep -hoE \"wp_version *= *'[0-9.]+'\" wp-includes/version.php 2>/dev/null | head -1\n") % (sq(path), QS_UP.get(kind, "images"), rx)


def quick_scan(ctx, res, head: str, home: str, here: str) -> None:
    """Optionaler, rein lesender Schnellscan der im Konto gefundenen Installationen (Auswahl über Namensteile, Zeitgrenze je Installation)."""
    want = [w.strip().lower() for w in str(ctx.opt("names", "")).split(",") if w.strip()]
    minutes = max(1, min(10, ctx.opt_int("minutes", 2)))
    latest = {"JOOMLA": ctx.adv.get("joomla", {}).get("latest_known", ""), "WORDPRESS": (ctx.adv.get("wordpress", {}) or {}).get("latest_known", "")}
    todo = []
    for ln in lines_of(head):
        p = ln.split("|")
        if len(p) < 3 or (here and p[1].rstrip("/") == here.rstrip("/")):
            continue
        rel = p[1][len(home) + 1:] if home and p[1].startswith(home + "/") else p[1]
        if want and not any(w in rel.lower() for w in want):
            continue
        todo.append((p[0], p[1], rel, p[2]))
    if not todo:
        res.add("info", "Schnellscan: keine passende weitere Installation", "Es gibt nichts zu scannen (keine weitere gefunden oder keine passt zur Auswahl).")
        return
    skipped = todo[QS_MAX:]
    for kind, path, rel, ver in todo[:QS_MAX]:
        ctx.progress("Schnellscan: %s" % rel[:50])
        name = {"JOOMLA": "Joomla", "WORDPRESS": "WordPress", "DRUPAL": "Drupal", "TYPO3": "TYPO3", "CONTAO": "Contao", "PRESTASHOP": "PrestaShop", "SHOPWARE": "Shopware"}.get(kind, kind)
        try:
            out = ctx.sh(qs_script(path, kind), timeout=minutes * 60).out
        except CheckSkipped:
            res.add("info", "Schnellscan unvollständig: %s" % rel, "Die Zeitgrenze von %d Minute(n) wurde erreicht oder der Ordner ist nicht lesbar." % minutes)
            continue
        sec = split_sections(out)
        up = [clean_line(x) for x in lines_of(sec.get("UP", ""))]
        sh = [clean_line(x) for x in lines_of(sec.get("SH", ""))]
        wpv = re.search(r"'([0-9.]+)'", sec.get("WPV", ""))
        v = ver or (wpv.group(1) if wpv else "")
        hit = False
        if up:
            hit = True
            res.add("crit", "%s: %d PHP-Datei(en) in Upload-Ordnern (%s)" % (name, len(up), rel), "Dort gehört kein ausführbarer Code hin.", up[:30],
                    "Diese Installation einzeln mit allen Tests prüfen (Verzeichnis eingeben).")
        if sh:
            hit = True
            res.add("warn", "%s: %d Datei(en) mit Hintertür-Mustern (%s)" % (name, len(sh), rel), "Treffer des Schnellscans; er kennt keine Ausnahmen für Sicherheits-Erweiterungen.", sh[:30],
                    "Diese Installation einzeln mit allen Tests prüfen.")
        lk = latest.get(kind, "")
        if v and lk and vcmp(v, lk) < 0:
            hit = True
            res.add("warn", "%s: veraltete Version %s (%s)" % (name, v, rel), "Neueste bekannte Version: %s." % lk, hint="Aktualisieren.")
        if not hit:
            res.add("ok", "Schnellscan ohne Befund: %s%s" % (rel, (" (Version %s)" % v) if v else ""),
                    "Geprüft: PHP in Upload-Ordnern und häufige Hintertür-Muster. Das ist kein Ersatz für die vollständige Prüfung.")
    if skipped:
        res.add("info", "Schnellscan: %d weitere Installation(en) nicht gescannt" % len(skipped), "Höchstens %d Installationen je Lauf." % QS_MAX, [s[2] for s in skipped])
