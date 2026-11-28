"""Zusatzprüfungen (2.15.0) aus der Recherche zu aktuellen Einbruchswegen: versteckter Code in WordPress, versteckte Optionen, bekannte Joomla-Angriffe, Spam-Dateien für Suchmaschinen.
Alles rein lesend. Die Bewertung steht in reinen Funktionen (evaluate_*), damit sie mit Beispieltexten prüfbar ist."""
from __future__ import annotations

import re
import time
from typing import Any, Dict, List, Tuple
from urllib.parse import urlparse

from ..registry import check
from ..util import clean_line, extract_hosts, host_allowed, lines_of, split_sections, trunc, vcmp
from .database import add_manual_sql, fetch, need_db

Row = Tuple[str, str, str, List[str], str]
SHOW = 30

# ============================================================================ WordPress: versteckter Code
# Namen aus veröffentlichten Berichten über selbstheilende WordPress-Schadsoftware (2026). Ein Treffer ist ein starker Hinweis, aber kein Beweis.
WP_KNOWN_PATHS = ("wp-content/mu-plugins/widget-cache.php", "wp-content/mu-plugins/hyper-engine-kit.php", "wp-content/plugins/hyper-engine-kit",
                  "wp-content/c1b12371.php", "wp-content/.c1b12371.php", "wp-content/themes/khorshidi", "wp-content/.wp-config-cache.php")
STUB_DIR = re.compile(r"^[a-z]+(?:-[a-z]+){1,3}-[0-9a-f]{4}$")

WP_HIDDEN_SCRIPT = r"""
echo '@@HIDDEN'
find wp-content -type f -name '.*.php' -not -path '*/node_modules/*' 2>/dev/null | head -n 100 | while IFS= read -r f; do printf 'H\t%s\t%s\n' "$f" "$(stat -c %s "$f" 2>/dev/null)"; done
echo '@@DBPHP'
if [ -f wp-content/db.php ]; then
  w=0; grep -qE 'class[[:space:]]+[A-Za-z_]+[[:space:]]+extends[[:space:]]+wpdb|class[[:space:]]+wpdb|new[[:space:]]+wpdb' wp-content/db.php 2>/dev/null && w=1
  printf 'D\t%s\t%s\n' "$(stat -c %s wp-content/db.php 2>/dev/null)" "$w"
fi
echo '@@USERHOOK'
grep -rlE 'pre_user_query|views_users' wp-content/mu-plugins wp-content/db.php wp-content/advanced-cache.php wp-content/object-cache.php 2>/dev/null | head -n 30 | sed 's/^/M\t/'
grep -rlE 'pre_user_query' wp-content/plugins wp-content/themes --include=*.php 2>/dev/null | head -n 200 | while IFS= read -r f; do
  grep -qE 'views_users' "$f" 2>/dev/null && printf 'P\t%s\n' "$f"
done
echo '@@STUBS'
find wp-content/plugins wp-content/mu-plugins -maxdepth 2 -type f -name '*.php' -size 0 -not -name index.php 2>/dev/null | head -n 400
echo '@@KNOWN'
for p in @KNOWN@; do [ -e "$p" ] && printf 'K\t%s\n' "$p"; done
"""


def evaluate_wp_hidden(sec: Dict[str, str]) -> List[Row]:
    rows: List[Row] = []
    known = [clean_line(l.split("\t", 1)[1]) for l in lines_of(sec.get("KNOWN", "")) if l.startswith("K\t")]
    if known:
        rows.append(("crit", "%d Datei(en) mit Namen aus bekannten WordPress-Angriffen" % len(known),
                     "Diese Namen wurden 2026 in Berichten über selbstheilende WordPress-Schadsoftware genannt. Sie kommen bei normalen Installationen nicht vor.", known,
                     "Datei NICHT ausführen. Vor dem Löschen eine Kopie und die Datenbank sichern: Die Schadsoftware baut sich oft aus der Datenbank neu auf. Passwörter und Schlüssel erneuern."))
    hook_m = [clean_line(l.split("\t", 1)[1]) for l in lines_of(sec.get("USERHOOK", "")) if l.startswith("M\t")]
    hook_p = [clean_line(l.split("\t", 1)[1]) for l in lines_of(sec.get("USERHOOK", "")) if l.startswith("P\t")]
    if hook_m:
        rows.append(("crit", "%d Datei(en) verstecken Benutzer vor der Benutzerliste" % len(hook_m),
                     "Must-Use-Plugins oder Drop-ins greifen in die Benutzerabfrage ein (pre_user_query/views_users). So bleibt ein Administrator-Konto im Dashboard und in WP-CLI unsichtbar; "
                     "nur eine direkte Datenbankabfrage zeigt es.", hook_m,
                     "Datei ansehen und sichern, dann die Benutzer-Prüfung dieses Programms lesen: Sie fragt die Datenbank direkt ab und zeigt versteckte Konten."))
    if hook_p:
        rows.append(("warn", "%d Plugin-/Theme-Datei(en) verändern die Benutzerabfrage" % len(hook_p),
                     "Rollen- und Benutzer-Plugins tun das aus gutem Grund. Kennst du die Erweiterung nicht, kann es ein Versteck für ein Konto sein.", hook_p[:SHOW]))
    d = [l.split("\t") for l in lines_of(sec.get("DBPHP", "")) if l.startswith("D\t")]
    if d:
        size = int(d[0][1] or 0) if len(d[0]) > 1 else 0
        has_wpdb = len(d[0]) > 2 and d[0][2] == "1"
        if not has_wpdb:
            rows.append(("crit", "wp-content/db.php enthält keine Datenbank-Schicht (%d Byte)" % size,
                         "Ein echtes db.php-Drop-in (z. B. HyperDB) ersetzt die Klasse wpdb. Diese Datei tut das nicht, ist aber ein Drop-in, das bei jedem Aufruf läuft: "
                         "Genau dort versteckt sich Schadcode, der sich nach dem Löschen selbst wiederherstellt.", ["wp-content/db.php"],
                         "Datei sichern und ansehen. Gehört sie zu keinem Plugin, das du kennst, entfernen und die Datenbank auf große Base64-Einträge prüfen (Test 'Versteckte Optionen')."))
        else:
            rows.append(("info", "wp-content/db.php vorhanden (Datenbank-Schicht)", "Ein Drop-in ersetzt die Datenbankklasse. Bei Caching- oder Datenbank-Plugins normal.", ["wp-content/db.php"]))
    hidden = [l.split("\t") for l in lines_of(sec.get("HIDDEN", "")) if l.startswith("H\t")]
    if hidden:
        rows.append(("warn", "%d versteckte PHP-Datei(en) in wp-content" % len(hidden),
                     "Dateien mit Punkt am Namensanfang sind im Datei-Manager meist unsichtbar. Selbstheilende Schadsoftware legt dort Lader oder leere Ersatzdateien ab.",
                     ["%s  (%s Byte)" % (clean_line(h[1]), h[2] if len(h) > 2 else "?") for h in hidden[:SHOW]],
                     "Inhalt ansehen. Außer bei bekannten Cache-Plugins gehört dort keine versteckte PHP-Datei hin."))
    stubs = [clean_line(l) for l in lines_of(sec.get("STUBS", ""))]
    by_dir: Dict[str, List[str]] = {}
    for p in stubs:
        by_dir.setdefault(p.rsplit("/", 1)[0], []).append(p)
    pattern_dirs = [d for d in by_dir if STUB_DIR.match(d.rsplit("/", 1)[-1])]
    if pattern_dirs:
        rows.append(("crit", "%d Plugin-Ordner mit Zufallsnamen und leeren PHP-Dateien" % len(pattern_dirs),
                     "Namen wie 'wort-wort-wort-1a2b' mit leeren PHP-Dateien sind Platzhalter: Sie sollen die Plugin-Liste füllen oder dienen als Ablage für Wiederherstellung.",
                     sorted(pattern_dirs)[:SHOW], "Ordner ansehen, Kopie sichern, entfernen, wenn kein Plugin dazugehört."))
    mu_stubs = [p for p in stubs if p.startswith("wp-content/mu-plugins/") and p.count("/") == 2]
    if mu_stubs:
        rows.append(("warn", "%d leere Datei(en) in mu-plugins" % len(mu_stubs),
                     "Leere Must-Use-Plugins haben keinen Zweck. Bei Schadsoftware dienen sie als Platzhalter, die sich später füllen.", sorted(mu_stubs)[:SHOW]))
    other = [d for d in by_dir if d not in pattern_dirs and d.startswith("wp-content/plugins/")]
    if len(other) >= 15:
        rows.append(("warn", "%d Plugin-Ordner enthalten nur leere PHP-Dateien" % len(other), "Eine größere Zahl solcher Ordner ist ungewöhnlich.", sorted(other)[:SHOW]))
    return rows


@check(
    "wp_hidden_code", "konfig", "Versteckter Code: Benutzer-Tarnung, Drop-ins, Platzhalter",
    "Versteckt sich Code, der Benutzer verbirgt oder sich nach dem Löschen selbst wiederherstellt?",
    what="Sucht in mu-plugins und Drop-ins nach Code, der die Benutzerliste verändert (pre_user_query, views_users), prüft wp-content/db.php, versteckte PHP-Dateien in wp-content, "
         "Plugin-Ordner mit Zufallsnamen und leeren PHP-Dateien sowie Dateinamen aus bekannten Berichten über selbstheilende WordPress-Schadsoftware (2026).",
    why="Aktuelle WordPress-Schadsoftware legt ein Administrator-Konto an und blendet es im Dashboard aus. Sie liegt gleichzeitig in Dateien, Datenbank und Drop-ins und stellt sich nach dem Löschen "
        "einer Stelle aus der anderen wieder her. Wer nur eine Datei löscht, hat nichts erreicht.",
    reads="Dateinamen, Größen und Treffer einzelner Suchwörter in wp-content. Nichts wird verändert oder ausgeführt.",
    load="mittel", presets=["schnell", "hack"], cms="wordpress",
)
def wp_hidden_code(ctx, res):
    out = ctx.sh(WP_HIDDEN_SCRIPT.replace("@KNOWN@", " ".join(WP_KNOWN_PATHS)), timeout=120, raw="treffer").out
    rows = evaluate_wp_hidden(split_sections(out))
    for sev, title, detail, items, hint in rows:
        res.add(sev, title, detail, items, hint)
    if not [r for r in rows if r[0] in ("warn", "crit")]:
        res.add("ok", "Kein versteckter Code gefunden", "Benutzer-Tarnung, Drop-ins, versteckte Dateien und Platzhalter wurden geprüft.")


# ============================================================================ WordPress: versteckte Optionen
WP_KNOWN_OPTIONS = ("_core_version_check_hash", "_site_compatibility_data_wcfg", "_wp_theme_compat_718175affdbd", "_tds_stats", "_wp_site_activity", "_wp_session_tokens_data", "wp_0899e252b1_cfg")
Q_OPT_NAMES = ("SELECT option_name AS name, LENGTH(option_value) AS len FROM #__options WHERE option_name IN (%s)" % ",".join("'%s'" % n for n in WP_KNOWN_OPTIONS))
Q_OPT_BIG = ("SELECT option_name AS name, LENGTH(option_value) AS len, SUBSTRING(option_value, 1, 80) AS head FROM #__options WHERE LENGTH(option_value) > 20000 "
             "AND option_name NOT LIKE '%transient%' AND option_name NOT IN ('cron','rewrite_rules','active_plugins','sidebars_widgets','wp_user_roles','recently_activated') ORDER BY len DESC LIMIT 60")
Q_OPT_WS = ("SELECT option_name AS name, SUBSTRING(option_value, LOCATE('ws', option_value), 160) AS v FROM #__options WHERE option_name NOT LIKE '%transient%' "
            "AND (option_value LIKE '%wss://%' OR option_value LIKE '%new WebSocket%') LIMIT 40")
B64 = re.compile(r"^[A-Za-z0-9+/=]{60,}$")


def evaluate_wp_options(names: List[Dict[str, Any]], big: List[Dict[str, Any]], ws: List[Dict[str, Any]], own: str, allow: List[str]) -> List[Row]:
    rows: List[Row] = []
    if names:
        rows.append(("crit", "%d Datenbank-Eintrag/Einträge mit Namen aus bekannten Angriffen" % len(names),
                     "Diese Optionsnamen wurden 2026 bei einer Schadsoftware beobachtet, die Code in der Datenbank ablegt und daraus Dateien neu erzeugt.",
                     ["%s  (%s Zeichen)" % (clean_line(n.get("name") or ""), n.get("len")) for n in names],
                     "Eintrag sichern (Export), bevor du ihn löschst, und zuerst die Dateien bereinigen, die ihn wieder anlegen (Test 'Versteckter Code')."))
    hid = []
    for b in big:
        head = (b.get("head") or "").strip()
        name = str(b.get("name") or "")
        if B64.match(head[:80].replace("\n", "")) or (name.startswith("_") and head[:1] not in ("a", "{", "[", "<", "s", "O", "i")):
            hid.append("%s  (%s Zeichen, beginnt mit %s)" % (clean_line(name), b.get("len"), trunc(clean_line(head), 24)))
    if hid:
        rows.append(("warn", "%d große Option(en) mit verschlüsselt wirkendem Inhalt" % len(hid),
                     "Zehntausende Zeichen Base64-Text in einer Option sind kein normaler Plugin-Inhalt, sondern ein typisches Versteck für Programmcode, aus dem sich Dateien wiederherstellen.", hid[:SHOW],
                     "Optionsname im Internet und in den Plugin-Dateien suchen. Gehört sie zu keinem Plugin, sichern und entfernen."))
    bad = []
    for w in ws:
        snip = w.get("v") or ""
        hs = [h for h in extract_hosts(snip) if h != own and not host_allowed(h, allow)]
        if hs:
            bad.append("%s: %s" % (clean_line(w.get("name") or ""), trunc(clean_line(snip), 150)))
    if bad:
        rows.append(("warn", "%d Einstellung(en) mit WebSocket-Verbindung zu unbekannter Adresse" % len(bad),
                     "Zahlungsdaten-Skimmer nutzen WebSocket-Verbindungen, die klassische Filter oft übersehen. In Einstellungen von Tracking- und Checkout-Plugins (z. B. 'Externe Skripte') ist das ein Warnzeichen.",
                     bad[:SHOW], "Checkout-Einstellungen der Plugins (Funnel-Plugins, Tag-Manager-Plugins, Code-Einfüge-Plugins) ansehen und Unbekanntes entfernen."))
    return rows


@check(
    "wp_db_hidden_options", "datenbank", "Versteckte Optionen und WebSocket-Skripte in den Einstellungen",
    "Liegt Programmcode verschlüsselt in der Datenbank - oder ein Skript, das über WebSocket nach außen telefoniert?",
    what="Sucht in der Optionstabelle nach Namen aus bekannten Angriffen, nach sehr großen Optionen mit Base64-Inhalt und nach Einstellungen, die eine WebSocket-Verbindung (wss://) zu einer unbekannten Adresse öffnen.",
    why="Selbstheilende Schadsoftware speichert ihren Code als Base64-Text in der Datenbank und erzeugt daraus gelöschte Dateien neu. Zahlungsdaten-Skimmer stehen oft in Plugin-Einstellungen "
        "('Externe Skripte') und senden die Daten über WebSocket.",
    reads="Optionsnamen, Längen und kurze Textanfänge aus der Optionstabelle. Kein Inhalt wird vollständig gelesen oder gespeichert.",
    load="leicht", needs="db", presets=["hack"], cms="wordpress",
)
def wp_db_hidden_options(ctx, res):
    db = need_db(ctx, res, "Versteckte Optionen", [("Bekannte Namen", Q_OPT_NAMES), ("Große Optionen", Q_OPT_BIG), ("WebSocket", Q_OPT_WS)])
    names, big, ws = fetch(db, Q_OPT_NAMES) or [], fetch(db, Q_OPT_BIG) or [], fetch(db, Q_OPT_WS) or []
    rows = evaluate_wp_options(names, big, ws, ctx.own_host(), ctx.allow())
    for sev, title, detail, items, hint in rows:
        res.add(sev, title, detail, items, hint)
    if rows:
        add_manual_sql(ctx, db, "Auffällige Optionen", [("Große Optionen ansehen", Q_OPT_BIG)])
    else:
        res.add("ok", "Keine versteckten Optionen gefunden", "%d große Optionen wurden angesehen." % len(big))


# ============================================================================ Joomla: bekannte Angriffe (Helix3, JCE, Template-Defacement)
# (Name, Datei mit <version>, erste sichere Version, Hinweis)
JOOMLA_VULN = (
    ("Helix3 (JoomShaper)", ("plugins/ajax/helix3/helix3.xml", "plugins/system/helix3/helix3.xml"), "3.1.2",
     "Die Ajax-Schnittstelle des Helix3-Frameworks prüft keine Anmeldung. Besucher können Template-Einstellungen überschreiben, Dateien schreiben oder löschen (CVE-2026-49049, 2026 massenhaft für Defacement genutzt)."),
    ("JCE-Editor", ("administrator/components/com_jce/jce.xml", "plugins/editors/jce/jce.xml"), "2.9.99.5",
     "Ohne Anmeldung lassen sich Editor-Profile anlegen und PHP-Code hochladen (CVE-2026-48907, von CISA als aktiv ausgenutzt gelistet)."),
)
JOOMLA_SCRIPT = r"""
echo '@@VER'
for f in @VERFILES@; do [ -f "$f" ] && printf 'V\t%s\t%s\n' "$f" "$(grep -m1 -oE '<version>[^<]+' "$f" 2>/dev/null | sed 's/<version>//')"; done
echo '@@COX'
find . -maxdepth 4 -type f -name 'cox.json' -not -path './node_modules/*' 2>/dev/null | head -n 20
"""
DEFACE = ("innerHTML", "document.title", "document.body", "2147483647", "position:fixed", "hacked")
Q_TPL = ("SELECT id, template AS name, SUBSTRING(params, 1, 4000) AS v FROM #__template_styles WHERE params LIKE '%innerHTML%' OR params LIKE '%2147483647%' OR params LIKE '%hacked%' OR params LIKE '%document.title%'")


def evaluate_joomla_files(sec: Dict[str, str]) -> List[Row]:
    rows: List[Row] = []
    vers = {}
    for l in lines_of(sec.get("VER", "")):
        p = l.split("\t")
        if p[0] == "V" and len(p) >= 3:
            vers[p[1]] = p[2].strip()
    crit, ok = [], []
    for name, files, fixed, why in JOOMLA_VULN:
        for f in files:
            v = vers.get(f)
            if v:
                if vcmp(v, fixed) < 0:
                    crit.append(("%s %s (sicher ab %s)" % (name, v, fixed), why))
                else:
                    ok.append("%s %s" % (name, v))
                break
    for title, why in crit:
        rows.append(("crit", "Verwundbare Version: " + title, why, [], "Erweiterung sofort aktualisieren (oder entfernen). Danach Administratoren, Template-Einstellungen und Dateien auf Fremdänderungen prüfen."))
    cox = [clean_line(l) for l in lines_of(sec.get("COX", ""))]
    if cox:
        rows.append(("crit", "cox.json gefunden (Spur eines Angriffs)", "Diese Datei legen Angreifer bei der Helix3-Angriffswelle 2026 zur Erkundung ab. Normale Seiten haben sie nicht.", cox,
                     "Zugriffsprotokolle auf Aufrufe von com_ajax mit plugin=helix3 prüfen, Template-Einstellungen und Administratoren kontrollieren."))
    if ok and not (crit or cox):
        rows.append(("ok", "Bekannte Erweiterungen mit sicherer Version", "", ok, ""))      # positive Aussage, kein Hinweis
    return rows


def evaluate_joomla_templates(rows_db: List[Dict[str, Any]]) -> List[Row]:
    rows: List[Row] = []
    crit, warn = [], []
    for r in rows_db:
        v = (r.get("v") or "").lower()
        hits = [m for m in DEFACE if m.lower() in v]
        line = "Template-Stil %s (%s): %s" % (r.get("id"), clean_line(r.get("name") or ""), ", ".join(hits))
        if len(hits) >= 3 or ("hacked" in hits and "innerHTML" in hits):
            crit.append(line)
        elif len(hits) >= 2:
            warn.append(line)
    if crit:
        rows.append(("crit", "%d Template-Stil/Stile mit Defacement-Skript" % len(crit),
                     "Bei der Angriffswelle 2026 wurde die Startseite über Template-Parameter (eigenes JavaScript, 'Vor </head>', 'Vor </body>') verändert. Die Dateien bleiben dabei unverändert.", crit,
                     "Template-Stil im Backend öffnen (System -> Template-Stile), die Felder für eigenes JavaScript/CSS leeren, Helix3 aktualisieren und Administratoren prüfen."))
    if warn:
        rows.append(("warn", "%d Template-Stil/Stile mit auffälligen Skriptmerkmalen" % len(warn), "Mehrere typische Merkmale eines Defacement-Skripts stehen in den Parametern.", warn,
                     "Parameter ansehen; eigenes JavaScript, das du nicht kennst, entfernen."))
    return rows


@check(
    "joomla_known_exploits", "erweiterungen", "Bekannte Angriffe: Helix3, JCE, Template-Defacement",
    "Läuft eine Erweiterung, die gerade massenhaft ausgenutzt wird - und gibt es Spuren davon?",
    what="Liest die Version von Helix3 und JCE aus den Erweiterungsdateien und meldet Versionen unter der sicheren Version, sucht cox.json und prüft die Template-Parameter in der Datenbank auf Defacement-Skripte "
         "(innerHTML, document.title, z-index 2147483647).",
    why="Die Helix3-Lücke (CVE-2026-49049) und die JCE-Lücke (CVE-2026-48907) wurden 2026 in großer Zahl ausgenutzt. Bei Helix3 liegt der Schaden nur in der Datenbank, die Dateien sehen sauber aus.",
    reads="Versionszeilen aus zwei Erweiterungsdateien, Dateinamen und Ausschnitte der Template-Parameter (bis 4000 Zeichen).",
    load="leicht", presets=["schnell", "hack"],
)
def joomla_known_exploits(ctx, res):
    files = [f for v in JOOMLA_VULN for f in v[1]]
    out = ctx.sh(JOOMLA_SCRIPT.replace("@VERFILES@", " ".join(files)), timeout=60, raw="treffer").out
    rows = evaluate_joomla_files(split_sections(out))
    db = ctx.db()
    if db.ok:
        rows += evaluate_joomla_templates(fetch(db, Q_TPL) or [])
    else:
        res.add("info", "Template-Parameter nicht geprüft", "Kein Datenbankzugriff vom Server aus. Die Dateiprüfung ist trotzdem erfolgt.")
    for sev, title, detail, items, hint in rows:
        res.add(sev, title, detail, items, hint)
    if not [r for r in rows if r[0] in ("warn", "crit")]:
        res.add("ok", "Keine Spuren der bekannten Angriffe gefunden")


# ============================================================================ alle Systeme: Spam-Dateien für Suchmaschinen
SPAM_SCRIPT = r"""
echo '@@SITEMAPS'
find . -maxdepth 2 -type f \( -iname 'sitemap*.xml' -o -iname 'sitemap*.xml.gz' -o -iname 'sitemap*.txt' \) -not -path './node_modules/*' -not -path './vendor/*' 2>/dev/null | head -n 50 | while IFS= read -r f; do
  printf 'S\t%s\t%s\t%s\n' "$f" "$(stat -c %s "$f" 2>/dev/null)" "$(stat -c %Y "$f" 2>/dev/null)"
  case "$f" in *.gz) ;; *) grep -oE '<loc>[^<]+' "$f" 2>/dev/null | head -n 300 | sed 's/<loc>//' | sed -E 's#^https?://([^/:]+).*#L\t\1#' | sort | uniq -c | sort -rn | head -n 5 | sed -E 's/^ *([0-9]+) (L\t.*)$/\2\t\1/';; esac
done
echo '@@ROBOTS'
[ -f robots.txt ] && grep -iE '^[[:space:]]*sitemap:' robots.txt 2>/dev/null | head -n 20
echo '@@ADS'
for f in ads.txt app-ads.txt; do [ -f "$f" ] && printf 'A\t%s\t%s\t%s\n' "$f" "$(stat -c %Y "$f" 2>/dev/null)" "$(wc -l < "$f" 2>/dev/null)"; done
"""


def evaluate_spam(sec: Dict[str, str], own: str, now: float = 0.0) -> List[Row]:
    now = now or time.time()
    own = (own or "").replace("www.", "")
    rows: List[Row] = []
    sitemaps: List[Dict[str, Any]] = []
    for l in lines_of(sec.get("SITEMAPS", "")):
        p = l.split("\t")
        if p[0] == "S" and len(p) >= 4:
            sitemaps.append({"path": p[1], "size": int(p[2] or 0), "mtime": int(p[3] or 0), "hosts": {}})
        elif p[0] == "L" and len(p) >= 3 and sitemaps:
            sitemaps[-1]["hosts"][p[1].lower()] = int(p[2] or 0)
    foreign, young = [], []
    for s in sitemaps:
        total = sum(s["hosts"].values())
        alien = {h: n for h, n in s["hosts"].items() if own and h.replace("www.", "") != own}
        if total and own and sum(alien.values()) * 2 > total:
            foreign.append("%s  (Adressen anderer Domains: %s)" % (clean_line(s["path"]), ", ".join(sorted(alien)[:3])))
        elif s["size"] > 2_000_000 and now - s["mtime"] < 30 * 86400:
            young.append("%s  (%d KB, in den letzten 30 Tagen geändert)" % (clean_line(s["path"]), s["size"] // 1024))
    if foreign:
        rows.append(("crit", "%d Sitemap-Datei(en) mit Adressen fremder Domains" % len(foreign),
                     "Spam-Kampagnen (z. B. 'Japanese Keyword Hack') legen Sitemaps an, die Suchmaschinen auf Spam-Seiten leiten. Eigene Sitemaps nennen nur die eigene Domain.", foreign,
                     "Datei sichern, entfernen und in der Search Console prüfen, ob fremde Sitemaps eingereicht wurden."))
    if young:
        rows.append(("warn", "%d sehr große, frisch geänderte Sitemap(s)" % len(young), "Spam-Sitemaps enthalten oft Tausende Adressen. Bei Shops mit vielen Produkten kann es normal sein.", young))
    alien_r = []
    for l in lines_of(sec.get("ROBOTS", "")):
        m = re.search(r"(?i)sitemap:\s*(\S+)", l)
        if m:
            h = (urlparse(m.group(1)).hostname or "").lower().replace("www.", "")
            if own and h and h != own:
                alien_r.append(clean_line(m.group(1)))
    if alien_r:
        rows.append(("warn", "robots.txt nennt Sitemaps fremder Domains", "Ein Eintrag 'Sitemap:' mit fremder Adresse lenkt Suchmaschinen auf andere Seiten. Mancher Dienst nutzt das bewusst (Sitemap-Dienste).", alien_r[:10],
                     "Eintrag prüfen und entfernen, wenn du ihn nicht kennst."))
    ads = [l.split("\t") for l in lines_of(sec.get("ADS", "")) if l.startswith("A\t")]
    fresh = [a for a in ads if len(a) >= 4 and now - int(a[2] or 0) < 30 * 86400]
    if fresh:
        rows.append(("info", "ads.txt wurde in den letzten 30 Tagen geändert", "Angreifer tragen dort eigene Werbekonten ein und leiten so Werbeeinnahmen um. Nutzt du keine Werbung, sollte die Datei fehlen.",
                     ["%s  (%s Zeilen)" % (clean_line(a[1]), a[3].strip()) for a in fresh]))
    return rows


@check(
    "seo_spam_files", "dateien", "Spam für Suchmaschinen: Sitemaps, robots.txt, ads.txt",
    "Wurden Dateien angelegt, die Suchmaschinen oder Werbenetzwerke auf fremde Inhalte lenken?",
    what="Sucht Sitemap-Dateien im Hauptordner und meldet solche, deren Adressen überwiegend zu fremden Domains gehören oder die sehr groß und frisch sind. Prüft die Sitemap-Zeilen der robots.txt auf fremde Adressen "
         "und ob die ads.txt kürzlich geändert wurde.",
    why="Spam-Angriffe (Japanese Keyword Hack, Pharma-Spam) zeigen auf der Seite selbst nichts, schicken aber Suchmaschinen Tausende Spam-Adressen. Du erfährst es erst durch fremde Treffer in Google oder eine Warnung.",
    reads="Dateinamen, Größe, Datum und die Domains der ersten 300 Adressen jeder Sitemap sowie die Sitemap-Zeilen der robots.txt. Es wird nichts verändert.",
    load="leicht", presets=["schnell", "hack"],
)
def seo_spam_files(ctx, res):
    out = ctx.sh(SPAM_SCRIPT, timeout=60, raw="treffer").out
    rows = evaluate_spam(split_sections(out), ctx.own_host())
    for sev, title, detail, items, hint in rows:
        res.add(sev, title, detail, items, hint)
    if not [r for r in rows if r[0] in ("warn", "crit")]:
        res.add("ok", "Keine Spam-Sitemaps oder fremden robots.txt-Einträge gefunden")


# ============================================================================ alle Systeme: Dateien, die sich nicht löschen lassen
LOCK_SCRIPT = r"""
echo '@@ME'
id -un 2>/dev/null
echo '@@IMM'
(command -v lsattr >/dev/null 2>&1 && lsattr -R -a . 2>/dev/null | awk 'NF>=2 && $1 ~ /^[-A-Za-z]+$/ && $1 ~ /[ia]/ {print}' | head -n 200)
echo '@@FOREIGN'
find . -not -type l \( -not -user "$(id -un 2>/dev/null)" \) -printf '%u\t%y\t%p\n' 2>/dev/null | head -n 300
"""


def evaluate_locked(sec: Dict[str, str]) -> List[Row]:
    rows: List[Row] = []
    imm = []
    for ln in lines_of(sec.get("IMM", "")):
        p = ln.split(None, 1)
        if len(p) == 2 and re.fullmatch(r"[-A-Za-z]+", p[0]) and re.search(r"[ia]", p[0]):
            kind = "gesperrt" if "i" in p[0] else "nur anhängbar"
            imm.append("%s  (%s)" % (clean_line(p[1].strip()), kind))
    if imm:
        rows.append(("crit", "%d Datei(en)/Ordner mit Löschschutz-Attribut (chattr +i/+a)" % len(imm),
                     "Diese Einträge lassen sich nicht löschen, umbenennen oder ändern - auch nicht per FTP und auch nicht mit den richtigen Dateirechten. Das Attribut kann nur der Administrator des Servers (root) setzen "
                     "und entfernen. Schadsoftware und Angreifer mit Serverrechten nutzen das, damit eine Hintertür bei der Bereinigung stehen bleibt. Auch Hoster setzen es manchmal bewusst als Schutz.", imm[:SHOW],
                     "Du kannst das Attribut als normaler Benutzer nicht entfernen. Den Hoster bitten, mit 'lsattr' zu prüfen und es mit 'chattr -i' (bzw. '-a') zu entfernen. "
                     "Gleichzeitig fragen, wie ein Angreifer es setzen konnte: Das spricht für eine Kompromittierung auf Serverebene, nicht nur der Webseite."))
    me = (lines_of(sec.get("ME", "")) or [""])[0].strip()
    other = []
    owners: Dict[str, int] = {}
    for ln in lines_of(sec.get("FOREIGN", "")):
        p = ln.split("\t", 2)
        if len(p) == 3 and p[0] and p[0] != me:
            owners[p[0]] = owners.get(p[0], 0) + 1
            other.append("%s  (Besitzer %s)" % (clean_line(p[2]), p[0]))
    if other:
        rows.append(("warn", "%d Datei(en)/Ordner gehören einem anderen Benutzer als dem Konto" % len(other),
                     "Gehört ein Ordner nicht deinem Konto (z. B. root, nobody oder ein Webserver-Benutzer), darfst du ihn per FTP nicht löschen, selbst wenn die Rechte 777 anzeigen. Das passiert, wenn ein Angreifer oder ein "
                     "Dienst mit anderen Rechten die Dateien angelegt hat. Besitzer: " + ", ".join("%s (%d)" % (u, n) for u, n in sorted(owners.items(), key=lambda x: -x[1])[:5]) + ".", other[:SHOW],
                     "Nur der Hoster kann den Besitzer ändern oder die Einträge löschen. Bitte ihn darum und nenne die Pfade aus dieser Liste."))
    return rows


@check(
    "locked_files", "dateien", "Nicht löschbare Dateien und Ordner",
    "Gibt es Einträge, die sich auch bei richtigen Rechten nicht löschen lassen?",
    what="Zeigt mit lsattr alle Einträge mit Löschschutz-Attribut (i = unveränderbar, a = nur anhängbar) und alle Einträge, die einem anderen Benutzer als deinem Konto gehören.",
    why="Nach einem Hack lassen sich manche Ordner nicht mehr löschen, obwohl die Rechte stimmen und das FTP-Konto das Verzeichnis besitzt. Meist liegt ein Attribut (chattr +i) oder ein anderer Besitzer dahinter. "
        "Beides kann nur der Hoster ändern. Der Befund zeigt dem Hoster genau, wo er ansetzen muss.",
    reads="Dateinamen und die Attributzeichen von lsattr sowie der Besitzername. Es wird nichts verändert.",
    load="mittel", presets=["schnell", "hack"],
)
def locked_files(ctx, res):
    out = ctx.sh(LOCK_SCRIPT, timeout=150, raw="treffer").out
    rows = evaluate_locked(split_sections(out))
    for sev, title, detail, items, hint in rows:
        res.add(sev, title, detail, items, hint)
    if not rows:
        res.add("ok", "Keine gesperrten oder fremden Einträge gefunden", "Weder Löschschutz-Attribute noch Dateien anderer Besitzer wurden gesehen (lsattr muss auf dem Server verfügbar sein).")
