"""TYPO3-Prüfungen (2.10.0): Kern, Einstellungen, abrufbare Dateien, Erweiterungen, Backend-Konten und Code in Inhalten. Klassische und Composer-Installationen, nur lesend.

Die Bewertung steckt in auswertung_typo3.py (reine Funktionen, mit Beispieldaten geprüft). Hier stehen nur die Abfragen.
Noch NICHT gegen einen echten TYPO3-Server geprüft: Antwortformat von get.typo3.org und Packagist sowie die Tabellen- und Feldnamen (be_users, tt_content, sys_template).
Fehlt etwas, melden die Prüfungen 'nicht prüfbar' statt zu raten. Schlüssel, Passwörter und encryptionKey werden nie ausgegeben."""
from __future__ import annotations

import os
import re
from typing import Any, Dict, List, Tuple
from urllib.parse import quote

from .. import coreref, typo3, typo3ref
from ..model import CheckSkipped
from ..registry import check
from ..util import digits, split_sections
from . import auswertung_typo3 as at
from . import web as webmod
from .database import fetch, need_db
from .joomla_core import parse_sums

RELEASE_URLS = ("https://get.typo3.org/json", "https://get.typo3.org/v1/api/major/%d/release")
ADVISORY_URL = "https://packagist.org/api/security-advisories/?"
MAX_PACKAGES = 150          # so viele Pakete werden höchstens bei Packagist nachgefragt (in Stapeln zu je 25)
BATCH = 25

Q_USERS = ("SELECT uid AS uid, username AS name, admin AS adm, disable AS dis, crdate AS created, lastlogin AS access "
           "FROM #__be_users WHERE deleted = 0 ORDER BY uid LIMIT 500")
LIKE_TMPL = "(%(c)s LIKE '%%<script%%' OR %(c)s LIKE '%%<iframe%%' OR %(c)s LIKE '%%atob(%%' OR %(c)s LIKE '%%fromCharCode%%' OR %(c)s LIKE '%%eval(%%' OR %(c)s LIKE '%%javascript:%%')"
Q_CODE = {"tt_content": ("SELECT uid AS id, bodytext AS text FROM #__tt_content WHERE deleted = 0 AND " + LIKE_TMPL % {"c": "bodytext"} + " LIMIT 200"),
          "sys_template": ("SELECT uid AS id, config AS text FROM #__sys_template WHERE deleted = 0 AND " + LIKE_TMPL % {"c": "config"} + " LIMIT 200"),
          "tx_news_domain_model_news": ("SELECT uid AS id, bodytext AS text FROM #__tx_news_domain_model_news WHERE deleted = 0 AND " + LIKE_TMPL % {"c": "bodytext"} + " LIMIT 200")}


def _emit(res, rows) -> None:
    for sev, title, text, items, hint in rows:
        res.add(sev, title, text, items, hint)


G_KONFIG, G_EXT, G_DB = "konfig", "erweiterungen", "datenbank"


def layout(ctx) -> Dict[str, Any]:
    """Version, Einstellungsdatei, Install-Tool-Datei und Art der Installation (einmal je Lauf lesen)."""
    if "typo3_layout" not in ctx.shared:
        script = r"""V=""
for f in %s; do if [ -f "$f" ]; then V="$f"; break; fi; done
echo '@@VFILE'; echo "$V"
echo '@@VER'; if [ -n "$V" ]; then head -c 6000 "$V"; fi
echo '@@OLD'; grep -hm1 "TYPO3_version'" %s 2>/dev/null
echo '@@MODE'; if [ -d vendor/typo3 ] || [ -d ../vendor/typo3 ]; then echo composer; else echo classic; fi
echo '@@INSTALL'; for f in %s; do if [ -e "$f" ]; then echo "$f"; stat -c %%Y "$f" 2>/dev/null; date +%%s; break; fi; done
""" % (" ".join(typo3.VERSION_FILES), typo3.OLD_VERSION_FILE, " ".join(typo3.INSTALL_TOOL_FILES))
        sec = split_sections(ctx.sh(script, timeout=40).out)
        inst = [x for x in sec.get("INSTALL", "").splitlines() if x.strip()]
        tool = None
        if inst:
            age = None
            if len(inst) >= 3 and digits(inst[1].strip()) and digits(inst[2].strip()):
                age = int(inst[2]) - int(inst[1])
            tool = {"path": inst[0].strip(), "age_s": age}
        ctx.shared["typo3_layout"] = {"version": typo3.parse_typo3_version(sec.get("VER", ""), sec.get("OLD", "")), "mode": (sec.get("MODE", "classic").split() or ["classic"])[0],
                                      "install_tool": tool}
    return ctx.shared["typo3_layout"]


def typo3_version(ctx) -> str:
    return layout(ctx)["version"]


def need_supported(ctx) -> str:
    """Datenbank-Prüfungen gelten für TYPO3 ab Version 7 (Tabellen be_users, tt_content); sehr alte Versionen werden in der Kernprüfung gemeldet."""
    v = typo3_version(ctx)
    if v and typo3.major(v) < 7:
        raise CheckSkipped("Diese Prüfung gilt für TYPO3 ab Version 7. Gefunden wurde TYPO3 %s (siehe die Kernprüfung)." % v)
    return v


def releases(ctx, major: int) -> List[Dict[str, str]]:
    if "typo3_releases" not in ctx.shared:
        out: List[Dict[str, str]] = []
        if not os.environ.get("CLAUDIA_OFFLINE"):
            for u in RELEASE_URLS:
                f = webmod.fetch(u % major if "%d" in u else u, webmod.UA_BROWSER, max_bytes=6_000_000, timeout=25)
                if not f.error and f.status == 200:
                    out = typo3.parse_release_list(f.body)
                    if out:
                        break
        ctx.shared["typo3_releases"] = out
    return ctx.shared["typo3_releases"]


def advisories(packages: List[str]) -> Tuple[Dict[str, List[Dict[str, str]]], bool]:
    """Sicherheitsmeldungen zu den Paketen von Packagist (in Stapeln). Rückgabe (Meldungen je Paket, alles abgefragt?)."""
    if os.environ.get("CLAUDIA_OFFLINE"):
        return {}, False
    names = [p for p in dict.fromkeys(packages) if re.fullmatch(r"[a-z0-9_.\-]+/[a-z0-9_.\-]+", p)][:MAX_PACKAGES]
    out: Dict[str, List[Dict[str, str]]] = {}
    ok = bool(names)
    for i in range(0, len(names), BATCH):
        q = "&".join("packages%%5B%%5D=%s" % quote(p, safe="") for p in names[i:i + BATCH])
        f = webmod.fetch(ADVISORY_URL + q, webmod.UA_BROWSER, max_bytes=8_000_000, timeout=30)
        if f.error or f.status != 200:
            ok = False
            continue
        try:
            import json
            if not isinstance(json.loads(f.body).get("advisories"), (dict, list)):
                ok = False
                continue
        except (ValueError, AttributeError):
            ok = False
            continue
        out.update(typo3.parse_advisories(f.body))
    return out, ok


@check(
    "typo3_core", G_KONFIG, "TYPO3-Kern: Version, Sicherheitsmeldungen und Originaldateien",
    "Ist TYPO3 aktuell und unterstützt, und stimmen die Dateien in typo3/sysext mit dem Original überein?",
    what="Liest die Version aus dem Kern (klassisch: typo3/sysext/core, Composer: vendor/typo3/cms-core), prüft, ob die Hauptversion noch Sicherheitsupdates bekommt, fragt bei get.typo3.org nach der neuesten Version "
         "und bei Packagist nach Sicherheitsmeldungen zu dieser Version und vergleicht alle Dateien der Systemerweiterungen mit dem Original-Paket von get.typo3.org (Prüfsumme von der Release-Seite). Auf dem Server werden nur Prüfsummen berechnet.",
    why="Veraltete TYPO3-Versionen werden massenhaft automatisch angegriffen. Manipulierte Kerndateien sind ein häufiger Ort für Hintertüren, die keinem Schadcode-Muster entsprechen.",
    reads="Dateinamen und Prüfsummen unter typo3/sysext (bzw. vendor/typo3/cms-*) des Servers sowie die Version; vom Internet die Versionsliste, die Sicherheitsmeldungen und das Original-Paket (nur https). Es wird nichts verändert.",
    load="mittel", needs="web", presets=["schnell", "hack", "komplett"], cms="typo3",
)
def typo3_core(ctx, res):
    lay = layout(ctx)
    ver = lay["version"]
    rel: List[Dict[str, str]] = []
    adv: Dict[str, List[Dict[str, str]]] = {}
    adv_ok = False
    if ver and typo3.major(ver) >= 7:
        ctx.progress("Frage get.typo3.org und Packagist")
        rel = releases(ctx, typo3.major(ver))
        adv, adv_ok = advisories(["typo3/cms-core"])
    _emit(res, at.judge_core(ver, rel, typo3.advisories_for(ver, adv, "typo3/cms-core") if ver else [], adv_ok=adv_ok if ver and typo3.major(ver) >= 7 else True))
    if not ver or typo3.major(ver) < 9:
        return
    if os.environ.get("CLAUDIA_OFFLINE"):
        res.add("info", "Dateivergleich übersprungen", "Offline-Modus (CLAUDIA_OFFLINE): Das Original-Paket wird nicht geladen.")
        return
    if not typo3ref.VERSION_RE.match(ver):
        res.add("info", "TYPO3 %s ist eine Vorabversion" % ver, "Für Vorabversionen gibt es kein Paket zum Vergleich.")
        return
    out = ctx.sh(r"""H=""
if command -v sha256sum >/dev/null 2>&1; then H="sha256sum"; elif command -v shasum >/dev/null 2>&1; then H="shasum -a 256"; fi
echo '@@HASHER'; echo "${H:-none}"
echo '@@SUMS'
B=""
if [ -d typo3/sysext ]; then B="typo3/sysext"; elif [ -d typo3_src/typo3/sysext ]; then B="typo3_src/typo3/sysext"; fi
if [ -n "$H" ] && [ -n "$B" ]; then
  find -L "$B" -type f -print0 2>/dev/null | xargs -0 $H 2>/dev/null | sed "s#  $B/#  typo3/sysext/#"
elif [ -n "$H" ]; then
  for V in vendor ../vendor; do
    if [ -d "$V/typo3" ]; then
      for d in "$V"/typo3/cms-*; do
        [ -d "$d" ] || continue
        n=$(basename "$d" | sed 's/^cms-//; s/-/_/g')
        find -L "$d" -type f -print0 2>/dev/null | xargs -0 $H 2>/dev/null | sed "s#  $d/#  typo3/sysext/$n/#"
      done
      break
    fi
  done
fi""", timeout=600, raw="pruefsummen", raw_cap=40_000).out
    sec = split_sections(out)
    if "none" in sec.get("HASHER", "none").split():
        res.add("info", "Dateivergleich nicht möglich", "Auf dem Server gibt es weder sha256sum noch shasum.")
        return
    server = parse_sums(sec.get("SUMS", ""))
    if len(server) < 100:
        res.add("info", "Dateivergleich nicht möglich", "Unter typo3/sysext bzw. vendor/typo3/cms-* wurden nur %d Dateien gefunden. Der Ordner der Seite ist vermutlich falsch." % len(server))
        return
    sha = ""
    page = webmod.fetch(typo3ref.PAGE % ver, webmod.UA_BROWSER, max_bytes=400_000, timeout=25)
    if not page.error and page.status == 200:
        sha = typo3.sha256_from_version_page(page.body, ver)
    ctx.progress("Lade das Original-Paket von TYPO3 %s (groß, das dauert)" % ver)
    try:
        ref = typo3ref.reference(ver, sha)
    except coreref.RefError as e:
        res.add("info", "Dateivergleich nicht möglich", "Original-Paket nicht verfügbar: %s" % e)
        return
    ctx.progress("Vergleiche %d Dateien" % len(server))
    composer = lay["mode"] == "composer"
    refs = {p: h for p, h in ref["files"].items() if not re.search(r"(^|/)(node_modules|\.git)(/|$)", p)}
    present = [p for p in refs if p in server]
    changed = sorted(p for p in present if server[p] != refs[p])
    missing = sorted(p for p in refs if p not in server)
    dirs = {p.rsplit("/", 1)[0] for p in refs}
    extra = sorted(p for p in server if p not in refs and p.rsplit("/", 1)[0] in dirs and not re.search(r"(^|/)(node_modules|\.git|\.htaccess)(/|$)", p))
    src = "Original-Paket %s, %s." % (ref["package"], "Prüfsumme von get.typo3.org bestätigt" if ref["verified"] else "OHNE veröffentlichte Prüfsumme (nur https-Quelle)")
    _emit(res, at.judge_core_files(len(present) if composer else len(refs), changed, missing, extra, src, composer=composer))


@check(
    "typo3_settings", G_KONFIG, "TYPO3-Einstellungsdatei (settings.php)",
    "Steht in der Einstellungsdatei Auffälliges, ist das Install-Tool gesperrt, und sind die Rechte richtig gesetzt?",
    what="Liest die Einstellungsdatei (config/system/settings.php, bei klassischer Installation typo3conf/system/settings.php, vor TYPO3 12 typo3conf/LocalConfiguration.php) und die additional.php. Geprüft werden auffällige Befehle "
         "(eval, base64_decode), Fehleranzeige, devIPmask, trustedHostsPattern, Debug-Modus, Länge des encryptionKey, das Passwort-Verfahren, eine liegengebliebene Datei ENABLE_INSTALL_TOOL und die Schreibrechte.",
    why="Die Einstellungsdatei läuft bei jedem Aufruf und enthält die Zugangsdaten zur Datenbank. Sie ist ein beliebter Ort für Hintertüren. Ein dauerhaft freigeschaltetes Install-Tool ist ein direkter Weg zur Übernahme der Seite.",
    reads="Die Einstellungsdateien (Passwörter und Schlüssel werden nie angezeigt oder gespeichert; vom encryptionKey nur die Länge), die Dateirechte und das Vorhandensein der Datei ENABLE_INSTALL_TOOL. Es wird nichts verändert.",
    load="leicht", needs="ssh", presets=["schnell", "hack", "komplett"], cms="typo3",
)
def typo3_settings(ctx, res):
    cfg = ctx.config()
    lay = layout(ctx)
    modes: Dict[str, str] = {}
    path = cfg.get("path") or ""
    if path:
        out = ctx.sh("stat -c '%%a %%U %%n' %s %s 2>/dev/null" % (_q(path), _q(os.path.dirname(path) or ".")), timeout=20).out
        for ln in out.splitlines():
            m = re.match(r"^(\d{3,4}) (\S+) (.+)\Z", ln.strip())
            if m:
                modes[m.group(3)] = "%s %s" % (m.group(1), m.group(2))
    _emit(res, at.judge_settings(cfg, modes, lay.get("install_tool")))


def _q(s: str) -> str:
    return "'" + s.replace("'", "'\\''") + "'"


@check(
    "typo3_exposed", G_KONFIG, "TYPO3: frei abrufbare Dateien und Seiten",
    "Kann jeder Besucher Einstellungen, Composer-Dateien oder den Installations-Assistenten abrufen?",
    what="Ruft von DIESEM PC aus einzelne Adressen ohne Anmeldung auf: die Einstellungsdateien, composer.json und composer.lock, .env, .git/config, die Ordnerlisten von typo3conf/ext, fileadmin und typo3temp, das Install-Tool und die Backend-Anmeldung. "
         "Es werden nur normale Seitenaufrufe gesendet.",
    why="Eine abrufbare Konfigurationsdatei oder ein erreichbarer Installations-Assistent können zur Übernahme der Seite führen. Das lässt sich ohne Anmeldung von außen sehen.",
    reads="Öffentlich erreichbare Adressen Ihrer Domain, so wie jeder Besucher sie sieht. Inhalte werden nicht gespeichert. Es wird nichts verändert.",
    load="leicht", needs="web", presets=["schnell", "hack", "komplett"], cms="typo3",
)
def typo3_exposed(ctx, res):
    url = (ctx.s.url or "").strip()
    if not url:
        raise CheckSkipped("Keine Adresse der Webseite angegeben (Feld 'Webseite' in den Verbindungsdaten).")
    from .. import secure
    url, _ = secure.to_https(url)
    base = url.rstrip("/")
    targets = [("file", "Einstellungsdatei", "/typo3conf/LocalConfiguration.php"), ("file", "Einstellungsdatei", "/typo3conf/system/settings.php"), ("file", "Einstellungsdatei", "/config/system/settings.php"),
               ("file", "Zusatz-Einstellungen", "/typo3conf/AdditionalConfiguration.php"), ("file", "Composer-Datei", "/composer.json"), ("file", "Composer-Sperrdatei", "/composer.lock"),
               ("file", "Umgebungsdatei", "/.env"), ("file", "Git-Konfiguration", "/.git/config"),
               ("dir", "Ordner typo3conf/ext", "/typo3conf/ext/"), ("dir", "Ordner fileadmin", "/fileadmin/"), ("dir", "Ordner typo3temp", "/typo3temp/"),
               ("install", "Install-Tool", "/typo3/install.php"), ("backend", "Backend-Anmeldung", "/typo3/")]
    web: List[Dict[str, Any]] = []
    for kind, label, path in targets:
        ctx.progress("Rufe %s ab" % path)
        f = webmod.fetch(base + path, webmod.UA_BROWSER, max_bytes=20000, timeout=15)
        if f.error:
            continue
        web.append({"kind": kind, "label": label, "url": base + path, "status": f.status, "body": f.body})
    _emit(res, at.judge_exposed(web))


def _inventory(ctx) -> Tuple[List[Dict[str, Any]], Dict[str, str]]:
    """Erweiterungen (Anzeige) und {Paketname: Version} zum Abfragen bei Packagist (Erweiterungen und, wenn bekannt, die Systemerweiterungen)."""
    out = ctx.sh(r"""echo '@@INSTALLED'
for f in vendor/composer/installed.json ../vendor/composer/installed.json; do if [ -f "$f" ]; then head -c 4000000 "$f"; break; fi; done
echo; echo '@@EXT'
for d in typo3conf/ext/*/ public/typo3conf/ext/*/; do
  [ -f "$d/ext_emconf.php" ] || continue
  echo "@@E $d"; head -c 6000 "$d/ext_emconf.php"; echo; echo '@@C:'; head -c 3000 "$d/composer.json" 2>/dev/null; echo
done
echo '@@SYSEXT'; ls -1 typo3/sysext typo3_src/typo3/sysext 2>/dev/null | grep -v ':' | head -200""", timeout=120, raw="erweiterungen", raw_cap=20_000).out
    sec = split_sections(out)
    inv: List[Dict[str, Any]] = []
    pkgs: Dict[str, str] = {}
    seen = set()
    for p in typo3.parse_installed_json(sec.get("INSTALLED", "")):
        if p["name"].startswith("typo3/cms-"):
            if p["name"] != "typo3/cms-core" and p["version"]:
                pkgs[p["name"]] = p["version"]
            continue
        if p["type"] != "typo3-cms-extension":
            continue
        seen.add(p["name"])
        inv.append({"key": p["name"], "name": p["name"], "version": p["version"], "state": "", "pkg": p["name"], "custom": bool(p["path"])})
        if p["version"]:
            pkgs[p["name"]] = p["version"]
    for blk in (sec.get("EXT", "")).split("@@E ")[1:]:
        head, _, rest = blk.partition("\n")
        emconf, _, comp = rest.partition("@@C:")
        key = typo3.ext_key_of(head.strip().rstrip("/")) or head.strip()
        info = typo3.parse_ext_emconf(emconf)
        pkg = typo3.composer_name_of(comp)
        if key in seen or (pkg and pkg in seen):
            continue
        seen.add(key)
        inv.append({"key": key, "name": info.get("title") or key, "version": info.get("version", ""), "state": info.get("state", ""), "pkg": pkg, "custom": False})
        if pkg and info.get("version"):
            pkgs[pkg] = info["version"]
    core = typo3_version(ctx)
    if core and not any(k.startswith("typo3/cms-") for k in pkgs):
        for name in [x.strip() for x in sec.get("SYSEXT", "").splitlines() if re.fullmatch(r"[a-z0-9_]+", x.strip())][:80]:
            if name != "core":
                pkgs[typo3.sysext_package(name)] = core
    return inv, pkgs


@check(
    "typo3_extensions", G_EXT, "TYPO3-Erweiterungen und Systemerweiterungen",
    "Welche Erweiterungen laufen, und gibt es zu ihren Versionen bekannte Sicherheitsmeldungen?",
    what="Liest die Erweiterungen (klassisch: ext_emconf.php unter typo3conf/ext; Composer: vendor/composer/installed.json) mit Name, Version und Status und fragt bei Packagist nach Sicherheitsmeldungen des TYPO3-Sicherheitsteams, "
         "die auf genau diese Versionen zutreffen. Das gilt auch für die Systemerweiterungen (typo3/cms-*). Es werden höchstens 150 Pakete abgefragt. Eigene Erweiterungen (lokale Pakete) werden nur aufgelistet.",
    why="Die meisten Einbrüche bei TYPO3 laufen über veraltete Erweiterungen. Das TYPO3-Sicherheitsteam veröffentlicht Meldungen mit den betroffenen Versionen; das lässt sich automatisch vergleichen.",
    reads="Die Dateien ext_emconf.php und composer.json (nur die ersten Zeichen) sowie installed.json und eine Liste der Systemerweiterungen; im Internet Packagist (nur Paketnamen und Versionen werden gesendet). Es wird nichts verändert.",
    load="mittel", needs="web", presets=["schnell", "hack", "komplett"], cms="typo3",
)
def typo3_extensions(ctx, res):
    inv, pkgs = _inventory(ctx)
    adv: Dict[str, List[Dict[str, str]]] = {}
    ok = False
    if pkgs:
        ctx.progress("Frage Packagist nach Sicherheitsmeldungen (%d Pakete)" % len(pkgs))
        adv, ok = advisories(list(pkgs))
        if len(pkgs) > MAX_PACKAGES:
            res.add("info", "Nur %d von %d Paketen wurden abgefragt" % (MAX_PACKAGES, len(pkgs)), "Mehr Abfragen auf einmal werden bewusst nicht gestellt.")
    hits: Dict[str, List[Dict[str, str]]] = {}
    for m in inv:
        if m.get("pkg") and m.get("version"):
            h = typo3.advisories_for(m["version"], adv, m["pkg"])
            if h:
                hits[m["key"]] = h
    for pkg, v in pkgs.items():                         # Systemerweiterungen nur, wenn eine Meldung zutrifft
        if pkg.startswith("typo3/cms-"):
            h = typo3.advisories_for(v, adv, pkg)
            if h:
                inv.append({"key": pkg, "name": "Systemerweiterung " + (typo3.package_sysext(pkg) or pkg), "version": v, "state": "", "pkg": pkg, "custom": False})
                hits[pkg] = h
    _emit(res, at.judge_extensions(inv, hits, checked=len(pkgs), adv_ok=ok))


@check(
    "typo3_users", G_DB, "TYPO3-Backend-Konten und Administratoren",
    "Wer ist Administrator, und wurde kürzlich ein neues Konto mit Administratorrechten angelegt?",
    what="Liest aus der Tabelle be_users Name, Status, Anlege- und Anmeldedatum und ob ein Konto Administrator ist. Gemeldet werden neue Administrator-Konten, nie benutzte Administrator-Konten, sehr viele Administratoren und leicht zu erratende Namen.",
    why="Nach einem Einbruch legen Angreifer gern ein eigenes Administrator-Konto an, weil es auch nach einer Säuberung der Dateien bleibt.",
    reads="Benutzername, Status, Anlege- und Anmeldedatum und das Administrator-Merkmal. Passwörter und E-Mail-Adressen werden nicht abgefragt. Es wird nichts verändert.",
    load="leicht", needs="db", presets=["schnell", "hack", "komplett"], cms="typo3",
)
def typo3_users(ctx, res):
    db = need_db(ctx, res, "TYPO3-Konten", [("Backend-Benutzer", Q_USERS)])
    need_supported(ctx)
    rows = fetch(db, Q_USERS)
    if rows is None:
        _emit(res, at.judge_users(None))
        return
    us = [{"uid": r.get("uid"), "name": r.get("name"), "admin": str(r.get("adm") or "0") not in ("0", ""), "disabled": str(r.get("dis") or "0") not in ("0", ""),
           "created_ts": _ts(r.get("created")), "access_ts": _ts(r.get("access"))} for r in rows]
    _emit(res, at.judge_users(us))


def _ts(v):
    """TYPO3 speichert Zeitpunkte als Unix-Sekunden (Zahl); 0 = nie."""
    try:
        n = int(str(v).strip())
        return float(n) if n > 0 else None
    except (TypeError, ValueError):
        return None


@check(
    "typo3_db_code", G_DB, "Eingeschleuster Code in TYPO3-Inhalten",
    "Stehen in Inhaltselementen, im TypoScript oder in Nachrichten Skripte, Iframes oder verschleierter Code?",
    what="Sucht in den Textfeldern der Inhaltselemente (tt_content), der TypoScript-Vorlagen (sys_template) und, falls vorhanden, der Nachrichten der Erweiterung news nach <script>, <iframe>, javascript:, eval(, atob( und fromCharCode und zeigt die Stelle.",
    why="Angreifer schleusen Code gern in Inhalte ein, weil er in der Datenbank steht und bei einer Dateisuche nicht auftaucht. Besucher werden dann umgeleitet oder ihre Eingaben abgegriffen.",
    reads="Die Textfelder bodytext und config (nur Treffer, höchstens 200 je Tabelle). Es wird nichts verändert.",
    load="mittel", needs="db", presets=["hack", "komplett"], cms="typo3",
)
def typo3_db_code(ctx, res):
    db = need_db(ctx, res, "Code in TYPO3-Inhalten", [("Inhaltselemente", Q_CODE["tt_content"])])
    need_supported(ctx)
    rows: List[Dict[str, Any]] = []
    got = False
    for tbl, q in Q_CODE.items():
        r = fetch(db, q)
        if r is None:
            continue
        got = True
        rows += [{"table": tbl, "id": x.get("id"), "text": x.get("text")} for x in r]
    _emit(res, at.judge_db_code(rows if got else None))
