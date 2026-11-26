"""Laufen die automatischen Updates wirklich? für Drupal, TYPO3, Contao, PrestaShop, Shopware und WooCommerce (2.19.0)

Rein lesend. Keines dieser Systeme spielt Kern-Updates von sich aus ein (Drupal nur mit dem Modul 'Automatic Updates'); die Prüfung beantwortet deshalb, was sich lesen lässt:
Läuft der Zeitplan (Cron, Scheduler, Action Scheduler), der Update-Prüfungen und Hintergrundaufgaben auslöst, ist das passende Update-Werkzeug vorhanden, und wird die Seite
überhaupt über Composer verwaltet? Die Bewertung steckt in reinen Funktionen (rows_*), die mit Beispieldaten geprüft werden; die Abfragen stehen darunter.
Noch NICHT gegen echte Server geprüft: Tabellen- und Feldnamen (key_value, tx_scheduler_task, tl_cron_job, scheduled_task, actionscheduler_actions), das Format der Zeitwerte."""
from __future__ import annotations

import calendar
import re
import time
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from ..util import clean_line, lines_of, split_sections
from .database import fetch

Row = Tuple[str, str, str, List[str], str]
STALE_S = 36 * 3600                 # so lange darf ein Zeitplan still stehen, bevor es auffällt
UPDATE_CHECK_S = 3 * 86400          # Drupals Update-Prüfung läuft normalerweise täglich
IDENT = re.compile(r"^[A-Za-z0-9_]{1,64}\Z")


def to_ts(v: Any) -> Optional[int]:
    """Zeitwert aus der Datenbank: Unix-Zeit (Ziffern, auch serialisiert 'i:123;') oder 'JJJJ-MM-TT hh:mm:ss' (als UTC gelesen: eine Abweichung von Stunden ist hier unerheblich)."""
    if v is None:
        return None
    t = str(v).strip()
    m = re.match(r"^(?:[id]:)?(\d{9,11})(?:\.\d+)?;?\Z", t)
    if m:
        return int(m.group(1))
    m = re.match(r"^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2}):(\d{2})", t)
    if m and not t.startswith("0000"):
        try:
            return calendar.timegm(tuple(int(x) for x in m.groups()) + (0, 0, 0))     # type: ignore[arg-type]
        except (ValueError, OverflowError):
            return None
    return None


def ago(ts: int, now: float) -> str:
    s = max(0, int(now - ts))
    if s < 3600:
        return "vor %d Minuten" % (s // 60)
    if s < 2 * 86400:
        return "vor %d Stunden" % (s // 3600)
    return "vor %d Tagen" % (s // 86400)


def stamp(ts: int) -> str:
    return time.strftime("%Y-%m-%d %H:%M", time.gmtime(ts)) + " UTC"


def module_names(config_text: str) -> Set[str]:
    """Namen aus der Konfiguration 'core.extension' (serialisiertes PHP, nur gelesen, nie ausgeführt)."""
    return set(re.findall(r's:\d+:"([a-z0-9_]+)";i:-?\d+;', config_text or ""))


# ------------------------------------------------------------------------------------------------ Bewertung (rein)
def rows_drupal(modules: Optional[Set[str]], cron_last: Optional[int], update_last: Optional[int], auto_cfg: str, composer: bool, cron_lines: List[str], now: float) -> List[Row]:
    out: List[Row] = []
    mods = modules or set()
    if modules is not None and "update" not in mods:
        out.append(("warn", "Das Drupal-Modul 'Update Manager' (update) ist ausgeschaltet",
                    "Ohne dieses Modul prüft Drupal nicht, ob Sicherheitsupdates für Kern, Module und Themes erschienen sind, und zeigt keine Warnung im Backend.",
                    ["Modul 'update': aus"], "Unter Erweitern das Modul 'Update Manager' einschalten (oder Updates über Composer und den Sicherheitsverteiler selbst verfolgen)."))
    if cron_last is None:
        pass
    elif now - cron_last > STALE_S:
        auto = "automated_cron" in mods
        out.append(("warn" if auto else "crit", "Der Drupal-Cron läuft nicht (letzter Lauf %s)" % ago(cron_last, now),
                    "Der Cron löst die Prüfung auf Updates, das Aufräumen und die Aufgaben der Module aus. Steht er, melden sich Sicherheitsupdates nicht mehr, und mit dem Modul 'Automatic Updates' laufen auch die automatischen Updates nicht.",
                    ["letzter Lauf: %s" % stamp(cron_last), "Modul 'automated_cron': an (läuft nur bei Besuchen)" if auto else "Modul 'automated_cron': aus (ein Cronjob des Servers muss cron.php aufrufen)"]
                    + (["Cronjob im Konto: " + x for x in cron_lines] if cron_lines else []),
                    "Einen Cronjob einrichten (z. B. alle 15 Minuten: drush core:cron oder ein Aufruf von /cron/<Schlüssel>) und Bericht unter Berichte > Letzte Protokolleinträge prüfen."))
    if update_last is not None and now - update_last > UPDATE_CHECK_S and not any(r[1].startswith("Der Drupal-Cron") for r in out):
        out.append(("warn", "Drupal hat seit %d Tagen nicht mehr nach Updates gesucht" % ((now - update_last) // 86400),
                    "Die Update-Suche läuft über den Cron. Ist sie lange nicht gelaufen, fehlen aktuelle Hinweise auf Sicherheitsupdates.", ["letzte Suche: %s" % stamp(update_last)],
                    "Cron prüfen (siehe oben) und unter Berichte > Verfügbare Updates manuell prüfen."))
    if "automatic_updates" in mods:
        out.append(("info", "Das Modul 'Automatic Updates' ist eingeschaltet", "Es kann Sicherheitsupdates für den Kern selbst einspielen, wenn es dafür eingestellt ist. Das Programm bewertet die Einstellung nicht, sondern zeigt sie.",
                    [clean_line(auto_cfg)[:300]] if auto_cfg else ["(Einstellungen nicht gefunden)"], "Einstellungen unter Berichte > Verfügbare Updates > Einstellungen ansehen."))
    else:
        out.append(("info", "Drupal aktualisiert sich nicht selbst (das Modul 'Automatic Updates' ist nicht eingeschaltet)",
                    "Sicherheitsupdates müssen von Hand eingespielt werden. Das Modul 'Automatic Updates' kann Sicherheits- und Patch-Updates des Kerns automatisch einspielen, setzt aber eine Seite voraus, die mit Composer verwaltet wird.",
                    ["Seite mit Composer verwaltet: %s" % ("ja (composer.lock vorhanden)" if composer else "nein (keine composer.lock)")],
                    "Sicherheitsmeldungen von drupal.org abonnieren und Updates zeitnah einspielen; für Automatik das Modul 'Automatic Updates' prüfen."))
    return out


def rows_typo3(scheduler: Optional[bool], tasks: int, overdue: int, last_run: Optional[int], composer: bool, now: float) -> List[Row]:
    out: List[Row] = []
    if scheduler is False:
        out.append(("info", "Der TYPO3-Scheduler ist nicht eingerichtet",
                    "Ohne Scheduler (Systemerweiterung 'scheduler') laufen keine regelmäßigen Aufgaben wie Aufräumen oder das Aktualisieren der Erweiterungsliste.", [], "Scheduler installieren und einen Cronjob für 'vendor/bin/typo3 scheduler:run' einrichten."))
    elif scheduler:
        if tasks == 0:
            out.append(("info", "Im TYPO3-Scheduler sind keine Aufgaben aktiv", "Der Scheduler ist installiert, führt aber nichts aus: Aufräumen und andere regelmäßige Aufgaben laufen nicht.", [], "Im Backend unter System > Scheduler Aufgaben anlegen und einen Cronjob für den Scheduler einrichten."))
        elif overdue:
            out.append(("warn", "Der TYPO3-Scheduler steht: %d Aufgabe(n) sind seit über einem Tag überfällig" % overdue,
                        "Die Aufgaben laufen nur, wenn ein Cronjob den Scheduler aufruft. Steht er, bleiben auch Aufräumarbeiten und Prüfungen liegen.",
                        (["letzter Lauf: %s (%s)" % (stamp(last_run), ago(last_run, now))] if last_run else ["letzter Lauf: unbekannt"]) + ["aktive Aufgaben: %d" % tasks],
                        "Cronjob prüfen (z. B. alle 5 Minuten: vendor/bin/typo3 scheduler:run) und im Backend unter System > Scheduler nach Fehlern sehen."))
        elif last_run is not None and now - last_run > STALE_S:
            out.append(("warn", "Der TYPO3-Scheduler lief zuletzt %s" % ago(last_run, now), "Es ist nichts überfällig, aber der Scheduler wurde lange nicht aufgerufen.", ["letzter Lauf: %s" % stamp(last_run)], "Cronjob prüfen."))
    out.append(("info", "TYPO3 aktualisiert sich nicht selbst",
                "Weder der Kern noch Erweiterungen werden automatisch aktualisiert; das Einspielen von Sicherheitsupdates ist Handarbeit.",
                ["Seite mit Composer verwaltet: %s" % ("ja (composer.lock vorhanden)" if composer else "nein: Updates über das Install-Tool oder Dateien von Hand")],
                "Die Sicherheitsmeldungen des TYPO3-Teams verfolgen und Updates zeitnah einspielen (composer update)."))
    return out


def rows_contao(cron_jobs: Optional[int], last_run: Optional[int], composer: bool, manager: bool, now: float) -> List[Row]:
    out: List[Row] = []
    if cron_jobs is None:
        pass
    elif cron_jobs == 0 or last_run is None:
        out.append(("info", "In Contao ist noch kein Cronjob gelaufen", "Die Tabelle der Cronjobs ist leer: Der Zeitplan wurde noch nie ausgelöst.", [], "Cron einrichten (Befehl 'contao:cron' jede Minute) oder die Cron-Auslösung über Seitenaufrufe zulassen."))
    elif now - last_run > STALE_S:
        out.append(("warn", "Der Contao-Cron läuft nicht (letzter Lauf %s)" % ago(last_run, now),
                    "Contao führt regelmäßige Aufgaben (Suchindex, Aufräumen, Erweiterungen) über seinen Cron aus. Steht er, bleiben diese Aufgaben liegen.", ["letzter Lauf: %s" % stamp(last_run), "Cronjobs in der Tabelle: %d" % cron_jobs],
                    "Cronjob einrichten (jede Minute: php vendor/bin/contao-console contao:cron) oder prüfen, ob der Aufruf blockiert wird."))
    out.append(("info", "Contao aktualisiert sich nicht selbst",
                "Updates für Kern und Erweiterungen werden über Composer oder den Contao Manager eingespielt, nie automatisch.",
                ["Seite mit Composer verwaltet: %s" % ("ja (composer.lock vorhanden)" if composer else "nein (keine composer.lock)"), "Contao Manager im Webordner: %s" % ("ja" if manager else "nein")],
                "Sicherheitsmeldungen verfolgen und Updates zeitnah einspielen; den Contao Manager nur bei Bedarf bereitstellen und schützen."))
    return out


def rows_prestashop(modules: Dict[str, Dict[str, str]], cron_rows: Optional[int], cron_last: Optional[int], now: float) -> List[Row]:
    out: List[Row] = []
    au = modules.get("autoupgrade")
    if not au:
        out.append(("info", "Das Modul '1-Click-Upgrade' (autoupgrade) ist nicht installiert", "PrestaShop aktualisiert sich nie selbst. Das Modul führt ein Update auf Knopfdruck oder per Befehl aus; ohne es bleibt nur das Einspielen von Hand.", [],
                    "Das Modul 'autoupgrade' aus dem Back Office (Modulkatalog) installieren."))
    elif str(au.get("active")) != "1":
        out.append(("info", "Das Modul '1-Click-Upgrade' (autoupgrade) ist installiert, aber ausgeschaltet", "Updates laufen auch mit diesem Modul nur auf Anstoß, hier ist es aber nicht einmal aktiv.", ["Version: %s" % clean_line(au.get("version") or "?")], "Modul im Back Office einschalten."))
    else:
        out.append(("info", "PrestaShop aktualisiert sich nicht selbst (das Modul '1-Click-Upgrade' ist bereit)", "Das Modul spielt Updates nur auf Anstoß ein (Back Office oder Befehl), nicht von allein.", ["Version des Moduls: %s" % clean_line(au.get("version") or "?")],
                    "Sicherheitsmeldungen verfolgen und Updates zeitnah anstoßen."))
    cj = modules.get("cronjobs")
    if cj and str(cj.get("active")) == "1" and cron_rows is not None:
        if cron_last is None or now - cron_last > STALE_S:
            out.append(("warn", "Die Cronjobs von PrestaShop laufen nicht" + (" (letzter Lauf %s)" % ago(cron_last, now) if cron_last else ""), "Das Modul 'cronjobs' führt Aufgaben wie das Aufräumen und geplante Aktionen aus; es braucht einen echten Cronjob des Servers.",
                        ["aktive Aufgaben: %d" % cron_rows] + (["letzter Lauf: %s" % stamp(cron_last)] if cron_last else []), "Cronjob einrichten, der die Adresse des Moduls regelmäßig aufruft (siehe Modul-Einstellungen), oder das Modul ausschalten, wenn es nicht gebraucht wird."))
    return out


def rows_shopware(tasks: Optional[int], overdue: int, failed: int, last_run: Optional[int], auto_lines: List[str], composer: bool, now: float) -> List[Row]:
    out: List[Row] = []
    if tasks is not None:
        if overdue:
            out.append(("warn", "Shopware: %d geplante Aufgabe(n) sind seit über einem Tag überfällig" % overdue,
                        "Die Aufgaben (Suchindex, Aufräumen, Update-Prüfungen) laufen nur, wenn 'scheduled-task:run' und ein Message-Worker laufen. Steht der Zeitplan, bleiben auch die Prüfungen auf neue Versionen liegen.",
                        (["letzte Ausführung: %s (%s)" % (stamp(last_run), ago(last_run, now))] if last_run else ["letzte Ausführung: unbekannt"]) + ["Aufgaben gesamt: %d" % tasks],
                        "Cronjob für 'bin/console scheduled-task:run' und einen Worker ('bin/console messenger:consume') einrichten; im Admin unter Einstellungen > System > Geplante Aufgaben nachsehen."))
        if failed:
            out.append(("info", "Shopware: %d geplante Aufgabe(n) sind fehlgeschlagen" % failed, "Fehlgeschlagene Aufgaben laufen nicht von selbst wieder an.", [], "Protokoll der Aufgabe ansehen und die Aufgabe neu planen."))
    out.append(("info", "Shopware aktualisiert sich nicht selbst",
                "Updates werden im Admin (Update-Manager), per Befehl oder bei Composer-Installationen über Composer eingespielt, nie ganz ohne Anstoß.",
                ["Seite mit Composer verwaltet: %s" % ("ja (composer.lock vorhanden)" if composer else "nein")] + [clean_line(x)[:160] for x in auto_lines[:4]],
                "Sicherheitsmeldungen von Shopware verfolgen und Updates zeitnah einspielen."))
    return out


def rows_woocommerce(pending_overdue: int, oldest: Optional[int], failed_week: int, now: float) -> List[Row]:
    out: List[Row] = []
    if pending_overdue:
        out.append(("warn", "WooCommerce: %d geplante Aufgabe(n) sind überfällig" % pending_overdue,
                    "WooCommerce führt Hintergrundaufgaben (Webhooks, Abos, Datenbank-Updates) über den Action Scheduler aus; er hängt am WP-Cron. Überfällige Aufgaben heißen: Der Zeitplan läuft nicht richtig.",
                    (["älteste fällige Aufgabe: %s (%s)" % (stamp(oldest), ago(oldest, now))] if oldest else []), "WP-Cron wieder zum Laufen bringen (siehe oben) und unter WooCommerce > Status > Geplante Aktionen nachsehen."))
    if failed_week >= 20:
        out.append(("info", "WooCommerce: %d fehlgeschlagene geplante Aufgaben in den letzten 7 Tagen" % failed_week, "Viele Fehlschläge deuten auf ein Plugin oder eine Schnittstelle hin, die nicht antwortet.", [], "Unter WooCommerce > Status > Geplante Aktionen > Fehlgeschlagen die Meldungen ansehen."))
    return out


# ------------------------------------------------------------------------------------------------ Abfragen
def _emit(res, rows: Iterable[Row]) -> bool:
    bad = False
    for sev, title, text, items, hint in rows:
        res.add(sev, title, text, items, hint)
        bad = bad or sev in ("warn", "crit")
    return bad


def _one(db, sql: str) -> Optional[Dict[str, Any]]:
    try:
        rows = fetch(db, sql)
    except Exception:                                    # noqa: BLE001  fremde Tabelle mit unerwartetem Aufbau: nicht prüfbar
        return None
    return (rows[0] if rows else {}) if rows is not None else None


def _composer(sec: Dict[str, str]) -> bool:
    return "LOCK" in sec.get("FILES", "")


def _crontab_lines(sec: Dict[str, str]) -> List[str]:
    return [clean_line(x)[:160] for x in lines_of(sec.get("CRONTAB", ""))]


def run(ctx, res) -> None:
    """Einstieg für Drupal, TYPO3, Contao, PrestaShop und Shopware."""
    now = time.time()
    cms = ctx.cms
    out = ctx.sh("echo '@@FILES'\ntest -f composer.lock && echo LOCK\nfor f in web/contao-manager.phar.php public/contao-manager.phar.php contao-manager.phar.php; do test -f \"$f\" && echo MANAGER; done\n"
                 "echo '@@CRONTAB'\ncrontab -l 2>/dev/null | grep -iE 'drush|cron|typo3|scheduler|contao|console|prestashop|shopware' | head -6\n"
                 + ("echo '@@SWCFG'\ngrep -rhn 'auto_update' config/packages/*.yaml .env 2>/dev/null | head -4\n" if cms == "shopware" else ""), timeout=60, raw="auto_updates_cms").out
    sec = split_sections(out)
    composer = _composer(sec)
    db = ctx.db()
    dbok = bool(db and db.ok)
    notes: List[str] = []
    if not dbok:
        notes.append("Zeitplan aus der Datenbank (kein Datenbankzugriff vom Server aus)")
    rows: List[Row] = []
    if cms == "drupal":
        modules = cron = upd = None
        cfg = ""
        if dbok:
            r = _one(db, "SELECT LEFT(data, 60000) AS v FROM #__config WHERE name = 'core.extension'")
            modules = module_names(str((r or {}).get("v") or "")) if r else None
            r = _one(db, "SELECT LEFT(data, 1500) AS v FROM #__config WHERE name = 'automatic_updates.settings'")
            cfg = str((r or {}).get("v") or "") if r else ""
            for name in ("system.cron_last", "update.last_check"):
                r = _one(db, "SELECT value AS v FROM #__key_value WHERE collection = 'state' AND name = '%s'" % name)
                ts = to_ts((r or {}).get("v")) if r else None
                if name == "system.cron_last":
                    cron = ts
                else:
                    upd = ts
            if modules is None:
                notes.append("Liste der Module (Konfiguration 'core.extension' nicht lesbar)")
        rows = rows_drupal(modules, cron, upd, cfg, composer, _crontab_lines(sec), now)
    elif cms == "typo3":
        scheduler: Optional[bool] = None
        tasks = overdue = 0
        last: Optional[int] = None
        if dbok:
            r = _one(db, "SELECT COUNT(*) AS n, SUM(nextexecution > 0 AND nextexecution < UNIX_TIMESTAMP() - 86400) AS od, MAX(lastexecution_time) AS l FROM #__tx_scheduler_task WHERE deleted = 0 AND disable = 0")
            if r is None:
                scheduler = False
            else:
                scheduler = True
                tasks, overdue, last = int(r.get("n") or 0), int(r.get("od") or 0), to_ts(r.get("l"))
            reg = _one(db, "SELECT LEFT(entry_value, 400) AS v FROM #__sys_registry WHERE entry_namespace = 'tx_scheduler' AND entry_key = 'lastRun'")
            m = re.search(r'"end";[is]:(?:\d+:")?(\d{9,11})', str((reg or {}).get("v") or ""))
            if m:
                last = max(last or 0, int(m.group(1)))
        rows = rows_typo3(scheduler if dbok else None, tasks, overdue, last, composer, now)
    elif cms == "contao":
        jobs: Optional[int] = None
        last = None
        if dbok:
            r = _one(db, "SELECT COUNT(*) AS n, MAX(lastrun) AS l FROM #__tl_cron_job")
            if r is not None:
                jobs, last = int(r.get("n") or 0), to_ts(r.get("l"))
            else:
                notes.append("Cronjobs von Contao (Tabelle tl_cron_job fehlt oder ist nicht lesbar)")
        rows = rows_contao(jobs, last, composer, "MANAGER" in sec.get("FILES", ""), now)
    elif cms == "prestashop":
        mods: Dict[str, Dict[str, str]] = {}
        cj_rows: Optional[int] = None
        cj_last = None
        if dbok:
            for r in fetch(db, "SELECT name, active, version FROM #__module WHERE name IN ('autoupgrade', 'cronjobs')") or []:
                if IDENT.match(str(r.get("name"))):
                    mods[str(r["name"])] = {"active": str(r.get("active")), "version": str(r.get("version") or "")}
            if "cronjobs" in mods:
                r = _one(db, "SELECT COUNT(*) AS n, MAX(updated_at) AS l FROM #__cronjobs WHERE active = 1")
                if r is not None:
                    cj_rows, cj_last = int(r.get("n") or 0), to_ts(r.get("l"))
        rows = rows_prestashop(mods, cj_rows, cj_last, now)
    elif cms == "shopware":
        tasks_n: Optional[int] = None
        overdue = failed = 0
        last = None
        if dbok:
            r = _one(db, "SELECT COUNT(*) AS n, SUM(next_execution_time < UTC_TIMESTAMP() - INTERVAL 1 DAY AND status IN ('scheduled', 'queued')) AS od, "
                         "SUM(status = 'failed') AS f, MAX(last_execution_time) AS l FROM #__scheduled_task")
            if r is not None:
                tasks_n, overdue, failed, last = int(r.get("n") or 0), int(r.get("od") or 0), int(r.get("f") or 0), to_ts(r.get("l"))
            else:
                notes.append("Geplante Aufgaben (Tabelle scheduled_task nicht lesbar)")
        rows = rows_shopware(tasks_n, overdue, failed, last, [clean_line(x) for x in lines_of(sec.get("SWCFG", ""))], composer, now)
    bad = _emit(res, rows)
    if not bad:
        info = [r[1] for r in rows if r[0] == "info"]
        res.add("ok", "Der Zeitplan zeigt keine Auffälligkeiten", "Es wurde nichts gefunden, was Update-Prüfungen oder Hintergrundaufgaben stoppt (soweit lesbar). Ob und wann ein Update eingespielt wird, bleibt Handarbeit; siehe die Hinweise.",
                ["geprüft: " + t for t in info] + ["nicht prüfbar: " + n for n in notes])
    elif notes:
        res.add("info", "Nicht alles war prüfbar", "Diese Angaben konnten nicht gelesen werden.", ["nicht prüfbar: " + n for n in notes], "")


def woocommerce(ctx, res) -> bool:
    """WooCommerce-Zusatz für WordPress: überfällige Aufgaben im Action Scheduler. Gibt True zurück, wenn ein Befund gemeldet wurde."""
    db = ctx.db()
    if not (db and db.ok):
        return False
    r = _one(db, "SELECT COUNT(*) AS n, MIN(scheduled_date_gmt) AS o FROM #__actionscheduler_actions WHERE status = 'pending' AND scheduled_date_gmt < UTC_TIMESTAMP() - INTERVAL 1 HOUR")
    if r is None:
        return False
    f = _one(db, "SELECT COUNT(*) AS n FROM #__actionscheduler_actions WHERE status = 'failed' AND scheduled_date_gmt > UTC_TIMESTAMP() - INTERVAL 7 DAY") or {}
    return _emit(res, rows_woocommerce(int(r.get("n") or 0), to_ts(r.get("o")), int(f.get("n") or 0), time.time()))
