"""Laufen die automatischen Updates wirklich? bei Drupal, TYPO3, Contao, PrestaShop, Shopware und WooCommerce: Bewertung mit Beispieldaten, Abfragen gegen einen Platzhalter-Kontext."""
import os
import sys
import time
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

from claudia.checks import auto_updates_cms as ac  # noqa: E402
from claudia.db import DbTableMissing  # noqa: E402
from claudia.model import CheckResult  # noqa: E402
from claudia.registry import REGISTRY, load_all, ordered  # noqa: E402
from test_auto_updates import FakeCtx, FakeDb  # noqa: E402

load_all()
NOW = 1_800_000_000.0
RECENT = int(NOW) - 3600
OLD = int(NOW) - 5 * 86400


def run(ctx):
    res = CheckResult("auto_updates", "t", "grundlagen")
    REGISTRY["auto_updates"].fn(ctx, res)
    res.finalize()
    return res


def titles(res):
    return [f.title for f in res.findings]


def mod_cfg(*names):
    return 'a:2:{s:6:"module";a:%d:{%s}s:5:"theme";a:0:{}}' % (len(names), "".join('s:%d:"%s";i:0;' % (len(n), n) for n in names))


class Helfer(unittest.TestCase):
    def test_to_ts(self):
        self.assertEqual(ac.to_ts("1700000000"), 1700000000)
        self.assertEqual(ac.to_ts("i:1700000000;"), 1700000000)
        self.assertEqual(ac.to_ts("2023-11-14 22:13:20.123"), 1700000000)
        self.assertEqual(ac.to_ts("2023-11-14T22:13:20"), 1700000000)
        for bad in (None, "", "0000-00-00 00:00:00", "gestern", "12", "i:abc;"):
            self.assertIsNone(ac.to_ts(bad), bad)

    def test_module_names(self):
        self.assertEqual(ac.module_names(mod_cfg("update", "automated_cron")), {"update", "automated_cron"})
        self.assertEqual(ac.module_names(""), set())
        self.assertEqual(ac.module_names(None), set())

    def test_ago(self):
        self.assertEqual(ac.ago(int(NOW) - 600, NOW), "vor 10 Minuten")
        self.assertEqual(ac.ago(int(NOW) - 5 * 3600, NOW), "vor 5 Stunden")
        self.assertEqual(ac.ago(int(NOW) - 5 * 86400, NOW), "vor 5 Tagen")


class Bewertung(unittest.TestCase):
    def sev(self, rows):
        return [r[0] for r in rows]

    def test_drupal_good_but_manual(self):
        rows = ac.rows_drupal({"update", "automated_cron"}, RECENT, RECENT, "", True, [], NOW)
        self.assertEqual(self.sev(rows), ["info"])
        self.assertIn("nicht selbst", rows[0][1])
        self.assertIn("ja (composer.lock", rows[0][3][0])

    def test_drupal_update_module_off(self):
        rows = ac.rows_drupal({"automated_cron"}, RECENT, RECENT, "", False, [], NOW)
        self.assertEqual(rows[0][0], "warn")
        self.assertIn("Update Manager", rows[0][1])

    def test_drupal_cron_stale_severity_depends_on_automated_cron(self):
        self.assertEqual(ac.rows_drupal({"update"}, OLD, RECENT, "", True, [], NOW)[0][0], "crit")
        self.assertEqual(ac.rows_drupal({"update", "automated_cron"}, OLD, RECENT, "", True, [], NOW)[0][0], "warn")
        self.assertIn("Cronjob im Konto: 0 * * * * drush cron", ac.rows_drupal({"update"}, OLD, RECENT, "", True, ["0 * * * * drush cron"], NOW)[0][3])

    def test_drupal_update_check_stale_only_when_cron_fine(self):
        rows = ac.rows_drupal({"update"}, RECENT, OLD, "", True, [], NOW)
        self.assertEqual(rows[0][0], "warn")
        self.assertIn("5 Tagen", rows[0][1])
        rows = ac.rows_drupal({"update"}, OLD, OLD, "", True, [], NOW)
        self.assertEqual(len([r for r in rows if r[0] != "info"]), 1)          # nur der Cron-Befund, nicht doppelt

    def test_drupal_automatic_updates_module_shows_settings(self):
        rows = ac.rows_drupal({"update", "automatic_updates"}, RECENT, RECENT, "a:1:{s:9:\"unattended\";a:1:{s:5:\"level\";i:1;}}", True, [], NOW)
        self.assertIn("eingeschaltet", rows[-1][1])
        self.assertIn("unattended", rows[-1][3][0])

    def test_drupal_unknown_modules_does_not_guess(self):
        self.assertEqual(self.sev(ac.rows_drupal(None, None, None, "", False, [], NOW)), ["info"])

    def test_typo3_cases(self):
        self.assertEqual(self.sev(ac.rows_typo3(False, 0, 0, None, True, NOW)), ["info", "info"])
        rows = ac.rows_typo3(True, 3, 2, OLD, True, NOW)
        self.assertEqual(rows[0][0], "warn")
        self.assertIn("2 Aufgabe", rows[0][1])
        self.assertEqual(self.sev(ac.rows_typo3(True, 3, 0, RECENT, False, NOW)), ["info"])
        self.assertEqual(ac.rows_typo3(True, 3, 0, OLD, False, NOW)[0][0], "warn")
        self.assertEqual(ac.rows_typo3(True, 0, 0, None, False, NOW)[0][0], "info")

    def test_contao_cases(self):
        self.assertEqual(self.sev(ac.rows_contao(None, None, True, False, NOW)), ["info"])
        self.assertEqual(ac.rows_contao(0, None, True, False, NOW)[0][0], "info")
        self.assertEqual(ac.rows_contao(5, OLD, True, False, NOW)[0][0], "warn")
        rows = ac.rows_contao(5, RECENT, False, True, NOW)
        self.assertEqual(self.sev(rows), ["info"])
        self.assertIn("Contao Manager im Webordner: ja", rows[0][3])

    def test_prestashop_cases(self):
        self.assertIn("nicht installiert", ac.rows_prestashop({}, None, None, NOW)[0][1])
        self.assertIn("ausgeschaltet", ac.rows_prestashop({"autoupgrade": {"active": "0", "version": "5.0"}}, None, None, NOW)[0][1])
        mods = {"autoupgrade": {"active": "1", "version": "7.0.1"}, "cronjobs": {"active": "1", "version": "2"}}
        self.assertEqual(self.sev(ac.rows_prestashop(mods, 2, RECENT, NOW)), ["info"])
        rows = ac.rows_prestashop(mods, 2, OLD, NOW)
        self.assertEqual(self.sev(rows), ["info", "warn"])
        self.assertEqual(ac.rows_prestashop(mods, 2, None, NOW)[1][0], "warn")
        self.assertEqual(self.sev(ac.rows_prestashop({"cronjobs": {"active": "0"}}, 0, None, NOW)), ["info"])       # ausgeschaltet: kein Befund

    def test_shopware_cases(self):
        rows = ac.rows_shopware(20, 3, 1, OLD, ["config/packages/shopware.yaml:4:auto_update: enabled"], True, NOW)
        self.assertEqual(self.sev(rows), ["warn", "info", "info"])
        self.assertIn("auto_update", rows[-1][3][-1])
        self.assertEqual(self.sev(ac.rows_shopware(20, 0, 0, RECENT, [], False, NOW)), ["info"])
        self.assertEqual(self.sev(ac.rows_shopware(None, 0, 0, None, [], False, NOW)), ["info"])

    def test_woocommerce_cases(self):
        self.assertEqual(self.sev(ac.rows_woocommerce(0, None, 3, NOW)), [])
        rows = ac.rows_woocommerce(12, OLD, 25, NOW)
        self.assertEqual(self.sev(rows), ["warn", "info"])
        self.assertIn("12", rows[0][1])


class Abfragen(unittest.TestCase):
    """Platzhalter-Kontext: Datenbankzeilen und Ausgaben der Shell-Aufrufe."""

    def setUp(self):
        p = mock.patch.object(ac.time, "time", return_value=NOW)
        p.start()
        self.addCleanup(p.stop)

    def ctx(self, cms, tables=None, files="", cron="", db=True, extra=""):
        d = FakeDb(tables or {}) if db else None
        sh = {"@@FILES": "@@FILES\n%s\n@@CRONTAB\n%s\n%s" % (files, cron, extra)}
        return FakeCtx(cms=cms, db=d, shell_extra=sh)

    def test_drupal_ok_and_queries_are_read_only(self):
        c = self.ctx("drupal", {"core.extension": [{"v": mod_cfg("update", "automated_cron")}], "system.cron_last": [{"v": "i:%d;" % RECENT}], "update.last_check": [{"v": "i:%d;" % RECENT}]}, files="LOCK")
        res = run(c)
        self.assertEqual(res.status, "info", titles(res))
        self.assertIn("keine Auffälligkeiten", titles(res)[-1])
        self.assertTrue(all(q.lstrip().upper().startswith("SELECT") for q in c.db_obj.queries), c.db_obj.queries)
        self.assertFalse(any(w in s for s in c.scripts for w in ("rm ", "chmod", "> ", "mv ", "sed -i")), c.scripts)

    def test_drupal_cron_stale_is_critical(self):
        res = run(self.ctx("drupal", {"core.extension": [{"v": mod_cfg("update")}], "system.cron_last": [{"v": "i:%d;" % OLD}]}))
        self.assertEqual(res.status, "crit", titles(res))
        self.assertIn("Cron läuft nicht", res.findings[0].title)

    def test_drupal_without_db_says_not_checkable_but_not_ok_claims(self):
        res = run(self.ctx("drupal", db=False))
        self.assertEqual(res.status, "info")
        self.assertTrue(any("nicht prüfbar" in i for f in res.findings for i in (f.items if hasattr(f, "items") else [])) or any("nicht prüfbar" in str(f.__dict__) for f in res.findings))

    def test_typo3_table_missing_means_no_scheduler(self):
        def raise_missing(sql):
            raise DbTableMissing("tx_scheduler_task")
        res = run(self.ctx("typo3", {"tx_scheduler_task": raise_missing}))
        self.assertIn("nicht eingerichtet", titles(res)[0])

    def test_typo3_overdue(self):
        res = run(self.ctx("typo3", {"tx_scheduler_task": [{"n": "4", "od": "2", "l": str(OLD)}]}, files="LOCK"))
        self.assertEqual(res.status, "warn", titles(res))
        self.assertIn("2 Aufgabe", titles(res)[0])

    def test_typo3_registry_last_run(self):
        reg = 'a:3:{s:5:"start";i:%d;s:3:"end";i:%d;s:4:"type";s:4:"cron";}' % (RECENT - 5, RECENT)
        res = run(self.ctx("typo3", {"tx_scheduler_task": [{"n": "4", "od": "0", "l": str(OLD)}], "sys_registry": [{"v": reg}]}))
        self.assertEqual(res.status, "info", titles(res))
        self.assertIn("keine Auffälligkeiten", titles(res)[-1])

    def test_contao_stale_and_manager(self):
        res = run(self.ctx("contao", {"tl_cron_job": [{"n": "6", "l": "2026-01-01 04:00:00"}]}, files="LOCK\nMANAGER"))
        self.assertEqual(res.status, "warn", titles(res))
        res = run(self.ctx("contao", {"tl_cron_job": [{"n": "6", "l": str(RECENT)}]}, files="LOCK\nMANAGER"))
        self.assertEqual(res.status, "info", titles(res))

    def test_prestashop_modules(self):
        rows = [{"name": "autoupgrade", "active": "1", "version": "7.0.1"}, {"name": "cronjobs", "active": "1", "version": "2"}, {"name": "x';DROP", "active": "1", "version": "1"}]
        res = run(self.ctx("prestashop", {"FROM #__module": rows, "#__cronjobs": [{"n": "2", "l": "2026-01-01 00:00:00"}]}))
        self.assertEqual(res.status, "warn", titles(res))

    def test_shopware_overdue_and_config_lines(self):
        res = run(self.ctx("shopware", {"scheduled_task": [{"n": "20", "od": "3", "f": "0", "l": str(OLD)}]}, files="LOCK", extra="@@SWCFG\nconfig/packages/shopware.yaml:4:auto_update: enabled: false\n"))
        self.assertEqual(res.status, "warn", titles(res))
        self.assertEqual(titles(res)[0][:8], "Shopware")

    def test_woocommerce_in_wordpress_check(self):
        fresh = 'a:1:{i:%d;a:1:{s:16:"wp_version_check";a:0:{}}}' % (int(time.time()) + 600)
        ok = {"CRON_CURL": "HTTP/2 200\ncontent-type: text/html\n", "CRON_BROWSER": "HTTP/2 200\ncontent-type: text/html\n"}
        d = FakeDb({"option_name = 'cron'": [{"v": fresh}], "actionscheduler_actions WHERE status = 'pending'": [{"n": "7", "o": "2026-01-01 00:00:00"}], "status = 'failed'": [{"n": "0"}]})
        with mock.patch.dict(os.environ):
            os.environ.pop("CLAUDIA_OFFLINE", None)
            res = run(FakeCtx(cms="wordpress", db=d, probes=ok, cfg={"defines": {}}))
        self.assertEqual(res.status, "warn", titles(res))
        self.assertTrue(any("WooCommerce" in t for t in titles(res)))

    def test_wordpress_without_woocommerce_unchanged(self):
        fresh = 'a:1:{i:%d;a:1:{s:16:"wp_version_check";a:0:{}}}' % (int(time.time()) + 600)
        ok = {"CRON_CURL": "HTTP/2 200\ncontent-type: text/html\n", "CRON_BROWSER": "HTTP/2 200\ncontent-type: text/html\n"}

        def missing(sql):
            raise DbTableMissing("actionscheduler_actions")
        d = FakeDb({"option_name = 'cron'": [{"v": fresh}], "actionscheduler_actions": missing})
        with mock.patch.dict(os.environ):
            os.environ.pop("CLAUDIA_OFFLINE", None)
            res = run(FakeCtx(cms="wordpress", db=d, probes=ok, cfg={"defines": {}}))
        self.assertEqual(res.status, "ok", titles(res))


class Registrierung(unittest.TestCase):
    def test_check_runs_for_all_systems_with_own_texts(self):
        seen = set()
        for cms in ("joomla", "wordpress", "drupal", "typo3", "contao", "prestashop", "shopware"):
            c = [x for x in ordered(cms) if x.id == "auto_updates"]
            self.assertEqual(len(c), 1, cms)
            v = c[0].view(cms)
            seen.add(v["summary"])
            if cms not in ("joomla", "wordpress"):
                self.assertNotIn("Joomla", " ".join(v.values()), cms)
        self.assertEqual(len(seen), 7)


if __name__ == "__main__":
    unittest.main()
