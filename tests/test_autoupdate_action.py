"""Aktion 'API für automatische Joomla-Updates einschalten' (Angebot, Vorschau, Ausführung, Rückgängig-Datei, Schutz, Abbruch ohne Sicherung)."""
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

import test_actions2 as t2  # noqa: E402
from claudia import actions  # noqa: E402
from claudia.runner import LocalRunner  # noqa: E402
from test_account_actions import CH, q  # noqa: E402

INS = ("INSERT INTO j_extensions (extension_id,name,type,element,folder,client_id,enabled,manifest_cache,params,protected) VALUES "
       "(801,'Web Services - Joomla-Update','plugin','joomlaupdate','webservices',0,0,'{}','',0),"
       "(802,'API-Authentifizierung - Token','plugin','token','api-authentication',0,0,'{}','',0),"
       "(803,'Web Services - Content','plugin','content','webservices',0,0,'{}','',0),"
       "(804,'Benutzer - Joomla API-Token','plugin','token','user',0,0,'{}','',0),"
       "(805,'System - Fremd','plugin','fremd','system',0,0,'{}','',0)")
TITLE = "Die Joomla-API ist (teilweise) ausgeschaltet: automatische Updates können nicht laufen"


def offer(findings, cms="joomla", rid="auto_updates"):
    res = [{"id": rid, "title": "x", "status": "crit", "findings": findings}]
    info = {"cms": cms, "php_candidates": [{"name": "php8.3", "version": "PHP 8.3.6"}]}
    return {a["id"]: a for a in actions.available(res, info, "8.3", {}, {})}


class Offer(unittest.TestCase):
    def test_offered_only_for_the_api_finding(self):
        self.assertIn("enable_autoupdate_api", offer([{"sev": "crit", "title": TITLE, "items": []}]))
        self.assertNotIn("enable_autoupdate_api", offer([{"sev": "warn", "title": "Automatische Updates sind in Joomla ausgeschaltet", "items": []}]))
        self.assertNotIn("enable_autoupdate_api", offer([{"sev": "crit", "title": TITLE, "items": []}], rid="joomla_api"))
        self.assertNotIn("enable_autoupdate_api", offer([{"sev": "crit", "title": TITLE, "items": []}], cms="wordpress"))

    def test_has_undo_backup_and_risk(self):
        a = offer([{"sev": "crit", "title": TITLE, "items": []}])["enable_autoupdate_api"]
        self.assertIn("rueckgaengig.sql", a["undo"])
        self.assertEqual(a["sicherung"]["art"], "gezielt")
        self.assertEqual(a["risk"], "mittel")
        self.assertIn("Zielkonflikt", a["warning"])

    def test_disable_api_warns_about_autoupdates(self):
        self.assertIn("automatischen Core-Updates", actions.ACTIONS["disable_api"]["warning"])
        self.assertIn("automatischen Core-Updates", actions.STEP_WHY["disable_api"])

    def test_preview_shows_commands(self):
        txt = "\n".join(actions.commands_preview("enable_autoupdate_api", {}, CH))
        self.assertIn("UPDATE #__extensions SET enabled = 1", txt)
        self.assertIn("rueckgaengig.sql", txt)


class Run(unittest.TestCase):
    def test_switches_on_only_the_two_plugins_and_writes_undo(self):
        r, w = t2.world()
        q(w, INS)
        res = actions.run_action(r, w["site_rel"], "enable_autoupdate_api", {}, CH)
        self.assertTrue(res["ok"], res)
        st = dict(q(w, "SELECT extension_id, enabled FROM j_extensions WHERE extension_id BETWEEN 801 AND 805"))
        self.assertEqual(st, {801: 1, 802: 1, 803: 0, 804: 0, 805: 0})                 # nur die zwei nötigen, keine weiteren API-Plugins
        txt = open(os.path.join(res["backup_dir"], "rueckgaengig.sql")).read()
        self.assertIn("SET enabled = 0 WHERE extension_id IN (801,802)", txt.replace(", ", ","))
        self.assertTrue(os.path.exists(os.path.join(res["backup_dir"], "extensions.sql.gz")))

    def test_no_tokens_created(self):
        r, w = t2.world()
        q(w, INS)
        n = q(w, "SELECT COUNT(*) FROM j_user_profiles")[0][0]
        actions.run_action(r, w["site_rel"], "enable_autoupdate_api", {}, CH)
        self.assertEqual(q(w, "SELECT COUNT(*) FROM j_user_profiles")[0][0], n)

    def test_nothing_to_do(self):
        r, w = t2.world()
        res = actions.run_action(r, w["site_rel"], "enable_autoupdate_api", {}, CH)
        self.assertTrue(res["ok"])
        self.assertFalse(res.get("backup_dir"))
        self.assertIn("nichts einzuschalten", res["message"])

    def test_no_backup_no_change(self):
        r, w = t2.world()
        q(w, INS)
        broken = tempfile.mkdtemp(prefix="claudia_nodump_")
        t2.script(os.path.join(broken, "mysqldump"), "echo kaputt >&2; exit 2")
        r2 = LocalRunner(w["home"], extra_path=broken + os.pathsep + w["bin"])
        res = actions.run_action(r2, w["site_rel"], "enable_autoupdate_api", {}, CH)
        self.assertFalse(res["ok"])
        self.assertEqual(q(w, "SELECT COUNT(*) FROM j_extensions WHERE extension_id IN (801,802) AND enabled=1")[0][0], 0)

    def test_undo_file_restores_state(self):
        r, w = t2.world()
        q(w, INS)
        res = actions.run_action(r, w["site_rel"], "enable_autoupdate_api", {}, CH)
        undo = open(os.path.join(res["backup_dir"], "rueckgaengig.sql")).read().split("\n", 1)[1]
        q(w, undo)
        self.assertEqual(q(w, "SELECT COUNT(*) FROM j_extensions WHERE extension_id IN (801,802) AND enabled=1")[0][0], 0)


if __name__ == "__main__":
    unittest.main()
