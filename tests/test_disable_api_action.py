"""2.4.1: Aktion 'Joomla-API abschalten' (Angebot, Vorschau, Ausführung, Rückgängig-Datei, Schutz, Abbruch ohne Sicherung)."""
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
       "(701,'Web Services - Content','plugin','content','webservices',0,1,'{}','',0),"
       "(702,'Benutzer - Joomla API-Token','plugin','token','user',0,1,'{}','',0),"
       "(703,'API-Authentifizierung - Token','plugin','token','api-authentication',0,1,'{}','',0),"
       "(704,'Web Services - Users','plugin','users','webservices',0,0,'{}','',0),"
       "(705,'System - Fremd','plugin','fremd','system',0,1,'{}','',0),"
       "(706,'Web Services - Geschützt','plugin','prot','webservices',0,1,'{}','',1)")


def offer(findings, cms="joomla"):
    res = [{"id": "joomla_api", "title": "x", "status": "warn", "findings": findings}]
    info = {"cms": cms, "php_candidates": [{"name": "php8.3", "version": "PHP 8.3.6"}]}
    return {a["id"]: a for a in actions.available(res, info, "8.3", {}, {})}


class Offer(unittest.TestCase):
    def test_offered_when_api_active(self):
        for t in ("3 Benutzer mit API-Token, API-Zugang aktiv", "Web-Services aktiv, aber kein API-Token gefunden"):
            self.assertIn("disable_api", offer([{"sev": "warn", "title": t, "items": []}]))

    def test_not_offered_when_off_or_wordpress(self):
        self.assertNotIn("disable_api", offer([{"sev": "ok", "title": "Keine aktive API mit Token", "items": []}]))
        self.assertNotIn("disable_api", offer([{"sev": "warn", "title": "Web-Services aktiv, aber kein API-Token gefunden", "items": []}], "wordpress"))

    def test_has_undo_and_backup_description(self):
        a = offer([{"sev": "info", "title": "Web-Services aktiv, aber kein API-Token gefunden", "items": []}])["disable_api"]
        self.assertIn("rueckgaengig.sql", a["undo"])
        self.assertEqual(a["sicherung"]["art"], "gezielt")
        self.assertEqual(a["risk"], "mittel")

    def test_preview_shows_commands(self):
        txt = "\n".join(actions.commands_preview("disable_api", {}, CH))
        self.assertIn("UPDATE #__extensions SET enabled = 0", txt)
        self.assertIn("rueckgaengig.sql", txt)


class Run(unittest.TestCase):
    def test_switches_off_only_api_plugins_and_writes_undo(self):
        r, w = t2.world()
        q(w, INS)
        res = actions.run_action(r, w["site_rel"], "disable_api", {}, CH)
        self.assertTrue(res["ok"], res)
        st = dict(q(w, "SELECT extension_id, enabled FROM j_extensions WHERE extension_id BETWEEN 701 AND 706"))
        # 703 ist 'API-Authentifizierung - Token': der Update-Dienst braucht es, es bleibt an (3.1.0)
        self.assertEqual(st, {701: 0, 702: 0, 703: 1, 704: 0, 705: 1, 706: 1})
        txt = open(os.path.join(res["backup_dir"], "rueckgaengig.sql")).read()
        self.assertIn("SET enabled = 1 WHERE extension_id IN (701,702)", txt.replace(", ", ","))
        self.assertNotIn("703", txt)
        self.assertTrue(os.path.exists(os.path.join(res["backup_dir"], "extensions.sql.gz")))

    def test_tokens_stay(self):
        r, w = t2.world()
        q(w, INS)
        n = q(w, "SELECT COUNT(*) FROM j_user_profiles")[0][0]
        actions.run_action(r, w["site_rel"], "disable_api", {}, CH)
        self.assertEqual(q(w, "SELECT COUNT(*) FROM j_user_profiles")[0][0], n)

    def test_nothing_to_do(self):
        r, w = t2.world()
        res = actions.run_action(r, w["site_rel"], "disable_api", {}, CH)
        self.assertTrue(res["ok"])
        self.assertFalse(res.get("backup_dir"))
        self.assertIn("nichts auszuschalten", res["message"])

    def test_no_backup_no_change(self):
        r, w = t2.world()
        q(w, INS)
        broken = tempfile.mkdtemp(prefix="claudia_nodump_")
        t2.script(os.path.join(broken, "mysqldump"), "echo kaputt >&2; exit 2")
        r2 = LocalRunner(w["home"], extra_path=broken + os.pathsep + w["bin"])
        res = actions.run_action(r2, w["site_rel"], "disable_api", {}, CH)
        self.assertFalse(res["ok"])
        self.assertEqual(q(w, "SELECT COUNT(*) FROM j_extensions WHERE extension_id BETWEEN 701 AND 703 AND enabled=1")[0][0], 3)


if __name__ == "__main__":
    unittest.main()
