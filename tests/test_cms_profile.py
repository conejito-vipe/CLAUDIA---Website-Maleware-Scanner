"""CMS-Profile (2.6.0): jedes unterstützte System beschreibt sich vollständig selbst; der Code liest daraus statt zu verzweigen."""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from claudia import cms  # noqa: E402

REQUIRED = {"id", "name", "config_file", "upload_dirs", "cache_dirs", "prune_find", "recent_skip", "lib_exclude", "lib_exclude2", "ext_root_re", "manifest_find",
            "code_dir_re", "root_ok", "ext_dir_re", "installer_sql_re", "core_dirs", "core_files", "ext_word", "ext_words", "upload_word", "admin_url",
            "version_key", "admin_word", "enable_hint", "sec_base", "sec_depth", "no_sec_title", "install_hint", "outside_dir", "spool", "root_find",
            "need_mods", "zip_note", "root_text", "store", "update_cli", "vel"}


class Profiles(unittest.TestCase):
    def test_every_profile_is_complete_and_consistent(self):
        for key, p in cms.PROFILES.items():
            self.assertEqual(p["id"], key)
            self.assertEqual(sorted(REQUIRED - set(p)), [], key)

    def test_known_falls_back_to_joomla(self):
        for bad in (None, "", "prestashop", 5):
            self.assertEqual(cms.known(bad), "joomla")
        self.assertEqual(cms.known("wordpress"), "wordpress")
        self.assertEqual(cms.profile("gibt-es-nicht")["id"], "joomla")

    def test_names_roundtrip(self):
        for key in cms.PROFILES:
            self.assertEqual(cms.by_name(cms.name_of(key)), key)
        self.assertEqual(cms.by_name("Unbekannt"), "joomla")

    def test_values_that_code_relied_on_before(self):
        j, w = cms.profile("joomla"), cms.profile("wordpress")
        self.assertEqual((j["admin_word"], w["admin_word"]), ("Backend", "Dashboard"))
        self.assertEqual((j["need_mods"], w["need_mods"]), (["zlib", "json", "mbstring", "xml"], ["json", "mysqli"]))
        self.assertEqual((j["sec_depth"], w["sec_depth"]), (2, 1))
        self.assertTrue(j["update_cli"] and not w["update_cli"])
        self.assertEqual((j["store"], w["store"]), ("jed", "wporg"))
        self.assertIn("wp-content/uploads", w["outside_dir"])
        self.assertEqual(j["outside_dir"], "images/files")

    def test_cluster_for_matches_old_rule(self):
        from claudia.registry import ordered
        for c in ordered("wordpress"):
            self.assertEqual(c.cluster_for("wordpress"), c.cluster_wp or c.cluster)
        for c in ordered("joomla"):
            self.assertEqual(c.cluster_for("joomla"), c.cluster)

    def test_no_direct_system_name_branches_left_in_converted_places(self):
        """Die umgestellten Stellen dürfen nicht wieder auf feste Systemnamen verzweigen."""
        root = os.path.dirname(HERE)
        for rel, forbidden in (("claudia/report.py", '"WordPress" if'), ("claudia/checks/update_ready.py", 'name = "WordPress" if'),
                               ("claudia/checks/security_ext.py", 'name = "WordPress" if'), ("claudia/server.py", '"cms_name": "WordPress" if')):
            self.assertNotIn(forbidden, open(os.path.join(root, rel), encoding="utf-8").read(), rel)


if __name__ == "__main__":
    unittest.main()
