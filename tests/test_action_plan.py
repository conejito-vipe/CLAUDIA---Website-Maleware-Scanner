"""Maßnahmenplan (claudia/actionplan.py): Phasen, Reihenfolge, Aktionsregeln und Hinweise. Reine Funktion, eigene Beispieldaten."""
import copy
import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

from claudia.actionplan import ACTION_ORDER, build_plan  # noqa: E402

CMAP = {
    "webshells": "php_shells", "js_scan": "js_inject", "db_users": "joomla_konten", "sessions": "konto",
    "update_ready": "update", "ext_integrity": "ext_pruefen", "perms": "rechte", "web_headers": "besucher",
    "backup_tool": "ext_sicherung", "joomla_info": "umfeld", "ohne_cluster": "", "fremd": "gibt_es_nicht",
}


def f(sev, title="Befund"):
    return {"sev": sev, "title": title, "detail": "d", "items": ["x"], "hint": "", "evidence": []}


def res(cid, status, *findings):
    return {"id": cid, "title": "Prüfung " + cid, "group": "g", "status": status, "findings": list(findings), "message": ""}


def act(aid, risk="niedrig", irreversible=None):
    a = {"id": aid, "title": "Aktion " + aid, "risk": risk}
    if irreversible is not None:
        a["irreversible"] = irreversible
    return a


def ids(plan, phase=None):
    out = []
    for p in plan["phases"]:
        if phase is None or p["id"] == phase:
            out += [s.get("action_id") or s["check_id"] for s in p["steps"]]
    return out


def phase_ids(plan):
    return [p["id"] for p in plan["phases"]]


class Leer(unittest.TestCase):
    def test_empty_and_none(self):
        for args in [([], []), (None, None), ({}, "x")]:
            p = build_plan(*args, cluster_map=CMAP)
            self.assertEqual(p["phases"], [])
            self.assertEqual(p["summary"], {"crit": 0, "warn": 0, "actions": 0})
            self.assertEqual(len(p["notes"]), 1)

    def test_incomplete_dicts(self):
        r = [{}, None, 5, {"id": "webshells"}, {"findings": None}, {"status": "crit", "findings": [None, {}, {"sev": "crit"}]}]
        p = build_plan(r, [{}, None, 5, {"title": "ohne id"}], cluster_map=CMAP)
        self.assertEqual(p["summary"]["crit"], 1)
        self.assertEqual(p["summary"]["actions"], 0)
        json.dumps(p)

    def test_empty_note_is_not_a_clean_bill(self):
        note = build_plan([], [])["notes"][0]
        self.assertIn("kein Beweis", note)

    def test_only_harmless_statuses(self):
        r = [res("webshells", "ok", f("ok")), res("js_scan", "info", f("info")),
             res("db_users", "error", f("crit")), res("sessions", "skipped", f("warn"))]
        p = build_plan(r, [], cluster_map=CMAP)
        self.assertEqual(p["phases"], [])
        self.assertEqual(len(p["notes"]), 1)

    def test_info_findings_inside_warn_result_ignored(self):
        p = build_plan([res("webshells", "warn", f("info"), f("warn", "W"))], [], cluster_map=CMAP)
        self.assertEqual([s["title"] for s in p["phases"][0]["steps"]], ["W"])


class Reihenfolge(unittest.TestCase):
    def test_phase_order_is_fixed(self):
        r = [res("backup_tool", "warn", f("warn")), res("perms", "warn", f("warn")), res("update_ready", "warn", f("warn")),
             res("sessions", "warn", f("warn")), res("webshells", "crit", f("crit")), res("fremd", "warn", f("warn"))]
        p = build_plan(r, [], cluster_map=CMAP)
        self.assertEqual(phase_ids(p), ["einbruch", "zugaenge", "luecken", "haertung", "umfeld", "weitere"])

    def test_crit_before_warn_in_input_order(self):
        r = [res("webshells", "crit", f("warn", "w1"), f("crit", "c1")), res("js_scan", "crit", f("crit", "c2"), f("warn", "w2"))]
        steps = build_plan(r, [], cluster_map=CMAP)["phases"][0]["steps"]
        self.assertEqual([s["title"] for s in steps], ["c1", "c2", "w1", "w2"])

    def test_findings_before_actions(self):
        steps = build_plan([res("webshells", "crit", f("crit"))], [act("remove_shells")], cluster_map=CMAP)["phases"][-1]["steps"]
        self.assertEqual([s["kind"] for s in steps], ["finding", "action"])

    def test_actions_follow_action_order(self):
        p = build_plan([], [act("clean_tmp"), act("reset_htaccess"), act("remove_shells")])
        self.assertEqual(ids(p, "einbruch"), ["remove_shells", "reset_htaccess", "clean_tmp"])

    def test_action_order_list_is_complete_copy(self):
        self.assertEqual(ACTION_ORDER[0], "backup_now")
        self.assertEqual(ACTION_ORDER[-1], "delete_old_backups")
        self.assertEqual(len(ACTION_ORDER), 34)

    def test_actions_missing_in_order_go_to_phase_end(self):
        p = build_plan([], [act("delete_quarantine"), act("restore_quarantine"), act("clean_tmp")])
        self.assertEqual(ids(p, "einbruch"), ["clean_tmp", "delete_quarantine", "restore_quarantine"])

    def test_irreversible_last_in_phase(self):
        p = build_plan([], [act("clean_tmp", "mittel", True), act("remove_shells", "mittel", False), act("reset_htaccess", "mittel")])
        self.assertEqual(ids(p, "einbruch"), ["remove_shells", "reset_htaccess", "clean_tmp"])

    def test_irreversible_keep_order_among_themselves(self):
        p = build_plan([], [act("delete_quarantine", "mittel", True), act("clean_tmp", "mittel", True), act("remove_shells")])
        self.assertEqual(ids(p, "einbruch"), ["remove_shells", "clean_tmp", "delete_quarantine"])


class Aktionen(unittest.TestCase):
    def test_backup_with_other_action(self):
        p = build_plan([], [act("remove_shells"), act("backup_now")])
        self.assertEqual(phase_ids(p), ["vorbereitung", "einbruch"])
        self.assertEqual(ids(p, "vorbereitung"), ["backup_now"])

    def test_backup_alone_dropped(self):
        p = build_plan([], [act("backup_now")])
        self.assertEqual(p["phases"], [])
        self.assertEqual(p["summary"]["actions"], 0)

    def test_backup_with_only_excluded_others_dropped(self):
        p = build_plan([], [act("backup_now"), act("check_updates", "keine"), act("clear_cache", "keine")])
        self.assertEqual(p["phases"], [])

    def test_backup_with_findings_only_dropped(self):
        p = build_plan([res("webshells", "crit", f("crit"))], [act("backup_now")], cluster_map=CMAP)
        self.assertEqual(ids(p), ["webshells"])

    def test_check_updates_and_risk_keine_never_in_plan(self):
        p = build_plan([], [act("check_updates", "niedrig"), act("check_updates", "keine"), act("clear_cache", "keine"), act("block_users")])
        self.assertEqual(ids(p), ["block_users"])

    def test_unknown_action_goes_to_weitere(self):
        p = build_plan([], [act("etwas_neues", "mittel")])
        self.assertEqual(phase_ids(p), ["weitere"])
        self.assertEqual(p["phases"][0]["steps"][0]["action_id"], "etwas_neues")

    def test_duplicate_action_once(self):
        p = build_plan([], [act("remove_shells"), act("remove_shells", "hoch", True), act("clean_tmp")])
        self.assertEqual(ids(p, "einbruch"), ["remove_shells", "clean_tmp"])
        self.assertEqual(p["summary"]["actions"], 2)

    def test_action_step_fields(self):
        step = build_plan([], [act("remove_shells", "mittel", True), act("clean_tmp")])["phases"][0]["steps"][-1]
        self.assertEqual(step, {"kind": "action", "action_id": "remove_shells", "title": "Aktion remove_shells", "risk": "mittel", "irreversible": True})

    def test_missing_title_and_irreversible_defaults(self):
        step = build_plan([], [{"id": "block_users", "risk": "niedrig"}])["phases"][0]["steps"][0]
        self.assertEqual((step["title"], step["irreversible"]), ("block_users", False))

    def test_no_invented_actions(self):
        offered = ["remove_shells", "block_users", "core_update", "harden_headers", "clear_cache"]
        p = build_plan([res("webshells", "crit", f("crit"))], [act(a, "mittel") for a in offered], cluster_map=CMAP)
        planned = [s["action_id"] for ph in p["phases"] for s in ph["steps"] if s["kind"] == "action"]
        self.assertEqual(sorted(planned), sorted(offered))

    def test_phase_mapping_of_actions(self):
        wanted = {"remove_shells": "einbruch", "block_users": "zugaenge", "core_update": "luecken",
                  "harden_headers": "haertung", "clear_cache": "umfeld"}
        p = build_plan([], [act(a, "mittel") for a in wanted])
        for ph in p["phases"]:
            for s in ph["steps"]:
                self.assertEqual(wanted[s["action_id"]], ph["id"])


class Befunde(unittest.TestCase):
    def test_finding_step_has_no_details(self):
        step = build_plan([res("webshells", "crit", f("crit", "Hintertür"))], [], cluster_map=CMAP)["phases"][0]["steps"][0]
        self.assertEqual(step, {"kind": "finding", "check_id": "webshells", "severity": "crit", "title": "Hintertür"})

    def test_no_cluster_map_all_in_weitere(self):
        p = build_plan([res("webshells", "crit", f("crit"))], [], cluster_map=None)
        self.assertEqual(phase_ids(p), ["weitere"])

    def test_missing_empty_or_unknown_cluster_goes_to_weitere(self):
        r = [res("nicht_in_karte", "warn", f("warn")), res("ohne_cluster", "warn", f("warn")), res("fremd", "warn", f("warn"))]
        p = build_plan(r, [], cluster_map=CMAP)
        self.assertEqual(phase_ids(p), ["weitere"])
        self.assertEqual(len(p["phases"][0]["steps"]), 3)

    def test_cluster_to_phase(self):
        r = [res("webshells", "crit", f("crit")), res("db_users", "warn", f("warn")), res("ext_integrity", "warn", f("warn")),
             res("web_headers", "warn", f("warn")), res("joomla_info", "warn", f("warn"))]
        p = build_plan(r, [], cluster_map=CMAP)
        self.assertEqual(phase_ids(p), ["einbruch", "zugaenge", "luecken", "haertung", "umfeld"])

    def test_phase_has_title_and_why(self):
        p = build_plan([res("webshells", "crit", f("crit"))], [act("backup_now"), act("remove_shells")], cluster_map=CMAP)
        self.assertEqual([x["title"] for x in p["phases"]], ["Vorbereitung: Sicherung", "Einbruchstelle und Schadcode"])
        for ph in p["phases"]:
            self.assertTrue(ph["why"].endswith("."))
            self.assertNotIn("garantiert", ph["why"])


class Zaehlung(unittest.TestCase):
    def test_summary_counts(self):
        r = [res("webshells", "crit", f("crit"), f("crit"), f("warn")), res("perms", "warn", f("warn")), res("js_scan", "info", f("info"))]
        p = build_plan(r, [act("backup_now"), act("remove_shells"), act("harden_perms")], cluster_map=CMAP)
        self.assertEqual(p["summary"], {"crit": 2, "warn": 2, "actions": 3})


class Reinheit(unittest.TestCase):
    def setUp(self):
        self.r = [res("webshells", "crit", f("crit")), res("perms", "warn", f("warn"))]
        self.a = [act("backup_now"), act("remove_shells", "hoch", True), act("remove_shells"), act("x_neu")]

    def test_inputs_not_mutated(self):
        r0, a0, c0 = copy.deepcopy(self.r), copy.deepcopy(self.a), copy.deepcopy(CMAP)
        build_plan(self.r, self.a, "joomla", CMAP)
        self.assertEqual((self.r, self.a, CMAP), (r0, a0, c0))

    def test_json_serializable(self):
        json.dumps(build_plan(self.r, self.a, "joomla", CMAP))

    def test_same_result_twice(self):
        self.assertEqual(build_plan(self.r, self.a, "joomla", CMAP), build_plan(self.r, self.a, "joomla", CMAP))

    def test_result_does_not_share_input_objects(self):
        p = build_plan(self.r, self.a, "joomla", CMAP)
        p["phases"][0]["steps"][0]["title"] = "geändert"
        self.assertEqual(self.r[0]["findings"][0]["title"], "Befund")


class Hinweise(unittest.TestCase):
    def test_crit_in_einbruch_gives_password_note(self):
        notes = build_plan([res("webshells", "crit", f("crit"))], [], cluster_map=CMAP)["notes"]
        self.assertEqual(len(notes), 1)
        self.assertIn("nach der Bereinigung", notes[0])
        self.assertIn("Empfehlung", notes[0])

    def test_warn_in_einbruch_or_crit_elsewhere_no_password_note(self):
        for r in [res("webshells", "warn", f("warn")), res("db_users", "crit", f("crit"))]:
            notes = build_plan([r], [], cluster_map=CMAP)["notes"]
            self.assertEqual(notes, [])

    def test_irreversible_note_once(self):
        notes = build_plan([], [act("delete_quarantine", "mittel", True), act("delete_old_backups", "mittel", True)])["notes"]
        self.assertEqual(len(notes), 1)
        self.assertIn("nicht vollständig rückgängig", notes[0])

    def test_irreversible_false_gives_no_note(self):
        self.assertEqual(build_plan([], [act("clean_tmp", "mittel", False)])["notes"], [])

    def test_high_risk_note_once(self):
        notes = build_plan([], [act("core_update", "hoch"), act("update_extensions", "hoch")])["notes"]
        self.assertEqual(len(notes), 1)
        self.assertIn("Sicherung", notes[0])

    def test_all_notes_together_without_duplicates(self):
        p = build_plan([res("webshells", "crit", f("crit"))], [act("core_update", "hoch"), act("delete_quarantine", "mittel", True)], cluster_map=CMAP)
        self.assertEqual(len(p["notes"]), 3)
        self.assertEqual(len(set(p["notes"])), 3)

    def test_notes_name_the_program_in_capitals(self):
        for n in build_plan([res("webshells", "crit", f("crit"))], [], cluster_map=CMAP)["notes"]:
            self.assertNotIn("Claudia", n)


class Systeme(unittest.TestCase):
    def test_wordpress_actions(self):
        wp_map = {"wp_core": "einstieg", "wp_plugins": "ext_pruefen"}
        r = [res("wp_core", "crit", f("crit", "Core verändert")), res("wp_plugins", "warn", f("warn", "Plugin veraltet"))]
        p = build_plan(r, [act("wp_update", "hoch"), act("wp_salts", "mittel"), act("backup_now"), act("check_updates", "keine")],
                       cms="wordpress", cluster_map=wp_map)
        self.assertEqual(phase_ids(p), ["vorbereitung", "einbruch", "zugaenge", "luecken"])
        self.assertEqual(ids(p, "zugaenge"), ["wp_salts"])
        self.assertEqual(ids(p, "luecken"), ["wp_plugins", "wp_update"])
        self.assertEqual(p["summary"], {"crit": 1, "warn": 1, "actions": 3})
        self.assertEqual(len(p["notes"]), 2)

    def test_joomla_actions(self):
        r = [res("webshells", "crit", f("crit")), res("web_headers", "warn", f("warn"))]
        a = [act("harden_headers"), act("core_update", "hoch"), act("remove_shells", "mittel"), act("block_users", "mittel"), act("backup_now")]
        p = build_plan(r, a, cms="joomla", cluster_map=CMAP)
        self.assertEqual(phase_ids(p), ["vorbereitung", "einbruch", "zugaenge", "luecken", "haertung"])
        self.assertEqual(ids(p, "einbruch"), ["webshells", "remove_shells"])
        self.assertEqual(ids(p, "haertung"), ["web_headers", "harden_headers"])


if __name__ == "__main__":
    unittest.main()
