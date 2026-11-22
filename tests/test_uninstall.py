"""Deinstallation: Plan, Sicherheitsprüfungen und Löschskript."""
import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from claudia import uninstall  # noqa: E402


def world():
    base = os.path.realpath(tempfile.mkdtemp(prefix="claudia_un_"))
    root, data = os.path.join(base, "CLAUDIA"), os.path.join(base, "appdata", "CLAUDIA")
    os.makedirs(os.path.join(root, ".venv", "Lib"))
    os.makedirs(os.path.join(root, "claudia"))
    open(os.path.join(root, "start.bat"), "w").write("x")
    open(os.path.join(root, ".venv", "Lib", "paramiko.py"), "w").write("x" * 100)
    os.makedirs(os.path.join(data, "cache"))
    open(os.path.join(data, "cache", "joomla.json"), "w").write("{}")
    open(os.path.join(data, "launcher.log"), "w").write("log")
    open(os.path.join(data, "profile.json"), "w").write("{}")
    reports = os.path.join(base, "Dokumente", "CLAUDIA", "Berichte")
    os.makedirs(reports)
    open(os.path.join(reports, "bericht.txt"), "w").write("r")
    return base, root, data, reports


class Plan(unittest.TestCase):
    def test_defaults_do_not_touch_personal_data(self):
        _, root, data, reports = world()
        items = {i["id"]: i for i in uninstall.plan(root, data, reports)}
        self.assertTrue(items["venv"]["default"] and items["cache"]["default"] and items["log"]["default"])
        for k in ("profiles", "reports", "program"):
            self.assertFalse(items[k]["default"], k)
        self.assertTrue(items["profiles"]["personal"] and items["reports"]["personal"])
        self.assertFalse(items["hosts"]["exists"])
        self.assertGreater(items["venv"]["bytes"], 0)

    def test_validate_rejects_unknown_and_outside(self):
        _, root, data, reports = world()
        plan = uninstall.plan(root, data, reports)
        with self.assertRaises(ValueError):
            uninstall.validate(plan, ["../../etc"], root, data)
        plan2 = [dict(i) for i in plan]
        for i in plan2:
            if i["id"] == "cache":
                i["path"] = os.path.join(os.path.dirname(root), "fremd")
                os.makedirs(i["path"])
        with self.assertRaises(ValueError):
            uninstall.validate(plan2, ["cache"], root, data)

    def test_symlink_is_refused(self):
        base, root, data, reports = world()
        target = os.path.join(base, "wichtig")
        os.makedirs(target)
        shutil_link = os.path.join(data, "cache2")
        os.symlink(target, shutil_link)
        plan = [{"id": "cache", "label": "x", "path": shutil_link, "why": "", "default": True, "exists": True, "personal": False, "kind": "dir", "files": 0, "bytes": 0}]
        with self.assertRaises(ValueError):
            uninstall.validate(plan, ["cache"], root, data)

    def test_program_and_python_are_last(self):
        _, root, data, reports = world()
        plan = uninstall.plan(root, data, reports)
        chosen = uninstall.validate(plan, ["program", "venv", "cache"], root, data)
        self.assertEqual(chosen[-1]["id"], "program")


class Script(unittest.TestCase):
    def test_windows_script_text(self):
        _, root, data, reports = world()
        plan = uninstall.plan(root, data, reports)
        chosen = uninstall.validate(plan, ["venv", "log"], root, data)
        txt = uninstall.build_script(chosen, [4242, 4243], data, windows=True)
        self.assertIn('tasklist /fi "PID eq 4242"', txt)
        self.assertIn('rmdir /s /q "%s"' % os.path.join(root, ".venv"), txt)
        self.assertIn('del /f /q "%s"' % os.path.join(data, "launcher.log"), txt)
        self.assertIn("FEHLER", txt)
        self.assertLess(txt.index("PID eq 4242"), txt.index("rmdir /s /q"))      # erst warten, dann löschen

    def test_percent_is_escaped(self):
        items = [{"id": "x", "label": "a", "path": "C:\\Users\\100%\\x", "kind": "dir"}]
        self.assertIn("100%%", uninstall.build_script(items, [], "C:\\d", windows=True))

    @unittest.skipIf(os.name == "nt", "sh-Skript")
    def test_sh_script_deletes_selected_only(self):
        base, root, data, reports = world()
        plan = uninstall.plan(root, data, reports)
        chosen = uninstall.validate(plan, ["venv", "cache", "log"], root, data)
        path = uninstall.write_script(chosen, [], data)
        out = subprocess.run(["/bin/sh", path], capture_output=True, text=True, timeout=30)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertFalse(os.path.exists(os.path.join(root, ".venv")))
        self.assertFalse(os.path.exists(os.path.join(data, "cache")))
        self.assertTrue(os.path.exists(os.path.join(data, "profile.json")))          # persönliche Daten bleiben
        self.assertTrue(os.path.exists(os.path.join(reports, "bericht.txt")))
        self.assertTrue(os.path.exists(os.path.join(root, "start.bat")))
        self.assertFalse(os.path.exists(path))                                         # Skript löscht sich selbst


class WindowRun(unittest.TestCase):
    """Das Deinstallations-Fenster (ohne Oberfläche getestet): löscht nur sichere Pfade, meldet jeden Schritt."""

    def test_execute_removes_items_and_reports(self):
        from claudia import uninstall_window as uw
        d = tempfile.mkdtemp(prefix="claudia_uw_")
        a, b = os.path.join(d, "cache"), os.path.join(d, "x.log")
        os.makedirs(os.path.join(a, "sub"))
        open(os.path.join(a, "sub", "f.txt"), "w").write("1")
        open(b, "w").write("1")
        logs, steps = [], []
        res = uw.execute([{"label": "Zwischenspeicher", "path": a, "kind": "dir"}, {"label": "Protokoll", "path": b, "kind": "file"},
                          {"label": "Weg", "path": os.path.join(d, "gibtsnicht"), "kind": "dir"}, {"label": "Python", "path": "winget", "kind": "winget"}],
                         [], d, logs.append, lambda p, t, dd: steps.append(p))
        self.assertEqual((res["failed"], res["winget"]), ([], True))
        self.assertFalse(os.path.exists(a) or os.path.exists(b))
        self.assertEqual(steps[-1], 100)
        self.assertTrue(any(x.startswith("erledigt") and "Zwischenspeicher" in x for x in logs), logs)
        self.assertTrue(steps == sorted(steps))

    def test_unsafe_paths_are_refused(self):
        from claudia import uninstall_window as uw
        keep = tempfile.mkdtemp(prefix="claudia_uw_")
        logs = []
        items = [{"label": "Heim", "path": os.path.expanduser("~"), "kind": "dir"}, {"label": "Relativ", "path": "relativ/pfad/lang", "kind": "dir"},
                 {"label": "Wurzel", "path": os.path.abspath(os.sep), "kind": "dir"}]
        res = uw.execute(items, [], os.path.join(keep, "daten"), logs.append, lambda *a: None)
        self.assertEqual(len(res["failed"]), 3)
        self.assertTrue(os.path.isdir(os.path.expanduser("~")))
        link = os.path.join(keep, "lnk")
        os.symlink(keep, link)
        self.assertFalse(uw.safe_path(link))

    def test_launch_window_writes_plan_without_secrets_and_uses_base_python(self):
        from unittest import mock
        base, root, data, reports = world()
        plan = uninstall.plan(root, data, reports)
        chosen = uninstall.validate(plan, ["cache", "log"], root, data)
        with mock.patch("subprocess.Popen") as pop:
            p = uninstall.launch_window(chosen, [123], data)
        cmd = pop.call_args[0][0]
        self.assertTrue(cmd[1].endswith("uninstall_window.py") and os.path.isfile(cmd[1]))
        self.assertNotIn(os.sep + ".venv" + os.sep, cmd[0])
        d = json.load(open(p))
        self.assertEqual([i["id"] for i in d["items"]], ["cache", "log"])
        self.assertEqual(d["pids"], [123])


if __name__ == "__main__":
    unittest.main()
