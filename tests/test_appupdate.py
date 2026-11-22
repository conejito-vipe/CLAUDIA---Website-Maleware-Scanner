"""Programm-Update (claudia/appupdate.py und die Schnittstelle in server.py): Suche, Prüfsumme, Sicherung, Rückweg, Dialog-Ablauf.

Alles gegen nachgebildete Antworten; es wird nie ins Netz gegangen und nie der echte Programmordner verändert."""
import hashlib
import io
import json
import os
import shutil
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
import zipfile
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from claudia import appupdate, coreref  # noqa: E402
from claudia.server import make_server  # noqa: E402

URL = appupdate.DOWNLOAD_PREFIX + "v9.9.0/CLAUDIA_v9.9.0.zip"


def make_zip(version="9.9.0", top="CLAUDIA", extra=None, init=None):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        pre = top + "/" if top else ""
        z.writestr(pre + "claudia/__init__.py", init if init is not None else '__version__ = "%s"\n' % version)
        z.writestr(pre + "claudia/__main__.py", "# neu\n")
        z.writestr(pre + "claudia/neu.py", "# neue Datei\n")
        z.writestr(pre + "start.bat", "@echo neu\n")
        z.writestr(pre + ".venv/pyvenv.cfg", "darf nicht ankommen\n")
        for k, v in (extra or {}).items():
            z.writestr(k, v)
    return buf.getvalue()


def release(version="9.9.0", sha="", name=None, url=URL, body=None):
    return {"tag_name": "v" + version, "html_url": "https://github.com/x/y/releases/tag/v" + version, "published_at": "2026-11-23T10:00:00Z",
            "body": body if body is not None else "Neu: Update-Check\n\nSHA-256: %s" % sha,
            "assets": [{"name": name or "CLAUDIA_v%s.zip" % version, "browser_download_url": url, "size": 1234}]}


def old_program(base):
    root = os.path.join(base, "prog")
    os.makedirs(os.path.join(root, "claudia"))
    os.makedirs(os.path.join(root, ".venv"))
    with open(os.path.join(root, "claudia", "__init__.py"), "w") as fh:
        fh.write('__version__ = "2.15.0"\n')
    with open(os.path.join(root, "claudia", "__main__.py"), "w") as fh:
        fh.write("# alt\n")
    with open(os.path.join(root, "claudia", "nur_alt.py"), "w") as fh:
        fh.write("# bleibt\n")
    with open(os.path.join(root, "start.bat"), "w") as fh:
        fh.write("@echo alt\n")
    with open(os.path.join(root, ".venv", "pyvenv.cfg"), "w") as fh:
        fh.write("meins\n")
    return root


def snapshot(root):
    out = {}
    for b, _, fs in os.walk(root):
        for f in fs:
            p = os.path.join(b, f)
            with open(p, "rb") as fh:
                out[os.path.relpath(p, root)] = fh.read()
    return out


class Parse(unittest.TestCase):
    def test_newer_and_asset(self):
        sha = "a" * 64
        i = appupdate.parse_release(release(sha=sha), "2.15.0")
        self.assertTrue(i["newer"])
        self.assertEqual((i["version"], i["name"], i["url"], i["sha256"]), ("9.9.0", "CLAUDIA_v9.9.0.zip", URL, sha))

    def test_same_or_older_is_not_newer(self):
        self.assertFalse(appupdate.parse_release(release("2.15.0"), "2.15.0")["newer"])
        self.assertFalse(appupdate.parse_release(release("2.14.0"), "2.15.0")["newer"])

    def test_digest_of_asset_wins_and_old_name_accepted(self):
        r = release(sha="b" * 64, name="Claudia_v9.9.0.zip")
        r["assets"][0]["digest"] = "sha256:" + "c" * 64
        self.assertEqual(appupdate.parse_release(r, "1.0.0")["sha256"], "c" * 64)

    def test_foreign_download_url_is_dropped(self):
        i = appupdate.parse_release(release(url="https://evil.example/CLAUDIA_v9.9.0.zip", sha="a" * 64), "1.0.0")
        self.assertEqual(i["url"], "")

    def test_no_checksum_found(self):
        self.assertEqual(appupdate.parse_release(release(body="Nur Text"), "1.0.0")["sha256"], "")

    def test_bad_tag_raises(self):
        with self.assertRaises(ValueError):
            appupdate.parse_release({"tag_name": "nightly"}, "1.0.0")


class Check(unittest.TestCase):
    def setUp(self):
        env = mock.patch.dict(os.environ)                                                     # andere Tests dürfen CLAUDIA_OFFLINE nicht hereinreichen
        env.start()
        self.addCleanup(env.stop)
        os.environ.pop("CLAUDIA_OFFLINE", None)

    def test_check_ok_and_error_never_raises(self):
        r = appupdate.check("2.15.0", lambda *a: json.dumps(release(sha="a" * 64)).encode())
        self.assertTrue(r["ok"] and r["info"]["newer"])

        def boom(*a):
            raise coreref.RefError("kein Netz")
        r = appupdate.check("2.15.0", boom)
        self.assertFalse(r["ok"])
        self.assertIn("kein Netz", r["error"])
        self.assertFalse(appupdate.check("2.15.0", lambda *a: b"kein json")["ok"])

    def test_offline_mode(self):
        with mock.patch.dict(os.environ, {"CLAUDIA_OFFLINE": "1"}):
            self.assertFalse(appupdate.check("1.0.0", lambda *a: b"{}")["ok"])

    def test_skip_state(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        self.assertFalse(appupdate.skipped(d, "9.9.0"))
        appupdate.save_state(d, skip="9.9.0")
        self.assertTrue(appupdate.skipped(d, "9.9.0"))
        self.assertFalse(appupdate.skipped(d, "10.0.0"))


class Verify(unittest.TestCase):
    def test_wrong_checksum_and_missing_checksum(self):
        data = make_zip()
        with self.assertRaises(appupdate.UpdateError):
            appupdate.verify_package(data, "9.9.0", "0" * 64)
        with self.assertRaises(appupdate.UpdateError):
            appupdate.verify_package(data, "9.9.0", "")

    def test_version_mismatch_and_garbage(self):
        data = make_zip(version="9.8.0")
        with self.assertRaises(appupdate.UpdateError):
            appupdate.verify_package(data, "9.9.0", hashlib.sha256(data).hexdigest())
        junk = b"kein zip"
        with self.assertRaises(appupdate.UpdateError):
            appupdate.verify_package(junk, "9.9.0", hashlib.sha256(junk).hexdigest())

    def test_path_traversal_refused(self):
        data = make_zip(extra={"CLAUDIA/../../evil.py": "x"})
        with self.assertRaises(appupdate.UpdateError):
            appupdate.verify_package(data, "9.9.0", hashlib.sha256(data).hexdigest())

    def test_flat_and_wrapped_packages(self):
        for top in ("CLAUDIA", ""):
            data = make_zip(top=top)
            names = [n for n, _ in appupdate.verify_package(data, "9.9.0", hashlib.sha256(data).hexdigest())]
            self.assertIn("claudia/__init__.py", names)
            self.assertFalse([n for n in names if n.startswith(".venv")])


class Install(unittest.TestCase):
    def setUp(self):
        self.base = tempfile.mkdtemp(prefix="claudia_upd_")
        self.addCleanup(shutil.rmtree, self.base, True)
        self.root = old_program(self.base)
        self.data = os.path.join(self.base, "daten")
        self.zip = make_zip()
        self.info = appupdate.parse_release(release(sha=hashlib.sha256(self.zip).hexdigest()), "2.15.0")

    def fetch(self, url, *a):
        return self.zip

    def test_success_replaces_files_and_keeps_the_rest(self):
        before = snapshot(self.root)
        steps = []
        r = appupdate.install(self.info, self.root, self.data, lambda p, t: steps.append(p), self.fetch, current="2.15.0")
        self.assertTrue(r["ok"], r)
        self.assertEqual(steps, sorted(steps))
        after = snapshot(self.root)
        self.assertIn("9.9.0", after[os.path.join("claudia", "__init__.py")].decode())
        self.assertEqual(after[os.path.join("claudia", "neu.py")], b"# neue Datei\n")
        self.assertEqual(after[os.path.join("claudia", "nur_alt.py")], before[os.path.join("claudia", "nur_alt.py")])
        self.assertEqual(after[os.path.join(".venv", "pyvenv.cfg")], b"meins\n")             # .venv wird nie angefasst
        self.assertEqual(after["start.bat"], before["start.bat"])                             # Startdatei erst nach dem Beenden
        self.assertEqual(r["late"], ["start.bat"])
        self.assertTrue(os.path.isfile(os.path.join(r["staging"], "start.bat")))
        self.assertTrue(os.path.isfile(r["backup"]))
        self.assertTrue(os.path.isfile(r["log"]))

    def test_backup_has_old_state_without_venv(self):
        r = appupdate.install(self.info, self.root, self.data, None, self.fetch, current="2.15.0")
        with zipfile.ZipFile(r["backup"]) as z:
            names = z.namelist()
            self.assertIn("claudia/nur_alt.py", names)
            self.assertFalse([n for n in names if n.startswith(".venv")])
            self.assertIn("2.15.0", z.read("claudia/__init__.py").decode())

    def test_failure_midway_restores_everything(self):
        before = snapshot(self.root)
        real = appupdate._write
        calls = {"n": 0}

        def flaky(root, rel, data, mode=0):
            calls["n"] += 1
            if calls["n"] == 3 and root == self.root:
                raise OSError("Platte voll")
            return real(root, rel, data, mode)
        with mock.patch.object(appupdate, "_write", flaky):
            r = appupdate.install(self.info, self.root, self.data, None, self.fetch, current="2.15.0")
        self.assertFalse(r["ok"])
        self.assertIn("wiederhergestellt", r["error"])
        self.assertEqual(snapshot(self.root), before)                                         # Zustand wie vorher, neue Dateien entfernt
        with open(r["log"], encoding="utf-8") as fh:
            self.assertIn("FEHLER", fh.read())

    def test_bad_checksum_changes_nothing(self):
        before = snapshot(self.root)
        self.info["sha256"] = "0" * 64
        r = appupdate.install(self.info, self.root, self.data, None, self.fetch, current="2.15.0")
        self.assertFalse(r["ok"])
        self.assertEqual(snapshot(self.root), before)

    def test_refuses_foreign_url_missing_checksum_and_not_newer(self):
        for change in ({"url": "https://evil.example/a.zip"}, {"sha256": ""}, {"version": "2.15.0"}, {"version": "abc"}):
            info = dict(self.info, **change)
            self.assertFalse(appupdate.install(info, self.root, self.data, None, self.fetch, current="2.15.0")["ok"], change)

    def test_old_backups_are_replaced(self):
        appupdate.install(self.info, self.root, self.data, None, self.fetch, current="2.15.0")
        appupdate.install(self.info, self.root, self.data, None, self.fetch, current="2.15.0")
        d = appupdate.update_dir(self.data)
        self.assertEqual([f for f in os.listdir(d) if f.startswith("sicherung_")], ["sicherung_2.15.0.zip"])

    def test_restart_helper_code_is_valid(self):
        import ast
        ast.parse(appupdate.finish_code())

    def test_finish_script_moves_late_files(self):
        r = appupdate.install(self.info, self.root, self.data, None, self.fetch, current="2.15.0")
        code = appupdate.finish_code().split("os.chdir(root)")[0]                              # nur das Ersetzen, ohne Neustart
        import subprocess
        subprocess.run([sys.executable, "-c", code, self.root, r["staging"], "4194301"], check=True, timeout=60)
        with open(os.path.join(self.root, "start.bat")) as fh:
            self.assertEqual(fh.read(), "@echo neu\n")
        self.assertFalse(os.path.exists(r["staging"]))


class Api(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base = tempfile.mkdtemp(prefix="claudia_updapi_")
        cls.root = old_program(cls.base)
        cls.zip = make_zip()
        cls.rel = release(sha=hashlib.sha256(cls.zip).hexdigest())

        def fetch(url, *a):
            return json.dumps(cls.rel).encode() if "api.github.com" in url else cls.zip
        cls.srv = make_server(directory=os.path.join(cls.base, "daten"))
        cls.srv.app.selfupd_fetch = fetch
        cls.srv.app.selfupd_root = cls.root
        cls._env = mock.patch.dict(os.environ, {"CLAUDIA_NO_RESTART": "1"})
        cls._env.start()
        os.environ.pop("CLAUDIA_OFFLINE", None)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.sid = cls.srv.new_session()

    @classmethod
    def tearDownClass(cls):
        cls._env.stop()
        cls.srv.shutdown()
        shutil.rmtree(cls.base, True)

    def call(self, path, data=None):
        req = urllib.request.Request(self.srv.url.rstrip("/") + path, data=json.dumps(data).encode() if data is not None else None,
                                     headers={"Content-Type": "application/json", "X-Claudia": "1", "Cookie": "claudia=" + self.sid}, method="POST" if data is not None else "GET")
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            return dict(json.loads(e.read().decode()), _status=e.code)

    def test_flow_check_skip_install_restart(self):
        st = self.call("/api/app-update")
        self.assertFalse(st["checked"])
        st = self.call("/api/app-update-check", {})
        self.assertTrue(st["checked"] and st["ok"] and st["newer"] and st["installable"])
        self.assertEqual(st["info"]["version"], "9.9.0")
        self.assertFalse(st["skipped"])
        self.assertTrue(self.call("/api/app-update-skip", {"version": "9.9.0"})["skipped"])
        self.assertEqual(self.call("/api/app-update-skip", {"version": "x"}).get("_status"), 400)
        self.assertEqual(self.call("/api/app-update-restart", {}).get("_status"), 409)         # noch kein fertiges Update
        self.assertEqual(self.call("/api/app-update-install", {"version": "1.2.3"}).get("_status"), 409)
        self.call("/api/app-update-install", {"version": "9.9.0"})
        for _ in range(100):
            st = self.call("/api/app-update")
            if st["install"]["done"] or st["install"]["error"]:
                break
            time.sleep(0.1)
        self.assertTrue(st["install"]["done"], st["install"])
        with open(os.path.join(self.root, "claudia", "__init__.py")) as fh:
            self.assertIn("9.9.0", fh.read())
        res = self.call("/api/app-update-restart", {})
        self.assertTrue(res["ok"])
        self.assertFalse(res["started"])                                                      # in Tests wird nichts gestartet


if __name__ == "__main__":
    unittest.main()
