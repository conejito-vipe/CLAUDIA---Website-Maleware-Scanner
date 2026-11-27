"""Sicherheits-Erweiterung installieren: Angebot, Store-Angaben (Bild/Text/Link), Prüfungen und Ablauf mit Attrappen."""
import base64
import json
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))
os.environ.setdefault("CLAUDIA_OFFLINE", "1")

import wpfixture  # noqa: E402
from claudia import actions, store  # noqa: E402
from claudia.runner import LocalRunner  # noqa: E402

CHOICES = [{"name": "php8.3", "version": "8.3.6", "default": True}]
INFO = {"cms": "wordpress", "wordpress": "6.8.3", "php": "", "php_candidates": [{"name": "php8.3", "version": "PHP 8.3.6"}]}
MISSING = [{"id": "security_ext", "title": "x", "status": "info", "findings": [
    {"sev": "info", "title": "Kein Sicherheits-Plugin (Firewall/Scanner) gefunden", "items": []}]}]
PRESENT = [{"id": "security_ext", "title": "x", "status": "ok", "findings": [
    {"sev": "ok", "title": "Sicherheits-Erweiterung vorhanden: Wordfence Security (eingeschaltet)", "items": []}]}]
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 40


def script(path, body):
    with open(path, "w") as fh:
        fh.write("#!/bin/sh\n" + body + "\n")
    os.chmod(path, 0o755)


def world(active=True, install_ok=True, with_cli=True):
    w = wpfixture.make_wp_world(tempfile.mkdtemp(prefix="wp_sec_"), False)
    b = w["bin"]
    script(os.path.join(b, "mysqldump"), 'cat >/dev/null; for i in $(seq 1 3000); do echo "INSERT INTO x VALUES ($i,\'$RANDOM$RANDOM$RANDOM$RANDOM\');"; done')
    script(os.path.join(b, "php8.3"), r'''
if [ "$1" = "-v" ]; then echo "PHP 8.3.6 (cli)"; exit 0; fi
echo "php $*" >> "$HOME/php_calls.txt"
case "$*" in
  *"core version"*) echo "6.8.3";;
  *"plugin install"*) %s;;
  *"plugin is-active"*) %s;;
  *"verify-checksums"*) echo "Success: Verified 1 of 1 plugins.";;
  *) echo ok;;
esac''' % (('echo "Success: Plugin installed successfully."' if install_ok else 'echo "Error: Download failed."; exit 1'), ("exit 0" if active else "exit 1")))
    if with_cli:
        open(os.path.join(w["home"], "wp-cli.phar"), "w").write("<?php\n")
    return LocalRunner(w["home"], extra_path=b), w


class Offer(unittest.TestCase):
    def test_offered_only_when_missing_and_wordpress_lists_installable(self):
        av = {a["id"]: a for a in actions.available(MISSING, INFO, "8.3", {}, {"wpcli": "/h/wp-cli.phar"})}
        a = av["install_security"]
        ids = [t["id"] for t in a["params"]["tools"]]
        self.assertIn("wordfence", ids)
        self.assertNotIn("cerber", ids)                                     # Hintergrund-Helfer gehören nicht zur Auswahl
        self.assertTrue(all(t["installable"] for t in a["params"]["tools"]))
        self.assertTrue(all(t["store_url"].startswith("https://wordpress.org/plugins/") for t in a["params"]["tools"]))
        self.assertEqual(a["reason"], "")
        self.assertNotIn("install_security", [x["id"] for x in actions.available(PRESENT, INFO, "8.3", {}, {"wpcli": "/h/wp-cli.phar"})])

    def test_without_wpcli_only_links(self):
        a = {x["id"]: x for x in actions.available(MISSING, INFO, "8.3", {}, {})}["install_security"]
        self.assertFalse(any(t["installable"] for t in a["params"]["tools"]))
        self.assertIn("WP-CLI", a["reason"])

    def test_joomla_installable_only_with_verified_update_server(self):
        info = {"cms": "joomla", "joomla": "5.2.0", "php_candidates": INFO["php_candidates"]}
        a = {x["id"]: x for x in actions.available(MISSING, info, "8.3", {}, {})}["install_security"]
        self.assertTrue(a["params"]["tools"])
        self.assertEqual(sorted(t["id"] for t in a["params"]["tools"] if t["installable"]), ["admintools", "htprotect", "securitycheck"])   # nur kostenlos und mit geprüftem Update-Server
        self.assertTrue(all(t["store_url"].startswith("https://extensions.joomla.org/") for t in a["params"]["tools"]))
        self.assertTrue(all(t["howto"] for t in a["params"]["tools"] if not t["installable"]))

    def test_paid_joomla_tool_is_never_installable_even_with_manifest(self):
        data = {"stand": "2026-11-02", "joomla": [{"id": "x", "name": "X", "price": "kostenpflichtig", "text": "t", "jed": "https://extensions.joomla.org/x/",
                            "install": {"manifest": "https://example.org/x.xml", "element": "com_x"}}], "wordpress": []}
        from unittest import mock
        with mock.patch("claudia.checks.security_ext.load_tools", return_value=data):
            self.assertFalse(actions.security_choices("joomla")[0]["installable"])
            with self.assertRaises(actions.ActionError):
                actions._security_target({"cms": "joomla", "tool": "x"})
            data["joomla"][0]["price"] = "kostenlos"
            self.assertTrue(actions.security_choices("joomla")[0]["installable"])
            self.assertEqual(actions._security_target({"cms": "joomla", "tool": "x"})["element"], "com_x")


class Target(unittest.TestCase):
    def test_unknown_or_hostile_tool_is_refused(self):
        for bad in ("", "nope", "wordfence; rm -rf ~", "cerber", "../x"):
            with self.assertRaises(actions.ActionError, msg=bad):
                actions._security_target({"cms": "wordpress", "tool": bad})
        self.assertEqual(actions._security_target({"cms": "wordpress", "tool": "wordfence"})["slug"], "wordfence")

    def test_preview(self):
        cmds = "\n".join(actions.commands_preview("install_security", {"cms": "wordpress", "tool": "sucuri", "wpcli": "/h/wp-cli.phar", "php": "php8.3"}, CHOICES))
        self.assertIn("plugin install sucuri-scanner --activate", cmds)
        self.assertIn("Sicherung", cmds)
        with self.assertRaises(actions.ActionError):
            actions.commands_preview("install_security", {"cms": "wordpress", "tool": "?", "wpcli": "x", "php": "php8.3"}, CHOICES)


class Run(unittest.TestCase):
    P = {"cms": "wordpress", "tool": "wordfence", "php": "php8.3"}

    def test_install_and_activate(self):
        r, w = world()
        res = actions.run_action(r, w["site_rel"], "install_security", dict(self.P, wpcli=os.path.join(w["home"], "wp-cli.phar")), CHOICES)
        self.assertTrue(res["ok"], res)
        self.assertTrue(os.path.isdir(res["backup_dir"]))                                   # erst Sicherung
        calls = open(os.path.join(w["home"], "php_calls.txt")).read()
        self.assertIn("plugin install wordfence --activate", calls)
        self.assertIn("plugin verify-checksums wordfence", calls)

    def test_not_active_is_reported(self):
        r, w = world(active=False)
        res = actions.run_action(r, w["site_rel"], "install_security", dict(self.P, wpcli=os.path.join(w["home"], "wp-cli.phar")), CHOICES)
        self.assertFalse(res["ok"])
        self.assertIn("nicht eingeschaltet", res["error"])

    def test_failed_install_is_reported(self):
        r, w = world(install_ok=False)
        res = actions.run_action(r, w["site_rel"], "install_security", dict(self.P, wpcli=os.path.join(w["home"], "wp-cli.phar")), CHOICES)
        self.assertFalse(res["ok"])
        self.assertIn("fehlgeschlagen", res["error"])

    def test_unknown_tool_changes_nothing(self):
        r, w = world()
        res = actions.run_action(r, w["site_rel"], "install_security", dict(self.P, tool="evil", wpcli=os.path.join(w["home"], "wp-cli.phar")), CHOICES)
        self.assertFalse(res["ok"])
        self.assertEqual(res["backup_dir"], "")
        self.assertFalse(os.path.exists(os.path.join(w["home"], "php_calls.txt")))

    def test_odd_wpcli_path_changes_nothing(self):
        r, w = world()
        res = actions.run_action(r, w["site_rel"], "install_security", dict(self.P, wpcli="/x; rm -rf ~"), CHOICES)
        self.assertFalse(res["ok"])
        self.assertEqual(res["backup_dir"], "")


class Manifest(unittest.TestCase):
    XML = """<updates>
<update><version>1.2.0</version><downloads><downloadurl type="full" format="zip">https://example.org/x-1.2.0.zip</downloadurl></downloads></update>
<update><version>1.10.1</version><downloads><downloadurl type="full" format="zip">https://example.org/x-1.10.1.zip</downloadurl></downloads></update>
<update><version>2.0.0</version><downloads><downloadurl type="full" format="zip">http://example.org/insecure.zip</downloadurl></downloads></update>
</updates>"""

    def test_newest_with_https(self):
        self.assertEqual(actions.newest_download(self.XML), {"version": "1.10.1", "url": "https://example.org/x-1.10.1.zip", "sha256": "", "sha512": ""})

    def test_refuses_doctype_and_garbage(self):
        self.assertEqual(actions.newest_download('<!DOCTYPE x [<!ENTITY a "b">]><updates/>'), {})
        self.assertEqual(actions.newest_download("not xml"), {})


class Store(unittest.TestCase):
    def test_sniff_accepts_only_real_images(self):
        self.assertEqual(store.sniff(PNG), "image/png")
        self.assertEqual(store.sniff(b"\xff\xd8\xff\xe0abc"), "image/jpeg")
        self.assertEqual(store.sniff(b"GIF89a....."), "image/gif")
        self.assertEqual(store.sniff(b"RIFF\x00\x00\x00\x00WEBPVP8 "), "image/webp")
        self.assertEqual(store.sniff(b"<svg xmlns='http://www.w3.org/2000/svg' onload='alert(1)'/>"), "")
        self.assertEqual(store.sniff(b"<html>"), "")
        self.assertEqual(store.data_uri(b"<svg/>"), "")
        self.assertEqual(store.data_uri(PNG + b"\x00" * store.MAX_IMAGE), "")           # zu groß
        self.assertTrue(store.data_uri(PNG).startswith("data:image/png;base64,"))
        self.assertEqual(base64.b64decode(store.data_uri(PNG).split(",", 1)[1]), PNG)

    def test_image_hosts(self):
        ok = store.image_ok
        self.assertTrue(ok("https://ps.w.org/wordfence/assets/icon-256x256.png"))
        self.assertFalse(ok("http://ps.w.org/x.png"))
        self.assertFalse(ok("https://evil.example/x.png"))
        self.assertFalse(ok("https://ps.w.org.evil.example/x.png"))
        self.assertFalse(ok("https://user@ps.w.org/x.png"))
        self.assertFalse(ok("https://ps.w.org:8443/x.png"))
        self.assertFalse(ok("https://ps.w.org/x y.png"))

    def test_parse_wp(self):
        d = {"short_description": "Schutz &amp; <b>Firewall</b>", "icons": {"svg": "https://ps.w.org/a/icon.svg", "2x": "https://evil.example/i.png", "1x": "https://ps.w.org/a/icon-128.png"}}
        got = store.parse_wp(json.dumps(d))
        self.assertEqual(got["short"], "Schutz & Firewall")
        self.assertEqual(got["image_url"], "https://ps.w.org/a/icon-128.png")           # fremder Host und SVG werden übersprungen
        self.assertEqual(store.parse_wp("kaputt"), {})

    def test_parse_jed(self):
        page = '<head><meta property="og:description" content="Firewall &amp; Scanner"><meta property="og:image" content="/cache/x/logo.png"></head>'
        got = store.parse_jed(page, "https://extensions.joomla.org/extension/a/b/")
        self.assertEqual(got["short"], "Firewall & Scanner")
        self.assertEqual(got["image_url"], "https://extensions.joomla.org/cache/x/logo.png")
        self.assertNotIn("image_url", store.parse_jed('<meta property="og:image" content="https://evil.example/a.png">', "https://extensions.joomla.org/"))

    def test_lookup_live_with_fakes(self):
        from unittest import mock
        from claudia.checks import web as webmod
        store.clear_cache()
        api = webmod.Fetched()
        api.status, api.body = 200, json.dumps({"short_description": "Kurz", "icons": {"1x": "https://ps.w.org/w/icon.png"}})
        img = webmod.Fetched()
        img.status, img.raw, img.final = 200, PNG, "https://ps.w.org/w/icon.png"
        calls = []

        def fake(url, ua, referer="", max_bytes=0, timeout=0, binary=False):
            calls.append(url)
            return img if binary else api
        tool = {"id": "wordfence", "name": "Wordfence", "slug": "wordfence", "text": "Eigener Text"}
        with mock.patch.object(webmod, "fetch", fake):
            res = store.lookup(tool, "wordpress", offline=False)
            again = store.lookup(tool, "wordpress", offline=False)
        self.assertTrue(res["live"])
        self.assertEqual(res["short"], "Kurz")
        self.assertTrue(res["image"].startswith("data:image/png"))
        self.assertEqual(res["store_url"], "https://wordpress.org/plugins/wordfence/")
        self.assertEqual(len(calls), 2)                                                  # beim zweiten Mal aus dem Zwischenspeicher
        self.assertEqual(again["short"], "Kurz")
        store.clear_cache()

    def test_lookup_offline_falls_back(self):
        store.clear_cache()
        res = store.lookup({"id": "a", "name": "A", "slug": "a", "text": "Eigener Text"}, "wordpress", offline=True)
        self.assertFalse(res["live"])
        self.assertEqual((res["short"], res["image"]), ("Eigener Text", ""))

    def test_hostile_image_bytes_are_dropped(self):
        from unittest import mock
        from claudia.checks import web as webmod
        store.clear_cache()
        api = webmod.Fetched()
        api.status, api.body = 200, json.dumps({"short_description": "K", "icons": {"1x": "https://ps.w.org/w/icon.png"}})
        img = webmod.Fetched()
        img.status, img.raw, img.final = 200, b"<svg onload=alert(1)>", "https://ps.w.org/w/icon.png"
        with mock.patch.object(webmod, "fetch", lambda url, *a, **k: img if k.get("binary") else api):
            res = store.lookup({"id": "w2", "name": "W", "slug": "w", "text": "t"}, "wordpress", offline=False)
        self.assertEqual(res["image"], "")
        store.clear_cache()


if __name__ == "__main__":
    unittest.main()
