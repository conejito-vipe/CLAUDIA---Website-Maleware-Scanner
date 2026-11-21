"""Profile der unterstützten Systeme (Joomla, WordPress): Ordner, Dateinamen und Bezeichnungen.

Die Prüfungen sind für beide Systeme gleich aufgebaut. Dieses Profil sagt ihnen, wo bei welchem System was liegt.
"""
from __future__ import annotations

import re
from typing import Any, Dict

JOOMLA: Dict[str, Any] = {
    "id": "joomla", "name": "Joomla",
    "config_file": "configuration.php",
    "upload_dirs": "images media tmp files",
    "cache_dirs": "cache administrator/cache logs administrator/logs",
    "prune_find": "-path ./node_modules -o -path ./cache -o -path '*/vendor' -o -path ./administrator/cache",
    "recent_skip": "-not -path './cache/*' -not -path './administrator/cache/*' -not -path './tmp/*' -not -path './logs/*' -not -path './administrator/logs/*' -not -path './node_modules/*'",
    "lib_exclude": r"^\./(libraries/|.*/vendor/|cache/|administrator/cache/|language/|administrator/language/)",
    "lib_exclude2": r"^\./(libraries/|.*/vendor/)",
    "ext_root_re": r"^(\./plugins/[^/]+/[^/]+|\./(?:administrator/)?(?:components|modules|templates)/[^/]+)(?:/|$)",
    "manifest_find": "find plugins administrator/components components modules templates administrator/modules administrator/templates -maxdepth 3 -name '*.xml' -type f -printf 'MF\\t%T@\\t%h\\n' 2>/dev/null | head -5000",
    "code_dir_re": r"^\./(administrator/)?(components|modules|plugins|templates|layouts|libraries|language)/|^\./(layouts|libraries|api|includes|cli)/",
    "root_ok": ("./index.php", "./configuration.php", "./.htaccess", "./.user.ini", "./administrator/index.php", "./api/index.php"),
    "ext_dir_re": r"^\./(libraries|administrator/components|components|plugins|modules|templates|administrator/modules|administrator/templates|media|language|administrator/language|includes|administrator/includes|api|cli|layouts|administrator/manifests)/",
    "installer_sql_re": r"^\./(administrator/)?(components|modules|plugins|templates)/.+/sql/.*\.sql$|^\./installation/.*\.sql$",
    "core_dirs": {"administrator", "api", "cache", "cli", "components", "images", "includes", "language", "layouts",
                  "libraries", "media", "modules", "plugins", "templates", "tmp", ".well-known"},
    "core_files": {"index.php", "configuration.php", "htaccess.txt", "license.txt", "readme.txt", "robots.txt.dist",
                   "robots.txt", "web.config.txt", ".htaccess", ".user.ini", "favicon.ico", "php.ini"},
    "ext_word": "Erweiterung", "ext_words": "Erweiterungen",
    "upload_word": "images, media, files, tmp",
    "admin_url": "/administrator/",
}

WORDPRESS: Dict[str, Any] = {
    "id": "wordpress", "name": "WordPress",
    "config_file": "wp-config.php",
    "upload_dirs": "wp-content/uploads wp-content/upgrade wp-content/backup-db wp-content/ai1wm-backups wp-content/backups",
    "cache_dirs": "wp-content/cache wp-content/upgrade wp-content/wflogs",
    "prune_find": "-path ./node_modules -o -path ./wp-content/cache -o -path '*/vendor'",
    "recent_skip": "-not -path './wp-content/cache/*' -not -path './wp-content/upgrade/*' -not -path './wp-content/wflogs/*' -not -path './node_modules/*'",
    "lib_exclude": r"^\./(wp-includes/|wp-admin/|.*/vendor/|wp-content/cache/|wp-content/languages/)",
    "lib_exclude2": r"^\./(wp-includes/|wp-admin/|.*/vendor/)",
    "ext_root_re": r"^(\./wp-content/(?:plugins|themes|mu-plugins)/[^/]+)(?:/|$)",
    "manifest_find": "find wp-content/plugins wp-content/themes -maxdepth 2 \\( -name readme.txt -o -name style.css \\) -type f -printf 'MF\\t%T@\\t%h\\n' 2>/dev/null | head -5000",
    "code_dir_re": r"^\./wp-content/(plugins|themes|mu-plugins)/|^\./(wp-includes|wp-admin)/",
    "root_ok": ("./index.php", "./wp-config.php", "./.htaccess", "./.user.ini", "./wp-load.php", "./wp-blog-header.php",
                "./wp-settings.php", "./wp-login.php", "./wp-cron.php", "./wp-activate.php", "./wp-signup.php", "./wp-mail.php",
                "./wp-comments-post.php", "./wp-links-opml.php", "./wp-trackback.php", "./xmlrpc.php"),
    "ext_dir_re": r"^\./(wp-content/(plugins|themes|mu-plugins|languages)|wp-includes|wp-admin)/",
    "installer_sql_re": r"^\./wp-content/(plugins|themes)/.+/(sql|schema|install)[^/]*\.sql$",
    "core_dirs": {"wp-admin", "wp-content", "wp-includes", ".well-known", "cgi-bin"},
    "core_files": {"index.php", "wp-config.php", "wp-config-sample.php", "wp-activate.php", "wp-blog-header.php",
                   "wp-comments-post.php", "wp-cron.php", "wp-links-opml.php", "wp-load.php", "wp-login.php", "wp-mail.php",
                   "wp-settings.php", "wp-signup.php", "wp-trackback.php", "xmlrpc.php", "license.txt", "readme.html",
                   "robots.txt", ".htaccess", ".user.ini", "favicon.ico", "php.ini", "sitemap.xml"},
    "ext_word": "Plugin", "ext_words": "Plugins und Themes",
    "upload_word": "wp-content/uploads, upgrade, cache",
    "admin_url": "/wp-admin/",
}

# ---- Weitere Angaben je System (früher als Weichen "wenn WordPress ... sonst Joomla" im Code verstreut)
JOOMLA.update({
    "version_key": "joomla",                                   # Schlüssel der erkannten Version in info/shared
    "admin_word": "Backend",
    "enable_hint": "Im Backend unter System -> Verwalten -> Plugins (bzw. Komponenten) einschalten.",
    "sec_base": "administrator/components components plugins administrator/modules", "sec_depth": 2,
    "no_sec_title": "Keine Sicherheits-Erweiterung (Firewall/Scanner) gefunden", "install_hint": "Eine der folgenden Erweiterungen installieren",
    "outside_dir": "images/files",                             # üblicher Ablageort von Dateien (für Hinweise)
    "spool": "tmp cache administrator/cache logs",
    "root_find": "-name index.php -o -name htaccess.txt -o -name LICENSE.txt -o -name README.txt -o -name web.config.txt",
    "need_mods": ["zlib", "json", "mbstring", "xml"], "zip_note": "",
    "root_text": "Joomla legt hier nur index.php und configuration.php ab. ",
    "store": "jed", "update_cli": True, "vel": True,
})
WORDPRESS.update({
    "version_key": "wordpress",
    "admin_word": "Dashboard",
    "enable_hint": "Im Dashboard unter Plugins einschalten.",
    "sec_base": "wp-content/plugins wp-content/mu-plugins", "sec_depth": 1,
    "no_sec_title": "Kein Sicherheits-Plugin (Firewall/Scanner) gefunden", "install_hint": "Eines der folgenden Plugins installieren",
    "outside_dir": "wp-content/uploads",
    "spool": "wp-content/cache wp-content/uploads wp-content/upgrade",
    "root_find": "-name index.php -o -name wp-login.php -o -name wp-settings.php -o -name wp-load.php -o -name wp-blog-header.php",
    "need_mods": ["json", "mysqli"], "zip_note": "PHP-Modul 'zip' fehlt (WordPress nutzt dann eine langsamere Ersatzmethode; kein Fehler)",
    "root_text": "WordPress legt hier nur die bekannten wp-*.php-Dateien, index.php und die wp-config.php ab. ",
    "store": "wporg", "update_cli": False, "vel": False,                      # Updates kommen aus den Befunden, keine Joomla-Kommandozeile
})

# ---- Drupal (seit 2.8.0): Drupal 8 und neuer. Drupal 7 wird erkannt und als nicht mehr unterstützt gemeldet.
DRUPAL: Dict[str, Any] = {
    "id": "drupal", "name": "Drupal",
    "config_file": "sites/default/settings.php",
    "upload_dirs": "sites/default/files",
    "cache_dirs": "sites/default/files/css sites/default/files/js sites/default/files/php",
    "prune_find": "-path ./node_modules -o -path '*/vendor' -o -path ./sites/default/files/css -o -path ./sites/default/files/js",
    "recent_skip": "-not -path './sites/default/files/css/*' -not -path './sites/default/files/js/*' -not -path './sites/default/files/php/*' -not -path './node_modules/*'",
    "lib_exclude": r"^\./(core/|vendor/|.*/vendor/|sites/default/files/(css|js|php)/)",
    "lib_exclude2": r"^\./(core/|vendor/|.*/vendor/)",
    "ext_root_re": r"^(\./(?:modules|themes|profiles)/(?:(?:contrib|custom)/)?[^/]+)(?:/|$)",
    "manifest_find": "find modules themes profiles -maxdepth 4 -name '*.info.yml' -type f -printf 'MF\\t%T@\\t%h\\n' 2>/dev/null | head -5000",
    "code_dir_re": r"^\./(core|modules|themes|profiles)/",
    "root_ok": ("./index.php", "./autoload.php", "./update.php", "./.htaccess", "./.user.ini", "./cron.php", "./install.php", "./xmlrpc.php", "./authorize.php"),
    "ext_dir_re": r"^\./(core|modules|themes|profiles|vendor|libraries)/",
    "installer_sql_re": r"^\./(modules|themes|profiles)/.+/(sql|schema|install)[^/]*\.sql$|^\./core/.*\.sql$",
    "core_dirs": {"core", "modules", "profiles", "sites", "themes", "vendor", "libraries", ".well-known", "cgi-bin"},
    "core_files": {"index.php", "autoload.php", "update.php", "composer.json", "composer.lock", ".htaccess", ".csslintrc", ".editorconfig", ".eslintignore", ".eslintrc.json",
                   ".gitattributes", "INSTALL.txt", "LICENSE.txt", "README.md", "README.txt", "robots.txt", "web.config", "example.gitignore", ".user.ini", "php.ini",
                   "favicon.ico", "sitemap.xml", ".ht.router.php"},
    "ext_word": "Modul", "ext_words": "Module und Themes",
    "upload_word": "sites/default/files",
    "admin_url": "/user/login",
    "version_key": "drupal",
    "admin_word": "Verwaltungsbereich",
    "enable_hint": "Im Verwaltungsbereich unter Erweitern einschalten.",
    "sec_base": "modules", "sec_depth": 2,
    "no_sec_title": "Kein Sicherheits-Modul gefunden", "install_hint": "Ein Sicherheits-Modul installieren",
    "outside_dir": "sites/default/files",
    "spool": "sites/default/files/css sites/default/files/js sites/default/files/php",
    "root_find": "-name index.php -o -name autoload.php -o -name update.php",
    "need_mods": ["json", "xml", "mbstring", "pdo"], "zip_note": "",
    "root_text": "Drupal legt hier nur index.php, autoload.php, update.php und die Einstellungen ab. ",
    "store": "none", "update_cli": False, "vel": False,
    # Von den gemeinsamen Prüfungen laufen bei Drupal nur die, die nichts Joomla- oder WordPress-Spezifisches lesen (Ordner, Server, Web, Datenbank allgemein).
    "common_checks": {"root_files", "perms", "node_modules", "js_scan", "php_in_uploads", "webshells", "suspicious_names", "recent_changes", "backups_in_webroot", "php_ini", "web_source",
                      "web_headers", "web_csp", "access_logs", "local_logs", "php_settings", "safe_browsing", "malware_patterns", "hidden_structure", "crontab", "authorized_keys",
                      "processes", "shell_startup", "skimmer_scan", "mail_dns", "dns_changes", "plaintext_creds", "backup_age", "tls_protocols", "cookie_flags", "js_libs", "db_access"},
}

# ---- TYPO3 (seit 2.10.0): klassische Installation (typo3, typo3conf) und Composer-Installation (config, vendor, public). Maßgeblich ist TYPO3 11 und neuer.
TYPO3: Dict[str, Any] = {
    "id": "typo3", "name": "TYPO3",
    "config_file": "config/system/settings.php",           # klassisch: typo3conf/system/settings.php, vor TYPO3 12: typo3conf/LocalConfiguration.php
    "upload_dirs": "fileadmin public/fileadmin uploads public/uploads typo3temp/assets public/typo3temp/assets",
    "cache_dirs": "typo3temp/var typo3temp/assets var/cache var/log public/typo3temp/var public/typo3temp/assets",
    "prune_find": "-path ./node_modules -o -path '*/vendor' -o -path ./var/cache -o -path ./typo3temp/var/cache -o -path ./public/typo3temp/var/cache",
    "recent_skip": "-not -path './var/cache/*' -not -path './var/log/*' -not -path './typo3temp/var/*' -not -path './public/typo3temp/var/*' -not -path './typo3temp/assets/*' -not -path './public/typo3temp/assets/*' -not -path './node_modules/*'",
    "lib_exclude": r"^\./(typo3/|typo3_src[^/]*/|vendor/|.*/vendor/|var/|typo3temp/|public/typo3temp/)",
    "lib_exclude2": r"^\./(typo3/|typo3_src[^/]*/|vendor/|.*/vendor/)",
    "ext_root_re": r"^(\./(?:typo3conf/ext|public/typo3conf/ext|packages)/[^/]+)(?:/|$)",
    "manifest_find": "find typo3conf/ext public/typo3conf/ext packages -maxdepth 2 -name ext_emconf.php -type f -printf 'MF\\t%T@\\t%h\\n' 2>/dev/null | head -5000",
    "code_dir_re": r"^\./(typo3|typo3conf|typo3_src[^/]*|packages|config|public/typo3conf)/",
    "root_ok": ("./index.php", "./typo3/index.php", "./typo3/install.php", "./public/index.php", "./.htaccess", "./.user.ini", "./_.htaccess"),
    "ext_dir_re": r"^\./(typo3|typo3_src[^/]*|typo3conf|public/typo3conf|vendor|config|packages|public/_assets|_assets)/",
    "installer_sql_re": r"^\./(typo3conf/ext|packages|typo3/sysext)/.+/ext_tables\.sql$|^\./(typo3conf/ext|packages)/.+/(sql|schema|install)[^/]*\.sql$",
    "core_dirs": {"typo3", "typo3conf", "typo3temp", "typo3_src", "fileadmin", "uploads", "public", "config", "var", "vendor", "packages", "_assets", ".well-known", "cgi-bin"},
    "core_dir_re": r"^typo3_src-\d+\.\d+\.\d+$",
    "core_files": {"index.php", "typo3", "typo3_src", ".htaccess", "_.htaccess", "robots.txt", "favicon.ico", "sitemap.xml", "composer.json", "composer.lock", "README.md", "LICENSE", "LICENSE.txt",
                   ".gitignore", ".user.ini", "php.ini", "FIRST_INSTALL"},
    "ext_word": "Erweiterung", "ext_words": "Erweiterungen",
    "upload_word": "fileadmin, uploads, typo3temp",
    "admin_url": "/typo3/",
    "version_key": "typo3",
    "admin_word": "Backend",
    "enable_hint": "Im Backend unter Verwaltung > Erweiterungen einschalten.",
    "sec_base": "typo3conf/ext packages", "sec_depth": 1,
    "no_sec_title": "Keine Sicherheits-Erweiterung gefunden", "install_hint": "Eine Sicherheits-Erweiterung installieren",
    "outside_dir": "fileadmin",
    "spool": "typo3temp var",
    "root_find": "-name index.php -o -name composer.json",
    "need_mods": ["json", "xml", "mbstring", "pdo"], "zip_note": "",
    "root_text": "TYPO3 legt hier nur index.php, die Ordner typo3, typo3conf, typo3temp, fileadmin und (bei Composer) config, public, var, vendor ab. ",
    "store": "none", "update_cli": False, "vel": False,
    "common_checks": DRUPAL["common_checks"],
}

# ---- Contao (seit 2.11.0): Composer-Installation ab Contao 4.13 (Ordner config, vendor, public, files, templates, var, contao).
CONTAO: Dict[str, Any] = {
    "id": "contao", "name": "Contao",
    "config_file": ".env",                                 # dazu config/parameters.yaml, config/config.yaml und (ältere Versionen) system/config/localconfig.php
    "upload_dirs": "files public/files assets public/assets",
    "cache_dirs": "var/cache var/logs var/log public/assets public/share",
    "prune_find": "-path ./node_modules -o -path '*/vendor' -o -path ./var/cache",
    "recent_skip": "-not -path './var/cache/*' -not -path './var/logs/*' -not -path './var/log/*' -not -path './public/assets/*' -not -path './assets/*' -not -path './node_modules/*'",
    "lib_exclude": r"^\./(vendor/|.*/vendor/|var/|public/assets/|assets/)",
    "lib_exclude2": r"^\./(vendor/|.*/vendor/)",
    "ext_root_re": r"^(\./(?:vendor/[^/]+|contao|system/modules)/[^/]+)(?:/|$)",
    "manifest_find": "find vendor/contao system/modules -maxdepth 2 -name composer.json -type f -printf 'MF\\t%T@\\t%h\\n' 2>/dev/null | head -5000",
    "code_dir_re": r"^\./(contao|config|src|templates|system/modules|public/bundles)/",
    "root_ok": ("./index.php", "./public/index.php", "./.htaccess", "./.user.ini", "./_.htaccess", "./console", "./bin/console"),
    "ext_dir_re": r"^\./(vendor|config|src|contao|system/modules|public/bundles|public/assets|assets|templates)/",
    "installer_sql_re": r"^\./(vendor|contao|system/modules)/.+\.sql$",
    "core_dirs": {"contao", "config", "vendor", "public", "files", "assets", "templates", "var", "system", "src", "bin", "web", "app", ".well-known", "cgi-bin"},
    "core_dir_re": r"^$",
    "core_files": {"index.php", ".htaccess", "_.htaccess", "robots.txt", "favicon.ico", "sitemap.xml", "composer.json", "composer.lock", "README.md", "LICENSE", "LICENSE.txt",
                   ".gitignore", ".user.ini", "php.ini", ".env", ".env.local", "symfony.lock", "console", "contao-manager.phar.php"},
    "ext_word": "Erweiterung", "ext_words": "Erweiterungen",
    "upload_word": "files, assets",
    "admin_url": "/contao",
    "version_key": "contao",
    "admin_word": "Backend",
    "enable_hint": "Im Contao Manager oder mit composer require installieren und aktivieren.",
    "sec_base": "vendor/contao", "sec_depth": 1,
    "no_sec_title": "Keine Sicherheits-Erweiterung gefunden", "install_hint": "Eine Sicherheits-Erweiterung installieren",
    "outside_dir": "files",
    "spool": "var",
    "root_find": "-name index.php -o -name composer.json",
    "need_mods": ["json", "xml", "mbstring", "pdo", "intl"], "zip_note": "",
    "root_text": "Contao legt hier nur index.php, die Ordner config, contao, files, public, templates, var und vendor ab. ",
    "store": "none", "update_cli": False, "vel": False,
    "common_checks": DRUPAL["common_checks"],
}

# ---- PrestaShop (seit 2.12.0): 1.7, 8, 9 (Symfony, app/config/parameters.php) und 1.6 (config/settings.inc.php).
PRESTASHOP: Dict[str, Any] = {
    "id": "prestashop", "name": "PrestaShop",
    "config_file": "app/config/parameters.php",
    "upload_dirs": "img upload download modules",
    "cache_dirs": "var/cache var/logs cache",
    "prune_find": "-path ./node_modules -o -path ./var/cache -o -path ./cache",
    "recent_skip": "-not -path './var/cache/*' -not -path './var/logs/*' -not -path './cache/*' -not -path './node_modules/*' -not -path './img/*'",
    "lib_exclude": r"^\./(vendor/|.*/vendor/|var/|cache/|img/)",
    "lib_exclude2": r"^\./(vendor/|.*/vendor/)",
    "ext_root_re": r"^(\./(?:modules|themes|override)/[^/]+)(?:/|$)",
    "manifest_find": "find modules -maxdepth 2 -name config.xml -type f -printf 'MF\\t%T@\\t%h\\n' 2>/dev/null | head -5000",
    "code_dir_re": r"^\./(classes|controllers|src|override|modules|themes|app|config)/",
    "root_ok": ("./index.php", "./.htaccess", "./robots.txt", "./_.htaccess", "./.user.ini"),
    "ext_dir_re": r"^\./(modules|themes|override|vendor)/",
    "installer_sql_re": r"^\./(modules|install|install-dev)/.+\.sql$",
    "core_dirs": {"app", "bin", "cache", "classes", "config", "controllers", "docs", "download", "img", "js", "localization", "mails", "modules", "override", "pdf", "src", "themes",
                  "tools", "translations", "upload", "var", "vendor", "webservice", "admin", "admin-dev", "install", "install-dev", "web", "css", "Adapter", "Core", ".well-known", "cgi-bin"},
    "core_dir_re": r"^admin[0-9A-Za-z_\-]*$",
    "core_files": {"index.php", ".htaccess", "robots.txt", "favicon.ico", "composer.json", "composer.lock", "README.md", "LICENSE.md", "INSTALL.txt", "Install_PrestaShop.html",
                   ".gitignore", ".user.ini", "php.ini", "init.php", "error500.html", "maintenance.html", "sitemap.xml", "_.htaccess", "docker_updt_ps_domains.php", "ps_shop_domains.php", "CHANGELOG.txt"},
    "ext_word": "Modul", "ext_words": "Module",
    "upload_word": "img, upload, download",
    "admin_url": "/admin",
    "version_key": "prestashop",
    "admin_word": "Verwaltung",
    "enable_hint": "Im Verwaltungsbereich unter Module installieren und aktivieren.",
    "sec_base": "modules", "sec_depth": 1,
    "no_sec_title": "Kein Sicherheits-Modul gefunden", "install_hint": "Ein Sicherheits-Modul installieren",
    "outside_dir": "upload",
    "spool": "var",
    "root_find": "-name index.php -o -name composer.json",
    "need_mods": ["json", "xml", "mbstring", "pdo", "gd", "intl"], "zip_note": "",
    "root_text": "PrestaShop legt hier nur index.php, die Ordner app, classes, config, controllers, img, modules, override, src, themes, var, vendor und den Verwaltungsordner ab. ",
    "store": "none", "update_cli": False, "vel": False,
    "common_checks": DRUPAL["common_checks"],
}

# ---- Shopware 6 (seit 2.13.0): Composer-Installation ab 6.5 (Ordner config, custom, files, public, src, var, vendor).
SHOPWARE: Dict[str, Any] = {
    "id": "shopware", "name": "Shopware",
    "config_file": ".env",
    "upload_dirs": "public/media public/thumbnail public/sitemap files custom/plugins",
    "cache_dirs": "var/cache var/log public/theme public/bundles",
    "prune_find": "-path ./node_modules -o -path '*/vendor' -o -path ./var/cache",
    "recent_skip": "-not -path './var/cache/*' -not -path './var/log/*' -not -path './public/theme/*' -not -path './public/bundles/*' -not -path './public/thumbnail/*' -not -path './public/media/*' -not -path './node_modules/*'",
    "lib_exclude": r"^\./(vendor/|.*/vendor/|var/|public/theme/|public/bundles/|public/thumbnail/)",
    "lib_exclude2": r"^\./(vendor/|.*/vendor/)",
    "ext_root_re": r"^(\./(?:custom/plugins|custom/apps|vendor/shopware)/[^/]+)(?:/|$)",
    "manifest_find": "find custom/plugins custom/apps -maxdepth 2 \\( -name composer.json -o -name manifest.xml \\) -type f -printf 'MF\\t%T@\\t%h\\n' 2>/dev/null | head -5000",
    "code_dir_re": r"^\./(config|custom|src|templates|public/bundles|migration)/",
    "root_ok": ("./index.php", "./public/index.php", "./.htaccess", "./.user.ini", "./_.htaccess", "./bin/console"),
    "ext_dir_re": r"^\./(vendor|config|custom|src|public/bundles|public/theme|templates)/",
    "installer_sql_re": r"^\./(vendor|custom)/.+\.sql$",
    "core_dirs": {"bin", "config", "custom", "files", "public", "src", "templates", "var", "vendor", "migration", "docs", "tests", ".well-known", "cgi-bin", "app", "web"},
    "core_dir_re": r"^$",
    "core_files": {"index.php", ".htaccess", "_.htaccess", "robots.txt", "favicon.ico", "sitemap.xml", "composer.json", "composer.lock", "README.md", "LICENSE", "LICENSE.txt", "symfony.lock",
                   ".gitignore", ".user.ini", "php.ini", ".env", ".env.local", ".env.dist", "docker-compose.yml", "phpunit.xml.dist", "shopware-installer.phar.php"},
    "ext_word": "Plugin", "ext_words": "Plugins",
    "upload_word": "public/media, public/thumbnail",
    "admin_url": "/admin",
    "version_key": "shopware",
    "admin_word": "Verwaltung",
    "enable_hint": "In der Verwaltung unter Erweiterungen > Meine Erweiterungen installieren und aktivieren.",
    "sec_base": "custom/plugins", "sec_depth": 1,
    "no_sec_title": "Kein Sicherheits-Plugin gefunden", "install_hint": "Ein Sicherheits-Plugin installieren",
    "outside_dir": "files",
    "spool": "var",
    "root_find": "-name index.php -o -name composer.json",
    "need_mods": ["json", "xml", "mbstring", "pdo", "gd", "intl", "zip", "curl"], "zip_note": "",
    "root_text": "Shopware legt hier nur die Ordner bin, config, custom, files, public, src, var und vendor ab. ",
    "store": "none", "update_cli": False, "vel": False,
    "common_checks": DRUPAL["common_checks"],
}

PROFILES = {"joomla": JOOMLA, "wordpress": WORDPRESS, "drupal": DRUPAL, "typo3": TYPO3, "contao": CONTAO, "prestashop": PRESTASHOP, "shopware": SHOPWARE}
DEFAULT = "joomla"


def known(cms: str) -> str:
    """Kennung eines unterstützten Systems; Unbekanntes oder Leeres wird zu Joomla (Standard)."""
    return cms if cms in PROFILES else DEFAULT


def runs_common(cms: str, check_id: str) -> bool:
    """Läuft die gemeinsame Prüfung (cms='both') bei diesem System? Joomla und WordPress: alle; Drupal, TYPO3, Contao, PrestaShop und Shopware: nur die geprüfte Auswahl 'common_checks'."""
    allow = profile(cms).get("common_checks")
    return allow is None or check_id in allow


def other(cms: str) -> bool:
    """True, wenn es nicht das Standardsystem (Joomla) ist. Für Stellen, die sich nur zwischen 'Standard' und 'anderes System' unterscheiden."""
    return known(cms) != DEFAULT


def profile(cms: str) -> Dict[str, Any]:
    return PROFILES[known(cms)]


def name_of(cms: str) -> str:
    return profile(cms)["name"]


def by_name(name: str) -> str:
    """Kennung zu einem Anzeigenamen ("WordPress" -> "wordpress"); Unbekanntes wird zu Joomla (Standard)."""
    for k, v in PROFILES.items():
        if v["name"] == name:
            return k
    return DEFAULT


def ext_root(cms: str, path: str):
    m = re.match(profile(cms)["ext_root_re"], path)
    return m.group(1) if m else None
