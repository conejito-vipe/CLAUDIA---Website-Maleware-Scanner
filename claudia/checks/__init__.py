"""Alle Tests. Jedes Modul registriert seine Tests beim Import."""
import importlib

_MODULES = [
    "system",
    "files",
    "config",
    "ext",
    "database",
    "dbarea",
    "logs",
    "web",
    "csp",
    "online",
    "wp",
    "update_ready",
    "auto_updates",
    "security_ext",
    "joomla_core",
    "php_config",
    "blacklist",
    "threat",
    "hidden",
    "konto",
    "compare",
    "skimmer",
    "ext_integrity",
    "mail_dns",
    "mail_send",
    "joomla_einstellungen",
    "woocommerce",
    "drupal_checks",
    "typo3_checks",
    "contao_checks",
    "prestashop_checks",
    "shopware_checks",
    "umgebung_pruefungen",
    "zusatz",
]

for _m in _MODULES:
    try:
        importlib.import_module("%s.%s" % (__name__, _m))
    except ModuleNotFoundError as _e:   # Modul noch nicht vorhanden (Entwicklungsstand)
        if _e.name != "%s.%s" % (__name__, _m):
            raise
