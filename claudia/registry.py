"""Registrierung der Tests (Decorator) und Gruppen/Voreinstellungen."""
from __future__ import annotations

from typing import Callable, Dict, List, Optional

from . import cms as cmsmod
from .model import CheckDef, Option

REGISTRY: Dict[str, CheckDef] = {}
ORDER: List[str] = []

GROUPS = [
    ("grundlagen", "Grundlagen & Umfeld", "Was ist installiert, was liegt im Verzeichnis, gibt es weitere Seiten?"),
    ("dateien", "Schadcode im Dateisystem", "Gezielte Suche nach versteckten Skripten, Hintertüren und manipulierten Dateien."),
    ("konto", "Konto & Dauerzugänge", "Cronjobs, SSH-Schlüssel, Prozesse, Start-Dateien der Shell und angemeldete Sitzungen: Orte, an denen sich ein Angreifer außerhalb der Dateien der Seite festsetzt."),
    ("konfig", "Konfiguration & Zugriffsregeln", ".htaccess, PHP-Einstellungen und Joomla-Konfiguration auf Manipulation prüfen."),
    ("erweiterungen", "Erweiterungen", "Welche Erweiterungen laufen - und gibt es bekannte Sicherheitslücken?"),
    ("datenbank", "Joomla-Daten in der Datenbank", "Benutzer, Editor-Profile, eingeschleuster Code in Inhalten und Aktivitätsprotokoll (mit den Zugangsdaten der Joomla-Seite)."),
    ("dbbereich", "Datenbank (optional, eigene Verbindung)", "Prüft ausschließlich die Datenbank selbst: Schadcode in allen Tabellen, Auffälligkeiten im Aufbau und die aktuelle Sicherheitslage des Datenbank-Servers."),
    ("logs", "Protokolle & Webseite", "Spuren im Zugriffsprotokoll und was Besucher tatsächlich ausgeliefert bekommen."),
]

# Cluster: zusammengehörige Tests innerhalb eines Bereichs. id -> (Titel, Beschreibung des Vorgehens)
CLUSTERS = {
    "umfeld": ("Umfeld erkennen", "Das Programm stellt fest, was auf dem Webspace liegt: Joomla-Version, fremde Dateien im Hauptordner und weitere Webseiten, über die ein Angreifer ebenfalls hineinkommen könnte."),
    "rechte": ("Dateirechte prüfen", "Es wird geprüft, welche Dateien und Ordner für alle beschreibbar sind. Dort kann ein Angreifer Code ablegen."),
    "update": ("Automatische Updates prüfen", "Es wird geprüft, ob sich die Seite im Backend/Dashboard selbst aktualisieren lässt: Schreibrechte und Besitzer der Kernordner, falsch gesetzte Rechte, Reste abgebrochener Updates, freier Speicher, PHP-Module und die Erreichbarkeit des Update-Servers. Nur wenn nichts im Weg steht, kommt eine Erfolgsmeldung."),
    "php_shells": ("PHP nach Shells durchsuchen", "Alle PHP-Dateien werden nach typischen Merkmalen von Hintertüren durchsucht (verschleierter Code, Befehle zum Ausführen von Eingaben) und dort, wo kein PHP liegen darf (Uploads, Temp), gemeldet."),
    "js_inject": ("Injection prüfen", "JavaScript-Dateien werden auf eingeschleusten Code durchsucht, der Besucher umleitet oder Fremdcode nachlädt."),
    "versteck": ("Verstecke und Spuren suchen", "Orte, an denen sich Schadcode gern versteckt: node_modules, frisch geänderte Dateien und liegengebliebene Sicherungen oder Datenbank-Dumps."),
    "zugriffsregeln": ("Zugriffsregeln und PHP-Einstellungen prüfen", "Die Dateien .htaccess, .user.ini und php.ini steuern den Server. Manipulierte Regeln leiten um oder führen Fremdcode automatisch aus."),
    "einstieg": ("Einstiegspunkte prüfen", "Die Dateien, die bei jedem Aufruf laufen (configuration.php, index.php, Templates), werden auf eingebauten Fremdcode geprüft."),
    "ext_schutz": ("Schutz durch Sicherheits-Erweiterung prüfen", "Es wird geprüft, ob eine Firewall oder ein Scanner installiert und eingeschaltet ist. Fehlt sie, erklärt das Programm, warum sich eine lohnt, und zeigt Empfehlungen mit Bewertungen."),
    "ext_sicherung": ("Sicherung prüfen", "Es wird geprüft, ob eine Sicherungs-Erweiterung installiert und eingeschaltet ist. Fehlt sie, zeigt das Programm eine Auswahl und kann sie auf Wunsch installieren."),
    "ext_pruefen": ("Erweiterungen gegen Schwachstellenlisten abgleichen", "Die installierte Version jeder Erweiterung wird mit eigenen und offiziellen Listen verwundbarer Versionen verglichen."),
    "joomla_zugang": ("Zugang und Verbindung", "Prüft, ob das Programm die Datenbank der Joomla-Seite über den Server abfragen kann."),
    "joomla_konten": ("Konten und Aktivität prüfen", "Wer darf sich anmelden, welche Editor-Profile existieren und was wurde im Admin-Bereich getan?"),
    "joomla_einst": ("Einstellungen und Erweiterungsalter prüfen", "Textfilter, erlaubte Upload-Endungen und das Alter der installierten Erweiterungen werden aus der Datenbank gelesen und bewertet: Einstellungen, die Angreifern die Arbeit erleichtern, und Erweiterungen, die lange nicht gepflegt wurden."),
    "shop_woo": ("Onlineshop (WooCommerce) prüfen", "Nur bei WordPress-Seiten mit WooCommerce: API-Schlüssel, Webhooks, Zahlungsarten, Konten mit Shop-Rechten und frei abrufbare Bestell- oder Protokolldaten werden gelesen und bewertet."),
    "drupal_kern": ("Drupal-Kern, Einstellungen und abrufbare Dateien prüfen", "Nur bei Drupal-Seiten: Version und Originaldateien des Kerns, die settings.php und von außen abrufbare Dateien und Schnittstellen werden gelesen und bewertet."),
    "drupal_module": ("Drupal-Module und Themes prüfen", "Nur bei Drupal-Seiten: Jedes Modul und Theme wird inventarisiert und bei drupal.org auf Sicherheitsupdates und aufgegebene Versionen geprüft."),
    "drupal_daten": ("Konten, Einstellungen und Inhalte in der Datenbank prüfen", "Nur bei Drupal-Seiten: Administrator-Konten, Einstellungen in der Tabelle config und Code in Inhalten werden aus der Datenbank gelesen und bewertet."),
    "typo3_kern": ("TYPO3-Kern, Einstellungen und abrufbare Dateien prüfen", "Nur bei TYPO3-Seiten: Version, Sicherheitsmeldungen und Originaldateien des Kerns, die Einstellungsdatei samt Install-Tool und von außen abrufbare Dateien werden gelesen und bewertet."),
    "typo3_erweiterungen": ("TYPO3-Erweiterungen prüfen", "Nur bei TYPO3-Seiten: Jede Erweiterung und Systemerweiterung wird inventarisiert und mit den Sicherheitsmeldungen des TYPO3-Teams (Packagist) abgeglichen."),
    "typo3_daten": ("Konten und Inhalte in der Datenbank prüfen", "Nur bei TYPO3-Seiten: Backend-Administratoren und Code in Inhaltselementen, TypoScript und Nachrichten werden aus der Datenbank gelesen und bewertet."),
    "contao_kern": ("Contao-Kern, Einstellungen und abrufbare Dateien prüfen", "Nur bei Contao-Seiten: Version, Sicherheitsmeldungen und Originaldateien der Kern-Pakete, die Einstellungsdateien (.env, parameters.yaml) und von außen abrufbare Dateien und Verwaltungswerkzeuge werden gelesen und bewertet."),
    "contao_erweiterungen": ("Contao-Pakete und Erweiterungen prüfen", "Nur bei Contao-Seiten: Jedes Paket aus composer.lock wird inventarisiert und mit den Sicherheitsmeldungen von Packagist abgeglichen."),
    "contao_daten": ("Konten und Inhalte in der Datenbank prüfen", "Nur bei Contao-Seiten: Backend-Administratoren (mit Zwei-Faktor-Status) und Code in Inhaltselementen, Modulen und Layouts werden aus der Datenbank gelesen und bewertet."),
    "prestashop_kern": ("PrestaShop-Kern, Einstellungen und abrufbare Dateien prüfen", "Nur bei PrestaShop-Seiten: Version, Support-Stand, Sicherheitsmeldungen und Originaldateien des Kerns, die Einstellungsdateien (parameters.php) und von außen abrufbare Dateien werden gelesen und bewertet."),
    "prestashop_module": ("PrestaShop-Module und Overrides prüfen", "Nur bei PrestaShop-Seiten: Jedes Modul wird inventarisiert und, soweit bei Packagist geführt, mit Sicherheitsmeldungen abgeglichen; Overrides werden aufgelistet."),
    "prestashop_daten": ("Konten, Einstellungen und Inhalte in der Datenbank prüfen", "Nur bei PrestaShop-Seiten: Mitarbeiterkonten, HTTPS- und Webservice-Einstellungen sowie Code in Seiten, Produkten und Textblöcken werden aus der Datenbank gelesen und bewertet."),
    "joomla_code": ("Eingeschleusten Code in Joomla-Daten prüfen", "Artikel, Module, Template-Einstellungen, Weiterleitungen und Erweiterungs-Einträge werden auf fremden Code und fremde Adressen durchsucht."),
    "konto": ("Dauerzugänge im Konto prüfen", "Cronjobs, SSH-Schlüssel, laufende Prozesse, Start-Dateien der Shell und angemeldete Sitzungen werden angesehen. Hier setzt sich ein Angreifer fest, wenn er die Seite verlassen muss."),
    "logs_spuren": ("Protokolle nach Angriffsspuren durchsuchen", "Die Protokolle des Servers werden nach Zugriffen auf Schadcode, Scans und Anmeldeversuchen durchsucht."),
    "besucher": ("Webseite aus Besuchersicht prüfen", "Die Seite wird so aufgerufen, wie ein Besucher sie sieht. So fällt Code auf, der nur Besuchern oder Suchmaschinen ausgeliefert wird."),
    "dbx_aufbau": ("Server und Rechte prüfen", "Version des Datenbank-Servers und die Rechte des Zugangs werden bewertet. Zu weitreichende Rechte erleichtern einem Angreifer, Dateien zu schreiben oder fremde Datenbanken zu lesen."),
    "dbx_inject": ("Injection prüfen", "Alle Textfelder aller Tabellen werden nach eingeschleustem Code durchsucht, auch in Tabellen fremder Erweiterungen. Gefundene Stellen werden mit Tabelle, Spalte und Ausschnitt gezeigt."),
    "dbx_auffaellig": ("Auffälligkeiten suchen", "Gesucht wird, was nicht zu einer normalen Joomla-Datenbank gehört: fremde Tabellen, Trigger, Ereignisse, gespeicherte Prozeduren und frisch angelegte Tabellen."),
    "dbx_lage": ("Aktuelle Sicherheitslage", "Die installierten Erweiterungen aus der Datenbank werden mit der aktuellen Joomla-Liste verwundbarer Erweiterungen verglichen, mit Blick auf SQL-Injection."),
}
CLUSTER_MEMBERS = {
    "drupal_core": "drupal_kern", "drupal_settings": "drupal_kern", "drupal_exposed": "drupal_kern", "drupal_modules": "drupal_module",
    "drupal_users": "drupal_daten", "drupal_config_db": "drupal_daten", "drupal_db_code": "drupal_daten",
    "typo3_core": "typo3_kern", "typo3_settings": "typo3_kern", "typo3_exposed": "typo3_kern", "typo3_extensions": "typo3_erweiterungen", "typo3_users": "typo3_daten", "typo3_db_code": "typo3_daten",
    "contao_core": "contao_kern", "contao_settings": "contao_kern", "contao_exposed": "contao_kern", "contao_packages": "contao_erweiterungen", "contao_users": "contao_daten", "contao_db_code": "contao_daten",
    "prestashop_core": "prestashop_kern", "prestashop_settings": "prestashop_kern", "prestashop_exposed": "prestashop_kern", "prestashop_modules": "prestashop_module", "prestashop_users": "prestashop_daten", "prestashop_shop": "prestashop_daten", "prestashop_db_code": "prestashop_daten",
    "joomla_info": "umfeld", "mail_dns": "umfeld", "dns_changes": "umfeld", "mail_send": "umfeld", "plaintext_creds": "konto", "backup_age": "versteck", "js_libs": "js_inject", "tls_protocols": "besucher", "cookie_flags": "besucher", "threat_intel": "umfeld", "other_installs": "umfeld", "root_files": "umfeld", "perms": "rechte", "update_ready": "update",
    "webshells": "php_shells", "php_in_uploads": "php_shells", "suspicious_names": "php_shells", "malware_patterns": "php_shells", "hidden_structure": "versteck", "compare_runs": "versteck", "skimmer_scan": "js_inject",
    "js_scan": "js_inject",
    "node_modules": "versteck", "recent_changes": "versteck", "backups_in_webroot": "versteck",
    "htaccess": "zugriffsregeln", "htaccess_structure": "zugriffsregeln", "php_ini": "zugriffsregeln", "php_settings": "zugriffsregeln",
    "configuration": "einstieg", "entry_points": "einstieg", "joomla_core": "einstieg", "config_integrity": "einstieg",
    "extensions_fs": "ext_pruefen", "security_ext": "ext_schutz", "backup_tool": "ext_sicherung", "vel_feed": "ext_pruefen", "jed_listing": "ext_pruefen", "ext_integrity": "ext_pruefen",
    "db_access": "joomla_zugang",
    "db_users": "joomla_konten", "db_jce": "joomla_konten", "db_actionlog": "joomla_konten", "db_mfa": "joomla_konten", "db_registration": "joomla_konten", "db_admin_logins": "joomla_konten",
    "db_textfilter": "joomla_einst", "db_upload_ext": "joomla_einst", "db_ext_age": "joomla_einst",
    "db_content": "joomla_code", "db_redirects": "joomla_code", "db_extensions": "joomla_code",
    "crontab": "konto", "authorized_keys": "konto", "processes": "konto", "shell_startup": "konto", "sessions": "konto", "joomla_api": "konto", "joomla_api_exposure": "besucher",
    "access_logs": "logs_spuren", "local_logs": "logs_spuren", "joomla_logs": "logs_spuren",
    "web_source": "besucher", "web_headers": "besucher", "web_csp": "besucher", "safe_browsing": "besucher",
    "dbx_server": "dbx_aufbau", "dbx_codescan": "dbx_inject", "dbx_anomalies": "dbx_auffaellig", "dbx_incidents": "dbx_lage",
}

# ---- WordPress: gleicher Aufbau, andere Texte. Fehlt ein Eintrag, gilt der Joomla-Text.
GROUPS_WP = {
    "grundlagen": ("Grundlagen & Umfeld", "Was ist installiert, was liegt im Verzeichnis, gibt es weitere Seiten im selben Konto?"),
    "dateien": ("Schadcode im Dateisystem", "Gezielte Suche nach versteckten Skripten, Hintertüren und manipulierten Dateien in wp-content und im WordPress-Kern."),
    "konfig": ("Konfiguration & Zugriffsregeln", ".htaccess, PHP-Einstellungen und die wp-config.php auf Manipulation und unsichere Einstellungen prüfen."),
    "erweiterungen": ("Plugins & Themes", "Welche Plugins und Themes laufen - und gibt es bekannte Sicherheitslücken oder aufgegebene Plugins?"),
    "datenbank": ("WordPress-Daten in der Datenbank", "Benutzer, Optionen, eingeschleuster Code in Beiträgen und Widgets (mit den Zugangsdaten aus der wp-config.php)."),
}
CLUSTERS_WP = {
    "umfeld": ("Umfeld erkennen", "Das Programm stellt fest, was auf dem Webspace liegt: WordPress-Version, fremde Dateien im Hauptordner und weitere Webseiten, über die ein Angreifer ebenfalls hineinkommen könnte."),
    "php_shells": ("PHP nach Shells durchsuchen", "Alle PHP-Dateien werden nach typischen Merkmalen von Hintertüren durchsucht und dort gemeldet, wo kein PHP liegen darf (wp-content/uploads, Cache, Upgrade-Ordner)."),
    "zugriffsregeln": ("Zugriffsregeln und PHP-Einstellungen prüfen", "Die Dateien .htaccess, .user.ini und php.ini steuern den Server. Manipulierte Regeln leiten um oder führen Fremdcode automatisch aus."),
    "einstieg": ("Einstiegspunkte und WordPress-Kern prüfen", "Die wp-config.php, die Dateien, die bei jedem Aufruf laufen (Drop-ins, Must-Use-Plugins, functions.php des Themes) und die Kerndateien von WordPress werden auf Fremdcode und Veränderungen geprüft."),
    "ext_pruefen": ("Plugins und Themes prüfen", "Jedes Plugin und Theme wird inventarisiert, mit Listen verwundbarer Versionen verglichen und - online - auf aufgegebene oder veraltete Versionen im offiziellen Verzeichnis geprüft."),
    "joomla_zugang": ("Zugang und Verbindung", "Prüft, ob das Programm die Datenbank der WordPress-Seite über den Server abfragen kann."),
    "joomla_konten": ("Konten prüfen", "Wer darf sich anmelden, welche Administratoren gibt es und wann wurden sie angelegt?"),
    "joomla_code": ("Eingeschleusten Code in WordPress-Daten prüfen", "Beiträge, Seiten, Widgets, Optionen und Kommentare werden auf fremden Code und fremde Adressen durchsucht; Webadresse und aktive Plugins werden mit den Dateien abgeglichen."),
    "besucher": ("Webseite aus Besuchersicht prüfen", "Die Seite wird so aufgerufen, wie ein Besucher sie sieht. So fällt Code auf, der nur Besuchern oder Suchmaschinen ausgeliefert wird; außerdem wird geprüft, was öffentlich abrufbar ist (debug.log, xmlrpc.php, Benutzerliste)."),
    "dbx_lage": ("Aktuelle Sicherheitslage", "Die aktiven Plugins aus der Datenbank werden mit der Liste bekannter Lücken verglichen, mit Blick auf SQL-Injection und Rechteausweitung."),
    "dbx_auffaellig": ("Auffälligkeiten suchen", "Gesucht wird, was nicht zu einer normalen WordPress-Datenbank gehört: fremde Tabellen, Trigger, Ereignisse, gespeicherte Prozeduren und frisch angelegte Tabellen."),
}
CLUSTER_MEMBERS_WP = {
    "wp_info": "umfeld", "mail_dns": "umfeld", "dns_changes": "umfeld", "mail_send": "umfeld", "plaintext_creds": "konto", "backup_age": "versteck", "js_libs": "js_inject", "tls_protocols": "besucher", "cookie_flags": "besucher", "wp_config": "einstieg", "wp_entry_points": "einstieg", "wp_core": "einstieg",
    "wp_plugins": "ext_pruefen", "wp_plugins_online": "ext_pruefen", "wp_plugin_integrity": "ext_pruefen", "wp_theme_integrity": "ext_pruefen",
    "db_access": "joomla_zugang", "wp_db_users": "joomla_konten", "wp_2fa": "joomla_konten", "wp_db_options": "joomla_code", "wp_db_content": "joomla_code",
    "woo_overview": "shop_woo", "woo_api_keys": "shop_woo", "woo_webhooks": "shop_woo", "woo_gateways": "shop_woo", "woo_managers": "shop_woo", "woo_exposed": "shop_woo",
    "wp_cron": "konto", "wp_db_incidents": "dbx_lage", "wp_logs": "logs_spuren", "wp_exposure": "besucher",
}


# Tests, die für beide Systeme laufen (Pfade und Bezeichnungen kommen aus dem Profil in cms.py)
BOTH = {"backup_tool", "crontab", "authorized_keys", "processes", "shell_startup", "sessions", "root_files", "perms", "other_installs", "node_modules", "js_scan", "php_in_uploads", "webshells", "suspicious_names",
        "recent_changes", "backups_in_webroot", "htaccess", "php_ini", "access_logs", "local_logs", "web_source", "web_headers", "web_csp", "db_access", "mail_dns", "dns_changes", "mail_send", "plaintext_creds", "backup_age", "js_libs", "tls_protocols", "cookie_flags",
        "dbx_server", "dbx_codescan", "dbx_anomalies", "update_ready", "security_ext", "php_settings", "safe_browsing", "threat_intel", "malware_patterns", "hidden_structure", "htaccess_structure", "compare_runs", "skimmer_scan"}

# Texte für den WordPress-Bereich der gemeinsamen Tests (Titel, Beschreibung, Vorgehen, Begründung)
WP_TEXTS = {
    "root_files": {"what": "Listet alle Dateien und Ordner direkt im WordPress-Hauptverzeichnis auf und vergleicht sie mit dem, was WordPress dort normalerweise ablegt (wp-admin, wp-content, wp-includes und die wp-*.php-Dateien). "
                          "Unbekannte PHP-Dateien, versteckte Ordner wie .git, ein node_modules-Ordner oder alte Kopien der .htaccess werden gesondert gemeldet.",
                   "why": "Angreifer legen Hintertüren gern direkt im Hauptverzeichnis ab, oft mit Namen, die wie WordPress-Dateien aussehen (wp-feed.php, wp-vcd.php). Entwickler-Altlasten gehören nicht auf einen Live-Server."},
    "perms": {"what": "Sucht nach Dateien und Ordnern mit Schreibrecht für 'alle' (z. B. 777/666) und prüft die Rechte der wp-config.php.",
              "why": "Auf geteilten Servern können andere Konten oder eingeschleuste Skripte solche Dateien manipulieren. Die wp-config.php enthält Datenbank-Passwort und Schlüssel."},
    "other_installs": {"summary": "Laufen im selben Hosting-Konto noch andere WordPress- oder Joomla-Seiten?"},
    "php_in_uploads": {"title": "PHP-Dateien in Uploads, Upgrade- und Backup-Ordnern",
                       "what": "Sucht in wp-content/uploads, upgrade und Backup-Ordnern nach PHP-Dateien (.php, .phtml, .phar ...), nach versteckten Dateien (z. B. .cache.ico) und nach Dateien mit harmloser Endung (z. B. .jpg), die PHP-Code enthalten. "
                               "In Cache-Ordnern werden nur Dateien mit Hintertür-Merkmalen gemeldet.",
                       "why": "Fast jede Lücke in einem Plugin (Datei-Upload, Formulare, Datei-Manager) dient dazu, genau dort eine Web-Shell abzulegen. In wp-content/uploads hat PHP-Code nichts zu suchen - das ist die wirksamste Einzelprüfung.",
                       "reads": "Dateinamen und - nur bei Verdacht - der Anfang von Dateien in diesen Ordnern. Nichts wird verändert."},
    "webshells": {"what": "Durchsucht alle PHP-Dateien (auch in wp-content/plugins, themes, uploads) in drei Stufen: (1) eindeutige Hintertür-Muster, (2) Dateien mit base64/eval, die in den letzten Tagen geändert wurden, (3) Dateien mit extrem langen Zeilen (verschleierter Code). "
                          "Der WordPress-Kern (wp-admin, wp-includes) wird in Stufe 2 und 3 geschont - er wird gesondert gegen die offiziellen Prüfsummen geprüft.",
                  "why": "Web-Shells erlauben dem Angreifer, jederzeit Befehle auszuführen, auch nach einem Passwortwechsel. Bei WordPress stecken sie meist in Plugins, Themes und Uploads."},
    "suspicious_names": {"what": "Sucht nach Dateien mit typischen Hintertür-Namen, nach wp-*.php-Dateien im Hauptordner, die nicht zum Kern gehören, Dateien mit Doppelendung (z. B. bild.php.jpg), .phtml/.phar-Dateien, "
                                 "ungewöhnlich kurzen PHP-Namen (a.php) sowie .git, .env, error_log und Sicherungskopien von PHP-Dateien (.php.bak).",
                         "why": "Angreifer wählen oft unauffällige Namen. Sicherungskopien wie wp-config.php.bak können Passwörter im Klartext ausliefern."},
    "backups_in_webroot": {"what": "Sucht nach Archiven und Datenbank-Dumps in der Seite (auch .wpress von All-in-One WP Migration) und prüft, ob der jeweilige Ordner durch eine .htaccess mit Zugriffssperre geschützt ist.",
                           "why": "Ein frei abrufbares Backup enthält Datenbank, Benutzer und Passwort-Hashes. Angreifer suchen gezielt nach Backup-Ordnern von Plugins (UpdraftPlus, Duplicator, All-in-One WP Migration) und .sql-Dateien."},
    "db_access": {"summary": "Kann das Programm die WordPress-Datenbank über den Server abfragen?",
                  "what": "Liest Host, Benutzer und Datenbank aus der wp-config.php und führt über das mysql-Programm des Servers eine harmlose Testabfrage aus. "
                          "Das Passwort wird nicht in der Befehlszeile übergeben, sondern über einen verdeckten Kanal, und nie gespeichert oder exportiert."},
    "web_source": {"title": "Webseite aus Besuchersicht prüfen"},
}


# ---- Drupal: gleicher Aufbau; fehlt ein Eintrag, gilt der Joomla-Text mit ersetzten Begriffen (Joomla -> Drupal, configuration.php -> settings.php)
GROUPS_DRUPAL = {
    "konfig": ("Konfiguration & Zugriffsregeln", "Kern, settings.php, .htaccess und PHP-Einstellungen auf Manipulation und unsichere Einstellungen prüfen."),
    "erweiterungen": ("Module & Themes", "Welche Module und Themes laufen - und gibt es Sicherheitsupdates oder aufgegebene Versionen?"),
    "datenbank": ("Drupal-Daten in der Datenbank", "Benutzer, Einstellungen und eingeschleuster Code in Inhalten (mit den Zugangsdaten aus der settings.php)."),
}


# ---- TYPO3: gleicher Aufbau wie bei Drupal
GROUPS_TYPO3 = {
    "konfig": ("Konfiguration & Zugriffsregeln", "Kern, Einstellungsdatei, Install-Tool, .htaccess und PHP-Einstellungen auf Manipulation und unsichere Einstellungen prüfen."),
    "erweiterungen": ("Erweiterungen", "Welche Erweiterungen laufen - und gibt es Sicherheitsmeldungen zu ihren Versionen?"),
    "datenbank": ("TYPO3-Daten in der Datenbank", "Backend-Benutzer und eingeschleuster Code in Inhalten (mit den Zugangsdaten aus der Einstellungsdatei)."),
}
GROUPS_CONTAO = {
    "konfig": ("Konfiguration & Zugriffsregeln", "Kern, Einstellungsdateien, Install-Tool, .htaccess und PHP-Einstellungen auf Manipulation und unsichere Einstellungen prüfen."),
    "erweiterungen": ("Pakete & Erweiterungen", "Welche Pakete und Erweiterungen laufen - und gibt es Sicherheitsmeldungen zu ihren Versionen?"),
    "datenbank": ("Contao-Daten in der Datenbank", "Backend-Benutzer und eingeschleuster Code in Inhalten (mit den Zugangsdaten aus der .env bzw. parameters.yaml)."),
}
GROUPS_PRESTASHOP = {
    "konfig": ("Konfiguration & Zugriffsregeln", "Kern, Einstellungsdateien, Installations- und Verwaltungsordner, .htaccess und PHP-Einstellungen auf Manipulation und unsichere Einstellungen prüfen."),
    "erweiterungen": ("Module & Overrides", "Welche Module und Overrides laufen - und gibt es Sicherheitsmeldungen zu ihren Versionen?"),
    "datenbank": ("PrestaShop-Daten in der Datenbank", "Mitarbeiterkonten, HTTPS- und Webservice-Einstellungen und eingeschleuster Code in Inhalten (mit den Zugangsdaten aus der parameters.php)."),
}
_OTHER_GROUPS = {"drupal": GROUPS_DRUPAL, "typo3": GROUPS_TYPO3, "contao": GROUPS_CONTAO, "prestashop": GROUPS_PRESTASHOP}


def _cms_text(cms: str, text: str) -> str:
    from .model import _wp_words
    return _wp_words(text, cms) if cms in _OTHER_GROUPS else text


def groups_for(cms: str = "joomla"):
    if cms in _OTHER_GROUPS:
        return [(g[0],) + _OTHER_GROUPS[cms].get(g[0], (_cms_text(cms, g[1]), _cms_text(cms, g[2]))) for g in GROUPS]
    if cms != "wordpress":
        return list(GROUPS)
    return [(g[0],) + GROUPS_WP.get(g[0], (g[1], g[2])) for g in GROUPS]


def cluster_title_defs(cms: str = "joomla"):
    if cms in _OTHER_GROUPS:
        return [{"id": k, "title": _cms_text(cms, v[0]), "text": _cms_text(cms, v[1])} for k, v in CLUSTERS.items()]
    if cms != "wordpress":
        return cluster_defs()
    out = []
    for k, v in CLUSTERS.items():
        t = CLUSTERS_WP.get(k, v)
        out.append({"id": k, "title": t[0], "text": t[1]})
    return out


PRESETS = [
    ("schnell", "Schnellcheck", "Die wichtigsten Prüfungen, dauert wenige Minuten und belastet den Server kaum."),
    ("hack", "Nach einem Hack", "Empfohlen nach einem Vorfall: alles Wichtige inklusive Datenbank und Zugriffsprotokoll."),
    ("komplett", "Komplett", "Alle Tests, auch die langsamen."),
]


def check(id: str, group: str, title: str, summary: str, what: str, why: str, reads: str,
          load: str = "leicht", needs: str = "ssh", presets: Optional[List[str]] = None,
          options: Optional[List[Option]] = None, cms: str = "joomla", wp: Optional[Dict[str, str]] = None) -> Callable:
    def deco(fn: Callable) -> Callable:
        if id in REGISTRY:
            raise ValueError("Doppelte Test-ID: " + id)
        kind = "both" if (id in BOTH and cms == "joomla") else cms
        pr = list(presets or [])
        if "komplett" not in pr:
            pr.append("komplett")
        REGISTRY[id] = CheckDef(id=id, group=group, title=title, summary=summary, what=what, why=why,
                                reads=reads, load=load, needs=needs, fn=fn, presets=pr,
                                options=list(options or []), cluster=CLUSTER_MEMBERS.get(id, ""),
                                cms=kind, cluster_wp=CLUSTER_MEMBERS_WP.get(id, ""), wp={**WP_TEXTS.get(id, {}), **dict(wp or {})})
        ORDER.append(id)
        return fn
    return deco


def cluster_defs():
    return [{"id": k, "title": v[0], "text": v[1]} for k, v in CLUSTERS.items()]


def cluster_map(cms: str = "joomla") -> Dict[str, str]:
    """{Prüfungs-ID: Cluster} für das System (WordPress: eigener Cluster, sonst der gemeinsame). Grundlage des Maßnahmenplans."""
    load_all()
    return {c.id: c.cluster_for(cms) or "" for c in ordered(cms)}


def load_all() -> Dict[str, CheckDef]:
    """Importiert alle Test-Module (registriert sie dabei)."""
    from . import checks  # noqa: F401
    return REGISTRY


def ordered(cms: str = "joomla") -> List[CheckDef]:
    """Alle Tests für das System (cms='joomla' oder 'wordpress'), sortiert nach Bereich und Cluster."""
    load_all()
    group_idx = {g[0]: i for i, g in enumerate(GROUPS)}
    live = [i for i in ORDER if i in REGISTRY]
    cl_idx = {k: i for i, k in enumerate(CLUSTERS)}
    def cl(c):
        return c.cluster_for(cms)
    sel = [REGISTRY[i] for i in live if REGISTRY[i].cms == cms or (REGISTRY[i].cms == "both" and cmsmod.runs_common(cms, i))]
    return sorted(sel, key=lambda c: (group_idx.get(c.group, 99), cl_idx.get(cl(c), 99), 0 if c.id == "wp_info" else 1, live.index(c.id)))
