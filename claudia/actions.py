"""Lösungen auf Knopfdruck (optional, nur nach ausdrücklicher Bestätigung).

Die PRÜFUNGEN des Programms sind rein lesend. Dieses Modul ist der einzige Ort, der auf dem Server etwas verändert, und nur
- für eine kleine, feste Liste von Aktionen (keine frei eingegebenen Befehle),
- nach Vorschau der Befehle und ausdrücklicher Bestätigung durch den Benutzer,
- bei Aktionen mit Risiko erst NACH einer geprüften Sicherung (Datenbank und Dateien). Misslingt die Sicherung, passiert nichts.
"""
from __future__ import annotations

import re
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from . import db as dbmod, joomla, wordpress
from . import updcheck
from .runner import Runner, RunnerError
from .util import lines_of, sq

CHMOD_MAX = 200


class ActionError(Exception):
    pass


ACTIONS: Dict[str, Dict[str, Any]] = {
    "backup_now": {
        "title": "Vollständige Sicherung anlegen",
        "summary": "Legt eine Sicherung der Datenbank und aller Dateien (ohne images, cache, tmp, logs) im Home-Verzeichnis des Servers an und prüft sie. "
                   "Das ist dein Rückweg, falls bei den späteren Schritten etwas schiefgeht, und zugleich eine Kopie des jetzigen Zustands.",
        "warning": "Die Sicherung braucht Platz auf dem Server und kann bei großen Seiten einige Minuten dauern. Sie enthält auch die infizierten Dateien "
                   "und darf nicht in einen öffentlich erreichbaren Ordner kopiert werden.",
        "risk": "niedrig", "backup": True, "needs_php": False,
        "undo": "Nicht nötig. Löschen kannst du sie später mit 'Alte Sicherungen löschen'.",
    },
    "fix_permissions": {
        "title": "Schreibrechte für 'alle' entfernen",
        "summary": "Entfernt bei den gemeldeten Dateien/Ordnern das Schreibrecht für alle anderen (chmod o-w). Der Besitzer behält seine Rechte.",
        "warning": "Sehr selten braucht eine Erweiterung das Schreibrecht für alle (z. B. wenn PHP unter einem anderen Konto läuft). Dann zeigt die Seite "
                   "Fehler beim Speichern. Das lässt sich mit dem unten genannten Befehl rückgängig machen. Jede Änderung wird protokolliert. "
                   "Hinweis: Ein chmod ändert bei den Dateien die Änderungszeit des Eintrags (ctime). Die Prüfung 'Kürzlich geänderte Dateien' zeigt sie danach als ctime-Änderung; das ist dann diese Aktion und kein Angriff.",
        "risk": "niedrig", "backup": False, "needs_php": False,
        "undo": "Die ursprünglichen Rechte stehen im Protokoll (rechte_vorher.txt im Sicherungsordner auf dem Server).",
    },
    "fix_update_perms": {
        "title": "Schreibrecht für den Besitzer wiederherstellen",
        "summary": "Setzt bei den Dateien und Ordnern, die der Test 'Lässt sich die Seite automatisch aktualisieren?' gemeldet hat, das Schreibrecht für den Besitzer (chmod u+rwX). "
                   "Alle anderen Rechte bleiben unverändert. Danach können Updates diese Dateien ersetzen.",
        "warning": "Nur Dateien und Ordner aus der Meldung werden angefasst, Verweise (Symlinks) werden übersprungen. Jede Änderung wird mit den alten Rechten protokolliert.",
        "risk": "niedrig", "backup": False, "needs_php": False,
        "undo": "Die ursprünglichen Rechte stehen im Protokoll (rechte_vorher.txt im Sicherungsordner auf dem Server).",
    },
    "wp_remove_maintenance": {
        "title": "Hängenden Wartungsmodus beenden (.maintenance löschen)",
        "summary": "Löscht die Datei .maintenance im WordPress-Hauptordner. Sie enthält nur einen Zeitstempel und bleibt nach einem abgebrochenen Update liegen. Vorher wird eine Kopie angelegt.",
        "warning": "Läuft gerade wirklich ein Update, stört das Löschen es. Das Programm löscht nur, wenn die Datei klein ist und nur aus dem üblichen Zeitstempel besteht.",
        "risk": "niedrig", "backup": False, "needs_php": False,
        "undo": "Nicht nötig. Die Kopie liegt im Sicherungsordner auf dem Server (~/claudia-sicherung-wartung-<datum>).",
    },
    "check_updates": {
        "title": "Nach Joomla- und Erweiterungs-Updates suchen",
        "summary": "Fragt Joomla über seine Kommandozeile, ob neue Versionen vorhanden sind (core:check-updates und update:extensions:check). "
                   "Es wird nichts installiert.",
        "warning": "Joomla aktualisiert dabei seine interne Update-Liste in der Datenbank. Sonst ändert sich nichts.",
        "risk": "keine", "backup": False, "needs_php": True, "hidden": True,
        "undo": "Nicht nötig.",
    },
    "core_update": {
        "title": "Joomla auf die neueste Version aktualisieren",
        "summary": "Legt zuerst eine Sicherung an (Datenbank und Dateien), prüft sie, und führt dann 'core:update' aus. "
                   "Erweiterungen werden NICHT automatisch aktualisiert (die Joomla-Kommandozeile kann das nicht).",
        "warning": "ACHTUNG: Ein Update verändert viele Dateien. Es kann scheitern oder Erweiterungen/Templates brechen. Die Sicherung wird vorher geprüft; "
                   "wenn sie nicht gelingt, passiert nichts. Mache NUR dann weiter, wenn 'Nach Updates suchen' eine neue Version gezeigt hat und du zur Not "
                   "die Sicherung selbst zurückspielen kannst. Die Seite kann einige Minuten fehlerhaft sein.",
        "risk": "hoch", "backup": True, "needs_php": True,
        "undo": "Sicherung zurückspielen: Datenbank (db.sql.gz) per phpMyAdmin importieren, Dateien (dateien.tgz) im Joomla-Ordner entpacken.",
    },
    "update_extensions": {
        "title": "Erweiterungen aktualisieren",
        "summary": "Installiert die Updates, die Joomla selbst aus den offiziellen Update-Quellen der Hersteller gemeldet hat. Das Programm holt die "
                   "Download-Adresse aus dem Update-Manifest des Herstellers und installiert das Paket mit Joomlas eigenem Befehl (extension:install), "
                   "genau wie der Web-Updater im Backend.",
        "warning": "ACHTUNG: Updates verändern Dateien und Datenbank der Erweiterung und können Seiten oder Layouts brechen, vor allem bei neuen "
                   "Hauptversionen. Vorher wird eine Sicherung (Datenbank und Dateien) angelegt und geprüft. Nach jedem Update wird die installierte "
                   "Version kontrolliert. Bei einem Fehler wird abgebrochen. Kostenpflichtige Erweiterungen mit Download-Schlüssel werden nicht angeboten.",
        "risk": "hoch", "backup": True, "needs_php": True,
        "undo": "Sicherung zurückspielen: Datenbank (db.sql.gz) per phpMyAdmin importieren, Dateien (dateien.tgz) im Joomla-Ordner entpacken.",
    },
    "clean_tmp": {
        "title": "Temp-Ordner leeren (tmp und images/tmp)",
        "summary": "Die Ordner tmp und images/tmp sind nur Zwischenlager für Installationen, Updates und Uploads. Alte Installationspakete, entpackte Erweiterungen und "
                   "eingeschleuste Dateien liegen dort oft jahrelang und sind für Angreifer ein beliebter Ablageort. Die Ordner selbst bleiben bestehen.",
        "warning": "Gelöscht wird alles in diesen Ordnern außer index.html und .htaccess. Läuft gerade ein Update oder eine Installation in Joomla, bricht sie ab "
                   "(dann einfach neu starten). Vorher wird der gesamte Inhalt als Archiv außerhalb des Web-Ordners gesichert und geprüft.",
        "risk": "mittel", "backup": False, "needs_php": False,
        "undo": "Archiv tmp.tgz im Sicherungsordner auf dem Server (~/claudia-sicherung-tmp-<datum>) im Joomla-Ordner entpacken: tar xzf tmp.tgz",
    },
    "delete_old_backups": {
        "title": "Alte Sicherungen auf dem Server löschen",
        "summary": "Zeigt alle Sicherungsordner, die dieses Programm früher im Home-Verzeichnis angelegt hat (claudia-sicherung-... und die Ordner früherer Versionen), mit Datum, Größe und Inhalt. "
                   "Dazu die Protokolle früherer Aktionen auf diesem Computer: Sie können zusammen mit den Sicherungen gelöscht werden, "
                   "das jeweils neueste Protokoll jeder Aktion bleibt immer erhalten. Du wählst aus, was gelöscht wird. Andere Dateien und Ordner werden nie angefasst.",
        "warning": "Gelöschte Sicherungen sind weg. Die Sicherungen enthalten Datenbank-Abzüge mit personenbezogenen Daten und (bei infizierten Seiten) Schadcode. "
                   "Behalte nur die Sicherung, die du für einen Rückweg brauchst, und lösche den Rest erst, wenn die Seite wieder sauber läuft.",
        "risk": "mittel", "backup": False, "needs_php": False,
        "undo": "Nicht möglich. Lade dir vorher bei Bedarf eine Kopie per SFTP herunter.",
    },
    "remove_jce_profiles": {
        "title": "Schädliche JCE-Profile löschen",
        "summary": "Löscht genau die JCE-Profile, die der Test gemeldet hat und in deren Einstellungen der Upload von PHP-Dateien erlaubt wird. "
                   "Die normalen Profile (Default, Front End, Blogger, Mobile, Markdown) werden nie angefasst.",
        "warning": "Gelöscht wird in der Datenbank. Vorher wird die Tabelle der JCE-Profile gesichert und geprüft. Hast du ein dieser Profile selbst "
                   "angelegt und brauchst du es, lege es danach neu an, ohne PHP als erlaubten Dateityp.",
        "risk": "mittel", "backup": False, "needs_php": False, "can_skip_backup": True,
        "undo": "Sicherung wf_profiles.sql.gz im Sicherungsordner auf dem Server per phpMyAdmin importieren.",
    },
    "remove_shells": {
        "title": "Hintertüren und PHP-Dateien in images in Quarantäne verschieben",
        "summary": "Verschiebt die Dateien, die der Test als Hintertür (Web-Shell) gemeldet hat, sowie die angehakten PHP-Dateien im Ordner images in einen Quarantäne-Ordner "
                   "außerhalb des Web-Ordners (~/claudia-quarantaene-<Datum>, Rechte 700). Nichts wird gelöscht. Die Dateien verlieren ihr Ausführrecht und ihre Endung (aus .php wird .q); "
                   "die Liste QUARANTAENE.txt hält je Datei Ursprungspfad, Rechte, Besitzer und Prüfsumme fest. Mit 'Dateien aus der Quarantäne zurückholen' kommen sie an ihren Platz zurück. "
                   "In einem Bilder-Ordner hat PHP nie etwas zu suchen. Die Dateien im Ordner tmp erledigt 'Temp-Ordner leeren'.",
        "warning": "Prüfe die Dateiliste. Erkennst du eine Datei als deine eigene, hake sie ab. Die Dateien bleiben schädlich, auch in der Quarantäne: nicht öffnen, nicht ausführen. "
                   "Liegt das Home-Verzeichnis im Web-Ordner der Seite, bricht die Aktion ab, weil es dann keinen sicheren Platz gibt. Liegt der Quarantäne-Ordner auf einem anderen Dateisystem, "
                   "wird erst kopiert und geprüft, dann das Original entfernt. Das Verschieben allein schließt die Einbruchstelle nicht: Erweiterungen aktualisieren und Passwörter ändern bleibt nötig.",
        "risk": "mittel", "backup": False, "needs_php": False,
        "undo": "Aktion 'Dateien aus der Quarantäne zurückholen' (mit Vorschau; je Datei Abbruch, wenn am Ursprungsort schon etwas liegt). Von Hand: "
                "mv -n -- ~/claudia-quarantaene-<Datum>/d/<Nr>.q <Seitenordner>/<Ursprungspfad laut QUARANTAENE.txt>. Vorsicht: Die Dateien sind schädlich, nur bei Bedarf und nicht im Browser öffnen.",
    },
    "restore_quarantine": {
        "title": "Dateien aus der Quarantäne zurückholen",
        "summary": "Holt die angehakten Dateien aus einem Quarantäne-Ordner (~/claudia-quarantaene-<Datum>) an ihren ursprünglichen Platz zurück, mit den ursprünglichen Rechten. "
                   "Gedacht für den Fall, dass eine Datei zu Unrecht in die Quarantäne kam (z. B. eine eigene Datei). Es ist nichts vorausgewählt.",
        "warning": "Ein Zurückholen stellt auch echte Schadsoftware wieder her: Hole nur Dateien zurück, die du sicher kennst. Je Datei prüft das Programm vorher, ob die Datei noch in der Quarantäne liegt, "
                   "die Prüfsumme der Liste entspricht, der Ursprungsordner vorhanden und beschreibbar ist und am Ursprungsort nichts liegt. Trifft etwas davon nicht zu, wird genau diese Datei übersprungen; "
                   "nie wird etwas überschrieben und nie ein Ordner neu angelegt. Den Besitzer kann das Programm ohne Administratorrechte nicht setzen; weicht er ab, steht ein Hinweis im Ergebnis.",
        "risk": "hoch", "backup": False, "needs_php": False,
        "undo": "Dieselben Dateien lassen sich über 'Hintertüren und PHP-Dateien in Quarantäne verschieben' wieder verschieben (wenn die Prüfung sie meldet). "
                "Von Hand: mv -n -- <Seitenordner>/<Pfad> ~/claudia-quarantaene-<Datum>/d/<Nr>.q und chmod 600. Das Protokoll steht in ZURUECK.txt im Quarantäne-Ordner.",
    },
    "delete_quarantine": {
        "title": "Quarantäne-Ordner auf dem Server löschen",
        "summary": "Zeigt die Quarantäne-Ordner dieser Seite (~/claudia-quarantaene-...) mit Datum, Anzahl der noch enthaltenen Dateien und Größe. Die angehakten Ordner werden samt Inhalt und Liste gelöscht. "
                   "Es ist nichts vorausgewählt. Nur Ordner, die dieses Programm für genau diese Seite angelegt hat (erkennbar an der Liste QUARANTAENE.txt), werden angefasst; Ordner anderer Seiten und fremde Ordner nie.",
        "warning": "Gelöscht ist endgültig: Die Dateien lassen sich danach nicht mehr zurückholen. Lösche eine Quarantäne erst, wenn du sicher bist, dass keine der Dateien eine eigene war "
                   "(sonst vorher 'Dateien aus der Quarantäne zurückholen'). Die Dateien darin sind schädlich; beim Löschen werden sie nicht geöffnet oder ausgeführt.",
        "risk": "hoch", "backup": False, "needs_php": False,
        "undo": "Kein Rückweg: Ein gelöschter Quarantäne-Ordner ist weg. Vorher einzelne Dateien über 'Dateien aus der Quarantäne zurückholen' wiederherstellen.",
    },
    "reset_htaccess": {
        "title": "Hauptdatei .htaccess auf den Standard zurücksetzen",
        "summary": "Ersetzt die .htaccess im Hauptordner durch die Standarddatei: bei Joomla htaccess.txt aus dem geprüften Original-Paket, bei WordPress der Standardblock. "
                   "Harmlose eigene Regeln und Blöcke bekannter Plugins werden auf Wunsch übernommen, auffällige oder gefährliche Regeln nicht. Die Vorschau zeigt jede Änderung als Vergleich "
                   "(rot = entfällt, grün = neu). Danach ruft das Programm die Startseite ab; liefert sie einen Serverfehler, wird sofort der alte Stand hergestellt.",
        "warning": "Gilt nur für die .htaccess im Hauptordner, nicht für Unterordner. Regeln, die das Programm als auffällig einstuft (z. B. Weiterleitungen auf fremde Domains), werden nicht übernommen; "
                   "hast du sie selbst angelegt, ergänze sie nach dem Zurücksetzen von Hand. Blöcke mit auto_prepend_file (z. B. von Firewall-Plugins) werden ebenfalls nicht übernommen; "
                   "das Plugin schreibt seinen Block bei Bedarf neu. Zusätzliche Schutzregeln deines Hosters in dieser Datei können entfallen: Lies die Vorschau. Das Zurücksetzen ersetzt nicht das Schließen der Einbruchstelle.",
        "risk": "hoch", "backup": False, "needs_php": False,
        "undo": "Die alte .htaccess liegt als htaccess.vorher im Sicherungsordner auf dem Server (~/claudia-sicherung-htaccess-<datum>); rueckgaengig.txt dort nennt den Befehl.",
    },
    "remove_db_code": {
        "title": "Eingeschleusten Code in der Datenbank entfernen",
        "summary": "Entfernt aus den von dir gewählten Datenbank-Einträgen (Artikel, Module, Template-Einstellungen, Beiträge, Optionen) genau die Skript- und Frame-Blöcke, die die Prüfung als schädlich oder verdächtig eingestuft hat "
                   "(bekannter Schadcode, verschleierter Code, Skripte oder Frames auf fremde Adressen, unsichtbare Frames). Der Rest des Eintrags bleibt unverändert. Die Vorschau zeigt je Eintrag, was entfernt wird. "
                   "Vorher wird der alte Wert jedes Eintrags als SQL-Befehl gesichert.",
        "warning": "Es wird ein Wert in der Datenbank verändert; das Programm sichert vorher den alten Wert jedes gewählten Eintrags (rueckgaengig.sql) und bricht ohne gültige Sicherung ab. "
                   "Nicht angefasst werden: serialisierte WordPress-Werte (a:..., s:...; ein Eingriff würde sie unbrauchbar machen), Werte über 1 MB und Einträge, in denen nichts Eindeutiges zu entfernen ist; dafür nennt das Programm den Grund. "
                   "Auch Code außerhalb von Skript-/Frame-Blöcken (z. B. eval( im Fließtext) bleibt stehen und wird gemeldet. Das Entfernen schließt die Einbruchstelle nicht; danach Cache leeren und die Seite neu prüfen.",
        "risk": "hoch", "backup": False, "needs_php": False, "pick": True,
        "undo": "Die alten Werte stehen als UPDATE-Befehle in rueckgaengig.sql im Sicherungsordner auf dem Server (~/claudia-sicherung-dbcode-<datum>). Im phpMyAdmin (Reiter SQL) einfügen und ausführen.",
    },
    "block_php_uploads": {
        "title": "PHP-Ausführung im Bilder-Ordner sperren",
        "summary": "Legt im Ordner images (WordPress: wp-content/uploads) eine .htaccess an bzw. ergänzt sie, die PHP-Dateien dort sperrt. Ein Bilder-Ordner braucht kein PHP; "
                   "eine eingeschleuste Hintertür dort läuft dann nicht mehr. Danach prüft das Programm mit zwei harmlosen Testdateien (eine .txt, eine .php) über https, "
                   "ob die Sperre wirkt und Bilder weiter ausgeliefert werden. Wirkt sie nicht oder macht sie Fehler, wird sofort der alte Stand hergestellt.",
        "warning": "Gilt nur für Apache (und kompatible Server mit .htaccess); bei nginx hat die Datei keine Wirkung, das erkennt der Test und stellt zurück. "
                   "Braucht eine Erweiterung ausnahmsweise PHP in diesem Ordner, funktioniert sie danach nicht mehr. Die Testdateien werden nach dem Test wieder gelöscht. "
                   "Die Sperre ersetzt nicht das Entfernen vorhandener Hintertüren und das Schließen der Einbruchstelle.",
        "risk": "mittel", "backup": False, "needs_php": False,
        "undo": "Die alte .htaccess liegt als htaccess.vorher im Sicherungsordner auf dem Server (~/claudia-sicherung-htaccess-<datum>); rueckgaengig.txt dort nennt den Befehl. "
                "War vorher keine .htaccess da, genügt es, die Datei zu löschen.",
    },
    "wp_update": {
        "title": "WordPress, Plugins und Themes aktualisieren",
        "summary": "Legt zuerst eine Sicherung an (Datenbank und Dateien), prüft sie, und führt dann die Aktualisierung mit WP-CLI aus (core update, plugin update --all, theme update --all). "
                   "Danach werden die Kern-Dateien gegen die offiziellen Prüfsummen geprüft.",
        "warning": "ACHTUNG: Updates verändern viele Dateien und können Seiten, Plugins oder Layouts brechen, vor allem bei neuen Hauptversionen. Die Sicherung wird vorher geprüft; "
                   "wenn sie nicht gelingt, passiert nichts. Kostenpflichtige Plugins mit eigenem Lizenzschlüssel werden von WP-CLI nur aktualisiert, wenn der Hersteller es zulässt.",
        "risk": "hoch", "backup": True, "needs_php": True,
        "undo": "Sicherung zurückspielen: Datenbank (db.sql.gz) per phpMyAdmin importieren, Dateien (dateien.tgz) im WordPress-Ordner entpacken.",
    },
    "joomla_core_reinstall": {
        "title": "Joomla-Kerndateien neu einspielen",
        "summary": "Ersetzt genau die Kerndateien, die der Test 'Joomla-Kern gegen Original prüfen' als verändert oder fehlend gemeldet hat, durch das Original derselben Joomla-Version. "
                   "Das Original-Paket wird auf diesem Computer geladen und gegen die veröffentlichte Prüfsumme geprüft; zum Server geht nur ein kleines ZIP mit den betroffenen Dateien. "
                   "Unbekannte zusätzliche Dateien, die configuration.php, images, Erweiterungen und Sprachdateien werden nicht angefasst.",
        "warning": "Die Seite ist während des Kopierens kurz nicht erreichbar. Vorher wird eine Sicherung (Datenbank und Dateien) angelegt und geprüft. Danach werden alle ersetzten Dateien per Prüfsumme kontrolliert. "
                   "Wurde der Kern durch einen Einbruch verändert, ist die Hintertür damit nur dort beseitigt: Prüfe danach weiter die Meldungen zu Hintertüren, Erweiterungen und Datenbank.",
        "risk": "mittel", "backup": True, "needs_php": False,
        "undo": "Sicherung zurückspielen: Dateien (dateien.tgz) im Joomla-Ordner entpacken.",
    },
    "wp_core_reinstall": {
        "title": "WordPress-Kerndateien neu installieren",
        "summary": "Lädt die Kerndateien derselben WordPress-Version neu herunter und überschreibt wp-admin, wp-includes und die Dateien im Hauptordner (WP-CLI: core download --force --skip-content). "
                   "wp-content (Plugins, Themes, Uploads) und die wp-config.php bleiben unberührt. Zusätzliche, unbekannte Dateien in wp-admin/wp-includes werden dabei NICHT gelöscht, sie stehen im Test 'WordPress-Kern gegen Original prüfen'.",
        "warning": "Die Seite ist während des Kopierens kurz nicht erreichbar. Vorher wird eine Sicherung (Datenbank und Dateien) angelegt und geprüft. Nach dem Kopieren werden die Prüfsummen kontrolliert.",
        "risk": "mittel", "backup": True, "needs_php": True,
        "undo": "Sicherung zurückspielen: Dateien (dateien.tgz) im WordPress-Ordner entpacken.",
    },
    "wp_fix_registration": {
        "title": "Gefährliche Registrierungs-Einstellung zurücksetzen",
        "summary": "Setzt in der Datenbank 'Jeder kann sich registrieren' auf aus und die Standardrolle neuer Benutzer auf 'Abonnent' (Tabelle options: users_can_register, default_role).",
        "warning": "Gelöscht wird nichts, nur zwei Werte geändert. Vorher wird die Tabelle options gesichert und geprüft. Brauchst du die offene Registrierung bewusst, schalte sie danach im Dashboard "
                   "(Einstellungen -> Allgemein) mit der Rolle 'Abonnent' wieder ein.",
        "risk": "niedrig", "backup": False, "needs_php": False,
        "undo": "Sicherung options.sql.gz im Sicherungsordner auf dem Server per phpMyAdmin importieren, oder die Werte im Dashboard zurücksetzen.",
    },
    "wp_salts": {
        "title": "Schlüssel und Salts in der wp-config.php erneuern",
        "summary": "Ersetzt die acht Sicherheitsschlüssel (AUTH_KEY ... NONCE_SALT) durch neue Zufallswerte, die auf diesem PC erzeugt werden. Alle angemeldeten Benutzer (auch ein Angreifer) werden damit abgemeldet.",
        "warning": "Alle müssen sich danach neu anmelden. Vorher wird eine Kopie der wp-config.php angelegt; die Rechte der Datei bleiben unverändert. Die Datenbank-Zugangsdaten werden nicht angefasst.",
        "risk": "niedrig", "backup": False, "needs_php": False,
        "undo": "Kopie wp-config.php im Sicherungsordner auf dem Server (~/claudia-sicherung-wpconfig-<datum>) zurückkopieren.",
    },
    "wp_disallow_edit": {
        "title": "Dateibearbeitung im Dashboard sperren",
        "summary": "Trägt define('DISALLOW_FILE_EDIT', true); in die wp-config.php ein. Danach gibt es im Dashboard keinen Theme-/Plugin-Editor mehr. Ein übernommenes Administrator-Konto kann so keinen PHP-Code mehr einschleusen.",
        "warning": "Wer den Editor bisher nutzt, muss Änderungen künftig per SFTP machen. Vorher wird eine Kopie der wp-config.php angelegt.",
        "risk": "niedrig", "backup": False, "needs_php": False,
        "undo": "Kopie wp-config.php im Sicherungsordner auf dem Server (~/claudia-sicherung-wpconfig-<datum>) zurückkopieren, oder die Zeile entfernen.",
    },
    "block_users": {
        "title": "Verdächtige Benutzerkonten sperren",
        "summary": "Sperrt die Konten, die du in der Liste ausgewählt hast (neu angelegte oder nie benutzte Administratoren). Joomla: Das Konto wird auf 'gesperrt' gesetzt. "
                   "WordPress kennt keine Sperre: dort werden alle Rollen entzogen und das Passwort wird entwertet. In beiden Fällen werden die angemeldeten Sitzungen des Kontos beendet. Es wird nichts gelöscht.",
        "warning": "Wähle nur Konten, die du nicht kennst. Der letzte aktive Administrator bzw. Super User kann nicht gesperrt werden, damit du nicht ausgesperrt wirst. "
                   "Vorher werden die Benutzertabellen gesichert und geprüft. Ein Passwortwechsel allein beendet die Sitzung eines Angreifers nicht, das Sperren schon.",
        "risk": "mittel", "backup": False, "needs_php": False, "pick": True,
        "undo": "Joomla: Datei rueckgaengig.sql im Sicherungsordner enthält die genauen Befehle (UPDATE ... SET block = 0). WordPress: Sicherung benutzer.sql.gz im Sicherungsordner per phpMyAdmin importieren "
                "(stellt Rollen und Passwörter wieder her, überschreibt aber auch spätere Änderungen an diesen beiden Tabellen).",
    },
    "revoke_tokens": {
        "title": "API-Tokens und Anwendungs-Passwörter widerrufen",
        "summary": "Löscht bei den ausgewählten Benutzern die Dauerzugänge, die ein Passwortwechsel nicht beendet: bei Joomla den API-Token, bei WordPress die Anwendungs-Passwörter.",
        "warning": "Dienste, die diesen Zugang nutzen (Apps, Schnittstellen, Automatisierungen), verlieren den Zugriff. Du kannst später neue anlegen. Vorher wird die betroffene Tabelle gesichert und geprüft.",
        "risk": "mittel", "backup": False, "needs_php": False, "pick": True,
        "undo": "Sicherung (benutzerprofile.sql.gz bzw. benutzerdaten.sql.gz im Sicherungsordner) per phpMyAdmin importieren. Besser: neuen Zugang im Backend/Profil anlegen.",
    },
    "end_sessions": {
        "title": "Alle angemeldeten Sitzungen beenden",
        "summary": "Beendet alle Anmeldungen auf der Seite, auch die eines Angreifers, der ein Passwort oder ein Cookie erbeutet hat. Joomla: Tabelle der Sitzungen leeren. WordPress: gespeicherte Sitzungen aller Benutzer löschen.",
        "warning": "Auch DU und alle anderen Benutzer werden abgemeldet und müssen sich neu anmelden. Das ist der Sinn der Aktion. Danach unbedingt die Passwörter ändern. "
                   "Die Sitzungen sind kurzlebig und werden nicht gesichert.",
        "risk": "niedrig", "backup": False, "needs_php": False,
        "undo": "Nicht nötig: Du meldest dich einfach neu an.",
    },
    "deactivate_extension": {
        "title": "Verwundbare Erweiterung ausschalten",
        "summary": "Schaltet die ausgewählten Erweiterungen mit bekannter Sicherheitslücke in der Datenbank aus (Joomla). Die Dateien bleiben liegen und lassen sich später wieder einschalten. "
                   "Das ist die schnelle Notlösung, bis ein Update verfügbar ist.",
        "warning": "Funktionen der Erweiterung fallen aus (Seiten, Formulare, Module). Kern, Anmelde- und Zwei-Faktor-Erweiterungen und erkannte Sicherheits- und Sicherungs-Erweiterungen werden nie ausgeschaltet. "
                   "Eine ausgeschaltete Erweiterung mit Lücke liegt weiterhin als Datei da: Aktualisieren oder deinstallieren bleibt nötig.",
        "risk": "mittel", "backup": False, "needs_php": False, "pick": True,
        "undo": "Datei rueckgaengig.sql im Sicherungsordner enthält die genauen Befehle (UPDATE ... SET enabled = 1), oder im Backend unter System -> Verwalten -> Erweiterungen einschalten.",
    },
    "disable_api": {
        "title": "Joomla-API (Web-Services) abschalten",
        "summary": "Schaltet in der Datenbank die Plugins der Joomla-Programmierschnittstelle aus: alle Web-Services-Plugins, 'Benutzer - Joomla API-Token' und die API-Authentifizierung. "
                   "Danach nimmt die Seite keine Anfragen an /api mehr an. Tokens und Dateien bleiben unverändert.",
        "warning": "Wenn du die API nutzt (Apps, Anbindungen an andere Systeme, Headless-Betrieb), funktionieren diese danach nicht mehr. Normale Seiten und das Backend sind nicht betroffen. "
                   "Vorher wird die Tabelle extensions gesichert und geprüft, die genauen Rückgängig-Befehle werden als Datei gespeichert. Gelöscht wird nichts.",
        "risk": "mittel", "backup": False, "needs_php": False,
        "undo": "Datei rueckgaengig.sql im Sicherungsordner enthält die genauen Befehle (UPDATE ... SET enabled = 1), oder im Backend unter System -> Verwalten -> Plugins die Plugins wieder einschalten.",
    },
    "wp_deactivate_plugin": {
        "title": "Verwundbares Plugin ausschalten",
        "summary": "Schaltet die ausgewählten Plugins mit bekannter Sicherheitslücke mit WP-CLI aus ('wp plugin deactivate'). Die Dateien bleiben liegen. Das ist die schnelle Notlösung, bis ein Update verfügbar ist.",
        "warning": "Funktionen des Plugins fallen aus. Erkannte Sicherheits- und Sicherungs-Plugins werden nie ausgeschaltet. Vorher wird die Tabelle options (dort steht die Liste der aktiven Plugins) gesichert und geprüft. "
                   "Ein ausgeschaltetes Plugin mit Lücke ist als Datei weiter angreifbar: Aktualisieren oder löschen bleibt nötig.",
        "risk": "mittel", "backup": False, "needs_php": True, "pick": True,
        "undo": "Datei rueckgaengig.txt im Sicherungsordner enthält die genauen Befehle (wp plugin activate ...), oder im Dashboard unter Plugins einschalten.",
    },
    "install_security": {
        "title": "Sicherheits-Erweiterung installieren",
        "summary": "Installiert die Sicherheits-Erweiterung, die du unten auswählst (Firewall und Scanner). WordPress: aus dem offiziellen Plugin-Verzeichnis wordpress.org mit WP-CLI, danach wird sie eingeschaltet "
                   "und gegen die Prüfsummen von wordpress.org kontrolliert. Joomla: nur kostenlose Erweiterungen, deren Hersteller eine öffentliche Update-Adresse (https) anbietet, "
                   "mit Joomlas eigenem Befehl (extension:install). Kostenpflichtige Erweiterungen bekommst du nur über den Link zur Store-Seite.",
        "warning": "Eine neue Erweiterung verändert Dateien und Datenbank und kann Seiten verlangsamen oder in seltenen Fällen legitimen Verkehr blockieren (z. B. wenn deine eigene IP gesperrt wird). "
                   "Vorher wird eine Sicherung (Datenbank und Dateien) angelegt und geprüft. Installiere nur EINE Firewall. Die Einrichtung (Regeln, E-Mail-Benachrichtigung, Lizenz) machst du danach im Backend.",
        "risk": "mittel", "backup": True, "needs_php": True,
        "undo": "Die Erweiterung im Backend deinstallieren (Joomla: System -> Verwalten -> Erweiterungen; WordPress: Plugins -> Deaktivieren und Löschen) oder die Sicherung zurückspielen: Datenbank (db.sql.gz) per phpMyAdmin importieren, Dateien (dateien.tgz) entpacken.",
    },
    "install_backup": {
        "title": "Sicherungs-Erweiterung installieren",
        "summary": "Installiert die Sicherungs-Erweiterung, die du unten auswählst. WordPress: aus dem offiziellen Plugin-Verzeichnis wordpress.org mit WP-CLI, danach wird sie eingeschaltet "
                   "und gegen die Prüfsummen von wordpress.org kontrolliert. Joomla: nur kostenlose Erweiterungen, deren Hersteller eine öffentliche Update-Adresse (https) anbietet, "
                   "mit Joomlas eigenem Befehl (extension:install). Sonst bekommst du den Link zur Store-Seite (Joomla Extensions Directory) mit Anleitung.",
        "warning": "Eine neue Erweiterung verändert Dateien und Datenbank. Sie legt noch keine Sicherung an: Die Einrichtung (Zeitplan, Speicherort, Aufbewahrung) machst du danach im Backend. "
                   "Lege die Sicherungen außerhalb des Webspaces oder in einem Cloud-Speicher ab und probiere die Wiederherstellung einmal aus. Vorher wird eine Sicherung (Datenbank und Dateien) angelegt und geprüft.",
        "risk": "mittel", "backup": True, "needs_php": True,
        "undo": "Die Erweiterung im Backend deinstallieren (Joomla: System -> Verwalten -> Erweiterungen; WordPress: Plugins -> Deaktivieren und Löschen) oder die Sicherung zurückspielen: Datenbank (db.sql.gz) per phpMyAdmin importieren, Dateien (dateien.tgz) im Seitenordner entpacken.",
    },
    "clear_cache": {
        "title": "Joomla-Cache leeren",
        "summary": "Führt 'cache:clean' aus. Joomla baut den Zwischenspeicher selbst neu auf.",
        "warning": "Die Seite ist kurz etwas langsamer, bis der Cache wieder gefüllt ist.",
        "risk": "niedrig", "backup": False, "needs_php": True,
        "undo": "Nicht nötig.",
    },
}

# Härtung per .htaccess im Hauptordner (2.4.1): je ein eigener, klar markierter Block; Vorschau, Sicherung, Wirkungstest per Abruf, Rückweg.
_HT_UNDO = ("Die alte .htaccess liegt als htaccess.vorher im Sicherungsordner auf dem Server (~/claudia-sicherung-htaccess-<datum>); rueckgaengig.txt dort nennt den Befehl. "
            "War vorher keine .htaccess da, genügt es, die Datei zu löschen. Alternativ den Block von der Zeile '# CLAUDIA: ...' bis '# Ende CLAUDIA: ...' löschen.")
_HT_APACHE = "Gilt nur für Apache (und kompatible Server mit .htaccess); bei nginx hat der Block keine Wirkung, das erkennt der Test und das Programm stellt zurück. "
HARDEN_ACTIONS: Dict[str, Dict[str, Any]] = {
    "harden_headers": {
        "title": "Sicherheits-Header setzen",
        "summary": "Ergänzt die .htaccess im Hauptordner um einen eigenen Block, der die fehlenden einfachen Schutz-Header setzt: X-Content-Type-Options: nosniff (Browser erraten keine Dateitypen), "
                   "X-Frame-Options: SAMEORIGIN (fremde Seiten können deine Seite nicht in einen Rahmen laden) und Referrer-Policy: strict-origin-when-cross-origin. Gesetzt werden nur die Header, die laut Prüfung fehlen. "
                   "Danach ruft das Programm die Startseite einmal ab und prüft, dass die Header ankommen und die Seite weiter ausgeliefert wird; sonst wird sofort der alte Stand hergestellt.",
        "warning": _HT_APACHE + "SAMEORIGIN verhindert, dass andere Seiten deine Seite einbetten; nutzt du eine Einbettung bewusst (z. B. in einem Portal), funktioniert sie danach nicht mehr. "
                   "Die Content-Security-Policy wird nicht gesetzt (zu aufwendig, kann Seiten brechen).",
        "risk": "mittel", "backup": False, "needs_php": False,
        "undo": _HT_UNDO,
    },
    "harden_hsts": {
        "title": "HSTS aktivieren (Browser erzwingen https)",
        "summary": "Setzt den Header Strict-Transport-Security mit einer KURZEN Laufzeit von 7 Tagen (max-age=604800), ohne Unterdomains und ohne Preload-Liste. Browser, die ihn einmal gesehen haben, rufen deine Seite danach nur noch verschlüsselt auf. "
                   "Das Programm bietet das nur an, wenn die Seite über https erreichbar ist und das Zertifikat gültig ist, und prüft nach dem Schreiben, dass der Header ankommt.",
        "warning": "NICHT VOLLSTÄNDIG RÜCKGÄNGIG ZU MACHEN: Entfernst du den Header später wieder, merken sich die Browser, die ihn gesehen haben, die Vorgabe noch bis zu 7 Tage. "
                   "In dieser Zeit sehen Besucher bei einem abgelaufenen oder falschen Zertifikat eine Fehlerseite ohne Möglichkeit, sie zu umgehen, und ein Aufruf über http wird nicht mehr zugelassen. "
                   "Stelle vorher sicher, dass das Zertifikat sich automatisch erneuert und alle Unterseiten über https laufen. " + _HT_APACHE.strip(),
        "risk": "hoch", "backup": False, "needs_php": False, "irreversible": True,
        "undo": "Der Block kann wie bei den anderen Härtungen entfernt werden (htaccess.vorher bzw. Block löschen). Die Wirkung in den Browsern der Besucher endet aber erst nach der Laufzeit (7 Tage); sie lässt sich vom Server aus nicht zurückrufen.",
    },
    "harden_listing": {
        "title": "Ordnerlisten abschalten",
        "summary": "Ergänzt die .htaccess im Hauptordner um 'Options -Indexes'. Dann zeigt der Server für Ordner ohne Startdatei keine Dateiliste mehr an, sondern die Meldung 'Verboten'. "
                   "Das Programm bietet das an, wenn die Prüfung eine öffentliche Ordnerliste gefunden hat. Danach prüft es, dass die Startseite weiter ausgeliefert wird.",
        "warning": _HT_APACHE + "Erlaubt der Hoster keine Options-Anweisungen in der .htaccess, antwortet der Server mit einem Fehler; das erkennt der Test an der Startseite und das Programm stellt zurück. "
                   "Dass die Ordnerliste danach wirklich weg ist, prüft das Programm nicht einzeln: Wiederhole dazu die Prüfung 'Öffentlich abrufbare Dateien'.",
        "risk": "niedrig", "backup": False, "needs_php": False,
        "undo": _HT_UNDO,
    },
    "wp_block_xmlrpc": {
        "title": "XML-RPC von WordPress sperren",
        "summary": "Sperrt die Datei xmlrpc.php per .htaccess. Über sie werden Passwörter massenhaft durchprobiert und Server für Angriffe auf andere missbraucht. "
                   "Danach ruft das Programm xmlrpc.php einmal ab und prüft, dass sie gesperrt ist und die Startseite weiter funktioniert.",
        "warning": _HT_APACHE + "Nutzt du die WordPress-App fürs Handy, Jetpack oder ein Programm, das Beiträge über XML-RPC veröffentlicht, funktioniert das danach nicht mehr. "
                   "Der normale Anmeldebildschirm und die Arbeit im Dashboard sind nicht betroffen.",
        "risk": "niedrig", "backup": False, "needs_php": False,
        "undo": _HT_UNDO,
    },
}
HARDEN_ACTIONS["harden_perms"] = {
    "title": "Dateirechte auf Sollwerte setzen",
    "summary": "Setzt die Rechte auf die Sollwerte: Das Schreibrecht für die GRUPPE wird bei den gemeldeten Dateien und Ordnern entfernt (Dateien werden 644, Ordner 755, sofern sie sonst keine Sonderrechte hatten), "
               "und die Konfigurationsdatei (configuration.php bzw. wp-config.php) wird auf 440 gesetzt, wenn sie für alle lesbar ist. Es werden nur Einträge angefasst, die die Prüfung selbst gemeldet hat. "
               "Vorher werden die alten Rechte in rechte_vorher.txt festgehalten. Danach ruft das Programm die Startseite einmal ab; ist sie nicht mehr erreichbar, werden die alten Rechte sofort wiederhergestellt.",
    "warning": "Läuft PHP bei deinem Hoster unter einem anderen Konto als dem Besitzer der Dateien (selten, z. B. manche Apache-Einrichtungen), kann die Seite nach 440 ausfallen; das erkennt der Test an der Startseite und das Programm stellt die alten Rechte wieder her. "
               "Arbeitet eine Erweiterung oder ein Deploy-Werkzeug mit einem zweiten Konto in derselben Gruppe, kann es danach nicht mehr schreiben. Dateiinhalte ändern sich nicht.",
    "risk": "mittel", "backup": False, "needs_php": False,
    "undo": "Die alten Rechte stehen in rechte_vorher.txt im Sicherungsordner auf dem Server (~/claudia-sicherung-rechte-<datum>), je Zeile 'Rechte Pfad'. Zurück: chmod <Rechte> <Pfad>; das Programm macht das bei einem Fehler selbst.",
}
ACTIONS.update(HARDEN_ACTIONS)

# Empfohlene Reihenfolge, um eine infizierte Seite sicher zu bereinigen (Nummer, kurze Begründung "Warum jetzt?")
STEP_ORDER = ["backup_now", "fix_update_perms", "wp_remove_maintenance", "deactivate_extension", "wp_deactivate_plugin", "core_update", "wp_update", "update_extensions", "joomla_core_reinstall", "wp_core_reinstall", "remove_jce_profiles", "wp_fix_registration", "remove_db_code", "remove_shells", "block_php_uploads", "reset_htaccess", "clean_tmp",
              "block_users", "revoke_tokens", "disable_api", "end_sessions", "wp_salts", "wp_disallow_edit", "install_security", "install_backup", "harden_headers", "harden_listing", "wp_block_xmlrpc", "harden_hsts", "harden_perms", "fix_permissions", "clear_cache", "delete_old_backups"]
# Welche Sicherung eine Aktion vorher anlegt: voll = Datenbank und alle Dateien, gezielt = nur das, was verändert wird,
# protokoll = nur die alten Werte werden festgehalten, keine = nichts nötig (mit Grund). Steht in Vorschau, Katalog und MANIFEST.txt.
SICHERUNG: Dict[str, Tuple[str, str]] = {
    "backup_now": ("voll", "Voll: Das ist die Sicherung selbst, Datenbank und alle Dateien (ohne Bilder, Cache, tmp und Logs)."),
    "fix_permissions": ("protokoll", "Nur Protokoll: Die alten Rechte werden in rechte_vorher.txt festgehalten. Dateiinhalte ändern sich nicht und werden deshalb nicht gesichert."),
    "fix_update_perms": ("protokoll", "Nur Protokoll: Die alten Rechte werden in rechte_vorher.txt festgehalten. Dateiinhalte ändern sich nicht und werden deshalb nicht gesichert."),
    "wp_remove_maintenance": ("gezielt", "Gezielt: Nur die Datei .maintenance wird vorher kopiert."),
    "check_updates": ("keine", "Keine nötig: Die Aktion liest nur und ändert nichts."),
    "core_update": ("voll", "Voll: Datenbank und alle Dateien (ohne Bilder, Cache, tmp und Logs) werden vorher gesichert und geprüft."),
    "update_extensions": ("voll", "Voll: Datenbank und alle Dateien (ohne Bilder, Cache, tmp und Logs) werden vorher gesichert und geprüft."),
    "clean_tmp": ("gezielt", "Gezielt: Der Inhalt der Temp-Ordner wird vorher als tmp.tgz gesichert und geprüft."),
    "delete_old_backups": ("keine", "Keine nötig: Gelöscht werden nur alte Sicherungen des Programms. Eine Sicherung davon wäre sinnlos."),
    "remove_jce_profiles": ("gezielt", "Gezielt: Nur die Tabelle der JCE-Profile wird vorher gesichert."),
    "remove_shells": ("gezielt", "Gezielt: Die Dateien werden nicht gelöscht, sondern in den Quarantäne-Ordner verschoben; das ist zugleich die Sicherung. Die Liste mit Prüfsummen (QUARANTAENE.txt) wird vor dem Verschieben geschrieben, die Prüfsumme wird nach dem Verschieben verglichen. Bei einem anderen Dateisystem wird erst kopiert und geprüft, dann das Original entfernt."),
    "delete_quarantine": ("keine", "Keine nötig: Gelöscht wird nur schädlicher Inhalt in der Quarantäne, den das Programm selbst angelegt hat. Eine Sicherung davon wäre sinnlos; das Zurückholen einzelner Dateien ist der Rückweg davor."),
    "restore_quarantine": ("protokoll", "Nur Protokoll (ZURUECK.txt): Die Datei wird verschoben, nicht verändert. Vorher wird die Prüfsumme gegen die Liste geprüft, nachher noch einmal; bei Abweichung bricht die Aktion für diese Datei ab."),
    "remove_db_code": ("gezielt", "Gezielt: Der alte Wert jedes gewählten Eintrags wird als UPDATE-Befehl in rueckgaengig.sql gesichert (geprüft), bevor etwas geändert wird."),
    "reset_htaccess": ("gezielt", "Gezielt: Nur die .htaccess im Hauptordner wird vorher kopiert (htaccess.vorher), dazu rueckgaengig.txt."),
    "block_php_uploads": ("gezielt", "Gezielt: Nur die .htaccess im Bilder-Ordner wird vorher kopiert (htaccess.vorher), dazu rueckgaengig.txt."),
    "harden_perms": ("protokoll", "Nur Protokoll: Die alten Rechte werden in rechte_vorher.txt festgehalten. Dateiinhalte ändern sich nicht und werden deshalb nicht gesichert."),
    "wp_update": ("voll", "Voll: Datenbank und alle Dateien (ohne uploads, Cache und Logs) werden vorher gesichert und geprüft."),
    "harden_headers": ("gezielt", "Gezielt: Nur die .htaccess im Hauptordner wird vorher kopiert (htaccess.vorher), dazu rueckgaengig.txt."),
    "harden_hsts": ("gezielt", "Gezielt: Nur die .htaccess im Hauptordner wird vorher kopiert (htaccess.vorher), dazu rueckgaengig.txt."),
    "harden_listing": ("gezielt", "Gezielt: Nur die .htaccess im Hauptordner wird vorher kopiert (htaccess.vorher), dazu rueckgaengig.txt."),
    "wp_block_xmlrpc": ("gezielt", "Gezielt: Nur die .htaccess im Hauptordner wird vorher kopiert (htaccess.vorher), dazu rueckgaengig.txt."),
    "joomla_core_reinstall": ("voll", "Voll: Datenbank und alle Dateien (ohne Bilder, Cache, tmp und Logs) werden vorher gesichert und geprüft."),
    "wp_core_reinstall": ("voll", "Voll: Datenbank und alle Dateien (ohne uploads, Cache und Logs) werden vorher gesichert und geprüft."),
    "wp_fix_registration": ("gezielt", "Gezielt: Nur die Tabelle options wird vorher gesichert."),
    "wp_salts": ("gezielt", "Gezielt: Nur die wp-config.php wird vorher kopiert."),
    "wp_disallow_edit": ("gezielt", "Gezielt: Nur die wp-config.php wird vorher kopiert."),
    "install_security": ("voll", "Voll: Datenbank und alle Dateien (ohne uploads, Cache, tmp und Logs) werden vorher gesichert und geprüft."),
    "install_backup": ("voll", "Voll: Datenbank und alle Dateien (ohne uploads, Cache, tmp und Logs) werden vorher gesichert und geprüft."),
    "clear_cache": ("keine", "Keine nötig: Der Cache besteht nur aus Kopien, die Joomla selbst neu aufbaut."),
    "block_users": ("gezielt", "Gezielt: Nur die Benutzertabellen werden vorher gesichert (bei Joomla zusätzlich die Datei rueckgaengig.sql mit den alten Werten)."),
    "revoke_tokens": ("gezielt", "Gezielt: Nur die Tabelle mit den Tokens bzw. Anwendungs-Passwörtern wird vorher gesichert."),
    "end_sessions": ("keine", "Keine nötig: Sitzungen sind kurzlebig und werden bei der nächsten Anmeldung neu angelegt."),
    "disable_api": ("gezielt", "Gezielt: Nur die Tabelle extensions wird vorher gesichert, dazu die Datei rueckgaengig.sql."),
    "deactivate_extension": ("gezielt", "Gezielt: Nur die Tabelle extensions wird vorher gesichert, dazu die Datei rueckgaengig.sql mit den alten Werten."),
    "wp_deactivate_plugin": ("gezielt", "Gezielt: Nur die Tabelle options wird vorher gesichert, dazu die Datei rueckgaengig.txt mit den Befehlen zum Wiedereinschalten."),
}


def sicherung_info(aid: str) -> Dict[str, str]:
    art, text = SICHERUNG.get(aid, ("keine", ""))
    return {"art": art, "text": text}


_HDR_ITEM_KEYS = (("nosniff", "X-Content-Type-Options"), ("frame", "Schutz vor Einbettung"), ("referrer", "Referrer-Policy"), ("hsts", "HSTS"))
JOOMLA_ONLY = {"disable_api", "deactivate_extension", "check_updates", "core_update", "update_extensions", "remove_jce_profiles", "clear_cache", "joomla_core_reinstall"}
WP_ONLY = {"harden_listing", "wp_block_xmlrpc", "wp_deactivate_plugin", "wp_update", "wp_core_reinstall", "wp_fix_registration", "wp_salts", "wp_disallow_edit", "wp_remove_maintenance"}
# Zugeschnittene Texte der gemeinsamen Aktionen für WordPress
WP_ACTION_TEXT = {
    "backup_now": {"summary": "Legt eine Sicherung der Datenbank und aller Dateien (ohne wp-content/uploads, Cache, Upgrade-Ordner) im Home-Verzeichnis des Servers an und prüft sie. "
                              "Das ist dein Rückweg, falls bei den späteren Schritten etwas schiefgeht, und zugleich eine Kopie des jetzigen Zustands."},
    "remove_shells": {"title": "Hintertüren und PHP-Dateien in wp-content/uploads in Quarantäne verschieben",
                      "summary": "Verschiebt die Dateien, die der Test als Hintertür (Web-Shell) gemeldet hat und die eindeutig nicht zu WordPress, einem Plugin oder Theme gehören "
                                 "(in uploads, Cache, Upgrade, mu-plugins, lose Dateien im Plugin-Ordner, unbekannte Dateien im Kern), sowie die angehakten PHP-Dateien in wp-content/uploads "
                                 "in einen Quarantäne-Ordner außerhalb des Web-Ordners (~/claudia-quarantaene-<Datum>, Rechte 700). Nichts wird gelöscht; die Liste QUARANTAENE.txt hält je Datei Ursprungspfad, "
                                 "Rechte, Besitzer und Prüfsumme fest. Dateien, in die Schadcode nur eingefügt wurde (z. B. die functions.php eines Themes), fasst das Programm NICHT an - sie stehen unten als Handarbeit mit der genauen Zeile.",
                      "undo": "Aktion 'Dateien aus der Quarantäne zurückholen' (mit Vorschau; je Datei Abbruch, wenn am Ursprungsort schon etwas liegt). Von Hand: "
                              "mv -n -- ~/claudia-quarantaene-<Datum>/d/<Nr>.q <Seitenordner>/<Ursprungspfad laut QUARANTAENE.txt>. Vorsicht: Die Dateien sind schädlich, nur bei Bedarf und nicht im Browser öffnen."},
    "clean_tmp": {"summary": "Die Ordner %s sind nur Zwischenlager für Updates, Installationen und Zwischenspeicher. Alte Pakete und eingeschleuste Dateien liegen dort oft lange und sind ein beliebter Ablageort. Die Ordner selbst bleiben bestehen."},
}
STEP_WHY = {
    "deactivate_extension": "Solange die verwundbare Erweiterung läuft, kann der Angreifer nach dem Aufräumen zurückkommen. Ausschalten schließt die Tür sofort, auch wenn es noch kein Update gibt.",
    "wp_deactivate_plugin": "Solange das verwundbare Plugin läuft, kann der Angreifer nach dem Aufräumen zurückkommen. Ausschalten schließt die Tür sofort, auch wenn es noch kein Update gibt.",
    "block_users": "Ein vom Angreifer angelegtes Konto ist sein Dauerzugang. Es muss weg, bevor du Passwörter änderst, sonst legt er sich über dieses Konto einen neuen Zugang an.",
    "revoke_tokens": "Tokens und Anwendungs-Passwörter überleben jeden Passwortwechsel. Ohne Widerruf behält der Angreifer seinen Zugang.",
    "disable_api": "Die API ist ein zweiter Eingang neben dem Backend und arbeitet mit Tokens. Wer sie nicht braucht, schließt sie am besten ganz, nachdem du die Tokens widerrufen hast.",
    "end_sessions": "Erst wenn alle Sitzungen beendet sind, ist ein Passwortwechsel wirksam: Ein erbeutetes Cookie bleibt sonst gültig.",
    "fix_update_perms": "Ohne Schreibrecht kann ein Update die Dateien nicht ersetzen und bricht mittendrin ab. Das muss vor jedem Update stimmen.",
    "wp_remove_maintenance": "Solange die Datei liegt, zeigt die Seite 'Wartungsarbeiten' und weitere Updates werden verweigert.",
    "wp_update": "Erst die Einbruchstelle schließen. Veraltete Plugins sind bei WordPress der häufigste Einstieg; solange eines verwundbar ist, kann der Angreifer nach dem Aufräumen zurückkommen.",
    "joomla_core_reinstall": "Veränderte Kerndateien durch das Original ersetzen, bevor aufgeräumt wird. Erweiterungen, Bilder und die Konfiguration bleiben unberührt.",
    "wp_core_reinstall": "Veränderte Kerndateien durch das Original ersetzen, bevor aufgeräumt wird. Plugins, Themes und Uploads bleiben unberührt.",
    "wp_fix_registration": "Solange sich jeder als Administrator registrieren kann, entstehen nach dem Aufräumen sofort neue Konten.",
    "wp_salts": "Neue Schlüssel melden alle Anmeldungen ab - auch die eines Angreifers, der ein altes Anmelde-Cookie besitzt.",
    "wp_disallow_edit": "Ein gestohlenes Administrator-Konto könnte sonst über den Editor im Dashboard sofort neuen PHP-Code einfügen.",
    "backup_now": "Zuerst ein Rückweg: Falls bei einem späteren Schritt etwas schiefgeht, kannst du den jetzigen Stand wiederherstellen.",
    "core_update": "Erst die Einbruchstelle schließen. Solange Joomla oder eine Erweiterung verwundbar ist, kann der Angreifer nach dem Aufräumen zurückkommen.",
    "update_extensions": "Verwundbare Erweiterungen (z. B. JCE, Convert Forms) sind meist der Einstieg. Updates schließen die Lücke, bevor aufgeräumt wird.",
    "remove_jce_profiles": "Manipulierte JCE-Profile erlauben den Upload von PHP-Dateien. Sie müssen weg, bevor du Dateien entfernst, sonst entstehen neue.",
    "remove_shells": "Jetzt die Hintertüren aus dem Web-Bereich nehmen. Die Einbruchstelle ist zu, die Dateien werden nicht mehr neu eingeschleust. Sie liegen gesichert in der Quarantäne und lassen sich zurückholen.",
    "restore_quarantine": "Nur bei Bedarf: wenn eine Datei zu Unrecht in die Quarantäne kam.",
    "delete_quarantine": "Erst am Ende, wenn klar ist, dass keine Datei aus der Quarantäne zurückgeholt werden muss.",
    "remove_db_code": "Schadcode in der Datenbank wird auf jeder Seite ausgeliefert, auch wenn alle Dateien sauber sind. Das Entfernen nur der schädlichen Blöcke lässt den restlichen Inhalt unangetastet.",
    "reset_htaccess": "Eine manipulierte .htaccess leitet Besucher um oder lädt fremden Code vor jeder Seite. Die Standarddatei beseitigt das, ohne dass jede Zeile von Hand gesucht werden muss; harmlose eigene Regeln bleiben auf Wunsch erhalten.",
    "block_php_uploads": "Erst nach dem Entfernen der Hintertüren: Die Sperre verhindert, dass ein neu eingeschleustes PHP im Bilder-Ordner ausgeführt wird, bis die Einbruchstelle sicher geschlossen ist.",
    "harden_headers": "Einfacher Zusatzschutz für Besucher. Erst nach dem Aufräumen, damit die .htaccess nur einmal angefasst werden muss und vorher sauber ist.",
    "harden_listing": "Eine öffentliche Ordnerliste verrät Angreifern, welche Dateien und Plugins vorhanden sind. Erst nach dem Aufräumen.",
    "wp_block_xmlrpc": "Schließt den bekanntesten Weg für Massenversuche an Passwörtern, wenn du XML-RPC nicht brauchst. Erst nach dem Aufräumen.",
    "harden_hsts": "Zuletzt und nur bewusst: HSTS bindet Browser für einige Tage an https. Vorher müssen alle anderen Schritte erledigt und das Zertifikat in Ordnung sein.",
    "harden_perms": "Schreibrecht für die Gruppe und lesbare Konfigurationsdateien sind auf geteilten Servern unnötig. Erst nach dem Aufräumen, damit nicht schon veränderte Dateien 'festgeschrieben' werden.",
    "clean_tmp": "Temp-Ordner sind beliebte Ablageorte für Schadcode. Erst nach den Hintertüren, damit nichts nachgeladen wird.",
    "install_security": "Ohne Firewall und Scanner bleibt die Seite zwischen dem Bekanntwerden einer Lücke und deinem Update ungeschützt. Erst nach dem Aufräumen, damit der Scanner einen sauberen Stand als Ausgangspunkt hat.",
    "install_backup": "Eine Sicherung, die außerhalb des Webspaces liegt, ist der Rückweg, wenn Hintertüren zurückkommen oder ein Update schiefgeht. Am besten sofort nach der Säuberung einrichten, damit der saubere Stand gesichert wird.",
    "fix_permissions": "Schreibrechte für 'alle' verhindern, dass fremde Konten auf dem Server Dateien verändern.",
    "clear_cache": "Zum Schluss, damit die Seite nicht mehr mit altem, evtl. manipuliertem Zwischenspeicher ausgeliefert wird.",
    "delete_old_backups": "Ganz zuletzt, erst wenn die Seite sauber läuft und die Prüfung nichts Kritisches mehr zeigt. Sicherungen enthalten Daten und Schadcode.",
}
OLD_ID = "".join(chr(c) for c in (106, 115, 99))      # Vorsilbe der Ordner früherer Versionen; sie bleiben auf dem Server les- und löschbar
BACKUP_NAME_RE = re.compile(r"^(?:claudia|" + OLD_ID + r")-sicherung-(?:[a-z]+-)?\d{8}-\d{6}(?:-[0-9a-f]{8})?$")

_PERM_RE = re.compile(r"^(\d{3,4})\s+(\./\S.*)$")


def php_choices(info: Dict[str, Any], manual: str = "") -> List[Dict[str, Any]]:
    """Wählbare PHP-Programme (aus dem Verbindungstest). Vorbelegt wird das, das zur angegebenen Version passt."""
    out: List[Dict[str, Any]] = []
    want = re.sub(r"[^0-9.]", "", manual or "")[:3]
    for c in info.get("php_candidates") or []:
        if not c.get("version") or not re.match(r"^[A-Za-z0-9._/+-]+$", c.get("name", "")):
            continue
        ver = c["version"].replace("PHP ", "")
        out.append({"name": c["name"], "version": ver, "default": bool(want and ver.startswith(want))})
    if info.get("php") and info.get("php_source") == "php":
        out.insert(0, {"name": "php", "version": info["php"].replace("PHP ", ""), "default": not any(o["default"] for o in out)})
    if out and not any(o["default"] for o in out) and len(out) == 1:
        out[0]["default"] = True
    return out


_JCE_ITEM_RE = re.compile(r"^#(\d+)\s+(.*?):")
_SHELL_ITEM_RE = re.compile(r"^(\./\S+?)\s+-\s+\d+:")
_UPLOAD_ITEM_RE = re.compile(r"^(\./)?((?:images|files|wp-content/uploads)/\S+?\.\w+)\s+\(")
WP_DELETE_RE = re.compile(r"^wp-content/(?:uploads|upgrade|mu-plugins|cache|backups?|backup-db|ai1wm-backups)/|^wp-content/plugins/[^/]+\.php$")


def wp_shell_deletable(path: str, extra_files=(), extra_prefixes=()) -> bool:
    """Darf das Programm diese gemeldete Datei bei WordPress löschen? Nur, wenn sie eindeutig nicht zu Kern, Plugin oder Theme gehört.
    Dateien mit eingefügtem Schadcode (z. B. functions.php) bleiben der Handarbeit überlassen - Löschen würde die Seite zerstören."""
    from .cms import WORDPRESS
    p = path.lstrip("./") if path.startswith("./") else path
    if p in extra_files or any(p.startswith(x) for x in extra_prefixes):
        return True
    if WP_DELETE_RE.match(p):
        return True
    return bool(re.match(r"^wp-[\w-]+\.php$", p)) and p.lower() not in WORDPRESS["core_files"]
PHP_EXT_FIND = r"\( -iname '*.php' -o -iname '*.php[0-9]' -o -iname '*.phtml' -o -iname '*.pht' -o -iname '*.phps' -o -iname '*.phar' -o -iname '*.php.*' \)"
SAFE_JCE_NAMES = {"default", "front end", "blogger", "mobile", "markdown"}
MAX_FILES = 300
# Aktionen, die Dateien auf dem Server ändern: Ein Dateiwächter (Sicherheits-Erweiterung, Hoster-Schutz) kann sie melden oder zurückdrehen
FILE_ACTIONS = ("remove_shells", "restore_quarantine", "delete_quarantine", "block_php_uploads", "reset_htaccess", "harden_perms", "harden_headers", "harden_hsts", "harden_listing", "wp_block_xmlrpc", "clean_tmp", "joomla_core_reinstall", "wp_core_reinstall", "wp_salts", "wp_disallow_edit", "wp_remove_maintenance")
FILEWATCH_HINT = ("Dateiwächter: Hat die Seite eine Sicherheits-Erweiterung oder der Hoster einen Schutz, der Dateien überwacht oder schreibschützt, kann er diese Änderung melden oder wieder zurückdrehen. "
                  "Das Programm prüft vorher, ob die Ordner beschreibbar sind, und bricht sonst ohne Änderung ab; einen Wächter selbst erkennt es nicht sicher. Schalte ihn bei Bedarf kurz aus.")
PHP_NAME_RE = re.compile(r"\.(?:php\d?|phtml|pht|phps|phar)(?:\.|$)", re.I)


SCAN_SCRIPT = r"""
echo '@@HOME'; printf '%s\n' "$HOME"
echo '@@TMP'
for d in tmp images/tmp wp-content/upgrade wp-content/cache; do
  if [ -d "$d" ] && [ ! -L "$d" ]; then
    n=$(find "$d" -mindepth 1 ! -name index.html ! -name .htaccess 2>/dev/null | wc -l)
    k=$(du -sk "$d" 2>/dev/null | cut -f1)
    p=$(find "$d" -type f \( -iname '*.php' -o -iname '*.php[0-9]' -o -iname '*.phtml' -o -iname '*.pht' -o -iname '*.phar' -o -iname '*.php.*' \) 2>/dev/null | wc -l)
    printf '%s\t%s\t%s\t%s\n' "$d" "$n" "$k" "$p"
  fi
done
echo '@@IMGTMP'
[ -d images ] && echo 'images_vorhanden'
[ -e images/tmp ] && echo 'images_tmp_vorhanden'
find images -maxdepth 4 -type d \( -iname tmp -o -iname temp -o -iname .tmp \) 2>/dev/null | head -10 | sed 's/^/KAND\t/'
echo '@@WPCLI'
for c in "$(command -v wp 2>/dev/null)" "$HOME/wp-cli.phar" "$HOME/bin/wp" "$HOME/.wp-cli/wp-cli.phar" "./wp-cli.phar"; do [ -n "$c" ] && [ -f "$c" ] && { echo "$c"; break; }; done
echo '@@BACKUPS'
for d in "$HOME"/claudia-sicherung-* "$HOME"/@OLD@-sicherung-*; do
  [ -d "$d" ] && [ ! -L "$d" ] || continue
  printf '%s\t%s\t%s\t' "$(basename "$d")" "$(stat -c %Y "$d" 2>/dev/null)" "$(du -sk "$d" 2>/dev/null | cut -f1)"
  ls -1 "$d" 2>/dev/null | head -8 | tr '\n' ','
  echo
done
echo '@@QUAR'
S=$(pwd -P); c=0
for d in "$HOME"/claudia-quarantaene-* "$HOME"/@OLD@-quarantaene-*; do
  [ -d "$d" ] && [ ! -L "$d" ] && [ -f "$d/QUARANTAENE.txt" ] || continue
  q=$(basename "$d")
  site=$(sed -n 's/^# Seitenordner: //p' "$d/QUARANTAENE.txt" | head -1)
  own=0; [ "$site" = "$S" ] && own=1
  printf 'DIR\t%s\t%s\t%s\t%s\t%s\t%s\n' "$q" "$(stat -c %Y "$d" 2>/dev/null)" "$site" "$(ls -1 "$d/d" 2>/dev/null | wc -l | tr -d ' ')" "$(du -sk -- "$d" 2>/dev/null | cut -f1)" "$own"
  [ "$site" = "$S" ] || continue
  while IFS=$'\t' read -r id sha size mode own mt origin; do
    case "$id" in ''|'#'*) continue;; esac
    [ -f "$d/d/$id.q" ] || continue
    c=$((c+1)); [ "$c" -gt 400 ] && break
    st=frei; { [ -e "$origin" ] || [ -L "$origin" ]; } && st=belegt
    printf 'E\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$q" "$id" "$size" "$mode" "$own" "$sha" "$st" "$origin"
  done < "$d/QUARANTAENE.txt"
done
echo '@@END'
"""
SCAN_SCRIPT = SCAN_SCRIPT.replace("@OLD@", OLD_ID)

QUAR_PREFIX = "claudia-quarantaene"
QUAR_NAME_RE = re.compile(r"^(?:claudia|" + OLD_ID + r")-quarantaene-\d{8}-\d{6}(?:-\d{1,2})?$")
QUAR_KEY_RE = re.compile(r"^((?:claudia|" + OLD_ID + r")-quarantaene-\d{8}-\d{6}(?:-\d{1,2})?)/(\d{4,6})$")
QUAR_LIST_NAME = "QUARANTAENE.txt"
TMP_DIRS_ALL = ("tmp", "images/tmp", "wp-content/upgrade", "wp-content/cache")
BACKUP_KINDS = {"wartung": "Kopie der .maintenance", "options": "WordPress-Optionen (Tabelle)", "wpconfig": "Kopie der wp-config.php", "tmp": "Inhalt von tmp", "jce": "JCE-Profile (Tabelle)", "dateien": "entfernte Schadcode-Dateien", "rechte": "Protokoll der Rechte-Änderung"}


def parse_scan(text: str) -> Dict[str, Any]:
    from .util import split_sections
    sec = split_sections(text or "")
    out: Dict[str, Any] = {"home": (lines_of(sec.get("HOME", "")) or [""])[0], "tmp": [], "backups": []}
    for ln in (sec.get("TMP", "") or "").splitlines():
        p = ln.split("\t")
        if len(p) >= 4 and p[0] in TMP_DIRS_ALL and p[1].strip().isdigit():
            out["tmp"].append({"dir": p[0], "count": int(p[1]), "kb": int(p[2] or 0) if p[2].strip().isdigit() else 0, "php": int(p[3] or 0) if p[3].strip().isdigit() else 0})
    it = sec.get("IMGTMP", "") or ""
    out["wpcli"] = (lines_of(sec.get("WPCLI", "")) or [""])[0].strip()
    out["images_exists"] = "images_vorhanden" in it
    out["images_tmp_exists"] = "images_tmp_vorhanden" in it
    out["tmp_candidates"] = [ln.split("\t", 1)[1].strip() for ln in it.splitlines() if ln.startswith("KAND\t")]
    for ln in (sec.get("BACKUPS", "") or "").splitlines():
        p = ln.split("\t")
        if len(p) >= 3 and BACKUP_NAME_RE.match(p[0]):
            m = re.match(r"^(?:claudia|" + OLD_ID + r")-sicherung-([a-z]+)-\d", p[0])
            kind = BACKUP_KINDS.get(m.group(1), m.group(1)) if m else "Vollsicherung (Datenbank + Dateien)"
            try:
                mt = int(p[1])
            except ValueError:
                mt = 0
            out["backups"].append({"name": p[0], "mtime": mt, "kb": int(p[2]) if p[2].strip().isdigit() else 0, "kind": kind,
                                   "malware": (not m) or m.group(1) in ("dateien", "tmp"),
                                   "files": [x for x in (p[3].split(",") if len(p) > 3 else []) if x.strip()]})
    out["backups"].sort(key=lambda b: b["mtime"], reverse=True)
    qmap: Dict[str, Dict[str, Any]] = {}
    for ln in (sec.get("QUAR", "") or "").splitlines():
        p = ln.split("\t")
        if p[0] == "DIR" and len(p) >= 3 and QUAR_NAME_RE.match(p[1]):
            qmap[p[1]] = {"name": p[1], "mtime": int(p[2]) if p[2].strip().isdigit() else 0, "site": p[3] if len(p) > 3 else "", "entries": [],
                          "count": int(p[4]) if len(p) > 4 and p[4].strip().isdigit() else 0, "kb": int(p[5]) if len(p) > 5 and p[5].strip().isdigit() else 0,
                          "own": len(p) > 6 and p[6].strip() == "1"}
        elif p[0] == "E" and len(p) >= 9 and p[1] in qmap and p[2].isdigit():
            origin = "\t".join(p[8:])
            if _safe_path(origin):
                qmap[p[1]]["entries"].append({"id": p[2], "size": int(p[3]) if p[3].strip().isdigit() else 0, "mode": p[4], "owner": p[5], "sha": p[6],
                                              "state": "belegt" if p[7] == "belegt" else "frei", "origin": origin})
    out["quarantines"] = sorted([q for q in qmap.values() if q["entries"]], key=lambda q: q["mtime"], reverse=True)
    # zum Löschen: alle Quarantäne-Ordner DIESER Seite (auch leere); die Einträge stehen nur bei Ordnern dieser Seite im Scan
    out["quarantine_dirs"] = sorted([q for q in qmap.values() if q["own"]], key=lambda q: q["mtime"], reverse=True)
    return out


def scan_server(runner: Runner, site_dir: str) -> Dict[str, Any]:
    """Liest (nur lesend), was es aufzuräumen gibt: gefüllte Temp-Ordner und alte Sicherungen des Programms."""
    try:
        r = runner.sh(site_dir, SCAN_SCRIPT, 90)
    except RunnerError:
        return {"home": "", "tmp": [], "backups": [], "error": "Server nicht erreichbar"}
    return parse_scan(r.out)


_PHP_FATAL_RE = re.compile(r"(Fatal error|Parse error|Uncaught [\w\\]+|Call to undefined|Class [\"'\\\w]+ not found|syntax error|Out of memory|Allowed memory size)", re.I)
_PHP_LOC_RE = re.compile(r"(?:in\s+|at\s+)?(/[^\s:]+\.php)(?:\s+on line\s+|:)(\d+)")


def php_problems(text: str) -> Dict[str, Any]:
    """Wertet PHP-Meldungen in der Ausgabe der Joomla-Kommandozeile aus. fatal = Abbruchgrund; warnings = nur Warnungen/Hinweise."""
    fatal: List[str] = []
    warn = 0
    for ln in (text or "").splitlines():
        low = ln.lower()
        if _PHP_FATAL_RE.search(ln):
            fatal.append(ln.strip()[:300])
        elif "undefined variable" in low or "undefined array key" in low or "deprecated" in low or low.lstrip().startswith(("warning", "php warning", "notice", "php notice", "php deprecated")):
            warn += 1
    return {"fatal": fatal[:3], "warnings": warn}


def php_problem_text(text: str, php: str = "") -> str:
    pp = php_problems(text)
    if not pp["fatal"]:
        return ""
    loc = _PHP_LOC_RE.search(pp["fatal"][0])
    return ("PHP meldet einen Programmfehler: %s%s. Das liegt im Programmcode von Joomla oder einer Erweiterung (oder an einer zu neuen PHP-Version), nicht an deiner Eingabe. "
            "Versuche ein anderes PHP-Programm aus der Liste (z. B. php-8.3 oder php-8.4)%s und prüfe, ob die genannte Datei verändert wurde."
            % (pp["fatal"][0], (" (Datei %s, Zeile %s)" % loc.groups()) if loc else "", (" statt %s" % php) if php else ""))


def parse_core_check(out: str, current: str) -> Optional[Dict[str, Any]]:
    """Wertet die Ausgabe von 'core:check-updates' aus. None = nicht eindeutig."""
    low = (out or "").lower()
    found = re.findall(r"\b\d+\.\d+\.\d+(?:\.\d+)?\b", out or "")
    newer = [v for v in found if current and joomla_vcmp(v, current) > 0]
    if newer and ("available" in low or "verf" in low or "new" in low or "update" in low):
        latest = newer[0]
        for v in newer:
            if joomla_vcmp(v, latest) > 0:
                latest = v
        return {"has_update": True, "latest": latest}
    if "latest joomla" in low or "up to date" in low or "no update" in low or "already" in low or "aktuell" in low:
        return {"has_update": False, "latest": current}
    return None


def _major(v: str) -> str:
    return (re.findall(r"\d+", v or "") or ["?"])[0]


def joomla_vcmp(a: str, b: str) -> int:
    from .util import vcmp
    return vcmp(a, b)


def available(results: List[Dict[str, Any]], info: Dict[str, Any], manual: str = "", update: Optional[Dict[str, Any]] = None,
              scan: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """Aktionen, die jetzt sinnvoll sind, samt Parametern.

    update: Ergebnis von 'Nach Updates suchen' ({"checked": bool, "has_update": bool|None, "latest": str}). Das Joomla-Update wird nur angeboten,
    wenn ein Update bekannt ist (laut Suche oder laut Hinweis aus der Prüfung 'Joomla ist älter als die neueste bekannte Version')."""
    update = update or {}
    scan = scan or {}
    cms = str((info or {}).get("cms") or "joomla")
    if cms in ("drupal", "typo3", "contao"):      # 2.8.0/2.10.0/2.11.0: Für Drupal, TYPO3 und Contao gibt es nur Prüfungen, keine Lösungen auf Knopfdruck (jede Aktion braucht eigene Tests und Freigabe)
        return []
    res = []
    wp_flags = {"update": False, "core": False, "salts": False, "edit": False, "reg": False}
    user_pick: List[Dict[str, Any]] = []
    token_pick: List[Dict[str, Any]] = []
    ext_pick: List[Dict[str, Any]] = []
    any_crit = False
    wp_extra_files: List[str] = []
    wp_extra_prefixes: List[str] = []
    wp_manual_files: List[str] = []
    perm_items: List[str] = []
    lock_items: List[str] = []
    maintenance = False
    jce_ids: List[int] = []
    jce_names: List[str] = []
    shell_files: List[str] = []
    core_fix: List[str] = []
    tmp_seen = False
    ht_root_bad = False
    dbcode_pick: List[Dict[str, Any]] = []
    images_php = False
    image_files: List[str] = []
    older_known = False
    sec_missing = False
    api_on = False
    backup_missing = False
    hdr_missing: List[str] = []
    hsts_missing = False
    cert_bad = False
    web_server = ""
    listing_public = False
    xmlrpc_active = False
    group_items: List[str] = []
    cfg_item = ""
    for r in results:
        for f in r.get("findings", []):
            title = f.get("title", "")
            items = f.get("items", []) or []
            sev = f.get("sev")
            if r.get("id") == "web_headers":
                if title.endswith("Sicherheits-Header fehlen"):
                    for i in items:
                        for key, lab in _HDR_ITEM_KEYS:
                            if isinstance(i, str) and i.startswith(lab) and key not in hdr_missing:
                                hdr_missing.append(key)
                    hsts_missing = "hsts" in hdr_missing
                    hdr_missing = [k for k in hdr_missing if k != "hsts"]
                if title.startswith("Server-Typ laut Antwort:"):
                    web_server = title.split(":", 1)[1].strip().lower()
                if sev in ("crit", "warn") and "ertifikat" in title:
                    cert_bad = True
            if r.get("id") == "perms" and sev == "info":
                if "für die Gruppe beschreibbar" in title:
                    group_items += [i for i in items if isinstance(i, str) and _PERM_RE.match(i) and i not in group_items]
                if "ist für alle lesbar" in title:
                    for i in items:
                        if isinstance(i, str) and _PERM_RE.match(i):
                            cfg_item = i
            if r.get("id") == "wp_exposure":
                if any(isinstance(i, str) and i.startswith("Ordnerliste ist öffentlich") for i in items):
                    listing_public = True
                if any(isinstance(i, str) and i.startswith("xmlrpc.php ist aktiv") for i in items):
                    xmlrpc_active = True
            if sev in ("warn", "crit") and r.get("id") in ("perms", "update_ready") and "beschreibbar" in title:
                perm_items += [i for i in items if _PERM_RE.match(i) and i not in perm_items]
            if sev in ("warn", "crit") and r.get("id") == "update_ready":
                if "ohne Schreibrecht für den Besitzer" in title:
                    lock_items += [i for i in items if _PERM_RE.match(i)]
                if title.startswith(".maintenance liegt"):
                    maintenance = True
            if r.get("id") == "joomla_core" and title.startswith("Kerndateien lassen sich aus dem Original neu einspielen"):
                core_fix = [i for i in items if isinstance(i, str)]
            if sev == "crit":
                any_crit = True
            if r.get("id") in ("db_users", "wp_db_users") and sev == "warn":
                if "angelegt" in title or "ohne jede Anmeldung" in title or "Administrator" in title:
                    user_pick += [x for x in pick_from_items(items, "u") if x["key"] not in {u["key"] for u in user_pick}]
                if "API-Token" in title or "Anwendungs-Passwörter" in title:
                    token_pick += [x for x in pick_from_items(items, "u") if x["key"] not in {u["key"] for u in token_pick}]
            if r.get("id") in ("extensions_fs", "wp_plugins") and sev in ("warn", "crit") and "Sicherheitslücke" in title:
                ext_pick += [x for x in pick_from_items(items, "p" if r.get("id") == "wp_plugins" else "e") if x["key"] not in {u["key"] for u in ext_pick}]
            if r.get("id") == "db_jce" and sev == "crit":
                for i in items:
                    m = _JCE_ITEM_RE.match(i)
                    if m and int(m.group(1)) not in jce_ids:
                        jce_ids.append(int(m.group(1)))
                        jce_names.append(m.group(2).strip())
            if r.get("id") == "webshells" and sev == "crit" and "Hintert" in title:
                for i in items:
                    m = _SHELL_ITEM_RE.match(i)
                    if m and not m.group(1).startswith("./tmp/") and m.group(1) not in shell_files:
                        shell_files.append(m.group(1))
            if cms == "wordpress":
                rid = r.get("id")
                if rid == "wp_core" and sev in ("warn", "crit"):
                    if "weichen vom Original ab" in title or "fehlen" in title:
                        wp_flags["core"] = True
                    if "unbekannte Datei" in title:
                        wp_extra_files += [i for i in items if isinstance(i, str)]
                if rid == "wp_plugins" and sev in ("warn", "crit"):
                    if "Sicherheitslücke" in title:
                        wp_flags["update"] = True
                    if "ohne Plugin-Beschreibung" in title:
                        wp_extra_prefixes += [re.sub(r"\s+\(.*$", "", i).lstrip("./") for i in items if isinstance(i, str)]
                if rid == "wp_plugins_online" and sev in ("warn", "crit") and ("neuere Version" in title or "UNSICHER" in title or "veraltet" in title):
                    wp_flags["update"] = True
                if rid == "wp_info" and title.startswith("WordPress ist älter"):
                    wp_flags["update"] = True
                if rid == "wp_config" and title.startswith("Schlüssel und Salts"):
                    wp_flags["salts"] = True
                if rid == "wp_config" and title.startswith("Dateien lassen sich im Dashboard bearbeiten"):
                    wp_flags["edit"] = True
                if rid == "wp_db_options" and (title.startswith("Jeder darf sich als Administrator") or title.startswith("Offene Registrierung mit der Rolle")):
                    wp_flags["reg"] = True
            if sev in ("warn", "crit"):
                for i in items:
                    t = i.lstrip("./") if isinstance(i, str) else ""
                    if r.get("id") == "htaccess" and isinstance(i, str) and i.startswith("./.htaccess Zeile "):
                        ht_root_bad = True
                    if r.get("id") in ("db_content", "wp_db_content") and isinstance(i, str) and not i.startswith(" "):
                        mm = DBFIND_RE.match(i)
                        if mm and (mm.group(1), mm.group(4)) in _dbcode_targets(cms) and ("x:%s.%s:%s" % (mm.group(1), mm.group(4), mm.group(2))) not in {c["key"] for c in dbcode_pick}:
                            dbcode_pick.append({"key": "x:%s.%s:%s" % (mm.group(1), mm.group(4), mm.group(2)), "label": i[:300], "pre": False})
                    if t.startswith("tmp/"):
                        tmp_seen = True
                    m = _UPLOAD_ITEM_RE.match(i) if isinstance(i, str) else None
                    if m and m.group(2).startswith("images/") and re.search(r"\.(php\d?|phtml|pht|phps|phar)\b", m.group(2), re.I):
                        images_php = True
                    up = "wp-content/uploads/" if cms == "wordpress" else "images/"
                    if m and m.group(2).startswith(up) and PHP_NAME_RE.search(m.group(2)) and ("./" + m.group(2)) not in image_files:
                        image_files.append("./" + m.group(2))
            if title.startswith("Joomla ist älter als die neueste bekannte Version"):
                older_known = True
            if r.get("id") == "security_ext" and (title.startswith("Keine Sicherheits-Erweiterung") or title.startswith("Kein Sicherheits-Plugin")):
                sec_missing = True
            if r.get("id") == "joomla_api" and (title.startswith("Web-Services aktiv") or title.endswith("API-Zugang aktiv")):
                api_on = True
            if r.get("id") == "backup_tool" and title.startswith("Kein Sicherungs-Tool"):
                backup_missing = True
    choices = php_choices(info, manual)
    wpcli = str(scan.get("wpcli") or "")
    if cms == "wordpress":
        deletable = [f for f in shell_files if wp_shell_deletable(f, wp_extra_files, wp_extra_prefixes)]
        wp_manual_files = [f for f in shell_files if f not in deletable]
        shell_files = deletable
    for aid, a in ACTIONS.items():
        if (cms == "wordpress" and aid in JOOMLA_ONLY) or (cms != "wordpress" and aid in WP_ONLY):
            continue
        d = {"id": aid, **{k: a[k] for k in ("title", "summary", "warning", "risk", "backup", "needs_php", "undo")}, "sicherung": sicherung_info(aid), "params": {}, "reason": ""}
        if aid in FILE_ACTIONS:
            d["warning"] = (d["warning"] + " " + FILEWATCH_HINT).strip()
        if cms == "wordpress" and aid in WP_ACTION_TEXT:
            for k, v in WP_ACTION_TEXT[aid].items():
                if k in d and "%s" not in v:
                    d[k] = v
        if aid == "wp_update":
            if not wp_flags["update"]:
                continue
            d["params"] = {"wpcli": wpcli}
        elif aid == "joomla_core_reinstall":
            if not core_fix:
                continue
            d["params"] = {"version": str((info or {}).get("joomla") or ""), "files": core_fix}
        elif aid == "wp_core_reinstall":
            if not wp_flags["core"]:
                continue
            d["params"] = {"wpcli": wpcli, "version": str((info or {}).get("wordpress") or "")}
        elif aid == "wp_salts":
            if not wp_flags["salts"]:
                continue
        elif aid == "wp_disallow_edit":
            if not wp_flags["edit"]:
                continue
        elif aid == "wp_fix_registration":
            if not wp_flags["reg"]:
                continue
        elif aid == "fix_update_perms":
            files = [_PERM_RE.match(i).group(2) for i in lock_items][:CHMOD_MAX]
            if not files:
                continue
            d["params"] = {"files": files}
        elif aid == "wp_remove_maintenance":
            if not maintenance:
                continue
        elif aid == "fix_permissions":
            files = [_PERM_RE.match(i).group(2) for i in perm_items][:CHMOD_MAX]
            if not files:
                continue
            d["params"] = {"files": files}
        elif aid == "core_update":
            if update.get("checked"):
                if update.get("has_update") is not True:
                    continue
                d["title"] = "Joomla auf Version %s aktualisieren" % update.get("latest", "") if update.get("latest") else d["title"]
            elif not older_known:
                continue
        elif aid == "update_extensions":
            ups = [u for u in (update.get("ext_updates") or []) if not u.get("needs_key")]
            if not ups:
                continue
            d["params"] = {"updates": [{"uid": u["uid"], "name": u["name"], "old": u.get("old_version", ""), "new": u["new_version"],
                                        "type": u.get("type", ""), "source": re.sub(r"^https://([^/]+)/.*$", r"\1", u.get("detailsurl", "")),
                                        "major": _major(u.get("old_version", "")) != _major(u["new_version"]) and bool(u.get("old_version"))} for u in ups]}
        elif aid in ("install_security", "install_backup"):
            if not (sec_missing if aid == "install_security" else backup_missing):
                continue
            tools = security_choices(cms, wpcli, _tool_kind(aid))
            d["params"] = {"cms": "wordpress" if cms == "wordpress" else "joomla", "tools": tools, "wpcli": wpcli}
            if not any(t["installable"] for t in tools):
                d["reason"] = ("Auf dem Server wurde WP-CLI nicht gefunden. Installiere das Plugin im Dashboard unter Plugins -> Installieren (Suche nach dem Namen) oder lade wp-cli.phar von wp-cli.org per SFTP in dein Home-Verzeichnis hoch und suche erneut."
                               if cms == "wordpress" else
                               "Für Joomla ist keine kostenlose Erweiterung mit geprüfter öffentlicher Download-Adresse hinterlegt. Öffne die Store-Seite (Link), lade die Erweiterung dort und installiere sie "
                               "im Backend unter System -> Installieren -> Erweiterungen.")
        elif aid in ("block_users", "revoke_tokens"):
            cand = user_pick if aid == "block_users" else token_pick
            if not cand:
                continue
            d["params"] = {"cms": "wordpress" if cms == "wordpress" else "joomla", "pick": cand[:100]}
        elif aid == "disable_api":
            if not api_on:
                continue
            d["params"] = {"cms": "joomla"}
        elif aid == "end_sessions":
            if not (user_pick or token_pick or any_crit):
                continue
            d["params"] = {"cms": "wordpress" if cms == "wordpress" else "joomla"}
        elif aid in ("deactivate_extension", "wp_deactivate_plugin"):
            cand = [x for x in ext_pick if x["key"].startswith("p:" if aid == "wp_deactivate_plugin" else "e:")]
            if not cand:
                continue
            d["params"] = {"pick": cand[:100], "wpcli": wpcli}
        elif aid == "backup_now":
            if not (jce_ids or shell_files or images_php or tmp_seen or update.get("has_update") or update.get("ext_updates") or any(wp_flags.values())):
                continue
        elif aid == "clean_tmp":
            dirs = [t for t in (scan.get("tmp") or []) if t["count"] > 0]
            if scan.get("tmp") is not None and scan:
                if not dirs:
                    continue
            elif not tmp_seen:
                continue
            names = [t["dir"] for t in dirs] or ["tmp"]
            d["params"] = {"dirs": names, "info": dirs}
            if scan:
                d["params"]["images_tmp_exists"] = bool(scan.get("images_tmp_exists"))
                d["params"]["candidates"] = [c for c in scan.get("tmp_candidates", []) if c not in ("images/tmp",)]
            d["title"] = "Temp-Ordner leeren (%s)" % " und ".join(names)
            d["summary"] = (WP_ACTION_TEXT["clean_tmp"]["summary"] % " und ".join(names)) if cms == "wordpress" else ("Die Ordner %s sind nur Zwischenlager für Installationen, Updates und Uploads. Alte Installationspakete, entpackte Erweiterungen und "
                            "eingeschleuste Dateien liegen dort oft jahrelang und sind für Angreifer ein beliebter Ablageort. Die Ordner selbst bleiben bestehen."
                            % " und ".join(names))
        elif aid == "delete_old_backups":
            if not scan.get("backups") and not any(not l.get("newest") for l in scan.get("local_logs") or []):
                continue
            d["params"] = {"backups": scan.get("backups") or [], "logs": scan.get("local_logs") or [], "log_dir": scan.get("log_dir") or ""}
        elif aid == "remove_db_code":
            if not dbcode_pick:
                continue
            d["params"] = {"cms": "wordpress" if cms == "wordpress" else "joomla", "pick": dbcode_pick[:100]}
        elif aid == "reset_htaccess":
            if not ht_root_bad:
                continue
            d["params"] = {"cms": "wordpress" if cms == "wordpress" else "joomla", "version": str((info or {}).get("joomla") or "")}
        elif aid == "block_php_uploads":
            if not (shell_files or images_php or image_files):
                continue
            d["params"] = {"upload_dir": "wp-content/uploads" if cms == "wordpress" else "images"}
        elif aid == "harden_perms":
            cfg = _PERM_RE.match(cfg_item).group(2) if cfg_item else ""
            files = ([cfg] if cfg else []) + [_PERM_RE.match(i).group(2) for i in group_items if _PERM_RE.match(i).group(2) != cfg]
            files = files[:CHMOD_MAX]
            if not files:
                continue
            d["params"] = {"files": files, "config": cfg}
            d["irreversible"] = False
        elif aid in HARDEN_ACTIONS:
            if web_server in ("nginx", "iis"):
                continue                      # liest keine .htaccess; die Aktion würde nichts bewirken
            if aid == "harden_headers":
                if not hdr_missing:
                    continue
                d["params"] = {"headers": hdr_missing}
            elif aid == "harden_hsts":
                if not hsts_missing or cert_bad:
                    continue
            elif aid == "harden_listing":
                if not listing_public:
                    continue
            elif aid == "wp_block_xmlrpc":
                if not xmlrpc_active:
                    continue
            d["irreversible"] = bool(a.get("irreversible"))
        elif aid == "remove_jce_profiles":
            if not jce_ids:
                continue
            d["params"] = {"ids": jce_ids, "names": jce_names}
        elif aid == "delete_quarantine":
            qd = scan.get("quarantine_dirs") or []
            if not qd:
                continue
            by_q = {q["name"]: q for q in scan.get("quarantines") or []}
            cand = []
            for q in qd:
                origins = [e["origin"] for e in (by_q.get(q["name"]) or {}).get("entries", [])]
                cand.append({"key": "k:%s" % q["name"], "pre": False,
                             "label": "%s  (%d Datei(en) noch in der Quarantäne, %d KB)%s" % (
                                 q["name"], q["count"], q["kb"], ("  " + ", ".join(origins[:4]) + (" ..." if len(origins) > 4 else "")) if origins else "  leer")})
            d["params"] = {"quarantine_dirs": qd, "pick": cand}
        elif aid == "restore_quarantine":
            qs = scan.get("quarantines") or []
            cand = []
            for q in qs:
                for e in q["entries"]:
                    cand.append({"key": "q:%s/%s" % (q["name"], e["id"]), "pre": False,
                                 "label": "%s  (Quarantäne %s, Nr. %s, %d Byte, Rechte %s, Besitzer %s)%s" % (
                                     e["origin"], q["name"].replace(QUAR_PREFIX + "-", ""), e["id"], e["size"], e["mode"], e["owner"],
                                     "  [Ursprungsort belegt, wird übersprungen]" if e["state"] == "belegt" else "")})
            if not cand:
                continue
            d["params"] = {"quarantines": qs, "pick": cand[:400]}
        elif aid == "remove_shells":
            if not (shell_files or images_php):
                continue
            d["params"] = {"files": shell_files[:MAX_FILES], "images": images_php,
                           "upload_dir": "wp-content/uploads" if cms == "wordpress" else "images", "manual_files": wp_manual_files[:50]}
            cand = [{"key": "f:" + f, "label": "%s  (Hintertür-Muster)" % f, "pre": True} for f in shell_files[:MAX_FILES]]
            cand += [{"key": "f:" + f, "label": "%s  (PHP-Datei im Bilder-Ordner)" % f, "pre": True} for f in image_files[:MAX_FILES] if f not in shell_files]
            if cand:
                d["params"]["pick"] = cand[:MAX_FILES]
        if a["needs_php"]:
            d["php_choices"] = choices
            if not choices and aid in ("install_security", "install_backup"):
                d["reason"] = "Es wurde kein funktionierendes PHP-Programm gefunden. Installiere die Erweiterung über die Store-Seite (Link) im Backend bzw. Dashboard."
            elif not choices:
                d["reason"] = ("Es wurde kein funktionierendes PHP-Programm gefunden. Aktualisiere über das WordPress-Dashboard (Dashboard -> Aktualisierungen)." if cms == "wordpress"
                               else "Es wurde kein funktionierendes PHP-Programm gefunden. Aktualisiere über das Joomla-Backend (System -> Aktualisieren).")
            elif aid in ("wp_update", "wp_core_reinstall", "wp_deactivate_plugin") and not wpcli:
                d["reason"] = ("Auf dem Server wurde WP-CLI nicht gefunden (weder 'wp' noch wp-cli.phar im Home-Verzeichnis). Aktualisiere im Dashboard unter "
                               "Dashboard -> Aktualisierungen. Alternativ lädst du wp-cli.phar von wp-cli.org per SFTP in dein Home-Verzeichnis hoch und suchst erneut.")
        d["hidden"] = bool(a.get("hidden"))
        d["can_skip_backup"] = bool(a.get("can_skip_backup"))
        d["why"] = STEP_WHY.get(aid, "")
        res.append(d)
    res.sort(key=lambda x: STEP_ORDER.index(x["id"]) if x["id"] in STEP_ORDER else 99)
    return res


SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,80}$")
ELEMENT_RE = re.compile(r"^[a-z][a-z0-9_]{1,60}$")
STAND_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
MANIFEST_RE = re.compile(r"^https://[A-Za-z0-9.-]+(:\d+)?/[^\s'\"\\`$;|&<>]*$")


def _tool_kind(aid: str) -> str:
    """Welche feste Liste zu einer Installations-Aktion gehört: 'security' (Firewall, Scanner) oder 'backup' (Sicherung)."""
    return "backup" if aid == "install_backup" else "security"


# E (2.4.0): Joomla-Erweiterungen installiert das Programm nur, wenn der Hersteller eine öffentliche Update-Adresse (install.manifest) anbietet, sie kostenlos sind und die Liste ein Stand-Datum trägt.
# Für alle anderen gibt es die Store-Seite (JED) und diese Anleitung.
JOOMLA_URL_HOWTO = ("Selbst installieren: Store-Seite öffnen, die Erweiterung dort herunterladen (nur von extensions.joomla.org oder der Seite des Herstellers) "
                    "und im Backend unter System -> Installieren -> Erweiterungen -> 'Von URL installieren' die Adresse des Pakets eintragen oder unter 'Paket hochladen' die Datei wählen.")


def security_choices(cms: str, wpcli: str = "", kind: str = "security") -> List[Dict[str, Any]]:
    """Erweiterungen zur Auswahl (aus der festen Liste der Art 'security' oder 'backup'). 'installable': das Programm darf sie installieren."""
    from . import store
    from .checks.security_ext import load_tools, stars_text
    out: List[Dict[str, Any]] = []
    wp = cms == "wordpress"
    lst = load_tools(kind)
    stand = str(lst.get("stand") or "")
    for t in lst.get(cms, []):
        if t.get("background"):
            continue
        if wp:
            inst = bool(wpcli) and bool(SLUG_RE.match(str(t.get("slug") or "")))
        else:
            ins = t.get("install") or {}
            inst = bool(MANIFEST_RE.match(str(ins.get("manifest") or ""))) and bool(ELEMENT_RE.match(str(ins.get("element") or ""))) and str(t.get("price") or "").startswith("kostenlos") and bool(STAND_RE.match(stand))
        out.append({"id": t["id"], "name": t["name"], "price": "" if wp else (t.get("price") or ""), "rating": "" if wp else stars_text(t),
                    "stars": 0 if wp else int(t.get("stars") or 0), "reviews": 0 if wp else int(t.get("reviews") or 0),
                    "developer": t.get("developer") or "", "text": t["text"], "store_url": store.store_url(t, cms), "installable": inst,
                    "stand": stand if (inst and not wp) else "", "howto": "" if (inst or wp) else JOOMLA_URL_HOWTO})
    return out


def _security_target(params: Dict[str, Any], kind: str = "security") -> Dict[str, Any]:
    """Die gewählte Erweiterung, erneut gegen die feste Liste geprüft (nie aus Angaben der Oberfläche übernommen)."""
    from .checks.security_ext import load_tools
    cms = "wordpress" if str(params.get("cms")) == "wordpress" else "joomla"
    tid = str(params.get("tool") or "")
    lst = load_tools(kind)
    for t in lst.get(cms, []):
        if t["id"] != tid or t.get("background"):
            continue
        if cms == "wordpress":
            if SLUG_RE.match(str(t.get("slug") or "")):
                return {"cms": cms, "tool": t, "slug": t["slug"]}
        else:
            ins = t.get("install") or {}
            if (MANIFEST_RE.match(str(ins.get("manifest") or "")) and ELEMENT_RE.match(str(ins.get("element") or "")) and str(t.get("price") or "").startswith("kostenlos")
                    and STAND_RE.match(str(lst.get("stand") or ""))):
                return {"cms": cms, "tool": t, "manifest": ins["manifest"], "element": ins["element"]}
    raise ActionError("Diese Erweiterung kann das Programm nicht installieren. Bitte eine andere wählen oder den Link zur Store-Seite nutzen.")


def newest_download(xml_text: str) -> Dict[str, str]:
    """Neueste Version aus dem Update-Manifest (XML) mit ihrer https-Download-Adresse. Leeres Ergebnis, wenn nichts Passendes darin steht."""
    import xml.etree.ElementTree as ET
    if "<!DOCTYPE" in xml_text or "<!ENTITY" in xml_text:
        return {}
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return {}
    best: Dict[str, str] = {}
    for up in root.iter("update"):
        v = (up.findtext("version") or "").strip()
        if not re.match(r"^[0-9A-Za-z._-]+$", v):
            continue
        url = pick_download(ET.tostring(up, encoding="unicode").join(["<updates>", "</updates>"]), v)
        if url and (not best or joomla_vcmp(v, best["version"]) > 0):
            best = {"version": v, "url": url}
    return best


_DOC_PARAMS = {"selected_pick": ["u:42", "e:component/-/com_beispiel", "p:beispiel-plugin"], "php": "php", "wpcli": "wp", "files": [], "ids": [0], "dirs": ["tmp"], "selected": [], "updates": [], "backups": [{"name": "claudia-sicherung-20250101-000000"}], "selected_backups": ["claudia-sicherung-20250101-000000"], "logs": [], "tool": "wordfence",
               "cms": "wordpress", "images": True, "version": "<Version>", "upload_dir": "images"}


def catalog() -> List[Dict[str, Any]]:
    """Alle Aktionen für die Dokumentation: Was, Wie (die Befehle, wie sie in der Vorschau erscheinen), Warum, Warnung, Rückweg, Sicherung."""
    out: List[Dict[str, Any]] = []
    order = [a for a in STEP_ORDER if a in ACTIONS] + [a for a in ACTIONS if a not in STEP_ORDER]
    for aid in order:
        a = ACTIONS[aid]
        params = dict(_DOC_PARAMS)
        if aid in ("install_security", "install_backup"):
            params["tool"] = "wordfence" if aid == "install_security" else "akeeba"
        try:
            how = re.sub(r"für \d+ Datei\(en\)", "für jede gemeldete Datei", "\n".join(commands_preview(aid, params, [{"name": "php"}])))
        except (ActionError, KeyError, ValueError, TypeError):
            how = ""
        out.append({"id": aid, "cms": "joomla" if aid in JOOMLA_ONLY else ("wordpress" if aid in WP_ONLY else "both"), "title": a["title"], "what": a["summary"],
                    "how": how, "why": STEP_WHY.get(aid, ""), "warning": a["warning"], "undo": a["undo"], "risk": a["risk"],
                    "backup": sicherung_info(aid)["text"]})
    return out


def build_plan(acts: List[Dict[str, Any]], results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Empfohlene Reihenfolge als nummerierte Liste (Aktionen und Handarbeit). Setzt 'step' in den Aktionen."""
    from . import snippets
    manual_code = bool(snippets.manual_targets(results))
    risky = any(r.get("status") == "crit" or any(f.get("sev") == "crit" for f in r.get("findings", [])) for r in results or [])
    items: List[Dict[str, Any]] = []
    by_id = {a["id"]: a for a in acts if not a.get("hidden")}
    for aid in STEP_ORDER:
        if aid in ("fix_permissions", "clear_cache", "delete_old_backups"):
            continue
        if aid in by_id:
            items.append({"kind": "action", "id": aid, "title": by_id[aid]["title"], "why": STEP_WHY[aid]})
    if manual_code:
        items.append({"kind": "manual", "id": "manual_code", "title": "Eingeschleusten Code in Dateien von Hand entfernen",
                      "why": "Schadcode mitten in normalen Dateien (z. B. in der Vorlage) entfernt das Programm nicht selbst. Unten siehst du die Stelle mit Zeilennummern."})
    if risky:
        items.append({"kind": "manual", "id": "manual_passwords", "title": "Passwörter und Zugänge erneuern",
                      "why": ("Nach einem Einbruch gelten alle Zugänge als bekannt: WordPress-Administratoren, Datenbank-Passwort (wp-config.php), SFTP/SSH, E-Mail, Anwendungspasswörter."
                              if any(x["id"] in WP_ONLY for x in acts) else
                              "Nach einem Einbruch gelten alle Zugänge als bekannt: Joomla-Admin-Passwörter, Datenbank-Passwort (configuration.php), SFTP/SSH, E-Mail, API-Token.")})
    for aid in ("fix_permissions", "clear_cache"):
        if aid in by_id:
            items.append({"kind": "action", "id": aid, "title": by_id[aid]["title"], "why": STEP_WHY[aid]})
    items.append({"kind": "manual", "id": "recheck", "title": "Prüfung wiederholen", "why": "Erst wenn die Prüfung nichts Kritisches mehr zeigt, ist der Zustand belegt."})
    if "delete_old_backups" in by_id:
        items.append({"kind": "action", "id": "delete_old_backups", "title": by_id["delete_old_backups"]["title"], "why": STEP_WHY["delete_old_backups"]})
    for i, it in enumerate(items, 1):
        it["step"] = i
        if it["kind"] == "action":
            by_id[it["id"]]["step"] = i
    return items


# ------------------------------------------------------------------------------------------------ Sicherung
def _check_vars(vars_: Dict[str, Any]) -> None:
    """Zugangsdaten stammen vom geprüften Server: ungewöhnliche Zeichen (Optionen, Anführungszeichen, Semikolons) führen zum Abbruch, bevor ein Befehl entsteht."""
    host, port, sock = joomla.split_db_host(str(vars_.get("host", "localhost")))
    bad = dbmod.validate_vars(str(vars_.get("db", "")), str(vars_.get("dbprefix", "jos_")), str(vars_.get("user", "")), host, sock)
    if bad:
        raise ActionError(bad + " Aus Sicherheitsgründen wird nichts geändert.")


def _db_dump_script(vars_: Dict[str, Any], outdir: str, tables: Optional[List[str]] = None, fname: str = "db.sql.gz") -> str:
    """mysqldump-Aufruf. Bewusst nur Optionen, die jede mysqldump-/mariadb-dump-Version kennt (--connect-timeout z. B. kennt mysqldump
    bei manchen Hostern NICHT und bricht mit 'unknown variable' ab). --no-tablespaces wird zuerst versucht und bei Ablehnung weggelassen."""
    _check_vars(vars_)
    if any(not re.match(r"^[A-Za-z0-9_]{1,80}$", t) for t in (tables or [])):
        raise ActionError("Ein Tabellenname sieht ungewöhnlich aus. Aus Sicherheitsgründen wird nichts gesichert.")
    host, port, sock = joomla.split_db_host(str(vars_.get("host", "localhost")))
    opts = ["--single-transaction", "--default-character-set=utf8mb4"]
    opts += ["-S", sock] if sock else (["-h", host or "localhost"] + (["-P", str(port)] if port else []))
    opts += ["-u", str(vars_.get("user", ""))]
    o = " ".join(sq(x) for x in opts)
    db = sq(str(vars_.get("db", "")))
    tb = " ".join(sq(t) for t in (tables or []))
    f = "%s/%s" % (sq(outdir), fname)
    return ("D=$(command -v mysqldump || command -v mariadb-dump) || { echo 'mysqldump fehlt' >&2; exit 41; }\n"
            "IFS= read -r MYSQL_PWD; export MYSQL_PWD\n"
            "ok=0\n"
            "for extra in '--no-tablespaces' ''; do\n"
            "  timeout -k 5 900 \"$D\" $extra %s %s %s 2>%s/dump_meldungen.txt | gzip > %s\n"
            "  rc=${PIPESTATUS[0]}\n"
            "  if [ \"$rc\" -eq 0 ]; then ok=1; break; fi\n"
            "  grep -qiE 'unknown (variable|option)|unrecognized option' %s/dump_meldungen.txt || break\n"
            "done\n"
            "if [ \"$ok\" -ne 1 ]; then head -c 600 %s/dump_meldungen.txt >&2; echo 'mysqldump fehlgeschlagen' >&2; exit 42; fi\n"
            "gzip -t %s && [ -s %s ]\n" % (o, db, tb, sq(outdir), f, sq(outdir), sq(outdir), f, f))


def _mysql_script(vars_: Dict[str, Any], sql: str) -> str:
    """mysql-Aufruf mit Passwort über stdin (nie in der Befehlszeile). 'sql' darf #__ als Tabellenpräfix enthalten."""
    prefix = str(vars_.get("dbprefix", "jos_"))
    _check_vars(vars_)
    host, port, sock = joomla.split_db_host(str(vars_.get("host", "localhost")))
    opts = ["--batch", "--default-character-set=utf8mb4", "--connect-timeout=15"]
    opts += ["-S", sock] if sock else (["-h", host or "localhost"] + (["-P", str(port)] if port else []))
    opts += ["-u", str(vars_.get("user", ""))]
    return ("IFS= read -r MYSQL_PWD; export MYSQL_PWD; B=$(command -v mysql || command -v mariadb) || { echo 'mysql fehlt' >&2; exit 41; }; "
            "\"$B\" %s %s -e %s" % (" ".join(sq(o) for o in opts), sq(str(vars_.get("db", ""))), sq(sql.replace("#__", prefix))))


def _read_cfg_site(runner: Runner, site_dir: str):
    """Liest die Konfiguration der Seite (Joomla: configuration.php, WordPress: wp-config.php). Rückgabe: (Zugangsdaten, 'joomla'|'wordpress')."""
    r = runner.sh(site_dir, "test -f configuration.php && head -c 300000 configuration.php", 30)
    if r.out.strip():
        return joomla.parse_config(r.out)["vars"], "joomla"
    r = runner.sh(site_dir, "if test -f wp-config.php; then head -c 300000 wp-config.php; elif test -f ../wp-config.php; then head -c 300000 ../wp-config.php; fi", 30)
    if r.out.strip():
        return wordpress.parse_wp_config(r.out)["vars"], "wordpress"
    raise ActionError("Weder configuration.php noch wp-config.php lesbar: Ohne Datenbank-Zugangsdaten geht es nicht.")


def _read_cfg(runner: Runner, site_dir: str) -> Dict[str, Any]:
    return _read_cfg_site(runner, site_dir)[0]


def _home_dir(runner: Runner, site_dir: str) -> str:
    home = lines_of(runner.sh(site_dir, 'printf "%s\\n" "$HOME"', 15).out)
    if not home or not home[0].startswith("/"):
        raise ActionError("Das Home-Verzeichnis auf dem Server konnte nicht ermittelt werden.")
    return home[0].rstrip("/")


HTACCESS_DENY = ("# CLAUDIA: Dieser Ordner enthält eine Sicherung und darf nie aus dem Internet erreichbar sein.\n"
                 "<IfModule mod_authz_core.c>\nRequire all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\nOrder deny,allow\nDeny from all\n</IfModule>\n")
PUBLIC_WARNING = ("ACHTUNG: Der Sicherungsordner liegt im öffentlich erreichbaren Bereich der Seite (das Home-Verzeichnis ist zugleich der Webordner). "
                  "Das Programm hat ihn mit einer Zugriffssperre (.htaccess) und einem Zufallsnamen geschützt, das ist aber nur ein Notbehelf, "
                  "weil nicht jeder Server die .htaccess beachtet. Lade die Sicherung so bald wie möglich herunter und lösche sie danach vom Server.")


def _note(runner, text: str) -> None:
    """Hinweis für das Ergebnis der Aktion (steht im Statusfenster und in der Abschlussmeldung)."""
    notes = getattr(runner, "notes", None)
    if isinstance(notes, list) and text not in notes:
        notes.append(text)
    emit = getattr(runner, "emit", None)
    if callable(emit):
        emit("info", text)


def _inside_site(runner: Runner, site_dir: str, home: str) -> bool:
    """Liegt das Home-Verzeichnis (und damit der Sicherungsordner) im Seitenordner oder ist es dieser selbst?"""
    r = runner.sh(site_dir, 'S=$(pwd -P); P=$(cd -- %s 2>/dev/null && pwd -P); case "$P/" in "$S"/*) echo drin;; *) echo draussen;; esac' % sq(home), 15)
    return "drin" in r.out


def _manifest_text(runner, site_dir: str, art: str, protected: bool) -> str:
    from . import __version__
    meta = getattr(runner, "meta", None) or {}
    aid = str(meta.get("aid") or "")
    lines = ["CLAUDIA %s - Sicherung" % __version__,
             "Zeitpunkt: %s (Uhr dieses Computers)" % time.strftime("%Y-%m-%d %H:%M:%S"),
             "Aktion: %s%s" % (meta.get("title") or "?", (" (%s)" % aid) if aid else ""),
             "Seitenordner: %s" % site_dir,
             "Art: %s" % (SICHERUNG.get(aid, ("", ""))[1] or art),
             "Befund bei der letzten Prüfung: %s" % (meta.get("befund") or "keine Prüfung in dieser Sitzung"),
             "",
             "WARNUNG: Diese Sicherung enthält möglicherweise Schadcode (infizierte Dateien) und die Zugangsdaten der Seite (Datenbank, Schlüssel).",
             "Nicht öffnen, nicht ausführen, nicht in einen öffentlich erreichbaren Ordner kopieren und nicht weitergeben.",
             "Zurückspielen: siehe 'Rückgängig' bei der Aktion im Programm (z. B. tar xzf dateien.tgz im Seitenordner)."]
    if protected:
        lines += ["", PUBLIC_WARNING]
    return "\n".join(lines) + "\n"


def _new_backup_dir(runner: Runner, site_dir: str, label: str) -> str:
    """Neuen Sicherungsordner anlegen (Rechte 700). Liegt er im öffentlichen Bereich: Zufallsname, .htaccess-Sperre, index.html und Warnung.
    Danach kommt MANIFEST.txt hinein (wann, welche Aktion, Befund, Warnung). Das Manifest ist nur eine Beigabe; scheitert es, läuft die Aktion weiter."""
    home = _home_dir(runner, site_dir)
    inside = _inside_site(runner, site_dir, home)
    name = "claudia-sicherung-%s%s" % ((label + "-") if label else "", time.strftime("%Y%m%d-%H%M%S"))
    if inside:
        import secrets as _s
        name += "-" + _s.token_hex(4)
    out = "%s/%s" % (home, name)
    r = runner.sh(site_dir, "mkdir -p -m 700 %s && echo angelegt" % sq(out), 30)
    if "angelegt" not in r.out:
        raise ActionError("Der Sicherungsordner konnte nicht angelegt werden.")
    if inside:
        r = runner.sh(site_dir, "cat > %s/.htaccess && : > %s/index.html && echo gesperrt" % (sq(out), sq(out)), 30, stdin=HTACCESS_DENY)
        if "gesperrt" not in r.out:
            raise ActionError("Der Sicherungsordner liegt im öffentlichen Bereich und konnte nicht gesperrt werden. Es wurde nichts verändert. Verschiebe dein Home-Verzeichnis oder wähle einen Seitenordner unterhalb davon.")
        _note(runner, PUBLIC_WARNING)
    art = SICHERUNG.get(str((getattr(runner, "meta", None) or {}).get("aid") or ""), ("", ""))[0] or "gezielt"
    try:
        runner.sh(site_dir, "cat > %s/MANIFEST.txt" % sq(out), 30, stdin=_manifest_text(runner, site_dir, art, inside))
    except RunnerError:
        pass
    return out


def _mkdir_backup(runner: Runner, site_dir: str, label: str) -> str:
    return _new_backup_dir(runner, site_dir, label)


def _safe_path(f: str) -> bool:
    return isinstance(f, str) and f.startswith("./") and "/../" not in f and not f.endswith("/..") and "\n" not in f and "\0" not in f and len(f) < 400


WP_TAR_EXCLUDES = ["./wp-content/cache", "./wp-content/uploads", "./wp-content/upgrade", "./wp-content/wflogs", "./wp-content/ai1wm-backups", "./node_modules"]
TAR_EXCLUDES = ["./cache", "./administrator/cache", "./tmp", "./logs", "./administrator/logs", "./images", "./node_modules"]


def make_backup(runner: Runner, site_dir: str, log: Callable[[str, bool, str], None]) -> str:
    """Sicherung auf dem Server anlegen und prüfen. Rückgabe: Ordner. Wirft ActionError, wenn etwas nicht stimmt."""
    try:
        cfg, cms = _read_cfg_site(runner, site_dir)
    except ActionError:
        raise ActionError("Die Konfigurationsdatei ist nicht lesbar: Ohne Datenbank-Zugangsdaten gibt es keine Sicherung.")
    excludes = WP_TAR_EXCLUDES if cms == "wordpress" else TAR_EXCLUDES
    excl = " ".join("--exclude=%s" % sq(e) for e in excludes) + " --exclude='*.jpa' --exclude='*.wpress'"
    # 1. Platz
    est = runner.sh(site_dir, "du -sk %s . 2>/dev/null | tail -1 | cut -f1; df -Pk \"$HOME\" | awk 'NR==2{print $4}'"
                    % " ".join("--exclude=%s" % sq(e[2:]) for e in excludes), 180)
    nums = [int(x) for x in lines_of(est.out) if x.strip().isdigit()]
    if len(nums) < 2:
        raise ActionError("Der freie Speicherplatz konnte nicht ermittelt werden.")
    need, free = nums[0], nums[1]
    ok = free > need * 1.3 + 200_000
    log("Speicherplatz prüfen", ok, "Seite etwa %d MB, frei %d MB" % (need // 1024, free // 1024))
    if not ok:
        raise ActionError("Zu wenig freier Speicherplatz für die Sicherung (benötigt etwa %d MB, frei %d MB)." % (need * 13 // 10 // 1024, free // 1024))
    # 2. Ordner und Datenbank
    outdir = _new_backup_dir(runner, site_dir, "")
    r = runner.sh(site_dir, _db_dump_script(cfg, outdir), 900, stdin=str(cfg.get("password", "")) + "\n")
    pw = str(cfg.get("password", ""))
    err = (r.err or r.out or "").replace(pw, "***") if pw else (r.err or r.out)
    log("Datenbank sichern", r.rc == 0 and not r.timed_out, err.strip()[:300])
    if r.rc != 0 or r.timed_out:
        raise ActionError("Die Datenbank konnte nicht gesichert werden (%s)." % (err.strip()[:200] or "Zeitüberschreitung"))
    # 3. Dateien
    q = sq(outdir)
    r = runner.sh(site_dir, "tar czf %s/dateien.tgz %s . 2>%s/tar_meldungen.txt; rc=$?; [ $rc -le 1 ] && tar tzf %s/dateien.tgz >/dev/null && echo fertig"
                  % (q, excl, q, q), 1800)
    log("Dateien sichern (ohne %s)" % ("wp-content/uploads, cache, upgrade, logs" if cms == "wordpress" else "images, cache, tmp, logs, *.jpa"), "fertig" in r.out, r.err.strip()[:200])
    if "fertig" not in r.out:
        raise ActionError("Die Dateien konnten nicht gesichert werden.")
    # 4. Prüfung
    r = runner.sh(site_dir, "ls -l %s/db.sql.gz %s/dateien.tgz | awk '{print $5, $9}'" % (q, q), 30)
    sizes = [l.split()[0] for l in lines_of(r.out) if l.split() and l.split()[0].isdigit()]
    good = len(sizes) == 2 and all(int(s) > 1000 for s in sizes)
    log("Sicherung prüfen", good, r.out.strip())
    if not good:
        raise ActionError("Die Sicherung wirkt unvollständig (zu klein). Es wurde nichts verändert.")
    return outdir


# ------------------------------------------------------------------------------------------------ Ausführung
def _php(params: Dict[str, Any], choices: List[Dict[str, Any]]) -> str:
    name = str(params.get("php") or "")
    if name not in {c["name"] for c in choices}:
        raise ActionError("Bitte ein PHP-Programm aus der Liste wählen.")
    return name


def pre_backup() -> List[str]:
    return ["Sicherung: mysqldump ... | gzip  ->  ~/claudia-sicherung-<datum>/db.sql.gz", "Sicherung: tar czf ~/claudia-sicherung-<datum>/dateien.tgz (ohne images, cache, tmp, logs, *.jpa)",
            "Die Sicherung wird geprüft (gzip -t, tar t, Größe). Nur wenn alles stimmt, geht es weiter."]


def commands_preview(aid: str, params: Dict[str, Any], choices: List[Dict[str, Any]]) -> List[str]:
    """Die Befehle, die ausgeführt würden (zur Anzeige VOR der Bestätigung)."""
    a = ACTIONS.get(aid)
    if not a:
        raise ActionError("Unbekannte Aktion.")
    pre = pre_backup() if a["backup"] else []
    if aid == "fix_update_perms":
        n = len(params.get("files") or [])
        return ["Rechte-Protokoll: stat -c '%a %n' <Datei>  (vorher)", "chmod u+rwX -- <Datei>   für %d Datei(en)/Ordner (Besitzer darf schreiben, bei Ordnern auch betreten)" % n]
    if aid == "joomla_core_reinstall":
        n = len(params.get("files") or [])
        return pre + ["Auf diesem Computer: Original-Paket von Joomla %s laden, Prüfsumme gegen die veröffentlichte prüfen, ZIP mit den %d betroffenen Dateien bauen" % (params.get("version") or "?", n),
                      "Hochladen nach ~/claudia-sicherung-<datum>/original.zip  (base64 -d, Prüfsumme sha256sum muss stimmen)",
                      "unzip -o original.zip   (oder python3 zipfile)  im Joomla-Ordner  -> nur die %d Dateien werden überschrieben" % n,
                      "Kontrolle: sha256sum der ersetzten Dateien = Original"]
    if aid == "wp_remove_maintenance":
        return ["Prüfen: .maintenance ist eine normale Datei (kein Verweis), unter 1 KB und enthält nur  $upgrading = <Zahl>;",
                "Kopie: cp -p .maintenance ~/claudia-sicherung-wartung-<datum>/.maintenance", "rm -f -- .maintenance", "Kontrolle: Datei ist weg"]
    if aid == "fix_permissions":
        n = len(params.get("files") or [])
        return ["Rechte-Protokoll: stat -c '%a %n' <Datei>  (vorher)", "chmod o-w -- <Datei>   für %d Datei(en)/Ordner" % n]
    if aid == "backup_now":
        return pre
    if aid == "clean_tmp":
        dirs = _tmp_dirs(params)
        return (["Sicherung: tar czf ~/claudia-sicherung-tmp-<datum>/tmp.tgz %s   (ganzer Inhalt, wird geprüft: tar tzf)" % " ".join(dirs)] +
                ["( cd %s && find . -mindepth 1 -maxdepth 1 ! -name index.html ! -name .htaccess -exec rm -rf -- {} + )" % d for d in dirs] +
                ["Danach: Zählen, was noch in diesen Ordnern liegt"])
    if aid == "delete_old_backups":
        names = _backup_selection(params)
        logs = _log_selection(params)
        out = ["rm -rf -- ~/%s" % n for n in names]
        if names:
            out.append("Kontrolle: Ordner sind nicht mehr vorhanden")
        out += ["Lokal (dieser Computer): Protokolldatei löschen: %s" % n for n in logs[:20]]
        if len(logs) > 20:
            out.append("... und %d weitere Protokolle (das jeweils neueste Protokoll einer Aktion bleibt immer erhalten)" % (len(logs) - 20))
        return out
    if aid == "update_extensions":
        php = _php(params, choices)
        sel = params.get("selected") or []
        names = {int(u["uid"]): u for u in params.get("updates") or []}
        lines = pre_backup()
        for i in sel:
            u = names.get(int(i))
            if u:
                lines += ["# %s: %s -> %s   (Quelle: %s)" % (u["name"], u.get("old") or "?", u["new"], u.get("source", "?")),
                          "curl -fsSL --proto '=https' <Update-Manifest des Herstellers>   (liest die Download-Adresse der Version %s)" % u["new"],
                          "%s cli/joomla.php extension:install --url=<Download-Adresse>" % php,
                          "Kontrolle: installierte Version in der Datenbank == %s" % u["new"]]
        return lines + ["%s cli/joomla.php update:extensions:check" % php, "%s cli/joomla.php cache:clean" % php]
    if aid == "remove_jce_profiles":
        ids = ", ".join(str(int(i)) for i in params.get("ids") or [])
        bak = ("-- OHNE Sicherung (auf deinen Wunsch): es entsteht keine Kopie der Profile." if params.get("no_backup") else
               "-- Sicherung: mysqldump <Datenbank> #__wf_profiles | gzip > ~/claudia-sicherung-jce-<datum>/wf_profiles.sql.gz   (wird geprüft)")
        return ["-- Prüfen, dass diese Profile noch 'php' enthalten und nicht zu den Standardprofilen gehören:",
                "SELECT id, name FROM #__wf_profiles WHERE id IN (%s) AND params LIKE '%%php%%';" % ids, bak,
                "DELETE FROM #__wf_profiles WHERE id IN (%s) AND params LIKE '%%php%%';" % ids,
                "-- Kontrolle: SELECT COUNT(*) FROM #__wf_profiles WHERE id IN (%s);" % ids]
    if aid in WP_ONLY and aid in ("wp_salts", "wp_disallow_edit", "wp_fix_registration"):
        if aid == "wp_fix_registration":
            return (["Sicherung: mysqldump <Datenbank> <Präfix>options | gzip > ~/claudia-sicherung-options-<datum>/options.sql.gz   (wird geprüft)",
                     "UPDATE <Präfix>options SET option_value = '0' WHERE option_name = 'users_can_register';",
                     "UPDATE <Präfix>options SET option_value = 'subscriber' WHERE option_name = 'default_role' AND option_value = 'administrator';",
                     "Kontrolle: Werte erneut lesen"])
        cp = ["Kopie: cp -p wp-config.php ~/claudia-sicherung-wpconfig-<datum>/wp-config.php"]
        if aid == "wp_salts":
            return cp + ["Die acht Zeilen AUTH_KEY ... NONCE_SALT in der wp-config.php werden durch neue Zufallswerte ersetzt (erzeugt auf diesem PC, kryptografisch sicher).",
                         "Kontrolle: Datei enthält weiterhin wp-settings.php und alle acht Schlüssel, Rechte unverändert"]
        return cp + ["Vor der Zeile mit 'wp-settings.php' wird eingefügt:  define( 'DISALLOW_FILE_EDIT', true );", "Kontrolle: Datei enthält die neue Zeile und weiterhin wp-settings.php"]
    if aid in ("wp_update", "wp_core_reinstall"):
        php = _php(params, choices)
        wp = "%s %s --path=<Seitenordner>" % (php, params.get("wpcli") or "wp")
        if aid == "wp_core_reinstall":
            return pre_backup() + ["%s core download --force --skip-content --version=%s --locale=<aktuelle Sprache>" % (wp, params.get("version") or "<installierte Version>"),
                                   "%s core verify-checksums" % wp]
        return pre_backup() + ["%s core update" % wp, "%s core update-db" % wp, "%s plugin update --all" % wp, "%s theme update --all" % wp,
                               "%s core verify-checksums" % wp, "%s plugin list --update=available --format=count" % wp]
    if aid in ("install_security", "install_backup"):
        tgt = _security_target(params, _tool_kind(aid))
        php = _php(params, choices)
        if tgt["cms"] == "wordpress":
            wp = "%s %s --path=<Seitenordner>" % (php, params.get("wpcli") or "wp")
            return pre_backup() + ["%s plugin install %s --activate   (aus dem Verzeichnis wordpress.org)" % (wp, tgt["slug"]),
                                   "%s plugin is-active %s" % (wp, tgt["slug"]), "%s plugin verify-checksums %s   (Dateien gegen die Prüfsummen von wordpress.org)" % (wp, tgt["slug"])]
        return pre_backup() + ["curl -fsSL --max-time 40 --proto '=https' %s   (liest die Download-Adresse der neuesten Version)" % tgt["manifest"],
                               "%s cli/joomla.php extension:install --url=<Download-Adresse>" % php,
                               "Kontrolle: Erweiterung %s steht in der Datenbank" % tgt["element"], "%s cli/joomla.php cache:clean" % php]
    if aid in ("block_users", "revoke_tokens"):
        ids = _sql_ints(_picked_ids(params)) or "<IDs>"
        if not _picked_ids(params):
            raise ActionError("Keine Konten ausgewählt.")
        wp = (params.get("cms") == "wordpress")
        if aid == "block_users" and wp:
            return ["-- Schutz: mindestens ein anderer Administrator muss übrig bleiben (SELECT COUNT(*) ... meta_value LIKE '%%administrator%%' AND user_id NOT IN (%s))" % ids,
                    "Sicherung: mysqldump <Datenbank> <Präfix>users <Präfix>usermeta | gzip > ~/claudia-sicherung-benutzer-<datum>/benutzer.sql.gz   (wird geprüft)",
                    "UPDATE <Präfix>usermeta SET meta_value = 'a:0:{}' WHERE meta_key = '<Präfix>capabilities' AND user_id IN (%s);" % ids,
                    "UPDATE <Präfix>users SET user_pass = '!<Zufallswert>', user_activation_key = '' WHERE ID IN (%s);" % ids,
                    "DELETE FROM <Präfix>usermeta WHERE meta_key IN ('session_tokens', '_application_passwords') AND user_id IN (%s);" % ids,
                    "-- Kontrolle: Konten mit Rolle unter den ausgewählten = 0"]
        if aid == "block_users":
            return ["-- Schutz: mindestens ein anderer aktiver Super User/Administrator muss übrig bleiben (Gruppen 'Super Users', 'Administrator'; id NOT IN (%s))" % ids,
                    "Sicherung: mysqldump <Datenbank> <Präfix>users | gzip > ~/claudia-sicherung-benutzer-<datum>/benutzer.sql.gz   (wird geprüft)",
                    "rueckgaengig.sql schreiben: UPDATE #__users SET block = 0 WHERE id IN (<die Konten, die jetzt aktiv sind>);",
                    "UPDATE #__users SET block = 1 WHERE id IN (%s);" % ids, "DELETE FROM #__session WHERE userid IN (%s);" % ids,
                    "-- Kontrolle: aktive Konten unter den ausgewählten = 0"]
        if wp:
            return ["Sicherung: mysqldump <Datenbank> <Präfix>usermeta | gzip > ~/claudia-sicherung-tokens-<datum>/benutzerdaten.sql.gz   (wird geprüft)",
                    "DELETE FROM <Präfix>usermeta WHERE meta_key = '_application_passwords' AND user_id IN (%s);" % ids, "-- Kontrolle: Anzahl = 0"]
        return ["Sicherung: mysqldump <Datenbank> <Präfix>user_profiles | gzip > ~/claudia-sicherung-tokens-<datum>/benutzerprofile.sql.gz   (wird geprüft)",
                "DELETE FROM #__user_profiles WHERE profile_key LIKE 'joomlatoken.%%' AND user_id IN (%s);" % ids, "-- Kontrolle: Anzahl = 0"]
    if aid == "end_sessions":
        if params.get("cms") == "wordpress":
            return ["SELECT COUNT(*) FROM <Präfix>usermeta WHERE meta_key = 'session_tokens';   (so viele Sitzungen gibt es jetzt)",
                    "DELETE FROM <Präfix>usermeta WHERE meta_key = 'session_tokens';", "-- Kontrolle: Anzahl = 0"]
        return ["SELECT COUNT(*) FROM #__session;   (so viele Sitzungen gibt es jetzt)", "DELETE FROM #__session;", "-- Kontrolle: Anzahl = 0"]
    if aid == "disable_api":
        return ["SELECT extension_id, folder, element, enabled FROM #__extensions WHERE type = 'plugin' AND enabled = 1 AND (%s);" % API_PLUGIN_SQL,
                "Sicherung: mysqldump <Datenbank> <Präfix>extensions | gzip > ~/claudia-sicherung-api-<datum>/extensions.sql.gz   (wird geprüft)",
                "rueckgaengig.sql schreiben: UPDATE #__extensions SET enabled = 1 WHERE extension_id IN (<die jetzt eingeschalteten>);",
                "UPDATE #__extensions SET enabled = 0 WHERE extension_id IN (<geprüfte Auswahl>) AND protected = 0;",
                "-- Kontrolle: Anzahl noch eingeschalteter = 0"]
    if aid == "deactivate_extension":
        keys = [k for k in _picked(params, "e") if EXT_KEY_RE.match(k)]
        if not keys:
            raise ActionError("Keine Erweiterungen ausgewählt.")
        return ["SELECT extension_id, type, folder, element, enabled, protected, name FROM #__extensions WHERE <Typ, Gruppe und Name der Auswahl: %s>;" % ", ".join(keys[:6]),
                "-- Geschützt (wird übersprungen): vom System geschützt, Joomla-Kern, Anmelde-/Zwei-Faktor-Erweiterungen, erkannte Sicherheits- und Sicherungs-Erweiterungen",
                "Sicherung: mysqldump <Datenbank> <Präfix>extensions | gzip > ~/claudia-sicherung-erweiterungen-<datum>/extensions.sql.gz   (wird geprüft)",
                "rueckgaengig.sql schreiben: UPDATE #__extensions SET enabled = 1 WHERE extension_id IN (<die jetzt eingeschalteten>);",
                "UPDATE #__extensions SET enabled = 0 WHERE extension_id IN (<geprüfte Auswahl>) AND protected = 0;", "-- Kontrolle: Anzahl noch eingeschalteter = 0"]
    if aid == "wp_deactivate_plugin":
        slugs = [k for k in _picked(params, "p") if SLUG_RE.match(k)]
        if not slugs:
            raise ActionError("Keine Plugins ausgewählt.")
        php = _php(params, choices)
        wp = "%s %s --path=<Seitenordner>" % (php, params.get("wpcli") or "wp")
        return (["%s plugin is-active %s   (nur aktive werden angefasst; Sicherheits- und Sicherungs-Plugins nie)" % (wp, s) for s in slugs[:6]] +
                ["Sicherung: mysqldump <Datenbank> <Präfix>options | gzip > ~/claudia-sicherung-plugins-<datum>/options.sql.gz   (wird geprüft)",
                 "rueckgaengig.txt schreiben: wp plugin activate <Plugin> (je ausgeschaltetes Plugin)"] +
                ["%s plugin deactivate %s" % (wp, s) for s in slugs[:6]] + ["%s plugin is-active <Plugin>   (muss jetzt fehlschlagen)" % wp])
    if aid == "remove_shells":
        picked = _picked(params, "f")
        files = _picked_shell_files(params, picked, None) if picked else [f for f in params.get("files") or [] if _safe_path(f)]
        qd = "~/%s-<datum>" % QUAR_PREFIX
        lines = ["Quarantäne-Ordner anlegen: mkdir -m 700 %s %s/d   (nur außerhalb des Web-Ordners, sonst Abbruch ohne Änderung; dazu eine Zugriffssperre .htaccess)" % (qd, qd),
                 "Liste vorab schreiben: sha256sum und stat (Rechte, Besitzer, Größe, Datum) je Datei -> %s/QUARANTAENE.txt" % qd,
                 "Je Datei vorher prüfen: normale Datei (kein Verweis), Ordner liegt in der Seite und ist beschreibbar; sonst wird genau diese Datei übersprungen"]
        if params.get("images") and not picked:
            lines.append("find %s -type f %s ! -size 0   -> alle gefundenen PHP-Dateien (die Liste siehst du nach dem Ausführen im Ergebnis)" % (_upload_dir(params), PHP_EXT_FIND.replace("\\(", "(").replace("\\)", ")")))
        lines += ["mv -n -- %s %s/d/<Nr>.q" % (f, qd) for f in files[:40]] or ["mv -n -- <Datei> %s/d/<Nr>.q" % qd]
        if len(files) > 40:
            lines.append("# ... und %d weitere Dateien" % (len(files) - 40))
        lines += ["chmod 600 %s/d/<Nr>.q   (kein Ausführrecht, die Endung .php entfällt)" % qd,
                  "Anderes Dateisystem: cp -p, Prüfsumme vergleichen, erst dann das Original entfernen (sonst bleibt es)",
                  "Kontrolle je Datei: sha256sum in der Quarantäne = Prüfsumme vorher; Ursprungsort ist leer. Nichts wird gelöscht."]
        return lines
    if aid == "delete_quarantine":
        dirs = {q.get("name"): q for q in params.get("quarantine_dirs") or []}
        names = [k for k in _picked(params, "k") if QUAR_NAME_RE.match(k)]
        lines = ["Je Ordner zuerst prüfen (ohne Änderung): liegt im Home-Verzeichnis, ist kein Verweis, enthält QUARANTAENE.txt und gehört laut Liste zu dieser Seite. Sonst wird er übersprungen."]
        for n in names[:40]:
            q = dirs.get(n) or {}
            lines.append("rm -rf -- ~/%s%s" % (n, "   # %d Datei(en), danach nicht mehr zurückholbar" % q["count"] if q.get("count") else ""))
        if len(names) > 40:
            lines.append("# ... und %d weitere Ordner" % (len(names) - 40))
        if not names:
            lines.append("rm -rf -- ~/claudia-quarantaene-<datum>")
        lines.append("Kontrolle: Ordner ist nicht mehr vorhanden. Die Dateien werden nicht geöffnet oder ausgeführt.")
        return lines
    if aid == "restore_quarantine":
        known = {}
        for q in params.get("quarantines") or []:
            for e in q.get("entries") or []:
                known["%s/%s" % (q.get("name"), e.get("id"))] = e
        keys = [k for k in _picked(params, "q") if QUAR_KEY_RE.match(k)]
        lines = ["Je Datei zuerst prüfen (ohne Änderung): liegt noch in der Quarantäne, gehört zu dieser Seite, SHA-256 gleich der Liste, Ursprungsordner vorhanden, beschreibbar und in der Seite, "
                 "Ursprungsort leer. Trifft etwas nicht zu, wird genau diese Datei übersprungen; nichts wird überschrieben, kein Ordner angelegt."]
        for k in keys[:40]:
            e = known.get(k) or {}
            qn, nr = k.split("/")
            lines.append("mv -n -- ~/%s/d/%s.q %s%s" % (qn, nr, e.get("origin") or "<Ursprungspfad laut Liste>",
                                                          "    # Ursprungsort belegt: wird übersprungen" if e.get("state") == "belegt" else ""))
            lines.append("chmod %s %s   (ursprüngliche Rechte laut Liste)" % (e.get("mode") or "<Rechte>", e.get("origin") or "<Ursprungspfad>"))
        if len(keys) > 40:
            lines.append("# ... und %d weitere Dateien" % (len(keys) - 40))
        if not keys:
            lines += ["mv -n -- ~/claudia-quarantaene-<datum>/d/<Nr>.q <Ursprungspfad laut QUARANTAENE.txt>", "chmod <Rechte laut Liste> <Ursprungspfad>"]
        lines += ["Anderes Dateisystem: cp -p, Prüfsumme vergleichen, erst dann die Datei in der Quarantäne entfernen",
                  "Kontrolle: sha256sum am Ursprungsort = Liste; die Datei in der Quarantäne ist weg; Eintrag in ZURUECK.txt. Der Besitzer wird nicht gesetzt (nur ein Hinweis, falls er abweicht)."]
        return lines
    if aid == "remove_db_code":
        n = len(_picked(params, "x"))
        return ["SELECT HEX(<Spalte>) FROM #__<Tabelle> WHERE <ID-Spalte> = <ID>   (nur lesend; für die %d gewählten Einträge)" % n,
                "Auf diesem Computer: schädliche <script>/<iframe>-Blöcke bestimmen und entfernen (Regeln wie in der Prüfung)",
                "Sicherung: ~/claudia-sicherung-dbcode-<datum>/rueckgaengig.sql mit je einem UPDATE ... SET <Spalte> = UNHEX('<alter Wert>') je Eintrag, Prüfsumme kontrolliert",
                "UPDATE #__<Tabelle> SET <Spalte> = UNHEX('<neuer Wert>') WHERE <ID-Spalte> = <ID> AND HEX(<Spalte>) = '<alter Wert>'   (nur wenn der Wert seit dem Lesen unverändert ist)",
                "Kontrolle: SELECT HEX(<Spalte>) ... muss dem neuen Wert entsprechen",
                "Der genaue Inhalt (was entfernt wird) steht unter 'Änderungen'."]
    if aid == "reset_htaccess":
        std = ("Auf diesem Computer: Original-Paket von Joomla %s laden, Prüfsumme prüfen, daraus htaccess.txt lesen" % (params.get("version") or "?")) if params.get("cms") != "wordpress" else "Standardblock von WordPress (RewriteBase aus der vorhandenen Datei, sonst /)"
        return ["Lesen: cat .htaccess   (Hauptordner; ein Verweis/Symlink wird abgelehnt)", std,
                "Sicherung: cp -p .htaccess ~/claudia-sicherung-htaccess-<datum>/htaccess.vorher   (mit cmp geprüft), dazu rueckgaengig.txt",
                "Neue Datei schreiben: .htaccess.claudia-neu (Rechte wie die alte Datei), Prüfsumme vergleichen, dann mv -f .htaccess.claudia-neu .htaccess",
                "Test: Startseite per https abrufen; bei Serverfehler (5xx) sofort cp -p htaccess.vorher .htaccess",
                "Der genaue Inhalt (Vergleich alt/neu) steht unter 'Änderungen'."]
    if aid == "harden_perms":
        n = len(params.get("files") or [])
        cfg = params.get("config") or ""
        return ["Rechte-Protokoll: stat -c '%a %n' <Datei>  (vorher, nach ~/claudia-sicherung-rechte-<datum>/rechte_vorher.txt)"] + (["chmod 440 -- %s   (Konfigurationsdatei)" % cfg] if cfg else []) + \
               ["chmod g-w -- <Datei oder Ordner>   für %d Eintrag/Einträge, die die Prüfung gemeldet hat" % (n - (1 if cfg else 0)),
                "Test: Startseite per https abrufen; bei Fehler oder HTTP 500 und höher sofort chmod <alte Rechte> aus rechte_vorher.txt"]
    if aid in HARDEN_ACTIONS:
        return ["Lesen: .htaccess im Hauptordner (ein Verweis/Symlink wird abgelehnt; Apache nötig)",
                "Sicherung: cp -p .htaccess ~/claudia-sicherung-htaccess-<datum>/htaccess.vorher   (nur wenn schon eine .htaccess da ist; wird mit cmp geprüft)",
                "rueckgaengig.txt schreiben: Befehl zum Wiederherstellen bzw. zum Löschen der neuen Datei",
                "Anhängen bzw. anlegen: .htaccess  mit diesem Block (der Rest der Datei bleibt unverändert):"] + ["    " + l for l in ht_block_text(aid, dict(params, headers=params.get("headers") or list(HT_HEADERS))).rstrip("\n").split("\n")] + [
                "Test: " + HT_TEST[aid],
                "Bei Fehler (Startseite nicht erreichbar, Wirkung fehlt): sofort cp -p htaccess.vorher .htaccess bzw. rm der neuen Datei"]
    if aid == "block_php_uploads":
        ud = _upload_dir(params)
        return ["Sicherung: cp -p %s/.htaccess ~/claudia-sicherung-htaccess-<datum>/htaccess.vorher   (nur wenn schon eine .htaccess da ist; wird mit cmp geprüft)" % ud,
                "rueckgaengig.txt schreiben: Befehl zum Wiederherstellen bzw. zum Löschen der neuen Datei",
                "Anhängen bzw. anlegen: %s/.htaccess  mit diesem Inhalt:" % ud] + ["    " + l for l in HTACCESS_NOPHP.rstrip("\n").split("\n")] + [
                "Test: Datei %s/claudia-test-<Zufall>.txt und .php anlegen (harmloser Inhalt), beide per https abrufen" % ud,
                "Erwartet: .txt wird ausgeliefert, .php wird NICHT ausgeführt; sonst Rückgängig mit dem gesicherten Stand",
                "rm -f -- %s/claudia-test-<Zufall>.txt %s/claudia-test-<Zufall>.php   (immer, auch bei Fehlern)" % (ud, ud)]
    php = _php(params, choices) if a["needs_php"] else ""
    if aid == "check_updates":
        return ["%s cli/joomla.php core:check-updates" % php, "%s cli/joomla.php update:extensions:check" % php]
    if aid == "core_update":
        return pre + ["%s cli/joomla.php core:check-updates" % php, "%s cli/joomla.php core:update" % php]
    if aid == "clear_cache":
        return ["%s cli/joomla.php cache:clean" % php]
    raise ActionError("Unbekannte Aktion.")


class Traced:
    """Hüllt den Runner ein: jeder Befehl und jede Antwort des Servers wird dem Statusfenster gemeldet (Passwörter und Download-Schlüssel maskiert)."""

    def __init__(self, runner: Runner, emit: Callable[[str, str], None], secrets: Optional[List[str]] = None):
        self.runner, self.emit, self.secrets = runner, emit, [x for x in (secrets or []) if x]
        self.notes: List[str] = []              # Hinweise für das Ergebnis (z. B. Sicherungsordner im öffentlichen Bereich)
        self.meta: Dict[str, Any] = {}          # Aktion, Titel, Befund: kommt in die MANIFEST.txt der Sicherung

    def mask(self, text: str) -> str:
        for sec in self.secrets:
            text = text.replace(sec, "***")
        return re.sub(r"(dlid|download_key|key|token)=[^&\s'\"]+", r"\1=***", text, flags=re.I)

    def sh(self, site_dir: str, script: str, timeout: float = 120.0, stdin: Optional[str] = None):
        self.emit("cmd", self.mask(script.strip()))
        r = self.runner.sh(site_dir, script, timeout, stdin)
        text = (r.out or "").rstrip()
        if (r.err or "").strip():
            text += ("\n" if text else "") + r.err.rstrip()
        self.emit("out", self.mask(text)[-2500:] if text else "(keine Ausgabe)")
        if r.timed_out:
            self.emit("err", "Zeitüberschreitung: der Server hat nicht rechtzeitig geantwortet.")
        return r


def _ext_updates_sql() -> str:
    return ("SELECT u.update_id AS uid, u.extension_id AS eid, u.name AS name, u.element AS element, u.type AS type, u.client_id AS client, "
            "u.version AS new_version, IFNULL(JSON_UNQUOTE(JSON_EXTRACT(e.manifest_cache,'$.version')),'') AS old_version, "
            "u.detailsurl AS detailsurl, IF(IFNULL(u.extra_query,'')='',0,1) AS needs_key "
            "FROM #__updates u JOIN #__extensions e ON e.extension_id=u.extension_id "
            "WHERE u.extension_id<>0 AND NOT (u.element='joomla' AND u.type='file') ORDER BY u.name")


def parse_ext_updates(out: str) -> List[Dict[str, Any]]:
    lines = [l for l in (out or "").split("\n") if l.strip()]
    if len(lines) < 2:
        return []
    head = lines[0].split("\t")
    rows = []
    for ln in lines[1:]:
        cells = ln.split("\t")
        if len(cells) < len(head):
            continue
        d = dict(zip(head, cells))
        try:
            d["uid"], d["eid"] = int(d["uid"]), int(d["eid"])
        except (ValueError, KeyError):
            continue
        d["needs_key"] = d.get("needs_key") == "1"
        if not re.match(r"^https://[A-Za-z0-9.-]+(:\d+)?/\S*$", d.get("detailsurl", "")) or not re.match(r"^[0-9A-Za-z._-]+$", d.get("new_version", "")):
            continue
        rows.append(d)
    return rows[:80]


def pick_download(xml_text: str, version: str, element: str = "") -> str:
    """Download-Adresse des Pakets zur gewünschten Version aus dem Update-Manifest (XML). Leer, wenn nichts Passendes gefunden wird."""
    import xml.etree.ElementTree as ET
    try:
        if "<!DOCTYPE" in xml_text or "<!ENTITY" in xml_text:
            return ""
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return ""
    best = ""
    for up in root.iter("update"):
        v = (up.findtext("version") or "").strip()
        if v != version:
            continue
        for dl in up.iter("downloadurl"):
            u = (dl.text or "").strip()
            if re.match(r"^https://[A-Za-z0-9.-]+(:\d+)?/\S*$", u) and (dl.get("type", "full") in ("full", "")):
                return u
            if re.match(r"^https://[A-Za-z0-9.-]+(:\d+)?/\S*$", u) and not best:
                best = u
    return best


def run_action(runner: Runner, site_dir: str, aid: str, params: Dict[str, Any], choices: List[Dict[str, Any]],
               allowed_files: Optional[List[str]] = None, emit: Optional[Callable[[str, str], None]] = None,
               secrets: Optional[List[str]] = None, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Führt die Aktion aus. Rückgabe: {ok, steps:[{title, ok, output}], backup_dir, message}.

    emit(kind, text) meldet laufend an das Statusfenster: info | cmd | out | ok | err.
    context: {"ext_updates": [...], "joomla": "6.2.0"} aus der letzten Update-Suche."""
    a = ACTIONS.get(aid)
    if not a:
        raise ActionError("Unbekannte Aktion.")
    emit = emit or (lambda k, t: None)
    tr = Traced(runner, emit, secrets)
    context = context or {}
    tr.meta = {"aid": aid, "title": a["title"], "befund": str(context.get("befund") or "")}
    steps: List[Dict[str, Any]] = []

    def log(title: str, ok: bool, out: str = "") -> None:
        steps.append({"title": title, "ok": ok, "output": tr.mask(out or "")})
        emit("ok" if ok else "err", ("%s: erledigt" if ok else "%s: FEHLGESCHLAGEN") % title)

    result: Dict[str, Any] = {"ok": False, "steps": steps, "backup_dir": "", "message": ""}

    def finish(res: Dict[str, Any]) -> Dict[str, Any]:
        if tr.notes:
            res["warnings"] = list(tr.notes)
            if res.get("ok") and res.get("message"):
                res["message"] = res["message"] + " " + " ".join(tr.notes)
        if res["ok"]:
            emit("done", res.get("message") or "Fertig.")
        else:
            emit("fail", res.get("error") or "Die Aktion wurde nicht erfolgreich abgeschlossen. Details stehen oben.")
        return res

    emit("info", "Start: %s" % a["title"])
    try:
        php = _php(params, choices) if a["needs_php"] else ""
        if aid == "update_extensions":
            _selected_updates(params, context)          # ohne gültige Auswahl nicht erst eine Sicherung anlegen
        if aid in ("install_security", "install_backup"):
            tgt = _security_target(params, _tool_kind(aid))              # unbekannte Erweiterung: abbrechen, bevor eine Sicherung entsteht
            if tgt["cms"] == "wordpress" and not re.match(r"^[A-Za-z0-9._/~+-]+$", str(params.get("wpcli") or "")):
                raise ActionError("WP-CLI wurde auf dem Server nicht gefunden. Installiere das Plugin im Dashboard unter Plugins -> Installieren.")
        if aid in ("wp_update", "wp_core_reinstall") and not re.match(r"^[A-Za-z0-9._/~+-]+$", str(params.get("wpcli") or "")):
            raise ActionError("WP-CLI wurde auf dem Server nicht gefunden. Aktualisiere im WordPress-Dashboard unter Dashboard -> Aktualisierungen.")
        if a["backup"]:
            emit("info", "Schritt 1: Sicherung anlegen und prüfen (ohne gültige Sicherung wird nichts verändert)")
            result["backup_dir"] = make_backup(tr, site_dir, log)
        runner = tr   # ab hier laufen alle Befehle über das Statusfenster

        if aid == "wp_remove_maintenance":
            chk = runner.sh(site_dir, 'if [ -f .maintenance ] && [ ! -L .maintenance ] && [ "$(wc -c < .maintenance)" -lt 1024 ]; then cat .maintenance; echo; echo "@@OK"; fi', 30)
            body = chk.out.split("@@OK")[0]
            if "@@OK" not in chk.out or not re.fullmatch(r"\s*<\?php\s*\$upgrading\s*=\s*\d+\s*;\s*(\?>)?\s*", body):
                raise ActionError("Die Datei .maintenance sieht nicht wie die übliche Wartungsdatei aus (oder gibt es nicht mehr). Es wurde nichts gelöscht.")
            out = _mkdir_backup(runner, site_dir, "wartung")
            r = runner.sh(site_dir, "cp -p .maintenance %s/.maintenance && echo kopiert" % sq(out), 30)
            log("Kopie der .maintenance anlegen", "kopiert" in r.out, (r.err or "")[:200])
            if "kopiert" not in r.out:
                raise ActionError("Die Kopie ist nicht gelungen. Es wurde nichts gelöscht.")
            r = runner.sh(site_dir, "rm -f -- .maintenance; [ ! -e .maintenance ] && echo weg", 30)
            log(".maintenance löschen", "weg" in r.out, (r.err or "")[:200])
            result["ok"] = "weg" in r.out
            result["backup_dir"] = out
            result["message"] = "Der Wartungsmodus ist beendet, die Seite ist wieder erreichbar. Kopie: %s" % out if result["ok"] else ""
            if not result["ok"]:
                result["error"] = "Die Datei konnte nicht gelöscht werden (Rechte?). Lösche .maintenance per SFTP."
            return finish(result)
        if aid == "joomla_core_reinstall":
            _run_joomla_core(runner, site_dir, params, log, result)
            return finish(result)
        if aid in ("fix_permissions", "fix_update_perms"):
            files = [f for f in (params.get("files") or []) if isinstance(f, str)]
            if allowed_files is not None:
                files = [f for f in files if f in allowed_files]          # nur, was die Prüfung selbst gemeldet hat
            files = [f for f in files if _safe_path(f)][:CHMOD_MAX]
            if not files:
                raise ActionError("Keine passenden Dateien.")
            args = " ".join(sq(f) for f in files)
            log_path = _mkdir_backup(runner, site_dir, "rechte")
            r = runner.sh(site_dir, "mkdir -p -m 700 %s && for f in %s; do if [ -e \"$f\" ] && [ ! -L \"$f\" ]; then stat -c '%%a %%n' -- \"$f\" >> %s/rechte_vorher.txt; "
                                    "chmod %s -- \"$f\" && echo \"OK $f\" || echo \"FEHLER $f\"; else echo \"UEBERSPRUNGEN $f\"; fi; done"
                          % (sq(log_path), args, sq(log_path), "u+rwX" if aid == "fix_update_perms" else "o-w"), 120)
            okn = sum(1 for l in lines_of(r.out) if l.startswith("OK "))
            bad = [l for l in lines_of(r.out) if l.startswith(("FEHLER", "UEBERSPRUNGEN"))]
            log("Rechte ändern", okn > 0 and not any(l.startswith("FEHLER") for l in bad),
                "%d geändert, %d übersprungen/fehlgeschlagen. Vorher-Rechte: %s/rechte_vorher.txt" % (okn, len(bad), log_path))
            result["ok"] = okn > 0
            result["backup_dir"] = log_path
            result["message"] = ("Bei %d Datei(en) hat der Besitzer wieder Schreibrecht." if aid == "fix_update_perms" else "Bei %d Datei(en) wurde das Schreibrecht für alle entfernt. Hinweis: Deren ctime (Änderungszeit des Eintrags) ist jetzt neu; die Prüfung 'Kürzlich geänderte Dateien' zeigt sie als ctime-Änderung.") % okn
            return finish(result)

        if aid == "backup_now":
            result["ok"] = True
            result["message"] = "Die Sicherung wurde angelegt und geprüft: %s" % result["backup_dir"]
            return finish(result)
        if aid == "clean_tmp":
            _run_clean_tmp(runner, site_dir, params, log, result)
            return finish(result)
        if aid == "delete_old_backups":
            _run_delete_backups(runner, site_dir, params, log, result)
            return finish(result)
        if aid == "remove_jce_profiles":
            _run_remove_jce(runner, site_dir, params, log, result)
            return finish(result)
        if aid == "remove_shells":
            _run_remove_shells(runner, site_dir, params, allowed_files, log, result)
            return finish(result)
        if aid == "restore_quarantine":
            _run_restore_quarantine(runner, site_dir, params, log, result)
            return finish(result)
        if aid == "delete_quarantine":
            _run_delete_quarantine(runner, site_dir, params, log, result)
            return finish(result)
        if aid == "remove_db_code":
            _run_remove_db_code(runner, site_dir, params, log, result)
            return finish(result)
        if aid == "reset_htaccess":
            _run_reset_htaccess(runner, site_dir, params, context, log, result)
            return finish(result)
        if aid == "block_php_uploads":
            _run_block_php(runner, site_dir, params, context, log, result)
            return finish(result)
        if aid == "harden_perms":
            _run_harden_perms(runner, site_dir, params, allowed_files, context, log, result)
            return finish(result)
        if aid in HARDEN_ACTIONS:
            _run_ht_block(runner, site_dir, aid, params, context, log, result)
            return finish(result)
        if aid == "block_users":
            _run_block_users(runner, site_dir, params, log, result)
            return finish(result)
        if aid == "revoke_tokens":
            _run_revoke_tokens(runner, site_dir, params, log, result)
            return finish(result)
        if aid == "end_sessions":
            _run_end_sessions(runner, site_dir, log, result)
            return finish(result)
        if aid == "disable_api":
            _run_disable_api(runner, site_dir, log, result)
            return finish(result)
        if aid == "deactivate_extension":
            _run_deactivate_joomla(runner, site_dir, params, log, result)
            return finish(result)
        if aid == "wp_deactivate_plugin":
            _run_deactivate_wp(runner, site_dir, php, params, log, result)
            return finish(result)
        if aid == "update_extensions":
            _run_update_extensions(runner, site_dir, php, params, context, log, result, emit)
            return finish(result)
        if aid in ("wp_update", "wp_core_reinstall"):
            _run_wp_cli(runner, site_dir, php, aid, params, log, result)
            return finish(result)
        if aid in ("install_security", "install_backup"):
            _run_install_security(runner, site_dir, php, tgt, params, log, result)
            return finish(result)
        if aid in ("wp_salts", "wp_disallow_edit"):
            _run_wp_config_edit(runner, site_dir, aid, log, result)
            return finish(result)
        if aid == "wp_fix_registration":
            _run_wp_registration(runner, site_dir, log, result)
            return finish(result)

        cli = "timeout -k 5 %d %s cli/joomla.php " % (1500 if aid == "core_update" else 300, sq(php))
        if aid == "check_updates":
            r1 = runner.sh(site_dir, cli + "core:check-updates </dev/null 2>&1", 330)
            log("Joomla-Update prüfen", r1.rc == 0, r1.out.strip()[-800:])
            r2 = runner.sh(site_dir, cli + "update:extensions:check </dev/null 2>&1", 330)
            log("Erweiterungs-Updates prüfen", r2.rc == 0, r2.out.strip()[-1500:])
            current = str(context.get("joomla") or "")
            result["core_check"] = parse_core_check(r1.out, current)
            result["ext_updates"] = []
            ext_rows = None
            sites: List[Dict[str, Any]] = []
            try:
                cfg = _read_cfg(runner, site_dir)
                pw = str(cfg.get("password", "")) + "\n"
                r3 = runner.sh(site_dir, _mysql_script(cfg, _ext_updates_sql()), 60, stdin=pw)
                if r3.rc == 0:
                    ext_rows = parse_ext_updates(r3.out)
                    result["ext_updates"] = ext_rows
                    log("Liste der Erweiterungs-Updates auslesen", True, "%d Update(s) gefunden" % len(ext_rows))
                else:
                    log("Liste der Erweiterungs-Updates auslesen", False, (r3.err or r3.out)[:300])
                r4 = runner.sh(site_dir, _mysql_script(cfg, updcheck.SITES_SQL), 90, stdin=pw)
                if r4.rc == 0:
                    sites = updcheck.parse_sites(r4.out)
            except ActionError as e:
                log("Liste der Erweiterungs-Updates auslesen", False, str(e))
            ages = {x["sid"]: x["age"] for x in sites}
            stale = (sum(1 for v in ages.values() if v > updcheck.FRESH_SECONDS), len(ages)) if ages else None
            live = updcheck.live_extensions(sites, current, lambda m: emit("info", m))
            live_core = updcheck.live_core(current)
            result["assess"] = updcheck.assess(result["core_check"], r1.rc == 0 and r2.rc == 0, ext_rows, stale, live, live_core, current)
            log("Gegenprobe über die Update-Server", bool(live.get("ran")) and not result["assess"]["live_extra"],
                ("%d Update-Server abgefragt, %d Abweichung(en)" % (live.get("sites", 0), len(result["assess"]["live_extra"]))) if live.get("ran") else "nicht möglich (%s)" % (live.get("reason") or "keine Quellen"))
            result["ok"] = r1.rc == 0 and r2.rc == 0
            diag = php_problem_text(r1.out + "\n" + r2.out, php)
            if diag and not result["ok"]:
                result["error"] = diag
            elif not result["ok"]:
                result["error"] = "Die Joomla-Kommandozeile hat die Suche nicht abgeschlossen. Mögliche Ursache: PHP-Version der Kommandozeile oder fehlende Rechte. Mit „Erneut suchen“ probierst du es noch einmal."
            result["message"] = updcheck.message(result["assess"], len(result["ext_updates"]))
        elif aid == "core_update":
            r = runner.sh(site_dir, cli + "core:update </dev/null 2>&1", 1560)
            log("Joomla aktualisieren", r.rc == 0 and not r.timed_out, r.out.strip()[-1500:])
            result["ok"] = r.rc == 0 and not r.timed_out
            if not result["ok"]:
                result["error"] = php_problem_text(r.out, php) or "Das Update ist fehlgeschlagen. Die Einzelheiten stehen im Statusfenster. Die Sicherung liegt in %s." % result.get("backup_dir", "-")
            result["message"] = "Joomla wurde aktualisiert. Prüfe deine Webseite im Browser." if result["ok"] else ""
        elif aid == "clear_cache":
            r = runner.sh(site_dir, cli + "cache:clean </dev/null 2>&1", 330)
            log("Cache leeren", r.rc == 0, r.out.strip()[-600:])
            result["ok"] = r.rc == 0
            result["message"] = "Der Cache wurde geleert." if result["ok"] else ""
    except ActionError as e:
        log("Abbruch", False, str(e))
        result["error"] = str(e)
    except RunnerError as e:
        log("Verbindungsfehler", False, str(e))
        result["error"] = str(e)
    return finish(result)


# ------------------------------------------------------------------------------------------------ einzelne Aktionen
def _salt() -> str:
    import secrets as _s
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#%^&*()-_=+[]{}<>~,.;:|"
    return "".join(_s.choice(alphabet) for _ in range(64))


def _wp_config_text(runner, site_dir: str) -> str:
    r = runner.sh(site_dir, "test -f wp-config.php && cat wp-config.php", 30)
    if not r.out.strip() or "wp-settings.php" not in r.out:
        raise ActionError("Die wp-config.php liegt nicht im Seitenordner oder sieht ungewöhnlich aus (liegt sie eine Ebene höher, bitte von Hand ändern). Es wurde nichts verändert.")
    return r.out


def edit_wp_config(text: str, kind: str) -> str:
    """Reine Textänderung der wp-config.php (testbar). kind: 'salts' | 'edit'."""
    if kind == "salts":
        new = text
        for k in wordpress.SECRET_KEYS:
            pat = re.compile(r"(define\s*\(\s*['\"]%s['\"]\s*,\s*)(['\"]).*?\2(\s*\)\s*;)" % k, re.S)
            val = _salt()                      # enthält weder ' noch \
            if pat.search(new):
                new = pat.sub(lambda m: "%s'%s'%s" % (m.group(1), val, m.group(3)), new, count=1)
            else:
                marker = re.search(r"\n\$table_prefix", new) or re.search(r"\n[^\n]*wp-settings\.php", new)
                if marker:
                    new = new[:marker.start() + 1] + "define( '%s', '%s' );\n" % (k, val) + new[marker.start() + 1:]
        return new
    if re.search(r"define\s*\(\s*['\"]DISALLOW_FILE_EDIT['\"]", text):
        return re.sub(r"(define\s*\(\s*['\"]DISALLOW_FILE_EDIT['\"]\s*,\s*)(false|0|'0'|\"0\")(\s*\))", r"\1true\3", text, count=1)
    m = re.search(r"\n[^\n]*(?:That's all|require_once\s+ABSPATH\s*\.\s*['\"]wp-settings\.php|require_once\s*\(?\s*ABSPATH)", text)
    line = "define( 'DISALLOW_FILE_EDIT', true );\n"
    if not m:
        raise ActionError("Die Stelle für die neue Zeile wurde in der wp-config.php nicht gefunden. Bitte von Hand ergänzen.")
    return text[:m.start() + 1] + line + text[m.start() + 1:]


def _run_wp_config_edit(runner, site_dir: str, aid: str, log, result: Dict[str, Any]) -> None:
    kind = "salts" if aid == "wp_salts" else "edit"
    old = _wp_config_text(runner, site_dir)
    new = edit_wp_config(old, kind)
    if new == old:
        result["ok"] = True
        result["message"] = "Es gab nichts zu ändern: Die Einstellung ist bereits so gesetzt."
        return
    out = _mkdir_backup(runner, site_dir, "wpconfig")
    q = sq(out)
    r = runner.sh(site_dir, "cp -p wp-config.php %s/wp-config.php && echo kopiert" % q, 30)
    log("Kopie der wp-config.php anlegen", "kopiert" in r.out, (r.err or "")[:200])
    if "kopiert" not in r.out:
        raise ActionError("Die Kopie ist nicht gelungen. Es wurde nichts verändert.")
    result["backup_dir"] = out
    # neue Datei neben der alten schreiben, prüfen, dann mit denselben Rechten austauschen
    r = runner.sh(site_dir, "cat > wp-config.php.claudia-neu && chmod --reference=wp-config.php wp-config.php.claudia-neu 2>/dev/null; echo geschrieben", 30, stdin=new)
    if "geschrieben" not in r.out:
        runner.sh(site_dir, "rm -f wp-config.php.claudia-neu", 15)
        raise ActionError("Die neue Datei konnte nicht geschrieben werden. Es wurde nichts verändert.")
    chk = runner.sh(site_dir, "grep -c 'wp-settings.php' wp-config.php.claudia-neu; wc -c < wp-config.php.claudia-neu", 15)
    nums = [x.strip() for x in lines_of(chk.out)]
    good = len(nums) >= 2 and nums[0].isdigit() and int(nums[0]) >= 1 and nums[1].isdigit() and abs(int(nums[1]) - len(old.encode("utf-8"))) < 3000
    log("Neue Datei prüfen", good, "Größe %s Byte (vorher %d)" % (nums[1] if len(nums) > 1 else "?", len(old.encode("utf-8"))))
    if not good:
        runner.sh(site_dir, "rm -f wp-config.php.claudia-neu", 15)
        raise ActionError("Die neue Datei sieht nicht richtig aus. Es wurde nichts verändert.")
    r = runner.sh(site_dir, "mv -f wp-config.php.claudia-neu wp-config.php && echo getauscht", 15)
    log("wp-config.php austauschen", "getauscht" in r.out, (r.err or "")[:200])
    result["ok"] = "getauscht" in r.out
    if result["ok"]:
        result["message"] = ("Neue Schlüssel gesetzt. Alle Benutzer müssen sich neu anmelden. Kopie: %s" % out) if kind == "salts" else (
            "Die Dateibearbeitung im Dashboard ist gesperrt. Kopie: %s" % out)
    else:
        result["error"] = "Die Datei konnte nicht ausgetauscht werden (Rechte?). Eine Kopie liegt in %s." % out


def _run_wp_registration(runner, site_dir: str, log, result: Dict[str, Any]) -> None:
    cfg = _read_cfg(runner, site_dir)
    pw = str(cfg.get("password", "")) + "\n"
    prefix = str(cfg.get("dbprefix", "wp_"))
    out = _mkdir_backup(runner, site_dir, "options")
    r = runner.sh(site_dir, _db_dump_script(cfg, out, [prefix + "options"], "options.sql.gz"), 300, stdin=pw)
    log("Tabelle options sichern", r.rc == 0, (r.err or r.out)[:300])
    if r.rc != 0:
        raise ActionError("Die Sicherung der Tabelle options ist nicht gelungen (%s). Es wurde nichts geändert." % ((r.err or r.out).strip()[:160] or "unbekannter Fehler"))
    result["backup_dir"] = out
    r = runner.sh(site_dir, _mysql_script(cfg, "UPDATE #__options SET option_value = '0' WHERE option_name = 'users_can_register'"), 60, stdin=pw)
    log("Registrierung ausschalten", r.rc == 0, (r.err or r.out)[:200])
    r = runner.sh(site_dir, _mysql_script(cfg, "UPDATE #__options SET option_value = 'subscriber' WHERE option_name = 'default_role' AND option_value = 'administrator'"), 60, stdin=pw)
    log("Standardrolle zurücksetzen", r.rc == 0, (r.err or r.out)[:200])
    r = runner.sh(site_dir, _mysql_script(cfg, "SELECT option_name, option_value FROM #__options WHERE option_name IN ('users_can_register','default_role')"), 60, stdin=pw)
    vals = {}
    for l in lines_of(r.out)[1:]:
        p = l.split("\t")
        if len(p) >= 2:
            vals[p[0]] = p[1]
    ok = vals.get("users_can_register") == "0" and vals.get("default_role") != "administrator"
    log("Kontrolle", ok, "users_can_register=%s, default_role=%s" % (vals.get("users_can_register", "?"), vals.get("default_role", "?")))
    result["ok"] = ok
    result["message"] = "Die offene Registrierung ist aus, neue Benutzer bekommen nie die Rolle Administrator. Sicherung: %s" % out if ok else ""
    if not ok:
        result["error"] = "Die Werte konnten nicht gesetzt werden. Ändere sie im Dashboard unter Einstellungen -> Allgemein."


def _wp_cmd(php: str, wpcli: str, tail: str, seconds: int = 600) -> str:
    return "timeout -k 5 %d %s %s --path=\"$(pwd)\" %s </dev/null 2>&1" % (seconds, sq(php), sq(wpcli), tail)


def _run_wp_cli(runner, site_dir: str, php: str, aid: str, params: Dict[str, Any], log, result: Dict[str, Any]) -> None:
    wpcli = str(params.get("wpcli") or "")
    if not wpcli or not re.match(r"^[A-Za-z0-9._/~+-]+$", wpcli):
        raise ActionError("WP-CLI wurde auf dem Server nicht gefunden. Aktualisiere im WordPress-Dashboard unter Dashboard -> Aktualisierungen.")
    r = runner.sh(site_dir, _wp_cmd(php, wpcli, "core version", 90), 120)
    if r.rc != 0 or not re.search(r"\d+\.\d+", r.out):
        raise ActionError("WP-CLI lässt sich mit diesem PHP-Programm nicht starten: %s. Wähle ein anderes PHP oder aktualisiere im Dashboard." % (php_problem_text(r.out, php) or r.out.strip()[-200:]))
    log("WP-CLI starten", True, "WordPress %s" % r.out.strip().splitlines()[-1])
    if aid == "wp_core_reinstall":
        ver = re.sub(r"[^0-9A-Za-z.\-]", "", str(params.get("version") or ""))
        vopt = ("--version=%s " % ver) if ver else ""
        r = runner.sh(site_dir, _wp_cmd(php, wpcli, "core download --force --skip-content %s--locale=\"$(%s %s --path=\"$(pwd)\" language core list --status=active --field=language 2>/dev/null | head -1)\"" % (
            vopt, sq(php), sq(wpcli)), 900), 960)
        log("Kerndateien neu laden", r.rc == 0 and not r.timed_out, r.out.strip()[-800:])
        if r.rc != 0:
            raise ActionError("Der Download ist fehlgeschlagen (kein Internetzugang des Servers?). Sicherung: %s. Installiere den Kern im Dashboard neu (Aktualisierungen -> Erneut installieren)." % result.get("backup_dir", "-"))
    else:
        for title, tail in (("WordPress-Kern aktualisieren", "core update"), ("Datenbank des Kerns aktualisieren", "core update-db"),
                            ("Plugins aktualisieren", "plugin update --all"), ("Themes aktualisieren", "theme update --all")):
            r = runner.sh(site_dir, _wp_cmd(php, wpcli, tail, 1200), 1260)
            log(title, r.rc == 0 and not r.timed_out, r.out.strip()[-1200:])
    r = runner.sh(site_dir, _wp_cmd(php, wpcli, "core verify-checksums", 300), 330)
    ok_sum = r.rc == 0 and "Success" in r.out
    log("Kerndateien gegen Prüfsummen kontrollieren", ok_sum, r.out.strip()[-800:])
    pending = ""
    if aid == "wp_update":
        r2 = runner.sh(site_dir, _wp_cmd(php, wpcli, "plugin list --update=available --field=name", 120), 150)
        names = [x.strip() for x in lines_of(r2.out) if re.match(r"^[\w.-]+$", x.strip())]
        pending = ", ".join(names)
        log("Noch ausstehende Plugin-Updates", not names, pending or "keine")
    result["ok"] = ok_sum and not pending
    if result["ok"]:
        result["message"] = ("WordPress wurde aktualisiert, die Kerndateien stimmen mit dem Original überein. Prüfe deine Webseite im Browser." if aid == "wp_update"
                             else "Die Kerndateien wurden neu geladen und stimmen mit dem Original überein.")
    else:
        result["error"] = ("Nicht alles war erfolgreich" + ((": für diese Plugins gibt es weiter Updates (meist Premium-Plugins mit eigener Lizenz): %s." % pending) if pending else ".")
                           + " Einzelheiten stehen im Statusfenster. Sicherung: %s." % result.get("backup_dir", "-"))
def _run_install_security(runner, site_dir: str, php: str, tgt: Dict[str, Any], params: Dict[str, Any], log, result: Dict[str, Any]) -> None:
    name = tgt["tool"]["name"]
    if tgt["cms"] == "wordpress":
        wpcli, slug = str(params.get("wpcli") or ""), tgt["slug"]
        r = runner.sh(site_dir, _wp_cmd(php, wpcli, "core version", 90), 120)
        if r.rc != 0 or not re.search(r"\d+\.\d+", r.out):
            raise ActionError("WP-CLI lässt sich mit diesem PHP-Programm nicht starten: %s." % (php_problem_text(r.out, php) or r.out.strip()[-200:]))
        log("WP-CLI starten", True, "WordPress %s" % r.out.strip().splitlines()[-1])
        r = runner.sh(site_dir, _wp_cmd(php, wpcli, "plugin install %s --activate" % sq(slug), 900), 960)
        log("Plugin installieren und einschalten: %s" % name, r.rc == 0 and not r.timed_out, r.out.strip()[-1000:])
        if r.rc != 0:
            raise ActionError("Die Installation ist fehlgeschlagen (kein Internetzugang des Servers oder Plugin nicht kompatibel?). Es wurde nichts weiter verändert. Sicherung: %s." % result.get("backup_dir", "-"))
        r = runner.sh(site_dir, _wp_cmd(php, wpcli, "plugin is-active %s && echo @@AKTIV" % sq(slug), 120), 150)
        active = r.rc == 0 and "@@AKTIV" in r.out
        log("Ist das Plugin eingeschaltet?", active, r.out.strip()[-300:])
        r = runner.sh(site_dir, _wp_cmd(php, wpcli, "plugin verify-checksums %s" % sq(slug), 300), 330)
        log("Dateien gegen die Prüfsummen von wordpress.org kontrollieren", r.rc == 0 and "Success" in r.out, r.out.strip()[-500:])
        result["ok"] = active
        result["message"] = ("%s wurde installiert und eingeschaltet. Öffne jetzt das Dashboard und folge der Einrichtung des Plugins (Benachrichtigungen, Regeln)." % name) if active else ""
        if not active:
            result["error"] = "Das Plugin wurde installiert, ist aber nicht eingeschaltet. Schalte es im Dashboard unter Plugins ein. Sicherung: %s." % result.get("backup_dir", "-")
        return
    cli = "timeout -k 5 600 %s cli/joomla.php " % sq(php)
    r = runner.sh(site_dir, "curl -fsSL --max-time 40 --proto '=https' -- %s 2>&1 | head -c 2000000" % sq(tgt["manifest"]), 60)
    best = newest_download(r.out)
    log("Download-Adresse aus dem Update-Manifest", bool(best), (("Version %s: %s" % (best["version"], best["url"])) if best else "Im Manifest wurde keine https-Adresse gefunden."))
    if not best:
        raise ActionError("Die Download-Adresse konnte nicht ermittelt werden. Es wurde nichts verändert. Installiere die Erweiterung über die Store-Seite.")
    r = runner.sh(site_dir, cli + "extension:install --url=%s </dev/null 2>&1" % sq(best["url"]), 660)
    good = r.rc == 0 and not r.timed_out
    log("Installieren: %s" % name, good, r.out.strip()[-800:])
    if not good:
        manual = classify_install_failure(r.out) == "cli"
        raise ActionError(("Der Installer dieser Erweiterung läuft nicht über die Kommandozeile. Lade das ZIP von %s und installiere es im Backend unter System -> Installieren -> Erweiterungen." % best["url"]) if manual
                          else "Die Installation ist fehlgeschlagen. Einzelheiten stehen im Statusfenster. Sicherung: %s." % result.get("backup_dir", "-"))
    cfg = _read_cfg(runner, site_dir)
    r = runner.sh(site_dir, _mysql_script(cfg, "SELECT COUNT(*) AS n FROM #__extensions WHERE element = '%s'" % tgt["element"]), 60, stdin=str(cfg.get("password", "")) + "\n")
    n = (lines_of(r.out)[1:] or ["0"])[0].strip()
    ok = n.isdigit() and int(n) > 0
    log("Steht die Erweiterung in der Datenbank?", ok, "Einträge: %s" % (n or "?"))
    runner.sh(site_dir, cli + "cache:clean </dev/null 2>&1", 330)
    result["ok"] = ok
    result["message"] = ("%s %s wurde installiert. Öffne das Backend, schalte die Plugins der Erweiterung ein falls nötig und folge ihrer Einrichtung." % (name, best["version"])) if ok else ""
    if not ok:
        result["error"] = "Die Installation lief durch, die Erweiterung steht aber nicht in der Datenbank. Prüfe das Backend unter System -> Verwalten -> Erweiterungen. Sicherung: %s." % result.get("backup_dir", "-")


def _upload_dir(params: Dict[str, Any]) -> str:
    d = str(params.get("upload_dir") or "images")
    return d if d in ("images", "wp-content/uploads") else "images"


def _tmp_dirs(params: Dict[str, Any]) -> List[str]:
    dirs = [d for d in (params.get("dirs") or ["tmp"]) if d in TMP_DIRS_ALL]
    return list(dict.fromkeys(dirs)) or ["tmp"]


def _log_selection(params: Dict[str, Any]) -> List[str]:
    """Gewählte lokale Protokolle, nur solche aus der angebotenen Liste und nie das neueste je Aktion."""
    if not params.get("log_dir"):
        return []
    known = {l["name"] for l in params.get("logs") or [] if not l.get("newest")}
    return [n for n in dict.fromkeys(params.get("selected_logs") or []) if isinstance(n, str) and LOG_NAME_RE.match(n) and n in known]


def _backup_selection(params: Dict[str, Any]) -> List[str]:
    known = {b["name"] for b in params.get("backups") or []}
    return [n for n in dict.fromkeys(params.get("selected_backups") or []) if isinstance(n, str) and BACKUP_NAME_RE.match(n) and n in known]


LOG_NAME_RE = re.compile(r"^aktion_([a-z_]+)_(\d{8}-\d{6})\.txt$")


def list_local_logs(directory: str) -> List[Dict[str, Any]]:
    """Aktionsprotokolle dieses Programms im lokalen Berichte-Ordner. Je Aktion ist das neueste markiert (newest=True) und wird nie zum Löschen angeboten."""
    import os
    out: List[Dict[str, Any]] = []
    try:
        names = os.listdir(directory)
    except OSError:
        return out
    for n in names:
        m = LOG_NAME_RE.match(n)
        path = os.path.join(directory, n)
        if not m or os.path.islink(path) or not os.path.isfile(path):
            continue
        try:
            kb = max(1, (os.path.getsize(path) + 1023) // 1024)
        except OSError:
            continue
        out.append({"name": n, "action": m.group(1), "stamp": m.group(2), "kb": kb, "newest": False})
    newest: Dict[str, str] = {}
    for e in out:
        if e["action"] not in newest or e["stamp"] > newest[e["action"]]:
            newest[e["action"]] = e["stamp"]
    for e in out:
        e["newest"] = e["stamp"] == newest[e["action"]]
    out.sort(key=lambda e: (e["stamp"], e["name"]), reverse=True)
    return out


def deletable_local_logs(directory: str) -> List[Dict[str, Any]]:
    return [e for e in list_local_logs(directory) if not e["newest"]]


def delete_local_logs(directory: str, names: List[str]) -> Dict[str, List[str]]:
    """Löscht ausgewählte lokale Aktionsprotokolle. Der Server-Teil (Prüfung gegen die Liste auf der Platte) stellt sicher, dass nur passende Dateinamen
    und nie das jeweils neueste Protokoll einer Aktion gelöscht werden."""
    import os
    ok_names = {e["name"] for e in deletable_local_logs(directory)}
    done: List[str] = []
    skipped: List[str] = []
    for n in dict.fromkeys(x for x in names if isinstance(x, str)):
        if n not in ok_names:
            skipped.append(n)
            continue
        try:
            os.remove(os.path.join(directory, n))
            done.append(n)
        except OSError:
            skipped.append(n)
    return {"deleted": done, "skipped": skipped}


def _run_clean_tmp(runner, site_dir: str, params: Dict[str, Any], log, result: Dict[str, Any]) -> None:
    dirs = _tmp_dirs(params)
    chk_lines = []
    for d in dirs:
        q = sq(d)
        chk_lines.append('if [ -d %s ] && [ ! -L %s ]; then r=$(cd %s && pwd -P); p=$(pwd -P); [ "$r" = "$p/%s" ] && '
                         'printf "OK\\t%%s\\t%%s\\t%%s\\n" %s "$(du -sk %s 2>/dev/null | cut -f1)" "$(find %s -mindepth 1 2>/dev/null | wc -l)"; fi' % (q, q, q, d, q, q, q))
    chk = runner.sh(site_dir, "\n".join(chk_lines) + '\ndf -Pk "$HOME" | awk \'NR==2{print $4}\'', 120)
    ok_dirs, size_kb, count = [], 0, 0
    free_kb = 0
    for ln in lines_of(chk.out):
        p = ln.split("\t")
        if p[0] == "OK" and len(p) >= 4 and p[2].strip().isdigit() and p[3].strip().isdigit():
            ok_dirs.append(p[1])
            size_kb += int(p[2])
            count += int(p[3])
        elif ln.strip().isdigit():
            free_kb = int(ln.strip())
    if not ok_dirs:
        raise ActionError("Die Ordner %s wurden nicht eindeutig gefunden (oder sind ein Verweis). Es wurde nichts verändert." % ", ".join(dirs))
    if free_kb < size_kb * 1.3 + 100_000:
        raise ActionError("Zu wenig freier Speicherplatz für die Sicherung von %s." % ", ".join(ok_dirs))
    out = _mkdir_backup(runner, site_dir, "tmp")
    q = sq(out)
    r = runner.sh(site_dir, "tar czf %s/tmp.tgz %s 2>%s/tar_meldungen.txt; rc=$?; [ $rc -le 1 ] && tar tzf %s/tmp.tgz >/dev/null && echo fertig"
                  % (q, " ".join(sq(d) for d in ok_dirs), q, q), 1800)
    log("Inhalt von %s sichern (%d Einträge, %d MB)" % (" und ".join(ok_dirs), count, size_kb // 1024), "fertig" in r.out, r.err.strip()[:200])
    if "fertig" not in r.out:
        raise ActionError("Die Sicherung ist nicht gelungen. Es wurde nichts gelöscht.")
    result["backup_dir"] = out
    script = "\n".join("( cd %s && find . -mindepth 1 -maxdepth 1 ! -name index.html ! -name .htaccess -exec rm -rf -- {} + )" % sq(d) for d in ok_dirs)
    script += "\n" + "\n".join("( cd %s && find . -mindepth 1 ! -name index.html ! -name .htaccess | wc -l )" % sq(d) for d in ok_dirs)
    r = runner.sh(site_dir, script, 900)
    left = [x.strip() for x in lines_of(r.out)[-len(ok_dirs):]] if r.out.strip() else []
    ok = len(left) == len(ok_dirs) and all(x == "0" for x in left)
    log("Ordner leeren", ok, "Übrig geblieben: %s" % ", ".join("%s: %s" % (d, n) for d, n in zip(ok_dirs, left or ["?"] * len(ok_dirs))))
    result["ok"] = ok
    result["message"] = ("%s wurde geleert (%d Einträge). Eine Kopie liegt in %s." % (" und ".join(ok_dirs), count, out)) if ok else ""
    if not ok:
        result["error"] = "Nicht alles konnte gelöscht werden (Rechte?). Der Rest muss im Datei-Manager des Hosters gelöscht werden."


_CORE_PATH_RE = re.compile(r"^[A-Za-z0-9_@+.-]+(?:/[A-Za-z0-9_@+.-]+)*$")


def _upload_file(runner, site_dir: str, local: str, remote: str, log) -> bool:
    """Lädt eine (kleine) Datei verschlüsselt über die bestehende SSH-Verbindung hoch: base64-Text über stdin, Prüfsumme danach."""
    import base64
    import hashlib
    with open(local, "rb") as fh:
        data = fh.read()
    want = hashlib.sha256(data).hexdigest()
    r = runner.sh(site_dir, ": > %s && echo leer" % sq(remote), 30)
    if "leer" not in r.out:
        return False
    step = 3 * 1024 * 1024
    for i in range(0, len(data), step):
        chunk = base64.b64encode(data[i:i + step]).decode("ascii") + "\n"
        r = runner.sh(site_dir, "base64 -d >> %s && echo ok" % sq(remote), 300, stdin=chunk)
        if "ok" not in r.out:
            log("Hochladen", False, (r.err or r.out)[:200])
            return False
    r = runner.sh(site_dir, "sha256sum -- %s 2>/dev/null || shasum -a 256 -- %s" % (sq(remote), sq(remote)), 60)
    got = (lines_of(r.out) or [""])[0].split()[0] if r.out.strip() else ""
    log("Hochgeladene Datei prüfen", got == want, "Erwartet %s..., gelesen %s..." % (want[:16], got[:16]))
    return got == want


def _run_joomla_core(runner, site_dir: str, params: Dict[str, Any], log, result: Dict[str, Any]) -> None:
    import io
    import os
    import tempfile
    import zipfile
    from . import coreref
    version = str(params.get("version") or "")
    if not coreref.VERSION_RE.match(version):
        raise ActionError("Die Joomla-Version ist nicht eindeutig bekannt (%s). Es wurde nichts verändert." % (version or "?"))
    try:
        ref = coreref.reference(version)
        pkg, _ = coreref.package_path(ref)
    except coreref.RefError as e:
        raise ActionError("Das Original-Paket ist nicht verfügbar: %s. Es wurde nichts verändert." % e)
    if not ref.get("verified"):
        raise ActionError("Die Prüfsumme des Original-Pakets ist nicht bestätigt. Es wurde nichts verändert.")
    log("Original-Paket Joomla %s geladen und geprüft" % version, True, "%s, sha256 %s..." % (ref["package"], ref["sha256"][:16]))
    wanted = [str(f)[2:] if str(f).startswith("./") else str(f) for f in (params.get("files") or [])]
    files = [f for f in dict.fromkeys(wanted) if f in ref["files"] and coreref.is_compared(f) and _CORE_PATH_RE.match(f) and not f.startswith(("language/", "administrator/language/"))][:600]
    if not files:
        raise ActionError("Keine passenden Dateien. Es wurde nichts verändert.")
    # Was weicht jetzt noch ab? (Zustand kann sich seit dem Test geändert haben)
    lst = "\n".join(files) + "\n"
    r = runner.sh(site_dir, 'H=sha256sum; command -v sha256sum >/dev/null 2>&1 || H="shasum -a 256"; while IFS= read -r f; do if [ -f "$f" ] && [ ! -L "$f" ]; then $H -- "$f"; '
                  'else echo "FEHLT $f"; fi; done', 300, stdin=lst)
    now = {}
    for ln in lines_of(r.out):
        m = re.match(r"^([0-9a-f]{64})\s+\*?(.+)$", ln)
        if m:
            now[m.group(2)] = m.group(1)
    todo = [f for f in files if now.get(f) != ref["files"][f]]
    log("Abweichende Dateien auf dem Server", True, "%d von %d gemeldeten Dateien weichen noch ab" % (len(todo), len(files)))
    if not todo:
        result["ok"] = True
        result["message"] = "Alle gemeldeten Kerndateien stimmen schon mit dem Original überein. Es war nichts zu tun."
        return
    buf = io.BytesIO()
    with zipfile.ZipFile(pkg) as zin, zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zout:
        for f in todo:
            zi = zipfile.ZipInfo(f, date_time=(2000, 1, 1, 0, 0, 0))
            zi.external_attr = 0o644 << 16
            zi.compress_type = zipfile.ZIP_DEFLATED
            zout.writestr(zi, zin.read(f))
    tmp = tempfile.mkdtemp(prefix="claudia_core_")
    local = os.path.join(tmp, "original.zip")
    try:
        with open(local, "wb") as fh:
            fh.write(buf.getvalue())
        out = result.get("backup_dir") or ""
        if not out:
            raise ActionError("Der Sicherungsordner ist unbekannt. Es wurde nichts verändert.")
        remote = out.rstrip("/") + "/original.zip"
        if not _upload_file(runner, site_dir, local, remote, log):
            raise ActionError("Das Hochladen des Original-ZIPs ist nicht gelungen. Es wurde nichts verändert.")
    finally:
        try:
            os.remove(local)
            os.rmdir(tmp)
        except OSError:
            pass
    q = sq(remote)
    r = runner.sh(site_dir, 'if command -v unzip >/dev/null 2>&1; then unzip -o -q %s -d . && echo entpackt; '
                  'elif command -v python3 >/dev/null 2>&1; then python3 -c "import sys,zipfile; zipfile.ZipFile(sys.argv[1]).extractall(\'.\')" %s && echo entpackt; fi' % (q, q), 600)
    log("Dateien ersetzen", "entpackt" in r.out, (r.err or r.out)[:300])
    lst2 = "\n".join(todo) + "\n"
    r = runner.sh(site_dir, 'H=sha256sum; command -v sha256sum >/dev/null 2>&1 || H="shasum -a 256"; while IFS= read -r f; do [ -f "$f" ] && $H -- "$f"; done', 300, stdin=lst2)
    after = {}
    for ln in lines_of(r.out):
        m = re.match(r"^([0-9a-f]{64})\s+\*?(.+)$", ln)
        if m:
            after[m.group(2)] = m.group(1)
    bad = [f for f in todo if after.get(f) != ref["files"][f]]
    log("Prüfsummen nach dem Ersetzen", not bad, "%d von %d Dateien stimmen mit dem Original überein%s" % (len(todo) - len(bad), len(todo), ("; abweichend: " + ", ".join(bad[:5])) if bad else ""))
    runner.sh(site_dir, "rm -f -- %s" % q, 30)
    result["ok"] = not bad
    result["message"] = "%d Kerndatei(en) wurden durch das Original von Joomla %s ersetzt und per Prüfsumme kontrolliert. Sicherung: %s" % (len(todo), version, result.get("backup_dir")) if not bad else ""
    if bad:
        result["error"] = "Nicht alle Dateien konnten ersetzt werden (Rechte?): %s. Die Sicherung liegt in %s." % (", ".join(bad[:5]), result.get("backup_dir"))


def _run_delete_backups(runner, site_dir: str, params: Dict[str, Any], log, result: Dict[str, Any]) -> None:
    names = _backup_selection(params)
    logdir = str(params.get("log_dir") or "")
    sel_logs = _log_selection(params)
    if not names and not sel_logs:
        raise ActionError("Nichts ausgewählt.")
    ok_all, msgs, errs = True, [], []
    if names:
        script = ('H="$HOME"; while IFS= read -r -d "" n; do case "$n" in claudia-sicherung-*|' + OLD_ID + '-sicherung-*) ;; *) echo "UEBERSPRUNGEN $n"; continue;; esac; p="$H/$n"; '
                  'if [ -d "$p" ] && [ ! -L "$p" ]; then rm -rf -- "$p"; if [ -e "$p" ]; then echo "FEHLER $n"; else echo "OK $n"; fi; else echo "UEBERSPRUNGEN $n"; fi; done')
        r = runner.sh(site_dir, script, 600, stdin="\0".join(names) + "\0")
        okn = [l[3:] for l in lines_of(r.out) if l.startswith("OK ")]
        bad = [l for l in lines_of(r.out) if not l.startswith("OK ")]
        log("Sicherungen löschen", len(okn) == len(names), "%d gelöscht, %d nicht gelöscht" % (len(okn), len(bad)))
        if len(okn) == len(names):
            msgs.append("%d Sicherung(en) auf dem Server gelöscht." % len(okn))
        else:
            ok_all = False
            errs.append("Nicht alle Sicherungen konnten gelöscht werden: " + "; ".join(bad[:4]))
    if sel_logs:
        res = delete_local_logs(logdir, sel_logs)
        good = len(res["deleted"]) == len(sel_logs)
        log("Protokolle auf diesem Computer löschen", good,
            "%d gelöscht%s" % (len(res["deleted"]), ("; nicht gelöscht (z. B. das neueste Protokoll einer Aktion): " + ", ".join(res["skipped"][:4])) if res["skipped"] else ""))
        if good:
            msgs.append("%d Protokoll(e) auf diesem Computer gelöscht." % len(res["deleted"]))
        else:
            ok_all = False
            errs.append("Nicht alle Protokolle konnten gelöscht werden: " + ", ".join(res["skipped"][:4]))
    result["ok"] = ok_all
    result["message"] = " ".join(msgs) if ok_all else ""
    if not ok_all:
        result["error"] = " ".join(errs)


def _run_remove_jce(runner, site_dir: str, params: Dict[str, Any], log, result: Dict[str, Any]) -> None:
    ids = sorted({int(i) for i in (params.get("ids") or [])})
    if not ids:
        raise ActionError("Keine Profile ausgewählt.")
    idl = ",".join(str(i) for i in ids)
    cfg = _read_cfg(runner, site_dir)
    pw = str(cfg.get("password", "")) + "\n"
    r = runner.sh(site_dir, _mysql_script(cfg, "SELECT id, name FROM #__wf_profiles WHERE id IN (%s) AND params LIKE '%%php%%'" % idl), 60, stdin=pw)
    if r.rc != 0:
        raise ActionError("Die Profile konnten nicht gelesen werden: %s" % (r.err or r.out)[:200])
    rows = [l.split("\t") for l in lines_of(r.out)[1:]]
    todo = [int(x[0]) for x in rows if len(x) >= 2 and x[0].isdigit() and x[1].strip().lower() not in SAFE_JCE_NAMES]
    kept = [x[1] for x in rows if len(x) >= 2 and x[1].strip().lower() in SAFE_JCE_NAMES]
    log("Profile prüfen", True, "Zu löschen: %s%s" % (", ".join("#%d" % i for i in todo) or "keine", ("; Standardprofile mit 'php' bitte von Hand ansehen: " + ", ".join(kept)) if kept else ""))
    if not todo:
        result["ok"] = True
        result["message"] = "Es gibt keine schädlichen Profile mehr, die gelöscht werden müssten."
        return
    out = ""
    if params.get("no_backup"):
        log("Sicherung übersprungen (auf deinen ausdrücklichen Wunsch)", True, "Es entsteht keine Kopie der Profile.")
    else:
        out = _mkdir_backup(runner, site_dir, "jce")
        prefix = str(cfg.get("dbprefix", "jos_"))
        r = runner.sh(site_dir, _db_dump_script(cfg, out, [prefix + "wf_profiles"], "wf_profiles.sql.gz"), 300, stdin=pw)
        log("Tabelle der JCE-Profile sichern", r.rc == 0, (r.err or r.out)[:300])
        if r.rc != 0:
            result["backup_failed"] = True
            raise ActionError("Die Sicherung der JCE-Profile ist nicht gelungen (%s). Es wurde nichts gelöscht. Du kannst die Profile auf eigenen Wunsch "
                              "auch ohne Sicherung löschen (zusätzlicher Knopf) oder die Tabelle vorher selbst im phpMyAdmin exportieren."
                              % ((r.err or r.out).strip()[:160] or "unbekannter Fehler"))
        result["backup_dir"] = out
    tl = ",".join(str(i) for i in todo)
    r = runner.sh(site_dir, _mysql_script(cfg, "DELETE FROM #__wf_profiles WHERE id IN (%s) AND params LIKE '%%php%%'" % tl), 60, stdin=pw)
    log("Profile löschen", r.rc == 0, (r.err or r.out)[:200])
    r = runner.sh(site_dir, _mysql_script(cfg, "SELECT COUNT(*) AS rest FROM #__wf_profiles WHERE id IN (%s)" % tl), 60, stdin=pw)
    rest = (lines_of(r.out)[1:] or ["?"])[0].strip()
    ok = rest == "0"
    log("Kontrolle", ok, "Übrig: %s" % rest)
    result["ok"] = ok
    result["message"] = ("%d schädliche(s) JCE-Profil(e) gelöscht. %s" % (len(todo), ("Sicherung: " + out) if out else "Es wurde bewusst keine Sicherung angelegt.")) if ok else ""
    if not ok:
        result["error"] = "Die Profile sind noch vorhanden. Lösche sie im Backend: Komponenten -> JCE Editor -> Profile."


# Verschieben in die Quarantäne. Platzhalter @Q@ = Quarantäne-Ordner. Eingabe (stdin): Pfade, durch NUL getrennt. Ausgabe je Datei: OK / UEBERSPRUNGEN / FEHLER / HINWEIS (Tabulator-getrennt).
# Die Listenzeile wird VOR dem Verschieben geschrieben; maßgeblich für "liegt in der Quarantäne" ist, ob d/<Nr>.q existiert.
QUAR_MOVE = r"""Q=@Q@; S=$(pwd -P); H=sha256sum; command -v sha256sum >/dev/null 2>&1 || H="shasum -a 256"
T=$(printf '\t'); n=0; qdev=$(stat -c %d -- "$Q/d" 2>/dev/null)
skip() { printf 'UEBERSPRUNGEN\t%s\t%s\n' "$f" "$1"; }
fail() { printf 'FEHLER\t%s\t%s\n' "$f" "$1"; }
while IFS= read -r -d "" f; do
  if [ ! -f "$f" ] || [ -L "$f" ]; then skip "keine normale Datei (fehlt oder Verweis)"; continue; fi
  case "$f" in *"$T"*) skip "Tabulator im Dateinamen"; continue;; esac
  d=$(dirname -- "$f"); P=$(cd -P -- "$d" 2>/dev/null && pwd -P)
  case "$P/" in "$S"/*) ;; *) skip "Ordner liegt außerhalb der Seite (Verweis)"; continue;; esac
  [ -w "$d" ] || { skip "Ordner nicht beschreibbar"; continue; }
  h1=$($H -- "$f" 2>/dev/null | cut -d" " -f1)
  [ -n "$h1" ] || { skip "nicht lesbar"; continue; }
  s=$(stat -c %s -- "$f"); m=$(stat -c %a -- "$f"); o=$(stat -c %U:%G -- "$f"); t=$(stat -c %y -- "$f" | cut -c1-19); l=$(stat -c %h -- "$f"); fd=$(stat -c %d -- "$f")
  n=$((n+1)); id=$(printf '%04d' "$n"); dest="$Q/d/$id.q"
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$id" "$h1" "${s:--}" "${m:--}" "${o:--}" "${t:--}" "$f" >> "$Q/QUARANTAENE.txt"
  if [ "$fd" = "$qdev" ]; then
    mv -n -- "$f" "$dest" 2>/dev/null
  elif cp -p -- "$f" "$dest" 2>/dev/null && [ "$($H -- "$dest" 2>/dev/null | cut -d" " -f1)" = "$h1" ]; then
    rm -f -- "$f" 2>/dev/null
  else
    rm -f -- "$dest" 2>/dev/null; fail "Kopie auf das andere Dateisystem gescheitert, das Original bleibt"; continue
  fi
  h2=$($H -- "$dest" 2>/dev/null | cut -d" " -f1)
  if [ -f "$dest" ] && [ ! -e "$f" ] && [ "$h1" = "$h2" ]; then
    chmod 600 -- "$dest" 2>/dev/null || printf 'HINWEIS\t%s\tRechte in der Quarantäne konnten nicht gesetzt werden (Ausführrecht evtl. noch vorhanden)\n' "$f"
    if [ "${l:-1}" -gt 1 ] 2>/dev/null; then printf 'HINWEIS\t%s\tweitere feste Verknüpfungen (Hardlinks): %s; der Inhalt ist unter diesen Namen weiter erreichbar\n' "$f" "$((l-1))"; fi
    printf 'OK\t%s\t%s\n' "$id" "$f"
  else
    [ -e "$f" ] && rm -f -- "$dest" 2>/dev/null
    fail "Verschieben nicht bestätigt (Datei oder Prüfsumme)"
  fi
done"""

# Zurückholen. Eingabe (stdin): "<Quarantäne-Ordner>/<Nr>", durch NUL getrennt. Alle Angaben (Ursprung, Prüfsumme, Rechte) kommen aus der Liste auf dem Server, nie aus der Auswahl.
QUAR_BACK = r"""H=sha256sum; command -v sha256sum >/dev/null 2>&1 || H="shasum -a 256"; S=$(pwd -P)
skip() { printf 'UEBERSPRUNGEN\t%s\t%s\n' "$e" "$1"; }
fail() { printf 'FEHLER\t%s\t%s\n' "$e" "$1"; }
while IFS= read -r -d "" e; do
  qd=${e%%/*}; id=${e##*/}
  case "$qd" in claudia-quarantaene-*|@OLD@-quarantaene-*) ;; *) skip "kein Quarantäne-Ordner"; continue;; esac
  case "$id" in ""|*[!0-9]*) skip "ungültige Nummer"; continue;; esac
  Q="$HOME/$qd"
  if [ ! -d "$Q" ] || [ -L "$Q" ] || [ ! -f "$Q/QUARANTAENE.txt" ]; then skip "Quarantäne-Ordner oder Liste fehlt"; continue; fi
  src="$Q/d/$id.q"
  if [ ! -f "$src" ] || [ -L "$src" ]; then skip "liegt nicht mehr in der Quarantäne"; continue; fi
  site=$(sed -n 's/^# Seitenordner: //p' "$Q/QUARANTAENE.txt" | head -1)
  [ "$site" = "$S" ] || { skip "gehört zu einer anderen Seite"; continue; }
  row=$(awk -F'\t' -v k="$id" 'substr($0,1,1)!="#" && $1==k {print; exit}' "$Q/QUARANTAENE.txt")
  [ -n "$row" ] || { skip "keine Zeile in der Liste"; continue; }
  sha=$(printf '%s\n' "$row" | cut -f2); mode=$(printf '%s\n' "$row" | cut -f4); own=$(printf '%s\n' "$row" | cut -f5); origin=$(printf '%s\n' "$row" | cut -f7-)
  case "$origin" in ./*) ;; *) skip "ungültiger Ursprungspfad in der Liste"; continue;; esac
  case "$origin" in */../*|*/..|*/./*|*/) skip "ungültiger Ursprungspfad in der Liste"; continue;; esac
  case "$mode" in ""|*[!0-7]*) skip "ungültige Rechte in der Liste"; continue;; esac
  d=$(dirname -- "$origin")
  [ -d "$d" ] || { skip "Ursprungsordner fehlt (wird nicht neu angelegt)"; continue; }
  P=$(cd -P -- "$d" 2>/dev/null && pwd -P)
  case "$P/" in "$S"/*) ;; *) skip "Ursprungsordner liegt außerhalb der Seite (Verweis)"; continue;; esac
  [ -w "$d" ] || { skip "Ursprungsordner nicht beschreibbar"; continue; }
  if [ -e "$origin" ] || [ -L "$origin" ]; then skip "am Ursprungsort liegt schon etwas (nichts wird überschrieben)"; continue; fi
  h=$($H -- "$src" 2>/dev/null | cut -d" " -f1)
  [ "$h" = "$sha" ] || { skip "Prüfsumme weicht von der Liste ab (Datei in der Quarantäne verändert)"; continue; }
  if [ "$(stat -c %d -- "$src")" = "$(stat -c %d -- "$d")" ]; then
    mv -n -- "$src" "$origin" 2>/dev/null
  elif cp -p -- "$src" "$origin" 2>/dev/null && [ "$($H -- "$origin" 2>/dev/null | cut -d" " -f1)" = "$sha" ]; then
    rm -f -- "$src" 2>/dev/null
  else
    rm -f -- "$origin" 2>/dev/null; fail "Kopie auf das andere Dateisystem gescheitert, die Datei bleibt in der Quarantäne"; continue
  fi
  if [ -f "$origin" ] && [ ! -e "$src" ] && [ "$($H -- "$origin" 2>/dev/null | cut -d" " -f1)" = "$sha" ]; then
    chmod "$mode" -- "$origin" 2>/dev/null || printf 'HINWEIS\t%s\tRechte konnten nicht gesetzt werden\n' "$origin"
    now=$(stat -c %U:%G -- "$origin" 2>/dev/null)
    [ "$now" = "$own" ] || printf 'HINWEIS\t%s\tBesitzer weicht ab (vorher %s, jetzt %s); ohne Administratorrechte nicht änderbar\n' "$origin" "$own" "$now"
    printf '%s\t%s\t%s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$id" "$origin" >> "$Q/ZURUECK.txt"
    printf 'OK\t%s\t%s\n' "$e" "$origin"
  else
    fail "Zurückholen nicht bestätigt (Datei oder Prüfsumme)"
  fi
done"""
QUAR_BACK = QUAR_BACK.replace("@OLD@", OLD_ID)


def _new_quarantine_dir(runner, site_dir: str) -> str:
    """Legt ~/claudia-quarantaene-<Datum>/ mit Unterordner d/ an (Rechte 700). Liegt das Home-Verzeichnis im Seitenordner, gibt es keinen sicheren Platz: Abbruch ohne Änderung.
    Zusätzlich eine Zugriffssperre (.htaccess, index.html), falls der Ordner doch über das Web erreichbar wäre (der Webroot selbst ist dem Programm nicht bekannt)."""
    home = _home_dir(runner, site_dir)
    if _inside_site(runner, site_dir, home):
        raise ActionError("Das Home-Verzeichnis liegt im Web-Ordner der Seite. Dort gibt es keinen Platz außerhalb des Web-Ordners für die Quarantäne. Es wurde nichts verändert. "
                          "Verschiebe die Dateien von Hand oder lege den Seitenordner unterhalb deines Home-Verzeichnisses an.")
    stamp = time.strftime("%Y%m%d-%H%M%S")
    out = ""
    for n in range(1, 10):
        cand = "%s/%s-%s%s" % (home, QUAR_PREFIX, stamp, "" if n == 1 else "-%d" % n)
        r = runner.sh(site_dir, "mkdir -m 700 -- %s 2>/dev/null && mkdir -m 700 -- %s/d && echo angelegt" % (sq(cand), sq(cand)), 30)
        if "angelegt" in r.out:
            out = cand
            break
    if not out:
        raise ActionError("Der Quarantäne-Ordner konnte nicht angelegt werden. Es wurde nichts verändert.")
    runner.sh(site_dir, "cat > %s/.htaccess && : > %s/index.html && echo gesperrt" % (sq(out), sq(out)), 30, stdin=HTACCESS_DENY)
    return out


def _quarantine_header(site_abs: str) -> str:
    from . import __version__
    return ("# CLAUDIA %s: Quarantäne (Dateien wurden verschoben, nicht gelöscht)\n"
            "# Angelegt: %s (Uhr dieses Computers)\n"
            "# Seitenordner: %s\n"
            "# Spalten (Tabulator): Nr, SHA-256, Größe in Byte, Rechte (oktal), Besitzer:Gruppe, Änderungsdatum, Ursprungspfad\n"
            "# Die Dateien liegen im Unterordner d/ als <Nr>.q (ohne Ausführrecht). Eine Zeile steht auch dann hier, wenn das Verschieben dieser Datei misslang: maßgeblich ist, ob d/<Nr>.q existiert.\n"
            "# WARNUNG: schädlicher Inhalt. Nicht öffnen, nicht ausführen, nicht in einen öffentlich erreichbaren Ordner legen.\n"
            "# Zurückholen: im Programm 'Dateien aus der Quarantäne zurückholen'; von Hand: mv -n -- d/<Nr>.q <Seitenordner>/<Ursprungspfad>\n"
            % (__version__, time.strftime("%Y-%m-%d %H:%M:%S"), site_abs))


def _parse_quar_lines(out: str) -> List[Tuple[str, ...]]:
    return [tuple(l.split("\t")) for l in out.splitlines() if l.split("\t")[0] in ("OK", "UEBERSPRUNGEN", "FEHLER", "HINWEIS")]


# ---- B7 (2.4.0): Schadcode in der Datenbank entfernen (nur Skript-/Frame-Blöcke, je Eintrag mit Sicherung des alten Werts)
DBFIND_RE = re.compile(r"^(\w+) #(\d+) '(.*)' \((\w+)\): ")
DBKEY_RE = re.compile(r"^([a-z_]{1,30})\.([a-z_]{1,30}):(\d{1,12})$")
DBCODE_MAX_HEX = 2_000_000
_SCRIPT_EL = re.compile(r"<script\b[^>]*>.*?</script\s*>|<script\b[^>]*/>", re.IGNORECASE | re.DOTALL)
_IFRAME_EL = re.compile(r"<iframe\b[^>]*>.*?</iframe\s*>|<iframe\b[^>]*/>", re.IGNORECASE | re.DOTALL)
_SERIALIZED = re.compile(r"^\s*(?:[aOsibdC]:\d+[:;{]|N;)")


def _dbcode_targets(cms: str) -> Dict[Tuple[str, str], str]:
    """{(Tabelle, Spalte): ID-Spalte}: nur diese Stellen durchsucht die Prüfung und nur diese darf die Aktion ändern."""
    if cms == "wordpress":
        from .checks.wp import WP_INJ_TARGETS as T
    else:
        from .checks.database import INJ_TARGETS as T
    return {(t, c): i for t, i, _ti, c in T}


def _el_flagged(el: str, own: str, allow: List[str], ioc: List[str]) -> bool:
    """Gleiche Maßstäbe wie die Prüfung: bekannter Schadcode, verschleierter Code, fremde Adresse, unsichtbarer Frame."""
    from .checks.database import HIDDEN_RE, OBF_RE
    from .util import extract_hosts, host_allowed
    low = el.lower()
    if any(i and i.lower() in low for i in ioc):
        return True
    if OBF_RE.search(el):
        return True
    if [h for h in extract_hosts(el) if h != own and not host_allowed(h, allow)]:
        return True
    return low.startswith("<iframe") and bool(HIDDEN_RE.search(el))


def _clean_text(text: str, own: str, allow: List[str], ioc: List[str], removed: List[str]) -> str:
    def repl(m):
        el = m.group(0)
        if _el_flagged(el, own, allow, ioc):
            removed.append(el)
            return ""
        return el
    return _IFRAME_EL.sub(repl, _SCRIPT_EL.sub(repl, text))


def _clean_json(obj: Any, own: str, allow: List[str], ioc: List[str], removed: List[str]) -> Any:
    if isinstance(obj, str):
        return _clean_text(obj, own, allow, ioc, removed)
    if isinstance(obj, list):
        return [_clean_json(x, own, allow, ioc, removed) for x in obj]
    if isinstance(obj, dict):
        return {k: _clean_json(v, own, allow, ioc, removed) for k, v in obj.items()}
    return obj


def dbcode_clean(value: str, own: str = "", allow: Optional[List[str]] = None, ioc: Optional[List[str]] = None) -> Dict[str, Any]:
    """Reine Funktion. Rückgabe: {new, removed:[Blöcke], skip:'' | Grund, leftover:bool}. Entfernt nur Skript-/Frame-Blöcke, die nach den Maßstäben der Prüfung schädlich sind.
    JSON-Werte (Joomla-Parameter) werden als JSON bearbeitet und wieder so geschrieben, wie PHP es tut (ASCII-Escapes, \\/); serialisierte PHP-Werte werden nicht angefasst."""
    import json
    from .checks.database import OBF_RE
    allow, ioc = list(allow or []), list(ioc or [])
    if value is None:
        return {"new": value, "removed": [], "skip": "leer (NULL)", "leftover": False}
    if _SERIALIZED.match(value):
        return {"new": value, "removed": [], "skip": "serialisierter PHP-Wert (ein Eingriff würde ihn unbrauchbar machen): bitte im Dashboard bzw. von Hand bearbeiten", "leftover": False}
    removed: List[str] = []
    new = value
    st = value.lstrip()
    if st[:1] in ("{", "["):
        try:
            obj = json.loads(value)
        except ValueError:
            obj = None
        if obj is not None:
            cleaned = _clean_json(obj, own, allow, ioc, removed)
            if removed:
                new = json.dumps(cleaned, ensure_ascii=True, separators=(",", ":")).replace("/", "\\/")
        else:
            new = _clean_text(value, own, allow, ioc, removed)
    else:
        new = _clean_text(value, own, allow, ioc, removed)
    if not removed:
        return {"new": value, "removed": [], "skip": "kein eindeutig schädlicher Skript-/Frame-Block gefunden: bitte von Hand ansehen", "leftover": False}
    return {"new": new, "removed": removed, "skip": "", "leftover": bool(OBF_RE.search(new))}


def _dbcode_read(runner, site_dir: str, cfg: Dict[str, Any], pw: str, table: str, idcol: str, col: str, rid: int) -> Optional[str]:
    """Wert einer Zelle (UTF-8) oder None (Zeile fehlt/NULL). Wirft ActionError bei Lesefehlern oder zu großen/ungültigen Werten."""
    r = runner.sh(site_dir, _mysql_script(cfg, "SELECT HEX(`%s`) AS h FROM #__%s WHERE `%s` = %d" % (col, table, idcol, rid)), 60, stdin=pw)
    if r.rc != 0:
        raise ActionError("Eintrag %s #%d konnte nicht gelesen werden: %s" % (table, rid, (r.err or r.out)[:160]))
    rows = lines_of(r.out)[1:]
    if not rows or not rows[0].strip() or rows[0].strip() == "NULL":
        return None
    h = rows[0].strip()
    if len(h) > DBCODE_MAX_HEX:
        raise ValueError("Wert größer als 1 MB")
    if not re.fullmatch(r"(?:[0-9A-Fa-f]{2})*", h):
        raise ActionError("Unerwartete Antwort der Datenbank für %s #%d." % (table, rid))
    try:
        return bytes.fromhex(h).decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("Wert ist nicht als UTF-8 lesbar (andere Zeichenkodierung)")


def _dbcode_plan(runner, site_dir: str, params: Dict[str, Any]) -> Tuple[Dict[str, Any], str, List[Dict[str, Any]]]:
    cms = "wordpress" if params.get("cms") == "wordpress" else "joomla"
    targets = _dbcode_targets(cms)
    keys = _picked(params, "x")
    if not keys:
        raise ActionError("Keine Einträge ausgewählt.")
    cfg = _read_cfg(runner, site_dir)
    pw = str(cfg.get("password", "")) + "\n"
    plan: List[Dict[str, Any]] = []
    for k in keys[:100]:
        m = DBKEY_RE.match(k)
        if not m or (m.group(1), m.group(2)) not in targets:
            raise ActionError("Ungültige Auswahl (%s). Es wurde nichts verändert." % k[:60])
        table, col, rid = m.group(1), m.group(2), int(m.group(3))
        item = {"key": "x:" + k, "table": table, "col": col, "idcol": targets[(table, col)], "id": rid, "old": None, "new": None, "removed": [], "skip": "", "leftover": False}
        try:
            old = _dbcode_read(runner, site_dir, cfg, pw, table, item["idcol"], col, rid)
        except ValueError as e:
            item["skip"] = str(e)
            plan.append(item)
            continue
        item["old"] = old
        res = dbcode_clean(old, str(params.get("own_host") or ""), list(params.get("allow") or []), list(params.get("ioc") or [])) if old is not None else \
            {"new": None, "removed": [], "skip": "Eintrag oder Wert nicht mehr vorhanden", "leftover": False}
        item.update(new=res["new"], removed=res["removed"], skip=res["skip"], leftover=res["leftover"])
        plan.append(item)
    return cfg, pw, plan


def dbcode_preview(runner, site_dir: str, params: Dict[str, Any]) -> Dict[str, Any]:
    """Nur lesend: je gewähltem Eintrag, was entfernt würde (oder warum nicht)."""
    _cfg, _pw, plan = _dbcode_plan(runner, site_dir, params)
    return {"items": [{"label": "%s #%d (%s)" % (p["table"], p["id"], p["col"]), "skip": p["skip"], "leftover": p["leftover"],
                       "removed": [re.sub(r"\s+", " ", x)[:300] for x in p["removed"][:10]], "size_old": len(p["old"] or ""), "size_new": len(p["new"] or "")} for p in plan]}


def _run_remove_db_code(runner, site_dir: str, params: Dict[str, Any], log, result: Dict[str, Any]) -> None:
    import hashlib
    cfg, pw, plan = _dbcode_plan(runner, site_dir, params)
    todo = [p for p in plan if not p["skip"] and p["new"] != p["old"]]
    for p in plan:
        if p["skip"]:
            log("Eintrag %s #%d übersprungen" % (p["table"], p["id"]), True, p["skip"])
    if not todo:
        result["ok"] = True
        result["message"] = "Es wurde nichts geändert: " + "; ".join("%s #%d (%s)" % (p["table"], p["id"], p["skip"]) for p in plan[:5])
        return
    prefix = str(cfg.get("dbprefix", "jos_"))
    if not re.fullmatch(r"[A-Za-z0-9_]{1,40}", prefix):
        raise ActionError("Das Tabellenpräfix ist ungewöhnlich. Es wurde nichts verändert.")
    out = _mkdir_backup(runner, site_dir, "dbcode")
    result["backup_dir"] = out
    q = sq(out)
    sql = ["-- CLAUDIA: alte Werte der geänderten Datenbank-Einträge. Zum Rückgängigmachen im phpMyAdmin (Reiter SQL) ausführen."]
    for p in todo:
        sql.append("UPDATE `%s%s` SET `%s` = UNHEX('%s') WHERE `%s` = %d;" % (prefix, p["table"], p["col"], p["old"].encode("utf-8").hex().upper(), p["idcol"], p["id"]))
    text = "\n".join(sql) + "\n"
    want = hashlib.sha256(text.encode("utf-8")).hexdigest()
    r = runner.sh(site_dir, "cat > %s/rueckgaengig.sql && chmod 600 %s/rueckgaengig.sql && sha256sum -- %s/rueckgaengig.sql" % (q, q, q), 60, stdin=text)
    if want not in r.out:
        result["backup_failed"] = True
        raise ActionError("Die Sicherung der alten Werte (rueckgaengig.sql) ist nicht gelungen. Es wurde nichts verändert.")
    log("Alte Werte gesichert", True, "%d Eintrag/Einträge in rueckgaengig.sql" % len(todo))
    done, fail = 0, 0
    for p in todo:
        oh, nh = p["old"].encode("utf-8").hex().upper(), p["new"].encode("utf-8").hex().upper()
        upd = "UPDATE #__%s SET `%s` = UNHEX('%s') WHERE `%s` = %d AND HEX(`%s`) = '%s'" % (p["table"], p["col"], nh, p["idcol"], p["id"], p["col"], oh)
        r = runner.sh(site_dir, _mysql_script(cfg, upd), 120, stdin=pw)
        try:
            now = _dbcode_read(runner, site_dir, cfg, pw, p["table"], p["idcol"], p["col"], p["id"])
        except (ActionError, ValueError):
            now = None
        ok = r.rc == 0 and now == p["new"]
        done += ok
        fail += not ok
        log("Eintrag %s #%d (%s)" % (p["table"], p["id"], p["col"]), ok,
            ("%d Block/Blöcke entfernt, %d → %d Zeichen" % (len(p["removed"]), len(p["old"]), len(p["new"]))) if ok else
            ("Der Wert hat sich seit dem Lesen geändert oder konnte nicht geschrieben werden; nichts verändert. " + (r.err or "")[:120]))
        if ok and p["leftover"]:
            log("Hinweis zu %s #%d" % (p["table"], p["id"]), True, "Im Rest des Werts steht noch verdächtiger Code außerhalb von Skript-/Frame-Blöcken (z. B. eval(). Bitte von Hand ansehen.")
    result["ok"] = fail == 0
    result["message"] = ("%d Eintrag/Einträge bereinigt. Cache leeren und die Seite neu prüfen. Rückgängig: %s/rueckgaengig.sql" % (done, out)) if not fail else ""
    if fail:
        result["error"] = "%d von %d Einträgen konnten nicht geändert werden (%d erfolgreich). Rückgängig: %s/rueckgaengig.sql" % (fail, len(todo), done, out)


# ---- B5 (2.4.0): .htaccess im Hauptordner auf den Standard zurücksetzen
HT_MAX_BYTES = 200_000
WP_HT_STD = ("# BEGIN WordPress\n<IfModule mod_rewrite.c>\nRewriteEngine On\nRewriteRule .* - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization}]\nRewriteBase @BASE@\n"
             "RewriteRule ^index\\.php$ - [L]\nRewriteCond %{REQUEST_FILENAME} !-f\nRewriteCond %{REQUEST_FILENAME} !-d\nRewriteRule . @BASE@index.php [L]\n</IfModule>\n# END WordPress\n")
HT_OWN_HEAD = "# CLAUDIA: eigene Regeln, aus der bisherigen .htaccess übernommen"


def _ht_norm(line: str) -> str:
    return re.sub(r"\s+", " ", line.strip())


def _ht_code(lines: List[str]) -> List[str]:
    return [l for l in lines if l.strip() and not l.strip().startswith("#")]


def ht_segments(text: str) -> List[Dict[str, Any]]:
    """Teilt eine .htaccess in geschlossene Blöcke ('# BEGIN Name' bis '# END Name') und Regel-Absätze (durch Leerzeilen getrennt). Reine Kommentar-Absätze entfallen."""
    from .checks.config import HT_MARK_RE
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    segs: List[Dict[str, Any]] = []
    cur: List[str] = []

    def flush() -> None:
        nonlocal cur
        if _ht_code(cur):
            segs.append({"kind": "rules", "name": "", "lines": cur})
        cur = []

    i = 0
    while i < len(lines):
        ln = lines[i]
        m = HT_MARK_RE.match(ln)
        if m and m.group(1).upper() == "BEGIN":
            name, end = m.group(2), None
            for k in range(i + 1, len(lines)):
                m2 = HT_MARK_RE.match(lines[k])
                if m2 and m2.group(1).upper() == "END" and m2.group(2).strip().lower() == name.strip().lower():
                    end = k
                    break
            if end is not None:
                flush()
                segs.append({"kind": "block", "name": name, "lines": lines[i:end + 1]})
                i = end + 1
                continue
        if not ln.strip():
            flush()
        else:
            cur.append(ln)
        i += 1
    flush()
    return segs


def ht_classify(seg: Dict[str, Any], own: str) -> Tuple[str, str, str]:
    """(Schweregrad, Begründung, auslösende Zeile) eines Segments nach denselben Regeln wie die Prüfung 'htaccess'."""
    from .checks.config import HT_PATTERN, _classify_ht
    order = {"info": 0, "warn": 1, "crit": 2}
    worst, why, sample = "info", "", ""
    for ln in _ht_code(seg["lines"]):
        if re.search(HT_PATTERN, ln, re.IGNORECASE):
            sev, w = _classify_ht(ln.strip(), "./.htaccess", own, [])
            if order[sev] > order[worst]:
                worst, why, sample = sev, w, ln.strip()
    return worst, why, sample


def ht_plan(current: str, std: str, cms: str, keep_own: bool = True, own: str = "") -> Dict[str, Any]:
    """Reine Funktion: aus der aktuellen Datei und der Standarddatei die neue Datei bauen. Rückgabe: {text, carried, dropped, same}.
    Übernommen wird nur, was nicht zum Standard gehört UND (nach den Regeln der Prüfung) harmlos ist; alles andere wird mit Begründung aufgelistet."""
    std_norm = {_ht_norm(l) for l in _ht_code(std.splitlines())}
    carried: List[Dict[str, Any]] = []
    dropped: List[Dict[str, Any]] = []
    same = 0
    for seg in ht_segments(current):
        body = [_ht_norm(l) for l in _ht_code(seg["lines"])]
        if cms == "wordpress" and seg["kind"] == "block" and seg["name"].strip().lower() == "wordpress":
            same += 1
            continue
        if seg["kind"] == "rules" and body and all(b in std_norm for b in body):
            same += 1
            continue
        lines = [l for l in seg["lines"] if not l.startswith(HT_OWN_HEAD) and not re.match(r"^\s*RewriteBase\s", l, re.IGNORECASE)]
        if not _ht_code(lines):
            same += 1
            continue
        sev, why, sample = ht_classify({"lines": lines}, own)
        item = {"sev": sev, "why": why, "name": seg["name"], "sample": sample or (_ht_code(lines) or [""])[0].strip(), "lines": lines}
        if sev == "info" and keep_own:
            carried.append(item)
        else:
            item["why"] = why or "eigene Regel, nicht übernommen (Schalter 'Eigene Regeln übernehmen' ist aus)"
            dropped.append(item)
    body = std.rstrip("\n") + "\n"
    if carried:
        own_txt = HT_OWN_HEAD + "\n" + "\n\n".join("\n".join(c["lines"]).rstrip("\n") for c in carried) + "\n"
        body = (own_txt + "\n" + body) if cms == "wordpress" else (body + "\n" + own_txt)
    return {"text": body, "carried": carried, "dropped": dropped, "same": same}


def ht_standard(cms: str, version: str, current: str) -> Tuple[str, str]:
    """(Standardtext, Quelle). WordPress: eingebauter Standardblock; Joomla: htaccess.txt aus dem geprüften Original-Paket (sonst Abbruch)."""
    m = re.search(r"^\s*RewriteBase\s+(\S+)", current, re.IGNORECASE | re.MULTILINE)
    base = m.group(1) if m and re.fullmatch(r"/[A-Za-z0-9._/~-]*", m.group(1)) else "/"
    if not base.endswith("/"):
        base += "/"
    if cms == "wordpress":
        return WP_HT_STD.replace("@BASE@", base), "Standardblock von WordPress"
    import zipfile
    from . import coreref
    if not coreref.VERSION_RE.match(version or ""):
        raise ActionError("Die Joomla-Version ist nicht eindeutig bekannt (%s). Es wurde nichts verändert." % (version or "?"))
    try:
        ref = coreref.reference(version)
        pkg, _ = coreref.package_path(ref)
    except coreref.RefError as e:
        raise ActionError("Das Original-Paket ist nicht verfügbar: %s. Es wurde nichts verändert." % e)
    if not ref.get("verified"):
        raise ActionError("Die Prüfsumme des Original-Pakets ist nicht bestätigt. Es wurde nichts verändert.")
    try:
        with zipfile.ZipFile(pkg) as z:
            txt = z.read("htaccess.txt").decode("utf-8", "replace")
    except (KeyError, OSError, zipfile.BadZipFile):
        raise ActionError("Im Original-Paket fehlt htaccess.txt. Es wurde nichts verändert.")
    if "RewriteEngine" not in txt:
        raise ActionError("htaccess.txt aus dem Paket ist unerwartet aufgebaut. Es wurde nichts verändert.")
    if base != "/":
        txt = re.sub(r"^#\s*RewriteBase /\s*$", "RewriteBase " + base.rstrip("/") or "/", txt, count=1, flags=re.MULTILINE)
    return txt, "htaccess.txt aus dem geprüften Original-Paket von Joomla %s (sha256 %s...)" % (version, ref["sha256"][:12])


def ht_diff(old: str, new: str, limit: int = 400) -> List[str]:
    import difflib
    out = list(difflib.unified_diff(old.splitlines(), new.splitlines(), "bisherige .htaccess", "neue .htaccess", lineterm="", n=2))
    if len(out) > limit:
        out = out[:limit] + ["... (%d weitere Zeilen)" % (len(out) - limit)]
    return out


def _ht_read(runner, site_dir: str) -> str:
    r = runner.sh(site_dir, 'f=.htaccess; if [ -L "$f" ]; then echo "@@LINK"; elif [ ! -f "$f" ]; then echo "@@NONE"; '
                  'elif [ "$(wc -c < "$f")" -gt %d ]; then echo "@@BIG"; else cat -- "$f"; fi' % HT_MAX_BYTES, 30)
    out = r.out
    first = out.strip()
    if first == "@@LINK":
        raise ActionError("Die .htaccess im Hauptordner ist ein Verweis (Symlink). Es wurde nichts verändert.")
    if first == "@@NONE":
        raise ActionError("Im Hauptordner gibt es keine .htaccess. Es wurde nichts verändert.")
    if first == "@@BIG":
        raise ActionError("Die .htaccess ist größer als %d KB und damit ungewöhnlich. Sie wird nicht automatisch ersetzt." % (HT_MAX_BYTES // 1000))
    return out


def htaccess_preview(runner, site_dir: str, params: Dict[str, Any]) -> Dict[str, Any]:
    """Nur lesend: der Vergleich alt/neu für die Vorschau. Liest die Datei und lädt die Standarddatei, ändert aber nichts."""
    cms = "wordpress" if params.get("cms") == "wordpress" else "joomla"
    cur = _ht_read(runner, site_dir)
    std, src = ht_standard(cms, str(params.get("version") or ""), cur)
    plan = ht_plan(cur, std, cms, params.get("keep_own", True) is not False, str(params.get("own_host") or ""))
    return {"source": src, "diff": ht_diff(cur, plan["text"]), "unchanged": cur.replace("\r\n", "\n") == plan["text"],
            "carried": [{"name": c["name"], "first": c["sample"]} for c in plan["carried"]],
            "dropped": [{"sev": d["sev"], "why": d["why"], "name": d["name"], "line": " / ".join(l.strip() for l in _ht_code(d["lines"])[:2])[:200]} for d in plan["dropped"]]}


def _run_reset_htaccess(runner, site_dir: str, params: Dict[str, Any], context: Dict[str, Any], log, result: Dict[str, Any]) -> None:
    cms = "wordpress" if params.get("cms") == "wordpress" else "joomla"
    base = str((context or {}).get("url") or "").strip().rstrip("/")
    if not base.lower().startswith("https://"):
        raise ActionError("Zum Prüfen der neuen Datei braucht die Aktion die https-Adresse der Seite (Feld 'Adresse der Seite'). Es wurde nichts verändert.")
    cur = _ht_read(runner, site_dir)
    std, src = ht_standard(cms, str(params.get("version") or ""), cur)
    plan = ht_plan(cur, std, cms, params.get("keep_own", True) is not False, str(params.get("own_host") or ""))
    new = plan["text"]
    log("Standarddatei bereit", True, src)
    if cur.replace("\r\n", "\n") == new:
        result["ok"] = True
        result["message"] = "Die .htaccess entspricht schon dem Standard. Es wurde nichts geändert."
        return
    w = runner.sh(site_dir, 'if [ ! -w . ]; then echo SCHUTZ-ORDNER; elif [ ! -w .htaccess ]; then echo SCHUTZ-DATEI; else echo frei; fi', 30)
    if "SCHUTZ" in w.out:
        raise ActionError("Die .htaccess oder der Hauptordner ist schreibgeschützt (Rechte, Dateiwächter oder Hoster). Es wurde nichts verändert. Hebe den Schutz kurz auf und versuche es erneut.")
    before = _fetch_url(base + "/")
    out = _mkdir_backup(runner, site_dir, "htaccess")
    result["backup_dir"] = out
    q = sq(out)
    r = runner.sh(site_dir, "cp -p -- .htaccess %s/htaccess.vorher && cmp -s .htaccess %s/htaccess.vorher && echo gesichert" % (q, q), 30)
    if "gesichert" not in r.out:
        raise ActionError("Die vorhandene .htaccess konnte nicht gesichert werden. Es wurde nichts verändert.")
    log("Sicherung der .htaccess", True, "Alter Stand: htaccess.vorher")
    runner.sh(site_dir, "cat > %s/rueckgaengig.txt" % q, 30, stdin="# CLAUDIA: so wird das Zurücksetzen der .htaccess rückgängig gemacht\ncp -p -- %s/htaccess.vorher <Seitenordner>/.htaccess\n" % out)

    def restore() -> bool:
        rr = runner.sh(site_dir, "cp -p -- %s/htaccess.vorher .htaccess && cmp -s %s/htaccess.vorher .htaccess && echo zurueck" % (q, q), 30)
        return "zurueck" in rr.out

    import hashlib
    want = hashlib.sha256(new.encode("utf-8")).hexdigest()
    r = runner.sh(site_dir, "cat > .htaccess.claudia-neu && chmod --reference=.htaccess .htaccess.claudia-neu 2>/dev/null; sha256sum -- .htaccess.claudia-neu", 30, stdin=new)
    mh = re.search(r"([0-9a-f]{64})", r.out)
    got = mh.group(1) if mh else ""
    if got != want:
        runner.sh(site_dir, "rm -f -- .htaccess.claudia-neu", 30)
        raise ActionError("Die neue Datei kam nicht unverändert auf dem Server an (Prüfsumme). Die alte .htaccess ist unverändert.")
    r = runner.sh(site_dir, "mv -f -- .htaccess.claudia-neu .htaccess && sha256sum -- .htaccess", 30)
    if want not in r.out:
        restore()
        raise ActionError("Die .htaccess konnte nicht ersetzt werden. Der alte Stand ist wiederhergestellt.")
    log("Neue .htaccess geschrieben", True, "%d Zeilen; übernommen: %d eigene Regel(n); nicht übernommen: %d" % (len(new.splitlines()), len(plan["carried"]), len(plan["dropped"])))
    after = _fetch_url(base + "/")
    if after.error or after.status >= 500:
        if before.error or before.status >= 500:
            verdict, why = "nicht prüfbar", "Die Startseite war schon vorher nicht erreichbar oder fehlerhaft (%s); der Test sagt nichts über die neue Datei." % (before.error or "HTTP %s" % before.status)
        else:
            ok = restore()
            log("Wirkung prüfen", False, "Startseite liefert jetzt %s; alter Stand %s." % (after.error or "HTTP %s" % after.status, "wiederhergestellt" if ok else "NICHT wiederhergestellt, bitte htaccess.vorher von Hand zurückkopieren"))
            raise ActionError("Die Startseite ist mit der neuen .htaccess nicht erreichbar (%s). %s" % (after.error or "HTTP %s" % after.status, "Der alte Stand ist wiederhergestellt." if ok else "ACHTUNG: Der alte Stand konnte nicht wiederhergestellt werden. Befehl: " + out + "/rueckgaengig.txt"))
    else:
        verdict, why = "ok", "Startseite liefert HTTP %s." % after.status
    log("Wirkung prüfen", verdict == "ok", why)
    result["ok"] = True
    result["message"] = ("Die .htaccess ist auf den Standard zurückgesetzt (%s). %d eigene Regel(n) übernommen, %d nicht übernommen. %s Rückgängig: %s/rueckgaengig.txt"
                         % (src, len(plan["carried"]), len(plan["dropped"]), "Die Startseite wird weiter ausgeliefert." if verdict == "ok" else "Hinweis: " + why, out))
    if plan["dropped"]:
        result["message"] += " Nicht übernommen: " + "; ".join("%s (%s)" % (d["sample"][:70], d["why"][:60]) for d in plan["dropped"][:5])


HTACCESS_NOPHP = ("# CLAUDIA: PHP-Sperre - in diesem Ordner darf kein PHP ausgeführt werden\n"
                  '<FilesMatch "(?i)\\.(php[0-9]?|phtml|pht|phps|phar)(\\.|$)">\n'
                  "  <IfModule mod_authz_core.c>\n    Require all denied\n  </IfModule>\n"
                  "  <IfModule !mod_authz_core.c>\n    Order allow,deny\n    Deny from all\n  </IfModule>\n"
                  "</FilesMatch>\n# Ende CLAUDIA: PHP-Sperre\n")
PHP_MARK = "CLAUDIA: PHP-Sperre"   # Suche ohne Beachtung der Groß-/Kleinschreibung (ältere Sperren tragen "Claudia")


def _fetch_url(url: str):
    """Ein einzelner Abruf über https (in Tests ersetzbar)."""
    from .checks.web import UA_BROWSER, fetch
    return fetch(url, UA_BROWSER, max_bytes=20000, timeout=20.0)


def _run_block_php(runner, site_dir: str, params: Dict[str, Any], context: Dict[str, Any], log, result: Dict[str, Any]) -> None:
    import secrets as _s
    ud = _upload_dir(params)
    base = str((context or {}).get("url") or "").strip().rstrip("/")
    if not base.lower().startswith("https://"):
        raise ActionError("Zum Prüfen der Sperre braucht die Aktion die https-Adresse der Seite (Feld 'Adresse der Seite'). Es wurde nichts verändert.")
    f = "%s/.htaccess" % ud
    r = runner.sh(site_dir, 'd=%s; f=%s; if [ ! -d "$d" ] || [ -L "$d" ]; then echo KEINORDNER; elif [ -L "$f" ]; then echo LINK; '
                  'elif [ -f "$f" ]; then if grep -qi %s "$f"; then echo SCHON; else echo VORHANDEN; fi; else echo NEU; fi' % (sq(ud), sq(f), sq(PHP_MARK)), 30)
    state = (lines_of(r.out) or [""])[-1].strip()
    if state in ("NEU", "VORHANDEN"):
        w = runner.sh(site_dir, 'if [ ! -w %s ]; then echo SCHUTZ-ORDNER; elif [ -e %s ] && [ ! -w %s ]; then echo SCHUTZ-DATEI; else echo frei; fi' % (sq(ud), sq(f), sq(f)), 30)
        if "SCHUTZ" in w.out:
            raise ActionError("%s ist schreibgeschützt (Rechte, Dateiwächter oder Hoster). Es wurde nichts verändert. Hebe den Schutz kurz auf und versuche es erneut." % (f if "DATEI" in w.out else ud))
    if state not in ("NEU", "VORHANDEN", "SCHON"):
        raise ActionError("Der Ordner %s ist nicht vorhanden oder die .htaccess ist ein Verweis. Es wurde nichts verändert." % ud)
    if state == "SCHON":
        log("Vorhandene Sperre", True, "In %s steht die Sperre schon." % f)
        result["ok"] = True
        result["message"] = "Die PHP-Sperre steht in %s schon. Es wurde nichts geändert." % f
        return
    out = _mkdir_backup(runner, site_dir, "htaccess")
    result["backup_dir"] = out
    q = sq(out)
    if state == "VORHANDEN":
        r = runner.sh(site_dir, "cp -p -- %s %s/htaccess.vorher && cmp -s %s %s/htaccess.vorher && echo gesichert" % (sq(f), q, sq(f), q), 30)
        if "gesichert" not in r.out:
            raise ActionError("Die vorhandene .htaccess konnte nicht gesichert werden. Es wurde nichts verändert.")
        undo = "cp -p -- %s/htaccess.vorher <Seitenordner>/%s" % (out, f)
    else:
        undo = "rm -f -- <Seitenordner>/%s" % f
    log("Sicherung der .htaccess", True, "Alter Stand: %s" % ("htaccess.vorher" if state == "VORHANDEN" else "keine Datei vorhanden"))
    runner.sh(site_dir, "cat > %s/rueckgaengig.txt" % q, 30, stdin="# CLAUDIA: so wird die PHP-Sperre rückgängig gemacht\n%s\n" % undo)

    def restore() -> bool:
        cmd = ("cp -p -- %s/htaccess.vorher %s && cmp -s %s/htaccess.vorher %s && echo zurueck" % (q, sq(f), q, sq(f))) if state == "VORHANDEN" else ("rm -f -- %s && echo zurueck" % sq(f))
        return "zurueck" in runner.sh(site_dir, cmd, 30).out

    write = ("printf '\\n' >> %s && cat >> %s" if state == "VORHANDEN" else "cat > %s && chmod 644 %s") % (sq(f), sq(f))
    runner.sh(site_dir, write + " && echo geschrieben", 30, stdin=HTACCESS_NOPHP)
    r = runner.sh(site_dir, "grep -qi %s %s && echo da" % (sq(PHP_MARK), sq(f)), 30)
    if "da" not in r.out:
        restore()
        raise ActionError("Die .htaccess konnte nicht geschrieben werden. Der alte Stand ist wiederhergestellt.")
    log("Sperre schreiben", True, "%s/.htaccess" % ud)
    name = "claudia-test-" + _s.token_hex(6)
    ptxt, pphp = "%s/%s.txt" % (ud, name), "%s/%s.php" % (ud, name)
    verdict, why = "", ""
    try:
        runner.sh(site_dir, "cat > %s && echo ok" % sq(ptxt), 30, stdin="claudia-ok\n")
        runner.sh(site_dir, "cat > %s && echo ok" % sq(pphp), 30, stdin="<?php echo 'claudia' . '-' . (40 + 2);\n")
        ft = _fetch_url("%s/%s" % (base, ptxt))
        fp = _fetch_url("%s/%s" % (base, pphp))
        if ft.error or fp.error:
            verdict, why = "nicht prüfbar", "Abruf nicht möglich: %s" % (ft.error or fp.error)
        elif ft.status != 200 or "claudia-ok" not in (ft.body or ""):
            verdict, why = "fehler", "Eine Textdatei im Ordner wird nicht mehr ausgeliefert (Status %s). Die Datei verursacht Fehler." % ft.status
        elif "claudia-42" in (fp.body or ""):
            verdict, why = "wirkungslos", "PHP wird im Ordner weiter ausgeführt (der Server beachtet die .htaccess nicht, z. B. nginx)."
        else:
            verdict = "ok"
            why = "Textdatei wird ausgeliefert (Status %s), PHP-Datei wird nicht ausgeführt (Status %s)." % (ft.status, fp.status)
    finally:
        r = runner.sh(site_dir, "rm -f -- %s %s; [ ! -e %s ] && [ ! -e %s ] && echo weg" % (sq(ptxt), sq(pphp), sq(ptxt), sq(pphp)), 30)
        log("Testdateien löschen", "weg" in r.out, "weg" if "weg" in r.out else "Bitte von Hand löschen: %s" % ", ".join((ptxt, pphp)))
    log("Wirkung prüfen", verdict == "ok", why)
    if verdict == "ok":
        result["ok"] = True
        result["message"] = "PHP ist im Ordner %s jetzt gesperrt und die Sperre wirkt (geprüft per Abruf). Rückgängig: %s/rueckgaengig.txt" % (ud, out)
        return
    ok = restore()
    log("Alten Stand herstellen", ok, "Die .htaccess ist wieder wie vorher." if ok else "Der alte Stand konnte nicht hergestellt werden: %s" % undo)
    result["error"] = "%s Die Sperre wurde %s." % (why, "zurückgenommen" if ok else "NICHT zurückgenommen, bitte von Hand: " + undo)
    result["message"] = ""


HT_MARK = {"harden_headers": "CLAUDIA: Sicherheits-Header", "harden_hsts": "CLAUDIA: HSTS", "harden_listing": "CLAUDIA: Ordnerlisten aus", "wp_block_xmlrpc": "CLAUDIA: XML-RPC gesperrt"}
HT_HEADERS = {"nosniff": ("X-Content-Type-Options", "nosniff"), "frame": ("X-Frame-Options", "SAMEORIGIN"), "referrer": ("Referrer-Policy", "strict-origin-when-cross-origin")}
HSTS_MAX_AGE = 604800     # 7 Tage; bewusst kurz, ohne includeSubDomains und ohne preload
HT_TEST = {
    "harden_headers": "Startseite per https abrufen; die gesetzten Header müssen in der Antwort stehen, die Seite muss HTTP < 500 liefern",
    "harden_hsts": "Startseite per https abrufen; Strict-Transport-Security mit max-age=604800 muss in der Antwort stehen, die Seite muss HTTP < 500 liefern",
    "harden_listing": "Startseite per https abrufen; sie muss HTTP < 500 liefern (ein Fehler 500 würde bedeuten, dass der Hoster 'Options' in der .htaccess nicht erlaubt)",
    "wp_block_xmlrpc": "xmlrpc.php und die Startseite per https abrufen; xmlrpc.php muss gesperrt sein (403/404/410), die Startseite HTTP < 500 liefern",
}


def ht_block_text(aid: str, params: Optional[Dict[str, Any]] = None) -> str:
    """Der Block, der in die .htaccess kommt (fest vorgegeben; nur die zu setzenden Header kommen aus der Prüfung, aus einer festen Liste)."""
    mark = HT_MARK[aid]
    if aid == "harden_headers":
        keys = [k for k in ((params or {}).get("headers") or []) if k in HT_HEADERS]
        if not keys:
            raise ActionError("Es ist kein Header zu setzen.")
        body = "<IfModule mod_headers.c>\n" + "".join('  Header always set %s "%s"\n' % HT_HEADERS[k] for k in HT_HEADERS if k in keys) + "</IfModule>\n"
    elif aid == "harden_hsts":
        body = '<IfModule mod_headers.c>\n  Header always set Strict-Transport-Security "max-age=%d"\n</IfModule>\n' % HSTS_MAX_AGE
    elif aid == "harden_listing":
        body = "<IfModule mod_autoindex.c>\n  Options -Indexes\n</IfModule>\n"
    else:
        body = ("<Files xmlrpc.php>\n  <IfModule mod_authz_core.c>\n    Require all denied\n  </IfModule>\n"
                "  <IfModule !mod_authz_core.c>\n    Order allow,deny\n    Deny from all\n  </IfModule>\n</Files>\n")
    return "# %s\n%s# Ende %s\n" % (mark, body, mark)


def ht_block_verdict(aid: str, params: Dict[str, Any], base: str) -> Tuple[str, str]:
    """Wirkung per Abruf prüfen: ('ok'|'fehler'|'wirkungslos'|'nicht prüfbar', Begründung)."""
    home = _fetch_url(base + "/")
    if home.error:
        return "nicht prüfbar", "Die Startseite ist nicht abrufbar: %s" % home.error
    if home.status >= 500:
        return "fehler", "Die Startseite liefert mit dem neuen Block HTTP %s." % home.status
    h = home.headers or {}
    if aid == "harden_headers":
        miss = [HT_HEADERS[k][0] for k in HT_HEADERS if k in (params.get("headers") or []) and HT_HEADERS[k][1].lower() not in h.get(HT_HEADERS[k][0].lower(), "").lower()]
        if miss:
            return "wirkungslos", "Diese Header kommen nicht an: %s (der Server beachtet die .htaccess nicht oder hat mod_headers nicht, z. B. nginx)." % ", ".join(miss)
        return "ok", "Die Header kommen an, die Startseite liefert HTTP %s." % home.status
    if aid == "harden_hsts":
        if "max-age=%d" % HSTS_MAX_AGE not in h.get("strict-transport-security", ""):
            return "wirkungslos", "Der HSTS-Header kommt nicht an (der Server beachtet die .htaccess nicht oder hat mod_headers nicht)."
        return "ok", "Der HSTS-Header kommt an (max-age=%d), die Startseite liefert HTTP %s." % (HSTS_MAX_AGE, home.status)
    if aid == "harden_listing":
        return "ok", "Die Startseite liefert HTTP %s. Ob eine Ordnerliste weg ist, wird nicht einzeln geprüft; wiederhole die Prüfung." % home.status
    x = _fetch_url(base + "/xmlrpc.php")
    if x.error:
        return "nicht prüfbar", "xmlrpc.php ist nicht abrufbar: %s" % x.error
    if x.status in (403, 404, 410):
        return "ok", "xmlrpc.php ist gesperrt (HTTP %s), die Startseite liefert HTTP %s." % (x.status, home.status)
    return "wirkungslos", "xmlrpc.php antwortet weiter mit HTTP %s (der Server beachtet die .htaccess nicht, z. B. nginx)." % x.status


def _run_ht_block(runner, site_dir: str, aid: str, params: Dict[str, Any], context: Dict[str, Any], log, result: Dict[str, Any]) -> None:
    """Fügt einen markierten Block an die .htaccess im Hauptordner an: Sicherung, Schreiben, Wirkung prüfen, sonst alter Stand."""
    base = str((context or {}).get("url") or "").strip().rstrip("/")
    if not base.lower().startswith("https://"):
        raise ActionError("Zum Prüfen der Wirkung braucht die Aktion die https-Adresse der Seite (Feld 'Adresse der Seite'). Es wurde nichts verändert.")
    block = ht_block_text(aid, params)
    mark = HT_MARK[aid]
    f = ".htaccess"
    r = runner.sh(site_dir, 'f=%s; if [ -L "$f" ]; then echo LINK; elif [ -f "$f" ]; then if grep -qi %s "$f"; then echo SCHON; else echo VORHANDEN; fi; else echo NEU; fi' % (sq(f), sq(mark)), 30)
    state = (lines_of(r.out) or [""])[-1].strip()
    if state not in ("NEU", "VORHANDEN", "SCHON"):
        raise ActionError("Die .htaccess ist ein Verweis. Es wurde nichts verändert.")
    if state == "SCHON":
        log("Vorhandener Block", True, "In der .htaccess steht der Block '%s' schon." % mark)
        result["ok"] = True
        result["message"] = "Der Block '%s' steht in der .htaccess schon. Es wurde nichts geändert. Wirkt er nicht, hat der Server die Regel nicht angenommen: Prüfe dann Hoster-Einstellungen bzw. den Server-Typ." % mark
        return
    w = runner.sh(site_dir, 'if [ ! -w . ]; then echo SCHUTZ-ORDNER; elif [ -e .htaccess ] && [ ! -w .htaccess ]; then echo SCHUTZ-DATEI; else echo frei; fi', 30)
    if "SCHUTZ" in w.out:
        raise ActionError("Die .htaccess oder der Hauptordner ist schreibgeschützt (Rechte, Dateiwächter oder Hoster). Es wurde nichts verändert. Hebe den Schutz kurz auf und versuche es erneut.")
    out = _mkdir_backup(runner, site_dir, "htaccess")
    result["backup_dir"] = out
    q = sq(out)
    if state == "VORHANDEN":
        r = runner.sh(site_dir, "cp -p -- .htaccess %s/htaccess.vorher && cmp -s .htaccess %s/htaccess.vorher && echo gesichert" % (q, q), 30)
        if "gesichert" not in r.out:
            raise ActionError("Die vorhandene .htaccess konnte nicht gesichert werden. Es wurde nichts verändert.")
        undo = "cp -p -- %s/htaccess.vorher <Seitenordner>/.htaccess" % out
    else:
        undo = "rm -f -- <Seitenordner>/.htaccess"
    log("Sicherung der .htaccess", True, "Alter Stand: %s" % ("htaccess.vorher" if state == "VORHANDEN" else "keine Datei vorhanden"))
    runner.sh(site_dir, "cat > %s/rueckgaengig.txt" % q, 30, stdin="# CLAUDIA: so wird '%s' rückgängig gemacht\n%s\n" % (ACTIONS[aid]["title"], undo))

    def restore() -> bool:
        cmd = ("cp -p -- %s/htaccess.vorher .htaccess && cmp -s %s/htaccess.vorher .htaccess && echo zurueck" % (q, q)) if state == "VORHANDEN" else "rm -f -- .htaccess && echo zurueck"
        return "zurueck" in runner.sh(site_dir, cmd, 30).out

    write = "printf '\\n' >> .htaccess && cat >> .htaccess" if state == "VORHANDEN" else "cat > .htaccess && chmod 644 .htaccess"
    runner.sh(site_dir, write + " && echo geschrieben", 30, stdin=block)
    r = runner.sh(site_dir, "grep -qi %s .htaccess && echo da" % sq(mark), 30)
    if "da" not in r.out:
        restore()
        raise ActionError("Der Block konnte nicht geschrieben werden. Der alte Stand ist wiederhergestellt.")
    log("Block schreiben", True, ".htaccess: %s" % mark)
    verdict, why = ht_block_verdict(aid, params, base)
    log("Wirkung prüfen", verdict == "ok", why)
    if verdict == "ok":
        result["ok"] = True
        result["message"] = "%s Rückgängig: %s/rueckgaengig.txt" % (why, out)
        if ACTIONS[aid].get("irreversible"):
            result["message"] += " ACHTUNG: Browser, die den Header gesehen haben, merken sich ihn %d Tage; das lässt sich vom Server aus nicht zurückrufen." % (HSTS_MAX_AGE // 86400)
        return
    ok = restore()
    log("Alten Stand herstellen", ok, "Die .htaccess ist wieder wie vorher." if ok else "Der alte Stand konnte nicht hergestellt werden: %s" % undo)
    result["error"] = "%s Der Block wurde %s." % (why, "zurückgenommen" if ok else "NICHT zurückgenommen, bitte von Hand: " + undo)
    result["message"] = ""


def _run_harden_perms(runner, site_dir: str, params: Dict[str, Any], allowed_files: Optional[List[str]], context: Dict[str, Any], log, result: Dict[str, Any]) -> None:
    """Gruppen-Schreibrecht entfernen und die Konfigurationsdatei auf 440 setzen; Wirkung per Abruf der Startseite prüfen, sonst alte Rechte zurück."""
    base = str((context or {}).get("url") or "").strip().rstrip("/")
    if not base.lower().startswith("https://"):
        raise ActionError("Zum Prüfen der Wirkung braucht die Aktion die https-Adresse der Seite (Feld 'Adresse der Seite'). Es wurde nichts verändert.")
    files = [f for f in (params.get("files") or []) if isinstance(f, str)]
    if allowed_files is not None:
        files = [f for f in files if f in allowed_files]          # nur, was die Prüfung selbst gemeldet hat
    files = [f for f in files if _safe_path(f)][:CHMOD_MAX]
    if not files:
        raise ActionError("Keine passenden Dateien.")
    cfg = str(params.get("config") or "")
    before = _fetch_url(base + "/")
    log_path = _mkdir_backup(runner, site_dir, "rechte")
    result["backup_dir"] = log_path
    q = sq(log_path)
    runner.sh(site_dir, "cat > %s/rueckgaengig.txt" % q, 30, stdin="# CLAUDIA: so werden die Dateirechte zurückgesetzt\n# rechte_vorher.txt enthält je Zeile 'Rechte Pfad' (Pfade relativ zum Seitenordner)\n"
              "# Beispiel: chmod 644 -- ./index.php\n")
    parts = []
    for f in files:
        mode = "440" if f == cfg else "g-w"
        parts.append('f=%s; if [ -e "$f" ] && [ ! -L "$f" ]; then stat -c \'%%a %%n\' -- "$f" >> %s/rechte_vorher.txt; chmod %s -- "$f" && echo "OK $f" || echo "FEHLER $f"; else echo "UEBERSPRUNGEN $f"; fi'
                     % (sq(f), q, mode))
    r = runner.sh(site_dir, "; ".join(parts), 120)
    okn = sum(1 for l in lines_of(r.out) if l.startswith("OK "))
    bad = [l for l in lines_of(r.out) if l.startswith(("FEHLER", "UEBERSPRUNGEN"))]
    log("Rechte ändern", okn > 0 and not any(l.startswith("FEHLER") for l in bad),
        "%d geändert, %d übersprungen/fehlgeschlagen. Vorher-Rechte: %s/rechte_vorher.txt" % (okn, len(bad), log_path))

    def restore() -> bool:
        rr = runner.sh(site_dir, 'while read -r m f; do if [ -e "$f" ] && [ ! -L "$f" ]; then chmod "$m" -- "$f" || echo "FEHLER $f"; fi; done < %s/rechte_vorher.txt; echo fertig' % q, 120)
        return "fertig" in rr.out and "FEHLER" not in rr.out

    if okn == 0:
        raise ActionError("Es konnte keine Datei geändert werden (übersprungen oder Rechte fehlen). Es wurde nichts verändert.")
    after = _fetch_url(base + "/")
    if after.error or after.status >= 500:
        if before.error or before.status >= 500:
            why = "Die Startseite war schon vorher nicht erreichbar oder fehlerhaft (%s); der Test sagt nichts über die neuen Rechte." % (before.error or "HTTP %s" % before.status)
            log("Wirkung prüfen", False, why)
            result["ok"] = True
            result["message"] = "Bei %d Eintrag/Einträgen wurden die Rechte gesetzt. Hinweis: %s Alte Rechte: %s/rechte_vorher.txt" % (okn, why, log_path)
            return
        ok = restore()
        log("Wirkung prüfen", False, "Startseite liefert jetzt %s; alte Rechte %s." % (after.error or "HTTP %s" % after.status, "wiederhergestellt" if ok else "NICHT vollständig wiederhergestellt"))
        raise ActionError("Die Startseite ist mit den neuen Rechten nicht erreichbar (%s). %s" % (after.error or "HTTP %s" % after.status,
                          "Die alten Rechte sind wiederhergestellt." if ok else "ACHTUNG: Die alten Rechte konnten nicht vollständig wiederhergestellt werden; siehe %s/rechte_vorher.txt" % log_path))
    log("Wirkung prüfen", True, "Startseite liefert HTTP %s." % after.status)
    result["ok"] = True
    result["message"] = ("Bei %d Eintrag/Einträgen wurden die Rechte auf die Sollwerte gesetzt%s. Die Startseite wird weiter ausgeliefert. Alte Rechte: %s/rechte_vorher.txt"
                         % (okn, " (Konfigurationsdatei: 440)" if cfg else "", log_path))
    if bad:
        result["message"] += " Nicht geändert: %d (übersprungen oder fehlgeschlagen)." % len(bad)


def _picked_shell_files(params: Dict[str, Any], picked: List[str], allowed: Optional[List[str]]) -> List[str]:
    """Angehakte Dateien: Hintertüren nur, wenn die Prüfung sie gemeldet hat; sonst nur PHP-Dateien im Upload-Ordner. Nie außerhalb der Seite."""
    ud = _upload_dir(params)
    reported = [f for f in (params.get("files") or []) if _safe_path(f) and (allowed is None or f in allowed)]
    out: List[str] = []
    for f in picked:
        if not _safe_path(f) or f in out:
            continue
        if f in reported or (f.startswith("./%s/" % ud) and PHP_NAME_RE.search(f)):
            out.append(f)
    return out[: MAX_FILES + 400]


def _run_remove_shells(runner, site_dir: str, params: Dict[str, Any], allowed: Optional[List[str]], log, result: Dict[str, Any]) -> None:
    files = [f for f in (params.get("files") or []) if _safe_path(f)]
    if allowed is not None:
        files = [f for f in files if f in allowed]
    picked = _picked(params, "f")
    if picked:
        files = _picked_shell_files(params, picked, allowed)          # nur, was du angehakt hast (und was die Prüfung gemeldet hat)
        log("Auswahl", bool(files), "%d von %d Datei(en) ausgewählt" % (len(files), len(params.get("files") or []) + len(picked)))
    elif params.get("images"):
        ud = _upload_dir(params)
        r = runner.sh(site_dir, "find %s -type f %s ! -size 0 -print0 2>/dev/null | head -c 200000" % (sq(ud), PHP_EXT_FIND), 120)
        for f in [x for x in r.out.split("\0") if x]:
            f = "./" + f.lstrip("./") if not f.startswith("./") else f
            if _safe_path(f) and f not in files:
                files.append(f)
        log("PHP-Dateien in %s suchen" % ud, True, "%d Datei(en) im Ordner %s" % (len([f for f in files if f.startswith("./%s/" % ud)]), ud))
    files = files[: MAX_FILES + 400]
    if not files:
        raise ActionError("Keine passenden Dateien gefunden.")
    # nur vorhandene, normale Dateien (keine Verweise)
    payload = "\0".join(files) + "\0"
    r = runner.sh(site_dir, 'while IFS= read -r -d "" f; do if [ -f "$f" ] && [ ! -L "$f" ]; then printf "%s\\0" "$f"; fi; done', 60, stdin=payload)
    present = [x for x in r.out.split("\0") if x]
    if not present:
        result["ok"] = True
        result["message"] = "Die Dateien sind nicht mehr vorhanden. Es gibt nichts zu löschen."
        return
    # Schreibschutz (Rechte 555/444, Dateiwächter, Hoster): Dateien in nicht beschreibbaren Ordnern können nicht gelöscht werden, das merkt das Programm vor der Sicherung
    r = runner.sh(site_dir, 'while IFS= read -r -d "" f; do d=$(dirname -- "$f"); if [ -w "$d" ]; then printf "%s\\0" "$f"; else printf "RO:%s\\0" "$f"; fi; done', 60, stdin="\0".join(present) + "\0")
    ro = [x[3:] for x in r.out.split("\0") if x.startswith("RO:")]
    present = [x for x in r.out.split("\0") if x and not x.startswith("RO:")]
    if ro:
        log("Schreibschutz", bool(present), "%d Datei(en) liegen in einem nicht beschreibbaren Ordner und werden ausgelassen: %s" % (len(ro), ", ".join(ro[:5])))
        result["readonly"] = ro[:50]
    if not present:
        raise ActionError("Alle ausgewählten Dateien liegen in Ordnern, in die das Konto nicht schreiben darf (Schreibschutz, Dateiwächter oder Hoster-Einstellung). Es wurde nichts verändert. Hebe den Schutz auf oder ändere die Rechte, dann versuche es erneut.")
    site_abs = (lines_of(runner.sh(site_dir, "pwd -P", 15).out) or [""])[0]
    if not site_abs.startswith("/"):
        raise ActionError("Der Seitenordner auf dem Server konnte nicht ermittelt werden. Es wurde nichts verändert.")
    out = _new_quarantine_dir(runner, site_dir)
    q = sq(out)
    result["backup_dir"] = out
    r = runner.sh(site_dir, "cat > %s/%s && echo fertig" % (q, QUAR_LIST_NAME), 30, stdin=_quarantine_header(site_abs))
    if "fertig" not in r.out:
        runner.sh(site_dir, "rm -rf -- %s" % q, 30)
        result["backup_dir"] = ""
        raise ActionError("Die Liste im Quarantäne-Ordner konnte nicht geschrieben werden. Es wurde nichts verschoben.")
    log("Quarantäne-Ordner anlegen", True, "%s (Rechte 700, außerhalb des Web-Ordners)" % out)
    r = runner.sh(site_dir, QUAR_MOVE.replace("@Q@", q), 900, stdin="\0".join(present) + "\0")
    rows = _parse_quar_lines(r.out)
    moved = [x for x in rows if x[0] == "OK"]
    skipped = [x for x in rows if x[0] == "UEBERSPRUNGEN"]
    bad = [x for x in rows if x[0] == "FEHLER"]
    notes = [x for x in rows if x[0] == "HINWEIS"]
    cnt = (lines_of(runner.sh(site_dir, "ls -1 -- %s/d | wc -l" % q, 30).out) or ["0"])[-1].strip()
    confirmed = cnt.isdigit() and int(cnt) == len(moved)
    log("%d Datei(en) verschieben" % len(present), len(moved) == len(present) and confirmed,
        "%d verschoben, %d übersprungen, %d fehlgeschlagen; im Quarantäne-Ordner liegen %s Datei(en)" % (len(moved), len(skipped), len(bad), cnt))
    for x in notes:
        log("Hinweis: %s" % x[1], True, x[2] if len(x) > 2 else "")
    for x in skipped + bad:
        log("%s: %s" % ("Übersprungen" if x[0] == "UEBERSPRUNGEN" else "Fehler", x[1]), False, x[2] if len(x) > 2 else "")
    if not moved:
        runner.sh(site_dir, "rm -rf -- %s" % q, 30)
        result["backup_dir"] = ""
        raise ActionError("Keine Datei konnte verschoben werden, es wurde nichts verändert. " + "; ".join("%s: %s" % (x[1], x[2]) for x in (skipped + bad)[:5] if len(x) > 2))
    result["quarantine"] = {"dir": out, "moved": [x[2] for x in moved], "skipped": [x[1] for x in skipped], "failed": [x[1] for x in bad]}
    result["ok"] = len(moved) == len(present) and confirmed
    if result["ok"]:
        result["message"] = ("%d Datei(en) in die Quarantäne verschoben (nicht gelöscht): %s. Sie sind schädlich: nicht öffnen. Zurückholen: Aktion 'Dateien aus der Quarantäne zurückholen'." % (len(moved), out))
    else:
        result["error"] = ("%d von %d Datei(en) verschoben (Quarantäne: %s). Nicht verschoben: %s. Die übrigen Dateien liegen unverändert an ihrem Platz."
                           % (len(moved), len(present), out, "; ".join("%s (%s)" % (x[1], x[2] if len(x) > 2 else "?") for x in (skipped + bad)[:5]) or "Kontrolle der Anzahl stimmt nicht"))


QUAR_DEL = r"""S=$(pwd -P)
skip() { printf 'UEBERSPRUNGEN\t%s\t%s\n' "$e" "$1"; }
fail() { printf 'FEHLER\t%s\t%s\n' "$e" "$1"; }
while IFS= read -r -d "" e; do
  case "$e" in claudia-quarantaene-*|@OLD@-quarantaene-*) ;; *) skip "kein Quarantäne-Ordner"; continue;; esac
  case "$e" in */*) skip "ungültiger Name"; continue;; esac
  Q="$HOME/$e"
  if [ ! -d "$Q" ] || [ -L "$Q" ]; then skip "Ordner fehlt oder ist ein Verweis"; continue; fi
  [ -f "$Q/QUARANTAENE.txt" ] || { skip "keine Liste QUARANTAENE.txt (nicht von diesem Programm)"; continue; }
  site=$(sed -n 's/^# Seitenordner: //p' "$Q/QUARANTAENE.txt" | head -1)
  [ "$site" = "$S" ] || { skip "gehört zu einer anderen Seite"; continue; }
  n=$(ls -1 "$Q/d" 2>/dev/null | wc -l | tr -d ' ')
  rm -rf -- "$Q" 2>/dev/null
  if [ -e "$Q" ]; then fail "Ordner konnte nicht vollständig gelöscht werden"; else printf 'OK\t%s\t%s Datei(en)\n' "$e" "$n"; fi
done"""
QUAR_DEL = QUAR_DEL.replace("@OLD@", OLD_ID)


def _run_delete_quarantine(runner, site_dir: str, params: Dict[str, Any], log, result: Dict[str, Any]) -> None:
    names: List[str] = []
    for k in _picked(params, "k"):
        if QUAR_NAME_RE.match(k) and k not in names:
            names.append(k)
    if not names:
        raise ActionError("Keine Ordner ausgewählt. Es wurde nichts verändert.")
    r = runner.sh(site_dir, QUAR_DEL, 600, stdin="\0".join(names) + "\0")
    rows = _parse_quar_lines(r.out)
    done = [x for x in rows if x[0] == "OK"]
    other = [x for x in rows if x[0] in ("UEBERSPRUNGEN", "FEHLER")]
    for x in rows:
        if x[0] == "OK":
            log("Gelöscht: %s" % x[1], True, x[2] if len(x) > 2 else "")
        else:
            log("%s: %s" % ("Übersprungen" if x[0] == "UEBERSPRUNGEN" else "Fehler", x[1]), False, x[2] if len(x) > 2 else "")
    result["deleted"] = [x[1] for x in done]
    result["ok"] = len(done) == len(names)
    if result["ok"]:
        result["message"] = "%d Quarantäne-Ordner gelöscht. Die Dateien darin sind endgültig weg." % len(done)
    else:
        result["error"] = ("%d von %d Ordner(n) gelöscht. Nicht gelöscht: %s"
                           % (len(done), len(names), "; ".join("%s (%s)" % (x[1], x[2] if len(x) > 2 else "?") for x in other[:6]) or "unbekannter Grund"))


def _run_restore_quarantine(runner, site_dir: str, params: Dict[str, Any], log, result: Dict[str, Any]) -> None:
    keys: List[str] = []
    for k in _picked(params, "q"):
        if QUAR_KEY_RE.match(k) and k not in keys:
            keys.append(k)
    if not keys:
        raise ActionError("Keine Dateien ausgewählt. Es wurde nichts verändert.")
    r = runner.sh(site_dir, QUAR_BACK, 900, stdin="\0".join(keys) + "\0")
    rows = _parse_quar_lines(r.out)
    done = [x for x in rows if x[0] == "OK"]
    skipped = [x for x in rows if x[0] == "UEBERSPRUNGEN"]
    bad = [x for x in rows if x[0] == "FEHLER"]
    for x in rows:
        if x[0] == "OK":
            log("Zurückgeholt: %s" % (x[2] if len(x) > 2 else x[1]), True, "aus %s" % x[1])
        elif x[0] == "HINWEIS":
            log("Hinweis: %s" % x[1], True, x[2] if len(x) > 2 else "")
        else:
            log("%s: %s" % ("Übersprungen" if x[0] == "UEBERSPRUNGEN" else "Fehler", x[1]), False, x[2] if len(x) > 2 else "")
    result["restored"] = [x[2] for x in done if len(x) > 2]
    result["ok"] = len(done) == len(keys)
    if result["ok"]:
        result["message"] = "%d Datei(en) aus der Quarantäne zurückgeholt, mit den ursprünglichen Rechten. Das Protokoll steht in ZURUECK.txt im Quarantäne-Ordner." % len(done)
    else:
        result["error"] = ("%d von %d Datei(en) zurückgeholt. Nicht zurückgeholt (unverändert in der Quarantäne): %s"
                           % (len(done), len(keys), "; ".join("%s (%s)" % (x[1], x[2] if len(x) > 2 else "?") for x in (skipped + bad)[:6]) or "unbekannter Grund"))


def _selected_updates(params: Dict[str, Any], context: Dict[str, Any]) -> List[Dict[str, Any]]:
    known = {int(u["uid"]): u for u in context.get("ext_updates") or []}
    want = []
    for i in params.get("selected") or []:
        try:
            want.append(int(i))
        except (TypeError, ValueError):
            pass
    todo = [known[i] for i in dict.fromkeys(want) if i in known and not known[i].get("needs_key")]
    if not todo:
        raise ActionError("Keine auswählbaren Updates. Updates mit Download-Schlüssel (kostenpflichtige Erweiterungen) bitte im Joomla-Backend installieren.")
    return todo


CLI_INCOMPATIBLE_RE = re.compile(r"Cannot assign Joomla\\CMS\\Application\\ConsoleApplication|ConsoleApplication to property|CMSApplication.*ConsoleApplication", re.I)
EXT_RETRIES = 3          # weitere Durchgänge nach einem Fehlschlag (Abhängigkeiten: andere Erweiterungen sind dann evtl. schon aktualisiert)


def classify_install_failure(output: str) -> str:
    """'cli' = der Installer der Erweiterung läuft nicht über die Kommandozeile (Wiederholen ändert nichts), sonst 'retry'."""
    return "cli" if CLI_INCOMPATIBLE_RE.search(output or "") else "retry"


def _run_update_extensions(runner, site_dir: str, php: str, params: Dict[str, Any], context: Dict[str, Any], log, result: Dict[str, Any], emit) -> None:
    todo = _selected_updates(params, context)
    cfg = _read_cfg(runner, site_dir)
    pw = str(cfg.get("password", "")) + "\n"
    cli = "timeout -k 5 600 %s cli/joomla.php " % sq(php)
    done: List[str] = []
    manual: List[Dict[str, str]] = []
    urls: Dict[str, str] = {}
    pending = list(todo)
    for rnd in range(EXT_RETRIES + 1):
        if rnd:
            emit("info", "Wiederholung %d von %d für: %s (andere Erweiterungen sind inzwischen evtl. aktualisiert, von denen diese abhängt)"
                 % (rnd, EXT_RETRIES, ", ".join(u["name"] for u in pending)))
        retry: List[Dict[str, Any]] = []
        for u in pending:
            tag = "" if not rnd else " (Versuch %d)" % (rnd + 1)
            emit("info", "Erweiterung: %s  %s -> %s%s" % (u["name"], u.get("old_version") or "?", u["new_version"], tag))
            if u["name"] not in urls:
                r = runner.sh(site_dir, "curl -fsSL --max-time 40 --proto '=https' -- %s 2>&1 | head -c 2000000" % sq(u["detailsurl"]), 60)
                urls[u["name"]] = pick_download(r.out, u["new_version"], u.get("element", "")) or ""
            url = urls[u["name"]]
            if not url:
                log("Download-Adresse für %s" % u["name"], False, "Im Update-Manifest wurde keine https-Adresse für Version %s gefunden." % u["new_version"])
                retry.append(u)
                continue
            log("Download-Adresse für %s" % u["name"], True, url)
            r = runner.sh(site_dir, cli + "extension:install --url=%s </dev/null 2>&1" % sq(url), 660)
            good = r.rc == 0 and not r.timed_out
            log("Installieren: %s%s" % (u["name"], tag), good, r.out.strip()[-800:])
            if not good:
                if classify_install_failure(r.out) == "cli":
                    manual.append({"name": u["name"], "url": url, "version": u["new_version"]})
                    emit("info", "%s lässt sich nicht über die Kommandozeile installieren (Installer-Skript der Erweiterung). Das wird nicht wiederholt, die Anleitung für das Backend folgt." % u["name"])
                else:
                    retry.append(u)
                continue
            r = runner.sh(site_dir, _mysql_script(cfg, "SELECT IFNULL(JSON_UNQUOTE(JSON_EXTRACT(manifest_cache,'$.version')),'') AS v FROM #__extensions WHERE extension_id=%d" % int(u["eid"])), 60, stdin=pw)
            now = (lines_of(r.out)[1:] or [""])[0].strip()
            ok = now == u["new_version"]
            log("Version kontrollieren: %s" % u["name"], ok, "Jetzt installiert: %s (erwartet %s)" % (now or "?", u["new_version"]))
            if ok:
                done.append(u["name"])
            else:
                retry.append(u)
        pending = retry
        if not pending:
            break
    failed = [u["name"] for u in pending]
    r = runner.sh(site_dir, cli + "update:extensions:check </dev/null 2>&1", 330)
    log("Update-Liste neu abgleichen", r.rc == 0, r.out.strip()[-400:])
    r = runner.sh(site_dir, cli + "cache:clean </dev/null 2>&1", 330)
    log("Cache leeren", r.rc == 0, r.out.strip()[-300:])
    result["ok"] = bool(done) and not failed
    result["updated"] = done
    result["manual"] = manual
    result["failed"] = failed
    parts = []
    if done:
        parts.append("%d Erweiterung(en) aktualisiert: %s. Prüfe deine Webseite im Browser." % (len(done), ", ".join(done)))
    man = ""
    if manual:
        man = ("Nicht per Kommandozeile installierbar: %s. Installiere sie im Joomla-Backend (System -> Aktualisieren, dort die Erweiterung) oder lade das ZIP "
               "von der Adresse und installiere es unter System -> Installieren -> Erweiterungen." % ", ".join("%s (%s)" % (m["name"], m["url"]) for m in manual))
        parts.append(man)
    result["message"] = " ".join(parts) if result["ok"] else ""
    if failed or (manual and not done):
        result["error"] = (("Auch nach %d weiteren Versuchen nicht installiert: %s. " % (EXT_RETRIES, ", ".join(failed))) if failed else "") + man + \
            " Bereits installierte Updates bleiben bestehen. Die Sicherung liegt in %s." % (result.get("backup_dir") or "-")


# ------------------------------------------------------------------------------------------------ Konten, Sitzungen, Erweiterungen (2.3.0)
# Welche kurzen, nur lesenden Prüfungen nach einer Aktion wiederholt werden (Kontrolle vorher/nachher), je CMS
RECHECK: Dict[str, Dict[str, List[str]]] = {
    "remove_shells": {"joomla": ["webshells", "php_in_uploads"], "wordpress": ["webshells", "php_in_uploads"]},
    "restore_quarantine": {"joomla": ["webshells", "php_in_uploads"], "wordpress": ["webshells", "php_in_uploads"]},
    "reset_htaccess": {"joomla": ["htaccess"], "wordpress": ["htaccess"]},
    "remove_db_code": {"joomla": ["db_content"], "wordpress": ["wp_db_content"]},
    "clean_tmp": {"joomla": ["php_in_uploads"], "wordpress": ["php_in_uploads"]},
    "fix_permissions": {"joomla": ["perms"], "wordpress": ["perms"]},
    "fix_update_perms": {"joomla": ["update_ready"], "wordpress": ["update_ready"]},
    "remove_jce_profiles": {"joomla": ["db_jce"]},
    "block_users": {"joomla": ["db_users"], "wordpress": ["wp_db_users"]},
    "revoke_tokens": {"joomla": ["joomla_api"], "wordpress": ["wp_db_users"]},
    "end_sessions": {"joomla": ["sessions"], "wordpress": ["sessions"]},
    "disable_api": {"joomla": ["joomla_api"]},
    "deactivate_extension": {"joomla": ["extensions_fs"]},
    "wp_deactivate_plugin": {"wordpress": ["wp_plugins"]},
    "wp_fix_registration": {"wordpress": ["wp_db_options"]},
    "wp_salts": {"wordpress": ["wp_config"]},
    "wp_disallow_edit": {"wordpress": ["wp_config"]},
    "joomla_core_reinstall": {"joomla": ["joomla_core"]},
    "wp_core_reinstall": {"wordpress": ["wp_core"]},
    "install_security": {"joomla": ["security_ext"], "wordpress": ["security_ext"]},
    "install_backup": {"joomla": ["backup_tool"], "wordpress": ["backup_tool"]},
    "delete_old_backups": {"joomla": ["backups_in_webroot"], "wordpress": ["backups_in_webroot"]},
    "harden_listing": {"wordpress": ["wp_exposure"]},
    "wp_block_xmlrpc": {"wordpress": ["wp_exposure"]},
}


def count_sev(findings: List[Any]) -> Tuple[int, int]:
    """(kritisch, Warnungen) aus Befunden (Objekte oder Dicts)."""
    c = w = 0
    for f in findings or []:
        sev = f.get("sev") if isinstance(f, dict) else getattr(f, "sev", "")
        c += sev == "crit"
        w += sev == "warn"
    return c, w


def recheck_line(kind: str, cw: Tuple[int, int]) -> str:
    return ("Vorher: %d kritisch, %d Warnung(en)." if kind == "before" else "Jetzt: %d kritisch, %d Warnung(en).") % cw


PICK_ACTIONS = ("block_users", "revoke_tokens", "deactivate_extension", "wp_deactivate_plugin", "remove_shells", "restore_quarantine", "delete_quarantine", "remove_db_code")
PICK_RE = re.compile(r"^(u|e|p|f|q|k|x):(.{1,400})$")
EXT_KEY_RE = re.compile(r"^(component|plugin|module)/([A-Za-z0-9_.-]{1,60}|-)/([A-Za-z0-9_.-]{1,80})$")
_ID_TAG_RE = re.compile(r"\s*\[ID (\d+)\]\s*$")
_EXT_TAG_RE = re.compile(r"\[Kennung: ([^\]]+)\]\s*$")
PROTECTED_JOOMLA_FOLDERS = ("authentication", "multifactorauth", "twofactorauth")


def _picked(params: Dict[str, Any], kind: str) -> List[str]:
    """Die gewählten Einträge einer Art ('u' Benutzer, 'e' Joomla-Erweiterung, 'p' Plugin, 'f' Datei, 'q' Datei in der Quarantäne, 'k' Quarantäne-Ordner) ohne die Vorsilbe, ohne Doppelte."""
    out: List[str] = []
    for k in params.get("selected_pick") or []:
        m = PICK_RE.match(str(k))
        if m and m.group(1) == kind and m.group(2) not in out:
            out.append(m.group(2))
    return out


def _picked_ids(params: Dict[str, Any]) -> List[int]:
    return sorted({int(x) for x in _picked(params, "u") if x.isdigit()})


def pick_from_items(items: List[str], kind: str) -> List[Dict[str, Any]]:
    """Wählbare Einträge aus den Zeilen eines Befunds (mit [ID n] bzw. [Kennung: ...] am Ende). Zeilen ohne Marke werden übersprungen."""
    out: List[Dict[str, Any]] = []
    seen = set()
    for i in items:
        if not isinstance(i, str) or i.startswith(" "):
            continue
        if kind == "u":
            m = _ID_TAG_RE.search(i)
            if not m or ("u:" + m.group(1)) in seen:
                continue
            key, label = "u:" + m.group(1), _ID_TAG_RE.sub("", i)
        else:
            m = _EXT_TAG_RE.search(i)
            if not m or (kind + ":" + m.group(1)) in seen:
                continue
            key, label = kind + ":" + m.group(1), _EXT_TAG_RE.sub("", i)
        seen.add(key)
        out.append({"key": key, "label": label.strip()[:300], "pre": True})
    return out


def _protected_tool_names() -> set:
    """Ordner- und Elementnamen der erkannten Sicherheits- und Sicherungs-Erweiterungen (aus den festen Listen). Diese werden nie ausgeschaltet."""
    from .checks.security_ext import load_tools
    names = set()
    for kind in ("security", "backup"):
        d = load_tools(kind)
        for cms in ("joomla", "wordpress"):
            for t in d.get(cms, []):
                for p in t.get("paths", []):
                    p = str(p).lower()
                    names.add(p)
                    names.add(re.sub(r"^(com|plg|mod)_", "", p))
    return names


def _sql_ints(ids: List[int]) -> str:
    return ",".join(str(int(i)) for i in ids)


def _dump_for_change(runner, site_dir: str, cfg: Dict[str, Any], pw: str, label: str, tables: List[str], fname: str, log) -> str:
    """Tabellen sichern und prüfen, bevor etwas geändert wird. Wirft ActionError ('Es wurde nichts geändert')."""
    out = _mkdir_backup(runner, site_dir, label)
    r = runner.sh(site_dir, _db_dump_script(cfg, out, tables, fname), 300, stdin=pw)
    log("Tabelle(n) sichern: %s" % ", ".join(tables), r.rc == 0, (r.err or r.out)[:300])
    if r.rc != 0:
        raise ActionError("Die Sicherung ist nicht gelungen (%s). Es wurde nichts geändert." % ((r.err or r.out).strip()[:160] or "unbekannter Fehler"))
    return out


def _sql_rows(runner, site_dir: str, cfg: Dict[str, Any], pw: str, sql: str) -> List[List[str]]:
    r = runner.sh(site_dir, _mysql_script(cfg, sql), 60, stdin=pw)
    if r.rc != 0:
        raise ActionError("Eine Datenbankabfrage ist fehlgeschlagen: %s" % (r.err or r.out)[:200])
    return [l.split("\t") for l in lines_of(r.out)[1:]]


def _sql_exec(runner, site_dir: str, cfg: Dict[str, Any], pw: str, sql: str, log, title: str) -> None:
    r = runner.sh(site_dir, _mysql_script(cfg, sql), 60, stdin=pw)
    log(title, r.rc == 0, (r.err or r.out)[:200])
    if r.rc != 0:
        raise ActionError("%s ist fehlgeschlagen: %s" % (title, (r.err or r.out)[:200]))


def _run_block_users(runner, site_dir: str, params: Dict[str, Any], log, result: Dict[str, Any]) -> None:
    ids = _picked_ids(params)
    if not ids:
        raise ActionError("Keine Konten ausgewählt.")
    cfg, cms = _read_cfg_site(runner, site_dir)
    pw = str(cfg.get("password", "")) + "\n"
    il = _sql_ints(ids)
    if cms == "wordpress":
        # letzter Administrator? Nur Konten mit Rolle administrator zählen.
        adm = '%"administrator";b:1%'
        left = _sql_rows(runner, site_dir, cfg, pw, "SELECT COUNT(*) FROM #__usermeta WHERE meta_key = '#__capabilities' AND meta_value LIKE '%s' AND user_id NOT IN (%s)" % (adm, il))
        sel = _sql_rows(runner, site_dir, cfg, pw, "SELECT COUNT(*) FROM #__usermeta WHERE meta_key = '#__capabilities' AND meta_value LIKE '%s' AND user_id IN (%s)" % (adm, il))
    else:
        grp = "SELECT id FROM #__usergroups WHERE title IN ('Super Users', 'Administrator')"
        base = ("SELECT COUNT(DISTINCT u.id) FROM #__users u JOIN #__user_usergroup_map m ON m.user_id = u.id WHERE m.group_id IN (%s) AND u.block = 0 AND u.id %%s IN (%s)" % (grp, il))
        left = _sql_rows(runner, site_dir, cfg, pw, base % "NOT")
        sel = _sql_rows(runner, site_dir, cfg, pw, base % "")
    n_left = int((left[0][0] if left and left[0] and left[0][0].isdigit() else "0"))
    n_sel = int((sel[0][0] if sel and sel[0] and sel[0][0].isdigit() else "0"))
    log("Schutz des letzten Administrators prüfen", n_sel == 0 or n_left > 0,
        "Ausgewählte Administratoren: %d, danach übrig: %d" % (n_sel, n_left))
    if n_sel > 0 and n_left == 0:
        raise ActionError("Damit würden alle Administratoren gesperrt, und du kämst nicht mehr in die Verwaltung. Es wurde nichts geändert. "
                          "Lege zuerst einen eigenen, bekannten Administrator an oder wähle weniger Konten.")
    if cms == "wordpress":
        prefix = str(cfg.get("dbprefix", "wp_"))
        out = _dump_for_change(runner, site_dir, cfg, pw, "benutzer", [prefix + "users", prefix + "usermeta"], "benutzer.sql.gz", log)
        result["backup_dir"] = out
        import secrets as _s
        junk = "!" + _s.token_hex(24)          # kein gültiger Passwort-Hash: Anmeldung unmöglich
        _sql_exec(runner, site_dir, cfg, pw, "UPDATE #__usermeta SET meta_value = 'a:0:{}' WHERE meta_key = '#__capabilities' AND user_id IN (%s)" % il, log, "Rollen entziehen")
        _sql_exec(runner, site_dir, cfg, pw, "UPDATE #__users SET user_pass = '%s', user_activation_key = '' WHERE ID IN (%s)" % (junk, il), log, "Passwort entwerten")
        _sql_exec(runner, site_dir, cfg, pw, "DELETE FROM #__usermeta WHERE meta_key IN ('session_tokens', '_application_passwords') AND user_id IN (%s)" % il, log, "Sitzungen und Anwendungs-Passwörter löschen")
        rest = _sql_rows(runner, site_dir, cfg, pw, "SELECT COUNT(*) FROM #__usermeta WHERE meta_key = '#__capabilities' AND meta_value <> 'a:0:{}' AND user_id IN (%s)" % il)
        ok = bool(rest and rest[0] and rest[0][0] == "0")
        log("Kontrolle", ok, "Konten mit Rollen: %s" % (rest[0][0] if rest and rest[0] else "?"))
        result["ok"] = ok
        result["message"] = ("%d Konto/Konten gesperrt (Rollen entzogen, Passwort entwertet, Sitzungen beendet). Sicherung: %s" % (len(ids), out)) if ok else ""
        if not ok:
            result["error"] = "Die Rollen konnten nicht entzogen werden. Sperre die Konten im Dashboard unter Benutzer (Rolle entziehen, Passwort ändern)."
        return
    prefix = str(cfg.get("dbprefix", "jos_"))
    old = _sql_rows(runner, site_dir, cfg, pw, "SELECT id, block FROM #__users WHERE id IN (%s)" % il)
    todo = [int(x[0]) for x in old if len(x) >= 2 and x[0].isdigit() and x[1] == "0"]
    out = _dump_for_change(runner, site_dir, cfg, pw, "benutzer", [prefix + "users"], "benutzer.sql.gz", log)
    result["backup_dir"] = out
    if todo:
        r = runner.sh(site_dir, "cat > %s/rueckgaengig.sql" % sq(out), 30,
                      stdin="-- CLAUDIA: macht das Sperren rückgängig (mit mysql oder phpMyAdmin ausführen; #__ durch den Tabellenpräfix %s ersetzen)\nUPDATE %susers SET block = 0 WHERE id IN (%s);\n" % (prefix, prefix, _sql_ints(todo)))
        log("Rückgängig-Datei schreiben", r.rc == 0, "rueckgaengig.sql im Sicherungsordner")
    _sql_exec(runner, site_dir, cfg, pw, "UPDATE #__users SET block = 1 WHERE id IN (%s)" % il, log, "Konten sperren")
    _sql_exec(runner, site_dir, cfg, pw, "DELETE FROM #__session WHERE userid IN (%s)" % il, log, "Sitzungen der Konten beenden")
    rest = _sql_rows(runner, site_dir, cfg, pw, "SELECT COUNT(*) FROM #__users WHERE id IN (%s) AND block = 0" % il)
    ok = bool(rest and rest[0] and rest[0][0] == "0")
    log("Kontrolle", ok, "Noch aktive Konten unter den ausgewählten: %s" % (rest[0][0] if rest and rest[0] else "?"))
    result["ok"] = ok
    result["message"] = ("%d Konto/Konten gesperrt, Sitzungen beendet. Rückgängig: rueckgaengig.sql in %s" % (len(ids), out)) if ok else ""
    if not ok:
        result["error"] = "Die Konten konnten nicht gesperrt werden. Sperre sie im Backend unter Benutzer -> Verwalten."


def _run_revoke_tokens(runner, site_dir: str, params: Dict[str, Any], log, result: Dict[str, Any]) -> None:
    ids = _picked_ids(params)
    if not ids:
        raise ActionError("Keine Benutzer ausgewählt.")
    cfg, cms = _read_cfg_site(runner, site_dir)
    pw = str(cfg.get("password", "")) + "\n"
    il = _sql_ints(ids)
    if cms == "wordpress":
        prefix = str(cfg.get("dbprefix", "wp_"))
        out = _dump_for_change(runner, site_dir, cfg, pw, "tokens", [prefix + "usermeta"], "benutzerdaten.sql.gz", log)
        _sql_exec(runner, site_dir, cfg, pw, "DELETE FROM #__usermeta WHERE meta_key = '_application_passwords' AND user_id IN (%s)" % il, log, "Anwendungs-Passwörter löschen")
        rest = _sql_rows(runner, site_dir, cfg, pw, "SELECT COUNT(*) FROM #__usermeta WHERE meta_key = '_application_passwords' AND user_id IN (%s)" % il)
    else:
        prefix = str(cfg.get("dbprefix", "jos_"))
        out = _dump_for_change(runner, site_dir, cfg, pw, "tokens", [prefix + "user_profiles"], "benutzerprofile.sql.gz", log)
        _sql_exec(runner, site_dir, cfg, pw, "DELETE FROM #__user_profiles WHERE profile_key LIKE 'joomlatoken.%%' AND user_id IN (%s)" % il, log, "API-Tokens löschen")
        rest = _sql_rows(runner, site_dir, cfg, pw, "SELECT COUNT(*) FROM #__user_profiles WHERE profile_key LIKE 'joomlatoken.%%' AND user_id IN (%s)" % il)
    result["backup_dir"] = out
    ok = bool(rest and rest[0] and rest[0][0] == "0")
    log("Kontrolle", ok, "Übrig: %s" % (rest[0][0] if rest and rest[0] else "?"))
    result["ok"] = ok
    result["message"] = ("Bei %d Benutzer(n) wurden die Dauerzugänge widerrufen. Sicherung: %s" % (len(ids), out)) if ok else ""
    if not ok:
        result["error"] = "Nicht alles wurde gelöscht. Widerrufe die Zugänge im Backend bzw. Profil."


CHECKLIST = ("Als Nächstes: 1. Alle Passwörter ändern (Administratoren, Hosting, FTP/SFTP, Datenbank, E-Mail). 2. Datenbank-Passwort in der Konfigurationsdatei anpassen. "
             "3. SSH-Schlüssel und Cronjobs im Hosting-Konto prüfen (Prüfung 'Konto & Dauerzugänge'). 4. Schlüssel der Seite erneuern (WordPress: Lösung 'Neue Schlüssel in der wp-config.php').")


def _run_end_sessions(runner, site_dir: str, log, result: Dict[str, Any]) -> None:
    cfg, cms = _read_cfg_site(runner, site_dir)
    pw = str(cfg.get("password", "")) + "\n"
    if cms == "wordpress":
        n = _sql_rows(runner, site_dir, cfg, pw, "SELECT COUNT(*) FROM #__usermeta WHERE meta_key = 'session_tokens'")
        _sql_exec(runner, site_dir, cfg, pw, "DELETE FROM #__usermeta WHERE meta_key = 'session_tokens'", log, "Gespeicherte Sitzungen löschen")
        rest = _sql_rows(runner, site_dir, cfg, pw, "SELECT COUNT(*) FROM #__usermeta WHERE meta_key = 'session_tokens'")
    else:
        n = _sql_rows(runner, site_dir, cfg, pw, "SELECT COUNT(*) FROM #__session")
        _sql_exec(runner, site_dir, cfg, pw, "DELETE FROM #__session", log, "Tabelle der Sitzungen leeren")
        rest = _sql_rows(runner, site_dir, cfg, pw, "SELECT COUNT(*) FROM #__session")
    was = n[0][0] if n and n[0] else "?"
    ok = bool(rest and rest[0] and rest[0][0] == "0")
    log("Kontrolle", ok, "Vorher %s, jetzt %s" % (was, rest[0][0] if rest and rest[0] else "?"))
    result["ok"] = ok
    result["message"] = ("Alle Sitzungen sind beendet (vorher: %s). Du musst dich neu anmelden. " % was + CHECKLIST) if ok else ""
    if not ok:
        result["error"] = "Die Sitzungen konnten nicht gelöscht werden."


API_PLUGIN_SQL = "folder = 'webservices' OR (folder = 'user' AND element = 'token') OR folder = 'api-authentication'"


def _run_disable_api(runner, site_dir: str, log, result: Dict[str, Any]) -> None:
    """Joomla-API abschalten: Web-Services-, API-Token- und API-Authentifizierungs-Plugins auf enabled = 0. Mit Sicherung und rueckgaengig.sql."""
    cfg, cms = _read_cfg_site(runner, site_dir)
    if cms == "wordpress":
        raise ActionError("Diese Aktion gibt es nur für Joomla.")
    pw = str(cfg.get("password", "")) + "\n"
    prefix = str(cfg.get("dbprefix", "jos_"))
    rows = _sql_rows(runner, site_dir, cfg, pw, "SELECT extension_id, IFNULL(folder, ''), element FROM #__extensions WHERE type = 'plugin' AND enabled = 1 AND protected = 0 AND (%s)" % API_PLUGIN_SQL)
    todo = [(int(x[0]), "%s/%s" % (x[1], x[2])) for x in rows if len(x) >= 3 and x[0].isdigit()]
    log("Eingeschaltete API-Plugins suchen", True, ", ".join("%s (#%d)" % (n, i) for i, n in todo) or "keine")
    if not todo:
        result["ok"] = True
        result["message"] = "Es gibt nichts auszuschalten: Die API-Plugins sind schon aus."
        return
    ids = [i for i, _ in todo]
    out = _dump_for_change(runner, site_dir, cfg, pw, "api", [prefix + "extensions"], "extensions.sql.gz", log)
    result["backup_dir"] = out
    r = runner.sh(site_dir, "cat > %s/rueckgaengig.sql" % sq(out), 30,
                  stdin="-- CLAUDIA: schaltet die API-Plugins wieder ein (mit mysql oder phpMyAdmin ausführen)\nUPDATE %sextensions SET enabled = 1 WHERE extension_id IN (%s);\n" % (prefix, _sql_ints(ids)))
    log("Rückgängig-Datei schreiben", r.rc == 0, "rueckgaengig.sql im Sicherungsordner")
    if r.rc != 0:
        raise ActionError("Die Rückgängig-Datei konnte nicht geschrieben werden. Es wurde nichts geändert.")
    _sql_exec(runner, site_dir, cfg, pw, "UPDATE #__extensions SET enabled = 0 WHERE extension_id IN (%s) AND protected = 0" % _sql_ints(ids), log, "API-Plugins ausschalten")
    rest = _sql_rows(runner, site_dir, cfg, pw, "SELECT COUNT(*) FROM #__extensions WHERE extension_id IN (%s) AND enabled = 1" % _sql_ints(ids))
    ok = bool(rest and rest[0] and rest[0][0] == "0")
    log("Kontrolle", ok, "Noch eingeschaltet: %s" % (rest[0][0] if rest and rest[0] else "?"))
    result["ok"] = ok
    result["message"] = ("%d API-Plugin(s) ausgeschaltet. Ist der Joomla-Cache aktiv, leere ihn im Backend unter System -> Cache leeren. Rückgängig: rueckgaengig.sql in %s" % (len(ids), out)) if ok else ""
    if not ok:
        result["error"] = "Die Plugins konnten nicht ausgeschaltet werden. Tu es im Backend unter System -> Verwalten -> Plugins (Suche: Web Services, API)."


def _run_deactivate_joomla(runner, site_dir: str, params: Dict[str, Any], log, result: Dict[str, Any]) -> None:
    keys = [k for k in _picked(params, "e") if EXT_KEY_RE.match(k)]
    if not keys:
        raise ActionError("Keine Erweiterungen ausgewählt.")
    cfg = _read_cfg(runner, site_dir)
    pw = str(cfg.get("password", "")) + "\n"
    prefix = str(cfg.get("dbprefix", "jos_"))
    conds = []
    for k in keys:
        t, g, e = EXT_KEY_RE.match(k).groups()
        conds.append("(type = '%s' AND IFNULL(folder, '') = '%s' AND element = '%s')" % (t, "" if g == "-" else g, e))
    rows = _sql_rows(runner, site_dir, cfg, pw,
                     "SELECT extension_id, type, IFNULL(folder, ''), element, enabled, protected, (manifest_cache LIKE '%%Joomla! Project%%') AS core, name FROM #__extensions WHERE %s" % " OR ".join(conds))
    tools = _protected_tool_names()
    todo, skipped = [], []
    for x in rows:
        if len(x) < 8 or not x[0].isdigit():
            continue
        eid, typ, folder, el, enabled, prot, core, name = x[:8]
        why = ""
        if prot == "1":
            why = "vom System geschützt"
        elif core == "1":
            why = "gehört zum Joomla-Kern"
        elif folder in PROTECTED_JOOMLA_FOLDERS:
            why = "Anmelde- bzw. Zwei-Faktor-Erweiterung"
        elif el.lower() in tools or re.sub(r"^(com|plg|mod)_", "", el.lower()) in tools:
            why = "erkannte Sicherheits- oder Sicherungs-Erweiterung"
        if why:
            skipped.append("%s (%s)" % (name or el, why))
        elif enabled == "1":
            todo.append((int(eid), name or el))
    log("Auswahl prüfen", True, "Auszuschalten: %s%s" % (", ".join("%s (#%d)" % (n, i) for i, n in todo) or "keine", ("; geschützt, bleibt an: " + "; ".join(skipped)) if skipped else ""))
    if not todo:
        result["ok"] = True
        result["message"] = "Es gibt nichts auszuschalten: Die Erweiterungen sind schon aus, geschützt oder nicht mehr vorhanden." + ((" Geschützt: " + "; ".join(skipped)) if skipped else "")
        return
    ids = [i for i, _ in todo]
    out = _dump_for_change(runner, site_dir, cfg, pw, "erweiterungen", [prefix + "extensions"], "extensions.sql.gz", log)
    result["backup_dir"] = out
    runner.sh(site_dir, "cat > %s/rueckgaengig.sql" % sq(out), 30,
              stdin="-- CLAUDIA: schaltet die Erweiterungen wieder ein\nUPDATE %sextensions SET enabled = 1 WHERE extension_id IN (%s);\n" % (prefix, _sql_ints(ids)))
    _sql_exec(runner, site_dir, cfg, pw, "UPDATE #__extensions SET enabled = 0 WHERE extension_id IN (%s) AND protected = 0" % _sql_ints(ids), log, "Erweiterungen ausschalten")
    rest = _sql_rows(runner, site_dir, cfg, pw, "SELECT COUNT(*) FROM #__extensions WHERE extension_id IN (%s) AND enabled = 1" % _sql_ints(ids))
    ok = bool(rest and rest[0] and rest[0][0] == "0")
    log("Kontrolle", ok, "Noch eingeschaltet: %s" % (rest[0][0] if rest and rest[0] else "?"))
    result["ok"] = ok
    result["message"] = ("%d Erweiterung(en) ausgeschaltet. Die Dateien liegen noch da: aktualisiere oder deinstalliere sie. Rückgängig: rueckgaengig.sql in %s" % (len(ids), out)) if ok else ""
    if not ok:
        result["error"] = "Die Erweiterungen konnten nicht ausgeschaltet werden. Tu es im Backend unter System -> Verwalten -> Erweiterungen."


def _run_deactivate_wp(runner, site_dir: str, php: str, params: Dict[str, Any], log, result: Dict[str, Any]) -> None:
    slugs = [k for k in _picked(params, "p") if SLUG_RE.match(k)]
    if not slugs:
        raise ActionError("Keine Plugins ausgewählt.")
    wpcli = str(params.get("wpcli") or "")
    if not re.match(r"^[A-Za-z0-9._/~+-]+$", wpcli):
        raise ActionError("WP-CLI wurde auf dem Server nicht gefunden. Schalte das Plugin im Dashboard unter Plugins aus.")
    tools = _protected_tool_names()
    todo, skipped = [], []
    for sl in slugs:
        if sl in tools:
            skipped.append(sl + " (erkannte Sicherheits- oder Sicherungs-Erweiterung)")
            continue
        r = runner.sh(site_dir, _wp_cmd(php, wpcli, "plugin is-active %s && echo @@AKTIV" % sq(sl), 120), 130)
        (todo if "@@AKTIV" in r.out else skipped).append(sl if "@@AKTIV" in r.out else sl + " (ist nicht aktiv)")
    log("Auswahl prüfen", True, "Auszuschalten: %s%s" % (", ".join(todo) or "keine", ("; bleibt: " + "; ".join(skipped)) if skipped else ""))
    if not todo:
        result["ok"] = True
        result["message"] = "Es gibt nichts auszuschalten." + ((" Übersprungen: " + "; ".join(skipped)) if skipped else "")
        return
    cfg = _read_cfg(runner, site_dir)
    pw = str(cfg.get("password", "")) + "\n"
    prefix = str(cfg.get("dbprefix", "wp_"))
    out = _dump_for_change(runner, site_dir, cfg, pw, "plugins", [prefix + "options"], "options.sql.gz", log)
    result["backup_dir"] = out
    runner.sh(site_dir, "cat > %s/rueckgaengig.txt" % sq(out), 30,
              stdin="# CLAUDIA: schaltet die Plugins wieder ein (im WordPress-Ordner ausführen)\n" + "".join("wp plugin activate %s\n" % s for s in todo))
    bad = []
    for sl in todo:
        r = runner.sh(site_dir, _wp_cmd(php, wpcli, "plugin deactivate %s" % sq(sl), 120), 130)
        r2 = runner.sh(site_dir, _wp_cmd(php, wpcli, "plugin is-active %s && echo @@AKTIV" % sq(sl), 120), 130)
        ok1 = "@@AKTIV" not in r2.out
        log("Plugin ausschalten: %s" % sl, ok1, r.out.strip()[-300:])
        if not ok1:
            bad.append(sl)
    result["ok"] = not bad
    result["message"] = ("%d Plugin(s) ausgeschaltet. Die Dateien liegen noch da: aktualisiere oder lösche sie. Rückgängig: rueckgaengig.txt in %s" % (len(todo), out)) if not bad else ""
    if bad:
        result["error"] = "Diese Plugins sind noch aktiv: %s. Schalte sie im Dashboard unter Plugins aus." % ", ".join(bad)
