# CLAUDIA

<p align="center"><img src="claudia/assets/claudia_logo.png" width="180" alt="CLAUDIA"></p>

CLAUDIA ist ein kostenloses Windows-Programm (Python, Standardbibliothek + paramiko), das eine **Joomla**-, **WordPress**- (auch mit WooCommerce-Shop), **Drupal**- (ab Version 8), **TYPO3**- (ab Version 11), **Contao**- (ab Version 4.13), **PrestaShop**- (ab Version 1.7) oder **Shopware**-Seite (ab Version 6.5) über eine verschlüsselte SSH-Verbindung auf Spuren eines Hacks und auf typische Schwachstellen prüft.
Die Oberfläche läuft lokal auf `127.0.0.1` im Browser, auf Deutsch und Englisch (Flaggen), mit eingebauter Dokumentation.

## Grundsätze

- **Alle Prüfungen sind nur lesend.** Eine Prüfung ändert, löscht oder installiert nichts auf dem Server.
- **Änderungen nur über "Lösungen auf Knopfdruck"**: feste Aktionen mit Befehlsvorschau, ausdrücklicher Bestätigung und vorheriger, geprüfter Sicherung.
- **Nur verschlüsselte Verbindungen** (SSH/SFTP, https für Online-Abfragen).
- **Keine Geheimnisse gespeichert oder exportiert.** Passwörter und API-Schlüssel bleiben im Arbeitsspeicher.
- **Ehrliche Grenzen.** CLAUDIA sucht bekannte Spuren. "Keine Auffälligkeiten" beweist nicht, dass eine Seite sauber ist.

## So sieht es aus

Alle Bilder zeigen ein Beispiel mit erfundenen Testdaten.

| Verbinden | Prüfungen wählen |
|---|---|
| <picture><source media="(prefers-color-scheme: dark)" srcset="docs/images/01-verbinden-dark.png"><img src="docs/images/01-verbinden-light.png" width="540" alt="Verbinden"></picture> | <picture><source media="(prefers-color-scheme: dark)" srcset="docs/images/02-auswahl-dark.png"><img src="docs/images/02-auswahl-light.png" width="540" alt="Prüfungen wählen"></picture> |
| **Prüfung läuft** | **Befunde, kritische zuerst** |
| <picture><source media="(prefers-color-scheme: dark)" srcset="docs/images/03-laeuft-dark.png"><img src="docs/images/03-laeuft-light.png" width="540" alt="Prüfung läuft"></picture> | <picture><source media="(prefers-color-scheme: dark)" srcset="docs/images/05-befund-dark.png"><img src="docs/images/05-befund-light.png" width="540" alt="Befunde"></picture> |

Jeder Befund nennt, was gefunden wurde, die betroffenen Dateien oder Einträge und eine Empfehlung. Kritische Befunde sind rot markiert und stehen oben.

## Herunterladen und starten (ohne PowerShell)

Du brauchst weder PowerShell noch die Eingabeaufforderung:

1. Auf der Seite [Releases](https://github.com/conejito-vipe/CLAUDIA---Website-Maleware-Scanner/releases) die neueste Version öffnen und die Datei `CLAUDIA_v….zip` herunterladen. Dort steht auch die SHA-256-Prüfsumme; sie lässt sich mit `PRUEFSUMMEN.txt` vergleichen.
2. ZIP in einen normalen Ordner entpacken.
3. **Windows:** `start.bat` doppelklicken. **Mac:** `start.command` doppelklicken. Mehr ist nicht nötig; fehlt Python, richtet die Startdatei es selbst ein.

**Installer (ab 2.14.0):** Statt des ZIPs kannst du unter Windows `CLAUDIA-Setup-….exe` ausführen (Installation nur für deinen Benutzer, ohne Administratorrechte, mit Startmenü-Eintrag und auf Wunsch Desktop-Verknüpfung; erscheint unter „Installierte Apps“). Auf dem Mac: ZIP entpacken und `install.command` ausführen (Ziel `~/Applications/CLAUDIA`). Ist CLAUDIA schon installiert, fragt der Installer, ob er aktualisieren soll; deine Verbindungen, Einstellungen und Berichte bleiben erhalten. Auch der Installer ist nicht von Microsoft zertifiziert, es gilt dieselbe SmartScreen-Erklärung wie unten.

**Ohne Python (ab 2.18.0):** Auf der [Release-Seite](../../releases) gibt es zusätzlich `CLAUDIA-Setup-….exe` (Windows-Installer in einer Datei), `CLAUDIA_v…_Windows.zip` (tragbarer Ordner mit `CLAUDIA.exe`) und `CLAUDIA_v…_Mac.zip` (`CLAUDIA.app`, Apple Silicon). Sie bringen Python und alle Bausteine mit; es gibt keine Einrichtung beim ersten Start und keine PowerShell. Auf dem Mac ist das Programm nicht notarisiert: beim ersten Start Rechtsklick > Öffnen. Diese Fassungen aktualisieren sich nicht selbst; die neue Version von der Release-Seite laden (Daten in `%APPDATA%\CLAUDIA` bzw. `~/Library/Application Support/CLAUDIA` bleiben erhalten). Prüfsummen aller Dateien: `SHA256SUMS.txt` im Release.

**Updates (ab 2.16.0):** Beim Start prüft CLAUDIA im Hintergrund auf GitHub, ob es eine neuere Version gibt, und lädt sie nur nach deiner Bestätigung, vergleicht die SHA-256-Prüfsumme, sichert den Programmordner und tauscht ihn aus (bei Fehlern automatisch zurück). Du kannst eine Version überspringen oder mit dem Knopf "Updates" selbst suchen.

**Dashboard (ab 2.17.0):** Der Knopf "Dashboard" zeigt je Seite Stand, Verlauf und Vergleich der Prüfungen und verwaltet Sicherungen und Quarantäne auf dem Server (Vorschau und Bestätigung wie bei den Lösungen auf Knopfdruck), prüft Sicherungen auf Lesbarkeit, erinnert an die Nachkontrolle nach einer Bereinigung und exportiert den Verlauf als CSV oder Bericht. Ein Support-Paket (ohne Passwörter und Serveradresse) hilft bei Fehlermeldungen.

### Windows zeigt eine Warnung (SmartScreen)

CLAUDIA ist kostenlos und nicht von Microsoft zertifiziert. Deshalb kann Windows beim ersten Start von `start.bat` ein blaues Fenster „Der Computer wurde durch Windows geschützt“ mit dem Text „Von Windows SmartScreen wurde der Start einer unbekannten App verhindert“ zeigen. So geht es weiter:

1. Im Fenster auf **Weitere Informationen** klicken.
2. Darunter erscheint der Name der Datei (`start.bat`) und der Herausgeber („Unbekannter Herausgeber“). Auf **Trotzdem ausführen** klicken.

Zeigt der Browser schon beim Herunterladen eine Warnung („wird nicht häufig heruntergeladen“), im Download-Menü **Behalten** bzw. **Trotzdem behalten** wählen. Vergleiche vorher die Prüfsumme der ZIP mit der auf der Releases-Seite.

Auf dem Mac meldet macOS bei `start.command` unter Umständen, dass die Datei nicht geöffnet werden kann: Mit der rechten Maustaste auf die Datei klicken, **Öffnen** wählen und noch einmal **Öffnen** bestätigen (bei neueren macOS-Versionen: Systemeinstellungen > Datenschutz & Sicherheit > **Trotzdem öffnen**).

## Schnellstart (Windows)

1. ZIP in einen normalen Ordner entpacken.
2. `start.bat` doppelklicken (einzige Startdatei, richtet sich beim ersten Start selbst ein). Fehlt Python, lädt und installiert start.bat es automatisch (python.org, Signatur geprüft, nur für dein Benutzerkonto, kein Neustart nötig). Beim ersten Start entsteht die Verknüpfung `CLAUDIA.lnk` mit dem Eichhörnchen-Symbol.
3. SSH-Zugangsdaten des Hosters eintragen, Prüfungen wählen, starten.

Entwicklung, Tests und Dokumentation: siehe [README.md](README.md) und das Handbuch im Programm (Knopf "Hilfe") bzw. `CLAUDIA_Dokumentation.html`.

## Schnellstart (Mac, ab 2.9.0, noch nicht auf einem echten Mac getestet)

1. ZIP im Finder entpacken. 2. `start.command` doppelklicken (beim ersten Mal Rechtsklick > Öffnen). Fehlt Python 3.9+, lädt start.command den offiziellen Installer von python.org, prüft die Signatur und installiert ihn (macOS fragt nach deinem Passwort). 3. SSH-Zugangsdaten eingeben und starten.

## Warnung von Windows oder Virenscanner (zu erwarten)

Windows (SmartScreen, Defender) oder ein anderer Virenscanner kann vor CLAUDIA oder `start.bat` warnen oder sie als Schadsoftware bzw. mögliches Einfallstor einstufen. **Das ist nachvollziehbar und in einem Punkt richtig:** CLAUDIA kann SSH-Verbindungen zu einem Server aufbauen, genau so arbeitet das Programm. Es tut das **nur, wenn du es willst**: Du gibst die Zugangsdaten selbst ein, startest selbst eine Prüfung, und die Verbindung geht nur zu dem Server, den du eingetragen hast. Es gibt keine Verbindung im Hintergrund, und nichts startet von selbst.

Weitere Gründe für Warnungen: Das Programm ist nicht code-signiert (unbekannter Herausgeber), und `start.bat` kann Python herunterladen und installieren, wenn es fehlt.

Das kannst du tun:
- Nur aus diesem Repository herunterladen und die Dateien mit `PRUEFSUMMEN.txt` vergleichen.
- Der Quelltext ist offen; vor dem Start selbst lesen oder prüfen lassen.
- Wenn du dich entscheidest, zu vertrauen: in SmartScreen "Weitere Informationen" und dann "Trotzdem ausführen" wählen, oder im Virenscanner nur den CLAUDIA-Ordner erlauben. Den Schutz nicht allgemein ausschalten.

## Geplant

Alle geplanten Systeme sind eingebaut (Joomla, WordPress mit WooCommerce, Drupal, TYPO3, Contao, PrestaShop, Shopware). Die Reihenfolge ist Absicht: erst Härtung, dann Komfort. Zugesagt ist nur, was schon unter „Änderungen“ im Handbuch steht; alles hier ist Planung und kann sich ändern.

1. **Englische Übersetzung vervollständigen** (danach, damit sich die Texte nicht mehr ändern).

2. **Praxistests** auf echten Windows- und Mac-Rechnern mit echten Seiten.

Wünsche und Fehler bitte als Issue melden (Vorschläge zum Code als Pull Request, siehe CONTRIBUTING.md).

## Lizenz & Nutzung

CLAUDIA wird öffentlich bereitgestellt, um sie zu testen und weiterzuentwickeln. Die genauen Bedingungen regelt die [LICENSE](LICENSE); die deutsche Fassung ist verbindlich.

- **Kostenlos nutzbar:** Privatpersonen (nicht kommerziell) sowie gemeinnützige Organisationen und Vereine (für gemeinnützige Zwecke), jeweils auf eigenen Seiten.
- **Keine kommerzielle Nutzung ohne Freigabe:** Unternehmen, Selbständige, Agenturen und Behörden müssen vorab über mein GitHub-Profil ([@conejito-vipe](https://github.com/conejito-vipe)) eine Freigabe bzw. Lizenz anfragen. Das gilt auch für die Prüfung von Kundenseiten.
- **Keine Änderung, keine Weitergabe:** Die Software darf nicht verändert und nicht an Dritte weitergegeben werden, auch nicht unverändert. Der Quelltext ist zum Lesen und Prüfen da.
- **Ausschlüsse:** Politische Parteien sowie Vereine oder Gruppen, die vom Verfassungsschutz (Bund oder Land) als rechtsextremistische Bestrebung eingestuft oder verboten sind, sind von der Nutzung ausgeschlossen (Einzelheiten in der [LICENSE](LICENSE)).

Ohne jegliche Gewährleistung oder Erfolgsgarantie. Änderungen am Server auf eigene Gefahr. vibecoded with Claude (Anthropic) by conejito-vipe with love ❤️.
