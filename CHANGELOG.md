# Changelog

Generated from `claudia/docs/aenderungen.en.txt` (do not edit by hand).

## 2.19.0 (2026-11-26) - Automatic updates: now also for Drupal, TYPO3, Contao, PrestaShop, Shopware and WooCommerce

### Check: Do automatic updates really run? (all systems)
- **What:** The check now exists for all seven systems. Drupal: whether 'Update Manager' and 'Automatic Updates' are enabled, when cron last ran and when updates were last looked for, whether the site is managed with Composer. TYPO3: scheduler tasks, overdue tasks, last run. Contao: cron schedule (tl_cron_job), Contao Manager in the web folder. PrestaShop: the modules '1-Click Upgrade' (autoupgrade) and 'Cronjobs', their version and last run. Shopware: scheduled tasks (overdue, failed), auto_update settings, Composer. WooCommerce (on WordPress): Action Scheduler, i.e. overdue and failed tasks. Each system shows its own texts; it is stated explicitly when a system does not install core updates by itself (except Drupal with the 'Automatic Updates' module).
- **Why:** A stalled schedule is the most common reason update notices, cleanup and background tasks stop without anyone noticing. Whether a system updates itself is not the rule for these systems; the check says so openly instead of suggesting a safety that is not there.
- **How:** Read-only queries (SELECT on config, key_value, tx_scheduler_task, sys_registry, tl_cron_job, module, cronjobs, scheduled_task, actionscheduler_actions) and a few read-only shell calls (composer.lock, contao-manager, crontab, search for auto_update in configuration files). Missing tables count as "not present", missing database access as "not checkable". The evaluation is in pure functions (claudia/checks/auto_updates_cms.py) that are tested with sample data. Not yet tested against real servers: table and field names and the format of the time values; if they differ, the line appears as "not checkable", not as an error.

### Internal
- **What:** New file claudia/checks/auto_updates_cms.py and tests/test_auto_updates_cms.py; CheckDef knows "texts" (own texts per system).
- **Why:** One check with the same ID can show suitable descriptions per system without four copies.
- **How:** view() applies the texts of the respective system after text substitution; the allow-list common_checks of Drupal (shared by TYPO3, Contao, PrestaShop, Shopware) contains "auto_updates".

## 2.18.0 (2026-11-24) - Single program file and release workflow

### Single program file without Python setup (Windows, Mac)
- **What:** In addition to the existing package, CLAUDIA is available as a single program file: on Windows as an installer (CLAUDIA-Setup-….exe) or as a portable folder with CLAUDIA.exe, on the Mac as CLAUDIA.app (Apple silicon). Python and all components are included; nothing is set up or downloaded at first start. This build does not update itself: the update display points to the release page, "Install update" is not possible there. On uninstall, the Python environment and the program folder are left out (you delete the file or app yourself); reports, connections and settings can be removed as before.
- **Why:** Anyone without Python, or who does not want to run a PowerShell script, can open CLAUDIA with a double click. A running program file cannot replace its own program code with an update; an attempt would damage the installation.
- **How:** PyInstaller (tools/build_exe.py) packs the program code together with the interface, help texts, language files and lists into one package; the source files are included because the chapter "Technik" reads them. The entry point (installer/exe_main.py) redirects missing console output to nowhere and starts the same function as the Python package. "--selftest" checks in the built program that all program data is present. appupdate.FROZEN blocks install() without loading or changing anything. Building is only possible on the respective system (Windows and Mac cannot be built on Linux), see release workflow.

### Release workflow (GitHub Actions)
- **What:** The workflow "Release" (button only) runs the tests, builds the package, Windows installer, Windows folder and Mac app, checks every program file with the self-test and then creates the GitHub release v<version> directly: release notes as text, all files as attachments, SHA256SUMS.txt and the line "SHA-256: …" for the checksum of the package. If the tag already exists, the files are replaced and the text is updated.
- **Why:** One run delivers all files with matching checksums; nothing can be forgotten or mixed up by hand. The program only installs an update if the release contains CLAUDIA_v<version>.zip and its SHA-256.
- **How:** Five jobs (tests, package, windows, mac, release); only the last has write permission (contents: write), all actions are pinned to a commit. tools/release_body.py creates SHA256SUMS.txt and the text and refuses if RELEASE_NOTES.md does not belong to the version or the package is missing. Checksums of other files are only in SHA256SUMS.txt, not in the text, so that a wrong line is never read as the checksum of the package.

### Release notes: English with a switch to German
- **What:** On GitHub the release notes come first in English; German follows in a collapsible block. In the program the display follows the interface language. The text only says what changed technically and why.
- **Why:** GitHub has an international audience; the program should still display in the chosen language.
- **How:** tools/build_release.py writes RELEASE_NOTES.md from the change texts (both languages); appupdate.notes_for_lang cuts out the matching part and hides the checksum line and file list.

### Check: Do automatic updates really run?
- **What:** New check (Joomla and WordPress). Joomla 5.4 and newer: checks the setting "Automated Updates" and the update source, the API plugins the joomla.org update service needs, the update site, a core update that is available but not installed, offline mode and mail sending, and calls /api of the own site once with and once without a browser identification. Recognizes firewall extensions (e.g. HTProtect, Admin Tools), shows their settings about API, updates and bot filters and entries of their log about /api. WordPress: checks WP-Cron (schedule overdue, wp-cron.php blocked, DISABLE_WP_CRON without cron job) and version control in the folder. New action "Enable API for automatic Joomla updates" (two plugins, with backup and undo file). The action "Disable Joomla API" and the note in the check "API access" now say that this removes automatic core updates from Joomla 5.4 on.
- **Why:** The previous check "Can the site be updated automatically?" only checks whether an update in the backend succeeds (permissions, space, PHP). A site can be updated by hand without problems and still never by itself: the joomla.org update service triggers updates through the API, and a firewall, a disabled API or a wrong update source prevent that without anything being noticed.
- **How:** Read-only queries (settings from the extensions table, update sites, activity log) and two calls of /api with the server's curl (only status code, kind of response, server identification). A response counts as "rejected before Joomla" if it is an error code with HTML instead of JSON; if responses with and without browser identification differ, a bot filter is reported. Settings of firewall extensions are filtered by keywords, values related to keys (token, secret, key, license) are not shown. Not checkable from here: access from joomla.org and the registration with the update service.

### Internal
- **What:** New files installer/exe_main.py, tools/build_exe.py, tools/release_body.py, .github/workflows/release.yml, tests/test_exe_build.py, claudia/checks/auto_updates.py, tests/test_auto_updates.py, tests/test_autoupdate_action.py; installer/claudia.iss now also knows /DFrozenApp=1; the old workflow build-windows.yml is removed (replaced by release.yml).
- **Why:** One single way to a release instead of two separate ones.
- **How:** The Inno Setup file stays the same for both builds (same program ID), so an installation over the Python build runs as an update and old start files are removed.

## 2.17.0 (2026-11-24) - Dashboard and more

### Dashboard: overview, comparison, management
- **What:** New button "Dashboard". For each site it shows the latest state, the history as a curve, what is new, fixed or unchanged since the previous run, the number of fixed findings and carried-out actions, and hints (last run or backup too old). After connecting it also shows backups and quarantine folders on the server and offers creating a backup, deleting old backups and restoring or deleting quarantine. The history of a site can be deleted in two steps.
- **Why:** Anyone looking after several sites sees at a glance where something is open and whether a fix worked.
- **How:** After every run that completed and every action carried out, CLAUDIA writes a short entry to verlauf.json (only time, site, CMS, version, counts, short titles, actions; no passwords or file contents, nothing is sent). Fixed counts only if the check really ran the second time. Management uses the existing, tested actions with preview and confirmation. Restoring a full backup is deliberately not automatic because it cannot be undone.

### Follow-up check, check backup, export, support package
- **What:** In the dashboard the follow-up check reminds you: three days after a cleanup (e.g. malicious code removed, accounts blocked) a hint appears to check the site once more; the later run shows whether anything new has appeared since before the cleanup. "Check backup" opens the archives of a backup read-only and reports whether they can be read completely. The history can be saved as CSV and, per site, as a report (HTML) in the reports folder. The support package is a short text file for a GitHub issue.
- **Why:** Malware often comes back, and a backup that cannot be opened is otherwise noticed only in an emergency. When something fails, a package with versions, check status and update log helps more than a description from memory.
- **How:** The backup check uses gzip -t and tar tzf, changes nothing and accepts only backups from the program's list. In CSV files cells starting with =, +, - or @ are defused; the report writes all texts HTML-safe. The support package contains no passwords, no server address, no user name, no site folder and no texts of the findings.

### Digital signature for updates and knowledge data (prepared)
- **What:** Program updates and new knowledge data (patterns, vulnerability lists in advisories.json) can be checked with a digital signature (Ed25519). CLAUDIA loads new knowledge data separately from the program and uses it from the next run. The check is switched on as soon as the author's public key is stored in the program; until then the checksum applies unchanged and nothing additional is loaded.
- **Why:** The checksum is on the same release page as the package. A signature made with the author's private key, which is never in the program, protects even if the release page were changed.
- **How:** Without a valid signature nothing is installed and nothing is taken over; a signature is valid only for its purpose (program or knowledge data). Knowledge data must contain all sections of the bundled version and have a newer date, and the signature is checked again on every read. New tool tools/signieren.py (create key pair, sign, check); the private key is never in the repository.

### Internal
- **What:** New modules claudia/verlauf.py, claudia/signatur.py, claudia/wissen.py and claudia/support.py, new tests (history, dashboard extensions, signature, browser test of the dashboard); the list of not yet translated texts (tests/uebersetzung_offen.json) contains the new texts.
- **Why:** New functions should be covered by tests like the rest, the protection functions with proof of effect and the interface in a real browser.
- **How:** Behaviour of the existing functions is unchanged; the action backup_now can also be used without a previous run once connected (for the management in the dashboard).

## 2.16.1 (2026-11-23) - Hardening and cleanup

### Code audit: inputs, run time, XML
- **What:** Values from the server's configuration (database name, prefix, user, host and more) are checked more strictly: a trailing line break used to pass. Foreign XML (update lists, extension manifests) is read the same safe way everywhere, including the update list from joomla.org. Numbers from server output are only accepted as real digits. Masking credentials no longer takes minutes for files with very many unterminated entries, only seconds. Aborted connections to the local window no longer print an error.
- **Why:** A code audit with attack patterns, random inputs and load on the local server found these places. No gap was exploited, and the protection functions are now covered by tests that prove their effect.
- **How:** New helpers util.parse_xml and util.digits; the input rules end with \Z instead of $. New tests test_sicherheitsfunktionen.py (each protection is weakened on purpose, the test must then fail) and test_stress_robustheit.py.

### Cleanup
- **What:** Duplicate code merged (shared helpers of the evaluations, version cycle for TYPO3, Contao, PrestaShop and Shopware), unused imports removed, the tool folders .hypothesis, .pytest_cache and .ruff_cache no longer enter the package, the GitHub Actions are pinned to fixed commits.
- **Why:** Fewer copies mean fewer differences between copies, the most common cause of gaps.
- **How:** Behavior unchanged; existing tests not changed.

## 2.16.0 (2026-11-22) - Program update

### CLAUDIA looks for new versions at start
- **What:** At start CLAUDIA checks in the background whether a newer version exists on GitHub. A window shows the release notes and offers "Cancel", "Skip update" and "Install update"; the "Updates" button at the top searches at any time on request.
- **Why:** New checks and fixes should arrive without downloading by hand, but never without your consent.
- **How:** The package is downloaded, compared with the published checksum (SHA-256), the program folder is backed up and only then replaced. On an error the old state is restored automatically and the log update.log is written. Then CLAUDIA restarts; connections, settings and reports stay unchanged. Without a published checksum nothing is installed and the release page is shown instead.

## 2.15.0 (2026-11-22) - More intrusion paths

### New checks after research into current attacks
- **What:** New for WordPress: "Hidden code" (code that hides users, a mismatched db.php, hidden PHP files, placeholder plugins, file names from known attacks) and "Hidden options" (Base64 code in the database, WebSocket scripts in plugin settings). New for Joomla: "Known attacks" (Helix3 below 3.1.2, JCE below 2.9.99.5, cox.json, defacement scripts in template parameters). New for all systems: "Undeletable files and folders" (entries with an immutable flag or a foreign owner that cannot be deleted via FTP even with correct permissions; only the host or root can fix this) and "Spam for search engines" (foreign sitemaps, robots.txt, ads.txt). Extended: the skimmer search reports WebSocket connections to unknown addresses and code that checks for an admin bar or a touch device; the process check shows the account's shared-memory segments.
- **Why:** In 2026, self-healing WordPress malware (files, database and shared memory at once, with an invisible administrator), the Helix3 and JCE flaws in Joomla, WebSocket skimmers in WooCommerce shops and spam sitemaps were observed. These traces were not covered before.
- **How:** Everything is read-only and shows hits as hints, not proof. File names and versions come from public reports; attackers change them, so the check does not replace a cleanup by specialists.

### Name is CLAUDIA everywhere
- **What:** The release package is now called CLAUDIA_v<version>.zip and unpacks into the folder CLAUDIA; the documentation is called CLAUDIA_Dokumentation.html. The guide, manual and installer also write the name and the folders Documents\CLAUDIA and %APPDATA%\CLAUDIA in capitals.
- **Why:** The name should look the same everywhere.
- **How:** Existing data is kept (Windows does not distinguish upper and lower case in folder names; on Mac and Linux an existing folder keeps being used).

### Intern
- **What:** New file claudia/checks/zusatz.py with pure assessment functions (evaluate_*), extended skimmer.py and konto.py.
- **Why:** The assessment can be tested with sample texts, without a server.
- **How:** New test test_zusatz.py; existing tests were only adjusted in their check counts (see change report).

## 2.14.0 (2026-11-22) - Installer

### Installer for Windows and Mac (no administrator rights)
- **What:** Windows now has an installer (CLAUDIA-Setup-<version>.exe) that installs CLAUDIA into your user folder (%LOCALAPPDATA%\\Programs\\CLAUDIA), with a Start menu entry, an optional desktop shortcut and an entry under "Installed apps". On the Mac there is install.command (target ~/Applications/CLAUDIA). Both detect an existing installation and ask whether to update (lower version), reinstall or downgrade.
- **Why:** Easier start without unpacking and hunting for the folder; updates without data loss.
- **How:** An update replaces program code only; your connections, settings and reports (the CLAUDIA folder under %APPDATA% or ~/Library/Application Support) and the Python environment .venv are kept. The installer needs no administrator rights, is not code-signed like the program (see README for the SmartScreen note) and is built on GitHub (Actions, windows-latest). If CLAUDIA was set up with the installer, "Uninstall" in the program no longer offers the program folder; use Settings > Apps instead.

### Intern
- **What:** New file installer/claudia.iss (Inno Setup), workflow .github/workflows/build-windows.yml (manual only), install.command, uninstall.installed_by_setup().
- **Why:** The installer can only be built on Windows; the Linux test system checks scripts and logic.
- **How:** New test test_installer.py; the installer itself is tested in practice on Windows and Mac.

## 2.13.0 (2026-11-21) - Shopware

### Shopware sites are detected and checked
- **What:** CLAUDIA now detects Shopware 6 (6.5 and newer, Composer installation) and shows its own checks: core (version from composer.lock, support phase from a built-in table, security advisories from Packagist, comparison of the shopware/core, administration and storefront packages with the original from GitHub), settings (.env, dev mode, APP_SECRET, permissions of the .env and the private JWT key), publicly reachable files and pages, packages, plugins and apps (security advisories where listed on Packagist), administrator accounts, HTTPS of the shop addresses, integrations with administrator rights, webhooks, and code in shopping experiences, products, categories, snippets and settings.
- **Why:** Shopware shops are attacked like the other systems, mostly through third-party plugins. Typical traces are a new administrator account, a new integration with full rights, a script in a snippet (payment skimmer), a webhook to a foreign address and a reachable .env.
- **How:** Everything is strictly read-only. The .env is only read as text and never executed; database credentials, APP_SECRET, mail credentials and integration access keys are never shown or stored (of the APP_SECRET only the length). The content of the JWT key files is not read, only their permissions. Shopware does not store the time of the last login, so there is no statement about it. Shopware 5 is reported as no longer supported but not checked. There are no one-click solutions for Shopware yet. Important: so far the checks were only tried against a rebuilt test world, not a real Shopware server; response formats of Packagist and GitHub as well as table and field names may differ. If something is missing, the checks report 'not checkable' instead of guessing. Feedback from real use is welcome (test data ticket on GitHub).

### Internal
- **What:** The Shopware checks were secured with a rebuilt Shopware test world (SQLite database with user, integration, webhook, sales_channel_domain, cms_slot_translation and others). The version comparison in security advisories now understands four-part versions (6.6.10.0); this also applies to PrestaShop (1.7.8.11).
- **Why:** With three-part versions, security advisories for Shopware and older PrestaShop versions would never have matched.
- **How:** New tests; nothing changes for the other checks.

## 2.12.0 (2026-11-21) - PrestaShop

### PrestaShop sites are detected and checked
- **What:** CLAUDIA now detects PrestaShop (versions 1.7, 8 and 9; 1.6 with limits) and shows its own checks: core (version from app/AppKernel.php, support phase from a built-in table, security advisories from Packagist, comparison of the classes, controllers and src folders with the original from GitHub), settings (parameters.php, dev mode, cookie_key, install and admin folders, file permissions), publicly reachable files and pages, modules and overrides (security advisories where a module is listed on Packagist), employee accounts and super administrators, HTTPS and webservice settings, and code in pages, products, categories and text blocks.
- **Why:** PrestaShop shops are attacked just like the other systems, mostly through third-party modules. Typical traces are a new super administrator account, a script in a text block (payment skimmer), a leftover install folder and a reachable settings file.
- **How:** Everything is strictly read-only. The settings files are only read as text and never executed; database credentials, cookie_key, secret and webservice keys are never shown or stored (of the cookie_key only the length). There are no one-click solutions for PrestaShop yet. Important: so far the checks were only tried against a rebuilt test world, not a real PrestaShop server; response formats of Packagist and GitHub as well as table and field names may differ. If something is missing, the checks report 'not checkable' instead of guessing. Feedback from real use is welcome (test data ticket on GitHub).

### Internal
- **What:** The PrestaShop checks were secured with a rebuilt PrestaShop test world (SQLite database with ps_employee, ps_configuration, ps_webservice_*, ps_cms_lang and others).
- **Why:** Without a test, typos in queries or section markers would only have shown up in practical tests.
- **How:** New tests only; nothing changes for the other checks.

## 2.11.0 (2026-11-21) - Contao

### Contao sites are detected and checked
- **What:** CLAUDIA now detects Contao (version 4.13 and newer, Composer installation; older versions are detected and reported as no longer supported) and shows its own checks: core (version, end of support from a built-in table, security advisories from Packagist, comparison of the core packages contao/core-bundle, manager-bundle and installation-bundle with the original from GitHub), settings (.env, config/parameters.yaml, older localconfig.php: suspicious commands, development mode, APP_DEBUG, APP_SECRET, TRUSTED_HOSTS, allowed upload file types and HTML tags, minimum password length, file permissions), publicly reachable files, Install Tool, Contao Manager and development entry point, packages from composer.lock (security advisories from Packagist, development packages on the live server, own packages), backend administrators (also without two-factor authentication) and code in content elements, modules and page layouts. The general checks that read nothing system-specific run as well.
- **Why:** Contao sites are attacked just like the other systems, mostly through outdated extensions. Typical traces are a new administrator account, a script in a content element and a leftover .env or a reachable Contao Manager.
- **How:** Everything is strictly read-only. The settings files are only read as text and never executed; database credentials, APP_SECRET and mail credentials are never shown or stored (of APP_SECRET only the length). There are no one-click solutions for Contao yet. Limits: the original packages from GitHub have no published checksum (only the https source); the response formats of Packagist and GitHub as well as Contao table and field names have not yet been checked against a real server; if something is missing, the check reports 'not checkable'. The support table comes from endoflife.date (as of 2026-11) because contao.org was not reachable. No Contao logo is shown because there is no approved source.

### Internal
- **What:** The Contao checks were secured with a rebuilt Contao test world (Composer, SQLite database with tl_user, tl_content, tl_module, tl_layout). A check was missing from the Tech Docs list (TYPO3); this is fixed.
- **Why:** Without a test, typos in queries or section markers could only have shown up in the practical test.
- **How:** Pure fix and test; the behavior of the other checks does not change.

## 2.10.1 (2026-11-20) - License

### License rewritten
- **What:** The license (LICENSE, LIZENZ.txt, section in the READMEs) is new: free only for individuals and non-profit organizations, no commercial use, no modification and no redistribution without the author's consent. Parties and groups that are classified as a right-wing extremist effort by the Office for the Protection of the Constitution or that are banned are excluded. The footer now says "vibecoded" and names conejito-vipe.
- **Why:** The previous freeware license allowed professional use, modification and redistribution. That is no longer wanted. Tying the exclusion to the Office for the Protection of the Constitution makes it verifiable.
- **How:** Text change only; the program and the checks do not change.

## 2.10.0 (2026-11-19) - TYPO3

### TYPO3 sites are detected and checked
- **What:** CLAUDIA now detects TYPO3 (version 11 and newer, classic and Composer installations; older versions are detected and reported as no longer supported) and shows its own checks: core (version, end of support, security advisories, comparison of all system extension files with the original package from get.typo3.org), settings file (settings.php and additional.php: suspicious commands, error output, devIPmask, trustedHostsPattern, key length, password hashing, write permissions, enabled Install Tool), publicly reachable files and the Install Tool, extensions (security advisories from Packagist, obsolete extensions, development extensions, own packages), backend administrators and code in content and templates. The general checks that read nothing system-specific run as well.
- **Why:** TYPO3 sites are attacked just like Joomla, WordPress and Drupal, mostly through outdated extensions. Typical traces are a new administrator account, a script in a content element and a permanently enabled Install Tool.
- **How:** Everything is strictly read-only. The settings file is only read as text and never executed; database credentials, the encryption key and the Install Tool password are never shown or stored. There are no one-click solutions and no security extensions to install for TYPO3 yet; those only come with explicit approval in a later release. Limits: the response formats of get.typo3.org and Packagist as well as TYPO3 table and field names have not yet been checked against a real server; if something is missing, the check reports 'not checkable'. No TYPO3 logo is shown because there is no approved source.

### Internal
- **What:** The extension list check and the section markers of the server output were secured with a rebuilt TYPO3 test world (classic and Composer). The author name in the program and in the documentation is now conejito-vipe.
- **Why:** A section marker in the server output would have cut the extension list off after the first extension; this only showed up in testing.
- **How:** Pure fix and test; the behavior of the other checks does not change.

## 2.9.0 (2026-11-18) - Mac support

### CLAUDIA also runs on the Mac
- **What:** New start file start.command for macOS (double-click in Finder). It looks for Python 3.9 or newer, sets up missing Python automatically (official installer from python.org, signature checked, macOS asks for the Mac password) and starts CLAUDIA. Program data lives in ~/Library/Application Support/CLAUDIA, reports in ~/Documents/CLAUDIA/Berichte. On the Mac the program window has the normal window frame, the CLAUDIA icon appears in the Dock, error messages come as a Mac window, and the uninstaller names the way to remove the Python installed by start.command.
- **Why:** Mac users should also be able to check their sites without setting anything up by hand. Windows and the checks stay unchanged.
- **How:** On Mac and Linux the program starts in its own session so that it survives a closed Terminal window. The release package stores start.command with the execute permission. New tests check the start file (syntax, Python search), the storage locations, the browser search, the window and the package; GitHub additionally checks on a macOS machine. Limit: not yet tested on a real Mac; window, Dock icon and the Python setup are only shown by your practical test.

## 2.8.1 (2026-11-18) - Automated test run on GitHub

### Internal
- **What:** The automated test run on GitHub has been repaired. On Linux the whole test suite runs; on Windows only the selection from tests/windows_tests.txt (start, window, uninstall, icons, reports, documentation). The tests now also work as a normal user (not only as administrator), are no longer influenced by a PHP that is really installed on the machine, and Pillow and Python 3.9 are set up correctly in the test run; the browser tests run only on Python 3.13.
- **Why:** The tests simulate a Linux server (Linux commands, Linux file permissions) because CLAUDIA sends Linux commands to the web server. That cannot work on Windows. The run was therefore red although nothing in the program was broken.
- **How:** A pure test and tooling change; nothing changes in the program or the checks. Limit: The Windows run does not replace the practical test with a real window and start.bat.

## 2.8.0 (2026-11-17) - Drupal

### Drupal sites are detected and checked
- **What:** CLAUDIA now detects Drupal (version 8 and later; Drupal 7 is detected and reported as no longer supported) and shows its own checks: core (version, security updates, comparison of all files in the core folder with the original package from drupal.org), settings.php (suspicious commands, update_free_access, trusted_host_patterns, write permissions), publicly accessible files and interfaces (settings.php, composer files, JSON:API, installation page, directory listings), modules and themes (security updates, insecure and no longer maintained versions according to drupal.org), administrator accounts, settings in the database (error messages, open registration, development modules, permissions of the visitor role), and code in posts, blocks, and comments. The general checks that do not read anything system-specific also run (web shells, PHP in uploads, permissions, cron jobs, access logs, headers, and others).
- **Why:** Drupal sites are attacked just like Joomla and WordPress, mostly through outdated modules. The patterns (new administrator account, code in content, tampered core files) are the same.
- **How:** Everything is strictly read-only. The database connection uses the credentials from settings.php; they are never displayed or stored. For Drupal there are not yet any one-click fixes or security extensions to install; that will only come after explicit approval in a later release. Limits: The response format of updates.drupal.org and Drupal's table and field names have not yet been verified against a real server; if something is missing, the check reports 'cannot be checked'. The Drupal logo is not displayed because there is no approved source for it.

### Internal
- **What:** The restructuring to profiles (2.6.0) now supports a third system; the selection of the shared checks per system is stored in the profile. A new test runner (tools/run_tests.py) repeats failing, known flaky tests twice and notes this in the result.
- **Why:** More systems need one common place for their specifics, and flaky tests should neither hide real errors nor needlessly fail a run.
- **How:** A pure restructuring and test tool; the behavior of the checks does not change. The result of a run is written to tests/ERGEBNIS.txt, and open flaky tests name the command for a manual rerun.

## 2.7.0 (2026-11-17) - WooCommerce checks

### New checks for online shops with WooCommerce
- **What:** If WooCommerce is installed on a WordPress site, six checks are added: overview (installed, active, database update completed), API keys (orphaned, never used, long unused, and those with write access), webhooks (active webhooks that send order or customer data to catch-all addresses, bare IP addresses, or unknown recipients), payment methods (enabled payment methods, test mode, program code in titles and descriptions), accounts with the shop manager role (newly created ones stand out), and publicly accessible shop data (order and customer interface without login, logs, and directory listings).
- **Why:** A shop collects customer data and payments and is therefore targeted deliberately. Typical traces are a secretly created API key, a webhook that copies every order, or a script in the description text of a payment method. These things sit in the database and are not found by a plain file search.
- **How:** Everything is strictly read-only. Keys, secrets, and the payment providers' credentials are never output or stored. Without WooCommerce, the checks are skipped with a notice. The checks appear in the "Plugins & Themes" area in their own section "Check online shop (WooCommerce)" and in the action plan under access. Limit: The names of the WooCommerce tables and entries have not yet been verified against a real shop; if a table is missing, the check reports "cannot be checked" instead of guessing. Zapier, Make, and Slack (addresses from the providers' official documentation) only produce a notice, because their addresses belong to many customers and do not say who owns the account. Add webhook recipients you know under the allowed addresses.

## 2.6.0 (2026-11-17) - Restructuring to profiles per system

### Profiles per system
- **What:** Everything that differs between Joomla and WordPress (names, folders, required modules, notes on how to enable things, store, version, directories for security extensions) is now in one place in the system's profile. The checks, the report, and the server look it up there instead of having their own case distinctions.
- **Why:** Further systems (for example WooCommerce, Drupal, TYPO3) can be added later by creating a profile, without searching in many places in the program.
- **How:** A pure restructuring; the behavior has stayed the same. The existing tests ran through unchanged; new is a test that checks that every profile is complete. Places that really work differently (for example reading the configuration and the WordPress-specific checks) stay separate for now.

## 2.5.0 (2026-11-16) - Radar, new checks, hosting provider list, interface

### Radar display during the check
- **What:** In addition to the text output, the running check shows a radar. Each test is a dot that lights up when its result comes in; the check currently running is highlighted, and critical findings appear in bold amber.
- **Why:** If you leave the window open in the background, you can see at a glance how far the check has progressed and whether anything unusual has turned up.
- **How:** The display is just an extra and does not change any results. With "Reduce animations" turned on in Windows, a calm still image appears instead.

### New check: DNS changes
- **What:** The check "DNS changes since the saved baseline" compares nameservers, mail servers, website address, SPF, and DMARC with a state you saved earlier, and reports removed and new records.
- **Why:** Whoever takes over an account or domain often changes DNS records, for example for phishing emails or redirects. A deviation from the saved state stands out immediately.
- **How:** Only public DNS records are queried through the server, and they are stored on your computer only if you tick the checkbox. If a record cannot be queried, it is not compared.

### Comparison with the baseline: .htaccess and .user.ini
- **What:** Changes to .htaccess and .user.ini files always appear in the comparison as a separate finding, even if many other files change during an update.
- **Why:** Redirects and third-party code loaded before every page can be hidden in these files. Until now, they got lost in the mass when many files changed.
- **How:** New .htaccess files in upload folders remain a separate, critical finding.

### New checks: Joomla settings, environment, email delivery
- **What:** Joomla settings from the database (text filters, allowed upload extensions, registration, two-factor authentication, admin logins, age of extensions), WordPress two-factor, plain-text credentials, age of the latest backup, TLS versions, cookie protection, outdated JavaScript libraries, and email delivery (limited: sender, mail log, queue).
- **Why:** Many entry points lie in settings rather than in files. Open registration, missing two-factor authentication, or a very old backup would otherwise go unnoticed.
- **How:** Read-only. The field names of the Joomla tables were only checked against simulated data, not against a real Joomla database. New group "Joomla settings".

### Hosting provider list instead of action plan
- **What:** The "Action plan (recommendation)" section is removed because it duplicated the notices below it. New is a list of all items that only the hosting provider can change, with a prepared email to support. It also appears in the report.
- **Why:** Settings such as blocked PHP functions, PHP version, or mail server cannot be changed in the program. The list saves you from gathering them yourself.
- **How:** The texts are suggestions; please read them before sending. "First, a way back" is now shown in red, and the spacing before "Warning" and "Backup first" is now consistent.

### Clearer findings
- **What:** Access logs: blocked or not-found requests are green everywhere, successful ones red. Leftovers of aborted updates: the search now looks for update.php (extract.php belongs to the Joomla core). Missing package files (for example 1082 PHP files) are explained and separated from installation files. SPF with ?all is explained. "Dangerous functions" shows which extensions use them. Unknown file in a core folder: the red marking shows the spot, with a clear distinction between own and third-party file.
- **Why:** Findings should be unambiguous and explain what to do.
- **How:** The classification of extract.php rests on an inference (same modification time as a core file) and was not verified against a real installation.

### Interface
- **What:** Uninstall dialog rebuilt (close button at top right, buttons fixed at the bottom, same size as in the main window, nothing overlaps the scroll bar). Logo flush with the line under the navigation. Link to the guide for the free Safe Browsing key in the start form and in the finding; addresses in findings are clickable. Recommendations for extensions: free first, then paid under its own heading. The help window stays usable and movable during the check. Folders of earlier versions are taken over at startup (renamed, otherwise copied and checked).
- **Why:** Consistent sizes, spacing and labels in all windows; the link saves searching for the guide to the Safe Browsing key.
- **How:** Tested only on Linux in the browser, not yet in the Windows window.

## 2.4.1 (2026-11-14) - Hardening, integrity, action plan, fewer false alarms

### One-click hardening
- **What:** New actions for missing security headers, HSTS (marked red, with a second confirmation), directory listings, XML-RPC (WordPress) and file permissions. There is also a new action, "Switch off Joomla API (web services)".
- **Why:** Many entry points are not malware but open doors that can be closed with a few changes.
- **How:** Every action shows the commands first, creates a verified backup, aborts if there is no valid backup and names the way to undo it (usually rueckgaengig.sql or rueckgaengig.txt).

### Integrity of themes and extensions
- **What:** New checks compare WordPress themes and Joomla extensions with the manufacturer's original package. The check "Email protection (SPF, DMARC, DKIM)" is new as well.
- **Why:** A modified file in a theme or extension is a common way to plant backdoors, and missing email protection makes it easier to commit fraud in the name of the site.
- **How:** Read-only. So far the comparisons have only been tested against simulated responses, not against real servers.

### Action plan and reminder
- **What:** The result shows an action plan in a sensible order (first back up, then remove malicious code, then renew access). After 14 days the program reminds you to run a new comparison with the saved baseline.
- **Why:** Renewing passwords before the malicious code is removed does not help. And an old comparison says little about the current state.
- **How:** The plan is a recommendation and no proof that the site is clean. The reminder does not need a background service.

### Fewer false alarms, clearer colors
- **What:** Development files of libraries in the Joomla core and assignments in security extensions no longer trigger a critical finding. Hits without a command are green. In the attack list, repelled attempts are green and only successful ones are red.
- **Why:** Too many red messages hide the real ones.
- **How:** Findings with a command stay red. Detection still relies on known patterns.

### Security extension and backup folders
- **What:** The recommendation of a security extension now appears only at the top. Backup folders on the server are now named claudia-sicherung-... (quarantine: claudia-quarantaene-...); folders of earlier versions stay visible and can be deleted.
- **Why:** The name should match the program, and the recommendation should not appear twice.
- **How:** WordPress extensions can be installed directly; for Joomla there are no verified update addresses, so the instructions for installing it yourself remain.

### Program window, startup and uninstall
- **What:** The window opens in the center, can be resized and is closed with the X. The help window has an X. The red "Uninstall" button is above the footer. start.bat sets up Python itself and creates a shortcut with an icon. If start.bat installed Python from python.org, the uninstall names the Windows way to remove it.
- **Why:** Anyone starting without Python experience should not be left without a result.
- **How:** Only tested under Linux, not yet under Windows.

### Note on Windows and antivirus software
- **What:** The README and the manual point out that Windows or an antivirus program may report CLAUDIA as malware.
- **Why:** CLAUDIA opens SSH connections, and that is exactly what protection programs detect.
- **How:** The program connects only when you want it to, and only in encrypted form.

## 2.4.0 (2026-11-11) - New checks, two new actions, new look

### Comparison with a saved baseline
- **What:** New check "Comparison with saved baseline". It calculates SHA-256 checksums of all PHP, JS and .htaccess files and lists the upload folders. It compares them with a run you saved earlier and reports new, changed and deleted files. A new PHP file in an upload folder is critical.
- **Why:** Against a state you consider clean, any deviation stands out, even if the code itself looks harmless.
- **How:** A baseline is saved only if you tick the box, and only on your computer (paths and checksums, no contents, no credentials). The result shows whether a baseline exists and offers "Delete baseline". Honest limits: after an update many files change (from 150 changes on, the check says "probably an update"); save the baseline again then. On shared hosting the run can take a few minutes (load "high", at most 30,000 files up to 2 MB).

### Check plugins against the original (WordPress)
- **What:** New check "Check plugin files against the original". For each installed plugin the program fetches the checksums published by wordpress.org and compares them with the files on the server.
- **Why:** A modified plugin is a common route for backdoors, even if the version number looks normal.
- **How:** Changed PHP files are critical, additional PHP files a warning, missing files a note. Plugins without checksums (premium, not on wordpress.org) are reported as "cannot be checked". Single requests are made one after another, at most 60 plugins (adjustable). Honest limit: the evaluation was tested against sample data, not against the live interface.

### Skimmer search (card data theft)
- **What:** New check "Skimmer search". It looks in files for code that reads card fields and sends them to a foreign address.
- **Why:** Skimmers in online shops steal payment data and are hard to notice.
- **How:** A finding appears only if card fields, a send call and a foreign address occur in the same file (your own address, known payment providers and your own list are excluded). Obfuscated code is critical, otherwise a warning; obfuscated script loaders are listed as a note. Honest limit: this is a pattern search and not proof; a shop with its own payment integration can trigger a match.

### Other installations: quick scan
- **What:** The check "Other websites on the same web space" can briefly examine each installation found, on request (options: quick scan, choice of names, time limit).
- **Why:** A forgotten second site is often the entry point for the whole web space.
- **How:** At most 10 installations, read-only: PHP in upload folders (critical), backdoor patterns (warning), outdated version (warning).

### Joomla API without login (CVE-2023-23752)
- **What:** New check "Joomla API: configuration without login". A single request from this PC, only for Joomla 4.0.0 to 4.2.7 or an unknown version.
- **Why:** The flaw lets any visitor read the database credentials and is exploited in bulk.
- **How:** The response is never shown or stored; only whether credentials are visible is reported.

### Backups made by other tools: access from outside
- **What:** The check "Backup tool present?" now also checks whether the backups of Akeeba, UpdraftPlus and others can be retrieved from outside.
- **Why:** A publicly retrievable backup contains the database and credentials; it can also contain the infection.
- **How:** One single request per storage folder for the newest file, only the first bytes, the content is never shown.

### More precise file checks
- **What:** The backdoor search now also finds PHP code in files that look like images or text files (image header with PHP behind it, include of image or text files). "Recently changed files" also evaluates the status change time (ctime), at most as a note or warning.
- **Why:** Attackers disguise code as images. And the modification date can be forged, the status change time not as easily.
- **How:** File size is limited. After "Remove write permission for everyone" the ctime of many files changes; the result points this out.

### Fewer false alarms from known extensions
- **What:** Files of known security and backup extensions are no longer reported as backdoors.
- **Why:** Before, a keyword in the path was enough; a backdoor named akeeba.php in the images folder would have slipped through.
- **How:** The allow list (known_tools.json, with date) applies only if the path is in the extension's folder AND the content contains its identifier.

### New action: reset the main .htaccess
- **What:** Replaces the .htaccess in the main folder with the standard file (Joomla: htaccess.txt from the verified original package, WordPress: standard block). Harmless own rules and blocks of known plugins are kept on request.
- **Why:** A manipulated .htaccess redirects visitors or runs code without any file standing out.
- **How:** The preview shows every change as a comparison (red = removed, green = new). Suspicious rules and auto_prepend_file are not kept. The old file is stored as htaccess.vorher in the backup folder, together with rueckgaengig.txt. Afterwards the program fetches the home page; on a server error the old state is restored immediately.

### New action: remove injected code from the database
- **What:** Removes from the database entries you select exactly the script and frame blocks the check classified as malicious or suspicious. The rest of the entry stays.
- **Why:** Malicious code in articles, modules and options otherwise returns after every file cleanup.
- **How:** Preview per entry; beforehand the old value of each entry is saved as an UPDATE statement in rueckgaengig.sql and verified; without a valid backup the action aborts. Not touched are serialized WordPress values, values over 1 MB and entries without a clear match; the reason is shown in the result. Afterwards clear the cache and check again.

### Joomla extensions from the directory: install only with a verified URL
- **What:** The program installs a Joomla extension only if the vendor offers a public update URL (https), the extension is free and the entry carries a date. Otherwise the card shows the directory link and instructions "Install from URL".
- **Why:** An unverified address must never lead to an installation unnoticed.
- **How:** At present only Akeeba Backup is stored this way; further addresses are added only after verification.

### New look: start, program and uninstall window
- **What:** Start, uninstall and program window have the same look: frameless with rounded corners, shadow, an orange name chip "CLAUDIA", logo, and a thin orange progress bar. New logo and new favicon. The program window has its own title bar with minimize, maximize and close. In the program window the name CLAUDIA appears as orange text without a chip; logo and name are 40% larger on the page. The name is written CLAUDIA everywhere (interface, reports, documentation). Folder and file names on the PC (e.g. %APPDATA%\CLAUDIA) stay unchanged so that existing profiles are still found. The former line with the acronym below the name is gone.
- **Why:** A uniform, calm appearance; the start window shows progress in percent.
- **How:** The start window uses PySide6 (package PySide6-Essentials, about 80 MB, set up in the Python environment on first start). On the very first start this setup still runs in the console because PySide6 is not there yet. If the setup fails, the program uses a simple tkinter window in the same color (without shadow and rounded corners). When uninstalling, the running Python environment cannot delete itself; an invisible helper removes it as soon as the window is closed. Honest limits: We have not yet tested the windows on Windows. With the environment variable CLAUDIA_NO_FRAMELESS the program window gets the normal frame again, with CLAUDIA_NO_QT the start window stays in tkinter.

### Counter: lines of pure Python code
- **What:** The footer shows the number of lines of pure Python code after the note "vibecoded by conejito-vipe with love".
- **Why:** An honest glimpse of the size of the program.
- **How:** tools/count_loc.py counts only lines with code using the Python parser, without blank lines, comments and docstrings, in claudia/ and tools/ (without tests). The release build writes the value to claudia/loc.json.

## 2.3.3 (2026-11-10) - Delete quarantine folders in the program

### New action: delete quarantine folders on the server
- **What:** Shows this site's quarantine folders (~/claudia-quarantaene-...) with the number of files still inside, size and origin paths. The ticked folders are deleted including contents and list. Nothing is preselected.
- **Why:** So far a quarantine could only be removed by hand via SFTP. Malicious code should not stay on the server forever once it is clear nothing needs to be restored.
- **How:** The preview shows the rm -rf command per folder. The script checks each folder: name matches, lies in the home directory, is not a link, contains the list QUARANTAENE.txt and belongs to this site according to the list. Otherwise it is skipped; foreign folders, other sites' folders and links are never touched. Afterwards it checks that the folder is gone. Honest limits: deleting is final, there is no way back and no backup (rescue single files first with "Restore files from quarantine"). A fully restored, empty folder is listed as well.

## 2.3.2 (2026-11-10) - Quarantine: move and restore

### Move backdoors into quarantine instead of deleting them
- **What:** The action "Backdoors and PHP files in images" no longer deletes anything. The ticked files are moved into a quarantine folder ~/claudia-quarantaene-<Datum> outside the web folder (mode 700). In quarantine they have no execute permission (600) and no .php extension, stored as d/<Nr>.q. The list QUARANTAENE.txt records origin path, permissions, owner, size, date and SHA-256 for each file.
- **Why:** A deleted file is gone, even if it was reported wrongly. A move can be reversed and documents what was removed.
- **How:** The list is written before the move, the checksum is compared after it. Special cases: symlinks and files in folders that lead out of the site via a link are skipped; the number makes equal file names from different folders unique; if the quarantine is on another file system the file is copied, the checksum compared and only then the original removed (otherwise it stays); files with further hard links are moved and a note names the remaining names. If the home directory lies inside the site folder the action aborts without any change. Honest limits: the program does not know the host's web root; it only checks whether the home directory is inside the site folder (an access block is also placed in the quarantine folder). The former archive backup dateien.tgz is dropped; the quarantine itself is the backup. The program does not delete old quarantine folders; do that by hand via SFTP.

### New action: restore files from quarantine
- **What:** Lists the files in this site's quarantine folders (nothing preselected), shows a preview with the commands first and, after your confirmation, moves the ticked files back to their original place with their original permissions.
- **Why:** A file moved by mistake (for example one of your own) should come back without manual work.
- **How:** Per file the program first checks: still in quarantine, belongs to this site, SHA-256 equals the list, origin folder exists, is writable and inside the site, origin location empty. If something is already there (even a link) exactly this file is skipped; nothing is ever overwritten and no folder is created. The data comes from the list on the server, not from the selection. The log is in ZURUECK.txt. Honest limits: without administrator rights the program cannot set the owner (a note appears in the result); the action also restores real malware if you select it.

## 2.3.1 (2026-11-09) - List when removing, PHP block, check afterwards, CSP check

### Removing backdoors: pick per file and a list with checksums
- **What:** When removing backdoors and PHP files in the images folder, you tick yourself which files go. Next to the backup archive there is now the file QUARANTAENE.txt with SHA-256, size, permissions, modification date and path of every removed file.
- **Why:** This keeps it traceable what was removed, and files you know stay untouched.
- **How:** Only ticked files are backed up (dateien.tgz, counted), listed and deleted; files outside the site or not reported by the check are ignored. Honest limit: This is a verified archive with a list, not a move into a quarantine folder; restoring works with tar (the command is in the list), there is no restore function in the program.

### Block PHP execution in the images folder
- **What:** New action: in the folder images (WordPress: wp-content/uploads) an .htaccess is created or extended that blocks PHP files there. Afterwards the program checks over https with two harmless test files (.txt and .php) that the block works and images are still served.
- **Why:** An images folder needs no PHP; a backdoor planted there then no longer runs until the point of entry is closed.
- **How:** Preview with the exact content, a copy of an existing .htaccess first (htaccess.vorher) and rueckgaengig.txt. If the block has no effect, causes errors or the request is not possible, the old state is restored immediately; the test files are always deleted. Honest limits: Only for Apache and compatible servers (nginx ignores .htaccess, the test detects that); the https address of the site must be entered; the block does not replace removing the backdoors. Tested against a simulated web server, not against a real site.

### Check after the action
- **What:** After a successful action the program runs the related checks again (read-only) and shows "Before" and "Now" (number of critical findings and warnings) in the result.
- **Why:** You see at once whether the action worked, without repeating the whole check.
- **How:** Each action is mapped to one or two checks (e.g. removing backdoors: webshells and php_in_uploads). The comparison uses the state of the last check in this session. Honest limits: Findings are counted, not files (if one entry of a combined finding remains, the number stays the same); the saved check report stays unchanged; without a previous check in the session there is no comparison; updates and backups have no check afterwards.

### Write protection and file watchers
- **What:** Actions that change files first check whether the folders are writable and otherwise abort without any change. The preview contains a note about file watchers.
- **Why:** Write protection (permissions, security extension, host) makes changes fail or reverts them; better you learn that beforehand.
- **How:** Test for write permission in the folder. Honest limit: The program cannot reliably detect a file watcher itself; the note is general.

### New check: Content Security Policy (CSP)
- **What:** The program checks whether a CSP is set (header or <meta> tag), shows every rule and explains individually what it does, and names weaknesses. If none is set, it explains the benefit and creates a proposal for the .htaccess from the addresses of your home page (first in test mode Report-Only).
- **Why:** A CSP can make the browsers of your visitors block planted malicious code instead of running it. It does not replace updates, but is an effective second line of defense.
- **How:** A single request of the home page, read-only; the proposal is only displayed. Honest limits: The proposal is based on the home page only (sub-pages, payment providers, maps and statistics may need more); the admin area usually needs looser rules; the CSP syntax is explained, not fully validated; tested against a simulated web server.

### Documentation: Tech Docs, shared styles, blank lines
- **What:** The area is now called "Tech Docs". In the change log there is a blank line before Why and How, like in the rest of the help area. All documentation styles are in one file (docs.css) with variables for spacing, colors and font at the top.
- **Why:** A uniform look and less duplicated style code.
- **How:** docs.css is used by the help window and the standalone HTML file together.

## 2.3.0 (2026-11-09) - Block accounts and extensions, findings in code, origin of attacks

### Block suspicious accounts, revoke permanent accesses, end sessions
- **What:** Three new actions: block user accounts (Joomla: block=1; WordPress: remove roles and invalidate the password), delete API tokens or application passwords of selected users, end all stored sessions. You pick the entries yourself in the list.
- **Why:** A password change alone ends neither an attacker's session nor his token; an account he created remains his permanent access.
- **How:** Preview with the exact commands, explicit confirmation, backup of the affected table first (without a valid backup it aborts); blocking and turning off additionally write an undo file in the backup folder. The last active administrator cannot be blocked. Honest limits: The storage location of the Joomla tokens is documented by the Joomla 4.2 API documentation; Joomla 5 and 6 were not individually checked against the source code (the check reports differing spellings as a counter-check). Sessions are not backed up because they are short-lived. You are logged out too.

### Turn off a vulnerable extension or plugin
- **What:** An extension (Joomla) or plugin (WordPress) with a known vulnerability can be turned off with one click until an update is available.
- **Why:** As long as the vulnerable component runs, the attacker can come back after the cleanup; turning it off closes the door immediately.
- **How:** Joomla: table extensions (enabled = 0), WordPress: WP-CLI (plugin deactivate). Backup and undo file first. The Joomla core, login and two-factor extensions and recognized security and backup extensions are never turned off. Honest limit: The files stay in place and can still be attacked; updating or deleting is still necessary.

### Findings with file, line and code marked in red
- **What:** For malware patterns, database hits and unknown files in core folders, the result shows the exact location and the surrounding code in a black code window; the hit is marked in red. Also in the TXT and HTML report.
- **Why:** A note without a location cannot be judged; this way you can see for yourself whether it is malicious code or a harmless hit.
- **How:** For every finding, 2 lines before and after are read (at most 30 places, 300 characters per line), read-only; the code is displayed, never executed. Honest limit: Very long lines are shortened; the marking shows the hit, not the whole malicious function.

### More precise assessment of patterns, hex sequences and core folders
- **What:** Assembled function names are distinguished by form (a name list in a security extension such as htprotect is a note, a call with an assembled name is a finding). Long \x.. sequences are decoded: a warning is given only if a command is in it (binary data in crypto libraries is harmless). Additional files in core folders are separated: program files (PHP) critical or warning with code, pure text and configuration files (README, XML, JSON) only as a note; files that belong to an installed extension are marked as such.
- **Why:** Before, harmless files of official extensions and crypto libraries raised alarms that hid real findings.
- **How:** Form (list or call), location, origin of the file and decoded content decide, not the word alone. Honest limit: Hex commands are only detected from 8 hex pairs; whether a file is unchanged cannot be checked by the program (recommendation: reinstall the extension via the updater).

### Origin of attackers with country flag
- **What:** At "Most frequent senders", the flag of the country in which the network is registered is shown before the IP.
- **Why:** Shows at a glance where scans come from.
- **How:** Official RDAP lookup at the five regional registries (ARIN, RIPE NCC, APNIC, LACNIC, AFRINIC); the responsible one is determined via the IANA list; only the truncated network is queried (last byte masked), never the full IP. Honest limits: This is the registration country, not the exact location; in the development environment the lookup was tested only with simulated responses, not live. Flags: Twemoji Country Flags (font: MIT; graphics: CC BY 4.0, Twitter/X and contributors).

### Official logos, profile name, prices and stars
- **What:** In the connection window, the official logo is shown next to the CMS name. Under "connected", the profile name comes first, then the server address. Installable tools are marked as free or paid and, if WordPress.org provides it, with their rating.
- **Why:** Easier to see what you are looking at and whether something costs money.
- **How:** The logos are loaded from the official servers at runtime and shown unaltered, not bundled. Sources: extensions.joomla.org and de.wordpress.org/plugins count as verified; the selection is deliberately small. Honest limits: Whether Joomla's brand policy allows a logo in programs is not clarified; concrete JED prices are not shown; the program trusts known security and backup extensions but does not look up every arbitrary extension at JED; the element identifier of Akeeba Backup for Joomla has not been checked against an installation.

### Uninstall in its own window
- **What:** The "Uninstall" button is at the bottom right; the uninstall runs in its own window with the size and layout of the start window, and the selection is readable.
- **Why:** The program cannot delete itself while it is running.
- **How:** A separate process from a copy in the temp folder waits until CLAUDIA has ended, deletes only the selected items (path check) and removes Python last with winget in its own console. Honest limit: This window (Tk) could not be started in the development environment; planning, path protection and sequence were tested with dummies. If tkinter is missing, the uninstall runs in the console.

### Help area as one area, status window without scroll bug
- **What:** "Check catalog, actions and technology" is one area with a table of contents, jump marks and "back to table of contents" at every entry. Every entry explains What and Why first, then How, then the code in a collapsed black window with green text and a copy button. Uniform style with a blank line after bullet lists and before subheadings. In the server-command window, the status no longer sticks after scrolling up, and "To the current status" leads back down.
- **Why:** One common thread for laypeople and professionals; the bug prevented following the running command.
- **How:** The area is generated from checks, actions and program code; the scroll position was read before redrawing instead of after.

### Not in 2.3.0
- **What:** Four items of the plan are still open: PHP block in the upload folder via .htaccess with web test and undo, quarantine with a list and selection of single files when removing web shells, automatic check before and after an action, protection list with a read-only note.
- **Why:** They change files on the server; they should only appear once preview, backup and undo are thoroughly tested.
- **How:** Planned for 2.3.1.

## 2.2.0 (2026-11-08) - Account & permanent access, technical chapter, backup tool, end of support

### Technical chapter in the documentation
- **What:** New "Technical" tab with the real commands, database queries, scripts, constants and functions behind every check and action, plus an explanation in plain words and the basics (connection, script execution, database access, backup).
- **Why:** Anyone who gives the program access to a server should be able to read and verify every step.
- **How:** The code is read from the program code when the documentation is generated (not copied by hand) and is therefore always current. Searchable, with copy buttons, in the program and in the HTML file. Honest limit: the explanation texts are written by hand; a test makes sure every check and action has one.

### Backups clearer and protected
- **What:** The preview of every action says what is backed up (full, targeted, log only or none). Every backup contains a MANIFEST.txt. If the backup folder lies in the public area of the site, it is protected and a warning is shown.
- **Why:** A backup in the web folder can contain credentials and malicious code and must never be reachable from the internet.
- **How:** Random names, .htaccess with a block, index.html, a note in the result. Honest limit: not every server honors .htaccess; the folder should be outside the web space.

### New group "Account & permanent access"
- **What:** Checks cron jobs, SSH keys, running processes, shell startup files, logged-in sessions, WordPress cron and the Joomla API with tokens.
- **Why:** Attackers often settle in outside the site's files; no file scan finds that.
- **How:** Read-only. Raw texts are not stored, passwords are masked, only fingerprints of SSH keys, only the count of tokens. Honest limits: ps, crontab and ssh-keygen are blocked on some hosts (the check then reports its limit); cron jobs in the host's customer area are not visible; the storage location of Joomla tokens is not checked against every version.

### End of support for Joomla and WordPress
- **What:** Reports when the installed Joomla series no longer receives security fixes or soon will not; for WordPress, how far the series is behind the newest.
- **Why:** On a series without security fixes every new vulnerability stays open.
- **How:** Comparison with a list (source endoflife.date, list date stated). Honest limit: the dates were not checked individually against every announcement of the project; WordPress has no fixed deadlines.

### Detect and install a backup tool
- **What:** The program detects Akeeba Backup, UpdraftPlus, Duplicator, BackWPup and WPvivid and whether they are switched on. If none is found, it offers installation with the same cards and the same preview as for security extensions.
- **Why:** Without a backup, only a rebuild remains after a hack or a failed update.
- **How:** WordPress via WP-CLI with activation and checksum verification, preceded by a backup and confirmation. Joomla: only link and instructions because no verified public update address is stored. Honest limit: it is not checked when the last backup ran or where the backups are stored.

### Server-level protection and .htaccess blocks
- **What:** Hints of server protection (e.g. ModSecurity, Imunify360) and BulletProof Security are detected. In the .htaccess, blocks of known programs are labeled; unknown blocks are listed.
- **Why:** Anyone protected by the host should not read "no protection" by mistake; rules from plugins should be distinguishable from foreign rules.
- **How:** The content of every block is still checked; a block name never softens a rating because an attacker can also write rules into such a block.

## 2.1.0 (2026-11-07) - Own program window, access protection, security extensions, action catalog

### One window instead of a browser tab
- **What:** CLAUDIA runs in its own program window. The start window appears only at startup and closes as soon as the program window has loaded. From then on exactly one window is open; closing it ends the program.
- **Why:** A browser tab looks like a web page, stays open and can be reopened by accident or addressed by other pages.
- **How:** Order of ways: own window with pywebview (Windows Edge engine), otherwise Edge/Chrome in app mode with its own temp profile, last the normal browser with a heartbeat (the program ends after 90 seconds without one). Closing during a check asks first.

### One-time start key instead of a token in the page
- **What:** Access works only through a start key that is valid once and for at most 120 seconds and goes only to the program's own window. After that a cookie applies (HttpOnly, SameSite=Strict). The page no longer contains a key.
- **Why:** A token in the page text can be read by other scripts; an ordinary browser tab could simply have opened the page.
- **How:** The server swaps the key for a session cookie and requires cookie and X-Claudia header for every API request. At most 4 sessions. Honest limit: this does not stop someone who changes the program code on the PC.

### Brake on wrong logins
- **What:** After 5 failed logins to the server there is a 10-minute pause; at least 1.5 seconds between two attempts.
- **Why:** Prevents the program from being abused as a password guesser against a server.
- **How:** Counter in the program, error 429 with an explanation.

### Readable start window
- **What:** The start window uses a dark background and the command-line font (Consolas or another fixed-width font).
- **Why:** The previous font was hard to read.
- **How:** The first available font of Consolas, Cascadia Mono, Lucida Console, DejaVu Sans Mono, Courier New is used.

### Install a security extension
- **What:** If the server has no firewall or scanner, the program shows cards with image, short description and a link to the store page and offers installation.
- **Why:** Without a protective layer the site stays vulnerable between a flaw becoming known and the update.
- **How:** WordPress via WP-CLI from wordpress.org with activation and checksum check. Joomla only free extensions with a public update address (https), otherwise only a store link. Always preview, confirmation and a backup first. Images are checked by their bytes (no SVG) and loaded only from fixed hosts.

### Action catalog in the documentation
- **What:** A new "Actions" tab with What, How (the commands), Why, warning, undo, risk and backup for every action; searchable, in the program and in the HTML file.
- **Why:** Anyone who allows changes on the server should be able to read beforehand what exactly happens.
- **How:** The catalog is generated from the program's action definitions and is therefore always current.

### Uninstall knows pywebview
- **What:** The entry "Own Python environment" now also mentions the window component pywebview.
- **Why:** pywebview lives in the same environment and is removed with it.
- **How:** Same deletion path as before.

## 2.0.1 (2026-11-06) - Fixes from real runs, uninstall, hardening

### Update display never falsely reassuring
- **What:** "No updates" now appears only when the search demonstrably worked. Otherwise it says "Result not reliable" with the reasons.
- **Why:** On a real site the program reported "no updates" although five extensions were outdated. The Joomla command line can fail silently.
- **How:** The command-line result is compared with the #__updates table, the timestamps of the update sources and a cross-check. The cross-check queries each update server individually over https from this PC (one after another, with a pause, at most 60 servers) and compares versions.

### PHP selector program on hosts
- **What:** On some servers "php" is only a selector ("Multiple PHP versions found"). The program now looks for a real PHP and names the case.
- **Why:** Before, this produced false critical findings (syntax error, missing modules, wrong settings).
- **How:** Each candidate is tested with "php -v"; only a real version line counts. Without a usable PHP nothing is rated and the reason is explained.

### Syntax errors with explanation
- **What:** The finding shows the line, the PHP message, the affected line (secrets masked), the reason and what a valid line looks like.
- **Why:** "Syntax error" alone does not help to fix it.
- **How:** Evaluation of the php -l output; only a real PHP parse error counts as critical.

### PHP modules explained
- **What:** For zip, json, mbstring, xml, openssl etc. it says what they are needed for. "Missing" is reported only if the PHP of the website was measured reliably.
- **Why:** The command-line PHP can have other modules than the web server.
- **How:** The command-line and website versions are compared; on a mismatch only a note is shown. The certificate (e.g. Let's Encrypt) is independent of PHP's OpenSSL; this is now stated.

### Threat situation only for what is installed
- **What:** Reports appear only for extensions present on the server. The general list of newest reports is gone.
- **Why:** Reports about unrelated products caused false alarms and worry.
- **How:** Matching by vendor/product from the report; generic words such as "joomla" or "system" never count as a match.

### SQL install scripts only when suspicious
- **What:** SQL files of known extensions are no longer listed. A warning appears only if a script contains something out of place, with the exact reason.
- **Why:** Normal install scripts are harmless and caused confusion.
- **How:** Content check for user/privilege changes, PHP code, file access, database accounts and central settings.

### Ratings as stars
- **What:** JED ratings are shown as a row of stars, in the interface and in the report.
- **Why:** Plain text was hard to read.
- **How:** The share of filled stars follows the rating; the number is shown next to it.

### Google Safe Browsing key in the connection form
- **What:** The key can be entered directly in the connection form.
- **Why:** The function was hidden deep in the check options.
- **How:** The field sits below the connection data; the key stays in memory, is never saved and never written to reports. Only the site address goes to Google.

### Uninstall
- **What:** An "Uninstall" button in the program and in the start window. It shows everything the program created on the PC and deletes only what is checked.
- **Why:** There was no clean way to remove its own Python environment, the cache and Python itself.
- **How:** List with size and explanation, confirmation, then a visible script deletes after the program has closed. Connections, reports and the program folder are never preselected; Python only if start.bat installed it itself.

### Larger help window, footer, US English
- **What:** The help window is about twice as large. Footer: "vibecoded by conejito-vipe with love". English is now US English with a US flag.
- **Why:** The help text is hard to read in the small window; US English and the flag match the selected language variant.
- **How:** Window size in app.css, texts in claudia/lang/en.json.

### Hardening after the code security review
- **What:** Several attack surfaces closed.
- **Why:** The checked server may itself be compromised and deliver crafted data.
- **How:** Malicious-spot search without nested patterns (no runaway on crafted files); database name, prefix, user and host from the configuration are strictly validated (no options, no SQL); fallback to outdated SSH methods only after explicit confirmation; Windows device names (nul, con, com1) defused in saved logs; settings and cache written atomically; request token checked before the body is read, size and time limits, additional CSP rules; unused code removed.

## 2.0.0 (2026-11-05) - CLAUDIA: new name, WordPress, English, many new checks

### New name, logo and claim
- **What:** The program is now called CLAUDIA, with its own technical logo.
- **Why:** The program no longer checks only Joomla and needs its own memorable name.
- **How:** Package claudia, start file start.bat, logo in the interface and report.

### WordPress area
- **What:** Own detection plus checks and actions for WordPress, laid out like the Joomla area.
- **Why:** Many sites run WordPress and have other entry points (plugins, mu-plugins, application passwords).
- **How:** When WordPress is detected the WordPress area appears automatically; core checksums come from api.wordpress.org.

### English with flags
- **What:** Interface, reports and documentation exist in German and English; switch with the flags at the top right.
- **Why:** More people should be able to use the program; further languages should be easy to add.
- **How:** Language files in claudia/lang (differing text only), tool tools/i18n.py to create, check and synchronise them.

### Technical icons
- **What:** Instead of colorful emoticons the interface and reports show simple technical icons.
- **Why:** A calm, uniform look that also prints well.
- **How:** Icon set in claudia/icons.json, as SVG in the HTML report.

### Encrypted connections only
- **What:** SSH/SFTP and https; the kind of encryption is shown in the connection display.
- **Why:** Credentials and reports must never travel unencrypted.
- **How:** Weak methods are reported; there is no unencrypted path.

### Joomla core against original checksums, reinstall core
- **What:** Changed, additional and missing core files are found; an action reinstalls the core.
- **Why:** Tampered core files are a common backdoor and cannot be seen by eye.
- **How:** Comparison with the official package of the installed version; only core files are replaced, after a backup and with confirmation.

### PHP settings, configuration file, Safe Browsing
- **What:** Check of dangerous PHP settings, of the configuration file's integrity and (with your own key) of the Google Safe Browsing lists.
- **Why:** Insecure settings and injected lines in the configuration are typical consequences of a hack.
- **How:** PHP values read via the command line (the website may differ); the API key is masked and never stored.

### Threat situation, malware patterns, hidden structures, .htaccess
- **What:** Before every run current entries (Joomla Vulnerable Extensions List, NVD/CVE) are read; new patterns for known backdoors, hidden files and suspicious .htaccess rules.
- **Why:** Attacks change constantly; hidden files and manipulated .htaccess files are common hiding places.
- **How:** Built-in lists with a date plus an online query; without internet the built-in state stays active.

### Security extension and recommendations
- **What:** Check whether a firewall or security extension is installed; otherwise recommendations with ratings from the Joomla Extensions Directory.
- **Why:** Checking alone does not protect; a running protection layer is often missing.
- **How:** Ratings with date and rounding note (security_tools.json).

### Update readiness and cleaning up old backups
- **What:** Check whether Joomla/WordPress can be updated automatically; old backups and old action logs can be deleted (the newest of each stays).
- **Why:** Failed updates usually have permission, space or module reasons; backups otherwise fill the web space.
- **How:** "Updates" card and action "Delete old backups" (selected items only).

## 1.5.1 - Updates on top, retries, green original line

### Update card and retries
- **What:** Own "Updates" card at the top of the result; failed extension updates are retried up to 3 times.
- **Why:** Some extensions need another one first; updates are the most important step after an incident.
- **How:** Every attempt appears in the status window; extensions without a command-line installer (e.g. OSMap) show the download address and the backend route.

### Original line in green, JCE via the database, images/tmp
- **What:** For Joomla core files the original line is shown in green below the red malicious line; harmful JCE profiles can be deleted right at the finding; images/tmp is only named if it exists.
- **Why:** Less guesswork when cleaning up; no messages about folders that do not exist.
- **How:** The original is fetched from GitHub by your PC; JCE deletion with preview and backup.

### Freeware footer
- **What:** New text: freeware, without warranty, changes at your own risk.
- **Why:** A clear statement about liability and use.
- **How:** Footer of the interface and LIZENZ.txt.

## 1.5 - Clusters, database area, order of fixes

### Checks in clusters
- **What:** Related checks stand in a bracket with a description of the approach.
- **Why:** An overview of what an approach covers.
- **How:** "Select/deselect cluster" toggles all of them.

### "Database" area (optional)
- **What:** Own connection, rights check, search for injected code in all text columns, structural anomalies, current incidents.
- **Why:** Many attacks live in the database, not in files.
- **How:** Read-only SELECT queries; the password stays in memory.

### Fixes in recommended order
- **What:** Numbered steps with "Why now?", temp folders, old backups, JCE without backup as a deliberate exception, malicious-code excerpts.
- **Why:** The order decides whether new backdoors are created.
- **How:** Only the steps needed for the site appear.

### One start file, PHP detection
- **What:** Only start.bat; the PHP version is detected instead of entered.
- **Why:** Fewer operating errors.
- **How:** Detection from web response, .htaccess and processes.

## 1.4 - Start screen, extension updates, status window

### Start screen with progress
- **What:** Instead of a black window, a start window shows every step with a percentage.
- **Why:** You can see that something is happening.
- **How:** The percentage is an estimate based on fixed weights.

### Extension updates and status window
- **What:** Free extension updates to click, with a backup before and a version check after; a status window shows every command and the answer.
- **Why:** Outdated extensions are the most common entry point.
- **How:** Joomla command extension:install with the download address from the update directory; only tested against test environments.

### Temp folders, JCE profiles, malicious-code files
- **What:** Actions to empty tmp, delete harmful JCE profiles and remove reported web shell files.
- **Why:** These are the most common leftovers after a hack.
- **How:** Always after a backup and confirmation; code in normal files remains manual work.

## 1.3 - Back up logs

### Back up logs to your PC
- **What:** Access and error logs are copied to your PC.
- **Why:** Many providers delete old logs; afterwards a break-in can no longer be traced.
- **How:** First search, then confirm, then back up; size and SHA-256 are verified; repeating copies only what is new.

## 1.2 - Hand over to Claude, online lists, first fixes

### Hand over to Claude and online comparison
- **What:** A button prepares the reports; the current list of vulnerable extensions is compared online.
- **Why:** Evaluation and comparison should be easier.
- **How:** The program uploads nothing and does not know your Claude account.

### One-click fixes
- **What:** Fixed actions: write permissions, clear cache, update Joomla.
- **Why:** Recurring manual steps should be safe and traceable.
- **How:** Preview, confirmation, backup, abort without a valid backup.

## 1.1 - Fewer false alarms

### False alarms reduced
- **What:** Images, cache files, empty index.php, usual file names, protective rules and update waves no longer raise alarms; attack attempts count as critical only on a 2xx response.
- **Why:** The first real run showed too many harmless hits.
- **How:** Finer rules and exceptions; repelled attempts appear as a notice.

### Connection test with countdown
- **What:** Time limit per step, Cancel button.
- **Why:** Hanging connections must not block.
- **How:** Countdown up to 45 seconds.

## 1.0 - First version

### Checks, interface, report
- **What:** SSH connection, check catalog for Joomla (web shells, files, permissions, extensions, logs, database), browser interface, report and ZIP export, start file for Windows.
- **Why:** After a hack, traces should be found quickly and without changing the server.
- **How:** All checks read-only; result with colors and recommendation.

