# CLAUDIA

<p align="center"><img src="claudia/assets/claudia_logo.png" width="180" alt="CLAUDIA"></p>

CLAUDIA is a free Windows tool (Python, standard library + paramiko) that checks a **Joomla**, **WordPress** (including WooCommerce shops), **Drupal** (8 and newer), **TYPO3** (11 and newer), **Contao** (4.13 and newer), **PrestaShop** (1.7 and newer) or **Shopware** (6.5 and newer) site over an encrypted SSH connection for traces of a hack and for typical vulnerabilities.
It runs a local web interface on `127.0.0.1` in your browser. German and English (switch with the flags), documentation built in.

> Deutsche Fassung: [README.de.md](README.de.md)

## Principles

- **All checks are read-only.** Nothing on the server is changed, deleted or installed by a check.
- **Changes only via "One-click fixes"**: fixed actions with a command preview, explicit confirmation and a verified backup first.
- **Encrypted connections only** (SSH/SFTP, https for online lookups).
- **No secrets stored or exported.** Passwords and API keys stay in memory; reports are scanned for known secrets.
- **Honest limits.** CLAUDIA searches for known traces. "No findings" does not prove a site is clean.

## What it checks (selection)

Web shells and backdoors, malware patterns, hidden files and `.htaccess` tricks, Joomla core against the official checksums (and reinstall), WordPress core checksums, Drupal core against the original package, WooCommerce (API keys, webhooks, payment methods), extensions/plugins against known vulnerabilities (VEL, NVD/CVE, online lists), configuration and PHP settings, database content (optional), logs, publicly reachable files, security-extension presence (with JED ratings), Google Safe Browsing (your own API key), update readiness. Full list: *Help* in the program or `CLAUDIA_Dokumentation.html`.

## Quick start (Windows)

1. Unpack the ZIP to a normal folder.
2. Double-click `start.bat` (the only start file; sets itself up on first start).
3. Enter the SSH access data of your hosting provider, choose the checks, start.

Requirements: Windows 10/11, Python 3.9+ (start.bat downloads and installs it automatically if missing: official installer from python.org, signature checked, current user only, no restart needed), SSH access to your web space.

## Quick start (Mac, since 2.9.0, not yet tested on a real Mac)

1. Unpack the ZIP in Finder. 2. Double-click `start.command` (first time: right-click > Open). If Python 3.9+ is missing, it downloads the official installer from python.org, checks the signature and installs it (macOS asks for your password). 3. Enter the SSH access data and start.

**Installer (since 2.14.0):** On Windows you can run `CLAUDIA-Setup-….exe` instead of the ZIP (current user only, no administrator rights, Start menu entry, optional desktop shortcut, listed under "Installed apps"). On the Mac, unpack the ZIP and run `install.command` (target `~/Applications/CLAUDIA`). If CLAUDIA is already installed, the installer asks whether to update; your connections, settings and reports are kept. The installer is not Microsoft-certified either, so the same SmartScreen explanation applies.

Run from source on any OS:

```
pip install -r requirements.txt
python -m claudia            # --lang en|de, --selftest
```

## Windows or antivirus warning (expected)

Windows (SmartScreen, Defender) or another virus scanner may warn about CLAUDIA or `start.bat`, or flag it as malware or a possible entry point. **That is understandable and, in one respect, correct:** CLAUDIA can open SSH connections to a server, and that is exactly how it works. It does so **only when you want it**: you enter the access data yourself, you start a check, and the connection goes only to the server you entered. There is no background connection and nothing starts on its own.

Further reasons for warnings: the program is not code-signed (unknown publisher), and `start.bat` can download and install Python if it is missing.

What you can do:
- Download only from this repository and compare the files with `PRUEFSUMMEN.txt`.
- The source code is open; read it or have it reviewed before you run it.
- If you decide to trust it: in SmartScreen choose "More info" and then "Run anyway", or allow only the CLAUDIA folder in your virus scanner. Do not switch protection off in general.

## Development

```
cd tests
PYTHONPATH=fake_paramiko:.. python -m unittest discover -s . -p "test_*.py"
python tools/i18n.py check en        # translation coverage
python tools/build_docs.py           # standalone documentation
python tools/build_release.py        # CHANGELOG.md, checksums, release ZIP
```

UI tests use Playwright (`pip install playwright && playwright install chromium`); they are skipped when it is missing.
More languages: `python tools/i18n.py neu fr "Français"` (see *Languages* in the manual). See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

## License & Usage

CLAUDIA is made publicly available for testing and ongoing development. See the [LICENSE](LICENSE) file for the full terms; the German version is binding.

- **Free use:** individuals (non-commercial) and non-profit organizations and associations (for non-profit purposes), each on their own sites.
- **No commercial use without permission:** companies, self-employed people, agencies and public authorities must contact me in advance via my GitHub profile ([@conejito-vipe](https://github.com/conejito-vipe)) to request permission or a license. This includes checking customers' sites.
- **No modification, no redistribution:** the software must not be modified or passed on to third parties, not even unchanged. The source code is there to be read and inspected.
- **Exclusions:** political parties, as well as associations or groups that are classified as a right-wing extremist effort by the Office for the Protection of the Constitution (federal or state) or that are banned, are excluded from using this software (details in the [LICENSE](LICENSE)).

Without any warranty or guarantee of success. Changes to servers are at your own risk. vibecoded with Claude (Anthropic) by conejito-vipe with love ❤️.
