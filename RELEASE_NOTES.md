# CLAUDIA 2.14.0 - Installer

- **Installer for Windows and Mac (no administrator rights)**: Windows now has an installer (CLAUDIA-Setup-<version>.exe) that installs CLAUDIA into your user folder (%LOCALAPPDATA%\\Programs\\CLAUDIA), with a Start menu entry, an optional desktop shortcut and an entry under "Installed apps". On the Mac there is install.command (target ~/Applications/CLAUDIA). Both detect an existing installation and ask whether to update (lower version), reinstall or downgrade.
- **Intern**: New file installer/claudia.iss (Inno Setup), workflow .github/workflows/build-windows.yml (manual only), install.command, uninstall.installed_by_setup().
