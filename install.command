#!/bin/bash
# CLAUDIA auf dem Mac installieren: nur für den aktuellen Benutzer, ohne Administratorrechte.
# Ziel: ~/Applications/CLAUDIA. Persönliche Daten (~/Library/Application Support/CLAUDIA) bleiben bei Updates erhalten.
cd "$(dirname "$0")" || exit 1
SRC="$(pwd)"
DEST="$HOME/Applications/CLAUDIA"
newv=$(sed -n 's/^__version__ = "\(.*\)"/\1/p' claudia/__init__.py)
if [ -f "$DEST/claudia/__init__.py" ]; then
    oldv=$(sed -n 's/^__version__ = "\(.*\)"/\1/p' "$DEST/claudia/__init__.py")
    echo "CLAUDIA $oldv ist bereits installiert. Neue Version: $newv."
    read -r -p "Aktualisieren? Verbindungen, Einstellungen und Berichte bleiben erhalten. (j/N) " a
    case "$a" in j|J|y|Y) ;; *) echo "Abgebrochen."; exit 0;; esac
    rm -rf "$DEST/claudia" "$DEST/tests" "$DEST/tools"   # .venv bleibt
else
    echo "CLAUDIA $newv wird nach $DEST installiert (ohne Administratorrechte)."
    read -r -p "Fortfahren? (j/N) " a
    case "$a" in j|J|y|Y) ;; *) echo "Abgebrochen."; exit 0;; esac
fi
mkdir -p "$DEST" || exit 1
cp -R "$SRC"/. "$DEST"/ || exit 1
chmod +x "$DEST/start.command" "$DEST/install.command" 2>/dev/null
mkdir -p "$HOME/Applications"
ln -sf "$DEST/start.command" "$HOME/Desktop/CLAUDIA.command" 2>/dev/null
echo "Fertig. Start: $DEST/start.command (Verknüpfung auf dem Schreibtisch: CLAUDIA.command)."
read -r -p "Jetzt starten? (j/N) " a
case "$a" in j|J|y|Y) exec "$DEST/start.command";; esac
