"""CLAUDIA - lesende Sicherheitsprüfung für Joomla- und WordPress-Seiten per SSH."""
__version__ = "2.13.0"
APP_NAME = "CLAUDIA"
APP_TAGLINE = "CMS security, step by step"

import os as _os
SECURITY_TOOLS_FILE = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "security_tools.json")
BACKUP_TOOLS_FILE = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "backup_tools.json")
KNOWN_TOOLS_FILE = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "known_tools.json")
