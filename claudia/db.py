"""Datenbankzugriff - nur lesend - über das 'mysql'-Programm auf dem Server.

Die Zugangsdaten stehen in der configuration.php der Seite und werden dort gelesen. Das Passwort
wird über die Standardeingabe (stdin) an den Befehl übergeben, damit es nie in der Prozessliste
des Servers auftaucht. Es werden ausschließlich SELECT-Abfragen ausgeführt.
"""
from __future__ import annotations

import re
from typing import Dict, List, Optional

from .joomla import split_db_host
from .util import digits, mysql_unescape, sq


class DbError(Exception):
    pass


class DbTableMissing(DbError):
    pass


def _clean_error(text: str, password: str) -> str:
    text = (text or "").strip()
    if password:
        text = text.replace(password, "***")
    return text[:600]


_NAME_RE = re.compile(r"^[A-Za-z0-9_$][A-Za-z0-9_$.-]{0,63}\Z")
_PREFIX_RE = re.compile(r"^[A-Za-z0-9_]{1,40}\Z")
_USER_RE = re.compile(r"^[A-Za-z0-9_$@][A-Za-z0-9_$@.+-]{0,79}\Z")
_HOST_RE = re.compile(r"^[A-Za-z0-9_\[][A-Za-z0-9_.:\[\]-]{0,254}\Z")
_SOCK_RE = re.compile(r"^/[A-Za-z0-9_./+-]{1,250}\Z")


def validate_vars(name: str, prefix: str, user: str, host: str, sock: str) -> str:
    """Die Angaben stammen aus der configuration.php des geprüften Servers und gelten als nicht vertrauenswürdig: Sie landen in einer Befehlszeile und in SQL.
    Nur gewöhnliche Zeichen sind erlaubt; vor allem darf nichts mit '-' beginnen (würde als Programmoption gelesen) und nichts Anführungszeichen oder Semikolons enthalten.
    Rückgabe: Fehlertext oder ''."""
    for label, val, rx in (("Datenbankname", name, _NAME_RE), ("Tabellenpräfix", prefix, _PREFIX_RE), ("Datenbank-Benutzer", user, _USER_RE)):
        if val and not rx.match(val):
            return "%s enthält ungewöhnliche Zeichen und wird aus Sicherheitsgründen nicht benutzt (in der Konfigurationsdatei prüfen)." % label
    if sock:
        if not _SOCK_RE.match(sock):
            return "Der Socket-Pfad der Datenbank enthält ungewöhnliche Zeichen und wird nicht benutzt."
    elif host and not _HOST_RE.match(host):
        return "Der Datenbank-Host enthält ungewöhnliche Zeichen und wird nicht benutzt."
    return ""


def check_identifiers(db: "DbAccess") -> str:
    return validate_vars(db.name, db.prefix, db.user, db.host, db.sock)


class DbAccess:
    def __init__(self, ctx, host: str, port: int, sock: str, user: str, password: str, name: str, prefix: str):
        self.ctx = ctx
        self.host, self.port, self.sock = host, port, sock
        self.user, self.password, self.name, self.prefix = user, password, name, prefix
        self.binary = "mysql"
        self.ok = False
        self.error = ""
        self.custom = False

    # -------------------------------------------------------------- Aufbau
    @classmethod
    def from_ctx(cls, ctx) -> "DbAccess":
        cfg = ctx.config()
        v = dict(cfg.get("vars", {}))
        own = dict(getattr(getattr(ctx, "s", None), "db", None) or {})
        custom = bool(own)
        # Eigene Angaben aus dem Bereich 'Datenbank' ersetzen nur die Felder, die ausgefüllt wurden.
        for src, dst in (("host", "host"), ("user", "user"), ("password", "password"), ("name", "db"), ("prefix", "dbprefix")):
            if str(own.get(src) or "").strip():
                v[dst] = str(own[src]).strip() if src != "password" else str(own[src])
        if digits(str(own.get("port") or "").strip()) and str(v.get("host", "")).find(":") < 0:
            v["host"] = "%s:%s" % (v.get("host") or "localhost", own["port"].strip())
        host, port, sock = split_db_host(str(v.get("host", "localhost")))
        db = cls(ctx, host, port, sock, str(v.get("user", "")), str(v.get("password", "")),
                 str(v.get("db", "")), str(v.get("dbprefix", "jos_")))
        db.custom = custom
        bad = check_identifiers(db)
        if bad:
            db.error = bad
            return db
        if cfg.get("missing") and not (custom and db.user and db.name):
            db.error = "Die %s wurde nicht gefunden - Zugangsdaten unbekannt." % ctx.prof["config_file"].rsplit("/", 1)[-1]
            return db
        if not (db.user and db.name):
            db.error = "In der %s fehlen Datenbank-Benutzer oder -Name." % ctx.prof["config_file"].rsplit("/", 1)[-1]
            return db
        dbtype = str(v.get("dbtype", "mysqli")).lower()
        if "mysql" not in dbtype:
            db.error = "Datenbanktyp '%s' wird nicht unterstützt (nur MySQL/MariaDB)." % dbtype
            return db
        res = ctx.sh("command -v mysql || command -v mariadb", timeout=20)
        path = res.out.strip().splitlines()[0] if res.out.strip() else ""
        if not path:
            db.error = "Auf dem Server gibt es kein 'mysql'-Programm in der Shell."
            return db
        db.binary = "mariadb" if path.endswith("mariadb") else "mysql"
        try:
            rows = db.query("SELECT 1 AS ok")
            db.ok = bool(rows)
            if not db.ok:
                db.error = "Testabfrage ohne Ergebnis."
        except DbError as e:
            db.error = str(e)
        return db

    # -------------------------------------------------------------- Abfragen
    def sql(self, text: str) -> str:
        return text.replace("#__", self.prefix)

    def _command(self, sql: str) -> str:
        opts = ["--batch", "--default-character-set=utf8mb4", "--connect-timeout=15"]
        if self.sock:
            opts += ["-S", self.sock]
        else:
            opts += ["-h", self.host or "localhost"]
            if self.port:
                opts += ["-P", str(self.port)]
        opts += ["-u", self.user]
        # Passwort kommt über stdin (erste Zeile) -> MYSQL_PWD, nie in der Befehlszeile
        return "IFS= read -r MYSQL_PWD; export MYSQL_PWD; %s %s %s -e %s" % (
            self.binary, " ".join(sq(o) for o in opts), sq(self.name), sq(sql))

    def query(self, sql: str, timeout: float = 90.0) -> List[Dict[str, Optional[str]]]:
        sql = self.sql(sql)
        res = self.ctx.sh(self._command(sql), timeout=timeout, stdin=self.password + "\n")
        if res.timed_out:
            raise DbError("Zeitüberschreitung bei der Abfrage.")
        if res.rc != 0:
            err = _clean_error(res.err or res.out, self.password)
            if re.search(r"ERROR 1146|doesn't exist|ERROR 1109", err):
                raise DbTableMissing(err)
            if "1045" in err:
                raise DbError("Zugriff verweigert (" + ("die eingegebenen Zugangsdaten stimmen nicht" if self.custom else "Passwort/Benutzer aus configuration.php stimmen nicht") + "): " + err)
            if re.search(r"2002|2003|2005|Can't connect|Unknown MySQL server host", err):
                raise DbError("Keine Verbindung zur Datenbank vom Server aus: " + err)
            raise DbError(err or ("mysql beendete sich mit Code %d" % res.rc))
        return self.parse(res.out)

    @staticmethod
    def parse(text: str) -> List[Dict[str, Optional[str]]]:
        lines = text.split("\n")
        while lines and lines[-1] == "":
            lines.pop()
        if not lines:
            return []
        header = lines[0].split("\t")
        rows = []
        for ln in lines[1:]:
            cells = ln.split("\t")
            if len(cells) < len(header):
                cells += [""] * (len(header) - len(cells))
            rows.append({h: mysql_unescape(c) for h, c in zip(header, cells)})
        return rows
