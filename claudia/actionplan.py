"""Maßnahmenplan: ordnet Prüfergebnisse und verfügbare Aktionen nach Dringlichkeit.

Reine Funktion ohne Dateizugriff, Netz, Uhrzeit oder Zufall. Der Plan ist eine EMPFEHLUNG
von CLAUDIA und sagt nichts darüber aus, ob eine Seite sauber oder sicher ist.
"""
from typing import Any, List, Optional

PHASE_ORDER = ["vorbereitung", "einbruch", "zugaenge", "luecken", "haertung", "umfeld", "weitere"]

PHASE_TITLE = {
    "vorbereitung": "Vorbereitung: Sicherung",
    "einbruch": "Einbruchstelle und Schadcode",
    "zugaenge": "Zugänge und Konten",
    "luecken": "Lücken und Updates",
    "haertung": "Härtung",
    "umfeld": "Sicherung und Umfeld",
    "weitere": "Weitere Hinweise",
}

PHASE_WHY = {
    "vorbereitung": "Vor jeder Änderung wird eine vollständige Sicherung angelegt, damit der jetzige Stand als Ausgangspunkt erhalten bleibt.",
    "einbruch": "Schadcode und Einbruchstellen werden zuerst entfernt, damit erneuerte Passwörter und Schlüssel nicht über noch vorhandenen Schadcode erneut abgegriffen werden.",
    "zugaenge": "Konten und Zugänge werden erst nach der Bereinigung erneuert, weil sie sonst durch verbliebenen Schadcode wieder gefährdet sein könnten.",
    "luecken": "Bekannte Schwachstellen und veraltete Software sind häufige Einstiegswege und werden nach der Bereinigung geschlossen.",
    "haertung": "Zusätzliche Schutzmaßnahmen erschweren künftige Angriffe, ersetzen aber keine Bereinigung.",
    "umfeld": "Sicherungen und Umfeld werden zuletzt geordnet, damit zuvor angelegte Sicherungen nicht zu früh gelöscht werden.",
    "weitere": "Diese Punkte lassen sich keiner der übrigen Phasen zuordnen und sollten nach eigenem Ermessen geprüft werden.",
}

CLUSTER_TO_PHASE = {
    "php_shells": "einbruch", "js_inject": "einbruch", "versteck": "einbruch", "einstieg": "einbruch",
    "joomla_code": "einbruch", "dbx_inject": "einbruch", "dbx_auffaellig": "einbruch", "logs_spuren": "einbruch",
    "konto": "zugaenge", "shop_woo": "zugaenge", "joomla_konten": "zugaenge", "joomla_zugang": "zugaenge",
    "ext_pruefen": "luecken", "update": "luecken", "dbx_lage": "luecken",
    "zugriffsregeln": "haertung", "joomla_einst": "haertung", "besucher": "haertung", "rechte": "haertung",
    "dbx_aufbau": "haertung", "ext_schutz": "haertung",
    "ext_sicherung": "umfeld", "umfeld": "umfeld",
}

_ACTIONS_BY_PHASE = {
    "vorbereitung": ["backup_now"],
    "einbruch": ["remove_shells", "block_php_uploads", "reset_htaccess", "remove_db_code", "clean_tmp",
                 "joomla_core_reinstall", "wp_core_reinstall", "remove_jce_profiles", "restore_quarantine",
                 "delete_quarantine"],
    "zugaenge": ["block_users", "revoke_tokens", "disable_api", "end_sessions", "wp_salts", "wp_fix_registration"],
    "luecken": ["fix_update_perms", "wp_remove_maintenance", "core_update", "wp_update", "update_extensions", "enable_autoupdate_api",
                "deactivate_extension", "wp_deactivate_plugin"],
    "haertung": ["harden_headers", "harden_listing", "wp_block_xmlrpc", "harden_hsts", "harden_perms",
                 "fix_permissions", "wp_disallow_edit", "install_security"],
    "umfeld": ["install_backup", "delete_old_backups", "clear_cache"],
}
ACTION_TO_PHASE = {aid: pid for pid, ids in _ACTIONS_BY_PHASE.items() for aid in ids}

# Kopie von STEP_ORDER aus CLAUDIA
ACTION_ORDER = ["backup_now", "fix_update_perms", "wp_remove_maintenance", "deactivate_extension", "wp_deactivate_plugin", "core_update", "wp_update", "update_extensions", "enable_autoupdate_api", "joomla_core_reinstall", "wp_core_reinstall", "remove_jce_profiles", "wp_fix_registration", "remove_db_code", "remove_shells", "block_php_uploads", "reset_htaccess", "clean_tmp", "block_users", "revoke_tokens", "disable_api", "end_sessions", "wp_salts", "wp_disallow_edit", "install_security", "install_backup", "harden_headers", "harden_listing", "wp_block_xmlrpc", "harden_hsts", "harden_perms", "fix_permissions", "clear_cache", "delete_old_backups"]

NEVER_IN_PLAN = ("check_updates",)

NOTE_NONE = ("Es liegen keine kritischen Befunde oder Warnungen vor. Das ist kein Beweis dafür, "
             "dass die Seite sauber oder sicher ist.")
NOTE_ORDER = ("Passwörter und Schlüssel erst nach der Bereinigung erneuern, nicht davor (siehe Reihenfolge der Phasen). "
              "Dieser Plan ist eine Empfehlung von CLAUDIA und ersetzt keine eigene Prüfung.")
NOTE_IRREVERSIBLE = ("Mindestens eine Aktion lässt sich nicht vollständig rückgängig machen "
                     "und verlangt eine eigene Bestätigung.")
NOTE_RISK_HIGH = "Für Aktionen mit hohem Risiko vorher eine Sicherung anlegen."


def _list(value: Any) -> list:
    return value if isinstance(value, (list, tuple)) else []


def _text(value: Any) -> str:
    if value is None:
        return ""
    return value if isinstance(value, str) else str(value)


def _phase_of_check(check_id: str, cluster_map: Any) -> str:
    cluster = cluster_map.get(check_id) if isinstance(cluster_map, dict) else None
    if not isinstance(cluster, str):
        return "weitere"
    return CLUSTER_TO_PHASE.get(cluster, "weitere")


def _action_sort_key(action: dict) -> tuple:
    aid = action["id"]
    pos = ACTION_ORDER.index(aid) if aid in ACTION_ORDER else len(ACTION_ORDER)
    return (action.get("irreversible") is True, pos)


def build_plan(results: list, available: list, cms: str = "joomla", cluster_map: Optional[dict] = None) -> dict:
    """Ordnet Befunde (crit/warn) und verfügbare Aktionen zu einem Maßnahmenplan nach Phasen.

    `cms` ist derzeit ohne Wirkung; die Zuordnung Check -> Cluster kommt flach (`{check_id: cluster}`) über
    `cluster_map`. Eingaben werden nicht verändert.
    """
    findings = {pid: {"crit": [], "warn": []} for pid in PHASE_ORDER}
    for res in _list(results):
        if not isinstance(res, dict) or res.get("status") in ("error", "skipped"):
            continue
        check_id = _text(res.get("id"))
        phase = _phase_of_check(check_id, cluster_map)
        for f in _list(res.get("findings")):
            if not isinstance(f, dict) or f.get("sev") not in ("crit", "warn"):
                continue
            findings[phase][f["sev"]].append({
                "kind": "finding", "check_id": check_id, "severity": f["sev"],
                "title": _text(f.get("title")) or _text(res.get("title")),
            })

    actions = []
    seen = set()
    for a in _list(available):
        aid = a.get("id") if isinstance(a, dict) else None
        if not isinstance(aid, str) or not aid or aid in seen:
            continue
        seen.add(aid)
        if aid in NEVER_IN_PLAN or a.get("risk") == "keine":
            continue
        actions.append(a)

    others = [a for a in actions if a["id"] != "backup_now"]
    by_phase = {pid: [] for pid in PHASE_ORDER}
    for a in actions:
        if a["id"] == "backup_now" and not others:
            continue
        by_phase[ACTION_TO_PHASE.get(a["id"], "weitere")].append(a)

    phases = []
    summary = {"crit": 0, "warn": 0, "actions": 0}
    action_steps = []
    for pid in PHASE_ORDER:
        steps = list(findings[pid]["crit"]) + list(findings[pid]["warn"])
        summary["crit"] += len(findings[pid]["crit"])
        summary["warn"] += len(findings[pid]["warn"])
        for a in sorted(by_phase[pid], key=_action_sort_key):
            step = {
                "kind": "action", "action_id": a["id"], "title": _text(a.get("title")) or a["id"],
                "risk": _text(a.get("risk")), "irreversible": a.get("irreversible") is True,
            }
            steps.append(step)
            action_steps.append(step)
        if steps:
            phases.append({"id": pid, "title": PHASE_TITLE[pid], "why": PHASE_WHY[pid], "steps": steps})
    summary["actions"] = len(action_steps)

    notes: List[str] = []

    def add(note: str) -> None:
        if note not in notes:
            notes.append(note)

    if not phases:
        add(NOTE_NONE)
    if findings["einbruch"]["crit"]:
        add(NOTE_ORDER)
    if any(s["irreversible"] for s in action_steps):
        add(NOTE_IRREVERSIBLE)
    if any(s["risk"] == "hoch" for s in action_steps):
        add(NOTE_RISK_HIGH)

    return {"phases": phases, "summary": summary, "notes": notes}
