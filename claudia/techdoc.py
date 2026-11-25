"""Technik-Kapitel der Dokumentation: zeigt, was das Programm im Hintergrund tut - mit dem echten Quelltext.

Nichts davon ist von Hand kopiert: Die Skripte, SQL-Abfragen und Funktionen werden beim Aufruf per AST aus den Quelldateien gelesen
(ast.get_source_segment). So kann die Dokumentation nicht vom Programm abweichen. Neue Prüfungen und Aktionen erscheinen automatisch;
die kurzen Erklärungen je Aktion stehen in docs/technik.<sprache>.txt (Pflicht bei jeder neuen Aktion, ein Test prüft das).

Es wird ausschließlich Programmcode gezeigt. Zugangsdaten, Schlüssel und Tokens kommen darin nicht vor (ein Test prüft das ebenfalls).
Kommentare im Code bleiben deutsch (nicht übersetzt)."""
from __future__ import annotations

import ast
import re
import sys
import textwrap
from typing import Any, Dict, List, Optional, Set, Tuple

from . import helpdocs

MAX_BLOCK = 14000          # Zeichen je Codeblock; längere werden am Ende gekürzt (mit Hinweis)
MAX_ENTRY = 60000          # Zeichen je Eintrag insgesamt
FUNC_DEPTH = 2             # Hilfsfunktionen aus demselben Modul werden bis zu dieser Tiefe mitgezeigt

# Allgemeine Bausteine, die jeder Eintrag benutzt: sie stehen einmal im Kapitel 'Grundlagen' und nicht bei jedem Test.
# (Modul, Name) - 'Klasse.Methode' für Methoden.
BASICS: List[Tuple[str, str, List[Tuple[str, str]]]] = [
    ("ablauf", "claudia.runner", [("claudia.runner", "wrap_script"), ("claudia.runner", "Runner.sh"), ("claudia.runner", "SSHRunner.run"),
                                  ("claudia.engine", "Ctx.sh"), ("claudia.util", "sq")]),
    ("datenbank", "claudia.db", [("claudia.db", "DbAccess._command"), ("claudia.db", "DbAccess.query"), ("claudia.db", "DbAccess.parse"),
                                 ("claudia.actions", "_mysql_script"), ("claudia.actions", "_check_vars"), ("claudia.actions", "_read_cfg_site"), ("claudia.actions", "_read_cfg")]),
    ("sicherung", "claudia.actions", [("claudia.actions", "_home_dir"), ("claudia.actions", "_mkdir_backup"), ("claudia.actions", "_db_dump_script"), ("claudia.actions", "make_backup")]),
    ("protokoll", "claudia.actions", [("claudia.actions", "Traced")]),
    ("programmupdate", "claudia.appupdate", [("claudia.appupdate", "parse_release"), ("claudia.appupdate", "check"), ("claudia.appupdate", "verify_package"),
                                            ("claudia.appupdate", "backup"), ("claudia.appupdate", "restore"), ("claudia.appupdate", "install"), ("claudia.appupdate", "finish_code")]),
    ("haertung", "claudia.util", [("claudia.util", "sq"), ("claudia.util", "parse_xml"), ("claudia.util", "digits"), ("claudia.util", "mask_secrets"), ("claudia.db", "validate_vars")]),
    ("dashboard", "claudia.verlauf", [("claudia.verlauf", "run_entry"), ("claudia.verlauf", "record_run"), ("claudia.verlauf", "compare"), ("claudia.verlauf", "nachkontrolle"), ("claudia.verlauf", "dashboard"), ("claudia.verlauf", "delete_site"),
                                              ("claudia.verlauf", "export_csv"), ("claudia.actions", "verify_backup"), ("claudia.support", "build")]),
    ("signatur", "claudia.signatur", [("claudia.signatur", "verify"), ("claudia.appupdate", "verify_signature"), ("claudia.wissen", "check"), ("claudia.wissen", "load"), ("claudia.wissen", "update")]),
]

# Welche Funktionen eine Aktion ausführt (Name im Modul claudia.actions). Aktionen ohne Eintrag laufen direkt in run_action
# und werden über den Zweig 'aid == ...' gefunden.
ACTION_FUNCS: Dict[str, List[str]] = {
    "wp_salts": ["_run_wp_config_edit", "edit_wp_config", "_wp_config_text"],
    "wp_disallow_edit": ["_run_wp_config_edit", "edit_wp_config", "_wp_config_text"],
    "wp_fix_registration": ["_run_wp_registration"],
    "wp_update": ["_run_wp_cli"],
    "wp_core_reinstall": ["_run_wp_cli"],
    "install_security": ["_security_target", "_run_install_security"],
    "install_backup": ["_security_target", "_run_install_security"],
    "block_users": ["_run_block_users", "_picked_ids", "_dump_for_change", "_sql_rows", "_sql_exec"],
    "revoke_tokens": ["_run_revoke_tokens", "_picked_ids", "_dump_for_change"],
    "end_sessions": ["_run_end_sessions", "_sql_rows", "_sql_exec"],
    "disable_api": ["_run_disable_api", "_dump_for_change", "_sql_rows", "_sql_exec"],
    "enable_autoupdate_api": ["_run_enable_autoupdate_api", "_dump_for_change", "_sql_rows", "_sql_exec"],
    "deactivate_extension": ["_run_deactivate_joomla", "_picked", "_protected_tool_names", "_dump_for_change"],
    "wp_deactivate_plugin": ["_run_deactivate_wp", "_picked", "_protected_tool_names", "_dump_for_change"],
    "clean_tmp": ["_run_clean_tmp"],
    "delete_old_backups": ["_run_delete_backups"],
    "remove_jce_profiles": ["_run_remove_jce"],
    "remove_shells": ["_run_remove_shells", "_picked_shell_files", "_new_quarantine_dir", "_quarantine_header", "_parse_quar_lines", "QUAR_MOVE"],
    "delete_quarantine": ["_run_delete_quarantine", "_picked", "_parse_quar_lines", "QUAR_DEL"],
    "restore_quarantine": ["_run_restore_quarantine", "_picked", "_parse_quar_lines", "QUAR_BACK"],
    "block_php_uploads": ["_run_block_php", "_fetch_url"],
    "harden_perms": ["_run_harden_perms", "_safe_path", "_fetch_url"],
    "harden_headers": ["_run_ht_block", "ht_block_text", "ht_block_verdict", "_fetch_url"],
    "harden_hsts": ["_run_ht_block", "ht_block_text", "ht_block_verdict", "_fetch_url"],
    "harden_listing": ["_run_ht_block", "ht_block_text", "ht_block_verdict", "_fetch_url"],
    "wp_block_xmlrpc": ["_run_ht_block", "ht_block_text", "ht_block_verdict", "_fetch_url"],
    "remove_db_code": ["_run_remove_db_code", "_dbcode_plan", "_dbcode_read", "dbcode_clean", "dbcode_preview", "_el_flagged", "_clean_text", "_clean_json"],
    "reset_htaccess": ["_run_reset_htaccess", "htaccess_preview", "ht_plan", "ht_segments", "ht_classify", "ht_standard", "ht_diff", "_ht_read", "_fetch_url"],
    "update_extensions": ["_selected_updates", "_run_update_extensions"],
    "joomla_core_reinstall": ["_run_joomla_core"],
}

_cache: Dict[str, "Source"] = {}


class Source:
    """Ein Modul als Syntaxbaum mit den Namen der obersten Ebene."""

    def __init__(self, modname: str):
        self.name = modname
        mod = sys.modules.get(modname)
        if mod is None:
            __import__(modname)
            mod = sys.modules[modname]
        self.path = getattr(mod, "__file__", "") or ""
        with open(self.path, encoding="utf-8") as fh:
            self.text = fh.read()
        self.tree = ast.parse(self.text)
        self.funcs: Dict[str, ast.AST] = {}
        self.classes: Dict[str, ast.ClassDef] = {}
        self.consts: Dict[str, ast.AST] = {}
        for n in self.tree.body:
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.funcs[n.name] = n
            elif isinstance(n, ast.ClassDef):
                self.classes[n.name] = n
            elif isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name):
                self.consts[n.targets[0].id] = n
            elif isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Name) and n.value is not None:
                self.consts[n.target.id] = n

    def file(self) -> str:
        parts = self.name.split(".")
        return "/".join(parts) + ".py"

    def node(self, name: str) -> Optional[ast.AST]:
        if "." in name:
            cls, _, meth = name.partition(".")
            c = self.classes.get(cls)
            if c is None:
                return None
            for n in c.body:
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == meth:
                    return n
            return None
        return self.funcs.get(name) or self.classes.get(name) or self.consts.get(name)

    def code(self, node: ast.AST) -> str:
        seg = ast.get_source_segment(self.text, node) or ""
        col = getattr(node, "col_offset", 0)
        if col:
            seg = (" " * col) + seg                # erste Zeile hat keine Einrückung, die folgenden schon
            seg = textwrap.dedent(seg)
        return seg

    def names(self, node: ast.AST) -> Set[str]:
        return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


def source(modname: str) -> Source:
    if modname not in _cache:
        _cache[modname] = Source(modname)
    return _cache[modname]


def _cut(code: str) -> str:
    if len(code) <= MAX_BLOCK:
        return code
    return code[:MAX_BLOCK].rsplit("\n", 1)[0] + "\n# ... (gekürzt, vollständig in der Quelldatei)"


def _block(src: Source, name: str, node: ast.AST, kind: str) -> Dict[str, str]:
    return {"kind": kind, "name": name.split(".")[-1] if kind == "func" else name, "file": src.file(), "line": str(getattr(node, "lineno", 0)), "code": _cut(src.code(node))}


def _shown(name: str, modname: str) -> bool:
    return (modname, name) in _basic_names()


_basics_cache: Optional[Set[Tuple[str, str]]] = None


def _basic_names() -> Set[Tuple[str, str]]:
    global _basics_cache
    if _basics_cache is None:
        _basics_cache = {(m, n) for _i, _t, items in BASICS for m, n in items}
    return _basics_cache


def collect(modname: str, roots: List[str]) -> List[Dict[str, str]]:
    """Programmcode zu den Funktionen 'roots': zuerst die Abfragen und Skripte (Konstanten), dann die Funktionen.
    Hilfsfunktionen desselben Moduls werden bis FUNC_DEPTH mitgenommen, die Bausteine aus BASICS nicht (stehen unter 'Grundlagen')."""
    src = source(modname)
    funcs: List[Tuple[str, ast.AST]] = []
    consts: List[Tuple[str, ast.AST]] = []
    seen_f: Set[str] = set()
    seen_c: Set[str] = set()

    def visit_const(cname: str) -> None:
        if cname in seen_c or cname not in src.consts:
            return
        seen_c.add(cname)
        node = src.consts[cname]
        consts.append((cname, node))
        for n in src.names(node):
            visit_const(n)

    def visit_func(fname: str, depth: int) -> None:
        if fname in seen_f or _shown(fname, modname):
            return
        node = src.node(fname)
        if node is None or fname not in src.funcs:
            return
        seen_f.add(fname)
        funcs.append((fname, node))
        for n in sorted(src.names(node)):
            if n in src.consts:
                visit_const(n)
            elif n in src.funcs and depth < FUNC_DEPTH:
                visit_func(n, depth + 1)

    for r in roots:
        visit_func(r, 0)
    out = [_block(src, n, node, "const") for n, node in consts if not n.startswith("__")]
    out += [_block(src, n, node, "func") for n, node in funcs]
    return out


def _branches(fn: ast.AST, aid: str, src: Source) -> List[Dict[str, str]]:
    """Die Zweige 'if aid == "<aid>"' (oder aid in (...)) in einer langen Funktion wie run_action."""
    out: List[Dict[str, str]] = []
    for n in ast.walk(fn):
        if not isinstance(n, ast.If):
            continue
        t = n.test
        hit = False
        if isinstance(t, ast.Compare) and isinstance(t.left, ast.Name) and t.left.id == "aid":
            for op, comp in zip(t.ops, t.comparators):
                if isinstance(op, ast.Eq) and isinstance(comp, ast.Constant) and comp.value == aid:
                    hit = True
                if isinstance(op, ast.In) and isinstance(comp, (ast.Tuple, ast.List, ast.Set)) and any(isinstance(e, ast.Constant) and e.value == aid for e in comp.elts):
                    hit = True
        if not hit:
            continue
        first, last = n.body[0].lineno, n.body[-1].end_lineno
        lines = src.text.split("\n")[first - 1:last]
        code = textwrap.dedent("\n".join(lines))
        head = ast.get_source_segment(src.text, t) or ""
        out.append({"kind": "branch", "name": "if " + head, "file": src.file(), "line": str(first), "code": _cut(code)})
    return out


def basics(lang: str = "de") -> List[Dict[str, Any]]:
    texts = _texts(lang)
    out = []
    for ident, _mod, items in BASICS:
        blocks = []
        for m, n in items:
            src = source(m)
            node = src.node(n)
            if node is not None:
                blocks.append(_block(src, n, node, "func"))
        t = texts.get("g:" + ident, {})
        out.append({"id": ident, "title": t.get("title", ident), "text": t.get("blocks", []), "code": blocks})
    return out


def _texts(lang: str) -> Dict[str, Dict[str, Any]]:
    """docs/technik.<sprache>.txt: '## g:kennung | Titel' (Grundlagen) und '## a:aktion | Titel' (Aktionen), darunter Absätze und Listen."""
    out: Dict[str, Dict[str, Any]] = {}
    raw = helpdocs._read("technik", lang)
    for part in re.split(r"(?m)^## ", raw)[1:]:
        head, _, body = part.partition("\n")
        ident, _, title = head.partition("|")
        out[ident.strip()] = {"title": title.strip(), "blocks": helpdocs._blocks(body.split("\n"))}
    return out


def check_entries() -> List[Dict[str, Any]]:
    from .registry import load_all, ordered
    load_all()
    seen: Set[str] = set()
    out: List[Dict[str, Any]] = []
    for cms in ("joomla", "wordpress", "drupal", "typo3", "contao", "prestashop", "shopware"):
        for c in ordered(cms):
            if c.id in seen:
                continue
            seen.add(c.id)
            fn = c.fn
            modname = fn.__module__
            src = source(modname)
            blocks = collect(modname, [fn.__name__])
            if not blocks:                                           # Prüfung ohne eigene Funktion auf oberster Ebene (sollte nicht vorkommen)
                import inspect
                blocks = [{"kind": "func", "name": fn.__name__, "file": src.file(), "line": "0", "code": _cut(textwrap.dedent(inspect.getsource(fn)))}]
            total = 0
            kept = []
            for b in blocks:
                total += len(b["code"])
                if total > MAX_ENTRY:
                    break
                kept.append(b)
            d = c.public(cms)
            out.append({"id": c.id, "cms": c.cms, "title": d["title"], "summary": d["summary"], "file": src.file(), "blocks": kept})
    return out


def action_entries(lang: str = "de") -> List[Dict[str, Any]]:
    from . import actions
    texts = _texts(lang)
    src = source("claudia.actions")
    run_action = src.funcs["run_action"]
    out: List[Dict[str, Any]] = []
    for item in actions.catalog():
        aid = item["id"]
        roots = ACTION_FUNCS.get(aid, [])
        blocks: List[Dict[str, str]] = []
        if a_backup(aid):
            blocks.append({"kind": "branch", "name": "if a[\"backup\"]", "file": src.file(), "line": "0",
                           "code": "result[\"backup_dir\"] = make_backup(tr, site_dir, log)    # erst die Sicherung; ohne gültige Sicherung geht es nicht weiter"})
        blocks += _branches(run_action, aid, src)
        if roots:
            blocks += collect("claudia.actions", roots)
        # Bestandteile, die die Aktion über Konstanten des Moduls erreicht (z. B. SCAN_SCRIPT), stehen bereits in collect()
        t = texts.get("a:" + aid, {})
        out.append({"id": aid, "cms": item["cms"], "title": item["title"], "commands": item["how"], "backup": a_backup(aid),
                    "text": t.get("blocks", []), "blocks": blocks})
    return out


def a_backup(aid: str) -> bool:
    from . import actions
    return bool(actions.ACTIONS.get(aid, {}).get("backup"))


def payload(lang: str = "de") -> Dict[str, Any]:
    """Alles für das Kapitel 'Technik'. Die Titel werden übersetzt, der Code nie."""
    from . import i18n
    chk = check_entries()
    acts = action_entries(lang)
    if lang != i18n.SOURCE:
        titles = i18n.tr_obj([{"id": c["id"], "title": c["title"], "summary": c["summary"]} for c in chk], lang)
        for c, t in zip(chk, titles):
            c["title"], c["summary"] = t["title"], t["summary"]
        at = i18n.tr_obj([{"id": a["id"], "title": a["title"]} for a in acts], lang)
        for a, t in zip(acts, at):
            a["title"] = t["title"]
    return {"lang": lang if lang in helpdocs.available() else helpdocs.SOURCE, "basics": basics(lang), "checks": chk, "actions": acts}
