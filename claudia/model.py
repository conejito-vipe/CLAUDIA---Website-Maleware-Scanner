"""Datenmodell: Befunde, Ergebnisse, Test-Definitionen."""
from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

SEV_RANK = {"ok": 0, "info": 1, "warn": 2, "crit": 3}
SEV_LABEL = {
    "ok": "In Ordnung",
    "info": "Hinweis",
    "warn": "Bitte prüfen",
    "crit": "Kritisch",
    "error": "Test fehlgeschlagen",
    "skipped": "Übersprungen",
}


@dataclass
class Finding:
    sev: str                      # ok | info | warn | crit
    title: str
    detail: str = ""
    items: List[str] = field(default_factory=list)
    hint: str = ""                # Handlungsempfehlung
    evidence: List[Dict[str, Any]] = field(default_factory=list)   # Fundstellen mit Code: {file, line, note, code:[{n, t, hit:[von,bis]|None}]}

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


@dataclass
class CheckResult:
    id: str
    title: str
    group: str
    status: str = "ok"            # ok | info | warn | crit | error | skipped
    findings: List[Finding] = field(default_factory=list)
    raw: Dict[str, str] = field(default_factory=dict)
    seconds: float = 0.0
    message: str = ""             # Fehler- oder Überspring-Grund

    def add(self, sev: str, title: str, detail: str = "", items: Optional[List[str]] = None, hint: str = "",
            evidence: Optional[List[Dict[str, Any]]] = None) -> Finding:
        f = Finding(sev, title, detail, list(items or []), hint, list(evidence or []))
        self.findings.append(f)
        return f

    def finalize(self) -> None:
        if self.status in ("error", "skipped"):
            return
        worst = "ok"
        for f in self.findings:
            if SEV_RANK[f.sev] > SEV_RANK[worst]:
                worst = f.sev
        self.status = worst

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id, "title": self.title, "group": self.group, "status": self.status,
            "findings": [f.to_dict() for f in self.findings],
            "raw": self.raw, "seconds": round(self.seconds, 2), "message": self.message,
        }


@dataclass
class Option:
    key: str
    label: str
    kind: str = "text"            # text | int | bool
    default: Any = ""
    help: str = ""


_WP_WORDS = (("configuration.php", "wp-config.php"), ("Joomla-", "WordPress-"), ("Joomla", "WordPress"))


_DRUPAL_WORDS = (("configuration.php", "settings.php"), ("Joomla-", "Drupal-"), ("Joomla", "Drupal"))
_TYPO3_WORDS = (("configuration.php", "settings.php"), ("Joomla-", "TYPO3-"), ("Joomla", "TYPO3"))
_CONTAO_WORDS = (("configuration.php", ".env"), ("Joomla-", "Contao-"), ("Joomla", "Contao"))
_SHOPWARE_WORDS = (("configuration.php", ".env"), ("Joomla-", "Shopware-"), ("Joomla", "Shopware"))
_PRESTASHOP_WORDS = (("configuration.php", "parameters.php"), ("Joomla-", "PrestaShop-"), ("Joomla", "PrestaShop"))


def _wp_words(text: str, cms: str = "wordpress") -> str:
    """Allgemeine Texte gemeinsamer Tests für ein anderes System: Joomla-Begriffe durch dessen Begriffe ersetzen."""
    for a, b in (_DRUPAL_WORDS if cms == "drupal" else _TYPO3_WORDS if cms == "typo3" else _CONTAO_WORDS if cms == "contao" else _PRESTASHOP_WORDS if cms == "prestashop" else _SHOPWARE_WORDS if cms == "shopware" else _WP_WORDS):
        text = text.replace(a, b)
    return text


@dataclass
class CheckDef:
    id: str
    group: str
    title: str
    summary: str                  # ein Satz für die Liste
    what: str                     # Was genau passiert?
    why: str                      # Warum ist das wichtig?
    reads: str                    # Was wird gelesen? (Transparenz: nichts wird verändert)
    load: str                     # leicht | mittel | hoch (Serverlast / Dauer)
    needs: str                    # ssh | db | web | local
    fn: Callable[..., None]
    presets: List[str] = field(default_factory=list)
    options: List[Option] = field(default_factory=list)
    cluster: str = ""
    cms: str = "joomla"           # joomla | wordpress | both
    cluster_wp: str = ""          # Cluster im WordPress-Bereich (leer = wie bei Joomla)
    wp: Dict[str, str] = field(default_factory=dict)   # Texte für den WordPress-Bereich (title, summary, what, why, reads)
    extern: bool = False          # läuft ohne Serverzugang (nur Abrufe von außen); Grundlage des externen Modus
    texts: Dict[str, Dict[str, str]] = field(default_factory=dict)   # Texte je weiterem System (drupal, typo3, contao, prestashop, shopware): ersetzen die automatisch umgeschriebenen Joomla-Texte

    def cluster_for(self, cms: str = "joomla") -> str:
        """Cluster dieses Tests im Bereich des Systems (WordPress kann abweichen; leer = wie Joomla)."""
        return (self.cluster_wp or self.cluster) if cms == "wordpress" else self.cluster

    def view(self, cms: str = "joomla") -> Dict[str, Any]:
        """Anzeigewerte für das jeweilige System (Titel und Erklärungen sind bei WordPress zugeschnitten)."""
        t = {"title": self.title, "summary": self.summary, "what": self.what, "why": self.why, "reads": self.reads}
        if cms in ("wordpress", "drupal", "typo3", "contao", "prestashop", "shopware"):
            if self.id != "other_installs" and (cms == "wordpress" or self.cms == "both"):      # dieser Test nennt andere Systeme absichtlich; eigene Drupal- und TYPO3-Tests brauchen keine Ersetzung
                t = {k: _wp_words(v, cms) for k, v in t.items()}
            if cms == "wordpress":
                t.update({k: v for k, v in self.wp.items() if k in t})
            t.update({k: v for k, v in self.texts.get(cms, {}).items() if k in t})
        return t

    def public(self, cms: str = "joomla") -> Dict[str, Any]:
        t = self.view(cms)
        cluster = self.cluster_for(cms)
        return {
            "id": self.id, "group": self.group, "title": t["title"], "summary": t["summary"],
            "what": t["what"], "why": t["why"], "reads": t["reads"], "load": self.load,
            "needs": self.needs, "extern": self.extern, "presets": self.presets, "cluster": cluster, "cms": self.cms,
            "options": [dataclasses.asdict(o) for o in self.options],
        }


class Cancelled(Exception):
    pass


class CheckSkipped(Exception):
    """Test kann mit den vorhandenen Möglichkeiten nicht laufen (z. B. kein Datenbankzugriff)."""
