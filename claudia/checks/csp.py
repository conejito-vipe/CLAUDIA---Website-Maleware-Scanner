"""Content-Security-Policy (CSP): ist eine aktiv, was erlaubt jede Regel, wo ist sie schwach - und wenn keine da ist: Nutzen und ein Vorschlag zum Testen."""
from __future__ import annotations

import re
from typing import Dict, List, Tuple
from urllib.parse import urljoin, urlparse

from .. import secure
from ..model import CheckSkipped
from ..registry import check
from ..util import clean_line
from .web import G, UA_BROWSER, fetch, waf_block

# Bedeutung der Regeln (Direktiven): Kurzname und Erklärung in Alltagssprache
DIRECTIVES: Dict[str, Tuple[str, str]] = {
    "default-src": ("Grundregel", "Gilt für alles, wofür es keine eigene Regel gibt (Skripte, Stile, Bilder, Schriften, Rahmen ...)."),
    "script-src": ("Skripte", "Legt fest, von wo JavaScript geladen und ausgeführt werden darf. Das ist die wichtigste Regel gegen eingeschleusten Schadcode."),
    "script-src-elem": ("Skript-Elemente", "Wie script-src, aber nur für <script>-Elemente."),
    "script-src-attr": ("Skript in Attributen", "Wie script-src, aber nur für Ereignis-Attribute wie onclick=\"...\"."),
    "style-src": ("Stile", "Legt fest, von wo CSS-Stile kommen dürfen."),
    "style-src-elem": ("Stil-Elemente", "Wie style-src, aber nur für <style> und <link rel=stylesheet>."),
    "style-src-attr": ("Stil in Attributen", "Wie style-src, aber nur für style=\"...\"-Attribute."),
    "img-src": ("Bilder", "Legt fest, von wo Bilder geladen werden dürfen."),
    "font-src": ("Schriften", "Legt fest, von wo Schriftdateien geladen werden dürfen."),
    "connect-src": ("Verbindungen", "Legt fest, wohin das Skript der Seite Daten senden oder von wo es nachladen darf (fetch, XMLHttpRequest, WebSocket)."),
    "media-src": ("Audio und Video", "Legt fest, von wo Audio- und Videodateien kommen dürfen."),
    "object-src": ("Plug-ins (object, embed)", "Legt fest, was als <object> oder <embed> geladen werden darf. 'none' ist empfohlen: Diese Technik braucht heute fast niemand mehr."),
    "frame-src": ("Rahmen (iframe)", "Legt fest, welche fremden Seiten du selbst in einen Rahmen einbinden darfst (z. B. YouTube, Karten)."),
    "child-src": ("Rahmen und Worker", "Ältere Regel für Rahmen und Web-Worker."),
    "worker-src": ("Web-Worker", "Legt fest, von wo Hintergrund-Skripte (Worker, Service-Worker) geladen werden dürfen."),
    "manifest-src": ("Web-App-Manifest", "Legt fest, von wo die Manifest-Datei der Web-App kommen darf."),
    "prefetch-src": ("Vorab-Laden", "Legt fest, was der Browser vorab laden darf."),
    "base-uri": ("Basis-Adresse", "Legt fest, welche <base>-Adresse erlaubt ist. Verhindert, dass ein eingeschleustes <base> alle relativen Links auf einen fremden Server umbiegt."),
    "form-action": ("Formular-Ziele", "Legt fest, wohin Formulare senden dürfen. Schützt davor, dass eingeschleuste Formulare Eingaben an Fremde schicken."),
    "frame-ancestors": ("Einbettung deiner Seite", "Legt fest, wer DEINE Seite in einen Rahmen laden darf. 'none' oder 'self' schützt vor Clickjacking (ersetzt X-Frame-Options)."),
    "sandbox": ("Sandbox", "Sperrt die Seite wie in einem Sandkasten (keine Skripte, Formulare, Popups), außer du erlaubst es einzeln."),
    "upgrade-insecure-requests": ("Auf https umstellen", "Der Browser ruft unverschlüsselte Adressen automatisch verschlüsselt ab (hilft gegen Mischinhalte)."),
    "block-all-mixed-content": ("Mischinhalte sperren", "Blockiert unverschlüsselte Inhalte auf verschlüsselten Seiten (veraltet, ersetzt durch upgrade-insecure-requests)."),
    "report-uri": ("Meldeadresse", "Adresse, an die der Browser Verstöße meldet (älter, ersetzt durch report-to)."),
    "report-to": ("Meldegruppe", "Name der Meldegruppe (Header Reporting-Endpoints), an die der Browser Verstöße meldet."),
    "require-trusted-types-for": ("Trusted Types", "Verlangt, dass gefährliche Skript-Schnittstellen nur mit geprüften Werten gefüttert werden (Schutz vor DOM-XSS)."),
    "trusted-types": ("Trusted-Types-Richtlinien", "Nennt die erlaubten Trusted-Types-Richtlinien."),
}
NO_SOURCES = {"upgrade-insecure-requests", "block-all-mixed-content", "sandbox", "require-trusted-types-for", "trusted-types", "report-uri", "report-to"}


def parse_policies(value: str) -> List[List[Tuple[str, List[str]]]]:
    """Eine oder mehrere Richtlinien (durch Komma getrennt, wenn der Server mehrere Kopfzeilen geschickt hat) als Liste von (Regel, Quellen)."""
    out = []
    for pol in (value or "").split(","):
        rules: List[Tuple[str, List[str]]] = []
        for part in pol.split(";"):
            tok = part.split()
            if tok:
                rules.append((tok[0].lower(), tok[1:]))
        if rules:
            out.append(rules)
    return out


def explain_source(s: str) -> str:
    low = s.lower()
    fixed = {
        "'self'": "die eigene Domain",
        "'none'": "nichts (gesperrt)",
        "'unsafe-inline'": "Inline-Code im Seitentext (schwächt den Schutz: eingeschleuster Schadcode im Text würde laufen)",
        "'unsafe-eval'": "eval() und ähnliches (schwächt den Schutz)",
        "'wasm-unsafe-eval'": "WebAssembly-Kompilierung",
        "'unsafe-hashes'": "Inline-Ereignis-Attribute mit passender Prüfsumme",
        "'strict-dynamic'": "Skripte, die ein bereits vertrauenswürdiges Skript nachlädt",
        "'report-sample'": "Codeauszug im Verstoß-Bericht",
        "'unsafe-allow-redirects'": "Weiterleitungen",
        "*": "jede Adresse (praktisch keine Einschränkung)",
        "data:": "data:-Adressen (Inhalt direkt in der Adresse)",
        "blob:": "blob:-Adressen (im Browser erzeugte Daten)",
        "https:": "jede verschlüsselte Adresse (sehr weit gefasst)",
        "http:": "jede Adresse, auch unverschlüsselt",
        "wss:": "jede verschlüsselte WebSocket-Adresse",
        "filesystem:": "Dateisystem-Adressen",
    }
    if low in fixed:
        return fixed[low]
    if low.startswith("'nonce-"):
        return "nur Code mit der passenden Einmalkennung (nonce)"
    if re.match(r"'sha(256|384|512)-", low):
        return "nur Code mit dieser Prüfsumme"
    if low.startswith("*."):
        return "alle Unterseiten von %s" % s[2:]
    return "von %s" % s


def explain_rule(name: str, sources: List[str]) -> List[str]:
    """Zeilen für eine Regel: erst die Regel mit Erklärung, darunter je Quelle eine Zeile ('Quelle - Bedeutung')."""
    short, what = DIRECTIVES.get(name, (name, "Dem Programm unbekannte oder neuere Regel; siehe die Dokumentation der Content-Security-Policy."))
    if name in NO_SOURCES or not sources:
        return ["%s - %s: %s" % (name, short, what)] + (["    %s" % " ".join(sources)] if sources else [])
    return ["%s - %s: %s" % (name, short, what)] + ["    %s - %s" % (x, explain_source(x)) for x in sources]


def judge(policy: List[Tuple[str, List[str]]]) -> List[str]:
    """Schwächen einer Richtlinie, in Alltagssprache."""
    d = {n: v for n, v in policy}
    weak: List[str] = []
    script = d.get("script-src", d.get("default-src"))
    where = "script-src" if "script-src" in d else "default-src"
    if script is None:
        weak.append("Für Skripte gibt es keine Regel (weder script-src noch default-src): Skripte dürfen von überall geladen werden.")
    else:
        low = [x.lower() for x in script]
        hardened = any(x.startswith("'nonce-") or x.startswith("'sha") or x == "'strict-dynamic'" for x in low)
        if "'unsafe-inline'" in low and not hardened:
            weak.append("%s erlaubt 'unsafe-inline': Eingeschleuster Code im Seitentext würde ausgeführt. Der Schutz gegen Schadcode ist damit weitgehend aufgehoben. Besser: Einmalkennungen (nonce) oder Prüfsummen." % where)
        if "'unsafe-eval'" in low:
            weak.append("%s erlaubt 'unsafe-eval': Text kann als Code ausgeführt werden (eval)." % where)
        if any(x in ("*", "https:", "http:", "data:") for x in low) and not (hardened and "'strict-dynamic'" in low):
            weak.append("%s erlaubt sehr weite Quellen (%s): Ein Angreifer kann Skripte von fast jeder Adresse einbinden." % (where, " ".join(x for x in script if x.lower() in ("*", "https:", "http:", "data:"))))
        if any(x.lower() == "http:" or x.lower().startswith("http://") for x in script):
            weak.append("%s erlaubt unverschlüsselte (http) Quellen." % where)
    if "object-src" not in d and not (d.get("default-src") and [x.lower() for x in d["default-src"]] == ["'none'"]):
        weak.append("object-src fehlt: Plug-in-Inhalte (<object>, <embed>) sind nicht eingeschränkt. Empfohlen: object-src 'none'.")
    if "base-uri" not in d:
        weak.append("base-uri fehlt: Ein eingeschleustes <base> könnte alle relativen Links auf einen fremden Server umbiegen. Empfohlen: base-uri 'self'.")
    if "frame-ancestors" not in d:
        weak.append("frame-ancestors fehlt: Andere Seiten dürfen deine Seite in einen Rahmen laden (Clickjacking). Alternativ schützt der Header X-Frame-Options.")
    return weak


META_RX = re.compile(r"<meta\b[^>]*?http-equiv\s*=\s*[\"']?content-security-policy(-report-only)?[\"']?[^>]*?>", re.I)
CONTENT_RX = re.compile(r"content\s*=\s*(?:\"([^\"]*)\"|'([^']*)')", re.I)


def meta_policies(html: str) -> List[Tuple[bool, str]]:
    out = []
    for m in META_RX.finditer(html or ""):
        c = CONTENT_RX.search(m.group(0))
        if c:
            out.append((bool(m.group(1)), (c.group(1) or c.group(2) or "").strip()))
    return out


# ---- Vorschlag aus dem, was die Startseite wirklich lädt
SRC_RX = {
    "script": re.compile(r"<script\b[^>]*?\bsrc\s*=\s*[\"']([^\"']+)[\"']", re.I),
    "style": re.compile(r"<link\b[^>]*?rel\s*=\s*[\"']?stylesheet[\"']?[^>]*?href\s*=\s*[\"']([^\"']+)[\"']|<link\b[^>]*?href\s*=\s*[\"']([^\"']+)[\"'][^>]*?rel\s*=\s*[\"']?stylesheet", re.I),
    "img": re.compile(r"<img\b[^>]*?\bsrc\s*=\s*[\"']([^\"']+)[\"']|<source\b[^>]*?\bsrcset\s*=\s*[\"']([^\"'\s,]+)", re.I),
    "frame": re.compile(r"<iframe\b[^>]*?\bsrc\s*=\s*[\"']([^\"']+)[\"']", re.I),
    "form": re.compile(r"<form\b[^>]*?\baction\s*=\s*[\"']([^\"']+)[\"']", re.I),
}
INLINE_SCRIPT = re.compile(r"<script\b(?![^>]*\bsrc\s*=)[^>]*>\s*\S", re.I)
INLINE_HANDLER = re.compile(r"\son(?:click|load|submit|change|mouseover|error)\s*=", re.I)


def origin_of(url: str, base: str) -> str:
    full = urljoin(base, url.strip())
    p = urlparse(full)
    if p.scheme not in ("http", "https") or not p.hostname:
        return ""
    return "%s://%s" % (p.scheme, p.netloc)


def inventory(html: str, base: str) -> Dict[str, object]:
    """Welche Fremd-Adressen lädt die Startseite? Nur die Startseite: andere Seiten können mehr brauchen."""
    own = origin_of("/", base)
    res: Dict[str, object] = {}
    for kind, rx in SRC_RX.items():
        found: List[str] = []
        for m in rx.finditer(html or ""):
            u = next((g for g in m.groups() if g), "")
            o = origin_of(u, base) if u and not u.lower().startswith(("data:", "blob:")) else ""
            if o and o != own and o not in found:
                found.append(o)
        res[kind] = found[:12]
    res["inline_script"] = bool(INLINE_SCRIPT.search(html or ""))
    res["inline_handler"] = bool(INLINE_HANDLER.search(html or ""))
    res["inline_style"] = bool(re.search(r"<style\b|\sstyle\s*=", html or "", re.I))
    return res


def propose(inv: Dict[str, object]) -> Tuple[str, List[str]]:
    """(Richtlinie als Text, Erklärungszeilen). Immer zuerst im Testmodus (Report-Only) verwenden."""
    def hosts(k):
        return " ".join(inv.get(k) or [])
    script = ["'self'"] + list(inv["script"])
    notes = []
    if inv["inline_script"] or inv["inline_handler"]:
        script.append("'unsafe-inline'")
        notes.append("Die Startseite enthält Inline-Skripte oder Ereignis-Attribute. Dafür steht im Vorschlag vorerst 'unsafe-inline' (schwächt den Schutz). Besser: die Skripte in Dateien auslagern oder mit Einmalkennungen (nonce) versehen; das geht meist nur mit Hilfe des Entwicklers oder einer Erweiterung.")
    style = ["'self'", "'unsafe-inline'"] + list(inv["style"])
    fonts = ["'self'", "data:"]
    if any("fonts.googleapis.com" in x for x in inv["style"]):
        fonts.append("https://fonts.gstatic.com")
    img = ["'self'", "data:"] + list(inv["img"])
    frames = list(inv["frame"]) or ["'none'"]
    forms = ["'self'"] + list(inv["form"])
    pol = [("default-src", ["'self'"]), ("script-src", script), ("style-src", style), ("img-src", img), ("font-src", fonts), ("connect-src", ["'self'"]),
           ("frame-src", frames), ("object-src", ["'none'"]), ("base-uri", ["'self'"]), ("form-action", forms), ("frame-ancestors", ["'self'"]), ("upgrade-insecure-requests", [])]
    text = "; ".join(("%s %s" % (n, " ".join(v))).strip() for n, v in pol)
    notes.append("Der Vorschlag beruht nur auf der Startseite. Unterseiten, Formulare, Zahlungsanbieter, Karten, Videos oder Statistik-Skripte können weitere Adressen brauchen.")
    notes.append("Der Verwaltungsbereich (Joomla-Backend, WordPress-Dashboard) braucht meist lockerere Regeln. Setze die Richtlinie deshalb nur für die öffentlichen Seiten, oder prüfe den Verwaltungsbereich ausdrücklich mit.")
    return text, notes


@check(
    "web_csp", G, "Content-Security-Policy (CSP) prüfen",
    "Ist eine Content-Security-Policy aktiv, und was erlaubt jede einzelne Regel?",
    what="Ruft die Startseite einmal ab und liest die Content-Security-Policy aus den Kopfzeilen (und aus einem <meta>-Tag im Quelltext). Jede Regel wird einzeln erklärt, Schwächen werden benannt. "
         "Ist keine gesetzt, erklärt das Ergebnis den Nutzen und erzeugt aus den Adressen, die deine Startseite wirklich lädt, einen Vorschlag zum Testen (zuerst im Modus Report-Only).",
    why="Eine CSP sagt dem Browser, von wo eine Seite Skripte, Bilder und anderes laden darf. Wird in eine Seite Schadcode eingeschleust (z. B. ein fremdes Skript), kann der Browser ihn blockieren, "
        "statt ihn auszuführen. Sie ist kein Ersatz für Updates und Aufräumen, aber eine wirksame zweite Verteidigungslinie für Besucher.",
    reads="Nur die Kopfzeilen und den Quelltext der Startseite, wie sie jeder Besucher bekommt. Es wird nichts verändert; der Vorschlag wird nur angezeigt.",
    load="leicht", needs="web", presets=["schnell"],
)
def web_csp(ctx, res):
    url = (ctx.s.url or "").strip()
    if not url:
        raise CheckSkipped("Keine Adresse der Webseite angegeben (Feld 'Webseite' in den Verbindungsdaten).")
    url, _up = secure.to_https(url)
    ctx.progress("Rufe die Startseite für die CSP-Prüfung ab")
    f = fetch(url, UA_BROWSER, max_bytes=400_000)
    if f.error:
        raise CheckSkipped("Webseite nicht erreichbar: %s" % f.error)
    who = waf_block(f)
    if who:
        res.add("info", "Von einer Firewall blockiert, CSP nicht aussagekräftig", "Die Antwort ist eine Sperrseite (%s). Die Kopfzeilen stammen von der Firewall, nicht von deiner Seite." % who)
        return
    enforced = parse_policies(f.headers.get("content-security-policy", ""))
    report_only = parse_policies(f.headers.get("content-security-policy-report-only", ""))
    metas = meta_policies(f.body)
    meta_enf = [p for ro, v in metas if not ro for p in parse_policies(v)]
    meta_ro = [p for ro, v in metas if ro for p in parse_policies(v)]
    active = enforced + meta_enf
    if active:
        n = sum(len(p) for p in active)
        items: List[str] = []
        for i, pol in enumerate(active, 1):
            if len(active) > 1:
                items.append("--- Richtlinie %d ---" % i)
            items += [clean_line(ln) for nm, vals in pol for ln in explain_rule(nm, vals)]
        src = "Kopfzeile" if enforced else "<meta>-Tag im Quelltext"
        res.add("ok", "Eine Content-Security-Policy ist aktiv (%d Regeln, %s)" % (n, src),
                "Jede Regel ist unten einzeln erklärt. Eine CSP wirkt zusätzlich zu Updates und Aufräumen: Sie begrenzt, was der Browser eines Besuchers laden und ausführen darf.", items)
        if not enforced and meta_enf:
            res.add("info", "Die CSP steht nur in einem <meta>-Tag", "Als <meta>-Tag werden frame-ancestors, report-uri und sandbox ignoriert, und sie greift erst, wenn der Browser das Tag gelesen hat. Besser als Kopfzeile des Servers setzen.")
        weak: List[str] = []
        for pol in active:
            for w in judge(pol):
                if w not in weak:
                    weak.append(w)
        if weak:
            res.add("info", "%d mögliche Schwächen in der Content-Security-Policy" % len(weak), "Das ist keine Sicherheitslücke an sich, aber der Schutz wirkt dann weniger stark, als er aussieht.", weak,
                    "Passe die Regeln schrittweise an und teste mit Content-Security-Policy-Report-Only, bevor du sie scharf stellst.")
        else:
            res.add("ok", "Keine auffälligen Schwächen in der Content-Security-Policy")
    ro = report_only + meta_ro
    if ro:
        items = [clean_line(ln) for pol in ro for nm, vals in pol for ln in explain_rule(nm, vals)]
        res.add("info", "Eine CSP im Testmodus (Report-Only) ist gesetzt" if not active else "Zusätzlich ist eine CSP im Testmodus (Report-Only) gesetzt",
                "Im Testmodus blockiert der Browser nichts, er meldet nur Verstöße (Konsole oder Meldeadresse). Wenn die Meldungen sauber sind, setze dieselbe Richtlinie als Content-Security-Policy scharf.", items)
    if active:
        return
    # keine CSP
    res.add("info", "Keine Content-Security-Policy gesetzt" if not ro else "Keine scharfgestellte Content-Security-Policy",
            "Eine CSP sagt dem Browser, von wo deine Seite Skripte, Stile, Bilder und Rahmen laden darf. Wird z. B. ein fremdes Skript eingeschleust oder ein Formular umgebogen, kann der Browser das blockieren, "
            "statt es bei deinen Besuchern auszuführen. Sie ersetzt keine Updates und kein Aufräumen, ist aber eine wirksame zweite Verteidigungslinie und mindert die Folgen von Lücken in Erweiterungen. "
            "Der Aufwand liegt im Einrichten: Jede Quelle, die deine Seite braucht (Statistik, Schriften, Karten, Videos), muss erlaubt werden, sonst funktioniert sie nicht mehr.",
            hint="Das Programm hat unten einen Vorschlag aus den Adressen deiner Startseite erzeugt. Teste ihn zuerst im Modus Report-Only; so geht nichts kaputt.")
    inv = inventory(f.body, f.final or url)
    pol, notes = propose(inv)
    snippet = ["# Vorschlag zum Testen (in die .htaccess im Hauptordner der Seite, Apache mit mod_headers)",
               "<IfModule mod_headers.c>",
               "  Header always set Content-Security-Policy-Report-Only \"%s\"" % pol,
               "</IfModule>",
               "# Nach dem Testen 'Content-Security-Policy-Report-Only' durch 'Content-Security-Policy' ersetzen."]
    ev = [{"file": "Vorschlag für die .htaccess (nur Anzeige, nichts wird geschrieben)", "line": 0, "note": "",
           "code": [{"n": i + 1, "t": t, "hit": None} for i, t in enumerate(snippet)]}]
    items = ["%s - %s: %s" % (nm, DIRECTIVES.get(nm, (nm, ""))[0], DIRECTIVES.get(nm, ("", ""))[1]) for nm in
             ("default-src", "script-src", "style-src", "img-src", "font-src", "connect-src", "frame-src", "object-src", "base-uri", "form-action", "frame-ancestors", "upgrade-insecure-requests")]
    res.add("info", "Vorschlag für eine Content-Security-Policy (zum Testen)",
            "Erzeugt aus dem, was deine Startseite wirklich lädt. Was jede Regel bewirkt, steht unten. So gehst du vor: 1. Im Testmodus (Report-Only) setzen. 2. Seite und Verwaltung durchklicken, in der Browser-Konsole "
            "(F12) stehen die Verstöße. 3. Regeln ergänzen, bis keine Meldungen mehr kommen. 4. Erst dann als Content-Security-Policy scharf stellen.",
            items + ["Hinweis: %s" % n for n in notes], "Brauchst du Hilfe beim Einrichten? Ergänze im Vorschlag die Fremd-Quellen deiner Seite (Statistik, Karten, Videos, Schriften) in der jeweils passenden Regel; im Zweifel hilft der Entwickler deiner Seite oder dein Hoster.",
            evidence=ev)
