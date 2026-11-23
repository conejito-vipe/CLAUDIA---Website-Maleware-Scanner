"""Skimmer-Suche (2.4.0): Code, der Kartendaten aus Formularen abgreift und an fremde Adressen sendet. CMS-neutral (Joomla, WordPress, Shop-Erweiterungen), rein lesend."""
from __future__ import annotations

import re
from typing import Dict, List

from ..registry import check
from ..util import clean_line, host_allowed, lines_of, split_sections

G = "dateien"
SHOW = 40

# Bekannte Zahlungsanbieter (Adressen, an die Zahlungs-Erweiterungen berechtigt senden); ergänzt die allgemeine Liste bekannter Adressen
PAYMENT_HOSTS = ["stripe.com", "stripe.network", "paypal.com", "paypalobjects.com", "braintreegateway.com", "braintree-api.com", "adyen.com", "mollie.com", "klarna.com", "klarnacdn.net",
                 "worldpay.com", "authorize.net", "squareup.com", "sumup.com", "payone.com", "unzer.com", "heidelpay.com", "payrexx.com", "datatrans.com", "saferpay.com", "computop-paygate.com",
                 "checkout.com", "2checkout.com", "amazon.com", "amazonpay.com", "apple.com", "shopify.com", "concardis.com", "nexi.com", "nexi-payments.com", "ratepay.com", "wirecard.com"]

# Namen von Kartenfeldern (ohne Anführungszeichen im Muster, damit es in einfache Shell-Anführungszeichen passt)
CARD_RE = r"card[-_ ]?(number|num|no|holder|cvc|cvv|expiry)|cc[-_]?(num|number|cvc|cvv|exp|expiry)|cvv2?|cvc2?|securitycode|security_code|kreditkarte|kartennummer|pan_number"
# Wege, Daten nach außen zu schicken
SEND_RE = r"XMLHttpRequest|fetch[[:space:]]*\(|sendBeacon|\.ajax[[:space:]]*\(|\$\.post[[:space:]]*\(|new[[:space:]]+WebSocket|new[[:space:]]+Image[[:space:]]*\(|\.src[[:space:]]*=|curl_exec|file_get_contents[[:space:]]*\([^)]*http|wp_remote_post|fsockopen"
# Verschleierung, die ein Lader nutzt
OBF_RE = r"eval[[:space:]]*\([[:space:]]*(atob|unescape|String\.fromCharCode)|atob[[:space:]]*\([[:space:]]*['\"][A-Za-z0-9+/=]{80,}|_0x[0-9a-f]{4,}[[:space:]]*\(|fromCharCode[[:space:]]*\(([[:space:]]*[0-9]{2,3}[[:space:]]*,){12,}"
# Der Code prüft, ob ein Administrator oder ein Mobilgerät zusieht (versteckt sich vor Prüfern, läuft nur bei Kunden)
GATE_RE = r"wpadminbar|pointer[[:space:]]*:[[:space:]]*coarse"
# Fremdskript-Lader
LOAD_RE = r"createElement[[:space:]]*\([[:space:]]*['\"]script['\"]\)|<script[^>]+src[[:space:]]*=[[:space:]]*['\"]?https?://|document\.write[[:space:]]*\([^)]*<script"

SCRIPT = r"""
find . -type f -size -1024k @SKIP@ \( -iname '*.js' -o -iname '*.php' -o -iname '*.phtml' -o -iname '*.html' -o -iname '*.htm' -o -iname '*.tpl' -o -iname '*.twig' \) \
  -not -iname '*.min.js.map' -not -path '*/vendor/*' -not -path '*/node_modules/*' -print0 2>/dev/null | head -z -n 20000 \
  | xargs -0 -r grep -lEi '@CARD@' 2>/dev/null | head -n 200 | while IFS= read -r f; do
  printf '@@@F\t%s\n' "$f"
  s=0; grep -qE '@SEND@' "$f" 2>/dev/null && s=1
  o=0; grep -qE '@OBF@' "$f" 2>/dev/null && o=1
  l=0; grep -qE '@LOAD@' "$f" 2>/dev/null && l=1
  g=0; grep -qE '@GATE@' "$f" 2>/dev/null && g=1
  printf 'FLAGS\t%s\t%s\t%s\t%s\n' "$s" "$o" "$l" "$g"
  grep -oE "https?://[A-Za-z0-9.-]+" "$f" 2>/dev/null | sort -u | head -n 30 | sed 's/^/HOST\t/'
done
echo '@@LOADERS'
find . -type f -size -1024k @SKIP@ \( -iname '*.js' \) -not -path '*/vendor/*' -not -path '*/node_modules/*' -print0 2>/dev/null | head -z -n 20000 \
  | xargs -0 -r grep -lE '@OBF@' 2>/dev/null | head -n 60
echo '@@WS'
find . -type f -size -1024k @SKIP@ \( -iname '*.js' -o -iname '*.php' -o -iname '*.html' -o -iname '*.phtml' -o -iname '*.twig' -o -iname '*.tpl' \) -not -path '*/vendor/*' -not -path '*/node_modules/*' -print0 2>/dev/null | head -z -n 20000 \
  | xargs -0 -r grep -HoE 'WebSocket[[:space:]]*\([[:space:]]*.wss?://[A-Za-z0-9.-]+' 2>/dev/null | head -n 100
"""


def parse(out: str) -> List[Dict]:
    sec = split_sections(out)
    first = out.split("@@LOADERS")[0]
    items: List[Dict] = []
    for chunk in first.split("@@@F\t")[1:]:
        lines = chunk.splitlines()
        it = {"path": clean_line(lines[0]), "send": False, "obf": False, "load": False, "gate": False, "hosts": []}
        for ln in lines[1:]:
            p = ln.split("\t")
            if p[0] == "FLAGS" and len(p) >= 4:
                it["send"], it["obf"], it["load"] = p[1] == "1", p[2] == "1", p[3] == "1"
                it["gate"] = len(p) >= 5 and p[4] == "1"
            elif p[0] == "HOST" and len(p) >= 2:
                it["hosts"].append(p[1])
        items.append(it)
    return items


def parse_ws(out: str) -> List[Dict[str, str]]:
    """Zeilen 'Pfad:WebSocket("wss://host' des Abschnitts @@WS: Datei und Zieladresse."""
    rows: List[Dict[str, str]] = []
    for ln in lines_of(split_sections(out).get("WS", "")):
        m = re.match(r"^(.*?):WebSocket\s*\(\s*.(wss?)://([A-Za-z0-9.-]+)\Z", ln.strip())
        if m:
            rows.append({"path": clean_line(m.group(1)), "host": m.group(3).lower()})
    return rows


def _items(lst: List[str]) -> List[str]:
    return lst[:SHOW] + (["... und %d weitere" % (len(lst) - SHOW)] if len(lst) > SHOW else [])


@check(
    "skimmer_scan", G, "Skimmer-Suche (Kartendaten-Diebstahl)",
    "Enthält Code Zugriffe auf Kartenfelder und schickt Daten an fremde Adressen oder lädt verschleiert Fremdcode nach?",
    what="Sucht in JavaScript-, PHP-, Template- und HTML-Dateien nach Code, der Kartenfelder (Kartennummer, Prüfziffer, Ablaufdatum) liest. Gemeldet wird es erst, wenn in derselben Datei zusätzlich Daten nach außen gesendet werden "
         "und eine fremde Adresse vorkommt, die nicht zu den bekannten Zahlungs- und Dienstanbietern gehört, oder wenn der Code verschleiert ist. Außerdem werden JavaScript-Dateien mit verschleierten Ladern aufgelistet. "
         "Funktioniert für Joomla, WordPress und Shop-Erweiterungen gleichermaßen.",
    why="Skimmer sind kleine Skripte auf Bestell- und Zahlungsseiten. Sie lesen Karten- und Adressdaten mit und schicken sie an den Angreifer; die Kunden und der Shop merken meist nichts. "
        "Gute Zahlungs-Erweiterungen greifen auf dieselben Felder zu, senden aber nur an ihren Anbieter. Deshalb zählt die Kombination, nicht das einzelne Wort.",
    reads="Durchsucht Texte von JS-, PHP-, Template- und HTML-Dateien bis 1 MB auf dem Server (nur lesend; übertragen werden nur Pfade, Markierungen und Hostnamen). Eigene Karten- oder Zahlungsdaten werden nicht gelesen oder gespeichert. Datenbankinhalte prüfen die Datenbank-Tests.",
    load="hoch", presets=["hack"],
)
def skimmer_scan(ctx, res):
    ctx.progress("Dateien nach Kartenfeld-Zugriffen durchsuchen")
    script = (SCRIPT.replace("@SKIP@", ctx.prof["recent_skip"]).replace("@CARD@", CARD_RE).replace("@SEND@", SEND_RE.replace("'", "'\"'\"'"))
              .replace("@OBF@", OBF_RE.replace("'", "'\"'\"'")).replace("@LOAD@", LOAD_RE.replace("'", "'\"'\"'")).replace("@GATE@", GATE_RE.replace("'", "'\"'\"'")))
    out = ctx.sh(script, timeout=600, raw="treffer", raw_cap=60_000).out
    own = ctx.own_host()
    allow = ctx.allow()
    crit: List[str] = []
    warn: List[str] = []
    seen = 0
    for it in parse(out):
        seen += 1
        foreign = sorted({h for h in (x.split("//", 1)[-1].lower() for x in it["hosts"]) if h and h != own and not host_allowed(h, allow + PAYMENT_HOSTS)})
        desc = it["path"] + ("  (fremde Adressen: %s)" % ", ".join(foreign[:4]) if foreign else "")
        if it["send"] and foreign:
            (crit if (it["obf"] or it.get("gate")) else warn).append(desc + ("  [prüft Administrator-Leiste oder Touch-Gerät]" if it.get("gate") else ""))
        elif it["obf"]:
            warn.append(it["path"] + "  (verschleierter Code in einer Datei mit Kartenfeldern)")
    if crit:
        res.add("crit", "%d Datei(en): Kartenfelder, Versand nach außen, fremde Adresse und verschleierter Code" % len(crit),
                "Das ist das Muster eines Skimmers: Kartendaten werden gelesen und an eine fremde Adresse gesendet, der Code ist absichtlich unleserlich.", _items(crit),
                "Datei NICHT ausführen, Kopie sichern (Beweis), Herkunft klären (Erweiterung neu installieren oder Datei löschen). Danach Zugänge erneuern und den Zahlungsanbieter informieren.")
    if warn:
        res.add("warn", "%d Datei(en) mit Kartenfeldern und Verbindung zu fremden Adressen" % len(warn),
                "Die Datei liest Kartenfelder und enthält Versand-Code zusammen mit Adressen, die nicht als Zahlungs- oder Dienstanbieter bekannt sind. Das ist bei Zahlungs-Erweiterungen mit eigenem Anbieter möglich, bei unbekannten Adressen aber ein Warnzeichen.",
                _items(warn), "Adresse und Herkunft der Datei prüfen. Gehört der Anbieter zu deiner Zahlungs-Erweiterung, ist es harmlos; dann den Hostnamen unter 'Bekannte Adressen' ergänzen.")
    ws = [w for w in parse_ws(out) if w["host"] != own and not host_allowed(w["host"], allow + PAYMENT_HOSTS)]
    if ws:
        res.add("warn", "%d Datei(en) öffnen eine WebSocket-Verbindung zu einer unbekannten Adresse" % len(ws),
                "Skimmer nutzen WebSocket-Verbindungen, weil klassische Filter und die Netzwerkliste vieler Prüfwerkzeuge sie übersehen. Chat- und Live-Dienste tun es auch, dann ist die Adresse bekannt.",
                _items(["%s  ->  %s" % (w["path"], w["host"]) for w in ws]),
                "Adresse und Datei prüfen. Gehört sie zu einem Dienst, den du nutzt, unter 'Bekannte Adressen' ergänzen; sonst Datei sichern und entfernen.")
    loaders = [clean_line(x) for x in lines_of(split_sections(out).get("LOADERS", ""))]
    if loaders:
        res.add("info", "%d JavaScript-Datei(en) mit verschleiertem Lader-Code" % len(loaders),
                "Verschleierung (z. B. eval(atob(...)) oder Kette aus Zeichencodes) ist bei Schadcode häufig, kommt aber auch in gepackten Bibliotheken vor. Der Test 'Bekannte Malware-Muster' bewertet sie genauer.",
                _items(loaders), "Nur beachten, wenn die Datei nicht zu einer bekannten Erweiterung oder Bibliothek gehört.")
    if not (crit or warn or loaders or ws):
        res.add("ok", "Keine Skimmer-Merkmale gefunden", "%d Datei(en) mit Kartenfeld-Namen wurden angesehen; keine sendet Daten an unbekannte Adressen." % seen)
