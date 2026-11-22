"""Abgleich der Webseite mit der Google-Safe-Browsing-Liste (Phishing, Schadsoftware, unerwünschte Software). Rein lesend.

Der API-Schlüssel kommt nur aus dem Eingabefeld des Tests, liegt nur im Arbeitsspeicher, wird per Kopfzeile (nicht in der Adresse) gesendet und
nie gespeichert, exportiert oder in Berichte übernommen."""
from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request
from typing import Any, Dict, List, Tuple
from urllib.parse import quote, urlparse

from .. import secure
from ..model import CheckSkipped, Option
from ..registry import check

G = "logs"
API = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
KEY_HOWTO = "https://developers.google.com/safe-browsing/v4/get-started"
REPORT = "https://transparencyreport.google.com/safe-browsing/search?url=%s"
THREATS = {
    "MALWARE": "Schadsoftware (Malware)",
    "SOCIAL_ENGINEERING": "Phishing / Täuschung (Social Engineering)",
    "UNWANTED_SOFTWARE": "Unerwünschte Software",
    "POTENTIALLY_HARMFUL_APPLICATION": "Möglicherweise schädliche Anwendung",
}


def post_json(url: str, payload: Dict[str, Any], key: str, timeout: float = 20.0) -> Tuple[int, str]:
    """POST über https. Der Schlüssel geht in die Kopfzeile X-Goog-Api-Key. Rückgabe: (HTTP-Status, Text). Netzwerkfehler -> (0, Meldung ohne Schlüssel)."""
    if not secure.is_secure_url(url):
        return 0, "Unverschlüsselte Adresse wird nicht benutzt."
    req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), method="POST",
                                 headers={"Content-Type": "application/json", "X-Goog-Api-Key": key, "User-Agent": "CLAUDIA/2.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ssl.create_default_context()) as r:
            return r.status, r.read(500_000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        try:
            body = e.read(20_000).decode("utf-8", "replace")
        except Exception:
            body = ""
        return e.code, body
    except (urllib.error.URLError, OSError, ValueError) as e:
        return 0, str(getattr(e, "reason", e))


def candidate_urls(url: str) -> List[str]:
    u, _ = secure.to_https(url)
    p = urlparse(u)
    host = (p.hostname or "").lower()
    if not host:
        return []
    bare = host[4:] if host.startswith("www.") else host
    out = []
    for h in dict.fromkeys([host, bare, "www." + bare]):
        out += ["https://%s/" % h]
    return list(dict.fromkeys(out + ["http://%s/" % bare]))      # ohne Verschlüsselung nur als Name in der Liste, es wird nichts dorthin gesendet


def parse_matches(body: str) -> List[Dict[str, str]]:
    try:
        d = json.loads(body or "{}")
    except ValueError:
        return []
    out = []
    for m in (d.get("matches") or []) if isinstance(d, dict) else []:
        out.append({"threat": str(m.get("threatType") or ""), "url": str((m.get("threat") or {}).get("url") or ""), "platform": str(m.get("platformType") or "")})
    return out


@check(
    "safe_browsing", G, "Blacklist-Abgleich (Google Safe Browsing)",
    "Steht die Webseite bei Google als gefährlich (Schadsoftware, Phishing) auf der Sperrliste?",
    what="Fragt bei der Google-Safe-Browsing-Schnittstelle an, ob die Adresse deiner Webseite (mit und ohne www) als Schadsoftware, Phishing oder unerwünschte Software geführt wird. "
         "Dazu wird nur die Adresse deiner Seite an Google gesendet, nichts von deinem Server. Ohne API-Schlüssel wird nichts angefragt; das Programm zeigt dann den Link zur manuellen Abfrage.",
    why="Wer auf Googles Liste steht, bekommt in Chrome, Firefox und Safari eine rote Warnseite vor die eigene Seite gesetzt, und Besucher bleiben weg. Oft ist das das erste sichtbare Zeichen eines Hacks, "
        "lange bevor ein Betreiber ihn bemerkt. Nach der Bereinigung muss die Seite bei Google (Search Console) zur erneuten Prüfung gemeldet werden.",
    reads="Nur die Adresse deiner Webseite geht an safebrowsing.googleapis.com (https). Der Schlüssel wird nirgends gespeichert und nicht in Berichte übernommen.",
    load="leicht", needs="web", presets=["schnell", "hack"],
    options=[Option("api_key", "Google-Safe-Browsing-API-Schlüssel (optional, kostenlos)", "secret", "",
                    "Ohne Schlüssel wird nicht angefragt. Einen Schlüssel gibt es kostenlos in der Google Cloud Console (Safe Browsing API aktivieren). Er bleibt nur im Arbeitsspeicher dieser Sitzung.")],
)
def safe_browsing(ctx, res):
    import os
    url = (ctx.s.url or "").strip()
    if not url:
        raise CheckSkipped("Keine Adresse der Webseite angegeben (Feld 'Webseite' in den Verbindungsdaten).")
    host = (urlparse(secure.to_https(url)[0]).hostname or "").lower()
    manual = REPORT % quote(host)
    key = str(ctx.opt("api_key", "") or "").strip()
    if not key:
        res.add("info", "Google Safe Browsing: nicht abgefragt (kein API-Schlüssel)",
                "Der Abgleich braucht einen kostenlosen API-Schlüssel von Google. Ohne ihn kannst du die Seite von Hand prüfen.", [manual, KEY_HOWTO],
                "Erster Link: Seite von Hand abfragen. Zweiter Link: Anleitung von Google, wie du den kostenlosen Schlüssel erstellst. Den Schlüssel trägst du beim Verbinden oder in den Optionen dieses Tests ein (wird nicht gespeichert).")
        return
    if os.environ.get("CLAUDIA_OFFLINE"):
        raise CheckSkipped("Offline-Modus (CLAUDIA_OFFLINE): Es wird nichts bei Google angefragt.")
    urls = candidate_urls(url)
    if not urls:
        raise CheckSkipped("Die Adresse der Webseite ist nicht lesbar.")
    payload = {"client": {"clientId": "claudia", "clientVersion": "2.0"},
               "threatInfo": {"threatTypes": list(THREATS), "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"], "threatEntries": [{"url": u} for u in urls]}}
    ctx.progress("Frage Google Safe Browsing ab")
    status, body = post_json(API, payload, key)
    safe_body = (body or "").replace(key, "***")
    if status == 0:
        raise CheckSkipped("Google Safe Browsing nicht erreichbar: %s" % safe_body[:200])
    if status in (400, 401, 403):
        why = "Der Schlüssel wurde abgelehnt oder die Safe Browsing API ist für das Projekt nicht aktiviert (HTTP %d)." % status
        res.add("info", "Google Safe Browsing: Anfrage abgelehnt", why, [manual], "Schlüssel und Freischaltung der Safe Browsing API in der Google Cloud Console prüfen. Du kannst die Seite auch von Hand abfragen.")
        return
    if status == 429:
        res.add("info", "Google Safe Browsing: Anfrage-Limit erreicht", "Später erneut versuchen.", [manual])
        return
    if status != 200:
        raise CheckSkipped("Google Safe Browsing antwortete mit HTTP %d." % status)
    matches = parse_matches(body)
    ctx.add_raw("safe_browsing_antwort", ("%d Treffer\n" % len(matches)) + "\n".join("%s %s" % (m["threat"], m["url"]) for m in matches))
    if matches:
        kinds = sorted({THREATS.get(m["threat"], m["threat"]) for m in matches})
        res.add("crit", "Die Webseite steht bei Google Safe Browsing auf der Sperrliste",
                "Browser zeigen Besuchern eine Warnseite. Gemeldet als: %s." % ", ".join(kinds), ["%s  (%s)" % (m["url"], THREATS.get(m["threat"], m["threat"])) for m in matches[:10]],
                "Seite bereinigen, Lücke schließen und danach in der Google Search Console (Sicherheitsprobleme) eine Überprüfung beantragen. Details: " + manual)
    else:
        res.add("ok", "Google Safe Browsing: kein Eintrag für die Webseite", "Geprüft: %s. Keine Treffer bei Schadsoftware, Phishing und unerwünschter Software." % ", ".join(u for u in urls if u.startswith("https")))
