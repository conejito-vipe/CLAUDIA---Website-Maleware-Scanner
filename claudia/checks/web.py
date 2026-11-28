"""Webseite aus Besuchersicht: Quelltext, Cloaking, eingebundene Skripte, öffentlich erreichbare Dateien."""
from __future__ import annotations

import re
import ssl
import time
import urllib.error
import urllib.request

from .. import secure
from html.parser import HTMLParser
from typing import Dict, List, Optional, Tuple
from urllib.parse import quote, urljoin, urlparse

from ..model import CheckSkipped, Option
from .files import NOCONFLICT_RE, jquery_kind
from ..registry import check
from ..util import clean_line, extract_hosts, host_allowed, trunc

G = "logs"
UA_BROWSER = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
UA_GOOGLE = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
UA_MOBILE = "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Mobile Safari/537.36"
VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}
HIDDEN_STYLE = re.compile(r"display\s*:\s*none|visibility\s*:\s*hidden|left\s*:\s*-\d{3,}|text-indent\s*:\s*-\d{3,}|font-size\s*:\s*0", re.IGNORECASE)
OBF = re.compile(r"_0x[0-9a-f]{4,6}.{0,400}_0x[0-9a-f]{4,6}.{0,400}_0x[0-9a-f]{4,6}", re.DOTALL)
PACKER = re.compile(r"eval\(function\(p,a,c,k,e,[dr]\)")
# Zeichencode-Verschleierung: eval(x.fromCharCode(118,97,114,...)) bzw. sehr lange Zahlenlisten für fromCharCode
FROMCHAR = re.compile(r"eval\s*\(\s*[\w$.]+\s*\.\s*fromCharCode\s*\(|fromCharCode\s*\(\s*(?:\d+\s*,\s*){25,}", re.I)
TAG_IDS = re.compile(r"\b(GTM-[A-Z0-9]{4,10}|G-[A-Z0-9]{8,12}|UA-\d{4,10}-\d+|AW-\d{6,12})\b")


class Page(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.scripts: List[Tuple[str, str]] = []     # (src, inline)
        self.iframes: List[str] = []
        self.css: List[str] = []
        self.links: List[Tuple[str, bool]] = []      # (href, versteckt)
        self.refresh = ""
        self.title = ""
        self.text: List[str] = []
        self._stack: List[Tuple[str, bool]] = []
        self._cur_script: Optional[List[str]] = None
        self._cur_src = ""
        self._cur_type = ""
        self.data_blocks = 0                         # JSON-LD, Importmaps, Vorlagen: kein ausführbarer Code
        self._in_title = False
        self._in_style = False

    def _hidden(self) -> bool:
        return any(h for _, h in self._stack)

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        hidden = bool(HIDDEN_STYLE.search(a.get("style", ""))) or "hidden" in a
        if tag == "script":
            self._cur_script, self._cur_src = [], a.get("src", "")
            self._cur_type = a.get("type", "").strip().lower()
            if self._cur_src:
                self.scripts.append((self._cur_src, ""))
        elif tag == "style":
            self._in_style = True
        elif tag == "title":
            self._in_title = True
        elif tag == "iframe" and a.get("src"):
            self.iframes.append(a["src"])
        elif tag == "link" and a.get("href") and "stylesheet" in a.get("rel", "").lower():
            self.css.append(a["href"])
        elif tag == "meta" and a.get("http-equiv", "").lower() == "refresh":
            self.refresh = a.get("content", "")
        elif tag == "a" and a.get("href"):
            self.links.append((a["href"], hidden or self._hidden()))
        if tag not in VOID:
            self._stack.append((tag, hidden))

    def handle_endtag(self, tag):
        if tag == "script" and self._cur_script is not None:
            inline = "".join(self._cur_script).strip()
            if inline and not self._cur_src:
                if self._cur_type and not self._cur_type.endswith(("javascript", "ecmascript", "module", "babel")) and self._cur_type != "text/jsx":
                    self.data_blocks += 1
                else:
                    self.scripts.append(("", inline))
            self._cur_script = None
        elif tag == "style":
            self._in_style = False
        elif tag == "title":
            self._in_title = False
        for i in range(len(self._stack) - 1, -1, -1):
            if self._stack[i][0] == tag:
                del self._stack[i:]
                break

    def handle_data(self, data):
        if self._cur_script is not None:
            self._cur_script.append(data)
        elif self._in_title:
            self.title += data
        elif not self._in_style and not self._hidden():
            t = data.strip()
            if t:
                self.text.append(t)

    @property
    def visible_text(self) -> str:
        return " ".join(self.text)


class Fetched:
    def __init__(self) -> None:
        self.url = ""
        self.final = ""
        self.status = 0
        self.body = ""
        self.raw = b""
        self.chain: List[str] = []
        self.error = ""
        self.size = 0
        self.headers: Dict[str, str] = {}          # Antwort-Kopfzeilen, Namen klein geschrieben (mehrfache Zeilen mit ', ' verbunden)
        self.set_cookies: List[str] = []           # jede Set-Cookie-Zeile einzeln (die Zusammenfassung oben ist bei Cookies mehrdeutig)


class _Redirects(urllib.request.HTTPRedirectHandler):
    def __init__(self, chain: List[str]):
        super().__init__()
        self.chain = chain

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self.chain.append("%d -> %s" % (code, newurl))
        if not secure.is_secure_url(newurl):
            # Weiterleitung auf unverschlüsseltes http: nicht folgen (Herabstufung der Verschlüsselung)
            raise urllib.error.URLError("Die Seite leitet auf eine unverschlüsselte Adresse (http) weiter: %s. Das Programm folgt dem nicht." % newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _headers_of(msg) -> Dict[str, str]:
    out: Dict[str, str] = {}
    try:
        for k, v in msg.items():
            k = k.lower()
            out[k] = (out[k] + ", " + v) if k in out else v
    except Exception:
        pass
    return out


def _cookies_of(msg) -> List[str]:
    try:
        return [str(c) for c in (msg.get_all("Set-Cookie") or [])][:40]
    except Exception:
        return []


def _read_until(r: Any, max_bytes: int, deadline: float) -> bytes:
    """Antwort stückweise lesen und spätestens zur Frist aufhören: Die Zeitgrenze des Sockets gilt je Lesevorgang;
    ein Server, der alle paar Sekunden ein Byte schickt, würde sonst beliebig lange festhalten."""
    out = bytearray()
    while len(out) < max_bytes:
        if time.monotonic() > deadline:
            break
        chunk = r.read(min(65536, max_bytes - len(out)))
        if not chunk:
            break
        out += chunk
    return bytes(out)


def fetch(url: str, ua: str, referer: str = "", max_bytes: int = 3_000_000, timeout: float = 25.0, binary: bool = False) -> Fetched:
    f = Fetched()
    f.url = url
    if not secure.is_secure_url(url):
        f.error = "Unverschlüsselte Adresse (http) wird nicht abgerufen. Das Programm verbindet sich nur verschlüsselt (https)."
        return f
    ctxssl = ssl.create_default_context()
    opener = urllib.request.build_opener(_Redirects(f.chain), urllib.request.HTTPSHandler(context=ctxssl))
    req = urllib.request.Request(url, headers={"User-Agent": ua, "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
                                               "Accept-Language": "de-DE,de;q=0.9,en;q=0.5", **({"Referer": referer} if referer else {})})
    try:
        with opener.open(req, timeout=timeout) as r:
            f.status = r.status
            f.final = r.geturl()
            f.headers = _headers_of(r.headers)
            f.set_cookies = _cookies_of(r.headers)
            raw = _read_until(r, max_bytes, time.monotonic() + max(5.0, timeout * 2))
            f.size = len(raw)
            if binary:
                f.raw = raw
            else:
                f.body = raw.decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        f.status = e.code
        f.final = e.geturl() if hasattr(e, "geturl") else url
        f.headers = _headers_of(e.headers)
        try:
            f.body = e.read(200_000).decode("utf-8", "replace")
        except Exception:
            f.body = ""
    except (urllib.error.URLError, OSError, ValueError) as e:
        f.error = str(getattr(e, "reason", e))
    return f


def _norm_host(h: str) -> str:
    h = (h or "").lower()
    return h[4:] if h.startswith("www.") else h


def _same_site(a: str, b: str) -> bool:
    a, b = _norm_host(a), _norm_host(b)
    return bool(a) and (a == b or a.endswith("." + b) or b.endswith("." + a))


LOADER_CTX = re.compile(r"\.src\s*=|\bsrc\s*[:=]|createElement\s*\(|\bimport\s*\(|getScript|loadScript|appendChild|insertBefore|importScripts", re.IGNORECASE)
_URL_IN_JS = re.compile(r"https?://([A-Za-z0-9.-]+)[^\s\"'<>)]*", re.IGNORECASE)


def _loader_hosts(inline: str) -> Dict[str, bool]:
    """Hosts aus einem Inline-Skript. True = wird vermutlich geladen (Skript-Adresse), False = nur im Text erwähnt."""
    out: Dict[str, bool] = {}
    for m in _URL_IN_JS.finditer(inline):
        h = m.group(1).lower().rstrip(".")
        url_path = m.group(0).split("?", 1)[0].split("#", 1)[0]
        loads = url_path.lower().endswith(".js") or bool(LOADER_CTX.search(inline[max(0, m.start() - 120):m.start()]))
        out[h] = out.get(h, False) or loads
    return out


def _external_hosts(page: Page, base: str, own: str) -> Dict[str, str]:
    """Hosts aller Skripte, Frames und Stylesheets (Host -> Art)."""
    out: Dict[str, str] = {}
    def add(url: str, kind: str):
        h = urlparse(urljoin(base, url)).hostname or ""
        if h and not _same_site(h, own):
            out.setdefault(h.lower(), kind)
    for src, inline in page.scripts:
        if src:
            add(src, "Skript")
        elif inline:
            for h, loads in _loader_hosts(inline).items():
                if not _same_site(h, own):
                    if loads:
                        out[h] = "Inline-Skript"
                    else:
                        out.setdefault(h, "nur erwähnt")
    for u in page.iframes:
        add(u, "Frame")
    for u in page.css:
        add(u, "Stylesheet")
    return out


def _page_facts(body: str, base: str, own: str) -> Tuple[Page, Dict[str, str]]:
    p = Page()
    try:
        p.feed(body)
        p.close()
    except Exception:
        pass
    return p, _external_hosts(p, base, own)


# ---- Sperrseiten von Firewalls (D3): Status 403/406/429/503 oder eine Herausforderungsseite mit Status 200
WAF_PATTERNS = [
    (re.compile(r"cf-chl|Just a moment\.\.\.|Attention Required! \| Cloudflare|cloudflare ray id|Checking your browser before", re.I), "Cloudflare"),
    (re.compile(r"Sucuri Website Firewall|Access Denied - Sucuri|cloudproxy@sucuri", re.I), "Sucuri"),
    (re.compile(r"imunify360|Access denied by Imunify|i360", re.I), "Imunify360"),
    (re.compile(r"Wordfence|Your access to this site has been limited", re.I), "Wordfence"),
    (re.compile(r"ModSecurity|Mod_Security|Not Acceptable!|This error was generated by Mod_Security", re.I), "ModSecurity"),
    (re.compile(r"Incapsula incident|_Incapsula_Resource", re.I), "Imperva"),
    (re.compile(r"AWS WAF|Request blocked\.|captcha-delivery\.com|px-captcha|DataDome", re.I), "Bot-Schutz/WAF"),
    (re.compile(r"\bcaptcha\b|are you a human|verify you are human|bot protection", re.I), "Bot-Schutz"),
]


def waf_block(f: "Fetched") -> str:
    """Name der Firewall (oder 'Firewall'), wenn die Antwort eine Sperr- oder Herausforderungsseite ist, sonst ''. Eine normale Seite bleibt unberührt."""
    if f.error:
        return ""
    body = f.body or ""
    hdr = f.headers or {}
    hit = ""
    for rx, name in WAF_PATTERNS:
        if rx.search(body[:60_000]):
            hit = name
            break
    if f.status in (403, 406, 429, 503) and (hit or f.status in (406, 429)):
        return hit or "Firewall"
    if f.status in (403, 503) and ("cf-ray" in hdr or "x-sucuri-id" in hdr or hdr.get("server", "").lower().startswith("cloudflare")) and len(body) < 20_000:
        return hit or "Firewall"
    # Herausforderungsseite mit Status 200: kurz, ohne eigene Inhalte, mit Muster
    if f.status == 200 and hit and len(body) < 15_000 and hit != "Bot-Schutz":
        return hit
    return ""


PROBES = [
    ("/.git/config", re.compile(r"\[core\]|\[remote ", re.I), "Git-Daten (Quellcode)"),
    ("/.env", re.compile(r"^[A-Z0-9_]+=", re.M), "Konfigurationsdatei .env"),
    ("/configuration.php~", re.compile(r"class JConfig|\$password", re.I), "Sicherung der configuration.php"),
    ("/configuration.php.bak", re.compile(r"class JConfig|\$password", re.I), "Sicherung der configuration.php"),
    ("/configuration.php.old", re.compile(r"class JConfig|\$password", re.I), "Sicherung der configuration.php"),
    ("/phpinfo.php", re.compile(r"phpinfo\(\)|PHP Version", re.I), "phpinfo-Seite"),
    ("/administrator/logs/joomla_error.php", re.compile(r"#Date|#Fields|ERROR", re.I), "Joomla-Fehlerprotokoll"),
]


@check(
    "web_source", G, "Webseite aus Besuchersicht prüfen",
    "Was bekommen Besucher und Google wirklich ausgeliefert - und ist es überall dasselbe?",
    what="Ruft deine Startseite von DIESEM PC aus mehrfach ab: als normaler Browser, als Googlebot, als Besucher von Google und als Handy. Vergleicht Inhalt und Weiterleitungen (Cloaking), "
         "listet alle eingebundenen Skripte, Frames und Fremd-Server, prüft die eigenen JavaScript-Dateien auf Schadcode-Merkmale und testet, ob Dateien wie .env oder Backups öffentlich abrufbar sind.",
    why="Manche Manipulationen zeigen nur Suchmaschinen oder Handy-Besuchern Spam oder Weiterleitungen, damit du als Betreiber nichts bemerkst. "
        "Und Schadcode, der Besucher infiziert, ist nur im ausgelieferten Quelltext zu sehen. Dazu braucht der Test keinen Server-Zugang.",
    reads="Öffentlich erreichbare Seiten deiner Domain, so wie jeder Besucher sie sieht. Es wird nichts verändert und nichts gesendet außer normalen Seitenaufrufen.",
    load="leicht", needs="web", presets=["schnell", "hack"],
    options=[Option("must_block", "Adressen, die gesperrt sein müssen (eine pro Zeile, optional)", "text", "",
                    "z. B. der Ordner mit Akeeba-Backups oder /administrator/components/com_akeebabackup/Backup-Ordner/. Erwartet wird 403 oder 404.")],
)
def web_source(ctx, res):
    url = (ctx.s.url or "").strip()
    if not url:
        raise CheckSkipped("Keine Adresse der Webseite angegeben (Feld 'Webseite' in den Verbindungsdaten).")
    url, upgraded = secure.to_https(url)
    if upgraded:
        res.add("info", "Die Adresse wurde auf https umgestellt", "Du hast eine unverschlüsselte Adresse (http://) angegeben. Das Programm ruft Webseiten nur verschlüsselt ab.", [url])
    own = urlparse(url).hostname or ""
    allow = ctx.allow()
    ioc = [i.lower() for i in ctx.adv.get("ioc_strings", []) if i]
    spam = [w.lower() for w in ctx.adv.get("spam_words", [])]
    variants = [("Browser", UA_BROWSER, ""), ("Googlebot", UA_GOOGLE, ""), ("Besucher aus Google", UA_BROWSER, "https://www.google.com/"),
                ("Handy aus Google", UA_MOBILE, "https://www.google.com/")]
    got: Dict[str, Fetched] = {}
    facts: Dict[str, Tuple[Page, Dict[str, str]]] = {}
    for name, ua, ref in variants:
        ctx.progress("Rufe Startseite ab als: %s" % name)
        f = fetch(url, ua, ref)
        got[name] = f
        if f.error:
            if name == "Browser":
                res.add("warn", "Webseite nicht erreichbar", "Fehler beim Abruf von %s: %s" % (url, f.error),
                        hint="Adresse prüfen (https://...). Ist die Seite von deinem PC aus erreichbar?")
                return
            continue
        facts[name] = _page_facts(f.body, f.final or url, own)
    base = got["Browser"]
    blocked = {n: waf_block(f) for n, f in got.items() if waf_block(f)}
    if "Browser" in blocked:
        res.add("warn", "Von einer Firewall blockiert, Webseite nicht prüfbar",
                "Der Abruf der Startseite lieferte eine Sperr- oder Herausforderungsseite (%s, HTTP %d), keine echte Seite. Alle Tests, die die Seite lesen, wären dadurch wertlos, deshalb bricht die Prüfung hier ab." % (blocked["Browser"], base.status),
                ["Erkannt: %s" % blocked["Browser"], "Antwort: HTTP %d, %d Byte" % (base.status, base.size)],
                "Im Schutz (Firewall, Wordfence, Cloudflare, Hoster) die IP-Adresse dieses PCs für die Prüfung freigeben oder die Prüfung kurz ohne Schutz wiederholen. "
                "Ob Besucher die Seite normal sehen, sagt dieser Test dann nicht.")
        return
    for n, who in blocked.items():
        res.add("info", "%s wird von einer Firewall blockiert (%s)" % (n, who),
                "Dieser Abruf wird im Vergleich nicht gewertet, weil die Sperrseite keine echte Seite ist. Cloaking kann dafür nur mit den übrigen Abrufen geprüft werden.", [])
        got.pop(n, None)
        facts.pop(n, None)
    bpage, bhosts = facts["Browser"]
    res.add("info", "Startseite ausgeliefert", "", ["Adresse: %s" % url, "Antwort: HTTP %d, %d Byte" % (base.status, base.size),
                                                    "Titel: %s" % clean_line(trunc(bpage.title.strip(), 100))] +
            (["Weiterleitungen: " + " | ".join(base.chain)] if base.chain else []))
    if base.status >= 400:
        res.add("warn", "Die Startseite antwortet mit HTTP %d" % base.status, "Besucher sehen vermutlich eine Fehlerseite.")
    ctx.add_raw("quelltext_browser.html", base.body[:400_000])

    # ---- Weiterleitungen / Cloaking
    cloak: List[str] = []
    for name in ("Googlebot", "Besucher aus Google", "Handy aus Google"):
        f = got.get(name)
        if not f:
            continue
        if f.error:
            # Weiterleitung auf einen Server, der nicht abrufbar ist: die Kette verrät das Ziel trotzdem
            for hop in f.chain:
                hh = extract_hosts(hop)
                if hh and not _same_site(hh[0], own):
                    cloak.append("%s wird auf %s geleitet (%s)" % (name, hh[0], hop))
                    break
            continue
        fh = urlparse(f.final or url).hostname or ""
        if not _same_site(fh, own):
            cloak.append("%s wird auf %s geleitet (HTTP %d)" % (name, fh, f.status))
            continue
        page, hosts = facts[name]
        new_hosts = sorted(set(hosts) - set(bhosts))
        if new_hosts:
            cloak.append("%s bekommt zusätzliche Fremd-Server: %s" % (name, ", ".join(new_hosts[:5])))
        ta, tb = len(bpage.visible_text), len(page.visible_text)
        if max(ta, tb) > 200 and abs(ta - tb) / float(max(ta, tb)) > 0.35:
            cloak.append("%s sieht deutlich anderen Text (%d statt %d Zeichen)" % (name, tb, ta))
        sp_b = {w for w in spam if re.search(r"\b%s\b" % re.escape(w), bpage.visible_text, re.I)}
        sp_x = {w for w in spam if re.search(r"\b%s\b" % re.escape(w), page.visible_text, re.I)}
        if sp_x - sp_b:
            cloak.append("%s sieht Spam-Wörter, die dir verborgen bleiben: %s" % (name, ", ".join(sorted(sp_x - sp_b)[:6])))
    bh = urlparse(base.final or url).hostname or ""
    if not _same_site(bh, own):
        res.add("warn", "Die Startseite leitet auf eine andere Domain weiter", "Aufgerufen: %s, angekommen: %s" % (own, bh),
                hint="Ist das gewollt (Domain-Umzug)? Sonst auf eine Manipulation prüfen (.htaccess, Plugins).")
    if cloak:
        res.add("crit", "Cloaking-Verdacht: Besucher bekommen unterschiedliche Seiten", "Das ist das typische Muster von SEO-Spam und versteckten Weiterleitungen.",
                cloak, "Test 'htaccess' und 'db_content' beachten. Seite in Google mit 'site:deine-domain.de' prüfen (fremde Titel?).")
    else:
        res.add("ok", "Alle Abrufe liefern dieselbe Seite", "Browser, Googlebot, Google-Besucher und Handy bekommen vergleichbare Inhalte.")

    # ---- Fremd-Server
    unknown = {h: k for h, k in bhosts.items() if not host_allowed(h, allow) and k != "nur erwähnt"}
    mentioned = {h: k for h, k in bhosts.items() if not host_allowed(h, allow) and k == "nur erwähnt"}
    known = {h: k for h, k in bhosts.items() if host_allowed(h, allow)}
    if unknown:
        res.add("warn", "%d unbekannte Fremd-Server werden eingebunden" % len(unknown),
                "Skripte, Frames oder Stylesheets von diesen Servern laufen bei jedem Besucher. Kennst du alle?",
                ["%s (%s)" % (h, k) for h, k in sorted(unknown.items())],
                "Unbekanntes herausfinden (Quelltext, Template, Module). Bekannte Dienste kannst du in den Einstellungen zur Liste hinzufügen.")
    if mentioned:
        res.add("info", "%d weitere Adresse(n) in Skripten erwähnt (werden nicht geladen)" % len(mentioned),
                "Z. B. Links zu sozialen Netzwerken in Inline-Skripten. Es wird nichts von dort nachgeladen.", sorted(mentioned))
    if known:
        res.add("info", "%d bekannte Fremd-Server" % len(known), "Z. B. Google, Elfsight, CDNs.", ["%s (%s)" % (h, k) for h, k in sorted(known.items())])
    ids = sorted(set(TAG_IDS.findall(base.body)))
    if ids:
        res.add("info", "Tracking-/Tag-Manager-IDs im Quelltext", "Prüfe, ob alle zu deinen Konten gehören; im Tag Manager nach unbekannten HTML-Tags schauen.", ids)
    hidden_ext = [h for h, hid in bpage.links if hid and not _same_site(urlparse(urljoin(url, h)).hostname or "", own)]
    if hidden_ext:
        res.add("warn", "%d versteckte Links auf fremde Seiten" % len(hidden_ext), "Unsichtbare Links (display:none, weit außerhalb des Bildschirms) dienen oft SEO-Spam.",
                [trunc(h, 120) for h in hidden_ext[:15]])
    meta_ext = bpage.refresh and extract_hosts(bpage.refresh)
    if meta_ext and not all(_same_site(h, own) for h in meta_ext):
        res.add("crit", "Meta-Refresh auf fremde Adresse", bpage.refresh)

    # ---- Schadcode-Merkmale in Quelltext und eigenen JS-Dateien
    problems: List[str] = []
    checked = 0
    js_urls: List[str] = []
    for src, _inline in bpage.scripts:
        if src:
            full = urljoin(base.final or url, src)
            if _same_site(urlparse(full).hostname or "", own):
                js_urls.append(full)
    texts = [("Quelltext der Startseite", base.body)]
    for ju in list(dict.fromkeys(js_urls))[:40]:
        ctx.progress("Prüfe %s" % ju.rsplit("/", 1)[-1][:40])
        jf = fetch(ju, UA_BROWSER, url, max_bytes=2_500_000, timeout=20)
        if jf.error or jf.status != 200:
            continue
        checked += 1
        texts.append((ju, jf.body))
        low = jf.body.lstrip()[:200]
        jpath = urlparse(ju).path
        kind = jquery_kind(jpath) if re.search(r"jquery[^/]*\.js", jpath, re.I) else ""
        if kind == "wrapper" and NOCONFLICT_RE.match(low.strip()) and len(jf.body) <= 200:
            continue            # Joomlas Mini-Datei window.$ = jQuery.noConflict()
        if kind in ("core", "wrapper") and low and not low.startswith(("/*", "//", "!function", "(function")):
            problems.append("%s beginnt nicht mit dem üblichen Kommentar-Kopf: \"%s\"" % (ju, trunc(clean_line(low), 60)))
    for label, body in texts:
        lb = body.lower()
        for i in ioc:
            if i in lb:
                problems.append("%s enthält bekannten Schadcode-Hinweis '%s'" % (label, i))
        if OBF.search(body):
            problems.append("%s enthält verschleierten Code im Stil von obfuscator.io (_0x1a2b-Namen)" % label)
        elif PACKER.search(body):
            problems.append("%s enthält ein gepacktes Skript eval(function(p,a,c,k,e,...)" % label)
        if FROMCHAR.search(body):
            problems.append("%s enthält verschleierten Code: eval(...fromCharCode(Zahlenliste)). Das Skript baut seinen Code aus Zeichencodes zusammen und führt ihn aus" % label)
    if problems:
        res.add("crit", "Schadcode-Merkmale in der ausgelieferten Seite", "Diese Merkmale kommen in normalen Webseiten fast nie vor.", problems,
                "Die Stelle steckt meist in der index.php der aktiven Vorlage (templates/<Name>/index.php) oder in einer Erweiterung. Test 'JavaScript-Dateien auf Schadcode prüfen' "
                "nennt Datei und Zeile; unter 'Lösungen' zeigt das Programm den Ausschnitt mit Zeilennummern.")
    else:
        res.add("ok", "Keine Schadcode-Merkmale im Quelltext und in %d eigenen JavaScript-Dateien" % checked)

    # ---- öffentlich abrufbare Dateien
    root = "%s://%s" % (urlparse(url).scheme, urlparse(url).netloc)
    exposed: List[str] = []
    for path, sig, label in PROBES:
        ctx.progress("Teste %s" % path)
        f = fetch(root + path, UA_BROWSER, max_bytes=60_000, timeout=15)
        if not f.error and f.status == 200 and sig.search(f.body):
            exposed.append("%s - %s ist öffentlich abrufbar" % (path, label))
    if exposed:
        res.add("crit", "%d Datei(en) öffentlich abrufbar" % len(exposed), "Jeder im Internet kann diese Dateien lesen.", exposed,
                "Datei löschen oder per .htaccess sperren. Enthaltene Passwörter ändern.")
    else:
        res.add("ok", "Typische Fehlerquellen (.git, .env, Sicherungen der configuration.php) sind nicht abrufbar")
    # Backups, die auf dem Server liegen, automatisch per Abruf testen (nur mit SSH-Verbindung)
    auto_found: List[str] = []
    if ctx.runner is not None:
        try:
            lst = ctx.sh(r"""find . \( -path ./node_modules -o -path ./libraries -o -path '*/vendor' -o -path ./installation -o -path ./cache -o -path ./tmp \) -prune -o -type f \
  \( -iname '*.jpa' -o -iname '*.sql' -o -iname '*.sql.gz' -o -iname '*.wpress' -o \( \( -iname '*.zip' -o -iname '*.tar.gz' \) -ipath '*backup*' \) \) \
  -size +200k -print 2>/dev/null | head -12""", timeout=60).out
            auto_found = [l.strip()[2:] for l in lst.splitlines() if l.strip().startswith("./")]
        except CheckSkipped:
            auto_found = []
    if auto_found:
        a_bad, a_good = [], []
        for rel in auto_found:
            ctx.progress("Teste Backup-Adresse %s" % rel.rsplit("/", 1)[-1][:40])
            full = root + "/" + quote(rel)
            f = fetch(full, UA_BROWSER, max_bytes=2000, timeout=15)
            if f.error:
                a_good.append("/%s - nicht erreichbar (%s)" % (rel, f.error))
            elif f.status in (401, 403, 404, 410):
                a_good.append("/%s - gesperrt (HTTP %d)" % (rel, f.status))
            else:
                a_bad.append("/%s - HTTP %d, Backup ist öffentlich HERUNTERLADBAR" % (rel, f.status))
        if a_bad:
            res.add("crit", "%d Backup-Datei(en) sind öffentlich herunterladbar" % len(a_bad),
                    "Ein Backup enthält Datenbank, Benutzer und Passwort-Hashes. Jeder, der die Adresse kennt, kann es laden.", a_bad,
                    "Sofort sperren (.htaccess mit 'Require all denied' im Ordner) oder aus dem Web-Verzeichnis entfernen, danach Passwörter ändern.")
        if a_good:
            res.add("ok", "%d Backup-Datei(en) auf dem Server sind von außen nicht abrufbar" % len(a_good),
                    "Das Programm hat die Adressen wie ein Besucher aufgerufen (nur die ersten Bytes).", a_good)
    must = [l.strip() for l in str(ctx.opt("must_block", "") or "").splitlines() if l.strip()]
    if must:
        bad, good = [], []
        for u in must:
            full = u if "//" in u else root + (u if u.startswith("/") else "/" + u)
            f = fetch(full, UA_BROWSER, max_bytes=5000, timeout=15)
            if f.error:
                good.append("%s - nicht erreichbar (%s)" % (full, f.error))
            elif f.status in (401, 403, 404, 410):
                good.append("%s - gesperrt (HTTP %d)" % (full, f.status))
            else:
                bad.append("%s - HTTP %d, ist ABRUFBAR" % (full, f.status))
        if bad:
            res.add("crit", "%d Adresse(n) sollten gesperrt sein, sind es aber nicht" % len(bad), "", bad,
                    "Ordner per .htaccess ('Require all denied') sperren oder aus dem Web-Verzeichnis verschieben.")
        if good:
            res.add("ok", "%d Adresse(n) korrekt gesperrt" % len(good), "", good)


# ---- Sicherheits-Header, HTTPS und Zertifikat (A14)
HEADER_INFO = [
    ("strict-transport-security", "HSTS (Strict-Transport-Security)", "Der Browser darf die Seite danach nur noch verschlüsselt aufrufen."),
    ("x-content-type-options", "X-Content-Type-Options: nosniff", "Der Browser darf Dateitypen nicht erraten (schützt vor untergeschobenen Skripten)."),
    ("frame", "Schutz vor Einbettung (X-Frame-Options oder CSP frame-ancestors)", "Andere Seiten dürfen deine Seite nicht unsichtbar in einen Rahmen laden (Clickjacking)."),
    ("referrer-policy", "Referrer-Policy", "Steuert, welche Adresse beim Klick auf externe Links mitgesendet wird."),
    ("content-security-policy", "Content-Security-Policy", "Legt fest, woher Skripte geladen werden dürfen. Aufwendig einzurichten, deshalb nur ein Hinweis."),
]


def cert_info(host: str, port: int = 443, timeout: float = 15.0) -> Tuple[Optional[int], str, str]:
    """(Tage bis Ablauf, Aussteller, Fehler). Prüft die Kette mit dem Zertifikatsspeicher des PCs; sendet nichts außer dem Verbindungsaufbau."""
    import socket
    import time
    try:
        ctxssl = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctxssl.wrap_socket(sock, server_hostname=host) as ss:
                cert = ss.getpeercert()
        end = ssl.cert_time_to_seconds(cert["notAfter"])
        issuer = ""
        for rdn in cert.get("issuer", ()):
            for k, v in rdn:
                if k in ("organizationName", "commonName") and not issuer:
                    issuer = v
        return int((end - time.time()) // 86400), issuer, ""
    except ssl.SSLCertVerificationError as e:
        return None, "", "Zertifikat wird nicht als vertrauenswürdig akzeptiert: %s" % getattr(e, "verify_message", e)
    except (OSError, ValueError, KeyError) as e:
        return None, "", str(e)


def judge_headers(h: Dict[str, str], https: bool) -> Tuple[List[str], List[str], List[str]]:
    """(fehlend, vorhanden, Hinweise) aus den Antwort-Kopfzeilen. Bei http (nur eigener Rechner) entfällt HSTS."""
    missing: List[str] = []
    present: List[str] = []
    notes: List[str] = []
    for key, label, why in HEADER_INFO:
        if key == "strict-transport-security":
            if not https:
                continue
            v = h.get(key, "")
            m = re.search(r"max-age\s*=\s*(\d+)", v, re.I)
            if not v:
                missing.append("%s - %s" % (label, why))
            elif not m or int(m.group(1)) < 15_552_000:
                notes.append("HSTS ist gesetzt, aber max-age ist kurz (%s Sekunden). Empfohlen sind mindestens 6 Monate (15552000)." % (m.group(1) if m else "fehlt"))
                present.append(label)
            else:
                present.append(label)
        elif key == "x-content-type-options":
            (present if "nosniff" in h.get(key, "").lower() else missing).append(label if "nosniff" in h.get(key, "").lower() else "%s - %s" % (label, why))
        elif key == "frame":
            ok = bool(h.get("x-frame-options")) or "frame-ancestors" in h.get("content-security-policy", "").lower()
            (present if ok else missing).append(label if ok else "%s - %s" % (label, why))
        else:
            ok = bool(h.get(key))
            (present if ok else missing).append(label if ok else "%s - %s" % (label, why))
    srv = h.get("server", "")
    if re.search(r"\d+\.\d+", srv):
        notes.append("Der Server nennt seine genaue Version (Server: %s). Das hilft Angreifern bei der Suche nach passenden Lücken." % trunc(clean_line(srv), 60))
    xp = h.get("x-powered-by", "")
    if re.search(r"\d+\.\d+", xp):
        notes.append("Der Server nennt die PHP-Version (X-Powered-By: %s)." % trunc(clean_line(xp), 60))
    return missing, present, notes


def server_kind(h: Dict[str, str]) -> str:
    """'apache', 'nginx', 'litespeed', 'iis' oder '' aus dem Header Server (nur ein Hinweis, Proxys und CDNs verschleiern ihn)."""
    s = h.get("server", "").lower()
    for k in ("litespeed", "nginx", "apache", "iis"):
        if k in s:
            return k
    return ""


@check(
    "web_headers", G, "HTTPS, Sicherheits-Header und Zertifikat prüfen",
    "Schützt die Seite Besucher im Browser, und läuft das Zertifikat bald ab?",
    what="Ruft die Startseite einmal ab und liest die Antwort-Kopfzeilen: HSTS, X-Content-Type-Options, Schutz vor Einbettung, Referrer-Policy, Content-Security-Policy, und ob der Server seine Version verrät. "
         "Außerdem wird das Zertifikat geprüft (Kette, Restlaufzeit). Es wird nie unverschlüsselt (http) abgerufen; ob die Seite von http auf https weiterleitet, wird deshalb nicht getestet.",
    why="Fehlende Header erleichtern Angriffe auf Besucher (Einbettung, untergeschobene Skripte). Ein abgelaufenes Zertifikat zeigt Besuchern eine Warnseite und kostet Vertrauen und Ranking.",
    reads="Nur die Kopfzeilen der Startseite und das öffentliche Zertifikat, wie sie jeder Besucher bekommt. Es wird nichts verändert.",
    load="leicht", needs="web", presets=["schnell"],
)
def web_headers(ctx, res):
    url = (ctx.s.url or "").strip()
    if not url:
        raise CheckSkipped("Keine Adresse der Webseite angegeben (Feld 'Webseite' in den Verbindungsdaten).")
    url, _up = secure.to_https(url)
    p = urlparse(url)
    ctx.progress("Rufe Kopfzeilen der Startseite ab")
    f = fetch(url, UA_BROWSER, max_bytes=200_000)
    if f.error:
        raise CheckSkipped("Webseite nicht erreichbar: %s" % f.error)
    who = waf_block(f)
    if who:
        res.add("info", "Von einer Firewall blockiert, Header nicht aussagekräftig", "Die Antwort ist eine Sperrseite (%s). Die Kopfzeilen stammen von der Firewall, nicht von deiner Seite." % who)
        return
    https = p.scheme == "https"
    kind = server_kind(f.headers)
    ctx.shared["web_server"] = kind
    missing, present, notes = judge_headers(f.headers, https)
    if not https:
        res.add("info", "Adresse ohne https (nur eigener Rechner)", "HSTS und Zertifikat werden nur bei https geprüft.")
    if missing:
        res.add("info", "%d Sicherheits-Header fehlen" % len(missing), "Das ist keine Lücke an sich, aber ein einfacher zusätzlicher Schutz für Besucher. "
                "Setzen kannst du sie in der .htaccess (Header always set ...), im Hoster-Bereich oder mit einem Plugin.", missing)
    if present:
        res.add("ok", "%d Sicherheits-Header gesetzt" % len(present), "", present)
    for n in notes:
        res.add("info", n.split(".")[0][:90], n)
    if kind:
        res.add("info", "Server-Typ laut Antwort: %s" % kind, "Wird für Aktionen gebraucht, die .htaccess verwenden (nginx liest .htaccess nicht). Proxys und CDNs können den Typ verschleiern.")
    if https and not secure.is_loopback(p.hostname or ""):
        days, issuer, err = cert_info(p.hostname or "", p.port or 443)
        if err:
            res.add("crit", "Zertifikat nicht prüfbar oder ungültig", err, hint="Zertifikat beim Hoster erneuern (Let's Encrypt/AutoSSL) und die Kette prüfen.")
        elif days is not None and days < 0:
            res.add("crit", "Das Zertifikat ist abgelaufen (seit %d Tagen)" % -days, "Besucher sehen eine Warnseite.", ["Aussteller: %s" % issuer], "Sofort erneuern.")
        elif days is not None and days < 14:
            res.add("crit", "Das Zertifikat läuft in %d Tagen ab" % days, "Danach sehen Besucher eine Warnseite.", ["Aussteller: %s" % issuer], "Jetzt erneuern; bei Let's Encrypt die automatische Verlängerung prüfen.")
        elif days is not None and days < 30:
            res.add("warn", "Das Zertifikat läuft in %d Tagen ab" % days, "", ["Aussteller: %s" % issuer], "Erneuerung einplanen; die automatische Verlängerung prüfen.")
        elif days is not None:
            res.add("ok", "Zertifikat gültig, noch %d Tage" % days, "", ["Aussteller: %s" % issuer])
    res.add("info", "Weiterleitung von http auf https nicht getestet", "Das Programm ruft nie unverschlüsselt ab. Ob die Weiterleitung eingerichtet ist, siehst du in der .htaccess (RewriteRule ... https) oder im Hoster-Bereich.")


# ---- A13 (2.4.0): Joomla-Gegenstück zu wp_exposure. CVE-2023-23752: Joomla 4.0.0 bis 4.2.7 gab die Konfiguration (auch Datenbank-Zugangsdaten) ohne Anmeldung über die API aus.
CVE_23752_FIRST, CVE_23752_LAST = "4.0.0", "4.2.7"
API_CONFIG_PATH = "/api/index.php/v1/config/application?public=true"
API_SECRET_KEYS = re.compile(r'"(password|user|db|dbtype|host|secret)"\s*:', re.I)


def api_config_verdict(f: "Fetched") -> str:
    """'sichtbar' (Zugangsdaten in der Antwort), 'gesperrt' (kein Zugriff/nicht vorhanden), 'firewall' oder 'unklar'. Der Inhalt der Antwort wird nie weitergegeben."""
    if f.error:
        return "fehler"
    if waf_block(f):
        return "firewall"
    if f.status == 200 and API_SECRET_KEYS.search(f.body or "") and '"attributes"' in (f.body or ""):
        return "sichtbar"
    if f.status in (401, 403, 404, 405, 410) or (f.status == 200 and not API_SECRET_KEYS.search(f.body or "")):
        return "gesperrt"
    return "unklar"


@check(
    "joomla_api_exposure", G, "Joomla-API: Konfiguration ohne Anmeldung (CVE-2023-23752)",
    "Gibt die Joomla-Schnittstelle ohne Anmeldung die Zugangsdaten der Datenbank heraus?",
    what="Ruft EINMAL die Adresse /api/index.php/v1/config/application?public=true deiner Seite von DIESEM PC aus ab, aber nur bei Joomla 4.0.0 bis 4.2.7 oder wenn die Version unbekannt ist. "
         "Die Antwort wird nie angezeigt oder gespeichert; gemeldet wird nur, OB Zugangsdaten sichtbar sind.",
    why="Diese Lücke (CVE-2023-23752) lässt jeden Besucher die Datenbank-Zugangsdaten lesen und wird massenhaft ausgenutzt. Mit den Zugangsdaten sind Konten und Inhalte angreifbar.",
    reads="Ein einzelner normaler Seitenaufruf an deine eigene Domain. Es wird nichts verändert, und es werden keine Inhalte der Antwort gezeigt.",
    load="leicht", needs="web", presets=["hack"], cms="joomla",
)
def joomla_api_exposure(ctx, res):
    from .. import joomla
    from ..util import vcmp
    url = (ctx.s.url or "").strip()
    if not url:
        raise CheckSkipped("Keine Adresse der Webseite angegeben (Feld 'Webseite' in den Verbindungsdaten).")
    ver = ctx.shared.get("joomla_version") or ""
    if not ver and getattr(ctx, "runner", None) is not None:
        try:
            r = ctx.sh("head -c 8000 libraries/src/Version.php 2>/dev/null; echo '@@M'; head -c 4000 administrator/manifests/files/joomla.xml 2>/dev/null").out
            a, _, b = r.partition("@@M")
            ver = joomla.parse_joomla_version(a, b)
        except Exception:
            ver = ""
    if ver:
        if vcmp(ver, CVE_23752_FIRST) < 0:
            res.add("ok", "Joomla %s hat diese Schnittstelle nicht (sie gibt es erst ab 4.0)" % ver)
            return
        if vcmp(ver, CVE_23752_LAST) > 0:
            res.add("ok", "Joomla %s ist von CVE-2023-23752 nicht betroffen (behoben ab 4.2.8)" % ver, "Es wurde deshalb nichts abgerufen.")
            return
    url, _ = secure.to_https(url)
    ctx.progress("Rufe die API-Adresse einmal ab")
    f = fetch(url.rstrip("/") + API_CONFIG_PATH, UA_BROWSER, max_bytes=40_000, timeout=15)
    v = api_config_verdict(f)
    if v == "sichtbar":
        res.add("crit", "Zugangsdaten sichtbar: Die Joomla-API gibt die Konfiguration ohne Anmeldung heraus",
                "Jeder Besucher kann damit die Datenbank-Zugangsdaten abrufen (CVE-2023-23752). Die Antwort wird hier absichtlich nicht gezeigt.",
                [], "Sofort auf Joomla 4.2.8 oder neuer aktualisieren und danach das Datenbank-Passwort erneuern (Passwort beim Hoster ändern, dann in configuration.php eintragen). "
                "Weil die Zugangsdaten schon abrufbar waren, danach auch auf Fremdzugriffe prüfen.")
    elif v == "firewall":
        res.add("info", "Von einer Firewall blockiert, Ergebnis nicht aussagekräftig",
                "Die Antwort ist eine Sperrseite (%s). Ob die Schnittstelle selbst offen ist, ist damit nicht geklärt." % waf_block(f))
    elif v == "gesperrt":
        res.add("ok", "Die Konfiguration ist über die API ohne Anmeldung nicht abrufbar", "Version laut Prüfung: %s." % (ver or "unbekannt"))
    elif v == "fehler":
        raise CheckSkipped("Webseite nicht erreichbar: %s" % f.error)
    else:
        res.add("info", "Antwort der API nicht eindeutig (HTTP %s)" % f.status, "Die Schnittstelle liefert weder Zugangsdaten noch eine klare Sperre. Bitte Joomla aktualisieren.")
