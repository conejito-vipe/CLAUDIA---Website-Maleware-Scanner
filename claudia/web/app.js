/* CLAUDIA - Oberfläche (reines JavaScript, keine Fremdbibliotheken).
   Alle Texte vom Server werden ausschließlich als Text eingefügt (nie als HTML). */
"use strict";

const SEV_LABEL = { ok: "In Ordnung", info: "Hinweis", warn: "Bitte prüfen", crit: "Kritisch", error: "Fehlgeschlagen", skipped: "Übersprungen" };
const SEV_RANK = { crit: 0, warn: 1, error: 2, info: 3, skipped: 4, ok: 5 };
const STEPS = [["connect", "Verbindung"], ["tests", "Tests auswählen"], ["run", "Prüfung"], ["result", "Ergebnis"]];

const S = {
  init: null, step: "connect",
  form: { profile: "", host: "", port: "22", user: "", auth: "password", password: "", key_file: "", site_dir: "", url: "", save: false, profname: "" },
  conn: null, connError: null, busy: false, showPw: false, connJob: null,
  preset: "hack", sel: new Set(), opts: {}, set: { log_dir: "", allow_hosts: "", mask_ips: true }, open: new Set(),
  results: [], next: 0, plan: [], current: {}, running: false, summary: null, elapsed: 0, cancelled: false, runError: "",
  db: { custom: false, host: "", port: "", user: "", name: "", prefix: "", password: "", filled: false, busy: false, test: null, err: "" },
  actions: null, actState: {}, ls: { plan: null, busy: false, job: null, ok: false, err: "", joomla: true }, filter: null, timer: null, exported: null, exporting: false, revealed: false,
};

/* ------------------------------------------------------------------ Helfer */
/* Erkanntes System: nach dem Verbindungstest "joomla" oder "wordpress". Layout bleibt gleich, nur die Texte wechseln. */
const cmsId = () => ((S.conn && S.conn.cms) || (S.init && S.init.cms) || "joomla");
const isWP = () => cmsId() === "wordpress";
const cmsName = () => ({ wordpress: "WordPress", drupal: "Drupal", typo3: "TYPO3", contao: "Contao", prestashop: "PrestaShop", shopware: "Shopware" }[cmsId()] || "Joomla");
const cmsConfig = () => ({ wordpress: "wp-config.php", drupal: "settings.php", typo3: "settings.php", contao: ".env", prestashop: "parameters.php", shopware: ".env" }[cmsId()] || "configuration.php");
const cmsVersion = i => (i && i[cmsId()]) || "";
const cmsHasConfig = i => (cmsId() === "wordpress" ? i.wp_config : cmsId() === "drupal" ? i.drupal_config : cmsId() === "typo3" ? i.typo3_config : cmsId() === "contao" ? i.contao_config : cmsId() === "prestashop" ? i.prestashop_config : cmsId() === "shopware" ? i.shopware_config : i.config);
function h(tag, props, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k === "class") el.className = v;
    else if (k === "text") el.textContent = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (k === "value" || k === "checked" || k === "disabled" || k === "hidden" || k === "open") el[k] = v;
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const kid of kids.flat()) {
    if (kid === null || kid === undefined || kid === false) continue;
    el.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
  }
  return el;
}
const $ = (sel, root) => (root || document).querySelector(sel);

/* ------------------------------------------------------------------ Sprachen
   Deutsch ist die Quellsprache. Weitere Sprachen kommen als Katalog {deutscher Satz: Übersetzung} vom Server (claudia/lang/<code>.json).
   Übersetzt wird satzweise (gleiches Verfahren wie i18n.py). Alle Texte im Dokument, auch nachträglich eingefügte, laufen durch tr(). */
const L = { code: "de", exact: new Map(), tpl: [], cache: new Map(), obs: null };
const L_ABBR = ["z. B.", "d. h.", "u. a.", "u. U.", "z. T.", "i. d. R.", "s. o.", "s. u.", "o. ä.", "v. a.", "ca.", "bzw.", "evtl.", "ggf.", "Nr.", "usw.", "etc.", "inkl.", "vgl.", "max.", "min.", "ggü.", "Dr.", "Abs.", "Std.", "Sek."];
const L_PH = /%(?:\d+\$)?[-+ 0#]*\d*(?:\.\d+)?[sdifx]|\{\d*\}|\{[a-z_]+\}/g;
const L_BOUND = /(?<=[.!?:])(\s+)(?=[A-ZÄÖÜ0-9%{„"'(\[])/g;
const L_ARROW = /(\s+(?:->|<-|\|)\s+)/;
const L_DASH = /(\s+-\s+)/;
const L_ATTRS = ["title", "placeholder", "aria-label", "alt"];
const reEsc = x => x.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
function lAfterAbbr(before) {
  for (const a of L_ABBR) if (before.endsWith(a) && (before.length === a.length || !/[A-Za-z0-9ÄÖÜäöüß]/.test(before[before.length - a.length - 1]))) return true;
  const toks = before.split(/\s+/).filter(Boolean);
  return toks.length > 0 && /^[A-Za-zÄÖÜäöü]\.$/.test(toks[toks.length - 1].replace(/^[("'\[]+/, ""));
}
function splitSentences(text) {
  const out = [];
  text.split(/(\n+)/).forEach((line, i) => {
    if (i % 2) { out.push(line); return; }
    let pos = 0;
    for (const m of line.matchAll(L_BOUND)) {
      if (lAfterAbbr(line.slice(pos, m.index))) continue;
      out.push(line.slice(pos, m.index), m[1]);
      pos = m.index + m[1].length;
    }
    out.push(line.slice(pos));
  });
  return out;
}
function setCatalog(payload) {
  L.code = (payload && payload.code) || "de";
  L.exact = new Map(); L.tpl = []; L.cache = new Map();
  const msg = (payload && payload.msg) || {};
  for (const [k, v] of Object.entries(msg)) {
    if (!v || v === k) continue;
    const phs = k.match(L_PH);
    if (!phs) { L.exact.set(k, v); continue; }
    let rx = "", pos = 0, m;
    L_PH.lastIndex = 0;
    while ((m = L_PH.exec(k))) {
      rx += reEsc(k.slice(pos, m.index)) + (/^%.*[dif]$/.test(m[0]) ? "([-+]?\\d[\\d.,]*)" : "([\\s\\S]*?)");
      pos = m.index + m[0].length;
    }
    rx += reEsc(k.slice(pos));
    if (!/\{\d+\}/.test(v)) L.exact.set(k, v);
    L.tpl.push({ rx: new RegExp("^" + rx + "$"), v, lit: k.replace(L_PH, "").length });
  }
  L.tpl.sort((a, b) => b.lit - a.lit);
}
function lFill(v, groups) {
  if (/\{\d+\}/.test(v)) return v.replace(/\{(\d+)\}/g, (m, n) => (+n > 0 && +n <= groups.length ? groups[+n - 1] : m));
  let i = 0;
  return v.replace(L_PH, m => (i < groups.length ? groups[i++] : m));
}
function trOne(s) {
  if (L.exact.has(s)) return L.exact.get(s);
  for (const t of L.tpl) { const m = t.rx.exec(s); if (m) return lFill(t.v, m.slice(1).map(g => (g && g.length <= 120 && L.exact.has(g) ? L.exact.get(g) : g))); }
  if (L_ARROW.test(s)) return s.split(L_ARROW).map((p, i) => (i % 2 ? p : (p.trim() ? p.slice(0, p.indexOf(p.trim())) + trOne(p.trim()) + p.slice(p.indexOf(p.trim()) + p.trim().length) : p))).join("");
  if (L_DASH.test(s)) {
    const out = s.split(L_DASH).map((p, i) => (i % 2 ? p : (p.trim() ? p.slice(0, p.indexOf(p.trim())) + trOne(p.trim()) + p.slice(p.indexOf(p.trim()) + p.trim().length) : p))).join("");
    if (out !== s) return out;
  }
  const look = x => { const r = L.exact.get(x); if (r !== undefined) return r; for (const t of L.tpl) { const m = t.rx.exec(x); if (m) return lFill(t.v, m.slice(1)); } };
  const lm = /^([^:\n]{2,60}:)(\s+)(\S[\s\S]*)$/.exec(s);
  if (lm) {
    let lab = look(lm[1]);
    if (lab === undefined) { const b = look(lm[1].slice(0, -1)); if (b !== undefined) lab = b + ":"; }
    if (lab !== undefined) return lab + lm[2] + trOne(lm[3]);
  }
  for (const end of [".", ":"]) if (s.endsWith(end) && s.length > 2) { const r = look(s.slice(0, -1)); if (r !== undefined) return r + end; }
  return s;
}
function trCore(p) { const core = p.trim(); return core ? p.slice(0, p.indexOf(core)) + trOne(core) + p.slice(p.indexOf(core) + core.length) : p; }
function lMatch(x) {                                    // nur Schlüssel/Vorlage, ohne Ersatzstrategien
  if (L.exact.has(x)) return L.exact.get(x);
  for (const t of L.tpl) { const m = t.rx.exec(x); if (m) return lFill(t.v, m.slice(1).map(g => (g && g.length <= 120 && L.exact.has(g) ? L.exact.get(g) : g))); }
  return undefined;
}
function trSentences(parts) {                           // wie Catalog._sentences: bis zu 3 Nachbarsätze zusammen versuchen
  let out = "", i = 0; const n = parts.length;
  while (i < n) {
    let used = 1, res;
    if (parts[i].trim() && lMatch(parts[i].trim()) === undefined) {
      for (const span of [3, 2]) {
        const j = i + 2 * (span - 1);
        if (j < n) {
          const joined = parts.slice(i, j + 1).join(""), r = lMatch(joined.trim());
          if (r !== undefined) { const c = joined.trim(); res = joined.slice(0, joined.indexOf(c)) + r + joined.slice(joined.indexOf(c) + c.length); used = 2 * span - 1; break; }
        }
      }
    }
    out += res !== undefined ? res : trCore(parts[i]);
    i += used;
    if (i < n) { out += parts[i]; i++; }
  }
  return out;
}
function tr(text) {
  if (L.code === "de" || !text || typeof text !== "string") return text;
  const c = L.cache.get(text);
  if (c !== undefined) return c;
  let res = L.exact.get(text);
  if (res === undefined) res = trSentences(splitSentences(text));
  if (L.cache.size > 20000) L.cache.clear();
  L.cache.set(text, res);
  return res;
}
/* Jeder Textknoten und jedes Attribut merkt sich den deutschen Ursprungstext, damit beim Umschalten wieder neu übersetzt werden kann. */
const L_NODES = new WeakMap();
function lText(node) {
  const rec = L_NODES.get(node);
  const src = rec && node.data === rec.out ? rec.src : node.data;
  const out = tr(src);
  L_NODES.set(node, { src, out });
  if (node.data !== out) node.data = out;
}
function lAttrs(el) {
  let rec = L_NODES.get(el); if (!rec) { rec = {}; L_NODES.set(el, rec); }
  for (const a of L_ATTRS) {
    const cur = el.getAttribute(a);
    if (cur === null) continue;
    const r = rec[a];
    const src = r && cur === r.out ? r.src : cur;
    const out = tr(src);
    rec[a] = { src, out };
    if (cur !== out) el.setAttribute(a, out);
  }
}
function lWalk(root) {
  if (root.nodeType === 3) { lText(root); return; }
  if (root.nodeType !== 1 || /^(SCRIPT|STYLE|CODE|PRE|TEXTAREA)$/.test(root.tagName) || root.closest && root.closest("[data-nt]")) {
    if (root.nodeType === 1 && root.tagName === "TEXTAREA" && !root.closest("[data-nt]")) lAttrs(root);   // Platzhalter ja, Inhalt nein
    return;
  }
  lAttrs(root);
  for (const k of root.childNodes) lWalk(k);
}
function lStart() {
  if (L.obs) return;
  L.obs = new MutationObserver(list => {
    for (const m of list) {
      if (m.type === "characterData") lText(m.target);
      else if (m.type === "attributes") lAttrs(m.target);
      else m.addedNodes.forEach(n => lWalk(n));
    }
  });
  L.obs.observe(document.documentElement, { subtree: true, childList: true, characterData: true, attributes: true, attributeFilter: L_ATTRS });
}
function applyLang(payload) {
  setCatalog(payload);
  const m = (payload && payload.meta) || {};
  document.documentElement.lang = m.html || L.code;
  lStart();
  lWalk(document.body);
}
/* Dokumentation (Handbuch, Änderungen, Prüfkatalog mit Suche) im Hauptfenster, mit derselben Seitenleiste */
async function openHelp() {
  if (S.step !== "help") { S.helpBack = S.step; S.step = "help"; }
  render();
}
function viewHelp() {
  const box = h("div", { class: "help-view" }, loadingBox("Lade die Dokumentation …"));
  const back = () => { S.step = S.helpBack && S.helpBack !== "help" ? S.helpBack : "connect"; render(); };
  (async () => {
    try {
      if (!S.docs) S.docs = await api("/api/docs");
      box.replaceChildren();
      window.ClaudiaDocs.mount(box, S.docs, { onclose: back, loadTech: () => api("/api/techdoc") });
    } catch (e) { box.replaceChildren(h("p", { text: String(e.message || e.error || e) }), h("button", { class: "btn", type: "button", onclick: back }, "Zurück")); }
  })();
  return box;
}
function loadingBox(text) { return h("div", { class: "loader" }, h("i", { class: "spin", "aria-hidden": "true" }), h("span", { text })); }
/* Installation prüfen: fehlende oder veränderte Dateien des Originalpakets */
async function loadIntegrity() {
  try { S.integ = await api("/api/integritaet"); } catch (e) { S.integ = null; }
  if (S.integ && !S.integ.ok) render();
}
function integrityBanner() {
  const g = S.integ;
  if (!g.liste_da) return h("div", { class: "integ" }, h("h3", { text: "Installation nicht prüfbar" }),
    h("p", { class: "small", text: "Die Prüfsummenliste PRUEFSUMMEN.txt fehlt im Programmordner. Ohne sie lässt sich nicht feststellen, ob Dateien fehlen. Installiere CLAUDIA neu." }));
  const alle = [...g.fehlend.map(x => ["fehlt: ", x]), ...g.geaendert.map(x => ["verändert: ", x])];
  return h("div", { class: "integ" }, h("h3", { text: "Installation unvollständig oder verändert: " + g.fehlend_anzahl + " Datei(en) fehlen, " + g.geaendert_anzahl + " weichen ab" }),
    h("p", { class: "small", text: "Das kann passieren, wenn ein Virenscanner Dateien entfernt hat oder ein Update abgebrochen ist. Installiere CLAUDIA über das Setup neu. Deine Verbindungen, Einstellungen und Berichte bleiben erhalten." }),
    h("details", {}, h("summary", { text: "Betroffene Dateien anzeigen (" + alle.length + ")" }),
      h("ul", {}, alle.slice(0, 200).map(([a, b]) => h("li", {}, a, h("code", { text: b }))))));
}
/* Hilfefenster per Kopfzeile verschieben (bleibt im sichtbaren Bereich) */
function helpDrag(dlg, box) {
  const head = box.querySelector(".docs-head");
  if (!head || head.dataset.drag) return;
  head.dataset.drag = "1";
  head.addEventListener("pointerdown", ev => {
    if (ev.button !== 0 || ev.target.closest("input, button, a, textarea, select")) return;
    const r = dlg.getBoundingClientRect(), dx = ev.clientX - r.left, dy = ev.clientY - r.top;
    dlg.style.inset = "auto"; dlg.style.left = r.left + "px"; dlg.style.top = r.top + "px"; dlg.style.width = r.width + "px"; dlg.style.height = r.height + "px";
    head.setPointerCapture(ev.pointerId);
    const move = e => {
      const x = Math.min(Math.max(e.clientX - dx, 80 - r.width), window.innerWidth - 80), y = Math.min(Math.max(e.clientY - dy, 0), window.innerHeight - 40);
      dlg.style.left = x + "px"; dlg.style.top = y + "px";
    };
    const up = () => { head.removeEventListener("pointermove", move); head.removeEventListener("pointerup", up); head.removeEventListener("pointercancel", up); };
    head.addEventListener("pointermove", move); head.addEventListener("pointerup", up); head.addEventListener("pointercancel", up);
  });
}
/* ------------------------------------------------------------------ Deinstallation */
async function openUninstall() {
  const dlg = $("#unidlg"), box = $("#uni-body");
  const xbtn = () => h("button", { class: "dlg-x", type: "button", title: "Schließen", "aria-label": "Schließen", onclick: () => dlg.close(), text: "\u2715" });
  const frame = (title, scroll, foot) => box.replaceChildren(
    h("div", { class: "uni-head" }, h("h2", { text: title }), xbtn()),
    h("div", { class: "uni-scroll" }, scroll),
    foot ? h("div", { class: "uni-foot" }, foot) : null);
  frame("Programm deinstallieren", h("p", { text: "…" }));
  if (!dlg.open) dlg.showModal();
  let plan;
  try { plan = await api("/api/uninstall-plan"); } catch (e) { frame("Programm deinstallieren", h("p", { text: e.error || "Nicht möglich." })); return; }
  const chosen = new Set(plan.items.filter(i => i.exists && i.default).map(i => i.id));
  const ok = h("input", { type: "checkbox", id: "uni-ok" });
  const go = h("button", { class: "btn danger-fill", type: "button", disabled: true }, "Jetzt deinstallieren");
  const sync = () => { go.disabled = !(ok.checked && chosen.size); };
  ok.addEventListener("change", sync);
  const rows = plan.items.map(i => h("label", { class: "uni-row" + (i.exists ? "" : " gone") },
    h("input", { type: "checkbox", checked: chosen.has(i.id), disabled: !i.exists, onchange: e => { e.target.checked ? chosen.add(i.id) : chosen.delete(i.id); sync(); } }),
    h("span", {}, h("b", { text: i.label }), i.personal ? h("span", { class: "docs-tag", text: " deine Daten" }) : null,
      h("span", { class: "hint", text: i.exists ? (i.kind === "winget" ? i.path : i.path + "  (" + fmtSize(i.bytes || 0) + ", " + i.files + " Dateien)") : "nicht vorhanden" }),
      h("span", { class: "hint", text: i.why }))));
  go.addEventListener("click", async () => {
    go.disabled = true;
    try {
      const r = await api("/api/uninstall-run", { ids: [...chosen], confirm: ok.checked });
      frame("Deinstallation läuft", h("p", { text: "Das Programm wird jetzt beendet. Ein Fenster zeigt, was entfernt wird (" + r.count + " Einträge). Dieses Browserfenster kann geschlossen werden." }));
    } catch (e) { toast(e.error || "Nicht möglich."); sync(); }
  });
  frame("Programm deinstallieren", [
    h("p", { text: "Hier siehst du alles, was dieses Programm auf deinem PC angelegt hat. Angehakte Einträge werden gelöscht, sobald das Programm beendet ist. Auf dem Server ändert das nichts. Deine Daten (Verbindungen, Berichte) und der Programmordner sind nicht vorgewählt." }),
    h("div", { class: "uni-list" }, rows),
    h("label", { class: "check" }, ok, h("span", { text: "Ich habe die Liste gelesen und möchte die angehakten Einträge unwiderruflich löschen." }))],
    h("div", { class: "dlg-actions" }, h("button", { class: "btn ghost", type: "button", onclick: () => dlg.close() }, "Abbrechen"), go));
}

function renderLangs() {
  const box = $("#langs"); if (!box) return;
  box.replaceChildren();
  const langs = (S.init && S.init.langs) || [];
  if (langs.length < 2) { box.hidden = true; return; }
  box.hidden = false;
  for (const l of langs) {
    const b = h("button", { class: "lang" + (l.code === L.code ? " on" : ""), type: "button", title: l.name, "data-nt": "1", "aria-label": l.name, "aria-pressed": l.code === L.code ? "true" : "false",
      disabled: S.running, onclick: () => switchLang(l.code) });
    b.innerHTML = l.flag || "";
    if (!l.flag) b.textContent = l.code.toUpperCase();
    box.append(b);
  }
}
async function switchLang(code) {
  if (S.running || code === L.code) return;
  try {
    await api("/api/lang", { lang: code });
    const [init, cat] = await Promise.all([api("/api/init"), api("/api/lang")]);
    S.init = init;
    if (S.conn && init.connected) S.conn = init.info;
    if (S.results.length) { const st = await api("/api/state?since=0"); S.results = st.results; S.next = st.next; S.summary = st.summary; S.plan = st.plan; S.hoster = st.hoster || null; }
    S.actions = null;
    applyLang(cat);
    render();
  } catch (e) { toast(e.error || "Die Sprache konnte nicht gewechselt werden."); }
}

/* Technisches Icon-Set (Linien-Symbole): Quelle ist icons.json, geliefert über /api/init */
function ic(name) {
  const inner = ((S.init && S.init.icons) || {})[name];
  if (!inner) return null;
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", "0 0 24 24"); svg.setAttribute("class", "ic"); svg.setAttribute("aria-hidden", "true"); svg.setAttribute("focusable", "false");
  svg.innerHTML = inner;
  return svg;
}
// Zeile mit "N von 5 Sternen" bzw. "N of 5 stars": die Zahl wird als Sternreihe gezeichnet (Anteil gefüllt), der Rest bleibt Text.
const RATING_RE = /(\d+(?:[.,]\d+)?) (?:von|of) 5 (?:Sternen|stars)/;
function ratingLine(t) {
  const m = RATING_RE.exec(t);
  if (!m) {
    const u = /https:\/\/[^\s<>"')]+/.exec(t);                         // https-Adressen in Hinweisen anklickbar machen (öffnet im normalen Browser)
    if (!u) return h("li", { text: t });
    return h("li", {}, t.slice(0, u.index), h("a", { href: u[0], target: "_blank", rel: "noopener noreferrer", text: u[0] }), t.slice(u.index + u[0].length));
  }
  const v = Math.max(0, Math.min(5, parseFloat(m[1].replace(",", "."))));
  const stars = h("span", { class: "stars", style: "--v:" + (v * 20) + "%", title: m[1] + " / 5", "aria-label": m[1] + " / 5" , text: "★★★★★" });
  return h("li", { class: "rated" }, t.slice(0, m.index), stars, h("b", { class: "rnum", text: m[1] + "/5" }), t.slice(m.index + m[0].length));
}

function badge(sev, text, style) {
  return h("span", { class: "badge", "data-s": sev, style }, ic(sev), text);
}

async function api(path, body) {
  const opt = { headers: { "X-Claudia": "1" } };
  if (body !== undefined) { opt.method = "POST"; opt.headers["Content-Type"] = "application/json"; opt.body = JSON.stringify(body); }
  let r;
  try { r = await fetch(path, opt); } catch (e) { throw { error: "Das Programm im Hintergrund antwortet nicht mehr. Bitte das Programm schließen und mit start.bat bzw. start.command neu starten." }; }
  const data = await r.json().catch(() => ({ error: "Unerwartete Antwort." }));
  if (!r.ok) throw data;
  return data;
}

let toastTimer = null;
function toast(msg) {
  const t = $("#toast"); t.textContent = msg; t.hidden = false;
  clearTimeout(toastTimer); toastTimer = setTimeout(() => { t.hidden = true; }, 3500);
}
const plural = (n, one, many) => n + " " + (n === 1 ? one : many);
const checkById = id => S.init.checks.find(c => c.id === id);

/* ------------------------------------------------------------------ Rahmen */
/* Verbindungsanzeige: erst der Profilname, dann die Serveradresse; ohne Profilname nur die Serveradresse */
function connLabel() {
  const c = S.conn;
  if (!c || c.mode === "none") return c && c.host ? tr("Externer Modus") + " · " + c.host : tr("Ohne Serverzugang");
  const profs = S.init.profiles || {};
  let name = S.form.profile && profs[S.form.profile] && profs[S.form.profile].host === c.host ? S.form.profile : "";
  if (!name) name = Object.keys(profs).find(n => profs[n].host === c.host && (profs[n].user || "") === (c.user || "")) || "";
  return name ? name + " · " + c.host : c.host;
}
/* Kopfzeile, Seitenleiste und Fußleiste: Titel, Verbindung, Sprache, Hilfe */
function viewTitle() {
  if (S.step === "dash") return "Dashboard";
  if (S.step === "help") return "Hilfe und Handbuch";
  const i = STEPS.findIndex(s => s[0] === S.step);
  return i >= 0 ? "Schritt " + (i + 1) + " von " + STEPS.length + ": " + STEPS[i][1] : "CLAUDIA";
}
const STEP_ICON = { connect: "⇄", tests: "☑", run: "▶", result: "⚑" };
function renderFrame() {
  renderLangs();
  $("#tb-ver").textContent = S.init.version;
  const ub = $("#uninstall"), bar = $("#uni-bar");
  if (ub.parentElement !== bar) bar.append(ub);                     // aus der Verbindungsansicht zurückholen, bevor diese abgebaut wird
  bar.hidden = S.step !== "result";
  const c = $("#conn");
  if (S.conn) { c.hidden = false; $("#conn-text").textContent = connLabel(); } else c.hidden = true;
  $("#foot-off").textContent = S.conn ? connLabel() + " · " + tr("nur lesend") : tr("Nicht verbunden");
  document.querySelector("#sbar .sdot").classList.toggle("on", !!S.conn);
  $("#tb-title").textContent = viewTitle();
  $("#dashbtn").classList.toggle("on", S.step === "dash");
  $("#help").classList.toggle("on", S.step === "help");
  const order = STEPS.map(s => s[0]);
  const cur = order.indexOf(S.step);
  const reach = { connect: true, tests: !!S.conn, run: S.running || S.results.length > 0, result: !S.running && S.results.length > 0 };
  const nav = $("#steps"); nav.replaceChildren();
  STEPS.forEach(([id, label], i) => {
    const done = i < cur && reach[id];
    const b = h("button", {
      class: "step" + (i === cur ? " on" : "") + (done ? " done" : ""), type: "button",
      "aria-current": i === cur ? "step" : false, disabled: !(done || i === cur),
      onclick: () => { if (done) go(id); },
    }, h("span", { class: "n", "aria-hidden": "true", text: done ? "✓" : STEP_ICON[id] }), label);
    nav.append(b);
  });
}

/* Im Programmfenster (eigene Titelleiste) scrollt der Seitenkörper, sonst das Dokument. */
function scroller() { return document.documentElement.classList.contains("has-titlebar") ? document.body : (document.scrollingElement || document.documentElement); }
function go(step) {
  S.step = step; render();
  scroller().scrollTo(0, 0);
}

function render() {
  const keepY = scroller().scrollTop;
  renderFrame();
  const v = $("#view"); v.replaceChildren();
  if (S.integ && !S.integ.ok && S.step !== "help") v.append(integrityBanner());
  if (S.step === "connect") v.append(viewConnect());
  else if (S.step === "tests") v.append(viewTests());
  else if (S.step === "run") v.append(viewRun());
  else if (S.step === "dash") v.append(viewDashboard());
  else if (S.step === "help") v.append(viewHelp());
  else v.append(viewResult());
  radarSync();
  scroller().scrollTo(0, keepY);
}

/* ------------------------------------------------------------------ 1. Verbindung */
function field(label, input, hint, id) {
  return h("div", { class: "field" }, h("label", { for: id, text: label }), input, hint ? h("div", { class: "hint", text: hint }) : null);
}
function bind(el, key) {
  el.addEventListener("input", () => { S.form[key] = el.type === "checkbox" ? el.checked : el.value; });
  return el;
}

const SB_KEY_URL = "https://developers.google.com/safe-browsing/v4/get-started";
function viewConnect() {
  const f = S.form, profiles = S.init.profiles || {};
  const root = h("div", {});
  root.append(h("h1", { text: "Mit dem Server verbinden" }),
    h("p", { class: "lead", text: "Trage die SSH-Zugangsdaten deines Hosters ein. Das Programm liest nur und ändert nichts auf dem Server." }));

  const card = h("div", { class: "card" });
  const names = Object.keys(profiles);
  if (names.length) {
    const sel = h("select", { id: "f-profile", "aria-label": "Gespeichertes Profil" },
      h("option", { value: "", text: "Neues Profil" }), names.map(n => h("option", { value: n, text: n, selected: f.profile === n })));
    sel.addEventListener("change", () => loadProfile(sel.value));
    card.append(h("div", { class: "field" }, h("label", { for: "f-profile", text: "Gespeicherte Profile" }),
      h("div", { class: "actions", style: "margin:0" }, h("div", { style: "flex:1;min-width:200px" }, sel),
        f.profile ? h("button", { class: "btn ghost", type: "button", onclick: () => deleteProfile(f.profile) }, "Profil löschen") : null)));
  }
  const host = bind(h("input", { type: "text", id: "f-host", value: f.host, autocomplete: "off", spellcheck: "false", placeholder: "z. B. ssh.beispiel.de" }), "host");
  const port = bind(h("input", { type: "number", id: "f-port", value: f.port, min: "1", max: "65535" }), "port");
  card.append(h("div", { class: "row" }, field("Server (Host)", host, "", "f-host"), field("Port", port, "", "f-port")));
  card.append(field("Benutzername", bind(h("input", { type: "text", id: "f-user", value: f.user, autocomplete: "off", spellcheck: "false" }), "user"), "", "f-user"));

  const seg = h("div", { class: "seg", role: "group", "aria-label": "Anmeldeart" },
    ["password", "key"].map(k => h("button", { type: "button", "aria-pressed": String(f.auth === k),
      onclick: () => { f.auth = k; render(); }, text: k === "password" ? "Passwort" : "Schlüsseldatei" })));
  card.append(h("div", { class: "field" }, h("span", { class: "lbl", text: "Anmeldung" }), seg));

  if (f.auth === "password") {
    const pw = bind(h("input", { type: S.showPw ? "text" : "password", id: "f-pw", value: f.password, autocomplete: "off" }), "password");
    card.append(field("Passwort", h("div", { class: "pw" }, pw,
      h("button", { class: "link", type: "button", onclick: () => { S.showPw = !S.showPw; pw.type = S.showPw ? "text" : "password"; event.target.textContent = S.showPw ? "verbergen" : "anzeigen"; } }, S.showPw ? "verbergen" : "anzeigen")),
      "Das Passwort bleibt nur im Arbeitsspeicher und wird weder gespeichert noch exportiert.", "f-pw"));
  } else {
    card.append(field("Pfad zur Schlüsseldatei", bind(h("input", { type: "text", id: "f-key", value: f.key_file, placeholder: "C:\\Users\\Name\\.ssh\\id_ed25519" }), "key_file"), "", "f-key"));
    card.append(field("Passwort der Schlüsseldatei (falls vorhanden)", bind(h("input", { type: "password", id: "f-kp", value: f.password, autocomplete: "off" }), "password"), "", "f-kp"));
  }

  const dl = h("datalist", { id: "folders" }, ((S.conn && S.conn.folders) || []).map(x => h("option", { value: x })));
  card.append(field("Verzeichnis der Webseite auf dem Server (Joomla, WordPress, Drupal, TYPO3, Contao, PrestaShop oder Shopware)", h("div", {}, bind(h("input", { type: "text", id: "f-dir", value: f.site_dir, list: "folders", autocomplete: "off", spellcheck: "false", placeholder: "z. B. html oder htdocs/meineseite" }), "site_dir"), dl),
    "Der Ordner mit configuration.php (Joomla), wp-config.php (WordPress), sites/default/settings.php (Drupal), config/system/settings.php bzw. typo3conf (TYPO3) oder .env bzw. config/parameters.yaml (Contao), relativ zum Login-Ordner. Nach dem ersten Verbindungstest schlägt das Programm vorhandene Ordner vor.", "f-dir"));
  card.append(field("Adresse der Webseite (optional)", bind(h("input", { type: "text", id: "f-url", value: f.url, placeholder: "https://www.google.de" }), "url"),
    "Für die Prüfung aus Besuchersicht (Weiterleitungen, fremder Code, offene Ordner). Das Programm ruft Webseiten nur verschlüsselt (https) ab; eine Adresse mit http:// wird automatisch auf https umgestellt.", "f-url"));

  const sbSet = v => { (S.opts.safe_browsing = S.opts.safe_browsing || {}).api_key = v; };
  card.append(field("Google-Safe-Browsing-Schlüssel (optional)", h("input", { type: "password", id: "f-sb", value: (S.opts.safe_browsing || {}).api_key || "", autocomplete: "off", spellcheck: "false", oninput: e => sbSet(e.target.value) }),
    "Damit fragt das Programm bei Google ab, ob deine Webseite auf der Sperrliste für Schadsoftware und Phishing steht. Dabei geht nur die Adresse deiner Seite an Google. Der Schlüssel ist kostenlos (Google Cloud Console, Safe Browsing API aktivieren). Er bleibt nur im Arbeitsspeicher, wird nie gespeichert und nie in Berichte übernommen.", "f-sb"));
  card.lastChild.querySelector(".hint").append(" ", h("a", { href: SB_KEY_URL, target: "_blank", rel: "noopener noreferrer", text: "Kostenlosen Schlüssel erstellen (Anleitung von Google)" }));

  card.append(h("label", { class: "check" }, bind(h("input", { type: "checkbox", checked: f.save }), "save"),
    h("span", {}, "Diese Einstellungen als Profil speichern (ohne Passwort)")));
  const pn = bind(h("input", { type: "text", id: "f-pn", value: f.profname, placeholder: "Profilname, z. B. Meine Webseite" }), "profname");
  card.append(h("div", { class: "field", style: "margin-top:10px" }, pn));

  if (S.connError) card.append(h("div", { class: "notice err", role: "alert" }, h("div", {}, h("strong", { text: "Verbindung nicht möglich" }), S.connError.error,
    S.connError.known ? h("div", { class: "mono", text: "Bisher bekannt: " + S.connError.known }) : null,
    S.connError.seen ? h("div", { class: "mono", text: "Jetzt gesehen: " + S.connError.seen }) : null)));
  if (S.busy) card.append(connectProgress());
  card.append(h("div", { class: "actions" },
    h("button", { class: "btn primary", type: "button", disabled: S.busy, onclick: () => testConnection() }, S.busy ? "Verbindungstest läuft ..." : "Verbindung testen"),
    h("button", { class: "link", type: "button", disabled: S.busy, onclick: () => noServer() }, "Externer Modus (ohne Serverzugang)")));

  const side = h("div", { class: "side" });
  side.append(h("div", { class: "card" }, h("h2", { text: "So geht das Programm mit deinen Daten um" }),
    h("ul", { class: "promise" },
      h("li", {}, h("b", { text: "Nur lesen" }), "Es werden ausschließlich lesende Befehle ausgeführt. Dateien und Datenbank bleiben unverändert."),
      h("li", {}, h("b", { text: "Alles bleibt auf diesem PC" }), "Die Oberfläche läuft lokal. Es gibt keinen Dienst im Internet außer deinem Server."),
      h("li", {}, h("b", { text: "Passwörter werden nicht gespeichert" }), "Weder im Profil noch in den Berichten. Zugangsdaten aus der configuration.php werden in Ergebnissen unkenntlich gemacht."),
      h("li", {}, h("b", { text: "Server wird geprüft" }), "Beim ersten Mal bestätigst du den Fingerabdruck des Servers. Ändert er sich später, warnt das Programm."))));
  if (S.conn && S.conn.mode !== "none") side.append(connectionCard());

  /* Deinstallieren steht rechts neben dem Kasten, auf der Höhe von "Verbindung testen" */
  const slot = h("div", { class: "uni-slot" });
  slot.append($("#uninstall"));
  side.append(slot);
  root.append(h("div", { class: "grid2 stretch" }, card, side));
  return root;
}

/* Offizielles Logo des erkannten Systems (wird vom Server des Projekts geladen; ohne Internet bleibt nur der Name) */
async function loadCmsLogo() {
  const id = cmsId();
  S.logos = S.logos || {};
  if (S.logos[id] !== undefined) return;
  S.logos[id] = "";
  try { const r = await api("/api/cms-logo"); S.logos[id] = r.image || ""; } catch (e) { S.logos[id] = ""; }
  if (S.logos[id] && S.step === "connect") render();
}
function cmsBadge(text) {
  const src = (S.logos || {})[cmsId()];
  return h("span", { class: "cmsbadge" }, src ? h("img", { class: "cmslogo", src, alt: cmsName() + "-Logo", height: "28" }) : null, h("span", { text }));
}
function connectionCard() {
  const i = S.conn;
  const card = h("div", { class: "card" });
  if (!i.site_found) {
    card.append(h("h2", { text: "Verbunden, aber Ordner nicht gefunden" }),
      h("p", { class: "sub", text: i.error || "Im angegebenen Ordner wurde weder Joomla, WordPress, Drupal, TYPO3, Contao, PrestaShop noch Shopware erkannt." }));
    if (i.folders && i.folders.length) {
      card.append(h("p", { class: "small", text: "Ordner im Login-Verzeichnis (zum Übernehmen anklicken):" }),
        h("div", { class: "tags", style: "justify-content:flex-start" }, i.folders.slice(0, 30).map(x =>
          h("button", { class: "tag", type: "button", style: "cursor:pointer", onclick: () => { S.form.site_dir = x; testConnection(); } }, x))));
    }
    return card;
  }
  card.append(h("h2", { text: "Verbindung steht" }));
  loadCmsLogo();
  card.append(h("dl", { class: "facts" },
    h("dt", { text: "System" }), h("dd", {}, cmsBadge(cmsName() + " " + (cmsVersion(i) || "(Version nicht erkannt)"))),
    h("dt", { text: "Verschlüsselung" }), h("dd", {}, ic("lock"), encryptionText(i.security)),
    h("dt", { text: "PHP der Webseite" }), h("dd", { text: i.php_web ? i.php_web + "  (erkannt über: " + i.php_web_source + ")" : "nicht erkannt" }),
    h("dt", { text: "PHP Kommandozeile" }), h("dd", { text: i.php || "nicht erkannt" }),
    h("dt", { text: "Datenbank-Programm" }), h("dd", { text: i.mysql ? "vorhanden (" + (i.mysql_path || "mysql") + ")" : "nicht gefunden (Datenbanktests liefern SQL für phpMyAdmin)" }),
    h("dt", { text: "Konfiguration" }), h("dd", { text: cmsHasConfig(i) ? cmsConfig() + " vorhanden" : "fehlt" }),
    h("dt", { text: "Angemeldet als" }), h("dd", { text: i.who || i.user }),
    h("dt", { text: "Ordner" }), h("dd", { class: "mono", text: i.pwd || i.site_dir })));
  if (!i.php_web) card.append(h("div", { class: "notice info" }, h("div", {}, h("strong", { text: "PHP-Version der Webseite: nicht erkannt" }),
    (i.php_web_note || "Weder die Webseite noch der Server verraten sie.") + " Das Programm rät nichts. Für Updates über die Kommandozeile wählst du später das PHP-Programm aus einer Liste.")));
  if (!cmsVersion(i)) card.append(h("div", { class: "notice warn" }, h("div", {}, h("strong", { text: "Keine " + cmsName() + "-Version erkannt" }), "Bitte prüfe, ob der Ordner stimmt.")));
  if (cmsId() === "drupal") card.append(h("div", { class: "notice info" }, h("div", {}, h("strong", { text: "Drupal erkannt" }), "Das Programm zeigt jetzt die Drupal-Prüfungen (Drupal 8 und neuer). Lösungen auf Knopfdruck gibt es für Drupal noch nicht; die Prüfungen sind rein lesend.")));
  if (cmsId() === "typo3") card.append(h("div", { class: "notice info" }, h("div", {}, h("strong", { text: "TYPO3 erkannt" }), "Das Programm zeigt jetzt die TYPO3-Prüfungen (TYPO3 11 und neuer). Lösungen auf Knopfdruck gibt es für TYPO3 noch nicht; die Prüfungen sind rein lesend.")));
  if (cmsId() === "contao") card.append(h("div", { class: "notice info" }, h("div", {}, h("strong", { text: "Contao erkannt" }), "Das Programm zeigt jetzt die Contao-Prüfungen (Contao 4.13 und neuer). Lösungen auf Knopfdruck gibt es für Contao noch nicht; die Prüfungen sind rein lesend.")));
  if (cmsId() === "shopware") card.append(h("div", { class: "notice info" }, h("div", {}, h("strong", { text: "Shopware erkannt" }), "Das Programm zeigt jetzt die Shopware-Prüfungen (Shopware 6.5 und neuer). Lösungen auf Knopfdruck gibt es für Shopware noch nicht; die Prüfungen sind rein lesend.")));
  if (cmsId() === "prestashop") card.append(h("div", { class: "notice info" }, h("div", {}, h("strong", { text: "PrestaShop erkannt" }), "Das Programm zeigt jetzt die PrestaShop-Prüfungen (PrestaShop 1.7, 8 und 9). Lösungen auf Knopfdruck gibt es für PrestaShop noch nicht; die Prüfungen sind rein lesend.")));
  if (isWP()) card.append(h("div", { class: "notice info" }, h("div", {}, h("strong", { text: "WordPress erkannt" }), "Das Programm zeigt jetzt die WordPress-Prüfungen und -Lösungen. Aufbau und Ablauf sind wie bei Joomla.")));
  card.append(h("div", { class: "actions", style: "margin-top:16px" }, h("button", { class: "btn primary", type: "button", onclick: () => goTests() }, "Weiter zur Testauswahl")));
  return card;
}

/* Wie ist die Verbindung zum Server geschützt? */
function encryptionText(sec) {
  if (!sec) return "SSH (verschlüsselt)";
  if (sec.local) return "keine (nur Test auf diesem Rechner)";
  const parts = ["SSH, verschlüsselt"];
  if (sec.cipher) parts.push(sec.cipher);
  if (sec.host_key_type) parts.push("Serverschlüssel " + sec.host_key_type);
  let t = parts.join(", ");
  if (sec.fingerprint) t += "  |  Fingerabdruck " + sec.fingerprint;
  if (sec.weak_fallback || (sec.weak && sec.weak.length)) t += "  |  ACHTUNG: Der Server kann nur veraltete Verfahren. Bitte beim Hoster nachfragen.";
  return t;
}
function formData() {
  const f = S.form;
  return { host: f.host, port: f.port, user: f.user, auth: f.auth, key_file: f.key_file, site_dir: f.site_dir, url: f.url,
    log_dir: S.set.log_dir, allow_hosts: S.set.allow_hosts, mask_ips: S.set.mask_ips };
}

const sleep = ms => new Promise(r => setTimeout(r, ms));

function connectProgress() {
  const first = ["Mit dem Server verbinden", "Ordner auflisten", "Joomla, WordPress, Drupal, TYPO3, Contao, PrestaShop oder Shopware erkennen", "Datenbank-Programm suchen", "PHP-Version ermitteln"]
    .map((label, i) => ({ label, state: i === 0 ? "run" : "todo" }));
  const j = S.connJob || { limit: 45, remaining: 45, steps: first, msg: "Verbinde mit dem Server ..." };
  const pct = Math.max(0, Math.min(100, 100 * j.remaining / j.limit));
  const low = j.remaining <= 10;
  return h("div", { class: "cprog" + (low ? " low" : ""), id: "cprog", role: "status", "aria-live": "polite" },
    h("div", { class: "cprog-head" },
      h("b", { text: j.msg || "Verbinde ..." }),
      h("span", { class: "cprog-time", text: "Zeitlimit: noch " + Math.ceil(j.remaining) + " s" })),
    h("div", { class: "cprog-bar", "aria-hidden": "true" }, h("i", { style: "width:" + pct + "%" })),
    h("ul", { class: "cprog-steps" }, (j.steps || []).map(st => h("li", { class: st.state },
      h("span", { class: "dot", "aria-hidden": "true" }), st.label))),
    h("div", { class: "hint", text: "Bricht der Test nach Ablauf der Zeit ab, steht die Ursache darunter. Du kannst ihn auch selbst abbrechen." }),
    h("button", { class: "btn ghost", type: "button", onclick: cancelConnect }, "Abbrechen"));
}
function updateConnProgress() {
  const old = $("#cprog"); if (!old) return;
  old.replaceWith(connectProgress());
}
async function cancelConnect() { try { await api("/api/connect-cancel", {}); } catch (e) { /* egal */ } }

async function waitForConnect() {
  for (;;) {
    await sleep(350);
    const st = await api("/api/connect-state");
    S.connJob = st; updateConnProgress();
    if (st.done) { if (st.error) throw st.error; return st.result; }
  }
}

async function testConnection(trustFp, weak) {
  const f = S.form;
  S.busy = true; S.connError = null; S.connJob = null; render();
  try {
    await api("/api/connect", { ...formData(), password: f.password, trust_fp: trustFp || "", allow_weak: weak === true });
    const r = await waitForConnect();
    S.busy = false;
    if (r.need_weak) {
      const ok = await askWeak(r.detail);
      if (ok) return testConnection(trustFp, true);
      S.connError = { error: "Verbindung abgebrochen: Der Server bietet nur veraltete Verschlüsselung an." }; render(); return;
    }
    if (r.need_trust) {
      const ok = await askTrust(r.host_id, r.fingerprint);
      if (ok) return testConnection(r.fingerprint, weak);
      S.connError = { error: "Verbindung abgebrochen, der Server wurde nicht bestätigt." }; render(); return;
    }
    S.conn = r.info;
    await reloadInit();
    if (f.save && f.profname.trim()) {
      const p = await api("/api/profile/save", { name: f.profname.trim(), data: formData() });
      S.init.profiles = p.profiles; f.profile = f.profname.trim(); toast("Profil gespeichert (ohne Passwort).");
    }
    render();
  } catch (e) {
    S.busy = false; S.conn = null; S.connJob = null;
    if (e && e.kind === "cancelled") { toast("Verbindungstest abgebrochen."); } else { S.connError = e; }
    render();
  }
}

function askWeak(detail) {
  return new Promise(resolve => {
    const d = $("#weakdlg");
    $("#weak-detail").textContent = detail || "";
    d.addEventListener("close", () => resolve(d.returnValue === "yes"), { once: true });
    d.returnValue = "no"; d.showModal();
  });
}

function askTrust(hostId, fp) {
  return new Promise(resolve => {
    const d = $("#trust");
    $("#trust-host").textContent = hostId; $("#trust-fp").textContent = fp;
    d.addEventListener("close", () => resolve(d.returnValue === "yes"), { once: true });
    d.returnValue = "no"; d.showModal();
    $("#trust-yes").focus();
  });
}

async function noServer() {
  const url = (S.form.url || "").trim();
  if (!url) { S.connError = { error: "Für den externen Modus bitte die Adresse der Webseite eintragen (Feld „Adresse der Webseite“)." }; render(); return; }
  try {
    S.busy = true; S.connError = null; render();
    const r = await api("/api/connect", { mode: "none", url });
    S.busy = false;
    S.conn = r.info || { mode: "none" };
    await reloadInit();
    const d = S.conn.detected || {};
    toast(d.cms ? tr("Erkannt:") + " " + d.name + (d.version ? " " + d.version : "") : tr("Das System wurde nicht erkannt; bitte unter „Prüfungen“ prüfen."));
    goTests();
  } catch (e) { S.busy = false; S.connError = e; render(); }
}

function loadProfile(name) {
  const p = (S.init.profiles || {})[name];
  const f = S.form;
  f.profile = name; f.password = "";
  if (p) {
    Object.assign(f, { host: p.host || "", port: String(p.port || 22), user: p.user || "", auth: p.auth || "password", key_file: p.key_file || "",
      site_dir: p.site_dir || "", url: p.url || "", profname: name, save: true });
    S.set.log_dir = p.log_dir || ""; S.set.allow_hosts = p.allow_hosts || ""; S.set.mask_ips = p.mask_ips !== false;
  }
  render();
}
async function deleteProfile(name) {
  const r = await api("/api/profile/delete", { name });
  S.init.profiles = r.profiles; S.form.profile = ""; toast("Profil gelöscht."); render();
}

async function quitApp() {
  if (!confirm(tr("Das Programm jetzt beenden?\n\nDie Verbindung zum Server wird getrennt. Gespeicherte Berichte und Protokolle bleiben erhalten."))) return;
  try { await api("/api/quit", {}); } catch (e) { /* Server endet, Antwort kann fehlen */ }
  document.body.innerHTML = '<main style="max-width:36rem;margin:12vh auto;padding:0 16px;font:16px/1.5 system-ui,sans-serif"><h1>Das Programm wurde beendet.</h1><p>Du kannst dieses Browserfenster schließen. Zum erneuten Starten die Startdatei doppelklicken.</p></main>';
}

/* Prüfungen und Texte hängen vom erkannten System ab (Joomla oder WordPress): nach Verbindung/Trennung neu laden */
async function reloadInit() {
  try {
    const n = await api("/api/init");
    S.init = Object.assign(S.init || {}, { cms: n.cms, cms_name: n.cms_name, groups: n.groups, clusters: n.clusters, checks: n.checks });
    S.sel = new Set(); S.preset = null;
  } catch (e) { /* alte Liste bleibt */ }
}
async function disconnect() {
  await api("/api/disconnect", {});
  S.db = { custom: false, host: "", port: "", user: "", name: "", prefix: "", password: "", filled: false, busy: false, test: null, err: "" };
  S.conn = null; S.results = []; S.next = 0; S.summary = null; S.hoster = null; S.form.password = "";
  await reloadInit();
  go("connect");
}

/* ------------------------------------------------------------------ 2. Testauswahl */
function applyPreset(id) {
  S.preset = id;
  S.sel = new Set(S.init.checks.filter(c => c.presets.includes(id) && usable(c)).map(c => c.id));
}
function usable(c) { return !(S.conn && S.conn.mode === "none" && !(c.extern || c.needs === "local")); }
function goTests() { if (!S.sel.size) applyPreset(S.conn && S.conn.mode === "none" ? "schnell" : "hack"); go("tests"); }

function viewTests() {
  const root = h("div", {});
  root.append(h("h1", { text: "Welche Prüfungen sollen laufen?" }),
    h("p", { class: "lead", text: "Wähle eine Voreinstellung oder stelle die Auswahl selbst zusammen. Über „Details“ steht bei jedem Test, was genau passiert und warum das wichtig ist." }));

  root.append(compareReminder());
  root.append(h("div", { class: "presets" }, S.init.presets.map(p => {
    const n = S.init.checks.filter(c => c.presets.includes(p.id) && usable(c)).length;
    return h("button", { class: "preset", type: "button", "aria-pressed": String(S.preset === p.id), onclick: () => { applyPreset(p.id); render(); } },
      h("b", { text: p.title + " (" + n + ")" }), h("span", { text: p.text }));
  })));

  root.append(logSaveCard());
  root.append(settingsBox());

  for (const g of S.init.groups) {
    const list = S.init.checks.filter(c => c.group === g.id);
    if (!list.length) continue;
    const head = h("div", { class: "group-head" }, h("div", {}, h("h2", {}, ic(g.id), g.title), h("p", { text: g.text })),
      h("button", { class: "link", type: "button", onclick: () => {
        const all = list.filter(usable).every(c => S.sel.has(c.id));
        list.filter(usable).forEach(c => all ? S.sel.delete(c.id) : S.sel.add(c.id));
        S.preset = null; render();
      } }, "alle ein/aus"));
    const sec = h("section", { class: "group", id: "grp-" + g.id }, head);
    if (g.id === "dbbereich") sec.append(dbCard());
    // zusammengehörige Tests (Cluster) hintereinander, jeweils mit Klammer und Beschreibung des Vorgehens
    const blocks = [];
    for (const c of list) {
      const last = blocks[blocks.length - 1];
      if (last && last.id === (c.cluster || "") && c.cluster) last.list.push(c); else blocks.push({ id: c.cluster || "", list: [c] });
    }
    for (const b of blocks) sec.append(clusterBlock(b));
    root.append(sec);
  }

  const n = S.sel.size, heavy = [...S.sel].some(id => checkById(id).load === "hoch");
  root.append(h("div", { class: "bar" }, h("div", { class: "bar-in" },
    h("div", {}, h("b", { text: plural(n, "Test", "Tests") + " ausgewählt" }),
      heavy ? h("span", { class: "muted", text: "  Enthält Tests, die länger dauern und den Server etwas belasten." }) : null),
    h("div", { class: "actions", style: "margin:0" },
      h("button", { class: "btn ghost", type: "button", onclick: () => go("connect") }, "Zurück"),
      h("button", { class: "btn primary", type: "button", disabled: n === 0, onclick: () => startRun() }, "Prüfung starten")))));
  return root;
}

function clusterBlock(b) {
  const def = (S.init.clusters || []).find(c => c.id === b.id);
  if (!def) return h("div", { class: "tests" }, b.list.map(testRow));
  const ids = b.list.filter(usable);
  const allOn = ids.length && ids.every(c => S.sel.has(c.id));
  return h("div", { class: "cluster", role: "group", "aria-label": def.title },
    h("div", { class: "cluster-head" }, h("div", {}, h("h3", { text: def.title }), h("p", { text: def.text })),
      ids.length > 1 ? h("button", { class: "link", type: "button", onclick: () => { ids.forEach(c => allOn ? S.sel.delete(c.id) : S.sel.add(c.id)); S.preset = null; render(); } },
        allOn ? "Cluster abwählen" : "Cluster auswählen") : null),
    h("div", { class: "tests" }, b.list.map(testRow)));
}

/* ---- Bereich 'Datenbank': eigene Verbindung (optional) */
function dbBody() {
  const d = S.db;
  return { custom: d.custom, host: d.host, port: d.port, user: d.user, name: d.name, prefix: d.prefix, password: d.password };
}
async function dbPrefill() {
  const d = S.db; d.busy = true; d.err = ""; render();
  try {
    const r = await api("/api/db-prefill", { site_dir: S.form.site_dir });
    if (!r.found) d.err = "Auf dem Server wurde keine configuration.php gefunden. Trage die Daten selbst ein.";
    else { Object.assign(d, { host: r.host, port: r.port, user: r.user, name: r.name, prefix: r.prefix, filled: true, test: null }); d.hasPw = r.has_password; }
  } catch (e) { d.err = e.error || "Die Daten konnten nicht gelesen werden."; }
  d.busy = false; render();
}
async function dbTest() {
  const d = S.db; d.busy = true; d.err = ""; d.test = null; render();
  try { d.test = await api("/api/db-test", { db: dbBody(), site_dir: S.form.site_dir }); }
  catch (e) { d.err = e.error || "Der Test war nicht möglich."; }
  d.busy = false; render();
}
function dbCard() {
  const d = S.db;
  const card = h("div", { class: "card dbcard", id: "dbcard" });
  card.append(h("h3", { text: "Datenbank-Verbindung" }),
    h("p", { class: "small", text: "Die Tests dieses Bereichs fragen die Datenbank über den Server ab (nur lesend). Standardmäßig nutzt das Programm dafür die Zugangsdaten aus der configuration.php deiner Webseite. " +
      "Du kannst sie hier überschreiben, zum Beispiel mit einem eigenen Benutzer, der nur Leserechte hat." }),
    h("label", { class: "check" }, h("input", { type: "checkbox", checked: d.custom, onchange: e => { d.custom = e.target.checked; d.test = null; render(); } }),
      h("span", {}, "Eigene Zugangsdaten verwenden (sonst: Zugangsdaten aus der configuration.php)")));
  if (!d.custom) {
    card.append(h("div", { class: "actions", style: "margin:10px 0 0" }, h("button", { class: "btn", type: "button", disabled: d.busy || !S.conn || S.conn.mode === "none", onclick: dbTest }, "Verbindung testen")));
  } else {
    const inp = (key, ph, type) => h("input", { type: type || "text", id: "db-" + key, value: d[key], placeholder: ph || "", autocomplete: "off", oninput: e => { d[key] = e.target.value; d.test = null; } });
    card.append(h("div", { class: "dbgrid" },
      field("Server (Host)", inp("host", "localhost"), "Meist localhost oder ein Name wie db123.mariadb.hosting.zone.", "db-host"),
      field("Port (optional)", inp("port", "3306"), "", "db-port"),
      field("Datenbank-Benutzer", inp("user"), "", "db-user"),
      field("Datenbank-Name", inp("name"), "", "db-name"),
      field("Tabellenpräfix", inp("prefix", "z. B. jos_"), "Steht in der configuration.php als $dbprefix.", "db-prefix"),
      field("Passwort", inp("password", d.hasPw ? "leer = wie configuration.php" : "", "password"),
        "Wird nur im Arbeitsspeicher gehalten, nie gespeichert und nicht in Berichte geschrieben. Leer lassen = Passwort aus der configuration.php. " +
        "Zusätzliche Passwörter (z. B. eines eigenen Benutzers) musst du hier selbst eintragen.", "db-password")));
    card.append(h("div", { class: "actions", style: "margin:10px 0 0" },
      h("button", { class: "btn", type: "button", disabled: d.busy || !S.conn || S.conn.mode === "none", onclick: dbPrefill }, "Aus dem Server übernehmen"),
      h("button", { class: "btn", type: "button", disabled: d.busy || !S.conn || S.conn.mode === "none", onclick: dbTest }, "Verbindung testen")));
    if (d.filled) card.append(h("p", { class: "small muted", text: "Host, Benutzer, Datenbank und Präfix wurden aus der configuration.php übernommen (ohne Passwort). Du kannst sie ändern." }));
  }
  if (d.busy) card.append(h("p", { class: "small", text: "Einen Moment ..." }));
  if (d.err) card.append(h("div", { class: "notice err", style: "margin-top:10px" }, h("div", {}, d.err)));
  if (d.test) card.append(d.test.ok
    ? h("div", { class: "notice ok", style: "margin-top:10px" }, h("div", {}, h("strong", { text: "Verbindung funktioniert" }),
        h("div", { class: "small", text: "Server " + d.test.version + ", Datenbank " + d.test.database + ", Benutzer " + d.test.user + ", Präfix " + d.test.prefix + (d.test.custom ? " (eigene Angaben)" : " (aus der configuration.php)") })))
    : h("div", { class: "notice err", style: "margin-top:10px" }, h("div", {}, h("strong", { text: "Keine Verbindung" }), h("div", { class: "small", text: d.test.error || "" }))));
  return card;
}

function settingsBox() {
  const st = S.set;
  const d = h("details", { class: "card settings" }, h("summary", { text: "Weitere Einstellungen" }));
  const inner = h("div", {});
  inner.append(
    field("Protokoll-Ordner auf dem Server (optional)", h("input", { type: "text", id: "s-log", value: st.log_dir, placeholder: "leer lassen = automatisch suchen (z. B. logs)",
      oninput: e => { st.log_dir = e.target.value; } }), "Ordner mit den Zugriffsprotokollen deines Hosters, relativ zum Login-Ordner.", "s-log"),
    field("Zusätzlich erlaubte Fremd-Domains (optional)", h("textarea", { id: "s-allow", value: st.allow_hosts, placeholder: "eine Domain pro Zeile, z. B. cdn.meinepartner.de",
      oninput: e => { st.allow_hosts = e.target.value; } }),
      "Bekannte Dienste (Google, Cloudflare, Matomo ...) sind bereits hinterlegt. Alles andere wird bei der Webseitenprüfung als fremder Code gemeldet.", "s-allow"),
    h("label", { class: "check" }, h("input", { type: "checkbox", checked: st.mask_ips, onchange: e => { st.mask_ips = e.target.checked; } }),
      h("span", {}, "IP-Adressen in den Ergebnissen kürzen (empfohlen, wenn du die Berichte weitergibst)")));
  d.append(inner);
  return d;
}

function testRow(c) {
  const ok = usable(c), on = S.sel.has(c.id), open = S.open.has(c.id);
  const cb = h("input", { type: "checkbox", id: "t-" + c.id, checked: on && ok, disabled: !ok, "aria-label": c.title,
    onchange: e => { e.target.checked ? S.sel.add(c.id) : S.sel.delete(c.id); S.preset = null; updateBar(); } });
  const tags = h("div", { class: "tags" });
  if (!ok) tags.append(h("span", { class: "tag", text: "braucht SSH" }));
  if (c.needs === "db") tags.append(h("span", { class: "tag", text: "Datenbank" }));
  if (c.needs === "web") tags.append(h("span", { class: "tag", text: "Webseite" }));
  if (c.needs === "local") tags.append(h("span", { class: "tag", text: "Datei vom PC" }));
  if (c.load === "mittel") tags.append(h("span", { class: "tag mittel", text: "etwas Last" }));
  if (c.load === "hoch") tags.append(h("span", { class: "tag hoch", text: "dauert länger" }));
  const row = h("div", { class: "test" });
  const main = h("div", { class: "test-main" }, cb,
    h("div", {}, h("label", { class: "test-title", for: "t-" + c.id, text: c.title }), h("div", { class: "test-sum", text: c.summary }),
      h("button", { class: "link more-btn", type: "button", "aria-expanded": String(open), onclick: () => { open ? S.open.delete(c.id) : S.open.add(c.id); render(); keepScroll(c.id); } },
        open ? "Details ausblenden" : "Details")),
    tags);
  row.append(main);
  if (open) {
    const det = h("div", { class: "detail detail-in" },
      h("div", {}, h("h4", { text: "Was passiert?" }), h("p", { text: c.what })),
      h("div", {}, h("h4", { text: "Warum ist das wichtig?" }), h("p", { text: c.why })),
      h("div", {}, h("h4", { text: "Was wird gelesen?" }), h("p", { text: c.reads })));
    for (const o of c.options) det.append(optionInput(c, o));
    row.append(det);
  }
  return row;
}
function keepScroll(id) { const el = document.getElementById("t-" + id); if (el) el.scrollIntoView({ block: "center" }); }
function optionInput(c, o) {
  const cur = (S.opts[c.id] || {})[o.key];
  const set = v => { (S.opts[c.id] = S.opts[c.id] || {})[o.key] = v; };
  const id = "o-" + c.id + "-" + o.key;
  let input;
  if (o.kind === "bool") {
    input = h("input", { type: "checkbox", id, checked: cur !== undefined ? !!cur : !!o.default, onchange: e => set(e.target.checked) });
    const row = h("div", { class: "field opt", style: "margin:0" }, h("label", { class: "check", for: id }, input, h("span", { text: o.label })), o.help ? h("div", { class: "hint", text: o.help }) : null);
    if (c.id === "compare_runs") row.append(baselineBox());
    return row;
  }
  if (o.kind === "int") input = h("input", { type: "number", id, min: "1", value: cur !== undefined ? cur : o.default, oninput: e => set(e.target.value) });
  else if (o.key === "must_block") input = h("textarea", { id, value: cur || "", oninput: e => set(e.target.value) });
  else if (o.kind === "secret") input = h("input", { type: "password", id, value: cur || "", autocomplete: "off", spellcheck: "false", oninput: e => set(e.target.value) });
  else input = h("input", { type: "text", id, value: cur || "", oninput: e => set(e.target.value) });
  return h("div", { class: "field opt", style: "margin:0" }, h("label", { for: id, text: o.label }), input, o.help ? h("div", { class: "hint", text: o.help }) : null);
}
function compareReminder() {
  /* Erinnerung beim Öffnen der Auswahl (kein Hintergrunddienst): wann zuletzt mit der Vergleichsbasis verglichen wurde. */
  const box = h("div", {});
  if (!S.conn) return box;
  api("/api/baseline-info", { site_dir: S.form.site_dir }).then(d => {
    const r = d && d.reminder;
    if (!r || r.level === "ok") { if (r) box.append(h("div", { class: "hint", style: "margin-top:10px", text: r.text })); return; }
    box.append(h("div", { class: "notice " + (r.level === "due" ? "warn" : "info") }, h("div", {}, h("strong", { text: r.level === "due" ? "Zeit für einen Vergleich" : "Vergleichsbasis" }), r.text,
      h("div", { class: "hint", text: "Zum Vergleichen den Test „Vergleich mit gespeicherter Basis“ anhaken (in „komplett“ enthalten)." }))));
  }).catch(() => {});
  return box;
}
function baselineBox() {
  const box = h("div", { class: "hint", style: "margin-top:6px" }, "Vergleichsbasis wird gesucht ...");
  const load = async () => {
    box.replaceChildren();
    let d;
    try { d = await api("/api/baseline-info", { site_dir: S.form.site_dir }); } catch (e) { box.append(e.error || "Nicht abrufbar."); return; }
    if (!d.exists) { box.append("Für diese Verbindung ist noch keine Vergleichsbasis gespeichert."); return; }
    box.append("Gespeicherte Basis vom " + d.saved + ": " + d.files + " Code-Dateien, " + d.uploads + " Dateien in Upload-Ordnern (nur Pfade und Prüfsummen, auf diesem Computer). ",
      h("button", { class: "btn ghost", type: "button", onclick: async () => {
        if (!confirm("Die gespeicherte Vergleichsbasis auf diesem Computer löschen? Auf dem Server wird nichts verändert.")) return;
        try { await api("/api/baseline-delete", { site_dir: S.form.site_dir }); toast("Vergleichsbasis gelöscht."); } catch (e) { toast(e.error || "Löschen nicht möglich."); }
        load();
      } }, "Basis löschen"));
  };
  load();
  return box;
}
function updateBar() {
  const strong = $(".bar b"); if (strong) strong.textContent = plural(S.sel.size, "Test", "Tests") + " ausgewählt";
  const btn = $(".bar .btn.primary"); if (btn) btn.disabled = S.sel.size === 0;
  document.querySelectorAll(".preset").forEach((b, i) => b.setAttribute("aria-pressed", String(S.preset === S.init.presets[i].id)));
}

/* ------------------------------------------------------------------ 3. Prüfung */
async function startRun() {
  const ids = S.init.checks.map(c => c.id).filter(id => S.sel.has(id));
  const opts = {};
  for (const id of ids) if (S.opts[id]) opts[id] = S.opts[id];
  try {
    await api("/api/run", { ids, settings: { site_dir: S.form.site_dir, url: S.form.url, log_dir: S.set.log_dir, allow_hosts: S.set.allow_hosts, mask_ips: S.set.mask_ips, opts, db: S.db.custom ? dbBody() : {} } });
  } catch (e) { toast(e.error || "Start nicht möglich."); return; }
  Object.assign(S, { actions: null, actState: {}, exported: null, handover: null, revealed: false, results: [], next: 0, plan: ids, current: {}, running: true, summary: null, cancelled: false, runError: "", filter: null, elapsed: 0 });
  go("run"); poll();
}

function poll() {
  clearTimeout(S.timer);
  S.timer = setTimeout(async () => {
    let st;
    try { st = await api("/api/state?since=" + S.next); } catch (e) { toast(e.error || "Keine Verbindung zum Programm."); return poll(); }
    S.plan = st.plan; S.current = st.current || {}; S.elapsed = st.elapsed; S.running = st.running;
    S.results.push(...st.results); S.next = st.next;
    if (st.running) { if (S.step === "run") updateRun(); return poll(); }
    S.summary = st.summary; S.cancelled = st.cancelled; S.runError = st.error;
    S.step = "result"; render(); scroller().scrollTo(0, 0);
  }, 650);
}

function strip(opts) {
  const o = opts || {};
  const el = h("div", { class: "strip" + (o.reveal ? " reveal" : ""), role: "img", "aria-label": "Prüfstreifen: ein Feld je Test, gefärbt nach Ergebnis" });
  S.plan.forEach((id, i) => {
    const r = S.results.find(x => x.id === id);
    const status = r ? r.status : (S.current.id === id ? "running" : "");
    const c = checkById(id);
    const attrs = { class: "pad" + (o.click ? " pad-btn" : ""), "data-s": status, "data-id": id, title: c.title + (r ? " - " + SEV_LABEL[r.status] : ""), style: "--i:" + i };
    el.append(o.click ? h("button", Object.assign(attrs, { type: "button", "aria-label": c.title, onclick: () => jumpTo(id) })) : h("span", attrs));
  });
  return el;
}

function viewRun() {
  const root = h("div", {});
  root.append(h("h1", { text: "Die Prüfung läuft" }),
    h("p", { class: "lead", text: "Jedes Feld steht für einen Test und färbt sich, sobald sein Ergebnis da ist. Du kannst das Fenster offen lassen und etwas anderes tun." }));
  root.append(h("div", { class: "card", style: "margin-top:22px" }, h("div", { id: "run-strip" }, strip()),
    legend(),
    h("div", { class: "runwrap" },
      h("div", { class: "radar", "aria-hidden": "true" }, h("canvas", { id: "radar" })),
      h("div", {},
        h("div", { class: "now" }, h("div", { class: "now-title", id: "now-t" }), h("div", { class: "now-msg", id: "now-m", "aria-live": "polite" })),
        h("div", { class: "meter" }, h("span", { id: "m-n" }), h("span", { id: "m-t" }), h("span", { id: "m-p" })),
        h("div", { class: "found", id: "found", "aria-live": "polite" }),
        h("div", { class: "actions", style: "margin-top:18px" }, h("button", { class: "btn danger", type: "button", id: "cancel", onclick: cancelRun }, "Abbrechen"))))));
  root.append(h("div", { id: "live" }));
  setTimeout(updateRun, 0);
  return root;
}

function legend() {
  const items = [["ok", "In Ordnung"], ["info", "Hinweis"], ["warn", "Bitte prüfen"], ["crit", "Kritisch"], ["skipped", "Übersprungen / fehlgeschlagen"]];
  const col = { ok: "var(--ok)", info: "var(--info)", warn: "var(--warn)", crit: "var(--crit)", skipped: "var(--skip)" };
  return h("div", { class: "legend" }, items.map(([k, t]) => h("span", {}, h("i", { style: "background:" + col[k] }), t)));
}

function updateRun() {
  const s = $("#run-strip"); if (!s) return;
  s.replaceChildren(strip());
  const cur = S.current && S.current.id ? checkById(S.current.id) : null;
  $("#now-t").textContent = cur ? cur.title : (S.running ? "Wird vorbereitet ..." : "Fertig");
  $("#now-m").textContent = cur ? (S.current.msg || cur.summary) : "";
  $("#m-n").replaceChildren(h("b", { text: S.results.length + " / " + S.plan.length }), "Tests fertig");
  $("#m-t").replaceChildren(h("b", { text: fmtTime(S.elapsed) }), "Laufzeit");
  const crit = S.results.filter(r => r.status === "crit").length, warn = S.results.filter(r => r.status === "warn").length;
  $("#m-p").replaceChildren(h("b", { text: crit + " / " + warn }), "kritisch / prüfen");
  const fl = $("#found");
  if (fl) {                                                                  // ganz kurze Liste der Funde (neueste oben), damit man nicht auf das Ergebnis warten muss
    const hits = S.results.filter(r => r.status === "crit" || r.status === "warn").slice(-5).reverse();
    fl.replaceChildren(...(hits.length ? hits.map(r => {
      const f = (r.findings || []).find(x => x.sev === r.status) || (r.findings || [])[0];
      return h("div", { class: "found-i", "data-s": r.status, title: r.title }, h("i"), h("span", { text: r.title + (f && f.title ? ": " + f.title : "") }));
    }) : [h("div", { class: "found-none", text: "Bisher nichts Auffälliges gefunden." })]));
  }
  radarSync();
}

/* Radar (zusätzliche Animation): wird beim Betreten der Ansicht angelegt und beim Verlassen zerstört. Ein Fehler darin darf die Prüfung nie stören. */
let radarInst = null;
function radarSync() {
  try {
    const cv = $("#radar");
    if (radarInst && radarInst.canvas !== cv) { radarInst.destroy(); radarInst = null; }
    if (!cv) return;
    if (!radarInst && typeof ClaudiaRadar !== "undefined") radarInst = ClaudiaRadar.mount(cv);
    if (!radarInst) return;
    const status = {};
    S.results.forEach(r => { status[r.id] = (r.status === "error" ? "skipped" : r.status); });
    radarInst.set({ plan: S.plan.slice(), status, current: (S.current && S.current.id) || null, running: !!S.running });
  } catch (e) { radarInst = null; }
}
function fmtTime(s) { s = Math.round(s); return Math.floor(s / 60) + ":" + String(s % 60).padStart(2, "0"); }

async function cancelRun() {
  const b = $("#cancel"); if (b) { b.disabled = true; b.textContent = "Wird abgebrochen ..."; }
  try { await api("/api/cancel", {}); } catch (e) { toast(e.error); }
}

/* ------------------------------------------------------------------ 4. Ergebnis */
function viewResult() {
  const sum = S.summary || { level: "none", headline: "Noch keine Ergebnisse", text: "", caveat: "", counts: {}, total: 0 };
  const root = h("div", {});
  root.append(h("div", { class: "verdict", "data-l": sum.level }, h("h1", { text: sum.headline }), h("p", { class: "lead", text: sum.text })));
  if (S.results.length && !S.running) root.append(updatesCard());
  if (S.results.length && !S.running) root.append(securityCard());
  if (S.results.length && !S.running) root.append(hosterCard());
  if (S.cancelled) root.append(h("div", { class: "notice warn" }, h("div", {}, h("strong", { text: "Prüfung abgebrochen" }), "Es liegen nur die bis dahin fertigen Ergebnisse vor.")));
  if (S.runError) root.append(h("div", { class: "notice err" }, h("div", {}, h("strong", { text: "Fehler im Programm" }), S.runError)));
  const doReveal = !S.revealed; S.revealed = true;
  root.append(h("div", { class: "card", style: "margin-top:20px" }, strip({ reveal: doReveal, click: true }), legend()));
  if (sum.caveat) root.append(h("p", { class: "caveat", text: sum.caveat }));
  if (S.results.length) root.append(exportCard());
  if (S.results.length && !S.running) root.append(actionsCard());

  const c = sum.counts || {};
  const defs = [["crit", "Kritisch"], ["warn", "Bitte prüfen"], ["info", "Hinweis"], ["ok", "In Ordnung"], ["skip", "Nicht gelaufen"]];
  const col = { crit: "var(--crit)", warn: "var(--warn)", info: "var(--info)", ok: "var(--ok)", skip: "var(--skip)" };
  const num = k => k === "skip" ? (c.skipped || 0) + (c.error || 0) : (c[k] || 0);
  root.append(h("div", { class: "counts", role: "group", "aria-label": "Ergebnisse filtern" }, defs.map(([k, t]) =>
    h("button", { class: "count", type: "button", "aria-pressed": String(S.filter === k), onclick: () => { S.filter = S.filter === k ? null : k; render(); } },
      ic(k === "skip" ? "skipped" : k), h("b", { text: num(k) }), t))));

  root.append(h("div", { class: "actions", style: "margin-top:10px" },
    h("button", { class: "link", type: "button", onclick: () => document.querySelectorAll("#results > details.res").forEach(d => { d.open = true; }) }, "Alle aufklappen"),
    h("button", { class: "link", type: "button", onclick: () => document.querySelectorAll("#results > details.res").forEach(d => { d.open = false; }) }, "Alle zuklappen")));

  const shown = S.results.filter(r => !S.filter || (S.filter === "skip" ? (r.status === "skipped" || r.status === "error") : r.status === S.filter))
    .sort((a, b) => SEV_RANK[a.status] - SEV_RANK[b.status] || S.plan.indexOf(a.id) - S.plan.indexOf(b.id));
  const list = h("div", { id: "results" });
  if (!shown.length) list.append(h("p", { class: "muted", style: "margin-top:20px", text: "In dieser Kategorie gibt es nichts." }));
  shown.forEach(r => list.append(resultCard(r)));
  root.append(list);

  root.append(h("div", { class: "actions", style: "margin-top:28px" },
    h("button", { class: "btn", type: "button", onclick: () => go("tests") }, "Andere Tests wählen"),
    h("button", { class: "btn primary", type: "button", onclick: () => startRun() }, "Prüfung wiederholen")));
  return root;
}

function exportCard() {
  const card = h("div", { class: "card", id: "export" });
  card.append(h("h2", { text: "Ergebnisse speichern und weitergeben" }),
    h("p", { class: "sub", text: "Das ZIP enthält Bericht, Befunde und Rohdaten, aber keine Passwörter. Zugangsdaten aus der configuration.php sind unkenntlich gemacht" +
      (S.set.mask_ips ? " und IP-Adressen gekürzt." : ", IP-Adressen sind nicht gekürzt.") }),
    h("div", { class: "actions", style: "margin-top:0" },
      h("button", { class: "btn primary", type: "button", disabled: S.exporting, onclick: handover }, "An Claude übergeben"),
      h("button", { class: "btn", type: "button", onclick: downloadZip }, "ZIP herunterladen"),
      h("button", { class: "btn", type: "button", disabled: S.exporting, onclick: saveReports }, S.exporting ? "Speichere ..." : "Alle Berichte als Dateien speichern")));
  if (S.handover) {
    const hv = S.handover;
    card.append(h("div", { class: "notice ok", id: "handover" }, h("div", {},
      h("strong", { text: "So übergibst du den Bericht an Claude" }),
      h("ol", { class: "small", style: "margin:6px 0 8px 18px;padding:0" },
        h("li", { text: "Der Ordner mit fuer_claude.zip wurde geöffnet (die Datei ist markiert)." }),
        h("li", { text: "Claude wurde in einem neuen Browser-Tab geöffnet. Melde dich dort an, falls nötig." }),
        h("li", { text: "Füge den Text unten ein (Strg+V) und ziehe fuer_claude.zip in das Chatfenster. Dann abschicken." })),
      h("textarea", { id: "handover-text", readonly: "readonly", rows: 6, style: "width:100%", text: hv.prompt }),
      h("div", { class: "actions", style: "margin:8px 0 0" },
        h("button", { class: "btn", type: "button", onclick: copyHandover }, "Text kopieren"),
        h("button", { class: "btn", type: "button", onclick: () => window.open(hv.url, "_blank", "noopener") }, "Claude erneut öffnen"),
        h("button", { class: "btn", type: "button", onclick: openFolder }, "Ordner öffnen")),
      h("div", { class: "small", text: "Das Programm lädt die Datei nicht selbst hoch: Dafür wären Zugangsdaten zu deinem Claude-Konto nötig, die es nie bekommt." }))));
  }
  if (S.exported && !S.handover) {
    card.append(h("div", { class: "notice ok" }, h("div", {},
      h("strong", { text: "Gespeichert" }), h("div", { class: "mono", text: S.exported.dir }),
      h("div", { class: "small", text: exportSummary(S.exported.files) }),
      h("div", { class: "actions", style: "margin:8px 0 0" }, h("button", { class: "btn", type: "button", onclick: openFolder }, "Ordner öffnen")))));
  }
  return card;
}
function exportSummary(files) {
  const top = files.filter(f => !f.name.startsWith("rohdaten/")).map(f => f.name);
  const raw = files.length - top.length;
  return top.join(", ") + (raw ? ", Ordner rohdaten (" + raw + " Dateien)" : "");
}

/* ------------------------------------------------------------------ Protokolle auf den PC sichern */
function fmtDate(t) { return t ? new Date(t * 1000).toLocaleDateString("de-DE") : "-"; }
function updateLogCard() { const old = $("#logsave"); if (old) old.replaceWith(logSaveCard()); }
function logSaveCard() {
  const L = S.ls;
  const card = h("div", { class: "card", id: "logsave" });
  card.append(h("h2", { text: "Protokolle auf deinen PC sichern" }),
    h("p", { class: "sub", text: "Hoster löschen Zugriffsprotokolle nach einer festen Zeit automatisch. Wer später wissen will, wann und wie ein Angriff lief, hat sie dann nicht mehr. " +
      "Hier kopierst du sie auf deinen Rechner. Auf dem Server wird nichts verändert oder gelöscht, es wird nur gelesen." }));
  if (!S.conn) { card.append(h("p", { class: "small", text: "Dafür zuerst die Verbindung herstellen." })); return card; }
  card.append(h("label", { class: "check" }, h("input", { type: "checkbox", id: "ls-joomla", checked: L.joomla, disabled: !!L.job && !L.job.done,
    onchange: e => { L.joomla = e.target.checked; L.plan = null; L.ok = false; updateLogCard(); } }),
    h("span", {}, (isWP() ? "Auch die WordPress-Protokolle (wp-content/debug.log) mitnehmen" : "Auch die Joomla-Protokolle (administrator/logs) mitnehmen"))));
  if (L.err) card.append(h("div", { class: "notice err" }, h("div", {}, h("strong", { text: "Nicht möglich" }), L.err)));
  const j = L.job;
  if (j && !j.none) {
    const pct = j.bytes ? Math.min(100, Math.round(100 * j.done_bytes / j.bytes)) : 100;
    if (!j.done) {
      card.append(h("div", { class: "notice info", id: "ls-prog" }, h("div", {},
        h("strong", { text: "Sichere ... " + pct + " %" }),
        h("div", { class: "small", text: j.done_files + " von " + j.files + " Dateien, " + fmtSize(j.done_bytes) + " von " + fmtSize(j.bytes) + ", " + fmtTime(j.elapsed) + " Min." }),
        j.current ? h("div", { class: "small mono", text: j.current }) : null,
        h("div", { class: "actions", style: "margin:8px 0 0" }, h("button", { class: "btn ghost", type: "button", onclick: cancelLogSave }, "Abbrechen")))));
      return card;
    }
    card.append(h("div", { class: "notice " + ((j.failed || []).length ? "warn" : "ok"), id: "ls-done" }, h("div", {},
      h("strong", { text: j.cancelled ? "Abgebrochen" : "Fertig: " + j.saved + " Datei(en) gesichert" }),
      h("div", { class: "small", text: "Ordner auf diesem PC: " + j.dir }),
      (j.failed || []).length ? h("div", { class: "small" }, "Nicht gesichert:", h("pre", { class: "mono", style: "white-space:pre-wrap", text: j.failed.join("\n") })) : null,
      h("div", { class: "actions", style: "margin:8px 0 0" },
        h("button", { class: "btn", type: "button", onclick: () => api("/api/logs-open", {}).catch(e => toast(e.error || "Ordner nicht zu öffnen.")) }, "Ordner öffnen")),
      h("div", { class: "small", text: "Auswerten: Test „Zugriffsprotokoll von diesem PC auswerten“ wählen und diesen Ordner als Pfad eintragen." }))));
  }
  const pl = L.plan;
  if (!pl) {
    card.append(h("div", { class: "actions", style: "margin:8px 0 0" },
      h("button", { class: "btn", type: "button", disabled: L.busy, onclick: planLogSave }, L.busy ? "Suche Protokolle auf dem Server ..." : "Protokolle suchen")));
    return card;
  }
  if (!pl.files) {
    card.append(h("p", { class: "small", text: "Auf dem Server wurden keine Protokolle gefunden. Trage unter „Weitere Einstellungen“ den Protokoll-Ordner ein und suche erneut." }),
      h("div", { class: "actions", style: "margin:8px 0 0" }, h("button", { class: "btn", type: "button", onclick: planLogSave }, "Erneut suchen")));
    return card;
  }
  card.append(h("dl", { class: "facts" },
    h("dt", { text: "Gefunden" }), h("dd", { text: pl.files + " Dateien, Zeitraum " + fmtDate(pl.oldest) + " bis " + fmtDate(pl.newest) }),
    h("dt", { text: "Noch zu sichern" }), h("dd", { text: pl.new + " neue" + (pl.changed ? ", " + pl.changed + " geänderte" : "") + " (" + fmtSize(pl.bytes) + "), " + pl.have + " schon vorhanden" }),
    h("dt", { text: "Speicherort" }), h("dd", { class: "mono", text: pl.dir })));
  if (!pl.fits) card.append(h("div", { class: "notice err" }, h("div", {}, h("strong", { text: "Zu wenig Platz" }), "Auf dem PC sind nur " + fmtSize(pl.free) + " frei.")));
  if (!(pl.new + pl.changed)) { card.append(h("p", { class: "small", text: "Alles ist schon gesichert. Wiederhole das in ein paar Wochen." })); return card; }
  card.append(h("p", { class: "small", text: "Datenschutz: Zugriffsprotokolle enthalten IP-Adressen deiner Besucher. Der Ordner bleibt auf deinem PC und wird nicht in die ZIP für Claude aufgenommen. " +
    "Behalte die Dateien nur so lange, wie du sie brauchst." }),
    h("label", { class: "small", style: "display:block;margin:6px 0" }, h("input", { type: "checkbox", id: "ls-ok", checked: L.ok, onchange: e => { L.ok = e.target.checked; updateLogCard(); } }),
      " Ich habe das gelesen und möchte die Protokolle jetzt auf diesen PC kopieren."),
    h("div", { class: "actions", style: "margin:8px 0 0" },
      h("button", { class: "btn primary", type: "button", disabled: !L.ok || !pl.fits, onclick: startLogSave }, "Jetzt sichern"),
      h("button", { class: "btn ghost", type: "button", onclick: () => { L.plan = null; L.ok = false; updateLogCard(); } }, "Neu suchen")));
  return card;
}
async function planLogSave() {
  const L = S.ls; L.busy = true; L.err = ""; updateLogCard();
  try { L.plan = await api("/api/logs-plan", { log_dir: S.set.log_dir, joomla: L.joomla }); L.ok = false; L.job = null; }
  catch (e) { L.err = e.error || "Die Protokolle konnten nicht gesucht werden."; }
  L.busy = false; updateLogCard();
}
async function startLogSave() {
  const L = S.ls; L.err = "";
  try {
    const r = await api("/api/logs-save", { log_dir: S.set.log_dir, joomla: L.joomla, confirm: true });
    if (!r.started) { L.err = ""; toast(r.message || "Nichts zu sichern."); await planLogSave(); return; }
  } catch (e) { L.err = e.error || "Die Sicherung konnte nicht gestartet werden."; updateLogCard(); return; }
  for (;;) {
    await sleep(500);
    try { L.job = await api("/api/logs-state"); } catch (e) { L.err = e.error || "Verbindung zum Programm verloren."; break; }
    updateLogCard();
    if (L.job.done) break;
  }
  L.plan = null; L.ok = false; updateLogCard();
}
async function cancelLogSave() { try { await api("/api/logs-cancel", {}); } catch (e) { /* egal */ } }

/* ------------------------------------------------------------------ Lösungen auf Knopfdruck */
const RISK_LEVEL = { keine: 0, niedrig: 1, mittel: 3, hoch: 5 };
function riskMeter(risk) {
  const lv = RISK_LEVEL[risk];
  if (lv === undefined) return null;
  const w = h("span", { class: "risk-meter", title: risk, style: "margin-right:8px;white-space:nowrap;letter-spacing:.08em" });
  for (let i = 1; i <= 5; i++) w.append(h("span", { text: "\u26A0\uFE0F", style: i <= lv ? "" : "filter:grayscale(1);opacity:.28" }));
  return w;
}
const RISK_LABEL = { keine: "ändert nichts", niedrig: "geringes Risiko", mittel: "mittleres Risiko", hoch: "HOHES Risiko" };
async function loadActions(quiet) {
  if (S.actionsLoading) return;
  S.actionsLoading = true;
  try { S.actions = await api("/api/actions"); } catch (e) { S.actions = { actions: [], connected: false }; }
  S.actionsLoading = false;
  if (!quiet || !document.getElementById("status-modal")) render();
}
function actState(id) { return S.actState[id] || (S.actState[id] = { php: "", preview: null, ok: false, running: false, sel: null, selB: null, selL: null, noBackup: false, last: null }); }
async function copyText(t) {
  try { await navigator.clipboard.writeText(t); }
  catch (e) { const ta = h("textarea", { value: t, style: "position:fixed;left:-9999px" }); document.body.append(ta); ta.select(); document.execCommand("copy"); ta.remove(); }
  toast("Kopiert.");
}
/* Vorschau der .htaccess-Zurücksetzung: Quelle, Vergleich alt/neu (rot = entfällt, grün = neu), nicht übernommene Regeln */
function htaccessPreview(p) {
  const wrap = h("div", { class: "ht-preview", style: "margin:10px 0" });
  wrap.append(h("div", { class: "small" }, h("strong", { text: "Änderungen: " }), "Standard aus: " + p.source));
  if (p.unchanged) wrap.append(h("p", { class: "small", text: "Die Datei entspricht schon dem Standard, es würde nichts geändert." }));
  for (const d of p.dropped || []) {
    wrap.append(h("div", { class: "small", style: "color:" + (d.sev === "crit" ? "#b00020" : d.sev === "warn" ? "#b26a00" : "inherit") + ";margin:4px 0" },
      h("strong", { text: (d.sev === "crit" ? "Gefährlich, wird NICHT übernommen: " : d.sev === "warn" ? "Auffällig, wird NICHT übernommen: " : "Wird nicht übernommen: ") }), d.line + "  (" + d.why + ")"));
  }
  if ((p.carried || []).length) wrap.append(h("div", { class: "small", text: "Übernommen werden " + p.carried.length + " eigene Regel(n)/Block/Blöcke: " + p.carried.map(c => c.name || c.first).join("; ").slice(0, 300) }));
  const pre = h("pre", { class: "code", style: "max-height:320px;overflow:auto" });
  for (const l of p.diff || []) {
    pre.append(h("div", { text: l || " ", style: l.startsWith("+") && !l.startsWith("+++") ? "color:#2e7d32" : l.startsWith("-") && !l.startsWith("---") ? "color:#c62828" : l.startsWith("@@") ? "opacity:.7" : "" }));
  }
  wrap.append(pre);
  return wrap;
}
/* Vorschau "Code in der Datenbank entfernen": je Eintrag die Blöcke, die entfallen (rot), oder der Grund, warum nichts geändert wird */
function dbcodePreview(p) {
  const wrap = h("div", { style: "margin:10px 0" }, h("div", { class: "small" }, h("strong", { text: "Änderungen:" })));
  for (const it of p.items || []) {
    const box = h("div", { class: "small", style: "margin:6px 0" }, h("strong", { text: it.label + ": " }),
      it.skip ? h("span", { style: "color:#b26a00", text: "wird NICHT geändert, " + it.skip }) : h("span", { text: it.removed.length + " Block/Blöcke entfallen (" + it.size_old + " → " + it.size_new + " Zeichen)" }));
    if (it.leftover) box.append(h("div", { style: "color:#b26a00", text: "Im Rest steht noch verdächtiger Code außerhalb von Skript-/Frame-Blöcken; bitte danach von Hand ansehen." }));
    if (it.removed.length) { const pre = h("pre", { class: "code", style: "max-height:200px;overflow:auto;color:#c62828" }); pre.textContent = it.removed.map(x => "- " + x).join("\n"); box.append(pre); }
    wrap.append(box);
  }
  return wrap;
}
function codeBox(lines, title) {
  const text = lines.join("\n");
  return h("div", { class: "codebox" },
    h("div", { class: "codebox-head" }, h("span", { text: title || "Befehle" }),
      h("button", { class: "btn mini", type: "button", onclick: () => copyText(text) }, "Kopieren")),
    h("pre", { class: "code", text }));
}
/* Codefenster: schwarz mit grünem Code (wie das Fenster bei Serverbefehlen), eingeklappt, mit Kopierfunktion; die Treffer-Stelle ist rot markiert */
function codeWindow(ev, opened) {
  const head = ev.line ? ev.file + ", Zeile " + ev.line : ev.file;
  const pre = h("pre", { class: "cw-pre" });
  for (const c of ev.code) {
    const row = h("div", { class: "cw-row" + (c.hit ? " cw-hit" : "") });
    row.append(h("span", { class: "cw-ln", text: ev.kind === "db" ? "" : String(c.n) }));
    const t = c.t || "";
    if (c.hit) row.append(h("span", { text: t.slice(0, c.hit[0]) }), h("mark", { text: t.slice(c.hit[0], c.hit[1]) }), h("span", { text: t.slice(c.hit[1]) }));
    else row.append(h("span", { text: t }));
    pre.append(row);
  }
  const plain = ev.code.map(c => (ev.kind === "db" ? "" : c.n + " | ") + c.t).join("\n");
  return h("details", { class: "cw", open: !!opened },
    h("summary", {}, h("span", { class: "cw-sum", text: "Code anzeigen: " + head }), ev.note ? h("span", { class: "cw-note", text: ev.note }) : null),
    h("div", { class: "cw-body" }, pre,
      h("div", { class: "cw-foot" }, h("span", { class: "cw-legend" }, h("mark", { text: "rot" }), " = die gefundene Stelle. Den Code nur lesen, nie ausführen."),
        h("button", { class: "btn mini", type: "button", onclick: () => copyText(plain) }, "Kopieren"))));
}
const TOP_IDS = ["core_update", "update_extensions", "wp_update"];
const SEC_IDS = ["install_security"];
const isTop = id => TOP_IDS.includes(id) || SEC_IDS.includes(id);
/* Updates ganz oben: Suche, Status und die Updates selbst */
function updatesCard() {
  if (S.actions === null) { loadActions(); return h("div", {}); }
  if (!S.actions.connected) return h("div", {});
  const card = h("div", { class: "card updatescard", id: "updates" });
  card.append(h("h2", { text: "Updates" }), updateStatusBox());
  const list = (S.actions.actions || []).filter(a => TOP_IDS.includes(a.id) && !a.hidden);
  const u = S.actions.update || {};
  if (list.length) {
    const plan = S.actions.plan || [];
    for (const a of list) card.append(actionBlock(a));
    if (plan.length) card.append(h("p", { class: "small muted", text: "Die Reihenfolge aller Schritte steht weiter unten unter „Lösungen auf Knopfdruck“. Updates kommen nach der Sicherung zuerst dran." }));
  } else if (isWP()) {
    card.append(h("p", { class: "small", text: "Die Prüfungen haben keine veraltete WordPress-Version und keine veralteten oder unsicheren Plugins und Themes gemeldet, die das Programm aktualisieren könnte." }));
  } else if (u.checked && !u.failed) {
    card.append(h("p", { class: "small", text: "Es gibt zurzeit keine Updates, die das Programm für dich installieren kann." }));
  }
  return card;
}

/* Sicherheits-Erweiterung: wird nur hier oben empfohlen und angeboten, nicht noch einmal unter „Lösungen auf Knopfdruck“ */
function securityCard() {
  if (S.actions === null || !S.actions.connected) return h("div", {});
  const a = (S.actions.actions || []).find(x => x.id === "install_security" && !x.hidden);
  if (!a) return h("div", {});
  const card = h("div", { class: "card securitycard", id: "security" });
  card.append(h("h2", { text: "Sicherheits-Erweiterung" }),
    h("p", { class: "small", text: "Auf dieser Seite wurde keine Firewall und kein Schadcode-Scanner gefunden. Du kannst hier eine installieren lassen. Das ändert Dateien auf dem Server und läuft erst nach deiner Bestätigung (mit Sicherung vorher)." }),
    actionBlock(a));
  return card;
}

/* Nur beim Hoster änderbar: Befunde, die sich nur dort ändern lassen, samt fertigem Text für eine E-Mail (nur Anzeige und Kopieren, nichts wird gesendet) */
function hosterCard() {
  const ho = S.hoster;
  if (!ho || !(ho.items || []).length) return h("div", {});
  const mailText = (ho.mail.subject ? "Betreff: " + ho.mail.subject + "\n\n" : "") + ho.mail.body;
  const card = h("div", { class: "card", id: "hoster" });
  card.append(h("h2", { text: "Nur beim Hoster änderbar" }),
    h("p", { class: "small muted", text: "Diese Punkte kannst du nicht selbst ändern, sie liegen in der Server-Einstellung oder im DNS deines Hosters. Unten steht ein fertiger Text für eine E-Mail an ihn." }));
  const list = h("ol", { class: "hoster-list" });
  for (const it of ho.items) list.append(h("li", {}, h("strong", { class: "plan-sev " + it.sev, text: (it.sev === "crit" ? "Kritisch: " : it.sev === "warn" ? "Bitte prüfen: " : "Hinweis: ") }), it.title,
    h("div", { class: "small", text: it.ask })));
  card.append(list);
  const copied = h("span", { class: "small muted", style: "margin-left:10px" });
  card.append(h("details", { class: "hoster-mail" }, h("summary", { class: "link", style: "cursor:pointer", text: "E-Mail an den Hoster anzeigen" }),
    h("pre", { class: "hoster-pre", text: mailText }),
    h("div", { class: "actions", style: "margin:8px 0 0" }, h("button", { class: "btn mini", type: "button", onclick: async () => {
      try { await navigator.clipboard.writeText(mailText); copied.textContent = "Kopiert."; } catch (e) { copied.textContent = "Kopieren nicht möglich. Text markieren und mit Strg+C kopieren."; }
    } }, "Text kopieren"), copied)));
  return card;
}

function actionsCard() {
  if (S.actions === null) { loadActions(); return h("div", {}); }
  const list = (S.actions.actions || []);
  const card = h("div", { class: "card", id: "actions" });
  card.append(h("h2", { text: "Lösungen auf Knopfdruck (optional)" }),
    h("div", { class: "notice warn actions-intro" }, h("div", {},
      h("p", {}, "Ab hier kannst du das Programm nutzen um etwas konkretes ", h("span", { class: "redbold", text: "auf dem Webserver zu ändern" }),
        ". Alle Prüfungen oben waren rein lesend. Die folgenden Buttons führen feste, vorher angezeigte Befehle aus, und zwar nur nach deiner Bestätigung. " +
        "Aktionen mit Risiko legen zuerst eine Sicherung an und prüfen sie. Gelingt die Sicherung nicht, passiert nichts."),
      h("p", {}, h("span", { class: "redbold", text: "Wenn du unsicher bist, lass es und frage Claude oder einen Spezialisten." })))));
  if (!S.actions.connected) { card.append(h("p", { class: "sub", text: "Dafür muss die Verbindung zum Server noch bestehen." })); return card; }
  const plan = S.actions.plan || [];
  const visible = list.filter(a => !a.hidden && !isTop(a.id));
  if (!visible.length && !(plan.some(p => p.kind === "manual" && p.id !== "recheck"))) {
    card.append(h("p", { class: "sub", text: "Für diese Befunde gibt es keine Aktion, die das Programm sicher selbst ausführen kann." }));
    return card;
  }
  if (plan.length) {
    card.append(h("div", { class: "plan", id: "plan" }, h("h3", { text: "Empfohlene Reihenfolge" }),
      h("p", { class: "small", text: "So gehst du am sichersten vor, um eine infizierte Seite zu bereinigen. Jeder Schritt erscheint nur, wenn er für deine Seite nötig ist." }),
      h("ol", {}, plan.map(p => h("li", {}, h("b", { text: p.title }), p.kind === "manual" ? h("span", { class: "tag", text: "von Hand" }) : null,
        TOP_IDS.includes(p.id) ? h("span", { class: "tag", text: "siehe oben bei „Updates“" }) : SEC_IDS.includes(p.id) ? h("span", { class: "tag", text: "siehe oben bei „Sicherheits-Erweiterung“" }) : null)))));
  }
  const byId = {}; for (const a of list) byId[a.id] = a;
  for (const p of plan) {
    if (p.kind === "action" && byId[p.id] && !isTop(p.id)) card.append(actionBlock(byId[p.id]));
    else if (p.id === "manual_code") card.append(manualCodeBlock(p));
    else if (p.id === "manual_passwords") card.append(manualInfoBlock(p, "Ändere nacheinander: alle " + cmsName() + "-Admin-Passwörter, das Datenbank-Passwort (beim Hoster ändern, dann in " + cmsConfig() + " eintragen), SFTP/SSH-Passwort, E-Mail-Passwort der Admin-Adresse und " + (isWP() ? "lösche alle Anwendungspasswörter (Profil jedes Benutzers) und API-Schlüssel von Plugins." : "lösche alle API-Token.") + " Nutze lange, nur dafür verwendete Passwörter."));
    else if (p.id === "recheck") card.append(manualInfoBlock(p, "Starte die Prüfung nach den Schritten erneut (Schritt 'Tests auswählen'). Erst wenn nichts Kritisches mehr gemeldet wird, ist der Zustand belegt. Danach beobachte das Zugriffsprotokoll einige Wochen.",
      h("button", { class: "btn", type: "button", onclick: () => goTests() }, "Zur Testauswahl")));
  }
  for (const qid of ["restore_quarantine", "delete_quarantine"]) {
    const rq = byId[qid];
    if (rq && !rq.hidden) card.append(actionBlock(rq));
  }
  return card;
}
function stepHead(a) {
  return h("div", { class: "stephead" }, h("span", { class: "stepno", text: String(a.step || "") }),
    a.why ? h("span", { class: "small muted" }, "Warum jetzt? ", ...summaryParts(a.why)) : h("span", { class: "small muted" }));
}
function manualInfoBlock(p, text, extra) {
  return h("div", { class: "finding action manual", "data-s": "info", id: "act-" + p.id },
    stepHead(p), h("h4", {}, h("span", { class: "badge", "data-s": "info", style: "margin-right:8px", text: "von Hand" }), p.title), h("p", { text }), extra ? h("div", { class: "actions", style: "margin:8px 0 0" }, extra) : null);
}
function updateStatusBox() {
  const u = (S.actions && S.actions.update) || {};
  const box = h("div", { class: "updstatus notice " + (u.failed ? "err" : u.checking ? "info" : "ok"), id: "updstatus" });
  if (u.checking) {
    box.append(h("div", {}, h("strong", { text: "Suche nach Updates ..." }), h("span", { class: "spinner small-spin", "aria-hidden": "true" }),
      h("div", { class: "small", text: "Das Programm fragt " + cmsName() + " über seine Kommandozeile nach neuen Versionen. Es wird nichts installiert." })));
    setTimeout(() => { if (S.step === "result") loadActions(true); }, 1500);
  } else if (u.failed) {
    box.append(h("div", {}, h("strong", { text: "Die Update-Suche ist fehlgeschlagen" }), h("div", { class: "small", text: u.error || "" }),
      h("div", { class: "actions", style: "margin:8px 0 0" }, h("button", { class: "btn", type: "button", onclick: recheckUpdates }, "Erneut suchen"))));
  } else if (u.checked && !u.reliable) {
    box.className = "updstatus notice warn";
    const rows = (u.live_extra || []).map((x) => x.name + ": " + x.old + " -> " + x.new + " (" + x.source + ")");
    box.append(h("div", {}, h("strong", { text: "Das Ergebnis der Update-Suche ist nicht verlässlich" }),
      h("div", { class: "small", text: (u.reasons || []).join(" ") }),
      rows.length ? h("ul", { class: "small" }, rows.map((t) => h("li", { text: t }))) : null,
      h("div", { class: "small", text: "Bitte im Joomla-Backend unter System > Aktualisieren nachsehen. Es wird nicht behauptet, dass es keine Updates gibt." }),
      h("div", { class: "actions", style: "margin:8px 0 0" }, h("button", { class: "btn mini", type: "button", onclick: recheckUpdates }, "Erneut suchen"))));
  } else if (u.checked) {
    const parts = [u.has_update ? cmsName() + ": Update auf " + (u.latest || "neue Version") + " verfügbar" : cmsName() + ": aktuell", "Erweiterungen: " + (u.ext_count ? u.ext_count + " Update(s) verfügbar" : "keine Updates")];
    box.append(h("div", {}, h("strong", { text: "Update-Suche abgeschlossen" }), h("div", { class: "small", text: parts.join("  |  ") }),
      h("div", { class: "small", text: u.confirmed ? "Bestätigt durch die Update-Server der Erweiterungen." : "Die Gegenprobe über die Update-Server war nicht möglich." }),
      h("div", { class: "actions", style: "margin:8px 0 0" }, h("button", { class: "btn mini", type: "button", onclick: recheckUpdates }, "Erneut suchen"))));
  } else {
    return h("div", {});
  }
  return box;
}
async function recheckUpdates() {
  try { await api("/api/update-check", {}); } catch (e) { toast(e.error || "Suche nicht möglich."); }
  await loadActions(true);
}
function backupRows(a, st) {
  const bs = (a.params && a.params.backups) || [];
  const logs = (a.params && a.params.logs) || [];
  if (!st.selB) st.selB = [];
  if (!st.selL) st.selL = [];
  const reset = () => { st.preview = null; st.ok = false; render(); };
  const fmtD = t => t ? new Date(t * 1000).toLocaleString("de-DE", { dateStyle: "short", timeStyle: "short" }) : "?";
  const fmtStamp = t => { const m = /^(\d{4})(\d{2})(\d{2})-(\d{2})(\d{2})/.exec(t || ""); return m ? m[3] + "." + m[2] + "." + m[1] + " " + m[4] + ":" + m[5] : (t || "?"); };
  const rows = bs.map((b, i) => h("label", { class: "uprow" },
    h("input", { type: "checkbox", checked: st.selB.includes(b.name), disabled: st.running,
      onchange: e => { st.selB = e.target.checked ? [...st.selB, b.name] : st.selB.filter(x => x !== b.name); reset(); } }),
    h("span", {}, h("b", { text: b.name }), "   " + b.kind + ", " + fmtSize((b.kb || 0) * 1024) + ", angelegt " + fmtD(b.mtime),
      i === 0 ? h("span", { class: "tag", text: "neueste" }) : null,
      b.malware ? h("span", { class: "tag warnTag", text: "enthält möglicherweise Schadcode" }) : null,
      h("span", { class: "small muted", text: "   Inhalt: " + ((b.files || []).join(", ") || "-") }))));
  const logRows = logs.map(l => h("label", { class: "uprow" },
    h("input", { type: "checkbox", checked: !l.newest && st.selL.includes(l.name), disabled: st.running || l.newest,
      onchange: e => { st.selL = e.target.checked ? [...st.selL, l.name] : st.selL.filter(x => x !== l.name); reset(); } }),
    h("span", {}, h("b", { text: l.name }), "   " + fmtSize((l.kb || 0) * 1024) + ", " + fmtStamp(l.stamp),
      l.newest ? h("span", { class: "tag", text: "neuestes dieser Aktion, bleibt erhalten" }) : null)));
  const box = h("div", {});
  if (bs.length) box.append(h("div", { class: "small" }, h("strong", { text: "Sicherungen auf dem Server" })), h("div", { class: "uplist" }, rows));
  if (logs.length) box.append(h("div", { class: "small", style: "margin-top:8px" }, h("strong", { text: "Protokolle früherer Aktionen auf diesem Computer" })),
    h("div", { class: "uplist" }, logRows));
  box.append(h("div", { class: "actions", style: "margin:6px 0" },
    h("button", { class: "btn mini", type: "button", disabled: st.running, onclick: () => { st.selB = bs.slice(1).map(b => b.name); st.selL = logs.filter(l => !l.newest).map(l => l.name); reset(); } }, "Alle außer der neuesten auswählen"),
    h("button", { class: "btn mini ghost", type: "button", disabled: st.running, onclick: () => { st.selB = []; st.selL = []; reset(); } }, "Auswahl aufheben")));
  return box;
}
function tmpInfo(a) {
  const info = (a.params && a.params.info) || [];
  const box = h("div", {});
  if (info.length) box.append(h("ul", { class: "items" }, info.map(t => h("li", { text: t.dir + ": " + t.count + " Einträge, " + fmtSize((t.kb || 0) * 1024) + (t.php ? ", davon " + t.php + " PHP-Datei(en)" : "") }))));
  const p = a.params || {};
  if (p.images_tmp_exists === false) box.append(h("p", { class: "small muted", text: "Geprüft: Den Ordner images/tmp gibt es auf deinem Server nicht. Er wird deshalb nicht angefasst." }));
  if ((p.candidates || []).length) box.append(h("p", { class: "small", text: "Weitere Ordner namens tmp/temp unter images (werden NICHT automatisch geleert): " + p.candidates.join(", ") }));
  return box.childNodes.length ? box : null;
}
/* "Zuerst ein Rückweg:" am Anfang einer Beschreibung wird rot und fett gezeigt: Das ist der wichtigste Satz einer Aktion. */
function summaryParts(text) {
  const t = String(text || "");
  const m = /^(Zuerst ein Rückweg:)\s*/.exec(t);
  return m ? [h("strong", { class: "redbold", text: m[1] }), " " + t.slice(m[0].length)] : [t];
}
function actionBlock(a) {
  const st = actState(a.id);
  const sev = a.risk === "hoch" ? "crit" : a.risk === "mittel" ? "warn" : "info";
  const box = h("div", { class: "finding action", "data-s": sev, id: "act-" + a.id });
  box.append(stepHead(a), h("h4", {}, badge(sev, RISK_LABEL[a.risk] || a.risk, "margin-right:8px"), riskMeter(a.risk), a.title),
    h("p", {}, ...summaryParts(a.summary)), h("p", { class: "small act-sub", text: "Warnung: " + a.warning }),
    a.sicherung && a.sicherung.text ? h("p", { class: "small act-sub", "data-sicherung": a.sicherung.art }, h("strong", { text: "Sicherung vorher: " }), a.sicherung.text) : null);
  if (a.id === "install_security" || a.id === "install_backup") box.append(securityOffer(a, st));
  if (a.irreversible) box.append(h("div", { class: "notice err irrev", style: "margin:10px 0;border:2px solid #c62828;font-weight:600" }, h("div", {},
    h("strong", { text: "NICHT VOLLSTÄNDIG RÜCKGÄNGIG ZU MACHEN" }),
    h("div", { text: "Diese Aktion wirkt auch dann weiter, wenn du sie auf dem Server zurücknimmst (in den Browsern deiner Besucher). Lies die Warnung genau, bevor du fortfährst." }))));
  if (a.reason) { box.append(h("p", { class: "small", text: a.reason })); return box; }
  if (a.id === "clean_tmp") { const ti = tmpInfo(a); if (ti) box.append(h("div", { class: "small" }, h("strong", { text: "Das liegt dort jetzt:" }), ti)); }
  if (a.id === "delete_old_backups") box.append(backupRows(a, st));
  if (a.params && Array.isArray(a.params.pick) && a.params.pick.length) {
    if (!st.pick) st.pick = a.params.pick.filter(x => x.pre).map(x => x.key);
    box.append(h("p", { class: "small" }, h("strong", { text: "Auswahl: " }), a.id === "restore_quarantine"
      ? "Nur angehakte Dateien werden zurückgeholt. Es ist nichts vorausgewählt. Hole nur Dateien zurück, die du sicher kennst."
      : a.id === "delete_quarantine"
      ? "Nur angehakte Ordner werden samt Inhalt endgültig gelöscht. Es ist nichts vorausgewählt."
      : "Nur angehakte Einträge werden angefasst. Wähle ab, was du kennst und behalten willst."));
    box.append(h("div", { class: "uplist" }, a.params.pick.map(x => h("label", { class: "uprow" },
      h("input", { type: "checkbox", checked: st.pick.includes(x.key), disabled: st.running,
        onchange: e => { st.pick = e.target.checked ? [...st.pick, x.key] : st.pick.filter(k => k !== x.key); st.preview = null; st.ok = false; render(); } }),
      h("span", {}, x.label)))));
  }
  if (a.id === "update_extensions") {
    const ups = (a.params && a.params.updates) || [];
    if (!st.sel) st.sel = ups.filter(u => !u.major).map(u => u.uid);
    box.append(h("div", { class: "uplist" }, ups.map(u => h("label", { class: "uprow" },
      h("input", { type: "checkbox", checked: st.sel.includes(u.uid), disabled: st.running,
        onchange: e => { st.sel = e.target.checked ? [...st.sel, u.uid] : st.sel.filter(x => x !== u.uid); st.preview = null; st.ok = false; render(); } }),
      h("span", {}, h("b", { text: u.name }), "  " + (u.old || "?") + " → " + u.new,
        u.major ? h("span", { class: "tag warnTag", text: "neue Hauptversion, nicht vorausgewählt" }) : null,
        h("span", { class: "small muted", text: "   Quelle: " + (u.source || "?") }))))));
  }
  if (a.needs_php) {
    if (!st.php) { const d = (a.php_choices || []).find(c => c.default); if (d) st.php = d.name; }
    const sel = h("select", { id: "php-" + a.id, onchange: e => { st.php = e.target.value; st.preview = null; st.ok = false; render(); } },
      h("option", { value: "", text: "PHP-Programm wählen ..." }),
      (a.php_choices || []).map(c => h("option", { value: c.name, selected: c.name === st.php, text: c.name + " (PHP " + c.version + ")" })));
    box.append(h("div", { class: "small" }, "PHP-Programm für den " + cmsName() + "-Befehl: ", sel));
  }
  if (st.last) box.append(h("div", { class: "notice " + (st.last.ok ? "ok" : "err"), style: "margin:10px 0" }, h("div", {}, h("strong", { text: st.last.ok ? "Zuletzt ausgeführt: erfolgreich" : "Zuletzt ausgeführt: nicht erfolgreich" }),
    h("div", { class: "small", text: st.last.text || "" }))));
  if (st.last && (st.last.manual || []).length) {
    box.append(h("div", { class: "notice warn", style: "margin:10px 0" }, h("div", {}, h("strong", { text: "Diese Erweiterung(en) lassen sich nicht über den Server installieren" }),
      h("div", { class: "small", text: "Der Installer der Erweiterung ist nicht für die Kommandozeile gebaut. Das ist keine Fehlbedienung. Installiere sie so: Joomla-Backend -> System -> Aktualisieren, dort die Erweiterung auswählen und „Aktualisieren“ drücken. " +
        "Alternativ das ZIP von der Adresse laden und unter System -> Installieren -> Erweiterungen hochladen." }),
      st.last.manual.map(m => h("div", { class: "small", style: "margin-top:6px" }, h("b", { text: m.name + " " + m.version }), "  ", h("code", { text: m.url }), " ",
        h("button", { class: "btn mini", type: "button", onclick: () => copyText(m.url) }, "Adresse kopieren"))))));
  }
  if (a.can_skip_backup && st.last && !st.last.ok && st.last.backupFailed && !st.noBackup) {
    box.append(h("div", { class: "notice warn", style: "margin:10px 0" }, h("div", {}, h("strong", { text: "Die Sicherung ist nicht gelungen, deshalb wurde nichts gelöscht." }),
      h("div", { class: "small", text: "Wenn du die Sicherung nicht brauchst (die Profile sind ohnehin schädlich), kannst du sie auch OHNE Sicherung löschen. Dann gibt es keine Kopie." }),
      h("div", { class: "actions", style: "margin:8px 0 0" }, h("button", { class: "btn danger", type: "button", onclick: () => { st.noBackup = true; st.preview = null; st.ok = false; render(); } }, "Profile trotzdem löschen (ohne Sicherung) ...")))));
  }
  if (st.noBackup) box.append(h("div", { class: "notice err", style: "margin:10px 0" }, h("div", {}, h("strong", { text: "Modus: ohne Sicherung" }),
    h("div", { class: "small", text: "Die Profile werden gelöscht, ohne dass eine Kopie entsteht." }),
    h("div", { class: "actions", style: "margin:8px 0 0" }, h("button", { class: "btn mini", type: "button", onclick: () => { st.noBackup = false; st.preview = null; st.ok = false; render(); } }, "Zurück zum normalen Modus")))));
  const needsSel = ((a.id === "install_security" || a.id === "install_backup") && !st.tool) || (a.id === "update_extensions" && !(st.sel || []).length) || (a.id === "delete_old_backups" && !(st.selB || []).length && !(st.selL || []).length)
    || (a.params && Array.isArray(a.params.pick) && a.params.pick.length && !(st.pick || []).length);
  if (a.id === "reset_htaccess") {
    box.append(h("label", { class: "small", style: "display:block;margin:8px 0" },
      h("input", { type: "checkbox", checked: st.keepOwn !== false, onchange: e => { st.keepOwn = e.target.checked; st.preview = null; st.htaccess = null; st.ok = false; render(); } }),
      " Eigene harmlose Regeln und Blöcke bekannter Plugins übernehmen (auffällige Regeln werden nie übernommen)"));
  }
  if (!st.preview) {
    box.append(h("div", { class: "actions", style: "margin:8px 0 0" },
      h("button", { class: "btn", type: "button", disabled: st.running || (a.needs_php && !st.php) || needsSel, onclick: () => previewAction(a) }, "Befehle ansehen")));
  } else {
    box.append(h("div", { class: "small", style: "margin-top:10px" }, h("strong", { text: "Diese Befehle werden ausgeführt:" })),
      codeBox(st.preview, "Befehle"),
      st.htaccess ? htaccessPreview(st.htaccess) : "",
      st.dbcode ? dbcodePreview(st.dbcode) : "",
      h("p", { class: "small", text: "Rückgängig: " + a.undo }),
      h("label", { class: "small", style: "display:block;margin:6px 0" }, h("input", { type: "checkbox", checked: st.ok, onchange: e => { st.ok = e.target.checked; render(); } }),
        st.noBackup ? " Ich weiß, dass dabei KEINE Sicherung entsteht, und möchte die Profile trotzdem löschen." : " Ich habe die Warnung gelesen und möchte das jetzt ausführen."),
      a.irreversible ? h("label", { class: "small", style: "display:block;margin:6px 0;color:#c62828;font-weight:600" }, h("input", { type: "checkbox", checked: !!st.ok2, onchange: e => { st.ok2 = e.target.checked; render(); } }),
        " Ich habe verstanden, dass sich diese Aktion nicht vollständig rückgängig machen lässt (Browser merken sich die Vorgabe 7 Tage), und möchte sie trotzdem ausführen.") : "",
      h("div", { class: "actions", style: "margin:8px 0 0" },
        h("button", { class: "btn " + (a.irreversible ? "danger" : "primary"), type: "button", disabled: !st.ok || (a.irreversible && !st.ok2) || st.running, onclick: () => runAction(a) }, "Jetzt ausführen"),
        h("button", { class: "btn ghost", type: "button", disabled: st.running, onclick: () => { st.preview = null; st.ok = false; st.ok2 = false; render(); } }, "Abbrechen")));
  }
  return box;
}
/* ---- Sicherheits-Erweiterung auswählen: Bild, Kurzbeschreibung und Link kommen vom Store (offline: eigene Texte und Platzhalter) */
async function loadStore(id, kind) {
  const m = (S.storeInfo = S.storeInfo || {});
  const key = (kind === "backup" ? "b:" : "") + id;
  if (m[key]) return;
  m[key] = { loading: true };
  try { m[key] = await api("/api/store-info", { id, kind: kind || "security" }); } catch (e) { m[key] = { failed: true }; }
  if (S.step === "result") render();
}
/* Preis und Bewertung als Symbole: 🆓 kostenlos, 💶/💲 kostenpflichtig, ⭐ Sterne. Symbole stehen in eigenen Knoten (data-nt), der Text daneben wird einzeln übersetzt. */
const ico = x => h("span", { class: "ico", "data-nt": "1", text: x });
function priceTag(p) {
  const x = String(p || "").toLowerCase();
  if (!x) return null;
  const free = x.startsWith("kostenlos"), paid = x.includes("kostenpflichtig") || /[€$]/.test(x);
  const sym = x.includes("$") ? "💲" : "💶";
  if (free && paid) return [ico("🆓 + " + sym), " kostenlos und kostenpflichtig (Pro)"];
  if (paid) return [ico(sym), " " + p];
  if (free) return [ico("🆓"), " " + (x.trim() === "kostenlos" ? "kostenlos (laut Verzeichnis)" : p)];
  return [p];
}
function starsTag(stars, reviews) {
  const n = Math.max(0, Math.min(5, Math.round(Number(stars) || 0)));
  if (!n || !reviews) return null;
  const v = Number(stars), num = Number.isInteger(v) ? String(v) : v.toFixed(1);
  const shown = L.code === "de" ? num.replace(".", ",") : num;
  const text = tr("%s von 5 (%s Bewertungen)").replace("%s", shown).replace("%s", String(reviews));
  return [ico("⭐".repeat(n) + "☆".repeat(5 - n)), h("span", { "data-nt": "1", text: "  " + text })];
}
function securityOffer(a, st) {
  const tools = (a.params && a.params.tools) || [];
  const kind = a.id === "install_backup" ? "backup" : "security", pre = kind === "backup" ? "b:" : "";
  const info = (S.storeInfo = S.storeInfo || {});
  const wrap = h("div", { class: "secoffer" });
  wrap.append(h("p", { class: "small" }, h("strong", { text: "Bei der gewünschten Erweiterung auf „Installieren“ klicken. " }),
    "Bild, Beschreibung und Link stammen von der Store-Seite " + (isWP() ? "(wordpress.org)" : "(Joomla Extensions Directory)") + ". Ohne Internetverbindung siehst du statt dessen die Kurzbeschreibung des Programms."));
  /* erst die kostenlosen, dann unter eigener Überschrift die kostenpflichtigen (Preis unklar zuletzt) */
  const pg = t => { const x = String(t.price || "").toLowerCase(); return x.startsWith("kostenlos") ? 0 : (x.includes("kostenpflichtig") || /[€$]/.test(x)) ? 2 : (t.price === undefined || t.price === null || isWP()) ? 0 : (t.price === "" ? 1 : 0); };
  const sorted = tools.map((t, n) => [pg(t), n, t]).sort((p, q) => p[0] - q[0] || p[1] - q[1]);
  const mixed = new Set(sorted.map(e => e[0])).size > 1;
  let lastGroup = -1;
  for (const [grp, , t] of sorted) {
    if (mixed && grp !== lastGroup) wrap.append(h("h4", { class: "sec-group", text: grp === 0 ? "Kostenlos" : grp === 2 ? "Kostenpflichtig" : "Preis im Verzeichnis nachsehen" }));
    lastGroup = grp;
    if (!info[pre + t.id]) loadStore(t.id, kind);
    const i = info[pre + t.id] || {};
    const pic = i.image ? h("img", { class: "secimg", src: i.image, alt: "", width: "64", height: "64" })
      : h("div", { class: "secimg ph", "aria-hidden": "true", text: (t.name || "?").trim().charAt(0).toUpperCase() });
    const stars = starsTag(t.stars || i.stars, t.reviews || i.reviews) || (t.rating ? [t.rating] : null);
    const price = priceTag(t.price) || (isWP() ? [ico("🆓"), " kostenlos im Verzeichnis (Zusatzfunktionen können kostenpflichtig sein)"] : null);
    const metaParts = [price, stars, t.developer ? [t.developer] : null].filter(Boolean);
    const meta = [];
    metaParts.forEach((part, k) => { if (k) meta.push("  |  "); meta.push(...part); });
    const radio = h("input", { type: "radio", name: "secsel", checked: st.tool === t.id, disabled: st.running || !t.installable,
      onchange: () => { st.tool = t.id; st.preview = null; st.ok = false; render(); } });
    wrap.append(h("div", { class: "seccard" + (st.tool === t.id ? " sel" : "") + (t.installable ? "" : " off") },
      pic,
      h("div", { class: "secbody" },
        h("label", { class: "sectitle" }, radio, h("b", { text: " " + t.name }),
          t.installable ? null : h("span", { class: "tag", text: isWP() ? "nicht installierbar (WP-CLI fehlt)" : "nur Store-Link" })),
        meta.length ? h("div", { class: "small muted" }, meta) : null,
        h("div", { class: "small", text: i.short || t.text }),
        t.howto ? h("div", { class: "small muted", text: t.howto }) : null,
        t.stand ? h("div", { class: "small muted", text: "Download-Adresse des Herstellers geprüft, Stand der Liste: " + t.stand }) : null,
        t.installable && !st.running ? h("div", { class: "secact" }, h("button", { class: "btn primary mini", type: "button", onclick: () => { st.tool = t.id; st.preview = null; st.ok = false; previewAction(a); } }, "Installieren …"), h("span", { class: "small muted", text: "  Zeigt die Befehle und die Bestätigung unten." })) : null,
        h("div", { class: "small" }, (grp === 2 || !t.installable) ? h("a", { href: t.store_url, target: "_blank", rel: "noopener noreferrer", text: "Store-Seite öffnen" }) : null,
          i.live === false && !i.loading ? h("span", { class: "muted", text: "   (Store nicht erreichbar: eigener Text)" }) : null))));
  }
  return wrap;
}
function actBody(a, st) {
  return { id: a.id, tool: st.tool || "", php: st.php, selected: st.sel || [], backups: st.selB || [], logs: st.selL || [], pick: st.pick || [], no_backup: !!st.noBackup, keep_own: st.keepOwn !== false };
}
async function previewAction(a) {
  const st = actState(a.id);
  try { const p = await api("/api/action-preview", actBody(a, st)); st.preview = p.commands; st.htaccess = p.htaccess || null; st.dbcode = p.dbcode || null; st.ok = false; st.ok2 = false; }
  catch (e) { toast(e.error || "Vorschau nicht möglich."); }
  render();
}

/* ---- Schadcode von Hand entfernen: Ausschnitt mit Zeilennummern, Schadstelle rot markiert */
function snipKey(t) { return t.file + ":" + t.line; }
function manualCodeBlock(p) {
  const list = (S.actions && S.actions.manual) || [];
  const box = h("div", { class: "finding action manual", "data-s": "crit", id: "act-manual_code" });
  box.append(stepHead(p), h("h4", {}, h("span", { class: "badge", "data-s": "crit", style: "margin-right:8px", text: "von Hand" }), p.title),
    h("p", { text: "In diesen Dateien steckt Code, der dort nicht hingehört, mitten zwischen normalem Code. Das Programm löscht ihn nicht selbst, weil dabei auch Wichtiges verloren gehen könnte. Du siehst unten die Stelle: " +
      "die Schadstelle ist rot markiert, die grauen Zeilen davor und danach sind zur Orientierung. Mache vorher eine Kopie der Datei." }));
  for (const t of list) {
    const k = snipKey(t), sn = (S.snip = S.snip || {})[k] || (S.snip[k] = { loading: false, data: null, err: "" });
    const item = h("div", { class: "snip-item" }, h("div", { class: "snip-title" }, h("code", { text: t.file }), "  Zeile " + t.line));
    if (!sn.data && !sn.loading) item.append(h("div", { class: "actions", style: "margin:6px 0" }, h("button", { class: "btn", type: "button", onclick: () => loadSnippet(t) }, "Ausschnitt anzeigen")));
    if (sn.loading) item.append(h("p", { class: "small", text: "Lese die Stelle vom Server ..." }));
    if (sn.err) item.append(h("div", { class: "notice err" }, h("div", {}, sn.err)));
    if (sn.data) item.append(snippetView(sn.data));
    box.append(item);
  }
  return box;
}
async function loadSnippet(t) {
  const sn = S.snip[snipKey(t)]; sn.loading = true; sn.err = ""; render();
  try { sn.data = await api("/api/snippet", { file: t.file, line: t.line }); } catch (e) { sn.err = e.error || "Der Ausschnitt konnte nicht gelesen werden."; }
  sn.loading = false; render();
}
function segEl(sg) {
  if (sg.k === "bad") return h("span", { class: "snip-bad", title: sg.label || "Schadstelle", text: sg.s });
  if (sg.k === "gap") return h("span", { class: "snip-gap" + (sg.bad ? " snip-gapbad" : ""), text: sg.s });
  return h("span", { text: sg.s });
}
function snippetView(d) {
  const wrap = h("div", { class: "snip" });
  wrap.append(h("p", { class: "small", text: d.how }));
  const o = d.original || {};
  // Die Zeile, die stehen bleiben soll: Original (wenn vorhanden), sonst die Zeile ohne die rote Stelle
  const useOrig = (o.status === "identisch" || o.status === "abweichend") && typeof o.line === "string";
  const inserted = o.status === "eingefuegt";
  const keep = useOrig ? o.line : (d.fixed_line || "");
  const keepEmpty = inserted || !(keep || "").trim();
  const keepLabel = useOrig ? "Original" : "So soll es sein";
  const tbl = h("div", { class: "snip-code", role: "region", "aria-label": "Ausschnitt aus " + d.file });
  for (const r of d.rows) {
    tbl.append(h("div", { class: "snip-row" + (r.role === "ziel" ? " snip-target" : "") },
      h("span", { class: "snip-ln", text: String(r.n) }),
      h("span", { class: "snip-tx" }, r.segs.map(segEl)),
      r.role === "ziel" ? h("span", { class: "snip-mark", text: d.found ? "◄ löschen / ersetzen" : "◄ prüfen" }) : null));
    if (r.role === "ziel") {
      tbl.append(h("div", { class: "snip-row snip-keep" },
        h("span", { class: "snip-ln", text: "+" }),
        keepEmpty ? h("span", { class: "snip-tx snip-keeptxt" }, "(" + (inserted ? "im Original gibt es diese Zeile nicht" : "danach leer") + ": die ganze Zeile löschen)")
                  : h("span", { class: "snip-tx snip-keeptxt", text: keep }),
        h("span", { class: "snip-mark snip-keepmark", text: "◄ " + keepLabel + " (grün = bleibt)" })));
    }
  }
  wrap.append(tbl);
  // Ergebnis des Abgleichs mit dem Original, in Worten
  let msg = "";
  if (o.status === "identisch") msg = "Abgleich mit dem Original (" + o.source + "): Ohne die rote Stelle ist die Zeile genau wie im Original. Das Original steht grün darunter.";
  else if (o.status === "abweichend") msg = "Abgleich mit dem Original (" + o.source + "): Die Originalzeile (Zeile " + o.n + " im Original) steht grün darunter. Ersetze die rote Zeile durch sie.";
  else if (o.status === "eingefuegt") msg = "Abgleich mit dem Original (" + o.source + "): Die rote Zeile ist im Original nicht vorhanden, sie wurde eingefügt. Du kannst sie ganz löschen; die grauen Zeilen bleiben.";
  else if (o.status === "nicht_zuordenbar") msg = "Abgleich mit dem Original (" + o.source + "): Die Zeilen ließen sich dem Original nicht sicher zuordnen (Datei verändert oder andere Version). Die grüne Zeile ist aus der Zeile selbst abgeleitet. Prüfe sie besonders genau.";
  else if (o.note) msg = o.note;
  if (msg) wrap.append(h("p", { class: "small snip-orignote", "data-st": o.status || "", text: msg }));
  if (!keepEmpty) wrap.append(h("div", { class: "actions", style: "margin:6px 0" }, h("button", { class: "btn mini", type: "button", onclick: () => copyText(keep) }, "Grüne Zeile kopieren")));
  wrap.append(h("p", { class: "small muted", text: "Grün = so soll die Zeile aussehen und bleibt stehen. Rot = weg damit. Grau = unverändert, nur zur Orientierung. Datei " + d.file + (d.total ? " (" + d.total + " Zeilen)" : "") +
    ". Bearbeite sie mit dem Datei-Manager deines Hosters oder per SFTP in einem Texteditor. Danach: Prüfung wiederholen." }));
  return wrap;
}

/* ---- Statusfenster: zeigt Befehle, Antworten des Servers und das Ergebnis, solange eine Aktion läuft */
function statusBody() {
  const T = S.status, wrap = h("div", { class: "modal-in" });
  wrap.append(h("div", { class: "modal-head" }, h("div", {}, h("h2", { id: "st-title", text: T.title }),
    h("div", { class: "small muted", text: T.done ? "Beendet nach " + fmtTime(T.elapsed) + " Min." : "Läuft seit " + fmtTime(T.elapsed) + " Min. Bitte dieses Fenster offen lassen." })),
    T.done ? null : h("div", { class: "spinner", "aria-hidden": "true" })));
  const term = h("div", { class: "term", id: "st-term", role: "log", "aria-live": "polite" });
  for (const ev of T.events) {
    if (ev.t === "cmd") term.append(h("div", { class: "tl tl-cmd" }, h("span", { class: "tl-lbl", text: "Befehl an den Server" }), h("pre", { text: ev.text })));
    else if (ev.t === "out") term.append(h("div", { class: "tl tl-out" }, h("span", { class: "tl-lbl", text: "Antwort des Servers" }), h("pre", { text: ev.text })));
    else if (ev.t === "ok") term.append(h("div", { class: "tl tl-ok", text: "✓ " + ev.text }));
    else if (ev.t === "err" || ev.t === "fail") term.append(h("div", { class: "tl tl-err", text: "✗ " + ev.text }));
    else if (ev.t === "done") term.append(h("div", { class: "tl tl-ok tl-big", text: "✓ " + ev.text }));
    else term.append(h("div", { class: "tl tl-info", text: ev.text }));
  }
  if (!T.done) term.append(h("div", { class: "tl tl-wait", text: "Warte auf den Server ..." }));
  // Merkt, ob der Nutzer ganz unten ist (dann folgt das Fenster neuen Zeilen) oder weiter oben liest (dann bleibt die Stelle stehen)
  term.addEventListener("scroll", () => {
    const near = term.scrollTop + term.clientHeight >= term.scrollHeight - 30;
    if (S.status) S.status.stick = near;
    const b = document.getElementById("st-jump"); if (b) b.hidden = near;
  });
  wrap.append(term);
  wrap.append(h("button", { class: "btn mini st-jump", id: "st-jump", type: "button", hidden: S.status.stick !== false,
    onclick: () => { const t = document.getElementById("st-term"); if (t) { S.status.stick = true; t.scrollTop = t.scrollHeight; } } }, "↓ Zum aktuellen Stand"));
  if (T.done) {
    const r = T.result || {}, ok = !!T.ok;
    wrap.append(h("div", { class: "notice " + (ok ? "ok" : "err"), id: "st-final", role: "status" }, h("div", {},
      h("strong", { text: ok ? "Erfolgreich abgeschlossen" : "Nicht erfolgreich abgeschlossen" }),
      h("div", { text: ok ? (r.message || "Die Aktion wurde ausgeführt.") : (r.error || T.error || "Details stehen im Protokoll oben. Es wurde nichts verändert, was nicht gemeldet wurde.") }),
      r.backup_dir ? h("div", { class: "small", text: "Sicherung auf dem Server: " + r.backup_dir }) : null,
      (ok && Array.isArray(r.recheck) && r.recheck.length) ? h("div", { class: "small recheck" }, h("strong", { text: "Kontrolle danach:" }),
        r.recheck.map(c => h("div", {}, h("span", { text: c.title + " " }), h("span", { class: c.better ? "" : "bad", text: c.before }), " ", h("span", { text: c.after })))) : null,
      r.log ? h("div", { class: "small", text: "Protokoll auf diesem PC: " + r.log }) : null,
      ok ? h("div", { class: "small", text: "Prüfe danach deine Webseite im Browser und wiederhole die Prüfung." }) : null)));
  }
  wrap.append(h("div", { class: "actions", style: "margin:12px 0 0" },
    h("button", { class: "btn", type: "button", onclick: () => copyText(T.events.map(e => (e.t === "cmd" ? "$ " : e.t === "out" ? "> " : "") + e.text).join("\n")) }, "Protokoll kopieren"),
    h("button", { class: "btn primary", id: "st-close", type: "button", disabled: !T.done, onclick: closeStatus }, T.done ? "Schließen" : "Läuft ...")));
  return wrap;
}
function showStatus() {
  let back = document.getElementById("status-modal");
  if (!back) {
    back = h("div", { class: "modal-back", id: "status-modal" });
    back.append(h("div", { class: "modal", role: "dialog", "aria-modal": "true", "aria-labelledby": "st-title" }));
    document.body.append(back);
  }
  updateStatus();
}
function updateStatus() {
  const back = document.getElementById("status-modal"); if (!back || !S.status) return;
  const box = back.firstChild, old = document.getElementById("st-term");
  const keep = old ? old.scrollTop : 0;                           // vor dem Austausch lesen: ein ausgebautes Element meldet 0
  const stick = S.status.stick !== false;
  box.replaceChildren(statusBody());
  const t = document.getElementById("st-term");
  if (t) t.scrollTop = stick ? t.scrollHeight : keep;
  if (S.status.done) { const c = document.getElementById("st-close"); if (c && !S.status.focused) { c.focus(); S.status.focused = true; } }
}
async function closeStatus() {
  const T = S.status; if (!T || !T.done) return;
  const st = actState(T.id);
  st.running = false; st.preview = null; st.ok = false; st.ok2 = false;
  st.last = { ok: !!T.ok, text: T.ok ? ((T.result || {}).message || "") : ((T.result || {}).error || T.error || ""), backupFailed: !!(T.result || {}).backup_failed, manual: (T.result || {}).manual || [], failed: (T.result || {}).failed || [] };
  if (T.ok) { st.noBackup = false; st.selB = null; st.selL = null; st.sel = null; st.pick = null; }
  const back = document.getElementById("status-modal"); if (back) back.remove();
  S.status = null;
  await loadActions();
  if (S.dashReopen) { S.dashReopen = false; if (S.dashServer && S.dashServer.connected) S.dashServer = null; openDashboard(); }
}
async function runAction(a) {
  const st = actState(a.id); st.running = true;
  S.status = { id: a.id, title: a.title, events: [], done: false, ok: null, result: null, next: 0, elapsed: 0, error: "" };
  showStatus();
  try { await api("/api/action-run", Object.assign(actBody(a, st), { confirm: true, confirm_no_backup: !!st.noBackup, confirm_irreversible: !!st.ok2 })); }
  catch (e) {
    S.status.done = true; S.status.ok = false; S.status.error = e.error || "Die Aktion konnte nicht gestartet werden.";
    S.status.events.push({ t: "fail", text: S.status.error }); updateStatus(); return;
  }
  for (;;) {
    await sleep(400);
    let r;
    try { r = await api("/api/action-state?since=" + S.status.next); }
    catch (e) { S.status.events.push({ t: "fail", text: "Die Verbindung zum Programm ist abgebrochen." }); S.status.done = true; S.status.ok = false; break; }
    S.status.events.push(...r.events); S.status.next = r.next; S.status.elapsed = r.elapsed;
    if (r.done) { S.status.done = true; S.status.ok = r.ok; S.status.result = r.result; S.status.error = r.error || ""; break; }
    updateStatus();
  }
  updateStatus();
}
async function handover() {
  S.exporting = true; render();
  try {
    const r = await api("/api/handover", {});
    S.exported = { dir: r.dir, files: r.files || [] };
    S.handover = r;
    try { await navigator.clipboard.writeText(r.prompt); toast("Text für Claude kopiert (Strg+V zum Einfügen)."); } catch (e) { /* Text steht unten zum Kopieren */ }
    window.open(r.url, "_blank", "noopener");
  } catch (e) { toast(e.error || "Übergabe nicht möglich."); }
  S.exporting = false; render();
}
async function copyHandover() {
  const t = document.getElementById("handover-text");
  try { await navigator.clipboard.writeText(t.value); toast("Text kopiert."); }
  catch (e) { t.select(); document.execCommand("copy"); toast("Text kopiert."); }
}
async function downloadZip() {
  try {
    const r = await fetch("/api/zip", { headers: { "X-Claudia": "1" } });
    if (!r.ok) throw await r.json();
    const url = URL.createObjectURL(await r.blob());
    const a = h("a", { href: url, download: "fuer_claude.zip" });
    document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 5000);
    toast("fuer_claude.zip wurde heruntergeladen.");
  } catch (e) { toast(e.error || "Download nicht möglich."); }
}
async function saveReports() {
  S.exporting = true; render();
  try { S.exported = await api("/api/export", {}); }
  catch (e) { toast(e.error || "Speichern nicht möglich."); }
  S.exporting = false; render();
}
async function openFolder() {
  try { await api("/api/open-folder", {}); } catch (e) { toast(e.error || "Ordner nicht zu öffnen."); }
}

function resultCard(r) {
  const c = checkById(r.id) || { what: "", why: "", reads: "" };
  const grp = (S.init.groups.find(g => g.id === r.group) || {}).title || "";
  const el = h("details", { class: "res", id: "res-" + r.id, "data-s": r.status, open: r.status === "crit" || r.status === "error" },
    h("summary", {}, h("div", {}, h("div", { class: "res-t", text: r.title }), h("div", { class: "res-s", text: grp })),
      badge(r.status, SEV_LABEL[r.status])));
  const body = h("div", { class: "res-body" });
  if (r.message) body.append(h("div", { class: "notice " + (r.status === "error" ? "err" : "warn") }, h("div", {}, h("strong", { text: r.status === "error" ? "Der Test ist fehlgeschlagen" : "Der Test wurde übersprungen" }), r.message)));
  for (const f of r.findings) {
    body.append(h("div", { class: "finding", "data-s": f.sev },
      h("h4", {}, badge(f.sev, SEV_LABEL[f.sev], "margin-right:8px"), f.title),
      f.detail ? h("p", { text: f.detail }) : null,
      f.items && f.items.length ? h("ul", { class: "items" }, f.items.map(t => ratingLine(t))) : null,
      f.evidence && f.evidence.length ? h("div", { class: "cw-list" }, f.evidence.map(ev => codeWindow(ev, false))) : null,
      f.hint ? h("div", { class: "advice" }, h("b", { text: "Empfehlung:" }), f.hint) : null,
      fixOffer(r, f)));
  }
  if (!r.findings.length && !r.message) body.append(h("p", { class: "muted", text: "Keine Einzelbefunde." }));
  body.append(h("details", {}, h("summary", { class: "link small", style: "cursor:pointer;display:inline-block", text: "Was macht dieser Test?" }),
    h("div", { class: "detail", style: "margin-top:8px" },
      h("div", {}, h("h4", { text: "Was passiert?" }), h("p", { text: c.what })),
      h("div", {}, h("h4", { text: "Warum ist das wichtig?" }), h("p", { text: c.why })),
      h("div", {}, h("h4", { text: "Was wird gelesen?" }), h("p", { text: c.reads })))));
  const raws = (r.raw_files || []).map(x => x.name + " (" + fmtSize(x.size) + ")").join(", ");
  body.append(h("div", { class: "res-foot", text: "Dauer " + r.seconds + " s" + (raws ? "  |  Rohdaten für den Export: " + raws : "") }));
  el.append(body);
  return el;
}
/* Lösung direkt am Befund anbieten (öffnet die Vorschau der Befehle weiter oben, nichts wird ohne Bestätigung geändert) */
const FIX_FOR = [
  { test: "db_jce", sev: ["crit"], action: "remove_jce_profiles", label: "Diese JCE-Profile über die Datenbank löschen ..." },
  { test: "webshells", sev: ["crit"], title: /Hintert/, action: "remove_shells", label: "Diese Dateien entfernen ..." },
  { test: "php_in_uploads", sev: ["crit"], action: "remove_shells", label: "PHP-Dateien in images entfernen ..." },
  { test: "perms", sev: ["crit", "warn"], title: /beschreibbar/, action: "fix_permissions", label: "Schreibrechte für alle entfernen ..." },
  /* Automatische Updates: Rechte, Reste, hängender Wartungsmodus (Joomla und WordPress) */
  { test: "update_ready", sev: ["crit", "warn"], title: /ohne Schreibrecht für den Besitzer/, action: "fix_update_perms", label: "Schreibrecht für den Besitzer wiederherstellen ..." },
  { test: "update_ready", sev: ["crit", "warn"], title: /für alle beschreibbar/, action: "fix_permissions", label: "Schreibrechte für alle entfernen ..." },
  { test: "update_ready", sev: ["crit", "warn"], title: /^\.maintenance liegt/, action: "wp_remove_maintenance", label: "Wartungsmodus beenden (.maintenance löschen) ..." },
  { test: "update_ready", sev: ["warn"], title: /abgebrochener oder alter Updates/, action: "clean_tmp", label: "Temp-Ordner leeren ..." },
  { test: "joomla_core", sev: ["info"], title: /^Kerndateien lassen sich aus dem Original neu einspielen/, action: "joomla_core_reinstall", label: "Kerndateien aus dem Original neu einspielen ..." },
  { test: "joomla_core", sev: ["crit", "warn"], title: /weichen vom Original ab|fehlen/, action: "joomla_core_reinstall", label: "Kerndateien aus dem Original neu einspielen ..." },
  /* WordPress: gleiche Mechanik, andere Befunde */
  { test: "wp_core", sev: ["crit", "warn"], title: /weichen vom Original ab|fehlen/, action: "wp_core_reinstall", label: "WordPress-Kerndateien neu einspielen ..." },
  { test: "wp_plugins", sev: ["crit", "warn"], title: /Sicherheitslücke/, action: "wp_update", label: "Plugins und Themes aktualisieren ..." },
  { test: "wp_plugins_online", sev: ["crit", "warn"], title: /neuere Version|UNSICHER|veraltet/, action: "wp_update", label: "Plugins und Themes aktualisieren ..." },
  { test: "wp_info", sev: ["warn", "crit"], title: /^WordPress ist älter/, action: "wp_update", label: "WordPress aktualisieren ..." },
  { test: "wp_config", sev: ["warn", "crit"], title: /^Schlüssel und Salts/, action: "wp_salts", label: "Neue Schlüssel und Salts setzen ..." },
  { test: "wp_config", sev: ["info", "warn", "crit"], title: /^Dateien lassen sich im Dashboard bearbeiten/, action: "wp_disallow_edit", label: "Datei-Editor im Dashboard abschalten ..." },
  { test: "web_headers", sev: ["info"], title: /Sicherheits-Header fehlen/, action: "harden_headers", label: "Fehlende Sicherheits-Header setzen ..." },
  { test: "web_headers", sev: ["info"], title: /Sicherheits-Header fehlen/, action: "harden_hsts", label: "HSTS aktivieren (rote Aktion, mit Hinweis) ..." },
  { test: "wp_exposure", sev: ["warn"], title: /geben Informationen preis/, action: "harden_listing", label: "Ordnerlisten abschalten ..." },
  { test: "wp_exposure", sev: ["info"], title: /Hinweis\(e\) zur Absicherung/, action: "wp_block_xmlrpc", label: "XML-RPC sperren ..." },
  { test: "joomla_api", sev: ["warn", "info"], title: /(API-Zugang aktiv|^Web-Services aktiv)/, action: "disable_api", label: "Joomla-API abschalten ..." },
  { test: "wp_db_options", sev: ["warn", "crit"], title: /^(Jeder darf sich als Administrator|Offene Registrierung mit der Rolle)/, action: "wp_fix_registration", label: "Registrierung absichern ..." },
];
function fixOffer(r, f) {
  const m = FIX_FOR.find(x => x.test === r.id && x.sev.includes(f.sev) && (!x.title || x.title.test(f.title)));
  if (!m || !S.actions || !S.actions.connected || S.running) return null;
  const a = (S.actions.actions || []).find(x => x.id === m.action && !x.hidden);
  if (!a) return null;
  return h("div", { class: "actions", style: "margin:10px 0 0" },
    h("button", { class: "btn", type: "button", onclick: async () => {
      if (!a.reason) await previewAction(a);
      const el = document.getElementById("act-" + a.id); if (el) el.scrollIntoView({ behavior: "smooth", block: "center" });
    } }, m.label),
    h("span", { class: "small muted", text: "  Du siehst zuerst die Befehle und bestätigst danach noch einmal." }));
}
function fmtSize(n) { return n < 1024 ? n + " B" : n < 1048576 ? Math.round(n / 1024) + " KB" : (n / 1048576).toFixed(1) + " MB"; }

function jumpTo(id) {
  S.filter = null;
  const el = document.getElementById("res-" + id);
  if (el) { el.open = true; el.scrollIntoView({ behavior: "smooth", block: "start" }); }
}


/* ------------------------------------------------------------------ Programm-Update */
let updShown = false;
function updFrame(title, scroll, foot) {
  const dlg = $("#upddlg"), box = $("#upd-body");
  box.replaceChildren(
    h("div", { class: "uni-head" }, h("h2", { text: title }), h("button", { class: "dlg-x", type: "button", title: "Schließen", "aria-label": "Schließen", onclick: () => dlg.close(), text: "\u2715" })),
    h("div", { class: "uni-scroll" }, scroll),
    foot ? h("div", { class: "uni-foot" }, foot) : null);
  if (!dlg.open) dlg.showModal();
}
async function openUpdate(manual) {
  const dlg = $("#upddlg");
  updFrame("Programm-Update", loadingBox("Suche nach einer neuen Version …"));
  let st;
  try { st = manual ? await api("/api/app-update-check", {}) : await api("/api/app-update"); } catch (e) { updFrame("Programm-Update", h("p", { text: e.error || "Nicht möglich." })); return; }
  renderUpdate(st);
}
function renderUpdate(st) {
  const dlg = $("#upddlg"), close = h("button", { class: "btn ghost", type: "button", onclick: () => dlg.close() }, "Abbrechen");
  if (st.checking) { updFrame("Programm-Update", loadingBox("Suche nach einer neuen Version …")); setTimeout(async () => { try { renderUpdate(await api("/api/app-update")); } catch (e) { /* bleibt */ } }, 1200); return; }
  if (!st.newer) {
    const bad = st.checked && st.ok === false;
    updFrame("Programm-Update", [h("p", { text: bad ? "Die Suche war nicht möglich (keine Internetverbindung oder GitHub nicht erreichbar)." : "Du verwendest die aktuelle Version." }),
      h("p", { class: "hint", text: "Installierte Version: " + (st.current || (S.init && S.init.version) || "?") })],
      h("div", { class: "dlg-actions" }, h("button", { class: "btn", type: "button", onclick: () => dlg.close() }, "Schließen")));
    return;
  }
  const i = st.info, ins = st.install || {};
  if (ins.running || ins.done) { renderInstall(st); return; }
  const go = h("button", { class: "btn primary", type: "button", disabled: !st.installable || S.running }, "Update installieren");
  go.addEventListener("click", async () => {
    go.disabled = true;
    try { renderInstall(await api("/api/app-update-install", { version: i.version })); } catch (e) { toast(e.error || "Nicht möglich."); go.disabled = false; }
  });
  const skip = h("button", { class: "btn ghost", type: "button", onclick: async () => { try { await api("/api/app-update-skip", { version: i.version }); } catch (e) { /* egal */ } $("#updbtn").classList.remove("has-upd"); dlg.close(); } }, "Update überspringen");
  updFrame("Neue Version verfügbar", [
    h("p", { "data-nt": "1", text: tr("Version %s ist verfügbar. Installiert ist Version %s.").replace("%s", i.version).replace("%s", st.current) + (i.published ? " (" + i.published + ")" : "") }),
    i.notes ? h("div", { class: "upd-notes", "data-nt": "1", text: i.notes }) : null,
    h("p", { class: "hint", text: "Beim Installieren wird das Paket geladen und mit der veröffentlichten Prüfsumme verglichen, der bisherige Programmordner wird gesichert und bei einem Fehler automatisch wiederhergestellt. Danach startet CLAUDIA neu. Deine Verbindungen, Einstellungen und Berichte bleiben unverändert." }),
    st.installable ? null : h("p", { class: "hint", text: st.frozen ? "Diese Fassung besteht aus einer einzelnen Programmdatei und aktualisiert sich nicht selbst. Bitte die neue Version von der Release-Seite laden." : "Für diese Version gibt es kein Paket mit veröffentlichter Prüfsumme. Bitte von der Release-Seite laden." }),
    S.running ? h("p", { class: "hint", text: "Bitte warten, bis die Prüfung beendet ist." }) : null,
    i.page ? h("p", {}, h("a", { href: i.page, text: "Release-Seite im Browser öffnen" })) : null],
    h("div", { class: "dlg-actions" }, close, skip, go));
}
function renderInstall(st) {
  const dlg = $("#upddlg"), ins = st.install || {};
  if (ins.error) {
    updFrame("Update fehlgeschlagen", [h("p", { text: ins.error }), h("p", { class: "hint", text: "Protokoll: " + (ins.log || "") })],
      h("div", { class: "dlg-actions" }, h("button", { class: "btn", type: "button", onclick: () => dlg.close() }, "Schließen")));
    return;
  }
  if (ins.done) {
    updFrame("Update installiert", h("p", { text: "CLAUDIA wird jetzt neu gestartet. Dieses Fenster schließt sich von selbst." }));
    api("/api/app-update-restart", {}).catch(() => {});
    return;
  }
  const bar = h("i", {}); bar.style.width = (ins.pct || 1) + "%";
  updFrame("Update wird installiert", [h("p", { text: ins.step || "Start" }), h("div", { class: "upd-bar" }, bar), h("p", { class: "hint", text: "Bitte das Fenster nicht schließen." })]);
  setTimeout(async () => { try { renderInstall(await api("/api/app-update")); } catch (e) { /* Programm startet neu */ } }, 800);
}
async function autoUpdateCheck() {
  for (let n = 0; n < 12; n++) {
    let st;
    try { st = await api("/api/app-update"); } catch (e) { return; }
    if (st.checked && !st.checking) {
      if (st.newer) {
        $("#updbtn").classList.add("has-upd");
        $("#updbtn .rl").textContent = tr("Update verfügbar");
        if (!st.skipped && !updShown && !S.running && !$("#upddlg").open) { updShown = true; renderUpdate(st); }
      }
      return;
    }
    await new Promise(r => setTimeout(r, 2500));
  }
}

/* ------------------------------------------------------------------ Dashboard (Verlauf, Vergleich, Verwaltung) */
/* ------------------------------------------------------------------ Dashboard (Verlauf, Diagramme, Befunde) */
const LVL = { crit: "var(--crit)", warn: "var(--warn)", info: "var(--info)", ok: "var(--ok)" };
const LVL_NAME = { crit: "Kritisch", warn: "Prüfen", info: "Hinweis", ok: "In Ordnung" };
async function openDashboard() {
  S.step = "dash"; S.dashErr = ""; render();
  try {
    S.dash = await api("/api/dashboard");
    if (S.dashPick && !S.dash.sites.some(s => s.site === S.dashPick)) S.dashPick = "";
  } catch (e) { S.dash = null; S.dashErr = e.error || "Nicht möglich."; }
  render();
}
function svgEl(tag, attrs) { const e = document.createElementNS("http://www.w3.org/2000/svg", tag); for (const k in attrs) e.setAttribute(k, attrs[k]); return e; }
function ageText(days) { return days <= 0 ? "heute" : days === 1 ? "gestern" : "vor " + days + " Tagen"; }
/* Liniendiagramm: kritische Funde (durchgezogen) und Hinweise (gestrichelt) je Prüfung */
function dashLineChart(history) {
  const W = 620, H = 230, pl = 40, pr = 14, pt = 14, pb = 26, n = history.length;
  const max = Math.max(1, ...history.map(p => Math.max(p.crit, p.warn)));
  const x = i => n === 1 ? pl + (W - pl - pr) / 2 : pl + i * (W - pl - pr) / (n - 1);
  const y = v => pt + (H - pt - pb) * (1 - v / max);
  const svg = svgEl("svg", { viewBox: "0 0 " + W + " " + H, role: "img", "aria-label": "Verlauf der kritischen Funde und Hinweise" });
  for (const v of [0, max / 2, max]) {
    svg.append(svgEl("line", { x1: pl, x2: W - pr, y1: y(v), y2: y(v), class: "dash-grid" }));
    const t = svgEl("text", { x: pl - 8, y: y(v) + 4, "text-anchor": "end", class: "dash-axis" }); t.textContent = String(Math.round(v)); svg.append(t);
  }
  for (const [key, col, dash] of [["warn", "var(--warn)", "6 5"], ["crit", "var(--crit)", null]]) {
    const line = svgEl("polyline", { points: history.map((p, i) => x(i) + "," + y(p[key])).join(" "), fill: "none", "stroke-width": 2.5, "stroke-linejoin": "round" });
    line.style.stroke = col; if (dash) line.setAttribute("stroke-dasharray", dash);
    svg.append(line);
    history.forEach((p, i) => {
      const c = svgEl("circle", { cx: x(i), cy: y(p[key]), r: 3.5 }); c.style.fill = col;
      const tt = svgEl("title", {}); tt.textContent = fmtDate(p.ts) + ": " + p[key] + (key === "crit" ? " kritisch" : " Hinweise"); c.append(tt); svg.append(c);
    });
  }
  if (n) {
    const a = svgEl("text", { x: pl, y: H - 6, class: "dash-axis" }); a.textContent = fmtDate(history[0].ts); svg.append(a);
    const b = svgEl("text", { x: W - pr, y: H - 6, "text-anchor": "end", class: "dash-axis" }); b.textContent = fmtDate(history[n - 1].ts); svg.append(b);
  }
  return svg;
}
function dashStackBar(counts) {
  const total = (counts.crit || 0) + (counts.warn || 0) + (counts.info || 0) + (counts.ok || 0) || 1;
  const seg = k => { const i = h("i", {}); i.style.width = ((counts[k] || 0) / total * 100) + "%"; i.style.background = LVL[k]; i.title = LVL_NAME[k] + ": " + (counts[k] || 0); return i; };
  return h("div", { class: "hstack" }, seg("crit"), seg("warn"), seg("info"), seg("ok"));
}
function topFindingTitle(s) { const f = (s.findings || []).find(x => x.sev === "crit") || (s.findings || [])[0]; return f ? f.title : ""; }
/* Auswertung in Sätzen, aus den Zahlen des Verlaufs; wer einen Punkt anklickt, springt zur Seite */
function dashAnalysis(d) {
  const out = [];
  for (const s of d.sites) {
    if (s.counts.crit) out.push({ lvl: "crit", site: s.site, text: s.label + ": " + plural(s.counts.crit, "kritischer Fund", "kritische Funde") + "." + (topFindingTitle(s) ? " Zuerst prüfen: " + topFindingTitle(s) + "." : "") });
    if (s.history.length >= 2) {
      const a = s.history[0], b = s.history[s.history.length - 1];
      if (b.crit < a.crit) out.push({ lvl: "ok", site: s.site, text: s.label + ": kritische Funde von " + a.crit + " auf " + b.crit + " gesunken." });
      else if (b.crit > a.crit) out.push({ lvl: "crit", site: s.site, text: s.label + ": kritische Funde von " + a.crit + " auf " + b.crit + " gestiegen." });
      else if (b.warn < a.warn) out.push({ lvl: "ok", site: s.site, text: s.label + ": Hinweise von " + a.warn + " auf " + b.warn + " gesunken." });
    }
    if (s.compare && (s.compare.new || []).length) out.push({ lvl: "warn", site: s.site, text: s.label + ": " + plural(s.compare.new.length, "neuer Fund", "neue Funde") + " seit der Prüfung davor." });
    for (const t of s.hints) out.push({ lvl: "warn", site: s.site, text: s.label + ": " + t });
  }
  if (d.totals.fixed) out.push({ lvl: "ok", text: plural(d.totals.fixed, "Fund wurde", "Funde wurden") + " behoben: in einer späteren Prüfung nicht mehr gemeldet." });
  if (!out.length) out.push({ lvl: "ok", text: "Keine auffälligen Punkte in den bisherigen Prüfungen." });
  return out;
}
function findingDetail(s, f) {
  const c = (S.init.checks || []).find(x => x.id === f.id);
  const box = h("div", { class: "fdetail" }, h("h4", {}, badge(f.sev === "crit" ? "crit" : f.sev === "warn" ? "warn" : "info", SEV_LABEL[f.sev] || f.sev, "margin-right:8px"), f.title));
  box.append(h("div", { class: "small muted", text: "Seite: " + s.label + "  ·  Prüfung vom " + fmtDate(s.last_ts) + "  ·  Prüf-ID: " + f.id }));
  if (c) {
    box.append(h("p", {}, h("strong", { text: "Prüfung: " }), c.title));
    if (c.what) box.append(h("p", {}, h("strong", { text: "Was geprüft wird: " }), c.what));
    if (c.why) box.append(h("p", {}, h("strong", { text: "Warum das wichtig ist: " }), c.why));
  } else {
    box.append(h("p", { class: "small", text: "Zu dieser Prüfung gibt es in der aktuellen Sprache oder bei diesem System keine Beschreibung. Die Erklärung steht im Handbuch unter Prüfkatalog." }));
  }
  box.append(h("div", { class: "actions", style: "margin:8px 0 0" },
    h("button", { class: "btn mini", type: "button", onclick: () => openHelp() }, "Im Handbuch nachlesen"),
    h("button", { class: "btn mini ghost", type: "button", onclick: () => { S.dashFind = null; render(); } }, "Schließen")));
  return box;
}
function dashSiteCard(s) {
  const lvl = { crit: ["crit", "Kritische Funde"], warn: ["warn", "Hinweise"], ok: ["ok", "Keine Auffälligkeiten"] }[s.level] || ["info", ""];
  const card = h("div", { class: "sitecard", id: "site-" + String(s.site).replace(/[^a-zA-Z0-9_-]/g, "_") });
  card.style.setProperty("--sc", LVL[s.level] || "var(--line)");
  const c = s.compare;
  card.append(h("h3", {}, badge(lvl[0], lvl[1], "margin-right:4px"), s.label),
    h("div", { class: "meta" }, h("span", { text: (cmsNames()[s.cms] || s.cms || "?") + (s.version ? " " + s.version : "") }),
      h("span", { text: "Letzte Prüfung: " + fmtDate(s.last_ts) + " (" + ageText(s.age_days) + ")" }),
      h("span", { text: s.counts.crit + " kritisch, " + s.counts.warn + " Hinweise" }), h("span", { text: s.runs + " Prüfung" + (s.runs === 1 ? "" : "en") }),
      h("span", { text: s.fixed + " behoben" })));
  if ((s.findings || []).length) {
    card.append(h("div", { class: "small", style: "margin:4px 0 6px", text: "Befunde der letzten Prüfung (anklicken für die Erklärung):" }));
    const grid = h("div", { class: "fgrid" });
    s.findings.slice(0, 60).forEach((f, k) => {
      const on = S.dashFind && S.dashFind.site === s.site && S.dashFind.k === k;
      const dot = h("i", { class: "fd" }); dot.style.background = LVL[f.sev] || "var(--line)";
      grid.append(h("button", { class: "fbtn" + (on ? " on" : ""), type: "button", title: f.title, onclick: () => { S.dashFind = on ? null : { site: s.site, k }; render(); } }, dot, h("span", { class: "ft", text: f.title })));
    });
    card.append(grid);
    if (S.dashFind && S.dashFind.site === s.site && s.findings[S.dashFind.k]) card.append(findingDetail(s, s.findings[S.dashFind.k]));
    if (s.findings.length > 60) card.append(h("p", { class: "small muted", text: "… und " + (s.findings.length - 60) + " weitere" }));
  }
  if (s.hints.length) card.append(h("ul", { class: "analysis", style: "margin-top:8px" }, s.hints.map(t => h("li", { text: t }))));
  if (s.nachkontrolle && s.nachkontrolle.state !== "faellig") card.append(h("div", { class: "small", text: s.nachkontrolle.text }));
  card.append(h("div", { class: "small", style: "margin-top:8px" }, h("strong", { text: "Erledigt: " }),
    s.fixed + " Fund" + (s.fixed === 1 ? "" : "e") + " behoben, " + s.actions_ok + " Aktion" + (s.actions_ok === 1 ? "" : "en") + " ausgeführt" +
    (s.actions_failed ? ", " + s.actions_failed + " nicht erfolgreich" : "") + (s.last_backup ? ". Letzte Sicherung mit CLAUDIA: " + fmtDate(s.last_backup) : "")));
  if (c) {
    const list = (title, items) => items.length ? h("div", {}, h("strong", { text: title + " (" + items.length + ")" }), h("ul", {}, items.slice(0, 30).map(x => h("li", { text: x[2] })))) : null;
    card.append(h("details", { style: "margin-top:8px" }, h("summary", { text: "Vergleich mit der Prüfung davor (" + fmtDate(c.prev_ts) + " → " + fmtDate(c.cur_ts) + ")" }),
      list("Neu", c.new), list("Behoben", c.fixed), list("Nicht geprüft (nicht als behoben gezählt)", c.not_checked),
      h("div", { class: "small", text: c.same + " Befund" + (c.same === 1 ? "" : "e") + " unverändert." })));
  }
  const st = (S.dashDel = S.dashDel || {});
  card.append(h("div", { class: "actions", style: "margin:10px 0 0" },
    h("button", { class: "btn mini ghost", type: "button", onclick: () => dashExport("csv", s.site) }, "Verlauf als CSV"),
    h("button", { class: "btn mini ghost", type: "button", onclick: () => dashExport("html", s.site) }, "Bericht für diese Seite"),
    h("button", { class: "btn mini " + (st[s.site] ? "danger" : "ghost"), type: "button", onclick: async () => {
      if (!st[s.site]) { st[s.site] = true; render(); return; }
      try { await api("/api/dashboard-delete", { site: s.site }); } catch (e) { /* egal */ }
      delete st[s.site]; openDashboard();
    } }, st[s.site] ? "Wirklich löschen? (nur der Verlauf in CLAUDIA, nicht die Seite)" : "Verlauf dieser Seite löschen")));
  return card;
}
async function dashExport(fmt, site) {
  const box = document.getElementById("dash-msg"); if (!box) return;
  try { const r = await api("/api/dashboard-export", { fmt, site }); box.replaceChildren(h("div", { class: "notice ok" }, h("div", {}, "Gespeichert: " + r.file))); }
  catch (e) { box.replaceChildren(h("div", { class: "notice err" }, h("div", {}, e.error || "Nicht möglich."))); }
}
async function dashSupport() {
  const box = document.getElementById("dash-msg"); if (!box) return;
  try {
    const r = await api("/api/support-package", {});
    box.replaceChildren(h("div", { class: "notice ok" }, h("div", {}, "Gespeichert: " + r.file + ". Prüfe den Text kurz und hänge die Datei an dein GitHub-Issue.")),
      h("textarea", { class: "lic-key", readonly: "readonly", rows: "12", text: r.text }));
  } catch (e) { box.replaceChildren(h("div", { class: "notice err" }, h("div", {}, e.error || "Nicht möglich."))); }
}
function cmsNames() { return { joomla: "Joomla", wordpress: "WordPress", drupal: "Drupal", typo3: "TYPO3", contao: "Contao", prestashop: "PrestaShop", shopware: "Shopware" }; }
function viewDashboard() {
  const wrap = h("div", { class: "dash-view" });
  if (!S.dash) {
    wrap.append(h("div", { class: "loader" }, h("i", { class: "spin", "aria-hidden": "true" }), h("span", { text: S.dashErr || "Lade den Verlauf …" })));
    return wrap;
  }
  const d = S.dash, t = d.totals;
  const sumC = k => d.sites.reduce((a, s) => a + (s.counts[k] || 0), 0);
  wrap.append(h("div", { class: "pagehead" },
    h("div", { style: "flex:1;min-width:200px" }, h("h1", { text: "Dashboard" }),
      h("p", { class: "small", text: "Alles stammt aus dem, was CLAUDIA auf diesem Computer notiert hat (Datei verlauf.json im Datenordner). Keine Passwörter, keine Dateiinhalte." })),
    d.sites.length ? h("button", { class: "btn ghost mini", type: "button", onclick: () => dashExport("csv", "") }, "Gesamten Verlauf als CSV") : null,
    h("button", { class: "btn ghost mini", type: "button", onclick: () => openDashboard() }, "Aktualisieren")));
  if (!d.sites.length) {
    wrap.append(h("div", { class: "dcard" }, h("div", { class: "dbody" }, h("p", { text: "Noch kein Verlauf. Nach der ersten vollständigen Prüfung erscheinen hier Diagramme, Auswertung und die Befunde." }))));
  } else {
    const kpi = (v, label, col) => h("div", { class: "kpi", style: "--kc:" + col }, h("b", { text: String(v) }), h("span", { text: label }));
    wrap.append(h("div", { class: "kpis" },
      kpi(t.sites, "Geprüfte Seiten", "var(--accent)"),
      kpi(sumC("crit"), "Kritische Funde (aktuell)", "var(--crit)"),
      kpi(sumC("warn"), "Hinweise (aktuell)", "var(--warn)"),
      kpi(t.fixed, "Funde behoben", "var(--ok)"),
      kpi(t.actions_ok, "Aktionen erfolgreich", "var(--info)")));
    /* Befunde je Seite (Balken, anklickbar) und Auswertung */
    const pick = d.sites.find(s => s.site === S.dashPick) ? S.dashPick : d.sites[0].site;
    S.dashPick = pick;
    const bars = d.sites.map(s => h("button", { class: "hbar" + (s.site === pick ? " on" : ""), type: "button", title: "Verlauf dieser Seite anzeigen",
      onclick: () => { S.dashPick = s.site; S.dashFind = null; render(); } },
      h("span", { class: "hname", text: s.label }), dashStackBar(s.counts), h("span", { class: "hnum", text: s.counts.crit + " / " + s.counts.warn }))); 
    const legend = h("div", { class: "legend" }, ["crit", "warn", "info", "ok"].map(k => h("span", {}, h("i", { style: "background:" + LVL[k] }), LVL_NAME[k])));
    const items = dashAnalysis(d);
    const ana = h("ul", { class: "analysis" }, items.slice(0, 14).map(it => h("li", {}, badge(it.lvl, it.lvl === "crit" ? "Kritisch" : it.lvl === "warn" ? "Prüfen" : "Gut", "margin-right:8px"),
      it.site ? h("button", { type: "button", onclick: () => { S.dashPick = it.site; S.dashFind = null; render(); document.getElementById("site-" + String(it.site).replace(/[^a-zA-Z0-9_-]/g, "_"))?.scrollIntoView({ block: "start" }); } }, it.text) : h("span", { text: it.text }))));
    if (items.length > 14) ana.append(h("li", { class: "small muted", text: "… und " + (items.length - 14) + " weitere Punkte" }));
    wrap.append(h("div", { class: "dgrid" },
      h("div", { class: "dcard" }, h("h3", {}, h("span", { text: "Befunde je Seite" }), h("span", { class: "small muted", text: "kritisch / Hinweise" })),
        h("div", { class: "dbody" }, bars, legend)),
      h("div", { class: "dcard" }, h("h3", {}, h("span", { text: "Auswertung" })), h("div", { class: "dbody" }, ana))));
    /* Verlauf der gewählten Seite */
    const cur = d.sites.find(s => s.site === pick);
    const sel = h("select", { class: "dash-sel", onchange: e => { S.dashPick = e.target.value; S.dashFind = null; render(); } },
      d.sites.map(s => h("option", { value: s.site, selected: s.site === pick, text: s.label })));
    wrap.append(h("div", { class: "dcard", style: "margin-bottom:14px" },
      h("h3", {}, h("span", { text: "Verlauf" }), sel),
      h("div", { class: "dbody" },
        cur.history.length >= 2 ? dashLineChart(cur.history) : h("p", { class: "small", text: "Für den Verlauf braucht es mindestens zwei Prüfungen dieser Seite." }),
        h("div", { class: "legend" }, h("span", {}, h("i", { style: "background:var(--crit)" }), "kritisch (durchgezogen)"), h("span", {}, h("i", { style: "background:var(--warn)" }), "Hinweise (gestrichelt)")))));
    wrap.append(h("h2", { style: "margin:18px 0 8px;font-size:17px", text: "Seiten im Detail" }));
    for (const s of d.sites) wrap.append(dashSiteCard(s));
  }
  if (d.recent_actions && d.recent_actions.length) {
    wrap.append(h("div", { class: "dcard", style: "margin-top:14px" }, h("h3", {}, h("span", { text: "Zuletzt ausgeführte Aktionen" })),
      h("div", { class: "dbody" }, h("table", { class: "dtable" }, h("tr", {}, ["Datum", "Aktion", "Seite", "Ergebnis"].map(x => h("th", { text: x }))),
        d.recent_actions.slice(0, 15).map(a => h("tr", {}, h("td", { text: fmtDate(a.ts) }), h("td", { text: a.title }), h("td", { text: a.label }), h("td", { text: a.ok ? "erfolgreich" : "nicht erfolgreich" })))))));
  }
  wrap.append(h("div", { id: "dash-msg" }));
  wrap.append(h("div", { class: "dcard", style: "margin-top:14px" }, h("h3", {}, h("span", { text: "Sicherungen und Quarantäne auf dem Server" })), h("div", { class: "dbody", id: "dash-srv" })));
  wrap.append(h("div", { class: "dcard", style: "margin-top:14px" }, h("h3", {}, h("span", { text: "Aktionen verwalten" })), h("div", { class: "dbody", id: "dash-acts" })));
  wrap.append(h("div", { class: "dcard", style: "margin-top:14px" }, h("h3", {}, h("span", { text: "Hilfe bei Fehlern" })), h("div", { class: "dbody" },
    h("p", { class: "small", text: "Das Support-Paket ist eine kurze Textdatei mit Versionen, dem Ergebnis jeder Prüfung und dem Update-Protokoll, ohne Passwörter, Server- oder Zugangsdaten." }),
    h("button", { class: "btn mini ghost", type: "button", onclick: dashSupport }, "Support-Paket erstellen"))));
  setTimeout(() => { renderDashServer(); dashActionsRender(); }, 0);
  return wrap;
}
async function loadDashServer() {
  S.dashServer = { loading: true }; renderDashServer();
  try { S.dashServer = await api("/api/dashboard-server"); } catch (e) { S.dashServer = { error: e.error || "Nicht möglich." }; }
  if (S.dashServer.connected) await loadActions(true);
  renderDashServer();
}
function backupVerifyCell(name) {
  const st = (S.dashVerify = S.dashVerify || {})[name];
  if (!st) return h("button", { class: "btn mini ghost", type: "button", onclick: async () => {
    S.dashVerify[name] = { busy: true }; renderDashServer();
    try { S.dashVerify[name] = await api("/api/dashboard-verify", { name }); } catch (e) { S.dashVerify[name] = { error: e.error || "Nicht möglich." }; }
    renderDashServer();
  } }, "Sicherung prüfen");
  if (st.busy) return h("span", { class: "small", text: "Prüfe …" });
  if (st.error) return h("span", { class: "small", text: st.error });
  if (!st.found) return h("span", { class: "small", text: "Nicht mehr vorhanden." });
  return h("div", { class: "small" }, badge(st.ok ? "ok" : "crit", st.ok ? "Lesbar und vollständig" : "Fehler gefunden"),
    h("ul", { style: "margin:4px 0 0 16px" }, st.files.map(f => h("li", { text: f.name + " (" + fmtSize(f.size) + "): " + f.detail }))));
}
function renderDashServer() {
  const box = document.getElementById("dash-srv"); if (!box) return;
  const v = S.dashServer, kids = [];
  if (!(S.dash && S.dash.connected)) {
    kids.push(h("p", { class: "small", text: "Verbinde dich zuerst mit einer Seite (Schritt 1), dann kannst du hier ihre Sicherungen und die Quarantäne ansehen und verwalten." }));
  } else if (!v) {
    kids.push(h("p", { class: "small", text: "Liest nur (kein Eingriff), welche Sicherungen und Quarantäne-Ordner von CLAUDIA auf dem Server liegen." }),
      h("button", { class: "btn", type: "button", onclick: loadDashServer }, "Bestand auf dem Server ansehen"));
  } else if (v.loading) {
    kids.push(h("p", { text: "Lese den Bestand vom Server …" }));
  } else if (v.error || !v.connected) {
    kids.push(h("p", { text: v.error || "Die Verbindung besteht nicht mehr." }));
  } else {
    kids.push(h("p", { class: "small", text: "Seite: " + v.label }));
    kids.push(h("h4", { text: "Sicherungen (" + v.backups.length + ")" }), v.backups.length
      ? h("table", { class: "dash-tab" }, h("tr", {}, ["Name", "Art", "Datum", "Größe", "Prüfen"].map(x => h("th", { text: x }))),
          v.backups.map(b => h("tr", {}, h("td", { text: b.name }), h("td", { text: b.kind }), h("td", { text: fmtDate(b.mtime) }), h("td", { text: fmtSize(b.kb * 1024) }),
            h("td", {}, backupVerifyCell(b.name)))))
      : h("p", { class: "small", text: "Keine Sicherung von CLAUDIA auf dem Server." }));
    if (v.backups.length) kids.push(h("p", { class: "small", text: "\"Prüfen\" liest die Sicherung nur (Archive öffnen und auf Fehler testen) und spielt nichts zurück. So merkst du, ob eine Sicherung im Ernstfall brauchbar wäre." }));
    kids.push(h("h4", { text: "Quarantäne (" + v.quarantines.length + ")" }), v.quarantines.length
      ? h("table", { class: "dash-tab" }, h("tr", {}, ["Ordner", "Datum", "Dateien", "Größe"].map(x => h("th", { text: x }))),
          v.quarantines.map(q => h("tr", {}, h("td", { text: q.name }), h("td", { text: fmtDate(q.mtime) }), h("td", { text: q.count + (q.files.length ? ": " + q.files.slice(0, 3).join(", ") + (q.count > 3 ? " …" : "") : "") }), h("td", { text: fmtSize(q.kb * 1024) }))))
      : h("p", { class: "small", text: "Keine Quarantäne-Ordner mit Dateien." }));
    kids.push(h("div", { class: "notice warn" }, h("div", {}, h("strong", { text: "Vollsicherung zurückspielen: bewusst nicht automatisch." }),
      h("div", { class: "small", text: "Das Zurückspielen einer Vollsicherung überschreibt Datenbank und Dateien der laufenden Seite und lässt sich nicht rückgängig machen. Dafür bietet CLAUDIA keine Ein-Klick-Lösung. Frage Claude oder deinen Hoster, bevor du das tust. Dateien aus der Quarantäne zurückholen geht unten." }))));
    kids.push(h("h4", { text: "Verwalten (jede Aktion zeigt erst die Befehle und braucht deine Bestätigung)" }), h("div", { id: "dash-acts" }));
  }
  box.replaceChildren(...kids.filter(Boolean));
  dashActionsRender();
}
function dashActionsRender() {
  const box = document.getElementById("dash-acts"); if (!box) return;
  const list = (S.actions && S.actions.actions) || [], by = {};
  for (const a of list) by[a.id] = a;
  const ids = ["backup_now", "delete_old_backups", "restore_quarantine", "delete_quarantine"].filter(id => by[id] && !by[id].hidden);
  box.replaceChildren(...(ids.length ? ids.map(id => actionBlock(by[id])) : [h("p", { class: "small", text: "Im Moment gibt es hier nichts zu verwalten." })]));
}

/* ------------------------------------------------------------------ Lizenz */
function licFrame(title, scroll, foot) {
  const dlg = $("#licdlg"), box = $("#lic-body");
  box.replaceChildren(
    h("div", { class: "uni-head" }, h("h2", { text: title }), h("button", { class: "dlg-x", type: "button", title: "Schließen", "aria-label": "Schließen", onclick: () => dlg.close(), text: "\u2715" })),
    h("div", { class: "uni-scroll" }, scroll),
    foot ? h("div", { class: "uni-foot" }, foot) : null);
  if (!dlg.open) dlg.showModal();
}
async function openLicense(note) {
  let st;
  try { st = await api("/api/license"); } catch (e) { licFrame("Lizenz", h("p", { text: e.error || "Nicht möglich." })); return; }
  renderLicense(st, note);
}
function renderLicense(st, note) {
  const kids = [];
  if (note) kids.push(h("div", { class: "notice " + (note.ok ? "ok" : "err") }, h("div", { text: note.text })));
  if (st.valid) {
    kids.push(h("div", { class: "notice ok" }, h("div", {}, h("strong", { text: "Lizenz gültig" }),
      h("div", { text: st.name + " (" + st.art + ")" }), h("div", { class: "small", text: "Gültig bis " + st.until + " (noch " + st.days_left + " Tage)" }))));
    if (st.warn_expiry) kids.push(h("div", { class: "notice warn" }, h("div", { text: "Die Lizenz läuft bald ab. Bitte rechtzeitig einen neuen Schlüssel besorgen." })));
  } else if (st.has_key) {
    kids.push(h("div", { class: "notice err" }, h("div", { text: st.reason === "abgelaufen" ? "Der eingetragene Schlüssel ist abgelaufen." : st.reason === "gesperrt" ? "Der eingetragene Schlüssel wurde gesperrt." : "Der eingetragene Schlüssel ist ungültig." })));
  } else {
    kids.push(h("p", { text: "Es ist kein Lizenzschlüssel eingetragen." }));
  }
  if ((st.blocked || []).length) {
    kids.push(h("p", {}, h("strong", { text: "Ohne gültigen Schlüssel gesperrt:" })), h("ul", { class: "lic-free" }, st.blocked_text.map(t => h("li", { text: t }))));
  } else {
    kids.push(h("p", { class: "small", text: "Im Moment ist nichts gesperrt." }));
  }
  kids.push(h("p", { class: "small", text: "Die Prüfung (Suche nach Schadcode und Schwachstellen), die Verbindung, die Hilfe, Updates und der Rückweg (Sicherung anlegen, Dateien aus der Quarantäne zurückholen) sind immer frei." }),
    h("p", { class: "small", text: "Der Schlüssel wird nur auf diesem Computer geprüft. Es wird nichts ins Internet gesendet." }));
  const ta = h("textarea", { class: "lic-key", id: "lickey", placeholder: "Lizenzschlüssel (CL1.) oder Schaltdatei (SW1.) hier einfügen", spellcheck: "false" });
  kids.push(h("label", { for: "lickey", class: "small", text: "Lizenzschlüssel eintragen" }), ta);
  const set = h("button", { class: "btn primary", type: "button", onclick: async () => {
    try {
      const r = await api("/api/license-set", { key: ta.value });
      renderLicense(r, { ok: r.accepted, text: r.message });
      if (S.init) S.init.license = r;
    } catch (e) { renderLicense(st, { ok: false, text: e.error || "Nicht möglich." }); }
  } }, "Eintragen");
  const del = h("button", { class: "btn ghost", type: "button", disabled: !st.has_key, onclick: async () => {
    try { const r = await api("/api/license-remove", {}); renderLicense(r, { ok: true, text: "Der Schlüssel wurde entfernt." }); if (S.init) S.init.license = r; } catch (e) { /* egal */ }
  } }, "Schlüssel entfernen");
  const offer = S.init.offer ? h("button", { class: "btn ghost", type: "button", onclick: () => openOffer("") }, st.has_key ? "Lizenz verlängern" : "Normal und Pro vergleichen") : null;
  licFrame("Lizenz", h("div", {}, ...kids), h("div", { class: "actions" }, set, del, offer));
}
/* Vergleich Normal/Pro, Kauf und Rabattcode. Nur erreichbar, wenn der Server das Angebot freigeschaltet hat (S.init.offer); sonst ist nichts davon sichtbar. */
function euro(cent, cur) { return (cent / 100).toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 }) + " " + (cur || "EUR"); }
async function openOffer(code, note) {
  let st;
  try { st = await api("/api/offer", { code: code || "" }); } catch (e) { licFrame("Normal und Pro", h("p", { text: e.error || "Nicht möglich." })); return; }
  if (!st.aktiv) { licFrame("Normal und Pro", h("p", { text: "Dieses Angebot ist im Moment nicht verfügbar." })); return; }
  const kids = [];
  if (note) kids.push(h("div", { class: "notice " + (note.ok ? "ok" : "err") }, h("div", { text: note.text })));
  const mark = v => h("td", { class: "offer-mark", text: v ? "\u2713" : "\u2013", "aria-label": v ? "ja" : "nein" });
  kids.push(h("table", { class: "offer-table" },
    h("thead", {}, h("tr", {}, h("th", { text: "Funktion" }), h("th", { text: "Normal" }), h("th", { text: "Pro" }))),
    h("tbody", {}, st.features.map(f => h("tr", {}, h("td", { text: f.text }), mark(f.normal), mark(f.pro))))));
  if (st.preis_cent > 0) {
    const price = h("div", { class: "offer-price" }, h("strong", { text: euro(st.zu_zahlen_cent, st.waehrung) }),
      st.rabatt.valid ? h("span", { class: "small", text: " statt " + euro(st.preis_cent, st.waehrung) + " (" + st.rabatt.prozent + " % Rabatt)" }) : null);
    kids.push(h("p", {}, h("strong", { text: st.verlaengerung ? "Verlängerung" : "Pro-Lizenz" }), " für " + st.laufzeit_tage + " Tage"), price);
  }
  if (st.verlaengerung && st.lizenz_bis) kids.push(h("p", { class: "small", text: "Deine Lizenz gilt bis " + st.lizenz_bis + (st.tage_uebrig != null ? " (noch " + st.tage_uebrig + " Tage)." : ".") }));
  kids.push(h("div", { class: "notice ok" }, h("div", { text: st.ngo })));
  const ta = h("input", { class: "offer-input", id: "offercode", type: "text", placeholder: "Rabattcode (beginnt mit RB1.)", spellcheck: "false", value: code || "" });
  const apply = h("button", { class: "btn ghost", type: "button", onclick: () => openOffer(ta.value, null) }, "Code anwenden");
  kids.push(h("label", { for: "offercode", class: "small", text: "Rabattcode" }), h("div", { class: "offer-code" }, ta, apply));
  if (code && !st.rabatt.valid) kids.push(h("div", { class: "notice err" }, h("div", { text: "Der Rabattcode gilt nicht (" + st.rabatt.reason + ")." })));
  kids.push(h("h3", { text: "Nutzungsbedingungen" }), h("ul", { class: "lic-free" }, st.bedingungen.map(t => h("li", { text: t }))), h("p", { class: "small", text: st.hinweis }),
    h("p", { class: "small", text: "Bezahlt wird bei PayPal im Browser. Das Programm sendet nichts und speichert keine Zahlungsdaten; den Lizenzschlüssel erhältst du nach der Zahlung vom Autor." }));
  const buy = h("button", { class: "btn primary", type: "button", disabled: !st.kauf_moeglich, onclick: async () => {
    try { await api("/api/offer-buy", { code: st.rabatt.valid ? code : "" }); openOffer(code, { ok: true, text: "PayPal wurde im Browser geöffnet." }); }
    catch (e) { openOffer(code, { ok: false, text: e.error || "Nicht möglich." }); }
  } }, st.verlaengerung ? "Lizenz verlängern (PayPal)" : "Pro kaufen (PayPal)");
  const back = h("button", { class: "btn ghost", type: "button", onclick: () => openLicense() }, "Zurück zur Lizenz");
  licFrame("Normal und Pro", h("div", {}, ...kids), h("div", { class: "actions" }, buy, back));
}

/* ------------------------------------------------------------------ Start */
(async function main() {
  try { S.init = await api("/api/init"); } catch (e) { document.body.textContent = e.error || "Fehler beim Start."; return; }
  if (S.init.lang && S.init.lang !== "de") { try { applyLang(await api("/api/lang")); } catch (e) { /* bleibt deutsch */ } }
  $("#conn-off").addEventListener("click", disconnect);
  $("#help").addEventListener("click", openHelp);
  $("#updbtn").addEventListener("click", () => openUpdate(true));
  $("#licbtn").addEventListener("click", () => openLicense());
  { const lic = S.init.license || {}; $("#licbtn").hidden = !(S.init.offer || lic.public_key_set || lic.has_key || (lic.gesperrt_ohne_lizenz || []).length); }   // unsichtbar, solange es keinen öffentlichen Schlüssel und keine Sperre gibt
  $("#dashbtn").addEventListener("click", () => openDashboard());
  autoUpdateCheck();
  loadIntegrity();
  $("#uninstall").addEventListener("click", openUninstall);
  if (S.init.loc > 0) { $("#locn").textContent = Number(S.init.loc).toLocaleString(); $("#loc").hidden = false; }
  if (location.hash === "#uninstall") setTimeout(openUninstall, 300);
  applyPreset("hack");
  if (S.init.demo) S.form.host = "__demo__";
  if (S.init.connected) {
    S.conn = S.init.info;
    S.form.site_dir = S.conn.site_dir && S.conn.site_dir !== "." ? S.conn.site_dir : "";
    S.step = "tests";
    const st = await api("/api/state?since=0");
    if (st.total) {
      S.plan = st.plan; S.results = st.results; S.next = st.next; S.current = st.current || {}; S.running = st.running; S.hoster = st.hoster || S.hoster || null;
      S.summary = st.summary; S.cancelled = st.cancelled; S.elapsed = st.elapsed;
      S.step = st.running ? "run" : "result";
      if (st.running) poll();
    }
  }
  render();
})();

/* Externe Links öffnen im normalen Browser des PCs (das Programmfenster bleibt bei CLAUDIA); nur https. */
document.addEventListener("click", ev => {
  const a = ev.target.closest && ev.target.closest("a[href]");
  if (!a || a.hasAttribute("download")) return;
  let u;
  try { u = new URL(a.href, location.href); } catch (e) { return; }
  if (u.origin === location.origin || u.protocol === "blob:") return;
  ev.preventDefault();
  if (u.protocol === "https:") api("/api/open-url", { url: u.href }).catch(() => toast("Der Link konnte nicht geöffnet werden."));
});
/* Lebenszeichen: wird das Fenster geschlossen, endet das Programm (nur im Notfall-Modus mit normalem Browser nötig). */
setInterval(() => { fetch("/api/ping", { headers: { "X-Claudia": "1" } }).catch(() => {}); }, 15000);

// Eigene Titelleiste (nur im Programmfenster ohne Systemrahmen, siehe window.py)
(function () {
  let done = false;
  async function setup() {
    if (done || !window.pywebview || !window.pywebview.api || !window.pywebview.api.is_custom_frame) return;
    done = true;
    try {
      if (!(await window.pywebview.api.is_custom_frame())) return;
    } catch (e) { return; }
    document.documentElement.classList.add("has-titlebar");
    document.getElementById("titlebar").hidden = false;
    document.getElementById("tb-min").addEventListener("click", () => window.pywebview.api.minimize());
    document.getElementById("tb-max").addEventListener("click", () => { document.documentElement.classList.toggle("maxed"); window.pywebview.api.toggle_maximize(); });
    document.getElementById("tb-close").addEventListener("click", () => window.pywebview.api.close());
    /* Größe ändern: rahmenlose Fenster haben keinen eigenen Rand zum Ziehen, deshalb Griffe links, rechts, unten und in den unteren Ecken */
    for (const g of document.querySelectorAll(".rz")) {
      g.hidden = false;
      g.addEventListener("pointerdown", async ev => {
        ev.preventDefault();
        g.setPointerCapture(ev.pointerId);
        const x0 = ev.screenX, y0 = ev.screenY, dir = g.dataset.dir;
        let rect = [0, 0, 0, 0];
        try { rect = await window.pywebview.api.get_rect(); } catch (e) { return; }
        let busy = false, next = null;
        const send = async (dx, dy) => {
          if (busy) { next = [dx, dy]; return; }
          busy = true;
          try { await window.pywebview.api.resize_by(rect[0], rect[1], rect[2], rect[3], dx, dy, dir); } catch (e) { /* Fenster zu */ }
          busy = false;
          if (next) { const n = next; next = null; send(n[0], n[1]); }
        };
        const move = e => send(e.screenX - x0, e.screenY - y0);
        const up = () => { g.removeEventListener("pointermove", move); g.removeEventListener("pointerup", up); g.removeEventListener("pointercancel", up); };
        g.addEventListener("pointermove", move); g.addEventListener("pointerup", up); g.addEventListener("pointercancel", up);
      });
    }
    document.getElementById("titlebar").addEventListener("dblclick", e => { if (e.target.id === "titlebar" || e.target.classList.contains("tb-space")) { document.documentElement.classList.toggle("maxed"); window.pywebview.api.toggle_maximize(); } });
  }
  window.addEventListener("pywebviewready", setup);
  setup();
})();
