/* Dokumentation: Handbuch, Änderungsverlauf (was/warum/wie), Prüfkatalog und Aktionskatalog (was/wie/warum) mit Suche.
   Gleicher Code im Programm (Hilfe-Fenster) und in der eigenständigen Datei (tools/build_docs.py). Nutzt nur DOM-Methoden, kein innerHTML. */
(function (root) {
  "use strict";
  const T = {
    de: { title: "Dokumentation", search: "Suchen ...", handbook: "Handbuch", changes: "Änderungen", checks: "Prüfkatalog", actions: "Aktionen", tech: "Tech Doku", catalog: "Tech Doku", toc: "Inhaltsverzeichnis", back: "zurück zum Inhaltsverzeichnis", intro: "So liest du diesen Bereich: Jeder Eintrag erklärt zuerst in einfachen Worten, WAS passiert und WARUM. Danach steht, WIE das Programm es macht. Der Code ist eingeklappt und nur für alle gedacht, die es ganz genau wissen wollen. Jeder Code lässt sich mit einem Klick kopieren.", showcode: "Code anzeigen", important: "Wichtig", slowtag: "dauert länger", checksJ: "Prüfungen für Joomla", checksW: "Prüfungen für WordPress", checksD: "Prüfungen für Drupal", checksT: "Prüfungen für TYPO3", checksC: "Prüfungen für Contao", checksP: "Prüfungen für PrestaShop", checksB: "Prüfungen für mehrere Systeme", actionsAll: "Aktionen (Lösungen auf Knopfdruck)", basicsT: "Grundlagen: So arbeitet das Programm", sub: "Was, warum und wie", lines: "Zeilen", howAuto: "Das Programm zeigt dir vorher in einer Vorschau alle Befehle, die es an den Server schickt. Es legt zuerst eine geprüfte Sicherung an, wo die Aktion etwas verändert, und führt die Befehle erst nach deiner ausdrücklichen Bestätigung aus. Die Befehle stehen unten im Code.", none: "Nichts gefunden.", results: "Treffer", what: "Was", why: "Warum", how: "Wie", reads: "Was wird gelesen", warning: "Warnung", undo: "Rückgängig", risk: "Risiko", backup: "Sicherung vorher", both: "Joomla und WordPress", code: "Befehle", cmds: "Befehle in der Vorschau", prog: "Programmablauf (Quelltext)", sqls: "Abfragen, Skripte und Konstanten", basics: "Grundlagen", loading: "Wird geladen ...", copy: "Kopieren", copied: "Kopiert", techNote: "Der Code wird beim Aufruf direkt aus dem Programm gelesen und ist daher immer der echte. Kommentare im Code sind deutsch.", fn: "Funktion", ck: "Prüfung", version: "Version", slow: "dauert länger", close: "Schließen", joomla: "Joomla", wordpress: "WordPress", hits: "%d Treffer", more: "Suche leeren" },
    en: { title: "Documentation", search: "Search ...", handbook: "Manual", changes: "Changes", checks: "Check catalog", actions: "Actions", tech: "Tech Docs", catalog: "Tech Docs", toc: "Table of contents", back: "back to the table of contents", intro: "How to read this section: every entry first explains in plain words WHAT happens and WHY. Then it says HOW the program does it. The code is collapsed and meant for anyone who wants every detail. Every piece of code can be copied with one click.", showcode: "Show code", important: "Important", slowtag: "takes longer", checksJ: "Checks for Joomla", checksW: "Checks for WordPress", checksD: "Checks for Drupal", checksT: "Checks for TYPO3", checksC: "Checks for Contao", checksP: "Checks for PrestaShop", checksB: "Checks for several systems", actionsAll: "Actions (one-click fixes)", basicsT: "Basics: how the program works", sub: "What, why and how", lines: "lines", howAuto: "The program first shows you a preview of every command it sends to the server. Where the action changes something, it creates a verified backup first and runs the commands only after your explicit confirmation. The commands are listed below in the code.", none: "Nothing found.", results: "Results", what: "What", why: "Why", how: "How", reads: "What is read", warning: "Warning", undo: "Undo", risk: "Risk", backup: "Backup first", both: "Joomla and WordPress", code: "Commands", cmds: "Commands in the preview", prog: "Program flow (source code)", sqls: "Queries, scripts and constants", basics: "Basics", loading: "Loading ...", copy: "Copy", copied: "Copied", techNote: "The code is read directly from the program when you open this, so it is always the real code. Comments in the code are in German.", fn: "Function", ck: "Check", version: "Version", slow: "takes longer", close: "Close", joomla: "Joomla", wordpress: "WordPress", hits: "%d hits", more: "Clear search" },
  };
  function el(tag, attrs, ...kids) {
    const e = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (k === "text") e.textContent = v; else if (k === "class") e.className = v; else if (k.startsWith("on")) e.addEventListener(k.slice(2), v); else if (v !== null && v !== undefined && v !== false) e.setAttribute(k, v === true ? "" : v);
    }
    for (const kid of kids.flat(Infinity)) if (kid !== null && kid !== undefined && kid !== false) e.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
    return e;
  }
  const esc = s => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  function mark(text, terms) {
    if (!terms.length) return [text];
    const rx = new RegExp("(" + terms.map(esc).join("|") + ")", "gi");
    return text.split(rx).map((p, i) => (i % 2 ? el("mark", { text: p }) : p));
  }
  const fold = s => s.toLowerCase();

  function mount(host, data, opts) {
    opts = opts || {};
    const L = (data.lang === "de") ? T.de : T.en;
    const st = { tab: "handbook", q: "", sec: null };
    const hand = data.handbook || [], log = data.changelog || [], chk = data.checks || [], act = data.actions || [];
    let tech = data.tech || null, techBusy = false;
    const hasTech = () => !!(tech || opts.loadTech);
    host.replaceChildren();
    const box = el("div", { class: "docs" });
    const input = el("input", { type: "search", class: "docs-q", placeholder: L.search, "aria-label": L.search, autocomplete: "off" });
    const head = el("div", { class: "docs-head" }, el("h2", { text: L.title + (data.version ? " - CLAUDIA " + data.version : "") }), input,
      opts.onclose ? el("button", { type: "button", class: "docs-x", onclick: opts.onclose, title: L.close, "aria-label": L.close, text: "\u2715" }) : null);
    const tabs = el("div", { class: "docs-tabs", role: "tablist" });
    const nav = el("nav", { class: "docs-nav", "aria-label": L.handbook });
    const body = el("div", { class: "docs-body" });
    box.append(head, tabs, el("div", { class: "docs-cols" }, nav, body));
    host.append(box);

    const textOf = {
      handbook: s => [s.title].concat((s.blocks || []).map(b => (b.items || [b.text]).join(" "))).join(" "),
      changes: r => [r.version, r.title].concat(r.items.map(i => [i.title, i.what, i.why, i.how].join(" "))).join(" "),
      checks: c => [c.title, c.summary, c.what, c.why, c.reads].join(" "),
      actions: a => [a.title, a.what, a.how, a.why, a.warning, a.undo].join(" "),
    };
    const terms = () => st.q.trim().split(/\s+/).filter(x => x.length > 1);
    const hit = (txt, ts) => ts.every(t => fold(txt).includes(fold(t)));

    function blocks(list, ts) {
      return (list || []).map(b => b.t === "ul" ? el("ul", {}, b.items.map(i => el("li", {}, mark(i, ts)))) : el("p", {}, mark(b.text, ts)));
    }
    function showHandbook(ts) {
      nav.replaceChildren(...hand.map(s => el("a", { href: "#" + s.id, class: st.sec === s.id ? "on" : "", onclick: ev => { ev.preventDefault(); st.sec = s.id; draw(); const t = body.querySelector("#doc-" + s.id); if (t) t.scrollIntoView({ block: "start" }); } }, s.title)));
      body.replaceChildren(...hand.map(s => el("section", { id: "doc-" + s.id, class: "docs-sec" }, el("h3", {}, mark(s.title, ts)), blocks(s.blocks, ts))));
    }
    function showChanges(ts) {
      nav.replaceChildren(...log.map(r => el("a", { href: "#v" + r.version, onclick: ev => { ev.preventDefault(); const t = body.querySelector("#doc-v" + r.version.replace(/\./g, "_")); if (t) t.scrollIntoView({ block: "start" }); } }, L.version + " " + r.version)));
      body.replaceChildren(...log.map(r => el("section", { id: "doc-v" + r.version.replace(/\./g, "_"), class: "docs-sec" },
        el("h3", {}, L.version + " " + r.version + (r.date ? " (" + r.date + ")" : "") + (r.title ? " - " : ""), mark(r.title || "", ts)),
        r.items.map(i => el("div", { class: "docs-item" }, el("h4", {}, mark(i.title, ts)),
          ["what", "why", "how"].map(k => i[k] ? [sub(L[k]), el("p", {}, mark(i[k], ts))] : null))))));
    }
    /* ---- Ein Bereich: Prüfungen, Aktionen und Technik. Je Eintrag erst Was und Warum, dann Wie, dann (eingeklappt) der Code. */
    function copyText(txt, btn) {
      const done = () => { btn.textContent = L.copied; setTimeout(() => { btn.textContent = L.copy; }, 1400); };
      function fallback() { const ta = el("textarea", { style: "position:fixed;left:-9999px" }); ta.value = txt; document.body.append(ta); ta.select(); try { document.execCommand("copy"); done(); } catch (e) { /* ohne Zwischenablage */ } ta.remove(); }
      try { navigator.clipboard.writeText(txt).then(done, fallback); } catch (e) { fallback(); }
    }
    /* Codefenster: schwarz, Code grün, eingeklappt, Kopierfunktion. Der Inhalt wird erst beim Aufklappen aufgebaut (schnell auch bei vielen Blöcken). */
    function codeWin(name, where, code, ts) {
      const lines = String(code).split("\n").length;
      const btn = el("button", { type: "button", class: "docs-copy", text: L.copy });
      btn.addEventListener("click", ev => { ev.preventDefault(); ev.stopPropagation(); copyText(code, btn); });
      const d = el("details", { class: "docs-cw" });
      const inner = el("div", { class: "docs-cw-body" });
      d.append(el("summary", {}, el("span", { class: "docs-cw-t", text: L.showcode + ": " + name }), el("span", { class: "docs-cw-w", text: (where ? where + "  |  " : "") + lines + " " + L.lines }), btn), inner);
      d.addEventListener("toggle", () => { if (d.open && !inner.firstChild) inner.append(el("pre", {}, ts && ts.length ? mark(String(code), ts) : String(code))); });
      return d;
    }
    const sub = text => el("h5", { class: "docs-sub", text });
    function techIndex() {
      const idx = { c: {}, a: {}, g: [] };
      if (tech) {
        (tech.checks || []).forEach(c => { idx.c[c.id] = c; });
        (tech.actions || []).forEach(a => { idx.a[a.id] = a; });
        idx.g = tech.basics || [];
      }
      return idx;
    }
    function blockCode(list, ts) {
      const consts = list.filter(b => b.kind === "const"), progs = list.filter(b => b.kind !== "const");
      return [
        consts.length ? [sub(L.sqls), consts.map(b => codeWin(b.name, b.file + (b.line && b.line !== "0" ? ":" + b.line : ""), b.code, ts))] : null,
        progs.length ? [sub(L.prog), progs.map(b => codeWin(b.name, b.file + (b.line && b.line !== "0" ? ":" + b.line : ""), b.code, ts))] : null,
      ];
    }
    function catalogModel() {
      const ti = techIndex();
      const groups = [];
      if (ti.g.length) groups.push({ id: "g-basics", title: L.basicsT, items: ti.g.map(b => ({ key: "g:" + b.id, kind: "basic", title: b.title, t: b })) });
      const seen = {}, byCms = { joomla: [], wordpress: [], drupal: [], typo3: [], contao: [], prestashop: [], both: [] };
      chk.forEach(c => {
        const tc = ti.c[c.id], cms = tc ? tc.cms : (c.cms || "joomla");
        const k = c.id;
        if (seen[k]) return;
        seen[k] = true;
        const same = chk.filter(x => x.id === c.id).length > 1;
        byCms[same ? "both" : cms === "both" ? "both" : cms].push({ key: "c:" + c.id, kind: "check", title: c.title, c, t: tc });
      });
      Object.keys(byCms).forEach(k => byCms[k].sort((x, y) => x.title.localeCompare(y.title, data.lang || "de", { sensitivity: "base", numeric: true })));   // Prüfungen je System alphabetisch
      if (byCms.joomla.length) groups.push({ id: "g-cj", title: L.checksJ, items: byCms.joomla });
      if (byCms.wordpress.length) groups.push({ id: "g-cw", title: L.checksW, items: byCms.wordpress });
      if (byCms.drupal.length) groups.push({ id: "g-cd", title: L.checksD, items: byCms.drupal });
      if (byCms.typo3.length) groups.push({ id: "g-ct", title: L.checksT, items: byCms.typo3 });
      if (byCms.contao.length) groups.push({ id: "g-cc", title: L.checksC, items: byCms.contao });
      if (byCms.prestashop.length) groups.push({ id: "g-cp", title: L.checksP, items: byCms.prestashop });
      if (byCms.both.length) groups.push({ id: "g-cb", title: L.checksB, items: byCms.both });
      if (act.length) groups.push({ id: "g-act", title: L.actionsAll, items: act.map(a => ({ key: "a:" + a.id, kind: "action", title: a.title, a, t: ti.a[a.id] })) });
      return groups;
    }
    function entryText(it) {
      if (it._x === undefined) {
        const parts = [it.title];
        if (it.c) parts.push(it.c.summary, it.c.what, it.c.why, it.c.reads);
        if (it.a) parts.push(it.a.what, it.a.how, it.a.why, it.a.warning, it.a.undo, it.a.risk);
        if (it.t) {
          parts.push(it.t.summary || "", it.t.commands || "");
          (it.t.text || []).forEach(b => parts.push((b.items || [b.text]).join(" ")));
          (it.t.blocks || it.t.code || []).forEach(b => parts.push(b.name + " " + b.code));
        }
        it._x = fold(parts.filter(Boolean).join(" "));
      }
      return it._x;
    }
    function scrollToKey(key) {
      const t = body.querySelector("[id='doc-" + key + "']");
      if (t) { t.scrollIntoView({ block: "start" }); navMark(key); }
    }
    function navMark(key) { st.sec = key; nav.querySelectorAll("a").forEach(a => a.classList.toggle("on", a.getAttribute("data-k") === key)); }
    const backLink = () => el("a", { href: "#doc-toc", class: "docs-back", onclick: ev => { ev.preventDefault(); scrollToKey("toc"); } }, "↑ " + L.back);
    function entryNode(it, ts) {
      const kids = [];
      const tags = [];
      if (it.c && (it.c.load === "slow" || it.c.slow)) tags.push(el("span", { class: "docs-tag", text: " " + L.slowtag }));
      kids.push(el("div", { class: "docs-eh" }, el("h4", {}, mark(it.title, ts), tags), backLink()));
      if (it.kind === "basic") {
        kids.push(blocks(it.t.text, ts));
      } else if (it.kind === "check") {
        const c = it.c;
        if (c.summary) kids.push(el("p", { class: "docs-lead" }, mark(c.summary, ts)));
        if (c.what) kids.push(sub(L.what), el("p", {}, mark(c.what, ts)));
        if (c.why) kids.push(sub(L.why), el("p", {}, mark(c.why, ts)));
        if (c.reads) kids.push(sub(L.how + " / " + L.reads), el("p", {}, mark(c.reads, ts)));
        if (it.t && (it.t.blocks || []).length) kids.push(blockCode(it.t.blocks, ts));
      } else {
        const a = it.a, t = it.t || {};
        if (a.what) kids.push(sub(L.what), el("p", {}, mark(a.what, ts)));
        if (a.why) kids.push(sub(L.why), el("p", {}, mark(a.why, ts)));
        const how = blocks(t.text, ts);
        kids.push(sub(L.how), how.length ? how : el("p", {}, L.howAuto));
        const imp = [["warning", a.warning], ["undo", a.undo], ["risk", a.risk], ["backup", a.backup]].filter(x => x[1]);
        if (imp.length) kids.push(sub(L.important), el("dl", {}, imp.map(([k, v]) => [el("dt", { text: L[k] }), el("dd", {}, [mark(v, ts), k === "risk" ? riskMeter(a.risk) : null])])));
        if (a.how) kids.push(sub(L.cmds), codeWin(L.code, "", a.how, ts));
        if ((t.blocks || []).length) kids.push(blockCode(t.blocks, ts));
      }
      return el("div", { class: "docs-item", id: "doc-" + it.key }, kids);
    }
    function riskMeter(risk) {
      const lv = { keine: 0, niedrig: 1, mittel: 3, hoch: 5 }[risk];
      if (lv === undefined) return null;
      const w = el("span", { class: "docs-risk", title: risk });
      for (let i = 1; i <= 5; i++) w.append(el("span", { text: "\u26A0\uFE0F", style: i <= lv ? "" : "filter:grayscale(1);opacity:.28" }));
      return w;
    }
    function showCatalog(ts) {
      if (!tech && opts.loadTech) ensureTech();
      const groups = catalogModel();
      const navs = [el("a", { href: "#doc-toc", "data-k": "toc", class: st.sec === "toc" ? "on" : "", onclick: ev => { ev.preventDefault(); scrollToKey("toc"); } }, L.toc)];
      groups.forEach(g => navs.push(el("a", { href: "#doc-" + g.id, "data-k": g.id, class: st.sec === g.id ? "on" : "", onclick: ev => { ev.preventDefault(); scrollToKey(g.id); } }, g.title)));
      nav.replaceChildren(...navs);
      const toc = el("section", { id: "doc-toc", class: "docs-sec docs-toc" }, el("h3", { text: L.toc }), el("p", { class: "docs-intro" }, L.intro),
        groups.map(g => el("div", { class: "docs-tocg" }, el("h5", { class: "docs-sub" }, el("a", { href: "#doc-" + g.id, onclick: ev => { ev.preventDefault(); scrollToKey(g.id); } }, g.title), " (" + g.items.length + ")"),
          el("ul", { class: "docs-toclist" }, g.items.map(it => el("li", {}, el("a", { href: "#doc-" + it.key, onclick: ev => { ev.preventDefault(); scrollToKey(it.key); } }, it.title)))))));
      const secs = groups.map(g => el("section", { id: "doc-" + g.id, class: "docs-sec" }, el("div", { class: "docs-eh" }, el("h3", { text: g.title }), backLink()), g.items.map(it => entryNode(it, ts))));
      if (!tech && opts.loadTech) secs.push(el("p", { class: "muted", text: L.loading }));
      body.replaceChildren(toc, ...secs);
      if (st.sec) setTimeout(() => scrollToKey(st.sec), 0);
    }
    function ensureTech() {
      if (tech || techBusy || !opts.loadTech) return;
      techBusy = true;
      opts.loadTech().then(t => { tech = t; techBusy = false; draw(); }, () => { techBusy = false; tech = { basics: [], checks: [], actions: [] }; draw(); });
    }
    function showSearch(ts) {
      nav.replaceChildren(el("a", { href: "#", onclick: ev => { ev.preventDefault(); input.value = ""; st.q = ""; draw(); input.focus(); }, text: L.more }));
      const rows = [];
      hand.forEach(s => { if (hit(textOf.handbook(s), ts)) rows.push({ tab: "handbook", title: s.title, kind: L.handbook, snip: snippet(textOf.handbook(s), ts), sec: s.id }); });
      log.forEach(r => r.items.forEach(i => { const t = [r.version, i.title, i.what, i.why, i.how].join(" "); if (hit(t, ts)) rows.push({ tab: "changes", title: L.version + " " + r.version + ": " + i.title, kind: L.changes, snip: snippet(t, ts) }); }));
      catalogModel().forEach(g => g.items.forEach(it => { if (hit(entryText(it), ts)) rows.push({ tab: "catalog", title: it.title, kind: it.kind === "action" ? L.actions : it.kind === "check" ? L.checks : L.tech, snip: snippet(entryText(it), ts), sec: it.key }); }));
      body.replaceChildren(el("h3", { text: L.results + ": " + rows.length }),
        ...(rows.length ? rows.slice(0, 80).map(r => el("div", { class: "docs-hit" }, el("a", { href: "#", onclick: ev => { ev.preventDefault(); input.value = ""; st.q = ""; st.tab = r.tab; st.sec = r.sec || null; draw(); } }, mark(r.title, ts)),
          el("span", { class: "docs-kind", text: " " + r.kind }), el("p", {}, mark(r.snip, ts)))) : [el("p", { class: "muted", text: L.none })]));
    }
    function snippet(txt, ts) {
      const i = Math.max(0, fold(txt).indexOf(fold(ts[0] || "")));
      return (i > 60 ? "... " : "") + txt.slice(Math.max(0, i - 60), i + 160) + (txt.length > i + 160 ? " ..." : "");
    }
    function draw() {
      const ts = terms();
      tabs.replaceChildren(...[["handbook", L.handbook], ["changes", L.changes]].concat(chk.length || act.length || hasTech() ? [["catalog", L.catalog]] : []).map(([k, name]) =>
        el("button", { type: "button", role: "tab", class: "docs-tab" + (st.tab === k && !ts.length ? " on" : ""), "aria-selected": String(st.tab === k && !ts.length), onclick: () => { input.value = ""; st.q = ""; st.tab = k; draw(); } }, name)));
      if (ts.length && opts.loadTech && !tech) ensureTech();
      if (ts.length) showSearch(ts);
      else if (st.tab === "changes") showChanges([]);
      else if (st.tab === "catalog") showCatalog([]);
      else showHandbook([]);
    }
    input.addEventListener("input", () => { st.q = input.value; draw(); });
    draw();
    return { setTab: k => { st.tab = ({ checks: "catalog", actions: "catalog", tech: "catalog" })[k] || k; draw(); } };
  }
  root.ClaudiaDocs = { mount };
})(typeof window !== "undefined" ? window : this);
