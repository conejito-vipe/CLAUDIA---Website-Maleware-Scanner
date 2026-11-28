/* CLAUDIA-Radar: zusätzliche Animation im Prüfungs-Bildschirm. Zeigt je Prüfung einen Punkt; alle Texte der Oberfläche bleiben unverändert.
   Schnittstelle:
     const r = ClaudiaRadar.mount(canvas);
     r.set({ plan: [ids], status: { id: "ok|info|warn|crit|skipped" }, current: id | null, running: bool });
     r.positions();   // [{id, x, y}] in CSS-Pixeln (für Tests)
     r.destroy();
   Darstellung: kritisch = kräftiges Bernstein mit Ring, Bitte prüfen = gedämpftes Bernstein, Hinweis = Blau, In Ordnung = gedämpftes Grün,
   Übersprungen = Grau mit hohlem Punkt. Es gibt keinen roten Kreis und keine Regler. Bei "Animationen reduzieren" (prefers-reduced-motion)
   wird nur ein ruhiges Standbild gezeichnet. Farben kommen aus den CSS-Variablen der Oberfläche (hell/dunkel) und werden bei Wechsel neu gelesen. */
const ClaudiaRadar = (() => {
  const TAU = Math.PI * 2;
  const FALLBACK = { ok: [79, 181, 129], info: [120, 166, 230], warn: [230, 165, 38], skip: [136, 150, 163], accent: [76, 195, 212] };
  const hash = s => { let h = 2166136261; for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619); } return (h >>> 0) / 4294967296; };
  const FIND = { crit: 1, warn: 1, info: 1 };                          // nur Funde werden als Punkt gezeigt; "in Ordnung", wartend und übersprungen bleiben unsichtbar
  const norm = a => ((a % TAU) + TAU) % TAU;

  function parseColor(v, fb) {
    v = (v || "").trim();
    let m = /^#([0-9a-f]{3}|[0-9a-f]{6})$/i.exec(v);
    if (m) { let x = m[1]; if (x.length === 3) x = x.replace(/./g, "$&$&"); return [0, 2, 4].map(i => parseInt(x.substr(i, 2), 16)); }
    m = /^rgba?\(\s*(\d+)[ ,]+(\d+)[ ,]+(\d+)/i.exec(v);
    return m ? [+m[1], +m[2], +m[3]] : fb;
  }
  /* Der Radarschirm ist in beiden Darstellungen dunkel; dunkle Farben (helles Design) werden deshalb aufgehellt, damit die Punkte leuchten. */
  function lift(c) {
    const lum = (0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2]) / 255;
    if (lum >= 0.5) return c;
    const t = Math.min(0.6, (0.55 - lum) * 1.4);
    return c.map(x => Math.round(x + (255 - x) * t));
  }
  function readPalette() {
    const cs = getComputedStyle(document.documentElement), g = (n, fb) => lift(parseColor(cs.getPropertyValue(n), fb));
    const warn = g("--warn", FALLBACK.warn);
    return {
      ok: g("--ok", FALLBACK.ok), info: g("--info", FALLBACK.info), warn, skipped: g("--skip", FALLBACK.skip), accent: g("--accent", FALLBACK.accent),
      crit: g("--crit", [255, 138, 128]),                               // kritisch: eigene Farbe (wie in Legende und Ergebnis), mit Ring
    };
  }
  const rgb = c => c.join(",");

  function mount(canvas, opts) {
    const ctx = canvas.getContext("2d");
    /* opts.motion: Strahl dreht sich immer, auch wenn Windows "Animationseffekte" ausgeschaltet hat (Wunsch für die Prüfungsansicht).
       Ohne die Option richtet sich das Radar nach "Bewegung reduzieren" und bleibt ruhig. */
    const still = (opts && opts.motion) ? { matches: false } : (window.matchMedia ? matchMedia("(prefers-reduced-motion: reduce)") : { matches: false });
    const dark = window.matchMedia ? matchMedia("(prefers-color-scheme: dark)") : null;
    let W = 0, cx = 0, R = 0, raf = 0, last = 0, sweep = -Math.PI / 2, alive = true;
    let st = { plan: [], status: {}, current: null, running: false };
    let dots = [], waves = [], pal = readPalette();

    function size() {
      const w = Math.max(120, Math.round(canvas.getBoundingClientRect().width)), d = window.devicePixelRatio || 1;
      canvas.width = w * d; canvas.height = w * d; ctx.setTransform(d, 0, 0, d, 0, 0);
      W = w; cx = w / 2; R = w / 2 - 6;
      if (!raf || still.matches) draw(0, 0);
    }
    function build() {
      dots = st.plan.map(id => ({ id, a: hash(id + "a") * TAU, h: hash(id + "d"), lit: 0, shown: st.status[id] || "" }));
    }
    /* Abstand zur Mitte nach Schwere: kritisch im inneren Ring (frühestens auf halbem Weg zwischen Mittelpunkt und innerem Kreis, nie ganz in der Mitte),
       "Bitte prüfen" im zweiten Ring, Hinweise außen */
    const BAND = { crit: [0.13, 0.23], warn: [0.29, 0.48], info: [0.54, 0.92] };
    function pos(d) { const b = BAND[st.status[d.id]] || BAND.info, r = (b[0] + d.h * (b[1] - b[0])) * R; return [cx + Math.cos(d.a) * r, cx + Math.sin(d.a) * r]; }
    function set(next) {
      if (!alive) return;
      const prev = st.status;
      st = Object.assign({ plan: [], status: {}, current: null, running: false }, next);
      if (dots.length !== st.plan.length || dots.some((d, i) => d.id !== st.plan[i])) build();
      dots.forEach(d => {
        const s = st.status[d.id] || "";
        if (FIND[s] && !prev[d.id] && d.shown !== s) { const p = pos(d); waves.push({ x: p[0], y: p[1], r: 3, al: 0.9 }); d.lit = 1; }
        d.shown = s;
      });
      if (still.matches) draw(0, 0); else start();
    }

    function drawDisc() {
      const g = ctx.createRadialGradient(cx, cx, 4, cx, cx, R);
      g.addColorStop(0, "#0a2c52"); g.addColorStop(0.65, "#05172e"); g.addColorStop(1, "#020914");
      ctx.beginPath(); ctx.arc(cx, cx, R, 0, TAU); ctx.fillStyle = g; ctx.fill();
      ctx.strokeStyle = "rgba(" + rgb(pal.accent) + ",.55)"; ctx.lineWidth = 2; ctx.stroke();
      ctx.lineWidth = 1;
      for (let i = 1; i < 4; i++) { ctx.beginPath(); ctx.arc(cx, cx, R / 4 * i, 0, TAU); ctx.strokeStyle = "rgba(56,160,230,.22)"; ctx.stroke(); }
      for (let i = 0; i < 4; i++) { const a = Math.PI / 4 * i; ctx.beginPath(); ctx.moveTo(cx + Math.cos(a) * R, cx + Math.sin(a) * R); ctx.lineTo(cx - Math.cos(a) * R, cx - Math.sin(a) * R); ctx.strokeStyle = "rgba(56,160,230,.18)"; ctx.stroke(); }
      for (let d = 0; d < 360; d += 10) {
        const a = d * Math.PI / 180, m = d % 30 === 0, i = R - (m ? 8 : 4);
        ctx.beginPath(); ctx.moveTo(cx + Math.cos(a) * i, cx + Math.sin(a) * i); ctx.lineTo(cx + Math.cos(a) * R, cx + Math.sin(a) * R);
        ctx.strokeStyle = m ? "rgba(" + rgb(pal.accent) + ",.5)" : "rgba(56,160,230,.22)"; ctx.stroke();
      }
      ctx.beginPath(); ctx.arc(cx, cx, 3.5, 0, TAU); ctx.fillStyle = "rgb(" + rgb(pal.accent) + ")"; ctx.fill();
    }
    function drawSweep() {
      const n = 40, len = Math.PI * 0.5, step = len / n, ac = rgb(pal.accent);
      ctx.save();
      for (let i = 0; i < n; i++) {
        ctx.beginPath(); ctx.moveTo(cx, cx); ctx.arc(cx, cx, R, sweep - (i + 1) * step, sweep - i * step); ctx.closePath();
        ctx.fillStyle = "rgba(" + ac + "," + (Math.pow(1 - i / n, 2.2) * (st.running ? 0.40 : 0.16)) + ")"; ctx.fill();
      }
      const x = cx + Math.cos(sweep) * R, y = cx + Math.sin(sweep) * R, lg = ctx.createLinearGradient(cx, cx, x, y);
      lg.addColorStop(0, "rgba(" + ac + ",.25)"); lg.addColorStop(1, "rgba(180,240,250,.95)");
      ctx.beginPath(); ctx.moveTo(cx, cx); ctx.lineTo(x, y); ctx.strokeStyle = lg; ctx.lineWidth = 2; ctx.shadowColor = "rgb(" + ac + ")"; ctx.shadowBlur = 10; ctx.stroke();
      ctx.restore();
    }
    function drawDots(t) {                          // Punkte erscheinen nur bei Funden, leuchten auf, wenn der Strahl sie trifft, und verblassen danach wieder
      dots.forEach(d => {
        const s = st.status[d.id] || "";
        if (!FIND[s] || d.lit < 0.02) return;
        const p = pos(d), x = p[0], y = p[1], c = pal[s] || pal.skipped, k = d.lit;
        const rad = (s === "crit" ? 4.6 : s === "warn" ? 3.8 : 3.2) + k * 1.6;
        ctx.save();
        ctx.beginPath(); ctx.arc(x, y, rad, 0, TAU);
        ctx.fillStyle = "rgba(" + rgb(c) + "," + Math.min(1, (s === "info" ? 0.8 : 1) * k) + ")";
        ctx.shadowColor = "rgb(" + rgb(c) + ")"; ctx.shadowBlur = (s === "crit" ? 18 : 10) * k; ctx.fill();
        if (s === "crit") { ctx.shadowBlur = 0; ctx.beginPath(); ctx.arc(x, y, rad + 4, 0, TAU); ctx.strokeStyle = "rgba(" + rgb(c) + "," + (0.6 * k) + ")"; ctx.lineWidth = 1.2; ctx.stroke(); }
        ctx.restore();
      });
    }
    function drawWaves(dt) {                        // einmalige ruhige Welle, wenn ein Ergebnis eintrifft
      for (let i = waves.length - 1; i >= 0; i--) {
        const w = waves[i]; w.r += dt * 42; w.al -= dt * 1.5;
        if (w.al <= 0) { waves.splice(i, 1); continue; }
        ctx.beginPath(); ctx.arc(w.x, w.y, w.r, 0, TAU); ctx.strokeStyle = "rgba(" + rgb(pal.accent) + "," + w.al + ")"; ctx.lineWidth = 1.5; ctx.stroke();
      }
    }
    function draw(dt, t) {
      ctx.clearRect(0, 0, W, W); drawDisc();
      if (!still.matches) drawSweep();
      dots.forEach(d => {                           // Treffer durch den Strahl: kurz hell, dann ruhiger
        if (still.matches) d.lit = FIND[st.status[d.id]] ? 0.85 : 0;
        else if (FIND[st.status[d.id]]) { let df = norm(sweep) - norm(d.a); if (df < 0) df += TAU; if (df < 0.12) d.lit = 1; else d.lit = Math.max(0, d.lit - dt * 0.4); }
      });
      drawDots(t || 0); if (!still.matches) drawWaves(dt);
    }
    function frame(ts) {
      if (!alive) return;
      if (!last) last = ts;
      const dt = Math.min((ts - last) / 1000, 0.1); last = ts;
      sweep = norm(sweep + (st.running ? 1.5 : 0.5) * dt);
      draw(dt, ts / 1000);
      raf = requestAnimationFrame(frame);
    }
    function start() { if (!raf && alive && !still.matches) { last = 0; raf = requestAnimationFrame(frame); } }
    function onStill() { if (still.matches) { cancelAnimationFrame(raf); raf = 0; waves = []; draw(0, 0); } else start(); }
    function onTheme() { pal = readPalette(); if (!raf) draw(0, 0); }
    const ro = window.ResizeObserver ? new ResizeObserver(size) : null; if (ro) ro.observe(canvas);
    const mo = window.MutationObserver ? new MutationObserver(onTheme) : null; if (mo) mo.observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme", "class"] });
    if (still.addEventListener) still.addEventListener("change", onStill);
    if (dark && dark.addEventListener) dark.addEventListener("change", onTheme);
    size();
    return {
      canvas, set, positions: () => dots.map(d => { const p = pos(d); return { id: d.id, x: p[0], y: p[1] }; }),
      destroy() {
        alive = false; cancelAnimationFrame(raf); raf = 0;
        if (ro) ro.disconnect(); if (mo) mo.disconnect();
        if (still.removeEventListener) still.removeEventListener("change", onStill);
        if (dark && dark.removeEventListener) dark.removeEventListener("change", onTheme);
      },
    };
  }
  return { mount };
})();
