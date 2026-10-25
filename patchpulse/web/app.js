/* PatchPulse dashboard. No frameworks, no build step, no inline HTML from data:
   every piece of text from a website goes through textContent (XSS-safe). */
"use strict";

// ---------- tiny helpers ----------
const $main = document.getElementById("main");
const $live = document.getElementById("live");
let STATE = { status: null, guides: null, pollTimer: null };

function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (k === "text") el.textContent = v;
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const kid of kids.flat(Infinity)) {
    if (kid === null || kid === undefined || kid === false) continue;
    el.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  }
  return el;
}
function svg(tag, attrs, ...kids) {
  const el = document.createElementNS("http://www.w3.org/2000/svg", tag);
  for (const [k, v] of Object.entries(attrs || {})) el.setAttribute(k, v);
  kids.flat().forEach((k) => k && el.append(k));
  return el;
}
function render(...nodes) {
  $main.replaceChildren(...nodes.flat().filter(Boolean));
  $main.focus({ preventScroll: true });
  window.scrollTo(0, 0);
}
function announce(msg) { $live.textContent = ""; setTimeout(() => ($live.textContent = msg), 50); }
function toast(msg, bad) {
  document.querySelectorAll(".toast").forEach((t) => t.remove());
  const t = h("div", { class: "toast" + (bad ? " bad" : ""), role: "status" }, msg);
  document.body.append(t);
  setTimeout(() => t.remove(), 5000);
}
function paras(text) { return String(text || "").split(/\n\n+/).map((p) => h("p", {}, p)); }
function ago(ts) {
  if (!ts) return "not yet";
  const s = Math.max(0, Date.now() / 1000 - ts);
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  if (s < 86400) return `${Math.round(s / 3600)} hr ago`;
  return `${Math.round(s / 86400)} day${s >= 172800 ? "s" : ""} ago`;
}
async function copy(text) {
  try { await navigator.clipboard.writeText(text); toast("Copied. Now paste it into a chat or email."); }
  catch { const ta = h("textarea", {}, text); document.body.append(ta); ta.select();
    document.execCommand("copy"); ta.remove(); toast("Copied."); }
}

class ApiErr extends Error { constructor(msg, status, code) { super(msg); this.status = status; this.code = code; } }
async function api(method, path, body) {
  const opt = { method, headers: { "X-PatchPulse": "1" }, credentials: "same-origin" };
  if (body !== undefined) { opt.headers["Content-Type"] = "application/json"; opt.body = JSON.stringify(body); }
  let res;
  try { res = await fetch(path, opt); }
  catch { throw new ApiErr("Can't reach PatchPulse. Is the PatchPulse window still open?", 0); }
  let data = {};
  try { data = await res.json(); } catch {}
  if (res.status === 401 && path !== "/api/login") { STATE.status = null; route(); throw new ApiErr("Please sign in.", 401); }
  if (!res.ok) throw new ApiErr(data.error || `Error ${res.status}`, res.status, data.code);
  return data;
}

const WORD = { critical: "At risk", warning: "Needs attention", ok: "Looks good", down: "Can't reach site",
  pending: "Waiting to check", error: "Check failed", scanning: "Checking…" };
const SEV = { critical: "Urgent", high: "Important", medium: "Fix soon", low: "Minor", info: "Good to know" };

function stateBadge(status, scanning) {
  const s = scanning ? "scanning" : status || "pending";
  return h("span", { class: "state " + s }, WORD[s] || s);
}

// The signature element: a heartbeat trace whose rhythm reflects health.
function pulseLine(status) {
  const w = 840, mid = 40;
  const beats = { ok: [[0, -6], [5, 22], [10, -30], [16, 10]], warning: [[0, -14], [5, 26], [9, -36], [14, 14]],
    critical: [[0, -26], [4, 34], [8, -38], [11, 30], [15, -22]], down: [], pending: [], none: [] }[status] || [];
  let d = `M0 ${mid}`;
  const spacing = 140;
  for (let x = 30; x < w; x += spacing) {
    if (!beats.length) break;
    d += ` L${x} ${mid}`;
    for (const [dx, dy] of beats) d += ` L${x + 20 + dx * 2} ${mid + dy}`;
    d += ` L${x + 60} ${mid}`;
  }
  d += ` L${w} ${mid}`;
  const grid = svg("g", { class: "grid" });
  for (let y = 8; y < 80; y += 16) grid.append(svg("line", { x1: 0, x2: w, y1: y, y2: y }));
  for (let x = 0; x <= w; x += 40) grid.append(svg("line", { x1: x, x2: x, y1: 0, y2: 80 }));
  return svg("svg", { class: "pulse " + (status || "none"), viewBox: `0 0 ${w} 80`, preserveAspectRatio: "none",
    "aria-hidden": "true" }, grid, svg("path", { class: "trace", d }));
}

async function guides() {
  if (!STATE.guides) STATE.guides = await api("GET", "/api/guides");
  return STATE.guides;
}

// ---------- text size ----------
(function textSize() {
  const btn = document.getElementById("textsize");
  const apply = (on) => { document.documentElement.dataset.size = on ? "large" : "";
    btn.setAttribute("aria-pressed", on ? "true" : "false"); btn.textContent = on ? "A−" : "A+";
    btn.title = on ? "Make text normal size" : "Make text bigger"; };
  let on = false;
  try { on = localStorage.getItem("pp-size") === "large"; } catch {}
  apply(on);
  btn.addEventListener("click", () => { on = !on; apply(on); try { localStorage.setItem("pp-size", on ? "large" : ""); } catch {} });
})();

// ---------- routing ----------
window.addEventListener("hashchange", route);
document.addEventListener("DOMContentLoaded", route);

async function route() {
  clearTimeout(STATE.pollTimer);
  if (!STATE.status) {
    try { STATE.status = await (await fetch("/api/status", { credentials: "same-origin" })).json(); }
    catch { return render(h("p", { class: "form-error" }, "Can't reach PatchPulse. Make sure the PatchPulse window is open, then refresh this page.")); }
  }
  const bar = document.getElementById("bar");
  if (STATE.status.setup_needed) { bar.hidden = true; return viewSetup(); }
  if (!STATE.status.signed_in) { bar.hidden = true; return viewLogin(); }
  bar.hidden = false;
  const hash = location.hash.replace(/^#/, "") || "/";
  if (STATE.status.license_state !== "active" && !["/settings", "/help", "/alerts"].includes(hash)) {
    document.querySelectorAll("[data-nav]").forEach((a) => a.removeAttribute("aria-current"));
    return viewActivate();
  }
  const nav = hash.startsWith("/alerts") ? "alerts" : hash.startsWith("/settings") ? "settings" :
    hash.startsWith("/help") ? "help" : "home";
  document.querySelectorAll("[data-nav]").forEach((a) =>
    a.dataset.nav === nav ? a.setAttribute("aria-current", "page") : a.removeAttribute("aria-current"));
  try {
    let m;
    if (hash === "/") return await viewHome();
    if (hash === "/add") return await viewAdd();
    if ((m = hash.match(/^\/site\/(\d+)/))) return await viewSite(+m[1]);
    if (hash === "/alerts") return await viewAlerts();
    if (hash === "/settings") return await viewSettings();
    if (hash === "/help") return await viewHelp();
    location.hash = "#/";
  } catch (e) {
    if (e.status !== 401) render(h("p", { class: "form-error" }, e.message));
  }
}

// ---------- first run & sign in ----------
function viewSetup() {
  const err = h("p", { class: "form-error", role: "alert" });
  const pw = h("input", { type: "password", id: "pw", autocomplete: "new-password", required: true, minlength: 8 });
  const pw2 = h("input", { type: "password", id: "pw2", autocomplete: "new-password", required: true });
  const form = h("form", { class: "sheet", onsubmit: async (ev) => {
    ev.preventDefault(); err.textContent = "";
    if (pw.value.length < 8) return (err.textContent = "Please use at least 8 characters.");
    if (pw.value !== pw2.value) return (err.textContent = "The two passwords don't match. Please type them again.");
    try { await api("POST", "/api/setup", { password: pw.value }); STATE.status = null; location.hash = "#/add"; route(); }
    catch (e) { err.textContent = e.message; }
  } },
    h("label", { for: "pw" }, "Choose a password",
      h("span", { class: "hint" }, "At least 8 characters. You'll use it to open PatchPulse.")), pw,
    h("label", { for: "pw2" }, "Type the same password again"), pw2,
    err, h("div", { class: "row" }, h("button", { class: "btn big", type: "submit" }, "Create password and continue")));
  render(h("div", { class: "narrow" }, pulseLine("ok"),
    h("h1", {}, "Welcome to PatchPulse"),
    h("p", { class: "lead" }, "PatchPulse keeps an eye on your websites and tells you, in plain English, when something needs fixing — like the PHP2Shell attacks happening right now."),
    h("p", {}, "Setup takes about two minutes. First, protect PatchPulse with a password."), form));
  pw.focus();
}

function viewLogin() {
  const err = h("p", { class: "form-error", role: "alert" });
  const pw = h("input", { type: "password", id: "pw", autocomplete: "current-password", required: true });
  render(h("div", { class: "narrow" }, pulseLine("none"), h("h1", {}, "Sign in to PatchPulse"),
    h("form", { class: "sheet", onsubmit: async (ev) => {
      ev.preventDefault(); err.textContent = "";
      try { await api("POST", "/api/login", { password: pw.value }); STATE.status = null; route(); }
      catch (e) { err.textContent = e.message; pw.select(); }
    } }, h("label", { for: "pw" }, "Password"), pw, err,
      h("div", { class: "row" }, h("button", { class: "btn big", type: "submit" }, "Sign in"))),
    h("p", { class: "muted small" }, "Forgot your password? Close PatchPulse, then run it once with the words ",
      h("span", { class: "code" }, "reset-password"), " (see the Start Here guide).")));
  pw.focus();
}

// ---------- license activation (no free tier) ----------
function viewActivate() {
  const st = STATE.status;
  const err = h("p", { class: "form-error", role: "alert" });
  const key = h("textarea", { id: "lic", placeholder: "PP1-…", spellcheck: "false", autocomplete: "off" });
  const btn = h("button", { class: "btn big", type: "submit" }, "Activate PatchPulse");
  const heading = { none: "Activate PatchPulse", expired: "Your license has expired", revoked: "Your license was cancelled",
    needs_activation: "Confirm your license", invalid: "Your license key isn't valid" }[st.license_state] || "Activate PatchPulse";
  render(h("div", { class: "narrow" }, pulseLine("none"),
    h("h1", {}, heading),
    h("p", { class: "lead" }, st.license_state === "none"
      ? "Paste the license key from your purchase email. Monitoring and threat hunting start the moment it's activated."
      : st.license_message),
    h("form", { class: "sheet", onsubmit: async (ev) => {
      ev.preventDefault(); err.textContent = ""; btn.disabled = true; btn.textContent = "Activating…";
      try {
        await api("POST", "/api/license", { key: key.value });
        STATE.status = null; toast("PatchPulse is active. Let's add your first website.");
        location.hash = "#/add"; route();
      } catch (e) { err.textContent = e.message; btn.disabled = false; btn.textContent = "Activate PatchPulse"; }
    } },
      h("label", { for: "lic" }, "License key", h("span", { class: "hint" }, "It starts with PP1- . Copy and paste the whole thing.")), key,
      err, h("div", { class: "row" }, btn)),
    st.buy_url ? h("p", {}, "Don't have a license yet? ", h("a", { href: st.buy_url, target: "_blank", rel: "noopener" }, "See plans and buy PatchPulse")) : null,
    st.support_email ? h("p", { class: "muted small" }, "Problems activating? Email ", h("a", { href: "mailto:" + st.support_email }, st.support_email), ".") : null));
  key.focus();
}

// ---------- threat watch panel ----------
function threatWatch(iv, onHunt) {
  if (!iv) return null;
  const sources = iv.sources || {};
  const down = Object.entries(sources).filter(([, v]) => v && v.ok === false).map(([k]) =>
    ({ kev: "CISA list", nvd: "NIST database", eol: "support dates", hub: "PatchPulse feed" }[k] || k));
  const btn = h("button", { class: "btn quiet", type: "button", disabled: iv.hunting, onclick: async () => {
    btn.disabled = true; btn.textContent = "Hunting…";
    try { await api("POST", "/api/intel/hunt"); announce("Threat hunt started"); setTimeout(onHunt, 4000); }
    catch (e) { toast(e.message, true); btn.disabled = false; btn.textContent = "Hunt now"; } } }, iv.hunting ? "Hunting…" : "Hunt now");
  return h("section", { class: "watch", "aria-label": "Threat watch" },
    h("div", { class: "watch-h" }, h("h2", {}, "Threat watch"), btn),
    h("p", {}, iv.last_hunt
      ? `Last hunt ${ago(iv.last_hunt)}. PatchPulse checks official threat sources every ${Math.round(iv.every_minutes)} minutes and re-checks your websites the moment a new threat matches their software.`
      : "The first threat hunt is starting. It can take a few minutes."),
    h("dl", { class: "facts" },
      fact("Actively exploited flaws on CISA's list", (iv.kev_count || 0).toLocaleString()),
      fact("Flaws matched to website software", (iv.tracked_flaws || 0).toLocaleString()),
      fact("Of those, being used in attacks", (iv.exploited_flaws || 0).toLocaleString()),
      fact("WordPress plugins watched", (iv.plugins_watched || 0).toLocaleString())),
    down.length ? h("p", { class: "muted small" }, `Couldn't reach: ${down.join(", ")}. PatchPulse will keep trying and uses what it already has in the meantime.`) : null);
}

// ---------- home ----------
async function viewHome() {
  const data = await api("GET", "/api/sites");
  const sites = data.sites;
  const scanning = sites.some((s) => s.scanning || s.status === "pending");
  const active = sites.filter((s) => s.active);
  const bad = active.filter((s) => ["critical", "down"].includes(s.status));
  const warn = active.filter((s) => s.status === "warning");
  let overall = "none", headline, sub;
  if (!sites.length) { headline = "Let's add your first website"; sub = "PatchPulse will check it right away, then keep checking automatically."; }
  else if (bad.length) { overall = "critical"; headline = bad.length === 1 ? `${bad[0].label || bad[0].url} needs you now` : `${bad.length} websites need you now`; sub = "Open the website below to see exactly what to do. Most fixes take a few minutes or one message to your host."; }
  else if (warn.length) { overall = "warning"; headline = `${warn.length} of ${active.length} website${active.length > 1 ? "s" : ""} need${warn.length === 1 ? "s" : ""} attention`; sub = "Nothing urgent, but worth fixing this week."; }
  else if (scanning) { overall = "pending"; headline = "Checking your websites…"; sub = "This usually takes under a minute."; }
  else { overall = "ok"; headline = active.length === 1 ? "Your website looks healthy" : `All ${active.length} websites look healthy`; sub = "PatchPulse keeps checking in the background and will alert you if anything changes."; }

  const recent = (data.advisories || []).filter((a) => a.published && (Date.now() - Date.parse(a.published)) < 45 * 864e5);
  const threat = recent.length ? h("div", { class: "notice red" },
    h("p", {}, h("strong", {}, `Active threat: ${recent[0].name}. `),
      "A critical flaw in PHP is being used to break into websites. PatchPulse checks every website on your list for it.")) : null;

  const list = h("ul", { class: "sites" }, sites.map((s) => {
    const st = s.scanning ? "pending" : s.status;
    return h("li", { class: `site ${st}${s.active ? "" : " inactive"}` },
      h("a", { class: "site-link", href: `#/site/${s.id}` },
        h("span", { class: "band", "aria-hidden": "true" }),
        h("div", {},
          h("div", { class: "site-name" }, s.label || s.url.replace(/^https?:\/\//, "")),
          s.label ? h("div", { class: "site-url" }, s.url) : null,
          h("div", { class: "site-top" },
            !s.active ? h("span", { class: "muted" }, "Not covered by your plan — upgrade to keep watching it.") :
            s.scanning ? h("span", { class: "muted" }, "Checking now…") :
            s.top ? [h("span", { class: "sev " + s.top.severity }, SEV[s.top.severity]), " ", s.top.title] :
            s.status === "ok" ? h("span", { class: "muted" }, "No problems found.") :
            s.error ? h("span", { class: "muted" }, s.error) : null)),
        h("div", { class: "site-side" }, stateBadge(s.status, s.scanning),
          h("span", { class: "muted small" }, "Checked " + ago(s.last_scan_at)))));
  }));

  const planName = data.plan ? data.plan[0].toUpperCase() + data.plan.slice(1) : "Your";
  const limitTxt = h("p", { class: "muted small" }, data.limit === null
      ? `${planName} plan: unlimited websites.`
      : `${planName} plan: ${Math.min(sites.length, data.limit)} of ${data.limit} website${data.limit > 1 ? "s" : ""}. `,
    data.limit !== null && sites.length >= data.limit && STATE.status.buy_url
      ? h("a", { href: STATE.status.buy_url, target: "_blank", rel: "noopener" }, "Upgrade to watch more") : null);

  render(
    h("h1", {}, headline), h("p", { class: "lead" }, sub), pulseLine(overall), threat,
    sites.length ? list : h("div", { class: "empty" },
      h("p", {}, "Type in your website address and PatchPulse will look for outdated software, leaked files and other common problems — the same things attackers' robots look for."),
      h("a", { class: "btn big", href: "#/add" }, "Add my website")),
    sites.length ? h("div", { class: "row mt2" },
      h("a", { class: "btn", href: "#/add" }, "Add a website"),
      h("button", { class: "btn quiet", type: "button", onclick: async (ev) => {
        ev.target.disabled = true;
        const r = await api("POST", "/api/sites/scan"); announce(`Checking ${r.started} websites`); viewHome(); } }, "Check all now")) : null,
    threatWatch(data.intel, viewHome),
    limitTxt);
  if (scanning || (data.intel && data.intel.hunting))
    STATE.pollTimer = setTimeout(() => location.hash.replace(/^#/, "") in { "": 1, "/": 1 } && viewHome(), scanning ? 2500 : 6000);
}

// ---------- add a website ----------
async function viewAdd() {
  const g = await guides();
  const err = h("p", { class: "form-error", role: "alert" });
  const url = h("input", { type: "text", id: "url", placeholder: "mysite.com", inputmode: "url", autocomplete: "url",
    autocapitalize: "off", spellcheck: "false", required: true });
  const label = h("input", { type: "text", id: "label", placeholder: "My shop", maxlength: 80 });
  const prov = h("select", { id: "prov" }, Object.entries(g.providers).map(([k, p]) => h("option", { value: k }, p.name)));
  const own = h("input", { type: "checkbox", id: "own" });
  const submit = h("button", { class: "btn big", type: "submit" }, "Start watching this website");
  render(h("a", { class: "back", href: "#/" }, "Back to websites"),
    h("h1", {}, "Add a website"),
    h("p", { class: "lead" }, "PatchPulse looks at your website from the outside, the same way any visitor would. It doesn't need your passwords and it doesn't change anything."),
    h("form", { class: "sheet", onsubmit: async (ev) => {
      ev.preventDefault(); err.textContent = ""; submit.disabled = true;
      try {
        const r = await api("POST", "/api/sites", { url: url.value, label: label.value, provider: prov.value, confirm_owner: own.checked });
        location.hash = `#/site/${r.id}`;
      } catch (e) {
        err.textContent = e.message; submit.disabled = false;
        if (e.code === "limit" && STATE.status.buy_url) err.append(" ", h("a", { href: STATE.status.buy_url, target: "_blank", rel: "noopener" }, "See plans"));
      }
    } },
      h("label", { for: "url" }, "Website address", h("span", { class: "hint" }, "Just the address, like mysite.com — the same thing you type into a browser.")), url,
      h("label", { for: "label" }, "Nickname (optional)", h("span", { class: "hint" }, "A name you'll recognize, like “My bakery”.")), label,
      h("label", { for: "prov" }, "Who hosts this website?", h("span", { class: "hint" }, "This lets PatchPulse give you step-by-step instructions for your host. Pick “I'm not sure” if you don't know.")), prov,
      h("label", { class: "check", for: "own" }, own, h("span", {}, "I own or manage this website, or I have permission to check it.")),
      err, h("div", { class: "row" }, submit)));
  url.focus();
}

// ---------- one website ----------
function supportMessage(site, asks, providerName) {
  const lines = [...new Set(asks.filter(Boolean))];
  return `Hello,\n\nI'm the owner of ${site.url}. A security check flagged ${lines.length > 1 ? "some things" : "something"} I need your help with:\n\n` +
    lines.map((a) => `- ${a}`).join("\n") +
    `\n\nCould you take care of ${lines.length > 1 ? "these" : "this"}, or tell me how? Please reply when it's done so I can re-check.\n\nThank you!`;
}

function fixSteps(f, prov, g) {
  const out = [];
  if (f.guide === "php_upgrade") {
    out.push(h("p", {}, f.fix));
    if (prov) out.push(h("h4", {}, `Steps for ${prov.name}`), h("ol", { class: "steps" }, prov.php.map((s) => h("li", {}, s))));
    out.push(h("p", { class: "muted small" }, g.topics.php_upgrade.safety));
  } else if (f.guide === "exposed_file") {
    out.push(h("p", {}, f.fix));
    if (prov) out.push(h("h4", {}, `Steps for ${prov.name}`), h("ol", { class: "steps" }, prov.files.map((s) => h("li", {}, s))));
  } else if (f.guide === "wordpress") {
    out.push(h("p", {}, f.fix));
    if (f.key === "wp:outdated" || f.key.startsWith("vuln:wordpress"))
      out.push(h("ol", { class: "steps" }, g.topics.wordpress.steps.map((s) => h("li", {}, s))));
  } else if (f.guide === "wp_plugin") {
    out.push(h("p", {}, f.fix), h("ol", { class: "steps" }, g.topics.wp_plugin.steps.map((s) => h("li", {}, s))));
  } else if (f.guide === "check_file") {
    out.push(h("p", {}, f.fix), h("p", {}, h("a", { href: "#php-helper" }, "Go to the exact PHP version helper")));
  } else {
    out.push(h("p", {}, f.fix));
    if (f.guide && g.topics[f.guide]) out.push(h("p", { class: "muted small" }, g.topics[f.guide].intro));
  }
  return out;
}

async function viewSite(id) {
  const [v, g] = await Promise.all([api("GET", `/api/sites/${id}`), guides()]);
  const site = v.site, scan = v.scan;
  const prov = g.providers[site.provider] || g.providers.unsure;
  const name = site.label || site.url.replace(/^https?:\/\//, "");
  const findings = (scan && scan.findings) || [];
  const open = findings.filter((f) => !f.dismissed);
  const handled = findings.filter((f) => f.dismissed);
  const busy = site.scanning || !scan;

  const groups = [
    ["Fix now", open.filter((f) => ["critical", "high"].includes(f.severity))],
    ["Fix soon", open.filter((f) => f.severity === "medium")],
    ["Good to know", open.filter((f) => ["low", "info"].includes(f.severity))],
  ];

  const rescan = h("button", { class: "btn no-print", type: "button", disabled: busy || !site.active, onclick: async () => {
    rescan.disabled = true;
    try { await api("POST", `/api/sites/${id}/scan`); announce("Checking now"); viewSite(id); }
    catch (e) { toast(e.message, true); rescan.disabled = false; } } }, busy ? "Checking…" : "Check now");

  const status = busy ? "pending" : site.last_status;
  let headline;
  if (busy) headline = "Checking this website…";
  else if (status === "down") headline = "We couldn't reach this website";
  else if (status === "error") headline = "The check couldn't finish";
  else if (status === "critical") headline = `${open.filter((f) => f.severity === "critical").length} urgent problem${open.filter((f) => f.severity === "critical").length === 1 ? "" : "s"} found`;
  else if (status === "warning") headline = "A few things need attention";
  else headline = "This website looks healthy";

  const facts = scan && scan.facts ? scan.facts : {};
  site._wp = !!facts.wordpress;
  const factList = h("dl", { class: "facts" },
    fact("PHP version", facts.php_version ? facts.php_version : "Hidden"),
    facts.wordpress ? fact("WordPress", facts.wordpress_version || "Yes (version hidden)") : null,
    facts.cert_days_left !== undefined && facts.cert_days_left !== null ? fact("Padlock certificate", facts.cert_days_left >= 0 ? `Valid ${facts.cert_days_left} more days` : "Expired") :
      fact("Secure (https)", facts.https ? "Yes" : scan ? "No" : "—"),
    fact("Last checked", ago(site.last_scan_at)),
    fact("Hosting", prov.name));

  const body = [
    h("a", { class: "back no-print", href: "#/" }, "Back to websites"),
    h("div", { class: "row" }, h("h1", { class: "m0" }, name), stateBadge(site.last_status, busy)),
    h("p", { class: "site-url" }, site.url),
    pulseLine(status),
    h("h2", { class: "mt0" }, headline),
    !site.active ? h("div", { class: "notice amber" }, h("p", {}, "This website isn't covered by your current plan, so it isn't being checked. Remove another website or upgrade.")) : null,
    busy ? h("p", { class: "lead" }, "This usually takes 10–30 seconds. You can leave this page — the check keeps running.") : null,
    scan && scan.error ? h("div", { class: "notice red" }, h("p", {}, scan.error)) : null,
    factList,
    scan && scan.reason === "new threat" ? h("div", { class: "notice" }, h("p", {},
      h("strong", {}, "Re-checked automatically. "), "A newly published threat matched software on this website, so PatchPulse checked it again right away.")) : null,
    h("div", { class: "row no-print my1" }, rescan,
      scan ? h("button", { class: "btn quiet", type: "button", onclick: () => window.print() }, "Print or save report") : null),
  ];

  const urgentAsks = open.filter((f) => ["critical", "high", "medium"].includes(f.severity)).map((f) => f.support_ask).filter(Boolean);
  if (!busy && urgentAsks.length) {
    const msg = supportMessage(site, urgentAsks, prov.name);
    body.push(h("div", { class: "notice" },
      h("p", {}, h("strong", {}, "Quickest fix: send this message to " + (site.provider === "unsure" ? "your hosting company" : prov.name) + ". "),
        "It covers every problem below. " + prov.support),
      h("div", { class: "message-box" }, msg),
      h("button", { class: "btn quiet no-print", type: "button", onclick: () => copy(msg) }, "Copy message")));
  }

  if (!busy) {
    for (const [title, list] of groups) {
      if (!list.length) continue;
      body.push(h("h2", { class: "group-h" }, title, h("span", { class: "muted small" }, `${list.length}`)));
      list.forEach((f, i) => body.push(findingCard(f, site, prov, g, i === 0 && title === "Fix now")));
    }
    if (scan && !open.length && !["down", "error"].includes(status))
      body.push(h("p", { class: "lead" }, "No problems found. PatchPulse will keep checking automatically and alert you if that changes."));
    if (handled.length) {
      body.push(h("h2", {}, "Marked as handled"),
        h("p", { class: "muted" }, "You told PatchPulse these are taken care of. They won't count toward the status or send alerts."));
      handled.forEach((f) => body.push(h("div", { class: "row mb1" },
        h("span", { class: "sev " + f.severity }, SEV[f.severity]), h("span", {}, f.title),
        h("button", { class: "btn quiet no-print", type: "button", onclick: async () => {
          await api("PATCH", `/api/sites/${id}`, { undismiss: f.key }); viewSite(id); } }, "Undo"))));
    }
  }

  // exact PHP version helper
  const ct = g.topics.check_file;
  const cfStatus = facts.check_file || "not set up";
  // software found on the site
  const soft = (facts.software || []);
  if (soft.length) {
    const RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    const productOf = (f) => {
      const k = f.key;
      if (k.startsWith("vuln:")) return k.split(":").slice(1, -2).join(":");
      if (k.startsWith("adv:") || k.startsWith("php:")) return "php";
      if (k.startsWith("wp:")) return "wordpress";
      if (k.startsWith("plugin:")) return "wp-plugin:" + k.split(":").slice(2).join(":");
      const m = k.match(/^(apache|nginx|drupal|joomla):/);
      return m ? m[1] : null;
    };
    const worst = {};
    for (const f of open) {
      const p = productOf(f);
      if (p && !f.key.startsWith("php:unknown") && (worst[p] === undefined || RANK[f.severity] < RANK[worst[p]])) worst[p] = f.severity;
    }
    const label = (i) => i.product === "php" ? "PHP" : i.product === "wordpress" ? "WordPress" : i.product === "apache" ? "Apache web server"
      : i.product === "nginx" ? "nginx web server" : i.product === "drupal" ? "Drupal" : i.product === "joomla" ? "Joomla"
      : i.product.startsWith("wp-plugin:") ? `Plugin: ${i.name || i.product.slice(10)}` : i.product;
    body.push(h("section", {},
      h("h2", {}, "Software we found"),
      h("p", { class: "muted" }, "PatchPulse checks each of these against new threats every hour."),
      h("table", { class: "soft" },
        h("thead", {}, h("tr", {}, h("th", { scope: "col" }, "Software"), h("th", { scope: "col" }, "Version"), h("th", { scope: "col" }, "Status"))),
        h("tbody", {}, soft.map((i) => h("tr", {},
          h("td", {}, label(i)),
          h("td", {}, i.version || "hidden"),
          h("td", {}, !i.version ? h("span", { class: "muted" }, "Version hidden")
            : ["critical", "high"].includes(worst[i.product]) ? h("span", { class: "state critical" }, "Fix needed")
            : worst[i.product] ? h("span", { class: "state warning" }, "Update available")
            : h("span", { class: "state ok" }, "No known issues"))))))));
  }

  // keep this site protected: switches the owner turns on once
  const pt = g.topics.protect;
  if (pt && scan) {
    const items = pt.items.filter((it) => !it.wordpress || facts.wordpress);
    const done = site.protect || {};
    const count = items.filter((it) => done[it.key]).length;
    body.push(h("section", { class: "protect" },
      h("h2", {}, pt.title),
      h("p", {}, pt.intro),
      h("p", { class: "muted" }, `${count} of ${items.length} done.`),
      items.map((it) => {
        const box = h("input", { type: "checkbox", id: `pr-${it.key}`, checked: !!done[it.key], onchange: async (ev) => {
          try { await api("PATCH", `/api/sites/${id}`, { protect: { [it.key]: ev.target.checked } }); viewSite(id); }
          catch (e) { toast(e.message, true); ev.target.checked = !ev.target.checked; } } });
        const l = ownerLink(it.link, site, prov);
        return h("div", { class: "protect-item" + (done[it.key] ? " done" : "") },
          h("label", { class: "check", for: `pr-${it.key}` }, box, h("strong", {}, it.title)),
          h("ol", { class: "steps" }, it.steps.map((x) => h("li", {}, x))),
          h("div", { class: "row no-print" }, linkButton(l),
            it.support_ask ? h("button", { class: "btn quiet", type: "button",
              onclick: () => copy(supportMessage(site, [it.support_ask], prov.name)) }, "Copy message for your host") : null),
          !l && it.link === "panel" ? h("p", { class: "muted small" },
            "Tip: set your hosting company in Website settings below to get a direct link to your control panel.") : null);
      })));
  }

  body.push(h("section", { id: "php-helper", class: "no-print" },
    h("h2", {}, ct.title),
    h("p", {}, ct.intro),
    h("p", {}, "Status: ", h("strong", {}, { "working": "working — PatchPulse can see your exact PHP version", "not found on website": "not uploaded yet", "not set up": "not uploaded yet" }[cfStatus] || cfStatus)),
    h("ol", { class: "steps" }, ct.steps.map((s) => h("li", {}, s))),
    h("p", { class: "muted small" }, ct.safety),
    h("div", { class: "row" },
      h("a", { class: "btn", href: `/api/sites/${id}/checkfile`, download: "patchpulse-check.php" }, "Download my check file"),
      h("button", { class: "btn quiet", type: "button", onclick: async () => {
        if (!confirm("Make a new secret key? The check file already on your website will stop working until you upload the new one.")) return;
        await api("POST", `/api/sites/${id}/checkfile/rotate`); toast("New key made. Download the file again and upload it."); } }, "Make a new key"))));

  // site settings
  const lbl = h("input", { type: "text", id: "s-label", value: site.label, maxlength: 80 });
  const provSel = h("select", { id: "s-prov" }, Object.entries(g.providers).map(([k, p]) =>
    h("option", { value: k, selected: k === site.provider }, p.name)));
  body.push(h("section", { class: "no-print" }, h("h2", {}, "Website settings"),
    h("label", { for: "s-label" }, "Nickname"), lbl,
    h("label", { for: "s-prov" }, "Hosting company"), provSel,
    h("div", { class: "row mt1" },
      h("button", { class: "btn", type: "button", onclick: async () => {
        await api("PATCH", `/api/sites/${id}`, { label: lbl.value, provider: provSel.value }); toast("Saved."); viewSite(id); } }, "Save changes"),
      h("button", { class: "btn danger", type: "button", onclick: async () => {
        if (!confirm(`Stop watching ${name}? Its history will be deleted.`)) return;
        await api("DELETE", `/api/sites/${id}`); toast("Website removed."); location.hash = "#/"; } }, "Remove this website"))));

  render(body);
  if (busy) STATE.pollTimer = setTimeout(() => location.hash === `#/site/${id}` && viewSite(id), 2500);
}

function fact(k, val) { return h("div", { class: "fact" }, h("dt", {}, k), h("dd", {}, val)); }

// Links that open the owner's OWN screens; PatchPulse never changes the site itself.
function ownerLink(kind, site, prov) {
  const base = site.url.replace(/\/$/, "");
  if (kind === "wp-updates") return { href: `${base}/wp-admin/update-core.php`, label: "Open WordPress updates" };
  if (kind === "wp-plugins") return { href: `${base}/wp-admin/plugins.php?plugin_status=upgrade`, label: "Open plugins that need updates" };
  if (kind === "wp-plugins-all") return { href: `${base}/wp-admin/plugins.php`, label: "Open WordPress plugins" };
  if (kind === "panel" && prov && prov.panel_url) return { href: prov.panel_url, label: `Open ${prov.panel || prov.name}` };
  return null;
}

function linkButton(l) {
  return l ? h("a", { class: "btn", href: l.href, target: "_blank", rel: "noopener noreferrer" }, l.label) : null;
}

function fixLinks(f, site, prov) {
  const k = f.key, g = f.guide;
  const kinds = [];
  if (g === "wordpress" || k.startsWith("vuln:wordpress") || k.startsWith("wp:")) kinds.push("wp-updates");
  if (g === "wp_plugin") kinds.push("wp-plugins");
  if (["php_upgrade", "server", "ssl", "exposed_file", "headers", "check_file", "cms", "integrity", "down"].includes(g)) kinds.push("panel");
  if (g === "integrity" && site._wp) kinds.push("wp-plugins-all");
  return kinds.map((x) => ownerLink(x, site, prov)).filter(Boolean);
}

function findingCard(f, site, prov, g, openFirst) {
  const parts = [h("h4", {}, "What this means"), ...paras(f.detail), h("h4", {}, "How to fix it"), ...fixSteps(f, prov, g)];
  const links = fixLinks(f, site, prov);
  if (links.length) parts.push(h("h4", {}, "Do it now"),
    h("p", { class: "muted small" }, "Opens your own screen in a new tab. You stay in control: PatchPulse never changes your website."),
    h("div", { class: "row no-print" }, links.map(linkButton)));
  if (f.support_ask) {
    const msg = supportMessage(site, [f.support_ask], prov.name);
    parts.push(h("h4", {}, "Or ask your host to do it"), h("div", { class: "message-box" }, msg),
      h("button", { class: "btn quiet no-print", type: "button", onclick: () => copy(msg) }, "Copy message"));
  }
  if (f.references && f.references.length)
    parts.push(h("p", { class: "refs" }, "Sources: ", f.references.map((r, i) => [i ? ", " : "", h("a", { href: r, target: "_blank", rel: "noopener noreferrer" }, r.replace(/^https:\/\//, "").split("/")[0])])));
  parts.push(h("div", { class: "row no-print mt1" },
    h("button", { class: "btn quiet", type: "button", onclick: async () => {
      if (!confirm("Mark this as handled? Only do this if your host confirmed it's fixed, or you're sure it doesn't apply. PatchPulse will stop counting it.")) return;
      await api("PATCH", `/api/sites/${site.id}`, { dismiss: f.key }); toast("Marked as handled."); viewSite(site.id);
    } }, f.can_dismiss ? "My host confirmed the fix" : "Mark as handled")));
  return h("details", { class: "finding " + f.severity, open: openFirst },
    h("summary", {}, h("span", { class: "sev " + f.severity }, SEV[f.severity]), h("span", {}, f.title)),
    h("div", { class: "finding-body" }, parts));
}

// ---------- alerts ----------
async function viewAlerts() {
  const st = await api("GET", "/api/settings");
  const a = st.alerts;
  const hadTopic = !!a.ntfy.topic;
  const ABC = "abcdefghjkmnpqrstuvwxyz23456789";
  if (!a.ntfy.topic) a.ntfy.topic = "patchpulse-" + Array.from(crypto.getRandomValues(new Uint8Array(12)), (b) => ABC[b % ABC.length]).join("");
  const inp = (id, val, type = "text", extra = {}) => h("input", { id, type, value: val ?? "", autocomplete: "off", ...extra });
  const level = h("select", { id: "lvl" },
    h("option", { value: "critical", selected: a.min_severity === "critical" }, "Only urgent problems"),
    h("option", { value: "high", selected: a.min_severity === "high" }, "Urgent and important problems (recommended)"),
    h("option", { value: "medium", selected: a.min_severity === "medium" }, "Everything except minor tips"),
    h("option", { value: "low", selected: a.min_severity === "low" }, "Everything"));
  const resolved = h("input", { type: "checkbox", id: "resolved", checked: a.notify_resolved });

  const nOn = h("input", { type: "checkbox", id: "n-on", checked: a.ntfy.enabled });
  const nTopic = inp("n-topic", a.ntfy.topic);
  const nServer = inp("n-server", a.ntfy.server);
  const eOn = h("input", { type: "checkbox", id: "e-on", checked: a.email.enabled });
  const e = { host: inp("e-host", a.email.smtp_host), port: inp("e-port", a.email.smtp_port, "number"),
    user: inp("e-user", a.email.username), pass: inp("e-pass", a.email.password, "password"),
    from: inp("e-from", a.email.from_addr, "email"), to: inp("e-to", a.email.to_addr, "email") };
  const eSec = h("select", { id: "e-sec" }, ["starttls", "ssl", "none"].map((x) =>
    h("option", { value: x, selected: a.email.security === x }, { starttls: "STARTTLS (port 587 — most common)", ssl: "SSL/TLS (port 465)", none: "None (not recommended)" }[x])));
  const wOn = h("input", { type: "checkbox", id: "w-on", checked: a.webhook.enabled });
  const wUrl = inp("w-url", a.webhook.url, "url", { placeholder: "https://hooks.slack.com/… or https://discord.com/api/webhooks/…" });

  const collect = () => ({ alerts: {
    min_severity: level.value, notify_resolved: resolved.checked,
    ntfy: { enabled: nOn.checked, topic: nTopic.value.trim(), server: nServer.value.trim() || "https://ntfy.sh" },
    email: { enabled: eOn.checked, smtp_host: e.host.value.trim(), smtp_port: +e.port.value || 587, security: eSec.value,
      username: e.user.value.trim(), password: e.pass.value, from_addr: e.from.value.trim() || e.user.value.trim(), to_addr: e.to.value.trim() || e.user.value.trim() },
    webhook: { enabled: wOn.checked, url: wUrl.value.trim() } } });
  const save = async (quiet) => { await api("PUT", "/api/settings", collect()); if (!quiet) toast("Alert settings saved."); };
  const test = (channel) => async (ev) => {
    const b = ev.target; b.disabled = true; b.textContent = "Sending…";
    try { await save(true); const r = await api("POST", "/api/alerts/test", { channel });
      r.ok ? toast("Test sent. Check your " + { ntfy: "phone", email: "inbox (and spam folder)", webhook: "chat" }[channel] + ".") : toast(r.error, true); }
    catch (err) { toast(err.message, true); }
    b.disabled = false; b.textContent = "Send a test";
  };
  const preset = (hst, port, sec) => () => { e.host.value = hst; e.port.value = port; eSec.value = sec; if (!e.from.value) e.from.value = e.user.value; };

  render(h("h1", {}, "Alerts"),
    h("p", { class: "lead" }, "Choose how PatchPulse reaches you when a website needs attention. You can turn on more than one."),
    h("label", { for: "lvl" }, "Alert me about"), level,
    h("label", { class: "check", for: "resolved" }, resolved, h("span", {}, "Also tell me when a problem is fixed")),

    h("section", { class: "channel" },
      h("div", { class: "channel-h" }, h("h2", {}, "Phone notifications"), h("label", { class: "switch", for: "n-on" }, nOn, "On")),
      h("p", {}, "The easiest option. Uses the free ntfy app — no account needed."),
      h("ol", { class: "steps" },
        h("li", {}, "On your phone, install the free app called “ntfy” from the App Store or Google Play."),
        h("li", {}, "Open it, tap the + button, and type this topic name exactly: ", h("strong", {}, a.ntfy.topic)),
        h("li", {}, "Tick “On” above, then press “Send a test” below.")),
      h("p", { class: "muted small" }, "Keep the topic name private: anyone who knows it can read these alerts. The long random name protects you."),
      h("label", { for: "n-topic" }, "Topic name"), nTopic,
      h("details", {}, h("summary", {}, "Advanced: use your own ntfy server"), h("label", { for: "n-server" }, "Server address"), nServer),
      h("div", { class: "row mt1" }, h("button", { class: "btn quiet", type: "button", onclick: test("ntfy") }, "Send a test"))),

    h("section", { class: "channel" },
      h("div", { class: "channel-h" }, h("h2", {}, "Email"), h("label", { class: "switch", for: "e-on" }, eOn, "On")),
      h("p", {}, "Pick your email provider to fill in the server details, then add your login."),
      h("div", { class: "presets" },
        h("button", { class: "btn quiet", type: "button", onclick: preset("smtp.gmail.com", 587, "starttls") }, "Gmail"),
        h("button", { class: "btn quiet", type: "button", onclick: preset("smtp-mail.outlook.com", 587, "starttls") }, "Outlook / Hotmail"),
        h("button", { class: "btn quiet", type: "button", onclick: preset("smtp.mail.yahoo.com", 465, "ssl") }, "Yahoo"),
        h("button", { class: "btn quiet", type: "button", onclick: preset("smtp.mail.me.com", 587, "starttls") }, "iCloud")),
      h("p", { class: "muted small" }, "Gmail, Yahoo and iCloud need an “app password” (a special password just for apps) instead of your normal password. Search “app password” in your email account's security settings to make one."),
      h("label", { for: "e-user" }, "Your email address (login)"), e.user,
      h("label", { for: "e-pass" }, "Password or app password"), e.pass,
      h("label", { for: "e-to" }, "Send alerts to"), e.to,
      h("details", {}, h("summary", {}, "Server details"),
        h("label", { for: "e-host" }, "Mail server"), e.host, h("label", { for: "e-port" }, "Port"), e.port,
        h("label", { for: "e-sec" }, "Security"), eSec, h("label", { for: "e-from" }, "Send from address"), e.from),
      h("div", { class: "row mt1" }, h("button", { class: "btn quiet", type: "button", onclick: test("email") }, "Send a test"))),

    h("section", { class: "channel" },
      h("div", { class: "channel-h" }, h("h2", {}, "Team chat"), h("label", { class: "switch", for: "w-on" }, wOn, "On")),
      h("p", {}, "Post alerts into Slack, Discord, Microsoft Teams, or any system that accepts a webhook (for example Zapier)."),
      h("label", { for: "w-url" }, "Webhook address", h("span", { class: "hint" }, "Your chat app gives you this when you add an “incoming webhook”.")), wUrl,
      h("div", { class: "row mt1" }, h("button", { class: "btn quiet", type: "button", onclick: test("webhook") }, "Send a test"))),

    h("div", { class: "row mt3" }, h("button", { class: "btn big", type: "button", onclick: () => save(false).catch((er) => toast(er.message, true)) }, "Save alert settings")));
  if (!hadTopic) save(true).catch(() => {}); // remember the generated topic
}

// ---------- settings ----------
async function viewSettings() {
  const st = await api("GET", "/api/settings");
  const freq = h("select", { id: "freq" }, [[1, "Every hour"], [3, "Every 3 hours (recommended)"], [6, "Every 6 hours"], [12, "Twice a day"], [24, "Once a day"]]
    .map(([v, t]) => h("option", { value: v, selected: Math.abs(st.scan_interval_hours - v) < 0.01 }, t)));
  const lic = h("textarea", { id: "lic", placeholder: "PP1-…", spellcheck: "false" });
  const keyOut = h("div");
  const cur = h("input", { type: "password", id: "pw-cur", autocomplete: "current-password" });
  const nw = h("input", { type: "password", id: "pw-new", autocomplete: "new-password" });
  const rulesUrl = h("input", { type: "url", id: "rules-url", value: st.rules_url, placeholder: "https://…" });
  const pub = h("input", { type: "url", id: "pub", value: st.public_url });
  const priv = h("input", { type: "checkbox", id: "priv", checked: st.allow_private });
  const L = st.license;
  const hunt = h("select", { id: "hunt" }, [[30, "Every 30 minutes"], [60, "Every hour (recommended)"], [180, "Every 3 hours"], [720, "Twice a day"]]
    .map(([v, t]) => h("option", { value: v, selected: Math.abs(st.hunt_minutes - v) < 1 }, t)));
  const nvd = h("input", { type: "password", id: "nvd", autocomplete: "off", value: st.has_nvd_key ? "********" : "" });

  render(h("h1", {}, "Settings"),
    h("h2", {}, "How often to re-check websites"),
    h("p", { class: "muted small" }, "This is a full re-check of each website. Separately, a website is re-checked immediately whenever threat hunting finds something that matches it."),
    h("label", { for: "freq" }, "Re-check every website"), freq,
    h("div", { class: "row mt1" }, h("button", { class: "btn", type: "button", onclick: async () => {
      await api("PUT", "/api/settings", { scan_interval_hours: +freq.value }); toast("Saved."); } }, "Save")),
    h("p", { class: "muted small" }, "PatchPulse checks only while it's running. On a home computer, leave it open (it uses almost no power). To check around the clock, run it on an always-on computer or server — see Help."),

    h("h2", {}, "Your license"),
    L ? h("p", {}, h("strong", {}, `${L.plan[0].toUpperCase() + L.plan.slice(1)} plan`), ` — licensed to ${L.name}. `,
      st.site_limit === null ? "Unlimited websites." : `Covers ${st.site_limit} websites.`,
      L.expires ? ` Renews ${L.expires}.` : "",
      L.activated_until ? ` Confirmed online until ${L.activated_until}.` : "") :
      h("p", {}, h("strong", {}, "Not active. "), st.license_message || "Enter your license key to start monitoring.",
        STATE.status.buy_url ? [" ", h("a", { href: STATE.status.buy_url, target: "_blank", rel: "noopener" }, "Buy a license")] : null),
    h("label", { for: "lic" }, L ? "Replace license key" : "License key", h("span", { class: "hint" }, "Paste the whole key from your purchase email.")), lic,
    h("div", { class: "row mt1" },
      h("button", { class: "btn", type: "button", onclick: async (ev) => {
        ev.target.disabled = true;
        try { await api("POST", "/api/license", { key: lic.value }); STATE.status = null; toast("License activated. Thank you!"); await route(); }
        catch (e) { toast(e.message, true); ev.target.disabled = false; } } }, "Activate license"),
      st.online_activation && L ? h("button", { class: "btn quiet", type: "button", onclick: async () => {
        await api("POST", "/api/license/refresh"); STATE.status = null; toast("License checked."); viewSettings(); } }, "Check license now") : null,
      L ? h("button", { class: "btn danger", type: "button", onclick: async () => {
        if (!confirm("Remove the license from this computer? Monitoring stops here, and you can activate it on another computer.")) return;
        await api("DELETE", "/api/license"); STATE.status = null; toast("License removed from this computer."); route(); } }, "Remove license from this computer") : null),

    h("h2", {}, "Threat hunting"),
    h("p", {}, "PatchPulse searches official threat sources for new flaws in the software your websites run, and re-checks a website the moment one matches. Sources: the U.S. government's list of actively exploited flaws (CISA), the NIST National Vulnerability Database, endoflife.date and WordPress.org."),
    h("label", { for: "hunt" }, "Hunt for new threats"), hunt,
    h("label", { for: "nvd" }, "NIST database key (optional)", h("span", { class: "hint" }, "A free key from nvd.nist.gov makes hunting about 10 times faster. Leave empty if you don't have one.")), nvd,
    h("div", { class: "row mt1" },
      h("button", { class: "btn", type: "button", onclick: async () => {
        try { await api("PUT", "/api/settings", { hunt_minutes: +hunt.value, nvd_api_key: nvd.value }); toast("Saved."); }
        catch (e) { toast(e.message, true); } } }, "Save"),
      h("button", { class: "btn quiet", type: "button", onclick: async (ev) => {
        ev.target.disabled = true;
        try { await api("POST", "/api/intel/hunt"); toast("Threat hunt started. Results appear on the Websites page."); }
        catch (e) { toast(e.message, true); }
        ev.target.disabled = false; } }, "Hunt now")),
    h("p", { class: "muted small" }, `Last hunt: ${ago(st.intel.last_hunt)}. Flaws matched to website software: ${(st.intel.tracked_flaws || 0).toLocaleString()}. Expert advisories version ${st.rules_version}.`),

    h("h2", {}, "Password"),
    h("label", { for: "pw-cur" }, "Current password"), cur,
    h("label", { for: "pw-new" }, "New password (at least 8 characters)"), nw,
    h("div", { class: "row mt1" }, h("button", { class: "btn quiet", type: "button", onclick: async () => {
      try { await api("POST", "/api/password", { current: cur.value, new: nw.value }); cur.value = nw.value = ""; toast("Password changed."); }
      catch (e) { toast(e.message, true); } } }, "Change password"),
      h("button", { class: "btn quiet", type: "button", onclick: async () => { await api("POST", "/api/logout"); STATE.status = null; route(); } }, "Sign out")),

    h("h2", {}, "Connect other software (API)"),
    h("p", {}, "For developers and businesses: an API key lets scripts and tools read results and start checks. See Help for examples."),
    h("p", {}, st.has_api_token ? "An API key is active." : "No API key yet."),
    h("div", { class: "row" },
      h("button", { class: "btn quiet", type: "button", onclick: async () => {
        if (st.has_api_token && !confirm("Make a new key? The old key will stop working.")) return;
        const r = await api("POST", "/api/token");
        keyOut.replaceChildren(h("p", {}, h("strong", {}, "Copy this key now — it won't be shown again:")), h("div", { class: "key-reveal" }, r.token),
          h("button", { class: "btn quiet", type: "button", onclick: () => copy(r.token) }, "Copy key")); } }, st.has_api_token ? "Replace API key" : "Create API key"),
      st.has_api_token ? h("button", { class: "btn danger", type: "button", onclick: async () => {
        await api("DELETE", "/api/token"); toast("API key turned off."); viewSettings(); } }, "Turn off API key") : null),
    keyOut,

    h("h2", {}, "Your data"),
    h("p", {}, "Everything PatchPulse knows is stored on this computer in: ", h("span", { class: "code" }, st.data_dir)),
    h("a", { class: "btn quiet", href: "/api/export", download: "patchpulse-export.json" }, "Download all results"),

    h("details", { class: "mt3" }, h("summary", {}, h("strong", {}, "Advanced settings")),
      h("label", { for: "pub" }, "PatchPulse address used in alert links"), pub,
      h("label", { for: "rules-url" }, "Threat list update address", h("span", { class: "hint" }, "Leave as is unless your provider tells you otherwise.")), rulesUrl,
      h("label", { class: "check", for: "priv" }, priv, h("span", {}, "Allow checking private network addresses (only for checking sites inside your own office network)")),
      h("div", { class: "row" }, h("button", { class: "btn quiet", type: "button", onclick: async () => {
        try { await api("PUT", "/api/settings", { public_url: pub.value, rules_url: rulesUrl.value, allow_private: priv.checked }); toast("Saved."); }
        catch (e) { toast(e.message, true); } } }, "Save advanced settings"))),
    h("p", { class: "muted small mt3" }, `PatchPulse ${st.version}`));
}

// ---------- help ----------
async function viewHelp() {
  const origin = location.origin;
  const q = (t, ...a) => [h("h3", {}, t), ...a];
  render(h("h1", {}, "Help"),
    h("p", { class: "lead" }, "Short answers to the questions people ask most."),
    ...q("What does PatchPulse actually check?",
      h("p", {}, "It visits your website like a normal visitor and makes a list of the software it runs: PHP, WordPress and its plugins, the web server, Drupal or Joomla. It checks each one against known flaws, support end dates and missing updates. It also looks for private files left public by accident (like passwords or database backups), padlock certificate problems, new outside code appearing on your homepage, and whether your site is down.")),
    ...q("How does PatchPulse keep up with new threats?",
      h("p", {}, "Every hour it hunts for new flaws in official sources: the U.S. Cybersecurity and Infrastructure Security Agency's list of flaws being used in real attacks, the NIST National Vulnerability Database, endoflife.date and WordPress.org. When a new flaw matches software on one of your websites, that website is re-checked right away and you're alerted."),
      h("p", {}, "No tool can know about a flaw before it's made public. PatchPulse's job is to tell you soon after it is (it checks every hour), and to warn you early about software that's out of date or about to lose support.")),
    ...q("Where does the threat information come from?",
      h("p", {}, "CISA Known Exploited Vulnerabilities catalog (public domain). PatchPulse is an independent product and is not endorsed by CISA or DHS."),
      h("p", {}, "NIST National Vulnerability Database. This product uses data from the NVD API but is not endorsed or certified by the NVD."),
      h("p", {}, "CVE Program records, used when the NVD can't be reached. CVE is a registered trademark of The MITRE Corporation."),
      h("p", {}, "endoflife.date (MIT License) and the WordPress.org plugin directory. Full notices are in THIRD-PARTY-NOTICES.txt.")),
    ...q("Can PatchPulse fix things for me?",
      h("p", {}, "It guides you instead of changing your site. Each problem has a 'Do it now' button that opens the right screen in your own WordPress dashboard or hosting control panel, with numbered steps. The 'Keep this website protected' checklist on each website's page helps you switch on automatic updates, backups and your host's firewall once, so many future fixes happen automatically.")),
    ...q("Does it change or attack my website?",
      h("p", {}, "No. It only reads public pages, the same way a browser or search engine does. It never logs in, never changes anything, and never tries to break in.")),
    ...q("Why does it say my PHP version is hidden?",
      h("p", {}, "Many hosts hide it, which is good security. To let PatchPulse see it anyway, use the “Get your exact PHP version” helper on your website's page — it's one small file you upload.")),
    ...q("Does PatchPulse need to stay open?",
      h("p", {}, "It checks while it's running. On a laptop that's asleep it pauses, then catches up when you open it again. For round-the-clock watching, run it on a computer that stays on, or on a server using Docker (instructions are in the README file that came with PatchPulse).")),
    ...q("Is my information private?",
      h("p", {}, "Yes. Your list of websites, results and alert settings stay on your own computer. PatchPulse only contacts your websites, wordpress.org (to learn the newest WordPress version), the threat list address, and the alert services you turn on.")),
    ...q("I forgot my password",
      h("p", {}, "Close PatchPulse. Then start it once using the “Reset password” shortcut that came with it (or run ", h("span", { class: "code" }, "patchpulse reset-password"), "). Open PatchPulse again and choose a new password. Your websites and settings are kept.")),
    STATE.status.support_email ? q("Still stuck?", h("p", {}, "Email ", h("a", { href: "mailto:" + STATE.status.support_email }, STATE.status.support_email), ".")) : [],

    h("h2", {}, "For developers: the API"),
    h("p", {}, "Create an API key in Settings, then:"),
    h("pre", { class: "api" },
`# List websites and their status
curl -H "Authorization: Bearer YOUR_KEY" ${origin}/api/sites

# Add a website (it is checked immediately)
curl -X POST -H "Authorization: Bearer YOUR_KEY" -H "Content-Type: application/json" \\
  -d '{"url":"example.com","confirm_owner":true,"provider":"cpanel"}' ${origin}/api/sites

# Full results for website 1
curl -H "Authorization: Bearer YOUR_KEY" ${origin}/api/sites/1

# Re-check everything now
curl -X POST -H "Authorization: Bearer YOUR_KEY" ${origin}/api/sites/scan

# One-off check without saving (great for CI pipelines)
curl -X POST -H "Authorization: Bearer YOUR_KEY" -H "Content-Type: application/json" \\
  -d '{"url":"example.com"}' ${origin}/api/check`),
    h("p", { class: "muted small" }, "Alerts can also go to any webhook as JSON with the fields app, title, message, level, url, site and findings — handy for Zapier, n8n or your own systems. The command line also works: ",
      h("span", { class: "code" }, "patchpulse scan example.com --json"), " (exit code 2 = urgent, 1 = needs attention, 0 = healthy)."));
}
