// Injected into the target page (world: MAIN). Returns serializable raw data.
// Defensive + read-only: only GETs resources a normal visitor could already load.
async function shipsafeCollect() {
  const origin = location.origin;
  const out = { html: "", scripts: "", headers: {}, exposedFiles: [], supabase: null, error: null };
  try {
    out.html = document.documentElement.outerHTML.slice(0, 3_000_000);

    // inline + same-origin external scripts (where hardcoded keys hide)
    const parts = [];
    for (const s of document.querySelectorAll("script")) {
      if (s.src) {
        try {
          const u = new URL(s.src, origin);
          if (u.origin === origin) {
            const r = await fetch(u.href);
            if (r.ok) parts.push((await r.text()).slice(0, 3_000_000));
          }
        } catch {}
      } else if (s.textContent) {
        parts.push(s.textContent);
      }
    }
    out.scripts = parts.join("\n");

    // response headers of the page itself
    try {
      const r = await fetch(origin + "/", { method: "GET" });
      for (const [k, v] of r.headers.entries()) out.headers[k.toLowerCase()] = v;
    } catch {}

    // downloadable secret files
    for (const p of ["/.env", "/.env.local", "/.git/config"]) {
      try {
        const r = await fetch(origin + p, { method: "GET" });
        if (r.ok) {
          const t = (await r.text()).slice(0, 400);
          if (t.length > 5 && !/<html/i.test(t.slice(0, 200))) out.exposedFiles.push(p);
        }
      } catch {}
    }

    // Supabase: is a table readable with no login? (RLS off = classic leak)
    const blob = out.html + out.scripts;
    const m = blob.match(/https:\/\/([a-z0-9]{20})\.supabase\.co/);
    const key = blob.match(/eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+/);
    if (m && key) {
      const sb = `https://${m[1]}.supabase.co`;
      const tables = ["users","profiles","customers","orders","posts","messages","todos","tasks","notes","products","subscribers","waitlist","contacts","leads"];
      for (const t of tables) {
        try {
          const r = await fetch(`${sb}/rest/v1/${t}?select=*&limit=1`, { headers: { apikey: key[0], authorization: "Bearer " + key[0] } });
          if (r.ok) {
            const body = await r.json();
            if (Array.isArray(body) && body.length > 0) { out.supabase = t; break; }
          }
        } catch {}
      }
    }
  } catch (e) {
    out.error = String(e && e.message || e);
  }
  return out;
}

/* ShipSafe popup: grabs the active tab, injects the collector, runs the pure
   analyzer on the returned data, renders the report. */
const $ = s => document.querySelector(s);
const HEADLINES = {
  A: "You're in good shape.",
  B: "Almost there — a couple of easy wins.",
  C: "Some gaps worth closing before you grow.",
  D: "Serious holes — fix these before sharing this app.",
  F: "Your app is leaking. Fix this now.",
};
let activeTab = null;

async function init() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  activeTab = tab;
  const url = tab?.url || "";
  if (!/^https?:\/\//.test(url)) {
    $("#scanBtn").disabled = true;
    showErr("Open the app you want to check in this tab first, then click Scan. (This page can't be scanned.)");
    return;
  }
  try { $("#target").textContent = new URL(url).host; } catch { $("#target").textContent = url; }
}
function showErr(msg){ const e=$("#err"); e.textContent=msg; e.hidden=false; }

async function scan() {
  $("#err").hidden = true; $("#result").hidden = true;
  $("#scanBtn").disabled = true; $("#loading").hidden = false;
  try {
    const [inj] = await chrome.scripting.executeScript({
      target: { tabId: activeTab.id }, world: "MAIN", func: shipsafeCollect,
    });
    const data = inj?.result;
    if (!data) throw new Error("Could not read this page.");
    const { findings, summary } = analyze(data);
    render(findings, summary);
  } catch (e) {
    showErr("Couldn't scan this page (" + (e.message || e) + "). Some sites block extensions from reading them.");
  } finally {
    $("#loading").hidden = true; $("#scanBtn").disabled = false;
  }
}

function render(findings, summary) {
  const g = summary.grade;
  const grade = $("#grade"); grade.textContent = g; grade.className = "grade " + g;
  $("#headline").textContent = HEADLINES[g] || "";
  const box = $("#findings"); box.innerHTML = "";
  if (!findings.length) box.innerHTML = '<div class="allclear">No exposed secrets, open databases, or leaked files found. Nice — you shipped clean.</div>';
  for (const f of findings) {
    const el = document.createElement("div");
    el.className = "card " + f.severity;
    el.innerHTML = `<span class="badge ${f.severity}">${f.severity}</span>` +
      `<h3>${esc(f.title)}</h3><div class="d">${esc(f.detail)}</div>` +
      `<div class="fix"><b>Fix:</b> ${esc(f.fix)}</div>`;
    box.appendChild(el);
  }
  $("#result").hidden = false;
}
const esc = s => String(s).replace(/[&<>"']/g, m => ({ "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;" }[m]));
$("#scanBtn").onclick = scan;
$("#rescan").onclick = scan;
init();
