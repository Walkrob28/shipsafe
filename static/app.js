const $ = s => document.querySelector(s);
const LOAD_MSGS = [
  "Loading your app the way a visitor would…",
  "Reading your app's code for exposed keys…",
  "Checking if your database is locked down…",
  "Looking for downloadable secret files…",
  "Writing your report in plain English…",
];

function setLoading(on) {
  $("#loading").hidden = !on;
  if (on) {
    $("#results").hidden = true;
    let i = 0;
    $("#loadingMsg").textContent = LOAD_MSGS[0];
    setLoading._t = setInterval(() => {
      i = (i + 1) % LOAD_MSGS.length;
      $("#loadingMsg").textContent = LOAD_MSGS[i];
    }, 1600);
  } else {
    clearInterval(setLoading._t);
  }
}

const HEADLINES = {
  A: "You're in good shape.",
  B: "Almost there — a couple of easy wins.",
  C: "Some gaps worth closing before you grow.",
  D: "Serious holes — fix these before you share this app.",
  F: "Stop — your app is leaking. Fix this now.",
};

async function scan() {
  const url = $("#url").value.trim();
  const consent = $("#consent").checked;
  $("#err").hidden = true;
  if (!url) { showErr("Enter your app's URL first."); return; }
  if (!consent) { showErr("Please confirm you own this app."); return; }

  $("#scanBtn").disabled = true;
  setLoading(true);
  try {
    const res = await fetch("/api/scan", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url, consent }),
    });
    const data = await res.json();
    setLoading(false);
    if (data.error) { showErr(data.error); return; }
    render(data);
  } catch (e) {
    setLoading(false);
    showErr("Something went wrong reaching the scanner. Try again.");
  } finally {
    $("#scanBtn").disabled = false;
  }
}

function showErr(msg) { const e = $("#err"); e.textContent = msg; e.hidden = false; }

function render(data) {
  const g = data.summary.grade;
  const grade = $("#grade");
  grade.textContent = g;
  grade.className = "grade " + g;
  $("#scoreHeadline").textContent = HEADLINES[g] || "";
  $("#scoreUrl").textContent = data.url;

  const box = $("#findings");
  box.innerHTML = "";
  if (!data.findings.length) {
    box.innerHTML = '<div class="allclear">✅ No exposed secrets, open databases, or leaked files found. Nice — you shipped clean.</div>';
  }
  for (const f of data.findings) {
    const el = document.createElement("div");
    el.className = "card " + f.severity;
    el.innerHTML = `
      <div class="card-head">
        <span class="badge ${f.severity}">${f.severity}</span>
        <h3>${esc(f.title)}</h3>
      </div>
      <p class="detail">${esc(f.detail)}</p>
      <div class="fix"><b>How to fix:</b> ${esc(f.fix)}</div>
      ${f.evidence ? `<div class="evidence">found: ${esc(f.evidence)}</div>` : ""}`;
    box.appendChild(el);
  }
  setupShare(g);
  $("#results").hidden = false;
  $("#results").scrollIntoView({ behavior: "smooth", block: "start" });
}

const esc = s => String(s).replace(/[&<>"']/g, m =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[m]));


function setupShare(grade) {
  const origin = window.location.origin;
  const badgeUrl = `${origin}/badge/${grade}`;
  document.querySelector("#badgeImg").src = badgeUrl;

  const proud = ["A", "B"].includes(grade);
  const text = proud
    ? `My app just passed ShipSafe's security scan — grade ${grade}. Scan yours free before you ship:`
    : `ShipSafe caught security holes in my app before I launched it. Check yours free in 30s:`;

  document.querySelector("#shareX").onclick = () => {
    const u = `https://twitter.com/intent/tweet?text=${encodeURIComponent(text)}&url=${encodeURIComponent(origin)}`;
    window.open(u, "_blank", "noopener,width=560,height=480");
  };
  document.querySelector("#copyLink").onclick = e => copyTxt(origin, e.target, "Copy link");
  document.querySelector("#copyBadge").onclick = e =>
    copyTxt(`[![ShipSafe](${badgeUrl})](${origin})`, e.target, "Copy README badge");
}

function copyTxt(txt, btn, label) {
  navigator.clipboard.writeText(txt).then(() => {
    btn.textContent = "Copied";
    btn.classList.add("copied");
    setTimeout(() => { btn.textContent = label; btn.classList.remove("copied"); }, 1600);
  }).catch(() => {});
}

$("#scanBtn").onclick = scan;
$("#url").addEventListener("keydown", e => { if (e.key === "Enter") scan(); });
$("#rescanBtn").onclick = () => {
  $("#results").hidden = true;
  $("#url").value = ""; $("#url").focus();
  window.scrollTo({ top: 0, behavior: "smooth" });
};
