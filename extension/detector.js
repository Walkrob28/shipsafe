// ShipSafe detection engine — browser port of detector.py.
// Pure functions, no network. The scanner collects page text/headers and
// passes them in here. Only-what-a-visitor-can-see, defensive, read-only.

const SECRET_RULES = [
  ["openai", /sk-(?:proj-)?[A-Za-z0-9_\-]{20,}/g, "Your OpenAI key is visible to anyone",
   "This key is sitting in your app's code, which every visitor can read. Someone can copy it and run up thousands of dollars in charges on your account.",
   "Delete the key from your code, move it to a server-side environment variable (never in front-end code), then rotate it in your OpenAI dashboard."],
  ["anthropic", /sk-ant-[A-Za-z0-9_\-]{20,}/g, "Your Anthropic (Claude) key is exposed",
   "Your Claude API key is readable in your app's code. Anyone can take it and bill your account.",
   "Move the key to a server-side environment variable, remove it from front-end code, and rotate it in the Anthropic Console."],
  ["aws", /AKIA[0-9A-Z]{16}/g, "Your AWS access key is exposed",
   "An AWS key in your code can let an attacker into your cloud account — spin up servers, read your files, or delete everything.",
   "Deactivate this key in AWS IAM immediately, create a new one, and keep it server-side only."],
  ["stripe_secret", /(?:sk|rk)_live_[0-9a-zA-Z]{20,}/g, "Your Stripe SECRET key is exposed — this is an emergency",
   "This is your live Stripe secret key. With it, someone can issue refunds, read customer payment data, and move money. It must never be in front-end code.",
   "Roll (revoke) this key in the Stripe Dashboard right now, then use the new secret key only on your server. The browser should only ever see your publishable (pk_) key."],
  ["github", /gh[pousr]_[A-Za-z0-9]{36,}/g, "Your GitHub token is exposed",
   "This token can give someone access to your code repositories — including private ones.",
   "Revoke it in GitHub → Settings → Developer settings → Tokens, then generate a new one and keep it server-side."],
  ["google_api", /AIza[0-9A-Za-z_\-]{35}/g, "A Google API key is visible in your app",
   "A Google/Firebase API key is in your code. Without restrictions it can be abused to run up billing on your Google account.",
   "In Google Cloud Console, restrict this key to your domain and only the APIs you use. Rotate it if it's sensitive."],
  ["sendgrid", /SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}/g, "Your SendGrid email key is exposed",
   "Someone can use this to send email as you — great for spammers and phishing under your name.",
   "Delete this key in SendGrid, create a new one, and send email only from your server."],
  ["private_key", /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g, "A private key is embedded in your app",
   "A cryptographic private key is exposed. Depending on what it's for, this can hand over your servers, signing ability, or encrypted data.",
   "Treat it as compromised: generate a new key pair, replace it everywhere, and never ship private keys in front-end code."],
];

function redact(s) {
  s = String(s).trim();
  return s.length <= 12 ? s.slice(0, 4) + "…" : s.slice(0, 6) + "…" + s.slice(-4);
}

function decodeJwtRole(tok) {
  try {
    let p = tok.split(".")[1].replace(/-/g, "+").replace(/_/g, "/");
    while (p.length % 4) p += "=";
    return JSON.parse(atob(p)).role || null;
  } catch { return null; }
}

function scanSecrets(text) {
  const out = [], seen = new Set();
  for (const [name, rx, title, detail, fix] of SECRET_RULES) {
    for (const m of text.matchAll(rx)) {
      const val = m[0], key = name + ":" + val.slice(0, 16);
      if (seen.has(key)) continue;
      seen.add(key);
      out.push({ id: "secret_" + name, severity: "critical", title, detail, fix, evidence: redact(val) });
    }
  }
  for (const m of text.matchAll(/eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+/g)) {
    const tok = m[0];
    if (decodeJwtRole(tok) === "service_role" && !seen.has("srv:" + tok.slice(0, 16))) {
      seen.add("srv:" + tok.slice(0, 16));
      out.push({ id: "secret_supabase_service_role", severity: "critical",
        title: "Your Supabase admin key is exposed — this bypasses all security",
        detail: "Your app ships the Supabase service_role key. This key ignores every access rule you set — anyone who finds it can read, change, or delete your entire database.",
        fix: "Remove the service_role key from all front-end code immediately and rotate it in Supabase → Project Settings → API. The browser should only ever use the anon (public) key.",
        evidence: redact(tok) });
    }
  }
  return out;
}

const SECURITY_HEADERS = {
  "content-security-policy": ["Content-Security-Policy", "Helps stop attackers from injecting malicious scripts into your pages.",
    "Add a Content-Security-Policy header (most hosts like Vercel/Netlify let you set this in a config file)."],
  "x-frame-options": ["X-Frame-Options", "Stops other sites from embedding yours to trick your users (clickjacking).",
    "Add 'X-Frame-Options: DENY' in your host's headers config."],
  "strict-transport-security": ["Strict-Transport-Security", "Forces browsers to always use secure HTTPS for your site.",
    "Add a 'Strict-Transport-Security' header (usually a one-line toggle on your host)."],
};

function scanHeaders(headers) {
  const out = [];
  for (const h in SECURITY_HEADERS) {
    if (!headers[h]) {
      const [label, detail, fix] = SECURITY_HEADERS[h];
      out.push({ id: "header_" + h, severity: "medium", title: "Missing protection: " + label, detail, fix, evidence: "" });
    }
  }
  return out;
}

function scoreFindings(findings) {
  const c = { critical: 0, high: 0, medium: 0, info: 0 };
  for (const f of findings) c[f.severity] = (c[f.severity] || 0) + 1;
  let grade = "A";
  if (c.critical) grade = "F";
  else if (c.high) grade = "D";
  else if (c.medium >= 2) grade = "C";
  else if (c.medium) grade = "B";
  return { grade, counts: c, total: findings.length };
}

if (typeof module !== "undefined") module.exports = { scanSecrets, scanHeaders, scoreFindings, decodeJwtRole };
