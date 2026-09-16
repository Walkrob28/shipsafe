"""
ShipSafe detection engine.

Pure, network-free functions so they can be unit-tested. The server does the
fetching and passes raw text/headers in here.

Everything is DEFENSIVE and passive: we look at what a normal visitor can already
see (the page, its JavaScript bundle, response headers) and tell the owner what's
exposed. No exploitation, no writes, no brute force.
"""
from __future__ import annotations
import base64, json, re
from dataclasses import dataclass, asdict, field


@dataclass
class Finding:
    id: str
    severity: str          # critical | high | medium | info
    title: str             # plain-English, non-technical
    detail: str            # what we found / why it matters, no jargon
    fix: str               # exact, click-by-click remedy
    evidence: str = ""     # a redacted snippet
    def to_dict(self): return asdict(self)


def _redact(s: str) -> str:
    s = s.strip()
    if len(s) <= 12:
        return s[:4] + "…"
    return s[:6] + "…" + s[-4:]


# --- exposed server-side secrets: the money-losing, data-losing kind ----------
# (name, regex, plain-English title, why, fix)
SECRET_RULES = [
    ("openai", r"sk-(?:proj-)?[A-Za-z0-9_\-]{20,}",
     "Your OpenAI key is visible to anyone",
     "This key is sitting in your app's code, which every visitor can read. Someone can copy it and run up thousands of dollars in charges on your account.",
     "Delete the key from your code. Put it in an environment variable on your server (never in front-end code), then rotate (regenerate) the key in your OpenAI dashboard so the old one stops working."),
    ("anthropic", r"sk-ant-[A-Za-z0-9_\-]{20,}",
     "Your Anthropic (Claude) key is exposed",
     "Your Claude API key is readable in your app's code. Anyone can take it and bill your account.",
     "Move the key to a server-side environment variable, remove it from front-end code, and rotate it in the Anthropic Console."),
    ("aws", r"AKIA[0-9A-Z]{16}",
     "Your AWS access key is exposed",
     "An AWS key in your code can let an attacker into your cloud account — spin up servers, read your files, or delete everything.",
     "Deactivate this key in AWS IAM immediately, create a new one, and keep it only on the server side. Never ship AWS keys to the browser."),
    ("stripe_secret", r"(?:sk|rk)_live_[0-9a-zA-Z]{20,}",
     "Your Stripe SECRET key is exposed — this is an emergency",
     "This is your live Stripe secret key. With it, someone can issue refunds, read customer payment data, and move money. It must never be in front-end code.",
     "Roll (revoke) this key in the Stripe Dashboard right now, then use the new secret key only on your server. The browser should only ever see your publishable (pk_) key."),
    ("github", r"gh[pousr]_[A-Za-z0-9]{36,}",
     "Your GitHub token is exposed",
     "This token can give someone access to your code repositories — including private ones.",
     "Revoke it in GitHub → Settings → Developer settings → Tokens, then generate a new one and keep it server-side."),
    ("google_api", r"AIza[0-9A-Za-z_\-]{35}",
     "A Google API key is visible in your app",
     "A Google/Firebase API key is in your code. On its own a web key can be okay, but without restrictions it can be abused to run up billing on your Google account.",
     "In Google Cloud Console, restrict this key to your domain and only the APIs you use. If it's a sensitive key, rotate it and move it server-side."),
    ("sendgrid", r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}",
     "Your SendGrid email key is exposed",
     "Someone can use this to send email as you — great for spammers and phishing under your name.",
     "Delete this key in SendGrid, create a new one, and send email only from your server."),
    ("private_key", r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
     "A private key is embedded in your app",
     "A cryptographic private key is exposed. Depending on what it's for, this can hand over your servers, signing ability, or encrypted data.",
     "Treat it as compromised: generate a new key pair, replace it everywhere, and never include private keys in shipped code."),
]
SECRET_RES = [(n, re.compile(rx), t, w, f) for (n, rx, t, w, f) in SECRET_RULES]


def _decode_jwt_role(tok: str) -> str | None:
    """Supabase keys are JWTs; the payload says the role. anon = public/fine,
    service_role = god-mode and must NEVER be in the browser."""
    try:
        payload = tok.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        data = json.loads(base64.urlsafe_b64decode(payload))
        return data.get("role")
    except Exception:
        return None


def scan_secrets(text: str) -> list[Finding]:
    out, seen = [], set()
    for name, rx, title, why, fix in SECRET_RES:
        for m in rx.findall(text):
            val = m if isinstance(m, str) else m[0]
            key = (name, val[:16])
            if key in seen:
                continue
            seen.add(key)
            out.append(Finding(id=f"secret_{name}", severity="critical", title=title,
                               detail=why, fix=fix, evidence=_redact(val)))
    # Supabase service_role JWT is the catastrophic one; anon JWT is expected
    for tok in re.findall(r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+", text):
        role = _decode_jwt_role(tok)
        if role == "service_role" and ("service_role", tok[:16]) not in seen:
            seen.add(("service_role", tok[:16]))
            out.append(Finding(id="secret_supabase_service_role", severity="critical",
                title="Your Supabase admin key is exposed — this bypasses all security",
                detail="Your app ships the Supabase service_role key. This key ignores every access rule you set — anyone who finds it can read, change, or delete your entire database.",
                fix="Remove the service_role key from all front-end code immediately and rotate it in Supabase → Project Settings → API. The browser should only ever use the anon (public) key.",
                evidence=_redact(tok)))
    return out


SECURITY_HEADERS = {
    "content-security-policy": ("Content-Security-Policy",
        "Helps stop attackers from injecting malicious scripts into your pages.",
        "Add a Content-Security-Policy header. Most hosts (Vercel, Netlify) let you set this in a config file."),
    "x-frame-options": ("X-Frame-Options",
        "Stops other sites from embedding yours to trick your users (clickjacking).",
        "Add 'X-Frame-Options: DENY' in your host's headers config."),
    "strict-transport-security": ("Strict-Transport-Security",
        "Forces browsers to always use secure HTTPS for your site.",
        "Add a 'Strict-Transport-Security' header (your host usually has a one-line toggle)."),
}


def scan_headers(headers: dict) -> list[Finding]:
    low = {k.lower(): v for k, v in headers.items()}
    out = []
    for h, (label, why, fix) in SECURITY_HEADERS.items():
        if h not in low:
            out.append(Finding(id=f"header_{h}", severity="medium",
                title=f"Missing protection: {label}", detail=why, fix=fix))
    return out


def score(findings: list[Finding]) -> dict:
    w = {"critical": 0, "high": 0, "medium": 0, "info": 0}
    for f in findings:
        w[f.severity] = w.get(f.severity, 0) + 1
    grade = "A"
    if w["critical"]: grade = "F"
    elif w["high"]: grade = "D"
    elif w["medium"] >= 2: grade = "C"
    elif w["medium"]: grade = "B"
    return {"grade": grade, "counts": w, "total": len(findings)}
