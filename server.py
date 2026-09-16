"""
ShipSafe — see what a hacker sees, before you launch.

Give it your app's URL; it looks only at what any visitor can already load
(the page, its JavaScript, response headers) and reports, in plain English,
what's exposed and how to fix it. Passive and read-only by design.
"""
from __future__ import annotations
import ipaddress, os, re, socket
from pathlib import Path
from urllib.parse import urlparse, urljoin

import httpx
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from detector import Finding, scan_secrets, scan_headers, score

BASE = Path(__file__).parent
app = FastAPI(title="ShipSafe")

UA = {"User-Agent": "ShipSafe-Scanner/1.0 (+security self-check)"}
MAX_JS = 12            # cap how many script files we pull
MAX_BYTES = 3_000_000  # per-file size cap
COMMON_TABLES = ["users", "profiles", "user", "customers", "accounts", "orders",
                 "posts", "messages", "todos", "tasks", "notes", "products",
                 "subscribers", "waitlist", "contacts", "feedback", "leads"]
EXPOSED_PATHS = {
    "/.env": ("Your .env file is downloadable", "critical",
              "Anyone can open your .env file in a browser and read every secret in it — API keys, database passwords, everything.",
              "Remove .env from what you deploy. Add it to .gitignore and your host's ignore list, then rotate any secrets that were inside it."),
    "/.env.local": ("Your .env.local file is downloadable", "critical",
              "A local environment file with secrets is publicly downloadable.",
              "Stop deploying this file and rotate any secrets it contained."),
    "/.git/config": ("Your source code history is exposed", "high",
              "Your .git folder is public, which usually means anyone can download your entire source code and its history.",
              "Configure your host to block access to the /.git path, or don't deploy the .git folder."),
}


def _is_public_host(host: str) -> bool:
    """SSRF guard: refuse localhost / private / cloud-metadata targets."""
    try:
        infos = socket.getaddrinfo(host, None)
    except Exception:
        return False
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            return False
    return True


async def _get(client, url):
    try:
        r = await client.get(url, headers=UA, timeout=12, follow_redirects=True)
        return r
    except Exception:
        return None


@app.post("/api/scan")
async def scan(payload: dict):
    url = (payload.get("url") or "").strip()
    if not payload.get("consent"):
        return JSONResponse({"error": "Please confirm you own this app before scanning."}, status_code=400)
    if not re.match(r"^https?://", url):
        url = "https://" + url
    parsed = urlparse(url)
    if not parsed.hostname:
        return JSONResponse({"error": "That doesn't look like a valid URL."}, status_code=400)
    if not _is_public_host(parsed.hostname):
        return JSONResponse({"error": "For safety, ShipSafe only scans public websites (not localhost or private addresses)."}, status_code=400)

    findings: list[Finding] = []
    async with httpx.AsyncClient(max_redirects=5) as client:
        page = await _get(client, url)
        if page is None:
            return JSONResponse({"error": "Couldn't reach that URL. Is the app live?"}, status_code=502)

        html = page.text[:MAX_BYTES]
        findings += scan_headers(dict(page.headers))
        findings += scan_secrets(html)

        # pull linked JS bundles (where hardcoded keys usually hide)
        scripts = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I)[:MAX_JS]
        blob = ""
        for s in scripts:
            js = await _get(client, urljoin(url, s))
            if js is not None and js.status_code == 200:
                blob += "\n" + js.text[:MAX_BYTES]
        findings += scan_secrets(blob)

        # exposed sensitive files
        for path, (title, sev, why, fix) in EXPOSED_PATHS.items():
            r = await _get(client, urljoin(url, path))
            if r is not None and r.status_code == 200 and len(r.text) > 5 and "<html" not in r.text[:200].lower():
                findings.append(Finding(id=f"exposed{path}", severity=sev, title=title,
                                        detail=why, fix=fix, evidence=path))

        # Supabase: if we see a project URL, check whether tables are readable
        # without login (RLS off) — the classic vibe-coding data leak.
        m = re.search(r"https://([a-z0-9]{20})\.supabase\.co", html + blob)
        key = re.search(r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+", html + blob)
        if m and key:
            sb = f"https://{m.group(1)}.supabase.co"
            for t in COMMON_TABLES:
                r = await _get(client, f"{sb}/rest/v1/{t}?select=*&limit=1")
                if r is None:
                    continue
                try:
                    body = r.json()
                except Exception:
                    body = None
                if r.status_code == 200 and isinstance(body, list) and len(body) > 0:
                    findings.append(Finding(id="supabase_rls_off", severity="high",
                        title="Your database is readable by anyone (no login required)",
                        detail=f"Your Supabase table \"{t}\" returns real data to a visitor who isn't logged in. That means anyone can read — and often edit or delete — your users' data.",
                        fix="In Supabase, open Authentication → Policies (or the table's RLS settings) and turn on Row Level Security for every table, then add policies so people can only see their own rows.",
                        evidence=f"table: {t}"))
                    break

    # dedupe by (id, evidence)
    uniq, seen = [], set()
    for f in findings:
        k = (f.id, f.evidence)
        if k not in seen:
            seen.add(k); uniq.append(f)
    order = {"critical": 0, "high": 1, "medium": 2, "info": 3}
    uniq.sort(key=lambda f: order.get(f.severity, 9))
    return {"url": url, "summary": score(uniq), "findings": [f.to_dict() for f in uniq]}


@app.get("/api/health")
async def health():
    return {"ok": True}

app.mount("/", StaticFiles(directory=BASE / "static", html=True), name="static")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=int(os.getenv("PORT", "8000")))
