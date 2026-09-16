# ShipSafe — see what a hacker sees, before you launch

A plain-English security scanner for AI-built ("vibe-coded") apps. Paste your app's
URL and ShipSafe reports — in non-technical language — what a visitor can already see:
exposed API keys, downloadable secret files, databases left open, and missing protections,
each with an exact fix.

Passive and read-only by design: it only loads what any visitor can already load, never
writes or exploits, refuses non-public targets (SSRF-guarded), and requires the user to
confirm they own the app.

## Run locally
```
python3 -m venv .venv && ./.venv/bin/pip install -r requirements.txt
./.venv/bin/uvicorn server:app --port 8011
```

## Detection engine
`detector.py` is network-free and unit-tested (`test_detector.py`, 8/8). It flags server-side
secrets (OpenAI, Anthropic, AWS, Stripe secret, GitHub, Google, SendGrid, private keys, and the
Supabase service_role key) while correctly ignoring public-by-design keys (Supabase anon, Stripe
publishable). Evidence is always redacted.
