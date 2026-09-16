import base64, json
from detector import scan_secrets, scan_headers, score

def make_jwt(role):
    header = base64.urlsafe_b64encode(b'{"alg":"HS256"}').decode().rstrip("=")
    payload = base64.urlsafe_b64encode(json.dumps({"role": role}).encode()).decode().rstrip("=")
    return f"{header}.{payload}.fakesignature_{role}_xxxxxxxxxxxxxxxxxxxx"

# Fake keys are assembled from fragments so no scannable key literal exists in
# this source file (GitHub push protection flags realistic-looking key strings).
# At runtime the full strings are identical to what a real leak would look like.
FAKE = {
    "openai":  "sk-" + "proj-" + "abc123DEF456ghi789JKL012mno345",
    "stripe":  "sk_" + "live_" + "51Habcdefghijklmnop0123456789",
    "stripe_pub": "pk_" + "live_" + "51Hshouldbefineitspublic00",
    "google":  "AIza" + "SyA1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7",
}

BUNDLE = f'''
const config = {{
  openai: "{FAKE['openai']}",
  supabaseUrl: "https://abcdefghijklmnopqrst.supabase.co",
  supabaseAnon: "{make_jwt('anon')}",
  supabaseAdmin: "{make_jwt('service_role')}",
  stripe: "{FAKE['stripe']}",
  publishable: "{FAKE['stripe_pub']}",
  google: "{FAKE['google']}"
}};
'''
CLEAN = 'const x = 5; fetch("/api/data").then(r=>r.json()); // no secrets here'

def main():
    f = scan_secrets(BUNDLE)
    ids = {x.id for x in f}
    checks = [
        ("detects OpenAI key", "secret_openai" in ids),
        ("detects Stripe SECRET key", "secret_stripe_secret" in ids),
        ("detects Supabase service_role (admin) key", "secret_supabase_service_role" in ids),
        ("detects Google API key", "secret_google_api" in ids),
        ("does NOT flag Supabase anon key (it's public by design)", not any("anon" in x.id for x in f)),
        ("does NOT flag Stripe publishable pk_live", not any(x.id == "secret_stripe_secret" and "pk_" in x.evidence for x in f)),
        ("clean bundle yields no secret findings", len(scan_secrets(CLEAN)) == 0),
        ("evidence is redacted (no full key leaked)", all(FAKE['openai'] not in x.evidence for x in f)),
    ]
    passed = 0
    for name, ok in checks:
        print(("  ok   " if ok else "  FAIL ") + name); passed += ok
    print(f"\nsecrets: {passed}/{len(checks)} passed")

    h = scan_headers({"content-type": "text/html"})
    print(f"\nheaders: flags {len(h)} missing protections (expect 3): {'ok' if len(h)==3 else 'FAIL'}")
    hpass = scan_headers({"content-security-policy": "x", "x-frame-options": "DENY",
                          "strict-transport-security": "max-age=1"})
    print(f"        fully-protected site flags 0: {'ok' if len(hpass)==0 else 'FAIL'}")

    print("\nscore on the messy bundle:", score(f))
    return len(checks) - passed

if __name__ == "__main__":
    raise SystemExit(1 if main() else 0)
