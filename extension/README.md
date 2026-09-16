# ShipSafe — Chrome extension

One click checks the page you're currently on for the security mistakes AI-built
("vibe-coded") apps ship with — exposed API keys, downloadable secret files, open
Supabase tables, missing headers — and explains each in plain English with a fix.

**Runs entirely in your browser.** Detection is client-side; nothing is sent to a
server. It only reads what any visitor to the page can already load (passive,
read-only), and asks for the minimum permissions (`activeTab`, `scripting`) — it can
only look at a tab after you click the icon on it.

## Files
- `manifest.json` — MV3, minimal permissions
- `detector.js` — secret/JWT/header detection (pure; shared with the web app's engine)
- `analyze.js` — turns collected page data into ranked findings + a grade (pure)
- `popup.js` — grabs the active tab, injects the collector into the page, runs `analyze`, renders
- `popup.html` / `popup.css` — the report UI
- `test-extension.js` — integration test for the detection pipeline (`node test-extension.js`)

## Load it locally (for testing)
1. Go to `chrome://extensions`
2. Turn on **Developer mode** (top-right)
3. Click **Load unpacked** and select this `extension/` folder
4. Open any site you own, click the ShipSafe icon, hit **Scan this page**

## How detection stays honest
Flags server-side secrets (OpenAI, Anthropic, AWS, Stripe secret, GitHub, Google,
SendGrid, private keys, Supabase **service_role**) while ignoring keys that are public
by design (Supabase **anon**, Stripe **publishable**). Evidence is always redacted.
