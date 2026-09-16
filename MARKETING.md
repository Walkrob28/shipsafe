# ShipSafe — Launch Kit
Live: https://shipsafe-3s49.onrender.com

## HOW TO USE THIS
Post ONE thing first (r/vibecoding), watch the response for a day, then do the others.
Blasting all at once looks like spam and teaches us nothing. Reply to every comment —
that engagement is what makes a post take off.

Before posting, skim each community's rules. Many subreddits restrict links/self-promo.
If a sub blocks links in posts, put the link in the FIRST COMMENT instead.

Honest note: a brand-new/low-karma Reddit account often gets auto-filtered. If your post
vanishes, that's usually why — comment around the sub a bit first, or expect some removals.

---

## 1. REDDIT — r/vibecoding  (POST THIS FIRST)

TITLE:
Your vibe-coded app is probably exposing your API keys right now. Here's a free 30-second check.

BODY:
I kept seeing the same thing in this community: someone ships an app they built with
Lovable / Bolt / Cursor, and it's quietly leaking their OpenAI key, or has a Supabase
database anyone can read. One vibe-coded app leaked 1.5M API keys this way earlier this year.

The scary part is you can't see it — these mistakes are invisible unless you know where to look:

- **API keys hardcoded into the front-end.** Anyone can open your site's code in a browser,
  copy your key, and run up thousands in charges on your account.
- **Supabase tables with Row Level Security off.** Any visitor (not logged in) can read —
  and often edit or delete — all of your users' data.
- **.env files left downloadable.** Every secret you have, one click away.

So I built a free tool that checks for you. Paste your app's URL and in ~30 seconds it tells
you, in plain English, exactly what's exposed and how to fix it. No signup. It only looks at
what any visitor can already see — nothing is stored, nothing is changed.

https://shipsafe-3s49.onrender.com

It's genuinely free — I'm not selling anything, I just want it to be useful. Would love
feedback if you try it. And I'm curious: what's the worst leak you've caught in your own app?

---

## 2. X / TWITTER  (single post)

Most vibe-coded apps are quietly leaking their API keys or leaving their database wide open.

You can't see it. A hacker can.

Built a free tool: paste your app's URL, get a plain-English security report in 30 seconds.

https://shipsafe-3s49.onrender.com

### Optional follow-up replies (thread):
2/ The usual killers:
• API key hardcoded in your front-end → anyone copies it, runs up your bill
• Supabase table with RLS off → any visitor reads all your users' data
• .env file left downloadable → every secret, one click away

3/ It only checks what any visitor can already load. Nothing stored, nothing changed.
Free, no signup. Would love feedback.

---

## 3. DISCORD — Lovable / Bolt / Replit / Cursor community channels
(chatty + humble; post in a #showcase / #i-made-this / #general channel, not randomly)

hey all — made a free little tool that checks your app for the security stuff that's easy to
miss when you're shipping fast: exposed API keys, Supabase tables left open, downloadable .env
files. paste your URL, get a plain-English report in ~30s. no signup, only looks at what any
visitor can already see. would genuinely love feedback if you try it 🙏
https://shipsafe-3s49.onrender.com

---

## 4. REDDIT — r/SideProject  (second wave; "I built X" is welcome here)

TITLE:
I built a free tool that scans AI-built apps for security holes (exposed keys, open databases) in 30 seconds

BODY:
Vibe-coding (building apps with Lovable/Bolt/Cursor) has exploded, and a huge share of those
apps ship with invisible security holes — hardcoded API keys, Supabase databases left open to
the public, downloadable .env files. One leaked 1.5M keys this year.

ShipSafe checks for these in ~30 seconds: paste your app's URL, get a plain-English report of
what's exposed and how to fix each thing. Passive and read-only — it only loads what any
visitor can already load. Free, no signup.

https://shipsafe-3s49.onrender.com

Built the detection engine with a set of tests so it doesn't cry wolf (it correctly ignores
keys that are *supposed* to be public, like a Supabase anon key). Feedback welcome —
especially edge cases where it misses something or over-flags.

---

## 5. LATER: Product Hunt / Show HN (once it has some traction + feedback)

Show HN title:
Show HN: ShipSafe – see what a hacker sees in your vibe-coded app

One-liner:
A free, plain-English security scanner for AI-built apps. Paste a URL; it flags exposed API
keys, open Supabase tables, downloadable secret files, and missing headers, with exact fixes.
Passive/read-only, SSRF-guarded, owner-consent required.
