// Pure: turn collected page data into ranked findings + a grade. Testable in node.
function analyze(data) {
  const findings = [];
  findings.push(...scanSecrets((data.html || "") + "\n" + (data.scripts || "")));
  findings.push(...scanHeaders(data.headers || {}));

  for (const p of data.exposedFiles || []) {
    const isGit = p === "/.git/config";
    findings.push({
      id: "exposed" + p, severity: isGit ? "high" : "critical",
      title: isGit ? "Your source code history is exposed" : `Your ${p} file is downloadable`,
      detail: isGit
        ? "Your .git folder is public, which usually means anyone can download your entire source code and history."
        : "Anyone can open this file in a browser and read every secret inside it — API keys, database passwords, everything.",
      fix: isGit
        ? "Configure your host to block the /.git path, or stop deploying the .git folder."
        : "Stop deploying this file (add it to .gitignore and your host's ignore list) and rotate any secrets it held.",
      evidence: p,
    });
  }

  if (data.supabase) {
    findings.push({
      id: "supabase_rls_off", severity: "high",
      title: "Your database is readable by anyone (no login required)",
      detail: `Your Supabase table "${data.supabase}" returns real data to a visitor who isn't logged in. Anyone can read — and often edit or delete — your users' data.`,
      fix: "In Supabase, turn on Row Level Security for every table (Authentication → Policies), then add policies so people can only see their own rows.",
      evidence: "table: " + data.supabase,
    });
  }

  const order = { critical: 0, high: 1, medium: 2, info: 3 };
  const seen = new Set(), uniq = [];
  for (const f of findings) { const k = f.id + f.evidence; if (!seen.has(k)) { seen.add(k); uniq.push(f); } }
  uniq.sort((a, b) => order[a.severity] - order[b.severity]);
  return { findings: uniq, summary: scoreFindings(uniq) };
}
if (typeof module !== "undefined") module.exports = { analyze };
