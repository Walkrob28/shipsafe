// Integration test for the extension's pure pipeline (detector + analyze),
// simulating what shipsafeCollect() returns from a page. Run: node test-extension.js
global.atob = s => Buffer.from(s, "base64").toString("binary");
Object.assign(global, require("./detector.js"));
const { analyze } = require("./analyze.js");

function jwt(role){
  const b64=o=>Buffer.from(JSON.stringify(o)).toString("base64url");
  return `${b64({alg:"HS256"})}.${b64({role})}.sig_${role}_xxxxxxxxxxxx`;
}

const K = { openai:"sk-"+"proj-"+"abc123DEF456ghi789JKL012mno345",
            stripe:"sk_"+"live_"+"51Habcdefghijklmnop0123456789" };

const cases = [
  { name: "leaky app (F)",
    data: { html:`<script>const c={openai:"${K.openai}",admin:"${jwt('service_role')}",anon:"${jwt('anon')}"}</script>`,
            scripts:`const s="${K.stripe}"`, headers:{}, exposedFiles:["/.env"], supabase:"users" },
    expectGrade:"F", mustInclude:["secret_openai","secret_stripe_secret","secret_supabase_service_role","exposed/.env","supabase_rls_off"],
    mustExclude:["anon"] },
  { name: "clean app (A)",
    data: { html:"<h1>hi</h1><script>console.log('ok')</script>", scripts:"const x=1",
            headers:{"content-security-policy":"default-src 'self'","x-frame-options":"DENY","strict-transport-security":"max-age=1"},
            exposedFiles:[], supabase:null },
    expectGrade:"A", mustInclude:[], mustExclude:["secret_"] },
  { name: "only missing headers (C)",
    data: { html:"<h1>hi</h1>", scripts:"", headers:{}, exposedFiles:[], supabase:null },
    expectGrade:"C", mustInclude:["header_content-security-policy"], mustExclude:["secret_","exposed","supabase"] },
];

let pass=0, fail=0;
for (const c of cases) {
  const { findings, summary } = analyze(c.data);
  const ids = findings.map(f=>f.id).join(" ");
  let ok = summary.grade === c.expectGrade;
  for (const m of c.mustInclude) if (!ids.includes(m)) ok=false;
  for (const x of c.mustExclude) if (ids.includes(x)) ok=false;
  // no full secret leaked in evidence
  if (findings.some(f => (f.evidence||"").includes("abc123DEF456"))) ok=false;
  console.log((ok?"  ok   ":"  FAIL ") + `${c.name} -> grade ${summary.grade}, ${findings.length} findings`);
  if (!ok) { console.log("        ids:", ids); fail++; } else pass++;
}
console.log(`\n${pass}/${cases.length} passed`);
process.exit(fail?1:0);
