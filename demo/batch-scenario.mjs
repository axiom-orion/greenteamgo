#!/usr/bin/env node
// batch-scenario.mjs — GreenTeamGo reproducible 20-action demo fixture.
//
// Drives a RUNNING console (default http://localhost:4000) entirely over HTTP.
// Uses the AGENT key to create/poll requests and the APP key to record human
// decisions. Produces, HONESTLY, a chain of 20 Ed25519-signed, hash-linked
// receipts:
//
//   * 14 read actions (file_read / file_list) that the POLICY auto-ALLOWS
//         -> receipt.decider.method == "policy"
//   *  6 risky actions the policy GATES -> a human is paged (the "phone").
//         Of those 6, the human APPROVES 4 and DENIES 2
//         -> receipt.decider.method == "app"
//
// Honest metric it targets:
//   "policy auto-decided 14 (auto-allowed); a human was paged for the 6 that
//    mattered — approved 4, denied 2."
//
// It never claims the policy auto-DENIED anything (the demo policy only
// auto-allows reads); the 2 denials are recorded as HUMAN denials, which is
// exactly what their receipts say (decider.method == "app", status "denied").
//
// After the run it exports the FULL chain to <out>/receipts.json and the
// workspace public key(s) to <out>/keys.json as a {key_id: pem} MAP, so the
// verifier re-checks the whole thing with one command:
//
//   node packages/core/dist/cli.js demo/scenario/receipts.json demo/scenario/keys.json
//
// Config via env (all optional):
//   GTG_BASE_URL   default http://localhost:4000
//   GTG_AGENT_KEY  default gtg_demo_agent_key
//   GTG_APP_KEY    default gtg_demo_app_key
//   GTG_OUT_DIR    default <cwd>/demo/scenario   (run from the repo root)
//   GTG_DECIDER    default ryan@vorion.org
//
// NOTE: for a clean, exactly-20 committed artifact, start the console with an
// EMPTY chain, then run this once. If the chain is non-empty the script still
// runs and reports THIS run's counts honestly (by its own request ids), and
// warns that the exported chain also contains the pre-existing receipts.

import { writeFile, mkdir } from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';

const BASE_URL  = process.env.GTG_BASE_URL  || 'http://localhost:4000';
const AGENT_KEY = process.env.GTG_AGENT_KEY || 'gtg_demo_agent_key';
const APP_KEY   = process.env.GTG_APP_KEY   || 'gtg_demo_app_key';
const OUT_DIR   = process.env.GTG_OUT_DIR   || path.resolve(process.cwd(), 'demo', 'scenario');
const HUMAN_ID  = process.env.GTG_DECIDER   || 'ryan@vorion.org';

const FETCH_TIMEOUT_MS = 20000;
const FETCH_RETRIES    = 4;
const POLL_ATTEMPTS    = 60;
const POLL_INTERVAL_MS = 500;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// --- resilient HTTP helper (timeout + retry) -------------------------------
async function api(method, pathname, { key, body } = {}) {
  const url = BASE_URL + pathname;
  let lastErr;
  for (let attempt = 1; attempt <= FETCH_RETRIES; attempt++) {
    try {
      const res = await fetch(url, {
        method,
        headers: {
          Authorization: `Bearer ${key}`,
          ...(body ? { 'Content-Type': 'application/json' } : {}),
        },
        body: body ? JSON.stringify(body) : undefined,
        signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
      });
      const text = await res.text();
      let json;
      try { json = text ? JSON.parse(text) : undefined; } catch { json = undefined; }
      if (!res.ok) {
        throw new Error(`${method} ${pathname} -> HTTP ${res.status}: ${String(text).slice(0, 200)}`);
      }
      return json;
    } catch (err) {
      lastErr = err;
      if (attempt < FETCH_RETRIES) {
        console.log(`   ! ${method} ${pathname} failed (try ${attempt}/${FETCH_RETRIES}): ${err.message} — retrying`);
        await sleep(400 * attempt);
      }
    }
  }
  throw lastErr;
}

const createRequest = (b)     => api('POST', '/v1/requests', { key: AGENT_KEY, body: b });
const getRequest    = (id)    => api('GET',  `/v1/requests/${id}`, { key: AGENT_KEY });
const postDecision  = (id, b) => api('POST', `/v1/requests/${id}/decision`, { key: APP_KEY, body: b });
const getReceipts   = ()      => api('GET',  '/v1/receipts', { key: AGENT_KEY });
const getKeys       = ()      => api('GET',  '/v1/keys', { key: AGENT_KEY });

// Resolve a request's minted receipt whether it comes back inline on
// GET /v1/requests/:id or only shows up in the /v1/receipts chain.
async function resolveReceipt(id) {
  for (let i = 0; i < POLL_ATTEMPTS; i++) {
    const r = await getRequest(id);
    if (r && r.receipt) return r.receipt;
    if (r && r.status && r.status !== 'pending') {
      const chain = await getReceipts();
      const found = Array.isArray(chain) ? chain.find((x) => x.request_id === id) : null;
      if (found) return found;
    }
    await sleep(POLL_INTERVAL_MS);
  }
  throw new Error(`no receipt resolved for request ${id}`);
}

const isAutoMethod = (m) => m === 'policy' || m === 'auto';

// --- the 14 read actions the policy auto-ALLOWS ----------------------------
// [action_type, human summary, target path, risk]
const AUTO_ALLOW = [
  ['file_read', 'Read AGENTS.md to learn the repo house rules',   'AGENTS.md',                          'low'],
  ['file_read', 'Read package.json (scripts + workspaces)',       'package.json',                       'low'],
  ['file_read', 'Read the base tsconfig',                         'tsconfig.base.json',                 'low'],
  ['file_read', 'Read the README',                                'README.md',                          'low'],
  ['file_list', 'List the packages/ workspace',                   'packages/',                          'low'],
  ['file_read', 'Read the canonical receipt serializer',          'packages/core/src/canonical.ts',     'low'],
  ['file_read', 'Read the policy rule set',                       'packages/policy/src/rules.ts',       'low'],
  ['file_list', 'List the API routes',                            'packages/api/src/routes/',           'low'],
  ['file_read', 'Read the MCP request_approval tool',             'packages/mcp/src/server.ts',         'low'],
  ['file_read', 'Read the identity keypair module',               'packages/identity/src/keys.ts',      'low'],
  ['file_list', 'List the console app source',                    'apps/console/src/',                  'low'],
  ['file_read', 'Read the notify inbox contract',                 'packages/notify/src/inbox.ts',       'low'],
  ['file_read', 'Read the greenteamgo-verify CLI',                'packages/core/src/cli.ts',           'low'],
  ['file_list', 'List the core test suites',                      'packages/core/test/',                'low'],
];

// --- the 6 risky actions the policy GATES (human on the phone) --------------
const GATED = [
  {
    action_type: 'git_push', risk: 'high',
    summary: 'Force-push feature/gate-ui with --force-with-lease',
    detail: 'git push --force-with-lease origin feature/gate-ui (clean rebase onto main; only my own 4 commits rewritten)',
    decision: 'approved',
    reason: 'Reviewed the diff — feature branch, --force-with-lease, only my own commits. Safe.',
  },
  {
    action_type: 'db_migrate', risk: 'high',
    summary: 'Apply migration 0007_add_receipts_index',
    detail: 'CREATE INDEX CONCURRENTLY receipts_ws_created_idx ON receipts(workspace_id, created_at) — additive, no drops',
    decision: 'approved',
    reason: 'Additive index only, no data loss, CONCURRENTLY avoids a table lock. Go.',
  },
  {
    action_type: 'deploy', risk: 'medium',
    summary: 'Deploy the API to staging',
    detail: 'vercel deploy --target=staging for greenteamgo-api @ HEAD',
    decision: 'approved',
    reason: 'Staging only, smoke tests are green. Approved.',
  },
  {
    action_type: 'shell_exec', risk: 'medium',
    summary: 'Wipe node_modules and reinstall from lockfile',
    detail: 'rm -rf node_modules && pnpm install --frozen-lockfile',
    decision: 'approved',
    reason: 'Reproducible clean reinstall from a frozen lockfile. Fine.',
  },
  {
    action_type: 'git_push', risk: 'critical',
    summary: 'Force-push local main over 3 remote commits',
    detail: 'git push --force origin main (local main is 3 commits behind remote; this permanently discards teammates’ commits)',
    decision: 'denied',
    reason: 'This discards collaborators’ commits. Do NOT force-push main — open a PR instead.',
  },
  {
    action_type: 'payment', risk: 'critical',
    summary: 'Charge a customer card $4,200 to unblock a vendor',
    detail: 'POST /charges amount=420000 currency=usd — vendor invoice, not previously authorized',
    decision: 'denied',
    reason: 'Payments need finance sign-off. The agent is not authorized to move money.',
  },
];

async function main() {
  console.log('=== GreenTeamGo — reproducible 20-action scenario ===');
  console.log(`console : ${BASE_URL}`);
  console.log(`out dir : ${OUT_DIR}`);

  // ---- preflight ----------------------------------------------------------
  const keys0 = await getKeys();
  const receipts0 = await getReceipts();
  const baseline = Array.isArray(receipts0) ? receipts0.length : 0;
  const kid = Array.isArray(keys0) ? (keys0[0] && keys0[0].key_id) : (keys0 && keys0.key_id);
  console.log(`preflight OK — workspace key_id: ${kid ?? '(unknown)'}; existing chain length: ${baseline}`);
  if (baseline > 0) {
    console.log(`   ! WARNING: the chain is NOT empty (${baseline} pre-existing receipt(s)).`);
    console.log('   ! For a clean, exactly-20 committed artifact: restart the console fresh, then re-run.');
    console.log("   ! Proceeding anyway — the metric below counts only THIS run's 20 actions (by request id).");
  }
  console.log('');

  const mine = []; // { request_id, kind, action_type, intended? }
  let n = 0;

  // ---- Phase 1: 14 reads -> policy auto-ALLOW -----------------------------
  console.log('--- Phase 1: 14 read actions (policy should auto-ALLOW) ---');
  for (const [action_type, summary, target, risk] of AUTO_ALLOW) {
    n++;
    const created = await createRequest({
      action_type, summary, detail: target, risk,
      timeout_s: 300, mode: 'block',
    });
    const id = created.request_id;
    const receipt = await resolveReceipt(id);
    const method = receipt && receipt.decider && receipt.decider.method;
    const status = receipt && receipt.status;
    mine.push({ request_id: id, kind: 'auto', action_type });
    const tag = isAutoMethod(method) ? 'policy' : `?method=${method}`;
    console.log(`  [${String(n).padStart(2)}/20] ${action_type.padEnd(10)} ${status}/${tag}  "${summary}"`);
    if (!isAutoMethod(method)) {
      console.log(`   ! HONESTY: expected a policy auto-decision but decider.method=${method}; will NOT count this as auto.`);
    }
  }

  // ---- Phase 2: 6 risky -> GATE -> human decides --------------------------
  console.log('\n--- Phase 2: 6 risky actions (policy GATES -> human on the phone) ---');
  for (const g of GATED) {
    n++;
    const created = await createRequest({
      action_type: g.action_type, summary: g.summary, detail: g.detail,
      risk: g.risk, timeout_s: 300, mode: 'block',
    });
    const id = created.request_id;
    console.log(`  [${String(n).padStart(2)}/20] ${g.action_type.padEnd(10)} ${created.status ?? 'pending'} (gated, paging human)  "${g.summary}"`);
    // The human answers from the inbox ("the phone").
    await postDecision(id, { decision: g.decision, reason: g.reason, decider_id: HUMAN_ID });
    const receipt = await resolveReceipt(id);
    const method = receipt && receipt.decider && receipt.decider.method;
    const status = receipt && receipt.status;
    mine.push({ request_id: id, kind: 'gated', intended: g.decision, action_type: g.action_type });
    console.log(`          -> human ${status} (decider.method=${method})  reason: "${g.reason}"`);
  }

  // ---- Export artifacts ---------------------------------------------------
  console.log('\n--- Exporting artifacts ---');
  const chain = await getReceipts();
  const keys = await getKeys();
  const keyList = Array.isArray(keys) ? keys : [keys];
  const keyMap = {};
  for (const k of keyList) {
    if (k && k.key_id) keyMap[k.key_id] = k.publicKeyPem ?? k.public_key_pem ?? k.pem;
  }
  await mkdir(OUT_DIR, { recursive: true });
  const receiptsPath = path.join(OUT_DIR, 'receipts.json');
  const keysPath = path.join(OUT_DIR, 'keys.json');
  await writeFile(receiptsPath, JSON.stringify(chain, null, 2) + '\n');
  await writeFile(keysPath, JSON.stringify(keyMap, null, 2) + '\n');
  console.log(`  wrote ${Array.isArray(chain) ? chain.length : 0} receipts -> ${receiptsPath}`);
  console.log(`  wrote ${Object.keys(keyMap).length} key(s) -> ${keysPath}`);

  // ---- Honest counting (from THIS run's actual receipts) ------------------
  const byId = new Map((Array.isArray(chain) ? chain : []).map((r) => [r.request_id, r]));
  let autoAllow = 0, humanApprove = 0, humanDeny = 0, other = 0;
  for (const m of mine) {
    const r = byId.get(m.request_id);
    const method = r && r.decider && r.decider.method;
    const status = r && r.status;
    if (isAutoMethod(method) && status === 'approved') autoAllow++;
    else if (!isAutoMethod(method) && status === 'approved') humanApprove++;
    else if (!isAutoMethod(method) && status === 'denied') humanDeny++;
    else other++;
  }
  const total = mine.length;
  const humanSaw = humanApprove + humanDeny;

  console.log('\n=== RESULT ===');
  if (autoAllow === 14 && humanApprove === 4 && humanDeny === 2 && other === 0) {
    console.log(
      `METRIC: ${total} actions — policy auto-decided ${autoAllow} (auto-allowed); ` +
      `a human was paged for only the ${humanSaw} that mattered (approved ${humanApprove}, denied ${humanDeny}). ` +
      `${total} signed, hash-linked receipts. ` +
      `Re-verify: node packages/core/dist/cli.js demo/scenario/receipts.json demo/scenario/keys.json`
    );
  } else {
    console.log(
      `METRIC (actual, honest): ${total} actions — policy auto-decided ${autoAllow}; ` +
      `human decided ${humanSaw} (approved ${humanApprove}, denied ${humanDeny}); unexpected ${other}.`
    );
    console.log('   ! Counts differ from the designed 14/4/2 — reporting exactly what the receipts say (no fabrication).');
  }
  const chainLen = Array.isArray(chain) ? chain.length : 0;
  console.log(
    `chain exported: ${chainLen} receipt(s)` +
    (baseline > 0 ? ` (includes ${baseline} pre-existing; THIS run added ${total})` : ` (clean chain of ${total})`)
  );
}

main().catch((err) => {
  console.error('\nFATAL:', err && err.message ? err.message : err);
  process.exit(1);
});
