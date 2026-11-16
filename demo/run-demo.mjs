#!/usr/bin/env node
// run-demo.mjs — the whole GreenTeamGo story in one command, no Codex needed.
//
//   npm run build && npm run demo
//
// What it does, end to end, on your machine:
//   1. starts the console (inbox API + approval page) on a free local port
//   2. replays 20 agent actions through it (demo/batch-scenario.mjs):
//      14 reads the policy auto-allows, 6 risky ones a human decides
//   3. exports the signed receipt chain and the workspace public key
//   4. verifies the chain offline            -> must PASS
//   5. flips ONE character of one receipt    -> must FAIL
//
// Exit code 0 only if step 4 passes AND step 5 fails. Anything else is a
// non-zero exit, so CI can run this as a check on the tamper-evidence claim.
//
// Portable: plain Node (>= 22), no bash, curl or python. Scratch files go to
// demo/demo-work/ (gitignored).

import { spawn } from 'node:child_process';
import { mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { createServer } from 'node:net';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

const DEMO_DIR = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(DEMO_DIR, '..');
const CONSOLE = path.join(REPO, 'apps', 'console', 'dist', 'server.js');
const VERIFY = path.join(REPO, 'packages', 'core', 'dist', 'cli.js');
const SCENARIO = path.join(DEMO_DIR, 'batch-scenario.mjs');
const WORK = path.join(DEMO_DIR, 'demo-work');
const RECEIPTS = path.join(WORK, 'receipts.json');
const KEYS = path.join(WORK, 'keys.json');
const TAMPERED = path.join(WORK, 'receipts.tampered.json');

// Signed, human-readable content fields. Never sig / receipt_hash / prev_hash:
// the point is that editing *content* alone is caught.
const CONTENT_FIELDS = ['reason', 'action_type', 'verdict', 'status'];

const tty = process.stdout.isTTY;
const paint = (code, s) => (tty ? `\x1b[${code}m${s}\x1b[0m` : s);
const green = (s) => paint('1;32', s);
const red = (s) => paint('1;31', s);
const cyan = (s) => paint('1;36', s);
const dim = (s) => paint('2', s);
const step = (n, s) => console.log(`\n${cyan(`[${n}/5]`)} ${s}`);

/** Ask the OS for a free port so the demo never collides with a running console. */
function freePort() {
  return new Promise((resolve, reject) => {
    const srv = createServer();
    srv.once('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const { port } = srv.address();
      srv.close(() => resolve(port));
    });
  });
}

/** Run a node script; resolve with its exit code and captured output. */
function runNode(args, { env = {}, echo = false } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, args, {
      cwd: REPO,
      env: { ...process.env, ...env },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let out = '';
    const take = (buf) => {
      out += buf;
      if (echo) process.stdout.write(buf);
    };
    child.stdout.on('data', take);
    child.stderr.on('data', take);
    child.once('error', reject);
    child.once('close', (code) => resolve({ code: code ?? 1, out }));
  });
}

async function waitUntilUp(base, child) {
  for (let i = 0; i < 100; i++) {
    if (child.exitCode !== null) throw new Error(`console exited early (code ${child.exitCode})`);
    try {
      const res = await fetch(`${base}/`, { signal: AbortSignal.timeout(1000) });
      if (res.ok) return;
    } catch {
      /* not up yet */
    }
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error(`console did not come up at ${base}`);
}

/** Flip one letter in the first content field found; return what changed. */
export function tamperOneCharacter(receipts) {
  const copy = structuredClone(receipts);
  for (let i = 0; i < copy.length; i++) {
    for (const field of CONTENT_FIELDS) {
      const value = copy[i][field];
      if (typeof value !== 'string') continue;
      const pos = [...value].findIndex((c) => /[A-Za-z]/.test(c));
      if (pos < 0) continue;
      const ch = value[pos];
      const upper = ch === ch.toUpperCase();
      const swap = ch.toLowerCase() === 'a' ? 'e' : 'a';
      copy[i][field] = value.slice(0, pos) + (upper ? swap.toUpperCase() : swap) + value.slice(pos + 1);
      return { receipts: copy, index: i, field, before: value, after: copy[i][field] };
    }
  }
  throw new Error('no tamperable content field found in the chain');
}

async function main() {
  for (const built of [CONSOLE, VERIFY]) {
    if (!existsSync(built)) {
      console.error(red(`Not built: ${path.relative(REPO, built)}`));
      console.error('Run:  npm install && npm run build');
      return 2;
    }
  }
  await rm(WORK, { recursive: true, force: true });
  await mkdir(WORK, { recursive: true });

  console.log(`\n${paint('1', 'GreenTeamGo — approve, sign, verify, tamper')}`);

  step(1, 'Starting the console (inbox API + approval page) on a free port');
  const port = await freePort();
  const base = `http://127.0.0.1:${port}`;
  const consoleProc = spawn(process.execPath, [CONSOLE], {
    cwd: REPO,
    // No OPENAI_API_KEY: the optional risk summary is fail-soft and the demo
    // must run offline.
    env: { ...process.env, PORT: String(port), OPENAI_API_KEY: '' },
    stdio: 'ignore',
  });
  try {
    await waitUntilUp(base, consoleProc);
    console.log(`  up at ${base}`);

    step(2, 'Replaying 20 agent actions: 14 reads (policy decides), 6 risky (a human decides)');
    const scenario = await runNode([SCENARIO], {
      env: { GTG_BASE_URL: base, GTG_OUT_DIR: WORK, GTG_DECIDER: 'demo-operator' },
    });
    if (scenario.code !== 0) {
      console.error(scenario.out);
      console.error(red('The scenario failed.'));
      return 3;
    }
    const metric = scenario.out.split('\n').find((l) => l.startsWith('METRIC'));
    console.log(`  ${metric ?? '(no metric line)'}`.split(' Re-verify:')[0]);

    step(3, 'Exported the signed chain and the workspace public key');
    const receipts = JSON.parse(await readFile(RECEIPTS, 'utf8'));
    console.log(`  ${receipts.length} receipts -> ${path.relative(REPO, RECEIPTS)}`);
    console.log(`  public key  -> ${path.relative(REPO, KEYS)}`);
  } finally {
    consoleProc.kill();
  }
  console.log(dim('  console stopped: from here on, verification is offline.'));

  step(4, 'Verify the untouched chain (expect PASS)');
  const clean = await runNode([VERIFY, RECEIPTS, KEYS]);
  process.stdout.write(`  ${clean.out}`);
  if (clean.code !== 0) {
    console.error(red('Unexpected: the real chain did not verify.'));
    return 4;
  }
  console.log(`  ${green('PASS')} — chain intact, every signature valid.`);

  step(5, 'Flip ONE character of one receipt, then verify again (expect FAIL)');
  const hit = tamperOneCharacter(JSON.parse(await readFile(RECEIPTS, 'utf8')));
  await writeFile(TAMPERED, JSON.stringify(hit.receipts, null, 2) + '\n');
  console.log(`  receipt #${hit.index}, field "${hit.field}": ${JSON.stringify(hit.before)}`);
  console.log(`  ${' '.repeat(String(hit.index).length + hit.field.length + 16)}-> ${JSON.stringify(hit.after)}`);
  console.log(dim('  signature and receipt_hash left byte-for-byte untouched'));
  const dirty = await runNode([VERIFY, TAMPERED, KEYS]);
  process.stdout.write(`  ${dirty.out}`);
  if (dirty.code === 0) {
    console.error(red('Unexpected: the tampered chain PASSED. That must never happen.'));
    return 5;
  }
  console.log(`  ${red('FAIL')} — the verifier rejected the edited chain (exit ${dirty.code}).`);

  console.log(
    `\n${green('Demo OK.')} The real chain verifies; one changed character is caught, offline, ` +
      'with only the public key.\n',
  );
  return 0;
}

// Only run when executed directly, so tests can import tamperOneCharacter.
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().then(
    (code) => process.exit(code),
    (err) => {
      console.error(red(`FATAL: ${err?.message ?? err}`));
      process.exit(1);
    },
  );
}
