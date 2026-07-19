#!/usr/bin/env node
/**
 * greenteamgo-verify — verify a receipt chain without trusting the server.
 *
 * Usage:
 *   greenteamgo-verify <receipts.json> <pubkeys.json>
 *
 *   receipts.json : a single Receipt or an array of Receipts (a chain, in order)
 *   pubkeys.json  : { "<key_id>": "<public key PEM>", ... }
 *
 * Exit code 0 = chain verified, 1 = verification failed / bad input.
 */
import { readFileSync } from "node:fs";

import { verifyChain, type Receipt } from "./receipts.js";

function fail(msg: string): never {
  process.stderr.write(`greenteamgo-verify: ${msg}\n`);
  process.exit(1);
}

const [receiptsPath, keysPath] = process.argv.slice(2);
if (!receiptsPath || !keysPath) {
  fail("usage: greenteamgo-verify <receipts.json> <pubkeys.json>");
}

let receipts: Receipt[];
let keys: Record<string, string>;
try {
  const parsed = JSON.parse(readFileSync(receiptsPath, "utf8"));
  receipts = Array.isArray(parsed) ? parsed : [parsed];
} catch (err) {
  fail(`could not read/parse receipts: ${(err as Error).message}`);
}
try {
  keys = JSON.parse(readFileSync(keysPath, "utf8")) as Record<string, string>;
} catch (err) {
  fail(`could not read/parse pubkeys: ${(err as Error).message}`);
}

const result = verifyChain(receipts, (keyId) => keys[keyId]);
if (result.ok) {
  process.stdout.write(`OK: ${receipts.length} receipt(s) verified — chain intact, signatures valid.\n`);
  process.exit(0);
}
fail(result.reason ?? "verification failed");
