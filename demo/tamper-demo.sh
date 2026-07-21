#!/usr/bin/env bash
# ============================================================================
# GreenTeamGo — the tamper-evidence "money shot"
#
#   GREEN  = the real exported receipt chain verifies, offline, with only the
#            workspace public key.
#   RED    = flip ONE character of a receipt's *content* (not the signature)
#            and the same verifier rejects the whole chain, non-zero exit.
#
# "Codex asks first, and every yes, no, and timeout becomes a signed,
#  tamper-evident receipt you can verify yourself."
#
# Runs in Git Bash on Windows. Re-runnable; cleans its temp files at start.
# ============================================================================
set -uo pipefail

# ── config (per the submission brief) ──────────────────────────────────────
REPO="D:/voriongit/greenteamgo"
BASE="http://localhost:4000"
AGENT_KEY="gtg_demo_agent_key"
CLI="$REPO/packages/core/dist/cli.js"

# Keep the repo clean: all scratch lands next to this script.
WORK="$(cd "$(dirname "$0")" && pwd)/tamper-demo-work"
RECEIPTS="$WORK/receipts.json"
KEYS_RAW="$WORK/keys.raw.json"
KEYS="$WORK/keys.json"
TAMPERED="$WORK/receipts.tampered.json"

# ── colors (only when writing to a real terminal / recording) ──────────────
if [ -t 1 ]; then
  GREEN=$'\033[1;32m'; RED=$'\033[1;31m'; CYAN=$'\033[1;36m'
  BOLD=$'\033[1m'; DIM=$'\033[2m'; NC=$'\033[0m'
else
  GREEN=""; RED=""; CYAN=""; BOLD=""; DIM=""; NC=""
fi
hr(){ printf '%s\n' "────────────────────────────────────────────────────────────"; }

# ── (0) clean up any prior run ─────────────────────────────────────────────
rm -rf "$WORK"
mkdir -p "$WORK"

# ── preflight ──────────────────────────────────────────────────────────────
if [ ! -f "$CLI" ]; then
  echo "${RED}Verifier not built:${NC} $CLI"
  echo "  Build it first:  (cd \"$REPO\" && npm run build)"
  exit 2
fi

echo
echo "${BOLD}GreenTeamGo — tamper-evidence demo${NC}"
echo "${DIM}verifier: node packages/core/dist/cli.js  <receipts.json> <keys.json>${NC}"
echo

# ── (1) export the live chain + the workspace public key ───────────────────
echo "${CYAN}[1/5] Exporting the chain from ${BASE} ...${NC}"
curl -fsS -H "Authorization: Bearer $AGENT_KEY" "$BASE/v1/receipts" -o "$RECEIPTS" || {
  echo "${RED}Could not reach $BASE/v1/receipts — is the console running (npm run dev)?${NC}"; exit 2; }
curl -fsS -H "Authorization: Bearer $AGENT_KEY" "$BASE/v1/keys" -o "$KEYS_RAW" || {
  echo "${RED}Could not reach $BASE/v1/keys${NC}"; exit 2; }

# /v1/keys returns {key_id, publicKeyPem}; the CLI wants a MAP {key_id: pem}.
node -e '
  const fs=require("fs");
  const k=JSON.parse(fs.readFileSync(process.argv[1],"utf8"));
  fs.writeFileSync(process.argv[2], JSON.stringify({ [k.key_id]: k.publicKeyPem }, null, 2));
' "$KEYS_RAW" "$KEYS"

N=$(node -e 'process.stdout.write(String(JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")).length))' "$RECEIPTS")
if [ "${N:-0}" -eq 0 ] 2>/dev/null; then
  echo "${RED}The chain is empty — run the 20-action fixture first, then re-run this.${NC}"; exit 2
fi
echo "  exported ${BOLD}${N}${NC} receipt(s)  ->  receipts.json"
echo "  exported workspace public key  ->  keys.json  (as a {key_id: pem} map)"

# ── (2) verify the UNTOUCHED chain — expect GREEN ──────────────────────────
echo
echo "${CYAN}[2/5] Verify the UNTOUCHED chain  (expect GREEN):${NC}"
hr
node "$CLI" "$RECEIPTS" "$KEYS"; code=$?
hr
if [ "$code" -ne 0 ]; then
  echo "${RED}Unexpected: the real chain failed to verify (exit $code).${NC}"; exit 3
fi
echo "${GREEN}${BOLD}  GREEN${NC} ${GREEN}— chain intact, every signature valid.${NC}"

# ── (3) flip ONE character of content (never the signature) ────────────────
echo
echo "${CYAN}[3/5] Tamper: flip ONE character inside a receipt's content...${NC}"
node -e '
  const fs=require("fs");
  const [src,dst]=process.argv.slice(1);
  const arr=JSON.parse(fs.readFileSync(src,"utf8"));
  // Human-readable, signed content fields — NOT sig / receipt_hash / prev_hash.
  const fields=["reason","summary","action_type","verdict","status"];
  let hit=null;
  outer:
  for (let i=0;i<arr.length;i++){
    for (const f of fields){
      const v=arr[i][f];
      if (typeof v==="string" && v.length>0){
        const j=[...v].findIndex(c=>/[A-Za-z]/.test(c));
        const pos=j>=0?j:0, ch=v[pos];
        // guaranteed-different replacement letter, keeps the JSON valid
        const rep = ch.toLowerCase()==="a"
          ? (ch===ch.toUpperCase()?"E":"e")
          : (ch===ch.toUpperCase()?"A":"a");
        arr[i][f]=v.slice(0,pos)+rep+v.slice(pos+1);
        hit={i,f,before:v,after:arr[i][f]};
        break outer;
      }
    }
  }
  if(!hit){console.error("no tamperable content field found");process.exit(9);}
  fs.writeFileSync(dst, JSON.stringify(arr,null,2));
  console.log("  receipt index : "+hit.i);
  console.log("  field         : "+hit.f);
  console.log("  before        : "+JSON.stringify(hit.before));
  console.log("  after         : "+JSON.stringify(hit.after));
  console.log("  signature + receipt_hash : left BYTE-FOR-BYTE untouched");
' "$RECEIPTS" "$TAMPERED"
if [ $? -ne 0 ]; then echo "${RED}tamper step failed${NC}"; exit 3; fi

# ── (4) re-verify the TAMPERED chain — expect RED ──────────────────────────
echo
echo "${CYAN}[4/5] Re-verify the SAME chain, one char flipped  (expect RED):${NC}"
hr
node "$CLI" "$TAMPERED" "$KEYS"; code=$?
hr
if [ "$code" -eq 0 ]; then
  echo "${RED}Unexpected: the tampered chain PASSED — that must never happen.${NC}"; exit 4
fi
echo "${RED}${BOLD}  RED${NC} ${RED}— verifier rejected the chain (exit $code): receipt_hash mismatch, content was tampered.${NC}"

# ── (5) framing for the camera ─────────────────────────────────────────────
echo
echo "${CYAN}[5/5] For the camera:${NC}"
echo "  ${GREEN}${BOLD}GREEN${NC}  the real exported chain  ->  \"OK: ${N} receipt(s) verified — chain intact, signatures valid.\""
echo "  ${RED}${BOLD}RED${NC}    one character flipped     ->  \"receipt_hash mismatch — content was tampered\", non-zero exit."
echo
echo "  ${DIM}No one edited a signature. Flipping a single byte of *content* is enough:"
echo "  the receipt no longer hashes to its sealed value, and anyone can catch it"
echo "  offline with just the public key. Tamper-evident — alteration, deletion, or"
echo "  reordering is detectable by anyone, offline, with only the public key.${NC}"
echo
