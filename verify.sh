#!/usr/bin/env bash
# VaultSend — reproducible-build verifier
# Checks that the crypto bundle embedded in VaultSend_offline.html is
# byte-identical to a clean rebuild from the pinned upstream sources.
#
#   usage:  bash verify.sh path/to/VaultSend_offline.html
#   needs:  bash, python3, node, npm, sha256sum (or shasum on macOS)
#
# Every step prints its own status. If anything goes wrong you will see
# exactly which step failed and why — the script never silently exits.

# ── No set -e: we handle every error explicitly so nothing goes silent ────────
set -uo pipefail

EXP=2029930d2807bd3b37d5d4718194b77dd086ba7d420a18176cbdc616960c9eb2
PASS=0   # will stay 0 unless all checks succeed

# ── Colour helpers (suppressed if not a real terminal) ────────────────────────
if [ -t 1 ]; then
  RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[0;33m'; BLD='\033[1m'; RST='\033[0m'
else
  RED=''; GRN=''; YLW=''; BLD=''; RST=''
fi

ok()   { echo -e "${GRN}  [OK]${RST}  $*"; }
fail() { echo -e "${RED}  [FAIL]${RST} $*"; }
step() { echo -e "\n${BLD}── $* ──${RST}"; }
warn() { echo -e "${YLW}  [WARN]${RST} $*"; }

echo ""
echo -e "${BLD}VaultSend reproducible-build verifier${RST}"
echo "──────────────────────────────────────────"

# ── Step 0: argument check ────────────────────────────────────────────────────
step "0 / 5  Checking arguments"
HTML="${1:-}"
if [ -z "$HTML" ]; then
  fail "No HTML file given."
  echo "       usage:  bash verify.sh path/to/VaultSend_offline.html"
  exit 1
fi
if [ ! -f "$HTML" ]; then
  fail "File not found: $HTML"
  exit 1
fi
ok "Input file: $HTML"

# ── Step 1: prerequisite check ───────────────────────────────────────────────
step "1 / 5  Checking prerequisites"
PREREQ_OK=true

check_cmd() {
  local cmd="$1" label="${2:-$1}"
  if command -v "$cmd" >/dev/null 2>&1; then
    ok "$label found: $(command -v "$cmd")"
  else
    fail "$label not found — install it and re-run"
    PREREQ_OK=false
  fi
}
check_cmd python3  "python3"
check_cmd node     "node (Node.js)"
check_cmd npm      "npm"

# sha256sum (Linux) or shasum -a 256 (macOS)
if command -v sha256sum >/dev/null 2>&1; then
  SHA256="sha256sum"
  ok "sha256sum found: $(command -v sha256sum)"
elif command -v shasum >/dev/null 2>&1; then
  SHA256="shasum -a 256"
  ok "shasum found (macOS): $(command -v shasum)"
else
  fail "sha256sum / shasum not found — cannot hash files"
  PREREQ_OK=false
fi

if [ "$PREREQ_OK" != "true" ]; then
  echo ""
  fail "One or more prerequisites are missing. Install them and re-run."
  echo "      Debian/Ubuntu:  sudo apt install nodejs npm python3"
  echo "      macOS:          brew install node python3   (npm comes with node)"
  exit 1
fi

# ── Step 2: extract the embedded bundle ──────────────────────────────────────
step "2 / 5  Extracting embedded crypto bundle from HTML"
WORK="$(mktemp -d 2>/dev/null)" || { fail "Could not create temp directory"; exit 1; }
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

echo "       Temp dir: $WORK"

cat << 'PY' | python3 - "$HTML" "$WORK/embedded.js" 2>"$WORK/py_err.txt"
import sys, re
html_path, out_path = sys.argv[1], sys.argv[2]
b = open(html_path, "rb").read()
cs = [(m.start(), m.end()) for m in re.finditer(rb"<!--.*?-->", b, re.DOTALL)]
inc = lambda i: any(a <= i < c for a, c in cs)
pos = 0
found = False
while True:
    i = b.find(b"<script", pos)
    if i < 0: break
    if inc(i): pos = i + 7; continue
    gt = b.find(b">", i); j = b.find(b"</script>", gt + 1)
    open(out_path, "wb").write(b[gt+1:j])
    found = True
    break
if not found:
    print("ERROR: no inline <script> block found", file=sys.stderr)
    sys.exit(1)
PY
PY_RC=$?

if [ $PY_RC -ne 0 ]; then
  fail "Python extraction failed (exit $PY_RC)"
  if [ -s "$WORK/py_err.txt" ]; then
    echo "       python3 stderr:"; sed 's/^/         /' "$WORK/py_err.txt"
  fi
  exit 1
fi

if [ ! -s "$WORK/embedded.js" ]; then
  fail "Extracted bundle is empty — is this the right HTML file?"
  exit 1
fi

EMB_SIZE=$(wc -c < "$WORK/embedded.js" | tr -d ' ')
ok "Bundle extracted: $EMB_SIZE bytes"

EMB=$($SHA256 "$WORK/embedded.js" 2>/dev/null | awk '{print $1}')
if [ -z "$EMB" ]; then
  fail "sha256 of embedded bundle returned empty — hashing failed"
  exit 1
fi
ok "Embedded bundle SHA-256: $EMB"

# Early expected-hash check (no npm needed)
if [ "$EMB" = "$EXP" ]; then
  ok "Embedded hash matches the documented expected value ✓"
else
  warn "Embedded hash differs from the expected value"
  warn "  expected: $EXP"
  warn "  got     : $EMB"
  warn "  (continuing to attempt reproducible build for comparison)"
fi

# ── Step 3: npm install ───────────────────────────────────────────────────────
step "3 / 5  Installing pinned upstream packages (this may take a minute)"
echo "       age-encryption@0.2.4  fflate@0.8.2  esbuild@0.28.1"
echo "       @noble/ciphers@1.3.0  @noble/curves@1.9.7"
echo "       @noble/hashes@1.8.0   @scure/base@1.2.6"

cd "$WORK"
npm init -y >"$WORK/npm_init.log" 2>&1
INIT_RC=$?
if [ $INIT_RC -ne 0 ]; then
  fail "npm init failed (exit $INIT_RC)"
  echo "       npm init output:"; sed 's/^/         /' "$WORK/npm_init.log"
  exit 1
fi

cat > entry.js << 'JS'
import {generateIdentity,identityToRecipient,Encrypter,Decrypter,armor} from "age-encryption";
import {zipSync} from "fflate";
globalThis.__VS_AGE__={generateIdentity,identityToRecipient,Encrypter,Decrypter,armor};
globalThis.__VS_FFLATE__={zipSync};
JS

npm install \
    age-encryption@0.2.4 fflate@0.8.2 esbuild@0.28.1 \
    @noble/ciphers@1.3.0 @noble/curves@1.9.7 @noble/hashes@1.8.0 @scure/base@1.2.6 \
    >"$WORK/npm_install.log" 2>&1
NPM_RC=$?

if [ $NPM_RC -ne 0 ]; then
  fail "npm install failed (exit $NPM_RC)"
  echo ""
  echo "       ── npm output ──────────────────────────────────────────────"
  sed 's/^/       /' "$WORK/npm_install.log"
  echo "       ────────────────────────────────────────────────────────────"
  echo ""
  echo "       Common causes:"
  echo "         • No network / npm registry unreachable"
  echo "         • Proxy required (set npm config proxy)"
  echo "         • npm version too old:  npm --version  (need ≥ 8)"
  echo "         • Disk full in: $WORK"
  echo ""
  echo "       If you are in an air-gapped environment, you can do a"
  echo "       hash-only check instead:"
  echo "         expected: $EXP"
  echo "         embedded: $EMB"
  [ "$EMB" = "$EXP" ] && echo "         These match — the embedded bundle passes the hash check." \
                       || echo "         These differ — the embedded bundle does NOT match."
  exit 1
fi
ok "npm install complete"

# ── Step 4: rebuild with esbuild ─────────────────────────────────────────────
step "4 / 5  Rebuilding bundle with esbuild@0.28.1"
echo "       npx esbuild entry.js --bundle --format=iife --platform=browser \\"
echo "                            --target=es2020 --minify --legal-comments=none"

npx esbuild entry.js \
    --bundle --format=iife --platform=browser \
    --target=es2020 --minify --legal-comments=none \
    --outfile=rebuilt.js \
    >"$WORK/esbuild.log" 2>&1
EB_RC=$?

if [ $EB_RC -ne 0 ]; then
  fail "esbuild failed (exit $EB_RC)"
  echo "       ── esbuild output ──────────────────────────────────────────"
  sed 's/^/       /' "$WORK/esbuild.log"
  echo "       ────────────────────────────────────────────────────────────"
  exit 1
fi

if [ ! -s "$WORK/rebuilt.js" ]; then
  fail "esbuild produced an empty output file"
  exit 1
fi

REB_SIZE=$(wc -c < "$WORK/rebuilt.js" | tr -d ' ')
ok "Rebuilt bundle: $REB_SIZE bytes"

REB=$($SHA256 "$WORK/rebuilt.js" 2>/dev/null | awk '{print $1}')
if [ -z "$REB" ]; then
  fail "sha256 of rebuilt bundle returned empty — hashing failed"
  exit 1
fi
ok "Rebuilt bundle SHA-256: $REB"

# ── Step 5: compare ──────────────────────────────────────────────────────────
step "5 / 5  Comparing hashes"
echo ""
echo "  embedded bundle sha256 : $EMB"
echo "  rebuilt  bundle sha256 : $REB"
echo "  expected (pinned)      : $EXP"
echo ""

if [ "$EMB" != "$EXP" ]; then
  fail "Embedded bundle hash does NOT match the expected/pinned value"
  fail "The HTML file may have been tampered with."
  exit 1
fi

if [ "$REB" != "$EXP" ]; then
  fail "Rebuilt bundle hash does NOT match the expected value"
  fail "The build environment may have resolved different package versions."
  echo ""
  echo "       Verify your npm resolved the exact pinned versions:"
  echo "         npm ls --all | grep -E 'noble|scure|age|fflate|esbuild'"
  exit 1
fi

if cmp -s "$WORK/embedded.js" "$WORK/rebuilt.js"; then
  echo -e "${GRN}${BLD}"
  echo "  ✅  PASS"
  echo "      Embedded bundle is byte-identical to the pinned upstream rebuild."
  echo -e "${RST}"
  PASS=1
else
  fail "Hashes match but cmp found a byte difference — this should never happen."
  fail "Report this as a bug."
  exit 1
fi

[ "$PASS" -eq 1 ] && exit 0 || exit 1
