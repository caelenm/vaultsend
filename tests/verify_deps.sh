#!/usr/bin/env bash
# Verify the crates the vault feature's security rests on (VAULTS_PLAN.md §5.1):
#   1. each .crate in the local registry cache matches both Cargo.lock and the
#      checksum crates.io publishes for that version;
#   2. the branch adds no package to Cargo.lock;
#   3. the release binary builds with --locked, and its hash is printed to record.
# Needs network access (cargo fetch, crates.io API), python3 for the JSON, and a
# local `main` branch to compare against.
set -euo pipefail
cd "$(dirname "$0")/.."

LOCK=backend/Cargo.lock
REGISTRY="${CARGO_HOME:-$HOME/.cargo}/registry/cache"
CRATES="age age-core chacha20poly1305 scrypt x25519-dalek sha2 rand zeroize"
BASELINE_AGE=a07d86e4272c093c88caf7864a2d09af52a5159180848ca4832a3cdbd7d014d5
UA='vaultsend tests/verify_deps.sh (https://github.com/caelenm/vaultsend)'
failures=0

fail() { echo "FAIL: $1"; failures=$((failures + 1)); }

# Prints "version checksum" for a package in Cargo.lock.
lock_entry() {
    awk -v want="name = \"$1\"" '
        $0 == want { found = 1; next }
        found && /^version = / { gsub(/version = |"/, ""); version = $0; next }
        found && /^checksum = / { gsub(/checksum = |"/, ""); print version, $0; exit }
        found && /^$/ { exit }
    ' "$LOCK"
}

(cd backend && cargo fetch --locked)

printf '%-18s %-9s %-64s %s\n' crate version sha256 result
for name in $CRATES; do
    read -r version lock_sum < <(lock_entry "$name")
    if [ -z "${lock_sum:-}" ]; then
        fail "$name is not in $LOCK with a checksum"
        continue
    fi
    # shellcheck disable=SC2086 # the glob stands in for the registry's hashed folder
    file=$(ls $REGISTRY/*/"$name-$version.crate" 2>/dev/null | head -1)
    if [ -z "$file" ]; then
        fail "$name-$version.crate is not in the registry cache"
        continue
    fi
    local_sum=$(sha256sum "$file" | awk '{print $1}')
    api_sum=$(curl -fsS -A "$UA" "https://crates.io/api/v1/crates/$name/$version" |
        python3 -c 'import json, sys; print(json.load(sys.stdin)["version"]["checksum"])')
    sleep 1 # crates.io asks API clients for at most one request per second

    result=ok
    [ "$local_sum" = "$lock_sum" ] || { fail "$name: registry file differs from Cargo.lock"; result=MISMATCH; }
    [ "$local_sum" = "$api_sum" ] || { fail "$name: registry file differs from crates.io"; result=MISMATCH; }
    printf '%-18s %-9s %-64s %s\n' "$name" "$version" "$local_sum" "$result"
done

read -r _ age_sum < <(lock_entry age)
[ "$age_sum" = "$BASELINE_AGE" ] || fail "age checksum differs from the plan's baseline"

added=$(git diff main -- "$LOCK" | grep -c '^+\[\[package\]\]' || true)
if [ "$added" = 0 ]; then
    echo "Cargo.lock: no [[package]] added compared to main"
else
    fail "Cargo.lock adds $added package(s) compared to main"
fi

(cd backend && cargo build --release --locked)
echo "release binary ($(rustc --version)):"
sha256sum backend/target/release/vaultsend-backend

if [ "$failures" -ne 0 ]; then
    echo "$failures check(s) FAILED"
    exit 1
fi
echo "All dependency checks passed."
