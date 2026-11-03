#!/usr/bin/env bash
# End-to-end test of the vault commands against the release binary (VAULTS_PLAN.md
# §5.2). Everything lives in a fresh temp dir under /tmp, with HOME and XDG dirs
# pointing into it, so the real key and config are out of reach. /tmp rather than the
# repo because DrvFs under /mnt/c ignores 0600, which would make permission checks
# lie. Secrets go over --pass-fd from a here-string, never argv.
set -uo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BIN=${VAULTSEND_BACKEND:-$ROOT/backend/target/release/vaultsend-backend}
[ -x "$BIN" ] || { echo "no backend at $BIN; run: cargo build --release --locked"; exit 2; }

T=$(mktemp -d /tmp/vaultsend-roundtrip-XXXXXX) || exit 2
trap 'rm -rf "$T"' EXIT
export HOME="$T/home" XDG_DATA_HOME="$T/data" XDG_CONFIG_HOME="$T/config"
mkdir -p "$HOME" "$XDG_DATA_HOME" "$XDG_CONFIG_HOME"

ID_PASS='roundtrip identity passphrase'
VAULT_PASS='roundtrip vault password'
passed=0
failed=0

ok() { passed=$((passed + 1)); echo "ok    $1"; }
bad() { failed=$((failed + 1)); echo "FAIL  $1"; }
check() { local what=$1; shift; if "$@"; then ok "$what"; else bad "$what"; fi; }

# The backend, with the current vault and secret. Fails nothing by itself.
vault() {
    local cmd=$1; shift
    "$BIN" "$cmd" --dir "$V" "$@" --pass-fd 3 3<<<"$SECRET"
}

# Every file's hash plus the full folder list, so an empty folder counts too.
tree_digest() {
    (
        cd "$1" || exit 1
        find . -type f -print0 | LC_ALL=C sort -z | xargs -0 -r sha256sum
        find . -type d -print0 | LC_ALL=C sort -z | tr '\0' '\n'
    )
}

same_tree() { [ "$(tree_digest "$1")" = "$(tree_digest "$2")" ]; }

# Non-zero exit AND no output path, not even a staging file.
refuses_and_writes_nothing() {
    local what=$1 out=$2; shift 2
    if "$@" 2>"$T/err"; then
        bad "$what: should have failed"
    elif [ -e "$out" ] || [ -e "$out.vaultsend-part" ]; then
        bad "$what: left output behind"
    else
        ok "$what  [$(head -c 90 "$T/err" | tail -n 1)]"
    fi
}

flip_byte() {
    python3 -c 'import sys
p = sys.argv[1]
b = bytearray(open(p, "rb").read())
b[len(b) // 2] ^= 1
open(p, "wb").write(b)' "$1"
}

nth_blob() { find "$V/blobs" -name '*.age' | LC_ALL=C sort | sed -n "$1p"; }

# ---------------------------------------------------------------------------
# Test tree: nested folders, an empty folder, an empty file, a 1-byte file, a
# 3 MiB random binary, a file of exactly one age chunk, awkward names.
# ---------------------------------------------------------------------------
SRC="$T/src/tree"
mkdir -p "$SRC/nested/deeper/deepest" "$SRC/empty-folder" "$SRC/with space/ünï"
: >"$SRC/empty.txt"
printf x >"$SRC/one-byte.bin"
head -c 3145728 /dev/urandom >"$SRC/nested/random-3mib.bin"
head -c 65536 /dev/urandom >"$SRC/nested/deeper/exactly-64k.bin"
echo leaf >"$SRC/nested/deeper/deepest/leaf.txt"
echo spaces >"$SRC/with space/a file.txt"
echo unicode >"$SRC/with space/ünï/snow ☃.txt"
echo percent >"$SRC/100%done %20.txt"
echo dash >"$SRC/-dash.txt"
echo newline >"$SRC/new
line.txt"

# ---------------------------------------------------------------------------
echo "== 1. keygen and the existing encrypt/decrypt path still work"
# ---------------------------------------------------------------------------
PUBKEY=$("$BIN" keygen --pass-fd 3 3<<<"$ID_PASS") || { bad "keygen"; exit 1; }
ok "keygen"
"$BIN" encrypt -r "$PUBKEY" --in "$SRC/nested/random-3mib.bin" --out "$T/regress.age"
"$BIN" decrypt --pass-fd 3 --in "$T/regress.age" --out "$T/regress.out" 3<<<"$ID_PASS"
check "existing file encrypt/decrypt round trip" cmp -s "$SRC/nested/random-3mib.bin" "$T/regress.out"
printf 'text path' | "$BIN" encrypt -r "$PUBKEY" --armor >"$T/regress.asc"
check "existing armored text round trip" \
    [ "$("$BIN" decrypt --pass-fd 3 --in "$T/regress.asc" 3<<<"$ID_PASS")" = "text path" ]

# ---------------------------------------------------------------------------
# Steps 2-6, once per mode.
# ---------------------------------------------------------------------------
for MODE in self password; do
    if [ "$MODE" = self ]; then
        SECRET=$ID_PASS WRONG='not the identity passphrase'
    else
        SECRET=$VAULT_PASS WRONG='not the vault password'
    fi
    V="$T/$MODE.vsvault"
    W="$T/work-$MODE"
    mkdir -p "$W"

    echo "== 2. [$MODE] create, add, list, extract: extracted tree identical"
    check "vault-create" "$BIN" vault-create --dir "$V" --mode "$MODE" --pass-fd 3 3<<<"$SECRET"
    check "VAULT file says $MODE" grep -qx "mode $MODE" "$V/VAULT"
    check "vault-add the tree" vault vault-add --src "$SRC"
    [ -z "$(find "$V" -type f -perm /077)" ] && ok "every vault file is 0600" || bad "a vault file is group/world accessible"

    LIST=$(vault vault-list)
    check "vault-list: generation 1" grep -qx 'generation 1' <<<"$LIST"
    check "vault-list: empty folder" grep -qx 'D tree/empty-folder' <<<"$LIST"
    check "vault-list: empty file, size 0" grep -qx 'F 0 tree/empty.txt' <<<"$LIST"
    check "vault-list: chunk-boundary size" grep -qx 'F 65536 tree/nested/deeper/exactly-64k.bin' <<<"$LIST"
    check "vault-list: escaped name" grep -qx 'F 8 tree/100%25done%20%2520.txt' <<<"$LIST"
    check "vault-list: names and sizes only" \
        [ "$(grep -cvE '^(generation [0-9]+|D [^ ]+|F [0-9]+ [^ ]+)$' <<<"$LIST")" = 0 ]

    check "vault-extract the root" vault vault-extract --entry / --out "$W/all"
    check "extracted tree matches the original" same_tree "$SRC" "$W/all/tree"
    check "vault-check is clean" vault vault-check >/dev/null
    refuses_and_writes_nothing "wrong secret refused" "$W/nope" \
        "$BIN" vault-extract --dir "$V" --entry / --out "$W/nope" --pass-fd 3 3<<<"$WRONG"

    echo "== 3. [$MODE] remove one file, the others stay identical"
    before=$(find "$V/blobs" -name '*.age' -exec sha256sum {} + | LC_ALL=C sort)
    check "vault-remove" vault vault-remove --entry "tree/one-byte.bin"
    after=$(find "$V/blobs" -name '*.age' -exec sha256sum {} + | LC_ALL=C sort)
    check "exactly one blob went away, the rest are byte-identical" \
        [ "$(comm -23 <(echo "$before") <(echo "$after") | wc -l)$(comm -13 <(echo "$before") <(echo "$after") | wc -l)" = 10 ]
    check "vault-extract after remove" vault vault-extract --entry / --out "$W/after-remove"
    cp -a "$SRC" "$W/expected"
    rm "$W/expected/one-byte.bin"
    check "tree matches, less the removed file" same_tree "$W/expected" "$W/after-remove/tree"

    echo "== 4. [$MODE] replace one file"
    mkdir -p "$W/new"
    echo 'brand new contents' >"$W/new/leaf.txt"
    refuses_and_writes_nothing "add over an existing name, without --replace" "$W/unused" \
        vault vault-add --src "$W/new/leaf.txt" --dest tree/nested/deeper/deepest
    check "vault-add --replace" vault vault-add --src "$W/new/leaf.txt" --dest tree/nested/deeper/deepest --replace
    check "vault-extract the replaced file" vault vault-extract --entry tree/nested/deeper/deepest/leaf.txt --out "$W/leaf.out"
    check "it has the new contents" cmp -s "$W/new/leaf.txt" "$W/leaf.out"
    check "generation counted every change" grep -qx 'generation 3' <<<"$(vault vault-list)"

    echo "== 5. [$MODE] tampering: non-zero exit and no output"
    # A good copy with an older manifest kept aside, to restore between cases.
    cp "$V/manifest.age" "$W/manifest.gen3"
    echo 'another version' >"$W/new/leaf.txt"
    vault vault-add --src "$W/new/leaf.txt" --dest tree/nested/deeper/deepest --replace
    GOOD="$W/good.vsvault"
    cp -a "$V" "$GOOD"
    restore() { rm -rf "$V"; cp -a "$GOOD" "$V"; }

    flip_byte "$(nth_blob 1)"
    refuses_and_writes_nothing "flipped byte in a blob" "$W/t1" vault vault-extract --entry / --out "$W/t1"
    refuses_and_writes_nothing "vault-check notices the flipped byte" "$W/t1" vault vault-check
    restore

    blob=$(nth_blob 2)
    head -c "$(($(stat -c %s "$blob") - 20))" "$blob" >"$blob.short" && mv "$blob.short" "$blob"
    refuses_and_writes_nothing "truncated blob" "$W/t2" vault vault-extract --entry / --out "$W/t2"
    restore

    a=$(nth_blob 1) b=$(nth_blob 2)
    mv "$a" "$a.swap" && mv "$b" "$a" && mv "$a.swap" "$b"
    refuses_and_writes_nothing "two blobs swapped" "$W/t3" vault vault-extract --entry / --out "$W/t3"
    restore

    rm "$(nth_blob 3)"
    refuses_and_writes_nothing "deleted blob" "$W/t4" vault vault-extract --entry / --out "$W/t4"
    refuses_and_writes_nothing "vault-check notices the deleted blob" "$W/t4" vault vault-check
    restore

    # The blob this older manifest pins was deleted when the file was replaced.
    cp "$W/manifest.gen3" "$V/manifest.age"
    refuses_and_writes_nothing "old manifest put back" "$W/t5" vault vault-extract --entry / --out "$W/t5"
    check "old manifest reports its lower generation" grep -qx 'generation 3' <<<"$(vault vault-list)"
    restore

    flip_byte "$V/manifest.age"
    refuses_and_writes_nothing "flipped byte in the manifest" "$W/t6" vault vault-extract --entry / --out "$W/t6"
    restore

    # key.age from another of the owner's own vaults is genuine, but can't read this one.
    "$BIN" vault-create --dir "$W/other.vsvault" --mode "$MODE" --pass-fd 3 3<<<"$SECRET"
    cp "$W/other.vsvault/key.age" "$V/key.age"
    refuses_and_writes_nothing "key.age from another vault" "$W/t7" vault vault-extract --entry / --out "$W/t7"
    restore

    echo "== 6. [$MODE] vault-check after repair"
    check "vault-check is clean on the good vault" vault vault-check >/dev/null
    touch "$V/blobs/ab_not_a_blob"
    mkdir -p "$V/blobs/ab"
    echo stray >"$V/blobs/ab/abababababababababababababababab.age"
    check "vault-check reports the stray blob" grep -qx 'orphan blobs/ab/abababababababababababababababab.age' \
        <<<"$(vault vault-check 2>/dev/null)"
    check "a change collects the stray blob" vault vault-remove --entry tree/empty.txt
    check "stray blob is gone" [ ! -e "$V/blobs/ab/abababababababababababababababab.age" ]
    check "a file that isn't a blob is left alone" [ -e "$V/blobs/ab_not_a_blob" ]
done

# ---------------------------------------------------------------------------
echo "== other refusals"
# ---------------------------------------------------------------------------
SECRET=$ID_PASS
V="$T/self.vsvault"
mkdir -p "$T/links"
echo real >"$T/links/real.txt"
ln -s "$T/links/real.txt" "$T/links/link.txt"
mkfifo "$T/links/fifo"
vault vault-add --src "$T/links" 2>"$T/warn"
check "vault-add with specials exits 0" [ $? = 0 ]
check "skipped count on stderr" grep -q 'skipped 2 item' "$T/warn"
LIST=$(vault vault-list)
check "only the real file went in" [ "$(grep -c 'links/' <<<"$LIST")" = 1 ]
refuses_and_writes_nothing "output inside the vault" "$V/x" vault vault-extract --entry / --out "$V/x"
mkdir "$T/exists"
vault vault-extract --entry tree --out "$T/exists" 2>"$T/err"
check "folder extract refuses an existing path" [ $? != 0 ]
check "and leaves it untouched" [ -z "$(ls -A "$T/exists")" ]
refuses_a_full_folder() { ! "$BIN" vault-create --dir "$1" --mode self --pass-fd 3 3<<<"$ID_PASS" 2>/dev/null; }
check "create refuses a non-empty folder" refuses_a_full_folder "$T/links"
check "and leaves it untouched" [ -e "$T/links/real.txt" ]

# ---------------------------------------------------------------------------
echo "== forgeries: write access to the folder and only the owner's public key"
# ---------------------------------------------------------------------------
SECRET=$ID_PASS
V="$T/self.vsvault"
SEALED="$T/sealed-key.age"
cp "$V/key.age" "$SEALED"
check "key.age is sealed" grep -qa '^-> scrypt ' "$SEALED"
check "and not wrapped to the public key" bash -c '! grep -qa "^-> X25519 " "$0"' "$SEALED"
BLOBS_BEFORE=$(tree_digest "$V")

# What used to open: a key wrapped to the owner's public key. "does not open with your
# key" shows it stopped at the seal, before the contents were even looked at.
printf 'a key the attacker knows' | "$BIN" encrypt -r "$PUBKEY" --out "$T/forged-key.age"
cp "$T/forged-key.age" "$V/key.age"
forged_is_refused() {
    local what=$1; shift
    if "$@" 2>"$T/err" >/dev/null; then
        bad "$what: should have failed"
    elif grep -q 'does not open with your key' "$T/err"; then
        ok "$what  [$(head -c 90 "$T/err")]"
    else
        bad "$what: wrong error: $(cat "$T/err")"
    fi
}
forged_is_refused "forged key.age: vault-list" vault vault-list
forged_is_refused "forged key.age: vault-check" vault vault-check
forged_is_refused "forged key.age: vault-extract" vault vault-extract --entry / --out "$T/forged-out"
check "and it wrote nothing" [ ! -e "$T/forged-out" ]
forged_is_refused "forged key.age: vault-add" vault vault-add --src "$T/links/real.txt" --dest stolen
cp "$SEALED" "$V/key.age"
[ "$(tree_digest "$V")" = "$BLOBS_BEFORE" ] && ok "the vault is byte-identical afterwards" || bad "the vault changed"

# Making a self vault takes the private key, not just the public one.
check "a self vault can't be made without the passphrase" bash -c '! "$0" vault-create --dir "$1" --mode self 2>/dev/null' "$BIN" "$T/nopass.vsvault"
check "and nothing is created" [ ! -e "$T/nopass.vsvault" ]

# Another person's seal: a real vault, made properly, by someone else with the same passphrase.
OTHER="$T/stranger"
mkdir -p "$OTHER"
XDG_DATA_HOME="$OTHER" "$BIN" keygen --pass-fd 3 3<<<"$ID_PASS" >/dev/null
XDG_DATA_HOME="$OTHER" "$BIN" vault-create --dir "$T/theirs.vsvault" --mode self --pass-fd 3 3<<<"$ID_PASS"
XDG_DATA_HOME="$OTHER" check "the stranger opens their own vault" "$BIN" vault-list --dir "$T/theirs.vsvault" --pass-fd 3 3<<<"$ID_PASS" >/dev/null
V="$T/theirs.vsvault"
forged_is_refused "a stranger's vault doesn't open for the owner" vault vault-list
V="$T/self.vsvault"
XDG_DATA_HOME="$OTHER" forged_is_refused "the owner's vault doesn't open for a stranger" vault vault-list

# scrypt costly enough to stall the app is refused by its work factor, not paid for.
cp "$T/password.vsvault/key.age" "$V/key.age"
forged_is_refused "a password vault's key.age in a self vault" vault vault-list
cp "$SEALED" "$V/key.age"

# The other way round: the VAULT file is only a hint, and flipping it opens nothing.
cp "$V/VAULT" "$T/VAULT.real"
printf 'vaultsend-vault 1\nmode password\n' >"$V/VAULT"
refuses_and_writes_nothing "mode flipped to password" "$T/flip-out" vault vault-extract --entry / --out "$T/flip-out"
cp "$T/VAULT.real" "$V/VAULT"

# Only the private key matters: no state on this device is involved.
SECOND="$T/second-device"
mkdir -p "$SECOND"
cp -a "$XDG_DATA_HOME/." "$SECOND/"
XDG_DATA_HOME="$SECOND" XDG_CONFIG_HOME="$T/second-config" check "the same key on another device opens it" vault vault-list >/dev/null

# ---------------------------------------------------------------------------
echo "== 7. (optional) strace: output opened only after every blob was read"
# ---------------------------------------------------------------------------
if command -v strace >/dev/null; then
    LOG="$T/strace.log"
    SECRET=$ID_PASS
    strace -f -e trace=openat,rename -o "$LOG" "$BIN" vault-extract --dir "$V" --entry / --out "$T/traced" --pass-fd 3 3<<<"$SECRET"
    last_blob=$(grep -n '/blobs/.*\.age"' "$LOG" | tail -1 | cut -d: -f1)
    first_out=$(grep -n "$T/traced" "$LOG" | head -1 | cut -d: -f1)
    if [ -n "$last_blob" ] && [ -n "$first_out" ] && [ "$last_blob" -lt "$first_out" ]; then
        ok "last blob opened at line $last_blob, output first touched at line $first_out"
    else
        bad "verify-before-write order (blob=$last_blob out=$first_out)"
    fi
else
    echo "skip  strace is not installed"
fi

echo
echo "$passed passed, $failed failed"
[ "$failed" = 0 ]
