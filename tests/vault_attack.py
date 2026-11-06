#!/usr/bin/env python3
"""Attack the vault backend from outside, beyond tests/vault_roundtrip.sh: crashes at random
moments, a full disk, racing processes, symlink traps, special files, hostile vaults, argument
fuzzing and process hardening. If the `age` tool is on the PATH or passed with --age, the vault
format is also checked against that independent implementation, and hostile manifests are forged
with it. Standard library only. Everything lives under a fresh temp dir with HOME and the XDG
dirs pointing into it, so the real key and config are out of reach.

Usage: vault_attack.py BACKEND [--age DIR_WITH_AGE] [--only SECTION[,SECTION]] [--rounds N]
"""

import argparse
import base64
import hashlib
import hmac
import json
import os
import pty
import random
import re
import resource
import select
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("backend")
parser.add_argument("--age", default=None, help="folder holding age and age-keygen")
parser.add_argument("--only", default=None)
parser.add_argument("--rounds", type=int, default=20)
parser.add_argument("--in-namespace", action="store_true", help=argparse.SUPPRESS)
args = parser.parse_args()

BIN = str(Path(args.backend).resolve())
ID_PASS = "attack identity passphrase"
VAULT_PASS = "attack vault password"
AGE = shutil.which("age", path=args.age or os.environ.get("PATH"))
AGE_KEYGEN = shutil.which("age-keygen", path=args.age or os.environ.get("PATH"))
PART = ".vaultsend-part"

T = Path(tempfile.mkdtemp(prefix="vs-attack-", dir="/tmp"))
ENV = {
    "HOME": str(T / "home"), "XDG_DATA_HOME": str(T / "data"), "XDG_CONFIG_HOME": str(T / "config"),
    "PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C.UTF-8",
}
for d in (ENV["HOME"], ENV["XDG_DATA_HOME"], ENV["XDG_CONFIG_HOME"]):
    os.makedirs(d)

passed = failed = 0
notes = []


def check(condition, what, detail=""):
    global passed, failed
    if condition:
        passed += 1
        print(f"ok    {what}", flush=True)
    else:
        failed += 1
        print(f"FAIL  {what}{'  [' + str(detail)[:300] + ']' if detail else ''}", flush=True)
    return condition


def note(text):
    notes.append(text)
    print(f"note  {text}", flush=True)


def backend(*argv, secret=None, timeout=300, env=None):
    """Run the backend with a passphrase on a dedicated pipe, the way the app does."""
    cmd = [BIN, *map(str, argv)]
    fds = ()
    if secret is not None:
        r, w = os.pipe()
        os.write(w, secret.encode() if isinstance(secret, str) else secret)
        os.close(w)
        cmd += ["--pass-fd", str(r)]
        fds = (r,)
    try:
        return subprocess.run(cmd, pass_fds=fds, env=env or ENV, capture_output=True, text=True, timeout=timeout, errors="replace")
    finally:
        for fd in fds:
            os.close(fd)


def start(*argv, secret=None, **kw):
    cmd = [BIN, *map(str, argv)]
    r, w = os.pipe()
    os.write(w, secret.encode())
    os.close(w)
    cmd += ["--pass-fd", str(r)]
    p = subprocess.Popen(cmd, pass_fds=(r,), env=ENV, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, **kw)
    os.close(r)
    return p


def clean_failure(r):
    """Failed the way it's meant to: an error message, not a panic or a signal."""
    return r.returncode == 1 and "panicked" not in r.stderr and r.stderr.startswith("error:")


def tree_state(root):
    """Every file's hash and every folder, relative to root."""
    root = Path(root)
    state = {}
    for base, dirs, files in os.walk(root):
        rel = os.path.relpath(base, root)
        state[rel + "/"] = None
        for name in files:
            state[os.path.join(rel, name)] = hashlib.sha256(Path(base, name).read_bytes()).hexdigest()
    return state


def generation(vault, secret=ID_PASS):
    r = backend("vault-list", "--dir", vault, secret=secret)
    return int(r.stdout.split("\n")[0].split(" ")[1]) if r.returncode == 0 else None


def new_vault(name, mode="self", secret=ID_PASS):
    v = T / name
    r = backend("vault-create", "--dir", v, "--mode", mode, secret=secret)
    assert r.returncode == 0, r.stderr
    return v


def make_files(root, count, size=64):
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    for n in range(count):
        (root / f"file-{n:04}.bin").write_bytes(os.urandom(size))
    return root


def leftovers(root):
    return [str(p) for p in Path(root).rglob(f"*{PART}")]


# ---------------------------------------------------------------------------------------
def section_crash():
    print("== kill -9 at random moments: the vault is the old one or the new one, never a mix", flush=True)
    v = new_vault("crash.vsvault")
    assert backend("vault-add", "--dir", v, "--src", make_files(T / "crash-base", 10), secret=ID_PASS).returncode == 0
    source = make_files(T / "crash-batch" / "batch", 120, 2048)

    began = time.monotonic()
    r = backend("vault-add", "--dir", v, "--src", source, "--dest", "calibrate", secret=ID_PASS)
    assert r.returncode == 0, r.stderr
    full = time.monotonic() - began
    print(f"      an add takes {full:.2f}s here", flush=True)

    random.seed(20261103)
    add_ok = remove_ok = extract_ok = True
    committed = aborted = 0
    for n in range(args.rounds):
        before = generation(v)
        out_before = T / f"crash-before-{n}"
        assert backend("vault-extract", "--dir", v, "--entry", "/", "--out", out_before, secret=ID_PASS).returncode == 0
        state_before = tree_state(out_before)

        # Weighted to the end, past the scrypt, where the writing happens: some land after
        # the commit point, and some before.
        p = start("vault-add", "--dir", v, "--src", source, "--dest", f"round-{n}", secret=ID_PASS)
        time.sleep(random.uniform(full * 0.5, full * 1.15))
        p.kill()
        p.wait()

        after = generation(v)
        chk = backend("vault-check", "--dir", v, secret=ID_PASS)
        out_after = T / f"crash-after-{n}"
        ext = backend("vault-extract", "--dir", v, "--entry", "/", "--out", out_after, secret=ID_PASS)
        state_after = tree_state(out_after) if ext.returncode == 0 else None
        if after == before:
            aborted += 1
            good = state_after == state_before
        else:
            committed += 1
            expected = {os.path.normpath(k): d for k, d in state_before.items()}
            expected[f"round-{n}"] = None
            for path, digest in tree_state(source).items():
                expected[os.path.normpath(os.path.join(f"round-{n}/batch", path))] = digest
            got = {os.path.normpath(k): d for k, d in (state_after or {}).items()}
            good = after == before + 1 and got == expected
            if not good:
                print(f"      differs: {sorted(set(got.items()) ^ set(expected.items()))[:4]}", flush=True)
        if not (chk.returncode == 0 and good):
            add_ok = False
            print(f"      round {n}: before={before} after={after} check={chk.returncode} {chk.stderr[:200]} {ext.stderr[:200]}", flush=True)
        shutil.rmtree(out_before)
        shutil.rmtree(out_after, ignore_errors=True)
    check(add_ok, f"vault-add killed {args.rounds} times: every outcome complete ({aborted} kept the old vault, {committed} the new)")

    if committed + aborted:
        check(backend("vault-add", "--dir", v, "--src", make_files(T / "crash-after-add", 1), secret=ID_PASS).returncode == 0, "the next change works")
        chk = backend("vault-check", "--dir", v, secret=ID_PASS)
        check(chk.returncode == 0 and "orphan" not in chk.stdout, "and collects what the killed runs left", chk.stdout[-200:])

    # Removing: the same promise.
    r = backend("vault-list", "--dir", v, secret=ID_PASS)
    rounds = [line[2:] for line in r.stdout.split("\n") if line.startswith("D round-") and line.count("/") == 0]
    for n, entry in enumerate(rounds[: max(4, args.rounds // 3)]):
        before = generation(v)
        p = start("vault-remove", "--dir", v, "--entry", entry, secret=ID_PASS)
        time.sleep(random.uniform(0.2, 1.2))
        p.kill()
        p.wait()
        after = generation(v)
        listing = backend("vault-list", "--dir", v, secret=ID_PASS).stdout
        present = f"D {entry}\n" in listing
        chk = backend("vault-check", "--dir", v, secret=ID_PASS)
        if not (chk.returncode == 0 and ((after == before and present) or (after == before + 1 and not present))):
            remove_ok = False
            print(f"      remove {entry}: before={before} after={after} present={present} {chk.stderr[:200]}", flush=True)
    check(remove_ok, "vault-remove killed repeatedly: entry fully there or fully gone")

    # Extracting: the output is absent or complete, and a re-run clears the leftovers.
    want = None
    partial_seen = 0
    for n in range(max(5, args.rounds // 2)):
        out = T / f"crash-out-{n}"
        p = start("vault-extract", "--dir", v, "--entry", "/", "--out", out, secret=ID_PASS)
        time.sleep(random.uniform(0.3, 2.0))
        p.kill()
        p.wait()
        if out.exists():
            state = tree_state(out)
            want = want or state
            extract_ok = extract_ok and state == want
        if Path(str(out) + PART).exists():
            partial_seen += 1
            r = backend("vault-extract", "--dir", v, "--entry", "/", "--out", out, secret=ID_PASS)
            extract_ok = extract_ok and r.returncode == 0 and not Path(str(out) + PART).exists()
    check(extract_ok, "vault-extract killed repeatedly: output absent or complete, and a re-run clears leftovers")
    if partial_seen:
        note(f"a killed folder extract leaves decrypted files in <out>{PART} until re-run ({partial_seen} of the kills hit that window); expected, since a killed process can't clean up")

    # Creating: VAULT is the commit marker.
    created_ok = True
    for n in range(max(5, args.rounds // 2)):
        d = T / f"crash-create-{n}"
        p = start("vault-create", "--dir", d, "--mode", "password", secret=VAULT_PASS)
        time.sleep(random.uniform(0.0, 1.5))
        p.kill()
        p.wait()
        if (d / "VAULT").exists():
            created_ok = created_ok and backend("vault-check", "--dir", d, secret=VAULT_PASS).returncode == 0
        elif d.exists():
            created_ok = created_ok and clean_failure(backend("vault-list", "--dir", d, secret=VAULT_PASS))
    check(created_ok, "vault-create killed repeatedly: with VAULT it's complete; without, it's refused cleanly")


# ---------------------------------------------------------------------------------------
def section_disk():
    print("== a full disk (a small tmpfs in a private namespace)", flush=True)
    small = T / "small"
    small.mkdir()
    subprocess.run(["mount", "-t", "tmpfs", "-o", "size=4m", "tmpfs", str(small)], check=True)
    big = make_files(T / "disk-src", 1, 8 * 1024 * 1024)

    v = small / "v.vsvault"
    r = backend("vault-create", "--dir", v, "--mode", "password", secret=VAULT_PASS)
    check(r.returncode == 0, "a vault fits on the small disk", r.stderr)
    first = make_files(T / "disk-first", 3, 1024)
    assert backend("vault-add", "--dir", v, "--src", first, secret=VAULT_PASS).returncode == 0
    state = backend("vault-list", "--dir", v, secret=VAULT_PASS).stdout

    r = backend("vault-add", "--dir", v, "--src", big, secret=VAULT_PASS)
    check(clean_failure(r), "adding more than fits fails cleanly", r.stderr)
    check(backend("vault-list", "--dir", v, secret=VAULT_PASS).stdout == state, "and the vault hasn't changed")
    check(backend("vault-check", "--dir", v, secret=VAULT_PASS).returncode == 0, "and still verifies")
    check(not leftovers(small), "and no staging file is left", leftovers(small))
    r = subprocess.run(["df", "--output=used", str(small)], capture_output=True, text=True)
    used = int(r.stdout.split()[-1])
    check(used < 200, f"and its blobs were collected ({used} KB used)")

    # Squeeze the free space down so the failure lands on each later step in turn.
    filler = small / "filler"
    fd = os.open(filler, os.O_CREAT | os.O_WRONLY)
    try:
        while True:
            os.write(fd, b"\0" * 1024)
    except OSError:
        pass
    all_ok = True
    outcomes = {"added": 0, "refused": 0}
    size = os.path.getsize(filler)
    step_src = make_files(T / "disk-step", 1, 200)
    for n in range(40):
        size -= 256
        os.ftruncate(fd, max(0, size))
        before = generation(v, VAULT_PASS)
        r = backend("vault-add", "--dir", v, "--src", step_src / "file-0000.bin", "--dest", f"step{n}", secret=VAULT_PASS)
        after = generation(v, VAULT_PASS)
        chk = backend("vault-check", "--dir", v, secret=VAULT_PASS)
        if r.returncode == 0:
            outcomes["added"] += 1
            all_ok = all_ok and after == before + 1 and chk.returncode == 0
        else:
            outcomes["refused"] += 1
            all_ok = all_ok and clean_failure(r) and after == before and chk.returncode == 0
        if not all_ok:
            print(f"      step {n}: rc={r.returncode} {r.stderr[:200]} gen {before}->{after} check={chk.returncode} {chk.stderr[:200]}", flush=True)
            break
    os.close(fd)
    os.unlink(filler)
    check(all_ok, f"filling up byte by byte: always the old vault or the new one ({outcomes['added']} added, {outcomes['refused']} refused)")
    check(outcomes["refused"] > 0, "and the disk really did run out during that")

    # Extracting onto a full disk.
    home = new_vault("disk-home.vsvault", "password", VAULT_PASS)
    assert backend("vault-add", "--dir", home, "--src", big, secret=VAULT_PASS).returncode == 0
    out = small / "out"
    r = backend("vault-extract", "--dir", home, "--entry", big.name, "--out", out, secret=VAULT_PASS)
    check(clean_failure(r), "extracting a folder too big for the disk fails cleanly", r.stderr)
    check(not out.exists() and not leftovers(small), "and leaves nothing behind", leftovers(small))
    out = small / "one"
    r = backend("vault-extract", "--dir", home, "--entry", f"{big.name}/file-0000.bin", "--out", out, secret=VAULT_PASS)
    check(clean_failure(r), "extracting a file too big for the disk fails cleanly", r.stderr)
    check(not out.exists() and not leftovers(small), "and leaves nothing behind", leftovers(small))

    # Creating on a disk with no room.
    fill = small / "fill2"
    with open(fill, "wb") as f:
        try:
            while True:
                f.write(b"\0" * 65536)
                f.flush()
        except OSError:
            pass
    d = small / "new.vsvault"
    r = backend("vault-create", "--dir", d, "--mode", "password", secret=VAULT_PASS)
    check(clean_failure(r), "creating on a full disk fails cleanly", r.stderr)
    check(not d.exists(), "and removes what it started")
    subprocess.run(["umount", "-l", str(small)], check=False)


# ---------------------------------------------------------------------------------------
def section_race():
    print("== processes racing for one vault", flush=True)
    v = new_vault("race.vsvault", "password", VAULT_PASS)
    sources = [make_files(T / f"race-src-{n}", 3, 512) for n in range(12)]
    start_gen = generation(v, VAULT_PASS)
    procs = [start("vault-add", "--dir", v, "--src", s, secret=VAULT_PASS) for s in sources]
    results = [(p.wait(), p.stderr.read().decode(errors="replace")) for p in procs]
    wins = [n for n, (rc, _) in enumerate(results) if rc == 0]
    losers = [(rc, err) for rc, err in results if rc != 0]
    check(bool(wins), f"racing adds: {len(wins)} of {len(procs)} got the lock")
    check(all(rc == 1 and "another VaultSend operation" in err for rc, err in losers), "and every other one says the vault is busy", losers[:2])
    listing = backend("vault-list", "--dir", v, secret=VAULT_PASS).stdout
    check(generation(v, VAULT_PASS) == start_gen + len(wins), "the generation counted exactly the winners")
    check(all(f"D {sources[n].name}\n" in listing for n in wins), "every winner's files are there")
    check(all(f"D {sources[n].name}\n" not in listing for n in range(len(sources)) if n not in wins), "and no loser's")
    check(backend("vault-check", "--dir", v, secret=VAULT_PASS).returncode == 0, "and the vault verifies")

    # Serially from here, many adds while readers run: nothing ever reads a half-state.
    bad = []
    stop_at = time.monotonic() + 15
    readers = []
    n = 0
    writer = None
    while time.monotonic() < stop_at:
        if writer is None or writer.poll() is not None:
            n += 1
            writer = start("vault-add", "--dir", v, "--src", make_files(T / f"race-more-{n}", 2, 256), secret=VAULT_PASS)
        readers = [p for p in readers if p.poll() is None or p.returncode is None]
        reader = backend("vault-list", "--dir", v, secret=VAULT_PASS)
        if reader.returncode != 0 and "another VaultSend operation" not in reader.stderr:
            bad.append(reader.stderr)
    writer.wait()
    check(not bad, f"reads during {n} writes: each saw a whole vault, or was told it's busy", bad[:2])
    check(backend("vault-check", "--dir", v, secret=VAULT_PASS).returncode == 0, "and it still verifies")


# ---------------------------------------------------------------------------------------
def section_traps():
    print("== symlink traps at the output", flush=True)
    v = new_vault("trap.vsvault")
    src = T / "trap-src"
    (src / "sub").mkdir(parents=True)
    (src / "a.txt").write_text("vault contents\n")
    (src / "sub" / "b.txt").write_text("more vault contents\n")
    assert backend("vault-add", "--dir", v, "--src", src, secret=ID_PASS).returncode == 0
    entry = f"{src.name}/a.txt"
    victim = T / "victim.txt"
    victim.write_text("must not change\n")
    victim_dir = T / "victim-dir"
    victim_dir.mkdir()
    (victim_dir / "keep.txt").write_text("must not change\n")

    out = T / "trap-out-1"
    os.symlink(victim, str(out) + PART)
    r = backend("vault-extract", "--dir", v, "--entry", entry, "--out", out, secret=ID_PASS)
    check(r.returncode == 0 and out.read_text() == "vault contents\n", "a symlink at the file staging path is replaced", r.stderr)
    check(victim.read_text() == "must not change\n", "and not written through")

    out = T / "trap-out-2"
    os.symlink(victim, out)
    r = backend("vault-extract", "--dir", v, "--entry", entry, "--out", out, secret=ID_PASS)
    check(r.returncode == 0 and victim.read_text() == "must not change\n", "a symlink at --out isn't written through", r.stderr)
    check(not out.is_symlink() and out.read_text() == "vault contents\n", "it's replaced by the file")

    out = T / "trap-out-3"
    os.symlink(victim_dir, str(out) + PART)
    r = backend("vault-extract", "--dir", v, "--entry", src.name, "--out", out, secret=ID_PASS)
    check((victim_dir / "keep.txt").exists(), "a symlink at the folder staging path doesn't empty its target")
    check(not (victim_dir / "a.txt").exists(), "or get written through", r.stderr)
    check(r.returncode == 0 and (out / "a.txt").exists(), "and the extract still works", r.stderr)

    out = T / "trap-out-4"
    os.symlink(victim_dir, out)
    r = backend("vault-extract", "--dir", v, "--entry", src.name, "--out", out, secret=ID_PASS)
    check(clean_failure(r) and sorted(os.listdir(victim_dir)) == ["keep.txt"], "a symlink at a folder --out is refused, not followed", r.stderr)

    link = T / "into-vault"
    os.symlink(v, link)
    r = backend("vault-extract", "--dir", v, "--entry", entry, "--out", link / "x", secret=ID_PASS)
    check(clean_failure(r) and not (v / "x").exists(), "a path into the vault through a symlink is refused", r.stderr)

    out = T / "trap-dir"
    out.mkdir()
    (out / "keep.txt").write_text("keep\n")
    r = backend("vault-extract", "--dir", v, "--entry", entry, "--out", out, secret=ID_PASS)
    check(clean_failure(r) and (out / "keep.txt").exists() and not Path(str(out) + PART).exists(), "a folder at a file --out is refused, with no leftovers", r.stderr)

    readonly = T / "readonly"
    readonly.mkdir()
    os.chmod(readonly, 0o500)
    if os.access(readonly, os.W_OK):
        note("running with permission overrides, so the read-only folder case is skipped")
    else:
        r = backend("vault-extract", "--dir", v, "--entry", entry, "--out", readonly / "x", secret=ID_PASS)
        check(clean_failure(r), "extracting into a read-only folder fails cleanly", r.stderr)
    os.chmod(readonly, 0o700)

    print("== symlinks and odd files as sources", flush=True)
    outside = T / "outside-secret.txt"
    outside.write_text("should stay out\n")
    link_src = T / "link-src.txt"
    os.symlink(outside, link_src)
    r = backend("vault-add", "--dir", v, "--src", link_src, secret=ID_PASS)
    check(clean_failure(r), "--src that is itself a symlink is refused", r.stderr)
    d = T / "dir-with-loop"
    d.mkdir()
    os.symlink(d, d / "loop")
    (d / "real.txt").write_text("real\n")
    r = backend("vault-add", "--dir", v, "--src", d, secret=ID_PASS)
    listing = backend("vault-list", "--dir", v, secret=ID_PASS).stdout
    check(r.returncode == 0 and f"{d.name}/loop" not in listing and f"F 5 {d.name}/real.txt" in listing, "a symlink loop in a folder is skipped", r.stderr)

    names = T / "odd-names"
    names.mkdir()
    for name in ("--replace", "--dir", "-rf", "..hidden", "...", "a b", "tab\there", "new\nline", "quo'te\"", "back\\slash", "ünï ☃", "%2F", "%", "<b>&amp;<i>", "‮evil.txt", "x" * 255):
        (names / name).write_text(name)
    r = backend("vault-add", "--dir", v, "--src", names, secret=ID_PASS)
    check(r.returncode == 0, "awkward names go in", r.stderr)
    out = T / "odd-out"
    r = backend("vault-extract", "--dir", v, "--entry", "odd-names", "--out", out, secret=ID_PASS)
    check(r.returncode == 0 and tree_state(names) == tree_state(out), "and come back byte-identical", r.stderr)
    r = backend("vault-remove", "--dir", v, "--entry", "odd-names/--replace", secret=ID_PASS)
    check(r.returncode == 0 and "odd-names/--replace" not in backend("vault-list", "--dir", v, secret=ID_PASS).stdout, "a file called --replace is just a name", r.stderr)
    r = backend("vault-add", "--dir", v, "--src", names / "--dir", "--dest", "--dest", secret=ID_PASS)
    check(r.returncode == 0 and "D --dest\n" in backend("vault-list", "--dir", v, secret=ID_PASS).stdout, "and so is a folder called --dest", r.stderr)

    bad_name = T / "bad-utf8"
    os.mkdir(bad_name)
    with open(os.path.join(os.fsencode(bad_name), b"caf\xe9.txt"), "w") as f:
        f.write("x")
    before = generation(v)
    r = backend("vault-add", "--dir", v, "--src", bad_name, secret=ID_PASS)
    check(clean_failure(r) and generation(v) == before, "a non-UTF-8 name is refused and changes nothing", r.stderr)

    print("== special files inside a vault must not hang or crash it", flush=True)
    for name in ("VAULT", "key.age", "manifest.age"):
        victim_vault = T / f"fifo-{name}.vsvault"
        shutil.copytree(v, victim_vault)
        (victim_vault / name).unlink()
        os.mkfifo(victim_vault / name)
        try:
            r = backend("vault-list", "--dir", victim_vault, secret=ID_PASS, timeout=8)
            check(clean_failure(r), f"a FIFO at {name} is refused", r.stderr)
        except subprocess.TimeoutExpired:
            check(False, f"a FIFO at {name} is refused", "the backend hung")
        shutil.rmtree(victim_vault)

    victim_vault = T / "fifo-blob.vsvault"
    shutil.copytree(v, victim_vault)
    blob = next((victim_vault / "blobs").rglob("*.age"))
    blob.unlink()
    os.mkfifo(blob)
    try:
        r = backend("vault-check", "--dir", victim_vault, secret=ID_PASS, timeout=8)
        check(clean_failure(r), "a FIFO in place of a blob is refused", r.stderr)
    except subprocess.TimeoutExpired:
        check(False, "a FIFO in place of a blob is refused", "the backend hung")
    shutil.rmtree(victim_vault)

    for name, make in (
        ("key.age", lambda p: p.mkdir()),
        ("manifest.age", lambda p: p.mkdir()),
        ("VAULT", lambda p: p.mkdir()),
        ("key.age", lambda p: os.symlink("/nonexistent", p)),
        ("manifest.age", lambda p: os.symlink("/nonexistent", p)),
    ):
        victim_vault = T / "odd-file.vsvault"
        shutil.copytree(v, victim_vault)
        (victim_vault / name).unlink()
        make(victim_vault / name)
        r = backend("vault-list", "--dir", victim_vault, secret=ID_PASS, timeout=20)
        check(clean_failure(r), f"an odd {name} is refused cleanly", r.stderr)
        shutil.rmtree(victim_vault)

    for text in (b"", b"vaultsend-vault 1", b"vaultsend-vault 2\nmode self\n", b"vaultsend-vault 1\nmode root\n", b"\xff\xfe\x00garbage", b"vaultsend-vault 1\nmode self\nextra\n"):
        victim_vault = T / "odd-vault-file.vsvault"
        shutil.copytree(v, victim_vault)
        (victim_vault / "VAULT").write_bytes(text)
        r = backend("vault-list", "--dir", victim_vault, secret=ID_PASS, timeout=20)
        check(clean_failure(r), f"VAULT containing {text[:24]!r} is refused cleanly", r.stderr)
        shutil.rmtree(victim_vault)

    print("== mixing vaults", flush=True)
    a, b = new_vault("mix-a.vsvault"), new_vault("mix-b.vsvault")
    for vault, name in ((a, "from-a"), (b, "from-b")):
        (T / name).write_text(name)
        assert backend("vault-add", "--dir", vault, "--src", T / name, secret=ID_PASS).returncode == 0
    mixed = T / "mix-1.vsvault"
    shutil.copytree(a, mixed)
    shutil.copy(b / "manifest.age", mixed / "manifest.age")
    check(clean_failure(backend("vault-list", "--dir", mixed, secret=ID_PASS)), "another vault's manifest is refused")
    mixed = T / "mix-2.vsvault"
    shutil.copytree(a, mixed)
    blob_a = next((a / "blobs").rglob("*.age"))
    blob_b = next((b / "blobs").rglob("*.age"))
    target = mixed / blob_a.relative_to(a)
    shutil.copy(blob_b, target)
    check(clean_failure(backend("vault-check", "--dir", mixed, secret=ID_PASS)), "another vault's blob is refused")

    print("== permissions under umask 000", flush=True)
    old = os.umask(0)
    try:
        u = T / "umask.vsvault"
        r = backend("vault-create", "--dir", u, "--mode", "self", secret=ID_PASS)
        assert r.returncode == 0, r.stderr
        (T / "umask-src").mkdir()
        (T / "umask-src" / "f").write_text("x")
        assert backend("vault-add", "--dir", u, "--src", T / "umask-src", secret=ID_PASS).returncode == 0
        out = T / "umask-out"
        assert backend("vault-extract", "--dir", u, "--entry", "/", "--out", out, secret=ID_PASS).returncode == 0
        single = T / "umask-single"
        assert backend("vault-extract", "--dir", u, "--entry", "umask-src/f", "--out", single, secret=ID_PASS).returncode == 0
        def modes(root):
            found = []
            for base, dirs, files in os.walk(root):
                found.append((base, os.stat(base).st_mode & 0o777, 0o700))
                found += [(os.path.join(base, f), os.stat(os.path.join(base, f)).st_mode & 0o777, 0o600) for f in files]
            return found
        wrong = [m for m in modes(u) + modes(out) if m[1] != m[2]]
        check(not wrong, "every vault and extracted file is 0600, every folder 0700", wrong[:4])
        check(os.stat(single).st_mode & 0o777 == 0o600, "and a single extracted file is 0600")
    finally:
        os.umask(old)


# ---------------------------------------------------------------------------------------
def section_fuzz():
    print("== bad arguments and secrets never panic", flush=True)
    random.seed(7)
    v = new_vault("fuzz.vsvault", "password", VAULT_PASS)
    commands = ["vault-create", "vault-list", "vault-add", "vault-remove", "vault-extract", "vault-share", "vault-check", "vault-nonsense", "", "--help"]
    options = ["--dir", "--mode", "--pass-fd", "--src", "--dest", "--entry", "--out", "--replace", "--key-sha256", "--bogus", "-", "--"]
    values = [str(v), str(T / "missing"), "/", "", ".", "..", "../x", "a/../b", "self", "password", "root", "0", "1", "2", "3", "99", "-1", "99999999999999999999",
              "‮", "x" * 5000, "a" * 300 + "/b", "/dev/null", "/proc/self/mem", "%", "%2F", "é", "--replace", str(T)]
    panics = []
    unexpected = []
    runs = 500
    for _ in range(runs):
        argv = [random.choice(commands)]
        for _ in range(random.randint(0, 6)):
            argv.append(random.choice(options))
            if random.random() < 0.8:
                argv.append(random.choice(values))
        # Nothing here can touch anything but the throwaway dir, except reads of /dev/null
        # and /proc, and it never gets a secret, so scrypt is never reached.
        r = subprocess.run([BIN, *argv], env=ENV, capture_output=True, text=True, errors="replace", timeout=20, stdin=subprocess.DEVNULL)
        if "panicked" in r.stderr or r.returncode < 0 or r.returncode > 2:
            panics.append((argv, r.returncode, r.stderr[:160]))
        elif r.returncode not in (0, 1):
            unexpected.append((argv, r.returncode))
    check(not panics, f"{runs} random argument lists: no panic, no signal", panics[:3])
    if unexpected:
        note(f"exit codes other than 0 or 1: {unexpected[:3]}")

    for label, secret in (
        ("empty", b""), ("only a newline", b"\n"), ("not UTF-8", b"\xff\xfe\xfd"), ("with a NUL", b"pass\0word"),
        ("60 KB long", b"x" * 60_000),  # what fits in a pipe before anything is reading it
    ):
        r = backend("vault-list", "--dir", v, secret=secret, timeout=60)
        check(clean_failure(r), f"a secret that's {label} fails cleanly", r.stderr)
    for fd in ("0", "1", "2", "-1", "4096", "abc", ""):
        r = subprocess.run([BIN, "vault-list", "--dir", str(v), "--pass-fd", fd], env=ENV, capture_output=True, text=True, errors="replace", timeout=20, stdin=subprocess.DEVNULL)
        check(clean_failure(r), f"--pass-fd {fd!r} fails cleanly", r.stderr)
    r = backend("vault-create", "--dir", T / "short.vsvault", "--mode", "password", secret="short")
    check(clean_failure(r) and not (T / "short.vsvault").exists(), "a short vault password is refused", r.stderr)


# ---------------------------------------------------------------------------------------
def section_hardening():
    print("== process hardening, on a backend waiting for its secret", flush=True)
    r, w = os.pipe()
    v = new_vault("hard.vsvault", "password", VAULT_PASS)
    p = subprocess.Popen([BIN, "vault-list", "--dir", str(v), "--pass-fd", str(r)], pass_fds=(r,), env=ENV, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    os.close(r)
    time.sleep(0.5)
    try:
        cmdline = Path(f"/proc/{p.pid}/cmdline").read_bytes()
        check(VAULT_PASS.encode() not in cmdline, "the secret isn't on the command line")
        for name in ("mem", "environ", "maps"):
            try:
                Path(f"/proc/{p.pid}/{name}").open("rb").read(1)
                check(False, f"/proc/pid/{name} can't be read, even by the same user")
            except PermissionError:
                check(True, f"/proc/pid/{name} can't be read, even by the same user")
            except OSError as e:
                check(False, f"/proc/pid/{name} can't be read, even by the same user", e)
        limits = Path(f"/proc/{p.pid}/limits")
        try:
            core = next(l for l in limits.read_text().splitlines() if l.startswith("Max core file size"))
            check(core.split()[4] == "0", "core dumps are off", core)
        except PermissionError:
            note("/proc/pid/limits isn't readable here")
        status = Path(f"/proc/{p.pid}/status").read_text()
        locked = next((l for l in status.splitlines() if l.startswith("VmLck")), "")
        limit = resource.getrlimit(resource.RLIMIT_MEMLOCK)[0]
        kb = int(locked.split()[1]) if locked else 0
        if limit == resource.RLIM_INFINITY or limit >= 8192:
            check(kb > 0, f"the passphrase's buffer is locked out of swap before the secret arrives ({kb} kB, limit {limit})", locked)
        else:
            note(f"the limit on locked memory is too low to test locking here: {limit}")
    finally:
        os.write(w, VAULT_PASS.encode())
        os.close(w)
        p.wait()

    # A crash dumps nothing, even when core dumps are allowed for the parent.
    cwd = T / "core-test"
    cwd.mkdir()
    r2, w2 = os.pipe()
    def allow_core():
        resource.setrlimit(resource.RLIMIT_CORE, (resource.RLIM_INFINITY, resource.RLIM_INFINITY))
    p = subprocess.Popen([BIN, "vault-list", "--dir", str(v), "--pass-fd", str(r2)], pass_fds=(r2,), env=ENV, cwd=cwd, preexec_fn=allow_core, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    os.close(r2)
    time.sleep(0.3)
    # SIGABRT rather than SIGSEGV: Rust's runtime catches a SIGSEGV to report stack overflows.
    p.send_signal(signal.SIGABRT)
    p.wait(timeout=20)
    os.close(w2)
    check(p.returncode == -signal.SIGABRT and not list(cwd.iterdir()), "a crash leaves no core file", (p.returncode, list(cwd.iterdir())))


# ---------------------------------------------------------------------------------------
def section_leaks():
    print("== nothing readable left behind", flush=True)
    MARK_CONTENT = "PLAINTEXT-CONTENT-" + os.urandom(8).hex()
    MARK_NAME = "plaintext-name-" + os.urandom(8).hex()
    for mode, secret in (("self", ID_PASS), ("password", VAULT_PASS)):
        v = new_vault(f"leak-{mode}.vsvault", mode, secret)
        src = T / f"leak-src-{mode}" / MARK_NAME
        src.mkdir(parents=True)
        (src / f"{MARK_NAME}.txt").write_text(MARK_CONTENT)
        # A long run of a compressible pattern too, in case of anything size-revealing.
        (src / "big.bin").write_bytes(MARK_CONTENT.encode() * 2000)
        assert backend("vault-add", "--dir", v, "--src", src, secret=secret).returncode == 0
        out = T / f"leak-out-{mode}"
        assert backend("vault-extract", "--dir", v, "--entry", "/", "--out", out, secret=secret).returncode == 0
        assert backend("vault-check", "--dir", v, secret=secret).returncode == 0
        assert backend("vault-remove", "--dir", v, "--entry", f"{MARK_NAME}/big.bin", secret=secret).returncode == 0
        hits = []
        for base, dirs, files in os.walk(v):
            for name in dirs + files:
                if MARK_NAME in name:
                    hits.append(name)
            for name in files:
                data = Path(base, name).read_bytes()
                if MARK_CONTENT.encode() in data or MARK_NAME.encode() in data or secret.encode() in data:
                    hits.append(os.path.join(base, name))
        check(not hits, f"[{mode}] no name, content or secret in any vault file", hits[:3])

        public = [p for p in v.rglob("*") if p.is_file() and b"age1" in p.read_bytes() and b"-> X25519" not in p.read_bytes()[:400]]
        check(not public, f"[{mode}] no public key sits in the clear in the vault", public[:2])

    scanned = hits = 0
    skip = {str(T / f"leak-src-{m}") for m in ("self", "password")} | {str(T / f"leak-out-{m}") for m in ("self", "password")}
    for root in (ENV["HOME"], ENV["XDG_DATA_HOME"], ENV["XDG_CONFIG_HOME"]):
        for base, _dirs, files in os.walk(root):
            for name in files:
                scanned += 1
                data = Path(base, name).read_bytes()
                if MARK_CONTENT.encode() in data or MARK_NAME.encode() in data or ID_PASS.encode() in data or VAULT_PASS.encode() in data:
                    hits += 1
    check(hits == 0, f"nothing in the data, config or home dirs ({scanned} files read)")


# ---------------------------------------------------------------------------------------
def age_tty(argv, passphrase, timeout=120):
    """age reads a passphrase only from a terminal, so give it one."""
    pid, fd = pty.fork()
    if pid == 0:
        os.execve(argv[0], argv, ENV)
    output = b""
    sent = False
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        ready, _, _ = select.select([fd], [], [], 1)
        if ready:
            try:
                chunk = os.read(fd, 4096)
            except OSError:
                break
            if not chunk:
                break
            output += chunk
            if not sent and b"passphrase" in output.lower():
                os.write(fd, passphrase.encode() + b"\n")
                sent = True
    _, status = os.waitpid(pid, 0)
    os.close(fd)
    return os.waitstatus_to_exitcode(status), output.decode(errors="replace")


def age_decrypt_scrypt(path, passphrase):
    out = T / f"age-out-{os.urandom(4).hex()}"
    rc, text = age_tty([AGE, "-d", "-o", str(out), str(path)], passphrase)
    assert rc == 0, f"age couldn't open {path}: {text}"
    data = out.read_bytes()
    out.unlink()
    return data


def age_decrypt_identity(path, identity_file):
    r = subprocess.run([AGE, "-d", "-i", str(identity_file), str(path)], capture_output=True, env=ENV)
    assert r.returncode == 0, f"age couldn't open {path}: {r.stderr.decode()}"
    return r.stdout


def vault_identity_with_age(v, mode):
    """The vault's secret key, reached with age alone and what the format says."""
    wrapped = (v / "key.age").read_bytes()
    if mode == "password":
        return age_decrypt_scrypt(v / "key.age", VAULT_PASS).decode().strip()
    private = age_decrypt_scrypt(Path(ENV["XDG_DATA_HOME"]) / "vaultsend" / "identity.age", ID_PASS).decode().strip()
    if b"-> scrypt" in wrapped.split(b"---")[0]:
        return age_decrypt_scrypt(v / "key.age", "vaultsend-vault-key-1:" + private).decode().strip()
    idfile = T / "owner.key"
    idfile.write_text(private + "\n")
    os.chmod(idfile, 0o600)
    return age_decrypt_identity(v / "key.age", idfile).decode().strip()


def section_format():
    print("== the format, read by an independent implementation (age " + (subprocess.run([AGE, "--version"], capture_output=True, text=True).stdout.strip() if AGE else "missing") + ")", flush=True)
    if not AGE:
        note("age isn't available, so the format wasn't checked independently")
        return
    for mode, secret in (("self", ID_PASS), ("password", VAULT_PASS)):
        v = new_vault(f"fmt-{mode}.vsvault", mode, secret)
        src = T / f"fmt-src-{mode}"
        (src / "sub dir" / "deep").mkdir(parents=True)
        (src / "empty").mkdir()
        (src / "sub dir" / "a b.txt").write_text("hello age\n")
        (src / "sub dir" / "deep" / "ünï.bin").write_bytes(os.urandom(70000))
        (src / "zero").write_bytes(b"")
        assert backend("vault-add", "--dir", v, "--src", src, secret=secret).returncode == 0

        check((v / "VAULT").read_text() == f"vaultsend-vault 1\nmode {mode}\n", f"[{mode}] VAULT is exactly as documented")
        identity = vault_identity_with_age(v, mode)
        check(identity.startswith("AGE-SECRET-KEY-1"), f"[{mode}] key.age opens with age and holds an age identity")
        idfile = T / f"fmt-{mode}.key"
        idfile.write_text(identity + "\n")
        os.chmod(idfile, 0o600)

        text = age_decrypt_identity(v / "manifest.age", idfile).decode()
        lines = text.split("\n")
        check(lines[0] == "vaultsend-manifest 1" and lines[-1] == "" and re.fullmatch(r"generation \d+", lines[1]) is not None, f"[{mode}] manifest.age opens with age; its header is as documented")
        records = lines[2:-1]
        dirs, files = {}, {}
        good = True
        from urllib.parse import unquote
        for line in records:
            fields = line.split(" ")
            if fields[0] == "D" and len(fields) == 2:
                dirs[unquote(fields[1])] = True
            elif fields[0] == "F" and len(fields) == 5 and re.fullmatch("[0-9a-f]{32}", fields[1]) and re.fullmatch("[0-9a-f]{64}", fields[2]):
                files[unquote(fields[4])] = (fields[1], fields[2], int(fields[3]))
            else:
                good = False
        check(good and records == sorted(records, key=lambda l: l.split(" ")[-1].encode()) or good, f"[{mode}] every record has the documented shape")

        matched = True
        blobs_seen = set()
        for path, (blob, digest, size) in files.items():
            file = v / "blobs" / blob[:2] / f"{blob}.age"
            blobs_seen.add(file)
            data = file.read_bytes()
            plain = age_decrypt_identity(file, idfile)
            expected = (src.parent / path).read_bytes()
            matched = matched and hashlib.sha256(data).hexdigest() == digest and plain == expected and len(plain) == size
        check(matched and len(files) == 3, f"[{mode}] every blob has its pinned hash, opens with age, and equals the original")
        on_disk = {p for p in (v / "blobs").rglob("*") if p.is_file()}
        check(on_disk == blobs_seen, f"[{mode}] nothing else is stored under blobs/")
        check(all(ancestor in dirs for path in list(dirs) + list(files) for ancestor in [path[:i] for i, c in enumerate(path) if c == "/"]), f"[{mode}] every parent is a recorded folder")

    # Hostile manifests, forged with the password of a vault shared by an attacker.
    print("== hostile vaults: the sharer knows the password and writes whatever they like", flush=True)
    v = new_vault("hostile.vsvault", "password", VAULT_PASS)
    (T / "h.txt").write_text("real\n")
    assert backend("vault-add", "--dir", v, "--src", T / "h.txt", secret=VAULT_PASS).returncode == 0
    identity = age_decrypt_scrypt(v / "key.age", VAULT_PASS).decode().strip()
    idfile = T / "hostile.key"
    idfile.write_text(identity + "\n")
    os.chmod(idfile, 0o600)
    recipient = subprocess.run([AGE_KEYGEN, "-y", str(idfile)], capture_output=True, text=True, env=ENV).stdout.strip()
    real = age_decrypt_identity(v / "manifest.age", idfile).decode()
    f_line = next(l for l in real.split("\n") if l.startswith("F "))
    _, BLOB, SHA, SIZE, _ = f_line.split(" ")

    def forge(body, name="hostile-try.vsvault"):
        target = T / name
        shutil.rmtree(target, ignore_errors=True)
        shutil.copytree(v, target)
        plain = T / "forged-manifest"
        plain.write_bytes(body if isinstance(body, bytes) else body.encode())
        out = target / "manifest.age"
        out.unlink()
        r = subprocess.run([AGE, "-r", recipient, "-o", str(out), str(plain)], capture_output=True, env=ENV)
        assert r.returncode == 0, r.stderr
        return target

    head = "vaultsend-manifest 1\ngeneration 5\n"
    sentinel_root = T / "hostile-sandbox"
    sentinel_root.mkdir()
    refused = {
        "a parent-directory path": f"F {BLOB} {SHA} 5 ../evil\n",
        "a deep parent-directory path": f"D a\nF {BLOB} {SHA} 5 a/../../evil\n",
        "an absolute path": f"F {BLOB} {SHA} 5 /tmp/evil\n",
        "an escaped parent path": f"F {BLOB} {SHA} 5 %2E%2E/evil\n",
        "an escaped separator": f"F {BLOB} {SHA} 5 a%2Fb\n",
        "an escaped NUL": f"F {BLOB} {SHA} 5 a%00b\n",
        "a lowercase escape": f"F {BLOB} {SHA} 5 a%2fb\n",
        "an unescaped space": f"F {BLOB} {SHA} 5 a b\n",
        "a bare dot": f"F {BLOB} {SHA} 5 .\n",
        "an empty component": f"D a\nF {BLOB} {SHA} 5 a//b\n",
        "a trailing slash": f"D a/\n",
        "a missing parent": f"F {BLOB} {SHA} 5 missing/x\n",
        "a file used as a folder": f"F {BLOB} {SHA} 5 a\nF {BLOB} {SHA} 5 a/b\n",
        "a duplicate path": f"F {BLOB} {SHA} 5 a\nF {BLOB} {SHA} 5 a\n",
        "a file and folder with one name": f"D a\nF {BLOB} {SHA} 5 a\n",
        "an overlong path": f"F {BLOB} {SHA} 5 {'x/' * 3000}x\n",
        "an overlong name": f"F {BLOB} {SHA} 5 {'x' * 256}\n",
        "a blob id with a path in it": f"F ../../../../../../etc/passwd {SHA} 5 a\n",
        "an uppercase blob id": f"F {BLOB.upper()} {SHA} 5 a\n",
        "a short hash": f"F {BLOB} abc 5 a\n",
        "a negative size": f"F {BLOB} {SHA} -5 a\n",
        "a padded size": f"F {BLOB} {SHA} 05 a\n",
        "a size past u64": f"F {BLOB} {SHA} 18446744073709551616 a\n",
        "an unknown record": "X nonsense\n",
        "CRLF line endings": "D a\r\n",
        "extra fields": f"F {BLOB} {SHA} 5 a extra\n",
    }
    for label, body in refused.items():
        target = forge(head + body)
        listed = backend("vault-list", "--dir", target, secret=VAULT_PASS)
        out = sentinel_root / "out"
        extracted = backend("vault-extract", "--dir", target, "--entry", "/", "--out", out, secret=VAULT_PASS)
        escaped = list(sentinel_root.iterdir()) or (T / "evil").exists() or Path("/tmp/evil").exists()
        check(clean_failure(listed) and clean_failure(extracted) and not escaped, f"{label} is refused, and nothing is written", (listed.stderr, extracted.stderr, escaped))
        if escaped:
            shutil.rmtree(sentinel_root, ignore_errors=True)
            sentinel_root.mkdir()

    for label, text in (
        ("no magic", "generation 5\n"),
        ("a future version", "vaultsend-manifest 2\ngeneration 5\n"),
        ("no final newline", head.rstrip("\n")),
        ("a padded generation", "vaultsend-manifest 1\ngeneration 05\n"),
        ("a generation past u64", "vaultsend-manifest 1\ngeneration 18446744073709551616\n"),
        ("not UTF-8", b"vaultsend-manifest 1\ngeneration 5\n\xff\xfe\n"),
    ):
        r = backend("vault-list", "--dir", forge(text), secret=VAULT_PASS)
        check(clean_failure(r), f"a manifest with {label} is refused", r.stderr)

    # Allowed by the format, and must stay harmless.
    target = forge(f"vaultsend-manifest 1\ngeneration 18446744073709551615\nF {BLOB} {SHA} {SIZE} a\n")
    before = (target / "manifest.age").read_bytes()
    (T / "more.txt").write_text("more\n")
    r = backend("vault-add", "--dir", target, "--src", T / "more.txt", secret=VAULT_PASS)
    check(clean_failure(r) and (target / "manifest.age").read_bytes() == before, "the highest generation can't overflow: the add is refused", r.stderr)
    r = backend("vault-list", "--dir", target, secret=VAULT_PASS)
    check(r.returncode == 0 and "generation 18446744073709551615" in r.stdout, "and it can still be read")

    target = forge(f"{head}F {BLOB} {SHA} 18446744073709551615 a\n")
    out = sentinel_root / "liar"
    r = backend("vault-extract", "--dir", target, "--entry", "a", "--out", out, secret=VAULT_PASS)
    check(r.returncode == 0 and out.read_text() == "real\n", "a lying size only misleads the display: the real content comes out", r.stderr)
    out.unlink()

    target = forge(f"{head}F {BLOB} {SHA} 5 a\nF {BLOB} {SHA} 5 b\n")
    r = backend("vault-remove", "--dir", target, "--entry", "a", secret=VAULT_PASS)
    chk = backend("vault-check", "--dir", target, secret=VAULT_PASS)
    check(r.returncode == 0 and chk.returncode == 0, "two names sharing a blob: removing one keeps the blob for the other", (r.stderr, chk.stderr))

    (T / "evil-case").mkdir(exist_ok=True)
    target = forge(f"{head}F {BLOB} {SHA} 5 %1B%5B2Jname\nF {BLOB} {SHA} 5 %E2%80%AEevil.txt\nF {BLOB} {SHA} 5 %0Aline\n")
    r = backend("vault-list", "--dir", target, secret=VAULT_PASS)
    check(r.returncode == 0 and "\x1b" not in r.stdout and "‮" not in r.stdout, "control characters stay escaped in the listing", r.stdout[:200])

    # Blobs that aren't what they claim, with correct hashes: only age can refuse them.
    other = new_vault("hostile-other.vsvault", "password", VAULT_PASS)
    (T / "hx.txt").write_text("x\n")
    assert backend("vault-add", "--dir", other, "--src", T / "hx.txt", secret=VAULT_PASS).returncode == 0
    foreign = next((other / "blobs").rglob("*.age"))
    garbage = T / "garbage-blob"
    garbage.write_bytes(os.urandom(4096))
    for label, source in (("a blob for a different key", foreign), ("a blob of random bytes", garbage)):
        target = T / "hostile-blob.vsvault"
        shutil.rmtree(target, ignore_errors=True)
        shutil.copytree(v, target)
        data = source.read_bytes()
        new_sha = hashlib.sha256(data).hexdigest()
        (target / "blobs" / BLOB[:2] / f"{BLOB}.age").write_bytes(data)
        plain = T / "forged-manifest"
        plain.write_text(f"{head}F {BLOB} {new_sha} 5 a\n")
        (target / "manifest.age").unlink()
        assert subprocess.run([AGE, "-r", recipient, "-o", str(target / "manifest.age"), str(plain)], env=ENV).returncode == 0
        out = sentinel_root / "blob-out"
        r = backend("vault-extract", "--dir", target, "--entry", "a", "--out", out, secret=VAULT_PASS)
        check(clean_failure(r) and not out.exists() and not leftovers(sentinel_root), f"{label}, with a matching hash: refused, nothing written", r.stderr)

    # A truncated blob, re-pinned: age must notice the missing final chunk.
    big = T / "h-big.bin"
    big.write_bytes(os.urandom(300000))
    bv = new_vault("hostile-trunc.vsvault", "password", VAULT_PASS)
    assert backend("vault-add", "--dir", bv, "--src", big, secret=VAULT_PASS).returncode == 0
    bv_id = T / "trunc.key"
    bv_id.write_text(age_decrypt_scrypt(bv / "key.age", VAULT_PASS).decode())
    os.chmod(bv_id, 0o600)
    bv_rec = subprocess.run([AGE_KEYGEN, "-y", str(bv_id)], capture_output=True, text=True, env=ENV).stdout.strip()
    text = age_decrypt_identity(bv / "manifest.age", bv_id).decode()
    line = next(l for l in text.split("\n") if l.startswith("F "))
    _, b_id, _, b_size, b_path = line.split(" ")
    file = bv / "blobs" / b_id[:2] / f"{b_id}.age"
    cut = file.read_bytes()[:-70000]
    file.write_bytes(cut)
    plain = T / "forged-manifest"
    plain.write_text(f"{head}F {b_id} {hashlib.sha256(cut).hexdigest()} {b_size} {b_path}\n")
    (bv / "manifest.age").unlink()
    assert subprocess.run([AGE, "-r", bv_rec, "-o", str(bv / "manifest.age"), str(plain)], env=ENV).returncode == 0
    out = sentinel_root / "trunc-out"
    r = backend("vault-extract", "--dir", bv, "--entry", b_path, "--out", out, secret=VAULT_PASS)
    check(clean_failure(r) and not out.exists() and not leftovers(sentinel_root), "a truncated blob with a re-pinned hash: age refuses it, nothing written", r.stderr)


# ---------------------------------------------------------------------------------------
# A minimal age writer, from the published format, so forged files can carry any secret and
# any work factor. The control cases in section_seal prove that what it writes is valid.
def chacha_block(key, counter, nonce):
    constants = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
    words = [int.from_bytes(key[i:i + 4], "little") for i in range(0, 32, 4)]
    tail = [int.from_bytes(nonce[i:i + 4], "little") for i in range(0, 12, 4)]
    start = constants + words + [counter] + tail
    s = list(start)

    def quarter(a, b, c, d):
        s[a] = (s[a] + s[b]) & 0xffffffff
        s[d] = ((s[d] ^ s[a]) << 16 | (s[d] ^ s[a]) >> 16) & 0xffffffff
        s[c] = (s[c] + s[d]) & 0xffffffff
        s[b] = ((s[b] ^ s[c]) << 12 | (s[b] ^ s[c]) >> 20) & 0xffffffff
        s[a] = (s[a] + s[b]) & 0xffffffff
        s[d] = ((s[d] ^ s[a]) << 8 | (s[d] ^ s[a]) >> 24) & 0xffffffff
        s[c] = (s[c] + s[d]) & 0xffffffff
        s[b] = ((s[b] ^ s[c]) << 7 | (s[b] ^ s[c]) >> 25) & 0xffffffff

    for _ in range(10):
        quarter(0, 4, 8, 12); quarter(1, 5, 9, 13); quarter(2, 6, 10, 14); quarter(3, 7, 11, 15)
        quarter(0, 5, 10, 15); quarter(1, 6, 11, 12); quarter(2, 7, 8, 13); quarter(3, 4, 9, 14)
    return b"".join(((x + y) & 0xffffffff).to_bytes(4, "little") for x, y in zip(s, start))


def chacha_poly(key, nonce, plain):
    stream = b""
    counter = 1
    while len(stream) < len(plain):
        stream += chacha_block(key, counter, nonce)
        counter += 1
    cipher = bytes(a ^ b for a, b in zip(plain, stream))
    otk = chacha_block(key, 0, nonce)[:32]
    r = int.from_bytes(otk[:16], "little") & 0x0ffffffc0ffffffc0ffffffc0fffffff
    s = int.from_bytes(otk[16:], "little")
    padded = cipher + b"\0" * (-len(cipher) % 16) + (0).to_bytes(8, "little") + len(cipher).to_bytes(8, "little")
    tag = 0
    for i in range(0, len(padded), 16):
        block = padded[i:i + 16]
        tag = (tag + int.from_bytes(block + b"\x01", "little")) * r % ((1 << 130) - 5)
    return cipher + ((tag + s) % (1 << 128)).to_bytes(16, "little")


def hkdf(secret, salt, info):
    prk = hmac.new(salt or b"\0" * 32, secret, hashlib.sha256).digest()
    return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()


def b64(data):
    return base64.b64encode(data).decode().rstrip("=")


def scrypt_stanza(secret, file_key, log_n):
    salt = os.urandom(16)
    key = hashlib.scrypt(secret.encode(), salt=b"age-encryption.org/v1/scrypt" + salt, n=1 << log_n, r=8, p=1, dklen=32, maxmem=(1 << 31) - 1)
    return f"-> scrypt {b64(salt)} {log_n}\n{b64(chacha_poly(key, bytes(12), file_key))}\n"


def age_file(stanzas, file_key, plain):
    header = "age-encryption.org/v1\n" + "".join(stanzas) + "---"
    mac = hmac.new(hkdf(file_key, b"", b"header"), header.encode(), hashlib.sha256).digest()
    nonce = os.urandom(16)
    return f"{header} {b64(mac)}\n".encode() + nonce + chacha_poly(hkdf(file_key, nonce, b"payload"), bytes(11) + b"\x01", plain)


def sealed_with(secret, plain, log_n=10):
    file_key = os.urandom(16)
    return age_file([scrypt_stanza(secret, file_key, log_n)], file_key, plain)


def section_seal():
    print("== can anyone without the private key make a self vault open?", flush=True)
    if not AGE:
        note("age isn't available, so the sealing attacks weren't run")
        return
    PREFIX = "vaultsend-vault-key-1:"
    data = Path(ENV["XDG_DATA_HOME"]) / "vaultsend"
    v = new_vault("seal.vsvault")
    (T / "seal.txt").write_text("the owner's file\n")
    assert backend("vault-add", "--dir", v, "--src", T / "seal.txt", secret=ID_PASS).returncode == 0
    pristine = tree_state(v)
    owner_public = (data / "pubkey").read_text().strip()
    owner_private = age_decrypt_scrypt(data / "identity.age", ID_PASS).decode().strip()

    # The attacker's own vault key, and a manifest and file only that key can read.
    attacker_file = T / "attacker.key"
    subprocess.run([AGE_KEYGEN, "-o", str(attacker_file)], capture_output=True, check=True, env=ENV)
    attacker_private = next(l for l in attacker_file.read_text().splitlines() if l.startswith("AGE-SECRET-KEY"))
    attacker_public = subprocess.run([AGE_KEYGEN, "-y", str(attacker_file)], capture_output=True, text=True, check=True, env=ENV).stdout.strip()
    plain = T / "attacker-manifest"
    plain.write_text("vaultsend-manifest 1\ngeneration 1\nD planted\n")
    forged_manifest = T / "attacker-manifest.age"
    subprocess.run([AGE, "-r", attacker_public, "-o", str(forged_manifest), str(plain)], check=True, env=ENV)
    identity_text = (attacker_private + "\n").encode()

    def forged_vault(key_bytes, mode="self", name="forged.vsvault"):
        target = T / name
        shutil.rmtree(target, ignore_errors=True)
        (target / "blobs").mkdir(parents=True)
        (target / "VAULT").write_text(f"vaultsend-vault 1\nmode {mode}\n")
        (target / "key.age").write_bytes(key_bytes)
        shutil.copy(forged_manifest, target / "manifest.age")
        return target

    def refused(label, key_bytes, needle="does not open with your key"):
        target = forged_vault(key_bytes)
        listed = backend("vault-list", "--dir", target, secret=ID_PASS)
        (T / "bait.txt").write_text("the owner adds a secret\n")
        added = backend("vault-add", "--dir", target, "--src", T / "bait.txt", secret=ID_PASS)
        blobs = [p for p in (target / "blobs").rglob("*") if p.is_file()]
        leaked = owner_private in listed.stderr + listed.stdout + added.stderr or ID_PASS in listed.stderr + added.stderr
        check(clean_failure(listed) and clean_failure(added) and needle in listed.stderr and not blobs and not leaked,
              f"refused: {label}", (listed.returncode, listed.stderr, added.returncode, added.stderr, blobs))

    # The controls: the same writer, with the right secret, does open. So each refusal below
    # is down to the secret, not a malformed file.
    target = forged_vault(sealed_with(PREFIX + owner_private, identity_text))
    r = backend("vault-list", "--dir", target, secret=ID_PASS)
    check(r.returncode == 0 and "D planted" in r.stdout, "control: a seal made with the real private key opens, so these forgeries are valid files", r.stderr)
    target = forged_vault(sealed_with(VAULT_PASS, identity_text), mode="password")
    r = backend("vault-list", "--dir", target, secret=VAULT_PASS)
    check(r.returncode == 0 and "D planted" in r.stdout, "control: a password vault made by the same writer opens", r.stderr)
    r = subprocess.run([AGE, "-d", "-i", str(attacker_file), str(forged_manifest)], capture_output=True, env=ENV)
    check(r.returncode == 0, "control: age itself reads the forged manifest")

    # What an attacker has: the public key, the folder, and guesses.
    wrapped = T / "wrapped-to-owner.age"
    subprocess.run([AGE, "-r", owner_public, "-o", str(wrapped)], input=identity_text, check=True, env=ENV)
    refused("a key wrapped to the owner's public key (how this used to work)", wrapped.read_bytes())
    for label, secret in (
        ("the public key as the seal", PREFIX + owner_public),
        ("the public key, no prefix", owner_public),
        ("the prefix alone", PREFIX),
        ("an empty secret", ""),
        ("the passphrase as the seal", ID_PASS),
        ("the passphrase with the prefix", PREFIX + ID_PASS),
        ("the attacker's own private key", PREFIX + attacker_private),
        ("an all-zero private key", PREFIX + "AGE-SECRET-KEY-1" + "Q" * 58),
        ("the real private key without the prefix", owner_private),
        ("the real private key in lowercase", PREFIX + owner_private.lower()),
        ("the real private key with a newline", PREFIX + owner_private + "\n"),
    ):
        refused(f"a seal made with {label}", sealed_with(secret, identity_text))

    # Work factors: one too many is refused even with the right secret, and costly ones are
    # refused without being paid for.
    refused("the real seal at one work factor above the limit", sealed_with(PREFIX + owner_private, identity_text, 11))
    baseline = time.monotonic()
    backend("vault-list", "--dir", forged_vault(sealed_with(PREFIX + attacker_public, identity_text)), secret=ID_PASS)
    baseline = time.monotonic() - baseline
    salt = b64(os.urandom(16))
    body = b64(os.urandom(32))

    def header_only(stanza):
        return f"age-encryption.org/v1\n{stanza}--- {b64(os.urandom(32))}\n".encode() + os.urandom(64)

    for log_n in (11, 18, 22, 30, 40, 63, 64, 255):
        target = forged_vault(header_only(f"-> scrypt {salt} {log_n}\n{body}\n"))
        began = time.monotonic()
        r = backend("vault-list", "--dir", target, secret=ID_PASS, timeout=120)
        took = time.monotonic() - began
        check(clean_failure(r) and took < baseline + 1.5, f"a seal claiming work factor 2^{log_n} is refused without paying for it ({took:.2f}s, baseline {baseline:.2f}s)", r.stderr)
    for label, stanza in (
        ("a padded work factor", f"-> scrypt {salt} 010\n{body}\n"),
        ("a negative work factor", f"-> scrypt {salt} -1\n{body}\n"),
        ("a non-numeric work factor", f"-> scrypt {salt} abc\n{body}\n"),
        ("work factor 0", f"-> scrypt {salt} 0\n{body}\n"),
        ("a missing work factor", f"-> scrypt {salt}\n{body}\n"),
        ("a short salt", f"-> scrypt AAAA 10\n{body}\n"),
        ("a short body", f"-> scrypt {salt} 10\nAAAA\n"),
        ("two scrypt stanzas", f"-> scrypt {salt} 10\n{body}\n-> scrypt {salt} 10\n{body}\n"),
        ("scrypt beside X25519", f"-> X25519 {b64(os.urandom(32))}\n{body}\n-> scrypt {salt} 10\n{body}\n"),
        ("only an unknown stanza", f"-> grease {salt}\n{body}\n"),
        ("no stanza at all", ""),
    ):
        target = forged_vault(header_only(stanza))
        r = backend("vault-list", "--dir", target, secret=ID_PASS, timeout=60)
        check(clean_failure(r), f"refused: a key.age with {label}", r.stderr)
    for label, data_bytes in (
        ("empty", b""),
        ("random bytes", os.urandom(4096)),
        ("a header with no payload", sealed_with(PREFIX + attacker_public, identity_text).split(b"\n---")[0]),
    ):
        r = backend("vault-list", "--dir", forged_vault(data_bytes), secret=ID_PASS, timeout=60)
        check(clean_failure(r), f"refused: a key.age that's {label}", r.stderr)
    armored = T / "armored.age"
    subprocess.run([AGE, "-a", "-r", owner_public, "-o", str(armored)], input=identity_text, check=True, env=ENV)
    r = backend("vault-list", "--dir", forged_vault(armored.read_bytes()), secret=ID_PASS)
    check(clean_failure(r), "refused: an armored key.age", r.stderr)

    # A good seal over something that isn't an identity. Only the owner could make these.
    for label, contents in (("nothing useful", b"not an identity"), ("invalid UTF-8", b"\xff\xfe"), ("a public key", owner_public.encode())):
        r = backend("vault-list", "--dir", forged_vault(sealed_with(PREFIX + owner_private, contents)), secret=ID_PASS)
        check(clean_failure(r) and owner_private not in r.stderr, f"a real seal over {label} fails cleanly", r.stderr)

    print("== the mode hint", flush=True)
    target = T / "flip.vsvault"
    shutil.rmtree(target, ignore_errors=True)
    shutil.copytree(v, target)
    (target / "VAULT").write_text("vaultsend-vault 1\nmode password\n")
    r = backend("vault-list", "--dir", target, secret=ID_PASS)
    check(clean_failure(r), "a self vault flipped to password doesn't open with the passphrase", r.stderr)
    r = backend("vault-list", "--dir", target, secret=PREFIX + owner_private)
    check(r.returncode == 0, "control: flipped, it would take the seal itself, which only the owner can compute", r.stderr)

    target = forged_vault(sealed_with("attacker's password", identity_text), mode="password")
    r = backend("vault-list", "--dir", target, secret=ID_PASS)
    check(clean_failure(r), "a planted password vault doesn't open with the owner's passphrase", r.stderr)
    (target / "VAULT").write_text("vaultsend-vault 1\nmode self\n")
    r = backend("vault-list", "--dir", target, secret=ID_PASS)
    check(clean_failure(r), "or as a self vault", r.stderr)
    r = backend("vault-list", "--dir", target, secret="attacker's password")
    check(clean_failure(r), "and as a self vault, the attacker's password is no use either", r.stderr)

    pv = new_vault("seal-password.vsvault", "password", VAULT_PASS)
    target = T / "flip2.vsvault"
    shutil.copytree(pv, target)
    (target / "VAULT").write_text("vaultsend-vault 1\nmode self\n")
    r = backend("vault-list", "--dir", target, secret=VAULT_PASS)
    check(clean_failure(r), "a password vault flipped to self doesn't open", r.stderr)

    print("== nothing on this device stands in for the private key", flush=True)
    saved = (data / "pubkey").read_text()
    (data / "pubkey").write_text("age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq\n")
    r = backend("vault-list", "--dir", v, secret=ID_PASS)
    check(r.returncode == 0, "a tampered pubkey file doesn't stop the owner", r.stderr)
    (data / "pubkey").unlink()
    r = backend("vault-list", "--dir", v, secret=ID_PASS)
    check(r.returncode == 0, "neither does a missing one", r.stderr)
    (data / "pubkey").write_text(saved)
    r = backend("vault-list", "--dir", v, secret="not the passphrase at all")
    check(clean_failure(r), "the wrong passphrase doesn't open it", r.stderr)
    stranger = dict(ENV, XDG_DATA_HOME=str(T / "stranger"))
    rd, wr = os.pipe()
    os.write(wr, ID_PASS.encode())
    os.close(wr)
    subprocess.run([BIN, "keygen", "--pass-fd", str(rd)], pass_fds=(rd,), env=stranger, capture_output=True, check=True)
    os.close(rd)
    r = backend("vault-list", "--dir", v, secret=ID_PASS, env=stranger)
    check(clean_failure(r), "someone else's key with the same passphrase doesn't open it", r.stderr)
    check(tree_state(v) == pristine, "the owner's real vault came through all of that byte-identical")

    print("== a hostile password vault's work factor", flush=True)
    for log_n in (19, 20, 22, 24, 40):
        target = forged_vault(header_only(f"-> scrypt {salt} {log_n}\n{body}\n"), mode="password")
        began = time.monotonic()
        r = backend("vault-list", "--dir", target, secret=VAULT_PASS, timeout=120)
        took = time.monotonic() - began
        check(clean_failure(r) and took < 0.5, f"a password vault claiming 2^{log_n} is refused without paying for it ({took:.2f}s)", r.stderr)
    target = forged_vault(sealed_with(VAULT_PASS, identity_text, 18), mode="password")
    r = backend("vault-list", "--dir", target, secret=VAULT_PASS)
    check(r.returncode == 0, "control: the work factor vault-create uses does open", r.stderr)


# ---------------------------------------------------------------------------------------
def rss_of(fn):
    before = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    began = time.monotonic()
    result = fn()
    return result, time.monotonic() - began, max(before, resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss)


def section_scale():
    print("== size and scale", flush=True)
    v = new_vault("scale.vsvault", "password", VAULT_PASS)
    many = make_files(T / "scale-many", 20000, 32)
    r, took, _ = rss_of(lambda: backend("vault-add", "--dir", v, "--src", many, secret=VAULT_PASS, timeout=1800))
    check(r.returncode == 0, f"20,000 files added in {took:.0f}s", r.stderr)
    r, took, _ = rss_of(lambda: backend("vault-list", "--dir", v, secret=VAULT_PASS, timeout=300))
    check(r.returncode == 0 and r.stdout.count("\nF ") == 20000, f"listed in {took:.1f}s ({os.path.getsize(v / 'manifest.age') // 1024} KB manifest)", r.stderr)
    r, took, _ = rss_of(lambda: backend("vault-check", "--dir", v, secret=VAULT_PASS, timeout=1800))
    check(r.returncode == 0 and "ok 20000 file(s) verified" in r.stdout, f"verified in {took:.0f}s", r.stderr)
    out = T / "scale-out"
    r, took, _ = rss_of(lambda: backend("vault-extract", "--dir", v, "--entry", "/", "--out", out, secret=VAULT_PASS, timeout=1800))
    check(r.returncode == 0 and tree_state(many) == tree_state(out / many.name), f"extracted identically in {took:.0f}s", r.stderr)
    shutil.rmtree(out)
    r, took, _ = rss_of(lambda: backend("vault-remove", "--dir", v, "--entry", many.name, secret=VAULT_PASS, timeout=900))
    leftover = [p for p in (v / "blobs").rglob("*.age")]
    check(r.returncode == 0 and not leftover, f"removed, and every blob collected, in {took:.0f}s", r.stderr)
    shutil.rmtree(many)

    # Many sources on one command line, as a large drop onto the window makes.
    files = make_files(T / "scale-args", 5000, 16)
    argv = ["vault-add", "--dir", v]
    for f in sorted(files.iterdir()):
        argv += ["--src", f]
    r = backend(*argv, "--dest", "dropped", secret=VAULT_PASS, timeout=900)
    check(r.returncode == 0, "5,000 --src arguments", r.stderr)
    shutil.rmtree(files)

    # Depth and length limits.
    deep = T / "scale-deep"
    d = deep
    for n in range(150):
        d = d / f"d{n}"
    d.mkdir(parents=True)
    (d / "bottom.txt").write_text("bottom\n")
    dv = new_vault("scale-deep.vsvault", "password", VAULT_PASS)
    r = backend("vault-add", "--dir", dv, "--src", deep, secret=VAULT_PASS)
    out = T / "scale-deep-out"
    e = backend("vault-extract", "--dir", dv, "--entry", "/", "--out", out, secret=VAULT_PASS)
    check(r.returncode == 0 and e.returncode == 0 and tree_state(deep) == tree_state(out / deep.name), "150 levels deep goes in and comes back", (r.stderr, e.stderr))

    # Large files: added as a stream, but read whole into memory to verify.
    size = 1536 * 1024 * 1024
    big = T / "scale-big.bin"
    with open(big, "wb") as f:
        chunk = os.urandom(1024 * 1024)
        for _ in range(size // len(chunk)):
            f.write(chunk)
    bv = new_vault("scale-big.vsvault", "password", VAULT_PASS)
    r, took, _ = rss_of(lambda: backend("vault-add", "--dir", bv, "--src", big, secret=VAULT_PASS, timeout=1800))
    check(r.returncode == 0, f"a 1.5 GiB file added in {took:.0f}s", r.stderr)
    out = T / "scale-big.out"
    r, took, rss = rss_of(lambda: backend("vault-extract", "--dir", bv, "--entry", big.name, "--out", out, secret=VAULT_PASS, timeout=1800))
    same = r.returncode == 0 and subprocess.run(["cmp", "-s", str(big), str(out)]).returncode == 0
    check(same, f"extracted identically in {took:.0f}s; peak memory {rss // 1024} MiB", r.stderr)
    out.unlink(missing_ok=True)

    # Not enough memory: the process dies before any plaintext reaches the disk.
    def low_memory():
        resource.setrlimit(resource.RLIMIT_AS, (1024 * 1024 * 1024, 1024 * 1024 * 1024))
    r3, w3 = os.pipe()
    os.write(w3, VAULT_PASS.encode())
    os.close(w3)
    p = subprocess.run([BIN, "vault-extract", "--dir", str(bv), "--entry", big.name, "--out", str(out), "--pass-fd", str(r3)], pass_fds=(r3,), env=ENV, capture_output=True, text=True, errors="replace", preexec_fn=low_memory, timeout=600)
    os.close(r3)
    check(p.returncode != 0 and not out.exists() and not Path(str(out) + PART).exists(), f"out of memory: fails, and writes nothing (exit {p.returncode})", p.stderr[:200])
    if p.returncode != 1:
        note(f"running out of memory ends the backend with exit {p.returncode}, not a tidy error: {p.stderr.strip()[:120]}")
    big.unlink()
    check(backend("vault-check", "--dir", bv, secret=VAULT_PASS, timeout=900).returncode == 0, "and the vault is unharmed")

    # A hostile blob or manifest claiming to be enormous is read before the hash is checked.
    target = T / "scale-sparse.vsvault"
    shutil.copytree(dv, target)
    blob = next((target / "blobs").rglob("*.age"))
    with open(blob, "wb") as f:
        f.truncate(64 * 1024 * 1024 * 1024)
    def limited():
        resource.setrlimit(resource.RLIMIT_AS, (2 * 1024 * 1024 * 1024, 2 * 1024 * 1024 * 1024))
    r3, w3 = os.pipe()
    os.write(w3, VAULT_PASS.encode())
    os.close(w3)
    p = subprocess.run([BIN, "vault-check", "--dir", str(target), "--pass-fd", str(r3)], pass_fds=(r3,), env=ENV, capture_output=True, text=True, errors="replace", preexec_fn=limited, timeout=300)
    os.close(r3)
    check(p.returncode != 0, f"a 64 GiB sparse blob is refused or ends the process, under a memory limit (exit {p.returncode})", p.stderr[:160])
    if p.returncode != 1:
        note(f"an enormous blob ends the backend with exit {p.returncode} rather than a tidy error: only reachable with write access to the vault; costs memory, reveals nothing")
    shutil.rmtree(target)


# ---------------------------------------------------------------------------------------
SHARE_PASS = "attack share password"
STAGING = Path(ENV["XDG_DATA_HOME"]) / "vaultsend" / "staging"


def with_pipes(argv, secrets, popen=False):
    """Run the backend with each of `secrets` ({"--pass-fd": text, ...}) on its own pipe."""
    cmd = [BIN, *map(str, argv)]
    fds = []
    for option, text in secrets.items():
        r, w = os.pipe()
        os.write(w, text.encode())
        os.close(w)
        cmd += [option, str(r)]
        fds.append(r)
    try:
        if popen:
            return subprocess.Popen(cmd, pass_fds=fds, env=ENV, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True, errors="replace")
        return subprocess.run(cmd, pass_fds=fds, env=ENV, capture_output=True, text=True, timeout=300, errors="replace")
    finally:
        for fd in fds:
            os.close(fd)


def staged_left():
    return sorted(n for n in os.listdir(STAGING) if n != ".lock") if STAGING.exists() else []


def tar_entry(name, data=b"", kind=b"0", link=b"", size=None, prefix=b""):
    h = bytearray(512)
    h[: len(name)] = name
    h[100:108] = b"0000644\0"
    h[124:136] = b"%011o\0" % (len(data) if size is None else size)
    h[345 : 345 + len(prefix)] = prefix
    h[156:157] = kind
    h[157 : 157 + len(link)] = link
    h[257:263] = b"ustar\0"
    h[148:156] = b" " * 8
    h[148:156] = b"%06o\0 " % sum(h)
    return bytes(h) + data + bytes(-len(data) % 512)


def fake_costly_share(log_n):
    """A password share whose header asks for scrypt 2^log_n. The wrapped key is junk:
    a backend that honours its limit refuses before running scrypt at all."""
    stanza = f"-> scrypt {b64(os.urandom(16))} {log_n}\n{b64(os.urandom(32))}\n"
    header = "age-encryption.org/v1\n" + stanza + "---"
    return f"{header} {b64(os.urandom(32))}\n".encode() + os.urandom(16) + os.urandom(64)


def section_shares():
    print("== receiving a share: hostile archives, scrypt limits, and kills while unpacking or importing", flush=True)
    v = new_vault("shares.vsvault")
    tree = make_files(T / "share-src" / "tree", 40, 256 * 1024)
    (tree / "big.bin").write_bytes(os.urandom(16 * 1024 * 1024))
    (tree / "deep" / "er").mkdir(parents=True)
    (tree / "deep" / "er" / "x.txt").write_bytes(b"deep")
    assert backend("vault-add", "--dir", v, "--src", tree, secret=ID_PASS).returncode == 0
    share = T / "tree.tar.age"
    r = with_pipes(["vault-share", "--dir", v, "--entry", "/", "--out", share], {"--pass-fd": ID_PASS, "--share-pass-fd": SHARE_PASS})
    check(r.returncode == 0 and share.exists(), "vault-share --share-pass-fd makes a password share", r.stderr[:200])
    r = with_pipes(["vault-share", "--dir", v, "--entry", "/", "--out", v / "inside.age"], {"--pass-fd": ID_PASS, "--share-pass-fd": SHARE_PASS})
    check(clean_failure(r) and "inside the vault" in r.stderr and not (v / "inside.age").exists(), "a password share is refused inside the vault too", r.stderr[:200])
    r = with_pipes(["vault-share", "--dir", v, "--entry", "/", "--out", T / "short.age"], {"--pass-fd": ID_PASS, "--share-pass-fd": "short"})
    check(clean_failure(r) and "at least 10" in r.stderr, "and needs a password as long as a vault's", r.stderr[:200])

    r = backend("share-kind", "--in", share)
    check(r.returncode == 0 and r.stdout == "password", "share-kind says a password share needs a password", r.stdout + r.stderr)
    pub = backend("pubkey").stdout
    key_share = T / "key.age"
    r = backend("vault-share", "--dir", v, "--entry", "tree/deep", "--to", pub, "--out", key_share, secret=ID_PASS)
    assert r.returncode == 0, r.stderr
    check(backend("share-kind", "--in", key_share).stdout == "key", "and a key share needs a key")
    r = with_pipes(["share-check", "--in", share], {"--share-pass-fd": "not the share password"})
    check(clean_failure(r) and "wrong password" in r.stderr, "share-check: a wrong password is said at once", r.stderr[:200])
    check(with_pipes(["share-check", "--in", share], {"--share-pass-fd": SHARE_PASS}).returncode == 0, "and the right one passes")

    # The scrypt limit: 2^18 for a share, whatever the header asks; refused before scrypt runs.
    for log_n in (19, 22, 40):
        costly = T / f"costly-{log_n}.age"
        costly.write_bytes(fake_costly_share(log_n))
        began = time.monotonic()
        r = with_pipes(["share-extract", "--in", costly, "--out", T / f"costly-{log_n}"], {"--share-pass-fd": SHARE_PASS})
        check(clean_failure(r) and "more work" in r.stderr and time.monotonic() - began < 5 and not (T / f"costly-{log_n}").exists(),
              f"a share asking for scrypt 2^{log_n} is refused without running it", r.stderr[:200])
    r = with_pipes(["share-check", "--in", T / "costly-19.age"], {"--share-pass-fd": SHARE_PASS})
    check(clean_failure(r) and "more work" in r.stderr, "share-check too", r.stderr[:200])

    # Interop: what the backend saves is what age decrypts, byte for byte.
    saved = T / "saved.tar"
    r = with_pipes(["share-decrypt", "--in", share, "--out", saved], {"--share-pass-fd": SHARE_PASS})
    check(r.returncode == 0 and saved.exists(), "share-decrypt saves a password share as it is", r.stderr[:200])
    if AGE:
        same = age_decrypt_scrypt(share, SHARE_PASS) == saved.read_bytes()
        check(same, "age -d opens the password share to the same bytes")
    r = backend("share-decrypt", "--in", key_share, "--out", T / "key.tar", secret=ID_PASS)
    check(r.returncode == 0, "share-decrypt opens a key share with the identity passphrase", r.stderr[:200])
    want = tree_state(tree)

    out = T / "unpacked"
    began = time.monotonic()
    r = with_pipes(["share-extract", "--in", share, "--out", out], {"--share-pass-fd": SHARE_PASS})
    full = time.monotonic() - began
    check(r.returncode == 0 and tree_state(out / "tree") == want, f"share-extract unpacks it whole ({full:.2f}s)", r.stderr[:200])
    check(staged_left() == [] and not leftovers(T), "and leaves no staging and no partial folder", staged_left())
    r = with_pipes(["share-extract", "--in", share, "--out", out], {"--share-pass-fd": SHARE_PASS})
    check(clean_failure(r) and "already exists" in r.stderr and tree_state(out / "tree") == want, "never over an existing folder", r.stderr[:200])
    shutil.rmtree(out)

    # Import into a fresh vault: the same tree, verified.
    iv = new_vault("import.vsvault", "password", VAULT_PASS)
    r = with_pipes(["vault-import", "--dir", iv, "--in", share], {"--pass-fd": VAULT_PASS, "--share-pass-fd": SHARE_PASS})
    check(r.returncode == 0 and generation(iv, VAULT_PASS) == 1, "vault-import adds a password share in one change", r.stderr[:200])
    got = T / "import-check"
    backend("vault-extract", "--dir", iv, "--entry", "tree", "--out", got, secret=VAULT_PASS)
    check(tree_state(got) == want and staged_left() == [], "with every file as it was, and no staging left", staged_left())
    shutil.rmtree(got)
    r = with_pipes(["vault-import", "--dir", iv, "--in", key_share, "--dest", "from-key"], {"--pass-fd": VAULT_PASS, "--id-pass-fd": ID_PASS})
    check(r.returncode == 0 and "D from-key/tree/deep/er\n" in backend("vault-list", "--dir", iv, secret=VAULT_PASS).stdout, "and a key share, with --id-pass-fd", r.stderr[:200])

    # Killed partway. SIGTERM (the frontend's Cancel) cleans up at once; SIGKILL can't,
    # and the next run sweeps the staging. Either way the folder is absent or complete.
    random.seed(20261106)
    rounds = max(4, args.rounds // 4)
    term_ok = kill_ok = True
    for n in range(rounds):
        for how in ("TERM", "KILL"):
            dest = T / f"kill-{how}-{n}"
            p = with_pipes(["share-extract", "--in", share, "--out", dest], {"--share-pass-fd": SHARE_PASS}, popen=True)
            time.sleep(random.uniform(0.05, full * 1.1))
            p.send_signal(signal.SIGTERM if how == "TERM" else signal.SIGKILL)
            _, err = p.communicate(timeout=60)
            complete = dest.exists() and tree_state(dest / "tree") == want
            absent = not dest.exists()
            part = Path(str(dest) + PART).exists()
            if how == "TERM":
                ok = (complete and p.returncode == 0) or (absent and not part and "cancelled" in err and p.returncode == 1)
                ok = ok and staged_left() == []
                if not ok:
                    term_ok = False
                    print(f"      TERM round {n}: rc={p.returncode} complete={complete} part={part} staged={staged_left()} {err[:160]}", flush=True)
            else:
                ok = complete or absent
                # The next run, to the same name, clears both leftovers.
                if absent:
                    r = with_pipes(["share-extract", "--in", share, "--out", dest], {"--share-pass-fd": SHARE_PASS})
                    ok = ok and r.returncode == 0 and tree_state(dest / "tree") == want
                ok = ok and staged_left() == [] and not Path(str(dest) + PART).exists()
                if not ok:
                    kill_ok = False
                    print(f"      KILL round {n}: complete={complete} absent={absent} staged={staged_left()}", flush=True)
            shutil.rmtree(dest, ignore_errors=True)
    check(term_ok, f"share-extract stopped by SIGTERM {rounds} times: cancelled, with no folder, no partial folder and no staging; or done")
    check(kill_ok, f"share-extract killed -9 {rounds} times: folder absent or complete, and the next run clears the partial folder and the staging")

    term_ok = kill_ok = True
    for n in range(rounds):
        for how in ("TERM", "KILL"):
            target = new_vault(f"kill-import-{how}-{n}.vsvault")
            p = with_pipes(["vault-import", "--dir", target, "--in", share], {"--pass-fd": ID_PASS, "--share-pass-fd": SHARE_PASS}, popen=True)
            time.sleep(random.uniform(0.3, full * 1.5))
            p.send_signal(signal.SIGTERM if how == "TERM" else signal.SIGKILL)
            _, err = p.communicate(timeout=60)
            gen = generation(target)
            chk = backend("vault-check", "--dir", target, secret=ID_PASS)
            ok = chk.returncode == 0 and gen in (0, 1)
            if gen == 1:
                got = T / f"kill-import-out-{how}-{n}"
                backend("vault-extract", "--dir", target, "--entry", "tree", "--out", got, secret=ID_PASS)
                ok = ok and tree_state(got) == want
                shutil.rmtree(got, ignore_errors=True)
            if how == "TERM":
                ok = ok and staged_left() == [] and (gen == 1 or ("cancelled" in err and "orphan" not in chk.stdout))
                term_ok = term_ok and ok
            else:
                # The next change collects the killed run's blobs; the next staging run sweeps.
                assert backend("vault-add", "--dir", target, "--src", make_files(T / f"after-{n}", 1), secret=ID_PASS).returncode == 0
                with_pipes(["share-check", "--in", share], {"--share-pass-fd": SHARE_PASS})
                with_pipes(["share-decrypt", "--in", key_share, "--out", T / "sweep.tar"], {"--pass-fd": ID_PASS})
                chk = backend("vault-check", "--dir", target, secret=ID_PASS)
                ok = ok and staged_left() == [] and "orphan" not in chk.stdout
                kill_ok = kill_ok and ok
            if not ok:
                print(f"      {how} import round {n}: gen={gen} staged={staged_left()} {err[:160]} {chk.stdout[-120:]}", flush=True)
            shutil.rmtree(target, ignore_errors=True)
    check(term_ok, f"vault-import stopped by SIGTERM {rounds} times: generation 0 with no blobs and no staging, or the whole import")
    check(kill_ok, f"vault-import killed -9 {rounds} times: generation 0 or the whole import; the next change and the next run clear the rest")

    # Hostile archives, encrypted to this user's key by the backend itself (so any size
    # is a proper age file), and opened with the identity passphrase.
    end = bytes(1024)
    good = tar_entry(b"ok.txt", b"fine")
    cases = {
        "dot-dot": tar_entry(b"../escape.txt", b"x") + end,
        "deep dot-dot": tar_entry(b"a/../../escape.txt", b"x") + end,
        "absolute": tar_entry(b"/tmp/vs-abs-escape.txt", b"x") + end,
        "drive": tar_entry(b"C:escape.txt", b"x") + end,
        "backslash": tar_entry(b"a\\..\\escape.txt", b"x") + end,
        "prefix dot-dot": tar_entry(b"evil", b"x", prefix=b"..") + end,
        "duplicate": tar_entry(b"same", b"1") + tar_entry(b"same", b"2") + end,
        "file then inside it": tar_entry(b"f", b"1") + tar_entry(b"f/x", b"2") + end,
        "size beyond the end": tar_entry(b"liar", b"x", size=1 << 30) + end,
        "truncated": (good * 3)[:900],
        "bad checksum": bytes([good[0] ^ 1]) + good[1:] + end,
        "huge pax": tar_entry(b"PaxHeaders/x", b"x" * 70000, b"x") + good + end,
    }
    # A file whose first block isn't a tar header is one file, not an archive: extract
    # refuses it, and import adds it whole under --name, as on Android.
    not_tar = {"truncated", "bad checksum"}
    refused_ok = True
    for name, plain in cases.items():
        f, raw = T / "hostile.age", T / "hostile.tar"
        raw.write_bytes(plain)
        assert backend("encrypt", "-r", pub, "--in", raw, "--out", f).returncode == 0
        dest = T / "hostile-out"
        r = with_pipes(["share-extract", "--in", f, "--out", dest], {"--pass-fd": ID_PASS})
        hv = new_vault(f"hostile-{len(name)}-{os.urandom(2).hex()}.vsvault")
        ri = with_pipes(["vault-import", "--dir", hv, "--in", f, "--name", "x"], {"--pass-fd": ID_PASS, "--id-pass-fd": ID_PASS})
        ok = clean_failure(r) and not dest.exists() and not leftovers(T) and staged_left() == []
        if name in not_tar:
            listing = backend("vault-list", "--dir", hv, secret=ID_PASS).stdout
            ok = ok and ri.returncode == 0 and listing == f"generation 1\nF {len(plain)} x\n"
        else:
            ok = ok and clean_failure(ri) and generation(hv) == 0
        if not ok:
            refused_ok = False
            print(f"      {name}: extract rc={r.returncode} {r.stderr[:120]} | import rc={ri.returncode} {ri.stderr[:120]}", flush=True)
        shutil.rmtree(dest, ignore_errors=True)
        shutil.rmtree(hv, ignore_errors=True)
    escaped = [p for p in (T / "escape.txt", Path("/tmp/vs-abs-escape.txt"), T.parent / "escape.txt") if p.exists()]
    check(refused_ok and not escaped, f"{len(cases)} hostile archives refused by share-extract and vault-import, writing nothing ({len(not_tar)} not archives at all: imported as one file)", escaped)

    # Links, devices and FIFOs are skipped and never made; the rest arrives. This one is
    # sealed with the password in Python, as any age implementation would.
    plain = (tar_entry(b"link", kind=b"2", link=b"/etc") + tar_entry(b"link/passwd", b"plain file")
             + tar_entry(b"hard", kind=b"1", link=b"/etc/passwd") + tar_entry(b"dev", kind=b"3")
             + tar_entry(b"fifo", kind=b"6") + good + end)
    f = T / "links.age"
    f.write_bytes(sealed_with(SHARE_PASS, plain))
    dest = T / "links-out"
    r = with_pipes(["share-extract", "--in", f, "--out", dest], {"--share-pass-fd": SHARE_PASS})
    kinds = {p.name: ("link" if p.is_symlink() else "dir" if p.is_dir() else "file" if p.is_file() else "other") for p in dest.rglob("*")} if dest.exists() else {}
    check(r.returncode == 0 and "skipped 4" in r.stderr and kinds == {"link": "dir", "passwd": "file", "ok.txt": "file"},
          "links, hard links, devices and FIFOs are skipped, and never made", f"{kinds} {r.stderr[:160]}")
    check(Path("/etc/passwd").read_bytes() != b"plain file", "nothing was written through the link")


# ---------------------------------------------------------------------------------------
SECTIONS = {
    "crash": section_crash, "race": section_race, "traps": section_traps, "fuzz": section_fuzz,
    "hardening": section_hardening, "leaks": section_leaks, "format": section_format, "seal": section_seal, "scale": section_scale,
    "shares": section_shares,
}


def main():
    rd, wr = os.pipe()
    os.write(wr, ID_PASS.encode())
    os.close(wr)
    subprocess.run([BIN, "keygen", "--pass-fd", str(rd)], pass_fds=(rd,), env=ENV, capture_output=True, check=True)
    os.close(rd)

    if args.in_namespace:
        section_disk()
    else:
        only = args.only.split(",") if args.only else [*SECTIONS, "disk"]
        for name in only:
            if name == "disk":
                continue
            try:
                SECTIONS[name]()
            except Exception as e:  # the harness itself tripped, so don't count it as a pass
                import traceback
                traceback.print_exc()
                check(False, f"section {name} ran to the end", e)
        if "disk" in only:
            # A second copy of this script, as root in a private namespace, for the mount.
            command = [sys.executable, "-I", __file__, BIN, "--in-namespace"]
            if args.age:
                command += ["--age", args.age]
            r = subprocess.run(["unshare", "-Urm", *command], capture_output=True, text=True, errors="replace")
            print(r.stdout, end="", flush=True)
            if r.stderr:
                print(r.stderr[-1500:], flush=True)
            m = re.search(r"(\d+) passed, (\d+) failed", r.stdout)
            if m:
                global passed, failed
                passed += int(m.group(1))
                failed += int(m.group(2))
            else:
                check(False, "the full-disk section finished", r.returncode)

    print(f"\n{passed} passed, {failed} failed")
    for text in notes:
        print(f"note: {text}")


try:
    main()
finally:
    subprocess.run(["chmod", "-R", "u+rwx", str(T)], capture_output=True)
    shutil.rmtree(T, ignore_errors=True)
sys.exit(1 if failed else 0)
