#!/usr/bin/env node
// Tests for the reader that opens a shared archive (the tar inside a .tar.age that
// Share writes from a vault on the desktop or Android app).
//
//   node tests/shared_archive_test.mjs [path/to/index.html]
//
// Needs Node 18 or later and nothing else. It runs the reader out of index.html
// itself: the lines between the "vs-tar" marks in the app script are taken as they
// are and evaluated here, so what is tested is what ships. The cases are the Rust
// reader's own (tar.rs on the desktop and Android branches), so all three builds
// are held to the same rules, plus the names a web page has to watch for.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const htmlPath = process.argv[2] || path.join(here, "..", "index.html");
const html = fs.readFileSync(htmlPath, "utf8");
const from = html.indexOf("// >>> vs-tar"), to = html.indexOf("// <<< vs-tar");
if (from < 0 || to < from) {
  console.error("the vs-tar marks are missing from " + htmlPath);
  process.exit(2);
}
const reader = new Function(html.slice(from, to) + `
  return { TAR_BLOCK, TAR_MAX_SIZE, TAR_LIMITS, CANCELLED, validVaultPath, shownName,
           canonicalEntryPath, tarScan, looksLikeTar };`)();
const { TAR_BLOCK: BLOCK, TAR_MAX_SIZE: MAX_SIZE, TAR_LIMITS: LIMITS, CANCELLED,
        validVaultPath, shownName, canonicalEntryPath, tarScan, looksLikeTar } = reader;

// ── A small harness ──────────────────────────────────────────────────────────
let passed = 0, failed = 0;
async function test(name, fn) {
  try { await fn(); passed++; console.log("ok    " + name); }
  catch (e) { failed++; console.log("FAIL  " + name + "\n      " + (e && e.stack ? e.stack.split("\n").slice(0, 3).join("\n      ") : e)); }
}
function assert(cond, why) { if (!cond) throw new Error(why || "assertion failed"); }
function eq(a, b, why) { assert(JSON.stringify(a) === JSON.stringify(b), (why ? why + ": " : "") + JSON.stringify(a) + " != " + JSON.stringify(b)); }
async function fails(promiseOrFn, containing, why) {
  let err = null;
  try { await (typeof promiseOrFn === "function" ? promiseOrFn() : promiseOrFn); } catch (e) { err = e; }
  assert(err, (why || "") + " should have been refused");
  if (containing) assert(String(err.message).includes(containing), (why || "") + ` refused with "${err.message}", wanted "${containing}"`);
}

// ── Writing archives, as tar.rs does, to have something to read ──────────────
const enc = new TextEncoder();
const bytes = (x) => (typeof x === "string" ? enc.encode(x) : Uint8Array.from(x));
const cat = (...parts) => { const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0)); let at = 0; for (const p of parts) { out.set(p, at); at += p.length; } return out; };
const END = new Uint8Array(2 * BLOCK);
const padding = (size) => new Uint8Array((BLOCK - (size % BLOCK)) % BLOCK);
const octal = (value, width) => bytes(value.toString(8).padStart(width - 1, "0") + "\0");
function sealed(h) {
  h.fill(0x20, 148, 156);
  h.set(bytes(h.reduce((n, b) => n + b, 0).toString(8).padStart(6, "0") + "\0 "), 148);
  return h;
}
// A header with any name, size field and kind, its checksum made right.
function raw(name, sizeField, kind, prefix = "") {
  const h = new Uint8Array(BLOCK);
  h.set(bytes(name), 0);
  h.set(octal(0o600, 8), 100);
  h.set(bytes(sizeField), 124);
  h[156] = typeof kind === "string" ? kind.charCodeAt(0) : kind;
  h.set(bytes("ustar\0"), 257); h.set(bytes("00"), 263);
  h.set(bytes(prefix), 345);
  return sealed(h);
}
const sizeField = (n) => n.toString(8).padStart(11, "0") + "\0";
function rawFile(name, data, kind = "0") { const d = bytes(data); return cat(raw(name, sizeField(d.length), kind), d, padding(d.length)); }
function paxPath(value) {
  const body = bytes(" path=" + value + "\n");
  let len = body.length;
  while (body.length + String(len).length !== len) len = body.length + String(len).length;
  return cat(bytes(String(len)), body);
}
function pax(record) { const r = bytes(record); return cat(raw("PaxHeaders/x", sizeField(r.length), "x"), r, padding(r.length)); }
// What Share writes: ustar, plus a PAX record for a name over 100 bytes.
function entry(name, size, kind) {
  const n = bytes(name);
  if (n.length <= 100) return raw(n, sizeField(size), kind);
  let cut = 100;
  while (cut > 0 && (n[cut] & 0xc0) === 0x80) cut--;   // between characters
  return cat(pax(paxPath(name)), raw(n.subarray(0, cut), sizeField(size), kind));
}
function fileEntry(name, data) { const d = bytes(data); return cat(entry(name, d.length, "0"), d, padding(d.length)); }
const dirHeader = (name) => entry(name + "/", 0, "5");
const archive = (...parts) => cat(...parts, END);

const scanBytes = (data, limits = LIMITS, cancelled = () => false) => tarScan(new Blob([data]), limits, cancelled);
const paths = (s) => Array.from(s.items.keys()).sort();
const dataOf = (data, item) => Buffer.from(data.subarray(item.offset, item.offset + item.size)).toString();

// ── The Rust reader's tests ──────────────────────────────────────────────────
await test("what Share writes reads back, with every parent", async () => {
  const long = "d".repeat(120) + "/" + "é".repeat(30) + ".txt";
  const data = archive(dirHeader("docs"), fileEntry("docs/a.txt", "hello"),
    fileEntry("deep/er/b.bin", new Uint8Array(1000).fill(7)), fileEntry(long, "long"));
  const s = await scanBytes(data);
  eq(s.skipped, 0); eq(s.total, 5 + 1000 + 4);
  assert(s.items.get("deep").dir && s.items.get("deep/er").dir, "parents made: " + paths(s));
  eq(dataOf(data, s.items.get("docs/a.txt")), "hello");
  eq(dataOf(data, s.items.get(long)), "long");
  eq(s.items.get("d".repeat(120)), { dir: true });
});

await test("the vault path rules", () => {
  for (const bad of ["", "/a", "a//b", "./a", "a/..", "../x", "a/./b", "a/", "/", ".", "..", "a\0b"]) {
    assert(!validVaultPath(bad), "accepted " + JSON.stringify(bad));
  }
  assert(!validVaultPath("x".repeat(256)));
  assert(!validVaultPath(Array(21).fill("y".repeat(200)).join("/")), "over 4096 in all");
  for (const good of ["a", "a/b/c", "with space", "ünï/cödé.txt", "..hidden", "a.", "%25", "new\nline", "-x"]) {
    assert(validVaultPath(good), "rejected " + JSON.stringify(good));
  }
  assert(validVaultPath("x".repeat(255)));
  // Lengths are counted in bytes, as on disk, not in characters.
  assert(validVaultPath("é".repeat(127)) && !validVaultPath("é".repeat(128)));
});

await test("names are canonical and never leave the folder", () => {
  eq(canonicalEntryPath("./a/./b/"), "a/b");
  eq(canonicalEntryPath("./"), null);
  eq(canonicalEntryPath("."), null);
  for (const bad of ["../x", "a/../../x", "a/..", "/etc/passwd", "//x", "./../x", "C:x", "c:/x", "a\\..\\x",
    "a//b", "a\0b", "", "..", "x".repeat(256), "d/".repeat(2100) + "x"]) {
    let threw = false;
    try { canonicalEntryPath(bad); } catch { threw = true; }
    assert(threw, JSON.stringify(bad.slice(0, 40)) + " must be refused");
  }
  // A colon is an ordinary character after the first component, or not at the start.
  eq(canonicalEntryPath("notes: 2024/a"), "notes: 2024/a");
});

await test("traversal is refused however the name arrives", async () => {
  for (const name of ["../evil", "a/../../evil", "/abs/evil", "C:evil", "a\\..\\evil", "a//evil", "./../evil"]) {
    await fails(scanBytes(archive(rawFile(name, "x"))), "unsafe name", "plain " + name);
    await fails(scanBytes(archive(pax(paxPath(name)), rawFile("innocent", "x"))), "unsafe name", "pax " + name);
  }
  const prefixed = archive(cat(raw("evil", sizeField(1), "0", ".."), bytes("x"), padding(1)));
  await fails(scanBytes(prefixed), "unsafe name", "through the ustar prefix");
  // A NUL inside a PAX path, which the header field could never carry.
  await fails(scanBytes(archive(pax("13 path=a\0b\n"), rawFile("a", "x"))), null, "a NUL in a PAX path");
});

await test("links, devices and the like are skipped, never followed", async () => {
  const s = await scanBytes(archive(
    raw("link", sizeField(0), "2"),            // a symlink, pointing anywhere
    rawFile("link/evil", "inside"),            // ...becomes a plain folder and file
    raw("hard", sizeField(0), "1"), raw("chr", sizeField(0), "3"),
    raw("blk", sizeField(0), "4"), raw("fifo", sizeField(0), "6"),
    rawFile("cont", "c", "7"),
    rawFile("././@LongLink", "some/long/name\0", "L"),
    rawFile("truncated-name", "belongs to the long name"),
    rawFile("unknown", "?", "Z")));
  eq(s.skipped, 9, paths(s).join());
  eq(s.items.get("link"), { dir: true });
  eq(s.items.get("link/evil").size, 6);
  eq(s.items.size, 2, paths(s).join());
});

await test("huge declared sizes are refused", async () => {
  // Over the 8 GB a ustar size can say, in base-256 or not.
  const base256 = raw("big", sizeField(0), "0"); base256[124] = 0x80; sealed(base256);
  await fails(scanBytes(archive(base256)), null, "a base-256 size");
  await fails(scanBytes(archive(pax("23 size=99999999999999\n"), rawFile("big", ""))), "too large", "a PAX size");
  await fails(scanBytes(archive(pax("29 size=10000000000000000000\n"), rawFile("big", ""))), "too large", "a PAX size past 2^53");
  await fails(scanBytes(archive(pax("30 size=999999999999999999999\n"), rawFile("big", ""))), "bad extended header", "a PAX size past 2^64");
  // Bigger than the archive really is.
  await fails(scanBytes(archive(raw("liar", sizeField(2 ** 30), "0"))), "incomplete", "a lying size");
  // Per entry, in total, and in count, against lowered limits.
  const blob = (b) => new Uint8Array(600).fill(b);
  const three = archive(fileEntry("a", blob(1)), fileEntry("b", blob(2)), fileEntry("c", blob(3)));
  await fails(scanBytes(three, { maxEntries: 100, maxEntrySize: 500, maxTotal: 2 ** 20 }), "too large");
  await fails(scanBytes(three, { maxEntries: 100, maxEntrySize: 2 ** 20, maxTotal: 1000 }), "more than 1000 bytes");
  await fails(scanBytes(three, { maxEntries: 2, maxEntrySize: 2 ** 20, maxTotal: 2 ** 20 }), "more than 2 entries");
  // An extended header too large to read.
  const record = "path=" + "x".repeat(70000) + "\n";
  await fails(scanBytes(archive(pax((record.length + 6) + " " + record), rawFile("a", ""))), "too large", "a huge PAX record");
  eq(MAX_SIZE, 8 * 2 ** 30 - 1);
});

await test("truncated archives are refused", async () => {
  const whole = archive(fileEntry("a.txt", new Uint8Array(3000).fill(9)), dirHeader("d"));
  await scanBytes(whole);
  for (const cut of [0, 1, 100, 511, 512, 513, 2000, 3584, 4095, whole.length - END.length]) {
    await fails(scanBytes(whole.subarray(0, cut)), "incomplete", "cut at " + cut);
  }
  // A PAX record with nothing after it.
  await fails(scanBytes(cat(pax(paxPath("name")), END)), "incomplete", "a dangling PAX record");
});

await test("damaged headers, duplicates and clashes are refused", async () => {
  const badSum = fileEntry("a", "x"); badSum[0] = "b".charCodeAt(0);
  await fails(scanBytes(archive(badSum)), "checksum");
  await fails(scanBytes(archive(raw("a", "0000000009\0\0", "0"))), null, "a 9 in an octal field");
  await fails(scanBytes(archive(fileEntry("a", "1"), fileEntry("a", "2"))), "twice");
  await fails(scanBytes(archive(dirHeader("d"), dirHeader("d"))), "twice");
  await fails(scanBytes(archive(fileEntry("a", "1"), dirHeader("a"))), null, "a file, then a folder of its name");
  await fails(scanBytes(archive(fileEntry("a", "1"), fileEntry("a/b", "2"))), null, "a file, then something inside it");
  await fails(scanBytes(archive(fileEntry("a/b", "2"), fileEntry("a", "1"))), null, "something inside, then a file");
  // A folder named after what's in it was seen first is the same folder.
  await scanBytes(archive(fileEntry("a/b", "2"), dirHeader("a")));
  // Not UTF-8.
  await fails(scanBytes(archive(rawFile([0xff, 0xfe], "x"))), "UTF-8");
});

await test("PAX records are framed strictly", async () => {
  const with_ = (record) => scanBytes(archive(pax(record), rawFile("a", "x")));
  eq(paths(await with_("10 path=b\n")), ["b"]);
  eq(paths(await with_("11 other=1\n10 path=c\n")), ["c"]);
  for (const bad of ["010 path=b\n", "+10 path=b\n", "11 path=b\n", "8 path=b\n", "10 path=b ", "7 path\n", "x path=b\n", " path=b\n", "10path=b\n",
    "8 size=\n", "11 size=01\n", "11 size=+1\n", "11 size=1x\n"]) {
    await fails(with_(bad), "bad extended header", JSON.stringify(bad));
  }
  // A size from PAX replaces the header's, and is checked against the archive.
  const s = await scanBytes(archive(pax("9 size=3\n"), cat(raw("a", sizeField(0), "0"), bytes("abc"), padding(3))));
  eq(s.items.get("a").size, 3);
});

await test("cancel stops a scan", async () => {
  await fails(scanBytes(archive(fileEntry("a", "1"), fileEntry("b", "2")), LIMITS, () => true), CANCELLED);
});

await test("looksLikeTar needs a real header", () => {
  assert(looksLikeTar(fileEntry("a", "").subarray(0, BLOCK)));
  assert(!looksLikeTar(new Uint8Array(BLOCK)));
  assert(!looksLikeTar(new Uint8Array(BLOCK).fill(120)));
  assert(!looksLikeTar(bytes("short")));
});

// ── What a page has to watch for besides ─────────────────────────────────────
await test("names that are also JavaScript's own are ordinary names", async () => {
  const s = await scanBytes(archive(fileEntry("__proto__", "p"), fileEntry("constructor/prototype", "q"),
    fileEntry("toString", "t"), fileEntry("hasOwnProperty/valueOf", "v")));
  eq(paths(s), ["__proto__", "constructor", "constructor/prototype", "hasOwnProperty", "hasOwnProperty/valueOf", "toString"]);
  assert(Object.prototype.p === undefined && ({}).dir === undefined, "nothing reached Object.prototype");
});

await test("a name is shown with its hidden characters spelled out", () => {
  eq(shownName("photo\u202egpj.exe"), "photo\\u{202e}gpj.exe");
  eq(shownName("a\nb\x00c\x7f\u200b\ufeff"), "a\\u{a}b\\u{0}c\\u{7f}\\u{200b}\\u{feff}");
  eq(shownName("ünï cödé 日本.txt"), "ünï cödé 日本.txt");
  eq(Array.from(shownName("x".repeat(500))).length, 201);
});

await test("implied folders are counted against the limit too", async () => {
  // Few headers, but each path implies hundreds of folders.
  const deep = (i) => Array.from({ length: 200 }, (_, j) => "d" + i + "_" + j).join("/") + "/f";
  const parts = []; for (let i = 0; i < 12; i++) parts.push(fileEntry(deep(i), "x"));
  await fails(scanBytes(archive(...parts), { maxEntries: 1000, maxEntrySize: 2 ** 20, maxTotal: 2 ** 20 }), "more than 2000 files and folders");
  await scanBytes(archive(...parts.slice(0, 9)), { maxEntries: 1000, maxEntrySize: 2 ** 20, maxTotal: 2 ** 20 });
});

await test("a large archive of small files scans, and data is never read", async () => {
  const parts = []; for (let i = 0; i < 5000; i++) parts.push(fileEntry("dir" + (i % 50) + "/file" + i + ".txt", "n" + i));
  const data = archive(...parts);
  const s = await scanBytes(data);
  eq(s.items.size, 5050);
  eq(dataOf(data, s.items.get("dir49/file4999.txt")), "n4999");
  // A file far larger than the window is stepped over, not read: a Blob that
  // refuses to hand out more than its headers still scans.
  const big = archive(fileEntry("big.bin", new Uint8Array(3 * 2 ** 20)), fileEntry("after.txt", "after"));
  let most = 0;
  const blob = new Blob([big]);
  const spy = { size: blob.size, slice: (a, b) => { most = Math.max(most, Math.min(b, blob.size) - a); return blob.slice(a, b); } };
  const s2 = await tarScan(spy, LIMITS, () => false);
  eq(paths(s2), ["after.txt", "big.bin"]);
  assert(most <= 64 * 1024, "read " + most + " bytes at once");
});

// Seeded mutations of a good archive: whatever comes back must be safe.
await test("fuzzed archives never escape or overrun", async () => {
  let seed = 0x5eed;
  const rnd = (n) => { seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0; return Math.floor((seed / 2 ** 32) * n); };
  const base = archive(dirHeader("d"), fileEntry("d/a.txt", new Uint8Array(700).fill(1)),
    fileEntry("p".repeat(110) + "/long.bin", new Uint8Array(40).fill(2)), fileEntry("e/f/g", "g"));
  const limits = { maxEntries: 64, maxEntrySize: 2 ** 16, maxTotal: 2 ** 18 };
  let ok = 0, refused = 0;
  for (let round = 0; round < 5000; round++) {
    let data = base.slice();
    for (let n = 1 + rnd(5); n > 0 && data.length >= BLOCK; n--) {
      const how = rnd(5);
      if (how === 0) data[rnd(data.length)] ^= 1 << rnd(8);
      else if (how === 1) data[rnd(data.length)] = [0x2f, 0x2e, 0, 0x5c, 0x37, 0x78, 0x35, 0x32, 0xff][rnd(9)];
      else if (how === 2) data = data.slice(0, rnd(data.length));
      else if (how === 3) {
        // Rewrite a size field to something large, fixing the checksum.
        const at = rnd(Math.floor(data.length / BLOCK)) * BLOCK;
        const h = data.subarray(at, at + BLOCK);
        h.set(octal([2 ** 20, 2 ** 33, 2 ** 32 - 1, MAX_SIZE][rnd(4)], 12), 124);
        sealed(h);
      } else {
        const at = rnd(Math.floor(data.length / BLOCK) + 1) * BLOCK;
        data = cat(data.subarray(0, at), raw("../../x", sizeField(1), "0"), data.subarray(at));
      }
    }
    let s;
    try { s = await scanBytes(data, limits); } catch { refused++; continue; }
    ok++;
    assert(s.items.size <= 2 * 64, "bounded");
    assert(s.total <= limits.maxTotal);
    for (const [p, item] of s.items) {
      eq(canonicalEntryPath(p), p);
      assert(!p.split("/").some((c) => c === ".." || c === "." || c === ""), p);
      for (let i = p.indexOf("/"); i !== -1; i = p.indexOf("/", i + 1)) {
        assert(s.items.get(p.slice(0, i)) && s.items.get(p.slice(0, i)).dir, "a parent of " + p + " is no folder");
      }
      if (!item.dir) {
        assert(item.offset + item.size <= data.length, p + " overruns");
        assert(item.size <= limits.maxEntrySize);
      }
    }
  }
  assert(ok > 0 && refused > 0, `mutations must exercise both outcomes: ${ok} ok, ${refused} refused`);
});

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
