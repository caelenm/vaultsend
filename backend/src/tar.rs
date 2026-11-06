// Just enough of the tar format for Share to hand over a folder as one file, without a new
// crate (VAULTS_PLAN.md rules those out). ustar, plus a PAX record for a path that won't
// fit in its 100 bytes, which every tar since the 2000s understands.
//
// Reading (`scan`) exists for a shared archive someone sends back: `share-extract` unpacks
// it into a new folder, and `vault-import` adds it to a vault (shared.rs). The same reader
// as the Android build's, so both treat an archive alike. age has authenticated it, but
// only as coming from whoever knew the password (or the key), so it is read as hostile
// input. The rules, each enforced below and tested:
//   * Every path is canonicalized lexically (`canonical_entry_path`): no NUL, no
//     backslash, nothing absolute, no drive prefix, no `..`, no empty component. What
//     is left joins onto any root and stays inside it; writers re-check anyway.
//   * Only regular files and folders are taken. Links, devices, FIFOs and anything
//     else are skipped and counted, never followed or created.
//   * Entry count, each entry's size and the total are capped (`Limits`), and every
//     declared size must fit in the archive as it really is.
//   * Nothing is buffered whole: headers are read a block at a time and data is
//     seeked past; only a PAX record is read, and it is capped at 64 KiB.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Seek, SeekFrom};

use crate::vault::{ancestors, valid_vault_path, CANCELLED};
use crate::R;

const BLOCK: usize = 512;
/// What ustar's 11 octal digits can hold. Refused above that, not written wrong.
const MAX_SIZE: u64 = 0o77777777777;
/// Two empty blocks mark the end of an archive.
pub(crate) const END: [u8; 2 * BLOCK] = [0; 2 * BLOCK];

fn put_octal(field: &mut [u8], value: u64) {
    let text = format!("{value:0width$o}\0", width = field.len() - 1);
    field.copy_from_slice(text.as_bytes());
}

fn block(name: &str, size: u64, kind: u8, mode: u64, mtime: u64) -> [u8; BLOCK] {
    let mut h = [0u8; BLOCK];
    h[..name.len()].copy_from_slice(name.as_bytes());
    put_octal(&mut h[100..108], mode);
    put_octal(&mut h[108..116], 0); // uid
    put_octal(&mut h[116..124], 0); // gid
    put_octal(&mut h[124..136], size);
    put_octal(&mut h[136..148], mtime);
    h[148..156].fill(b' '); // counted as spaces while the checksum is worked out
    h[156] = kind;
    h[257..263].copy_from_slice(b"ustar\0");
    h[263..265].copy_from_slice(b"00");
    let sum: u64 = h.iter().map(|&b| u64::from(b)).sum();
    h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    h
}

/// "<length> path=<value>\n", where the length counts its own digits.
fn pax_path(value: &str) -> String {
    let body = format!(" path={value}\n");
    let mut len = body.len();
    while (body.len() + len.to_string().len()) != len {
        len = body.len() + len.to_string().len();
    }
    format!("{len}{body}")
}

/// What follows a file's data, to fill its last block.
pub(crate) fn padding(size: u64) -> Vec<u8> {
    vec![0; (BLOCK - (size % BLOCK as u64) as usize) % BLOCK]
}

fn entry(name: &str, size: u64, kind: u8, mode: u64, mtime: u64) -> Vec<u8> {
    if name.len() <= 100 {
        return block(name, size, kind, mode, mtime).to_vec();
    }
    let record = pax_path(name);
    let mut out = block("PaxHeaders/path", record.len() as u64, b'x', 0o600, mtime).to_vec();
    out.extend_from_slice(record.as_bytes());
    out.extend(padding(record.len() as u64));
    // For a tar too old to read the record: the start of the name, cut between characters.
    let cut = (0..=100).rev().find(|&i| name.is_char_boundary(i)).unwrap_or(0);
    out.extend_from_slice(&block(&name[..cut], size, kind, mode, mtime));
    out
}

pub(crate) fn file_header(path: &str, size: u64, mtime: u64) -> R<Vec<u8>> {
    if size > MAX_SIZE {
        return Err(format!("'{path}' is too large to share in a folder: over 8 GB"));
    }
    Ok(entry(path, size, b'0', 0o600, mtime))
}

pub(crate) fn dir_header(path: &str, mtime: u64) -> Vec<u8> {
    entry(&format!("{path}/"), 0, b'5', 0o700, mtime)
}


// ---------------------------------------------------------------------------
// Reading.
// ---------------------------------------------------------------------------

/// The most an archive may hold. Hitting any of these is an error, before anything
/// is written.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_entries: usize,
    pub max_entry_size: u64,
    pub max_total: u64,
}

/// Generous for a phone or a desktop, small enough that a hostile header can't exhaust it.
pub const LIMITS: Limits = Limits { max_entries: 100_000, max_entry_size: MAX_SIZE, max_total: 32 << 30 };

/// The largest PAX record read. Real ones are a few hundred bytes.
const MAX_PAX: u64 = 64 << 10;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Item {
    Dir,
    /// Where its data starts in the archive, and how long it is.
    File { offset: u64, size: u64 },
}

/// What an archive holds, by canonical path. A BTreeMap, so a folder always comes
/// before what's in it. Every parent of an entry is a folder entry.
#[derive(Debug, Default)]
pub struct Scan {
    pub items: BTreeMap<String, Item>,
    /// Entries that were neither a file nor a folder: links, devices and the like.
    pub skipped: usize,
    /// Bytes in all the files together.
    pub total: u64,
}

/// A name from an archive, safe to show in a message.
fn shown(raw: &str) -> String {
    let text: String = raw.escape_debug().collect();
    if text.chars().count() > 200 {
        format!("{}…", text.chars().take(200).collect::<String>())
    } else {
        text
    }
}

/// An archive's name for an entry as a path inside the output, or None for the
/// archive's own top (`./`). Purely lexical: no `..`, nothing absolute, no drive
/// prefix, no backslash, no NUL, no empty component, so what comes back can be
/// joined onto any folder and stay inside it.
pub(crate) fn canonical_entry_path(raw: &str) -> R<Option<String>> {
    let bad = || format!("the archive holds an unsafe name: \"{}\"", shown(raw));
    if raw.is_empty() || raw.contains(['\0', '\\']) || raw.starts_with('/') {
        return Err(bad());
    }
    let mut parts: Vec<&str> = Vec::new();
    for part in raw.trim_end_matches('/').split('/') {
        match part {
            "." => {}
            ".." | "" => return Err(bad()),
            _ => {
                let b = part.as_bytes();
                if parts.is_empty() && b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':' {
                    return Err(bad()); // C:, as Windows would read it
                }
                parts.push(part);
            }
        }
    }
    if parts.is_empty() {
        return Ok(None);
    }
    let path = parts.join("/");
    if !valid_vault_path(&path) {
        return Err(bad());
    }
    Ok(Some(path))
}

/// An octal header field: optional leading spaces, digits, then only spaces or NULs.
/// None for anything else, base-256 included (only needed above 8 GB).
fn octal(field: &[u8]) -> Option<u64> {
    let start = field.iter().position(|&b| b != b' ')?;
    let mut value: u64 = 0;
    let mut end = field.len();
    for (i, &b) in field.iter().enumerate().skip(start) {
        match b {
            b'0'..=b'7' => value = value.checked_mul(8)?.checked_add(u64::from(b - b'0'))?,
            b' ' | 0 => {
                end = i;
                break;
            }
            _ => return None,
        }
    }
    field[end..].iter().all(|&b| b == b' ' || b == 0).then_some(value)
}

fn checksum_ok(h: &[u8; BLOCK]) -> bool {
    let Some(stored) = octal(&h[148..156]) else { return false };
    let (mut unsigned, mut signed) = (0u64, 0i64);
    for (i, &b) in h.iter().enumerate() {
        let b = if (148..156).contains(&i) { b' ' } else { b };
        unsigned += u64::from(b);
        signed += i64::from(b as i8);
    }
    // Some old tars summed signed bytes; both are accepted, as GNU tar does.
    stored == unsigned || i64::try_from(stored).is_ok_and(|s| s == signed)
}

/// A NUL-terminated text field.
fn text(field: &[u8]) -> R<&str> {
    let end = field.iter().position(|&b| b == 0).unwrap_or(field.len());
    std::str::from_utf8(&field[..end]).map_err(|_| "a name in the archive is not valid UTF-8".to_string())
}

/// The `path` and `size` keys of a PAX record; the rest is ignored. Strict about
/// its framing: "<len> key=value\n", where len counts the whole record.
fn parse_pax(mut data: &[u8]) -> R<(Option<String>, Option<u64>)> {
    let bad = || "the archive is damaged (a bad extended header)".to_string();
    let (mut path, mut size) = (None, None);
    while !data.is_empty() {
        let space = data.iter().position(|&b| b == b' ').ok_or_else(bad)?;
        let digits = std::str::from_utf8(&data[..space]).map_err(|_| bad())?;
        let len: usize = digits.parse().ok().filter(|n: &usize| n.to_string() == digits).ok_or_else(bad)?;
        if len <= space + 1 || len > data.len() || data[len - 1] != b'\n' {
            return Err(bad());
        }
        let record = std::str::from_utf8(&data[space + 1..len - 1]).map_err(|_| bad())?;
        let (key, value) = record.split_once('=').ok_or_else(bad)?;
        if value.contains('\0') {
            return Err(bad());
        }
        match key {
            "path" => path = Some(value.to_string()),
            "size" => size = Some(value.parse::<u64>().ok().filter(|n| n.to_string() == value).ok_or_else(bad)?),
            _ => {}
        }
        data = &data[len..];
    }
    Ok((path, size))
}

fn add(scan: &mut Scan, explicit: &mut BTreeSet<String>, path: String, item: Item) -> R<()> {
    let clash = |p: &str| format!("\"{}\" appears twice in the archive, or is both a file and a folder", shown(p));
    for folder in ancestors(&path) {
        match scan.items.get(folder) {
            Some(Item::File { .. }) => return Err(clash(folder)),
            Some(Item::Dir) => {}
            None => {
                scan.items.insert(folder.to_string(), Item::Dir);
            }
        }
    }
    match (scan.items.get(&path), item) {
        (None, _) => {}
        // Made for something inside it first, and now named itself: the same folder.
        (Some(Item::Dir), Item::Dir) if !explicit.contains(&path) => {}
        _ => return Err(clash(&path)),
    }
    if item == Item::Dir {
        explicit.insert(path.clone());
    }
    scan.items.insert(path, item);
    Ok(())
}

/// Read an archive's headers, `len` bytes of it, and say what it holds. Nothing is
/// written and no file's data is read. `cancelled` is asked between headers.
pub(crate) fn scan<F: Read + Seek>(src: &mut F, len: u64, limits: &Limits, cancelled: &dyn Fn() -> bool) -> R<Scan> {
    let truncated = || "the archive is incomplete: it ends early".to_string();
    let damaged = || "the archive is damaged (a bad header checksum)".to_string();
    let io = |e: std::io::Error| format!("reading the archive: {e}");
    let mut scan = Scan::default();
    let mut explicit = BTreeSet::new();
    let mut pos: u64 = 0;
    let mut headers = 0usize;
    let (mut pax_path, mut pax_size): (Option<String>, Option<u64>) = (None, None);
    let mut skip_next = false;
    let mut h = [0u8; BLOCK];
    src.seek(SeekFrom::Start(0)).map_err(io)?;
    loop {
        if cancelled() {
            return Err(CANCELLED.into());
        }
        if len.saturating_sub(pos) < BLOCK as u64 {
            return Err(truncated());
        }
        src.read_exact(&mut h).map_err(io)?;
        pos += BLOCK as u64;
        if h.iter().all(|&b| b == 0) {
            break; // the end marker; anything after it is ignored, as tar does
        }
        headers += 1;
        if headers > limits.max_entries {
            return Err(format!("the archive holds more than {} entries", limits.max_entries));
        }
        if !checksum_ok(&h) {
            return Err(damaged());
        }
        let kind = h[156];
        let size = match pax_size.take() {
            Some(size) => size,
            None => octal(&h[124..136]).ok_or_else(damaged)?,
        };
        if size > limits.max_entry_size {
            return Err(format!("an entry in the archive is too large ({size} bytes)"));
        }
        let padded = size.checked_add(BLOCK as u64 - 1).ok_or_else(truncated)? / BLOCK as u64 * BLOCK as u64;
        if size > len - pos {
            return Err(truncated());
        }
        let data_at = pos;
        let next = pos.saturating_add(padded).min(len);
        match kind {
            b'x' => {
                if size > MAX_PAX {
                    return Err("the archive is damaged (an extended header is too large)".into());
                }
                let mut record = vec![0u8; size as usize];
                src.read_exact(&mut record).map_err(io)?;
                (pax_path, pax_size) = parse_pax(&record)?;
            }
            b'g' => {} // global settings: nothing VaultSend uses
            b'L' | b'K' => {
                // GNU long names: not read, so the entry they belong to is skipped too.
                scan.skipped += 1;
                skip_next = true;
            }
            _ => {
                let name = match pax_path.take() {
                    Some(name) => name,
                    None => {
                        let name = text(&h[0..100])?;
                        let prefix = if &h[257..263] == b"ustar\0" { text(&h[345..500])? } else { "" };
                        if prefix.is_empty() { name.to_string() } else { format!("{prefix}/{name}") }
                    }
                };
                let regular = kind == b'0' || kind == 0;
                let is_dir = kind == b'5' || (regular && name.ends_with('/'));
                if std::mem::take(&mut skip_next) || !(is_dir || regular) {
                    scan.skipped += 1; // a link, device, FIFO or unknown kind: never created
                } else if let Some(path) = canonical_entry_path(&name)? {
                    if is_dir {
                        add(&mut scan, &mut explicit, path, Item::Dir)?;
                    } else {
                        scan.total = scan.total.saturating_add(size);
                        if scan.total > limits.max_total {
                            return Err(format!("the archive holds more than {} bytes", limits.max_total));
                        }
                        add(&mut scan, &mut explicit, path, Item::File { offset: data_at, size })?;
                    }
                }
            }
        }
        pos = next;
        src.seek(SeekFrom::Start(pos)).map_err(io)?;
    }
    if pax_path.is_some() || pax_size.is_some() || skip_next {
        return Err(truncated());
    }
    Ok(scan)
}

/// Whether a block looks like the start of a tar archive: a valid header checksum.
pub(crate) fn looks_like_tar(first: &[u8]) -> bool {
    let Ok(h) = <&[u8; BLOCK]>::try_from(first) else { return false };
    !h.iter().all(|&b| b == 0) && checksum_ok(h)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field(h: &[u8], range: std::ops::Range<usize>) -> String {
        String::from_utf8_lossy(&h[range]).trim_end_matches(['\0', ' ']).to_string()
    }

    #[test]
    fn a_short_name_is_one_valid_block() {
        let h = file_header("docs/a.txt", 5, 7).unwrap();
        assert_eq!(h.len(), BLOCK);
        assert_eq!(field(&h, 0..100), "docs/a.txt");
        assert_eq!(field(&h, 124..136), "00000000005");
        assert_eq!(field(&h, 136..148), "00000000007");
        assert_eq!(h[156], b'0');
        assert_eq!(&h[257..263], b"ustar\0");
        // The checksum is the sum of the block with its own field read as spaces.
        let mut blanked = h.clone();
        blanked[148..156].fill(b' ');
        let sum: u64 = blanked.iter().map(|&b| u64::from(b)).sum();
        assert_eq!(u64::from_str_radix(&field(&h, 148..155), 8).unwrap(), sum);
    }

    #[test]
    fn a_folder_ends_in_a_slash() {
        let h = dir_header("docs", 0);
        assert_eq!(field(&h, 0..100), "docs/");
        assert_eq!(h[156], b'5');
    }

    #[test]
    fn a_long_name_gets_a_record_that_counts_itself() {
        for n in [94, 95, 96, 101, 985, 990, 995, 4000] {
            let record = pax_path(&"x".repeat(n));
            let (len, _) = record.split_once(' ').unwrap();
            assert_eq!(len.parse::<usize>().unwrap(), record.len(), "name of {n}");
        }
        let name = format!("{}/é.txt", "d".repeat(99));
        let out = file_header(&name, 1, 0).unwrap();
        assert_eq!(out.len() % BLOCK, 0);
        assert_eq!(out[156], b'x');
        assert!(String::from_utf8_lossy(&out[BLOCK..2 * BLOCK]).contains(&format!("path={name}\n")));
        assert_eq!(out.len(), 3 * BLOCK);
        assert_eq!(out[2 * BLOCK + 156], b'0');
    }

    #[test]
    fn a_long_name_is_never_cut_inside_a_character() {
        let out = file_header(&"é".repeat(60), 0, 0).unwrap();
        let fallback = &out[out.len() - BLOCK..][..100];
        let end = fallback.iter().position(|&b| b == 0).unwrap_or(100);
        assert!(std::str::from_utf8(&fallback[..end]).is_ok());
    }

    #[test]
    fn padding_fills_the_last_block_only() {
        assert_eq!(padding(0).len(), 0);
        assert_eq!(padding(1).len(), 511);
        assert_eq!(padding(512).len(), 0);
        assert_eq!(padding(513).len(), 511);
    }

    #[test]
    fn too_large_for_the_format_is_refused() {
        assert!(file_header("big", MAX_SIZE, 0).is_ok());
        assert!(file_header("big", MAX_SIZE + 1, 0).unwrap_err().contains("too large"));
    }

    // --- Reading ---------------------------------------------------------------

    use std::io::Cursor;

    const NEVER: &dyn Fn() -> bool = &|| false;

    fn scan_bytes(data: &[u8]) -> R<Scan> {
        scan(&mut Cursor::new(data), data.len() as u64, &LIMITS, NEVER)
    }

    fn scan_with(data: &[u8], limits: Limits) -> R<Scan> {
        scan(&mut Cursor::new(data), data.len() as u64, &limits, NEVER)
    }

    /// A header with any name, size field and kind, its checksum made right.
    fn raw(name: &[u8], size_field: &[u8], kind: u8, prefix: &[u8]) -> Vec<u8> {
        let mut h = [0u8; BLOCK];
        h[..name.len()].copy_from_slice(name);
        put_octal(&mut h[100..108], 0o600);
        h[124..124 + size_field.len()].copy_from_slice(size_field);
        h[156] = kind;
        h[257..263].copy_from_slice(b"ustar\0");
        h[263..265].copy_from_slice(b"00");
        h[345..345 + prefix.len()].copy_from_slice(prefix);
        h[148..156].fill(b' ');
        let sum: u64 = h.iter().map(|&b| u64::from(b)).sum();
        h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        h.to_vec()
    }

    fn file_entry(name: &str, data: &[u8]) -> Vec<u8> {
        let mut out = file_header(name, data.len() as u64, 0).unwrap();
        out.extend_from_slice(data);
        out.extend(padding(data.len() as u64));
        out
    }

    fn raw_file(name: &[u8], data: &[u8], kind: u8) -> Vec<u8> {
        let mut out = raw(name, format!("{:011o}\0", data.len()).as_bytes(), kind, b"");
        out.extend_from_slice(data);
        out.extend(padding(data.len() as u64));
        out
    }

    fn pax(record: &str) -> Vec<u8> {
        let mut out = raw(b"PaxHeaders/x", format!("{:011o}\0", record.len()).as_bytes(), b'x', b"");
        out.extend_from_slice(record.as_bytes());
        out.extend(padding(record.len() as u64));
        out
    }

    fn archive(parts: &[Vec<u8>]) -> Vec<u8> {
        let mut out: Vec<u8> = parts.concat();
        out.extend_from_slice(&END);
        out
    }

    fn files(s: &Scan) -> Vec<(&str, Item)> {
        s.items.iter().map(|(p, i)| (p.as_str(), *i)).collect()
    }

    #[test]
    fn what_share_writes_reads_back_with_every_parent() {
        let long = format!("{}/{}.txt", "d".repeat(120), "é".repeat(30));
        let data = archive(&[
            dir_header("docs", 0),
            file_entry("docs/a.txt", b"hello"),
            file_entry("deep/er/b.bin", &[7u8; 1000]),
            file_entry(&long, b"long"),
        ]);
        let s = scan_bytes(&data).unwrap();
        assert_eq!(s.skipped, 0);
        assert_eq!(s.total, 5 + 1000 + 4);
        let paths: Vec<&str> = s.items.keys().map(String::as_str).collect();
        assert!(paths.contains(&"deep") && paths.contains(&"deep/er"), "parents made: {paths:?}");
        let Item::File { offset, size } = s.items["docs/a.txt"] else { panic!() };
        assert_eq!(&data[offset as usize..(offset + size) as usize], b"hello");
        let Item::File { offset, size } = s.items[&long] else { panic!("{:?}", files(&s)) };
        assert_eq!(&data[offset as usize..(offset + size) as usize], b"long");
    }

    #[test]
    fn names_are_canonical_and_never_leave_the_folder() {
        assert_eq!(canonical_entry_path("./a/./b/").unwrap().as_deref(), Some("a/b"));
        assert_eq!(canonical_entry_path("./").unwrap(), None);
        assert_eq!(canonical_entry_path(".").unwrap(), None);
        for bad in [
            "../x", "a/../../x", "a/..", "/etc/passwd", "//x", "./../x", "C:x", "c:/x", "a\\..\\x",
            "a//b", "a\0b", "", "..", &"x".repeat(256), &format!("{}/x", "d/".repeat(2100)),
        ] {
            assert!(canonical_entry_path(bad).is_err(), "{bad:?} must be refused");
        }
        // A colon is an ordinary character after the first component, or not at the start.
        assert_eq!(canonical_entry_path("notes: 2024/a").unwrap().as_deref(), Some("notes: 2024/a"));
    }

    #[test]
    fn traversal_is_refused_however_the_name_arrives() {
        for name in ["../evil", "a/../../evil", "/abs/evil", "C:evil", "a\\..\\evil", "a//evil", "./../evil"] {
            let plain = archive(&[raw_file(name.as_bytes(), b"x", b'0')]);
            assert!(scan_bytes(&plain).unwrap_err().contains("unsafe name"), "plain {name}");
            let via_pax = archive(&[pax(&pax_path(name)), raw_file(b"innocent", b"x", b'0')]);
            assert!(scan_bytes(&via_pax).unwrap_err().contains("unsafe name"), "pax {name}");
        }
        let prefixed = archive(&[{
            let mut e = raw(b"evil", b"00000000001\0", b'0', b"..");
            e.extend_from_slice(b"x");
            e.extend(padding(1));
            e
        }]);
        assert!(scan_bytes(&prefixed).unwrap_err().contains("unsafe name"));
        // A NUL inside a PAX path, which the header field could never carry.
        let nul = archive(&[pax("13 path=a\0b\n"), raw_file(b"a", b"x", b'0')]);
        assert!(scan_bytes(&nul).is_err());
    }

    #[test]
    fn links_devices_and_the_like_are_skipped_never_followed() {
        let data = archive(&[
            raw(b"link", b"00000000000\0", b'2', b""), // symlink, pointing anywhere
            raw_file(b"link/evil", b"inside", b'0'),     // ...becomes a plain folder and file
            raw(b"hard", b"00000000000\0", b'1', b""),
            raw(b"chr", b"00000000000\0", b'3', b""),
            raw(b"blk", b"00000000000\0", b'4', b""),
            raw(b"fifo", b"00000000000\0", b'6', b""),
            raw_file(b"cont", b"c", b'7'),
            raw_file(b"././@LongLink", b"some/long/name\0", b'L'),
            raw_file(b"truncated-name", b"belongs to the long name", b'0'),
            raw_file(b"unknown", b"?", b'Z'),
        ]);
        let s = scan_bytes(&data).unwrap();
        assert_eq!(s.skipped, 9, "{:?}", files(&s));
        assert_eq!(s.items.get("link"), Some(&Item::Dir));
        assert!(matches!(s.items.get("link/evil"), Some(Item::File { size: 6, .. })));
        assert_eq!(s.items.len(), 2, "{:?}", files(&s));
    }

    #[test]
    fn huge_declared_sizes_are_refused() {
        // Over the 8 GB a ustar size can say, in base-256 or not.
        let mut base256 = raw(b"big", b"00000000000\0", b'0', b"");
        base256[124] = 0x80;
        base256[148..156].fill(b' ');
        let sum: u64 = base256.iter().map(|&b| u64::from(b)).sum();
        base256[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        assert!(scan_bytes(&archive(&[base256])).is_err());
        let pax_huge = archive(&[pax("23 size=99999999999999\n"), raw_file(b"big", b"", b'0')]);
        assert!(scan_bytes(&pax_huge).unwrap_err().contains("too large"));
        // Bigger than the archive really is.
        let lying = archive(&[raw(b"liar", format!("{:011o}\0", 1u64 << 30).as_bytes(), b'0', b"")]);
        assert!(scan_bytes(&lying).unwrap_err().contains("incomplete"));
        // Per entry, in total, and in count, against lowered limits.
        let three = archive(&[file_entry("a", &[1; 600]), file_entry("b", &[2; 600]), file_entry("c", &[3; 600])]);
        let small = Limits { max_entries: 100, max_entry_size: 500, max_total: 1 << 20 };
        assert!(scan_with(&three, small).unwrap_err().contains("too large"));
        let total = Limits { max_entries: 100, max_entry_size: 1 << 20, max_total: 1000 };
        assert!(scan_with(&three, total).unwrap_err().contains("more than 1000 bytes"));
        let count = Limits { max_entries: 2, max_entry_size: 1 << 20, max_total: 1 << 20 };
        assert!(scan_with(&three, count).unwrap_err().contains("more than 2 entries"));
        // An extended header too large to read.
        let record = format!("path={}\n", "x".repeat(70_000));
        let big_pax = archive(&[pax(&format!("{} {record}", record.len() + 6)), raw_file(b"a", b"", b'0')]);
        assert!(scan_bytes(&big_pax).unwrap_err().contains("too large"));
    }

    #[test]
    fn truncated_archives_are_refused() {
        let whole = archive(&[file_entry("a.txt", &[9; 3000]), dir_header("d", 0)]);
        assert!(scan_bytes(&whole).is_ok());
        for cut in [0, 1, 100, 511, 512, 513, 2000, 3584, 4095, whole.len() - END.len()] {
            assert!(scan_bytes(&whole[..cut]).unwrap_err().contains("incomplete"), "cut at {cut}");
        }
        // A PAX record with nothing after it.
        let mut dangling = pax(&pax_path("name"));
        dangling.extend_from_slice(&END);
        assert!(scan_bytes(&dangling).is_err());
    }

    #[test]
    fn damaged_headers_duplicates_and_clashes_are_refused() {
        let mut bad_sum = file_entry("a", b"x");
        bad_sum[0] = b'b';
        assert!(scan_bytes(&archive(&[bad_sum])).unwrap_err().contains("checksum"));
        let bad_digits = archive(&[raw(b"a", b"0000000009\0\0", b'0', b"")]);
        assert!(scan_bytes(&bad_digits).is_err());
        let twice = archive(&[file_entry("a", b"1"), file_entry("a", b"2")]);
        assert!(scan_bytes(&twice).unwrap_err().contains("twice"));
        let dir_twice = archive(&[dir_header("d", 0), dir_header("d", 0)]);
        assert!(scan_bytes(&dir_twice).unwrap_err().contains("twice"));
        let file_then_dir = archive(&[file_entry("a", b"1"), dir_header("a", 0)]);
        assert!(scan_bytes(&file_then_dir).is_err());
        let file_then_inside = archive(&[file_entry("a", b"1"), file_entry("a/b", b"2")]);
        assert!(scan_bytes(&file_then_inside).is_err());
        let inside_then_file = archive(&[file_entry("a/b", b"2"), file_entry("a", b"1")]);
        assert!(scan_bytes(&inside_then_file).is_err());
        // A folder named after what's in it was seen first is the same folder.
        let late_dir = archive(&[file_entry("a/b", b"2"), dir_header("a", 0)]);
        assert!(scan_bytes(&late_dir).is_ok());
        // Not UTF-8.
        assert!(scan_bytes(&archive(&[raw_file(b"\xff\xfe", b"x", b'0')])).unwrap_err().contains("UTF-8"));
    }

    #[test]
    fn cancel_stops_a_scan() {
        let data = archive(&[file_entry("a", b"1"), file_entry("b", b"2")]);
        let err = scan(&mut Cursor::new(&data), data.len() as u64, &LIMITS, &|| true).unwrap_err();
        assert_eq!(err, CANCELLED);
    }

    #[test]
    fn looks_like_tar_needs_a_real_header() {
        assert!(looks_like_tar(&file_header("a", 0, 0).unwrap()));
        assert!(!looks_like_tar(&[0u8; BLOCK]));
        assert!(!looks_like_tar(&[b'x'; BLOCK]));
        assert!(!looks_like_tar(b"short"));
    }

    /// Seeded mutations of a good archive: whatever comes back must be safe.
    #[test]
    fn fuzzed_archives_never_escape_or_overrun() {
        use rand::{Rng, SeedableRng};
        let base = archive(&[
            dir_header("d", 0),
            file_entry("d/a.txt", &[1; 700]),
            file_entry(&format!("{}/long.bin", "p".repeat(110)), &[2; 40]),
            file_entry("e/f/g", b"g"),
        ]);
        let limits = Limits { max_entries: 64, max_entry_size: 1 << 16, max_total: 1 << 18 };
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x5eed);
        let (mut ok, mut refused) = (0, 0);
        for _ in 0..5000 {
            let mut data = base.clone();
            for _ in 0..rng.gen_range(1..6) {
                if data.len() < BLOCK {
                    break;
                }
                match rng.gen_range(0..5) {
                    0 => {
                        let i = rng.gen_range(0..data.len());
                        data[i] ^= 1 << rng.gen_range(0..8);
                    }
                    1 => {
                        let i = rng.gen_range(0..data.len());
                        data[i] = *[b'/', b'.', 0, b'\\', b'7', b'x', b'5', b'2', 0xff].get(rng.gen_range(0..9)).unwrap();
                    }
                    2 => data.truncate(rng.gen_range(0..data.len())),
                    3 => {
                        // Rewrite a size field to something large, fixing the checksum.
                        let block = rng.gen_range(0..data.len() / BLOCK) * BLOCK;
                        let size = [1u64 << 20, 1 << 33, u64::from(u32::MAX), 0o77777777777][rng.gen_range(0..4)];
                        let mut h: [u8; BLOCK] = data[block..block + BLOCK].try_into().unwrap();
                        put_octal(&mut h[124..136], size.min(0o77777777777));
                        h[148..156].fill(b' ');
                        let sum: u64 = h.iter().map(|&b| u64::from(b)).sum();
                        h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
                        data[block..block + BLOCK].copy_from_slice(&h);
                    }
                    _ => {
                        let at = rng.gen_range(0..=data.len() / BLOCK) * BLOCK;
                        let extra = raw(b"../../x", b"00000000001\0", b'0', b"");
                        data.splice(at..at, extra);
                    }
                }
            }
            match scan_with(&data, limits) {
                Err(_) => refused += 1,
                Ok(s) => {
                    ok += 1;
                    assert!(s.items.len() <= 64 * 64, "bounded");
                    assert!(s.total <= limits.max_total);
                    for (path, item) in &s.items {
                        assert_eq!(canonical_entry_path(path).unwrap().as_deref(), Some(path.as_str()), "{path:?}");
                        assert!(!path.split('/').any(|c| c == ".." || c == "." || c.is_empty()), "{path:?}");
                        assert!(ancestors(path).all(|a| s.items.get(a) == Some(&Item::Dir)), "{path:?}");
                        if let Item::File { offset, size } = item {
                            assert!(offset + size <= data.len() as u64, "{path:?} overruns");
                            assert!(*size <= limits.max_entry_size);
                        }
                    }
                }
            }
        }
        assert!(ok > 0 && refused > 0, "mutations must exercise both outcomes: {ok} ok, {refused} refused");
    }
}
