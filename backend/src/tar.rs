// Just enough of the tar format for Share to hand over a folder as one file, without a new
// crate (VAULTS_PLAN.md rules those out). Writes only: this code never reads an archive, so
// nothing a stranger sends goes through it. ustar, plus a PAX record for a path that won't
// fit in its 100 bytes, which every tar since the 2000s understands.

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
}
