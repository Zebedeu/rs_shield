//! Printable ("paper") form of a key file, for `rsb key export --paper`.
//!
//! ```text
//! RSB-REPO-KEY PAPER v1 bytes=412 check=1a2b3c4d
//! 01  ABCD EFGH IJKL MNOP QRST UVWX YZ23 4567  K7Q2
//! 02  ...
//! ```
//!
//! The data is RFC 4648 base32 (A-Z, 2-7: no 0/1/8/9 to confuse with
//! O/I/B), 32 characters (20 bytes) per line in groups of four. Each line
//! ends with a 4-character checksum: base32 of the first 20 bits of
//! `BLAKE3("rsb paper v1" | line number u16 BE | the line's 32 characters)`,
//! so a typo is reported with its line number (a random typo slips through
//! with probability 2^-20). The header holds the byte count and the first 4
//! bytes of BLAKE3 of the whole content (catches missing or swapped lines).
//!
//! Decoding ignores case, blank lines and spacing, and reads `0`, `1` and
//! `8` as `O`, `I` and `B`.

const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const HEADER: &str = "RSB-REPO-KEY PAPER v1";
const CHARS_PER_LINE: usize = 32;
const GROUP: usize = 4;
const LINE_CHECK_LEN: usize = 4;

/// A paper key that cannot be decoded; the message names the line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaperError(pub String);

impl std::fmt::Display for PaperError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for PaperError {}

fn base32_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(5) * 8);
    let (mut buf, mut bits) = (0u32, 0u32);
    for &b in data {
        buf = (buf << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((buf >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buf << (5 - bits)) & 31) as usize] as char);
    }
    out
}

fn base32_value(c: u8) -> Option<u32> {
    match c {
        b'A'..=b'Z' => Some((c - b'A') as u32),
        b'2'..=b'7' => Some((c - b'2') as u32 + 26),
        _ => None,
    }
}

fn base32_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 5 / 8);
    let (mut buf, mut bits) = (0u32, 0u32);
    for c in s.bytes() {
        buf = (buf << 5) | base32_value(c)?;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    Some(out)
}

fn line_check(line_no: usize, chars: &str) -> String {
    let mut h = blake3::Hasher::new();
    h.update(b"rsb paper v1");
    h.update(&(line_no as u16).to_be_bytes());
    h.update(chars.as_bytes());
    base32_encode(&h.finalize().as_bytes()[..3])[..LINE_CHECK_LEN].to_string()
}

fn doc_check(data: &[u8]) -> String {
    blake3::hash(data).to_hex()[..8].to_string()
}

/// Canonical character: uppercase, with 0/1/8 read as O/I/B.
fn normalize(c: char) -> char {
    match c.to_ascii_uppercase() {
        '0' => 'O',
        '1' => 'I',
        '8' => 'B',
        c => c,
    }
}

/// Printable form of `data`.
pub fn encode(data: &[u8]) -> String {
    let b32 = base32_encode(data);
    let mut out = format!(
        "{} bytes={} check={}\n",
        HEADER,
        data.len(),
        doc_check(data)
    );
    for (i, chunk) in b32.as_bytes().chunks(CHARS_PER_LINE).enumerate() {
        let chars = std::str::from_utf8(chunk).unwrap_or_default();
        let groups: Vec<&str> = chunk
            .chunks(GROUP)
            .map(|g| std::str::from_utf8(g).unwrap_or_default())
            .collect();
        out.push_str(&format!(
            "{:02}  {}  {}\n",
            i + 1,
            groups.join(" "),
            line_check(i + 1, chars)
        ));
    }
    out
}

/// True if `text` looks like the output of [`encode`].
pub fn is_paper(text: &[u8]) -> bool {
    std::str::from_utf8(text)
        .map(|t| {
            t.trim_start()
                .to_ascii_uppercase()
                .starts_with(&HEADER.to_ascii_uppercase())
        })
        .unwrap_or(false)
}

/// Decodes the output of [`encode`] (possibly retyped by hand).
pub fn decode(text: &str) -> Result<Vec<u8>, PaperError> {
    let mut lines = text.lines().map(str::trim).filter(|l| !l.is_empty());
    let header = lines
        .next()
        .ok_or_else(|| PaperError("empty paper key".into()))?;
    let upper = header.to_ascii_uppercase();
    let rest = upper
        .strip_prefix(&HEADER.to_ascii_uppercase())
        .ok_or_else(|| PaperError(format!("first line must start with '{}'", HEADER)))?;
    let mut bytes = None;
    let mut check = None;
    for field in rest.split_whitespace() {
        if let Some(v) = field.strip_prefix("BYTES=") {
            bytes = v.parse::<usize>().ok();
        } else if let Some(v) = field.strip_prefix("CHECK=") {
            check = Some(v.to_ascii_lowercase());
        }
    }
    let (bytes, check) = match (bytes, check) {
        (Some(b), Some(c)) => (b, c),
        _ => return Err(PaperError("header line is missing bytes= or check=".into())),
    };

    let mut data = String::new();
    for (i, line) in lines.enumerate() {
        let expected_no = i + 1;
        let mut tokens = line.split_whitespace();
        let no = tokens
            .next()
            .and_then(|t| t.trim_end_matches(':').parse::<usize>().ok())
            .ok_or_else(|| PaperError(format!("line {}: missing line number", expected_no)))?;
        if no != expected_no {
            return Err(PaperError(format!(
                "line {}: numbered {} (missing, extra or reordered line)",
                expected_no, no
            )));
        }
        let mut chars: String = tokens.collect::<String>().chars().map(normalize).collect();
        if chars.len() <= LINE_CHECK_LEN {
            return Err(PaperError(format!("line {}: too short", no)));
        }
        let sum = chars.split_off(chars.len() - LINE_CHECK_LEN);
        if let Some(bad) = chars.chars().find(|c| base32_value(*c as u8).is_none()) {
            return Err(PaperError(format!(
                "line {}: invalid character '{}' (typo?)",
                no, bad
            )));
        }
        if line_check(no, &chars) != sum {
            return Err(PaperError(format!(
                "line {}: checksum mismatch (typo on this line?)",
                no
            )));
        }
        data.push_str(&chars);
    }
    let out = base32_decode(&data).ok_or_else(|| PaperError("invalid base32 data".into()))?;
    if out.len() != bytes || doc_check(&out) != check {
        return Err(PaperError(format!(
            "decoded {} bytes but the header says {} (or the overall check failed): \
             a line is missing or out of place",
            out.len(),
            bytes
        )));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base32_matches_rfc4648_vectors() {
        for (pt, ct) in [
            ("", ""),
            ("f", "MY"),
            ("fo", "MZXQ"),
            ("foo", "MZXW6"),
            ("foob", "MZXW6YQ"),
            ("fooba", "MZXW6YTB"),
            ("foobar", "MZXW6YTBOI"),
        ] {
            assert_eq!(base32_encode(pt.as_bytes()), ct);
            assert_eq!(base32_decode(ct).unwrap(), pt.as_bytes());
        }
    }

    #[test]
    fn roundtrip_lowercase_and_spacing() {
        for len in [0usize, 1, 19, 20, 21, 413] {
            let data: Vec<u8> = (0..len).map(|i| (i * 37 % 256) as u8).collect();
            let text = encode(&data);
            assert!(is_paper(text.as_bytes()));
            assert_eq!(decode(&text).unwrap(), data, "len {}", len);
            let sloppy = text.to_lowercase().replace("  ", "   ");
            assert_eq!(decode(&format!("\n{}\n\n", sloppy)).unwrap(), data);
        }
    }

    #[test]
    fn typos_are_located() {
        let data: Vec<u8> = (0..100u8).collect();
        let text = encode(&data);
        let mut lines: Vec<String> = text.lines().map(String::from).collect();
        // Change one data character on line 3.
        let l = &mut lines[3];
        let pos = 6;
        let c = l.as_bytes()[pos];
        let new = if c == b'A' { 'B' } else { 'A' };
        l.replace_range(pos..pos + 1, &new.to_string());
        let err = decode(&lines.join("\n")).unwrap_err();
        assert!(err.0.contains("line 3"), "{}", err);
        // Missing line.
        let mut lines: Vec<String> = text.lines().map(String::from).collect();
        lines.remove(2);
        assert!(decode(&lines.join("\n")).is_err());
        // Invalid character.
        let bad = text.replacen("01  ", "01  !", 1);
        assert!(decode(&bad).unwrap_err().0.contains("line 1"));
    }
}
