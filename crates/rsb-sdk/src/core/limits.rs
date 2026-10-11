//! Size limits for data decoded from a (possibly malicious) repository.
//!
//! A zstd frame of zeros expands ~32 000×, so every decompression of
//! repository data must be bounded by a size known independently of the
//! compressed input: the plaintext size recorded in the manifest entry
//! (`FileMetadata::size`, written since format v3), or the largest object
//! older versions could have written when that field is absent.

use std::io::{self, ErrorKind, Read};

/// Largest decoded manifest accepted.
pub const MAX_MANIFEST_SIZE: u64 = 256 * 1024 * 1024;
/// Largest single (non-chunked) object older versions wrote (their
/// multipart threshold was 4 GiB); bound for entries without `size`.
pub const LEGACY_MAX_OBJECT_SIZE: u64 = 4 * 1024 * 1024 * 1024;
/// Largest chunk older versions wrote (512 MiB); bound for chunk objects of
/// entries without `size`.
pub const LEGACY_MAX_CHUNK_SIZE: u64 = 512 * 1024 * 1024;

/// Typed error for decoded data exceeding its bound
/// (`io::ErrorKind::FileTooLarge`).
pub fn too_large(what: &str, limit: u64) -> io::Error {
    io::Error::new(
        ErrorKind::FileTooLarge,
        format!(
            "{} exceeds its expected size ({} bytes): refusing to decode further \
             (corrupt or malicious data)",
            what, limit
        ),
    )
}

/// Decompresses a zstd frame, failing with `FileTooLarge` as soon as the
/// output would exceed `limit` bytes (memory never exceeds `limit` + 64 KiB).
pub fn zstd_decode_bounded(input: &[u8], limit: u64, what: &str) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    zstd_decode_with(input, limit, what, |c| {
        out.extend_from_slice(c);
        Ok(())
    })?;
    Ok(out)
}

/// Decompresses a zstd frame and returns (BLAKE3 hex, length) without
/// keeping the output; fails with `FileTooLarge` beyond `limit` bytes.
pub fn zstd_hash_bounded(input: &[u8], limit: u64, what: &str) -> io::Result<(String, u64)> {
    let mut hasher = blake3::Hasher::new();
    let n = zstd_decode_with(input, limit, what, |c| {
        hasher.update(c);
        Ok(())
    })?;
    Ok((hasher.finalize().to_hex().to_string(), n))
}

fn zstd_decode_with(
    input: &[u8],
    limit: u64,
    what: &str,
    mut sink: impl FnMut(&[u8]) -> io::Result<()>,
) -> io::Result<u64> {
    let mut dec = zstd::stream::read::Decoder::with_buffer(input)?;
    let mut buf = vec![0u8; 64 * 1024];
    let mut total: u64 = 0;
    loop {
        let n = match dec.read(&mut buf) {
            Ok(0) => return Ok(total),
            Ok(n) => n,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        total += n as u64;
        if total > limit {
            return Err(too_large(what, limit));
        }
        sink(&buf[..n])?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bomb_is_refused_without_allocating_its_output() {
        // 64 MiB of zeros compress to a few KiB.
        let bomb = zstd::stream::encode_all(std::io::repeat(0).take(64 << 20), 19).unwrap();
        assert!(bomb.len() < 64 * 1024);
        let e = zstd_decode_bounded(&bomb, 1 << 20, "test").unwrap_err();
        assert_eq!(e.kind(), ErrorKind::FileTooLarge);
        let e = zstd_hash_bounded(&bomb, 1 << 20, "test").unwrap_err();
        assert_eq!(e.kind(), ErrorKind::FileTooLarge);
        // Exactly at the limit is fine.
        let ok = zstd::stream::encode_all(&[7u8; 1000][..], 3).unwrap();
        assert_eq!(
            zstd_decode_bounded(&ok, 1000, "t").unwrap(),
            vec![7u8; 1000]
        );
        assert_eq!(zstd_hash_bounded(&ok, 1000, "t").unwrap().1, 1000);
        assert!(zstd_decode_bounded(&ok, 999, "t").is_err());
    }
}
