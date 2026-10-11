use crate::{Config, core::types::FileMetadata, crypto::decrypt_data};

pub fn verify_content_hash(
    data: &[u8],
    metadata: &FileMetadata,
    config: &Config,
) -> Result<(), String> {
    // 1. Decriptação
    let decrypted = if metadata.encrypted {
        if let Some(k) = config.encryption_key.as_deref() {
            decrypt_data(data, k.as_bytes()).map_err(|e| format!("Decryption failed: {}", e))?
        } else {
            data.to_vec()
        }
    } else {
        data.to_vec()
    };

    let final_data = if metadata.compressed {
        crate::core::limits::zstd_decode_bounded(
            &decrypted,
            metadata.max_plain_size(),
            &metadata.hash,
        )
        .map_err(|e| format!("Decompression failed: {}", e))?
    } else {
        decrypted
    };

    let computed_hash = crate::crypto::hash_file_content(&final_data)
        .map_err(|e| format!("Hash calculation failed: {}", e))?;

    if computed_hash != metadata.hash {
        return Err(format!(
            "Hash mismatch: expected {}, got {}",
            metadata.hash, computed_hash
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zstd_bomb_is_bounded_by_recorded_size() {
        let bomb =
            zstd::stream::encode_all(std::io::Read::take(std::io::repeat(0), 64 << 20), 1).unwrap();
        let meta = FileMetadata::new("0".repeat(64), false, true).with_size(1024);
        let err = verify_content_hash(&bomb, &meta, &Config::default()).unwrap_err();
        assert!(err.contains("exceeds"), "{err}");
    }
}
