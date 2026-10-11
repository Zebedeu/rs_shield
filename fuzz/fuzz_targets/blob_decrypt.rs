#![no_main]
//! Arbitrary bytes -> encrypted blob parsing/decryption (legacy + v2).
//! TODO(format-v3): add a v3 `BlobDecryptor` once the new format lands.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    rsb_sdk::fuzzing::fuzz_blob_decrypt(data);
});
