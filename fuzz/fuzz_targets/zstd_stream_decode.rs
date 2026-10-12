#![no_main]
//! Arbitrary bytes -> streaming zstd decode (restore path), output capped.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    rsb_sdk::fuzzing::fuzz_zstd_stream_decode(data);
});
