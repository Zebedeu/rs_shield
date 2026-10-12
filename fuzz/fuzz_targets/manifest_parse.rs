#![no_main]
//! Arbitrary bytes -> manifest TOML, snapshot names and restore path checks.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    rsb_sdk::fuzzing::fuzz_manifest_parse(data);
});
