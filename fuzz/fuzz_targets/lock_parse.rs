#![no_main]
//! Arbitrary bytes -> repository lock object parsing + staleness decision.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    rsb_sdk::fuzzing::fuzz_lock_parse(data);
});
