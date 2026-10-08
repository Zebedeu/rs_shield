//! Snapshot manifest I/O.
//!
//! Thin re-export of [`crate::core::manifest`], the single implementation of
//! snapshot naming (`%Y-%m-%dT%H%M%S%.3fZ` with optional `-n` suffix),
//! parsing, id validation and (KeyCache-based) manifest decryption. Kept so
//! that `rsb_sdk::snapshot::manifest::*` paths resolve to the current code
//! instead of a stale copy.
pub use crate::core::manifest::*;
