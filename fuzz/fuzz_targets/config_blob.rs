//! Encrypted config blobs: arbitrary bytes are rejected without panicking.
#![no_main]
use libfuzzer_sys::fuzz_target;
use malo_core::config::UserConfig;

fuzz_target!(|data: &[u8]| {
    let key = zeroize::Zeroizing::new([3u8; 32]);
    assert!(UserConfig::open(&key, "user", data).is_err() || data.len() > 28);
});
