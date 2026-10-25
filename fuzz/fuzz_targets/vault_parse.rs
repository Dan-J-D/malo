//! vault.bin parsing never panics. Opening is only attempted with cheap KDF parameters: the
//! parameters live in the (server-written) file, so huge values would just allocate memory.
#![no_main]
use libfuzzer_sys::fuzz_target;
use malo_core::crypto::Vault;

fuzz_target!(|data: &[u8]| {
    if let Ok(v) = Vault::from_bytes(data) {
        assert_eq!(Vault::from_bytes(&v.to_bytes()).unwrap().to_bytes(), v.to_bytes());
        if v.params.m_kib <= 64 && v.params.m_kib >= 8 && v.params.t <= 2 && (1..=2).contains(&v.params.p) {
            assert!(v.open("user", "password").is_err(), "a fuzzed vault opened");
        }
    }
});
