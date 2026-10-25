//! Encrypted objects come back from storage: arbitrary ciphertext must be rejected cleanly, and
//! anything Malo encrypts must decrypt to the same bytes however it is split into chunks.
#![no_main]
use libfuzzer_sys::fuzz_target;
use malo_core::crypto::{decrypt_object, encrypt_object, Key, StreamDecryptor};

fuzz_target!(|data: &[u8]| {
    let key: Key = zeroize::Zeroizing::new([7u8; 32]);
    // 1. Arbitrary bytes: never panic, in one piece or in chunks.
    let _ = decrypt_object(&key, data);
    let split = data.first().map(|b| *b as usize + 1).unwrap_or(1);
    let mut d = StreamDecryptor::new(&key);
    let mut ok = true;
    for chunk in data.chunks(split) {
        if d.update(chunk).is_err() {
            ok = false;
            break;
        }
    }
    if ok {
        let _ = d.finish();
    }
    // 2. Round trip of the input as plaintext, with tampering detected.
    let ct = encrypt_object(&key, data);
    assert_eq!(decrypt_object(&key, &ct).expect("round trip"), data);
    let mut d = StreamDecryptor::new(&key);
    let mut out = Vec::new();
    for chunk in ct.chunks(split * 97) {
        out.extend(d.update(chunk).expect("chunked round trip"));
    }
    out.extend(d.finish().expect("final segment"));
    assert_eq!(out, data);
    if !ct.is_empty() {
        let mut bad = ct.clone();
        let i = split % bad.len();
        bad[i] ^= 1;
        assert!(decrypt_object(&key, &bad).is_err(), "tampering at byte {i} not detected");
        assert!(decrypt_object(&key, &ct[..ct.len() - 1]).is_err(), "truncation not detected");
    }
});
