//! Mailbox, account and file names from anywhere: decoding/encoding never panics, every generated
//! storage path passes the traversal check, components fit on disk, and UTF-7 round-trips.
#![no_main]
use libfuzzer_sys::fuzz_target;
use malo_core::layout::*;

fuzz_target!(|data: &[u8]| {
    let s = String::from_utf8_lossy(data);
    let decoded = decode_utf7(&s);
    assert_eq!(decode_utf7(&encode_utf7(&decoded)), decoded, "UTF-7 round trip");
    for delim in [Some("/"), Some("."), None] {
        let mailbox = mailbox_path(&s, delim);
        let path = plain_object_path("root", &plain_account_dir(&s, &s), &mailbox, 1, 2);
        assert!(check_rel_path(&path).is_ok(), "{path:?}");
        assert!(path.split('/').all(|c| c.len() <= 120 && c != ".." && c != "."), "{path:?}");
        let manifest = plain_manifest_path("root", "acc", &mailbox);
        assert!(check_rel_path(&manifest).is_ok(), "{manifest:?}");
    }
    let c = safe_component(&s);
    assert!(!c.contains('/') && !c.chars().any(is_invisible), "{c:?}");
    let _ = check_rel_path(&s);
    let _ = ascii_path(&s);
});
