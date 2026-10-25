//! Manifests are read back from storage (untrusted): parsing never panics, and the checks the
//! index rebuild applies hold for whatever comes out.
#![no_main]
use libfuzzer_sys::fuzz_target;
use malo_core::store::ManifestEntry;

fuzz_target!(|data: &[u8]| {
    for line in data.split(|b| *b == b'\n') {
        if let Ok(e) = serde_json::from_slice::<ManifestEntry>(line) {
            if malo_core::layout::check_rel_path(&e.object_path).is_ok() {
                assert!(!e.object_path.split('/').any(|s| s == ".." || s == "."));
                assert!(!e.object_path.contains('\\'));
            }
            let _ = malo_core::layout::mailbox_path(&e.mailbox, e.delimiter.as_deref());
        }
    }
});
