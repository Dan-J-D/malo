//! Request bodies for accounts and destinations: deserialization and validation never panic, and
//! anything that validates is safe to use as a storage location.
#![no_main]
use libfuzzer_sys::fuzz_target;
use malo_api::{AccountInput, DestinationInput};
use malo_core::config::{Account, Destination};

fuzz_target!(|data: &[u8]| {
    if let Ok(input) = serde_json::from_slice::<AccountInput>(data) {
        if let Ok(a) = Account::from_input("id".into(), input, None) {
            assert!(!a.name.chars().any(malo_core::layout::is_invisible));
            let _ = a.view();
        }
    }
    if let Ok(input) = serde_json::from_slice::<DestinationInput>(data) {
        if let Ok(d) = Destination::from_input("id".into(), input, None) {
            assert!(malo_core::layout::check_rel_path(&d.root).is_ok());
            assert!(malo_core::store::validate_destination(&d).is_ok());
            let _ = d.view();
        }
    }
});
