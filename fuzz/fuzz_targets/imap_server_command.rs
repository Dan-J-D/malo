//! Commands from a (malicious) mail app to Malo's IMAP server: the parsers never panic, and
//! nesting, wildcards and sets stay bounded.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() <= 64 * 1024 {
        malo_server::mail::imap::fuzz_command(data);
    }
});
