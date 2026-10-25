//! Raw responses from a (malicious) IMAP server: the parser Malo relies on never panics.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut rest = data;
    for _ in 0..64 {
        match imap_proto::parser::parse_response(rest) {
            Ok((next, _)) if next.len() < rest.len() => rest = next,
            _ => break,
        }
    }
});
