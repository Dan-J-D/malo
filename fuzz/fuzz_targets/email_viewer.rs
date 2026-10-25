//! Any email: parsing, rendering (text and sanitized HTML, with and without remote images),
//! attachment extraction and envelope building never panic, and HTML output stays inert.
#![no_main]
use libfuzzer_sys::fuzz_target;

mod html_check;
use malo_core::viewer;

fuzz_target!(|data: &[u8]| {
    for (html, remote) in [(false, false), (true, false), (true, true)] {
        if let Ok(v) = viewer::render(1, data, html, remote) {
            if let Some(h) = v.html {
                html_check::assert_inert(&h, remote);
            }
            for i in 0..v.attachments.len().min(4) {
                let _ = viewer::attachment(data, i as u32);
            }
        }
    }
    let _ = viewer::envelope_of(data);
    let _ = malo_core::imap::decode_words(&data[..data.len().min(512)]);
});
