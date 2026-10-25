//! Hostile HTML in → inert HTML out: no scripts, handlers, frames, forms, javascript: URLs,
//! CSS url()/expression, and (without permission) no remote resources.
#![no_main]
use std::collections::HashMap;

use libfuzzer_sys::fuzz_target;

mod html_check;
use malo_core::viewer::sanitize_html;

fuzz_target!(|data: &[u8]| {
    let html = String::from_utf8_lossy(data);
    let parts = HashMap::from([("a@b".to_string(), "data:image/png;base64,AAAA".to_string())]);
    let out = sanitize_html(&html, &parts, false).html;
    html_check::assert_inert(&out, false);
});
