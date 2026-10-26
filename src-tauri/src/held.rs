//! Secrets the UI passes along without seeing them: a refresh token from the OAuth sign-in or the
//! key in a plain recovery kit. The UI gets a placeholder; requests to the server carry the secret
//! in its place, put back here on the Rust side.

use std::sync::Mutex;

use rand::RngCore;
use zeroize::Zeroizing;

const PREFIX: &str = "malo-held-secret:";
/// Placeholders kept; the oldest go first.
const KEPT: usize = 16;

#[derive(Default)]
pub struct Held(Mutex<Vec<(String, Zeroizing<String>)>>);

impl Held {
    /// Keeps `secret` and returns the placeholder for it.
    pub fn hold(&self, secret: String) -> String {
        let mut b = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut b);
        let placeholder = format!("{PREFIX}{}", hex::encode(b));
        let mut held = self.0.lock().unwrap();
        if held.len() >= KEPT {
            held.remove(0);
        }
        held.push((placeholder.clone(), Zeroizing::new(secret)));
        placeholder
    }

    /// Puts the secrets back in place of their placeholders, anywhere in a request body.
    pub fn release(&self, value: &mut serde_json::Value) {
        match value {
            serde_json::Value::String(s) if s.starts_with(PREFIX) => {
                let held = self.0.lock().unwrap();
                if let Some((_, secret)) = held.iter().find(|(p, _)| p == s) {
                    *s = secret.to_string();
                }
            }
            serde_json::Value::Array(a) => a.iter_mut().for_each(|v| self.release(v)),
            serde_json::Value::Object(o) => o.values_mut().for_each(|v| self.release(v)),
            _ => {}
        }
    }

    pub fn clear(&self) {
        self.0.lock().unwrap().clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholders_are_swapped_back() {
        let held = Held::default();
        let p = held.hold("refresh-123".into());
        assert!(p.starts_with(PREFIX) && !p.contains("refresh"));
        let mut body = serde_json::json!({
            "auth": { "kind": "oauth2", "refresh_token": p },
            "list": [p, "other"],
            "unknown": format!("{PREFIX}00"),
        });
        held.release(&mut body);
        assert_eq!(body["auth"]["refresh_token"], "refresh-123");
        assert_eq!(body["list"][0], "refresh-123");
        assert_eq!(
            body["unknown"],
            format!("{PREFIX}00"),
            "unknown placeholders stay"
        );
        for i in 0..KEPT {
            held.hold(format!("s{i}"));
        }
        let mut old = serde_json::json!(p);
        held.release(&mut old);
        assert_eq!(old, serde_json::json!(p), "the oldest were dropped");
        held.clear();
    }
}
