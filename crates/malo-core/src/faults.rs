//! Test-only fault injection for storage and local-disk I/O.
//!
//! Compiled to no-ops unless the `fault-injection` cargo feature is enabled (only test builds do).
//! Fuzzers install seeded rules; every I/O site in Malo asks [`pick`] whether to misbehave.

use serde::{Deserialize, Serialize};

/// Where the I/O happens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Site {
    /// Object and manifest uploads to a destination.
    StoreWrite,
    /// Object and manifest downloads (read-back, viewer, deep checks, repair sources).
    StoreRead,
    /// stat / list / delete on a destination.
    StoreMeta,
    /// Encrypted download spool on the server's disk.
    Spool,
    /// Encrypted viewer cache on the server's disk.
    Cache,
    /// Atomic writes of config.bin / vault.bin.
    ConfigWrite,
    /// The SQLCipher index (any statement).
    Index,
}

/// What goes wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Fault {
    /// EIO
    Error,
    /// ENOSPC
    NoSpace,
    /// Only the first half of the bytes arrive (write) or come back (read).
    Truncate,
    /// One byte is silently flipped.
    FlipBit,
    /// The write reports success but nothing is stored.
    LostWrite,
    /// The write lands, then the call fails anyway (ambiguous outcome).
    WriteThenError,
    /// 300 ms extra latency.
    Slow,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub site: Site,
    pub fault: Fault,
    /// Probability in 1/1000.
    pub per_mille: u32,
    /// Destination id (store sites) — `None` matches everything.
    pub scope: Option<String>,
    /// Number of injections before the rule expires; `None` = until cleared.
    pub remaining: Option<u32>,
}

pub fn io_error(fault: Fault) -> std::io::Error {
    match fault {
        Fault::NoSpace => std::io::Error::other("No space left on device (injected)"),
        _ => std::io::Error::other("Input/output error (injected)"),
    }
}

/// Applies a read fault to bytes that were read successfully.
pub fn corrupt_read(fault: Fault, mut data: Vec<u8>) -> std::io::Result<Vec<u8>> {
    match fault {
        Fault::Truncate => {
            data.truncate(data.len() / 2);
            Ok(data)
        }
        Fault::FlipBit => {
            if !data.is_empty() {
                let i = data.len() / 2;
                data[i] ^= 0x10;
            }
            Ok(data)
        }
        Fault::Slow | Fault::LostWrite | Fault::WriteThenError => Ok(data),
        Fault::Error | Fault::NoSpace => Err(io_error(fault)),
    }
}

#[cfg(feature = "fault-injection")]
mod imp {
    use std::sync::Mutex;

    use once_cell::sync::Lazy;
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};

    use super::{Fault, Rule, Site};

    struct State {
        rules: Vec<Rule>,
        rng: StdRng,
        injected: u64,
        last: std::collections::HashMap<Site, std::time::Instant>,
    }

    static STATE: Lazy<Mutex<State>> = Lazy::new(|| {
        Mutex::new(State {
            rules: vec![],
            rng: StdRng::seed_from_u64(0),
            injected: 0,
            last: Default::default(),
        })
    });

    pub fn reset(seed: u64) {
        let mut s = STATE.lock().unwrap();
        s.rules.clear();
        s.rng = StdRng::seed_from_u64(seed);
        s.injected = 0;
        s.last.clear();
    }

    pub fn add(rule: Rule) {
        STATE.lock().unwrap().rules.push(rule);
    }

    pub fn clear() {
        STATE.lock().unwrap().rules.clear();
    }

    pub fn injected() -> u64 {
        STATE.lock().unwrap().injected
    }

    /// Whether a fault was injected at `site` within `within`.
    pub fn injected_recently(site: Site, within: std::time::Duration) -> bool {
        STATE
            .lock()
            .unwrap()
            .last
            .get(&site)
            .is_some_and(|t| t.elapsed() < within)
    }

    pub fn active(site: Site) -> bool {
        STATE.lock().unwrap().rules.iter().any(|r| r.site == site)
    }

    pub fn pick(site: Site, scope: &str) -> Option<Fault> {
        let mut s = STATE.lock().unwrap();
        if s.rules.is_empty() {
            return None;
        }
        let roll: u32 = s.rng.gen_range(0..1000);
        let i = s.rules.iter().position(|r| {
            r.site == site && r.scope.as_deref().is_none_or(|sc| sc == scope) && roll < r.per_mille
        })?;
        let fault = s.rules[i].fault;
        if let Some(n) = s.rules[i].remaining.as_mut() {
            *n = n.saturating_sub(1);
            if *n == 0 {
                s.rules.remove(i);
            }
        }
        s.injected += 1;
        s.last.insert(site, std::time::Instant::now());
        tracing::debug!(?site, scope, ?fault, "fault injected");
        Some(fault)
    }
}

#[cfg(not(feature = "fault-injection"))]
mod imp {
    use super::{Fault, Rule, Site};

    pub fn reset(_seed: u64) {}
    pub fn add(_rule: Rule) {}
    pub fn clear() {}
    pub fn injected() -> u64 {
        0
    }
    pub fn active(_site: Site) -> bool {
        false
    }
    pub fn injected_recently(_site: Site, _within: std::time::Duration) -> bool {
        false
    }
    #[inline(always)]
    pub fn pick(_site: Site, _scope: &str) -> Option<Fault> {
        None
    }
}

pub use imp::{active, add, clear, injected, injected_recently, pick, reset};
