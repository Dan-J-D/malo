//! Upload and download speed limits: server-wide (set by an administrator) and per destination.
//!
//! A limiter is a token bucket that may go into debt: a transfer takes what it needs and the next
//! one waits until the debt is paid off. Transfers are whole objects or messages, so the rate is
//! held on average, with bursts of at most one object above it.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use once_cell::sync::Lazy;

/// Burst allowance: one second's worth of bytes.
const BURST: Duration = Duration::from_secs(1);

#[derive(Debug)]
pub struct Limiter {
    state: Mutex<State>,
}

#[derive(Debug)]
struct State {
    /// Bytes per second; 0 means unlimited.
    rate: u64,
    /// When the bytes taken so far have been "paid for".
    free_at: Instant,
}

impl Limiter {
    pub fn new(kib_per_sec: u32) -> Limiter {
        Limiter {
            state: Mutex::new(State {
                rate: kib_per_sec as u64 * 1024,
                free_at: Instant::now(),
            }),
        }
    }

    pub fn set(&self, kib_per_sec: u32) {
        let mut s = self.state.lock().unwrap();
        let rate = kib_per_sec as u64 * 1024;
        if s.rate != rate {
            s.rate = rate;
            s.free_at = Instant::now();
        }
    }

    pub fn unlimited(&self) -> bool {
        self.state.lock().unwrap().rate == 0
    }

    /// How long to wait before transferring `bytes` (and books them).
    fn reserve(&self, bytes: u64) -> Duration {
        let mut s = self.state.lock().unwrap();
        if s.rate == 0 || bytes == 0 {
            return Duration::ZERO;
        }
        let now = Instant::now();
        // Unused allowance doesn't pile up beyond the burst.
        let start = s.free_at.max(now.checked_sub(BURST).unwrap_or(now));
        let cost = Duration::from_secs_f64(bytes as f64 / s.rate as f64);
        s.free_at = start + cost;
        s.free_at.saturating_duration_since(now + BURST)
    }

    /// Waits until `bytes` may be transferred.
    pub async fn take(&self, bytes: u64) {
        let wait = self.reserve(bytes);
        if !wait.is_zero() {
            tokio::time::sleep(wait).await;
        }
    }
}

static UPLOAD: Lazy<Arc<Limiter>> = Lazy::new(|| Arc::new(Limiter::new(0)));
static DOWNLOAD: Lazy<Arc<Limiter>> = Lazy::new(|| Arc::new(Limiter::new(0)));
/// Upload and download limiter of a destination.
type Pair = (Arc<Limiter>, Arc<Limiter>);
static DESTINATIONS: Lazy<Mutex<HashMap<String, Pair>>> = Lazy::new(Default::default);

/// Sets the server-wide limits (KiB/s, 0: none).
pub fn set_global(upload_kib_per_sec: u32, download_kib_per_sec: u32) {
    UPLOAD.set(upload_kib_per_sec);
    DOWNLOAD.set(download_kib_per_sec);
}

/// Every write to storage passes this, whatever the destination.
pub fn global_upload() -> Arc<Limiter> {
    UPLOAD.clone()
}

/// Every download from a mail server or from storage passes this.
pub fn global_download() -> Arc<Limiter> {
    DOWNLOAD.clone()
}

/// The upload and download limiters of one destination, shared by every job that uses it.
pub fn destination(id: &str, up_kib: u32, down_kib: u32) -> (Arc<Limiter>, Arc<Limiter>) {
    let mut map = DESTINATIONS.lock().unwrap();
    let pair = map.entry(id.to_string()).or_insert_with(|| {
        (
            Arc::new(Limiter::new(up_kib)),
            Arc::new(Limiter::new(down_kib)),
        )
    });
    pair.0.set(up_kib);
    pair.1.set(down_kib);
    pair.clone()
}

/// Bytes downloaded from a mail server.
pub async fn imap_download(bytes: u64) {
    DOWNLOAD.take(bytes).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unlimited_never_waits() {
        let l = Limiter::new(0);
        assert_eq!(l.reserve(u64::MAX / 2), Duration::ZERO);
    }

    #[test]
    fn rate_is_held_after_the_burst() {
        let l = Limiter::new(100); // 100 KiB/s
                                   // The first second's worth goes at once.
        assert_eq!(l.reserve(100 * 1024), Duration::ZERO);
        // The next 200 KiB are 2 s of transfer beyond the allowance.
        let w = l.reserve(200 * 1024);
        assert!(
            w > Duration::from_millis(1900) && w <= Duration::from_secs(2),
            "{w:?}"
        );
        l.set(0);
        assert_eq!(l.reserve(1 << 30), Duration::ZERO);
    }
}
