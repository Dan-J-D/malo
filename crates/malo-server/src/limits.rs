//! Limits on what unauthenticated clients can make the server do: failed-login backoff, and how
//! much Argon2id work runs at once.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use tokio::sync::{Semaphore, SemaphorePermit};

/// The address limits are counted for: an IPv4 address, or the /64 an IPv6 client can pick any
/// address in.
pub fn client_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => {
                let s = v6.segments();
                IpAddr::V6(Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0))
            }
        },
    }
}

// ───────────────────────────── failed logins ─────────────────────────────

/// Backoff for one client guessing one user's password: steep after five misses.
fn failure_delay(n: u32) -> Duration {
    if n < 5 {
        Duration::ZERO
    } else {
        Duration::from_secs((30u64 << (n - 5).min(5)).min(15 * 60))
    }
}

/// Backoff for one user across all clients: it slows guessing spread over many addresses, but is
/// short enough that nobody can keep a user locked out by failing on purpose.
fn user_failure_delay(n: u32) -> Duration {
    if n < 20 {
        Duration::ZERO
    } else {
        Duration::from_secs((5u64 << ((n - 20) / 5).min(4)).min(60))
    }
}

/// Backoff for one client across all names: guessing many names (or making up names to flood the
/// table) slows down too. Generous, as a NAT can put many people behind one address.
fn client_failure_delay(n: u32) -> Duration {
    if n < 30 {
        Duration::ZERO
    } else {
        Duration::from_secs((10u64 << ((n - 30) / 10).min(6)).min(10 * 60))
    }
}

/// How long to wait after `n` failures.
type Backoff = fn(u32) -> Duration;

/// A count is forgotten after this long without a new failure.
const FORGET_AFTER: Duration = Duration::from_secs(3600);
/// Most entries are for names that don't exist; the oldest are dropped so the table stays small.
const FAILURES_KEPT: usize = 10_000;

struct Entry {
    n: u32,
    at: Instant,
    delay: Backoff,
}

impl Entry {
    fn wait(&self) -> Option<Duration> {
        let wait = self.delay(self.n);
        let elapsed = self.at.elapsed();
        (elapsed < wait).then(|| wait - elapsed)
    }

    fn delay(&self, n: u32) -> Duration {
        (self.delay)(n)
    }
}

/// Failed logins, counted per name and client, per name alone and per client alone.
pub struct Failures {
    map: Mutex<HashMap<String, Entry>>,
    kept: usize,
}

impl Default for Failures {
    fn default() -> Self {
        Failures::with_capacity(FAILURES_KEPT)
    }
}

impl Failures {
    fn with_capacity(kept: usize) -> Failures {
        Failures {
            map: Mutex::new(HashMap::new()),
            kept,
        }
    }

    fn keys(name: &str, ip: IpAddr) -> [(String, Backoff); 3] {
        let name = name.to_lowercase();
        let ip = client_key(ip);
        [
            (format!("{name}|{ip}"), failure_delay),
            (format!("{ip}|"), client_failure_delay),
            (name, user_failure_delay),
        ]
    }

    /// The time left to wait if `name` or this client is backed off.
    pub fn check(&self, name: &str, ip: IpAddr) -> Option<Duration> {
        let map = self.map.lock().unwrap();
        Failures::keys(name, ip)
            .iter()
            .filter_map(|(k, _)| map.get(k)?.wait())
            .max()
    }

    pub fn record(&self, name: &str, ip: IpAddr) {
        let mut map = self.map.lock().unwrap();
        for (key, delay) in Failures::keys(name, ip) {
            if !map.contains_key(&key) && map.len() >= self.kept && !Failures::evict(&mut map) {
                // Everything kept is still backing someone off; the per-client count goes on.
                continue;
            }
            let e = map.entry(key).or_insert(Entry {
                n: 0,
                at: Instant::now(),
                delay,
            });
            if e.at.elapsed() > FORGET_AFTER {
                e.n = 0;
            }
            e.n = e.n.saturating_add(1);
            e.at = Instant::now();
        }
    }

    /// Drops the oldest tenth of the entries that no longer back anyone off. False if there are
    /// none: entries that still do are never dropped, or flooding the table would lift them.
    fn evict(map: &mut HashMap<String, Entry>) -> bool {
        let mut idle: Vec<(Instant, String)> = map
            .iter()
            .filter(|(_, e)| e.wait().is_none())
            .map(|(k, e)| (e.at, k.clone()))
            .collect();
        if idle.is_empty() {
            return false;
        }
        idle.sort_unstable();
        let n = (map.len() / 10).clamp(1, idle.len());
        for (_, k) in idle.into_iter().take(n) {
            map.remove(&k);
        }
        true
    }

    /// After a success: the name's counts go, the client's count stays.
    pub fn clear(&self, name: &str, ip: IpAddr) {
        let mut map = self.map.lock().unwrap();
        let [pair, _, own] = Failures::keys(name, ip);
        map.remove(&pair.0);
        map.remove(&own.0);
    }
}

// ───────────────────────────── key derivation ─────────────────────────────

/// What a key derivation is for, and so which slots it waits for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdfKind {
    /// Logging in, setting up or registering: anyone can ask, so it counts against the budget.
    Public,
    /// Opening a recovery kit someone uploaded: its own slot, so kits can't hold up logins.
    Kit,
    /// For a signed-in user (changing the password, saving a kit).
    Session,
}

/// Requests that may wait for a slot; more are turned away.
const KDF_QUEUE: usize = 16;

/// Caps concurrent Argon2id runs (256 MiB each), how many requests wait for one, and how many
/// unauthenticated runs start per second.
pub struct KdfGate {
    slots: Semaphore,
    kit_slots: Semaphore,
    waiting: AtomicUsize,
    /// Token bucket for [`KdfKind::Public`] and [`KdfKind::Kit`]: (tokens, last refill).
    budget: Mutex<(f64, Instant)>,
    per_second: f64,
    burst: f64,
}

/// Why a derivation didn't start.
#[derive(Debug, PartialEq, Eq)]
pub enum Busy {
    Queue,
    Budget,
}

struct Waiting<'a>(&'a AtomicUsize);

impl Drop for Waiting<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

impl KdfGate {
    /// `per_second` unauthenticated derivations on average, `burst` at once after a quiet spell.
    pub fn new(slots: usize, per_second: f64, burst: f64) -> KdfGate {
        KdfGate {
            slots: Semaphore::new(slots),
            kit_slots: Semaphore::new(1),
            waiting: AtomicUsize::new(0),
            budget: Mutex::new((burst, Instant::now())),
            per_second,
            burst,
        }
    }

    /// The defaults, or no budget with `MALO_INSECURE_FAST_KDF` (tests log in many times a second).
    pub fn from_env() -> KdfGate {
        if std::env::var("MALO_INSECURE_FAST_KDF").as_deref() == Ok("1") {
            KdfGate::new(2, f64::INFINITY, f64::INFINITY)
        } else {
            KdfGate::new(2, 4.0, 20.0)
        }
    }

    fn spend(&self) -> bool {
        if self.per_second.is_infinite() {
            return true;
        }
        let mut b = self.budget.lock().unwrap();
        let now = Instant::now();
        b.0 = (b.0 + now.duration_since(b.1).as_secs_f64() * self.per_second).min(self.burst);
        b.1 = now;
        if b.0 < 1.0 {
            return false;
        }
        b.0 -= 1.0;
        true
    }

    /// A slot for one derivation. Waits while few others do; otherwise (or when the budget is
    /// spent) the caller answers 429.
    pub async fn acquire(&self, kind: KdfKind) -> Result<SemaphorePermit<'_>, Busy> {
        let slots = match kind {
            KdfKind::Kit => &self.kit_slots,
            KdfKind::Public | KdfKind::Session => &self.slots,
        };
        if kind != KdfKind::Session && !self.spend() {
            return Err(Busy::Budget);
        }
        if let Ok(p) = slots.try_acquire() {
            return Ok(p);
        }
        if self.waiting.fetch_add(1, Ordering::Relaxed) >= KDF_QUEUE {
            self.waiting.fetch_sub(1, Ordering::Relaxed);
            return Err(Busy::Queue);
        }
        let _waiting = Waiting(&self.waiting);
        slots.acquire().await.map_err(|_| Busy::Queue)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_grows_and_caps() {
        assert_eq!(failure_delay(4).as_secs(), 0);
        assert_eq!(failure_delay(5).as_secs(), 30);
        assert_eq!(failure_delay(6).as_secs(), 60);
        assert_eq!(failure_delay(50).as_secs(), 900);
        assert_eq!(client_failure_delay(29).as_secs(), 0);
        assert_eq!(client_failure_delay(1000).as_secs(), 600);
    }

    #[test]
    fn ipv6_counts_per_64() {
        let a: IpAddr = "2001:db8:1:2:aaaa::1".parse().unwrap();
        let b: IpAddr = "2001:db8:1:2:bbbb::2".parse().unwrap();
        assert_eq!(client_key(a), client_key(b));
        assert_eq!(client_key(a), "2001:db8:1:2::".parse::<IpAddr>().unwrap());
        assert_ne!(
            client_key(a),
            client_key("2001:db8:1:3::1".parse().unwrap())
        );
        assert_eq!(
            client_key("::ffff:10.0.0.1".parse().unwrap()),
            "10.0.0.1".parse::<IpAddr>().unwrap()
        );
        let v4: IpAddr = "192.0.2.7".parse().unwrap();
        assert_eq!(client_key(v4), v4);
    }

    #[test]
    fn flooding_keeps_backoffs() {
        let f = Failures::with_capacity(100);
        let (attacker, victim): (IpAddr, IpAddr) = (
            "192.0.2.1".parse().unwrap(),
            "198.51.100.1".parse().unwrap(),
        );
        for _ in 0..5 {
            f.record("alice", victim);
        }
        assert!(f.check("alice", victim).is_some());
        // Many made-up names from many addresses fill the table over and over.
        for i in 0..2000u32 {
            let IpAddr::V4(base) = attacker else {
                unreachable!()
            };
            let ip = IpAddr::from(std::net::Ipv4Addr::from(u32::from(base) + i));
            f.record(&format!("nobody{i}"), ip);
        }
        assert!(f.check("alice", victim).is_some(), "the backoff survives");
        assert!(f.map.lock().unwrap().len() <= 100);
    }

    #[test]
    fn many_names_from_one_client() {
        let f = Failures::default();
        let ip: IpAddr = "2001:db8::1".parse().unwrap();
        for i in 0..30 {
            f.record(&format!("user{i}"), ip);
        }
        // A new name and a new address in the same /64 are backed off too.
        assert!(f
            .check("someone", "2001:db8::99".parse().unwrap())
            .is_some());
        assert!(f
            .check("someone", "2001:db8:1::1".parse().unwrap())
            .is_none());
        f.clear("user1", ip);
        assert!(
            f.check("someone", ip).is_some(),
            "a success keeps the client count"
        );
    }

    #[tokio::test]
    async fn kdf_queue_and_budget() {
        let gate = KdfGate::new(1, 0.001, 2.0);
        let held = gate.acquire(KdfKind::Public).await.unwrap();
        // The kit slot is separate.
        let kit = gate.acquire(KdfKind::Kit).await.unwrap();
        // The budget (burst of 2) is spent now; signed-in users aren't counted.
        assert_eq!(
            gate.acquire(KdfKind::Public).await.unwrap_err(),
            Busy::Budget
        );
        drop((held, kit));
        assert!(gate.acquire(KdfKind::Session).await.is_ok());

        let gate = std::sync::Arc::new(KdfGate::new(1, f64::INFINITY, f64::INFINITY));
        let held = gate.acquire(KdfKind::Session).await.unwrap();
        let mut waiters = vec![];
        for _ in 0..KDF_QUEUE {
            let g = gate.clone();
            waiters.push(tokio::spawn(async move {
                g.acquire(KdfKind::Public).await.map(drop)
            }));
        }
        while gate.waiting.load(Ordering::Relaxed) < KDF_QUEUE {
            tokio::task::yield_now().await;
        }
        assert_eq!(
            gate.acquire(KdfKind::Public).await.unwrap_err(),
            Busy::Queue
        );
        drop(held);
        for w in waiters {
            assert!(w.await.unwrap().is_ok());
        }
        assert_eq!(gate.waiting.load(Ordering::Relaxed), 0);
    }
}
