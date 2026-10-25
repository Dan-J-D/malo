//! Shared server state and the per-user event hub.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use malo_api::SyncEvent;
use malo_core::ctx::EventSink;
use tokio::sync::{broadcast, Semaphore};

use crate::config::ServerConfig;
use crate::db::Db;
use crate::jobs::JobManager;
use crate::keyring::KeyRing;

pub struct AppState {
    pub cfg: ServerConfig,
    pub db: Arc<Db>,
    pub keyring: KeyRing,
    pub events: Arc<EventHub>,
    pub jobs: JobManager,
    /// Caps concurrent Argon2id runs (256 MiB each).
    pub kdf_slots: Semaphore,
    pub login_failures: Mutex<HashMap<String, (u32, Instant)>>,
    pub cert_fingerprint: Option<String>,
    /// Background IMAP IDLE watchers per (user, account).
    pub idle_watchers: Mutex<HashMap<(String, String), tokio_util::sync::CancellationToken>>,
    /// Cancelled on shutdown: stops the scheduler and refuses new jobs.
    pub shutdown: tokio_util::sync::CancellationToken,
}

pub type SharedState = Arc<AppState>;

#[derive(Default)]
pub struct EventHub {
    channels: Mutex<HashMap<String, broadcast::Sender<SyncEvent>>>,
}

impl EventHub {
    fn sender(&self, user_id: &str) -> broadcast::Sender<SyncEvent> {
        self.channels
            .lock()
            .unwrap()
            .entry(user_id.to_string())
            .or_insert_with(|| broadcast::channel(4096).0)
            .clone()
    }

    pub fn subscribe(&self, user_id: &str) -> broadcast::Receiver<SyncEvent> {
        self.sender(user_id).subscribe()
    }

    pub fn emit(&self, user_id: &str, event: SyncEvent) {
        let _ = self.sender(user_id).send(event);
    }

    pub fn sink(self: &Arc<Self>, user_id: &str) -> Arc<dyn EventSink> {
        Arc::new(UserSink {
            hub: self.clone(),
            user_id: user_id.to_string(),
        })
    }
}

struct UserSink {
    hub: Arc<EventHub>,
    user_id: String,
}

impl EventSink for UserSink {
    fn emit(&self, event: SyncEvent) {
        self.hub.emit(&self.user_id, event);
    }
}
