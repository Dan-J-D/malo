//! Shared server state and the per-user event hub.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use malo_api::SyncEvent;
use malo_core::ctx::EventSink;
use tokio::sync::broadcast;

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
    /// Caps Argon2id runs (256 MiB each).
    pub kdf: crate::limits::KdfGate,
    /// Failed logins to Malo, and (separately) to the mail services.
    pub login_failures: crate::limits::Failures,
    pub mail_failures: crate::limits::Failures,
    pub cert_fingerprint: Option<String>,
    /// Malo's own certificate authority, for devices to install; None with user-provided files.
    pub tls_ca: Option<crate::tlsgen::CaInfo>,
    /// Ports and certificate of the IMAP/SMTP services.
    pub mail: crate::mail::MailInfo,
    /// Background IMAP IDLE watchers per (user, account).
    pub idle_watchers: Mutex<HashMap<(String, String), tokio_util::sync::CancellationToken>>,
    /// Exports prepared for download, by ticket.
    pub exports: Mutex<HashMap<String, crate::routes::PendingExport>>,
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
