//! Bundled `malo-server` for single-machine use: loopback only, random port, per-launch secret.

use std::path::Path;
use std::time::Duration;

use rand::RngCore;
use serde::Deserialize;
use tauri::AppHandle;
use tauri_plugin_shell::process::{CommandChild, CommandEvent};
use tauri_plugin_shell::ShellExt;

#[derive(Clone)]
pub struct SidecarInfo {
    pub url: String,
    pub fingerprint: Option<String>,
    pub secret: String,
    pub setup_token: Option<String>,
}

pub struct Sidecar {
    pub info: SidecarInfo,
    child: CommandChild,
}

impl Sidecar {
    pub fn stop(self) {
        let _ = self.child.kill();
    }
}

#[derive(Deserialize)]
struct Ready {
    port: u16,
    fingerprint: Option<String>,
    setup_token: Option<String>,
}

pub async fn spawn(app: &AppHandle, data_dir: &Path) -> anyhow::Result<Sidecar> {
    std::fs::create_dir_all(data_dir)?;
    let mut secret = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut secret);
    let secret = hex::encode(secret);
    let (mut rx, child) = app
        .shell()
        .sidecar("malo-server")?
        .env("MALO_LISTEN", "127.0.0.1:0")
        .env("MALO_DATA_DIR", data_dir.to_string_lossy().to_string())
        .env("MALO_SIDECAR_SECRET", &secret)
        .env("RUST_LOG", "info")
        .spawn()?;
    let ready = tokio::time::timeout(Duration::from_secs(30), async {
        let mut stderr_tail = String::new();
        while let Some(ev) = rx.recv().await {
            match ev {
                CommandEvent::Stdout(line) => {
                    let line = String::from_utf8_lossy(&line);
                    if let Some(json) = line.trim().strip_prefix("MALO_READY ") {
                        return serde_json::from_str::<Ready>(json).map_err(anyhow::Error::from);
                    }
                }
                CommandEvent::Stderr(line) => {
                    let l = String::from_utf8_lossy(&line).to_string();
                    tracing::info!(target: "malo-server", "{}", l.trim_end());
                    stderr_tail = l;
                }
                CommandEvent::Terminated(t) => {
                    anyhow::bail!("server exited ({:?}): {}", t.code, stderr_tail.trim())
                }
                _ => {}
            }
        }
        anyhow::bail!("server closed its output before becoming ready")
    })
    .await
    .map_err(|_| anyhow::anyhow!("the local server did not start within 30 s"))??;
    // Keep draining logs so the pipe never fills up.
    tokio::spawn(async move {
        while let Some(ev) = rx.recv().await {
            if let CommandEvent::Stderr(line) | CommandEvent::Stdout(line) = ev {
                tracing::info!(target: "malo-server", "{}", String::from_utf8_lossy(&line).trim_end());
            }
        }
    });
    Ok(Sidecar {
        info: SidecarInfo {
            url: format!("https://127.0.0.1:{}", ready.port),
            fingerprint: ready.fingerprint,
            secret,
            setup_token: ready.setup_token,
        },
        child,
    })
}
