//! Bundled `malo-server` for single-machine use: loopback only, random port, per-launch secret.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use anyhow::Context;
use rand::RngCore;
use serde::Deserialize;
use tauri::AppHandle;
use tokio::io::{AsyncBufReadExt, AsyncRead, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::mpsc;

#[derive(Clone)]
pub struct SidecarInfo {
    pub url: String,
    pub fingerprint: Option<String>,
    pub secret: String,
    pub setup_token: Option<String>,
}

pub struct Sidecar {
    pub info: SidecarInfo,
    child: Child,
}

impl Sidecar {
    pub fn stop(mut self) {
        let _ = self.child.start_kill();
    }
}

/// The bundled server next to the app's own executable (where bundles and `tauri dev` put
/// `externalBin`).
fn binary() -> anyhow::Result<PathBuf> {
    let exe = std::env::current_exe().context("can't find the app's own executable")?;
    let dir = exe.parent().context("the app's executable has no folder")?;
    Ok(dir.join(format!("malo-server{}", std::env::consts::EXE_SUFFIX)))
}

/// One line of the server's output.
enum Output {
    Stdout(String),
    Stderr(String),
}

fn forward<R: AsyncRead + Unpin + Send + 'static>(
    r: R,
    tx: mpsc::UnboundedSender<Output>,
    wrap: fn(String) -> Output,
) {
    tokio::spawn(async move {
        let mut lines = BufReader::new(r).lines();
        while let Ok(Some(l)) = lines.next_line().await {
            if tx.send(wrap(l)).is_err() {
                break;
            }
        }
    });
}

#[derive(Deserialize)]
struct Ready {
    port: u16,
    fingerprint: Option<String>,
    setup_token: Option<String>,
}

pub async fn spawn(_app: &AppHandle, data_dir: &Path) -> anyhow::Result<Sidecar> {
    std::fs::create_dir_all(data_dir)?;
    let mut secret = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut secret);
    let secret = hex::encode(secret);
    let mut cmd = Command::new(binary()?);
    cmd.env("MALO_LISTEN", "127.0.0.1:0")
        .env("MALO_DATA_DIR", data_dir)
        .env("MALO_SIDECAR_SECRET", &secret)
        .env("RUST_LOG", "info")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    #[cfg(windows)]
    {
        // CREATE_NO_WINDOW: no console window next to the app.
        cmd.creation_flags(0x0800_0000);
    }
    let mut child = cmd.spawn().context("can't start the local server")?;
    let (tx, mut rx) = mpsc::unbounded_channel();
    forward(child.stdout.take().unwrap(), tx.clone(), Output::Stdout);
    forward(child.stderr.take().unwrap(), tx, Output::Stderr);
    let ready = tokio::time::timeout(Duration::from_secs(30), async {
        let mut stderr_tail = String::new();
        while let Some(out) = rx.recv().await {
            match out {
                Output::Stdout(line) => {
                    if let Some(json) = line.trim().strip_prefix("MALO_READY ") {
                        return serde_json::from_str::<Ready>(json).map_err(anyhow::Error::from);
                    }
                }
                Output::Stderr(line) => {
                    tracing::info!(target: "malo-server", "{}", line.trim_end());
                    stderr_tail = line;
                }
            }
        }
        let status = child.wait().await?;
        anyhow::bail!("server exited ({status}): {}", stderr_tail.trim())
    })
    .await
    .map_err(|_| anyhow::anyhow!("the local server did not start within 30 s"))??;
    // Keep draining logs so the pipe never fills up.
    tokio::spawn(async move {
        while let Some(Output::Stdout(line) | Output::Stderr(line)) = rx.recv().await {
            tracing::info!(target: "malo-server", "{}", line.trim_end());
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
