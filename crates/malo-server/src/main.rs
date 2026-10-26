use malo_server::config::ServerConfig;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,tower_http=warn".into()),
        )
        .with_writer(std::io::stderr)
        .init();
    malo_server::harden_process();
    if std::env::args().any(|a| a == "--healthcheck") {
        return healthcheck().await;
    }
    let cfg = ServerConfig::load()?;
    let running = malo_server::start(cfg.clone()).await?;
    // A sidecar hands the token to its app on stdout; only a standalone server logs it.
    if let (Some(token), None) = (&running.setup_token, &cfg.sidecar_secret) {
        tracing::warn!("first start: create the admin account with setup token {token}");
    }
    // Machine-readable line for the desktop app that launches us as a sidecar.
    println!(
        "MALO_READY {}",
        serde_json::json!({
            "port": running.addr.port(),
            "tls": cfg.tls,
            "fingerprint": running.fingerprint,
            "setup_token": if cfg.sidecar_secret.is_some() { running.setup_token.clone() } else { None },
        })
    );
    tracing::info!(
        "listening on {}://{} (certificate SHA-256 {})",
        if cfg.tls { "https" } else { "http" },
        running.addr,
        running.fingerprint.as_deref().unwrap_or("-")
    );
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = terminate() => {}
        _ = parent_gone(cfg.sidecar_secret.is_some()) => {
            tracing::info!("the desktop app is gone (stdin closed)");
        }
    }
    tracing::info!("shutting down");
    running.shutdown(std::time::Duration::from_secs(20)).await;
    Ok(())
}

/// `malo-server --healthcheck`: used by the Docker HEALTHCHECK (distroless has no curl).
async fn healthcheck() -> anyhow::Result<()> {
    let cfg = ServerConfig::load()?;
    let port = cfg.listen.port();
    let scheme = if cfg.tls { "https" } else { "http" };
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()?;
    let r = client
        .get(format!("{scheme}://127.0.0.1:{port}/healthz"))
        .send()
        .await?;
    anyhow::ensure!(r.status().is_success(), "unhealthy: {}", r.status());
    Ok(())
}

/// Sidecar mode only: the desktop app keeps our stdin pipe open for as long as it runs. When it
/// exits for any reason (window closed, crash, killed, `tauri dev` restart) the pipe closes and
/// this resolves, so the bundled server never outlives the app. Never resolves otherwise: a
/// Docker server's stdin is usually /dev/null and reads EOF immediately.
async fn parent_gone(sidecar: bool) {
    if !sidecar {
        return std::future::pending().await;
    }
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    // A plain thread, not tokio's stdin: a blocking read there would hold up runtime shutdown.
    std::thread::spawn(move || {
        use std::io::Read;
        let mut buf = [0u8; 256];
        let mut stdin = std::io::stdin().lock();
        while matches!(stdin.read(&mut buf), Ok(n) if n > 0) {}
        let _ = tx.send(());
    });
    let _ = rx.await;
}

/// Resolves on SIGTERM (Docker stop); never on platforms without it.
async fn terminate() {
    #[cfg(unix)]
    {
        if let Ok(mut s) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            s.recv().await;
            return;
        }
    }
    std::future::pending::<()>().await
}
