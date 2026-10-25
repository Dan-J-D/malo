//! `WS /events`: user-scoped sync events, batched at ~10 Hz.

use std::time::Duration;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::response::Response;
use malo_api::{EventBatch, SyncEvent};
use tokio::sync::broadcast::error::RecvError;

use crate::auth::AuthUser;
use crate::state::SharedState;

pub async fn events(
    State(state): State<SharedState>,
    auth: AuthUser,
    ws: WebSocketUpgrade,
) -> Response {
    ws.on_upgrade(move |socket| stream(state, auth, socket))
}

async fn stream(state: SharedState, auth: AuthUser, mut socket: WebSocket) {
    let mut rx = state.events.subscribe(&auth.user.id);
    let mut tick = tokio::time::interval(Duration::from_millis(100));
    let mut session_check = tokio::time::interval(Duration::from_secs(30));
    let idle = chrono::Duration::minutes(state.cfg.session_idle_minutes.max(1));
    let mut pending: Vec<SyncEvent> = Vec::new();
    let mut close = false;
    loop {
        tokio::select! {
            ev = rx.recv() => match ev {
                Ok(e) => {
                    if matches!(e, SyncEvent::Locked { .. }) {
                        close = true;
                    }
                    pending.push(e);
                }
                Err(RecvError::Lagged(n)) => pending.push(SyncEvent::Notice {
                    level: "warning".into(),
                    message: format!("{n} events dropped; refresh to resync"),
                }),
                Err(RecvError::Closed) => break,
            },
            _ = tick.tick() => {
                if !pending.is_empty() {
                    let batch = EventBatch { events: std::mem::take(&mut pending) };
                    let text = serde_json::to_string(&batch).unwrap_or_default();
                    if socket.send(Message::Text(text.into())).await.is_err() {
                        break;
                    }
                }
                if close {
                    let _ = socket.send(Message::Close(None)).await;
                    break;
                }
            }
            _ = session_check.tick() => {
                if !matches!(state.db.check_session(&auth.token_hash, idle), Ok(Some(_))) {
                    let _ = socket.send(Message::Close(None)).await;
                    break;
                }
            }
            msg = socket.recv() => match msg {
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                _ => {}
            },
        }
    }
}
