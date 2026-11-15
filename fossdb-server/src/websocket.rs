use axum::{
    extract::{State, WebSocketUpgrade, ws::WebSocket},
    response::Response,
};
use futures::{SinkExt, StreamExt};
use tokio::sync::broadcast;

/// Broadcaster for timeline events
#[derive(Clone)]
pub struct TimelineBroadcaster {
    tx: broadcast::Sender<crate::TimelineEvent>,
}

impl TimelineBroadcaster {
    pub fn new() -> Self {
        let (tx, _rx) = broadcast::channel(100);
        Self { tx }
    }

    /// Broadcast a timeline event to all connected clients
    pub fn broadcast(&self, event: crate::TimelineEvent) {
        // Ignore send errors - they just mean no receivers are listening
        let _ = self.tx.send(event);
    }

    /// Subscribe to timeline events
    fn subscribe(&self) -> broadcast::Receiver<crate::TimelineEvent> {
        self.tx.subscribe()
    }
}

/// WebSocket handler for timeline updates
pub async fn timeline_websocket_handler(
    ws: WebSocketUpgrade,
    State(state): State<crate::AppState>,
) -> Response {
    ws.on_upgrade(move |socket| handle_socket(socket, state))
}

async fn handle_socket(socket: WebSocket, state: crate::AppState) {
    tracing::debug!("New WebSocket connection established");
    let (mut sender, mut receiver) = socket.split();
    let mut rx = state.broadcaster.subscribe();
    let mut user_id: Option<String> = None;

    // Use channels to communicate from receiver to sender
    let (auth_tx, mut auth_rx) = tokio::sync::mpsc::channel::<String>(1);
    let (ping_tx, mut ping_rx) = tokio::sync::mpsc::channel::<()>(1);

    let auth_db = state.db.clone();

    // Spawn a task to receive messages from the client
    let mut recv_task = tokio::spawn(async move {
        while let Some(Ok(msg)) = receiver.next().await {
            if let axum::extract::ws::Message::Text(text) = msg
                && let Ok(ws_msg) = serde_json::from_str::<crate::WebSocketMessage>(&text)
            {
                match ws_msg {
                    crate::WebSocketMessage::Auth { user_id } => {
                        // The credential arrives in-band here rather than in a
                        // header, because browsers cannot set headers on a
                        // WebSocket handshake.
                        let candidate = fossdb::user_id::normalize(&user_id);

                        // Shape-check before hitting storage, so a socket
                        // spamming junk cannot be turned into database load.
                        if !fossdb::user_id::is_well_formed(&candidate) {
                            tracing::debug!("WebSocket auth rejected: malformed id");
                            continue;
                        }

                        match auth_db.get_user(&candidate) {
                            Ok(Some(_)) => {
                                let _ = auth_tx.send(candidate).await;
                            }
                            Ok(None) => {
                                tracing::debug!("WebSocket auth rejected: unknown account");
                            }
                            Err(e) => {
                                tracing::error!("WebSocket auth lookup failed: {e}");
                            }
                        }
                    }
                    crate::WebSocketMessage::Ping => {
                        // Notify send task to respond with Pong
                        let _ = ping_tx.send(()).await;
                    }
                    _ => {}
                }
            }
        }
    });

    // Spawn a task to send messages to the client
    let mut send_task = tokio::spawn(async move {
        loop {
            tokio::select! {
                // Receive timeline events from the broadcaster.
                //
                // The whole `Result` is matched rather than using an
                // `Ok(..) = ..` pattern: an unmatched pattern disables this
                // branch for the rest of the `select!`, so a single `Lagged`
                // error would stall all event delivery until the 30s keepalive
                // timer fired.
                received = rx.recv() => {
                    let db_event = match received {
                        Ok(db_event) => db_event,
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                            tracing::warn!(
                                "WebSocket client lagged behind; dropped {} timeline event(s)",
                                skipped
                            );
                            continue;
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    };

                    // Filter events based on authentication:
                    // - If not authenticated: only send global events (user_id = None)
                    // - If authenticated: only send events for this user
                    let should_send = match (user_id.as_deref(), db_event.user_id.as_deref()) {
                        (None, None) => true,  // Not authenticated, global event
                        (Some(uid), Some(event_uid)) => uid == event_uid,  // Authenticated, personal event
                        _ => false,  // Don't send
                    };

                    if should_send {
                        let msg = crate::WebSocketMessage::TimelineEvent { event: db_event.inner };
                        let json = serde_json::to_string(&msg).unwrap();
                        if sender.send(axum::extract::ws::Message::Text(json.into())).await.is_err() {
                            break;
                        }
                    }
                }

                // Handle client authentication
                Some(uid) = auth_rx.recv() => {
                    tracing::debug!(
                        "WebSocket authenticated account {}",
                        fossdb::user_id::redact(&uid)
                    );
                    user_id = Some(uid);
                    // There is no `Authenticated` reply variant; the client
                    // infers success from receiving personal events.
                }

                // Respond to client ping
                Some(()) = ping_rx.recv() => {
                    let msg = crate::WebSocketMessage::Pong;
                    let json = serde_json::to_string(&msg).unwrap();
                    if sender.send(axum::extract::ws::Message::Text(json.into())).await.is_err() {
                        break;
                    }
                }

                // Send periodic server-side pings for keepalive
                _ = tokio::time::sleep(tokio::time::Duration::from_secs(30)) => {
                    let msg = crate::WebSocketMessage::Ping;
                    let json = serde_json::to_string(&msg).unwrap();
                    if sender.send(axum::extract::ws::Message::Text(json.into())).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    // Wait for either task to finish (which means the connection is closed)
    tokio::select! {
        _ = &mut send_task => recv_task.abort(),
        _ = &mut recv_task => send_task.abort(),
    }
    tracing::debug!("WebSocket connection closed");
}
