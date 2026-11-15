use dioxus::prelude::*;
use futures::{SinkExt, StreamExt};
use gloo_net::websocket::{Message, futures::WebSocket};
use std::cell::RefCell;
use std::rc::Rc;

#[derive(Clone, Copy, PartialEq, Debug)]
pub struct WebSocketState {
    pub connected: bool,
    pub reconnecting: bool,
}

/// Initial reconnect delay.
const RECONNECT_BASE_DELAY_SECS: u64 = 1;

/// Ceiling for the exponential reconnect backoff.
const RECONNECT_MAX_DELAY_SECS: u64 = 60;

/// Derive the WebSocket URL for `path` from the page's own location.
///
/// The scheme is taken from `location.protocol`, so an HTTPS deployment gets
/// `wss://`. Hardcoding `ws://` meant browsers blocked the connection as mixed
/// content on every HTTPS deployment, and the hook then retried forever.
pub fn websocket_url(path: &str) -> Option<String> {
    let location = web_sys::window()?.location();
    let host = location.host().ok()?;
    let scheme = match location.protocol().ok()?.as_str() {
        "https:" => "wss",
        _ => "ws",
    };
    Some(format!("{}://{}{}", scheme, host, path))
}

/// Maintain a WebSocket connection, reconnecting with exponential backoff.
///
/// Returns a signal describing the connection state so callers can surface it;
/// the previous signature returned `()`, leaving the state signal unobservable
/// dead weight.
/// Maintain a WebSocket connection, optionally authenticating it.
///
/// `credential` is the account id. When present it is sent as an in-band
/// `Auth` frame immediately after the socket opens, which is the only way to
/// authenticate a browser WebSocket - the handshake cannot carry an
/// `Authorization` header. Until this frame is sent the server treats the
/// connection as anonymous and delivers only global events, so personal
/// timeline updates never arrive.
pub fn use_websocket<T, F>(
    url: String,
    credential: Option<String>,
    on_message: F,
) -> Signal<WebSocketState>
where
    T: for<'de> serde::Deserialize<'de> + 'static,
    F: FnMut(T) + 'static,
{
    let mut state = use_signal(|| WebSocketState {
        connected: false,
        reconnecting: false,
    });

    let on_message = use_hook(|| Rc::new(RefCell::new(on_message)));

    // `use_reactive` makes the connection task restart when `url` changes.
    // Previously the task captured the URL from the first render and a changed
    // URL never triggered a reconnect.
    // Reconnect when either the URL or the credential changes, so signing in
    // or out rebinds the socket instead of leaving it on the old identity.
    use_effect(use_reactive!(|(url, credential)| {
        let on_message = on_message.clone();

        spawn(async move {
            let mut delay = RECONNECT_BASE_DELAY_SECS;

            loop {
                state.set(WebSocketState {
                    connected: false,
                    reconnecting: true,
                });

                match WebSocket::open(&url) {
                    Ok(mut ws) => {
                        state.set(WebSocketState {
                            connected: true,
                            reconnecting: false,
                        });
                        // Successful connection resets the backoff.
                        delay = RECONNECT_BASE_DELAY_SECS;

                        // Authenticate before reading, so no personal event
                        // can be missed in the gap.
                        if let Some(user_id) = credential.clone() {
                            let auth = fossdb::WebSocketMessage::Auth { user_id };
                            match serde_json::to_string(&auth) {
                                Ok(frame) => {
                                    if ws.send(Message::Text(frame)).await.is_err() {
                                        gloo_console::warn!(
                                            "WebSocket closed before authentication"
                                        );
                                        // Fall through to the reconnect path.
                                    }
                                }
                                Err(e) => gloo_console::warn!(format!(
                                    "Could not serialise websocket auth frame: {e}"
                                )),
                            }
                        }

                        while let Some(msg) = ws.next().await {
                            match msg {
                                Ok(Message::Text(text)) => {
                                    match serde_json::from_str::<T>(&text) {
                                        Ok(data) => (on_message.borrow_mut())(data),
                                        Err(e) => gloo_console::warn!(format!(
                                            "Ignoring unparseable websocket message: {e}"
                                        )),
                                    }
                                }
                                Ok(Message::Bytes(_)) => {}
                                Err(_) => break,
                            }
                        }
                    }
                    Err(e) => {
                        gloo_console::warn!(format!("WebSocket connection failed: {e}"));
                    }
                }

                state.set(WebSocketState {
                    connected: false,
                    reconnecting: true,
                });

                gloo_timers::future::sleep(std::time::Duration::from_secs(delay)).await;
                // Exponential backoff, so an unreachable or blocked endpoint
                // does not produce an endless 5s retry storm.
                delay = (delay * 2).min(RECONNECT_MAX_DELAY_SECS);
            }
        });
    }));

    state
}
