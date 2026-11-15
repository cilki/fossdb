//! Admin client, speaking HTTP/1 over fossdb-server's unix socket.
//!
//! `reqwest` has no unix-socket transport, so this drives hyper's HTTP/1
//! client directly over a `UnixStream`. That is about twenty lines and avoids
//! inventing a bespoke wire protocol for the control channel.

use anyhow::{Context, Result, bail};
use http_body_util::{BodyExt, Empty, Full, combinators::BoxBody};
use hyper::body::Bytes;
use hyper_util::rt::TokioIo;
use serde::de::DeserializeOwned;
use tokio::net::UnixStream;

/// Default socket path, matching the server's `ADMIN_SOCKET_PATH` default.
pub const DEFAULT_SOCKET: &str = "/run/fossdb/admin.sock";

/// Issue a GET against the admin socket and deserialise the JSON body.
pub async fn get<T: DeserializeOwned>(socket_path: &str, path: &str) -> Result<T> {
    request(socket_path, "GET", path, None).await
}

/// Issue a POST with a JSON body.
pub async fn post<T: DeserializeOwned>(
    socket_path: &str,
    path: &str,
    body: &impl serde::Serialize,
) -> Result<T> {
    let json = serde_json::to_vec(body).context("serialising the admin request body")?;
    request(socket_path, "POST", path, Some(json)).await
}

/// Issue a DELETE.
pub async fn delete<T: DeserializeOwned>(socket_path: &str, path: &str) -> Result<T> {
    request(socket_path, "DELETE", path, None).await
}

async fn request<T: DeserializeOwned>(
    socket_path: &str,
    method: &str,
    path: &str,
    body: Option<Vec<u8>>,
) -> Result<T> {
    let stream = UnixStream::connect(socket_path).await.with_context(|| {
        format!(
            "connecting to the admin socket at {socket_path}\n\
             Is fossdb-server running, and do you have permission to open its socket? \
             The socket is group-readable only (mode 0660)."
        )
    })?;

    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .context("HTTP handshake over the admin socket failed")?;

    // The connection task must be driven concurrently with the request, or
    // the request future never completes.
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            // Expected on clean shutdown; only interesting while debugging.
            tracing_hint(&format!("admin connection closed: {e}"));
        }
    });

    // `Host` is required by HTTP/1.1 but meaningless over a unix socket.
    let mut builder = hyper::Request::builder()
        .method(method)
        .uri(path)
        .header(hyper::header::HOST, "localhost");

    if body.is_some() {
        builder = builder.header(hyper::header::CONTENT_TYPE, "application/json");
    }

    // `Full` for a body, `Empty` otherwise, unified behind `BoxBody` so both
    // paths share one request type.
    let outgoing = builder
        .body(match body {
            Some(bytes) => BoxBody::new(Full::new(Bytes::from(bytes))),
            None => BoxBody::new(Empty::<Bytes>::new()),
        })
        .context("building admin request")?;

    let response = sender
        .send_request(outgoing)
        .await
        .context("sending admin request")?;

    let status = response.status();
    let body = response
        .into_body()
        .collect()
        .await
        .context("reading admin response")?
        .to_bytes();

    if !status.is_success() {
        let text = String::from_utf8_lossy(&body);
        let hint = if status == hyper::StatusCode::NOT_FOUND {
            "\nIf this was a revoke, check the key id with `fossdb admin api-key list`."
        } else {
            ""
        };
        bail!("admin request to {path} failed: {status} {text}{hint}");
    }

    serde_json::from_slice(&body).with_context(|| {
        format!(
            "could not parse the admin response from {path}; \
             is the server a matching version?"
        )
    })
}

/// Stand-in for a log line; the CLI has no tracing subscriber installed.
fn tracing_hint(message: &str) {
    if std::env::var_os("FOSSDB_DEBUG").is_some() {
        eprintln!("debug: {message}");
    }
}
