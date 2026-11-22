use anyhow::Result;
use fossdb::{WorkerAnalysis, WorkerTask};
use std::time::Duration;

/// Timeout for control-plane calls to fossdb-server. These exchange small JSON
/// payloads, so a generous ceiling is still far below "hang forever".
const CONTROL_TIMEOUT: Duration = Duration::from_secs(30);

/// Connect timeout for package downloads.
const DOWNLOAD_CONNECT_TIMEOUT: Duration = Duration::from_secs(20);

/// Per-read inactivity timeout for package downloads.
///
/// A total timeout is deliberately not used here: a large but legitimate
/// archive may take a while. What must be prevented is a host that accepts the
/// connection and then trickles (or stalls) forever. `reqwest` applies no
/// timeout of any kind by default, so without this a single bad host wedges the
/// worker's sequential loop indefinitely with nothing logged.
const DOWNLOAD_READ_TIMEOUT: Duration = Duration::from_secs(60);

/// Explain a failed request to fossdb-server when the cause is one the
/// operator has to fix: the server is unreachable at `WORKER_SERVER_URL`, or
/// it rejected `WORKER_API_KEY`. Both repeat on every poll, and reqwest's own
/// message names neither the setting nor how to get a working key.
fn server_error(e: reqwest::Error) -> anyhow::Error {
    let hint = if e.is_connect() {
        Some("cannot reach fossdb-server; check WORKER_SERVER_URL")
    } else if matches!(
        e.status(),
        Some(reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::FORBIDDEN)
    ) {
        Some(
            "fossdb-server rejected WORKER_API_KEY; it may be revoked, mistyped, or a \
             collector key. Mint one with `fossdb admin api-key create --role worker`",
        )
    } else {
        None
    };
    match hint {
        Some(hint) => anyhow::Error::new(e).context(hint),
        None => e.into(),
    }
}

pub struct WorkerClient {
    http: reqwest::Client,
    downloads: reqwest::Client,
    server_url: String,
    api_key: String,
}

impl WorkerClient {
    pub fn new(server_url: String, api_key: String) -> Result<Self> {
        let http = reqwest::Client::builder()
            .user_agent("fossdb-worker")
            .timeout(CONTROL_TIMEOUT)
            .connect_timeout(DOWNLOAD_CONNECT_TIMEOUT)
            .build()?;

        let downloads = reqwest::Client::builder()
            .user_agent("fossdb-worker")
            .connect_timeout(DOWNLOAD_CONNECT_TIMEOUT)
            .read_timeout(DOWNLOAD_READ_TIMEOUT)
            .build()?;

        Ok(Self {
            http,
            downloads,
            server_url,
            api_key,
        })
    }

    /// Fetch the next analysis task.
    ///
    /// Returns `Ok(None)` when the server reports no work available. The status
    /// code is inspected directly rather than substring-matching "404" in the
    /// error's `Display`, which also contains the request URL and would
    /// misclassify genuine failures for any server URL containing "404".
    pub async fn get_task(&self) -> Result<Option<WorkerTask>> {
        let resp = self
            .http
            .get(format!("{}/packages/next", self.server_url))
            .bearer_auth(&self.api_key)
            .send()
            .await
            .map_err(server_error)?;

        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }

        let resp = resp.error_for_status().map_err(server_error)?;
        Ok(Some(resp.json().await?))
    }

    pub async fn submit_analysis(&self, analysis: &WorkerAnalysis) -> Result<WorkerAnalysis> {
        let resp = self
            .http
            .post(format!("{}/analysis", self.server_url))
            .bearer_auth(&self.api_key)
            .json(analysis)
            .send()
            .await
            .map_err(server_error)?
            .error_for_status()
            .map_err(server_error)?;
        Ok(resp.json().await?)
    }

    /// Client for fetching package archives from third-party hosts.
    pub fn http(&self) -> &reqwest::Client {
        &self.downloads
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serve one canned HTTP response with `status` on a loopback port and
    /// return a client pointed at it.
    async fn client_answered_with(status: &'static str) -> WorkerClient {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            let _ = socket.read(&mut buf).await;
            let response =
                format!("HTTP/1.1 {status}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n");
            socket.write_all(response.as_bytes()).await.unwrap();
        });
        WorkerClient::new(url, "key".to_string()).unwrap()
    }

    #[tokio::test]
    async fn rejected_key_names_the_setting_and_the_fix() {
        let client = client_answered_with("401 Unauthorized").await;
        let err = client.get_task().await.unwrap_err();
        let logged = format!("{err:#}");
        assert!(logged.contains("WORKER_API_KEY"), "{logged}");
        assert!(logged.contains("--role worker"), "{logged}");
        assert!(logged.contains("401"), "{logged}");
    }

    #[tokio::test]
    async fn unreachable_server_names_the_setting() {
        // Bind and drop to get a loopback port nothing listens on.
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let client = WorkerClient::new(format!("http://127.0.0.1:{port}"), "key".into()).unwrap();
        let err = client.get_task().await.unwrap_err();
        let logged = format!("{err:#}");
        assert!(logged.contains("WORKER_SERVER_URL"), "{logged}");
        // The transport-level cause must still be in the log line.
        assert!(err.chain().count() > 2, "{logged}");
    }

    #[tokio::test]
    async fn other_server_errors_carry_no_configuration_hint() {
        let client = client_answered_with("500 Internal Server Error").await;
        let err = client.get_task().await.unwrap_err();
        let logged = format!("{err:#}");
        assert!(!logged.contains("WORKER_"), "{logged}");
    }

    #[tokio::test]
    async fn no_work_is_not_an_error() {
        let client = client_answered_with("404 Not Found").await;
        assert!(client.get_task().await.unwrap().is_none());
    }
}
