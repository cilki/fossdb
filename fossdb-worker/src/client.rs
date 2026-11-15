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
            .await?;

        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }

        let resp = resp.error_for_status()?;
        Ok(Some(resp.json().await?))
    }

    pub async fn submit_analysis(&self, analysis: &WorkerAnalysis) -> Result<WorkerAnalysis> {
        let resp = self
            .http
            .post(format!("{}/analysis", self.server_url))
            .bearer_auth(&self.api_key)
            .json(analysis)
            .send()
            .await?
            .error_for_status()?;
        Ok(resp.json().await?)
    }

    /// Client for fetching package archives from third-party hosts.
    pub fn http(&self) -> &reqwest::Client {
        &self.downloads
    }
}
