use anyhow::Result;
use chrono::{DateTime, Utc};
use fossdb::url::percent_encode;
use fossdb::{CollectedPackage, Package, PackageLookup};
use reqwest::{Client, Method, Response};
use serde::{Serialize, de::DeserializeOwned};
use std::time::Duration;

#[cfg(feature = "collector-libraries-io")]
use std::time::Instant;

/// Timeout for calls to fossdb-server. `reqwest` applies none by default, and
/// the collector loop is sequential, so a stalled connection would hang the
/// collector indefinitely with nothing logged.
const SERVER_TIMEOUT: Duration = Duration::from_secs(30);

const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// fossdb-server could not be reached, or it rejected the collector's API key.
///
/// Unlike a failure about one package, this repeats for every later request
/// in the run, so collectors abort the run on it (see [`aborts_run`]) rather
/// than logging one warning per item and then reporting the run as completed.
#[derive(Debug)]
pub struct ServerUnusable(reqwest::Error);

impl std::fmt::Display for ServerUnusable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.0.status().is_some() {
            write!(
                f,
                "fossdb-server rejected COLLECTOR_API_KEY ({}); it may be revoked, mistyped, \
                 or a worker key. Mint one with `fossdb admin api-key create --role collector`",
                self.0
            )
        } else {
            write!(
                f,
                "cannot reach fossdb-server ({}); check SERVER_INTERNAL_URL",
                self.0
            )
        }
    }
}

impl std::error::Error for ServerUnusable {
    /// The reqwest error's *cause*, not the reqwest error itself: `Display`
    /// already quotes the latter, and logging with `{:#}` would print it
    /// twice. Its cause is where "connection refused", a DNS failure or a TLS
    /// error is spelled out.
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        std::error::Error::source(&self.0)
    }
}

/// Wrap a request error to fossdb-server, marking the ones that every later
/// request would hit too.
fn server_error(e: reqwest::Error) -> anyhow::Error {
    let unusable = e.is_connect()
        || matches!(
            e.status(),
            Some(reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::FORBIDDEN)
        );
    if unusable {
        ServerUnusable(e).into()
    } else {
        e.into()
    }
}

/// Whether `e` means the rest of the collection run cannot succeed either.
pub fn aborts_run(e: &anyhow::Error) -> bool {
    e.downcast_ref::<ServerUnusable>().is_some()
}

pub struct CollectorClient {
    client: Client,
    base_url: String,
    api_key: String,
}

impl CollectorClient {
    pub fn new(base_url: String, api_key: String) -> Result<Self> {
        let client = Client::builder()
            .user_agent("fossdb-collector")
            .timeout(SERVER_TIMEOUT)
            .connect_timeout(CONNECT_TIMEOUT)
            .build()?;
        Ok(Self {
            client,
            base_url,
            api_key,
        })
    }

    /// Send `request` to `path` with the collector's key and return the
    /// response, or `None` for a 404. Any other non-success status is an
    /// error, marked by [`server_error`] when it would repeat.
    async fn send(
        &self,
        method: Method,
        path: &str,
        body: Option<&impl Serialize>,
    ) -> Result<Option<Response>> {
        let mut request = self
            .client
            .request(method, format!("{}{path}", self.base_url))
            .bearer_auth(&self.api_key);
        if let Some(body) = body {
            request = request.json(body);
        }
        let resp = request.send().await.map_err(server_error)?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        Ok(Some(resp.error_for_status().map_err(server_error)?))
    }

    /// [`Self::send`] a JSON `body` and decode the JSON answer, for endpoints
    /// where a 404 is an error like any other.
    async fn post<T: DeserializeOwned>(&self, path: &str, body: &impl Serialize) -> Result<T> {
        match self.send(Method::POST, path, Some(body)).await? {
            Some(resp) => Ok(resp.json().await?),
            None => anyhow::bail!("fossdb-server has no {path} endpoint (404)"),
        }
    }

    pub async fn get_package(&self, name: &str) -> Result<Option<PackageLookup>> {
        let path = format!("/packages?name={}", percent_encode(name));
        match self.send(Method::GET, &path, None::<&()>).await? {
            Some(resp) => Ok(Some(resp.json().await?)),
            None => Ok(None),
        }
    }

    pub async fn submit_package(&self, pkg: CollectedPackage) -> Result<Package> {
        self.post("/packages", &pkg).await
    }

    #[cfg(feature = "collector-osv")]
    pub async fn submit_advisory(
        &self,
        advisory: &fossdb::CollectedAdvisory,
    ) -> Result<fossdb::AdvisoryIngestResult> {
        self.post("/advisories", advisory).await
    }

    pub async fn update_package_timestamp(
        &self,
        name: &str,
        updated_at: DateTime<Utc>,
    ) -> Result<()> {
        let path = format!("/packages/{}/timestamp", percent_encode(name));
        let body = serde_json::json!({ "updated_at": updated_at });
        match self.send(Method::PUT, &path, Some(&body)).await? {
            Some(_) => Ok(()),
            None => anyhow::bail!("fossdb-server has no package {name} to update (404)"),
        }
    }
}

#[cfg(feature = "collector-libraries-io")]
pub struct AdaptiveConfig {
    /// Requests per minute to start at.
    pub initial_rate: u32,
    pub min_rate: u32,
    pub max_rate: u32,
}

/// Adaptive request pacer for libraries.io.
///
/// Implemented as a minimum interval between requests rather than with a
/// token-bucket limiter. The previous version rebuilt its `governor`
/// `RateLimiter` on every rate change, and a fresh limiter starts with its full
/// burst allowance - so the throttle never engaged during ramp-up, and a `429`
/// response (which halves the rate) immediately re-granted a full burst at the
/// exact moment the server asked us to back off.
///
/// Rates are per *minute*, matching libraries.io's documented quota. The old
/// code used `Quota::per_second` with the same numbers, allowing ~60x the
/// intended rate.
#[cfg(feature = "collector-libraries-io")]
pub struct AdaptiveRateLimitedClient {
    client: Client,
    config: AdaptiveConfig,
    state: tokio::sync::Mutex<PacerState>,
}

#[cfg(feature = "collector-libraries-io")]
struct PacerState {
    /// Current requests-per-minute budget.
    rate_per_minute: u32,
    /// Earliest instant at which the next request may be sent.
    next_allowed: Instant,
}

#[cfg(feature = "collector-libraries-io")]
impl AdaptiveRateLimitedClient {
    pub fn new(client: Client, config: AdaptiveConfig) -> Self {
        let initial = Self::clamp_rate(&config, config.initial_rate);
        Self {
            client,
            state: tokio::sync::Mutex::new(PacerState {
                rate_per_minute: initial,
                next_allowed: Instant::now(),
            }),
            config,
        }
    }

    /// Clamp into `[min_rate, max_rate]` and keep it at least 1, so the pacer
    /// can never be configured into a division by zero. The previous code called
    /// `NonZeroU32::new(rate).unwrap()`, a latent panic in a public API.
    fn clamp_rate(config: &AdaptiveConfig, rate: u32) -> u32 {
        let min = config.min_rate.max(1);
        let max = config.max_rate.max(min);
        rate.clamp(min, max)
    }

    fn interval(rate_per_minute: u32) -> Duration {
        Duration::from_secs_f64(60.0 / f64::from(rate_per_minute.max(1)))
    }

    pub async fn get(&self, url: &str) -> Result<Response, reqwest::Error> {
        // Reserve this request's slot, then release the lock before awaiting the
        // network so concurrent callers still queue in order.
        let wait = {
            let mut state = self.state.lock().await;
            let now = Instant::now();
            let slot = state.next_allowed.max(now);
            state.next_allowed = slot + Self::interval(state.rate_per_minute);
            slot.saturating_duration_since(now)
        };

        if !wait.is_zero() {
            tokio::time::sleep(wait).await;
        }

        let response = self.client.get(url).send().await?;
        self.report_result(response.status().as_u16()).await;
        Ok(response)
    }

    async fn report_result(&self, status_code: u16) {
        let mut state = self.state.lock().await;
        let old_rate = state.rate_per_minute;

        let new_rate = match status_code {
            429 => old_rate / 2,
            500..=599 => (old_rate * 9) / 10,
            200..=299 => (old_rate * 11) / 10,
            _ => old_rate,
        };
        let new_rate = Self::clamp_rate(&self.config, new_rate);

        if new_rate != old_rate {
            state.rate_per_minute = new_rate;
            tracing::debug!(
                "Adjusted libraries.io rate {} -> {} req/min after HTTP {}",
                old_rate,
                new_rate,
                status_code
            );
        }

        // On an explicit 429, additionally back off a full interval instead of
        // letting the next request go out immediately.
        if status_code == 429 {
            let penalty = Self::interval(new_rate);
            state.next_allowed = Instant::now() + penalty;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serve one canned HTTP response with `status` on a loopback port and
    /// return a client pointed at it.
    async fn client_answered_with(status: &'static str) -> CollectorClient {
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
        CollectorClient::new(url, "key".to_string()).unwrap()
    }

    #[tokio::test]
    async fn rejected_key_aborts_the_run() {
        let client = client_answered_with("401 Unauthorized").await;
        let err = client.get_package("serde").await.unwrap_err();
        assert!(aborts_run(&err), "{err}");
        assert!(err.to_string().contains("COLLECTOR_API_KEY"), "{err}");
    }

    #[tokio::test]
    async fn unreachable_server_aborts_the_run() {
        // Bind and drop to get a loopback port nothing listens on.
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let client =
            CollectorClient::new(format!("http://127.0.0.1:{port}"), "key".into()).unwrap();
        let err = client.get_package("serde").await.unwrap_err();
        assert!(aborts_run(&err), "{err}");
        assert!(err.to_string().contains("SERVER_INTERNAL_URL"), "{err}");

        // The log line (`{:#}`) must reach the transport-level cause, which
        // is what tells a refused connection from a DNS or TLS failure, and
        // must not repeat reqwest's own message on the way there.
        let logged = format!("{err:#}");
        assert!(err.chain().count() > 2, "{logged}");
        assert_eq!(
            logged.matches("error sending request").count(),
            1,
            "{logged}"
        );
    }

    #[tokio::test]
    async fn server_error_about_one_package_does_not_abort_the_run() {
        let client = client_answered_with("500 Internal Server Error").await;
        let err = client.get_package("serde").await.unwrap_err();
        assert!(!aborts_run(&err), "{err}");
    }

    #[cfg(feature = "collector-libraries-io")]
    #[test]
    fn rate_is_clamped_into_configured_bounds() {
        let config = AdaptiveConfig {
            initial_rate: 30,
            min_rate: 6,
            max_rate: 60,
        };
        assert_eq!(AdaptiveRateLimitedClient::clamp_rate(&config, 0), 6);
        assert_eq!(AdaptiveRateLimitedClient::clamp_rate(&config, 1000), 60);
        assert_eq!(AdaptiveRateLimitedClient::clamp_rate(&config, 30), 30);
    }

    #[cfg(feature = "collector-libraries-io")]
    #[test]
    fn interval_is_per_minute_not_per_second() {
        // 60 req/min is one per second, not 60 per second.
        assert_eq!(
            AdaptiveRateLimitedClient::interval(60),
            Duration::from_secs(1)
        );
        assert_eq!(
            AdaptiveRateLimitedClient::interval(30),
            Duration::from_secs(2)
        );
        // Never divides by zero.
        assert_eq!(
            AdaptiveRateLimitedClient::interval(0),
            Duration::from_secs(60)
        );
    }
}
