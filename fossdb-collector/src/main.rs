use anyhow::Result;
use std::sync::Arc;

mod client;
mod collectors;

use client::CollectorClient;
use collectors::Collector;

struct Config {
    server_url: String,
    api_key: String,
    interval_hours: u64,
    #[allow(dead_code)]
    libraries_io_api_key: Option<String>,
}

impl Config {
    fn from_env() -> Result<Self> {
        Ok(Self {
            server_url: std::env::var("SERVER_INTERNAL_URL")
                .unwrap_or_else(|_| "http://localhost:3001".to_string()),
            // Accepts `COLLECTOR_API_KEY` or `COLLECTOR_API_KEY_FILE`.
            api_key: fossdb::secret_file::from_env("COLLECTOR_API_KEY")?,
            interval_hours: std::env::var("COLLECTOR_INTERVAL_HOURS")
                .unwrap_or_else(|_| "1".to_string())
                .parse()
                .unwrap_or(1),
            libraries_io_api_key: std::env::var("LIBRARIES_IO_API_KEY").ok(),
        })
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt::init();

    let config = Config::from_env()?;

    if !fossdb::api_key::is_well_formed(&config.api_key) {
        tracing::warn!(
            "COLLECTOR_API_KEY does not look like a fossdb API key (expected {} characters \
             beginning with {:?}); the server will reject it",
            fossdb::api_key::TOTAL_LEN,
            fossdb::api_key::PREFIX
        );
    }

    let client = Arc::new(CollectorClient::new(config.server_url.clone(), config.api_key.clone())?);

    let mut collector_list: Vec<Arc<dyn Collector>> = vec![];

    #[cfg(feature = "collector-rust")]
    collector_list.push(Arc::new(collectors::crates_io::CratesIoCollector::new()));

    #[cfg(feature = "collector-nixpkgs")]
    collector_list.push(Arc::new(collectors::nixpkgs::NixpkgsCollector {}));

    #[cfg(feature = "collector-osv")]
    {
        // Exports run from a few MB (crates.io) to tens of MB (npm); allow
        // more than the 30 s used for API calls.
        let http = reqwest::Client::builder()
            .user_agent("fossdb-collector")
            .timeout(std::time::Duration::from_secs(300))
            .connect_timeout(std::time::Duration::from_secs(15))
            .build()?;
        let ecosystems = collectors::osv::ecosystems_from_env();
        tracing::info!("OSV ecosystems: {}", ecosystems.join(", "));
        collector_list.push(Arc::new(collectors::osv::OsvCollector::new(http, ecosystems)));
    }

    #[cfg(feature = "collector-libraries-io")]
    if let Some(api_key) = config.libraries_io_api_key {
        let http = reqwest::Client::builder()
            .user_agent("fossdb-collector")
            .timeout(std::time::Duration::from_secs(30))
            .connect_timeout(std::time::Duration::from_secs(15))
            .build()?;
        collector_list.push(Arc::new(collectors::libraries_io::LibrariesIoCollector::new(http, api_key)));
    }

    if collector_list.is_empty() {
        tracing::warn!("No collectors configured, exiting");
        return Ok(());
    }

    let handles: Vec<_> = collector_list
        .into_iter()
        .map(|collector| {
            let client = client.clone();
            let interval_hours = config.interval_hours;
            let name = collector.name().to_string();
            tokio::spawn(async move {
                run_collector_loop(collector, client, interval_hours).await;
                name
            })
        })
        .collect();

    // Surface panics instead of discarding the `JoinError`. Previously a
    // panicking collector vanished silently, and if every collector panicked
    // the process exited with status 0 as though all was well.
    let mut lost = 0usize;
    for result in futures::future::join_all(handles).await {
        match result {
            Ok(name) => tracing::error!("Collector {} loop exited unexpectedly", name),
            Err(e) => {
                lost += 1;
                tracing::error!("Collector task terminated abnormally: {}", e);
            }
        }
    }

    if lost > 0 {
        anyhow::bail!("{} collector task(s) terminated abnormally", lost);
    }

    Ok(())
}

async fn run_collector_loop(
    collector: Arc<dyn Collector>,
    client: Arc<CollectorClient>,
    interval_hours: u64,
) {
    let name = collector.name().to_string();
    loop {
        tracing::info!("Starting collector: {}", name);
        match collector.collect(client.clone()).await {
            Ok(()) => tracing::info!("Collector {} completed", name),
            Err(e) => tracing::error!("Collector {} failed: {:#}", name, e),
        }
        // `saturating_mul` so a large COLLECTOR_INTERVAL_HOURS cannot overflow
        // (a panic with overflow checks on, or a near-zero sleep without them).
        let duration = tokio::time::Duration::from_secs(interval_hours.saturating_mul(3600));
        tracing::info!("Collector {} sleeping for {} hours", name, interval_hours);
        tokio::time::sleep(duration).await;
    }
}
