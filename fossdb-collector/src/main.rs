use anyhow::Result;
use clap::Parser;
use std::sync::Arc;

mod client;
mod collectors;

use client::CollectorClient;
use collectors::Collector;

/// FossDB package collector
///
/// Fetches package metadata and security advisories and submits them to
/// fossdb-server's collector API, then repeats every `--interval-hours`.
///
/// Every option can also be set in the environment or in a `.env` file. The
/// API key is read from COLLECTOR_API_KEY, or from the file named by
/// COLLECTOR_API_KEY_FILE; mint one on the server with
/// `fossdb admin api-key create --role collector`. OSV_ECOSYSTEMS selects the
/// ecosystems whose advisories are ingested (default: crates.io).
#[derive(Parser)]
#[command(version)]
struct Config {
    /// Base URL of fossdb-server's collector API
    #[arg(long, env = "SERVER_INTERNAL_URL", default_value = "http://localhost:3001")]
    server_url: String,

    /// Hours to wait between runs of each collector
    #[arg(long, env = "COLLECTOR_INTERVAL_HOURS", default_value_t = 1)]
    interval_hours: u64,

    /// libraries.io API key; enables the libraries.io collector when built
    /// with the `collector-libraries-io` feature
    #[allow(dead_code)]
    #[arg(long, env = "LIBRARIES_IO_API_KEY", hide_env_values = true)]
    libraries_io_api_key: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();
    // Before anything else, so `--help` and a malformed setting stop here
    // rather than after a collection run has started.
    let config = Config::parse();
    tracing_subscriber::fmt::init();

    // Not a flag: a key on the command line would show up in `ps`.
    // Accepts `COLLECTOR_API_KEY` or `COLLECTOR_API_KEY_FILE`.
    let api_key = fossdb::secret_file::from_env("COLLECTOR_API_KEY")?;

    if !fossdb::api_key::is_well_formed(&api_key) {
        tracing::warn!(
            "COLLECTOR_API_KEY does not look like a fossdb API key (expected {} characters \
             beginning with {:?}); the server will reject it",
            fossdb::api_key::TOTAL_LEN,
            fossdb::api_key::PREFIX
        );
    }

    let client = Arc::new(CollectorClient::new(config.server_url.clone(), api_key)?);

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
    // `.env.example` ships `LIBRARIES_IO_API_KEY=`, which means "no key".
    if let Some(api_key) = config.libraries_io_api_key.filter(|k| !k.is_empty()) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_valid() {
        Config::command().debug_assert();
    }

    /// A typo used to fall back silently to one hour.
    #[test]
    fn malformed_interval_is_rejected() {
        assert!(Config::try_parse_from(["fossdb-collector", "--interval-hours", "2h"]).is_err());
    }
}
