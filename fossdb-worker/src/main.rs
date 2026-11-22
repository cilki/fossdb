use anyhow::Result;
use clap::Parser;

mod analysis;
mod client;

use client::WorkerClient;

/// FossDB package analysis worker
///
/// Claims unanalysed package versions from fossdb-server's worker API,
/// downloads and analyses them, and submits the results.
///
/// Every option can also be set in the environment or in a `.env` file. The
/// API key is read from WORKER_API_KEY, or from the file named by
/// WORKER_API_KEY_FILE; mint one on the server with
/// `fossdb admin api-key create --role worker`.
#[derive(Parser)]
#[command(version)]
struct Config {
    /// Base URL of fossdb-server's worker API
    #[arg(long, env = "WORKER_SERVER_URL", default_value = "http://localhost:3002")]
    server_url: String,

    /// Seconds to wait before asking again when the queue is empty or a task
    /// failed
    #[arg(long, env = "WORKER_INTERVAL_SECS", default_value_t = 60)]
    interval_secs: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();
    // Before anything else, so `--help` and a malformed setting stop here
    // rather than after the worker has started claiming tasks.
    let config = Config::parse();
    tracing_subscriber::fmt::init();

    // Not a flag: a key on the command line would show up in `ps`.
    // Accepts `WORKER_API_KEY` or `WORKER_API_KEY_FILE`; the latter is what a
    // service manager hands over via systemd credentials.
    let api_key = fossdb::secret_file::from_env("WORKER_API_KEY")?;
    let client = WorkerClient::new(config.server_url.clone(), api_key.clone())?;

    if !fossdb::api_key::is_well_formed(&api_key) {
        tracing::warn!(
            "WORKER_API_KEY does not look like a fossdb API key (expected {} characters \
             beginning with {:?}); the server will reject it",
            fossdb::api_key::TOTAL_LEN,
            fossdb::api_key::PREFIX
        );
    }

    tracing::info!("Worker started, connecting to {}", config.server_url);

    loop {
        let outcome = run_once(&client).await;
        if let Err(e) = &outcome {
            tracing::error!("Worker iteration failed: {:#}", e);
        }

        if should_sleep(&outcome) {
            tracing::debug!("Sleeping {} seconds before next task", config.interval_secs);
            tokio::time::sleep(tokio::time::Duration::from_secs(config.interval_secs)).await;
        }
    }
}

/// What one pass of the worker loop accomplished.
#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    /// A task was analysed and its result submitted.
    Analysed,
    /// The server had no unanalysed versions to hand out.
    Idle,
}

/// Whether to wait `WORKER_INTERVAL_SECS` before asking for the next task.
///
/// The interval is a poll interval for an idle queue and a backoff after a
/// failure. After a completed task the queue may well hold more, so the worker
/// asks again straight away; sleeping there instead capped throughput at one
/// analysis per interval (one a minute by default) however large the backlog
/// a collector run had just queued.
fn should_sleep(outcome: &Result<Outcome>) -> bool {
    !matches!(outcome, Ok(Outcome::Analysed))
}

async fn run_once(client: &WorkerClient) -> Result<Outcome> {
    let Some(task) = client.get_task().await? else {
        tracing::info!("No unanalyzed packages available, skipping");
        return Ok(Outcome::Idle);
    };

    tracing::info!(
        "Received task: {}@{}",
        task.package.name,
        task.version.version
    );

    let analysis = analysis::analyze(&task, client.http()).await?;

    tracing::info!(
        "Analysis complete: {} findings (license={:?}, checksum_ok={:?})",
        analysis.findings.len(),
        analysis.detected_license,
        analysis.checksum_verified
    );

    client.submit_analysis(&analysis).await?;
    tracing::info!("Analysis submitted successfully");

    Ok(Outcome::Analysed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_valid() {
        Config::command().debug_assert();
    }

    /// A typo used to fall back silently to 60 seconds.
    #[test]
    fn malformed_interval_is_rejected() {
        assert!(Config::try_parse_from(["fossdb-worker", "--interval-secs", "1m"]).is_err());
    }

    #[test]
    fn asks_again_immediately_after_a_completed_task() {
        assert!(!should_sleep(&Ok(Outcome::Analysed)));
    }

    #[test]
    fn waits_when_the_queue_is_empty() {
        assert!(should_sleep(&Ok(Outcome::Idle)));
    }

    /// A failure may be the server being down or a download host refusing us;
    /// retrying in a tight loop would hammer either.
    #[test]
    fn backs_off_after_a_failure() {
        assert!(should_sleep(&Err(anyhow::anyhow!("server unreachable"))));
    }
}
