use anyhow::Result;

mod analysis;
mod client;

use client::WorkerClient;

struct Config {
    server_url: String,
    api_key: String,
    interval_secs: u64,
}

impl Config {
    fn from_env() -> Result<Self> {
        Ok(Self {
            server_url: std::env::var("WORKER_SERVER_URL")
                .unwrap_or_else(|_| "http://localhost:3002".to_string()),
            // Accepts `WORKER_API_KEY` or `WORKER_API_KEY_FILE`; the latter is
            // what a service manager hands over via systemd credentials.
            api_key: fossdb::secret_file::from_env("WORKER_API_KEY")?,
            interval_secs: std::env::var("WORKER_INTERVAL_SECS")
                .unwrap_or_else(|_| "60".to_string())
                .parse()
                .unwrap_or(60),
        })
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt::init();

    let config = Config::from_env()?;
    let client = WorkerClient::new(config.server_url.clone(), config.api_key.clone())?;

    if !fossdb::api_key::is_well_formed(&config.api_key) {
        tracing::warn!(
            "WORKER_API_KEY does not look like a fossdb API key (expected {} characters \
             beginning with {:?}); the server will reject it",
            fossdb::api_key::TOTAL_LEN,
            fossdb::api_key::PREFIX
        );
    }

    tracing::info!("Worker started, connecting to {}", config.server_url);

    loop {
        match run_once(&client).await {
            Ok(()) => {}
            Err(e) => tracing::error!("Worker iteration failed: {:#}", e),
        }

        tracing::debug!("Sleeping {} seconds before next task", config.interval_secs);
        tokio::time::sleep(tokio::time::Duration::from_secs(config.interval_secs)).await;
    }
}

async fn run_once(client: &WorkerClient) -> Result<()> {
    let Some(task) = client.get_task().await? else {
        tracing::info!("No unanalyzed packages available, skipping");
        return Ok(());
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

    Ok(())
}
