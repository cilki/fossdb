//! HTTP client for the public fossdb API.

use std::time::Duration;

use anyhow::{Context, Result, bail};
use fossdb::url::percent_encode;
use fossdb::{
    AuthResponse, PackageSubscription, RegisterResponse, SubscribeResponse, SubscriptionRequest,
    SubscriptionResponse,
};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

pub struct Client {
    http: reqwest::Client,
    server: String,
    /// Present for every call except `register`.
    user_id: Option<String>,
}

impl Client {
    pub fn new(server: &str, user_id: Option<String>) -> Result<Self> {
        let http = reqwest::Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .user_agent(concat!("fossdb-cli/", env!("CARGO_PKG_VERSION")))
            .build()
            .context("building HTTP client")?;

        Ok(Self {
            http,
            server: crate::credentials::normalize_server(server),
            user_id,
        })
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.server, path)
    }

    /// Attach the bearer credential, if we have one.
    fn authed(&self, builder: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.user_id {
            Some(user_id) => builder.bearer_auth(user_id),
            None => builder,
        }
    }

    /// Decode a response, turning a non-2xx into a useful error.
    ///
    /// The status is translated into something actionable: a bare "401
    /// Unauthorized" tells a user nothing about what to do next.
    ///
    /// A 404 means something different on every endpoint (an unknown package,
    /// a package the account is not subscribed to, ...), so the caller says
    /// what it means for this request.
    async fn decode<T: serde::de::DeserializeOwned>(
        &self,
        response: reqwest::Response,
        what: &str,
        not_found: &str,
    ) -> Result<T> {
        let status = response.status();

        if !status.is_success() {
            let body = response.unwrap_or_default_text().await;

            let not_found = format!(" - {not_found}");
            let hint = match status.as_u16() {
                401 => " - the stored account id was rejected; it may have been purged \
                         (accounts with no subscriptions are deleted automatically). \
                         Run `fossdb login` again or `fossdb register` for a new account.",
                404 => not_found.as_str(),
                429 => " - rate limited; try again shortly",
                500..=599 => " - the server reported an internal error",
                _ => "",
            };

            if body.is_empty() {
                bail!("{what} failed: {status}{hint}");
            }
            bail!("{what} failed: {status}{hint}\nserver said: {body}");
        }

        response
            .json()
            .await
            .with_context(|| format!("{what}: could not parse the server's response"))
    }

    /// Create a new account. Needs no credential - that is what it returns.
    pub async fn register(&self) -> Result<RegisterResponse> {
        let response = self
            .http
            .post(self.url("/api/auth/register"))
            .send()
            .await
            .with_context(|| format!("connecting to {}", self.server))?;

        self.decode(response, "registration", "this server has no such endpoint; check that --server/FOSSDB_SERVER points at a FossDB server")
            .await
    }

    /// Confirm a credential names a live account.
    pub async fn login(&self, user_id: &str) -> Result<AuthResponse> {
        let response = self
            .http
            .post(self.url("/api/auth/login"))
            .json(&fossdb::LoginRequest {
                user_id: user_id.to_string(),
            })
            .send()
            .await
            .with_context(|| format!("connecting to {}", self.server))?;

        self.decode(response, "login", "this server has no such endpoint; check that --server/FOSSDB_SERVER points at a FossDB server").await
    }

    pub async fn subscriptions(&self) -> Result<Vec<PackageSubscription>> {
        let response = self
            .authed(self.http.get(self.url("/api/users/subscriptions")))
            .send()
            .await
            .with_context(|| format!("connecting to {}", self.server))?;

        let body: SubscriptionResponse = self
            .decode(
                response,
                "fetching subscriptions",
                "the account no longer exists; run `fossdb register` for a new one",
            )
            .await?;
        Ok(body.subscriptions)
    }

    pub async fn subscribe(&self, package_name: &str) -> Result<SubscribeResponse> {
        let response = self
            .authed(self.http.post(self.url("/api/users/subscriptions")))
            .json(&SubscriptionRequest {
                package_name: package_name.to_string(),
            })
            .send()
            .await
            .with_context(|| format!("connecting to {}", self.server))?;

        self.decode(
            response,
            &format!("subscribing to {package_name}"),
            &format!(
                "this server knows no package named `{package_name}` \
                 (names must match exactly, including case)"
            ),
        )
        .await
    }

    pub async fn unsubscribe(&self, package_name: &str) -> Result<Vec<PackageSubscription>> {
        // Percent-encode the path segment: package names legitimately contain
        // `/` (scoped npm packages such as `@angular/cli`), which would
        // otherwise be read as a path separator and hit a different route.
        let encoded = percent_encode(package_name);

        let response = self
            .authed(
                self.http
                    .delete(self.url(&format!("/api/users/subscriptions/{encoded}"))),
            )
            .send()
            .await
            .with_context(|| format!("connecting to {}", self.server))?;

        let body: SubscriptionResponse = self
            .decode(
                response,
                &format!("unsubscribing from {package_name}"),
                &not_subscribed(package_name),
            )
            .await?;
        Ok(body.subscriptions)
    }

    pub async fn set_package_notifications(
        &self,
        package_name: &str,
        enabled: bool,
    ) -> Result<Vec<PackageSubscription>> {
        let encoded = percent_encode(package_name);

        let response = self
            .authed(self.http.put(self.url(&format!(
                "/api/users/subscriptions/{encoded}/notifications"
            ))))
            .json(&serde_json::json!({ "notifications_enabled": enabled }))
            .send()
            .await
            .with_context(|| format!("connecting to {}", self.server))?;

        let body: SubscriptionResponse = self
            .decode(
                response,
                &format!("updating notifications for {package_name}"),
                &not_subscribed(package_name),
            )
            .await?;
        Ok(body.subscriptions)
    }
}

/// Explanation for an operation on a package the account does not follow.
pub fn not_subscribed(package_name: &str) -> String {
    format!(
        "this account is not subscribed to `{package_name}`; \
         run `fossdb subscriptions` to list the packages it follows"
    )
}

/// Read a response body as text, tolerating a failed read.
trait ResponseTextExt {
    async fn unwrap_or_default_text(self) -> String;
}

impl ResponseTextExt for reqwest::Response {
    async fn unwrap_or_default_text(self) -> String {
        self.text()
            .await
            .unwrap_or_default()
            .trim()
            .chars()
            // Keep error output to one terminal screen even if the server
            // returns an HTML error page.
            .take(500)
            .collect()
    }
}
