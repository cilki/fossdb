use super::types::*;
use gloo_console::log;
use serde::de::DeserializeOwned;
use serde::Serialize;
use wasm_bindgen::JsCast;
use wasm_bindgen::JsValue;
use wasm_bindgen_futures::JsFuture;
use web_sys::{Request, RequestInit, RequestMode, Response};

type Result<T> = std::result::Result<T, JsValue>;

/// Percent-encode a value for use in a URL path segment or query value.
///
/// Raw interpolation let user input change the request: searching for `c++`
/// arrived as two spaces, a `#` truncated the query client-side, and `&`
/// allowed injecting additional parameters such as `limit`.
pub(crate) fn encode_uri_component(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*byte as char)
            }
            _ => out.push_str(&format!("%{:02X}", byte)),
        }
    }
    out
}

/// Server-side filters for `GET /packages`.
#[derive(Default, Clone, Copy)]
pub struct PackageQuery<'a> {
    pub search: Option<&'a str>,
    pub tag: Option<&'a str>,
    pub language: Option<&'a str>,
    pub license: Option<&'a str>,
    pub updated_within: Option<&'a str>,
}

pub struct ApiClient {
    base_url: String,
    /// The account id, sent as a bearer credential.
    user_id: Option<String>,
}

impl ApiClient {
    pub fn new() -> Self {
        let base_url = web_sys::window()
            .and_then(|w| w.location().hostname().ok())
            .map(|hostname| {
                if hostname == "localhost" || hostname == "127.0.0.1" {
                    "http://localhost:3000/api".to_string()
                } else {
                    "/api".to_string()
                }
            })
            .unwrap_or_else(|| "/api".to_string());

        Self {
            base_url,
            user_id: None,
        }
    }

    pub fn with_user_id(mut self, user_id: Option<String>) -> Self {
        self.user_id = user_id;
        self
    }

    async fn request<T: DeserializeOwned>(
        &self,
        method: &str,
        path: &str,
        body: Option<String>,
    ) -> Result<T> {
        let url = format!("{}{}", self.base_url, path);

        let mut opts = RequestInit::new();
        opts.method(method);
        opts.mode(RequestMode::Cors);

        if let Some(body_str) = body {
            opts.body(Some(&JsValue::from_str(&body_str)));
        }

        let request = Request::new_with_str_and_init(&url, &opts)?;

        request.headers().set("Content-Type", "application/json")?;

        if let Some(user_id) = &self.user_id {
            request
                .headers()
                .set("Authorization", &format!("Bearer {}", user_id))?;
        }

        let window = web_sys::window().ok_or_else(|| JsValue::from_str("No window"))?;
        let resp_value = JsFuture::from(window.fetch_with_request(&request)).await?;
        let resp: Response = resp_value.dyn_into()?;

        if !resp.ok() {
            // Include the server's message so the UI can show something better
            // than the bare string "HTTP error: 401".
            let status = resp.status();
            let detail = match resp.text() {
                Ok(promise) => JsFuture::from(promise)
                    .await
                    .ok()
                    .and_then(|v| v.as_string())
                    .filter(|body| !body.trim().is_empty()),
                Err(_) => None,
            };

            return Err(JsValue::from_str(&match detail {
                Some(body) => format!("HTTP error {}: {}", status, body),
                None => format!("HTTP error {}", status),
            }));
        }

        let json = JsFuture::from(
            resp.json()
                .map_err(|_| JsValue::from_str("Failed to parse response"))?,
        )
        .await?;
        serde_wasm_bindgen::from_value(json)
            .map_err(|e| JsValue::from_str(&format!("Deserialization error: {:?}", e)))
    }

    /// Confirm an id names a live account. No token is issued; the id the
    /// caller already holds is the credential.
    pub async fn login(&self, user_id: String) -> Result<AuthResponse> {
        let body = serde_json::to_string(&LoginRequest { user_id })
            .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))?;
        self.request("POST", "/auth/login", Some(body)).await
    }

    /// Create an account. Takes no input - the server mints the credential
    /// and this is the only time it is ever disclosed.
    pub async fn register(&self) -> Result<RegisterResponse> {
        // An empty JSON body: the endpoint takes no parameters, but the
        // request still advertises `Content-Type: application/json`.
        self.request("POST", "/auth/register", Some("{}".to_string()))
            .await
    }

    pub async fn get_stats(&self) -> Result<DatabaseStats> {
        self.request("GET", "/stats", None).await
    }

    /// Filters passed to `GET /packages`. Empty values are omitted.
    ///
    /// All filtering happens server-side so that the reported `total` (and
    /// therefore the page count) matches what is actually returned.
    pub async fn get_packages(
        &self,
        filters: PackageQuery<'_>,
        page: u32,
        limit: u32,
    ) -> Result<PackagesResponse> {
        let mut path = format!("/packages?page={}&limit={}", page, limit);
        for (key, value) in [
            ("search", filters.search),
            ("tag", filters.tag),
            ("language", filters.language),
            ("license", filters.license),
            ("updated_within", filters.updated_within),
        ] {
            if let Some(value) = value.filter(|v| !v.is_empty()) {
                path.push_str(&format!("&{}={}", key, encode_uri_component(value)));
            }
        }
        self.request("GET", &path, None).await
    }

    pub async fn get_package(&self, id: &str) -> Result<Package> {
        self.request(
            "GET",
            &format!("/packages/{}", encode_uri_component(id)),
            None,
        )
        .await
    }

    pub async fn get_package_versions(&self, id: &str) -> Result<Vec<PackageVersion>> {
        self.request(
            "GET",
            &format!("/packages/{}/versions", encode_uri_component(id)),
            None,
        )
        .await
    }

    pub async fn get_package_subscribers(&self, id: &str) -> Result<usize> {
        // The server returns `{package_id, package_name, subscriber_count}`.
        // Deserializing a non-optional `count` field that does not exist made
        // this call always fail, so the UI always rendered 0 subscribers.
        #[derive(serde::Deserialize)]
        struct SubscriberCount {
            subscriber_count: usize,
        }
        let result: SubscriberCount = self
            .request(
                "GET",
                &format!("/packages/{}/subscribers", encode_uri_component(id)),
                None,
            )
            .await?;
        Ok(result.subscriber_count)
    }

    /// The server replies with a `SubscriptionResponse` object wrapping the
    /// list, not a bare array. Deserializing into `Vec<_>` always failed, so the
    /// subscriptions page showed "No Subscriptions Yet" to subscribed users and
    /// package pages never rendered the "Unsubscribe" state.
    pub async fn get_subscriptions(&self) -> Result<Vec<PackageSubscription>> {
        let response: SubscriptionResponse =
            self.request("GET", "/users/subscriptions", None).await?;
        Ok(response.subscriptions)
    }

    // The three mutations below return the updated `SubscriptionResponse`.
    // They were typed as `Result<()>`, and `serde_wasm_bindgen` only
    // deserializes `()` from null/undefined - so every call reported failure
    // even though the write had succeeded, and the UI never updated.

    pub async fn subscribe(&self, package_name: String) -> Result<Vec<PackageSubscription>> {
        let body = serde_json::to_string(&SubscriptionRequest { package_name })
            .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))?;
        let response: SubscriptionResponse = self
            .request("POST", "/users/subscriptions", Some(body))
            .await?;
        Ok(response.subscriptions)
    }

    pub async fn unsubscribe(&self, package_name: &str) -> Result<Vec<PackageSubscription>> {
        let response: SubscriptionResponse = self
            .request(
                "DELETE",
                &format!(
                    "/users/subscriptions/{}",
                    encode_uri_component(package_name)
                ),
                None,
            )
            .await?;
        Ok(response.subscriptions)
    }

    pub async fn toggle_notifications(
        &self,
        package_name: &str,
        enabled: bool,
    ) -> Result<Vec<PackageSubscription>> {
        #[derive(serde::Serialize)]
        struct NotificationToggle {
            notifications_enabled: bool,
        }
        let body = serde_json::to_string(&NotificationToggle {
            notifications_enabled: enabled,
        })
        .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))?;
        let response: SubscriptionResponse = self
            .request(
                "PUT",
                &format!(
                    "/users/subscriptions/{}/notifications",
                    encode_uri_component(package_name)
                ),
                Some(body),
            )
            .await?;
        Ok(response.subscriptions)
    }

    pub async fn get_timeline(&self, offset: usize, limit: usize) -> Result<TimelineResponse> {
        self.request(
            "GET",
            &format!("/users/timeline?offset={}&limit={}", offset, limit),
            None,
        )
        .await
    }
}

impl Default for ApiClient {
    fn default() -> Self {
        Self::new()
    }
}
