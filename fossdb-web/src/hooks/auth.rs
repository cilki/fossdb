//! Client-side authentication state.
//!
//! There is no session token. The account id stored here *is* the credential,
//! sent as a bearer value on every request. It is kept in `localStorage`,
//! which carries the usual caveat that any XSS on this origin can read it -
//! the same exposure a long-lived JWT had, with the difference that this
//! credential does not expire, so a leak is permanent until the account is
//! abandoned.

use crate::api::types::*;
use crate::hooks::storage::{LocalStorage, StorageKey};
use dioxus::prelude::*;

#[derive(Clone, Debug, PartialEq)]
pub struct AuthState {
    pub user_id: Option<String>,
    pub user: Option<UserResponse>,
}

impl Default for AuthState {
    fn default() -> Self {
        let stored: Option<String> = LocalStorage::get(StorageKey::UserId);

        // Discard anything that is not a well-formed id. Without this, a
        // stale or hand-edited entry would be sent as a bearer value on every
        // request and produce a wall of 401s instead of a clean logged-out
        // state.
        let user_id = stored.filter(|id| fossdb::user_id::is_well_formed(id));

        let user: Option<UserResponse> = if user_id.is_some() {
            LocalStorage::get(StorageKey::UserData)
        } else {
            None
        };

        Self { user_id, user }
    }
}

#[derive(Copy, Clone)]
pub struct AuthContext {
    auth_state: Signal<AuthState>,
}

impl AuthContext {
    pub fn is_authenticated(&self) -> bool {
        self.auth_state.read().user_id.is_some()
    }

    /// The stored credential, for use as a bearer value.
    pub fn user_id(&self) -> Option<String> {
        self.auth_state.read().user_id.clone()
    }

    pub fn user(&self) -> Option<UserResponse> {
        self.auth_state.read().user.clone()
    }

    pub fn login(&mut self, user_id: String, user: UserResponse) {
        let _ = LocalStorage::set(StorageKey::UserId, &user_id);
        let _ = LocalStorage::set(StorageKey::UserData, &user);

        // One write, so a reader never observes a half-updated state.
        let mut state = self.auth_state.write();
        state.user_id = Some(user_id);
        state.user = Some(user);
    }

    pub fn logout(&mut self) {
        LocalStorage::remove(StorageKey::UserId);
        LocalStorage::remove(StorageKey::UserData);

        let mut state = self.auth_state.write();
        state.user_id = None;
        state.user = None;
    }

    /// Feed URLs for the signed-in account.
    ///
    /// Built against the current origin, since the WASM bundle is served from
    /// the same host as the API.
    pub fn feed_urls(&self) -> Option<(String, String)> {
        let user_id = self.user_id()?;
        let origin = web_sys::window()?.location().origin().ok()?;

        Some((
            format!("{origin}/feed/{user_id}/atom.xml"),
            format!("{origin}/feed/{user_id}/rss.xml"),
        ))
    }
}

pub fn use_auth() -> AuthContext {
    let auth_state = use_context::<Signal<AuthState>>();

    AuthContext { auth_state }
}
