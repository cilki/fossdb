use gloo_storage::{LocalStorage as GlooLocalStorage, Storage};
use serde::{Deserialize, Serialize};

pub enum StorageKey {
    /// The account id. This is a credential, not a session token - see
    /// [`crate::hooks::auth`].
    UserId,
    UserData,
    ViewMode,
}

impl StorageKey {
    fn as_str(&self) -> &str {
        match self {
            StorageKey::UserId => "user_id",
            StorageKey::UserData => "user_data",
            StorageKey::ViewMode => "view_mode",
        }
    }
}

pub struct LocalStorage;

impl LocalStorage {
    pub fn get<T: for<'de> Deserialize<'de>>(key: StorageKey) -> Option<T> {
        GlooLocalStorage::get(key.as_str()).ok()
    }

    pub fn set<T: Serialize>(
        key: StorageKey,
        value: &T,
    ) -> Result<(), gloo_storage::errors::StorageError> {
        GlooLocalStorage::set(key.as_str(), value)
    }

    pub fn remove(key: StorageKey) {
        GlooLocalStorage::delete(key.as_str());
    }
}
