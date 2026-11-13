//! Moves a saved sign-in from one iloader to another (e.g. from a computer to an iPad).
//!
//! What makes a sign-in work smoothly is stored locally:
//! - the password (system keychain, entry "iloader"/<email>),
//! - the anisette state: the provisioned "virtual Mac" Apple already trusts, so no new
//!   2FA prompt and no new provisioning,
//! - the private key of the development certificate (`<sha256(email)>/key`), so the
//!   existing certificate keeps being used instead of creating a new one.
//!
//! The exported file contains all of that in plain form. It must be treated like the
//! password itself.

use keyring::Entry;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tauri::AppHandle;
use tauri_plugin_dialog::DialogExt;
use tauri_plugin_store::StoreExt;
use tracing::info;

use isideload::anisette::remote_v3::ANISETTE_STATE_KEY;

use crate::{error::AppError, secure_storage::create_sideloading_storage};

const FORMAT: &str = "iloader-session";
const VERSION: u32 = 1;

#[derive(Serialize, Deserialize)]
struct SessionExport {
    format: String,
    version: u32,
    email: String,
    password: String,
    /// Entries of iloader's sideloading storage, by key.
    storage: Vec<(String, Vec<u8>)>,
}

fn cert_key_storage_key(email: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(email.to_lowercase().as_bytes());
    format!("{}/key", hex::encode(hasher.finalize()))
}

fn keyring_entry(email: &str) -> Result<Entry, AppError> {
    Entry::new("iloader", email).map_err(|e| {
        AppError::KeyringWithMessage("Failed to create entry for credentials".into(), e.to_string())
    })
}

/// Writes a saved account's sign-in to a file the user chooses.
#[tauri::command]
pub async fn export_session(app: AppHandle, email: String) -> Result<(), AppError> {
    let password = keyring_entry(&email)?.get_password().map_err(|e| {
        AppError::KeyringWithMessage("Failed to read the saved password".into(), e.to_string())
    })?;

    let storage = create_sideloading_storage(&app)?;
    let mut items = Vec::new();
    for key in [ANISETTE_STATE_KEY.to_string(), cert_key_storage_key(&email)] {
        match storage.retrieve_data(&key) {
            Ok(Some(value)) => items.push((key, value)),
            Ok(None) => {}
            Err(e) => {
                return Err(AppError::Storage(
                    format!("Failed to read {key} from storage"),
                    e.to_string(),
                ));
            }
        }
    }

    let export = SessionExport {
        format: FORMAT.into(),
        version: VERSION,
        email: email.clone(),
        password,
        storage: items,
    };
    let data = serde_json::to_vec_pretty(&export)
        .map_err(|e| AppError::Misc(format!("Failed to serialize sign-in: {e}")))?;

    let save_path = app
        .dialog()
        .file()
        .add_filter("iloader sign-in", &["iloadersession"])
        .set_file_name("iloader-signin.iloadersession")
        .set_title("Export Sign-in")
        .blocking_save_file();

    match save_path.as_ref().and_then(|p| p.as_path()) {
        Some(path) => {
            tokio::fs::write(path, &data).await.map_err(|e| {
                AppError::Filesystem("Failed to write sign-in file".into(), e.to_string())
            })?;
            info!("Exported sign-in for {email}");
            Ok(())
        }
        None => Err(AppError::Canceled("Export".into())),
    }
}

/// Imports a sign-in exported by another iloader and saves it as a stored account.
/// Returns the account's email; signing in is then the usual "Sign in" on that account.
#[tauri::command]
pub async fn import_session(app: AppHandle, data: Vec<u8>) -> Result<String, AppError> {
    let export: SessionExport = serde_json::from_slice(&data).map_err(|e| {
        AppError::Misc(format!("This isn't an iloader sign-in file: {e}"))
    })?;
    if export.format != FORMAT {
        return Err(AppError::Misc("This isn't an iloader sign-in file.".into()));
    }
    if export.version > VERSION {
        return Err(AppError::Misc(
            "This sign-in file was made by a newer iloader. Update iloader and try again.".into(),
        ));
    }

    let storage = create_sideloading_storage(&app)?;
    for (key, value) in &export.storage {
        storage.store_data(key, value).map_err(|e| {
            AppError::Storage(format!("Failed to save {key}"), e.to_string())
        })?;
    }

    keyring_entry(&export.email)?
        .set_password(&export.password)
        .map_err(|e| {
            AppError::KeyringWithMessage("Failed to save credentials".into(), e.to_string())
        })?;

    // Same list of saved accounts login_new keeps.
    let store = app
        .store("data.json")
        .map_err(|e| AppError::Misc(format!("Failed to get store: {:?}", e)))?;
    let mut ids = store
        .get("ids")
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default();
    let value = Value::String(export.email.clone());
    if !ids.contains(&value) {
        ids.push(value);
    }
    store.set("ids", Value::Array(ids));

    info!(
        "Imported sign-in for {} ({} storage entries)",
        export.email,
        export.storage.len()
    );
    Ok(export.email)
}
