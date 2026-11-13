use futures::FutureExt;
use isideload::{
    anisette::{AnisetteClientInfo, remote_v3::RemoteV3AnisetteProvider},
    auth::apple_account::{AppleAccount, TwoFactorCallbackParams, TwoFactorCallbackResponse},
    dev::{
        app_ids::{AppIdsApi, ListAppIdsResponse},
        certificates::{CertificatesApi, DevelopmentCertificate},
        developer_session::DeveloperSession,
    },
    sideload::{
        SideloaderBuilder,
        builder::{ExtensionsBehavior, ExtensionsBehaviorSelection, MaxCertsBehavior},
        sideloader::Sideloader,
    },
    util::callbacks::{ExtensionsBehaviorCallbackBox, MaxCertsCallbackBox},
};
use keyring::Entry;
use rootcause::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::Duration;
use tauri::{AppHandle, Emitter, Listener, State, Window};
use tauri_plugin_store::StoreExt;
use tracing::debug;

use crate::{
    error::AppError,
    secure_storage::create_sideloading_storage,
    sideload::{SideloaderGuard, SideloaderMutex},
};

#[tauri::command]
pub async fn login_new(
    handle: AppHandle,
    window: Window,
    sideloader_state: State<'_, SideloaderMutex>,
    email: String,
    password: String,
    anisette_server: String,
    save_credentials: bool,
) -> Result<(), AppError> {
    let account = login(&handle, window, &email, &password, anisette_server).await?;
    let mut sideloader_guard = sideloader_state.lock().unwrap();
    *sideloader_guard = Some(account);

    if save_credentials {
        let pass_entry = Entry::new("iloader", &email).map_err(|e| {
            AppError::KeyringWithMessage(
                "Failed to create entry for credentials".into(),
                e.to_string(),
            )
        })?;
        pass_entry.set_password(&password).map_err(|e| {
            AppError::KeyringWithMessage("Failed to save credentials".into(), e.to_string())
        })?;
        let store = handle
            .store("data.json")
            .map_err(|e| AppError::Misc(format!("Failed to get store: {:?}", e)))?;
        let mut existing_ids = store
            .get("ids")
            .unwrap_or_else(|| Value::Array(vec![]))
            .as_array()
            .cloned()
            .unwrap_or_else(std::vec::Vec::new);
        let value = Value::String(email.clone());
        if !existing_ids.contains(&value) {
            existing_ids.push(value);
        }
        store.set("ids", Value::Array(existing_ids));
    }
    Ok(())
}

#[tauri::command]
pub async fn login_stored(
    handle: AppHandle,
    window: Window,
    email: String,
    anisette_server: String,
    sideloader_state: State<'_, SideloaderMutex>,
) -> Result<(), AppError> {
    let pass_entry = Entry::new("iloader", &email).map_err(|e| {
        AppError::KeyringWithMessage(
            "Failed to create keyring entry for credentials".to_string(),
            e.to_string(),
        )
    })?;
    let password = pass_entry.get_password().map_err(|e| {
        AppError::KeyringWithMessage("Failed to get credentials".to_string(), e.to_string())
    })?;
    let account = login(&handle, window, &email, &password, anisette_server).await?;
    let mut sideloader_guard = sideloader_state.lock().unwrap();
    *sideloader_guard = Some(account);

    Ok(())
}

#[tauri::command]
pub fn delete_account(handle: AppHandle, email: String) -> Result<(), AppError> {
    let store = handle
        .store("data.json")
        .map_err(|e| AppError::Misc(format!("Failed to get store: {:?}", e)))?;
    let mut existing_ids = store
        .get("ids")
        .unwrap_or_else(|| Value::Array(vec![]))
        .as_array()
        .cloned()
        .unwrap_or_else(std::vec::Vec::new);
    existing_ids.retain(|v| v.as_str().is_none_or(|s| s != email));
    store.set("ids", Value::Array(existing_ids));
    let pass_entry = Entry::new("iloader", &email).map_err(|e| {
        AppError::KeyringWithMessage(
            "Failed to create keyring entry for credentials".into(),
            e.to_string(),
        )
    })?;
    pass_entry.delete_credential().map_err(|e| {
        AppError::KeyringWithMessage("Failed to delete credentials".into(), e.to_string())
    })?;
    Ok(())
}

#[tauri::command]
pub fn logged_in_as(sideloader_state: State<'_, SideloaderMutex>) -> Option<String> {
    let sideloader_guard = sideloader_state.lock().unwrap();
    sideloader_guard
        .as_ref()
        .map(|account| account.get_email().to_string())
}

#[tauri::command]
pub fn invalidate_account(sideloader_state: State<'_, SideloaderMutex>) {
    let mut sideloader_guard = sideloader_state.lock().unwrap();
    *sideloader_guard = None;
}

#[tauri::command]
pub fn reset_anisette_state() -> Result<bool, AppError> {
    let state_entry = Entry::new("iloader", "anisette_state").map_err(|e| {
        AppError::KeyringWithMessage(
            "Failed to create keyring entry for anisette".into(),
            e.to_string(),
        )
    })?;

    match state_entry.delete_credential() {
        Ok(_) => {
            debug!("Anisette state deleted from keyring.");
            Ok(true)
        }
        Err(keyring::Error::NoEntry) => {
            debug!("No existing anisette state found in keyring, nothing to delete.");
            Ok(false)
        }
        Err(e) => Err(AppError::KeyringWithMessage(
            "Failed to delete anisette state".into(),
            e.to_string(),
        )),
    }
}

async fn login(
    app: &AppHandle,
    window: Window,
    email: &str,
    password: &str,
    anisette_server: String,
) -> Result<Sideloader<MaxCertsCallbackBox, ExtensionsBehaviorCallbackBox>, AppError> {
    let tfa_closure = {
        let window_clone = window.clone();
        move |params: TwoFactorCallbackParams| {
            let window_clone = window_clone.clone();

            async move {
                window_clone
                    .emit("2fa-required", params)
                    .context("Failed to emit 2fa-required event")?;

                let (tx, rx) = std::sync::mpsc::channel::<String>();
                let handler_id = window_clone.listen("2fa-recieved", move |event| {
                    let code = event.payload();
                    let _ = tx.send(code.to_string());
                });

                let result = rx.recv_timeout(Duration::from_secs(120))?;
                window_clone.unlisten(handler_id);

                let code = result.trim_matches('"').to_string();
                Ok(TwoFactorCallbackResponse::SubmitCode(code))
            }
            .boxed()
        }
    };

    let anisette_url = if !anisette_server.starts_with("http") {
        format!("https://{}", anisette_server)
    } else {
        anisette_server
    };

    // Apple only accepts sign-in requests whose User-Agent and X-MMe-Client-Info match
    // the client that produced the anisette data, and answers 503 otherwise. Try
    // iloader's usual identity first, then the anisette server's own identity.
    let mac_identity = AnisetteClientInfo {
        client_info:
            "<Mac15,7> <macOS;27.0;26A5378j> <com.apple.AuthKit/1 (com.apple.akd/1.0)>"
                .to_string(),
        user_agent: "akd/1.0 CFNetwork/811.5.4".to_string(),
    };
    let identities = [Some(mac_identity), None];
    let attempts = identities.len();
    let mut account = None;
    for (attempt, identity) in identities.into_iter().enumerate() {
        let using_override = identity.is_some();
        let mut provider = RemoteV3AnisetteProvider::default()?
            .set_serial_number("0".to_string())
            .set_storage(create_sideloading_storage(app)?);
        if identity.is_some() {
            provider = provider.set_client_info_override(identity);
        }
        let provider = provider.set_url(&anisette_url);

        let result = AppleAccount::builder(&email.to_lowercase())
            .anisette_provider(provider)
            .login(password, Box::new(tfa_closure.clone()))
            .await;
        match result {
            Ok(a) => {
                if !using_override {
                    tracing::info!("Signed in with the anisette server's own client identity");
                }
                account = Some(a);
                break;
            }
            Err(e) => {
                let text = format!("{e:?}");
                let rejected = text.contains("URL Bag") || text.contains("503");
                if rejected && attempt + 1 < attempts {
                    tracing::warn!(
                        "Apple rejected the sign-in with iloader's client identity, retrying with the anisette server's own identity"
                    );
                    continue;
                }
                if rejected {
                    let diagnosis = diagnose_url_bag(&anisette_url).await;
                    tracing::error!("URL bag diagnosis: {diagnosis}");
                    return Err(AppError::Auth(format!(
                        "Apple's sign-in server rejected the request (not a wrong password). Details: {diagnosis}"
                    )));
                }
                return Err(e.into());
            }
        }
    }
    let mut account = account.ok_or_else(|| AppError::Auth("Sign-in failed".into()))?;

    debug!("Logged in");

    let dev_session = DeveloperSession::from_account(&mut account).await?;

    debug!("Created developer session");

    let max_certs_callback: MaxCertsCallbackBox =
        Box::new(move |certs: Vec<DevelopmentCertificate>| {
            let window_clone = window.clone();
            Box::pin(async move {
                let cert_infos: Vec<CertificateInfo> = certs
                    .iter()
                    .map(|cert| CertificateInfo {
                        name: cert.name.clone(),
                        certificate_id: cert.certificate_id.clone(),
                        serial_number: cert.serial_number.clone(),
                        machine_name: cert.machine_name.clone(),
                        machine_id: cert.machine_id.clone(),
                    })
                    .collect();
                window_clone.emit("max-certs-reached", cert_infos)?;

                let (tx, rx) = std::sync::mpsc::channel::<Option<Vec<String>>>();
                let handler_id = window_clone.listen("max-certs-response", move |event| {
                    let certs = event.payload();
                    let certs = serde_json::from_str::<Option<Vec<String>>>(certs).unwrap_or(None);
                    let _ = tx.send(certs);
                });

                let result = rx.recv_timeout(Duration::from_secs(300));
                window_clone.unlisten(handler_id);
                Ok(result?)
            })
        });

    // TODO: Team Selection

    let sideloader = SideloaderBuilder::new(dev_session, email.to_lowercase())
        .machine_name("iloader".into())
        .storage(create_sideloading_storage(app)?)
        .extensions_behavior(ExtensionsBehaviorSelection::Fixed(
            ExtensionsBehavior::ReuseMain,
        ))
        .max_certs_behavior(MaxCertsBehavior::Prompt(max_certs_callback))
        .build();

    debug!("Built sideloader");

    Ok(sideloader)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificateInfo {
    pub name: Option<String>,
    pub certificate_id: Option<String>,
    pub serial_number: Option<String>,
    pub machine_name: Option<String>,
    pub machine_id: Option<String>,
}

#[tauri::command]
pub async fn get_certificates(
    sideloader_state: State<'_, SideloaderMutex>,
) -> Result<Vec<CertificateInfo>, AppError> {
    let mut sideloader = SideloaderGuard::take(&sideloader_state)?;

    let team = sideloader.get_mut().get_team().await?;
    let dev_session = sideloader.get_mut().get_dev_session();

    let certificates = dev_session.list_all_development_certs(&team, None).await?;

    Ok(certificates
        .into_iter()
        .map(|cert| CertificateInfo {
            name: cert.name,
            certificate_id: cert.certificate_id,
            serial_number: cert.serial_number,
            machine_name: cert.machine_name,
            machine_id: cert.machine_id,
        })
        .collect())
}

#[tauri::command]
pub async fn revoke_certificate(
    serial_number: String,
    sideloader_state: State<'_, SideloaderMutex>,
) -> Result<(), AppError> {
    let mut sideloader = SideloaderGuard::take(&sideloader_state)?;

    let team = sideloader.get_mut().get_team().await?;
    let dev_session = sideloader.get_mut().get_dev_session();

    dev_session
        .revoke_development_cert(&team, &serial_number, None)
        .await?;

    Ok(())
}

#[tauri::command]
pub async fn list_app_ids(
    sideloader_state: State<'_, SideloaderMutex>,
) -> Result<ListAppIdsResponse, AppError> {
    let mut sideloader = SideloaderGuard::take(&sideloader_state)?;

    let team = sideloader.get_mut().get_team().await?;
    let dev_session = sideloader.get_mut().get_dev_session();

    let response = dev_session.list_app_ids(&team, None).await?;

    Ok(response.clone())
}

#[tauri::command]
pub async fn delete_app_id(
    app_id_id: String,
    sideloader_state: State<'_, SideloaderMutex>,
) -> Result<(), AppError> {
    let mut sideloader = SideloaderGuard::take(&sideloader_state)?;

    let team = sideloader.get_mut().get_team().await?;
    let dev_session = sideloader.get_mut().get_dev_session();

    dev_session.delete_app_id(&team, &app_id_id, None).await?;

    Ok(())
}

/// Fetches GrandSlam's URL bag with several client identities and reports which ones
/// Apple accepts (HTTP status for each), plus the start of the first rejected body.
async fn diagnose_url_bag(anisette_url: &str) -> String {
    const URL_BAG: &str = "https://gsa.apple.com/grandslam/GsService2/lookup";
    let client = match reqwest::Client::builder().build() {
        Ok(c) => c,
        Err(e) => return format!("could not build HTTP client: {e}"),
    };

    let mut identities: Vec<(String, Option<(String, String)>)> = vec![
        (
            "iloader Mac".into(),
            Some((
                "akd/1.0 CFNetwork/811.5.4".into(),
                "<Mac15,7> <macOS;27.0;26A5378j> <com.apple.AuthKit/1 (com.apple.akd/1.0)>".into(),
            )),
        ),
        (
            "iTunes Windows".into(),
            Some((
                "akd/1.0 CFNetwork/808.1.4".into(),
                "<PC> <Windows;6.2(0,0);9200> <com.apple.AuthKit/1 (com.apple.iTunes/12.12.4.1)>".into(),
            )),
        ),
        ("no headers".into(), None),
    ];

    // The anisette server's own identity, which Apple expects to match its data.
    let info_url = format!("{}/v3/client_info", anisette_url.trim_end_matches('/'));
    match client.get(&info_url).send().await {
        Ok(resp) => match resp
            .text()
            .await
            .map_err(|e| e.to_string())
            .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).map_err(|e| e.to_string()))
        {
            Ok(v) => {
                let ci = v.get("client_info").and_then(|x| x.as_str());
                let ua = v.get("user_agent").and_then(|x| x.as_str());
                if let (Some(ci), Some(ua)) = (ci, ua) {
                    identities.insert(0, ("anisette server".into(), Some((ua.into(), ci.into()))));
                }
            }
            Err(e) => tracing::warn!("Invalid client_info from {info_url}: {e}"),
        },
        Err(e) => tracing::warn!("Could not fetch {info_url}: {e}"),
    }

    let mut results = Vec::new();
    let mut first_body = None;
    for (name, headers) in identities {
        let mut request = client.get(URL_BAG).header("Accept", "text/x-xml-plist");
        if let Some((ua, ci)) = &headers {
            request = request.header("User-Agent", ua).header("X-Mme-Client-Info", ci);
        }
        match request.send().await {
            Ok(resp) => {
                let status = resp.status();
                if !status.is_success() && first_body.is_none() {
                    let body = resp.text().await.unwrap_or_default();
                    first_body = Some(
                        body.chars().take(200).collect::<String>().split_whitespace().collect::<Vec<_>>().join(" "),
                    );
                }
                results.push(format!("{name}: HTTP {}", status.as_u16()));
            }
            Err(e) => results.push(format!("{name}: failed ({e})")),
        }
    }
    format!(
        "{}. First rejection body: {}",
        results.join(", "),
        first_body.unwrap_or_else(|| "none".into())
    )
}
