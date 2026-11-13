use std::{
    collections::HashMap,
    future::Future,
    net::IpAddr,
    path::PathBuf,
    pin::Pin,
    sync::{Mutex, OnceLock},
    time::Duration,
};

use idevice::{
    Idevice, IdeviceError, IdeviceService,
    lockdown::LockdownClient,
    pairing_file::PairingFile,
    provider::{IdeviceProvider, TcpProvider, UsbmuxdProvider},
    usbmuxd::UsbmuxdConnection,
};
#[cfg(not(target_os = "ios"))]
use idevice::usbmuxd::{Connection, UsbmuxdAddr};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager, State};
use tokio_util::sync::CancellationToken;
use tracing::warn;

use crate::{
    error::AppError,
    pairing::{pairing_file, with_pairing_storage},
};

#[derive(Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct DeviceInfo {
    pub name: String,
    pub id: u32,
    pub udid: String,
    pub connection_type: String,
    pub version: String,
    /// IP address for devices reached over the network with an imported pairing file.
    /// `None` for devices discovered through usbmuxd.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
}

#[derive(Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct DeviceInfoWithPairing {
    pub info: DeviceInfo,
    pub pairing: Vec<u8>,
}

pub type DeviceInfoMutex = Mutex<Option<DeviceInfoWithPairing>>;
pub type PairingCancelToken = Mutex<Option<CancellationToken>>;

// ---------------------------------------------------------------------------
// Provider that can talk to a device over usbmuxd (USB) or directly over TCP.
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum AnyProvider {
    Usb(UsbmuxdProvider),
    Tcp(TcpProvider),
}

impl IdeviceProvider for AnyProvider {
    fn connect(
        &self,
        port: u16,
    ) -> Pin<Box<dyn Future<Output = Result<Idevice, IdeviceError>> + Send>> {
        match self {
            AnyProvider::Usb(p) => p.connect(port),
            AnyProvider::Tcp(p) => p.connect(port),
        }
    }

    fn label(&self) -> &str {
        match self {
            AnyProvider::Usb(p) => p.label(),
            AnyProvider::Tcp(p) => p.label(),
        }
    }

    fn get_pairing_file(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<PairingFile, IdeviceError>> + Send>> {
        match self {
            AnyProvider::Usb(p) => p.get_pairing_file(),
            AnyProvider::Tcp(p) => p.get_pairing_file(),
        }
    }
}

// ---------------------------------------------------------------------------
// Saved network (Wi-Fi) devices.
//
// The device list (name, UDID, version, IP) is stored as JSON in the app data
// directory. The pairing files themselves contain private keys, so they go into
// the same secure storage used for RPPairing records (keychain when available).
// ---------------------------------------------------------------------------

const NETWORK_DEVICE_ID_BASE: u32 = 0x4000_0000;
const NETWORK_DEVICES_FILE: &str = "network_devices.json";
const NETWORK_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct SavedNetworkDevice {
    name: String,
    udid: String,
    version: String,
    address: String,
}

static NETWORK_PAIRINGS: OnceLock<Mutex<HashMap<String, Vec<u8>>>> = OnceLock::new();

fn network_pairings() -> &'static Mutex<HashMap<String, Vec<u8>>> {
    NETWORK_PAIRINGS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn network_pairing_key(udid: &str) -> String {
    format!("network_pairing_{udid}")
}

fn network_devices_path(app: &AppHandle) -> Result<PathBuf, AppError> {
    Ok(app
        .path()
        .app_data_dir()
        .map_err(|e| AppError::Misc(format!("Failed to get app data directory: {e:?}")))?
        .join(NETWORK_DEVICES_FILE))
}

fn load_saved_network_devices(app: &AppHandle) -> Result<Vec<SavedNetworkDevice>, AppError> {
    let path = network_devices_path(app)?;
    if !path.exists() {
        return Ok(vec![]);
    }
    let data = std::fs::read(&path).map_err(|e| {
        AppError::Filesystem("Failed to read saved Wi-Fi devices".into(), e.to_string())
    })?;
    serde_json::from_slice(&data).map_err(|e| {
        AppError::Storage("Saved Wi-Fi devices file is invalid".into(), e.to_string())
    })
}

fn save_network_devices(app: &AppHandle, devices: &[SavedNetworkDevice]) -> Result<(), AppError> {
    let path = network_devices_path(app)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            AppError::Filesystem("Failed to create app data directory".into(), e.to_string())
        })?;
    }
    let data = serde_json::to_vec_pretty(devices)
        .map_err(|e| AppError::Misc(format!("Failed to serialize Wi-Fi devices: {e}")))?;
    std::fs::write(&path, data).map_err(|e| {
        AppError::Filesystem("Failed to save Wi-Fi devices".into(), e.to_string())
    })
}

fn saved_to_info(index: usize, device: &SavedNetworkDevice) -> DeviceInfo {
    DeviceInfo {
        name: device.name.clone(),
        id: NETWORK_DEVICE_ID_BASE + index as u32,
        udid: device.udid.clone(),
        connection_type: "Wi-Fi".to_string(),
        version: device.version.clone(),
        address: Some(device.address.clone()),
    }
}

/// Loads saved Wi-Fi devices and caches their pairing files for `get_provider`.
fn load_network_devices(app: &AppHandle) -> Result<Vec<DeviceInfo>, AppError> {
    let saved = load_saved_network_devices(app)?;
    let mut infos = Vec::with_capacity(saved.len());
    for (index, device) in saved.iter().enumerate() {
        let key = network_pairing_key(&device.udid);
        let pairing = with_pairing_storage(app, |storage| {
            storage.retrieve_data(&key).map_err(|e| {
                AppError::Storage("Failed to read Wi-Fi pairing file".into(), e.to_string())
            })
        })?;
        match pairing {
            Some(pairing) => {
                network_pairings()
                    .lock()
                    .unwrap()
                    .insert(device.udid.clone(), pairing);
                infos.push(saved_to_info(index, device));
            }
            None => warn!(
                "No pairing file stored for Wi-Fi device {} ({}), skipping",
                device.name, device.udid
            ),
        }
    }
    Ok(infos)
}

fn parse_address(address: &str) -> Result<IpAddr, AppError> {
    address
        .trim()
        .parse::<IpAddr>()
        .map_err(|e| AppError::Misc(format!("Invalid IP address \"{}\": {e}", address.trim())))
}

fn tcp_provider(address: &str, pairing: &[u8]) -> Result<TcpProvider, AppError> {
    let pairing_file = PairingFile::from_bytes(pairing).map_err(|e| {
        AppError::LockdownPairing("Invalid pairing file".into(), e.to_string())
    })?;
    Ok(TcpProvider {
        addr: parse_address(address)?,
        scope_id: None,
        pairing_file,
        label: "iloader".to_string(),
    })
}

async fn lockdown_string(lockdown: &mut LockdownClient, key: &str) -> Result<String, AppError> {
    let value = lockdown.get_value(Some(key), None).await.map_err(|e| {
        AppError::DeviceComsWithMessage(format!("Failed to fetch {key}"), e.to_string())
    })?;
    value
        .as_string()
        .map(|s| s.to_string())
        .ok_or_else(|| AppError::DeviceComs(format!("{key} was not a string")))
}

/// Connects to a device over the network with an imported pairing file, verifies the
/// pairing works, and saves it so it shows up in the device list.
#[tauri::command]
pub async fn add_network_device(
    app: AppHandle,
    address: String,
    pairing: Vec<u8>,
) -> Result<DeviceInfo, AppError> {
    let address = address.trim().to_string();
    let provider = tcp_provider(&address, &pairing)?;

    let mut lockdown = tokio::time::timeout(NETWORK_CONNECT_TIMEOUT, LockdownClient::connect(&provider))
        .await
        .map_err(|_| {
            AppError::DeviceComs(
                "Timed out connecting to the device. Check the IP address and that both devices are on the same network. To install on this device, make sure LocalDevVPN (or StosVPN) is connected and use 10.7.0.1.".into(),
            )
        })?
        .map_err(|e| {
            AppError::DeviceComsWithMessage("Unable to connect to lockdown".into(), e.to_string())
        })?;

    lockdown
        .start_session(&provider.pairing_file)
        .await
        .map_err(|e| {
            AppError::LockdownPairing(
                "The device rejected this pairing file".into(),
                e.to_string(),
            )
        })?;

    let name = lockdown_string(&mut lockdown, "DeviceName").await?;
    let version = lockdown_string(&mut lockdown, "ProductVersion").await?;
    let udid = lockdown_string(&mut lockdown, "UniqueDeviceID").await?;

    let key = network_pairing_key(&udid);
    with_pairing_storage(&app, |storage| {
        storage.store_data(&key, &pairing).map_err(|e| {
            AppError::Storage("Failed to store Wi-Fi pairing file".into(), e.to_string())
        })
    })?;

    let mut saved = load_saved_network_devices(&app)?;
    let entry = SavedNetworkDevice {
        name,
        udid: udid.clone(),
        version,
        address,
    };
    let index = match saved.iter().position(|d| d.udid == udid) {
        Some(i) => {
            saved[i] = entry;
            i
        }
        None => {
            saved.push(entry);
            saved.len() - 1
        }
    };
    save_network_devices(&app, &saved)?;

    network_pairings()
        .lock()
        .unwrap()
        .insert(udid, pairing);

    Ok(saved_to_info(index, &saved[index]))
}

#[tauri::command]
pub async fn remove_network_device(app: AppHandle, udid: String) -> Result<(), AppError> {
    let mut saved = load_saved_network_devices(&app)?;
    saved.retain(|d| d.udid != udid);
    save_network_devices(&app, &saved)?;

    let key = network_pairing_key(&udid);
    with_pairing_storage(&app, |storage| {
        storage.delete(&key).map_err(|e| {
            AppError::Storage("Failed to delete Wi-Fi pairing file".into(), e.to_string())
        })
    })?;
    network_pairings().lock().unwrap().remove(&udid);
    Ok(())
}

#[tauri::command]
pub fn is_mobile() -> bool {
    cfg!(any(target_os = "ios", target_os = "android"))
}

// ---------------------------------------------------------------------------
// Device listing & selection
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn list_devices(app: AppHandle) -> Result<Vec<Result<DeviceInfo, AppError>>, AppError> {
    let mut results: Vec<Result<DeviceInfo, AppError>> = Vec::new();

    // usbmuxd is not available to apps on iOS, only Wi-Fi devices can be used there.
    #[cfg(not(target_os = "ios"))]
    let usb_error = match list_usbmuxd_devices().await {
        Ok(mut devices) => {
            results.append(&mut devices);
            None
        }
        Err(e) => Some(e),
    };
    #[cfg(target_os = "ios")]
    let usb_error: Option<AppError> = None;

    match load_network_devices(&app) {
        Ok(devices) => results.extend(devices.into_iter().map(Ok)),
        Err(e) => results.push(Err(e)),
    }

    if let Some(e) = usb_error {
        if results.is_empty() {
            return Err(e);
        }
        results.push(Err(e));
    }

    Ok(results)
}

#[cfg(not(target_os = "ios"))]
async fn list_usbmuxd_devices() -> Result<Vec<Result<DeviceInfo, AppError>>, AppError> {
    let mut usbmuxd = get_usbmuxd().await?;

    let devs = usbmuxd.get_devices().await.map_err(|e| {
        AppError::Usbmuxd("Failed to list devices from usbmuxd".into(), e.to_string())
    })?;
    if devs.is_empty() {
        return Ok(vec![]);
    }

    let usbmuxd_addr = UsbmuxdAddr::from_env_var().map_err(|e| {
        AppError::Usbmuxd(
            "Invalid usbmuxd address from environment".into(),
            e.to_string(),
        )
    })?;

    let device_info_futures: Vec<_> = devs
        .iter()
        .map(|d| {
            let usbmuxd_addr = usbmuxd_addr.clone();
            async move {
                let provider = d.to_provider(usbmuxd_addr, "iloader");
                let device_uid = d.device_id;
                let connection_type = match d.connection_type {
                    Connection::Usb => "USB",
                    Connection::Network(_) => "Network",
                    Connection::Unknown(_) => "Unknown",
                }
                .to_string();

                let mut lockdown_client =
                    LockdownClient::connect(&provider).await.map_err(|e| {
                        eprintln!("Unable to connect to lockdown for {}: {e:?}", d.udid);
                        AppError::DeviceComsWithMessage(
                            "Unable to connect to lockdown".into(),
                            e.to_string(),
                        )
                    })?;

                let device_name = lockdown_string(&mut lockdown_client, "DeviceName").await?;
                let version = lockdown_string(&mut lockdown_client, "ProductVersion").await?;

                Ok::<DeviceInfo, AppError>(DeviceInfo {
                    name: device_name,
                    id: device_uid,
                    udid: d.udid.clone(),
                    connection_type,
                    version,
                    address: None,
                })
            }
        })
        .collect();

    Ok(futures::future::join_all(device_info_futures).await)
}

#[tauri::command]
pub async fn set_selected_device(
    app: AppHandle,
    device_state: State<'_, DeviceInfoMutex>,
    cancel_state: State<'_, PairingCancelToken>,
    device: Option<DeviceInfo>,
) -> Result<(), AppError> {
    let Some(device) = device else {
        let mut device_state = device_state.lock().unwrap();
        *device_state = None;
        return Ok(());
    };

    // Wi-Fi devices already have an imported pairing file, no pairing needed.
    if device.address.is_some() {
        let pairing = network_pairings()
            .lock()
            .unwrap()
            .get(&device.udid)
            .cloned()
            .ok_or_else(|| {
                AppError::LockdownPairing(
                    "No pairing file stored for this device".into(),
                    "Remove the device and add it again".into(),
                )
            })?;
        let mut device_state = device_state.lock().unwrap();
        *device_state = Some(DeviceInfoWithPairing {
            info: device,
            pairing,
        });
        return Ok(());
    }

    let mut usbmuxd = get_usbmuxd().await?;

    let token = tokio_util::sync::CancellationToken::new();
    {
        let mut guard = cancel_state.lock().unwrap();
        if let Some(old) = guard.replace(token.clone()) {
            old.cancel();
        }
    }

    let pairing_result = pairing_file(&app, &device, &mut usbmuxd, token.clone()).await;

    if !token.is_cancelled() {
        let mut guard = cancel_state.lock().unwrap();
        *guard = None;
    }

    let pairing = pairing_result?;

    let device_with_pairing = DeviceInfoWithPairing {
        info: device,
        pairing,
    };
    let mut device_state = device_state.lock().unwrap();
    *device_state = Some(device_with_pairing);
    Ok(())
}

#[tauri::command]
pub async fn cancel_pairing(cancel_state: State<'_, PairingCancelToken>) -> Result<(), AppError> {
    let mut guard = cancel_state.lock().unwrap();
    if let Some(token) = guard.take() {
        token.cancel();
    }
    Ok(())
}

pub async fn get_usbmuxd() -> Result<UsbmuxdConnection, AppError> {
    UsbmuxdConnection::default()
        .await
        .map_err(|e| AppError::Usbmuxd("Failed to connect to usbmuxd".into(), e.to_string()))
}

pub async fn get_provider(device_info: &DeviceInfo) -> Result<AnyProvider, AppError> {
    if let Some(address) = &device_info.address {
        let pairing = network_pairings()
            .lock()
            .unwrap()
            .get(&device_info.udid)
            .cloned()
            .ok_or_else(|| {
                AppError::LockdownPairing(
                    "No pairing file stored for this device".into(),
                    "Remove the device and add it again".into(),
                )
            })?;
        return Ok(AnyProvider::Tcp(tcp_provider(address, &pairing)?));
    }

    #[cfg(target_os = "ios")]
    {
        Err(AppError::DeviceComs(
            "USB devices are not supported on iOS. Add the device over Wi-Fi instead.".into(),
        ))
    }
    #[cfg(not(target_os = "ios"))]
    {
        let mut connection = get_usbmuxd().await?;
        get_provider_from_connection(device_info, &mut connection).await
    }
}

#[cfg(not(target_os = "ios"))]
pub async fn get_provider_from_connection(
    device_info: &DeviceInfo,
    connection: &mut UsbmuxdConnection,
) -> Result<AnyProvider, AppError> {
    let device = connection
        .get_device(&device_info.udid)
        .await
        .map_err(|e| {
            AppError::DeviceComsWithMessage("Failed to get device".into(), e.to_string())
        })?;

    let provider = device.to_provider(UsbmuxdAddr::from_env_var().unwrap(), "iloader");
    Ok(AnyProvider::Usb(provider))
}
