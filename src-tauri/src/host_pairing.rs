//! Device-initiated pairing (iOS 27+), so iloader can pair a device without a computer
//! or a cable.
//!
//! Since iOS 27 a device can start pairing with a host on the local network: the host
//! advertises a `_remotepairing-pairable-host._tcp` Bonjour service, the user taps
//! "Pair with iloader" in Settings → Privacy & Security → Developer Mode and types the
//! PIN iloader shows. This works both for the device iloader runs on and for other
//! devices on the same network.
//!
//! The result is an RPPairing (remote pairing) record. iOS doesn't issue a classic
//! lockdown pairing record over the trusted tunnel (it answers InvalidHostID), so the
//! device is saved with the RPPairing record and reached through a CoreDevice tunnel
//! from then on (rp_tunnel.rs).

use std::{
    net::{IpAddr, Ipv4Addr},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use idevice::{
    IdeviceError,
    remote_pairing::{
        PAIRABLE_HOST_SERVICE_TYPE, PairableHost, PairableHostInfo, RpPairingFile, RpPairingSocket,
    },
};
use serde::Serialize;
use tauri::{AppHandle, Emitter};
use tokio::{net::TcpListener, task::JoinSet};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::{
    device::{DeviceInfo, store_network_device},
    error::AppError,
    rp_tunnel,
};

/// Name shown on the device in Settings ("Pair with iloader").
const HOST_NAME: &str = "iloader";
/// Hardware model advertised to the device. iOS uses it for the icon next to the name;
/// this is the value idevice's reference implementation uses.
const HOST_MODEL: &str = "Mac17,7";
/// LocalDevVPN / StosVPN route this address back to the device itself.
const SELF_ADDRESS: Ipv4Addr = Ipv4Addr::new(10, 7, 0, 1);
/// The device stops offering the pairing after a while, so don't wait forever.
const PAIRING_TIMEOUT: Duration = Duration::from_secs(5 * 60);

const EVENT: &str = "host-pairing";

static CANCEL: Mutex<Option<CancellationToken>> = Mutex::new(None);

#[derive(Serialize, Clone)]
#[serde(tag = "stage", rename_all = "camelCase")]
enum PairingEvent {
    /// Advertising; waiting for the user to start pairing on the device.
    Waiting,
    /// The device asked for a code; show it.
    Pin { pin: String },
    /// Pairing succeeded; now creating the lockdown pairing record.
    Finishing { device: String, this_device: bool },
}

fn emit(app: &AppHandle, event: PairingEvent) {
    if let Err(e) = app.emit(EVENT, event) {
        warn!("Failed to emit host pairing event: {e}");
    }
}

/// Starts advertising iloader as a pairable host and waits for a device to pair.
/// Resolves with the new Wi-Fi device once pairing completes.
#[tauri::command]
pub async fn start_host_pairing(app: AppHandle) -> Result<DeviceInfo, AppError> {
    // The whole pairing flow (listener, pairing, tunnel, RSD, lockdown) makes a very
    // large future. Tauri creates a command's future on the main thread before
    // spawning it, and iOS gives that thread a small stack, so keep the command's
    // own future tiny and put the real work on the heap.
    Box::pin(host_pairing(app)).await
}

async fn host_pairing(app: AppHandle) -> Result<DeviceInfo, AppError> {
    let token = CancellationToken::new();
    if let Some(old) = CANCEL.lock().unwrap().replace(token.clone()) {
        old.cancel();
    }

    info!("host pairing: starting background task");
    let _background = background::Task::begin();
    info!("host pairing: background task started");
    let result = tokio::select! {
        _ = token.cancelled() => Err(AppError::Canceled("Pairing".into())),
        r = tokio::time::timeout(PAIRING_TIMEOUT, run(&app)) => r.unwrap_or_else(|_| {
            Err(AppError::RemotePairing(
                "Pairing timed out. Start again, then tap \"Pair with iloader\" on the device within a few minutes.".into(),
            ))
        }),
    };

    // A newer pairing cancels this token when it replaces it, so only clear ours.
    if !token.is_cancelled() {
        *CANCEL.lock().unwrap() = None;
    }
    result
}

#[tauri::command]
pub fn cancel_host_pairing() {
    if let Some(token) = CANCEL.lock().unwrap().take() {
        token.cancel();
    }
}

/// LiveContainer sets this for the apps it runs.
fn in_livecontainer() -> bool {
    std::env::var_os("LC_HOME_PATH").is_some()
}

async fn run(app: &AppHandle) -> Result<DeviceInfo, AppError> {
    // Inside LiveContainer, iOS checks Local Network services and notifications
    // against LiveContainer's own Info.plist: the pairable-host service isn't listed
    // there, and touching notifications crashes unless LiveContainer's "Fix Local
    // Notification" is on. Stop with an explanation instead.
    if in_livecontainer() {
        return Err(AppError::RemotePairing(
            "Pairing without a computer doesn't work while iloader runs inside LiveContainer, because LiveContainer isn't allowed to advertise the pairing service. Install iloader as a regular app (SideStore, iloader on a computer...) to use it. Importing a pairing file still works here.".into(),
        ));
    }

    info!("host pairing: requesting notification permission");
    notifications::request_permission(app);
    info!("host pairing: opening pairing port");

    let listener = TcpListener::bind((Ipv4Addr::UNSPECIFIED, 0))
        .await
        .map_err(|e| AppError::RemotePairing(format!("Could not open the pairing port: {e}")))?;
    let port = listener
        .local_addr()
        .map_err(|e| AppError::RemotePairing(format!("Could not open the pairing port: {e}")))?
        .port();

    // The device only runs pair-setup with a host it doesn't know yet, so a fresh
    // identity each time is intended. The identifier is derived from the name, so the
    // device replaces its previous record for iloader instead of adding another one.
    info!("host pairing: generating identity (port {port})");
    let pairing_file = RpPairingFile::generate(HOST_NAME);
    let host_info = PairableHostInfo::generate(HOST_NAME, HOST_MODEL);
    let identifier = pairing_file.identifier.clone();
    let txt = host_info.mdns_txt_records(&identifier);
    info!("host pairing: registering Bonjour service {identifier} with {} TXT entries", txt.len());

    let _advertisement = bonjour::register(&identifier, PAIRABLE_HOST_SERVICE_TYPE, port, &txt)?;
    info!("Advertising {PAIRABLE_HOST_SERVICE_TYPE} on port {port}");
    emit(app, PairingEvent::Waiting);

    let paired = wait_for_device(app, listener, pairing_file, host_info).await?;
    drop(_advertisement);

    info!(
        "Paired with {} at {} (this device: {})",
        paired.device_name, paired.peer, paired.this_device
    );
    emit(
        app,
        PairingEvent::Finishing {
            device: paired.device_name.clone(),
            this_device: paired.this_device,
        },
    );

    // The device itself is only reachable through LocalDevVPN's loopback address.
    let address = if paired.this_device {
        IpAddr::V4(SELF_ADDRESS)
    } else {
        paired.peer
    };

    // iOS won't issue a classic lockdown pairing record over the trusted tunnel
    // (InvalidHostID), so keep the RPPairing record and use the tunnel from now on.
    let mut file = paired.file;
    let info = tokio::time::timeout(Duration::from_secs(60), async {
        let mut tunnel = rp_tunnel::open(address, &mut file).await?;
        tunnel.device_info().await
    })
    .await
    .map_err(|_| {
        AppError::RemotePairing(if paired.this_device {
            "Paired, but timed out connecting back to this device. Connect LocalDevVPN (or StosVPN) and try again.".into()
        } else {
            "Paired, but timed out connecting to the device. Make sure it is unlocked and on the same network.".into()
        })
    })??;

    store_network_device(
        app,
        address.to_string(),
        file.to_bytes(),
        info.name,
        info.udid,
        info.version,
        true,
    )
}

struct PairedDevice {
    file: RpPairingFile,
    device_name: String,
    peer: IpAddr,
    this_device: bool,
}

/// Serves every incoming connection at once: anything that connects but is not the
/// device's pairing attempt (or never speaks) must not block the real one.
async fn wait_for_device(
    app: &AppHandle,
    listener: TcpListener,
    pairing_file: RpPairingFile,
    host_info: PairableHostInfo,
) -> Result<PairedDevice, AppError> {
    let pin_shown = Arc::new(AtomicBool::new(false));
    let mut attempts = JoinSet::new();

    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, peer) = accepted.map_err(|e| {
                    AppError::RemotePairing(format!("Could not accept the device's connection: {e}"))
                })?;
                // A connection from one of our own addresses is the device pairing itself.
                let this_device = peer.ip().is_loopback()
                    || stream.local_addr().map(|l| l.ip() == peer.ip()).unwrap_or(false);
                let mut file = pairing_file.clone();
                let info = host_info.clone();
                let app = app.clone();
                let pin_shown = pin_shown.clone();
                attempts.spawn(async move {
                    let mut host = PairableHost::new(RpPairingSocket::new_device(stream), info);
                    let device = host
                        .accept(&mut file, move |pin| {
                            pin_shown.store(true, Ordering::SeqCst);
                            notifications::show_pin(&app, &pin);
                            emit(&app, PairingEvent::Pin { pin });
                            async {}
                        })
                        .await?;
                    Ok::<_, IdeviceError>(PairedDevice {
                        file,
                        device_name: device.name,
                        peer: peer.ip(),
                        this_device,
                    })
                });
            }
            Some(done) = attempts.join_next() => match done {
                Ok(Ok(paired)) => return Ok(paired),
                // Failing before the PIN step means it wasn't the device's pairing attempt.
                _ if !pin_shown.load(Ordering::SeqCst) => continue,
                Ok(Err(e)) => return Err(AppError::RemotePairing(format!("Pairing failed: {e}"))),
                Err(e) => return Err(AppError::RemotePairing(format!("Pairing failed: {e}"))),
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Bonjour advertisement through the system's mDNSResponder (dns_sd), which only needs
// the Local Network permission on iOS (raw multicast would need an extra entitlement).
// ---------------------------------------------------------------------------

#[cfg(any(target_os = "ios", target_os = "macos"))]
mod bonjour {
    use std::ffi::{CString, c_char, c_void};

    use crate::error::AppError;

    type DNSServiceRef = *mut c_void;

    unsafe extern "C" {
        fn DNSServiceRegister(
            sd_ref: *mut DNSServiceRef,
            flags: u32,
            interface_index: u32,
            name: *const c_char,
            regtype: *const c_char,
            domain: *const c_char,
            host: *const c_char,
            port: u16,
            txt_len: u16,
            txt_record: *const c_void,
            callback: Option<unsafe extern "C" fn()>,
            context: *mut c_void,
        ) -> i32;
        fn DNSServiceRefDeallocate(sd_ref: DNSServiceRef);
    }

    /// Keeps the service advertised until dropped.
    pub struct Registration(DNSServiceRef);
    // The ref is only deallocated, never used concurrently.
    unsafe impl Send for Registration {}
    unsafe impl Sync for Registration {}

    impl Drop for Registration {
        fn drop(&mut self) {
            unsafe { DNSServiceRefDeallocate(self.0) };
        }
    }

    fn txt_record(entries: &[(String, String)]) -> Result<Vec<u8>, AppError> {
        let mut out = Vec::new();
        for (key, value) in entries {
            let entry = format!("{key}={value}");
            let len = u8::try_from(entry.len())
                .map_err(|_| AppError::Misc(format!("Bonjour TXT entry too long: {key}")))?;
            out.push(len);
            out.extend_from_slice(entry.as_bytes());
        }
        Ok(out)
    }

    pub fn register(
        name: &str,
        regtype: &str,
        port: u16,
        txt: &[(String, String)],
    ) -> Result<Registration, AppError> {
        // dns_sd wants the type without the trailing dot of the full service name.
        let regtype = regtype.trim_end_matches('.').trim_end_matches(".local");
        let name = CString::new(name).map_err(|e| AppError::Misc(e.to_string()))?;
        let regtype = CString::new(regtype).map_err(|e| AppError::Misc(e.to_string()))?;
        let txt = txt_record(txt)?;
        let txt_len = u16::try_from(txt.len())
            .map_err(|_| AppError::Misc("Bonjour TXT record too long".into()))?;

        let mut sd_ref: DNSServiceRef = std::ptr::null_mut();
        // A NULL callback is allowed: the registration stays active as long as the ref.
        let err = unsafe {
            DNSServiceRegister(
                &mut sd_ref,
                0,
                0,
                name.as_ptr(),
                regtype.as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                port.to_be(),
                txt_len,
                txt.as_ptr() as *const c_void,
                None,
                std::ptr::null_mut(),
            )
        };
        if err != 0 || sd_ref.is_null() {
            return Err(AppError::RemotePairing(format!(
                "Could not advertise iloader on the local network (DNSServiceRegister error {err}). Allow Local Network access for iloader in Settings."
            )));
        }
        Ok(Registration(sd_ref))
    }
}

#[cfg(not(any(target_os = "ios", target_os = "macos")))]
mod bonjour {
    use crate::error::AppError;

    pub struct Registration;

    pub fn register(
        _name: &str,
        _regtype: &str,
        _port: u16,
        _txt: &[(String, String)],
    ) -> Result<Registration, AppError> {
        Err(AppError::Misc(
            "Pairing without a cable is only supported on iOS and macOS. Connect the device over USB instead.".into(),
        ))
    }
}

// ---------------------------------------------------------------------------
// Background time: when pairing the device iloader runs on, the user switches to the
// Settings app while iloader keeps listening. A background task gives it ~30 seconds.
// ---------------------------------------------------------------------------

#[cfg(target_os = "ios")]
mod background {
    use std::ffi::{c_char, c_void};

    type Id = *mut c_void;
    type Sel = *mut c_void;

    unsafe extern "C" {
        fn objc_getClass(name: *const c_char) -> Id;
        fn sel_registerName(name: *const c_char) -> Sel;
        fn objc_msgSend();
    }

    const INVALID: usize = 0; // UIBackgroundTaskInvalid

    unsafe fn shared_application() -> Id {
        unsafe {
            let send: unsafe extern "C" fn(Id, Sel) -> Id =
                std::mem::transmute(objc_msgSend as *const ());
            send(
                objc_getClass(c"UIApplication".as_ptr()),
                sel_registerName(c"sharedApplication".as_ptr()),
            )
        }
    }

    pub struct Task(usize);

    impl Task {
        pub fn begin() -> Task {
            unsafe {
                let app = shared_application();
                if app.is_null() {
                    return Task(INVALID);
                }
                // A nil expiration handler is allowed; iOS ends the task itself on expiry.
                let send: unsafe extern "C" fn(Id, Sel, Id) -> usize =
                    std::mem::transmute(objc_msgSend as *const ());
                Task(send(
                    app,
                    sel_registerName(c"beginBackgroundTaskWithExpirationHandler:".as_ptr()),
                    std::ptr::null_mut(),
                ))
            }
        }
    }

    impl Drop for Task {
        fn drop(&mut self) {
            if self.0 == INVALID {
                return;
            }
            unsafe {
                let app = shared_application();
                if app.is_null() {
                    return;
                }
                let send: unsafe extern "C" fn(Id, Sel, usize) =
                    std::mem::transmute(objc_msgSend as *const ());
                send(app, sel_registerName(c"endBackgroundTask:".as_ptr()), self.0);
            }
        }
    }
}

#[cfg(not(target_os = "ios"))]
mod background {
    pub struct Task;
    impl Task {
        pub fn begin() -> Task {
            Task
        }
    }
}

// ---------------------------------------------------------------------------
// The PIN is also posted as a notification, since the user is in Settings when the
// device asks for it while pairing this device.
// ---------------------------------------------------------------------------

#[cfg(any(target_os = "android", target_os = "ios"))]
mod notifications {
    use tauri::AppHandle;
    use tauri_plugin_notification::NotificationExt;
    use tracing::warn;

    pub fn request_permission(app: &AppHandle) {
        if let Err(e) = app.notification().request_permission() {
            warn!("Failed to request notification permission: {e}");
        }
    }

    pub fn show_pin(app: &AppHandle, pin: &str) {
        if let Err(e) = app
            .notification()
            .builder()
            .title("iloader pairing code")
            .body(pin)
            .show()
        {
            warn!("Failed to show pairing code notification: {e}");
        }
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
mod notifications {
    use tauri::AppHandle;

    pub fn request_permission(_app: &AppHandle) {}
    pub fn show_pin(_app: &AppHandle, _pin: &str) {}
}
