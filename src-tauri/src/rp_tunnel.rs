//! Connections to devices through an RPPairing (remote pairing) record.
//!
//! Devices paired without a computer (host_pairing.rs) only have an RPPairing record:
//! iOS refuses to issue a classic lockdown pairing record over the trusted tunnel
//! (InvalidHostID). Everything iloader needs from them goes through a CoreDevice tunnel
//! instead: pair-verify with the record, open a TLS-PSK tunnel, then reach services
//! (lockdown, installation_proxy, afc, house_arrest) through RemoteServiceDiscovery.

use std::{net::IpAddr, time::Duration};

use idevice::{
    IdeviceError, RsdService,
    lockdown::LockdownClient,
    remote_pairing::{
        RemotePairingClient, RpPairingFile, RpPairingSocket, connect_tls_psk_tunnel_native,
    },
    rsd::RsdHandshake,
    tcp::{adapter::Adapter, handle::AdapterHandle},
};
use tokio::net::TcpStream;

use crate::{device::lockdown_string, error::AppError};

/// Port of the device's remote pairing service (also reached through LocalDevVPN's
/// 10.7.0.1 for the device iloader runs on).
pub const REMOTE_PAIRING_PORT: u16 = 49152;
pub const HOST_NAME: &str = "iloader";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

fn rp_err(context: &'static str) -> impl Fn(IdeviceError) -> AppError {
    move |e| AppError::RemotePairing(format!("{context}: {e}"))
}

pub struct RpTunnel {
    pub adapter: AdapterHandle,
    pub handshake: RsdHandshake,
}

pub struct RpDeviceInfo {
    pub name: String,
    pub udid: String,
    pub version: String,
}

/// Opens a tunnel to the device at `address` with `file`. `file` may be updated by the
/// verification, so persist it afterwards when it was just created.
pub async fn open(address: IpAddr, file: &mut RpPairingFile) -> Result<RpTunnel, AppError> {
    let stream = tokio::time::timeout(
        CONNECT_TIMEOUT,
        TcpStream::connect((address, REMOTE_PAIRING_PORT)),
    )
    .await
    .map_err(|_| {
        AppError::RemotePairing(format!(
            "Timed out connecting to {address}. Make sure the device is unlocked and on the same network (for this device, connect LocalDevVPN)."
        ))
    })?
    .map_err(|e| AppError::RemotePairing(format!("Could not reach the device at {address}: {e}")))?;

    let mut client = RemotePairingClient::new(RpPairingSocket::new(stream), HOST_NAME);
    // Verify only: `connect` would fall back to a new pairing and wait for a PIN.
    client
        .attempt_pair_verify()
        .await
        .map_err(rp_err("The device refused the pairing"))?;
    client.validate_pairing(file).await.map_err(rp_err(
        "The device no longer accepts this pairing. Remove the device and pair it again",
    ))?;

    let tunnel_port = client
        .create_tcp_listener()
        .await
        .map_err(rp_err("Could not open a tunnel"))?;
    let stream = TcpStream::connect((address, tunnel_port))
        .await
        .map_err(|e| AppError::RemotePairing(format!("Could not open a tunnel: {e}")))?;
    let tunnel = connect_tls_psk_tunnel_native(stream, client.encryption_key())
        .await
        .map_err(rp_err("Could not open a tunnel"))?;

    let parse = |a: &str| {
        a.parse::<IpAddr>().map_err(|e| {
            AppError::RemotePairing(format!("The tunnel returned an invalid address: {e}"))
        })
    };
    let ours = parse(&tunnel.info.client_address)?;
    let theirs = parse(&tunnel.info.server_address)?;
    let mtu = tunnel.info.mtu as usize;
    let rsd_port = tunnel.info.server_rsd_port;
    let mut adapter = Adapter::new(Box::new(tunnel.into_inner()), ours, theirs);
    adapter.set_mss(mtu.min(8192).saturating_sub(60));
    let mut adapter = adapter.to_async_handle();

    let rsd_stream = adapter.connect(rsd_port).await.map_err(|e| {
        AppError::RemotePairing(format!("Could not reach the device's services: {e}"))
    })?;
    let handshake = RsdHandshake::new(rsd_stream)
        .await
        .map_err(rp_err("Could not reach the device's services"))?;

    Ok(RpTunnel { adapter, handshake })
}

pub async fn open_from_bytes(address: IpAddr, pairing: &[u8]) -> Result<RpTunnel, AppError> {
    let mut file = RpPairingFile::from_bytes(pairing)
        .map_err(rp_err("The stored pairing file is invalid"))?;
    open(address, &mut file).await
}

impl RpTunnel {
    pub async fn device_info(&mut self) -> Result<RpDeviceInfo, AppError> {
        let mut lockdown = LockdownClient::connect_rsd(&mut self.adapter, &mut self.handshake)
            .await
            .map_err(rp_err("Could not connect to lockdown"))?;
        Ok(RpDeviceInfo {
            name: lockdown_string(&mut lockdown, "DeviceName").await?,
            udid: lockdown_string(&mut lockdown, "UniqueDeviceID").await?,
            version: lockdown_string(&mut lockdown, "ProductVersion").await?,
        })
    }
}
