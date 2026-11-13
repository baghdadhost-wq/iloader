import { useCallback, useEffect, useRef, useState } from "react";
import "./Device.css";
import { invoke } from "@tauri-apps/api/core";
import { toast } from "sonner";
import { useTranslation } from "react-i18next";
import { Modal } from "./components/Modal";
import { useError } from "./ErrorContext";
import { AppError } from "./errors";
import { isMobile, pickFile, readFileBytes } from "./mobile";

// Address LocalDevVPN / StosVPN route back to the device itself.
const SELF_DEVICE_ADDRESS = "10.7.0.1";

export type DeviceInfo = {
  name: string;
  id: number;
  udid: string;
  connectionType: "USB" | "Network" | "Wi-Fi" | "Unknown";
  version: string;
  /** Set for devices added over Wi-Fi with an imported pairing file. */
  address?: string;
};

export const Device = ({
  selectedDevice,
  setSelectedDevice,
  registerRefresh,
}: {
  selectedDevice: DeviceInfo | null;
  setSelectedDevice: (device: DeviceInfo | null) => void;
  registerRefresh?: (fn?: () => void) => void;
}) => {
  const { t } = useTranslation();
  const [devices, setDevices] = useState<DeviceInfo[]>([]);
  const [waitingToPair, setWaitingToPair] = useState<DeviceInfo | null>(null);
  const [showPairingModal, setShowPairingModal] = useState(false);
  const [showAddWifi, setShowAddWifi] = useState(false);
  const [wifiAddress, setWifiAddress] = useState("");
  const [wifiPairing, setWifiPairing] = useState<File | null>(null);
  const [addingWifi, setAddingWifi] = useState(false);

  const listingDevices = useRef<boolean>(false);
  const pairingRequestId = useRef<number>(0);
  const pairingModalTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const { err } = useError();

  const clearPairingModalTimer = useCallback(() => {
    if (pairingModalTimer.current) {
      clearTimeout(pairingModalTimer.current);
      pairingModalTimer.current = null;
    }
  }, []);

  useEffect(() => {
    return () => {
      clearPairingModalTimer();
    };
  }, [clearPairingModalTimer]);

  const selectDevice = useCallback(
    (device: DeviceInfo | null) => {
      const requestId = ++pairingRequestId.current;
      clearPairingModalTimer();
      setShowPairingModal(false);
      setWaitingToPair(device);

      if (device) {
        pairingModalTimer.current = setTimeout(() => {
          if (pairingRequestId.current === requestId) {
            setShowPairingModal(true);
          }
        }, 100);
      }

      invoke("set_selected_device", { device })
        .then(() => {
          if (pairingRequestId.current !== requestId) {
            return;
          }
          clearPairingModalTimer();
          setShowPairingModal(false);
          setWaitingToPair(null);
          setSelectedDevice(device);
        })
        .catch((e) => {
          if (pairingRequestId.current !== requestId) {
            return;
          }

          const message = String((e.message ?? e) ?? "Unknown error");
          if (message !== "Pairing cancelled") {
            toast.error(err(t("device.failed_select"), e));
          }
          clearPairingModalTimer();
          setShowPairingModal(false);
          setWaitingToPair(null);
        });
    },
    [clearPairingModalTimer, setSelectedDevice, t],
  );

  const loadDevices = useCallback(async () => {
    if (listingDevices.current) return;
    const promise = new Promise<number>(async (resolve, reject) => {
      listingDevices.current = true;
      try {
        const results = await invoke<
          Array<{ Ok: DeviceInfo } | { Err: AppError }>
        >("list_devices");

        const devices: DeviceInfo[] = [];
        for (const result of results) {
          if ("Ok" in result) {
            devices.push(result.Ok);
          } else if ("Err" in result) {
            toast.error(err(t("device.unable_load_devices_prefix"), result.Err));
          }
        }

        setDevices(devices);
        if (selectedDevice) {
          const stillAvailable = devices.find(
            (d) => d.id === selectedDevice.id,
          );
          if (!stillAvailable) {
            selectDevice(null);
          }
        }
        if (devices.length > 0) {
          const devicesWithPairing = await Promise.all(
            devices.map(async (device) => {
              const hasPairing = await invoke<boolean>("has_stored_rppairing", {
                device,
              });
              return hasPairing ? device : null;
            }),
          )
            .catch(() => [])
            .then((results) =>
              results.filter((d): d is DeviceInfo => d !== null),
            );
          if (devicesWithPairing.length > 0) {
            selectDevice(devicesWithPairing[0]);
          }
        }
        listingDevices.current = false;
        resolve(devices.length);
      } catch (e) {
        setDevices([]);
        selectDevice(null);
        listingDevices.current = false;
        reject(e);
      }
    });

    toast.promise(promise, {
      loading: t("device.loading_devices"),
      success: (count) => {
        if (count === 0) {
          return t("device.no_devices_found");
        }
        return count > 1 ? t("device.found_devices") : t("device.found_device");
      },
      error: (e) => err(t("device.unable_load_devices_prefix"), e),
    });
  }, [setDevices, selectDevice, t]);
  useEffect(() => {
    loadDevices();
  }, [loadDevices]);

  useEffect(() => {
    registerRefresh?.(loadDevices);
    return () => registerRefresh?.(undefined);
  }, [registerRefresh, loadDevices]);

  const openAddWifi = useCallback(() => {
    setWifiAddress(isMobile() ? SELF_DEVICE_ADDRESS : "");
    setWifiPairing(null);
    setShowAddWifi(true);
  }, []);

  const addWifiDevice = useCallback(async () => {
    if (!wifiAddress.trim() || !wifiPairing) return;
    setAddingWifi(true);
    const promise = (async () => {
      const pairing = await readFileBytes(wifiPairing);
      return invoke<DeviceInfo>("add_network_device", {
        address: wifiAddress.trim(),
        pairing,
      });
    })();
    toast.promise(promise, {
      loading: t("device.wifi_adding"),
      success: (device) => t("device.wifi_added", { device: device.name }),
      error: (e) => err(t("device.wifi_failed_add"), e),
    });
    try {
      const device = await promise;
      setShowAddWifi(false);
      // Update the list in place: a full reload would auto-select the first device.
      setDevices((prev) => [
        ...prev.filter((d) => d.udid !== device.udid),
        device,
      ]);
      selectDevice(device);
    } catch {
      // error shown by the toast
    } finally {
      setAddingWifi(false);
    }
  }, [wifiAddress, wifiPairing, t, err, selectDevice]);

  const removeWifiDevice = useCallback(
    async (device: DeviceInfo) => {
      try {
        await invoke("remove_network_device", { udid: device.udid });
        if (selectedDevice?.udid === device.udid) {
          selectDevice(null);
        }
        toast.success(t("device.wifi_removed", { device: device.name }));
        loadDevices();
      } catch (e) {
        toast.error(err(t("device.wifi_failed_remove"), e as AppError));
      }
    },
    [selectedDevice, selectDevice, loadDevices, t, err],
  );

  return (
    <>
      <Modal
        isOpen={showPairingModal && waitingToPair !== null}
        close={() => {
          pairingRequestId.current += 1;
          clearPairingModalTimer();
          setShowPairingModal(false);
          invoke("cancel_pairing").catch(() => { });
          setWaitingToPair(null);
        }}
      >
        <div className="pairing-modal-content">
          <div className="spinner" />
          <h2>
            {t("device.pairing_in_progress_header", {
              device: waitingToPair?.name ?? "Unknown Device",
            })}
          </h2>
          <p>{t("device.pairing_in_progress_hint")}</p>
          <button
            onClick={async () => {
              pairingRequestId.current += 1;
              clearPairingModalTimer();
              setShowPairingModal(false);
              await invoke("cancel_pairing");
              setWaitingToPair(null);
            }}
          >
            {t("device.pairing_cancel")}
          </button>
        </div>
      </Modal>
      <Modal
        isOpen={showAddWifi}
        close={() => {
          if (!addingWifi) setShowAddWifi(false);
        }}
      >
        <div className="wifi-modal-content">
          <h2>{t("device.wifi_add_title")}</h2>
          <p className="wifi-hint">{t("device.wifi_hint")}</p>
          <label className="wifi-field">
            <span>{t("device.wifi_ip_address")}</span>
            <input
              type="text"
              inputMode="decimal"
              autoCapitalize="off"
              autoCorrect="off"
              placeholder="192.168.1.20"
              value={wifiAddress}
              onChange={(e) => setWifiAddress(e.target.value)}
              disabled={addingWifi}
            />
          </label>
          <button
            className="wifi-secondary"
            onClick={() => setWifiAddress(SELF_DEVICE_ADDRESS)}
            disabled={addingWifi}
          >
            {t("device.wifi_this_device")}
          </button>
          <p className="wifi-hint">{t("device.wifi_this_device_hint")}</p>
          <button
            className="wifi-secondary"
            onClick={async () => {
              const file = await pickFile();
              if (file) setWifiPairing(file);
            }}
            disabled={addingWifi}
          >
            {wifiPairing
              ? t("device.wifi_pairing_selected", { file: wifiPairing.name })
              : t("device.wifi_choose_pairing")}
          </button>
          <button
            onClick={addWifiDevice}
            disabled={addingWifi || !wifiAddress.trim() || !wifiPairing}
          >
            {t("device.wifi_add")}
          </button>
        </div>
      </Modal>
      <h2 style={{ marginTop: 0 }}>{t("device.title")}</h2>
      <div className="credentials-container">
        {devices.length === 0 && (
          <div>{t("device.no_devices_found_period")}</div>
        )}
        {devices.map((device) => {
          const isActive = selectedDevice?.id === device.id;
          return (
            <div className="device-row" key={device.id}>
            <button
              className={"device-card card" + (isActive ? " active" : "")}
              onClick={() => selectDevice(device)}
              disabled={waitingToPair !== null}
            >
              <div className="device-meta">
                <span className="device-name">{device.name}</span>
                <span className="device-connection">
                  {device.address
                    ? `${device.connectionType} · ${device.address}`
                    : device.connectionType}
                </span>
              </div>
              {isActive && (
                <span className="device-selected-pill">
                  {t("device.selected")}
                </span>
              )}
            </button>
            {device.address && (
              <button
                className="device-remove"
                title={t("device.wifi_remove")}
                aria-label={t("device.wifi_remove")}
                onClick={() => removeWifiDevice(device)}
                disabled={waitingToPair !== null}
              >
                ✕
              </button>
            )}
            </div>
          );
        })}
        <button disabled={waitingToPair !== null} onClick={loadDevices}>
          {t("common.refresh")}
        </button>
        <button disabled={waitingToPair !== null} onClick={openAddWifi}>
          {t("device.wifi_add_button")}
        </button>
      </div>
    </>
  );
};
