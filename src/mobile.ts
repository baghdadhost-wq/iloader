import { invoke } from "@tauri-apps/api/core";

let mobile = false;

/**
 * Resolves once the backend has reported whether this is a mobile (iOS/Android) build.
 * Started at import time so `isMobile()` can be read synchronously inside click
 * handlers; iOS only opens a file picker from a synchronous user gesture.
 */
export const mobileReady: Promise<boolean> = invoke<boolean>("is_mobile")
  .then((value) => {
    mobile = value;
    return value;
  })
  .catch(() => false);

export const isMobile = () => mobile;

/**
 * Opens the system file picker through a hidden <input type="file">.
 * Must be called synchronously from a click handler.
 * No `accept` filter by default: iOS greys out file types it doesn't know (like .ipa).
 */
export function pickFile(accept?: string): Promise<File | null> {
  return new Promise((resolve) => {
    const input = document.createElement("input");
    input.type = "file";
    if (accept) input.accept = accept;
    input.style.display = "none";

    let settled = false;
    const finish = (file: File | null) => {
      if (settled) return;
      settled = true;
      input.remove();
      resolve(file);
    };

    input.addEventListener("change", () => finish(input.files?.[0] ?? null));
    input.addEventListener("cancel", () => finish(null));

    document.body.appendChild(input);
    input.click();
  });
}

/** Sends a picked file to the backend, which writes it to a temp file and returns its path. */
export async function uploadFile(file: File): Promise<string> {
  const bytes = new Uint8Array(await file.arrayBuffer());
  return invoke<string>("upload_file", bytes, {
    headers: { "x-file-name": encodeURIComponent(file.name) },
  });
}

export async function readFileBytes(file: File): Promise<number[]> {
  return Array.from(new Uint8Array(await file.arrayBuffer()));
}
