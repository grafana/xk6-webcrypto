// this example demonstrates how to handle panic in the decrypt function
// we intentionally cut transmittedData from 12 to the end, so it will panic
// the panic will be caught
import { crypto } from "k6/experimental/webcrypto";

export default async function () {
  const keyData = new Uint8Array([
    7, 152, 164, 45, 255, 169, 164, 66, 164, 163, 20, 197, 194, 223, 48, 213,
    93, 115, 173, 86, 215, 81, 128, 188, 45, 237, 156, 92, 163, 197, 248, 114,
  ]);

  const transmittedData = new Uint8Array([
    167, 9, 89, 202, 97, 13, 137, 77, 223, 24, 226, 161, 225, 228, 121, 248,
    181, 4, 25, 202, 215, 230, 193, 94, 143, 77, 187, 231, 84, 3, 198, 75, 22,
    211, 83, 101, 241, 159, 117, 124, 155, 229, 244, 173, 58, 149, 57, 18,
  ]);

  const iv = new Uint8Array(transmittedData.slice(0, 16));

  // we intentionally cut incorrectly transmittedData from 12 to the end
  const encryptedData = new Uint8Array(transmittedData.slice(12));

  const importedKey = await crypto.subtle.importKey(
    "raw",
    keyData,
    { name: "AES-CBC", length: "256" },
    true,
    ["encrypt", "decrypt"]
  );

  // if we pass such transmittedData to decrypt function, it will panic
  await crypto.subtle.decrypt(
    {
      name: "AES-CBC",
      iv: iv,
    },
    importedKey,
    encryptedData
  );
}