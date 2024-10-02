import { crypto } from "k6/x/webcrypto";

export default async function() {
  const keyMaterial = crypto.subtle.importKey(
    "raw",
    new Uint8Array([65, 66, 67]),
    "PBKDF2",
    false,
    ["deriveBits", "deriveKey"],
  );
  const key = await crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt,
      iterations: 100000,
      hash: "SHA-256",
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"],
  )
  console.log(JSON.stringify(key));
}
