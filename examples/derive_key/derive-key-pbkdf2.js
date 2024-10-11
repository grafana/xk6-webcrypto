import { crypto } from "k6/x/webcrypto";

export default async function() {
  const keyMaterial = {
    type: "secret",
    extractable: true,
    algorithm: { name: "PBKDF2" },
    usages: ["deriveBits", "deriveKey"]
  }
  const key = await crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: new Uint8Array([67, 66, 65]),
      iterations: 100000,
      hash: "SHA-256",
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"],
  )
  console.error(key);
}
