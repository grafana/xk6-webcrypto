import { crypto } from "k6/x/webcrypto";

export default function () {
  crypto.subtle
    .generateKey(
      {
        name: "RSA-OAEP",
        modulusLength: 4096,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256",
      },
      true,
      ["encrypt", "decrypt"]
    )
    .then(
      (key) => {
        console.log(JSON.stringify(key));
      },
      (err) => {
        console.log(JSON.stringify(err));
      }
    );
}
