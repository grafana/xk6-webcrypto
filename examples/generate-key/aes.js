import { crypto } from "k6/x/webcrypto";

export default function () {
  crypto.subtle
    .generateKey({ name: "AES-GCM", length: "256" }, true, [
      "encrypt",
      "decrypt",
    ])
    .then((key) => {
      console.log(JSON.stringify(key));
    });
}
