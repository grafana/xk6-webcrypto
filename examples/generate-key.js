import { crypto } from "k6/x/webcrypto";

export default function () {
  crypto.subtle
    .generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
      "sign",
      "verify",
    ])
    .then((key) => {
      console.log(JSON.stringify(key));
    });
}
