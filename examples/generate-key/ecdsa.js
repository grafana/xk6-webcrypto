import { crypto } from "k6/x/webcrypto";

export default function () {
  crypto.subtle
    .generateKey(
      {
        name: "ECDSA",
        namedCurve: "P-384",
      },
      true,
      ["sign", "verify"]
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