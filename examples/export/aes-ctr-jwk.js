import { crypto } from "k6/x/webcrypto";

export default function () {
  crypto.subtle
    .generateKey(
      {
        name: "AES-CTR",
        length: 256,
      },
      true,
      ["encrypt", "decrypt"]
    )
    .then((key) => {
      return crypto.subtle.exportKey("jwk", key).then((exported) => {
        console.log(`exported key in jwk format: ${JSON.stringify(exported)}`);
      });
    });
}
