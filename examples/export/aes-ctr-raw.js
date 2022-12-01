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
      return crypto.subtle.exportKey("raw", key).then((exported) => {
        console.log(`exported key hex: ${arrayBuffer2Hex(exported)}`);
      });
    });
}

function arrayBuffer2Hex(buffer) {
  return [...new Uint8Array(buffer)]
    .map((x) => x.toString(16).padStart(2, "0"))
    .join("");
}
