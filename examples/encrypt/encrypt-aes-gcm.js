import { crypto } from "k6/x/webcrypto";

export default function () {
  const input = string2ArrayBuffer("Hello World");
  const iv = new ArrayBuffer(12);

  crypto.subtle
    .generateKey(
      {
        name: "AES-GCM",
        length: 256,
      },
      true,
      ["encrypt", "decrypt"]
    )
    .then((key) => {
      return crypto.subtle
        .encrypt(
          {
            name: "AES-GCM",
            iv: iv,
          },
          key,
          input
        )
        .then((encrypted) => {
          console.log(`script encrypted bytes: ${arrayBuffer2Hex(encrypted)}`);
        });
    });
}

function arrayBuffer2Hex(buffer) {
  return [...new Uint8Array(buffer)]
    .map((x) => x.toString(16).padStart(2, "0"))
    .join("");
}

function string2ArrayBuffer(str) {
  var buf = new ArrayBuffer(str.length * 2); // 2 bytes for each char
  var bufView = new Uint16Array(buf);
  for (var i = 0, strLen = str.length; i < strLen; i++) {
    bufView[i] = str.charCodeAt(i);
  }
  return buf;
}
