import { crypto } from "k6/x/webcrypto";

export default function () {
  const input = string2ArrayBuffer("Hello World");
  const counter = new ArrayBuffer(16);

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
      const ab = string2ArrayBuffer("Hello World!");

      return crypto.subtle
        .encrypt(
          {
            name: "AES-CTR",
            counter: counter,
            length: 64,
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
