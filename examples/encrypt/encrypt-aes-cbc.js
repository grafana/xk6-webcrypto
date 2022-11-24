import { crypto } from "k6/x/webcrypto";

// FIXME: we should make sure that passing a TypedArray as iv works as intended

export default function () {
  const input = string2ArrayBuffer("Hello World");
  const iv = new ArrayBuffer(16);

  crypto.subtle
    .generateKey(
      {
        name: "AES-CBC",
        length: 256,
      },
      true,
      ["encrypt", "decrypt"]
    )
    .then((key) => {
      return crypto.subtle
        .encrypt(
          {
            name: "AES-CBC",
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
