import { crypto } from "k6/x/webcrypto";

export default function () {
  const promise = crypto.subtle
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
    .then((key) => {
      const ab = string2ArrayBuffer("Hello World!");

      return crypto.subtle.encrypt(
        {
          name: "RSA-OAEP",
        },
        key.publicKey,
        ab
      );
    })
    .then((encrypted) => {
      console.log(`Hello world encrypted: ${arrayBuffer2Hex(encrypted)}`);
    });
}

function arrayBuffer2Hex(buffer) {
  return [...new Uint8Array(buffer)]
    .map((x) => x.toString(16).padStart(2, "0"))
    .join("");
}

function arrayBuffer2String(buf) {
  return String.fromCharCode.apply(null, new Uint16Array(buf));
}

function string2ArrayBuffer(str) {
  var buf = new ArrayBuffer(str.length * 2); // 2 bytes for each char
  var bufView = new Uint16Array(buf);
  for (var i = 0, strLen = str.length; i < strLen; i++) {
    bufView[i] = str.charCodeAt(i);
  }
  return buf;
}
