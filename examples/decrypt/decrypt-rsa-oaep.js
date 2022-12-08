import { crypto } from "k6/x/webcrypto";

// FIXME: we should make sure that passing a TypedArray as iv works as intended

export default function () {
  const input = string2ArrayBuffer("Hello World");

  crypto.subtle
    .generateKey(
      {
        name: "RSA-OAEP",
        modulusLength: 4096,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        hash: "SHA-256",
      },
      true,
      ["encrypt", "decrypt"]
    )
    .then((key) => {
      return crypto.subtle
        .encrypt(
          {
            name: "RSA-OAEP",
          },
          key,
          input
        )
        .then((encrypted) => {
          console.log(`script encrypted bytes: ${arrayBuffer2Hex(encrypted)}`);
          return crypto.subtle.decrypt(
            {
              name: "RSA-OAEP",
            },
            key,
            encrypted
          );
        });
    })
    .then((decrypted) => {
      console.log(`script decrypted bytes: ${arrayBuffer2Hex(decrypted)}`);
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
