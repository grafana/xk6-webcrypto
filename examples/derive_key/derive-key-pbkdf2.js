import { crypto } from "k6/x/webcrypto";

export default async function () {
  const key = await crypto.subtle.deriveKey();

  console.log(JSON.stringify(key));
}
