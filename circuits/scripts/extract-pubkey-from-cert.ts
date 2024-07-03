import fs from 'fs';
import path from 'path';
import { subtle } from "crypto";
import { Certificate } from 'pkijs';
import { stringToArrayBuffer } from 'pvutils';
import { fromBER } from "asn1js";

// Will return the certificate public key
async function getPublicKey() {
    const importedPem = fs
      .readFileSync(path.join(__dirname, "..", "assets", "testCertificate.pem"))
      .toString();
    const der = pemToDer(importedPem);
    const asn1 = fromBER(der);
    const certificate = new Certificate({ schema: asn1.result });
  
    const publicKey = await subtle.importKey(
      "spki",
      certificate.subjectPublicKeyInfo.toSchema().toBER(false),
      { name: "RSASSA-PKCS1-v1_5", hash: { name: "SHA-256" } },
      true,
      ["verify"]
    );

    console.log(publicKey)
  
    return publicKey;
  }

async function main() {
    getPublicKey()
}

main()

export function pemToDer(pem: string) {
    const pemHeader = "-----BEGIN CERTIFICATE-----";
    const pemFooter = "-----END CERTIFICATE-----";
    const pemContents = pem
      .replace(pemHeader, "")
      .replace(pemFooter, "")
      .replace(/\s/g, ""); // Remove newlines and spaces
  
    const binaryDer = Buffer.from(pemContents, "base64");
    return stringToArrayBuffer(binaryDer.toString("binary"));
}
