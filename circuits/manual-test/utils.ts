import path from "path";
import assert from "assert";

import forge from "node-forge";
import {
  bufferToHex,
  Uint8ArrayToCharArray,
} from "@zk-email/helpers/dist/binary-format";
import { sha256Pad } from "@zk-email/helpers/dist/sha-utils";
// @ts-ignore
import circom_tester from "circom_tester/wasm/tester";

import { splitToWords } from "../test/util";

const DEFAULT_ASSETS_DIR = path.join(__dirname, "..", "assets");
const DEFAULT_CIRCUIT_DIR = path.join(__dirname, "..", "src");
const DEFAULT_CIRCUIT_BUILD_DIR = path.join(__dirname, "..", "build");
const NODE_MODULES_PATH = path.join(__dirname, "..", "node_modules");

export async function getCircuit(
  name: string,
  circuitDirectory = DEFAULT_CIRCUIT_DIR,
  circuitBuildDirectory = DEFAULT_CIRCUIT_BUILD_DIR
) {
  const pathToCircuit = path.join(circuitDirectory, `${name}.circom`);

  const circuit = await circom_tester(pathToCircuit, {
    recompile: false,
    output: circuitBuildDirectory,
    include: [NODE_MODULES_PATH],
  });

  return circuit;
}

export function generateTestData(
  dataToSign: string,
  savePemFiles = false,
  assetsDirectory = DEFAULT_ASSETS_DIR
) {
  const keys = generateKeyPair();
  const cert = createSelfSignedCertificate(keys);

  const md = forge.md.sha256.create();
  md.update(dataToSign, "utf8");
  const signature = keys.privateKey.sign(md);

  const verify = keys.publicKey.verify(md.digest().bytes(), signature);
  assert(verify, "Signature verification failed");

  const pems = {
    privateKey: forge.pki.privateKeyToPem(keys.privateKey),
    publicKey: forge.pki.publicKeyToPem(keys.publicKey),
    certificate: forge.pki.certificateToPem(cert),
  };

  if (savePemFiles) {
    fs.writeFileSync(
      path.join(assetsDirectory, "testPrivateKey.pem"),
      pems.privateKey
    );
    fs.writeFileSync(
      path.join(assetsDirectory, "testPublicKey.pem"),
      pems.publicKey
    );
    fs.writeFileSync(
      path.join(assetsDirectory, "testCertificate.pem"),
      pems.certificate
    );
  }

  const [SODDataPadded, SODDataPaddedLen] = sha256Pad(
    new Uint8Array(Buffer.from(dataToSign, "utf-8")),
    512
  );
  const SODSignedDataPadded = Uint8ArrayToCharArray(SODDataPadded);
  const SODSignedDataPaddedLength = SODDataPaddedLen;
  const SODSignature = splitToWords(
    BigInt("0x" + bufferToHex(Buffer.from(signature, "binary")).toString()),
    BigInt(121),
    BigInt(17)
  );
  const CSCApublicKey = BigInt(keys.publicKey.n.toString());
  const CSCApubKey = splitToWords(CSCApublicKey, BigInt(121), BigInt(34)).slice(
    0,
    17
  );
  const dsPublicKey = CSCApubKey;

  return {
    ...keys,
    dataToSign,
    signature,
    pems,
    inputs: {
      SODSignedDataPadded,
      SODSignedDataPaddedLength,
      SODSignature,
      dsPublicKey,
    },
  };
}

function generateKeyPair() {
  // Generate an RSA key pair
  const keys = forge.pki.rsa.generateKeyPair(2048);
  return keys;
}

function createSelfSignedCertificate(keys: forge.pki.rsa.KeyPair) {
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = "01";
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1); // 1 year validity

  const attrs = [
    {
      name: "commonName",
      value: "example.org",
    },
    {
      name: "countryName",
      value: "US",
    },
    {
      shortName: "ST",
      value: "Virginia",
    },
    {
      name: "localityName",
      value: "Blacksburg",
    },
    {
      name: "organizationName",
      value: "Test",
    },
    {
      shortName: "OU",
      value: "Test",
    },
  ];

  cert.setSubject(attrs);
  cert.setIssuer(attrs); // Self-signed, so issuer is the same

  // Apply extensions
  cert.setExtensions([
    {
      name: "basicConstraints",
      cA: true,
    },
    {
      name: "keyUsage",
      keyCertSign: true,
      digitalSignature: true,
      nonRepudiation: true,
      keyEncipherment: true,
      dataEncipherment: true,
    },
    {
      name: "extKeyUsage",
      serverAuth: true,
      clientAuth: true,
      codeSigning: true,
      emailProtection: true,
      timeStamping: true,
    },
    {
      name: "nsCertType",
      client: true,
      server: true,
      email: true,
      objsign: true,
      sslCA: true,
      emailCA: true,
      objCA: true,
    },
    {
      name: "subjectAltName",
      altNames: [
        {
          type: 6, // URI
          value: "http://example.org/webid#me",
        },
        {
          type: 7, // IP
          ip: "127.0.0.1",
        },
      ],
    },
  ]);

  // Self-sign certificate
  cert.sign(keys.privateKey, forge.md.sha256.create());

  return cert;
}
