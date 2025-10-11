#!/usr/bin/env node

import {
  genHash,
  genHmac,
  verifyHmac,
  genRsaKey,
  signRsaPss,
  verifyRsaPss,
  genEccKey,
  signEcdsa,
  verifyEcdsa,
} from "./test-apis";
import { Command } from "commander";
import jseu from "js-encoding-utils";
import { getJscu } from "./util/env";

const pgm = new Command();
pgm.version("0.0.1");

pgm
  .command("gen-hash <data>", "")
  .description("Generate hash")
  .option("-h, --hash <hash>", "Name of hash function like 'SHA-256'", "SHA-256")
  .action(async (data, options) => {
    // get Hash
    const hashedData = await genHash(data, options.hash);
    console.log(`<Computed Hash>\n${jseu.encoder.arrayBufferToHexString(hashedData)}\n=======\n`);
  });

pgm
  .command("gen-hex-key <len>", "")
  .description("Generate hex key for HMAC generation")
  .action((len) => {
    const jscu = getJscu();
    const key = jscu.random.getRandomBytes(parseInt(len));
    console.log(`<Generated Hex Key>\n${jseu.encoder.arrayBufferToHexString(key)}\n=======\n`);
  });

pgm
  .command("gen-hmac <data>", "")
  .description("Generate HMAC (key length must be equal to that of hash.)")
  .option("-k, --key <key>", "Hex key of length equal to the hash size")
  .option("-h, --hash <hash>", "Name of hash function like 'SHA-256'", "SHA-256")
  .action(async (data, options) => {
    // get hmac
    const hashedData = await genHmac(data, options.key, options.hash);
    console.log(`<Computed HMAC with ${options.hash}>\n${jseu.encoder.arrayBufferToHexString(hashedData)}\n=======\n`);
  });

pgm
  .command("verify-hmac <data>", "")
  .description("Verify HMAC")
  .option("-k, --key <key>", "Hex key of length equal to the hash size")
  .option("-m, --mac <mac>", "Hex HMAC")
  .option("-h, --hash <hash>", "Name of hash function like 'SHA-256'", "SHA-256")
  .action(async (data, options) => {
    // verify
    const result = await verifyHmac(data, options.key, options.mac, options.hash);
    console.log(`<Verification result of given HMAC>\n${result}\n=======\n`);
  });

pgm
  .command("gen-rsa-key", "")
  .description("Generate RSA key pair")
  .option("-b, --bits <bits>", "Key length in bits", "2048")
  .action(async (options) => {
    // verify
    const result = await genRsaKey(parseInt(options.bits));
    console.log(`<Generated RSA Public Key>\n${result.publicKey}\n`);
    console.log(`<Generated RSA Private Key>\n${result.privateKey}\n=======\n`);
  });

pgm
  .command("sign-rsa-pss <data>", "")
  .description("Sign with RSASSA PSS")
  .option("-h, --hash <hash>", "Name of hash function like 'SHA-256'", "SHA-256")
  .option("-s, --privateKey <privateKey>", "Private key in Hex")
  .action(async (data, options) => {
    const sig = await signRsaPss(data, options.privateKey, options.hash, 32);
    console.log(`<Generated RSASSA-PSS Signature>\n${jseu.encoder.arrayBufferToHexString(sig)}\n=======\n`);
  });

pgm
  .command("verify-rsa-pss <data>", "")
  .description("Verify with RSASSA PSS")
  .option("-h, --hash <hash>", "Name of hash function like 'SHA-256'", "SHA-256")
  .option("-t, --signature <signature>", "Signature in Hex")
  .option("-p, --publicKey <publicKey>", "Public key in Hex")
  .action(async (data, options) => {
    const result = await verifyRsaPss(data, options.signature, options.publicKey, options.hash, 32);
    console.log(`<Verification Result of RSASSA-PSS Signature>\n${result}\n=======\n`);
  });

pgm
  .command("gen-ecc-key", "")
  .description("Generate ECC key pair")
  .option("-c, --curve <curve>", "Curve name like 'P-256'", "P-256")
  .action(async (options) => {
    // verify
    const result = await genEccKey(options.curve);
    console.log(`<Generated ECC Public Key>\n${result.publicKey}\n`);
    console.log(`<Generated ECC Private Key>\n${result.privateKey}\n=======\n`);
  });

pgm
  .command("sign-ecdsa <data>", "")
  .description("Sign with ECDSA")
  .option("-h, --hash <hash>", "Name of hash function like 'SHA-256'", "SHA-256")
  .option("-s, --privateKey <privateKey>", "Private key in Hex")
  .action(async (data, options) => {
    const sig = await signEcdsa(data, options.privateKey, options.hash);
    console.log(`<Generated ECDSA Signature>\n${jseu.encoder.arrayBufferToHexString(sig)}\n=======\n`);
  });

pgm
  .command("verify-ecdsa <data>", "")
  .description("Verify with ECDSA")
  .option("-h, --hash <hash>", "Name of hash function like 'SHA-256'", "SHA-256")
  .option("-t, --signature <signature>", "Signature in Hex")
  .option("-p, --publicKey <publicKey>", "Public key in Hex")
  .action(async (data, options) => {
    const result = await verifyEcdsa(data, options.signature, options.publicKey, options.hash);
    console.log(`<Verification Result of ECDSA Signature>\n${result}\n=======\n`);
  });

pgm.parse(process.argv);
