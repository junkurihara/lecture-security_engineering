#!/usr/bin/env node

import { ecdh, ecKeyGen, rsaKeyGen, rsaOaepDecrypt, rsaOaepEncrypt } from "./test-apis";
import pgm from "commander";
import jseu from "js-encoding-utils";
import msgpack from "msgpack-lite";
import { deriveKeyFromMasterSecret } from "./derive-key";
import { decryptAES, encryptAES } from "./encryptAES";

pgm.version("0.0.1");

pgm
  .command("check-ecdh", "")
  .description("Generate ECC key pair and check the consistency of ECDH derived bits")
  .action(async () => {
    // Generate key pairs
    const keyPairA = await ecKeyGen();
    const keyPairB = await ecKeyGen();

    console.log(
      `<ECC Key Pair A (DER Form)>\nPublic Key:\n${keyPairA.publicKey}\n\nPrivate Key:\n${keyPairA.privateKey}\n=======\n`
    );
    console.log(
      `<ECC Key Pair B (DER Form)>\nPublic Key:\n${keyPairB.publicKey}\n\nPrivate Key:\n${keyPairB.privateKey}\n=======\n`
    );

    // Execute ECDH at each end.
    const sharedAB = await ecdh(keyPairA.publicKey, keyPairB.privateKey);
    const sharedBA = await ecdh(keyPairB.publicKey, keyPairA.privateKey);

    console.log(`Shared Bits from Public Key A and Private Key B: ${sharedAB}`);
    console.log(`Shared Bits from Public Key B and Private Key A: ${sharedBA}`);
  });

pgm
  .command("rsa-oaep-demo <data>", "")
  .description("Execute RSAES-OAEP encryption and decryption demo with RSA key generation")
  .action(async (data) => {
    console.log(`<Input Data>\n${data}`);

    // GenerateKey Pair
    const rsaKeyPair = await rsaKeyGen();
    console.log(
      `<Generated RSA Key Pair (DER Form)>\nPublic Key:\n${rsaKeyPair.publicKey}\n\nPrivate Key:\n${rsaKeyPair.privateKey}\n=======\n`
    );

    // Encrypt
    const encryptedString = await rsaOaepEncrypt(data, rsaKeyPair.publicKey);
    console.log(`<Encrypted Data (in Base64)>\n${encryptedString}\n=======\n`);

    // Decrypt
    const decrypted = await rsaOaepDecrypt(encryptedString, rsaKeyPair.privateKey);
    console.log(`<Decrypted Data>\n${decrypted}\n=======\n`);
  });

pgm
  .command("rsa-keygen", "")
  .description("Generate RSA Key")
  .option("-b, --bits <bits>", "Modulus length like 2048", 2048)
  .action(async (options) => {
    const rsaKeyPair = await rsaKeyGen(options.bits);
    console.log(
      `<Generated RSA Key Pair (DER Form)>\nPublic Key:\n${rsaKeyPair.publicKey}\n\nPrivate Key:\n${rsaKeyPair.privateKey}\n=======\n`
    );
  });

pgm
  .command("ecc-keygen", "")
  .description("Generate ECC Key")
  .option("-c, --curve <curve>", "Named curve like P-256", "P-256")
  .action(async (options) => {
    const ecKeyPair = await ecKeyGen(options.curve);
    console.log(
      `<Generated ECC Key Pair (DER Form)>\nPublic Key:\n${ecKeyPair.publicKey}\n\nPrivate Key:\n${ecKeyPair.privateKey}\n=======\n`
    );
  });

pgm
  .command("rsa-oaep-encrypt <data>", "")
  .description("RSA-OAEP Encryption")
  .option("-p, --publicKey <publicKey>", "hex DER-formatted public key")
  .action(async (data, options) => {
    const encryptedString = await rsaOaepEncrypt(data, options.publicKey);
    console.log(`<Encrypted Data (in HexString)>\n${encryptedString}\n=======\n`);
  });

pgm
  .command("rsa-oaep-decrypt <data>", "")
  .description("RSA-OAEP Decryption")
  .option("-s, --privateKey <privateKey>", "hex DER-formatted private key")
  .action(async (data, options) => {
    const decrypted = await rsaOaepDecrypt(data, options.privateKey);
    console.log(`<Decrypted Data>\n${decrypted}\n=======\n`);
  });

pgm
  .command("ecdh-aes-encrypt <data>", "")
  .description("ECDH with AES Encryption")
  .option("-p, --publicKey <publicKey>", "DER-formatted public key")
  .option("-s, --privateKey <privateKey>", "DER-formatted private key")
  .action(async (data, options) => {
    // Shared bits
    const sharedBits = await ecdh(options.publicKey, options.privateKey);
    console.log(`<Shared Bits>\n${sharedBits}\n`);

    // HKDF key derivation
    const aesKey = await deriveKeyFromMasterSecret(sharedBits, 32);
    console.log(`<Derived AES Key>
Key: ${jseu.encoder.arrayBufferToHexString(aesKey.key)}
HKDF-Salt: ${aesKey.kdfParams.salt}
HKDF-Hash: ${aesKey.kdfParams.hash}\n`);

    // AES-CBC encryption
    const encrypted = await encryptAES(data, aesKey.key);
    console.log(`<Encrypted data>\nData: ${encrypted.data}\nInitial Vector: ${encrypted.iv}\n`);

    // packing for ease
    const packed = msgpack.encode({ encrypted, kdfParams: aesKey.kdfParams });
    console.log(`<Msgpacked encrypted and kdf data>\n${jseu.encoder.arrayBufferToHexString(new Uint8Array(packed))}`);
  });

pgm
  .command("ecdh-aes-decrypt <data>", "")
  .description("ECDH with AES Encryption")
  .option("-p, --publicKey <publicKey>", "hex DER-formatted public key")
  .option("-s, --privateKey <privateKey>", "hex DER-formatted private key")
  .action(async (data, options) => {
    // deserialized
    const decoded = jseu.encoder.hexStringToArrayBuffer(data);
    const depack = msgpack.decode(decoded);

    // Shared bits
    const sharedBits = await ecdh(options.publicKey, options.privateKey);
    console.log(`<Shared Bits>\n${sharedBits}\n`);

    // HKDF key derivation
    const aesKey = await deriveKeyFromMasterSecret(sharedBits, 32, depack.kdfParams.salt, depack.kdfParams.hash);
    console.log(`<Derived AES Key>\n${jseu.encoder.arrayBufferToHexString(aesKey.key)}\n`);

    // AES-CBC decryption
    const decrypted = await decryptAES(depack.encrypted.data, aesKey.key, depack.encrypted.iv);
    console.log(`<Decrypted Data>\n${decrypted}\n=======\n`);
  });

pgm.parse(process.argv);
