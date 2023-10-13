import jseu from 'js-encoding-utils';

import {getJscu} from './util/env';

/**
 * Get Hash
 * @param data {string}
 * @param hash {'SHA-256'|'SHA-384'|'SHA-512'|'SHA3-256'|'SHA3-384'|'SHA3-512'}
 * @return {Promise<Uint8Array>}
 */
export const genHash = (data, hash = 'SHA-256') => {
  const jscu = getJscu();
  const binary = jseu.encoder.stringToArrayBuffer(data);

  return jscu.hash.compute(binary, hash);
};


export const genHmac = (data, key, hash = 'SHA-256') => {
  const jscu = getJscu();
  const binaryData = jseu.encoder.stringToArrayBuffer(data);
  const binaryKey = jseu.encoder.hexStringToArrayBuffer(key);

  return jscu.hmac.compute(binaryKey, binaryData, hash);
};

export const verifyHmac = (data, key, mac, hash = 'SHA-256') => {
  const jscu = getJscu();
  const binaryData = jseu.encoder.stringToArrayBuffer(data);
  const binaryKey = jseu.encoder.hexStringToArrayBuffer(key);
  const binaryMac = jseu.encoder.hexStringToArrayBuffer(mac);

  return jscu.hmac.verify(binaryKey, binaryData, binaryMac, hash);
};

export const genRsaKey = async (bits = 2048) => {
  const jscu = getJscu();
  const kp = await jscu.pkc.generateKey('RSA', {modulusLength: bits});
  const publicKey = jseu.encoder.arrayBufferToHexString(await kp.publicKey.export('der'));
  const privateKey = jseu.encoder.arrayBufferToHexString(await kp.privateKey.export('der'));

  return {publicKey, privateKey};
};

export const signRsaPss = async(data, privateKeyHex, hash = 'SHA-256', saltLength = 32) => {
  const jscu = getJscu();
  const binaryData = jseu.encoder.stringToArrayBuffer(data);
  const privateKey = new jscu.Key('der', jseu.encoder.hexStringToArrayBuffer(privateKeyHex));

  return jscu.pkc.sign(binaryData, privateKey, hash, {name: 'RSA-PSS', saltLength});
};


export const verifyRsaPss = (data, signatureHex, publicKeyHex, hash = 'SHA-256', saltLength = 32) => {
  const jscu = getJscu();
  const binaryData = jseu.encoder.stringToArrayBuffer(data);
  const publicKey = new jscu.Key('der', jseu.encoder.hexStringToArrayBuffer(publicKeyHex));
  const signature = jseu.encoder.hexStringToArrayBuffer(signatureHex);

  return jscu.pkc.verify(binaryData, signature, publicKey, hash, {name: 'RSA-PSS', saltLength});
};

export const genEccKey = async (curve = 'P-256') => {
  const jscu = getJscu();
  const kp = await jscu.pkc.generateKey('EC', {namedCurve: curve});
  const publicKey = jseu.encoder.arrayBufferToHexString(await kp.publicKey.export('der'));
  const privateKey = jseu.encoder.arrayBufferToHexString(await kp.privateKey.export('der'));

  return {publicKey, privateKey};
};

export const signEcdsa = async (data, privateKeyHex, hash = 'SHA-256') => {
  const jscu = getJscu();
  const binaryData = jseu.encoder.stringToArrayBuffer(data);
  const privateKey = new jscu.Key('der', jseu.encoder.hexStringToArrayBuffer(privateKeyHex));

  return jscu.pkc.sign(binaryData, privateKey, hash);
};

export const verifyEcdsa = async(data, signatureHex, publicKeyHex, hash = 'SHA-256') => {
  const jscu = getJscu();
  const binaryData = jseu.encoder.stringToArrayBuffer(data);
  const publicKey = new jscu.Key('der', jseu.encoder.hexStringToArrayBuffer(publicKeyHex));
  const signature = jseu.encoder.hexStringToArrayBuffer(signatureHex);

  return jscu.pkc.verify(binaryData, signature, publicKey, hash);
};
