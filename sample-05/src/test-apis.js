import jseu from 'js-encoding-utils';

import {getJscu, getJscec} from './util/env';


export const ecdh = async (publicDer, privateDer) => {
  const jscu = getJscu();
  const jscec = getJscec();

  const publicKey = new jscu.Key('der', jseu.encoder.hexStringToArrayBuffer(publicDer));
  const privateKey = new jscu.Key('der', jseu.encoder.hexStringToArrayBuffer(privateDer));
  const publicJwk = await publicKey.export('jwk');
  const privateJwk = await privateKey.export('jwk');

  // Derive shared bits at each end.
  const derived = await jscec.deriveSecret(publicJwk, privateJwk);  // JWK formatted key is required
  return jseu.encoder.arrayBufferToHexString(derived);
};

export const rsaOaepEncrypt = async (stringData, publicDer, hash = 'SHA-256') => {
  const jscu = getJscu();

  const publicKey = new jscu.Key('der', jseu.encoder.hexStringToArrayBuffer(publicDer));

  const encrypted = await jscu.pkc.encrypt(
    jseu.encoder.stringToArrayBuffer(stringData),
    publicKey,
    {hash} // for OAEP
  );
  return jseu.encoder.arrayBufferToHexString(encrypted.data);
};

export const rsaOaepDecrypt = async (encryptedString, privateDer, hash = 'SHA-256') => {
  const jscu = getJscu();

  const privateKey = new jscu.Key('der', jseu.encoder.hexStringToArrayBuffer(privateDer));

  const decrypted = await jscu.pkc.decrypt(
    jseu.encoder.hexStringToArrayBuffer(encryptedString),
    privateKey,
    {hash} // for OAEP
  );
  return jseu.encoder.arrayBufferToString(decrypted);
};


export const rsaKeyGen = async (bits = 2048) => {
  const jscu = getJscu();
  const keyPair = await jscu.pkc.generateKey('RSA', {modulusLength: bits});
  return {
    publicKey: jseu.encoder.arrayBufferToHexString(await keyPair.publicKey.export('der')),
    privateKey: jseu.encoder.arrayBufferToHexString(await keyPair.privateKey.export('der'))
  };
};

export const ecKeyGen = async (namedCurve = 'P-256') => {
  const jscu = getJscu();
  const keyPair = await jscu.pkc.generateKey('EC', {namedCurve});
  return {
    publicKey: jseu.encoder.arrayBufferToHexString(await keyPair.publicKey.export('der')),
    privateKey: jseu.encoder.arrayBufferToHexString(await keyPair.privateKey.export('der'))
  };
};
