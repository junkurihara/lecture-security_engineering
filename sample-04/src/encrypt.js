// Works both in Node.js and Browsers by using "jscu"

import jseu from 'js-encoding-utils';
import {getJscu} from './util/env';
import {pkcs7Padding} from './util/pkcs7';

/**
 * Encrypt data here
 * @param data {string} - plaintext data to be encrypted
 * @param key {Uint8Array} - 256bit key
 * @return {Promise<{data: *, iv: *}>}
 */
export const encrypt = async (data, key) => {
  const jscu = getJscu();

  const iv = jscu.random.getRandomBytes(16);
  const encrypted = await jscu.aes.encrypt(
    jseu.encoder.stringToArrayBuffer(data),
    key,
    {name: 'AES-CBC', iv}
  );

  return {
    data: jseu.encoder.encodeBase64(encrypted),
    iv: jseu.encoder.encodeBase64(iv)
  };
};

/**
 * Decrypt data
 * @param data {string} - encrypted data in base64
 * @param key {Uint8Array} - 256bit key
 * @param iv {string} - iv in base64
 * @return {Promise<*|void|Promise<void>|IDBRequest<IDBValidKey>|[]>}
 */
export const decrypt = async (data, key, iv) => {
  const jscu = getJscu();

  const decrypted = await jscu.aes.decrypt(
    jseu.encoder.decodeBase64(data),
    key,
    {name: 'AES-CBC', iv: jseu.encoder.decodeBase64(iv)}
  );

  return jseu.encoder.arrayBufferToString(decrypted);
};



/////////////////////////////
// pseudo simulation of aes ecb mode
// ecb mode is implemented by tweaking cbc-mode
const AESBLOCK = 16;
//// DO NOT USE ECB MODE IN PRODUCTION
export const encryptECB = async (data, key) => {
  const jscu = getJscu();

  const iv = new Uint8Array([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]);
  const uint8data = jseu.encoder.stringToArrayBuffer(data);
  const pad = pkcs7Padding(AESBLOCK - (uint8data.length % AESBLOCK), AESBLOCK);

  const plaintext = new Uint8Array( uint8data.length + pad.length );
  plaintext.set(uint8data);
  plaintext.set(pad, uint8data.length);

  const blockNum = plaintext.length / AESBLOCK;
  const encrypted = new Uint8Array( plaintext.length );

  for(let i = 0; i < blockNum; i++){
    const block = plaintext.slice(i * AESBLOCK, (i+1) * AESBLOCK);
    const x = await jscu.aes.encrypt(
      block,
      key,
      {name: 'AES-CBC', iv}
    );

    // prune trailer 16 bytes that always correspond to padding bytes in this case
    encrypted.set(x.slice(0,16), i*AESBLOCK);
  }

  return {
    data: jseu.encoder.encodeBase64(encrypted)
  };
};
