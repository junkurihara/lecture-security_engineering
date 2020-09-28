// Works both in Node.js and Browsers by using "jscu"

import jseu from 'js-encoding-utils';
import {getJscu} from './util/env';

/**
 * Encrypt data here
 * @param data {string} - plaintext data to be encrypted
 * @param key {Uint8Array} - 256bit key
 * @return {Promise<{data: *, iv: *}>}
 */
export const encryptAES = async (data, key) => {
  const jscu = getJscu();

  const iv = jscu.random.getRandomBytes(16);
  const encrypted = await jscu.aes.encrypt(
    jseu.encoder.stringToArrayBuffer(data),
    key,
    {name: 'AES-CBC', iv}
  );

  return {
    data: jseu.encoder.arrayBufferToHexString(encrypted),
    iv: jseu.encoder.arrayBufferToHexString(iv)
  };
};

/**
 * Decrypt data
 * @param data {string} - encrypted data in hex string
 * @param key {Uint8Array} - 256bit key
 * @param iv {string} - iv in hex string
 * @return {Promise<*|void|Promise<void>|IDBRequest<IDBValidKey>|[]>}
 */
export const decryptAES = async (data, key, iv) => {
  const jscu = getJscu();

  const decrypted = await jscu.aes.decrypt(
    jseu.encoder.hexStringToArrayBuffer(data),
    key,
    {name: 'AES-CBC', iv: jseu.encoder.hexStringToArrayBuffer(iv)}
  );

  return jseu.encoder.arrayBufferToString(decrypted);
};
