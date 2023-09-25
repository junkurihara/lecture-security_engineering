// Works both in Node.js and Browsers by using "jscu"

import jseu from 'js-encoding-utils';
import {getJscu} from './common/env';

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
