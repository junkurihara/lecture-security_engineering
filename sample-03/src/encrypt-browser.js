import jseu from 'js-encoding-utils';

/**
 * Encrypt data here
 * @param data {string} - plaintext data to be encrypted
 * @param key {Uint8Array} - 256bit key
 * @return {Promise<{data: *, iv: *}>}
 */
export const encrypt = async (data, key) => {
  const crypto = window.crypto;

  const iv = crypto.getRandomValues(new Uint8Array(16));
  const importedKey = await crypto.subtle.importKey(
    'raw',
    key,
    { name: 'AES-CBC' },
    false, //whether the key is extractable (i.e. can be used in exportKey)
    ['encrypt', 'decrypt'] //can be "encrypt", "decrypt", "wrapKey", or "unwrapKey"
  );

  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-CBC', iv },
    importedKey, //from generateKey or importKey above
    jseu.encoder.stringToArrayBuffer(data) //ArrayBuffer of data you want to encrypt
  );

  return {
    data: jseu.encoder.encodeBase64(new Uint8Array(encrypted)),
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
  const crypto = window.crypto;

  const importedKey = await crypto.subtle.importKey(
    'raw',
    key,
    { name: 'AES-CBC' },
    false, //whether the key is extractable (i.e. can be used in exportKey)
    ['encrypt', 'decrypt'] //can be "encrypt", "decrypt", "wrapKey", or "unwrapKey"
  );

  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-CBC', iv: jseu.encoder.decodeBase64(iv) },
    importedKey, //from generateKey or importKey above
    jseu.encoder.decodeBase64(data)
  );

  return jseu.encoder.arrayBufferToString(decrypted);
};
