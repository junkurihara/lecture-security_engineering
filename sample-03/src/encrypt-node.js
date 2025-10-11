import jseu from 'js-encoding-utils';

/**
 * Encrypt data here
 * @param data {string} - plaintext data to be encrypted
 * @param key {Uint8Array} - 256bit key
 * @return {Promise<{data: *, iv: *}>}
 */
export const encrypt = async (data, key) => {
  const uint8data = jseu.encoder.stringToArrayBuffer(data);
  const crypto = require('crypto');
  const algorithm = 'aes-256-cbc';
  const iv = crypto.randomBytes(16); // Initialization vector.
  const cipher = crypto.createCipheriv(algorithm, key, iv);

  let encrypted = cipher.update(uint8data, 'utf8', 'base64');
  encrypted += cipher.final('base64');
  return {
    data: encrypted,
    iv: jseu.encoder.encodeBase64(new Uint8Array(iv))
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
  const crypto = require('crypto');

  const algorithm = 'aes-256-cbc';
  if (!iv) iv = Buffer.alloc(16, 0); // Initialization vector.
  const uint8iv = jseu.encoder.decodeBase64(iv);

  const decipher = crypto.createDecipheriv(algorithm, key, uint8iv);

  let decrypted = decipher.update(data, 'base64', 'utf8');
  decrypted += decipher.final();
  return decrypted;
};
