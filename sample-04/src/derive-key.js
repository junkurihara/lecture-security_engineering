import {getJscu} from './util/env';
import jseu from 'js-encoding-utils';


/**
 * Execute PBKDF2
 * @param password {string} - string password
 * @param len {number} - length of key in bytes
 * @param salt {string|null} - Uint8Array salt in Base64
 * @param hash {string} - Hash used in PBKDF2 algorithm, like 'SHA-256'
 * @param iterationCount {number} - Iteration count in PBKDF2 algorithm.
 * @return {Promise<{key: *, kdfParams: {salt: *,  hash: *, iterationCount: *}}>}
 */
export const deriveKeyFromPassword = async (password, len, salt=null, hash='SHA-256', iterationCount=2048) => {
  const jscu = getJscu();

  // derive key from password
  // following params (salt, iterationCount, aesKeyLen, hash) must be shared with receiver.
  if(!salt){
    salt = jscu.random.getRandomBytes(32); // Uint8Array -> must be shared with receiver
  }
  else {
    salt = jseu.encoder.decodeBase64(salt);
  }

  const key = await jscu.pbkdf.pbkdf2(
    password,
    salt,
    iterationCount,
    len,
    hash
  ).catch( (e) => {
    throw new Error(`failed to derive binary key from string password: ${e.message}`);
  });
  return {
    key,
    kdfParams: { // pbkdf2 parameters that must be shared with receiver
      salt: jseu.encoder.encodeBase64(salt),
      hash,
      iterationCount
    }
  };
};

/**
 * HKDF for perfect forward secrecy
 * @param masterSecret {string} - master secret (binary seed) in Base64
 * @param len {number} - output key length in byte
 * @param salt {string|null} - Uint8Array salt in Base64
 * @param hash {string} - Hash used in PBKDF2 algorithm, like 'SHA-256'
 * @return {Promise<{kdfParams: {salt: *, hash: *}, key: *}>}
 */
export const deriveKeyFromMasterSecret = async (masterSecret, len, salt=null, hash='SHA-256') => {
  const jscu = getJscu();

  // derive key from master secret binary
  // following params (salt, iterationCount, aesKeyLen, hash) must be shared with receiver.
  if(!salt){
    salt = jscu.random.getRandomBytes(32); // Uint8Array -> must be shared with receiver
  }
  else {
    salt = jseu.encoder.decodeBase64(salt);
  }

  const keyObj = await jscu.hkdf.compute(
    jseu.encoder.decodeBase64(masterSecret),
    hash,
    len,
    '', // 'info' field for RFC5869. This could be always blank.
    salt
  ).catch( (e) => {
    throw new Error(`failed to derive binary key from master secret binary: ${e.message}`);
  });
  return {
    key: keyObj.key,
    kdfParams: { // pbkdf2 parameters that must be shared with receiver
      salt: jseu.encoder.encodeBase64(keyObj.salt),
      hash
    }
  };
};

/**
 * Generate Base64 encoded binary (used as master secret)
 * @param len {number} - length of master secret in bytes
 * @return {*} - master secret encoded into Base64
 */
export const generateBase64MasterSecret = (len) => {
  const jscu = getJscu();
  const sec = jscu.random.getRandomBytes(len);
  return jseu.encoder.encodeBase64(sec);
};
