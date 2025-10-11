import {getJscu} from './util/env';
import jseu from 'js-encoding-utils';

/**
 * HKDF for perfect forward secrecy
 * @param masterSecret {string} - master secret (binary seed) in hex string
 * @param len {number} - output key length in byte
 * @param salt {string|null} - Uint8Array salt in hex string
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
    salt = jseu.encoder.hexStringToArrayBuffer(salt);
  }

  const keyObj = await jscu.hkdf.compute(
    jseu.encoder.hexStringToArrayBuffer(masterSecret),
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
      salt: jseu.encoder.arrayBufferToHexString(keyObj.salt),
      hash
    }
  };
};
