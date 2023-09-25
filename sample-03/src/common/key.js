import {getJscu} from './env';
import jseu from 'js-encoding-utils';

export const strToBinaryKey = async (str, len, salt=null) => {
  const jscu = getJscu();

  // derive key from password
  // following params (salt, iterationCount, aesKeyLen, hash) must be shared with receiver.
  if(!salt){
    salt = jscu.random.getRandomBytes(32); // Uint8Array -> must be shared with receiver
  }
  else {
    salt = jseu.encoder.decodeBase64(salt);
  }

  const iterationCount = 2048; // must be shared with receiver
  const hash = 'SHA-256'; // SHA-384, SHA-512, etc.

  const key = await jscu.pbkdf.pbkdf2(
    str,
    salt,
    iterationCount,
    len,
    hash
  ).catch( (e) => {
    throw new Error(`failed to derive binary key from string key: ${e.message}`);
  });
  return {key, salt: jseu.encoder.encodeBase64(salt)};
};
