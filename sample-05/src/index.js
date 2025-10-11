/**
 * index.js
 */
import {ecdh, ecKeyGen, rsaKeyGen, rsaOaepDecrypt, rsaOaepEncrypt} from './test-apis';
import {deriveKeyFromMasterSecret} from './derive-key';
import {encryptAES, decryptAES} from './encryptAES';

export {ecdh, encryptAES, decryptAES, ecKeyGen, rsaKeyGen, rsaOaepDecrypt, rsaOaepEncrypt, deriveKeyFromMasterSecret};
export default {ecdh, encryptAES, decryptAES, ecKeyGen, rsaKeyGen, rsaOaepDecrypt, rsaOaepEncrypt, deriveKeyFromMasterSecret};
