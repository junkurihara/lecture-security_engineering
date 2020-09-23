import {makeApiCall} from './util/comm';
import {mockDataUrl, remoteDataUrl} from './util/params';
import {deriveKeyFromPassword, deriveKeyFromMasterSecret} from './derive-key';
import jseu from 'js-encoding-utils';

import * as aes from './encrypt'

/**
 * Post data
 * @param data {string} - plaintext data to be encrypted
 * @param password {string|undefined} - string password
 * @param masterSecret {string|undefined} - binary master secret in Base64
 * @param remote {boolean} - fetch remote json-server if true
 * @param hash {'SHA-256'|'SHA-384'|'SHA-512'} - hash algorithm for pbkdf2
 * @param iterationCount {number} - iteration count for pbkdf2
 * @return {Promise<*>}
 */
export const postMyData = async ({data, password, masterSecret, remote=false, hash='SHA-256', iterationCount=2048}) => {
  if((password && masterSecret) || (!password && !masterSecret)) throw new Error('Either one of password or masterSecret must be specified');
  ////////////////////////
  const keyObj = (password)
    ? await deriveKeyFromPassword(password, 32, null, hash, iterationCount) // Derive key from password
    : await deriveKeyFromMasterSecret(masterSecret, 32, null, hash); // Derive key from master secret binary

  const kdf = (password) ? 'PBKDF2' : 'HKDF';
  let msg = '> Derived key and its related params:\n'
  + `\t Derived key in Base64: ${jseu.encoder.encodeBase64(keyObj.key)}\n`
  + `\t ${kdf} Param - Salt in Base64: ${keyObj.kdfParams.salt}\n`
  + `\t ${kdf} Param - Hash: ${keyObj.kdfParams.hash}`;
  msg += (password) ? `\n\t ${kdf} Param - Iteration: ${keyObj.kdfParams.iterationCount}` : '';
  console.log( msg );

  const payload = {};
  ////////////////////////
  // universal api
  const encryptedObj = await aes.encrypt(data, keyObj.key);
  ////////////////////////
  payload.data = encryptedObj.data;
  payload.iv = encryptedObj.iv;
  payload.kdfParams = keyObj.kdfParams;
  ////////////////////////

  const response = await makeApiCall({
    method: 'POST',
    requestUrl: (remote) ? remoteDataUrl : mockDataUrl,
    payload,
    headers: {'Content-Type': 'application/json'},
    mode: 'cors'
  });

  return {id: response.id};
};


/**
 * Get data
 * @param dataId - id registered in the json server
 * @param password {string|undefined} - the string password
 * @param masterSecret {string|undefined} - binary master secret in Base64
 * @param remote {boolean} - fetch remote json-server if true
 * @return {Promise<*>}
 */
export const getMyData = async ({id, password, masterSecret, remote=false}) => {
  const data = await makeApiCall({
    method: 'GET',
    requestUrl: `${(remote) ? remoteDataUrl : mockDataUrl}/${id}`,
    headers: {'Content-Type': 'application/json'},
    mode: 'cors'
  });

  ////////////////////////
  if((password && masterSecret) || (!password && !masterSecret)) throw new Error('Either one of password or masterSecret must be specified');
  if(!data.data || !data.iv || !data.kdfParams) throw new Error(`Maybe Unencrypted data => contents: ${data}`);
  const keyObj = (password)
    ? await deriveKeyFromPassword(password, 32, data.kdfParams.salt, data.kdfParams.hash, data.kdfParams.iterationCount) // Derive key from password
    : await deriveKeyFromMasterSecret(masterSecret, 32, data.kdfParams.salt, data.kdfParams.hash); // Derive key from master secret binary

  const kdf = (password) ? 'PBKDF2' : 'HKDF';
  let msg = '> Derived key and its related params:\n'
    + `\t Derived key in Base64: ${jseu.encoder.encodeBase64(keyObj.key)}\n`
    + `\t ${kdf} Param - Salt in Base64: ${keyObj.kdfParams.salt}\n`
    + `\t ${kdf} Param - Hash: ${keyObj.kdfParams.hash}`;
  msg += (password) ? `\n\t ${kdf} Param - Iteration: ${keyObj.kdfParams.iterationCount}` : '';
  console.log( msg );

  ////////////////////////
  // universal api
  const decrypted = await aes.decrypt(data.data, keyObj.key, data.iv);
  ////////////////////////
  return {data: decrypted};
  ////////////////////////
};
