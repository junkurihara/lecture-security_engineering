import {makeApiCall} from './comm';
import {mockDataUrl, remoteDataUrl} from './params';
import {strToBinaryKey} from './key';
import jseu from 'js-encoding-utils';

import * as webapi from '../encrypt-browser';
import * as nodeapi from '../encrypt-node';
import * as universalapi from '../encrypt-universal';

/**
 * Post data
 * @param data {string} - plaintext data to be encrypted
 * @param key {string} - the string password
 * @param encrypt {boolean} - encrypt or plaintext
 * @param remote {boolean} - fetch remote json-server if true
 * @param universal {boolean} - use jscu if true
 * @return {Promise<*>}
 */
export const postMyData = async ({data, key='', encrypt=false, remote=false, universal=false}) => {
  const payload = {};
  if(encrypt) {
    ////////////////////////
    // encrypt data here!!
    const keyObj = await strToBinaryKey(key, 32);
    console.log(`Note: Derived key binary in base64: ${jseu.encoder.encodeBase64(keyObj.key)}`);
    ////////////////////////
    // universal api or dedicated apis
    let encryptedObj;
    if (universal) encryptedObj = await universalapi.encrypt(data, keyObj.key);
    else encryptedObj = (typeof window !== 'undefined')
      ? await webapi.encrypt(data, keyObj.key)
      : await nodeapi.encrypt(data, keyObj.key);
    ////////////////////////
    payload.data = encryptedObj.data;
    payload.iv = encryptedObj.iv;
    payload.salt = keyObj.salt;
    ////////////////////////
  }
  else payload.data = data;


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
 * @param key {string} - the string password
 * @param remote {boolean} - fetch remote json-server if true
 * @param universal {boolean} - use jscu if true
 * @return {Promise<*>}
 */
export const getMyData = async ({id, key='', decrypt=false, remote=false, universal=false}) => {
  const data = await makeApiCall({
    method: 'GET',
    requestUrl: `${(remote) ? remoteDataUrl : mockDataUrl}/${id}`,
    headers: {'Content-Type': 'application/json'},
    mode: 'cors'
  });

  if(decrypt) {
    ////////////////////////
    // decryption data here!!
    if(!data.data || !data.iv || !data.salt) throw new Error(`Maybe Unencrypted data => contents: ${data}`);
    const keyObj = await strToBinaryKey(key, 32, data.salt);
    console.log(`Note: Derived key binary in base64: ${jseu.encoder.encodeBase64(keyObj.key)}`);
    ////////////////////////
    // universal api or dedicated apis
    let decrypted;
    if(universal) decrypted = await universalapi.decrypt(data.data, keyObj.key, data.iv);
    else decrypted = (typeof window !== 'undefined')
      ? await webapi.decrypt(data.data, keyObj.key, data.iv)
      : await nodeapi.decrypt(data.data, keyObj.key, data.iv);
    ////////////////////////
    return {data: decrypted};
    ////////////////////////
  }
  else return data;
};

/**
 * Get all entries without decryption
 * @param remote {boolean} - fetch remote json-server if true
 * @return {Promise<*>}
 */
export const getAllEntries = async (remote=false) => makeApiCall({
  method: 'GET',
  requestUrl: (remote) ? `${remoteDataUrl}` : `${mockDataUrl}`,
  headers: {'Content-Type': 'application/json'},
  mode: 'cors'
});
