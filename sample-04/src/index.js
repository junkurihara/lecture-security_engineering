/**
 * index.js
 */
import {getMyData, postMyData} from './post-get';
import {generateBase64MasterSecret} from './derive-key';
import {encryptECB, encrypt} from './encrypt';

export {getMyData, postMyData, generateBase64MasterSecret, encryptECB, encrypt};
export default {getMyData, postMyData, generateBase64MasterSecret, encryptECB, encrypt};
