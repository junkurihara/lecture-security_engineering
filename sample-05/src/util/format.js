import jseu from 'js-encoding-utils';
import {getJscu} from './env';

export const ecPemToHexString = async (pemKey) => {
  const jscu = getJscu();
  const keyObj = new jscu.Key('pem', pemKey);
  const bin = await keyObj.export('oct', {compact: true});
  return jseu.encoder.arrayBufferToHexString(bin);
};
