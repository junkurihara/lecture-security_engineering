import jseu from 'js-encoding-utils';
import { decode } from 'cbor-x/decode';
import { Buffer } from 'buffer';
window.Buffer = window.Buffer || Buffer;

export const coseToJwk = (cose: Uint8Array) => {
  const attestedCredentials = decode(Buffer.from(cose));
  // https://tools.ietf.org/html/rfc8152#section-7
  const jwk: JsonWebKey = {};
  Object.keys(attestedCredentials).forEach( (key: any) => {
    switch(parseInt(key)){
    case 1:
      if (<number>attestedCredentials[key] === 2) jwk.kty = 'EC';
      break;
    case 3:
      if (<number>attestedCredentials[key] === -7) jwk.alg = 'ES256';
      break;
    case -1:
      if(<number>attestedCredentials[key] === 1) jwk.crv = 'P-256';
      break;
    case -2:
      jwk.x = jseu.encoder.encodeBase64Url(new Uint8Array(attestedCredentials[key]));
      break;
    case -3:
      jwk.y = jseu.encoder.encodeBase64Url(new Uint8Array(attestedCredentials[key]));
      break;
    }
  });
  return jwk;
};
