import jseu from 'js-encoding-utils';
import * as cbor from 'cbor';

export const coseToJwk = (cose: Uint8Array) => {
  const attestedCredentials = cbor.decodeAllSync(Buffer.from(cose));
  // https://tools.ietf.org/html/rfc8152#section-7
  const jwk: JsonWebKey = {};
  attestedCredentials[0].forEach( (v: any, k: number) => {
    switch(k){
    case 1:
      if (<number>v === 2) jwk.kty = 'EC';
      break;
    case 3:
      if (<number>v === -7) jwk.alg = 'ES256';
      break;
    case -1:
      if(<number>v === 1) jwk.crv = 'P-256';
      break;
    case -2:
      jwk.x = jseu.encoder.encodeBase64Url(new Uint8Array(v));
      break;
    case -3:
      jwk.y = jseu.encoder.encodeBase64Url(new Uint8Array(v));
      break;
    }
  });
  return jwk;
};
