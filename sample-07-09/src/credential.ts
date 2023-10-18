import { decode } from 'cbor-x/decode';
import jseu from 'js-encoding-utils';
import {getJscu} from './env';
import { Buffer } from 'buffer';
window.Buffer = window.Buffer || Buffer;

export const checkCredentialId = (
  credential: PublicKeyCredential
): boolean => credential.id === jseu.encoder.encodeBase64Url(new Uint8Array(credential.rawId));

export const checkResponse = async (
  clientDataJson: any,
  authData: Uint8Array,
  type: 'webauthn.create'|'webauthn.get',
  challenge: Uint8Array
): Promise<{valid: boolean, msg: string}> => {
  const jscu = getJscu();

  if(clientDataJson.type !== type) return {valid: false, msg: 'InvalidType'};
  if(jseu.encoder.encodeBase64Url(challenge) !== clientDataJson.challenge) return {valid: false, msg: 'InvalidChallenge'};

  // check and parse authData https://www.w3.org/TR/webauthn/#authenticator-data
  const rpId = (new URL(clientDataJson.origin)).hostname;
  const rpIdHash = await jscu.hash.compute(jseu.encoder.stringToArrayBuffer(rpId), 'SHA-256');
  // check rpIdHash
  if (jseu.encoder.encodeBase64(authData.slice(0, 32)) !== jseu.encoder.encodeBase64(rpIdHash)) return {valid: false, msg: 'InvalidRpIdHash'};

  // check flag: TODO: Adapted only to Security Key By Yubico
  const flag = new Uint8Array([authData[32]]);
  if ((flag[0] & 0x01) !== 0x01) return {valid: false, msg: 'InvalidFlag'}; // check user present flag
  if (type === 'webauthn.create' && (flag[0] & 0x40) !== 0x40) return {valid: false, msg: 'InvalidFlag'}; // attestedCredentialData flag
  // TODO check clientExtensionResults and others from step 12...

  return {valid: true, msg: 'ok'};
};

// Parser
export const parseAuthenticatorResponse = (
  res: AuthenticatorAttestationResponse|AuthenticatorAssertionResponse
): {clientDataJSON: any, attestationObject?: any, authenticatorData?: any, signature?: any, userHandle?: any} => {
  const typeName = Object.prototype.toString.call(res).slice(8,-1);

  const clientDataJSON = JSON.parse(
    jseu.encoder.arrayBufferToString(new Uint8Array(res.clientDataJSON))
  );

  if(typeName === 'AuthenticatorAttestationResponse'){
    const attestationObject = decode(
      Buffer.from(
        (<AuthenticatorAttestationResponse>res).attestationObject
      ));
    return {clientDataJSON, attestationObject};
  }
  else {
    const authenticatorData = new Uint8Array((<AuthenticatorAssertionResponse>res).authenticatorData);
    const signature = new Uint8Array((<AuthenticatorAssertionResponse>res).signature);
    const userHandle = (<AuthenticatorAssertionResponse>res).userHandle;
    return {clientDataJSON, authenticatorData, signature, userHandle};
  }
};

export const getPublicKeyIdFromAssertion = (assertion: PublicKeyCredential): Uint8Array => new Uint8Array(assertion.rawId);
