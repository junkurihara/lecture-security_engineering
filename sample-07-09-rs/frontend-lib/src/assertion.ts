import {getJscu} from './env';
import {checkCredentialId, checkResponse, parseAuthenticatorResponse} from './credential';

export const verifyAssertion = async (
  assertion: PublicKeyCredential,
  challenge: Uint8Array,
  publicKeyPem: string
): Promise<{ valid: boolean, msg: string }> => {
  const jscu = getJscu();

  // Verifying the assertion for user authentication
  // https://www.w3.org/TR/webauthn/#verifying-assertion
  if (!checkCredentialId(assertion)) return {valid: false, msg: 'InvalidId'};

  // AuthenticatorAssertionResponse
  const response = (<AuthenticatorAssertionResponse>(assertion).response);
  const clientDataHash = await jscu.hash.compute(new Uint8Array(response.clientDataJSON), 'SHA-256');
  const decodedResponse = parseAuthenticatorResponse(response);
  const authenticatorData = decodedResponse.authenticatorData;
  const signature = decodedResponse.signature;

  // check clientDataJson and authData
  const r = await checkResponse(decodedResponse.clientDataJSON, authenticatorData, 'webauthn.get', challenge);
  if (!r.valid) {
    console.log(r.msg);
    return {valid: false, msg: r.msg};
  }

  const verificationData = new Uint8Array(authenticatorData.length + clientDataHash.length);
  verificationData.set(authenticatorData, 0);
  verificationData.set(clientDataHash, authenticatorData.length);
  // console.log(authenticatorData.toString());
  // console.log(clientDataHash.toString());
  // console.log(verificationData.toString());

  const jscuKeyObj = new jscu.Key('pem', publicKeyPem);
  const res = await jscu.pkc.verify(verificationData, signature, jscuKeyObj, 'SHA-256', {format: 'der'});
  // console.log(x);
  return (res) ? {valid: true, msg: 'OK'} : {valid: false, msg: 'InvalidSignature'};
};
