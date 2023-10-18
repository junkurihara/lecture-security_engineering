import jseu from 'js-encoding-utils';
import {getJscu} from './env';
import * as x509 from '@peculiar/x509';
import {coseToJwk} from './util';
import {checkCredentialId, checkResponse, parseAuthenticatorResponse} from './credential';

const parseAttestedCredentialData = async (
  authData: Uint8Array
): Promise<{ aaguid: Uint8Array, credentialId: string, publicKeyPem: string }> => {
  const tailer = authData.slice(37, authData.length);
  const aaguid = tailer.slice(0, 16);
  const credentialIdLength = (<number>tailer[16] << 8) + <number>tailer[17];
  const credentialId = tailer.slice(18, 18 + credentialIdLength);
  const attestedCredentialsBuf = tailer.slice(18 + credentialIdLength, tailer.length);
  const jwk = coseToJwk(attestedCredentialsBuf);
  const pemKey = await (new (getJscu()).Key('jwk', jwk)).export('pem');

  return {aaguid, credentialId: jseu.encoder.encodeBase64Url(credentialId), publicKeyPem: pemKey};
};


export const verifyAttestation = async (
  credential: PublicKeyCredential,
  challenge: Uint8Array
): Promise<{ valid: boolean, credentialPublicKey?: string, attestationCertificate?: string }> => {
  const jscu = getJscu();
  // https://www.w3.org/TR/webauthn/#registering-a-new-credential
  //check Id
  if (!checkCredentialId(credential)) {
    console.log('Credential ID is not valid');
    return {valid: false};
  }

  // AuthenticatorAttestationResponse
  const response = <AuthenticatorAttestationResponse>(credential.response);
  const decodedResponse = parseAuthenticatorResponse(response);
  const authData = decodedResponse.attestationObject.authData;

  // check clientDataJson and authData
  const r = await checkResponse(decodedResponse.clientDataJSON, authData, 'webauthn.create', challenge);
  if (!r.valid) {
    console.log(r.msg);
    return {valid: false};
  }
  const clientDataHash = await jscu.hash.compute(new Uint8Array(response.clientDataJSON), 'SHA-256');

  // TODO: Adapted only to Security Key By Yubico
  const fmt = decodedResponse.attestationObject.fmt;
  const attStmt = decodedResponse.attestationObject.attStmt; // attestation statement
  if (fmt === 'packed') {
    // to be verified for 'packed'
    const verificationData = new Uint8Array(authData.length + clientDataHash.length);
    verificationData.set(authData, 0);
    verificationData.set(clientDataHash, authData.length);

    // extract public key cert generated at Security Key By Yubico
    const pemCert = jseu.formatter.binToPem(new Uint8Array(attStmt.x5c[0]), 'certificate');
    const crt = new x509.X509Certificate(pemCert);
    const jscuKeyObj = new jscu.Key('der', new Uint8Array(crt.publicKey.rawData));

    // signature to be verified
    const signature = new Uint8Array(attStmt.sig);

    // @ts-ignore
    const validateSig = await jscu.pkc.verify(new Uint8Array(verificationData), signature, jscuKeyObj, 'SHA-256', {format: 'der'});
    if (!validateSig) {
      console.log('Signature is not valid');
      return {valid: false};
    }

    // Get Public Key From AuthData
    const parsed = await parseAttestedCredentialData(new Uint8Array(authData));
    return {valid: true, credentialPublicKey: parsed.publicKeyPem, attestationCertificate: pemCert};
  } else {
    console.log(`This format is not supported: ${fmt}`);
    return {valid: false};
  }
};
