import jscu from 'js-crypto-utils';
import jseu from 'js-encoding-utils';
import {getTestEnv} from './prepare';

const env = getTestEnv();
const library = env.library;
const envName = env.envName;

// Import default credential parameters defined in credential-params.ts
import {createCredentialDefaultArgs, getCredentialDefaultArgs} from './credential-params';

describe(`${envName}: Demo for User Registration`, () => {
  // For created key, managed at RP after registration
  let attestedCredentialPublicKeyRawId: ArrayBuffer;
  let attestedCredentialPublicKeyPEM: string;

  it('Validation and Key Extraction from WebAuthn Create Credential Procedure', async () => {
    console.log('======================== [USER REGISTRATION] ========================');

    // Receive a random challenge from Relaying Party (here we use a mock...)
    // 本当はここはRPからもらった乱数を利用することに注意する。
    const randomChallenge: ArrayBuffer = (jscu.random.getRandomBytes(32)).buffer;
    const createOptions: CredentialCreationOptions = createCredentialDefaultArgs;
    (<any>createOptions.publicKey).challenge = randomChallenge;

    // Create Public Key Credential and get Credential Certificate and Attestation Certificate
    const cred: Credential | null = await window.navigator.credentials.create(createOptions);

    // Check and output PublicKeyCredential
    expect(cred !== null).toBeTruthy();
    expect((<PublicKeyCredential>cred).type).toBe('public-key');
    const credential = <PublicKeyCredential>cred;
    console.log('------ [Response from Authenticator: PublicKeyCredential] ------');
    console.log(`> Credential ID: ${credential.id}`);
    console.log(`> Credential Raw ID: ${credential.rawId}`);
    console.log(`> Credential Type: ${credential.type}`);
    const attRes = <AuthenticatorAttestationResponse>(credential.response);
    console.log(`> AuthenticatorAttestationResponse.clientDataJSON: ${attRes.clientDataJSON}`);
    console.log(`> AuthenticatorAttestationResponse.attestationObject: ${attRes.attestationObject}`);

    /////////////////////////////
    const parsedAttRes = library.parseAuthenticatorResponse(attRes);
    console.log('');
    console.log('------ [Decoding result of elements of AuthenticatorAttestationResponse] ------');
    console.log(`> Decoded clientDataJSON:\n${JSON.stringify(parsedAttRes.clientDataJSON, undefined, '  ')}`);
    console.log(`> Decoded attestationObject:\n${
      JSON.stringify(
        parsedAttRes.attestationObject,
        (key: any, val: any) => (val instanceof Array && key === 'data') ? jseu.encoder.encodeBase64(new Uint8Array(val)) : val,
        '  ')}`
    );

    /////////////////////////////
    // Check the validity of PublicKeyCredential (attestation) as RP
    const createChallenge = (<any>createOptions.publicKey).challenge;
    const verifyAttestationResult = await library.verifyAttestation(credential, createChallenge);
    expect(verifyAttestationResult.valid).toBeTruthy();
    expect(typeof verifyAttestationResult.credentialPublicKey === 'string').toBeTruthy();
    expect(typeof verifyAttestationResult.attestationCertificate === 'string').toBeTruthy();
    console.log('');
    console.log('------ [Verification result on PublicKeyCredential.AuthenticatorAttestationResponse] ------');
    console.log(`> Verification result: ${verifyAttestationResult.valid}`);
    console.log(`> Attested Credential Public Key:\n${verifyAttestationResult.credentialPublicKey}`);
    console.log(`> Attestation Certificate:\n${verifyAttestationResult.attestationCertificate}`);

    // Register RawID and attested credential public key as RP
    attestedCredentialPublicKeyRawId = credential.rawId;
    attestedCredentialPublicKeyPEM = verifyAttestationResult.credentialPublicKey;
    console.log('');
  }, 200000);

  it('Validation at WebAuthn Get Credential Procedure', async () => {
    console.log('======================== [USER AUTHENTICATION] ========================');

    ///////////////////////////////////////////////////////////////////
    // Receive a random challenge and public key ID from Relaying Party (here we use a mock...)
    // 本当はここはRPからもらった乱数を利用することに注意する。
    const randomChallenge: ArrayBuffer = (jscu.random.getRandomBytes(32)).buffer;
    const getOptions: CredentialRequestOptions = getCredentialDefaultArgs;
    (<any>getOptions.publicKey).challenge = randomChallenge;
    (<any>getOptions.publicKey).allowCredentials[0].id = attestedCredentialPublicKeyRawId;

    // Retrieve an assertion on the given challenge
    const cred: Credential|null = await window.navigator.credentials.get(getOptions);
    expect(cred !== null).toBeTruthy();
    expect((<PublicKeyCredential>cred).type).toBe('public-key');
    const credential = <PublicKeyCredential>cred;
    console.log('------ [Response from Authenticator: PublicKeyCredential] ------');
    console.log(`> Credential ID: ${credential.id}`);
    console.log(`> Credential Raw ID: ${credential.rawId}`);
    console.log(`> Credential Type: ${credential.type}`);
    const assRes = <AuthenticatorAssertionResponse>(credential.response);
    console.log(`> AuthenticatorAssertionResponse.clientDataJSON: ${assRes.clientDataJSON}`);
    console.log(`> AuthenticatorAssertionResponse.authenticatorData: ${assRes.authenticatorData}`);
    console.log(`> AuthenticatorAssertionResponse.signature: ${assRes.signature}`);
    console.log(`> AuthenticatorAssertionResponse.userHandle: ${assRes.userHandle}`);

    const parsedAssRes = library.parseAuthenticatorResponse(assRes);
    console.log('');
    console.log('------ [Decoding result of elements of AuthenticatorAssertionResponse] ------');
    console.log(`> Decoded clientDataJSON: ${JSON.stringify(parsedAssRes.clientDataJSON, undefined, '  ')}`);
    console.log(`> Base64 authenticatorData: ${jseu.encoder.encodeBase64(assRes.authenticatorData)}`);
    console.log(`> Base64 signature: ${jseu.encoder.encodeBase64(assRes.signature)}`);


    /////////////////////////////
    // Check the validity of PublicKeyCredential (assertion) as RP
    const verifyAssertionResult = await library.verifyAssertion(credential, randomChallenge, attestedCredentialPublicKeyPEM);
    expect(verifyAssertionResult.valid).toBeTruthy();
    expect(typeof verifyAssertionResult.msg === 'string').toBeTruthy();
    console.log('');
    console.log('------ [Verification result on PublicKeyCredential.AuthenticatorAssertionResponse] ------');
    console.log(`> Verification result: ${verifyAssertionResult.valid}`);
  }, 200000);

});
