////////
// Parameters for FIDO2 WebAuthn Credential Creation
////////

// Parameters for Creation of Credential Key Pair/Certificate
// https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialCreationOptions
export const createCredentialDefaultArgs: CredentialCreationOptions = {
  publicKey: {
    // Challenge
    // 本当はサーバーで生成した暗号学的に安全な乱数をセット (16bytes以上)
    challenge: new Uint8Array([
      0x8C, 0x0A, 0x26, 0xFF, 0x22, 0x91, 0xC1, 0xE9, 0xB9, 0x4E, 0x2E, 0x17, 0x1A, 0x98, 0x6A, 0x73,
      0x71, 0x9D, 0x43, 0x48, 0xD5, 0xA7, 0x6A, 0x15, 0x7E, 0x38, 0x94, 0x52, 0x77, 0x97, 0x0F, 0xEF
    ]).buffer,

    // Relying Party Info (a.k.a. - Service):
    rp: {
      icon: 'https://login.example.com/login.ico', // optional
      id: 'localhost',
      name: 'Example RP'
    },

    // User Info:
    user: {
      icon: 'https://login.example.com/login.ico', // optional
      id: new Uint8Array(16),
      name: 'john.p.smith@example.com',
      displayName: 'John P. Smith',
    },

    // Public Key Credential Parameters
    // https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialCreationOptions/pubKeyCredParams
    pubKeyCredParams: [{
      type: 'public-key', // As of March 2019, only 'public-key' is accepted.
      alg: -7 // Signature Algorithm (ECDSA with SHA-256) // https://www.iana.org/assignments/cose/cose.xhtml#algorithms
    }],

    // Attestation Type (optional)
    // https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialCreationOptions/attestation
    attestation: 'direct',

    // Time out (optional)
    timeout: 60000,

    // List of Credentials that are already registered. (Optional)
    // Use to avoid existing users from re-creating credential.
    // https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialCreationOptions/excludeCredentials
    excludeCredentials: [],

    // Extensions (Optional)
    // https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialCreationOptions/extensions
    extensions: {}
  }
};

// Parameters for Authentication (Assertion)
// https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialRequestOptions
export const getCredentialDefaultArgs: CredentialRequestOptions = {
  publicKey: {
    // Challenge
    // 本当はサーバーで生成した暗号学的に安全な乱数をセット (16bytes以上)
    challenge: new Uint8Array([
      0x79, 0x50, 0x68, 0x71, 0xDA, 0xEE, 0xEE, 0xB9, 0x94, 0xC3, 0xC2, 0x15, 0x67, 0x65, 0x26, 0x22,
      0xE3, 0xF3, 0xAB, 0x3B, 0x78, 0x2E, 0xD5, 0x6F, 0x81, 0x26, 0xE2, 0xA6, 0x01, 0x7D, 0x74, 0x50
    ]).buffer,

    // Info of credential public keys allowed to use authentication (Optional)
    // 認証器次第ではここが空、RPが指定しなくても問題ない (RP IDに応じてユーザが鍵を選べる, Client-side discoverable Credentialと呼ぶ)
    allowCredentials: [{
      id: (new Uint8Array()).buffer,
      transports: ['usb', 'nfc', 'ble'],
      type: 'public-key'
    }],

    // rpId indicating Relying Party ID (default = current domain)
    rpId: 'localhost',

    // User verification (biometrics authentication, optional, default = 'preferred')
    // PINが未指定の場合などは、'required'にすると検証不可として認証エラー
    userVerification: 'required',

    // Time out (optional)
    timeout: 60000,

    // Extensions (Optional)
    // https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialRequestOptions/extensions
    extensions: {}
  },
};
