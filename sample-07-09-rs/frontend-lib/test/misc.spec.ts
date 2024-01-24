import {getTestEnv} from './prepare';
const env = getTestEnv();
// const library = env.library;
const envName = env.envName;
import jseu from 'js-encoding-utils';
// import * as x509 from '@fidm/x509';
import * as x509 from '@peculiar/x509'
// import * as x509 from '@peculiar/x509'
import * as jscu from 'js-crypto-utils';

describe(`${envName}: Misc tests for small utilities`, () => {
  it ('x509', async () => {
    const pemCert = '-----BEGIN CERTIFICATE-----\n' +
      'MIICvDCCAaSgAwIBAgIEBMX+/DANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZ\n' +
      'dWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAw\n' +
      'MDBaGA8yMDUwMDkwNDAwMDAwMFowbTELMAkGA1UEBhMCU0UxEjAQBgNVBAoMCVl1\n' +
      'YmljbyBBQjEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEmMCQG\n' +
      'A1UEAwwdWXViaWNvIFUyRiBFRSBTZXJpYWwgODAwODQ3MzIwWTATBgcqhkjOPQIB\n' +
      'BggqhkjOPQMBBwNCAAQc2Np2EaP17x+IXpULpl2A4zSFU5FYS9R/W3GcUyNcJCHk\n' +
      '45m9tXNngkGQk1dmYUk8kUwuZyTfk5T8+n3qixgEo2wwajAiBgkrBgEEAYLECgIE\n' +
      'FTEuMy42LjEuNC4xLjQxNDgyLjEuMTATBgsrBgEEAYLlHAIBAQQEAwIFIDAhBgsr\n' +
      'BgEEAYLlHAEBBAQSBBD4oBHzjApNFYAGFxEfntx9MAwGA1UdEwEB/wQCMAAwDQYJ\n' +
      'KoZIhvcNAQELBQADggEBAHcYTO91LRoF8wpThdwthvj6wGNxcLAiYqUZXPX+0Db+\n' +
      'AGVODSkVvEVSmj+JXmrBzNQel3FW4AupOgbgrJmmcWWEBZyXSpRQtYcl2LTNU0+I\n' +
      'z9WbyHNN1wQJ9ybFwj608xBuoNRC0rG8wgYbMC4usyRadt3dYOVdQi0cfaksVB2V\n' +
      'NKnw+ttQUWKoZsPHtuzFx8NlazLQBep1W2T0FCONFEG7x/l+ZcfNhT13azAbaurJ\n' +
      '2J0/ff6H0PXJP6h+Obne4xfz0+8ujftWDUSh9oaiVRYf+tgam/tzOKyEU38V2liV\n' +
      '11zMyHKWrXiK0AfyDgb58ky2HSrn/AgE5MW/oXg/CXc=\n' +
      '-----END CERTIFICATE-----';
    const crt = new x509.X509Certificate(pemCert);
    const key = new jscu.Key('der', new Uint8Array(crt.publicKey.rawData));
    const jwk = await key.export('jwk');
    expect((<JsonWebKey>jwk).kty).toBe('EC');
    expect((<JsonWebKey>jwk).crv).toBe('P-256');
  });

});
