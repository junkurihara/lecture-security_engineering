/**
 * index.ts
 */

import * as x5c from './credential';
import {verifyAssertion as verifyAssertion1} from './assertion';
import {verifyAttestation as verifyAttestation1} from './attestation';

export const parseAuthenticatorResponse = x5c.parseAuthenticatorResponse;
export const verifyAttestation = verifyAttestation1;
export const verifyAssertion = verifyAssertion1;
export const getPublicKeyIdFromAssertion = x5c.getPublicKeyIdFromAssertion;
export default {parseAuthenticatorResponse, verifyAttestation, verifyAssertion, getPublicKeyIdFromAssertion};
