import { Request } from 'express';
import {
  VerifyResult,
  verifySignature,
  withFailure,
  queryCanonicalizedHeaderField,
  SignatureParameters,
} from './signature-verifier';
import { SecretService } from '../services/secret-service';

export function verifyRequestSignature(
  request: Request,
  secretService: SecretService
): Promise<VerifyResult> {
  return verifyRequestSignatureImpl(request, secretService);
}

async function verifyRequestSignatureImpl(
  request: Request,
  secretService: SecretService
): Promise<VerifyResult> {
  const apiKey = queryCanonicalizedHeaderField(request.headers, 'x-api-key');

  if (!apiKey) {
    return withFailure('PRECONDITION', 'Missing "X-API-KEY" header field');
  }

  const result = await verifySignature({
    headerFields: request.headers,

    requiredComponents: [
      '@request-target',
      'audiohook-session-id',
      'audiohook-organization-id',
      'audiohook-correlation-id',
      'x-api-key',
      '@authority',
    ],

    maxSignatureAge: 10,

    derivedComponentLookup: (name) => {
      if (name === '@request-target') {
        const url = request.url ?? null;
        console.log('[auth] derived @request-target =', url);
        return url;
      }

      if (name === '@authority') {
        const host =
          queryCanonicalizedHeaderField(request.headers, 'host') ?? null;
        console.log('[auth] derived @authority(host) =', host);
        return host;
      }

      return null;
    },

    keyResolver: async (parameters: SignatureParameters) => {
      if (!parameters.nonce)
        return withFailure('PRECONDITION', 'Missing "nonce" signature parameter');
      if (parameters.nonce.length < 22)
        return withFailure(
          'PRECONDITION',
          'Provided "nonce" signature parameter is too small'
        );

      const keyId = parameters.keyid;
      if (!keyId)
        return withFailure('PRECONDITION', 'Missing "keyid" signature parameter');

      // Genesys sends x-api-key + keyid same value عادة
      if (keyId !== apiKey) {
        return withFailure(
          'PRECONDITION',
          'X-API-KEY header field and signature keyid mismatch'
        );
      }

      const secret = secretService.getSecretForKey(keyId);
      if (!secret || secret.length === 0) {
        return withFailure('PRECONDITION', `No secret found for keyid="${keyId}"`);
      }

      return { code: 'GOODKEY', key: secret };
    },
  });

  console.log('VERIFY RESULT:', result);

  // optional: allow unsigned for testing
  if (result.code === 'UNSIGNED') {
    return { code: 'VERIFIED' };
  }

  return result;
}
