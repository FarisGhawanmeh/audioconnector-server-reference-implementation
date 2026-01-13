import { Request } from 'express';
import {
  VerifyResult,
  verifySignature,
  withFailure,
  queryCanonicalizedHeaderField,
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
      '@authority',
      'audiohook-organization-id',
      'audiohook-session-id',
      'audiohook-correlation-id',
      'x-api-key',
    ],
    maxSignatureAge: 10,
    derivedComponentLookup: (name) => {
      if (name === '@request-target') {
        return request.url ?? null;
      }
      if (name === '@authority') {
        const host = request.headers['host'];
        return typeof host === 'string' && host.length > 0 ? host : null;
      }
      return null;
    },
    keyResolver: async (parameters) => {
      // Nonce checks (Genesys sends nonce in signature-input)
      if (!parameters.nonce) {
        return withFailure('PRECONDITION', 'Missing "nonce" signature parameter');
      } else if (parameters.nonce.length < 22) {
        return withFailure('PRECONDITION', 'Provided "nonce" signature parameter is too small');
      }

      const keyId = parameters.keyid;

      // Genesys sets keyid="<apiKey>" and also sends x-api-key: <apiKey>
      if (!keyId) {
        return withFailure('PRECONDITION', 'Missing "keyid" signature parameter');
      }

      if (keyId !== apiKey) {
        return withFailure('PRECONDITION', 'X-API-KEY header field and signature keyid mismatch');
      }

      const secret = secretService.getSecretForKey(keyId);

      // IMPORTANT: empty secret means "not found"
      if (!secret || secret.length === 0) {
        return withFailure('PRECONDITION', `No secret found for keyid="${keyId}"`);
      }

      return {
        code: 'GOODKEY',
        key: secret,
      };
    },
  });

  // Keep original behavior: if request was unsigned, allow it
  if (result.code === 'UNSIGNED') {
    return { code: 'VERIFIED' };
  }

  return result;
}
