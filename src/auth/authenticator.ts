import { Request } from 'express';
import {
  VerifyResult,
  verifySignature,
  withFailure,
  queryCanonicalizedHeaderField,
  SignatureParameters,
} from './signature-verifier';
import { SecretService } from '../services/secret-service';

export function verifyRequestSignature(request: Request, secretService: SecretService): Promise<VerifyResult> {
  return verifyRequestSignatureImpl(request, secretService);
}

async function verifyRequestSignatureImpl(request: Request, secretService: SecretService): Promise<VerifyResult> {
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

    // ✅ @request-target = "get /path"
    derivedComponentLookup: (name: any) => {
      if (name === '@request-target') {
        const method = ((request as any).method ?? 'GET').toLowerCase();
        const url = request.url ?? '';
        return `${method} ${url}`; // مثال: "get /openai-voice-bot"
      }
      return null;
    },

    keyResolver: async (parameters: SignatureParameters) => {
      if (!parameters.nonce) {
        return withFailure('PRECONDITION', 'Missing "nonce" signature parameter');
      }
      if (parameters.nonce.length < 22) {
        return withFailure('PRECONDITION', 'Provided "nonce" signature parameter is too small');
      }

      const keyId = parameters.keyid;
      if (!keyId) {
        return withFailure('PRECONDITION', 'Missing "keyid" signature parameter');
      }

      if (keyId !== apiKey) {
        return withFailure('PRECONDITION', 'X-API-KEY header field and signature keyid mismatch');
      }

      const secret = secretService.getSecretForKey(keyId);
      if (!secret || secret.length === 0) {
        return withFailure('PRECONDITION', `No secret found for keyid="${keyId}"`);
      }

      return { code: 'GOODKEY', key: secret };
    },
  });

  // If client didn't sign, accept (optional behavior from original reference)
  if (result.code === 'UNSIGNED') {
    return { code: 'VERIFIED' };
  }

  return result;
}
