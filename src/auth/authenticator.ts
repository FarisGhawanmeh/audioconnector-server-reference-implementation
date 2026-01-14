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

    // Must match exactly what Genesys lists in signature-input:
    // ("@request-target" "audiohook-session-id" "audiohook-organization-id"
    //  "audiohook-correlation-id" "x-api-key" "@authority")
    requiredComponents: [
      '@request-target',
      'audiohook-session-id',
      'audiohook-organization-id',
      'audiohook-correlation-id',
      'x-api-key',
      '@authority',
    ],

    maxSignatureAge: 10,

    // ✅ Genesys AudioHook usually expects @request-target to be the path ONLY
    // Example: "/openai-voice-bot"
    derivedComponentLookup: (name: any) => {
      if (name === '@request-target') {
        return request.url ?? null;
      }
      return null;
    },

    keyResolver: async (parameters: SignatureParameters) => {
      // nonce validations
      if (!parameters.nonce) {
        return withFailure('PRECONDITION', 'Missing "nonce" signature parameter');
      }
      if (parameters.nonce.length < 22) {
        return withFailure(
          'PRECONDITION',
          'Provided "nonce" signature parameter is too small'
        );
      }

      // keyid validations
      const keyId = parameters.keyid;
      if (!keyId) {
        return withFailure('PRECONDITION', 'Missing "keyid" signature parameter');
      }

      // Must match x-api-key header
      if (keyId !== apiKey) {
        return withFailure(
          'PRECONDITION',
          'X-API-KEY header field and signature keyid mismatch'
        );
      }

      // Resolve secret (HMAC key bytes)
      const secret = secretService.getSecretForKey(keyId);
      if (!secret || secret.length === 0) {
        return withFailure('PRECONDITION', `No secret found for keyid="${keyId}"`);
      }

      return { code: 'GOODKEY', key: secret };
    },
  });

  // Helpful log
  console.log('VERIFY RESULT:', result);

  // If not signed (some clients), accept – keep or remove حسب رغبتك
  if (result.code === 'UNSIGNED') {
    return { code: 'VERIFIED' };
  }

  return result;
}
