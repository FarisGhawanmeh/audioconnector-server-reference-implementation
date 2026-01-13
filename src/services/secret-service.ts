/**
 * SecretService resolves the HMAC secret for a given keyid (x-api-key).
 * Genesys provides the secret as BASE64 in the integration UI — we must decode it.
 */

export class SecretService {
  getSecretForKey(key: string): Uint8Array {
    // Support either naming scheme (you added both in Render)
    const envKey =
      (process.env.GENESYS_AUDIO_CONNECTOR_KEY_ID ?? process.env.AUDIOHOOK_API_KEY ?? '').trim();
    const envSecretB64 =
      (process.env.GENESYS_AUDIO_CONNECTOR_SECRET ?? process.env.AUDIOHOOK_CLIENT_SECRET ?? '').trim();

    if (!envKey || !envSecretB64) {
      // No env configured
      return new Uint8Array();
    }

    if (key !== envKey) {
      // keyid mismatch
      return new Uint8Array();
    }

    try {
      // IMPORTANT: decode base64 to raw bytes for HMAC
      return Buffer.from(envSecretB64, 'base64');
    } catch {
      return new Uint8Array();
    }
  }
}
