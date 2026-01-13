/**
 * SecretService resolves the HMAC secret for a given keyid (x-api-key).
 * Genesys Audio Connector "Client Secret" is base64-encoded — we must decode it.
 */
export class SecretService {
  getSecretForKey(keyId: string): Uint8Array {
    const envKeyId = (process.env.GENESYS_AUDIO_CONNECTOR_KEY_ID ?? process.env.AUDIOHOOK_API_KEY ?? '').trim();
    const envSecretB64 = (process.env.GENESYS_AUDIO_CONNECTOR_SECRET ?? process.env.AUDIOHOOK_CLIENT_SECRET ?? '').trim();

    if (!envKeyId || !envSecretB64) {
      console.error(
        'SecretService: Missing env vars. Need GENESYS_AUDIO_CONNECTOR_KEY_ID + GENESYS_AUDIO_CONNECTOR_SECRET (or AUDIOHOOK_API_KEY + AUDIOHOOK_CLIENT_SECRET).'
      );
      return new Uint8Array();
    }

    if (keyId !== envKeyId) {
      console.error(`SecretService: keyid mismatch. Got "${keyId}", expected "${envKeyId}".`);
      return new Uint8Array();
    }

    try {
      // IMPORTANT: decode base64 -> raw bytes for HMAC
      const decoded = Buffer.from(envSecretB64, 'base64');

      // quick sanity check (base64 decode should not be empty)
      if (!decoded || decoded.length === 0) {
        console.error('SecretService: base64 decoded secret is empty. Check the secret value.');
        return new Uint8Array();
      }

      return decoded;
    } catch (e) {
      console.error('SecretService: Failed to base64 decode secret.', e);
      return new Uint8Array();
    }
  }
}
