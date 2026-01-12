/*
 * This class provides the authentication process the secret for a given key.
 * In this implementation, we load the key/secret from environment variables.
 */

export class SecretService {
  private secrets = new Map<string, Uint8Array>();

  constructor() {
    // Prefer the GENESYS_* variables (what you're already setting in Render),
    // but also support AUDIOHOOK_* as fallback.
    const keyId =
      process.env.GENESYS_AUDIO_CONNECTOR_KEY_ID ||
      process.env.AUDIOHOOK_API_KEY ||
      '';

    const secretB64 =
      process.env.GENESYS_AUDIO_CONNECTOR_SECRET ||
      process.env.AUDIOHOOK_CLIENT_SECRET ||
      '';

    if (!keyId) {
      console.warn(
        'SecretService: Missing key id env var (GENESYS_AUDIO_CONNECTOR_KEY_ID or AUDIOHOOK_API_KEY).'
      );
    }

    if (!secretB64) {
      console.warn(
        'SecretService: Missing secret env var (GENESYS_AUDIO_CONNECTOR_SECRET or AUDIOHOOK_CLIENT_SECRET).'
      );
    }

    // Genesys expects the "Client Secret" to be base64-encoded.
    // We must decode it to raw bytes for HMAC verification.
    if (keyId && secretB64) {
      try {
        const secretBytes = Buffer.from(secretB64, 'base64');
        this.secrets.set(keyId, secretBytes);
        console.log(`SecretService: Loaded secret for keyId="${keyId}" (${secretBytes.length} bytes).`);
      } catch (e) {
        console.error('SecretService: Failed to base64-decode secret.', e);
      }
    }
  }

  getSecretForKey(key: string): Uint8Array {
    const secret = this.secrets.get(key);
    if (!secret) {
      // This log is VERY useful: it will show what keyid Genesys is using vs what you loaded.
      console.error(
        `SecretService: No secret found for key="${key}". Loaded keys: [${Array.from(
          this.secrets.keys()
        ).join(', ')}]`
      );
      return Buffer.from('');
    }

    return secret;
  }
}
