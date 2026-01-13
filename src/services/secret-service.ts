/**
 * SecretService resolves the HMAC secret for a given keyid (x-api-key).
 * Genesys Audio Connector "Client Secret" is base64-encoded — we must decode it.
 */
export class SecretService {
  getSecretForKey(key: string): Uint8Array {
    const envKey = (process.env.GENESYS_AUDIO_CONNECTOR_KEY_ID ??
      process.env.AUDIOHOOK_API_KEY ??
      '').trim();

    const envSecretB64 = (process.env.GENESYS_AUDIO_CONNECTOR_SECRET ??
      process.env.AUDIOHOOK_CLIENT_SECRET ??
      '').trim();

    console.log('SecretService: envKey =', envKey);
    console.log('SecretService: got key =', key);
    console.log('SecretService: secretB64 length =', envSecretB64.length);

    // Missing env vars
    if (!envKey || !envSecretB64) {
      console.log('SecretService: missing envKey or envSecretB64');
      return new Uint8Array();
    }

    // Key mismatch
    if (key !== envKey) {
      console.log('SecretService: key mismatch');
      return new Uint8Array();
    }

    // Decode base64 -> bytes (THIS IS THE IMPORTANT PART)
    try {
      const decoded = Buffer.from(envSecretB64, 'base64');

      console.log('SecretService: decoded length =', decoded.length);

      // If decode failed, Node may return empty buffer
      if (!decoded || decoded.length === 0) {
        console.log('SecretService: decoded secret is empty (bad base64?)');
        return new Uint8Array();
      }

      return decoded;
    } catch (e) {
      console.log('SecretService: base64 decode failed', e);
      return new Uint8Array();
    }
  }
}
