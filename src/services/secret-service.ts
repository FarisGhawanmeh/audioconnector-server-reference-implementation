/**
 * SecretService resolves the HMAC secret for a given keyid (x-api-key).
 *
 * IMPORTANT:
 * In many Genesys setups the "Client Secret" is a plain string (NOT base64),
 * so we must use it as raw UTF-8 bytes. Base64-decoding it will change the key
 * and cause "Signatures do not match".
 */
export class SecretService {
  getSecretForKey(key: string): Uint8Array {
    const envKey = (process.env.GENESYS_AUDIO_CONNECTOR_KEY_ID ?? process.env.AUDIOHOOK_API_KEY ?? '').trim();
    const envSecret = (process.env.GENESYS_AUDIO_CONNECTOR_SECRET ?? process.env.AUDIOHOOK_CLIENT_SECRET ?? '').trim();

    // (optional debug)
    console.log('SecretService: envKey =', envKey);
    console.log('SecretService: got key =', key);
    console.log('SecretService: secret length =', envSecret?.length ?? 0);

    if (!envKey || !envSecret) {
      return new Uint8Array();
    }

    if (key !== envKey) {
      return new Uint8Array();
    }

    // ✅ Use RAW secret bytes (utf8), not base64-decoded.
    return Buffer.from(envSecret, 'utf8');
  }
}
