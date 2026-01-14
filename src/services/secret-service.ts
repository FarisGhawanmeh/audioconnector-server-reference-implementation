/**
 * SecretService resolves the HMAC secret for a given keyid (x-api-key).
 * Genesys Audio Connector "Client Secret" is base64-encoded — decode it to bytes.
 */
export class SecretService {
  getSecretForKey(_keyid: string): Uint8Array {
    const envSecretB64 = (
      process.env.GENESYS_CLIENT_SECRET ??
      process.env.GENESYS_AUDIO_CONNECTOR_SECRET ??
      process.env.AUDIOHOOK_CLIENT_SECRET ??
      process.env.CLIENT_SECRET ??
      ''
    ).trim();

    console.log('SecretService: secretB64 length =', envSecretB64.length);

    if (!envSecretB64) {
      console.log('SecretService: missing envSecretB64');
      return new Uint8Array();
    }

    try {
      const decoded = Buffer.from(envSecretB64, 'base64');
      console.log('SecretService: decoded length =', decoded.length);

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
