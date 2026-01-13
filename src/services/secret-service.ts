/**
 * SecretService resolves the HMAC secret for a given keyid (x-api-key).
 * Genesys provides the secret as BASE64 in the integration UI — we must decode it.
 */
export class SecretService {
  getSecretForKey(key: string): Uint8Array {
    const envKey =
      (process.env.GENESYS_AUDIO_CONNECTOR_KEY_ID ?? process.env.AUDIOHOOK_API_KEY ?? "").trim();

    const envSecretB64 =
      (process.env.GENESYS_AUDIO_CONNECTOR_SECRET ?? process.env.AUDIOHOOK_CLIENT_SECRET ?? "").trim();

    console.log("SecretService: envKey =", envKey);
    console.log("SecretService: got key =", key);
    console.log("SecretService: secretB64 length =", envSecretB64.length);

    if (!envKey || !envSecretB64) {
      console.log("SecretService: missing env vars");
      return new Uint8Array();
    }

    if (key !== envKey) {
      console.log("SecretService: key mismatch");
      return new Uint8Array();
    }

    try {
      const decoded = Buffer.from(envSecretB64, "base64");
      console.log("SecretService: decoded length =", decoded.length);
      return decoded;
    } catch (e) {
      console.log("SecretService: base64 decode failed", e);
      return new Uint8Array();
    }
  }
}
