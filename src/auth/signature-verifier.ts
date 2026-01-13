import { createHmac, timingSafeEqual } from 'crypto';
import {
  BareItem,
  Dictionary,
  encodeBareItem,
  encodeInnerList,
  encodeItem,
  InnerList,
  isBoolean,
  isByteSequence,
  isInnerList,
  isInteger,
  isItem,
  isString,
  parseDictionaryField,
} from './structured-fields';

const MAX_CLOCK_SKEW = 3;

export type HeaderFields = Record<string, string | string[] | undefined>;

const derivedComponents = [
  '@method',
  '@authority',
  '@scheme',
  '@target-uri',
  '@request-target',
  '@path',
  '@query',
  '@status',
] as const;

export type DerivedComponentTag = (typeof derivedComponents)[number];

export type SignatureParameters = {
  alg?: string;
  created?: number;
  expires?: number;
  keyid?: string;
  nonce?: string;
};

export type SignatureComponentParameter =
  | { key: 'key'; value: string }
  | { key: 'name'; value: string }
  | { key: 'sf'; value: boolean }
  | { key: 'bs'; value: boolean }
  | { key: 'req'; value: boolean };

const signatureComponentParameterValidator: {
  [K in SignatureComponentParameter['key']]: (arg: BareItem) => boolean;
} = {
  key: isString,
  name: isString,
  sf: isBoolean,
  bs: isBoolean,
  req: isBoolean,
};

export type SignatureComponent = {
  name: string;
  params?: SignatureComponentParameter[];
};

export type SignatureInfo = {
  readonly label: string;
  readonly parameters: SignatureParameters;
  readonly components: SignatureComponent[];
  readonly signatureBase: InnerList;
  readonly signature: Uint8Array;
};

export type VerifyResultCode =
  | 'VERIFIED'
  | 'FAILED'
  | 'UNSIGNED'
  | 'EXPIRED'
  | 'INVALID'
  | 'PRECONDITION'
  | 'UNSUPPORTED';

export type VerifyResultFailureCode = Exclude<VerifyResultCode, 'VERIFIED'>;

export type VerifyResultFailure = {
  code: VerifyResultFailureCode;
  reason?: string;
};

export type VerifyResultSuccess = { code: 'VERIFIED' };

export type VerifyResult = VerifyResultFailure | VerifyResultSuccess;

export const withFailure = (code: VerifyResultFailureCode, reason?: string): VerifyResultFailure => ({
  code,
  reason,
});

export type SignatureSelector = (signatures: SignatureInfo[]) => string | null;
export type ExpirationTimeProvider = (parameters: SignatureParameters) => number;
export type DerivedComponentLookup = (name: DerivedComponentTag) => string | null;

export type KeyResolverResult =
  | { code: 'GOODKEY'; key: Uint8Array; alg?: string }
  | { code: 'BADKEY'; key: Uint8Array; alg?: string }
  | VerifyResultFailure;

export type KeyResolver = (parameters: SignatureParameters) => Promise<KeyResolverResult> | KeyResolverResult;

export type VerifierOptions = {
  headerFields: HeaderFields;
  requiredComponents?: string[];
  maxSignatureAge?: number;
  signatureSelector?: SignatureSelector;
  expirationTimeProvider?: ExpirationTimeProvider;
  derivedComponentLookup?: DerivedComponentLookup;
  keyResolver: KeyResolver;
};

export const canonicalizeHeaderFieldValue = (value: string): string =>
  value.trim().replace(/[ \t]*\r\n[ \t]+/g, ' ');

export const queryCanonicalizedHeaderField = (headers: HeaderFields, name: string): string | null => {
  const field = headers[name];
  return field
    ? Array.isArray(field)
      ? field.map(canonicalizeHeaderFieldValue).join(', ')
      : canonicalizeHeaderFieldValue(field)
    : null;
};

const querySignatureHeaderField = (headers: HeaderFields, name: string): Dictionary => {
  const value = headers[name];
  return value ? parseDictionaryField(value) : new Map();
};

// ✅ try multiple encodings of the env secret
function getCandidateKeysFromEnv(): { label: string; key: Uint8Array }[] {
  const secret = (
    process.env.GENESYS_AUDIO_CONNECTOR_SECRET ??
    process.env.AUDIOHOOK_CLIENT_SECRET ??
    ''
  ).trim();

  if (!secret) return [];

  const keys: { label: string; key: Uint8Array }[] = [];

  // raw utf8
  keys.push({ label: 'utf8', key: Buffer.from(secret, 'utf8') });

  // base64
  try {
    const b = Buffer.from(secret, 'base64');
    if (b.length > 0) keys.push({ label: 'base64', key: b });
  } catch {}

  // base64url
  try {
    let s = secret.replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4 !== 0) s += '=';
    const b = Buffer.from(s, 'base64');
    if (b.length > 0) keys.push({ label: 'base64url', key: b });
  } catch {}

  // hex
  try {
    if (/^[0-9a-fA-F]+$/.test(secret) && secret.length % 2 === 0) {
      const b = Buffer.from(secret, 'hex');
      if (b.length > 0) keys.push({ label: 'hex', key: b });
    }
  } catch {}

  // de-dup
  const seen = new Set<string>();
  const out: { label: string; key: Uint8Array }[] = [];
  for (const k of keys) {
    const fp = Buffer.from(k.key).toString('base64');
    if (!seen.has(fp)) {
      seen.add(fp);
      out.push(k);
    }
  }
  return out;
}

export const verifySignature = async (options: VerifierOptions): Promise<VerifyResult> => {
  const {
    headerFields,
    requiredComponents = [],
    maxSignatureAge,
    signatureSelector,
    derivedComponentLookup,
    keyResolver,
  } = options;

  let signatureInputFields: Dictionary;
  let signatureFields: Dictionary;

  try {
    signatureInputFields = querySignatureHeaderField(headerFields, 'signature-input');
  } catch {
    return withFailure('INVALID', 'Failed to parse "signature-input" header field');
  }
  try {
    signatureFields = querySignatureHeaderField(headerFields, 'signature');
  } catch {
    return withFailure('INVALID', 'Failed to parse "signature" header field');
  }

  if (signatureInputFields.size === 0) {
    if (signatureFields.size === 0) return withFailure('UNSIGNED', 'No "signature" and "signature-input" header fields');
    return withFailure('INVALID', 'Found "signature" but no "signature-input" header field');
  }
  if (signatureFields.size === 0) return withFailure('INVALID', 'Found "signature-input" but no "signature" header field');

  const signatures: SignatureInfo[] = [];

  for (const [label, signatureBase] of signatureInputFields) {
    const signatureItem = signatureFields.get(label);

    if (!signatureItem) return withFailure('INVALID', `Signature with label ${encodeBareItem(label)} not found`);
    if (!isItem(signatureItem) || !isByteSequence(signatureItem.value)) {
      return withFailure('INVALID', `Invalid "signature" header field value (label: ${encodeBareItem(label)})`);
    }
    if (!isInnerList(signatureBase)) {
      return withFailure('INVALID', `Invalid "signature-input" header field value for label ${encodeBareItem(label)}`);
    }

    const components: SignatureComponent[] = [];
    for (const { value, params } of signatureBase.value) {
      if (!isString(value)) return withFailure('INVALID', 'Invalid "signature-input" header field value');

      if (params) {
        const ok = params.every(({ key, value }) => {
          const validator = (signatureComponentParameterValidator as any)[key];
          return typeof validator === 'function' ? validator(value) : false;
        });
        if (!ok) return withFailure('INVALID', `Invalid signature component: ${encodeItem({ value, params })}`);
        components.push({ name: value, params: params as SignatureComponentParameter[] });
      } else {
        components.push({ name: value });
      }
    }

    if (!signatureBase.params) return withFailure('INVALID', 'Invalid "signature-input" header field value (no parameters)');

    const parameters: SignatureParameters = {};
    for (const { key, value } of signatureBase.params) {
      switch (key) {
        case 'alg':
          if (!isString(value)) return withFailure('INVALID', 'Invalid "alg" parameter');
          parameters.alg = value;
          break;
        case 'created':
          if (!isInteger(value) || value < 0) return withFailure('INVALID', 'Invalid "created" parameter');
          parameters.created = value;
          break;
        case 'expires':
          if (!isInteger(value) || value < 0) return withFailure('INVALID', 'Invalid "expires" parameter');
          parameters.expires = value;
          break;
        case 'keyid':
          if (!isString(value)) return withFailure('INVALID', 'Invalid "keyid" parameter');
          parameters.keyid = value;
          break;
        case 'nonce':
          if (!isString(value)) return withFailure('INVALID', 'Invalid "nonce" parameter');
          parameters.nonce = value;
          break;
        default:
          return withFailure('INVALID', `Unknown parameter ${encodeBareItem(key)}`);
      }
    }

    signatures.push({
      label,
      parameters,
      components,
      signatureBase,
      signature: signatureItem.value,
    });
  }

  const chosenLabel = signatureSelector ? signatureSelector(signatures) : signatures[0].label;
  if (!chosenLabel) return withFailure('PRECONDITION', 'Multiple signatures and none met selection criteria');

  const chosen = signatures.find((x) => x.label === chosenLabel) ?? signatures[0];
  const { parameters, components, signatureBase, signature } = chosen;

  // Expiration checks
  if (parameters.created || parameters.expires || maxSignatureAge) {
    const now = options.expirationTimeProvider?.(parameters) ?? Date.now() / 1000;
    if (parameters.created && parameters.created > now + MAX_CLOCK_SKEW) {
      return withFailure('PRECONDITION', 'Invalid "created" parameter value (time in the future)');
    }
    if (parameters.expires && parameters.expires < now + MAX_CLOCK_SKEW) {
      return withFailure('EXPIRED');
    }
    if (maxSignatureAge) {
      if (!parameters.created) return withFailure('PRECONDITION', 'Cannot determine signature age (no "created")');
      if (parameters.created + maxSignatureAge < now + MAX_CLOCK_SKEW) return withFailure('EXPIRED');
    }
  }

  // Build signing string
  const remaining = new Set(requiredComponents);
  const inputLines: string[] = [];
  const seen = new Set<string>();

  for (const { name, params } of components) {
    const encoded = encodeItem({ value: name, params });
    if (seen.has(encoded)) return withFailure('INVALID', `Duplicate ${encoded} component reference`);
    seen.add(encoded);

    let resolved: string | null = null;

    if (name.startsWith('@')) {
      resolved =
        derivedComponentLookup?.(name as DerivedComponentTag) ??
        (name === '@authority' ? queryCanonicalizedHeaderField(headerFields, 'host') : null);

      if (!resolved) return withFailure('PRECONDITION', `Cannot resolve reference to ${encoded}`);
    } else {
      resolved = queryCanonicalizedHeaderField(headerFields, name);
      if (!resolved) return withFailure('PRECONDITION', `Header field ${encodeBareItem(name)} not present`);
    }

    inputLines.push(`${encodeItem({ value: name, params })}: ${resolved}`);
    remaining.delete(name);
  }

  if (remaining.size) {
    return withFailure('PRECONDITION', `Missing required components: ${[...remaining].map(encodeBareItem).join(',')}`);
  }

  inputLines.push(`"@signature-params": ${encodeInnerList(signatureBase)}`);
  const signingData = inputLines.join('\n');

  console.log('===== SIGNATURE DEBUG =====');
  console.log('keyid:', parameters.keyid);
  console.log('alg:', parameters.alg);
  console.log('created:', parameters.created);
  console.log('expires:', parameters.expires);
  console.log('----- SIGNING DATA START -----');
  console.log(signingData);
  console.log('----- SIGNING DATA END -----');

  const resolverResult = await keyResolver(parameters);
  if (resolverResult.code !== 'GOODKEY' && resolverResult.code !== 'BADKEY') return resolverResult;

  const alg = resolverResult.alg ?? parameters.alg ?? 'hmac-sha256';
  if (alg !== 'hmac-sha256') return withFailure('UNSUPPORTED', `Unsupported alg ${encodeBareItem(alg)}`);

  const computed = createHmac('sha256', resolverResult.key).update(signingData).digest();

  console.log('RECEIVED signature (base64):', Buffer.from(signature).toString('base64'));
  console.log('COMPUTED signature (base64):', Buffer.from(computed).toString('base64'));

  if (timingSafeEqual(signature, computed)) {
    return resolverResult.code === 'GOODKEY' ? { code: 'VERIFIED' } : withFailure('FAILED', 'Signatures do not match');
  }

  // ✅ Confirm fallback is running
  const candidates = getCandidateKeysFromEnv();
  console.log('DEBUG: candidates tried =', candidates.map((x) => x.label));

  for (const c of candidates) {
    const alt = createHmac('sha256', c.key).update(signingData).digest();
    if (timingSafeEqual(signature, alt)) {
      console.log('✅ SIGNATURE MATCHED using secret encoding:', c.label);
      return { code: 'VERIFIED' };
    }
  }

  return withFailure('FAILED', 'Signatures do not match');
};
