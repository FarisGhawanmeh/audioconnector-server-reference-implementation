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

// Maximum clock skew we allow between the client and server clock.
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

// https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-message-signatures-11#section-6.4
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

export type VerifyResultSuccess = {
  code: 'VERIFIED';
};

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

function b64UrlToStd(b64: string): string {
  // convert base64url -> base64
  return b64.replace(/-/g, '+').replace(/_/g, '/');
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
          return withFailure('INVALID', `Invalid "signature-input" header field value (unknown parameter ${encodeBareItem(key)})`);
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
  const seen = new Set<string>();
  const inputLines: string[] = [];

  for (const { name, params } of components) {
    const encoded = encodeItem({ value: name, params });

    if (seen.has(encoded)) return withFailure('INVALID', `Duplicate ${encoded} component reference`);
    seen.add(encoded);

    let resolved: string | null = null;

    if (name.startsWith('@')) {
      resolved =
        derivedComponentLookup?.(name as DerivedComponentTag) ??
        (name === '@authority' ? queryCanonicalizedHeaderField(headerFields, 'host') : null);

      if (!resolved) return withFailure('PRECONDITION', `Cannot resolve reference to ${encoded} component`);
    } else {
      resolved = queryCanonicalizedHeaderField(headerFields, name);
      if (!resolved) return withFailure('PRECONDITION', `Header field ${encodeBareItem(name)} not present`);
    }

    inputLines.push(`${encodeItem({ value: name, params })}: ${resolved}`);
    remaining.delete(name);
  }

  if (remaining.size) {
    return withFailure(
      'PRECONDITION',
      `Signature does not cover required component(s): ${[...remaining].map(encodeBareItem).join(',')}`
    );
  }

  inputLines.push(`"@signature-params": ${encodeInnerList(signatureBase)}`);
  const signingData = inputLines.join('\n');

  // ==========================
  // DEBUG PRINT
  // ==========================
  console.log('===== SIGNATURE DEBUG =====');
  console.log('keyid:', parameters.keyid);
  console.log('alg:', parameters.alg);
  console.log('created:', parameters.created);
  console.log('expires:', parameters.expires);
  console.log('----- SIGNING DATA START -----');
  console.log(signingData);
  console.log('----- SIGNING DATA END -----');
  console.log('=============================');

  const resolverResult = await keyResolver(parameters);
  if (resolverResult.code !== 'GOODKEY' && resolverResult.code !== 'BADKEY') return resolverResult;

  const alg = resolverResult.alg ?? parameters.alg ?? 'hmac-sha256';
  if (alg !== 'hmac-sha256') {
    return withFailure('UNSUPPORTED', `Signature algorithm ${encodeBareItem(alg)} is not supported`);
  }

  const receivedB64 = Buffer.from(signature).toString('base64');

  // ==========================================
  // KEY / AUTHORITY brute candidates
  // ==========================================
  const secretBytes = Buffer.from(resolverResult.key);

  // IMPORTANT:
  // resolverResult.key might already be decoded bytes OR might be raw text bytes depending on your SecretService.
  // We'll try multiple interpretations anyway.
  const keyCandidates: Array<{ label: string; key: Uint8Array }> = [
    { label: 'key:as-is', key: secretBytes },

    // treat as utf8 text
    { label: 'key:utf8(text)->bytes', key: Buffer.from(secretBytes.toString('utf8'), 'utf8') },

    // treat as base64 string (NO decode in SecretService case)
    { label: 'key:as-base64-string-bytes', key: Buffer.from(secretBytes.toString('utf8'), 'utf8') },

    // try decoding that utf8 as base64
    {
      label: 'key:decode-base64(utf8)',
      key: (() => {
        try {
          return Buffer.from(secretBytes.toString('utf8'), 'base64');
        } catch {
          return Buffer.alloc(0);
        }
      })(),
    },

    // try decoding base64url -> base64 -> bytes
    {
      label: 'key:decode-base64url(utf8)',
      key: (() => {
        try {
          return Buffer.from(b64UrlToStd(secretBytes.toString('utf8')), 'base64');
        } catch {
          return Buffer.alloc(0);
        }
      })(),
    },
  ].filter((k) => k.key.length > 0);

  const lines = signingData.split('\n');

  const rtIndex = lines.findIndex((l) => l.startsWith('"@request-target": '));
  const authIndex = lines.findIndex((l) => l.startsWith('"@authority": '));

  const rtValue = rtIndex >= 0 ? lines[rtIndex].replace('"@request-target": ', '') : null;
  const authValue = authIndex >= 0 ? lines[authIndex].replace('"@authority": ', '') : null;

  const requestTargetCandidates = rtValue
    ? [rtValue, `get ${rtValue}`, `GET ${rtValue}`]
    : [];

  const authorityCandidates = authValue
    ? [authValue, `${authValue}:443`]
    : [];

  console.log('===== BRUTE DEBUG =====');
  console.log('received (base64):', receivedB64);
  console.log('request-target candidates:', requestTargetCandidates);
  console.log('authority candidates:', authorityCandidates);
  console.log('key candidates:', keyCandidates.map((k) => k.label));
  console.log('=======================');

  for (const rt of requestTargetCandidates) {
    for (const au of authorityCandidates) {
      const variantLines = [...lines];
      if (rtIndex >= 0) variantLines[rtIndex] = `"@request-target": ${rt}`;
      if (authIndex >= 0) variantLines[authIndex] = `"@authority": ${au}`;
      const variantSigningData = variantLines.join('\n');

      for (const kc of keyCandidates) {
        const computed = createHmac('sha256', kc.key).update(variantSigningData).digest();
        const computedB64 = Buffer.from(computed).toString('base64');

        console.log(`[try] ${kc.label} | rt="${rt}" | auth="${au}" | computed=${computedB64}`);

        if (computedB64 === receivedB64) {
          console.log('✅ MATCH FOUND:', { key: kc.label, requestTarget: rt, authority: au });
          return resolverResult.code === 'GOODKEY'
            ? { code: 'VERIFIED' }
            : withFailure('FAILED', 'Signatures do not match (BADKEY)');
        }
      }
    }
  }

  console.log('❌ NO MATCH across candidates');

  // fallback normal compare
  const computedSignature = createHmac('sha256', resolverResult.key).update(signingData).digest();

  console.log('RECEIVED signature (base64):', receivedB64);
  console.log('COMPUTED signature (base64):', Buffer.from(computedSignature).toString('base64'));

  if (timingSafeEqual(signature, computedSignature)) {
    return resolverResult.code === 'GOODKEY' ? { code: 'VERIFIED' } : withFailure('FAILED', 'Signatures do not match');
  }

  return withFailure('FAILED', 'Signatures do not match');
};
