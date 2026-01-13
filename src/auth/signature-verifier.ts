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
    signatureFields = querySignatureHeaderField(headerFields, 'signature');
  } catch {
    return withFailure('INVALID', 'Failed to parse signature headers');
  }

  if (!signatureInputFields.size || !signatureFields.size) {
    return withFailure('UNSIGNED', 'Missing signature headers');
  }

  const [label, signatureBase] = signatureInputFields.entries().next().value;
  const signatureItem = signatureFields.get(label);

  if (!signatureItem || !isItem(signatureItem) || !isByteSequence(signatureItem.value)) {
    return withFailure('INVALID', 'Invalid signature value');
  }

  if (!isInnerList(signatureBase)) {
    return withFailure('INVALID', 'Invalid signature-input structure');
  }

  const parameters: SignatureParameters = {};
  for (const { key, value } of signatureBase.params ?? []) {
    if (key === 'keyid' && isString(value)) parameters.keyid = value;
    if (key === 'nonce' && isString(value)) parameters.nonce = value;
    if (key === 'created' && isInteger(value)) parameters.created = value;
    if (key === 'expires' && isInteger(value)) parameters.expires = value;
    if (key === 'alg' && isString(value)) parameters.alg = value;
  }

  const now = Date.now() / 1000;
  if (parameters.expires && parameters.expires < now + MAX_CLOCK_SKEW) {
    return withFailure('EXPIRED');
  }

  const inputLines: string[] = [];
  const remaining = new Set(requiredComponents);

  for (const { value, params } of signatureBase.value) {
    if (!isString(value)) {
      return withFailure('INVALID', 'Invalid signature component');
    }

    if (params) {
      const ok = params.every(({ key, value }) => {
        const validator = (signatureComponentParameterValidator as any)[key];
        return typeof validator === 'function' && validator(value);
      });
      if (!ok) return withFailure('INVALID', 'Invalid component parameters');
    }

    let resolved: string | null = null;

    if (value.startsWith('@')) {
      resolved =
        derivedComponentLookup?.(value as DerivedComponentTag) ??
        (value === '@authority' ? queryCanonicalizedHeaderField(headerFields, 'host') : null);
    } else {
      resolved = queryCanonicalizedHeaderField(headerFields, value);
    }

    if (!resolved) {
      return withFailure('PRECONDITION', `Missing component ${value}`);
    }

    inputLines.push(`${encodeItem({ value, params })}: ${resolved}`);
    remaining.delete(value);
  }

  if (remaining.size) {
    return withFailure('PRECONDITION', 'Missing required components');
  }

  inputLines.push(`"@signature-params": ${encodeInnerList(signatureBase)}`);
  const signingData = inputLines.join('\n');

  const resolverResult = await keyResolver(parameters);
  if (resolverResult.code !== 'GOODKEY') {
    return withFailure('FAILED', 'Invalid key');
  }

  const computed = createHmac('sha256', resolverResult.key).update(signingData).digest();

  return timingSafeEqual(signatureItem.value, computed)
    ? { code: 'VERIFIED' }
    : withFailure('FAILED', 'Signatures do not match');
};
