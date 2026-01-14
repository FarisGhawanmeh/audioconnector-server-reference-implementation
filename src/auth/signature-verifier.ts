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
  return b64.replace(/-/g, '+').replace(/_/g, '/');
}

function stripSigLabel(rawSigInputHeader: string, label: string): string | null {
  // rawSigInputHeader example:
  // sig1=("<...>");created=...;...
  // return substring after "sig1="
  const needle = `${label}=`;
  const idx = rawSigInputHeader.indexOf(needle);
  if (idx < 0) return null;
  return rawSigInputHeader.slice(idx + needle.length);
}

type SigningVariant = {
  includeQuotesOnLeft: boolean; // '"header": value' vs 'header: value'
  requestTarget: string;
  authority: string;
  sigParamsLineValue: string; // value for @signature-params (after colon+space)
  eol: '\n' | '\r\n';
  trailingEol: boolean;
};

function buildSigningData(baseLines: string[], variant: SigningVariant): string {
  // baseLines are in canonical quoted-left format:
  // "@request-target": ...
  // "header": ...
  // "@signature-params": ...
  //
  // We patch @request-target, @authority, and @signature-params then optionally remove quotes on left.

  const lines = [...baseLines];

  const rtIdx = lines.findIndex((l) => l.startsWith('"@request-target": '));
  const auIdx = lines.findIndex((l) => l.startsWith('"@authority": '));
  const spIdx = lines.findIndex((l) => l.startsWith('"@signature-params": '));

  if (rtIdx >= 0) lines[rtIdx] = `"@request-target": ${variant.requestTarget}`;
  if (auIdx >= 0) lines[auIdx] = `"@authority": ${variant.authority}`;
  if (spIdx >= 0) lines[spIdx] = `"@signature-params": ${variant.sigParamsLineValue}`;

  let finalLines = lines;

  if (!variant.includeQuotesOnLeft) {
    // Turn:
    // "x-api-key": value
    // into:
    // x-api-key: value
    finalLines = lines.map((l) => {
      const m = l.match(/^"([^"]+)":\s(.*)$/);
      if (!m) return l;
      return `${m[1]}: ${m[2]}`;
    });
  }

  const joined = finalLines.join(variant.eol);
  return variant.trailingEol ? joined + variant.eol : joined;
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
          return withFailure(
            'INVALID',
            `Invalid "signature-input" header field value (unknown parameter ${encodeBareItem(key)})`
          );
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

  // Build canonical base signing string (quoted-left)
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

  // canonical @signature-params
  const canonicalSigParams = encodeInnerList(signatureBase);
  inputLines.push(`"@signature-params": ${canonicalSigParams}`);

  const canonicalSigningData = inputLines.join('\n');

  // ==========================
  // DEBUG PRINT (canonical)
  // ==========================
  console.log('===== SIGNATURE DEBUG =====');
  console.log('keyid:', parameters.keyid);
  console.log('alg:', parameters.alg);
  console.log('created:', parameters.created);
  console.log('expires:', parameters.expires);
  console.log('----- SIGNING DATA START -----');
  console.log(canonicalSigningData);
  console.log('----- SIGNING DATA END -----');
  console.log('=============================');

  const resolverResult = await keyResolver(parameters);
  if (resolverResult.code !== 'GOODKEY' && resolverResult.code !== 'BADKEY') return resolverResult;

  const alg = resolverResult.alg ?? parameters.alg ?? 'hmac-sha256';
  if (alg !== 'hmac-sha256') {
    return withFailure('UNSUPPORTED', `Signature algorithm ${encodeBareItem(alg)} is not supported`);
  }

  const receivedB64 = Buffer.from(signature).toString('base64');

  // Try raw ENV too (as you already do)
  const rawFromEnv =
    process.env.GENESYS_CLIENT_SECRET ??
    process.env.AUDIOHOOK_CLIENT_SECRET ??
    process.env.CLIENT_SECRET ??
    process.env.GENESYS_AUDIO_CONNECTOR_SECRET ??
    '';

  console.log('===== SECRET ENV DEBUG =====');
  console.log('rawFromEnv length:', rawFromEnv.length);
  console.log('rawFromEnv preview:', rawFromEnv ? rawFromEnv.slice(0, 6) + '...' + rawFromEnv.slice(-6) : '(empty)');
  console.log('============================');

  const rawTrim = rawFromEnv.trim();

  const keyCandidates: Array<{ label: string; key: Uint8Array }> = [
    { label: 'key:resolver(as-is)', key: Buffer.from(resolverResult.key) },

    ...(rawFromEnv ? [{ label: 'key:env(raw utf8 bytes)', key: Buffer.from(rawFromEnv, 'utf8') }] : []),
    ...(rawTrim && rawTrim !== rawFromEnv
      ? [{ label: 'key:env(raw utf8 bytes, trimmed)', key: Buffer.from(rawTrim, 'utf8') }]
      : []),

    ...(rawFromEnv ? [{ label: 'key:env(base64 decoded)', key: Buffer.from(rawFromEnv, 'base64') }] : []),
    ...(rawTrim && rawTrim !== rawFromEnv
      ? [{ label: 'key:env(base64 decoded, trimmed)', key: Buffer.from(rawTrim, 'base64') }]
      : []),

    ...(rawFromEnv
      ? [{ label: 'key:env(base64url decoded)', key: Buffer.from(b64UrlToStd(rawFromEnv), 'base64') }]
      : []),
    ...(rawTrim && rawTrim !== rawFromEnv
      ? [{ label: 'key:env(base64url decoded, trimmed)', key: Buffer.from(b64UrlToStd(rawTrim), 'base64') }]
      : []),
  ].filter((k) => k.key.length > 0);

  // Extract candidates for request-target / authority from canonical lines
  const baseLines = canonicalSigningData.split('\n');

  const rtLine = baseLines.find((l) => l.startsWith('"@request-target": ')) ?? '';
  const auLine = baseLines.find((l) => l.startsWith('"@authority": ')) ?? '';
  const rtValue = rtLine.replace('"@request-target": ', '');
  const auValue = auLine.replace('"@authority": ', '');

  const requestTargetCandidates = rtValue
    ? [rtValue, `get ${rtValue}`, `GET ${rtValue}`]
    : [];

  const authorityCandidates = auValue
    ? [auValue, `${auValue}:443`]
    : [];

  const eolCandidates: Array<{ label: string; eol: '\n' | '\r\n'; trailing: boolean }> = [
    { label: 'LF no-trailing', eol: '\n', trailing: false },
    { label: 'LF trailing', eol: '\n', trailing: true },
    { label: 'CRLF no-trailing', eol: '\r\n', trailing: false },
    { label: 'CRLF trailing', eol: '\r\n', trailing: true },
  ];

  // NEW: signature-params candidates (canonical vs raw from header)
  const sigInputHeaderRaw = typeof headerFields['signature-input'] === 'string'
    ? headerFields['signature-input']
    : Array.isArray(headerFields['signature-input'])
      ? headerFields['signature-input'][0]
      : undefined;

  const rawSigParams = sigInputHeaderRaw ? stripSigLabel(sigInputHeaderRaw, chosen.label) : null;

  const sigParamsCandidates: Array<{ label: string; value: string }> = [
    { label: 'sigparams:canonical', value: canonicalSigParams },
    ...(rawSigParams ? [{ label: 'sigparams:raw-from-header', value: rawSigParams }] : []),

    // some implementations might add a space after semicolons (rare, but quick to try)
    { label: 'sigparams:canonical(; space)', value: canonicalSigParams.replace(/;/g, '; ') },
    ...(rawSigParams ? [{ label: 'sigparams:raw(; space)', value: rawSigParams.replace(/;/g, '; ') }] : []),
  ];

  // NEW: quote-left variants
  const quoteLeftCandidates: Array<{ label: string; includeQuotesOnLeft: boolean }> = [
    { label: 'left:quoted', includeQuotesOnLeft: true },
    { label: 'left:unquoted', includeQuotesOnLeft: false },
  ];

  console.log('===== BRUTE DEBUG =====');
  console.log('received (base64):', receivedB64);
  console.log('request-target candidates:', requestTargetCandidates);
  console.log('authority candidates:', authorityCandidates);
  console.log('eol candidates:', eolCandidates.map((x) => x.label));
  console.log('sigparams candidates:', sigParamsCandidates.map((x) => x.label));
  console.log('left candidates:', quoteLeftCandidates.map((x) => x.label));
  console.log('key candidates:', keyCandidates.map((k) => k.label));
  console.log('=======================');

  for (const rt of requestTargetCandidates) {
    for (const au of authorityCandidates) {
      for (const sp of sigParamsCandidates) {
        for (const ql of quoteLeftCandidates) {
          for (const eol of eolCandidates) {
            const variant: SigningVariant = {
              includeQuotesOnLeft: ql.includeQuotesOnLeft,
              requestTarget: rt,
              authority: au,
              sigParamsLineValue: sp.value,
              eol: eol.eol,
              trailingEol: eol.trailing,
            };

            const variantSigningData = buildSigningData(baseLines, variant);

            for (const kc of keyCandidates) {
              const computed = createHmac('sha256', kc.key).update(variantSigningData).digest();
              const computedB64 = Buffer.from(computed).toString('base64');

              console.log(
                `[try] ${kc.label} | ${eol.label} | ${sp.label} | ${ql.label} | rt="${rt}" | auth="${au}" | computed=${computedB64}`
              );

              if (computedB64 === receivedB64) {
                console.log('✅ MATCH FOUND:', {
                  key: kc.label,
                  eol: eol.label,
                  sigparams: sp.label,
                  left: ql.label,
                  requestTarget: rt,
                  authority: au,
                });

                return resolverResult.code === 'GOODKEY'
                  ? { code: 'VERIFIED' }
                  : withFailure('FAILED', 'Signatures do not match (BADKEY)');
              }
            }
          }
        }
      }
    }
  }

  console.log('❌ NO MATCH across candidates');

  // fallback normal compare (canonical)
  const computedSignature = createHmac('sha256', resolverResult.key).update(canonicalSigningData).digest();

  console.log('RECEIVED signature (base64):', receivedB64);
  console.log('COMPUTED signature (base64):', Buffer.from(computedSignature).toString('base64'));

  if (timingSafeEqual(signature, computedSignature)) {
    return resolverResult.code === 'GOODKEY' ? { code: 'VERIFIED' } : withFailure('FAILED', 'Signatures do not match');
  }

  return withFailure('FAILED', 'Signatures do not match');
};
