export type JsonObject = Record<string, unknown>;
export type KeyInfo = { secret?: string; verified?: boolean };

export type JwsAlg = {
  name: string;
  hash: string;
  secret?: true;
  spki?: true;
  pkcs8?: true;
  curve?: string;
  salt?: number;
};

export const JWS: Record<string, JwsAlg> = {
  HS256: { name: 'HMAC', hash: 'SHA-256', secret: true },
  HS384: { name: 'HMAC', hash: 'SHA-384', secret: true },
  HS512: { name: 'HMAC', hash: 'SHA-512', secret: true },
  RS256: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256', spki: true, pkcs8: true },
  RS384: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-384', spki: true, pkcs8: true },
  RS512: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-512', spki: true, pkcs8: true },
  PS256: { name: 'RSA-PSS', hash: 'SHA-256', spki: true, pkcs8: true, salt: 32 },
  PS384: { name: 'RSA-PSS', hash: 'SHA-384', spki: true, pkcs8: true, salt: 48 },
  PS512: { name: 'RSA-PSS', hash: 'SHA-512', spki: true, pkcs8: true, salt: 64 },
  ES256: { name: 'ECDSA', hash: 'SHA-256', spki: true, pkcs8: true, curve: 'P-256' },
  ES384: { name: 'ECDSA', hash: 'SHA-384', spki: true, pkcs8: true, curve: 'P-384' },
  ES512: { name: 'ECDSA', hash: 'SHA-512', spki: true, pkcs8: true, curve: 'P-521' },
};

export function algInfo(alg: string): JwsAlg {
  const a = JWS[alg];
  if (!a) throw new Error('Unsupported algorithm: ' + alg);
  return a;
}

const textEnc = new TextEncoder();
const textDec = new TextDecoder();
const B64URL_RE = /^[A-Za-z0-9_-]+={0,2}$/;

export function bytesToB64url(bytes: Uint8Array): string {
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function strToB64url(str: string): string {
  return bytesToB64url(textEnc.encode(str));
}

export function b64urlToBytes(seg: string): Uint8Array<ArrayBuffer> {
  let s = String(seg).replace(/-/g, '+').replace(/_/g, '/').replace(/\s+/g, '');
  while (s.length % 4) s += '=';
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function b64urlToString(seg: string): string {
  return textDec.decode(b64urlToBytes(seg));
}

export function decodeSegment(seg: string, what: string): string {
  const s = String(seg).replace(/\s+/g, '');
  if (!B64URL_RE.test(s)) throw new Error(what + ' is not valid base64url (unexpected characters).');
  try {
    return b64urlToString(s);
  } catch {
    throw new Error(what + ' could not be base64url-decoded.');
  }
}

export function decodeSigBytes(seg: string): Uint8Array<ArrayBuffer> {
  const s = String(seg).replace(/\s+/g, '').replace(/=+$/, '');
  if (!B64URL_RE.test(s + '=')) throw new Error('Signature is not valid base64url (unexpected characters).');
  try {
    return b64urlToBytes(s);
  } catch {
    throw new Error('Signature could not be base64url-decoded.');
  }
}

export function pemToDer(pem: string): ArrayBuffer {
  const body = String(pem)
    .replace(/-----BEGIN [^-]+-----/g, '')
    .replace(/-----END [^-]+-----/g, '')
    .replace(/\s+/g, '');
  if (!body) throw new Error('Empty PEM key.');
  const bytes = b64urlToBytes(body.replace(/\+/g, '-').replace(/\//g, '_'));
  return bytes.buffer as ArrayBuffer;
}

export function derToPem(buffer: ArrayBuffer, label: string): string {
  const bytes = new Uint8Array(buffer);
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  const b64 = btoa(bin).replace(/(.{64})/g, '$1\n').replace(/\n$/, '');
  return '-----BEGIN ' + label + '-----\n' + b64 + '\n-----END ' + label + '-----';
}

export function isPem(s: string): boolean {
  return /-----BEGIN/.test(s);
}

function paramsFor(alg: string): AlgorithmIdentifier | RsaPssParams | EcdsaParams {
  const a = algInfo(alg);
  if (a.name === 'RSA-PSS') return { name: 'RSA-PSS', saltLength: a.salt };
  if (a.name === 'ECDSA') return { name: 'ECDSA', hash: a.hash };
  return { name: a.name };
}

function importParams(alg: string): AlgorithmIdentifier | HmacImportParams | RsaHashedImportParams | EcKeyImportParams {
  const a = algInfo(alg);
  if (a.secret) return { name: 'HMAC', hash: a.hash };
  if (a.name === 'ECDSA') return { name: 'ECDSA', namedCurve: a.curve! };
  return { name: a.name, hash: a.hash } as RsaHashedImportParams;
}

export async function importKey(alg: string, keyText: string, usage: KeyUsage): Promise<CryptoKey> {
  const a = algInfo(alg);
  if (a.secret) {
    return crypto.subtle.importKey('raw', textEnc.encode(keyText), importParams(alg), false, [usage]);
  }
  const der = pemToDer(keyText);
  const format = usage === 'sign' ? 'pkcs8' : 'spki';
  return crypto.subtle.importKey(format, der, importParams(alg), false, [usage]);
}

export async function verifySigned(raw: string, alg: string, key: CryptoKey): Promise<boolean> {
  const parts = raw.split('.');
  const data = textEnc.encode(parts[0] + '.' + parts[1]);
  return crypto.subtle.verify(paramsFor(alg), key, decodeSigBytes(parts[2]), data);
}

export async function signJwt(alg: string, keyText: string, header: JsonObject, payload: JsonObject): Promise<string> {
  header.alg = alg;
  const data = strToB64url(JSON.stringify(header)) + '.' + strToB64url(JSON.stringify(payload));
  if (alg === 'none') return data + '.';
  const text = keyText.trim();
  if (!text) throw new Error(alg.startsWith('HS') ? 'Enter a secret.' : 'Paste a PEM private key (or generate a key pair).');
  const key = await importKey(alg, text, 'sign');
  const sig = await crypto.subtle.sign(paramsFor(alg), key, textEnc.encode(data));
  return data + '.' + bytesToB64url(new Uint8Array(sig));
}

export async function verifyTokenWithKey(token: string, alg: string, keyText: string): Promise<boolean> {
  const p = String(token).split('.');
  if (p.length !== 3) throw new Error('Not a three-part JWT.');
  return verifySigned(String(token), alg, await importKey(alg, keyText, 'verify'));
}

export async function publicKeyFromPrivatePem(alg: string, privPem: string): Promise<string> {
  const algo = importParams(alg);
  const priv = await crypto.subtle.importKey('pkcs8', pemToDer(privPem), algo, true, ['sign']);
  const jwk = await crypto.subtle.exportKey('jwk', priv);
  for (const k of ['d', 'dp', 'dq', 'q', 'qi', 'p']) delete (jwk as Record<string, unknown>)[k];
  jwk.key_ops = ['verify'];
  const pub = await crypto.subtle.importKey('jwk', jwk, algo, true, ['verify']);
  return derToPem(await crypto.subtle.exportKey('spki', pub), 'PUBLIC KEY');
}

export async function roundTripVerify(token: string, alg: string, keyText: string): Promise<boolean> {
  const verifyKey = alg.startsWith('HS') ? keyText : await publicKeyFromPrivatePem(alg, keyText);
  return verifyTokenWithKey(token, alg, verifyKey);
}
