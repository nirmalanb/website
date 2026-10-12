import { $ } from 'domsure';
import { CLS } from './jwt-ui.ts';
import type { JsonObject, KeyInfo } from './jwt-crypto.ts';
import { algInfo, derToPem, isPem, roundTripVerify, signJwt, strToB64url } from './jwt-crypto.ts';
import { colorizeToken, esc, jsonError } from './jwt-view.ts';

const encHeader = $.required<HTMLTextAreaElement>('#encHeader');
const encPayload = $.required<HTMLTextAreaElement>('#encPayload');
const encAlg = $.required<HTMLSelectElement>('#encAlg');
const encKey = $.required<HTMLTextAreaElement>('#encKey');
const encPubKey = $.required<HTMLTextAreaElement>('#encPubKey');
const encOut = $.required('#encOut');
const encMsg = $.required('#encMsg');
const encHeaderError = $.required('#encHeaderError');
const encPayloadError = $.required('#encPayloadError');
let lastSignedToken = '';

function validateJsonFields(): void {
  const pairs: [HTMLTextAreaElement, HTMLElement][] = [
    [encHeader, encHeaderError],
    [encPayload, encPayloadError],
  ];
  for (const [field, slot] of pairs) {
    const err = jsonError(field.value);
    slot.textContent = err ?? '';
    if (err) field.setAttribute('aria-invalid', 'true');
    else field.removeAttribute('aria-invalid');
  }
}
encHeader.addEventListener('input', validateJsonFields);
encPayload.addEventListener('input', validateJsonFields);

const msgOk = (text: string) => '<div class="' + CLS.okmsg + '">' + text + '</div>';
const msgErr = (text: string) => '<div class="' + CLS.err + '">' + text + '</div>';

function encKeyLabelUpdate(): void {
  const alg = encAlg.value || 'HS256';
  if (alg === 'none') {
    $.required('#encKeyLabel').textContent = 'No key — alg: none emits an unsigned token';
    $.required('#btnGenKeys').classList.add('hidden');
    $.required('#pubKeyWrap').classList.add('hidden');
    encKey.value = '';
    encKey.placeholder = 'Not used for alg: none';
    return;
  }
  const isHMAC = alg.startsWith('HS');
  $.required('#encKeyLabel').textContent = isHMAC
    ? 'Secret (raw text or base64url)'
    : 'Private Key (PEM, ' +
      (alg.startsWith('PS') ? 'RSA-PSS' : alg.startsWith('RS') ? 'RSASSA-PKCS1-v1_5' : 'ECDSA ' + algInfo(alg).curve) +
      ')';
  $.required('#btnGenKeys').classList.toggle('hidden', isHMAC);
  $.required('#pubKeyWrap').classList.toggle('hidden', isHMAC);
  if (isHMAC && isPem(encKey.value)) encKey.value = 'a-string-secret-at-least-256-bits-long';
  if (!isHMAC && !isPem(encKey.value)) {
    encKey.value = '';
    encKey.placeholder = '-----BEGIN PRIVATE KEY-----\n…\n-----END PRIVATE KEY-----';
  }
  if (isHMAC && !encKey.value) encKey.value = 'a-string-secret-at-least-256-bits-long';
}

export async function signToken(): Promise<string> {
  const alg = encAlg.value || 'HS256';
  let header: JsonObject;
  let payload: JsonObject;
  try {
    header = JSON.parse(encHeader.value);
  } catch (e) {
    throw new Error('Header is not valid JSON: ' + (e as Error).message);
  }
  try {
    payload = JSON.parse(encPayload.value);
  } catch (e) {
    throw new Error('Payload is not valid JSON: ' + (e as Error).message);
  }
  if (!header || typeof header !== 'object' || Array.isArray(header)) throw new Error('Header must be a JSON object.');
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) throw new Error('Payload must be a JSON object.');

  const token = await signJwt(alg, encKey.value, header, payload);
  encHeader.value = JSON.stringify(header, null, 2);
  encOut.innerHTML = colorizeToken(token).replace(/\n$/, '');
  lastSignedToken = token;
  return token;
}

function dataB64(): string | null {
  try {
    const header = Object.assign(JSON.parse(encHeader.value), { alg: encAlg.value || 'HS256' });
    const payload = JSON.parse(encPayload.value);
    return strToB64url(JSON.stringify(header)) + '.' + strToB64url(JSON.stringify(payload));
  } catch {
    return null;
  }
}

export async function tokenForHandoff(): Promise<string> {
  const data = dataB64();
  if (!lastSignedToken || data === null || !lastSignedToken.startsWith(data + '.')) {
    return signToken();
  }
  return lastSignedToken;
}

export function encoderKeyForDecode(): string {
  const alg = encAlg.value || 'HS256';
  return alg.startsWith('HS') ? encKey.value.trim() : encPubKey.value;
}

export function loadIntoEncoder(header: JsonObject, payload: JsonObject, alg: string | null, keyInfo?: KeyInfo): void {
  if (!header || typeof header !== 'object' || Array.isArray(header)) throw new Error('Nothing to send — paste a decodable token first.');
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) throw new Error('The decoded payload is not a JSON object.');
  encHeader.value = JSON.stringify(header, null, 2);
  encPayload.value = JSON.stringify(payload, null, 2);
  validateJsonFields();
  lastSignedToken = '';
  encOut.innerHTML = '—';
  encMsg.innerHTML = '';

  const info = keyInfo || {};
  const opts = encAlg.options;
  const allowed = !alg || !opts || Array.from(opts).some((o) => o.value === alg);
  if (alg && allowed) encAlg.value = alg;
  encKeyLabelUpdate();

  const isHMAC = Boolean(alg && alg.startsWith('HS'));
  const note = $.required('#encKeyState');
  if (alg === 'none') {
    note.textContent = 'Unsigned (alg: none) — no key required.';
  } else if (isHMAC && info.verified && info.secret) {
    encKey.value = info.secret;
    note.textContent = 'Secret carried over from a token the Decoder verified.';
  } else if (isHMAC) {
    encKey.value = '';
    note.textContent = 'Paste the secret used to sign the original token.';
  } else if (alg && !allowed) {
    encKey.value = '';
    note.textContent = '‘' + alg + '’ can’t be used to sign here; the picker kept ' + encAlg.value + '.';
  } else if (alg) {
    encKey.value = '';
    note.textContent = 'Paste the private key for ' + alg + ' to re-sign this token.';
  } else {
    note.textContent = '';
  }
}

encAlg.addEventListener('change', () => {
  encKeyLabelUpdate();
  $.required('#encKeyState').textContent = '';
  encMsg.innerHTML = '';
});
encKeyLabelUpdate();

$.required('#btnEncExample').addEventListener('click', () => {
  encHeader.value = JSON.stringify({ alg: encAlg.value, typ: 'JWT' }, null, 2);
  encPayload.value = JSON.stringify({ sub: '1234567890', name: 'John Doe', admin: true, iat: Math.floor(Date.now() / 1000) }, null, 2);
  validateJsonFields();
});

$.required('#btnSign').addEventListener('click', async () => {
  encMsg.innerHTML = '';
  try {
    await signToken();
    encMsg.innerHTML = msgOk('Token signed with ' + esc(encAlg.value) + '. Use “Copy” or paste it into the Decoder tab.');
  } catch (e) {
    encMsg.innerHTML = msgErr(esc((e as Error).message));
  }
});

$.required('#btnVerifyOwn').addEventListener('click', async () => {
  encMsg.innerHTML = '';
  try {
    const alg = encAlg.value || 'HS256';
    const token = await signToken();
    if (alg === 'none') {
      encMsg.innerHTML = msgOk('Unsigned token created (alg: none) — there is no signature to verify.');
      return;
    }
    const ok = await roundTripVerify(token, alg, encKey.value.trim());
    encMsg.innerHTML = ok
      ? msgOk('Round-trip OK — ' + (alg.startsWith('HS') ? 'the secret' : 'a public key derived from your private key') + ' verifies this token.')
      : msgErr('Round-trip FAILED — signature did not verify.');
  } catch (e) {
    encMsg.innerHTML = msgErr(esc((e as Error).message));
  }
});

$.required('#btnCopyPub').addEventListener('click', async () => {
  const v = encPubKey.value;
  if (!v) {
    encMsg.innerHTML = msgErr('No public key yet — generate a key pair first.');
    return;
  }
  try {
    await navigator.clipboard.writeText(v);
  } catch {}
  const b = $.required('#btnCopyPub');
  const old = b.textContent;
  b.textContent = 'Copied!';
  setTimeout(() => {
    b.textContent = old;
  }, 1200);
});

$.required('#btnCopyOut').addEventListener('click', async () => {
  if (!lastSignedToken) {
    encMsg.innerHTML = msgErr('Nothing to copy yet — sign a token first.');
    return;
  }
  try {
    await navigator.clipboard.writeText(lastSignedToken);
  } catch {
    const ta = document.createElement('textarea');
    ta.value = lastSignedToken;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    ta.remove();
  }
  const b = $.required('#btnCopyOut');
  const old = b.textContent;
  b.textContent = 'Copied!';
  setTimeout(() => {
    b.textContent = old;
  }, 1200);
});

$.required('#btnGenKeys').addEventListener('click', async () => {
  encMsg.innerHTML = '';
  const alg = encAlg.value;
  try {
    let genParams: RsaHashedKeyGenParams | EcKeyGenParams;
    const usages: KeyUsage[] = ['sign', 'verify'];
    const info = algInfo(alg);
    if (info.name === 'RSASSA-PKCS1-v1_5' || info.name === 'RSA-PSS') {
      genParams = { name: info.name, modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: info.hash };
    } else {
      genParams = { name: 'ECDSA', namedCurve: info.curve! };
    }
    const kp = (await crypto.subtle.generateKey(genParams, true, usages)) as CryptoKeyPair;
    const priv = await crypto.subtle.exportKey('pkcs8', kp.privateKey);
    const pub = await crypto.subtle.exportKey('spki', kp.publicKey);
    encKey.value = derToPem(priv, 'PRIVATE KEY');
    encPubKey.value = derToPem(pub, 'PUBLIC KEY');
    $.required('#pubKeyWrap').classList.remove('hidden');
    encMsg.innerHTML = msgOk('Key pair generated (' + esc(alg.startsWith('ES') ? info.curve! : '2048-bit RSA') + '). Private key above, public key below.');
  } catch (e) {
    encMsg.innerHTML = msgErr(esc((e as Error).message));
  }
});
