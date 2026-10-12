import { $, $$ } from 'domsure';
import { CLS } from './jwt-ui.ts';
import type { JsonObject } from './jwt-crypto.ts';
import { decodeSegment, importKey, verifySigned } from './jwt-crypto.ts';
import { badge, claimsPane, colorizeToken, esc, fmtDate, jsonPane, relTime, setPaneHtml } from './jwt-view.ts';

interface JwtState {
  raw: string;
  parts: string[];
  header: JsonObject | null;
  payload: JsonObject | null;
  headerRaw: string;
  payloadRaw: string;
  sigRaw: string;
  headerErr: string | null;
  payloadErr: string | null;
  alg: string | null;
  verifiedKey: string | null;
}

const EXAMPLE_SECRET = 'a-string-secret-at-least-256-bits-long';
const DEMO_TOKEN =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30';

const tokInput = $.required<HTMLTextAreaElement>('#tokInput');
const tokBack = $.required('#tokBack');
const statusRow = $.required('#statusRow');
const headerBody = $.required('#headerBody');
const payloadBody = $.required('#payloadBody');
const secretInput = $.required<HTMLTextAreaElement>('#secretInput');

const state: JwtState = {
  raw: '',
  parts: [],
  header: null,
  payload: null,
  headerRaw: '',
  payloadRaw: '',
  sigRaw: '',
  headerErr: null,
  payloadErr: null,
  alg: null,
  verifiedKey: null,
};
let verifyToken = 0;
let verifyTimer: ReturnType<typeof setTimeout> | undefined;

function syncScroll(): void {
  tokBack.scrollTop = tokInput.scrollTop;
  tokBack.scrollLeft = tokInput.scrollLeft;
}

function renderTokenLayer(): void {
  tokBack.innerHTML = colorizeToken(tokInput.value.trim());
  syncScroll();
}

function setSecretLabel(alg: string | null): void {
  const label = $.required('#secretLabel');
  const text = !alg
    ? 'Secret'
    : alg === 'none'
      ? 'No key needed (alg: none, unsigned)'
      : alg.startsWith('HS')
        ? 'Secret (HMAC key used to sign)'
        : alg.startsWith('RS')
          ? 'Public Key (PEM, RSASSA-PKCS1-v1_5)'
          : alg.startsWith('PS')
            ? 'Public Key (PEM, RSA-PSS)'
            : alg.startsWith('ES')
              ? 'Public Key (PEM, ECDSA)'
              : 'Secret';
  label.textContent = text;
}

function renderStatus(): void {
  const b: string[] = [];
  const n = state.parts.length;
  const hasJson = Boolean(state.header && state.payload);
  if (!state.raw) {
    statusRow.innerHTML = badge('neutral', 'Awaiting token');
    return;
  }
  if (n !== 3) {
    b.push(badge('bad', n < 3 ? 'Incomplete JWT (' + n + ' of 3 segments)' : 'Invalid JWT (' + n + ' segments)'));
  } else if (!hasJson) {
    b.push(badge('bad', 'Invalid JWT — segments are not valid JSON'));
  } else {
    b.push(badge('ok', 'Valid JWT'));
  }
  if (state.alg === 'none') b.push(badge('warn', 'Unsigned (alg: none)'));

  const payload = state.payload;
  if (payload && typeof payload.exp === 'number') {
    b.push(
      Date.now() >= payload.exp * 1000
        ? badge('bad', 'Expired ' + relTime(payload.exp) + ' ago')
        : badge('ok', 'Expires in ' + relTime(payload.exp)),
    );
  }
  if (payload && typeof payload.nbf === 'number' && Date.now() < payload.nbf * 1000) {
    b.push(badge('warn', 'Not valid before ' + fmtDate(payload.nbf)));
  }
  if (payload && typeof payload.iat === 'number') {
    b.push(badge('neutral', 'Issued ' + relTime(payload.iat) + ' ago'));
  }
  b.push('<span id="sigBadge">' + badge('neutral', 'Signature not verified') + '</span>');
  statusRow.innerHTML = b.join('');
}

function scheduleVerify(): void {
  const id = ++verifyToken;
  const key = secretInput.value;
  const raw = state.raw;
  const alg = state.alg;
  if (!raw || state.parts.length !== 3 || !alg) return;
  if (alg === 'none') {
    const el = $.optional('#sigBadge');
    if (el) el.innerHTML = badge('warn', 'Unsigned token (alg: none)');
    $.required('#secretState').innerHTML =
      '<span class="' + CLS.warnText + '">This token declares alg "none" and carries no signature.</span>';
    return;
  }
  if (!key) return;
  clearTimeout(verifyTimer);
  verifyTimer = setTimeout(() => {
    void runVerify(id, key, raw, alg);
  }, 120);
}

async function runVerify(id: number, key: string, raw: string, alg: string): Promise<void> {
  try {
    let k: CryptoKey;
    try {
      k = await importKey(alg, key, 'verify');
    } catch (e) {
      throw new Error(
        'Could not load the ' + (alg.startsWith('HS') ? 'secret' : 'PEM public key') + ': ' + (e as Error).message,
      );
    }
    const ok = await verifySigned(raw, alg, k);
    if (id !== verifyToken) return;
    state.verifiedKey = ok ? key : null;
    const el = $.optional('#sigBadge');
    if (el) el.innerHTML = ok ? badge('ok', 'Signature Verified (' + alg + ')') : badge('bad', 'Invalid Signature (' + alg + ')');
    $.required('#secretState').innerHTML = ok
      ? '<span class="' + CLS.okText + '">Key matches this token’s signature.</span>'
      : '<span class="' + CLS.badText + '">Key does not produce the token’s signature.</span>';
  } catch (err) {
    if (id !== verifyToken) return;
    state.verifiedKey = null;
    const el = $.optional('#sigBadge');
    const msg = (err as Error).message;
    const malformed = /not valid base64url|could not be base64url-decoded/i.test(msg);
    if (el) el.innerHTML = malformed ? badge('bad', msg) : badge('warn', 'Verification error — ' + msg);
    $.required('#secretState').innerHTML = '<span class="' + CLS.warnText + '">' + esc(msg) + '</span>';
  }
}

function refreshClaimsView(which: 'header' | 'payload'): void {
  const pane = document.querySelector('[data-pane="' + which + '"]');
  const active = pane ? (pane.querySelector('button.active') as HTMLElement | null) : null;
  const view = active?.dataset.view ?? 'json';
  const obj = which === 'header' ? state.header : state.payload;
  const body = which === 'header' ? headerBody : payloadBody;
  if (!obj) return;
  const html = view === 'claims' ? claimsPane(obj, which === 'header') : jsonPane(obj);
  setPaneHtml(body, view + ':' + JSON.stringify(obj), html);
}

export function decodeToken(): void {
  const raw = tokInput.value.trim();
  state.raw = raw;
  state.parts = raw ? raw.split('.') : [];
  state.header = state.payload = null;
  state.headerErr = state.payloadErr = null;
  state.verifiedKey = null;
  $.required('#decMsg').innerHTML = '';
  state.headerRaw = state.parts[0] || '';
  state.payloadRaw = state.parts[1] || '';
  state.sigRaw = state.parts[2] || '';

  if (!raw) {
    setPaneHtml(headerBody, 'empty:header', '<div class="' + CLS.empty + '">Paste a token above to see the decoded header.</div>');
    setPaneHtml(payloadBody, 'empty:payload', '<div class="' + CLS.empty + '">Paste a token above to see the decoded payload.</div>');
    statusRow.innerHTML = '';
    setSecretLabel(null);
    return;
  }

  if (state.parts.length >= 2 && state.parts[0]) {
    try {
      state.header = JSON.parse(decodeSegment(state.parts[0], 'Header'));
      setPaneHtml(headerBody, 'json:' + JSON.stringify(state.header), jsonPane(state.header));
    } catch (e) {
      state.headerErr = (e as Error).message;
    }
  }
  if (state.parts.length >= 3 && state.parts[1]) {
    try {
      state.payload = JSON.parse(decodeSegment(state.parts[1], 'Payload'));
      setPaneHtml(payloadBody, 'json:' + JSON.stringify(state.payload), jsonPane(state.payload));
    } catch (e) {
      state.payloadErr = (e as Error).message;
    }
  }
  if (state.headerErr) {
    setPaneHtml(headerBody, 'err:header:' + state.headerErr, '<div class="' + CLS.empty + '">Could not decode header: ' + esc(state.headerErr) + '</div>');
  }
  if (state.payloadErr) {
    setPaneHtml(payloadBody, 'err:payload:' + state.payloadErr, '<div class="' + CLS.empty + '">Could not decode payload: ' + esc(state.payloadErr) + '</div>');
  }

  state.alg = state.header && state.header.alg ? String(state.header.alg) : null;
  setSecretLabel(state.alg);
  renderStatus();
  refreshClaimsView('header');
  refreshClaimsView('payload');
  scheduleVerify();
}

export function loadToken(raw: string, key?: string): void {
  tokInput.value = raw;
  if (key !== undefined) secretInput.value = key;
  renderTokenLayer();
  decodeToken();
}

export function snapshot(): { header: JsonObject | null; payload: JsonObject | null; alg: string | null; secret: string; verified: string | null } {
  return {
    header: state.header,
    payload: state.payload,
    alg: state.alg,
    secret: secretInput.value,
    verified: state.verifiedKey,
  };
}

tokInput.addEventListener('input', () => {
  renderTokenLayer();
  decodeToken();
});
tokInput.addEventListener('scroll', syncScroll);
tokInput.addEventListener('keydown', (e: KeyboardEvent) => {
  if (e.key === 'Tab') {
    e.preventDefault();
    const s = tokInput.selectionStart;
    const end = tokInput.selectionEnd;
    tokInput.value = tokInput.value.slice(0, s) + '  ' + tokInput.value.slice(end);
    tokInput.selectionStart = tokInput.selectionEnd = s + 2;
    renderTokenLayer();
    decodeToken();
  }
});
secretInput.addEventListener('input', () => {
  $.required('#secretState').textContent = '';
  scheduleVerify();
});

$$<HTMLElement>('[data-pane]').forEach((tab) => {
  tab.addEventListener('click', (e: Event) => {
    const btn = (e.target as Element).closest('button');
    if (!btn) return;
    tab.querySelectorAll('button').forEach((x) => x.classList.toggle('active', x === btn));
    refreshClaimsView(tab.dataset.pane as 'header' | 'payload');
  });
});

$.required('#btnExample').addEventListener('click', () => loadToken(DEMO_TOKEN, EXAMPLE_SECRET));
$.required('#btnClearToken').addEventListener('click', () => loadToken(''));
$.required('#btnExampleSecret').addEventListener('click', () => {
  secretInput.value = EXAMPLE_SECRET;
  $.required('#secretState').textContent = '';
  scheduleVerify();
});
$.required('#btnClearSecret').addEventListener('click', () => {
  secretInput.value = '';
  $.required('#secretState').textContent = '';
  scheduleVerify();
});

export function boot(): void {
  loadToken(DEMO_TOKEN, EXAMPLE_SECRET);
}
