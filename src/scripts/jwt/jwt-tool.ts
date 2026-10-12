/**
 * Entry point: tab switching, the two cross-panel buttons (Decoder → Encoder and
 * Encoder → Decoder), and boot. Panels own their own DOM.
 */

import { $ } from 'domsure';
import { CLS } from './jwt-ui.ts';
import { esc } from './jwt-view.ts';
import { boot, decodeToken, loadToken, snapshot } from './jwt-decoder.ts';
import { encoderKeyForDecode, loadIntoEncoder, tokenForHandoff } from './jwt-encoder.ts';

function scrollTop(): void {
  const reduce = window.matchMedia('(prefers-reduced-motion: no-preference)').matches;
  window.scrollTo({ top: 0, behavior: reduce ? 'smooth' : 'auto' });
}

function setTab(which: 'decode' | 'encode'): void {
  const isDecode = which === 'decode';
  const dec = $.required('#tabDecode');
  const enc = $.required('#tabEncode');
  dec.classList.toggle('active', isDecode);
  enc.classList.toggle('active', !isDecode);
  dec.setAttribute('aria-selected', String(isDecode));
  enc.setAttribute('aria-selected', String(!isDecode));
  $.required('#viewDecode').classList.toggle('hidden', !isDecode);
  $.required('#viewEncode').classList.toggle('hidden', isDecode);
  if (isDecode) decodeToken();
}

$.required('#tabDecode').addEventListener('click', () => setTab('decode'));
$.required('#tabEncode').addEventListener('click', () => setTab('encode'));

// Decoder → Encoder. The secret is carried only when the Decoder verified the
// original token with it — carrying the prefilled demo secret would silently
// re-sign an edited payload with the wrong key.
$.required('#btnDecodeToEncode').addEventListener('click', () => {
  const decMsg = $.required('#decMsg');
  try {
    const s = snapshot();
    if (!s.header || !s.payload) throw new Error('Paste a JWT with a decodable header and payload first.');
    loadIntoEncoder(s.header, s.payload, s.alg, {
      secret: s.secret,
      verified: Boolean(s.verified) && s.verified === s.secret,
    });
    decMsg.innerHTML = '';
    setTab('encode');
    scrollTop();
  } catch (e) {
    decMsg.innerHTML = '<span class="' + CLS.err + '">' + esc((e as Error).message) + '</span>';
  }
});

// Encoder → Decoder: hand over the signed token plus its key.
$.required('#btnSendDecode').addEventListener('click', async () => {
  try {
    loadToken(await tokenForHandoff(), encoderKeyForDecode());
    setTab('decode');
    scrollTop();
  } catch (e) {
    $.required('#encMsg').innerHTML = '<div class="' + CLS.err + '">' + esc((e as Error).message) + '</div>';
  }
});

boot();
