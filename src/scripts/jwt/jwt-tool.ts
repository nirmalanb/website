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
  dec.tabIndex = isDecode ? 0 : -1;
  enc.tabIndex = isDecode ? -1 : 0;
  $.required('#viewDecode').classList.toggle('hidden', !isDecode);
  $.required('#viewEncode').classList.toggle('hidden', isDecode);
  if (isDecode) decodeToken();
}

$.required('#tabDecode').addEventListener('click', () => setTab('decode'));
$.required('#tabEncode').addEventListener('click', () => setTab('encode'));

$.required('#toolTabs').addEventListener('keydown', (e: KeyboardEvent) => {
  if (e.key !== 'ArrowLeft' && e.key !== 'ArrowRight' && e.key !== 'Home' && e.key !== 'End') return;
  e.preventDefault();
  const next = e.key === 'ArrowLeft' || e.key === 'Home' ? 'decode' : 'encode';
  setTab(next);
  $.required(next === 'decode' ? '#tabDecode' : '#tabEncode').focus();
});

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
