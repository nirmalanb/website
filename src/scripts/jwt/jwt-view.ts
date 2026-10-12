/**
 * Pure string builders for the decoded panes: the JSON tree, the claims table,
 * status badges and the colourised token. No DOM writes except `setPaneHtml`,
 * which caches the rendered key so identical re-renders are skipped (that keeps
 * a user's collapsed/expanded <details> state across decoding).
 */

import { CLS, TREE_PL } from './jwt-ui.ts';
import type { JsonObject } from './jwt-crypto.ts';

export function esc(s: unknown): string {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

export const CLAIM_DOCS: Record<string, { d: string; fmt?: string }> = {
  iss: { d: 'Issuer — who created and signed this token', fmt: 'text' },
  sub: { d: 'Subject — whom the token refers to', fmt: 'text' },
  aud: { d: 'Audience — intended recipient(s) of the token', fmt: 'text' },
  exp: { d: 'Expiration Time — after this time the token must be rejected', fmt: 'date' },
  nbf: { d: 'Not Before — before this time the token must be rejected', fmt: 'date' },
  iat: { d: 'Issued At — when the token was issued', fmt: 'date' },
  jti: { d: 'JWT ID — unique identifier, prevents replay', fmt: 'text' },
  scope: { d: 'Scope — space-separated list of granted permissions', fmt: 'text' },
  scp: { d: 'Scope — granted permissions', fmt: 'text' },
  azp: { d: 'Authorized Party — party the token was issued to', fmt: 'text' },
  name: { d: 'Full name of the subject', fmt: 'text' },
  email: { d: 'Email address of the subject', fmt: 'text' },
  typ: { d: 'Type — token type, e.g. JWT', fmt: 'text' },
  alg: { d: 'Algorithm — signing algorithm (alg in header)', fmt: 'text' },
  kid: { d: 'Key ID — hints which key was used to sign', fmt: 'text' },
  admin: { d: 'Custom claim — application specific', fmt: 'text' },
};

export function fmtDate(sec: number): string {
  const d = new Date(sec * 1000);
  if (isNaN(d.getTime())) return String(sec);
  return d.toUTCString();
}

export function relTime(sec: number): string {
  const abs = Math.abs(Date.now() - sec * 1000);
  const units: [string, number][] = [
    ['year', 31536e6],
    ['month', 2592e6],
    ['day', 864e5],
    ['hour', 36e5],
    ['minute', 6e4],
    ['second', 1000],
  ];
  for (const [u, ms] of units) {
    if (abs >= ms || u === 'second') {
      const n = Math.max(1, Math.floor(abs / ms));
      return n + ' ' + u + (n > 1 ? 's' : '');
    }
  }
  return 'just now';
}

/* ------------------------------------------------------------- JSON tree */

function jtPrimitive(v: unknown): string {
  if (v === null) return '<span class="' + CLS.jtNull + '">null</span>';
  const t = typeof v;
  if (t === 'number') return '<span class="' + CLS.jtNum + '">' + esc(String(v)) + '</span>';
  if (t === 'boolean') return '<span class="' + CLS.jtBool + '">' + String(v) + '</span>';
  if (t === 'string') return '<span class="' + CLS.jtStr + '">' + esc(JSON.stringify(v)) + '</span>';
  return '<span class="' + CLS.jtNull + '">' + esc(String(v)) + '</span>';
}

function jtKey(key: string | null, isIndex: boolean): string {
  if (key === null) return '';
  return isIndex
    ? '<span class="' + CLS.jtIdx + '">' + esc(key) + '</span><span class="' + CLS.jtPunct + '">: </span>'
    : '<span class="' + CLS.jtKey + '">' + esc(JSON.stringify(key)) + '</span><span class="' + CLS.jtPunct + '">: </span>';
}

function jtNode(value: unknown, key: string | null, depth: number, isIndex: boolean): string {
  const line = CLS.jtLine + ' ' + TREE_PL[Math.min(depth, TREE_PL.length - 1)];
  const head = jtKey(key, isIndex);
  if (value !== null && typeof value === 'object') {
    const isArr = Array.isArray(value);
    const entries: [string, unknown][] = isArr
      ? value.map((v, i) => [String(i), v])
      : Object.entries(value);
    const open = isArr ? '[' : '{';
    const close = isArr ? ']' : '}';
    if (!entries.length) {
      return '<div class="' + line + '">' + head + '<span class="' + CLS.jtPunct + '">' + open + close + '</span></div>';
    }
    let inner = '';
    for (const [k, v] of entries) inner += jtNode(v, k, depth + 1, isArr);
    return '<details open><summary class="' + line + ' ' + CLS.jtSummary + '">' + head
      + '<span class="' + CLS.jtPunct + '">' + open + '</span>'
      + '<span class="' + CLS.jtCount + '">' + entries.length + (isArr ? ' items' : ' keys') + '</span>'
      + '<span class="' + CLS.jtPunct + '">' + close + '</span></summary>' + inner + '</details>';
  }
  return '<div class="' + line + '">' + head + jtPrimitive(value) + '</div>';
}

/** Collapsible, syntax-coloured JSON view. Every string goes through esc() so a
 *  malicious claim can never inject markup. */
export function jsonTreeView(obj: unknown): string {
  return '<div class="' + CLS.tree + '">' + jtNode(obj, null, 0, false) + '</div>';
}

export function jsonPane(obj: unknown): string {
  return jsonTreeView(obj);
}

export function setPaneHtml(body: HTMLElement, key: string, html: string): void {
  if (body.dataset && body.dataset.jwtKey === key) return;
  if (body.dataset) body.dataset.jwtKey = key;
  body.innerHTML = html;
}

/* ---------------------------------------------------------- claims table */

export function claimsPane(obj: JsonObject, headerMode: boolean): string {
  const keys = Object.keys(obj || {});
  if (!keys.length) return '<div class="' + CLS.empty + '">No claims.</div>';
  let rows = '<table class="' + CLS.claimsTable + '"><thead><tr>'
    + '<th class="' + CLS.claimsTh + '">Claim</th>'
    + '<th class="' + CLS.claimsTh + '">Value</th>'
    + '<th class="' + CLS.claimsTh + '">Description</th>'
    + '</tr></thead><tbody>';
  for (const k of keys) {
    const v = obj[k];
    const meta = CLAIM_DOCS[k];
    let val = typeof v === 'object' ? JSON.stringify(v) : String(v);
    let desc = meta ? meta.d : headerMode ? 'Header parameter' : 'Custom claim';
    if (meta && meta.fmt === 'date' && typeof v === 'number') {
      val = fmtDate(v) + '  (' + v + ')';
      desc += ' — ' + relTime(v) + (k === 'exp' ? ' from now' : ' ago');
    }
    rows += '<tr><td class="' + CLS.claimsK + '">' + esc(k)
      + '</td><td class="' + CLS.claimsV + '">' + esc(val)
      + '</td><td class="' + CLS.claimsD + '">' + esc(desc) + '</td></tr>';
  }
  return '<div class="' + CLS.claimsWrap + '">' + rows + '</tbody></table></div>';
}

/* -------------------------------------------------------------- badges */

export function badge(kind: string, text: string): string {
  return '<span class="' + CLS.badgeBase + ' ' + CLS.badge[kind] + '">'
    + '<span class="' + CLS.dotm + '"></span>' + esc(text) + '</span>';
}

/** Split on dots and colour each base64url segment (jwt.io's red/violet/blue). */
export function colorizeToken(raw: string): string {
  let out = '';
  const segs = raw.split('.');
  segs.forEach((seg, i) => {
    const cls = i === 0 ? CLS.seg.h : i === 1 ? CLS.seg.p : CLS.seg.s;
    out += '<span class="' + cls + '">' + esc(seg) + '</span>';
    if (i < segs.length - 1) out += '<span class="' + CLS.seg.dot + '">.</span>';
  });
  return out + '\n';
}
