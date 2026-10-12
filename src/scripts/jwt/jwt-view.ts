import { CLS, TREE_PL } from './jwt-ui.ts';
import type { JsonObject } from './jwt-crypto.ts';

export function esc(s: unknown): string {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
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

const ERR_POS = /\s*(?:in JSON )?at position (\d+)(?: \(line \d+ column \d+\))?/;
const ERR_NOISE = /,\s*"[\s\S]*is not valid JSON$/;

function firstJsonErrorIndex(src: string): number | null {
  const n = src.length;
  let i = 0;
  const ws = (): void => {
    while (i < n) {
      const c = src[i];
      if (c === ' ' || c === '\t' || c === '\n' || c === '\r') i++;
      else break;
    }
  };
  const isDigit = (c: string | undefined): boolean => c !== undefined && c >= '0' && c <= '9';
  const parseString = (): boolean => {
    i++;
    while (i < n) {
      const c = src[i];
      if (c === '"') {
        i++;
        return true;
      }
      if (c === '\\') {
        i++;
        const e = src[i];
        if (e === undefined) return false;
        if (e === 'u') {
          for (let k = 0; k < 4; k++) {
            i++;
            const h = src[i];
            if (h === undefined || !/[0-9a-fA-F]/.test(h)) return false;
          }
          i++;
          continue;
        }
        if ('"\\/bfnrt'.includes(e)) {
          i++;
          continue;
        }
        return false;
      }
      if (c.charCodeAt(0) < 0x20) return false;
      i++;
    }
    return false;
  };
  const parseNumber = (): boolean => {
    if (src[i] === '-') i++;
    if (src[i] === '0') i++;
    else if (isDigit(src[i])) {
      while (isDigit(src[i])) i++;
    } else return false;
    if (src[i] === '.') {
      i++;
      if (!isDigit(src[i])) return false;
      while (isDigit(src[i])) i++;
    }
    if (src[i] === 'e' || src[i] === 'E') {
      i++;
      if (src[i] === '+' || src[i] === '-') i++;
      if (!isDigit(src[i])) return false;
      while (isDigit(src[i])) i++;
    }
    return true;
  };
  const parseValue = (): boolean => {
    ws();
    const c = src[i];
    if (c === undefined) return false;
    if (c === '{') {
      i++;
      ws();
      if (src[i] === '}') {
        i++;
        return true;
      }
      for (;;) {
        ws();
        if (src[i] !== '"' || !parseString()) return false;
        ws();
        if (src[i] !== ':') return false;
        i++;
        if (!parseValue()) return false;
        ws();
        if (src[i] === ',') {
          i++;
          continue;
        }
        if (src[i] === '}') {
          i++;
          return true;
        }
        return false;
      }
    }
    if (c === '[') {
      i++;
      ws();
      if (src[i] === ']') {
        i++;
        return true;
      }
      for (;;) {
        if (!parseValue()) return false;
        ws();
        if (src[i] === ',') {
          i++;
          continue;
        }
        if (src[i] === ']') {
          i++;
          return true;
        }
        return false;
      }
    }
    if (c === '"') return parseString();
    if (c === '-' || isDigit(c)) return parseNumber();
    if (src.startsWith('true', i) || src.startsWith('false', i) || src.startsWith('null', i)) {
      i += src[i] === 't' ? 4 : src[i] === 'f' ? 5 : 4;
      return true;
    }
    return false;
  };
  ws();
  if (!parseValue()) return i;
  ws();
  return i === n ? null : i;
}

export function jsonError(src: string): string | null {
  if (!src.trim()) return null;
  let raw: string;
  try {
    JSON.parse(src);
    return null;
  } catch (e) {
    raw = (e as Error).message;
  }
  const msg = raw.replace(ERR_NOISE, '').replace(ERR_POS, '').trim() || 'Invalid JSON.';
  const at = firstJsonErrorIndex(src);
  if (at === null) return msg;
  const before = src.slice(0, at);
  const line = before.split('\n').length;
  return 'Line ' + line + ', column ' + (at - before.lastIndexOf('\n')) + ': ' + msg;
}

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
    rows += '<tr><td class="' + CLS.claimsTd + ' ' + CLS.claimsK + '">' + esc(k)
      + '</td><td class="' + CLS.claimsTd + ' ' + CLS.claimsV + '">' + esc(val)
      + '</td><td class="' + CLS.claimsTd + ' ' + CLS.claimsD + '">' + esc(desc) + '</td></tr>';
  }
  return '<div class="' + CLS.claimsWrap + '">' + rows + '</tbody></table></div>';
}

export function badge(kind: string, text: string): string {
  return '<span class="' + CLS.badgeBase + ' ' + CLS.badge[kind] + '">'
    + '<span class="' + CLS.dotm + '"></span>' + esc(text) + '</span>';
}

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
