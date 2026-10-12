import { CLS, TREE_PL } from "./jwt-ui.ts";

(function(){
"use strict";

/* ---------------------------------------------------------------- types */
type JsonObject = Record<string, unknown>;
/** Algorithm descriptor handed to Web Crypto; `usages` is consumed by keyParams callers. */
type KeyParams = { name: string; hash?: string; namedCurve?: string; saltLength?: number; usages?: KeyUsage[] };
type KeyInfo = { secret?: string; verified?: boolean };
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

/* ---------------------------------------------------------------- utils */
const $ = <T extends HTMLElement = HTMLElement>(s: string): T => document.querySelector(s) as T;
const textEnc = new TextEncoder();
const textDec = new TextDecoder();

function esc(s: unknown): string {
  return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
}
function bytesToB64url(bytes: Uint8Array): string {
  let bin = "";
  for (let i=0;i<bytes.length;i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
}
function strToB64url(str: string): string { return bytesToB64url(textEnc.encode(str)); }
function b64urlToBytes(seg: string): Uint8Array<ArrayBuffer> {
  let s = String(seg).replace(/-/g,"+").replace(/_/g,"/").replace(/\s+/g,"");
  while (s.length % 4) s += "=";
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i=0;i<bin.length;i++) out[i] = bin.charCodeAt(i);
  return out;
}
function b64urlToString(seg: string): string { return textDec.decode(b64urlToBytes(seg)); }
// Strict decode with a human-readable failure (JWS segments are unpadded base64url).
const B64URL_RE = /^[A-Za-z0-9_-]+={0,2}$/;
function decodeSegment(seg: string, what: string): string {
  const s = String(seg).replace(/\s+/g, "");
  if (!B64URL_RE.test(s)) throw new Error(what + " is not valid base64url (unexpected characters).");
  try { return b64urlToString(s); }
  catch(e){ throw new Error(what + " could not be base64url-decoded."); }
}
function decodeSigBytes(seg: string): Uint8Array<ArrayBuffer> {
  const s = String(seg).replace(/\s+/g, "").replace(/=+$/, "");
  if (!B64URL_RE.test(s + "=")) throw new Error("Signature is not valid base64url (unexpected characters).");
  try { return b64urlToBytes(s); }
  catch(e){ throw new Error("Signature could not be base64url-decoded."); }
}

function pemToDer(pem: string): ArrayBuffer {
  const body = String(pem).replace(/-----BEGIN [^-]+-----/g,"")
                         .replace(/-----END [^-]+-----/g,"")
                         .replace(/\s+/g,"");
  if (!body) throw new Error("Empty PEM key.");
  const bytes = b64urlToBytes(body.replace(/\+/g,"-").replace(/\//g,"_"));
  return bytes.buffer as ArrayBuffer;
}
function derToPem(buffer: ArrayBuffer, label: string): string {
  const bytes = new Uint8Array(buffer);
  let bin = "";
  for (let i=0;i<bytes.length;i++) bin += String.fromCharCode(bytes[i]);
  const b64 = btoa(bin).replace(/(.{64})/g,"$1\n").replace(/\n$/,"");
  return "-----BEGIN " + label + "-----\n" + b64 + "\n-----END " + label + "-----";
}
function hashFor(alg: string): string {
  if (/256$/.test(alg)) return "SHA-256";
  if (/384$/.test(alg)) return "SHA-384";
  if (/512$/.test(alg)) return "SHA-512";
  throw new Error("Unsupported algorithm: " + alg);
}
function curveFor(alg: string): string {
  if (alg === "ES256") return "P-256";
  if (alg === "ES384") return "P-384";
  if (alg === "ES512") return "P-521";
  throw new Error("Unsupported curve for " + alg);
}
function keyParams(alg: string, usages: KeyUsage[]): KeyParams {
  const hash = hashFor(alg);
  if (alg.startsWith("HS")) return { name:"HMAC", hash, usages };
  if (alg.startsWith("RS")) return { name:"RSASSA-PKCS1-v1_5", hash, usages };
  if (alg.startsWith("PS")) return { name:"RSA-PSS", hash, usages, saltLength: parseInt(alg.slice(2),10)/8 };
  if (alg.startsWith("ES")) return { name:"ECDSA", namedCurve:curveFor(alg), usages };
  throw new Error("Unsupported algorithm: " + alg);
}
function isPem(s: string): boolean { return /-----BEGIN/.test(s); }

async function importVerifyKey(alg: string, keyText: string): Promise<CryptoKey> {
  const hash = hashFor(alg);
  if (alg.startsWith("HS")) {
    return crypto.subtle.importKey("raw", textEnc.encode(keyText), { name:"HMAC", hash }, false, ["verify"]);
  }
  const der = pemToDer(keyText);
  if (alg.startsWith("RS")) return crypto.subtle.importKey("spki", der, { name:"RSASSA-PKCS1-v1_5", hash }, false, ["verify"]);
  if (alg.startsWith("PS")) return crypto.subtle.importKey("spki", der, { name:"RSA-PSS", hash }, false, ["verify"]);
  return crypto.subtle.importKey("spki", der, { name:"ECDSA", namedCurve:curveFor(alg) }, false, ["verify"]);
}
async function importSignKey(alg: string, keyText: string): Promise<CryptoKey> {
  const hash = hashFor(alg);
  if (alg.startsWith("HS")) {
    return crypto.subtle.importKey("raw", textEnc.encode(keyText), { name:"HMAC", hash }, false, ["sign"]);
  }
  const der = pemToDer(keyText);
  if (alg.startsWith("RS")) return crypto.subtle.importKey("pkcs8", der, { name:"RSASSA-PKCS1-v1_5", hash }, false, ["sign"]);
  if (alg.startsWith("PS")) return crypto.subtle.importKey("pkcs8", der, { name:"RSA-PSS", hash }, false, ["sign"]);
  return crypto.subtle.importKey("pkcs8", der, { name:"ECDSA", namedCurve:curveFor(alg) }, false, ["sign"]);
}
function verifyParams(alg: string): AlgorithmIdentifier | RsaPssParams | EcdsaParams {
  if (alg.startsWith("HS")) return { name:"HMAC" };
  if (alg.startsWith("RS")) return { name:"RSASSA-PKCS1-v1_5" };
  if (alg.startsWith("PS")) return { name:"RSA-PSS", saltLength: parseInt(alg.slice(2),10)/8 };
  return { name:"ECDSA", hash: hashFor(alg) };
}
function signParams(alg: string): AlgorithmIdentifier | RsaPssParams | EcdsaParams {
  if (alg.startsWith("HS")) return { name:"HMAC" };
  if (alg.startsWith("RS")) return { name:"RSASSA-PKCS1-v1_5" };
  if (alg.startsWith("PS")) return { name:"RSA-PSS", saltLength: parseInt(alg.slice(2),10)/8 };
  return { name:"ECDSA", hash: hashFor(alg) };
}

/* ------------------------------------------------------- claim metadata */
const CLAIM_DOCS: Record<string, { d: string; fmt?: string }> = {
  iss:{ d:"Issuer — who created and signed this token", fmt:"text" },
  sub:{ d:"Subject — whom the token refers to", fmt:"text" },
  aud:{ d:"Audience — intended recipient(s) of the token", fmt:"text" },
  exp:{ d:"Expiration Time — after this time the token must be rejected", fmt:"date" },
  nbf:{ d:"Not Before — before this time the token must be rejected", fmt:"date" },
  iat:{ d:"Issued At — when the token was issued", fmt:"date" },
  jti:{ d:"JWT ID — unique identifier, prevents replay", fmt:"text" },
  scope:{ d:"Scope — space-separated list of granted permissions", fmt:"text" },
  scp:{ d:"Scope — granted permissions", fmt:"text" },
  azp:{ d:"Authorized Party — party the token was issued to", fmt:"text" },
  name:{ d:"Full name of the subject", fmt:"text" },
  email:{ d:"Email address of the subject", fmt:"text" },
  typ:{ d:"Type — token type, e.g. JWT", fmt:"text" },
  alg:{ d:"Algorithm — signing algorithm (alg in header)", fmt:"text" },
  kid:{ d:"Key ID — hints which key was used to sign", fmt:"text" },
  admin:{ d:"Custom claim — application specific", fmt:"text" }
};
function fmtDate(sec: number): string {
  const d = new Date(sec*1000);
  if (isNaN(d.getTime())) return String(sec);
  return d.toUTCString();
}
function relTime(sec: number): string {
  const diff = Date.now() - sec*1000;
  const abs = Math.abs(diff);
  const units: [string, number][] = [["year",31536e6],["month",2592e6],["day",864e5],["hour",36e5],["minute",6e4],["second",1000]];
  for (const [u,ms] of units){
    if (abs >= ms || u === "second"){
      const n = Math.max(1, Math.floor(abs/ms));
      return n + " " + u + (n>1?"s":"");
    }
  }
  return "just now";
}
function jtPrimitive(v: unknown): string {
  if (v === null) return '<span class="' + CLS.jtNull + '">null</span>';
  const t = typeof v;
  if (t === "number") return '<span class="' + CLS.jtNum + '">' + esc(String(v)) + '</span>';
  if (t === "boolean") return '<span class="' + CLS.jtBool + '">' + String(v) + '</span>';
  if (t === "string") return '<span class="' + CLS.jtStr + '">' + esc(JSON.stringify(v)) + '</span>';
  return '<span class="' + CLS.jtNull + '">' + esc(String(v)) + '</span>';
}
function jtKey(key: string | null, isIndex: boolean): string {
  if (key === null) return "";
  return isIndex
    ? '<span class="' + CLS.jtIdx + '">' + esc(key) + '</span><span class="' + CLS.jtPunct + '">: </span>'
    : '<span class="' + CLS.jtKey + '">' + esc(JSON.stringify(key)) + '</span><span class="' + CLS.jtPunct + '">: </span>';
}
function jtNode(value: unknown, key: string | null, depth: number, isIndex: boolean): string {
  const line = CLS.jtLine + " " + TREE_PL[Math.min(depth, TREE_PL.length - 1)];
  const head = jtKey(key, isIndex);
  if (value !== null && typeof value === "object"){
    const isArr = Array.isArray(value);
    const entries = isArr ? value.map((v,i) => [String(i), v]) : Object.entries(value);
    const open = isArr ? "[" : "{", close = isArr ? "]" : "}";
    if (!entries.length){
      return '<div class="' + line + '">' + head + '<span class="' + CLS.jtPunct + '">' + open + close + '</span></div>';
    }
    let inner = "";
    for (const [k,v] of entries) inner += jtNode(v, k, depth + 1, isArr);
    return '<details open><summary class="' + line + ' ' + CLS.jtSummary + '">' + head
      + '<span class="' + CLS.jtPunct + '">' + open + '</span>'
      + '<span class="' + CLS.jtCount + '">' + entries.length + (isArr ? " items" : " keys") + '</span>'
      + '<span class="' + CLS.jtPunct + '">' + close + '</span></summary>' + inner + '</details>';
  }
  return '<div class="' + line + '">' + head + jtPrimitive(value) + '</div>';
}
// Collapsible, syntax-coloured JSON view. Every string goes through esc(JSON.stringify(...))
// so a malicious claim can never inject markup.
function jsonTreeView(obj: unknown): string {
  return '<div class="' + CLS.tree + '">' + jtNode(obj, null, 0, false) + '</div>';
}
function jsonPane(obj: unknown): string {
  return jsonTreeView(obj);
}
// Cache the rendered key on the pane so identical re-renders are skipped — that keeps a
// user's collapsed/expanded <details> state across keystroke-by-keystroke decoding.
function setPaneHtml(body: HTMLElement, key: string, html: string): void {
  if (body.dataset && body.dataset.jwtKey === key) return;
  if (body.dataset) body.dataset.jwtKey = key;
  body.innerHTML = html;
}
function claimsPane(obj: JsonObject, headerMode: boolean): string {
  const keys = Object.keys(obj||{});
  if (!keys.length) return '<div class="' + CLS.empty + '">No claims.</div>';
  let rows = '<table class="' + CLS.claimsTable + '"><thead><tr><th class="' + CLS.claimsTh + '">Claim</th><th class="' + CLS.claimsTh + '">Value</th><th class="' + CLS.claimsTh + '">Description</th></tr></thead><tbody>';
  for (const k of keys){
    const v = obj[k];
    const meta = CLAIM_DOCS[k];
    let val = (typeof v === "object") ? JSON.stringify(v) : String(v);
    let desc = meta ? meta.d : (headerMode ? "Header parameter" : "Custom claim");
    if (meta && meta.fmt === "date" && typeof v === "number"){
      val = fmtDate(v) + "  (" + v + ")";
      desc += " — " + relTime(v) + (k==="exp" ? " from now" : " ago");
    }
    rows += '<tr><td class="' + CLS.claimsK + '">' + esc(k) + '</td><td class="' + CLS.claimsV + '">' + esc(val) + '</td><td class="' + CLS.claimsD + '">' + esc(desc) + '</td></tr>';
  }
  return '<div class="' + CLS.claimsWrap + '">' + rows + '</tbody></table></div>';
}

/* ------------------------------------------------------------- decoder */
const tokInput = $<HTMLTextAreaElement>("#tokInput");
const tokBack = $("#tokBack");
const statusRow = $("#statusRow");
const headerBody = $("#headerBody");
const payloadBody = $("#payloadBody");
const secretInput = $<HTMLTextAreaElement>("#secretInput");

let state: JwtState = { raw:"", parts:[], header:null, payload:null, headerRaw:"", payloadRaw:"", sigRaw:"", headerErr:null, payloadErr:null, alg:null, verifiedKey:null };
let verifyToken = 0;

function colorizeToken(raw: string): string {
  // Split keeping dots; color each base64url segment.
  let out = "";
  const segs = raw.split(".");
  segs.forEach((seg,i)=>{
    const cls = i===0 ? CLS.seg.h : i===1 ? CLS.seg.p : CLS.seg.s;
    out += '<span class="' + cls + '">' + esc(seg) + "</span>";
    if (i < segs.length-1) out += '<span class="' + CLS.seg.dot + '">.</span>';
  });
  return out + "\n";
}
function syncScroll(){
  tokBack.scrollTop = tokInput.scrollTop;
  tokBack.scrollLeft = tokInput.scrollLeft;
}
function renderTokenLayer(){ tokBack.innerHTML = colorizeToken(tokInput.value.trim()); syncScroll(); }

function badge(kind: string, text: string): string {
  return '<span class="' + CLS.badgeBase + ' ' + CLS.badge[kind] + '"><span class="' + CLS.dotm + '"></span>' + esc(text) + "</span>";
}

function decodeToken(){
  const raw = tokInput.value.trim();
  state.raw = raw;
  state.parts = raw ? raw.split(".") : [];
  state.header = state.payload = null;
  state.headerErr = state.payloadErr = null;
  state.verifiedKey = null;
  $("#decMsg").innerHTML = "";
  state.headerRaw = state.parts[0] || "";
  state.payloadRaw = state.parts[1] || "";
  state.sigRaw = state.parts[2] || "";

  if (!raw){
    setPaneHtml(headerBody, "empty:header", '<div class="' + CLS.empty + '">Paste a token above to see the decoded header.</div>');
    setPaneHtml(payloadBody, "empty:payload", '<div class="' + CLS.empty + '">Paste a token above to see the decoded payload.</div>');
    statusRow.innerHTML = "";
    setSecretLabel(null);
    return;
  }

  // header
  if (state.parts.length >= 2 && state.parts[0]){
    try {
      const txt = decodeSegment(state.parts[0], "Header");
      state.header = JSON.parse(txt);
      setPaneHtml(headerBody, "json:" + JSON.stringify(state.header), jsonPane(state.header));
    } catch(e){ state.headerErr = (e as Error).message; }
  }
  // payload
  if (state.parts.length >= 3 && state.parts[1]){
    try {
      const txt = decodeSegment(state.parts[1], "Payload");
      state.payload = JSON.parse(txt);
      setPaneHtml(payloadBody, "json:" + JSON.stringify(state.payload), jsonPane(state.payload));
    } catch(e){ state.payloadErr = (e as Error).message; }
  }
  if (state.headerErr) setPaneHtml(headerBody, "err:header:" + state.headerErr, '<div class="' + CLS.empty + '">Could not decode header: ' + esc(state.headerErr) + "</div>");
  if (state.payloadErr) setPaneHtml(payloadBody, "err:payload:" + state.payloadErr, '<div class="' + CLS.empty + '">Could not decode payload: ' + esc(state.payloadErr) + "</div>");

  state.alg = state.header && state.header.alg ? String(state.header.alg) : null;
  setSecretLabel(state.alg);
  renderStatus();
  refreshClaimsView("header");
  refreshClaimsView("payload");
  scheduleVerify();
}

function setSecretLabel(alg: string | null): void {
  const label = $("#secretLabel");
  if (!alg){ label.textContent = "Secret"; return; }
  if (alg === "none"){ label.textContent = "No key needed (alg: none, unsigned)"; return; }
  if (alg.startsWith("HS")) label.textContent = "Secret (HMAC key used to sign)";
  else if (alg.startsWith("RS")) label.textContent = "Public Key (PEM, RSASSA-PKCS1-v1_5)";
  else if (alg.startsWith("PS")) label.textContent = "Public Key (PEM, RSA-PSS)";
  else if (alg.startsWith("ES")) label.textContent = "Public Key (PEM, ECDSA)";
  else label.textContent = "Secret";
}

function renderStatus(){
  const b = [];
  const n = state.parts.length;
  const hasJson = state.header && state.payload;

  if (!state.raw){ statusRow.innerHTML = badge("neutral","Awaiting token"); return; }

  if (n !== 3) b.push(badge("bad", n < 3 ? "Incomplete JWT (" + n + " of 3 segments)" : "Invalid JWT (" + n + " segments)"));
  else if (!hasJson) b.push(badge("bad","Invalid JWT — segments are not valid JSON"));
  else b.push(badge("ok","Valid JWT"));

  if (state.alg === "none") b.push(badge("warn","Unsigned (alg: none)"));

  if (state.payload && typeof state.payload.exp === "number"){
    if (Date.now() >= state.payload.exp*1000) b.push(badge("bad","Expired " + relTime(state.payload.exp) + " ago"));
    else b.push(badge("ok","Expires in " + relTime(state.payload.exp)));
  }
  if (state.payload && typeof state.payload.nbf === "number" && Date.now() < state.payload.nbf*1000){
    b.push(badge("warn","Not valid before " + fmtDate(state.payload.nbf)));
  }
  if (state.payload && typeof state.payload.iat === "number"){
    b.push(badge("neutral","Issued " + relTime(state.payload.iat) + " ago"));
  }
  const sigBadge = '<span id="sigBadge">' + badge("neutral","Signature not verified") + "</span>";
  b.push(sigBadge);
  statusRow.innerHTML = b.join("");
}

function scheduleVerify(){
  const id = ++verifyToken;
  const key = secretInput.value;
  if (!state.raw || state.parts.length !== 3 || !state.alg){
    return;
  }
  if (state.alg === "none"){
    const el = $("#sigBadge");
    if (el) el.innerHTML = badge("warn", "Unsigned token (alg: none)");
    const st = $("#secretState");
    if (st) st.innerHTML = '<span class="' + CLS.warnText + '">This token declares alg "none" and carries no signature.</span>';
    return;
  }
  if (!key){
    return;
  }
  runVerify(id, key, state.raw, state.alg);
}

async function runVerify(id: number, key: string, raw: string, alg: string): Promise<void> {
  const slot = () => $("#sigBadge");
  try {
    const parts = raw.split(".");
    const data = textEnc.encode(parts[0] + "." + parts[1]);
    const sigBytes = decodeSigBytes(parts[2]);
    let k;
    try { k = await importVerifyKey(alg, key); }
    catch(e){ throw new Error("Could not load the " + (alg.startsWith("HS") ? "secret" : "PEM public key") + ": " + (e as Error).message); }
    const ok = await crypto.subtle.verify(verifyParams(alg), k, sigBytes, data);
    if (id !== verifyToken) return;
    state.verifiedKey = ok ? key : null;
    const el = slot();
    if (el) el.innerHTML = ok ? badge("ok","Signature Verified (" + alg + ")") : badge("bad","Invalid Signature (" + alg + ")");
    $("#secretState").innerHTML = ok
      ? '<span class="' + CLS.okText + '">Key matches this token’s signature.</span>'
      : '<span class="' + CLS.badText + '">Key does not produce the token’s signature.</span>';
  } catch(err){
    if (id !== verifyToken) return;
    state.verifiedKey = null;
    const el = slot();
    // A malformed signature segment is a definite failure, not an "error".
    const malformed = /not valid base64url|could not be base64url-decoded/i.test((err as Error).message);
    if (el) el.innerHTML = malformed
      ? badge("bad", (err as Error).message)
      : badge("warn", "Verification error — " + (err as Error).message);
    $("#secretState").innerHTML = '<span class="' + CLS.warnText + '">' + esc((err as Error).message) + "</span>";
  }
}

function refreshClaimsView(which: string): void {
  const pane = document.querySelector('[data-pane="' + which + '"]');
  const active = pane ? (pane.querySelector("button.active") as HTMLElement | null) : null;
  const view = active ? active.dataset.view : "json";
  const obj = which === "header" ? state.header : state.payload;
  const body = which === "header" ? headerBody : payloadBody;
  if (!obj) return;
  const html = view === "claims" ? claimsPane(obj, which==="header") : jsonPane(obj);
  setPaneHtml(body, view + ":" + JSON.stringify(obj), html);
}

/* ------------------------------------------------- decoder wiring */
tokInput.addEventListener("input", ()=>{ renderTokenLayer(); decodeToken(); });
tokInput.addEventListener("scroll", syncScroll);
tokInput.addEventListener("keydown", (e: KeyboardEvent)=>{
  if (e.key === "Tab"){
    e.preventDefault();
    const s = tokInput.selectionStart, end = tokInput.selectionEnd;
    tokInput.value = tokInput.value.slice(0,s) + "  " + tokInput.value.slice(end);
    tokInput.selectionStart = tokInput.selectionEnd = s + 2;
    renderTokenLayer(); decodeToken();
  }
});
secretInput.addEventListener("input", ()=>{ $("#secretState").textContent = ""; scheduleVerify(); });

document.querySelectorAll("[data-pane]").forEach(tab=>{
  tab.addEventListener("click",(e: Event)=>{
    const btn = (e.target as Element).closest("button"); if (!btn) return;
    tab.querySelectorAll("button").forEach(x=>x.classList.toggle("active", x===btn));
    refreshClaimsView((tab as HTMLElement).dataset.pane as string);
  });
});

const EXAMPLE_SECRET = "a-string-secret-at-least-256-bits-long";
$("#btnExample").addEventListener("click", ()=>{
  tokInput.value = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30";
  secretInput.value = EXAMPLE_SECRET;
  renderTokenLayer(); decodeToken();
});
$("#btnClearToken").addEventListener("click", ()=>{ tokInput.value = ""; renderTokenLayer(); decodeToken(); });
$("#btnExampleSecret").addEventListener("click", ()=>{ secretInput.value = EXAMPLE_SECRET; $('#secretState').textContent = ""; scheduleVerify(); });
$("#btnClearSecret").addEventListener("click", ()=>{ secretInput.value = ""; $("#secretState").textContent = ""; scheduleVerify(); });

// Decoder → Encoder: load the decoded header/payload for editing. The secret is only
// carried over when the Decoder actually verified the original token with it — carrying a
// prefilled demo secret would silently re-sign an edited payload with the wrong key.
$("#btnDecodeToEncode").addEventListener("click", ()=>{
  try {
    if (!state.header || !state.payload) throw new Error("Paste a JWT with a decodable header and payload first.");
    const secret = secretInput.value;
    loadIntoEncoder(state.header, state.payload, state.alg, {
      secret,
      verified: !!state.verifiedKey && state.verifiedKey === secret,
    });
    $("#decMsg").innerHTML = "";
    setTab("encode");
    const reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: no-preference)").matches;
    window.scrollTo({ top: 0, behavior: reduce ? "smooth" : "auto" });
  } catch(e){
    $("#decMsg").innerHTML = '<span class="' + CLS.err + '">' + esc((e as Error).message) + "</span>";
  }
});

/* ------------------------------------------------------------- encoder */
const encHeader = $<HTMLTextAreaElement>("#encHeader");
const encPayload = $<HTMLTextAreaElement>("#encPayload");
const encAlg = $<HTMLSelectElement>("#encAlg");
const encKey = $<HTMLTextAreaElement>("#encKey");
const encOut = $("#encOut");
const encMsg = $("#encMsg");
let lastSignedToken = "";

function encKeyLabelUpdate(){
  const alg = encAlg.value || "HS256";
  if (alg === "none"){
    $("#encKeyLabel").textContent = "No key — alg: none emits an unsigned token";
    $("#btnGenKeys").classList.add("hidden");
    $("#pubKeyWrap").classList.add("hidden");
    encKey.value = "";
    encKey.placeholder = "Not used for alg: none";
    return;
  }
  const isHMAC = alg.startsWith("HS");
  $("#encKeyLabel").textContent = isHMAC
    ? "Secret (raw text or base64url)"
    : "Private Key (PEM, " + (alg.startsWith("PS") ? "RSA-PSS" : alg.startsWith("RS") ? "RSASSA-PKCS1-v1_5" : "ECDSA " + curveFor(alg)) + ")";
  $("#btnGenKeys").classList.toggle("hidden", isHMAC);
  $("#pubKeyWrap").classList.toggle("hidden", isHMAC);
  if (isHMAC && isPem(encKey.value)){ encKey.value = "a-string-secret-at-least-256-bits-long"; }
  if (!isHMAC && !isPem(encKey.value)){
    encKey.value = "";
    encKey.placeholder = "-----BEGIN PRIVATE KEY-----\n…\n-----END PRIVATE KEY-----";
  }
  if (isHMAC && !encKey.value) encKey.value = "a-string-secret-at-least-256-bits-long";
}
encAlg.addEventListener("change", ()=>{ encKeyLabelUpdate(); $("#encKeyState").textContent = ""; encMsg.innerHTML = ""; });
encKeyLabelUpdate();

$("#btnEncExample").addEventListener("click", ()=>{
  encHeader.value = JSON.stringify({ alg: encAlg.value, typ:"JWT" }, null, 2);
  encPayload.value = JSON.stringify({ sub:"1234567890", name:"John Doe", admin:true, iat: Math.floor(Date.now()/1000) }, null, 2);
});

async function signToken(){
  const alg = encAlg.value || "HS256";
  let header, payload;
  try { header = JSON.parse(encHeader.value); }
  catch(e){ throw new Error("Header is not valid JSON: " + (e as Error).message); }
  try { payload = JSON.parse(encPayload.value); }
  catch(e){ throw new Error("Payload is not valid JSON: " + (e as Error).message); }
  if (!header || typeof header !== "object" || Array.isArray(header)) throw new Error("Header must be a JSON object.");
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) throw new Error("Payload must be a JSON object.");

  header.alg = alg;
  if (alg === "none"){
    // RFC 7519 unsecured JWT: "<header>.<payload>." — empty signature segment.
    const b64h = strToB64url(JSON.stringify(header));
    const b64p = strToB64url(JSON.stringify(payload));
    const token = b64h + "." + b64p + ".";
    encHeader.value = JSON.stringify(header, null, 2);
    encOut.innerHTML = colorizeToken(token).replace(/\n$/,"");
    lastSignedToken = token;
    return token;
  }
  const keyText = encKey.value.trim();
  if (!keyText) throw new Error(alg.startsWith("HS") ? "Enter a secret." : "Paste a PEM private key (or generate a key pair).");

  const b64h = strToB64url(JSON.stringify(header));
  const b64p = strToB64url(JSON.stringify(payload));
  const data = b64h + "." + b64p;
  const key = await importSignKey(alg, keyText);
  const sig = await crypto.subtle.sign(signParams(alg), key, textEnc.encode(data));
  const token = data + "." + bytesToB64url(new Uint8Array(sig));

  encHeader.value = JSON.stringify(header, null, 2);
  encOut.innerHTML = colorizeToken(token).replace(/\n$/,"");
  lastSignedToken = token;
  return token;
}

$("#btnSign").addEventListener("click", async ()=>{
  encMsg.innerHTML = "";
  try {
    const t = await signToken();
    encMsg.innerHTML = '<div class="' + CLS.okmsg + '">Token signed with ' + esc(encAlg.value) + ". Use “Copy” or paste it into the Decoder tab.</div>";
  } catch(e){
    encMsg.innerHTML = '<div class="' + CLS.err + '">' + esc((e as Error).message) + "</div>";
  }
});

// Derive the public key from a private PEM via JWK, then verify a token we produced.
async function publicKeyFromPrivatePem(alg: string, privPem: string): Promise<string> {
  const jwk = await crypto.subtle.exportKey("jwk", await crypto.subtle.importKey("pkcs8", pemToDer(privPem), keyParams(alg,["sign"]), true, ["sign"]));
  for (const k of ["d","dp","dq","q","qi","p"]) delete (jwk as Record<string, unknown>)[k];
  jwk.key_ops = ["verify"];
  const pub = await crypto.subtle.importKey("jwk", jwk, keyParams(alg,["verify"]), true, ["verify"]);
  return derToPem(await crypto.subtle.exportKey("spki", pub), "PUBLIC KEY");
}

async function verifyTokenWithKey(token: string, alg: string, keyText: string): Promise<boolean> {
  const p = String(token).split(".");
  if (p.length !== 3) throw new Error("Not a three-part JWT.");
  const k = await importVerifyKey(alg, keyText);
  return crypto.subtle.verify(verifyParams(alg), k, b64urlToBytes(p[2]), textEnc.encode(p[0] + "." + p[1]));
}

async function roundTripVerify(token: string, alg: string, keyText: string): Promise<boolean> {
  const verifyKey = alg.startsWith("HS") ? keyText : await publicKeyFromPrivatePem(alg, keyText);
  return verifyTokenWithKey(token, alg, verifyKey);
}

$("#btnVerifyOwn").addEventListener("click", async ()=>{
  encMsg.innerHTML = "";
  try {
    const alg = encAlg.value || "HS256";
    const token = await signToken();
    if (alg === "none"){
      encMsg.innerHTML = '<div class="' + CLS.okmsg + '">Unsigned token created (alg: none) — there is no signature to verify.</div>';
      return;
    }
    const ok = await roundTripVerify(token, alg, encKey.value.trim());
    encMsg.innerHTML = ok
      ? '<div class="' + CLS.okmsg + '">Round-trip OK — ' + (alg.startsWith("HS") ? "the secret" : "a public key derived from your private key") + " verifies this token.</div>"
      : '<div class="' + CLS.err + '">Round-trip FAILED — signature did not verify.</div>';
  } catch(e){
    encMsg.innerHTML = '<div class="' + CLS.err + '">' + esc((e as Error).message) + "</div>";
  }
});

$("#btnCopyPub").addEventListener("click", async ()=>{
  const v = $<HTMLTextAreaElement>("#encPubKey").value;
  if (!v){ encMsg.innerHTML = '<div class="' + CLS.err + '">No public key yet — generate a key pair first.</div>'; return; }
  try { await navigator.clipboard.writeText(v); } catch(e){}
  const b = $("#btnCopyPub"), old = b.textContent;
  b.textContent = "Copied!"; setTimeout(()=>{ b.textContent = old; }, 1200);
});

// Sign (if needed), then hand the token + matching key to the Decoder tab.
$("#btnSendDecode").addEventListener("click", async ()=>{
  encMsg.innerHTML = "";
  try {
    const alg = encAlg.value || "HS256";
    let token = lastSignedToken;
    if (!token || !token.startsWith(hdrB64())) token = await signToken();
    const key = alg.startsWith("HS") ? encKey.value.trim() : $<HTMLTextAreaElement>("#encPubKey").value;
    setTab("decode");
    tokInput.value = token;
    renderTokenLayer();
    decodeToken();
    if (key){
      secretInput.value = key;
      secretInput.dispatchEvent(new Event("input"));
    }
    const reduce = window.matchMedia("(prefers-reduced-motion: no-preference)").matches;
    window.scrollTo({ top: 0, behavior: reduce ? "smooth" : "auto" });
  } catch(e){
    encMsg.innerHTML = '<div class="' + CLS.err + '">' + esc((e as Error).message) + "</div>";
  }
});

// b64url of the encoder header's current alg, used to detect a stale signed token
function hdrB64(){
  try { return strToB64url(JSON.stringify(Object.assign(JSON.parse(encHeader.value), { alg: encAlg.value || "HS256" }))); }
  catch(e){ return "\u0000\u0000"; }
}

$("#btnCopyOut").addEventListener("click", async ()=>{
  if (!lastSignedToken){ encMsg.innerHTML = '<div class="' + CLS.err + '">Nothing to copy yet — sign a token first.</div>'; return; }
  try { await navigator.clipboard.writeText(lastSignedToken); }
  catch(e){
    const ta = document.createElement("textarea");
    ta.value = lastSignedToken; document.body.appendChild(ta); ta.select();
    document.execCommand("copy"); ta.remove();
  }
  const b = $("#btnCopyOut"), old = b.textContent;
  b.textContent = "Copied!"; setTimeout(()=>{ b.textContent = old; }, 1200);
});

$("#btnGenKeys").addEventListener("click", async ()=>{
  encMsg.innerHTML = "";
  const alg = encAlg.value;
  try {
    let genParams: RsaHashedKeyGenParams | EcKeyGenParams;
    const usages: KeyUsage[] = ["sign","verify"];
    if (alg.startsWith("RS")) genParams = { name:"RSASSA-PKCS1-v1_5", modulusLength:2048, publicExponent:new Uint8Array([1,0,1]), hash:hashFor(alg) };
    else if (alg.startsWith("PS")) genParams = { name:"RSA-PSS", modulusLength:2048, publicExponent:new Uint8Array([1,0,1]), hash:hashFor(alg) };
    else genParams = { name:"ECDSA", namedCurve:curveFor(alg) };
    const kp = await crypto.subtle.generateKey(genParams, true, usages);
    const priv = derToPem(await crypto.subtle.exportKey("pkcs8", kp.privateKey), "PRIVATE KEY");
    const pub = derToPem(await crypto.subtle.exportKey("spki", kp.publicKey), "PUBLIC KEY");
    encKey.value = priv;
    $<HTMLTextAreaElement>("#encPubKey").value = pub;
    $("#pubKeyWrap").classList.remove("hidden");
    encMsg.innerHTML = '<div class="' + CLS.okmsg + '">Key pair generated (' + esc(alg.startsWith("ES") ? curveFor(alg) : "2048-bit RSA") + "). Private key above, public key below.</div>";
    (window as unknown as Record<string, unknown>).__generatedPublicKey = pub;
  } catch(e){ encMsg.innerHTML = '<div class="' + CLS.err + '">' + esc((e as Error).message) + "</div>"; }
});

// Populate the Encoder from a decoded token. Pure state change so it is testable without
// a DOM click; the caller switches tabs. Callers pass { secret, verified }.
function loadIntoEncoder(header: JsonObject, payload: JsonObject, alg: string | null, keyInfo?: KeyInfo): void {
  if (!header || typeof header !== "object" || Array.isArray(header)) throw new Error("Nothing to send — paste a decodable token first.");
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) throw new Error("The decoded payload is not a JSON object.");
  encHeader.value = JSON.stringify(header, null, 2);
  encPayload.value = JSON.stringify(payload, null, 2);
  lastSignedToken = "";
  encOut.innerHTML = "—";
  encMsg.innerHTML = "";

  const info = keyInfo || {};
  const opts = encAlg.options;
  const allowed = !alg || !opts || Array.from(opts).some((o) => o.value === alg);
  if (alg && allowed) encAlg.value = alg;
  encKeyLabelUpdate();

  const isHMAC = !!alg && alg.startsWith("HS");
  if (alg === "none"){
    $("#encKeyState").textContent = "Unsigned (alg: none) — no key required.";
  } else if (isHMAC && info.verified && info.secret){
    // After encKeyLabelUpdate, which otherwise refills an empty HMAC key with the demo secret.
    encKey.value = info.secret;
    $("#encKeyState").textContent = "Secret carried over from a token the Decoder verified.";
  } else if (isHMAC){
    encKey.value = "";
    $("#encKeyState").textContent = "Paste the secret used to sign the original token.";
  } else if (alg && !allowed){
    encKey.value = "";
    $("#encKeyState").textContent = "‘" + alg + "’ can’t be used to sign here; the picker kept " + encAlg.value + ".";
  } else if (alg){
    encKey.value = "";
    $("#encKeyState").textContent = "Paste the private key for " + alg + " to re-sign this token.";
  } else {
    $("#encKeyState").textContent = "";
  }
}

/* --------------------------------------------------------------- tabs */
$("#tabDecode").addEventListener("click", ()=>{ setTab("decode"); });
$("#tabEncode").addEventListener("click", ()=>{ setTab("encode"); });
function setTab(which: string): void {
  const isDecode = which === "decode";
  const dec = $("#tabDecode"), enc = $("#tabEncode");
  dec.classList.toggle("active", isDecode);
  enc.classList.toggle("active", !isDecode);
  dec.setAttribute("aria-selected", String(isDecode));
  enc.setAttribute("aria-selected", String(!isDecode));
  $("#viewDecode").classList.toggle("hidden", !isDecode);
  $("#viewEncode").classList.toggle("hidden", isDecode);
  if (isDecode) decodeToken();
}

/* ---------------------------------------------------------------- boot */
// Prefill the classic jwt.io example token so the page is useful immediately.
const DEMO_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30";
tokInput.value = DEMO_TOKEN;
secretInput.value = EXAMPLE_SECRET;
renderTokenLayer();
decodeToken();

// expose a tiny hook for automated tests
(window as unknown as { __jwtDebugger: Record<string, unknown> }).__jwtDebugger = { b64urlToBytes, strToB64url, pemToDer, derToPem, importVerifyKey, importSignKey, signToken, decodeToken, verifyTokenWithKey, roundTripVerify, publicKeyFromPrivatePem, decodeSegment, jsonTreeView, loadIntoEncoder };
})();
