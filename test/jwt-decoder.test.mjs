// Runs the JWT tool modules (src/scripts/jwt/) under a minimal DOM shim, round-trips
// HS/RS/PS/ES, and cross-checks signatures with node:crypto.
//
// Everything is imported dynamically *after* the shim is installed (static imports would
// hoist above it): the entry for its boot + wiring side effects, then the individual
// modules for the functions under test — no window hook required.
import fs from "node:fs";
import crypto from "node:crypto";
import assert from "node:assert";

if (!globalThis.crypto?.subtle) {
  throw new Error("Node 20+ is required (global Web Crypto missing)");
}

/* ------------------------------- DOM shim ------------------------------- */
const nodes = new Map();
function mkEl(sel) {
  const el = {
    _sel: sel,
    value: sel === "#encAlg" ? "HS256" : "",
    textContent: "",
    innerHTML: "",
    placeholder: "",
    dataset: {},
    style: {},
    scrollTop: 0,
    scrollLeft: 0,
    selectionStart: 0,
    selectionEnd: 0,
    classList: { toggle(){}, add(){}, remove(){}, contains(){ return false; } },
    addEventListener(){},
    removeEventListener(){},
    appendChild(){},
    remove(){},
    querySelector(){ return mkEl(sel + " > *"); },
    querySelectorAll(){ return []; },
    closest(){ return null; },
    focus(){},
    select(){},
    getAttribute(){ return null; },
  };
  return el;
}
globalThis.document = {
  querySelector(sel){ if(!nodes.has(sel)) nodes.set(sel, mkEl(sel)); return nodes.get(sel); },
  // domsure's fast path for bare `#id` selectors goes through getElementById.
  getElementById(id){ return this.querySelector("#" + id); },
  querySelectorAll(){ return []; },
  createElement(){ return mkEl("created"); },
  body: { appendChild(){} },
  execCommand(){},
};
globalThis.window = globalThis;
globalThis.btoa = (s) => Buffer.from(s, "latin1").toString("base64");
globalThis.atob = (s) => Buffer.from(s, "base64").toString("latin1");
try { globalThis.navigator = { clipboard: { writeText: async () => {} } }; }
catch { Object.defineProperty(globalThis, "navigator", { value: { clipboard: { writeText: async () => {} } }, configurable: true }); }

// Execute the tool now that the DOM shim exists, then collect the modules under test.
await import("../src/scripts/jwt/jwt-tool.ts");
const api = {
  ...(await import("../src/scripts/jwt/jwt-crypto.ts")),
  ...(await import("../src/scripts/jwt/jwt-view.ts")),
  ...(await import("../src/scripts/jwt/jwt-decoder.ts")),
  ...(await import("../src/scripts/jwt/jwt-encoder.ts")),
};

/* ------------------------------- helpers -------------------------------- */
const encSel = globalThis.document.querySelector("#encAlg");
const encKey = globalThis.document.querySelector("#encKey");
const encHeader = globalThis.document.querySelector("#encHeader");
const encPayload = globalThis.document.querySelector("#encPayload");

async function sign(alg, keyPem, header, payload) {
  encSel.value = alg;
  encKey.value = keyPem;
  encHeader.value = JSON.stringify(header);
  encPayload.value = JSON.stringify(payload);
  return api.signToken();
}
function parts(t){ const [h,p,s] = t.split("."); return { h, p, s, data: h + "." + p }; }

let pass = 0;
function ok(name){ pass++; console.log("  PASS  " + name); }

/* ------------------------------ 1. HS256/384/512 ------------------------ */
for (const [alg, hash] of [["HS256","sha256"],["HS384","sha384"],["HS512","sha512"]]) {
  const secret = "a-string-secret-at-least-256-bits-long";
  const t = await sign(alg, secret, { typ: "JWT" }, { sub: "1234567890", name: "Jöhn Döe — ünïcode ✓", iat: 1516239022 });
  const { s, data } = parts(t);
  const expect = crypto.createHmac(hash, secret).update(data).digest("base64url");
  assert.strictEqual(s, expect, alg + " signature mismatch");
  assert.strictEqual(s.includes("="), false, alg + " must be unpadded");
  const hdr = JSON.parse(Buffer.from(parts(t).h, "base64url").toString());
  const pld = JSON.parse(Buffer.from(parts(t).p, "base64url").toString());
  assert.strictEqual(hdr.alg, alg);
  assert.strictEqual(pld.name, "Jöhn Döe — ünïcode ✓", alg + " UTF-8 round-trip");
  ok(alg + " matches node:crypto HMAC + UTF-8 round-trip");
}

/* ------------------------------ 2. RSA / PS ----------------------------- */
for (const [alg, hash, padding] of [["RS256","sha256",crypto.constants.RSA_PKCS1_PADDING],["PS256","sha256",crypto.constants.RSA_PKCS1_PSS_PADDING]]) {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  const privPem = privateKey.export({ type: "pkcs8", format: "pem" });
  const pubPem = publicKey.export({ type: "spki", format: "pem" });
  const t = await sign(alg, privPem, { typ: "JWT" }, { sub: "abc", iat: 1700000000 });
  const { s, data } = parts(t);
  const v = crypto.verify(hash, Buffer.from(data), {
    key: publicKey,
    padding,
    ...(padding === crypto.constants.RSA_PKCS1_PSS_PADDING ? { saltLength: 32 } : {}),
  }, Buffer.from(s, "base64url"));
  assert.strictEqual(v, true, alg + " verify failed");
  assert.strictEqual(pubPem.includes("BEGIN PUBLIC KEY"), true);
  ok(alg + " verified by node:crypto public key");
}

/* ------------------------------ 3. ECDSA -------------------------------- */
for (const [alg, hash, curve] of [["ES256","sha256","P-256"],["ES384","sha384","P-384"],["ES512","sha512","P-521"]]) {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ec", { namedCurve: curve });
  const privPem = privateKey.export({ type: "pkcs8", format: "pem" });
  const t = await sign(alg, privPem, { typ: "JWT" }, { sub: "abc" });
  const { s, data } = parts(t);
  // JWS uses raw r||s; tell node so it doesn't expect DER
  const v = crypto.verify(hash, Buffer.from(data), { key: publicKey, dsaEncoding: "ieee-p1363" }, Buffer.from(s, "base64url"));
  assert.strictEqual(v, true, alg + " verify failed");
  assert.strictEqual(Buffer.from(s, "base64url").length, 2 * (curve === "P-256" ? 32 : curve === "P-384" ? 48 : 66), alg + " raw r||s length");
  ok(alg + " verified by node:crypto (raw r||s, " + curve + ")");
}

/* ------- 4. decoder-side verification path (public PEM + secret) -------- */
for (const [alg, kind, curve] of [["ES256","ec","P-256"],["ES384","ec","P-384"],["ES512","ec","P-521"],["RS256","rsa",null],["PS512","rsa",null]]) {
  const { privateKey, publicKey } = kind === "rsa"
    ? crypto.generateKeyPairSync("rsa", { modulusLength: 2048 })
    : crypto.generateKeyPairSync("ec", { namedCurve: curve });
  const privPem = privateKey.export({ type: "pkcs8", format: "pem" });
  const pubPem = publicKey.export({ type: "spki", format: "pem" });
  const t = await sign(alg, privPem, { typ: "JWT" }, { sub: "verifier" });

  assert.strictEqual(await api.verifyTokenWithKey(t, alg, pubPem), true, alg + " verifyTokenWithKey(publicPem)");
  const wrong = kind === "rsa" ? crypto.generateKeyPairSync("rsa", { modulusLength: 2048 }) : crypto.generateKeyPairSync("ec", { namedCurve: curve });
  assert.strictEqual(await api.verifyTokenWithKey(t, alg, wrong.publicKey.export({ type: "spki", format: "pem" })), false, alg + " must reject wrong key");
  const tp = parts(t);
  const tampered = tp.h + "." + Buffer.from(JSON.stringify({ sub: "evil" })).toString("base64url") + "." + tp.s;
  assert.strictEqual(await api.verifyTokenWithKey(tampered, alg, pubPem), false, alg + " must reject tampered payload");
  assert.strictEqual(await api.roundTripVerify(t, alg, privPem), true, alg + " roundTripVerify");
  const derived = await api.publicKeyFromPrivatePem(alg, privPem);
  assert.strictEqual(derived.replace(/\s+/g, ""), pubPem.replace(/\s+/g, ""), alg + " derived public key mismatch");
  ok(alg + " decoder verify path: accept + reject-wrong + reject-tampered + round-trip");
}

/* ------- 5. wrong secret for HMAC must fail --------------------------------- */ {
  const t = await sign("HS256", "right-secret", { typ: "JWT" }, { sub: "x" });
  assert.strictEqual(await api.verifyTokenWithKey(t, "HS256", "right-secret"), true);
  assert.strictEqual(await api.verifyTokenWithKey(t, "HS256", "wrong-secret"), false);
  ok("HS256 rejects a wrong secret");
}

/* ------------------------- 6. demo token decodes ------------------------ */
const DEMO = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30";
const d = parts(DEMO);
const demoHeader = JSON.parse(Buffer.from(d.h, "base64url").toString());
const demoPayload = JSON.parse(Buffer.from(d.p, "base64url").toString());
assert.deepStrictEqual(demoHeader, { alg: "HS256", typ: "JWT" });
assert.strictEqual(demoPayload.name, "John Doe");
const demoExpect = crypto.createHmac("sha256", "a-string-secret-at-least-256-bits-long").update(d.data).digest("base64url");
assert.strictEqual(d.s, demoExpect, "demo token signature must match the prefilled secret");
ok("prefilled demo token verifies with the prefilled secret in the UI");

/* ------------------- 7. Astro markup wires the same ids ----------------- */
// The app is injected via innerHTML for badges/claims/panes; every id the script looks
// up from the static markup must exist, or the tool silently no-ops. Markup lives in the
// page plus the tool components; the script may be one file or a folder of modules.
function readAll(dir, ext) {
  const out = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const path = new URL(entry.name + (entry.isDirectory() ? "/" : ""), dir);
    if (entry.isDirectory()) out.push(...readAll(path, ext));
    else if (entry.name.endsWith(ext)) out.push(fs.readFileSync(path, "utf8"));
  }
  return out;
}
const markup = [
  fs.readFileSync(new URL("../src/pages/tools/jwt-decoder.astro", import.meta.url), "utf8"),
  ...readAll(new URL("../src/components/tools/", import.meta.url), ".astro"),
].join("\n");
const script = readAll(new URL("../src/scripts/", import.meta.url), ".ts").join("\n");
const staticIds = new Set([...markup.matchAll(/\bid="([^"]+)"/g)].map((x) => x[1]));
const referenced = new Set([...script.matchAll(/["']#([A-Za-z0-9_-]+)["']/g)].map((x) => x[1]));
// sigBadge is created at runtime inside #statusRow, so it is legitimately absent.
referenced.delete("sigBadge");
const missing = [...referenced].filter((id) => !staticIds.has(id));
assert.deepStrictEqual(missing, [], "ids referenced by JS but missing from markup: " + missing.join(", "));
ok("every statically referenced DOM id exists in the markup");

// The build hook in astro.config.mjs keys its one-script budget off this marker.
assert.ok(markup.includes("data-tool-mount"), "tool page must keep its data-tool-mount marker");
ok("tool page declares data-tool-mount for the build's script budget");

/* ------------------- 8. JSON viewer ------------------------------------- */
const { CLS } = await import("../src/scripts/jwt/jwt-ui.ts");
const tree = api.jsonTreeView({
  evil: '<img src=x onerror=alert(1)>',
  n: 5,
  b: true,
  z: null,
  arr: [1, 2],
  empty: {},
});
assert.strictEqual(tree.includes("<img"), false, "tree viewer must escape claim strings (XSS)");
assert.ok(tree.includes("&lt;img"), "tree viewer should show the escaped string");
for (const cls of [CLS.jtKey, CLS.jtStr, CLS.jtNum, CLS.jtBool, CLS.jtNull, CLS.jtPunct, CLS.jtCount]) {
  assert.ok(tree.includes(cls), "tree viewer missing class: " + cls);
}
assert.ok(tree.includes("<details"), "nested objects should be collapsible");
assert.ok(api.jsonTreeView({}).includes("{}"), "empty object should render {}");
assert.ok(api.jsonTreeView([]).includes("[]"), "empty array should render []");
// "styling only Tailwind": the runtime-generated markup must carry no inline styles or
// hand-rolled CSS variables — only class utilities.
assert.strictEqual(tree.includes("style="), false, "generated tree must not use inline styles");
assert.strictEqual(tree.includes("var(--"), false, "generated tree must not use custom CSS vars");
ok("JSON tree viewer escapes input, colours types and collapses objects");

/* ------------------- 8b. claims breakdown ------------------------------ */
const claims = api.claimsPane({ sub: "1234567890", iat: 1516239022 }, false);
const tdCount = (claims.match(/<td /g) ?? []).length;
assert.strictEqual(tdCount, 6, "two claims should render six cells (3 columns each)");
assert.strictEqual(
  claims.split(CLS.claimsTd).length - 1,
  tdCount,
  "every claims cell must carry the shared cell class (padding/border/align)",
);
assert.ok(claims.includes(CLS.claimsTh), "claims header cells must carry the header class");
ok("claims breakdown builds a padded, bordered table");

/* --------------- 9. decoder panes render the tree ----------------------- */
const tokEl = globalThis.document.querySelector("#tokInput");
const statusEl = globalThis.document.querySelector("#statusRow");
const headerEl = globalThis.document.querySelector("#headerBody");
tokEl.value = DEMO;
api.decodeToken();
assert.ok(headerEl.innerHTML.includes(CLS.tree), "header pane should use the JSON tree");
assert.ok(statusEl.innerHTML.includes("Valid JWT"), "demo token should show a valid badge");
const firstKey = headerEl.dataset.jwtKey;
api.decodeToken();
assert.strictEqual(headerEl.dataset.jwtKey, firstKey, "unchanged JSON should not re-render (keeps collapse state)");
ok("decoder panes use the cached JSON tree view");

/* --------------- 10. alg: none (unsecured JWT) -------------------------- */
{
  const t = await sign("none", "ignored", { typ: "JWT" }, { sub: "unsigned" });
  const p = parts(t);
  assert.strictEqual(t.split(".").length, 3, "none JWT still has three segments");
  assert.strictEqual(p.s, "", "none JWT signature segment must be empty");
  assert.strictEqual(JSON.parse(Buffer.from(p.h, "base64url").toString()).alg, "none");
  tokEl.value = t;
  api.decodeToken();
  assert.ok(statusEl.innerHTML.includes("alg: none"), "decoder should flag an unsigned token");
  ok("alg: none signs an unsigned token and the decoder flags it");
}

/* -------- 11. decoder → encoder carries only a verified secret ---------- */
const encKeyEl = globalThis.document.querySelector("#encKey");
const encAlgEl = globalThis.document.querySelector("#encAlg");
api.loadIntoEncoder({ alg: "HS256", typ: "JWT" }, { sub: "a" }, "HS256", { secret: "s3cr3t", verified: true });
assert.strictEqual(JSON.parse(globalThis.document.querySelector("#encHeader").value).alg, "HS256");
assert.strictEqual(JSON.parse(globalThis.document.querySelector("#encPayload").value).sub, "a");
assert.strictEqual(encKeyEl.value, "s3cr3t", "verified secret should carry over");
api.loadIntoEncoder({ alg: "HS256" }, { sub: "b" }, "HS256", { secret: "a-string-secret-at-least-256-bits-long", verified: false });
assert.strictEqual(encKeyEl.value, "", "an unverified/prefilled secret must NOT be carried into the encoder");
api.loadIntoEncoder({ alg: "none" }, { sub: "c" }, "none", {});
assert.strictEqual(encAlgEl.value, "none", "none should be selectable in the encoder");
assert.ok(globalThis.document.querySelector("#encKeyState").textContent.includes("alg: none"));
ok("decoder→encoder hands over header/payload and only a verified secret");

console.log("\n" + pass + " checks passed");
