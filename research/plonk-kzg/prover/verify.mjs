// Independent reference verifier for gnark v0.16.4 PLONK (KZG, BN254, SHA-256 Fiat-Shamir, no BSB22
// commitments), over the byte format of FORMAT.md. It follows PROTOCOL.md step by step and is the spec the
// CashVM verifier follows. BigInt field arithmetic is written here; curve group law and the pairing come from
// @noble/curves 2.2.0 (bn254). SHA-256 is node:crypto.
//
//   node verify.mjs                     check every vector in vectors/*.json (valid accept, tampered reject)
//   node verify.mjs --trace mul2 0      print the transcript and intermediate values of one valid proof
//   node verify.mjs --counts            print the operation counts of one verification per circuit
import { createHash } from 'node:crypto';
import { readFileSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { bn254 } from '@noble/curves/bn254.js';

const P = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47n; // base field
const R = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001n; // scalar field
const G1 = bn254.G1.Point;
const G2 = bn254.G2.Point;
const Fp12 = bn254.fields.Fp12;

// ---- operation counter (PROTOCOL.md counts are printed from here) ----
let counting = true;
const C = { frMul: 0, g1Mul: 0, g1MulFixedBase: 0, g1MulProofBase: 0, g1Add: 0, frInv: 0, frExpSquarings: 0, sha256: [], pairings: 0, onCurve: 0 };
const resetCounts = () => { Object.assign(C, { frMul: 0, g1Mul: 0, g1MulFixedBase: 0, g1MulProofBase: 0, g1Add: 0, frInv: 0, frExpSquarings: 0, sha256: [], pairings: 0, onCurve: 0 }); };

// ---- Fr ----
const md = (a) => ((a % R) + R) % R;
const add = (a, b) => md(a + b);
const sub = (a, b) => md(a - b);
const mul = (a, b) => { if (counting) C.frMul++; return md(a * b); };
const powR = (a, e, count = true) => { let r = 1n, b = md(a); while (e > 0n) { if (e & 1n) r = mul(r, b); b = mul(b, b); e >>= 1n; if (count) C.frExpSquarings++; } return r; };
const inv = (a) => { if (md(a) === 0n) throw new Error('inverse of zero'); C.frInv++; counting = false; const x = powR(a, R - 2n, false); counting = true; return x; };

// ---- bytes ----
const hexToBytes = (h) => Uint8Array.from(Buffer.from(h, 'hex'));
const be = (b) => (b.length === 0 ? 0n : BigInt('0x' + Buffer.from(b).toString('hex')));
const u256 = (x) => hexToBytes(x.toString(16).padStart(64, '0'));
const cat = (...xs) => Uint8Array.from(Buffer.concat(xs.map((x) => Buffer.from(x))));
const ascii = (s) => Uint8Array.from(Buffer.from(s, 'ascii'));
const sha256 = (label, msg) => { C.sha256.push({ label, bytes: msg.length }); return Uint8Array.from(createHash('sha256').update(msg).digest()); };

// ---- G1 ----
// strict decode: x, y canonical (< p), not (0,0), on y^2 = x^3 + 3. BN254 G1 has cofactor 1.
const decodeG1 = (b, what, allowInfinity = false) => {
  const x = be(b.subarray(0, 32)), y = be(b.subarray(32, 64));
  if (x >= P || y >= P) throw new Error(`${what}: non-canonical coordinate`);
  if (x === 0n && y === 0n) { if (allowInfinity) return G1.ZERO; throw new Error(`${what}: point at infinity`); }
  C.onCurve++;
  const lhs = (y * y) % P, rhs = (((x * x) % P) * x + 3n) % P;
  if (lhs !== rhs) throw new Error(`${what}: not on curve`);
  return G1.fromAffine({ x, y });
};
const rawG1 = (pt) => { if (pt.is0()) return new Uint8Array(64); const a = pt.toAffine(); return cat(u256(a.x), u256(a.y)); };
const smul = (pt, s, kind) => { C.g1Mul++; if (kind === 'fixed') C.g1MulFixedBase++; else C.g1MulProofBase++; s = md(s); return s === 0n || pt.is0() ? G1.ZERO : pt.multiply(s); };
const padd = (a, b) => { C.g1Add++; return a.add(b); };

// ---- VK (FORMAT.md, 944 bytes) ----
export const parseVK = (hex) => {
  const b = hexToBytes(hex);
  if (b.length !== 944) throw new Error('vk length');
  const dv = new DataView(b.buffer, b.byteOffset);
  const n = dv.getBigUint64(0), nbPublic = Number(dv.getBigUint64(8));
  const omega = be(b.subarray(16, 48)), nInv = be(b.subarray(48, 80)), k = be(b.subarray(80, 112));
  const names = ['S1', 'S2', 'S3', 'Ql', 'Qr', 'Qm', 'Qo', 'Qk'];
  const vk = { n, nbPublic, omega, nInv, k, raw: {} };
  names.forEach((nm, i) => { const s = b.subarray(112 + 64 * i, 176 + 64 * i); vk.raw[nm] = s; vk[nm] = decodeG1(s, 'vk.' + nm, true); }); // VK commitments may be the identity (e.g. Qk with no constants)
  vk.g1 = decodeG1(b.subarray(624, 688), 'vk.g1');
  const g2 = (o) => {
    const f = (i) => be(b.subarray(o + 32 * i, o + 32 * i + 32));
    const Fp2 = bn254.fields.Fp2;
    const pt = G2.fromAffine({ x: Fp2.create({ c0: f(1), c1: f(0) }), y: Fp2.create({ c0: f(3), c1: f(2) }) });
    pt.assertValidity();
    return pt;
  };
  vk.g2 = g2(688); vk.g2x = g2(816);
  // sanity of the domain constants (VK is trusted, but a wrong file should fail loudly)
  if (powR(omega, n) !== 1n || (n > 1n && powR(omega, n / 2n) === 1n)) throw new Error('vk omega is not a primitive n-th root');
  if (mul(nInv, n % R) !== 1n) throw new Error('vk nInv');
  if (!vk.g1.equals(G1.BASE) || !vk.g2.equals(G2.BASE)) throw new Error('vk [1]_1/[1]_2 are not the standard generators');
  return vk;
};

// ---- the verifier (PROTOCOL.md) ----
export const verify = (vk, proofHex, pubHex, trace) => {
  const t = trace ?? (() => {});
  // 1. sizes
  const pb = hexToBytes(proofHex);
  if (pb.length !== 768) throw new Error('proof length');
  if (pubHex.length !== vk.nbPublic) throw new Error('public input count');
  // 2. public inputs and scalars: canonical, < r
  const pubRaw = pubHex.map((h) => { const b = hexToBytes(h); if (b.length !== 32) throw new Error('public input length'); return b; });
  const pub = pubRaw.map((b, i) => { const v = be(b); if (v >= R) throw new Error(`public input ${i} >= r`); return v; });
  const sc = (off, nm) => { const v = be(pb.subarray(off, off + 32)); if (v >= R) throw new Error(`${nm} >= r`); return v; };
  const [l, r, o, s1, s2] = [384, 416, 448, 480, 512].map((off, i) => sc(off, ['l', 'r', 'o', 's1', 's2'][i]));
  const zu = sc(608, 'z(zeta*omega)');
  // 3. points: canonical, not infinity, on curve
  const raw = (off) => pb.subarray(off, off + 64);
  const pt = (off, nm) => decodeG1(raw(off), nm);
  const L = pt(0, 'L'), Rr = pt(64, 'R'), O = pt(128, 'O'), H0 = pt(192, 'H0'), H1 = pt(256, 'H1'), H2 = pt(320, 'H2');
  const Z = pt(544, 'Z'), Wz = pt(640, 'Wzeta'), Wzw = pt(704, 'WzetaOmega');

  // 4. Fiat-Shamir (gnark fiat-shamir transcript, SHA-256): challenge = SHA256(name || prev || bindings), value = BE mod r
  const gammaRaw = sha256('gamma', cat(ascii('gamma'), ...['S1', 'S2', 'S3', 'Ql', 'Qr', 'Qm', 'Qo', 'Qk'].map((k) => vk.raw[k]), ...pubRaw, raw(0), raw(64), raw(128)));
  const betaRaw = sha256('beta', cat(ascii('beta'), gammaRaw));
  const alphaRaw = sha256('alpha', cat(ascii('alpha'), betaRaw, raw(544)));
  const zetaRaw = sha256('zeta', cat(ascii('zeta'), alphaRaw, raw(192), raw(256), raw(320)));
  const [gamma, beta, alpha, zeta] = [gammaRaw, betaRaw, alphaRaw, zetaRaw].map((x) => be(x) % R);
  t({ gamma, beta, alpha, zeta });

  // 5. vanishing polynomial, L_1 and PI(zeta), one batched inversion over the |pub| denominators zeta - omega^i
  const zn = powR(zeta, vk.n);
  const zh = sub(zn, 1n);
  const dens = []; let w = 1n;
  for (let i = 0; i < vk.nbPublic; i++) { dens.push(sub(zeta, w)); w = mul(w, vk.omega); }
  if (dens.some((d) => d === 0n)) throw new Error('zeta is in the domain');
  // Montgomery batch inversion: 1 inversion + 3(k-1) multiplications
  const pref = []; let acc = 1n;
  for (const d of dens) { pref.push(acc); acc = mul(acc, d); }
  let ia = inv(acc); const invDens = new Array(dens.length);
  for (let i = dens.length - 1; i >= 0; i--) { invDens[i] = mul(ia, pref[i]); ia = mul(ia, dens[i]); }
  const zhOverN = mul(zh, vk.nInv);
  let pi = 0n; w = 1n;
  for (let i = 0; i < vk.nbPublic; i++) { pi = add(pi, mul(mul(mul(zhOverN, invDens[i]), w), pub[i])); w = mul(w, vk.omega); }
  const lagrange0 = mul(zhOverN, invDens[0]); // L_1(zeta) = (zeta^n - 1) / (n (zeta - 1)), the i = 0 term (needs >= 1 public input)
  const alpha2L1 = mul(mul(alpha, alpha), lagrange0);

  // 6. opening of the linearised polynomial at zeta (recomputed, not sent)
  const t1 = add(add(l, mul(beta, s1)), gamma);
  const t2 = add(add(r, mul(beta, s2)), gamma);
  const r0 = sub(0n, add(sub(mul(mul(mul(mul(t1, t2), add(o, gamma)), alpha), zu), alpha2L1), pi));

  // 7. linearised commitment [Lin]
  const s1c = mul(mul(mul(mul(t1, t2), beta), alpha), zu);
  const bz = mul(beta, zeta);
  const s2c = add(sub(0n, mul(mul(mul(add(add(l, bz), gamma), add(add(r, mul(bz, vk.k)), gamma)), add(add(o, mul(bz, mul(vk.k, vk.k))), gamma)), alpha)), alpha2L1);
  const zn2 = mul(zn, mul(zeta, zeta)); // zeta^(n+2)
  let lin = smul(vk.Ql, l, 'fixed');
  lin = padd(lin, smul(vk.Qr, r, 'fixed'));
  lin = padd(lin, smul(vk.Qm, mul(l, r), 'fixed'));
  lin = padd(lin, smul(vk.Qo, o, 'fixed'));
  lin = padd(lin, vk.Qk);
  lin = padd(lin, smul(vk.S3, s1c, 'fixed'));
  lin = padd(lin, smul(Z, s2c, 'proof'));
  lin = padd(lin, smul(H0, sub(0n, zh), 'proof'));
  lin = padd(lin, smul(H1, sub(0n, mul(zh, zn2)), 'proof'));
  lin = padd(lin, smul(H2, sub(0n, mul(zh, mul(zn2, zn2))), 'proof'));
  const linRaw = rawG1(lin);

  // 8. KZG folding challenge v (gnark-crypto kzg.deriveGamma: its own transcript, single challenge "gamma")
  const vRaw = sha256('v', cat(ascii('gamma'), u256(zeta), linRaw, raw(0), raw(64), raw(128), vk.raw.S1, vk.raw.S2,
    u256(r0), u256(l), u256(r), u256(o), u256(s1), u256(s2), u256(zu)));
  const v = be(vRaw) % R;
  const vs = [1n, v]; for (let i = 2; i < 6; i++) vs.push(mul(vs[i - 1], v));
  let D = lin;
  [[L, l], [Rr, r], [O, o], [vk.S1, s1], [vk.S2, s2]].forEach(([Pt, _], i) => { D = padd(D, smul(Pt, vs[i + 1], i < 3 ? 'proof' : 'fixed')); });
  const e = [r0, l, r, o, s1, s2].reduce((a, x, i) => add(a, mul(vs[i], x)), 0n);

  // 9. multi-point batching challenge u (gnark Solidity verifier; gnark's Go verifier samples u at random)
  const uRaw = sha256('u', cat(rawG1(D), raw(640), raw(544), raw(704), u256(zeta), u256(v)));
  const u = be(uRaw) % R;
  t({ v, u, lin: lin.toAffine(), r0 });

  // 10. final 2-pairing check: e(F, [1]_2) * e(-Q, [x]_2) == 1
  //   F = D + u[Z] - (e + u*zu)[1]_1 + zeta[Wz] + u*zeta*omega[Wzw],   Q = [Wz] + u[Wzw]
  let F = padd(D, smul(Z, u, 'proof'));
  F = padd(F, smul(vk.g1, sub(0n, add(e, mul(u, zu))), 'fixed'));
  F = padd(F, smul(Wz, zeta, 'proof'));
  F = padd(F, smul(Wzw, mul(mul(u, zeta), vk.omega), 'proof'));
  const Q = padd(Wz, smul(Wzw, u, 'proof'));
  C.pairings += 2;
  const res = bn254.pairingBatch([{ g1: F, g2: vk.g2 }, { g1: Q.negate(), g2: vk.g2x }]);
  if (!Fp12.eql(res, Fp12.ONE)) throw new Error('pairing check failed');
  return true;
};

const tryVerify = (vk, proof, pub) => { try { return { ok: verify(vk, proof, pub) }; } catch (err) { return { ok: false, reason: err.message }; } };

// ---- CLI ----
const here = dirname(fileURLToPath(import.meta.url));
const vecDir = join(here, 'vectors');
const files = readdirSync(vecDir).filter((f) => f.endsWith('.json')).sort();
const load = (f) => JSON.parse(readFileSync(join(vecDir, f), 'utf8'));
const args = process.argv.slice(2);

if (args[0] === '--trace') {
  const d = load(`${args[1] ?? 'mul2'}.json`);
  const vk = parseVK(d.vk.hex), p = d.valid[Number(args[2] ?? 0)];
  verify(vk, p.proof, p.publicInputs, (o) => console.log(JSON.stringify(o, (_, x) => (typeof x === 'bigint' ? x.toString() : x), 2)));
  console.log('accepted');
} else if (args[0] === '--counts') {
  for (const f of files) {
    const d = load(f); const vk = parseVK(d.vk.hex); resetCounts();
    verify(vk, d.valid[0].proof, d.valid[0].publicInputs);
    const blocks = C.sha256.reduce((a, h) => a + Math.floor((h.bytes + 8) / 64) + 1, 0);
    console.log(JSON.stringify({ circuit: d.circuit.name, n: d.circuit.domainSize, nbPublic: d.circuit.nbPublic, ...C, sha256Blocks: blocks }, null, 1));
  }
} else {
  let bad = 0, total = 0;
  for (const f of files) {
    const d = load(f); const vk = parseVK(d.vk.hex);
    let acc = 0, rej = 0; const reasons = {};
    for (const p of d.valid) { total++; let r0; const r = (() => { try { return { ok: verify(vk, p.proof, p.publicInputs, (o) => { if (o.r0 !== undefined) r0 = o.r0; }) }; } catch (err) { return { ok: false, reason: err.message }; } })();
      if (p.linOpening && r0 !== BigInt('0x' + p.linOpening)) { bad++; console.log(`UNEXPECTED ${f}: recomputed r0 differs from gnark's ClaimedValues[0]`); } if (r.ok) acc++; else { bad++; console.log(`UNEXPECTED reject ${f} valid: ${r.reason}`); } }
    for (const p of d.tampered) {
      total++; const r = tryVerify(vk, p.proof, p.publicInputs);
      if (r.ok) { bad++; console.log(`UNEXPECTED accept ${f} ${p.name}`); } else { rej++; const k = r.reason.replace(/^(L|R|O|H\d|Z|Wzeta|WzetaOmega|public input \d|l|r|o|s1|s2|z\(zeta\*omega\))(:| >=)/, '<x>$2'); reasons[k] = (reasons[k] ?? 0) + 1; }
    }
    console.log(`${d.circuit.name}: valid ${acc}/${d.valid.length} accepted, tampered ${rej}/${d.tampered.length} rejected`);
    console.log('  rejection reasons:', JSON.stringify(reasons));
  }
  console.log(bad === 0 ? `OK: ${total} cases, 0 unexpected` : `FAIL: ${bad} unexpected of ${total}`);
  process.exit(bad === 0 ? 0 : 1);
}
