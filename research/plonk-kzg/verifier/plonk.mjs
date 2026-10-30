// gnark v0.16.4 PLONK/KZG (BN254, SHA-256 transcript, with or without BSB22 commitments) as the CashVM verifier computes it:
//   - decode + checks + the gnark transcript (gamma, beta, alpha, zeta, v) exactly as the prover track's verify.mjs;
//   - our two verifier-side substitutions (DESIGN.md section 3.3, plan B):
//       u, t' from uRaw = SHA256("u" || v_raw || W_zeta || W_zetaOmega): u1, u2 = LE u64 of bytes [0,8), [8,16),
//       u = u1 + lambda u2 (mod r) (G1 GLV eigenvalue), t' = LE u128 of bytes [16,32);
//       Lambda' (the linearised commitment) is a 64-byte witness, hashed into v; the pairing input is
//       P* = rest + (1 + t') Lambda' - t' Lambda_MSM  =  P_left + (1 + t')(Lambda' - Lambda);
//   - the MSM schedule (signed base-32 digits, 16-entry tables, affine with witnessed slopes or Jacobian),
//     shared by the witness generator here and the script generator (script.mjs).
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {bn254} from '@noble/curves/bn254.js';
import {p, r, mod, inv, powm, G1, G2, F2, GLV, OFFSET, aff} from './math.mjs';
import {FIXED_NAMES, gtConsts, nibbles} from './gt.mjs';

export const PROVER_DIR = process.env.PROVER_DIR ?? new URL('../prover/', import.meta.url).pathname; // research/plonk-kzg/prover/
export const loadVectors = (name) => JSON.parse(readFileSync(new URL(`./vectors/${name}.json`, import.meta.url)));
export const sha = (...xs) => createHash('sha256').update(Buffer.concat(xs.map((x) => Buffer.from(x)))).digest();
export const be = (b) => (b.length ? BigInt('0x' + Buffer.from(b).toString('hex')) : 0n);
export const be32 = (x) => Buffer.from(x.toString(16).padStart(64, '0'), 'hex');
export const le = (b) => be(Buffer.from(b).reverse());
export const le32 = (x) => { assert.ok(x >= 0n && x < 1n << 256n); return be32(x).reverse(); };
export class Reject extends Error {}
const rej = (why) => { throw new Reject(why); };

// ---------------- VK (944 B, or 944 + 8 + 72 m with m BSB22 commitments: FORMAT.md of the prover track) ----------------
export const VK_NAMES = ['S1', 'S2', 'S3', 'Ql', 'Qr', 'Qm', 'Qo', 'Qk'];
// BSB22 hash-to-field (gnark-crypto fr.Hash, RFC 9380 expand_message_xmd, SHA-256, DST "BSB22-Plonk", 48 bytes mod r)
export const HTF_DST = Buffer.from('BSB22-Plonk');
export const htfParts = (msg) => { const dstp = Buffer.concat([HTF_DST, Buffer.from([HTF_DST.length])]);
  const b0 = sha(Buffer.alloc(64), msg, Buffer.from([0, 48, 0]), dstp), b1 = sha(b0, Buffer.from([1]), dstp);
  const b2 = sha(Buffer.from(b0.map((x, i) => x ^ b1[i])), Buffer.from([2]), dstp); return {b0, b1, b2, value: be(Buffer.concat([b1, b2.subarray(0, 16)])) % r}; };
export function parseVK(hex, {fold = process.env.FOLD !== '0'} = {}) {
  const b = Buffer.from(hex, 'hex'); assert.ok(b.length === 944 || (b.length >= 952 && (b.length - 952) % 72 === 0), 'vk length');
  const n = b.readBigUInt64BE(0), nbPublic = Number(b.readBigUInt64BE(8));
  // k >= 1: alpha^2 L_1(zeta) is read from the first batch-inverse entry, which is 1/(zeta - omega^0) only when the first
  // Lagrange point is a public input's (with k = 0 and a BSB22 commitment it would be the commitment's 1/(zeta - omega^cci))
  assert.ok(nbPublic >= 1, 'k = 0 unsupported: L_1(zeta) uses the omega^0 denominator of the first public input');
  const vk = {fold, n, log2n: n.toString(2).length - 1, nbPublic, omega: be(b.subarray(16, 48)), nInv: be(b.subarray(48, 80)), k: be(b.subarray(80, 112)), raw: {}, pt: {}};
  assert.equal(1n << BigInt(vk.log2n), n);
  VK_NAMES.forEach((nm, i) => { const s = b.subarray(112 + 64 * i, 176 + 64 * i); vk.raw[nm] = s; const x = be(s.subarray(0, 32)), y = be(s.subarray(32)); vk.pt[nm] = x === 0n && y === 0n ? null : G1.fromAffine({x, y}); });
  const g1 = G1.fromAffine({x: be(b.subarray(624, 656)), y: be(b.subarray(656, 688))}); assert.ok(g1.equals(G1.BASE));
  const g2 = (o) => { const f = (i) => be(b.subarray(o + 32 * i, o + 32 * i + 32)); const Q = G2.fromAffine({x: F2.create({c0: f(1), c1: f(0)}), y: F2.create({c0: f(3), c1: f(2)})}); Q.assertValidity(); return Q; };
  vk.g2 = g2(688); vk.g2x = g2(816); assert.ok(vk.g2.equals(G2.BASE));
  assert.equal(powm(vk.omega, n, r), 1n); assert.equal(mod(vk.nInv * n, r), 1n);
  vk.omegaPow = Array.from({length: vk.nbPublic}, (_, i) => powm(vk.omega, BigInt(i), r));
  // BSB22 tail: u64 m, then per commitment u64 CommitmentConstraintIndex, [Qcp_j]
  vk.m = b.length > 944 ? Number(b.readBigUInt64BE(944)) : 0; assert.equal(b.length, vk.m ? 952 + 72 * vk.m : 944);
  vk.cci = []; vk.qcpNames = [];
  for (let j = 0; j < vk.m; j++) { const o = 952 + 72 * j, nm = 'Qcp' + j; vk.cci.push(b.readBigUInt64BE(o)); const s = b.subarray(o + 8, o + 72); vk.raw[nm] = s; vk.qcpNames.push(nm);
    const x = be(s.subarray(0, 32)), y = be(s.subarray(32)); assert.ok(x || y, 'Qcp at infinity is not supported'); vk.pt[nm] = G1.fromAffine({x, y}); }
  // Lagrange points of the commitment hashes: omega^(nbPublic + cci_j); they join the batch inversion after the k public ones
  vk.cmtPow = vk.cci.map((c) => powm(vk.omega, BigInt(vk.nbPublic) + c, r));
  vk.denPow = [...vk.omegaPow, ...vk.cmtPow];
  assert.equal(new Set(vk.denPow).size, vk.denPow.length, 'Lagrange indices collide');
  vk.rawAll = Buffer.concat([...VK_NAMES, ...vk.qcpNames].map((nm) => vk.raw[nm])); // gnark's gamma binds S1..Qk then Qcp_j
  return vk;
}

// ---------------- MSM schedule ----------------
export const W = 5, TBL = 16, NW = 51, NWR = 14; // window bits, table entries (1..16), windows (main / P_right)
// base list (index b). Qk (or any VK point) equal to infinity is dropped (circuit-specific constant).
// fold (default, Track 7): the fixed bases (VK points, Qcp_j, [1]_1) are applied in GT (gt.mjs) and the G1 MSM runs over
// the variable bases only. BSB22: Qcp_j is a fixed base (KZG fold, scalar v^(6+j)); Bsb22_j is a variable (proof) base
// (linearisation, scalar -t' qcp_j(zeta)). FOLD=0 gives Track 6's order with the BSB22 bases inserted.
export const fixedNames = (vk) => [...FIXED_NAMES.filter((nm) => nm !== 'G' && vk.pt[nm]), ...(vk.qcpNames ?? []), 'G'];
export const bsbNames = (vk) => Array.from({length: vk.m ?? 0}, (_, j) => 'Bsb' + j);
export const baseNames = (vk) => [...(vk.fold ? [] : fixedNames(vk)), 'L', 'R', 'O', 'Z', 'H0', 'H1', 'H2', ...bsbNames(vk), 'Wz', 'Lam', 'Wzw', 'phiWzw'];
export const PROOF_PTS = {L: 0, R: 64, O: 128, H0: 192, H1: 256, H2: 320, Z: 544, Wz: 640, Wzw: 704};
export const proofLen = (vk) => 768 + 96 * (vk.m ?? 0); // + m scalars qcp_j(zeta) at 768 + 32 j, then m points Bsb22_j at 768 + 32 m + 64 j
export const bsbOff = (vk, j) => 768 + 32 * vk.m + 64 * j;
export const recode = (s, nw) => { assert.ok(s >= 0n); const d = []; for (let i = 0; i < nw; i++) { let x = Number(s & 31n); if (x >= 16) x -= 32; d.push(x); s = (s - BigInt(x)) >> 5n; } assert.equal(s, 0n, 'recoding overflow'); return d; };
export const corr = (nw) => OFFSET.multiply(mod(-(1n << BigInt(W * nw)), r)); // added after the loop (every window starts with W doublings)

// ---------------- the verifier (value level), with the witness it needs ----------------
// opts.lam: override the Lambda' witness (affine [x, y]); returns {accept, ...} or throws Reject
export function verifyPlonk(vk, proofHex, pubHex, opts = {}) {
  const pb = Buffer.from(proofHex, 'hex'); if (pb.length !== proofLen(vk)) rej('proof length');
  if (pubHex.length !== vk.nbPublic) rej('public input count');
  const pubRaw = pubHex.map((h) => Buffer.from(h, 'hex')); if (pubRaw.some((b) => b.length !== 32)) rej('public input length');
  const pub = pubRaw.map((b) => { const v = be(b); if (v >= r) rej('public input >= r'); return v; });
  const sc = (o) => { const v = be(pb.subarray(o, o + 32)); if (v >= r) rej('scalar >= r'); return v; };
  const [l, rr, o, s1, s2] = [384, 416, 448, 480, 512].map(sc); const zu = sc(608);
  const decodePt = (b, what) => { const x = be(b.subarray(0, 32)), y = be(b.subarray(32, 64)); if (x >= p || y >= p) rej(what + ' coordinate >= p'); if (mod(y * y - x * x * x - 3n) !== 0n) rej(what + ' not on curve'); return G1.fromAffine({x, y}); };
  const raw = (off) => pb.subarray(off, off + 64);
  const P = Object.fromEntries(Object.entries(PROOF_PTS).map(([nm, off]) => [nm, decodePt(raw(off), nm)]));
  const m = vk.m, qcpZ = Array.from({length: m}, (_, j) => sc(768 + 32 * j));
  for (let j = 0; j < m; j++) P['Bsb' + j] = decodePt(raw(bsbOff(vk, j)), 'Bsb22_' + j);
  const bsbRaw = pb.subarray(bsbOff(vk, 0), pb.length);
  // transcript (gnark): gamma binds Qcp_j (in rawAll); alpha binds Bsb22_j before Z
  const gammaRaw = sha('gamma', vk.rawAll, ...pubRaw, pb.subarray(0, 192));
  const betaRaw = sha('beta', gammaRaw), alphaRaw = sha('alpha', betaRaw, bsbRaw, raw(544)), zetaRaw = sha('zeta', alphaRaw, pb.subarray(192, 384));
  const [gamma, beta, alpha, zeta] = [gammaRaw, betaRaw, alphaRaw, zetaRaw].map((x) => be(x) % r);
  // Fr block
  const M = (a, b) => mod(a * b, r);
  let zn = zeta; for (let i = 0; i < vk.log2n; i++) zn = M(zn, zn);
  const zh = mod(zn - 1n, r);
  const dens = vk.denPow.map((w) => mod(zeta - w, r)); const prod = dens.reduce(M, 1n);
  if (prod === 0n) rej('zeta in the domain');
  const invProd = opts.invProd ?? inv(prod, r); if (M(prod, invProd) !== 1n) rej('batch inverse');
  const invDens = dens.map((_, i) => dens.reduce((a, d, j) => (j === i ? a : M(a, d)), invProd));
  const zhOverN = M(zh, vk.nInv);
  const hc = Array.from({length: m}, (_, j) => htfParts(raw(bsbOff(vk, j))).value); // hash-to-field of each commitment
  const pi = [...pub, ...hc].reduce((a, x, i) => mod(a + M(M(M(zhOverN, invDens[i]), vk.denPow[i]), x), r), 0n);
  const alpha2L1 = M(M(alpha, alpha), M(zhOverN, invDens[0]));
  const t1 = mod(l + M(beta, s1) + gamma, r), t2 = mod(rr + M(beta, s2) + gamma, r);
  const r0 = mod(alpha2L1 - pi - M(M(M(M(t1, t2), mod(o + gamma, r)), alpha), zu), r);
  const s1c = M(M(M(M(t1, t2), beta), alpha), zu);
  const bz = M(beta, zeta);
  const s2c = mod(alpha2L1 - M(M(M(mod(l + bz + gamma, r), mod(rr + M(bz, vk.k) + gamma, r)), mod(o + M(bz, M(vk.k, vk.k)) + gamma, r)), alpha), r);
  const zn2 = M(zn, M(zeta, zeta));
  // Lambda (true) and the witness Lambda'
  const lin = [['Ql', l], ['Qr', rr], ['Qm', M(l, rr)], ['Qo', o], ['Qk', 1n], ['S3', s1c]].filter(([nm]) => vk.pt[nm]).map(([nm, s]) => [vk.pt[nm], s])
    .concat([[P.Z, s2c], [P.H0, mod(-zh, r)], [P.H1, mod(-M(zh, zn2), r)], [P.H2, mod(-M(zh, M(zn2, zn2)), r)]])
    .concat(qcpZ.map((q, j) => [P['Bsb' + j], q]));
  const smul = (B, s) => (mod(s, r) === 0n ? G1.ZERO : B.multiply(mod(s, r)));
  const Lam = lin.reduce((a, [B, s]) => a.add(smul(B, s)), G1.ZERO);
  const lamAff = opts.lam ?? (Lam.is0() ? [0n, 0n] : aff(Lam));
  if (lamAff[0] >= p || lamAff[1] >= p) rej('Lambda coordinate >= p');
  if (mod(lamAff[1] ** 2n - lamAff[0] ** 3n - 3n) !== 0n) rej('Lambda not on curve');
  const LamW = G1.fromAffine({x: lamAff[0], y: lamAff[1]});
  const lamRaw = Buffer.concat([be32(lamAff[0]), be32(lamAff[1])]);
  // v (kzg.FoldProof), e
  const qcpRaw = pb.subarray(768, 768 + 32 * m);
  const vRaw = sha('gamma', be32(zeta), lamRaw, pb.subarray(0, 192), vk.raw.S1, vk.raw.S2, ...vk.qcpNames.map((nm) => vk.raw[nm]), be32(r0), pb.subarray(384, 544), qcpRaw, pb.subarray(608, 640));
  const v = be(vRaw) % r; const vs = [1n]; for (let i = 1; i < 6 + m; i++) vs.push(M(vs[i - 1], v));
  const e = [r0, l, rr, o, s1, s2, ...qcpZ].reduce((a, x, i) => mod(a + M(vs[i], x), r), 0n);
  // ours: u, t'
  const uRaw = sha('u', vRaw, raw(640), raw(704));
  const u1 = le(uRaw.subarray(0, 8)), u2 = le(uRaw.subarray(8, 16)), tp = le(uRaw.subarray(16, 32));
  const u = mod(u1 + GLV.lambda * u2, r);
  const nt = mod(-tp, r);
  const S = {Ql: M(nt, l), Qr: M(nt, rr), Qm: M(nt, M(l, rr)), Qo: M(nt, o), Qk: nt, S3: M(nt, s1c), Z: mod(M(nt, s2c) + u, r),
    H0: M(tp, zh), H1: M(tp, M(zh, zn2)), H2: M(tp, M(zh, M(zn2, zn2))), Lam: mod(1n + tp, r), L: v, R: vs[2], O: vs[3], S1: vs[4], S2: vs[5],
    G: mod(-(e + M(u, zu)), r), Wz: zeta, Wzw: M(M(u, zeta), vk.omega)};
  for (let j = 0; j < m; j++) { S['Bsb' + j] = M(nt, qcpZ[j]); S['Qcp' + j] = vs[6 + j]; }
  const names = baseNames(vk);
  const ptOf = (nm) => (nm === 'G' ? G1.BASE : nm === 'Lam' ? LamW : nm === 'phiWzw' ? G1.fromAffine({x: mod(GLV.beta * aff(P.Wzw)[0]), y: aff(P.Wzw)[1]}) : P[nm] ?? vk.pt[nm]);
  const bases = names.map(ptOf);
  const Pstar = names.slice(0, -1).reduce((a, nm, i) => a.add(smul(bases[i], S[nm])), G1.ZERO); // P*_var when folded
  const Pright = P.Wz.add(P.Wzw.multiply(u)).negate();
  if (Pstar.is0() || Pright.is0()) rej('pairing input at infinity');
  let PstarFull = Pstar, gt = null;
  if (vk.fold) { const fixed = fixedNames(vk), fs = fixed.map((nm) => mod(S[nm], r));
    PstarFull = fixed.reduce((a, nm, i) => (fs[i] ? a.add((nm === 'G' ? G1.BASE : vk.pt[nm]).multiply(fs[i])) : a), Pstar);
    gt = {G: gtConsts(vk, fixed), fixed, fs, ...nibbles(fs)}; }
  const ok = !PstarFull.is0() && bn254.fields.Fp12.eql(bn254.pairingBatch([{g1: PstarFull, g2: vk.g2}, {g1: Pright, g2: vk.g2x}]), bn254.fields.Fp12.ONE);
  return {ok, Pstar, PstarFull, Pright, names, bases, S, u1, u2, tp, u, uRaw, vRaw, lamAff, invProd, pub, gamma, beta, alpha, zeta, v, r0, e, lamTrue: Lam, gt, hc, qcpZ};
}

// Jacobian formulas exactly as the script's kernels (EFD dbl-2009-l, madd-2007-bl); H = 0 (exceptional) is fatal here
export const jdbl = ([X, Y, Z]) => { const A = mod(X * X), B = mod(Y * Y), C = mod(B * B), D = mod(2n * ((X + B) ** 2n - A - C)), E = 3n * A, F = mod(E * E);
  const X3 = mod(F - 2n * D); return [X3, mod(E * (D - X3) - 8n * C), mod(2n * Y * Z)]; };
export const jmadd = ([X1, Y1, Z1], [x2, y2]) => { const Z1Z1 = mod(Z1 * Z1), U2 = mod(x2 * Z1Z1), S2 = mod(y2 * Z1 * Z1Z1), H = mod(U2 - X1); if (H === 0n) throw new Error('exceptional madd');
  const HH = mod(H * H), I4 = 4n * HH, J = mod(H * I4), rr = 2n * (S2 - Y1), V = mod(X1 * I4); const X3 = mod(rr * rr - J - 2n * V);
  return [X3, mod(rr * (V - X3) - 2n * Y1 * J), mod((Z1 + H) ** 2n - Z1Z1 - HH)]; };
// ---------------- MSM witness (exactly the script's consumption order) ----------------
// J / JR: number of leading windows run in Jacobian (main / P_right). Returns the slope stream and the inverses.
export function msmWitness(vk, V, {J = 0, JR = 0} = {}) {
  const slopes = [];
  const add = (A, B) => { const [x1, y1] = A, [x2, y2] = B; if (x1 === x2) throw new Error('exceptional affine add'); const l = mod((y2 - y1) * inv(x2 - x1)); slopes.push(l); const x3 = mod(l * l - x1 - x2); return [x3, mod(l * (x1 - x3) - y1)]; };
  const dbl = (A) => { const [x, y] = A; const l = mod(3n * x * x * inv(2n * y)); slopes.push(l); const x3 = mod(l * l - 2n * x); return [x3, mod(l * (x - x3) - y)]; };
  const nb = V.names.length;
  // tables: base b entries k = 1..16; the phi table is (beta x, y) of the Wzw table (no slopes)
  const T = [];
  for (let b = 0; b < nb - 1; b++) { const e = [aff(V.bases[b])]; e.push(dbl(e[0])); for (let k = 3; k <= TBL; k++) e.push(add(e[k - 2], e[0])); T.push(e); }
  T.push(T[nb - 2].map(([x, y]) => [mod(GLV.beta * x), y]));
  for (let b = 0; b < nb; b++) for (let k = 1; k <= TBL; k++) assert.deepEqual(T[b][k - 1], aff(V.bases[b].multiply(BigInt(k))));
  const inverses = [];
  const run = (bIdx, scal, nw, jw) => {
    const dig = scal.map((s) => recode(s, nw));
    let A = aff(OFFSET), Jc = jw > 0 ? [...aff(OFFSET), 1n] : null;
    for (let i = nw - 1; i >= 0; i--) {
      const jac = i >= nw - jw;
      for (let k = 0; k < W; k++) { if (jac) Jc = jdbl(Jc); else A = dbl(A); }
      for (let q = bIdx.length - 1; q >= 0; q--) { const d = dig[q][i]; if (!d) continue; let [x, y] = T[bIdx[q]][Math.abs(d) - 1]; if (d < 0) y = mod(-y);
        if (jac) Jc = jmadd(Jc, [x, y]); else A = add(A, [x, y]); }
      if (jac && i === nw - jw) { const zi = inv(Jc[2]); inverses.push(zi); A = [mod(Jc[0] * zi * zi), mod(Jc[1] * zi * zi * zi)]; } // the script checks Z zi == 1
    }
    return add(A, aff(corr(nw)));
  };
  const nbm = nb - 1;
  let PR = run([nb - 2, nb - 1], [V.u1, V.u2], NWR, JR); PR = add(PR, aff(V.bases[V.names.indexOf('Wz')])); PR = [PR[0], mod(-PR[1])];
  const PL = run(Array.from({length: nbm}, (_, b) => b), V.names.slice(0, nbm).map((nm) => V.S[nm]), NW, J);
  assert.deepEqual(PL, aff(V.Pstar), 'MSM P*'); assert.deepEqual(PR, aff(V.Pright), 'MSM P_right');
  return {slopes, Pleft: PL, Pright: PR, inverses};
}
