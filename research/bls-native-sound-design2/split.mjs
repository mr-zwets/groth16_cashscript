// Multi-input split of the BLS12-381 SI-GLS protocol (value level): builds every input's single witness push
// W_j = P1_j | Q_j | K_j | IN_j | CB | PAD (fixed sizes per role), the transcript over all inputs, the challenges,
// the handoffs (T, R) between consecutive inputs, and checks the conjunction of all inputs' checks.
// The skeleton prototype (proto_skeleton.mjs) runs parts of this in the VM and compares against these values.
import assert from 'node:assert/strict';
import {encodeDataPush} from '@bitauth/libauth';
import {p, r, mod, F2, X_ABS, XPOW, NE, BITS, peval, pneg, psi, frob1Monic, M, G1, B_TWIST} from './blsmath.mjs';
import {prove, quotient, VKC, glsFactorPoly, uniformBounds, nqMax, le, rdle, sha, toFp} from './protocol.mjs';

export const TAG = Buffer.from('BLS-SIGLS-MI/1');
export const W = 48;
// broadcast area (bcast layout), in decode order: challenges, z powers, loop environment, c^-1 at +-z, then the four
// GT-GLS tables, each from entry 15 down to entry 0 so that entry n ends at depth d0 + n
export const BC_NAMES = ['z', 'rho', 'z2', 'z3', 'z4', 'z5', 'z6', 't', 'xz2', 'xz2t', 'xz23', 'xz23t', 'yz3', 'yz3t', 'cz2', 'cz2t', 'ycz3', 'cp', 'cm',
  ...['TP0', 'TM0', 'TP1', 'TM1'].flatMap((T) => Array.from({length: 16}, (_, i) => `${T}_${15 - i}`))];
// layout: {N, chunks: [[c0, c1] per input] (event inputs = all N; the last one runs the terminal), q: [words per input], cbHost, pad: [bytes]}
export function buildSplit(pf, layout, {blob = Buffer.alloc(layout.cbBytes ?? 6800, 0x61), bounds = uniformBounds(2)} = {}) {
  const parts = layout.cbParts ?? [{host: layout.cbHost, len: blob.length}]; assert.equal(parts.reduce((a, x) => a + x.len, 0), blob.length, 'blob parts');
  const partOf = (j) => { let o = 0; for (const x of parts) { if (x.host === j) return blob.subarray(o, o + x.len); o += x.len; } return Buffer.alloc(0); };
  const pr = prove(pf, {bounds}); const {st, Sc, states, N: nib, ns} = pr; const NI = layout.N;
  const NQ = nqMax(bounds); assert.equal(layout.q.reduce((a, b) => a + b, 0), NQ, 'quotient words must sum to NQ');
  const w = (x) => le(mod(x), W);
  const STMT = Buffer.concat([st.xA, st.yA, st.xB.c0, st.xB.c1, st.yB.c0, st.yB.c1, st.xC, st.yC].map(w).concat(ns.map((n) => le(n, 32))));
  const NIB = Buffer.concat(nib.map((Nk) => Buffer.from(Nk))); // 2 x 64 bytes (event 0..63)
  const SC = Buffer.concat(Sc.slice(0, 6).map(w));
  const ST = (k) => Buffer.concat(states[k].slice(0, 6).map(w)); // S_{k+1} (closing state of chunk k)
  const P1 = layout.chunks.map(([c0, c1], j) => Buffer.concat([...(j === 0 ? [STMT, NIB, SC] : []), ...Array.from({length: c1 - c0}, (_, i) => ST(c0 + i))]));
  const K = layout.chunks.map(([c0, c1]) => { const e0 = c0 ? bounds[c0 - 1] : 0, e1 = bounds[c1 - 1];
    return Buffer.concat(VKC.lines.filter((l) => l.e >= e0 && l.e < e1).flatMap((l) => [w(l.c.c0), w(l.c.c1), w(l.lam.c0), w(l.lam.c1)])); });
  // witness sizes are fixed by the layout; the push header of W_j is PUSHDATA2 (3 bytes) for 256 <= |W_j| <= 65535
  const BCW = layout.bcast ? BC_NAMES.length : 0;
  const sizes = layout.chunks.map((_, j) => P1[j].length + layout.q[j] * W + K[j].length + (j ? 7 * W : 0) + (j === 0 ? BCW * W : 0) + partOf(j).length + layout.pad[j]);
  const hdr = (n) => Buffer.from(encodeDataPush(new Uint8Array(n)).subarray(0, 3));
  // transcript phase 1: h = SHA256(TAG | U_0[0, 3+|P1_0|]); h = SHA256(h | U_j[0, 3+|P1_j|])
  let h = sha(TAG, hdr(sizes[0]), P1[0]); for (let j = 1; j < NI; j++) h = sha(h, hdr(sizes[j]), P1[j]);
  const h0 = h, rhoRaw = sha(h0, Buffer.from('rho')), rho = toFp(rhoRaw);
  const q = quotient(pr, rho, NQ); // q_0..q_{NQ-1}, coefficient of X^(2j+1)
  const WQ = Buffer.concat(q.slice().reverse().map(w)); // highest first
  const Qseg = []; { let o = 0; for (let j = 0; j < NI; j++) { Qseg.push(WQ.subarray(o, o + layout.q[j] * W)); o += layout.q[j] * W; } }
  const zRaw = sha(h0, rhoRaw, WQ), z = toFp(zRaw); assert.ok(z !== 0n);
  // value-level run, input by input
  const zm = mod(-z), Sfull = [pneg(Sc), ...states]; const cp = peval(Sfull[0], z), cm = peval(Sfull[0], zm);
  let T = [st.xB, st.yB, F2.ONE], R = 0n; const IN = [null]; const trace = [];
  for (let j = 0; j < NI; j++) {
    const [c0, c1] = layout.chunks[j]; let Fp_ = peval(Sfull[c0], z), Fm_ = peval(Sfull[c0], zm);
    for (let k = c0; k < c1; k++) {
      for (let e = k ? bounds[k - 1] : 0; e < bounds[k]; e++) {
        const ev = pr.sched.events[e]; if (e) { Fp_ = mod(Fp_ * Fp_); Fm_ = mod(Fm_ * Fm_); }
        for (const f of ev.fs) { Fp_ = mod(Fp_ * peval(f, z)); Fm_ = mod(Fm_ * peval(f, zm)); }
        if (ev.add) { Fp_ = mod(Fp_ * cp); Fm_ = mod(Fm_ * cm); }
        T = ev.Tafter;
      }
      const S = Sfull[k + 1]; const Sp = peval(S, z), Sm = peval(S, zm); R = mod(R * rho + Fp_ * Sm - Fm_ * Sp); Fp_ = Sp; Fm_ = Sm;
    }
    trace.push({j, T, R, F: [Fp_, Fm_]});
    if (j + 1 < NI) IN.push(Buffer.concat([...T.flatMap((c) => [w(c.c0), w(c.c1)]), w(R)]));
    else { // terminal: F <- F Rconst(+-z); R <- R rho + F+ Frob(Sc)(-z) - F- Frob(Sc)(z); endpoint; quotient
      Fp_ = mod(Fp_ * peval(VKC.Rconst, z)); Fm_ = mod(Fm_ * peval(VKC.Rconst, zm));
      const Fr = frob1Monic(Sc); R = mod(R * rho + Fp_ * peval(Fr, zm) - Fm_ * peval(Fr, z));
      const [px, py] = psi(st.xB, st.yB); const [X, Y, Z] = T;
      const endpoint = !F2.is0(Z) && F2.eql(X, F2.mul(px, Z)) && F2.eql(Y, F2.mul(F2.neg(py), Z));
      let acc = 0n; const z2 = mod(z * z); for (let i = 0; i < NQ; i++) acc = mod(acc * z2 + rdle(WQ, W * i));
      const rhs = mod(z * acc * peval(M, z));
      // GLS binding: sum_e 2^(63-e) TB[N_k[e]] = n_k exactly, TB[n] = sum_{i in n} |x|^i
      const bind = [0, 1].every((k) => { let a = 0n; for (let e = 0; e <= NE; e++) { a *= 2n; for (let i = 0; i < 4; i++) if ((nib[k][e] >> i) & 1) a += XPOW[i]; } return a === ns[k]; });
      const curves = mod(st.yA ** 2n - st.xA ** 3n - 4n) === 0n && mod(st.yC ** 2n - st.xC ** 3n - 4n) === 0n && F2.eql(F2.sqr(st.yB), F2.add(F2.mul(F2.sqr(st.xB), st.xB), B_TWIST));
      trace.push({final: {R, rhs, ok: R === rhs, endpoint, bind, curves}});
    }
  }
  const final = trace.at(-1).final; if (process.env.DBG) console.error(final); assert.ok(process.env.NOASSERT || final.ok && final.endpoint && final.bind && final.curves, 'multi-input conjunction must accept the honest proof');
  // broadcast values (bcast layout): exactly what input 0 computes from the challenges and the statement
  const bcVals = (() => { const z2 = mod(z * z), z3 = mod(z2 * z), z4 = mod(z2 * z2), z5 = mod(z4 * z), z6 = mod(z3 * z3), t = mod(z6 - 1n);
    const xz2 = mod(st.xA * z2), yz3 = mod(st.yA * z3), cz2 = mod(st.xC * z2), xz23 = mod(3n * xz2);
    const v = {z, rho, z2, z3, z4, z5, z6, t, xz2, xz2t: mod(xz2 * t), xz23, xz23t: mod(xz23 * t), yz3, yz3t: mod(yz3 * t), cz2, cz2t: mod(cz2 * t), ycz3: mod(st.yC * z3), cp, cm};
    for (const k of [0, 1]) { const vp = [0, 1, 2, 3].map((i) => peval(glsFactorPoly(k, i), z)), vmm = [0, 1, 2, 3].map((i) => peval(glsFactorPoly(k, i), zm));
      for (const [nm, vv] of [[`TP${k}`, vp], [`TM${k}`, vmm]]) for (let n = 0; n < 16; n++) { let a = 1n; for (let b = 0; b < 4; b++) if ((n >> b) & 1) a = mod(a * vv[b]); v[`${nm}_${n}`] = a; } }
    return BC_NAMES.map((n) => { assert.ok(v[n] !== undefined, n); return v[n]; }); })();
  const BC = layout.bcast ? Buffer.concat(bcVals.map(w)) : Buffer.alloc(0);
  const Wj = layout.chunks.map((_, j) => Buffer.concat([P1[j], Qseg[j], K[j], ...(j ? [IN[j]] : []), ...(j === 0 ? [BC] : []), partOf(j), Buffer.alloc(layout.pad[j])]));
  Wj.forEach((x, j) => assert.equal(x.length, sizes[j]));
  const offsets = layout.chunks.map((_, j) => { let o = 0; const at = {}; at.P1 = o; o += P1[j].length; at.Q = o; o += Qseg[j].length; at.K = o; o += K[j].length; if (j) { at.IN = o; o += 7 * W; } if (j === 0) { at.BC = o; o += BC.length; } if (partOf(j).length) { at.CB = o; o += partOf(j).length; } at.PAD = o; return at; });
  return {pr, P1, K, Qseg, WQ, IN, BC, bcVals, Wj, sizes, offsets, h0, rhoRaw, rho, zRaw, z, trace, final, STMT, NIB, SC, Khash: K.map((k) => sha(k))};
}
