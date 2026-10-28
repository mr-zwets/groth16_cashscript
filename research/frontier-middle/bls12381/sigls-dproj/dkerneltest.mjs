// Value-level trace test of the on-chain delta kernels against DPROJ (review item), and ROLE.B against the reviewed kernels.
//   node dkerneltest.mjs [trials]       (default 4; output in dkerneltest.log)
//
// 1. delta (ROLE.D). The delta walk does not depend on the input; its only input-dependent use is the evaluation of each
//    line at P = C and +-z. The DDBL / DADD kernels (kProjDbl(ROLE.D), kProjAdd(ROLE.D)) are compiled ALONE with the
//    redeem's assembler and scheduler and run on the VM at every one of the 68 steps, fed the DPROJ walk point before
//    that step (DPROJ asserts every point against noble's [k]delta), the baked delta, a fixture C and its +-z
//    environment exactly as the script builds it (t = z^6 - 1, cz2 = xC z^2, cz2t = cz2 t, oC = yC z^3, oCt = oC t),
//    and independent uniform random F+, F- and z. Asserted mod p at every step:
//      - the output point equals the next DPROJ point, coordinate by coordinate (the same projective representative);
//      - F+ out = F+ * L_j(z) and F- out = F- * L_j(-z), with L_j = lineGenPoly(xC, yC, DPROJ.lines[j]), the line DPROJ
//        asserted to be l3 * (the reviewed design's baked affine line), l3 != 0.
//    Together these tie the on-chain delta section to DPROJ at the value level at every step: points exactly, lines
//    through their evaluations at a uniform z (a wrong line polynomial of degree <= 9 in z passes one trial with
//    probability <= 9/p).
// 2. B (ROLE.B). With SL removed from the kernel I/O, the ROLE.B kernels must compute what the reviewed sound-si-gls
//    kProjDbl / kProjAdd compute. Both are compiled with their own assembler and run on the VM at the same independent
//    uniform random inputs (point, environment, F+-, the reviewed SL pass-through); every output except SL must agree
//    mod p, and both must equal the projDbl / projAdd + lineGenPoly reference (F+ <- F+^2 L(z) for the doubling,
//    F+ <- F+ L(z) S_c(-z) for the addition, P = -A).
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {bigIntToVmNumber} from '@bitauth/libauth';
import {Asm} from './asm.mjs';
import {Asm as AsmReviewed} from '../../../../chunked/bls12-381/sound-si-gls/asm.mjs';
import {p, mod, F2, f2, peval, lineGenPoly, FIXTURES, VKC} from './math.mjs';
import {DPROJ, projDbl, projAdd} from './protocol.mjs';
import {kProjDbl, kProjAdd, ROLE} from './script.mjs';
import {kProjDbl as kProjDblReviewed, kProjAdd as kProjAddReviewed} from '../../../../chunked/bls12-381/sound-si-gls/script.mjs';
import {bare, num} from './vm.mjs';

const TRIALS = Number(process.argv[2] ?? 4);
const rnd = () => mod(BigInt('0x' + randomBytes(64).toString('hex')));
const rnd2 = () => f2(rnd(), rnd());

// compile K (every referenced name and p on the stack, in insertion order), run it, return the outputs mod p
function runKernel(K, vals, AsmClass = Asm) {
  const names = [...K.refs.keys()]; for (const n of names) assert.ok(n in vals, 'no value for ' + n);
  const a = new AsmClass([...names, 'p']); const outs = K.outs.map((_, i) => 'out' + i); a.kernel(K, outs, {iters: 300});
  const res = bare(Uint8Array.from(a.code), [...names.map((n) => mod(BigInt(vals[n]))), p].map((v) => bigIntToVmNumber(v)));
  // the kernel runs to the end; the only error allowed is the final clean-stack rule (outputs are left on the stack)
  assert.ok(res.error === undefined || /unexpected number of items on the stack/.test(res.error), 'kernel VM error: ' + res.error);
  return res.stack.slice(-outs.length).map((b) => mod(num(b)));
}
const ptVals = (names, T) => Object.fromEntries(names.map((n, i) => [n, T[i >> 1][i & 1 ? 'c1' : 'c0']]));
const flatPt = (T) => T.flatMap((c) => [c.c0, c.c1]);
const envFor = (x, y, z) => { const z2 = mod(z * z), z3 = mod(z2 * z), t = mod(z3 * z3 - 1n), xz2 = mod(x * z2), o = mod(y * z3); return {t, xz2, xz2t: mod(xz2 * t), o, ot: mod(o * t)}; };

// ---------------- 1. delta: all 68 steps against DPROJ ----------------
assert.equal(DPROJ.points.length, 68); assert.equal(DPROJ.lines.length, 68);
const d = VKC.deltaAff; const C = FIXTURES.committed.proof.c.toAffine();
const KD = {dbl: kProjDbl(ROLE.D), add: kProjAdd(ROLE.D)};
let steps = 0;
for (let trial = 0; trial < TRIALS; trial++) {
  const z = rnd(), e = envFor(C.x, C.y, z);
  const env = {t: e.t, cz2: e.xz2, cz2t: e.xz2t, oC: e.o, oCt: e.ot, xd0: d.x.c0, xd1: d.x.c1, yd0: d.y.c0, yd1: d.y.c1};
  for (let j = 0; j < 68; j++) {
    const Fp = rnd(), Fm = rnd(), kind = DPROJ.kinds[j];
    const out = runKernel(KD[kind], {...ptVals(ROLE.D.pt, DPROJ.points[j]), ...env, Fp, Fm});
    const next = j + 1 < 68 ? DPROJ.points[j + 1] : DPROJ.end;
    assert.deepEqual(out.slice(0, 6), flatPt(next), `delta step ${j} (${kind}): point != DPROJ`);
    const L = lineGenPoly(C.x, C.y, ...DPROJ.lines[j]);
    assert.equal(out[6], mod(Fp * peval(L, z)), `delta step ${j} (${kind}): F+ != F+ * L(z)`);
    assert.equal(out[7], mod(Fm * peval(L, mod(-z))), `delta step ${j} (${kind}): F- != F- * L(-z)`);
    steps++;
  }
}
console.log(`delta kernels (ROLE.D): ${steps} steps (${TRIALS} x 68) equal DPROJ: points exactly, lines at random +-z`);

// ---------------- 2. B: ROLE.B kernels vs the reviewed kernels and the reference ----------------
let bruns = 0;
for (let trial = 0; trial < 8 * TRIALS; trial++) {
  const T = [rnd2(), rnd2(), rnd2()], xA = rnd(), yA = rnd(), z = rnd(), e = envFor(xA, mod(-yA), z); // P = -A
  const q = [rnd2(), rnd2()], Scm = rnd(), Scp = rnd(), Fp = rnd(), Fm = rnd(), SL = rnd();
  const vals = {...ptVals(ROLE.B.pt, T), t: e.t, xz2: e.xz2, xz2t: e.xz2t, oP: e.o, oPt: e.ot, xB0: q[0].c0, xB1: q[0].c1, yB0: q[1].c0, yB1: q[1].c1, Scm, Scp, Fp, Fm, SL};
  const at = (L, s) => peval(L, s);
  { const o = runKernel(kProjDbl(ROLE.B), vals), rv = runKernel(kProjDblReviewed(), vals, AsmReviewed);
    assert.deepEqual(o, rv.slice(1), 'ROLE.B doubling != reviewed kProjDbl'); // reviewed outputs SL first (pass-through)
    const r = projDbl(T), L = lineGenPoly(xA, mod(-yA), ...r.line);
    assert.deepEqual(o, [...flatPt(r.T), mod(Fp * Fp * at(L, z)), mod(Fm * Fm * at(L, mod(-z)))], 'ROLE.B doubling != reference'); }
  { const o = runKernel(kProjAdd(ROLE.B), vals), rv = runKernel(kProjAddReviewed(), vals, AsmReviewed);
    assert.deepEqual(o, rv.slice(1), 'ROLE.B addition != reviewed kProjAdd');
    const r = projAdd(T, q), L = lineGenPoly(xA, mod(-yA), ...r.line);
    assert.deepEqual(o, [...flatPt(r.T), mod(Fp * at(L, z) * Scm), mod(Fm * at(L, mod(-z)) * Scp)], 'ROLE.B addition != reference'); }
  bruns++;
}
console.log(`B kernels (ROLE.B): ${bruns} random points, doubling and addition equal the reviewed kernels (SL aside) and the reference`);
