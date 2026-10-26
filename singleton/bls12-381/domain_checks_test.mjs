// Domain-check rejection tests for the BLS12-381 singleton verifier (groth16.cash):
// coordinate range (0 <= v < p), curve equations for A, C (y^2 = x^3 + 4) and B
// (y^2 = x^3 + 4(1+u)), and the G2 subgroup check on B (psi(B) == [-x]B, fused into
// B's Miller walk with the Z != 0 guard). Valid proofs (the committed instance and the
// bench multiproof set) must still verify.
//
// Each negative case is an ordinary malformed or out-of-domain proof input; the op-cost at
// rejection shows where it failed (the range/curve checks run first, the subgroup check right
// after B's Miller loop, the pairing verdict at the very end).
//
//   node singleton/bls12-381/domain_checks_test.mjs                 # compile groth16.cash (plain)
//   node singleton/bls12-381/domain_checks_test.mjs <vectors.json>  # test that file's lockingOK
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  hexToBin, bigIntToVmNumber, encodeDataPush,
  createVirtualMachine, createInstructionSetBch2026,
  createTestAuthenticationProgramBch, ConsensusBch2025, ripemd160, secp256k1, sha1, sha256,
} from '@bitauth/libauth';
import { compileFile } from 'cashc';
import { bls12_381 } from '@noble/curves/bls12-381.js';
import { proof, PUBLIC_INPUTS } from './bls_instance.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const VDIR = (process.env.BENCH_VDIR ?? join(here, '../../../zk-verifier-bench/src/bch')) + '/';
const P = bls12_381.fields.Fp.ORDER;
const R = bls12_381.fields.Fr.ORDER;
const Fp2 = bls12_381.fields.Fp2;
const G2 = bls12_381.G2.Point;
const H2 = 0x5d543a95414e7f1091d50792876a202cd91de4547085abaa68a205b2e5a7ddfa628f1cb4d9e82ef21537e293a6691ae1616ec6e786f0c70cf1c38e31c7238e5n;

const HUGE = Number.MAX_SAFE_INTEGER;
const loosened = {
  ...ConsensusBch2025, baseInstructionCost: 100, maximumFunctionIdentifierLength: 7,
  maximumMemorySlots: HUGE, maximumStandardLockingBytecodeLength: -1,
  maximumStandardUnlockingBytecodeLength: HUGE, maximumTokenCommitmentLength: 128,
  operationCostBudgetPerByte: HUGE, maximumStackItemLength: HUGE, maximumVmNumberByteLength: HUGE,
  maximumStackDepth: HUGE, maximumControlStackDepth: HUGE, maximumBytecodeLength: HUGE, maximumOperationCount: HUGE,
};
const vm = createVirtualMachine(createInstructionSetBch2026(false, { consensus: loosened, ripemd160, secp256k1, sha1, sha256 }));
const evalPair = (locking, unlocking) => {
  const st = vm.evaluate(createTestAuthenticationProgramBch({ lockingBytecode: locking, unlockingBytecode: unlocking, valueSatoshis: 1000n }));
  const top = st.stack[st.stack.length - 1];
  const accepted = st.error === undefined && st.stack.length === 1 && top?.length === 1 && top[0] === 1;
  return { accepted, error: st.error, operationCost: st.metrics.operationCost };
};
const pushInt = (n) => encodeDataPush(bigIntToVmNumber(n));
const unlockingFor = (args) => Uint8Array.from(args.slice().reverse().flatMap((a) => [...pushInt(a)]));

// ---- twist E'(Fp2): y^2 = x^3 + 4(1+u), affine arithmetic (null = O), for building non-G2 points ----
const B4 = Fp2.create({ c0: 4n, c1: 4n });
const onTwist = (Q) => Fp2.eql(Fp2.sqr(Q.y), Fp2.add(Fp2.mul(Fp2.sqr(Q.x), Q.x), B4));
const tAdd = (S, T) => {
  if (S === null) return T; if (T === null) return S;
  let l;
  if (Fp2.eql(S.x, T.x)) {
    if (!Fp2.eql(S.y, T.y) || Fp2.is0(S.y)) return null;
    l = Fp2.div(Fp2.mul(Fp2.sqr(S.x), Fp2.create({ c0: 3n, c1: 0n })), Fp2.add(S.y, S.y));
  } else {
    l = Fp2.div(Fp2.sub(T.y, S.y), Fp2.sub(T.x, S.x));
  }
  const x = Fp2.sub(Fp2.sub(Fp2.sqr(l), S.x), T.x);
  return { x, y: Fp2.sub(Fp2.mul(l, Fp2.sub(S.x, x)), S.y) };
};
const tMul = (Q, k) => { let acc = null, add = Q; for (; k > 0n; k >>= 1n) { if (k & 1n) acc = tAdd(acc, add); add = tAdd(add, add); } return acc; };
// a point of exact order 13 (13^2 | h2): strip every 13 from #E'(Fp2) = h2*r, take the
// 13-primary part of a twist point, then multiply by 13 until the next step would hit O
function order13Point() {
  if (H2 % 169n !== 0n) throw new Error('13^2 does not divide h2');
  let k = H2 * R; while (k % 13n === 0n) k /= 13n;
  for (let i = 1n; ; i++) {
    const x = Fp2.create({ c0: i, c1: 1n });
    const rhs = Fp2.add(Fp2.mul(Fp2.sqr(x), x), B4);
    let y; try { y = Fp2.sqrt(rhs); } catch { continue; }
    const Q = { x, y };
    if (tMul(Q, H2 * R) !== null) throw new Error('#E\'(Fp2) != h2*r');
    let T = tMul(Q, k);
    if (T === null) continue;
    while (tMul(T, 13n) !== null) T = tMul(T, 13n);
    return T;
  }
}

// ---- locking under test ----
const arg = process.argv[2];

const A = proof.a.toAffine(), Bp = proof.b.toAffine(), C = proof.c.toAffine();
const honest = { Ax: A.x, Ay: A.y, Bxa: Bp.x.c0, Bxb: Bp.x.c1, Bya: Bp.y.c0, Byb: Bp.y.c1, Cx: C.x, Cy: C.y };
const toArgs = (w, inputs = PUBLIC_INPUTS) => [w.Ax, w.Ay, w.Bxa, w.Bxb, w.Bya, w.Byb, w.Cx, w.Cy, ...inputs];
const withB = (Q) => ({ ...honest, Bxa: Q.x.c0, Bxb: Q.x.c1, Bya: Q.y.c0, Byb: Q.y.c1 });

const T13 = order13Point();
const Bt = { x: Bp.x, y: Bp.y };
const BplusT = tAdd(Bt, T13);
// a generic non-G2 twist point: B + [r]Q for a twist point Q (pure cofactor component)
const cof = (() => { for (let i = 2n; ; i++) { const x = Fp2.create({ c0: i, c1: 0n }); try { const y = Fp2.sqrt(Fp2.add(Fp2.mul(Fp2.sqr(x), x), B4)); const c = tMul({ x, y }, R); if (c) return c; } catch { /* non-square */ } } })();
const BplusCof = tAdd(Bt, cof);
for (const [n, Q] of [['B+T13', BplusT], ['T13', T13], ['B+cofactor', BplusCof]]) {
  if (!onTwist(Q)) throw new Error(`${n} not on the twist`);
  let inG2 = true; try { G2.fromAffine({ x: Q.x, y: Q.y }).assertValidity(); } catch { inG2 = false; }
  if (inG2) throw new Error(`${n} unexpectedly in G2`);
}


const locking = arg
  ? hexToBin(JSON.parse(readFileSync(arg, 'utf8')).lockingOK)
  : hexToBin(compileFile(join(here, 'groth16.cash'), { optimizeFor: 'size', rescheduleStacks: true }).debug.bytecode);
console.log(`locking ${locking.length} B (${arg ?? 'compiled groth16.cash'})`);

let fail = 0;
const expect = (label, args, want) => {
  const r = evalPair(locking, unlockingFor(args));
  const ok = r.accepted === want;
  if (!ok) fail++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${want ? 'accept' : 'reject'}  ${label.padEnd(44)} op-cost ${r.operationCost.toLocaleString()}${r.accepted ? '' : `  (${String(r.error).slice(0, 60)})`}`);
};

expect('honest proof (committed instance)', toArgs(honest), true);
let mp = null;
try { mp = JSON.parse(readFileSync(VDIR + 'groth16-bls12381-singleton-multiproof-vectors.json', 'utf8')); } catch { /* bench checkout absent */ }
if (mp) {
  mp.proofs.forEach((p, i) => {
    const a = evalPair(locking, hexToBin(p.unlocking)), r = evalPair(locking, hexToBin(p.invalidUnlocking));
    const ok = a.accepted && !r.accepted; if (!ok) fail++;
    console.log(`${ok ? 'PASS' : 'FAIL'}  multiproof #${i} accept valid / reject tampered input`);
  });
}
expect('tampered public input', toArgs(honest, [PUBLIC_INPUTS[0] + 1n, PUBLIC_INPUTS[1]]), false);
expect('A off-curve (Ay + 1)', toArgs({ ...honest, Ay: honest.Ay + 1n }), false);
expect('C off-curve (Cy + 1)', toArgs({ ...honest, Cy: honest.Cy + 1n }), false);
expect('A = (0,0) (no encoding of O)', toArgs({ ...honest, Ax: 0n, Ay: 0n }), false);
expect('C = (0,0) (no encoding of O)', toArgs({ ...honest, Cx: 0n, Cy: 0n }), false);
expect('B off-twist (Bya + 1)', toArgs({ ...honest, Bya: honest.Bya + 1n }), false);
expect('B = (0,0) (no encoding of O)', toArgs({ ...honest, Bxa: 0n, Bxb: 0n, Bya: 0n, Byb: 0n }), false);
expect('B on twist, not in G2: B + T13 (order 13)', toArgs(withB(BplusT)), false);
expect('B on twist, not in G2: T13 (walk collapses)', toArgs(withB(T13)), false);
expect('B on twist, not in G2: B + [r]Q (cofactor)', toArgs(withB(BplusCof)), false);
expect('Ax + p (same point, non-canonical)', toArgs({ ...honest, Ax: honest.Ax + P }), false);
expect('Cy + p (same point, non-canonical)', toArgs({ ...honest, Cy: honest.Cy + P }), false);
expect('Byb + p (same point, non-canonical)', toArgs({ ...honest, Byb: honest.Byb + P }), false);
expect('Ay - p (negative, same residue)', toArgs({ ...honest, Ay: honest.Ay - P }), false);
console.log(fail === 0 ? 'ALL PASS' : `${fail} FAILED`);
process.exit(fail === 0 ? 0 : 1);
