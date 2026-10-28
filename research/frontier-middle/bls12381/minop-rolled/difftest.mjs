// Differential test (rolled vs reviewed unrolled minop): the accumulator F at the terminal (after the e(alpha,beta)
// torus fold, canonicalised: tF0..tF11) must be EQUAL for both contracts, on every existing bench vector (committed,
// the 3 multiproof proofs and the dense worst case).
// Method: an in-memory debug copy of each contract takes 12 extra arguments expF0..11 and adds
// require(tF_i == expF_i) right after tF is formed (everything else unchanged). expF is computed in JS by replaying
// the reviewed contract's exact op order (C.millerBatchOps, NAF, fused c-folds, baked lines) with noble's Fp12. Both
// debug contracts accepting the same expF proves F_rolled == F_unrolled. A JS replay of the rolled op order (on-chain
// gamma/delta walks, per-digit reordering) is also asserted equal to expF.
//   node difftest.mjs
import { existsSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { compileFile, utils } from 'cashc';
import { hexToBin, decodeAuthenticationInstructions, vmNumberToBigInt, bigIntToVmNumber, encodeDataPush, createVirtualMachine, createInstructionSetBch2026,
  createTestAuthenticationProgramBch, ConsensusBch2025, ripemd160, secp256k1, sha1, sha256 } from '@bitauth/libauth';
const here = new URL('./', import.meta.url).pathname;
const C = await import('../../../../chunked/bls12-381/_pairingmath.mjs');
const { bls12_381 } = await import('../../../../chunked/bls12-381/_vkxmath.mjs');
const { Fp, Fp2, Fp6, Fp12 } = bls12_381.fields; const P = Fp.ORDER; const G1 = bls12_381.G1.Point, G2 = bls12_381.G2.Point;
// BENCH_DIR default: the sibling of this repository's checkout, zk-verifier-bench/ or bench/, whichever has the vectors
const REPO_PARENT = new URL('../../../../../', import.meta.url).pathname;
const BENCH = process.env.BENCH_DIR ?? (['zk-verifier-bench/', 'bench/'].map((d) => REPO_PARENT + d).find((d) => existsSync(d + 'src/bch/groth16-bls12381-singleton-minop-vectors.json')) ?? REPO_PARENT + 'zk-verifier-bench/');
const v = JSON.parse(readFileSync(BENCH + 'src/bch/groth16-bls12381-singleton-minop-vectors.json', 'utf8'));
const mp = JSON.parse(readFileSync(BENCH + 'src/bch/groth16-bls12381-singleton-minop-multiproof-vectors.json', 'utf8'));
const HUGE = Number.MAX_SAFE_INTEGER;
const vm = createVirtualMachine(createInstructionSetBch2026(false, { consensus: { ...ConsensusBch2025, baseInstructionCost: 100, maximumFunctionIdentifierLength: 7,
  maximumMemorySlots: HUGE, maximumStandardLockingBytecodeLength: -1, maximumStandardUnlockingBytecodeLength: HUGE, maximumTokenCommitmentLength: 128,
  operationCostBudgetPerByte: HUGE, maximumStackItemLength: HUGE, maximumVmNumberByteLength: HUGE, maximumStackDepth: HUGE, maximumControlStackDepth: HUGE,
  maximumBytecodeLength: HUGE, maximumOperationCount: HUGE }, ripemd160, secp256k1, sha1, sha256 }));
const accept = (lock, unl) => { const st = vm.evaluate(createTestAuthenticationProgramBch({ lockingBytecode: lock, unlockingBytecode: unl, valueSatoshis: 1000n })); const t = st.stack.at(-1); return st.error === undefined && st.stack.length === 1 && t?.length === 1 && t[0] === 1 ? true : st.error; };
// unlocking <-> spend args (pushed in reverse order: args[0] ends on top)
const argsOf = (hex) => decodeAuthenticationInstructions(hexToBin(hex)).map((i) => (i.data ? vmNumberToBigInt(i.data, { requireMinimalEncoding: false }) : BigInt(i.opcode === 0 ? 0 : i.opcode - 0x50))).reverse();
const unlockingFor = (args) => Uint8Array.from(args.slice().reverse().flatMap((a) => [...encodeDataPush(bigIntToVmNumber(a))]));
// debug copy: spend(..., expF0..11) and require(tF_i == expF_i)
const debugCopy = (src, name) => {
  let s = readFileSync(src, 'utf8');
  s = s.replace(/int vkxZinv\) \{/, `int vkxZinv, ${Array.from({ length: 12 }, (_, i) => `int expF${i}`).join(', ')}) {`);
  s = s.replace(/(        require\(tF0 \+ tF1[^\n]*\n)/, (m) => m + `        ${Array.from({ length: 12 }, (_, i) => `require(tF${i} == expF${i});`).join(' ')}\n`);
  s = s.replace(/import "\.\/lib\//, 'import "../../../../singleton/bls12-381/lib/');
  if (!s.includes('expF11);')) throw new Error('patch failed ' + src);
  const out = here + name; writeFileSync(out, s); const lock = utils.asmToBytecode(compileFile(out, { rescheduleStacks: true }).bytecode); rmSync(out); return lock;
};
const lockU = debugCopy(here + '../../../../singleton/bls12-381/groth16_minop.cash', '_diff_unrolled.cash');
const lockR = debugCopy(here + 'groth16_minop_rolled.cash', '_diff_rolled.cash');
// ---- JS replays ----
const f2 = (a, b) => Fp2.fromBigTuple([a, b]);
const torus = (T) => Fp12.create({ c0: Fp6.ONE, c1: Fp6.create({ c0: f2(T[0], T[1]), c1: f2(T[2], T[3]), c2: f2(T[4], T[5]) }) });
const limbs = (f) => C.f12limbs(f).map((x) => ((x % P) + P) % P);
const fabu = (() => { const fAB = Fp12.conjugate(C.singlePairMiller(C.pairsFor([1n, 1n])[1]).f); const t = Fp6.mul(fAB.c1, Fp6.inv(fAB.c0)); return [t.c0.c0, t.c0.c1, t.c1.c0, t.c1.c1, t.c2.c0, t.c2.c1]; })();
function expF(a, order) {
  const [Ax, Ay, Bxa, Bxb, Bya, Byb, Cx, Cy, in0, in1, ...rest] = a; const u = rest.slice(0, 6); const nu = u.map((x) => ((-x % P) + P) % P);
  const pf = C.proofFromLimbs(Ax, Ay, Bxa, Bxb, Bya, Byb, Cx, Cy); const pairs = C.pairsFor([in0, in1], pf);
  const NAF = C.ATE_NAF; let f = torus(nu);
  if (order === 'unrolled') {
    const { ops } = C.millerBatchOps(pairs, { skipPairs: new Set([1]) }); const pds = C.pairData(pairs); let k = -1;
    for (const op of ops) {
      if (op.t === 'sqr') { k++; f = Fp12.sqr(f); if (NAF[k]) f = Fp12.mul(f, torus(NAF[k] === -1 ? u : nu)); }
      else { const pd = pds[op.j]; f = C.lineFn(f, op.coeffs[0], op.coeffs[1], op.coeffs[2], pd.Px, pd.Py); }
    }
  } else { // rolled: per digit sqr, 3 doublings, then [c-fold, 3 additions]; gamma/delta walked here from (x : y : 1)
    const pds = C.pairData(pairs).filter((_, j) => j !== 1); const R = pds.map((pd) => ({ x: pd.Qx, y: pd.Qy, z: Fp2.ONE }));
    for (let k = 0; k < NAF.length; k++) {
      f = Fp12.sqr(f);
      pds.forEach((pd, j) => { const d = C.pointDouble(R[j].x, R[j].y, R[j].z); R[j] = d.R; f = C.lineFn(f, ...d.coeffs, pd.Px, pd.Py); });
      if (NAF[k]) { f = Fp12.mul(f, torus(NAF[k] === -1 ? u : nu)); pds.forEach((pd, j) => { const s = C.pointAdd(R[j].x, R[j].y, R[j].z, pd.Qx, NAF[k] === -1 ? pd.negQy : pd.Qy); R[j] = s.R; f = C.lineFn(f, ...s.coeffs, pd.Px, pd.Py); }); }
    }
  }
  return limbs(Fp12.mul(f, torus(fabu)));
}
const vecs = [['committed', v.unlocking], ...mp.proofs.filter((p) => !p.committed).map((p, i) => [`multiproof #${i + 1}`, p.unlocking]), ['worstCaseProof (dense)', mp.worstCaseProof.unlocking]];
let ok = true;
for (const [label, hex] of vecs) {
  const a = argsOf(hex); if (a.length !== 21) throw new Error('arg count ' + a.length);
  const X = expF(a, 'unrolled'), Y = expF(a, 'rolled'); const same = X.every((x, i) => x === Y[i]);
  const u = unlockingFor([...a, ...X]); const ru = accept(lockU, u), rr = accept(lockR, u);
  const bad = unlockingFor([...a, ...X.map((x, i) => (i === 7 ? (x + 1n) % P : x))]); const nu = accept(lockU, bad), nr = accept(lockR, bad);
  const pass = same && ru === true && rr === true && nu !== true && nr !== true; ok &&= pass;
  console.log(`${label.padEnd(24)} JS rolled == JS unrolled: ${same}; unrolled debug accepts expF: ${ru}; rolled debug accepts expF: ${rr}; expF+1 rejected: ${nu !== true}/${nr !== true} -> ${pass ? 'EQUAL' : 'MISMATCH'}`);
}
console.log(ok ? 'differential test PASSED: F_rolled == F_unrolled on all vectors' : 'differential test FAILED'); process.exit(ok ? 0 : 1);
