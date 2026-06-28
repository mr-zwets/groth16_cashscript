// Multiproof vectors for the OPTIMIZED singletons (min-bytes / min-op): mint distinct valid
// Groth16 proofs under the committed VK and, for each, compute the verifier's gated WITNESSES
// (residue c,cInv,w; min-op also fast-G2 zinv + GLV k-decomp + vkxZinv), validating every
// unlocking against the variant's committed locking on the loosened VM. Writes
// verifier/src/bch/groth16-singleton-{minbytes,minop}-multiproof-vectors.json.
//   VARIANT=minbytes node gen_multiproof_opt.mjs
//   VARIANT=minop    node gen_multiproof_opt.mjs
import { readFileSync, writeFileSync } from 'node:fs';
import {
  hexToBin, binToHex, bigIntToVmNumber, encodeDataPush,
  createVirtualMachine, createInstructionSetBch2026,
  createTestAuthenticationProgramBch, ConsensusBch2025, ripemd160, secp256k1, sha1, sha256,
} from '@bitauth/libauth';
import { bn254 } from '@noble/curves/bn254.js';

const C = await import('../../chunked/pairing/_millermath.mjs');
const R = await import('../../chunked/pairing/_residuemath.mjs');
const G2 = await import('../../chunked/pairing/gen_g2check.mjs');
const GLV = await import('../../chunked/pairing/gen_vkx_glv.mjs');

const VARIANT = process.env.VARIANT ?? 'minbytes';
const useFastG2 = VARIANT === 'minop';
const useGlv = VARIANT === 'minop';
const EXTRA = Number(process.env.EXTRA_PROOFS ?? 3);
const VDIR = 'C:/Users/mathi/Desktop/verifier/';

const r = bn254.fields.Fr.ORDER;
const Pm = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const canon = (x) => ((x % Pm) + Pm) % Pm;
const modr = (x) => ((x % r) + r) % r;
const invr = (x) => bn254.fields.Fr.inv(modr(x));
const G1 = (k) => bn254.G1.Point.BASE.multiply(modr(k));
const G2p = (k) => bn254.G2.Point.BASE.multiply(modr(k));

const HUGE = Number.MAX_SAFE_INTEGER;
const loosened = {
  ...ConsensusBch2025, baseInstructionCost: 100, maximumFunctionIdentifierLength: 7,
  maximumMemorySlots: HUGE, maximumStandardLockingBytecodeLength: -1,
  maximumStandardUnlockingBytecodeLength: HUGE, maximumTokenCommitmentLength: 128,
  operationCostBudgetPerByte: HUGE, maximumStackItemLength: HUGE, maximumVmNumberByteLength: HUGE,
  maximumStackDepth: HUGE, maximumControlStackDepth: HUGE, maximumBytecodeLength: HUGE, maximumOperationCount: HUGE,
};
const looseVm = createVirtualMachine(createInstructionSetBch2026(false, { consensus: loosened, ripemd160, secp256k1, sha1, sha256 }));
const evalPair = (locking, unlocking) => {
  const program = createTestAuthenticationProgramBch({ lockingBytecode: locking, unlockingBytecode: unlocking, valueSatoshis: 1000n });
  const state = looseVm.evaluate(program);
  const top = state.stack[state.stack.length - 1];
  return { accepted: state.error === undefined && state.stack.length === 1 && top !== undefined && top.length === 1 && top[0] === 1, error: state.error };
};
const pushInt = (n) => encodeDataPush(bigIntToVmNumber(n));
const unlockingFor = (args) => Uint8Array.from(args.slice().reverse().flatMap((a) => [...pushInt(a)]));

// --- VK scalars from the committed instance (to solve C in the exponent) ---
const vec = JSON.parse(readFileSync(VDIR + 'src/checkpoints/pairing-vectors.json', 'utf8'));
const s = vec.scalars;
const alpha_s = BigInt(s.alpha), beta_s = BigInt(s.beta), gamma_s = BigInt(s.gamma), delta_s = BigInt(s.delta);
const ic_s = s.ic.map(BigInt);

// --- the variant's committed locking ---
const single = JSON.parse(readFileSync(VDIR + `src/bch/groth16-singleton-${VARIANT}-vectors.json`, 'utf8'));
const locking = hexToBin(single.lockingOK);

// witnesses for a proof (A,B,C points + inputs)
const g1aff = (p) => { const a = p.toAffine(); return [a.x, a.y]; };
const g2aff = (p) => { const a = p.toAffine(); return [a.x.c0, a.x.c1, a.y.c0, a.y.c1]; };
function fullUnlocking(A, B, Cc, inputs) {
  const [Ax, Ay] = g1aff(A), [Bxa, Bxb, Bya, Byb] = g2aff(B), [Cx, Cy] = g1aff(Cc);
  const pf = C.proofFromLimbs(Ax, Ay, Bxa, Bxb, Bya, Byb, Cx, Cy);
  const pairs = C.pairsFor(inputs, pf);
  const { boundary: fRaw } = C.millerBatchOps(pairs);
  const { c, cInv, w } = R.residueWitness(fRaw);
  const args = [Ax, Ay, Bxa, Bxb, Bya, Byb, Cx, Cy, ...inputs,
    ...R.fp12limbsOf(c).map(canon), ...R.fp12limbsOf(cInv).map(canon), ...R.fp12limbsOf(w).map(canon)];
  if (useFastG2) { const [za, zb] = G2.g2checkFastZinv([[Bxa, Bxb], [Bya, Byb]]); args.push(canon(za), canon(zb)); }
  if (useGlv) {
    const [k10, k20] = GLV.glvDecompose(BigInt(inputs[0])), [k11, k21] = GLV.glvDecompose(BigInt(inputs[1]));
    args.push(k10, k20, k11, k21, canon(GLV.vkxGlvZinv(k10, k20, k11, k21)));
  }
  return unlockingFor(args.map(BigInt));
}

// deterministic PRNG (same as gen-multiproof.mjs) -> identical minted proofs
let _st = 0xA5A5A5A5DEADBEEFn;
const MASK64 = (1n << 64n) - 1n;
const nextU64 = () => { _st = (_st + 0x9e3779b97f4a7c15n) & MASK64; let z = _st; z = ((z ^ (z >> 30n)) * 0xbf58476d1ce4e5b9n) & MASK64; z = ((z ^ (z >> 27n)) * 0x94d049bb133111ebn) & MASK64; return (z ^ (z >> 31n)) & MASK64; };
const randScalar = () => { let a = 0n; for (let i = 0; i < 4; i++) a = (a << 64n) | nextU64(); return (a % r) || 1n; };
const mint = (denseInputs) => {
  const in0 = denseInputs ? (1n << 253n) - 1n : (randScalar() % 1000000n || 11n);
  const in1 = denseInputs ? (1n << 253n) - 1n : (randScalar() % 1000000n || 13n);
  const a_s = randScalar(), b_s = randScalar();
  const vkx_s = modr(ic_s[0] + in0 * ic_s[1] + in1 * ic_s[2]);
  const c_s = modr((a_s * b_s - alpha_s * beta_s - vkx_s * gamma_s) * invr(delta_s));
  return { inputs: [in0, in1], A: G1(a_s), B: G2p(b_s), C: G1(c_s) };
};

// proof #0 = committed (reuse the variant's vectors unlocking)
const proofs = [{ publicInputs: vec.publicInputs.map(String), unlocking: single.unlocking, invalidUnlocking: single.invalidUnlocking, committed: true }];
console.log(`=== ${VARIANT}: minting ${EXTRA} extra proofs + worst-case (witnessed) ===`);
for (let k = 0; k < EXTRA; k++) {
  const { inputs, A, B, Cc } = (() => { const m = mint(false); return { inputs: m.inputs, A: m.A, B: m.B, Cc: m.C }; })();
  const unlocking = fullUnlocking(A, B, Cc, inputs);
  // invalid: same witnesses, tampered in1 -> reject
  const tampered = [inputs[0], modr(inputs[1] + 1n)];
  const invalidUnlocking = (() => {
    // reuse this proof's witnesses but tamper the public input -> verdict/GLV gate fails
    const [Ax, Ay] = g1aff(A), [Bxa, Bxb, Bya, Byb] = g2aff(B), [Cx, Cy] = g1aff(Cc);
    const pf = C.proofFromLimbs(Ax, Ay, Bxa, Bxb, Bya, Byb, Cx, Cy);
    const { boundary: fRaw } = C.millerBatchOps(C.pairsFor(inputs, pf));
    const { c, cInv, w } = R.residueWitness(fRaw);
    const args = [Ax, Ay, Bxa, Bxb, Bya, Byb, Cx, Cy, ...tampered,
      ...R.fp12limbsOf(c).map(canon), ...R.fp12limbsOf(cInv).map(canon), ...R.fp12limbsOf(w).map(canon)];
    if (useFastG2) { const [za, zb] = G2.g2checkFastZinv([[Bxa, Bxb], [Bya, Byb]]); args.push(canon(za), canon(zb)); }
    if (useGlv) { const [k10, k20] = GLV.glvDecompose(inputs[0]), [k11, k21] = GLV.glvDecompose(inputs[1]); args.push(k10, k20, k11, k21, canon(GLV.vkxGlvZinv(k10, k20, k11, k21))); }
    return unlockingFor(args.map(BigInt));
  })();
  const good = evalPair(locking, unlocking), bad = evalPair(locking, invalidUnlocking);
  if (!good.accepted) throw new Error(`proof ${k} REJECTED: ${good.error}`);
  if (bad.accepted) throw new Error(`proof ${k} tamper ACCEPTED`);
  console.log(`  proof #${k + 1}: accept=${good.accepted} reject-tamper=${!bad.accepted} inputs=(${inputs.join(',')})`);
  proofs.push({ publicInputs: inputs.map(String), unlocking: binToHex(unlocking), invalidUnlocking: binToHex(invalidUnlocking), committed: false });
}

const out = {
  contract: single.contract,
  description: `${proofs.length} DISTINCT valid Groth16 proofs verifying under ONE fixed ${VARIANT} locking (VK baked); witnesses (residue${useFastG2 ? ', fast-G2 zinv' : ''}${useGlv ? ', GLV decomposition' : ''}) recomputed per proof. Demonstrates runtime-generality.`,
  lockingOK: single.lockingOK,
  lockingBytes: single.lockingBytes,
  numProofs: proofs.length,
  proofs,
};
const outPath = VDIR + `src/bch/groth16-singleton-${VARIANT}-multiproof-vectors.json`;
writeFileSync(outPath, JSON.stringify(out, null, 2));
console.log(`wrote ${outPath} (${proofs.length} proofs)`);
