// Multiproof vectors for the OP-OPTIMIZED BLS12-381 singleton: mint distinct valid
// Groth16 proofs under the committed VK and, for each, compute the verifier's gated
// WITNESSES (residue c,cInv,w over the unconjugated boundary; GLV k-decomp + vkxZinv),
// validating every unlocking against the committed minop locking on the loosened VM.
// Writes verifier/src/bch/groth16-bls12381-singleton-minop-multiproof-vectors.json.
//   node gen_multiproof_minop.mjs      (EXTRA_PROOFS=3 default)
import { readFileSync, writeFileSync } from 'node:fs';
import {
  hexToBin, binToHex, bigIntToVmNumber, encodeDataPush,
  createVirtualMachine, createInstructionSetBch2026,
  createTestAuthenticationProgramBch, ConsensusBch2025, ripemd160, secp256k1, sha1, sha256,
} from '@bitauth/libauth';

const C = await import('../../chunked/bls12-381/_pairingmath.mjs');
const R = await import('../../chunked/bls12-381/_residuemath.mjs');
const G = await import('./gen_singleton_minop.mjs');
const { bls12_381 } = await import('../../chunked/bls12-381/_vkxmath.mjs');

const EXTRA = Number(process.env.EXTRA_PROOFS ?? 3);
const VDIR = 'C:/Users/mathi/Desktop/verifier/';
const G1P = bls12_381.G1.Point, G2P = bls12_381.G2.Point;
const r = 52435875175126190479447740508185965837690552500527637822603658699938581184513n;
const Pm = bls12_381.fields.Fp.ORDER;
const canon = (x) => ((x % Pm) + Pm) % Pm;
const modr = (x) => ((x % r) + r) % r;
const invr = (x) => bls12_381.fields.Fr.inv(modr(x));
const G1 = (k) => G1P.BASE.multiply(modr(k));
const G2 = (k) => G2P.BASE.multiply(modr(k));

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

// --- VK scalars from the committed instance (bls_instance.mjs) to solve C in the exponent ---
const alpha_s = 3n, beta_s = 5n, gamma_s = 7n, delta_s = 11n;
const ic_s = [2n, 4n, 6n];

// --- the committed minop locking ---
const single = JSON.parse(readFileSync(VDIR + 'src/bch/groth16-bls12381-singleton-minop-vectors.json', 'utf8'));
const locking = hexToBin(single.lockingOK);

const g1aff = (p) => { const a = p.toAffine(); return [a.x, a.y]; };
const g2aff = (p) => { const a = p.toAffine(); return [a.x.c0, a.x.c1, a.y.c0, a.y.c1]; };
function witnessArgs(A, B, Cc, realInputs, claimedInputs) {
  const [Ax, Ay] = g1aff(A), [Bxa, Bxb, Bya, Byb] = g2aff(B), [Cx, Cy] = g1aff(Cc);
  const pf = C.proofFromLimbs(Ax, Ay, Bxa, Bxb, Bya, Byb, Cx, Cy);
  const { boundary: g } = C.millerBatchOps(C.pairsFor(realInputs, pf));
  const { c, cInv, w } = R.residueWitness(g);
  const [k10, k20] = G.glvDecompose(modr(claimedInputs[0])), [k11, k21] = G.glvDecompose(modr(claimedInputs[1]));
  return unlockingFor([
    Ax, Ay, Bxa, Bxb, Bya, Byb, Cx, Cy, ...claimedInputs,
    ...R.fp12limbsOf(c).map(canon), ...R.fp12limbsOf(cInv).map(canon), ...R.fp12limbsOf(w).map(canon),
    k10, k20, k11, k21, canon(G.vkxGlvZinv(k10, k20, k11, k21)),
  ]);
}

// deterministic PRNG (same as gen-multiproof.mjs) -> identical minted proofs
let _st = 0xA5A5A5A5DEADBEEFn;
const MASK64 = (1n << 64n) - 1n;
const nextU64 = () => { _st = (_st + 0x9e3779b97f4a7c15n) & MASK64; let z = _st; z = ((z ^ (z >> 30n)) * 0xbf58476d1ce4e5b9n) & MASK64; z = ((z ^ (z >> 27n)) * 0x94d049bb133111ebn) & MASK64; return (z ^ (z >> 31n)) & MASK64; };
const randScalar = () => { let a = 0n; for (let i = 0; i < 4; i++) a = (a << 64n) | nextU64(); return (a % r) || 1n; };
const mint = () => {
  const in0 = randScalar() % 1000000n || 11n;
  const in1 = randScalar() % 1000000n || 13n;
  const a_s = randScalar(), b_s = randScalar();
  const vkx_s = modr(ic_s[0] + in0 * ic_s[1] + in1 * ic_s[2]);
  const c_s = modr((a_s * b_s - alpha_s * beta_s - vkx_s * gamma_s) * invr(delta_s));
  return { inputs: [in0, in1], A: G1(a_s), B: G2(b_s), Cc: G1(c_s) };
};

// proof #0 = committed (reuse the vectors unlocking)
const proofs = [{ publicInputs: ['123', '456'], unlocking: single.unlocking, invalidUnlocking: single.invalidUnlocking, committed: true }];
console.log(`=== bls minop: minting ${EXTRA} extra proofs (witnessed) ===`);
for (let k = 0; k < EXTRA; k++) {
  const { inputs, A, B, Cc } = mint();
  const unlocking = witnessArgs(A, B, Cc, inputs, inputs);
  // invalid: same witnesses, tampered in1 -> GLV gate/verdict fails
  const invalidUnlocking = witnessArgs(A, B, Cc, inputs, [inputs[0], modr(inputs[1] + 1n)]);
  const good = evalPair(locking, unlocking), bad = evalPair(locking, invalidUnlocking);
  if (!good.accepted) throw new Error(`proof ${k} REJECTED: ${good.error}`);
  if (bad.accepted) throw new Error(`proof ${k} tamper ACCEPTED`);
  console.log(`  proof #${k + 1}: accept=${good.accepted} reject-tamper=${!bad.accepted} inputs=(${inputs.join(',')})`);
  proofs.push({ publicInputs: inputs.map(String), unlocking: binToHex(unlocking), invalidUnlocking: binToHex(invalidUnlocking), committed: false });
}

const out = {
  contract: single.contract,
  description: `${proofs.length} DISTINCT valid BLS12-381 Groth16 proofs verifying under ONE fixed min-op locking (VK baked); witnesses (residue c/cInv/w, GLV decomposition + vkxZinv) recomputed per proof. Demonstrates runtime-generality.`,
  lockingOK: single.lockingOK,
  lockingBytes: single.lockingBytes,
  numProofs: proofs.length,
  proofs,
};
const outPath = VDIR + 'src/bch/groth16-bls12381-singleton-minop-multiproof-vectors.json';
writeFileSync(outPath, JSON.stringify(out, null, 2));
console.log(`wrote ${outPath} (${proofs.length} proofs)`);
