// Assemble the GENERIC (proof-agnostic) BLS12-381 pairing covenant chunks into the
// benchmark vectors. Each chunk carries NO baked proof: the running state (Miller
// f+R, or live final-exp Fp12 values) + the proof-derived points live in the token
// NFT commitment (48-byte limbs), checked by introspection. The SAME chunk lockings
// verify multiple proofs (runtime-general) — we replay TWO instances (the committed
// one + a second valid instance with distinct public inputs, built the same way as
// singleton/bls12-381/bls_instance.mjs) through identical lockings.
//
// Emits TWO files:
//   pairing-bls12381-chunked-vectors.json  — Miller loops + combine + final exp ->
//     verdict (== Fp12 ONE): the "Miller loops + final exponentiation" milestone.
//   groth16-bls12381-chunked-vectors.json  — the FULL verifier: vk_x (the chunks from
//     gen_vkx) prepended to the pairing, i.e. the complete BCH-native BLS Groth16.
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, join } from 'node:path';
import {
  Fp12, millerBatchOps, f12limbs, r6limbs, pairsFor, ptLimbs, finalexpTrace, boundaryFor,
  compileBytecode, commitBin, CATEGORY, tok, covIn, P, OP_BUDGET, TARGET_UNLOCK, OP_DROP, OP_PUSHDATA2,
} from './_pairingmath.mjs';
import { PUBLIC_INPUTS, vk, proof, bls12_381 } from '../../singleton/bls12-381/bls_instance.mjs';
import { vkxStateAt, vkxFinalZinv, computeVkx, compileFileBytecode } from './_vkxmath.mjs';
import { g2checkAccAt } from './gen_g2check.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const GEN = join(here, 'generated');
const LIBAUTH = pathToFileURL('C:/Users/mathi/Desktop/verifier/node_modules/@bitauth/libauth/build/index.js').href;
const { binToHex, bigIntToVmNumber, hash256, encodeLockingBytecodeP2sh32, encodeDataPush, numberToBinUint16LE, createVirtualMachineBch2026 } = await import(LIBAUTH);
const realVm = createVirtualMachineBch2026(false);

const pushInt = (n) => encodeDataPush(bigIntToVmNumber(n));
const padPush = (argLen, target) => { const N = target - argLen - 3; return Uint8Array.from([OP_PUSHDATA2, ...numberToBinUint16LE(N), ...new Uint8Array(N)]); };
const tunedLen = (argLen, opCost) => Math.min(TARGET_UNLOCK, Math.max(argLen + 3, Math.ceil(opCost / 800) - 41 + 96));

// P2SH deployment: the redeem ([OP_DROP, contract]) lives in the scriptSig where it COUNTS
// toward the op-cost budget ((41+unlockingLen)*800), so it doubles as code + budget instead
// of sitting in a budget-ignored locking next to an equal-sized dead pad (~30% smaller). The
// covenant introspects the TOKEN, not bytecode, so P2SH is a pure win (no offsets to keep).
// Bare model via CHUNKED_BARE=1.
const P2SH = process.env.CHUNKED_BARE !== '1';
const p2shSpk = (redeem) => encodeLockingBytecodeP2sh32(hash256(redeem)); // OP_HASH256 <h> OP_EQUAL (35 B)
const padBytes = (total) => { const b = Math.max(2, total); const n = b <= 76 ? b - 1 : b <= 257 ? b - 2 : b - 3; return encodeDataPush(new Uint8Array(n)); };

function evalCov(locking, unlocking, inCommit, outCommit, terminal) {
  const outputs = terminal
    ? [{ lockingBytecode: locking, valueSatoshis: 1000n }] // verdict chunk: no token thread continues
    : [{ lockingBytecode: locking, valueSatoshis: 1000n, token: tok(outCommit) }];
  const program = {
    inputIndex: 0,
    sourceOutputs: [{ lockingBytecode: locking, valueSatoshis: 1000n, token: tok(inCommit) }],
    transaction: {
      version: 2,
      inputs: [{ outpointTransactionHash: new Uint8Array(32), outpointIndex: 0, sequenceNumber: 0, unlockingBytecode: unlocking }],
      outputs, locktime: 0,
    },
  };
  const st = realVm.evaluate(program);
  const top = st.stack[st.stack.length - 1];
  return { accepted: st.error === undefined && st.stack.length === 1 && top !== undefined && top.length === 1 && top[0] === 1, operationCost: st.metrics.operationCost, error: st.error ?? null };
}

const compileCache = new Map();
const stats = { maxLock: 0, maxUnlock: 0, allFit: true, allAccept: true, allInvalid: true };
// commitLimbs = committed carried state (NFT commitment, decl order). allArgs = everything
// the unlocking pushes (== commitLimbs except final-exp inv chunks append f^-1 witnesses).
// terminal = the verdict chunk (asserts ==ONE, produces no output token).
function buildCovStep(cashFile, commitLimbs, outLimbs, label, checkpoint, allArgs, terminal, noStats) {
  const pushArgs = allArgs ?? commitLimbs;
  let contract = compileCache.get(cashFile);
  // compileFile (not compileString) so the g2check chunks' relative library `import` resolves;
  // it compiles the inlined vkx/miller/finalexp chunks identically.
  if (!contract) { contract = compileFileBytecode(cashFile); compileCache.set(cashFile, contract); }
  const redeem = Uint8Array.from([...contract]); // trailing `bytes unused zeroPadding` param absorbs the pad (no OP_DROP)
  const rpush = encodeDataPush(redeem);                   // pushed LAST in the scriptSig (P2SH)
  const locking = P2SH ? p2shSpk(redeem) : redeem;        // P2SH scriptPubKey (35 B) or bare contract
  const tail = P2SH ? rpush.length : 0;                   // redeem in the scriptSig counts toward the budget
  const inCommit = commitBin(commitLimbs.map(BigInt)), outCommit = terminal ? new Uint8Array(32) : commitBin(outLimbs.map(BigInt));
  const argBytes = Uint8Array.from([...pushArgs].reverse().flatMap((c) => [...pushInt(BigInt(c))]));
  // `zeroPadding` is the LAST spend param -> pushed FIRST -> pad leads: [pad][args][redeem push (P2SH)].
  const mkUnlock = (target) => { const pad = padBytes(target - argBytes.length - tail); return P2SH ? Uint8Array.from([...pad, ...argBytes, ...rpush]) : Uint8Array.from([...pad, ...argBytes]); };
  const probe = evalCov(locking, mkUnlock(TARGET_UNLOCK), inCommit, outCommit, terminal);
  let target = tunedLen(argBytes.length + tail, probe.operationCost);
  let unlocking = mkUnlock(target);
  let real = evalCov(locking, unlocking, inCommit, outCommit, terminal);
  while (!real.accepted && target < TARGET_UNLOCK) { target = Math.min(TARGET_UNLOCK, target + 256); unlocking = mkUnlock(target); real = evalCov(locking, unlocking, inCommit, outCommit, terminal); }
  // tamper a state limb: args follow the leading pad, so the first arg push payload is at padLen + 1.
  const invalid = Uint8Array.from(unlocking); const padLen = unlocking.length - argBytes.length - tail; invalid[padLen + 1] ^= 0x01;
  const invReal = evalCov(locking, invalid, inCommit, outCommit, terminal);
  const r = {
    step: {
      label, locking: binToHex(locking), unlocking: binToHex(unlocking), invalidUnlocking: binToHex(invalid), checkpoint,
      covenant: { category: binToHex(CATEGORY), capability: 'mutable', inCommitment: binToHex(inCommit), outCommitment: binToHex(outCommit), outLockingBytecode: binToHex(locking) },
      lockingBytes: locking.length, unlockingBytes: unlocking.length, operationCost: real.operationCost,
    },
    accepted: real.accepted, invalidRejected: !invReal.accepted,
    fits: locking.length <= 10000 && unlocking.length <= 10000 && real.operationCost <= OP_BUDGET && real.accepted,
  };
  if (!noStats) {
    stats.maxLock = Math.max(stats.maxLock, r.step.lockingBytes); stats.maxUnlock = Math.max(stats.maxUnlock, r.step.unlockingBytes);
    stats.allFit &&= r.fits; stats.allAccept &&= r.accepted; stats.allInvalid &&= r.invalidRejected;
  }
  return r.step;
}

// ---- the two instances: #0 committed, #1 a distinct valid instance (same VK) ----
// Build a valid instance the same deterministic way as bls_instance.mjs: only A and
// vk_x change with the public inputs (B = G2 base, C = cS*G1 stay fixed).
const G1 = bls12_381.G1.Point;
const Rord = 52435875175126190479447740508185965837690552500527637822603658699938581184513n;
const mod = (x) => ((x % Rord) + Rord) % Rord;
const mkInstance = (inputs) => {
  const [s0, s1] = inputs.map(BigInt);
  const vx = mod(2n + s0 * 4n + s1 * 6n);          // ic = [2,4,6]
  const A = mod(3n * 5n + vx * 7n + 13n * 11n);    // a*b + vx*g + cS*d ; a,b,g,d,cS = 3,5,7,11,13
  return { inputs, proof: { a: G1.BASE.multiply(A), b: proof.b, c: proof.c } };
};
const INSTANCES = [
  { tag: 'committed', inputs: PUBLIC_INPUTS, proof },
  { tag: 'instance#1', ...mkInstance([135208n, 67633n]) },
];

// ---- BATCHED Miller replay (flat op list; final chunk conjugates f = boundary) ----
const stateLimbs = (s) => [...f12limbs(s.f), ...s.Rs.flatMap(r6limbs)];
function buildPairing(inst) {
  const pairs = pairsFor(inst.inputs, inst.proof);
  const { ops, states, finalF } = millerBatchOps(pairs);
  const ptL = pairs.flatMap((p, j) => ptLimbs(j, p.P.toAffine(), p.Q.toAffine()));
  const finalLimbs = [...f12limbs(finalF), ...states[ops.length].Rs.flatMap(r6limbs), ...ptL];
  const man = JSON.parse(readFileSync(join(GEN, 'manifest_miller.json'), 'utf8'));
  const steps = [];
  for (const ch of man.chunks) {
    const inLimbs = [...stateLimbs(states[ch.opLo]), ...ptL];
    const outLimbs = ch.final ? finalLimbs : [...stateLimbs(states[ch.opHi]), ...ptL];
    steps.push(buildCovStep(join(GEN, `miller_${String(ch.idx).padStart(2, '0')}.cash`), inLimbs, outLimbs, `miller ops[${ch.opLo},${ch.opHi})${ch.final ? ' +conj=boundary' : ''}`, ch.final ? 'miller-boundary' : undefined));
  }
  return { steps, boundaryVal: finalF };
}

function buildFinalexp(inst, boundaryVal) {
  const man = JSON.parse(readFileSync(join(GEN, 'manifest_finalexp.json'), 'utf8'));
  const tr = finalexpTrace(boundaryVal);
  if (!Fp12.eql(tr.result, Fp12.ONE)) throw new Error(`finalExp(boundary) != ONE for ${inst.tag}`);
  const liveLimbs = (cut) => tr.liveAt(cut).flatMap((id) => tr.limbs12(id));
  const steps = [];
  for (const ch of man.chunks) {
    const inLimbs = liveLimbs(ch.opLo);
    const outLimbs = ch.final ? [] : liveLimbs(ch.opHi);
    // inv witnesses for any inv ops in [opLo,opHi), in op order
    const witnesses = [];
    for (let i = ch.opLo; i < ch.opHi; i++) if (tr.ops[i].op === 'inv') witnesses.push(...tr.limbs12(tr.ops[i].id));
    const allArgs = witnesses.length ? [...inLimbs, ...witnesses] : inLimbs;
    steps.push(buildCovStep(join(GEN, `finalexp_${String(ch.idx).padStart(2, '0')}.cash`), inLimbs, outLimbs, `finalexp ops[${ch.opLo},${ch.opHi})${ch.final ? ' verdict==1' : ''}`, ch.final ? 'verify' : undefined, allArgs, ch.final));
  }
  return steps;
}

// ---- vk_x chunks (for the full groth16 verifier; from gen_vkx's manifest) ----
function buildVkx(inst) {
  const [in0, in1] = inst.inputs.map(BigInt);
  const man = JSON.parse(readFileSync(join(GEN, 'manifest_vkx.json'), 'utf8'));
  const vkxAff = computeVkx([in0, in1]).toAffine();
  const steps = [];
  for (const ch of man.chunks) {
    const inAcc = vkxStateAt(in0, in1, ch.lo);
    const commitLimbs = [...inAcc, in0, in1];
    let outLimbs, allArgs;
    if (ch.final) { outLimbs = [vkxAff.x, vkxAff.y]; allArgs = [...commitLimbs, vkxFinalZinv(in0, in1)]; }
    else { outLimbs = [...vkxStateAt(in0, in1, ch.hi), in0, in1]; allArgs = commitLimbs; }
    steps.push(buildCovStep(join(GEN, `vkx_${String(ch.idx).padStart(2, '0')}.cash`), commitLimbs, outLimbs, `vk_x [${ch.lo},${ch.hi})${ch.final ? ' assemble vk_x' : ''}`, ch.final ? 'vk_x' : undefined, allArgs));
  }
  return steps;
}

// ---- G2 input-validation prologue (EIP-197): on-curve A/B/C + psi(B) == [-x]B ----
// `bad` (optional) overrides the points with adversarial values (off-curve / off-subgroup)
// and suppresses stats — for an invalidInputs run that MUST reject.
const F2b = bls12_381.fields.Fp2;
const g2sLimbs = (R, Bx, By, Ax, Ay, Cx, Cy) =>
  [R.x.c0, R.x.c1, R.y.c0, R.y.c1, R.z.c0, R.z.c1, Bx.c0, Bx.c1, By.c0, By.c1, Ax, Ay, Cx, Cy];
function buildG2check(inst, bad) {
  const pf = inst.proof ?? proof;
  const Ba = pf.b.toAffine(), Aa = pf.a.toAffine(), Ca = pf.c.toAffine();
  const Bx = bad?.Bx ?? Ba.x, By = bad?.By ?? Ba.y;
  const Ax = Aa.x, Ay = bad?.Ay ?? Aa.y; // off-curve A bumps Ay off the G1 curve
  const Cx = Ca.x, Cy = Ca.y;
  const man = JSON.parse(readFileSync(join(GEN, 'manifest_g2check.json'), 'utf8'));
  const steps = [];
  for (const ch of man.chunks) {
    const inLimbs = g2sLimbs(g2checkAccAt(Bx, By, ch.lo), Bx, By, Ax, Ay, Cx, Cy);
    const outLimbs = ch.last ? [] : g2sLimbs(g2checkAccAt(Bx, By, ch.hi), Bx, By, Ax, Ay, Cx, Cy);
    steps.push(buildCovStep(join(GEN, `g2check_${String(ch.idx).padStart(2, '0')}.cash`), inLimbs, outLimbs,
      `g2check bits[${ch.lo},${ch.hi})${ch.last ? ' psi(B)==[-x]B' : ''}`, ch.first ? 'validate-inputs' : undefined, undefined, ch.last, bad !== undefined));
  }
  return steps;
}

// Build the FULL groth16 verifier FRESH, in spend order: g2check (EIP-197 input validation) ->
// vk_x -> batched Miller -> final exp. (Previously this reused the COMMITTED baseline to keep the
// miller's lazy-arithmetic optimization; now the miller imports the lazy LIBRARY Bls12381Lazy.cash,
// so a fresh rebuild preserves it — no stale baseline to read.)
const OUT = 'C:/Users/mathi/Desktop/verifier/src/bch';
const buildGroth16 = (inst) => {
  const g2 = buildG2check(inst);
  const vkx = buildVkx(inst);
  const { steps: pair, boundaryVal } = buildPairing(inst);
  const fe = buildFinalexp(inst, boundaryVal);
  return [...g2, ...vkx, ...pair, ...fe];
};
const steps = buildGroth16(INSTANCES[0]);
const extraValidProofs = [buildGroth16(INSTANCES[1])];
const sumOp = (a) => a.reduce((x, s) => x + s.operationCost, 0);
const maxOpOf = (a) => Math.max(...a.map((s) => s.operationCost));
console.error(`full groth16: ${steps.length} steps (g2check + vk_x + miller + finalexp)`);
console.error(`valid run: allFit=${stats.allFit} allAccept=${stats.allAccept} allInvalidRejected=${stats.allInvalid}`);
if (!stats.allFit || !stats.allAccept || !stats.allInvalid) { console.error('!! a step did not fit/accept/reject -- NOT writing vectors'); process.exit(1); }

// ---- adversarial INPUT runs (must REJECT) for the harness's input-validation grading ----
// off-curve A: bump A.y so y^2 != x^3+4 -> the first g2check chunk's G1 cubic require fails.
const Aa = proof.a.toAffine();
const offCurveARun = buildG2check(INSTANCES[0], { Ay: (Aa.y + 1n) % P });
// on-curve but OFF-SUBGROUP B: a point on the twist y^2=x^3+(4+4u) outside the order-r
// subgroup -> psi(B) == [-x]B fails at the last g2check chunk. Search small x.
const b2 = F2b.create({ c0: 4n, c1: 4n });
let offSub = null;
for (let i = 1n; i < 800n && !offSub; i++) {
  const x = F2b.create({ c0: i, c1: 0n });
  const rhs = F2b.add(F2b.mul(F2b.sqr(x), x), b2);
  let y; try { y = F2b.sqrt(rhs); } catch { continue; }
  if (!F2b.eql(F2b.sqr(y), rhs)) continue;
  try { bls12_381.G2.Point.fromAffine({ x, y }).assertValidity(); } catch { offSub = { x, y }; } // on-curve, not torsion-free
}
const offSubRun = offSub ? buildG2check(INSTANCES[0], { Bx: offSub.x, By: offSub.y }) : null;
console.error(`adversarial: off-curve A (${offCurveARun.length} steps), off-subgroup B (${offSubRun ? offSubRun.length + ' steps' : 'NONE'})`);
const invalidInputs = [offCurveARun, ...(offSubRun ? [offSubRun] : [])];

writeFileSync(`${OUT}/groth16-bls12381-chunked-vectors.json`, JSON.stringify({
  description: 'PROOF-AGNOSTIC full chunked BLS12-381 Groth16 verifier with EIP-197 input validation: a G2 prologue (on-curve A/B/C + the prime-order-subgroup test psi(B) == [-x]B) -> vk_x (on-chain from public inputs) -> a BATCHED 4-pair Miller loop -> final exponentiation -> assert verdict == Fp12 ONE, multi-tx. Generic covenant: all state + proof-derived points in the token NFT commitment (48-byte limbs), NO baked proof. One fixed set of lockings verifies multiple proofs (runtime-general): proof #0 = committed instance, extraValidProofs = a distinct instance under the same VK. invalidInputs (off-curve A, off-subgroup B) must each REJECT.',
  proofBinding: 'runtime', curve: 'BLS12-381', numSteps: steps.length, budgetPerInput: OP_BUDGET,
  totalOperationCost: sumOp(steps), maxStepOperationCost: maxOpOf(steps),
  allFit: stats.allFit, allAccept: stats.allAccept, allInvalidRejected: stats.allInvalid,
  steps, extraValidProofs,
  invalidInputs, // off-curve A + off-subgroup B; the harness requires each REJECTS (input validation)
}, null, 2));
console.error('wrote src/bch/groth16-bls12381-chunked-vectors.json');
