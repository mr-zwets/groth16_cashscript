// Assemble the GENERIC (proof-agnostic) BLS12-381 pairing covenant chunks into the
// benchmark vectors. Each chunk carries NO baked proof: the running state (Miller
// f+R, or live final-exp Fp12 values) + the proof-derived points live in the token
// NFT commitment (48-byte limbs), checked by introspection. The SAME chunk lockings
// verify multiple proofs (runtime-general) — we replay TWO instances (the committed
// one + a second valid instance with distinct public inputs, built the same way as
// singleton/bls12-381/bls_instance.mjs) through identical lockings.
//
// Emits TWO files:
//   pairing-bls12381-chunked-vectors.json  — prepared Miller product + final exp ->
//     verdict (== Fp12 ONE): the "Miller loops + final exponentiation" milestone.
//   groth16-bls12381-chunked-vectors.json  — the FULL verifier: vk_x (the chunks from
//     gen_vkx) prepended to the pairing, i.e. the complete BCH-native BLS Groth16.
import { readFileSync, writeFileSync, unlinkSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { basename, dirname, join } from 'node:path';
import {
  Fp12, millerPreparedOps, assertPreparedMillerManifest, f12limbs, r6limbs, pairsFor, ptLimbs, finalexpTrace, boundaryFor,
  commitBin, CATEGORY, tok, P, OP_BUDGET, TARGET_UNLOCK, OP_DROP, OP_PUSHDATA2, verifierPath,
} from './_pairingmath.mjs';
import { PUBLIC_INPUTS, proof, bls12_381 } from '../../singleton/bls12-381/bls_instance.mjs';
import { computeVkx, compileFileBytecode, compileFileBytecodeRaw } from './_vkxmath.mjs';
import {
  glvDecompose, vkxGlvStateAt, vkxGlvZinv, GLV_HIGH_COST_INPUTS,
  GLV_SHARED_AUDITED_BOUNDS, GLV_TABLE_HEX, regenGlvSharedAudited,
} from './gen_vkx_glv.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const GEN = join(here, 'generated');
const GLV_COUNT = GLV_SHARED_AUDITED_BOUNDS.length - 1;
regenGlvSharedAudited(GEN, null, true, true);
import { binToHex, hexToBin, bigIntToVmNumber, hash256, encodeLockingBytecodeP2sh32, encodeDataPush, numberToBinUint16LE, createVirtualMachineBch2026 } from '@bitauth/libauth';
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

function evalCov(locking, unlocking, inCommit, outCommit, terminal, outLocking = locking, outputToken = tok(outCommit)) {
  const outputs = terminal
    ? [{ lockingBytecode: locking, valueSatoshis: 1000n }] // verdict chunk: no token thread continues
    : [{ lockingBytecode: outLocking, valueSatoshis: 1000n, token: outputToken }];
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

const stats = { maxLock: 0, maxUnlock: 0, allFit: true, allAccept: true, allInvalid: true };
// commitLimbs = committed carried state (NFT commitment, decl order). allArgs = everything
// the unlocking pushes (== commitLimbs except final-exp inv chunks append f^-1 witnesses).
// terminal = the verdict chunk (asserts ==ONE, produces no output token).
const RESCHED = process.env.RESCHEDULE !== 'off';
const compileCache = new Map();
const chosenCache = new Map(); // source+successor -> chosen contract bytes (fixed on first use so
                               // both instances share identical lockings)
const bindSuccessor = (cashFile, nextLocking) => {
  const src = readFileSync(cashFile, 'utf8');
  if (nextLocking === undefined) return { path: cashFile, cleanup: false };
  const expected = binToHex(hash256(nextLocking));
  const marker = '\n    }\n}\n';
  if (!src.endsWith(marker)) throw new Error(`cannot bind successor locking in ${cashFile}`);
  const bound = src.slice(0, -marker.length) + `\n        require(hash256(tx.outputs[0].lockingBytecode) == 0x${expected});${marker}`;
  const temp = join(dirname(cashFile), `._bound_${basename(cashFile, '.cash')}_${expected.slice(0, 16)}.cash`);
  writeFileSync(temp, bound);
  return { path: temp, cleanup: true };
};

function compiledVariants(cashFile, nextLocking) {
  const key = `${cashFile}|${nextLocking === undefined ? 'terminal' : binToHex(nextLocking)}`;
  let variants = compileCache.get(key);
  if (variants) return { key, variants };
  const bound = bindSuccessor(cashFile, nextLocking);
  try {
    const resched = compileFileBytecode(bound.path);
    const raw = RESCHED ? compileFileBytecodeRaw(bound.path) : resched;
    variants = { resched };
    if (RESCHED && binToHex(raw) !== binToHex(resched)) variants.raw = raw;
    compileCache.set(key, variants);
    return { key, variants };
  } finally {
    if (bound.cleanup) unlinkSync(bound.path);
  }
}

function buildCovStep(spec, nextLocking, noStats) {
  const { cashFile, commitLimbs, outLimbs, label, checkpoint, allArgs, terminal = false } = spec;
  const pushArgs = allArgs ?? commitLimbs;
  // compileFile (not compileString) so generated chunks' relative library `import` resolves;
  // it compiles the inlined vkx/miller/finalexp chunks identically. Per-chunk A/B: BLS chunks
  // run close to the 10,000 B caps, so keep whichever of {rescheduled, plain-cashc} redeem
  // yields the smaller fitting step (covenant steps are independent txs, so the choice is local).
  const { key, variants: v } = compiledVariants(cashFile, terminal ? undefined : nextLocking);
  let contract = chosenCache.get(key);
  if (contract === undefined) {
    if (!v.raw) contract = v.resched;
    else {
      const a = evalStepWith(v.resched, commitLimbs, outLimbs, pushArgs, terminal, nextLocking);
      const b = evalStepWith(v.raw, commitLimbs, outLimbs, pushArgs, terminal, nextLocking);
      const score = (r) => (r.fits ? r.step.lockingBytes + r.step.unlockingBytes : Infinity);
      contract = score(b) < score(a) ? v.raw : v.resched;
    }
    chosenCache.set(key, contract);
  }
  const r = evalStepWith(contract, commitLimbs, outLimbs, pushArgs, terminal, nextLocking, label, checkpoint);
  if (!noStats) {
    stats.maxLock = Math.max(stats.maxLock, r.step.lockingBytes); stats.maxUnlock = Math.max(stats.maxUnlock, r.step.unlockingBytes);
    stats.allFit &&= r.fits; stats.allAccept &&= r.accepted; stats.allInvalid &&= r.invalidRejected;
    if (!r.fits || !r.accepted || !r.invalidRejected) {
      console.error(`  !! ${label}: lock=${r.step.lockingBytes} unlock=${r.step.unlockingBytes} op=${r.step.operationCost.toLocaleString()} accepted=${r.accepted} invalidRejected=${r.invalidRejected} err=${r.error ?? '(none)'}`);
    }
  }
  return r;
}

// assemble + evaluate one covenant step for a given compiled contract: P2SH envelope,
// pad tuned to the measured op-cost, tamper check. Pure function of its arguments.
function evalStepWith(contract, commitLimbs, outLimbs, pushArgs, terminal, nextLocking, label = '', checkpoint = undefined) {
  const redeem = Uint8Array.from([...contract]); // trailing `bytes unused zeroPadding` param absorbs the pad (no OP_DROP)
  const rpush = encodeDataPush(redeem);                   // pushed LAST in the scriptSig (P2SH)
  const locking = P2SH ? p2shSpk(redeem) : redeem;        // P2SH scriptPubKey (35 B) or bare contract
  const tail = P2SH ? rpush.length : 0;                   // redeem in the scriptSig counts toward the budget
  const inCommit = commitBin(commitLimbs.map(BigInt)), outCommit = terminal ? new Uint8Array(32) : commitBin(outLimbs.map(BigInt));
  const argBytes = Uint8Array.from([...pushArgs].reverse().flatMap((c) => [...pushInt(BigInt(c))]));
  // `zeroPadding` is the LAST spend param -> pushed FIRST -> pad leads: [pad][args][redeem push (P2SH)].
  const mkUnlock = (target) => { const pad = padBytes(target - argBytes.length - tail); return P2SH ? Uint8Array.from([...pad, ...argBytes, ...rpush]) : Uint8Array.from([...pad, ...argBytes]); };
  const outLocking = terminal ? locking : nextLocking;
  if (!terminal && outLocking === undefined) throw new Error(`missing successor locking for ${label}`);
  const probe = evalCov(locking, mkUnlock(TARGET_UNLOCK), inCommit, outCommit, terminal, outLocking);
  let target = tunedLen(argBytes.length + tail, probe.operationCost);
  let unlocking = mkUnlock(target);
  let real = evalCov(locking, unlocking, inCommit, outCommit, terminal, outLocking);
  while (!real.accepted && target < TARGET_UNLOCK) { target = Math.min(TARGET_UNLOCK, target + 256); unlocking = mkUnlock(target); real = evalCov(locking, unlocking, inCommit, outCommit, terminal, outLocking); }
  // tamper a state limb: args follow the leading pad, so the first arg push payload is at padLen + 1.
  const invalid = Uint8Array.from(unlocking); const padLen = unlocking.length - argBytes.length - tail; invalid[padLen + 1] ^= 0x01;
  const invReal = evalCov(locking, invalid, inCommit, outCommit, terminal, outLocking);
  const wrongLocking = terminal ? outLocking : Uint8Array.from(outLocking);
  if (!terminal) wrongLocking[wrongLocking.length - 1] ^= 0x01;
  const wrongLockReal = terminal ? { accepted: false } : evalCov(locking, unlocking, inCommit, outCommit, false, wrongLocking);
  const wrongCategory = tok(outCommit);
  wrongCategory.category = Uint8Array.from(wrongCategory.category);
  wrongCategory.category[0] ^= 0x01;
  const wrongCategoryReal = terminal ? { accepted: false } : evalCov(locking, unlocking, inCommit, outCommit, false, outLocking, wrongCategory);
  const strippedCapability = tok(outCommit);
  strippedCapability.nft.capability = 'none';
  const strippedCapabilityReal = terminal ? { accepted: false } : evalCov(locking, unlocking, inCommit, outCommit, false, outLocking, strippedCapability);
  return {
    step: {
      label, locking: binToHex(locking), unlocking: binToHex(unlocking), invalidUnlocking: binToHex(invalid), checkpoint,
      covenant: { category: binToHex(CATEGORY), capability: 'mutable', inCommitment: binToHex(inCommit), outCommitment: binToHex(outCommit), outLockingBytecode: binToHex(outLocking) },
      lockingBytes: locking.length, unlockingBytes: unlocking.length, operationCost: real.operationCost,
    },
    accepted: real.accepted,
    invalidRejected: !invReal.accepted && !wrongLockReal.accepted && !wrongCategoryReal.accepted && !strippedCapabilityReal.accepted,
    error: real.error,
    fits: locking.length <= 10000 && unlocking.length <= 10000 && real.operationCost <= OP_BUDGET && real.accepted,
  };
}

function buildChain(specs, { noStats = false, tailLocking, expectRejected = false } = {}) {
  const built = new Array(specs.length);
  const results = new Array(specs.length);
  let nextLocking = tailLocking;
  for (let i = specs.length - 1; i >= 0; i--) {
    const spec = specs[i];
    if (!spec.terminal && nextLocking === undefined) throw new Error(`nonterminal tail has no successor: ${spec.label}`);
    const result = buildCovStep(spec, nextLocking, noStats);
    results[i] = result;
    built[i] = result.step;
    nextLocking = hexToBin(result.step.locking);
  }
  for (let i = 0; i + 1 < built.length; i++) {
    if (built[i].covenant.outCommitment !== built[i + 1].covenant.inCommitment) throw new Error(`commitment seam mismatch at ${built[i].label}`);
    if (built[i].covenant.outLockingBytecode !== built[i + 1].locking) throw new Error(`locking seam mismatch at ${built[i].label}`);
  }
  const accepted = results.every((r) => r.accepted);
  if (expectRejected ? accepted : !accepted) throw new Error(expectRejected ? 'invalid chain unexpectedly accepted' : 'valid chain rejected');
  return built;
}

// ---- the two instances: #0 committed, #1 a distinct valid instance (same VK) ----
// Build a second valid instance under the same VK with distinct A, B, C, and vk_x.
const G1 = bls12_381.G1.Point;
const G2 = bls12_381.G2.Point;
const Fr = bls12_381.fields.Fr;
const Rord = 52435875175126190479447740508185965837690552500527637822603658699938581184513n;
const mod = (x) => ((x % Rord) + Rord) % Rord;
const mkInstance = (inputs, bS = 1n, cS = 13n) => {
  const [s0, s1] = inputs.map(BigInt);
  const vx = mod(2n + s0 * 4n + s1 * 6n);          // ic = [2,4,6]
  const rhs = mod(3n * 5n + vx * 7n + cS * 11n);   // alpha*beta + vk_x*gamma + C*delta
  const A = Fr.mul(rhs, Fr.inv(bS));                 // A*B = rhs
  return { inputs, proof: { a: G1.BASE.multiply(A), b: G2.BASE.multiply(bS), c: G1.BASE.multiply(cS) } };
};
const INSTANCES = [
  { tag: 'committed', inputs: PUBLIC_INPUTS, proof },
  { tag: 'instance#1', ...mkInstance([135208n, 67633n], 17n, 19n) },
  { tag: 'all-position', ...mkInstance(GLV_HIGH_COST_INPUTS, 23n, 29n) },
];

// ---- BATCHED Miller replay (flat op list; final chunk conjugates f = boundary) ----
const stateLimbs = (s) => [...f12limbs(s.f), ...r6limbs(s.Rs[0])];
const sameLimbs = (a, b) => a.length === b.length && a.every((v, i) => BigInt(v) === BigInt(b[i]));
const stageLimbs = (inst, bad = {}) => {
  const pf = inst.proof ?? proof;
  const A = pf.a.negate().toAffine(), B = pf.b.toAffine(), C = pf.c.toAffine();
  const vkx = computeVkx(inst.inputs.map(BigInt)).toAffine();
  return [
    bad.Ax ?? A.x, bad.Ay ?? A.y,
    bad.Bx?.c0 ?? B.x.c0, bad.Bx?.c1 ?? B.x.c1,
    bad.By?.c0 ?? B.y.c0, bad.By?.c1 ?? B.y.c1,
    bad.Cx ?? C.x, bad.Cy ?? C.y,
    bad.vkxX ?? vkx.x, bad.vkxY ?? vkx.y,
  ];
};

function specsMiller(inst, validated = false, bad = {}) {
  const pairs = pairsFor(inst.inputs, inst.proof);
  const trace = millerPreparedOps(pairs);
  const { ops, states, finalF } = trace;
  const ptL = pairs.flatMap((p, j) => ptLimbs(j, p.P.toAffine(), p.Q.toAffine()));
  const traceStage = [...ptL.slice(0, 6), ...ptL.slice(8, 10), ...ptL.slice(6, 8)];
  if (!sameLimbs(traceStage, stageLimbs(inst))) throw new Error(`Miller genesis layout mismatch for ${inst.tag}`);
  const stage = stageLimbs(inst, bad);
  const prefix = validated ? 'millerfull' : 'miller';
  const man = JSON.parse(readFileSync(join(GEN, `manifest_${prefix}.json`), 'utf8'));
  if (man.inputValidationFused !== validated) throw new Error(`${prefix} input-validation mode mismatch`);
  assertPreparedMillerManifest(man, trace, { checkReferenceBoundary: inst.tag === 'committed' });
  const specs = [];
  for (const ch of man.chunks) {
    const commitLimbs = ch.opLo === 0 ? stage : [...stateLimbs(states[ch.opLo]), ...ptL];
    const outLimbs = ch.final ? f12limbs(finalF) : [...stateLimbs(states[ch.opHi]), ...ptL];
    specs.push({
      cashFile: join(GEN, `${prefix}_${String(ch.idx).padStart(2, '0')}.cash`), commitLimbs, outLimbs,
      label: `${validated ? 'validated ' : ''}miller ops[${ch.opLo},${ch.opHi})${ch.final ? ' +subgroup+conj=boundary' : ''}`,
      checkpoint: ch.opLo === 0 && validated ? 'validate-inputs' : ch.final ? 'miller-boundary' : undefined,
    });
  }
  return { specs, boundaryVal: finalF };
}

function specsFinalexp(inst, boundaryVal, expectOne = true) {
  const man = JSON.parse(readFileSync(join(GEN, 'manifest_finalexp.json'), 'utf8'));
  const tr = finalexpTrace(boundaryVal);
  if (expectOne && !Fp12.eql(tr.result, Fp12.ONE)) throw new Error(`finalExp(boundary) != ONE for ${inst.tag}`);
  const liveLimbs = (cut) => tr.liveAt(cut).flatMap((id) => tr.limbs12(id));
  const specs = [];
  for (const ch of man.chunks) {
    const inLimbs = liveLimbs(ch.opLo);
    const outLimbs = ch.final ? [] : liveLimbs(ch.opHi);
    // inv witnesses for any inv ops in [opLo,opHi), in op order
    const witnesses = [];
    for (let i = ch.opLo; i < ch.opHi; i++) if (tr.ops[i].op === 'inv') witnesses.push(...tr.limbs12(tr.ops[i].id));
    const allArgs = witnesses.length ? [...inLimbs, ...witnesses] : inLimbs;
    specs.push({
      cashFile: join(GEN, `finalexp_${String(ch.idx).padStart(2, '0')}.cash`), commitLimbs: inLimbs, outLimbs,
      label: `finalexp ops[${ch.opLo},${ch.opHi})${ch.final ? ' verdict==1' : ''}`,
      checkpoint: ch.final ? 'verify' : undefined, allArgs, terminal: ch.final,
    });
  }
  return specs;
}

// ---- stage-bound GLV vk_x chunks (the standalone Shamir vector remains unchanged) ----
function specsVkx(inst) {
  const [in0, in1] = inst.inputs.map(BigInt);
  const [k10, k20] = glvDecompose(in0), [k11, k21] = glvDecompose(in1);
  const scalars = [in0, in1, k10, k20, k11, k21];
  const man = JSON.parse(readFileSync(join(GEN, 'manifest_vkxglvfull.json'), 'utf8'));
  if (man.stageBound !== true || man.fullStageBound !== true || man.sharedTable !== false || man.numChunks !== GLV_COUNT) {
    throw new Error('full GLV vk_x manifest is not the stage-bound baked-table layout');
  }
  const stage = stageLimbs(inst);
  const proofTuple = stage.slice(0, 8);
  const specs = [];
  for (const ch of man.chunks) {
    const fullIn = [...vkxGlvStateAt(k10, k20, k11, k21, ch.lo), ...scalars];
    const commitLimbs = ch.first ? fullIn.slice(3) : fullIn;
    let outLimbs, allArgs;
    if (ch.final) { outLimbs = stage; allArgs = [...commitLimbs, vkxGlvZinv(k10, k20, k11, k21), ...proofTuple]; }
    else { outLimbs = [...vkxGlvStateAt(k10, k20, k11, k21, ch.hi), ...scalars]; allArgs = commitLimbs; }
    const cashFile = join(GEN, `vkxglvfull_${String(ch.idx).padStart(2, '0')}.cash`);
    if (!readFileSync(cashFile, 'utf8').includes(GLV_TABLE_HEX)) throw new Error('covenant GLV chunk does not embed the exact VK table');
    specs.push({
      cashFile, commitLimbs, outLimbs,
      label: `GLV vk_x [${ch.lo},${ch.hi})${ch.final ? ' bind (-A,B,C,vk_x)' : ''}`,
      checkpoint: ch.final ? 'vk_x' : undefined, allArgs,
    });
  }
  return specs;
}

// Build the FULL verifier as one exact token-state chain:
// public inputs -> vk_x/(-A,B,C) -> input-validated prepared Miller -> final exponentiation.
// Pairing-only uses the separate, explicitly input-unvalidated Miller namespace.
const buildGroth16 = (inst) => {
  const vkx = specsVkx(inst);
  const { specs: miller, boundaryVal } = specsMiller(inst, true);
  const fe = specsFinalexp(inst, boundaryVal);
  return { all: buildChain([...vkx, ...miller, ...fe]), vkx, miller, fe };
};
const buildPairing = (inst) => {
  const { specs: miller, boundaryVal } = specsMiller(inst);
  const fe = specsFinalexp(inst, boundaryVal);
  return { all: buildChain([...miller, ...fe]), miller, fe };
};
const run0 = { ...buildGroth16(INSTANCES[0]), pairing: buildPairing(INSTANCES[0]).all };
const run1 = { ...buildGroth16(INSTANCES[1]), pairing: buildPairing(INSTANCES[1]).all };
const runDense = buildGroth16(INSTANCES[2]);
const steps = run0.all;
const extraValidProofs = [run1.all];
const sumOp = (a) => a.reduce((x, s) => x + s.operationCost, 0);
const maxOpOf = (a) => Math.max(...a.map((s) => s.operationCost));
console.error(`full groth16: ${steps.length} steps (vk_x + input-validated miller + finalexp)`);
console.error(`valid run: allFit=${stats.allFit} allAccept=${stats.allAccept} allInvalidRejected=${stats.allInvalid}`);
if (!stats.allFit || !stats.allAccept || !stats.allInvalid) { console.error('!! a step did not fit/accept/reject -- NOT writing vectors'); process.exit(1); }

// ---- negative-case INPUT runs (must REJECT) for the harness's input-validation grading ----
// Off-curve A/C fail in the first validated Miller chunk.
const Aa = proof.a.negate().toAffine();
const millerStart = run0.vkx.length;
const firstMillerTail = hexToBin(run0.all[millerStart + 1].locking);
const buildInvalidFirstMiller = (bad, extraArgs = []) => {
  const first = specsMiller(INSTANCES[0], true, bad).specs[0];
  if (extraArgs.length > 0) first.allArgs = [...extraArgs, ...first.commitLimbs];
  return buildChain([first], { noStats: true, tailLocking: firstMillerTail, expectRejected: true });
};
const offCurveARun = buildInvalidFirstMiller({ Ay: (Aa.y + 1n) % P });
// on-curve but OFF-SUBGROUP B: a point on the twist y^2=x^3+(4+4u) outside the order-r
// subgroup -> psi(B) == [-x]B fails in the final validated Miller chunk. Search small x.
const F2b = bls12_381.fields.Fp2;
const b2 = F2b.create({ c0: 4n, c1: 4n });
let offSub = null;
for (let i = 1n; i < 800n && !offSub; i++) {
  const x = F2b.create({ c0: i, c1: 0n });
  const rhs = F2b.add(F2b.mul(F2b.sqr(x), x), b2);
  let y; try { y = F2b.sqrt(rhs); } catch { continue; }
  if (!F2b.eql(F2b.sqr(y), rhs)) continue;
  try { bls12_381.G2.Point.fromAffine({ x, y }).assertValidity(); } catch { offSub = { x, y }; } // on-curve, not torsion-free
}
if (!offSub) throw new Error('failed to construct the off-subgroup B fixture; refusing to write vectors');
const offSubInst = {
  tag: 'off-subgroup-B', inputs: INSTANCES[0].inputs,
  proof: { ...proof, b: G2.fromAffine({ x: offSub.x, y: offSub.y }) },
};
const offSubMiller = specsMiller(offSubInst, true).specs;
const finalexpStart = millerStart + run0.miller.length;
const offSubRun = buildChain(offSubMiller, { noStats: true, tailLocking: hexToBin(run0.all[finalexpStart].locking), expectRejected: true });
const Ca = proof.c.toAffine();
const offCurveCRun = buildInvalidFirstMiller({ Cy: (Ca.y + 1n) % P });

// The validated genesis derives both f=1 and R_B=B; a caller-supplied legacy f/R prefix
// therefore fails clean-stack/arity rather than becoming verifier state.
const forgedStateRun = buildInvalidFirstMiller({}, Array.from({ length: 18 }, (_, i) => BigInt(i + 1)));

// Public scalars are canonical Fr elements, not values silently truncated to 255 bits.
const badRangeSpecs = specsVkx(INSTANCES[0]);
const badRangeGenesis = [...badRangeSpecs[0].commitLimbs]; badRangeGenesis[0] = Rord;
badRangeSpecs[0] = { ...badRangeSpecs[0], commitLimbs: badRangeGenesis, allArgs: badRangeGenesis };
const outOfRangeRun = buildChain([badRangeSpecs[0]], { noStats: true, tailLocking: hexToBin(run0.all[1].locking), expectRejected: true });

// The stage-bound GLV genesis exposes exactly six scalar limbs and rejects both oversized
// decomposition witnesses and witnesses that are not congruent to the public input.
if (specsVkx(INSTANCES[0])[0].commitLimbs.length !== 6) throw new Error('GLV genesis is not six-limb stage-bound');
const oversizedSpecs = specsVkx(INSTANCES[0]);
const oversizedGenesis = [...oversizedSpecs[0].commitLimbs]; oversizedGenesis[2] = 1n << 128n;
oversizedSpecs[0] = { ...oversizedSpecs[0], commitLimbs: oversizedGenesis, allArgs: oversizedGenesis };
const oversizedGlvRun = buildChain([oversizedSpecs[0]], { noStats: true, tailLocking: hexToBin(run0.all[1].locking), expectRejected: true });
const incongruentSpecs = specsVkx(INSTANCES[0]);
const incongruentGenesis = [...incongruentSpecs[0].commitLimbs]; incongruentGenesis[2] += 1n;
incongruentSpecs[0] = { ...incongruentSpecs[0], commitLimbs: incongruentGenesis, allArgs: incongruentGenesis };
const incongruentGlvRun = buildChain([incongruentSpecs[0]], { noStats: true, tailLocking: hexToBin(run0.all[1].locking), expectRejected: true });

// A proof from the second valid instance cannot be spliced onto the first instance's public
// inputs: all validation stages accept the points, but the final pairing verdict rejects.
const spliced = { tag: 'proof-splice', inputs: INSTANCES[0].inputs, proof: INSTANCES[1].proof };
const splicedVkx = specsVkx(spliced);
const { specs: splicedMiller, boundaryVal: splicedBoundary } = specsMiller(spliced, true);
const splicedRun = buildChain([...splicedVkx, ...splicedMiller, ...specsFinalexp(spliced, splicedBoundary, false)], { noStats: true, expectRejected: true });

// The vector assembler also refuses a direct cross-proof stage seam before any file is written.
let seamSpliceRejected = false;
try {
  const { specs: wrongMiller, boundaryVal: wrongBoundary } = specsMiller(INSTANCES[1], true);
  buildChain([...specsVkx(INSTANCES[0]), ...wrongMiller, ...specsFinalexp(INSTANCES[1], wrongBoundary)], { noStats: true });
} catch (error) {
  seamSpliceRejected = String(error?.message ?? error).includes('commitment seam mismatch');
}
if (!seamSpliceRejected) throw new Error('cross-proof stage seam was not rejected');

console.error(`negative cases: off-curve A/C, off-subgroup B, forged state, Fr/GLV ranges, GLV congruence, and proof splice all rejected`);
const invalidInputs = [offCurveARun, offSubRun, offCurveCRun, forgedStateRun, outOfRangeRun, oversizedGlvRun, incongruentGlvRun, splicedRun];

writeFileSync(verifierPath('src', 'bch', 'pairing-bls12381-chunked-vectors.json'), JSON.stringify({
  description: 'PROOF-AGNOSTIC chunked BLS12-381 Groth16 pairing: a prepared-VK 4-pair optimal-ate Miller product -> Miller boundary (the conjugated f; no separate combine), then final exponentiation -> verdict (== Fp12 ONE), multi-tx. Pairing-only intentionally does not validate G1/G2 inputs; the full Groth16 track does. Miller genesis accepts only (-A,B,C,vk_x), derives f=1 and R_B=B, and every nonterminal token state pins the actual successor locking. Fixed gamma/delta G2 trajectories use manifest-bound baked line coefficients, and fixed e(alpha,beta) is folded as one dense multiplication. Lazy field reduction (addFp deferred). One fixed set of lockings verifies multiple proofs under the same VK. The 381-iter Fermat inverse in the easy part is supplied as an unlocking witness and verified by fp12Mul(f, f^-1)==ONE.',
  proofBinding: 'runtime', curve: 'BLS12-381', numSteps: run0.pairing.length, budgetPerInput: OP_BUDGET,
  totalOperationCost: sumOp(run0.pairing), maxStepOperationCost: maxOpOf(run0.pairing),
  allFit: stats.allFit, allAccept: stats.allAccept, allInvalidRejected: stats.allInvalid,
  steps: run0.pairing, extraValidProofs: [run1.pairing],
}, null, 2));
console.error(`wrote src/bch/pairing-bls12381-chunked-vectors.json (${run0.pairing.length} steps)`);

writeFileSync(verifierPath('src', 'bch', 'groth16-bls12381-chunked-vectors.json'), JSON.stringify({
  description: 'PROOF-AGNOSTIC full chunked BLS12-381 Groth16 verifier with EIP-197 input validation: public inputs -> five-chunk stage-bound GLV vk_x with the exact fixed VK table embedded in each independent covenant locking -> committed (-A,B,C,vk_x) -> input-validated prepared-VK Miller product -> final exponentiation -> verdict. The GLV genesis accepts only six canonical scalar/decomposition limbs and derives infinity. The first Miller chunk checks A/C and B on-curve; the final Miller chunk reuses its running R_B=[|x|]B for the guarded psi(B)==[-x]B subgroup check. Miller derives f=1 and R_B=B; callers cannot supply either accumulator. Every stage emits the exact next-stage state, and every nonterminal covenant pins the actual successor locking, forming one cryptographically continuous mutable-NFT token chain. Fixed gamma/delta lines and e(alpha,beta) are manifest-bound VK constants. One fixed locking chain verifies multiple proofs. Negative cases cover point validity, forged state, Fr and GLV bounds, decomposition congruence, and cross-proof splices.',
  proofBinding: 'runtime', curve: 'BLS12-381', numSteps: steps.length, budgetPerInput: OP_BUDGET,
  totalOperationCost: sumOp(steps), maxStepOperationCost: maxOpOf(steps),
  allFit: stats.allFit, allAccept: stats.allAccept, allInvalidRejected: stats.allInvalid,
  steps, extraValidProofs, worstCaseProof: runDense.all,
  invalidInputs,
}, null, 2));
console.error('wrote src/bch/groth16-bls12381-chunked-vectors.json');
