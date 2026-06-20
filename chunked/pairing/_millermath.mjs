// Shared reference math + helpers for the chunked-pairing generators (noble
// Fp2/Fp6/Fp12, matching our CashScript ops bit-for-bit), plus the committed
// instance's 4 Groth16 pairs, state serialization, and a real-VM measurer.
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { pathToFileURL } from 'node:url';

const NOBLE = pathToFileURL('C:/Users/mathi/Desktop/verifier/node_modules/@noble/curves/bn254.js').href;
export const { bn254 } = await import(NOBLE);
export const { Fp, Fp2, Fp6, Fp12 } = bn254.fields;

// IN-PROCESS cashc compile (compileString + asmToBytecode) instead of spawning a
// `node cashc-cli` subprocess per candidate chunk — the planner compiles hundreds
// of times, so dropping the spawn + file I/O is a real speedup.
const CASHC_LIB = pathToFileURL('C:/Users/mathi/Desktop/cashscript/packages/cashc/dist/index.js').href;
const cashc = await import(CASHC_LIB);
const asmToBytecode = cashc.utils.asmToBytecode;
/** compile a .cash source string -> redeem bytecode (Uint8Array); throws on compile error */
export const compileBytecode = (src) => asmToBytecode(cashc.compileString(src).bytecode);

export const CASHC = 'C:/Users/mathi/Desktop/cashscript/packages/cashc/dist/cashc-cli.js';
export const OP_BUDGET = (41 + 10_000) * 800;
export const TARGET_UNLOCK = 10_000, OP_DROP = 0x75, OP_PUSHDATA2 = 0x4d;

const LIBAUTH = pathToFileURL('C:/Users/mathi/Desktop/verifier/node_modules/@bitauth/libauth/build/index.js').href;
const { hexToBin, bigIntToVmNumber, createTestAuthenticationProgramBch, createVirtualMachineBch2026 } = await import(LIBAUTH);
const realVm = createVirtualMachineBch2026(false);

// ---- constants ----
export const Fp2B = Fp2.fromBigTuple([
  19485874751759354771024239261021720505790618469301721065564631296452457478373n,
  266929791119991161246907387137283842545076965332900288569378510910307636690n,
]);
export const INV2 = Fp2.inv(Fp2.fromBigTuple([2n, 0n]));
export const PSI_X = Fp2.pow(Fp2.NONRESIDUE, (Fp.ORDER - 1n) / 3n);
export const PSI_Y = Fp2.pow(Fp2.NONRESIDUE, (Fp.ORDER - 1n) / 2n);
export const BN_X = 4965661367192848881n;
const naf = (a) => { const r = []; for (; a > 1n; a >>= 1n) { if ((a & 1n) === 0n) r.unshift(0); else if ((a & 3n) === 3n) { r.unshift(-1); a += 1n; } else r.unshift(1); } return r; };
export const ATE_NAF = naf(6n * BN_X + 2n);

// ---- miller-step math ----
const mulByB = (x) => Fp2.mul(x, Fp2B);
const scalarFp2 = (x, k) => Fp2.fromBigTuple([Fp.mul(x.c0, k), Fp.mul(x.c1, k)]);
export function pointDouble(Rx, Ry, Rz) {
  const t0 = Fp2.sqr(Ry), t1 = Fp2.sqr(Rz);
  const t2 = mulByB(Fp2.mul(t1, 3n)), t3 = Fp2.mul(t2, 3n);
  const t4 = Fp2.sub(Fp2.sub(Fp2.sqr(Fp2.add(Ry, Rz)), t1), t0);
  const c0 = Fp2.sub(t2, t0), c1 = Fp2.mul(Fp2.sqr(Rx), 3n), c2 = Fp2.neg(t4);
  const nx = Fp2.mul(Fp2.mul(Fp2.mul(Fp2.sub(t0, t3), Rx), Ry), INV2);
  const ny = Fp2.sub(Fp2.sqr(Fp2.mul(Fp2.add(t0, t3), INV2)), Fp2.mul(Fp2.sqr(t2), 3n));
  const nz = Fp2.mul(t0, t4);
  return { coeffs: [c0, c1, c2], R: { x: nx, y: ny, z: nz } };
}
export function pointAdd(Rx, Ry, Rz, Qx, Qy) {
  const t0 = Fp2.sub(Ry, Fp2.mul(Qy, Rz)), t1 = Fp2.sub(Rx, Fp2.mul(Qx, Rz));
  const c0 = Fp2.sub(Fp2.mul(t0, Qx), Fp2.mul(t1, Qy)), c1 = Fp2.neg(t0), c2 = t1;
  const t2 = Fp2.sqr(t1), t3 = Fp2.mul(t2, t1), t4 = Fp2.mul(t2, Rx);
  const t5 = Fp2.add(Fp2.sub(t3, Fp2.mul(t4, 2n)), Fp2.mul(Fp2.sqr(t0), Rz));
  const nx = Fp2.mul(t1, t5);
  const ny = Fp2.sub(Fp2.mul(Fp2.sub(t4, t5), t0), Fp2.mul(t3, Ry));
  const nz = Fp2.mul(Rz, t3);
  return { coeffs: [c0, c1, c2], R: { x: nx, y: ny, z: nz } };
}
function mul034(f, o0, o3, o4) {
  const A = Fp6.create({ c0: Fp2.mul(f.c0.c0, o0), c1: Fp2.mul(f.c0.c1, o0), c2: Fp2.mul(f.c0.c2, o0) });
  const B = Fp6.mul01(f.c1, o3, o4);
  const E = Fp6.mul01(Fp6.add(f.c0, f.c1), Fp2.add(o0, o3), o4);
  return Fp12.create({ c0: Fp6.add(Fp6.mulByNonresidue(B), A), c1: Fp6.sub(E, Fp6.add(A, B)) });
}
const lineFn = (f, c0, c1, c2, Px, Py) => mul034(f, scalarFp2(c2, Py), scalarFp2(c1, Px), c0);
const psi = (x, y) => [Fp2.mul(Fp2.frobeniusMap(x, 1), PSI_X), Fp2.mul(Fp2.frobeniusMap(y, 1), PSI_Y)];

export function millerStep(f, R, k, Qx, Qy, negQy, Px, Py) {
  f = Fp12.sqr(f);
  let d = pointDouble(R.x, R.y, R.z); R = d.R; f = lineFn(f, d.coeffs[0], d.coeffs[1], d.coeffs[2], Px, Py);
  if (ATE_NAF[k]) { let a = pointAdd(R.x, R.y, R.z, Qx, ATE_NAF[k] === -1 ? negQy : Qy); R = a.R; f = lineFn(f, a.coeffs[0], a.coeffs[1], a.coeffs[2], Px, Py); }
  return { f, R };
}
export function postPrecompute(f, R, Qx, Qy, Px, Py) {
  const q1 = psi(Qx, Qy);
  let a1 = pointAdd(R.x, R.y, R.z, q1[0], q1[1]); R = a1.R; f = lineFn(f, a1.coeffs[0], a1.coeffs[1], a1.coeffs[2], Px, Py);
  const q2 = psi(q1[0], q1[1]);
  let a2 = pointAdd(R.x, R.y, R.z, q2[0], Fp2.neg(q2[1])); R = a2.R; f = lineFn(f, a2.coeffs[0], a2.coeffs[1], a2.coeffs[2], Px, Py);
  return { f, R };
}
// full single-pair miller -> { f (Fp12), R (final) }
export function singlePairMiller(pair) {
  const Qa = pair.Q.toAffine(), Pa = pair.P.toAffine(), negQy = Fp2.neg(Qa.y);
  let f = Fp12.ONE, R = { x: Qa.x, y: Qa.y, z: Fp2.ONE };
  for (let k = 0; k < ATE_NAF.length; k++) ({ f, R } = millerStep(f, R, k, Qa.x, Qa.y, negQy, Pa.x, Pa.y));
  return postPrecompute(f, R, Qa.x, Qa.y, Pa.x, Pa.y);
}

// ---- serialization (matches cash hash256(toPaddedBytes(.,40))) ----
export const f12limbs = (f) => [f.c0.c0.c0, f.c0.c0.c1, f.c0.c1.c0, f.c0.c1.c1, f.c0.c2.c0, f.c0.c2.c1, f.c1.c0.c0, f.c1.c0.c1, f.c1.c1.c0, f.c1.c1.c1, f.c1.c2.c0, f.c1.c2.c1];
export const r6limbs = (R) => [R.x.c0, R.x.c1, R.y.c0, R.y.c1, R.z.c0, R.z.c1];
export const le40 = (n) => { const b = Buffer.alloc(40); let x = BigInt(n); for (let i = 0; i < 40; i++) { b[i] = Number(x & 0xffn); x >>= 8n; } return b; };
const sha256 = (b) => createHash('sha256').update(b).digest();
export const commit = (limbs) => sha256(sha256(Buffer.concat(limbs.map(le40)))).toString('hex');

// ---- the committed instance's 4 pairs ----
export const vec = JSON.parse(readFileSync('C:/Users/mathi/Desktop/verifier/src/checkpoints/pairing-vectors.json', 'utf8'));
const g1 = (o) => bn254.G1.Point.fromAffine({ x: BigInt(o.x), y: BigInt(o.y) });
const g2 = (o) => bn254.G2.Point.fromAffine({ x: Fp2.fromBigTuple([BigInt(o.x.c0), BigInt(o.x.c1)]), y: Fp2.fromBigTuple([BigInt(o.y.c0), BigInt(o.y.c1)]) });
export const vk = { alpha: g1(vec.vk.alpha), beta: g2(vec.vk.beta), gamma: g2(vec.vk.gamma), delta: g2(vec.vk.delta), ic: vec.vk.ic.map(g1) };
export const proof = { a: g1(vec.proof.a), b: g2(vec.proof.b), c: g1(vec.proof.c) };
export const vkxPoint = (inputs) => { let x = vk.ic[0]; inputs.map(BigInt).forEach((s, i) => { x = x.add(vk.ic[i + 1].multiply(s)); }); return x; };
export const pairsFor = (inputs, pf = proof) => [
  { name: 'negA_B', P: pf.a.negate(), Q: pf.b },
  { name: 'alpha_beta', P: vk.alpha, Q: vk.beta },
  { name: 'vkx_gamma', P: vkxPoint(inputs), Q: vk.gamma },
  { name: 'C_delta', P: pf.c, Q: vk.delta },
];
// build a proof object {a,b,c} (curve points) from raw limb bigints — used to
// replay a DIFFERENT proof (proof #1) through the same generic chunk programs.
export const proofFromLimbs = (Ax, Ay, Bxa, Bxb, Bya, Byb, Cx, Cy) => ({
  a: bn254.G1.Point.fromAffine({ x: Ax, y: Ay }),
  b: bn254.G2.Point.fromAffine({ x: Fp2.fromBigTuple([Bxa, Bxb]), y: Fp2.fromBigTuple([Bya, Byb]) }),
  c: bn254.G1.Point.fromAffine({ x: Cx, y: Cy }),
});

// Which of P (G1) and Q (G2) are PROOF-derived (runtime) per pair, vs VK (baked).
// pair0 e(-A,B): both proof.  pair1 e(alpha,beta): both VK.  pair2 e(vk_x,gamma):
// P=vk_x runtime, Q=gamma VK.  pair3 e(C,delta): P=C runtime, Q=delta VK.
// Runtime points ride in the carried (committed) state so they are bound; baked
// VK points stay literals. This is what makes the chunks proof-agnostic.
export const PT_CFG = [{ P: true, Q: true }, { P: false, Q: false }, { P: true, Q: false }, { P: true, Q: false }];
/** runtime point limbs (declaration order) for a pair's affine P (G1) and Q (G2). */
export const ptLimbs = (pairIdx, P, Q) => {
  const o = [], c = PT_CFG[pairIdx];
  if (c.P) o.push(P.x, P.y);
  if (c.Q) o.push(Q.x.c0, Q.x.c1, Q.y.c0, Q.y.c1);
  return o;
};

// ---- extract reusable functions from a singleton .cash (for chunk prologues) ----
export function fnExtractor(cashPath) {
  const src = readFileSync(cashPath, 'utf8').split('\n');
  return (name) => {
    const out = []; let p = false, depth = 0;
    for (const ln of src) {
      if (!p && ln.startsWith(`    function ${name}(`)) p = true;
      if (p) {
        out.push(ln);
        depth += (ln.match(/\{/g) || []).length - (ln.match(/\}/g) || []).length;
        if (depth === 0 && ln.includes('}')) break; // matched the function's closing brace (inline braces keep depth>0)
      }
    }
    return out.join('\n');
  };
}

// ---- real-VM measurement (padded like shamir) ----
const pushInt = (n) => {
  const d = bigIntToVmNumber(n);
  if (d.length === 0) return Uint8Array.from([0x00]);
  if (d.length === 1 && d[0] >= 1 && d[0] <= 16) return Uint8Array.from([0x50 + d[0]]);
  if (d.length === 1 && d[0] === 0x81) return Uint8Array.from([0x4f]);
  if (d.length <= 75) return Uint8Array.from([d.length, ...d]);
  if (d.length <= 255) return Uint8Array.from([0x4c, d.length, ...d]);
  return Uint8Array.from([0x4d, d.length & 0xff, (d.length >> 8) & 0xff, ...d]);
};
const padPush = (argLen, target) => { const N = target - argLen - 3; return Uint8Array.from([OP_PUSHDATA2, N & 0xff, (N >> 8) & 0xff, ...new Uint8Array(N)]); };
// compile `src` IN-PROCESS, run with `stateInts` (declaration order) on the real
// VM (padded to cap). Returns op-cost + size + accept; a compile error counts as
// "doesn't fit" so the planner just shrinks the window. (3rd arg kept for callers
// that still pass a probe path — ignored.)
export function measureChunk(src, stateInts) {
  let raw;
  try { raw = compileBytecode(src); }
  catch (e) { return { lockingBytes: Infinity, operationCost: Infinity, accepted: false, error: String(e?.message ?? e) }; }
  const locking = Uint8Array.from([OP_DROP, ...raw]);
  const argBytes = Uint8Array.from([...stateInts].reverse().flatMap((c) => [...pushInt(c)]));
  const unlocking = Uint8Array.from([...argBytes, ...padPush(argBytes.length, TARGET_UNLOCK)]);
  const st = realVm.evaluate(createTestAuthenticationProgramBch({ lockingBytecode: locking, unlockingBytecode: unlocking, valueSatoshis: 1000n }));
  const top = st.stack[st.stack.length - 1];
  const accepted = st.error === undefined && st.stack.length === 1 && top !== undefined && top.length === 1 && top[0] === 1;
  return { lockingBytes: locking.length, operationCost: st.metrics.operationCost, accepted, error: st.error ?? null };
}
export const decl = (names) => names.map((n) => `int ${n}`).join(',');
export const serExpr = (names) => 'hash256(' + names.map((n) => `toPaddedBytes(${n}, 40)`).join(' + ') + ')';

// ---- covenant (token state-threading) helpers ----------------------------------
// A GENERIC (proof-independent) chunk carries NO baked state: the running-state
// HASH lives in the spent/created token's NFT commitment. The unlocking script
// pushes the raw state limbs; the contract checks them against the input token's
// commitment, recomputes, and re-commits to output[0] under the same token thread.
// One fixed locking therefore verifies ANY proof (runtime-general).
export const CATEGORY = new Uint8Array(32).fill(0xcd); // benchmark thread id (32B)
const sha256d = (b) => sha256(sha256(b));
/** 32-byte NFT commitment of a state (decl-order limbs), as bytes. */
export const commitBin = (limbs) => new Uint8Array(sha256d(Buffer.concat(limbs.map(le40))));
/** require: the spent token commits hash(incoming state) (decl-order `names`). */
export const covIn = (names) =>
  `        require(tx.inputs[this.activeInputIndex].nftCommitment == ${serExpr(names)});`;
/** require: output[0] commits hash(outgoing, reduced) + perpetuates the token thread. */
export const covOut = (outNames) =>
  '        int P = 21888242871839275222246405745257275088696311157297823662689037894645226208583;\n' +
  `        require(tx.outputs[0].nftCommitment == hash256(${outNames.map((n) => `toPaddedBytes(${n} % P, 40)`).join(' + ')}));\n` +
  '        require(tx.outputs[0].tokenCategory == tx.inputs[this.activeInputIndex].tokenCategory);';

/** Real-VM measurer for a COVENANT chunk: drives it through a synthetic token tx
 * (spent UTXO = hash(incoming), output[0] = hash(outgoing)) so the introspection
 * resolves. `stateInts`/`outLimbs` are decl-order limbs (outLimbs already reduced). */
export function measureCovenant(src, stateInts, outLimbs) {
  let raw;
  try { raw = compileBytecode(src); }
  catch (e) { return { lockingBytes: Infinity, operationCost: Infinity, accepted: false, error: String(e?.message ?? e) }; }
  const locking = Uint8Array.from([OP_DROP, ...raw]);
  const argBytes = Uint8Array.from([...stateInts].reverse().flatMap((c) => [...pushInt(c)]));
  const unlocking = Uint8Array.from([...argBytes, ...padPush(argBytes.length, TARGET_UNLOCK)]);
  const tok = (commitment) => ({ amount: 0n, category: CATEGORY, nft: { capability: 'mutable', commitment } });
  const program = {
    inputIndex: 0,
    sourceOutputs: [{ lockingBytecode: locking, valueSatoshis: 1000n, token: tok(commitBin(stateInts)) }],
    transaction: {
      version: 2,
      inputs: [{ outpointTransactionHash: new Uint8Array(32), outpointIndex: 0, sequenceNumber: 0, unlockingBytecode: unlocking }],
      outputs: [{ lockingBytecode: locking, valueSatoshis: 1000n, token: tok(commitBin(outLimbs)) }],
      locktime: 0,
    },
  };
  const st = realVm.evaluate(program);
  const top = st.stack[st.stack.length - 1];
  const accepted = st.error === undefined && st.stack.length === 1 && top !== undefined && top.length === 1 && top[0] === 1;
  return { lockingBytes: locking.length, operationCost: st.metrics.operationCost, accepted, error: st.error ?? null };
}

// Predict-and-adjust greedy window planner. Instead of linear growth (compile
// every candidate from lo+1 upward — most thrown away), estimate the window from
// a running op-cost-per-unit average, compile that, then adjust ±1 to the budget
// boundary. ~2 compiles/chunk vs ~4-10. `state` is a mutable {perUnit:null} that
// the planner calibrates over successive chunks (first chunk falls back to linear
// growth to seed it). `tryAt(hi) -> { fits, operationCost, ... }` builds+measures
// the window [lo,hi); returns the best record (with its `.hi`).
export function planChunk(lo, max, opTarget, tryAt, state) {
  let best = null;
  const consider = (hi) => { const r = tryAt(hi); if (r.fits) best = { hi, ...r }; return r; };
  if (state.perUnit == null) {
    consider(lo + 1);
    for (let hi = lo + 2; hi <= max; hi++) if (!consider(hi).fits) break;
  } else {
    const guess = Math.min(max, lo + Math.max(1, Math.floor(opTarget / state.perUnit)));
    if (consider(guess).fits) { for (let hi = guess + 1; hi <= max; hi++) if (!consider(hi).fits) break; }
    else { for (let hi = guess - 1; hi > lo; hi--) if (consider(hi).fits) break; }
    if (!best) consider(lo + 1); // 1 unit always fits in practice
  }
  if (best) { const u = best.hi - lo, pu = best.operationCost / u; state.perUnit = state.perUnit == null ? pu : 0.5 * state.perUnit + 0.5 * pu; }
  return best;
}
