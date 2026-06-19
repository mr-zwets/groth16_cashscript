// Generator for the BCH-limit-viable, multi-transaction SINGLE-PAIR Miller loop.
// One pair e(P in G1, Q in G2): carried state = f (Fp12, 12 ints) + R = (x,y,z in
// Fp2, 6 ints) = 18 ints, hash256-committed (40-byte LE limbs, double-sha256),
// exactly the shamir vk_x pattern. Each chunk runs a window [lo,hi) of NAF steps
// (f=f^2; double+line; add+line when the NAF digit is set); the FINAL chunk also
// runs the two Q1/Q2 (psi) postPrecompute add-lines. Q,P and the NAF masks are
// baked; lo/hi/incoming/outgoing baked per chunk.
//
// The per-step math is noble's (which our CashScript fp2/fp6/fp12 ops match
// bit-for-bit), so the carried limbs == what the contract computes -> the baked
// hash commitments match. Windows are sized by MEASURED real-VM op-cost.
//
// Usage: node gen_miller.mjs <pairIndex 0..3>   (default 0)
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const GEN = join(here, 'generated'); // git-ignored output dir (reproducible artifacts)
mkdirSync(GEN, { recursive: true });
const CASHC = 'C:/Users/mathi/Desktop/cashscript/packages/cashc/dist/cashc-cli.js';
const MILLER_CASH = join(here, '..', '..', 'singleton', 'pairing', 'miller.cash');

const NOBLE = pathToFileURL('C:/Users/mathi/Desktop/verifier/node_modules/@noble/curves/bn254.js').href;
const { bn254 } = await import(NOBLE);
const { Fp, Fp2, Fp6, Fp12 } = bn254.fields;

const LIBAUTH = pathToFileURL('C:/Users/mathi/Desktop/verifier/node_modules/@bitauth/libauth/build/index.js').href;
const { hexToBin, bigIntToVmNumber, createTestAuthenticationProgramBch, createVirtualMachineBch2026 } = await import(LIBAUTH);
const realVm = createVirtualMachineBch2026(false);

const OP_BUDGET = (41 + 10_000) * 800; // 8,032,800
const OP_TARGET = Number(process.env.OP_COST_TARGET ?? 7_700_000);
const BYTE_BUDGET = Number(process.env.BYTE_BUDGET ?? 9_700);
const TARGET_UNLOCK = 10_000, OP_DROP = 0x75, OP_PUSHDATA2 = 0x4d;

// ---- constants (noble) ----
const Fp2B = Fp2.fromBigTuple([
  19485874751759354771024239261021720505790618469301721065564631296452457478373n,
  266929791119991161246907387137283842545076965332900288569378510910307636690n,
]);
const INV2 = Fp2.inv(Fp2.fromBigTuple([2n, 0n]));
const PSI_X = Fp2.pow(Fp2.NONRESIDUE, (Fp.ORDER - 1n) / 3n);
const PSI_Y = Fp2.pow(Fp2.NONRESIDUE, (Fp.ORDER - 1n) / 2n);
const BN_X = 4965661367192848881n;
const naf = (a) => { const r = []; for (; a > 1n; a >>= 1n) { if ((a & 1n) === 0n) r.unshift(0); else if ((a & 3n) === 3n) { r.unshift(-1); a += 1n; } else r.unshift(1); } return r; };
const ATE_NAF = naf(6n * BN_X + 2n); // 65 digits, MSB-first
const NZMASK = ATE_NAF.reduce((m, d, k) => d ? m | (1n << BigInt(k)) : m, 0n);
const NEGMASK = ATE_NAF.reduce((m, d, k) => d === -1 ? m | (1n << BigInt(k)) : m, 0n);

// ---- miller-step math (noble Fp2 primitives) ----
const mulByB = (x) => Fp2.mul(x, Fp2B);
const scalarFp2 = (x, k) => Fp2.fromBigTuple([Fp.mul(x.c0, k), Fp.mul(x.c1, k)]);
function pointDouble(Rx, Ry, Rz) {
  const t0 = Fp2.sqr(Ry), t1 = Fp2.sqr(Rz);
  const t2 = mulByB(Fp2.mul(t1, 3n)), t3 = Fp2.mul(t2, 3n);
  const t4 = Fp2.sub(Fp2.sub(Fp2.sqr(Fp2.add(Ry, Rz)), t1), t0);
  const c0 = Fp2.sub(t2, t0), c1 = Fp2.mul(Fp2.sqr(Rx), 3n), c2 = Fp2.neg(t4);
  const nx = Fp2.mul(Fp2.mul(Fp2.mul(Fp2.sub(t0, t3), Rx), Ry), INV2);
  const ny = Fp2.sub(Fp2.sqr(Fp2.mul(Fp2.add(t0, t3), INV2)), Fp2.mul(Fp2.sqr(t2), 3n));
  const nz = Fp2.mul(t0, t4);
  return { coeffs: [c0, c1, c2], R: { x: nx, y: ny, z: nz } };
}
function pointAdd(Rx, Ry, Rz, Qx, Qy) {
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

// one fused NAF step k on (f, R) for pair (Qx,Qy,Px,Py)
function step(f, R, k, Qx, Qy, negQy, Px, Py) {
  f = Fp12.sqr(f);
  let d = pointDouble(R.x, R.y, R.z); R = d.R; f = lineFn(f, d.coeffs[0], d.coeffs[1], d.coeffs[2], Px, Py);
  if (ATE_NAF[k]) { let a = pointAdd(R.x, R.y, R.z, Qx, ATE_NAF[k] === -1 ? negQy : Qy); R = a.R; f = lineFn(f, a.coeffs[0], a.coeffs[1], a.coeffs[2], Px, Py); }
  return { f, R };
}
function postPrecompute(f, R, Qx, Qy, Px, Py) {
  const q1 = psi(Qx, Qy);
  let a1 = pointAdd(R.x, R.y, R.z, q1[0], q1[1]); R = a1.R; f = lineFn(f, a1.coeffs[0], a1.coeffs[1], a1.coeffs[2], Px, Py);
  const q2 = psi(q1[0], q1[1]);
  let a2 = pointAdd(R.x, R.y, R.z, q2[0], Fp2.neg(q2[1])); R = a2.R; f = lineFn(f, a2.coeffs[0], a2.coeffs[1], a2.coeffs[2], Px, Py);
  return { f, R };
}

// ---- state serialization (matches the .cash hash256(toPaddedBytes(.,40))) ----
const f12limbs = (f) => [f.c0.c0.c0, f.c0.c0.c1, f.c0.c1.c0, f.c0.c1.c1, f.c0.c2.c0, f.c0.c2.c1, f.c1.c0.c0, f.c1.c0.c1, f.c1.c1.c0, f.c1.c1.c1, f.c1.c2.c0, f.c1.c2.c1];
const r6limbs = (R) => [R.x.c0, R.x.c1, R.y.c0, R.y.c1, R.z.c0, R.z.c1];
const stateLimbs = (f, R) => [...f12limbs(f), ...r6limbs(R)]; // 18 ints
const le40 = (n) => { const b = Buffer.alloc(40); let x = BigInt(n); for (let i = 0; i < 40; i++) { b[i] = Number(x & 0xffn); x >>= 8n; } return b; };
const sha256 = (b) => createHash('sha256').update(b).digest();
const commit = (limbs) => sha256(sha256(Buffer.concat(limbs.map(le40)))).toString('hex');

// ---- reconstruct the 4 Groth16 pairs from the committed instance ----
const vec = JSON.parse(readFileSync('C:/Users/mathi/Desktop/verifier/src/checkpoints/pairing-vectors.json', 'utf8'));
const g1 = (o) => bn254.G1.Point.fromAffine({ x: BigInt(o.x), y: BigInt(o.y) });
const g2 = (o) => bn254.G2.Point.fromAffine({ x: Fp2.fromBigTuple([BigInt(o.x.c0), BigInt(o.x.c1)]), y: Fp2.fromBigTuple([BigInt(o.y.c0), BigInt(o.y.c1)]) });
const vk = { alpha: g1(vec.vk.alpha), beta: g2(vec.vk.beta), gamma: g2(vec.vk.gamma), delta: g2(vec.vk.delta), ic: vec.vk.ic.map(g1) };
const proof = { a: g1(vec.proof.a), b: g2(vec.proof.b), c: g1(vec.proof.c) };
let vkx = vk.ic[0]; vec.publicInputs.map(BigInt).forEach((s, i) => { vkx = vkx.add(vk.ic[i + 1].multiply(s)); });
const PAIRS = [
  { name: 'negA_B', P: proof.a.negate(), Q: proof.b },
  { name: 'alpha_beta', P: vk.alpha, Q: vk.beta },
  { name: 'vkx_gamma', P: vkx, Q: vk.gamma },
  { name: 'C_delta', P: proof.c, Q: vk.delta },
];

// ---- extract the 24 miller-step functions (prologue) from singleton miller.cash ----
const millerSrc = readFileSync(MILLER_CASH, 'utf8').split('\n');
function extractFn(name) {
  const out = []; let p = false;
  for (const ln of millerSrc) {
    if (!p && ln.startsWith(`    function ${name}(`)) p = true;
    if (p) { out.push(ln); if (/\}\s*$/.test(ln)) break; }
  }
  return out.join('\n');
}
const BASE_FNS = ['addFp', 'subFp', 'mulFp', 'fp2Add', 'fp2Sub', 'fp2Neg', 'fp2Mul', 'fp2Sqr', 'fp2Scale', 'fp2MulXi', 'fp2MulByB', 'fp2Half', 'fp6Add', 'fp6Sub', 'fp6MulByV', 'fp6Mul', 'fp6Mul01', 'fp12Mul', 'fp12Sqr', 'mul034', 'line', 'pointDouble', 'pointAdd'];
const FINAL_FNS = ['fp2Conj', 'psi'];

// ---- chunk contract emitter (UNROLLED straight-line, fresh SSA vars) ----
// The runtime loop + 18-deep reassignment juggling bloats bytecode to ~11 KB; we
// instead unroll each step with fresh variables (cashc consumes intermediates via
// OP_ROLL last-use) and BAKE the NAF digit per step (no masks, no branch).
const decl = (names) => names.map((n) => `int ${n}`).join(',');
function genChunk(pair, lo, hi, final, incoming, outgoing) {
  const Q = pair.Q.toAffine(), P = pair.P.toAffine();
  const Qxa = Q.x.c0, Qxb = Q.x.c1, Qya = Q.y.c0, Qyb = Q.y.c1, Px = P.x, Py = P.y;
  const negQ = Fp2.neg(Q.y); // baked -Qy for NAF digit -1
  const fns = [...BASE_FNS, ...(final ? FINAL_FNS : [])].map(extractFn).join('\n');
  const fArgs = Array.from({ length: 12 }, (_, i) => `int f${i}`).join(',');
  const serOf = (f, r) => 'hash256(' + [...f, ...r].map((n) => `toPaddedBytes(${n}, 40)`).join(' + ') + ')';
  const inF = Array.from({ length: 12 }, (_, i) => `f${i}`);
  const inR = ['Rxa', 'Rxb', 'Rya', 'Ryb', 'Rza', 'Rzb'];
  const L = [];
  L.push('pragma cashscript ^0.13.0;');
  L.push(`// single-pair Miller chunk: pair ${pair.name}, NAF steps [${lo},${hi}), final=${final}.`);
  L.push('// carried state = f (12) + R (6); hash256-committed (40B LE limbs). Steps unrolled,');
  L.push('// NAF digit baked per step (no runtime loop/masks).');
  L.push('contract MillerChunk() {');
  L.push(fns);
  L.push(`    function spend(${fArgs}, int Rxa,int Rxb,int Rya,int Ryb,int Rza,int Rzb) {`);
  L.push(`        require(${serOf(inF, inR)} == 0x${incoming});`);
  let f = inF.slice(), r = inR.slice(), uid = 0;
  const fresh = (n) => Array.from({ length: n }, () => `v${uid++}`);
  for (let k = lo; k < hi; k++) {
    // f = f^2
    const sf = fresh(12);
    L.push(`        (${decl(sf)}) = fp12Sqr(${f.join(',')});`); f = sf;
    // double + line
    const dco = fresh(6), dr = fresh(6);
    L.push(`        (${decl([...dco, ...dr])}) = pointDouble(${r.join(',')});`); r = dr;
    const gf = fresh(12);
    L.push(`        (${decl(gf)}) = line(${f.join(',')}, ${dco.join(',')}, ${Px}, ${Py});`); f = gf;
    // baked NAF add
    const d = ATE_NAF[k];
    if (d) {
      const Y = d === -1 ? [negQ.c0, negQ.c1] : [Qya, Qyb];
      const aco = fresh(6), ar = fresh(6);
      L.push(`        (${decl([...aco, ...ar])}) = pointAdd(${r.join(',')}, ${Qxa}, ${Qxb}, ${Y[0]}, ${Y[1]});`); r = ar;
      const hf = fresh(12);
      L.push(`        (${decl(hf)}) = line(${f.join(',')}, ${aco.join(',')}, ${Px}, ${Py});`); f = hf;
    }
  }
  if (final) {
    // postPrecompute Q1, Q2 (psi), each an add-line, baked constants
    L.push(`        (int q1xa,int q1xb,int q1ya,int q1yb) = psi(${Qxa}, ${Qxb}, ${Qya}, ${Qyb});`);
    const bco = fresh(6), br = fresh(6);
    L.push(`        (${decl([...bco, ...br])}) = pointAdd(${r.join(',')}, q1xa,q1xb,q1ya,q1yb);`); r = br;
    const iff = fresh(12);
    L.push(`        (${decl(iff)}) = line(${f.join(',')}, ${bco.join(',')}, ${Px}, ${Py});`); f = iff;
    L.push('        (int q2xa,int q2xb,int q2ya,int q2yb) = psi(q1xa,q1xb,q1ya,q1yb);');
    L.push('        (int q2nya,int q2nyb) = fp2Neg(q2ya,q2yb);');
    const cco = fresh(6), cr = fresh(6);
    L.push(`        (${decl([...cco, ...cr])}) = pointAdd(${r.join(',')}, q2xa,q2xb,q2nya,q2nyb);`); r = cr;
    const jf = fresh(12);
    L.push(`        (${decl(jf)}) = line(${f.join(',')}, ${cco.join(',')}, ${Px}, ${Py});`); f = jf;
  }
  L.push(`        require(${serOf(f, r)} == 0x${outgoing});`);
  L.push('    }');
  L.push('}');
  return L.join('\n') + '\n';
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
function measure(src, stateInts) {
  writeFileSync(join(GEN, `_probe_${process.pid}.cash`), src);
  const lockHex = execFileSync('node', [CASHC, join(GEN, `_probe_${process.pid}.cash`), '-h'], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 }).trim();
  const locking = Uint8Array.from([OP_DROP, ...hexToBin(lockHex)]);
  const argBytes = Uint8Array.from([...stateInts].reverse().flatMap((c) => [...pushInt(c)]));
  const unlocking = Uint8Array.from([...argBytes, ...padPush(argBytes.length, TARGET_UNLOCK)]);
  const st = realVm.evaluate(createTestAuthenticationProgramBch({ lockingBytecode: locking, unlockingBytecode: unlocking, valueSatoshis: 1000n }));
  const top = st.stack[st.stack.length - 1];
  const accepted = st.error === undefined && st.stack.length === 1 && top !== undefined && top.length === 1 && top[0] === 1;
  return { lockingBytes: locking.length, operationCost: st.metrics.operationCost, accepted, error: st.error ?? null };
}

// ---- plan + emit chunks for one pair (forward pass, binary-search windows) ----
const pairIdx = Number(process.argv[2] ?? 0);
const pair = PAIRS[pairIdx];
const Qa = pair.Q.toAffine(); const negQy = Fp2.neg(Qa.y);
const Pa = pair.P.toAffine(); // G1: Pa.x, Pa.y are Fp scalars
console.error(`planning Miller chunks for pair ${pairIdx} (${pair.name})  OP_TARGET=${OP_TARGET.toLocaleString()}`);

// step states: state[k] = (f,R) BEFORE step k. state[0] = (ONE, (Q,1)).
const states = [{ f: Fp12.ONE, R: { x: Qa.x, y: Qa.y, z: Fp2.ONE } }];
let cur = states[0];
for (let k = 0; k < ATE_NAF.length; k++) { cur = step(cur.f, cur.R, k, Qa.x, Qa.y, negQy, Pa.x, Pa.y); states.push(cur); }
// state after postPrecompute = the final f_i
const finalState = postPrecompute(states[ATE_NAF.length].f, states[ATE_NAF.length].R, Qa.x, Qa.y, Pa.x, Pa.y);

const N = ATE_NAF.length; // 65

// QUICK size/op probe for fixed windows (no planner) -- node gen_miller.mjs 0 probe
if (process.argv[3] === 'probe') {
  for (const [a, b, fin] of [[0, 1, false], [0, 2, false], [0, 3, false], [63, 65, true]]) {
    const inc = commit(stateLimbs(states[a].f, states[a].R));
    const outL = fin ? stateLimbs(finalState.f, finalState.R) : stateLimbs(states[b].f, states[b].R);
    const src = genChunk(pair, a, b, fin, inc, commit(outL));
    const m = measure(src, stateLimbs(states[a].f, states[a].R));
    console.error(`window [${a},${b}) final=${fin}: lock=${m.lockingBytes}B op=${m.operationCost.toLocaleString()} accepted=${m.accepted} ${m.error ?? ''}`);
  }
  try { execFileSync('rm', [join(GEN, `_probe_${process.pid}.cash`)]); } catch {}
  process.exit(0);
}

const chunks = [];
let lo = 0;
while (lo < N) {
  const incoming = commit(stateLimbs(states[lo].f, states[lo].R));
  // binary search largest hi in (lo, N] that fits
  const tryHi = (hi) => {
    const final = hi === N;
    const outLimbs = final ? stateLimbs(finalState.f, finalState.R) : stateLimbs(states[hi].f, states[hi].R);
    const outgoing = commit(outLimbs);
    const src = genChunk(pair, lo, hi, final, incoming, outgoing);
    const m = measure(src, stateLimbs(states[lo].f, states[lo].R));
    const fits = m.accepted && m.lockingBytes <= BYTE_BUDGET && m.operationCost <= OP_TARGET;
    return { fits, hi, final, outgoing, src, m };
  };
  // linear forward growth: windows are only ~2-3 steps, so grow until one more
  // step would exceed op-cost/byte budget (far fewer + smaller compiles than a
  // binary search over giant candidate windows).
  let best = tryHi(lo + 1); // 1 step always fits (~1.8M)
  for (let hi = lo + 2; hi <= N; hi++) {
    const cand = tryHi(hi);
    if (cand.fits) best = cand; else break;
  }
  chunks.push({ idx: chunks.length, lo, hi: best.hi, final: best.final, incoming, outgoing: best.outgoing, opCost: best.m.operationCost, lockingBytes: best.m.lockingBytes });
  writeFileSync(join(GEN, `miller_p${pairIdx}_${String(chunks.length - 1).padStart(2, '0')}.cash`), best.src);
  console.error(`  chunk ${chunks.length - 1}: [${lo},${best.hi}) steps=${best.hi - lo} lock=${best.m.lockingBytes}B op=${best.m.operationCost.toLocaleString()} final=${best.final}`);
  lo = best.hi;
}
// continuity check
for (let i = 1; i < chunks.length; i++) if (chunks[i - 1].outgoing !== chunks[i].incoming) throw new Error('continuity break at ' + i);
// the final chunk's outgoing == hash of f_i (the boundary factor for this pair)
const fiLimbs = f12limbs(finalState.f);
console.error(`pair ${pairIdx}: ${chunks.length} chunks, total op=${chunks.reduce((s, c) => s + c.opCost, 0).toLocaleString()}, maxOp=${Math.max(...chunks.map((c) => c.opCost)).toLocaleString()}`);
console.error(`  f_${pairIdx} (first limb) = ${fiLimbs[0]}`);

writeFileSync(join(GEN, `manifest_p${pairIdx}.json`), JSON.stringify({
  pair: pair.name, pairIdx, numChunks: chunks.length,
  initialState: stateLimbs(states[0].f, states[0].R).map(String),
  fFinal: fiLimbs.map(String),
  chunks: chunks.map((c) => ({ ...c, opCost: undefined })),
}, null, 2));
try { execFileSync('rm', [join(GEN, `_probe_${process.pid}.cash`)]); } catch {}
console.error('done.');
