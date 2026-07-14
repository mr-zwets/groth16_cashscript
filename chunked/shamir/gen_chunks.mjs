// Generator for the BCH-limit-viable, multi-transaction vk_x checkpoint.
//
// Computes vk_x = IC0 + input0*IC1 + input1*IC2 (G1 on BN254/alt_bn128) with the
// SHAMIR / STRAUS shared-doubling trick: a SINGLE 254-iteration MSB-first
// double-and-add over one accumulator R, instead of two separate 254-iteration
// loops (508 doublings -> 254). Per bit position i it doubles R then conditionally
// adds one of {none, IC1, IC2, T=IC1+IC2} according to (bit_i(input0), bit_i(input1)).
// IC0 (the constant term) is folded in at the very end, then a single
// Jacobian->affine conversion gives vk_x.
//
// The public inputs input0/input1 are taken at RUNTIME: they are part of the carried,
// hash256-committed state (rX, rY, rZ, input0, input1) and the per-bit "add this point"
// decision is computed IN-SCRIPT from (input0>>i)&1, (input1>>i)&1 via a 2-bit Shamir
// select over the VK-derived constants {IC1, IC2, T=IC1+IC2}. The .cash contracts bake
// only VK-derived constants (IC0, IC1, IC2, T and the expected vk_x), never the inputs.
//
// The EC ops jacDouble/jacAddAffine/selectPoint + addFp/subFp/mulFp/sqrFp live ONCE in a shared
// lib/ tower (Fp -> G1 -> Vk, see emitLibs()); each chunk just `import "./lib/Vk.cash";`.
// Import resolution merges deps-first (Fp, then G1, then Vk) + tree-shaking -> each chunk
// is OP-COST-bound (not size-bound) so it packs many iterations.
//
// The Jacobian->affine inverse is a VERIFIED inverse-on-stack: the final chunk's witness
// supplies zInv = R.Z^(p-2) mod p; the contract require()s mulFp(R.Z, zInv) == 1 (so a
// forged zInv is rejected) then x = X*zInv^2, y = Y*zInv^3, asserting equality with the
// noble reference vk_x. No Fermat loop in-script.
//
// This is the JS port of the former gen_chunks.py: the authoritative reference is
// @noble/curves bn254 (was py_ecc) and the op-cost oracle compiles (cashc, in-process)
// and evaluates (libauth BCH 2026 VM) candidate chunks WITHOUT spawning a subprocess.
//
// Emits into generated/ (gitignored, like twoloop — the committed derived artifact is the
// verifier repo's vkx-chunked-shamir-vectors.json):
//   - lib/{Fp,G1,Vk}.cash : the shared field/curve/VK library tower (written before planning).
//   - chunkNN.cash        : one self-verifying CashScript contract per chunk.
//   - manifest.json       : ordered chunk metadata (windows, incoming/outgoing hash256
//                           commitments, incoming state, final zInv, expected affine point).
//
// State serialization (matches the .cash byte-for-byte):
//   state = LE(rX,W)||LE(rY,W)||LE(rZ,W)||LE(input0,W)||LE(input1,W),  W = 40.
//   commitment = sha256(sha256(state)).
import { bn254 } from '@noble/curves/bn254.js';
import { compileFile, utils } from 'cashc';
import {
  hexToBin, binToHex, bigIntToVmNumber, bigIntToBinUintLE, binToFixedLength, hash256,
  createTestAuthenticationProgramBch, createVirtualMachineBch2026,
} from '@bitauth/libauth';
import { readFileSync, writeFileSync, mkdirSync, readdirSync, rmSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const { asmToBytecode } = utils;
const here = dirname(fileURLToPath(import.meta.url));
const GEN = join(here, 'generated');
mkdirSync(GEN, { recursive: true });

const p = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const P = p.toString(); // emitted as `int constant P` in lib/Fp.cash
const ITERS = 254;

// ---- Fp ops (BigInt) — mirror the .cash exactly ----
const addFp = (x, y) => (x + y) % p;
const subFp = (x, y) => (x - y + p) % p;
const mulFp = (x, y) => (x * y) % p;
const sqrFp = (x) => (x * x) % p;
const modpow = (base, exp, mod) => {
  let r = 1n, b = base % mod, e = exp;
  while (e > 0n) { if (e & 1n) r = (r * b) % mod; b = (b * b) % mod; e >>= 1n; }
  return r;
};

// dbl-2009-l. z==0 -> nz = 2*Y*Z = 0, so infinity stays infinity (call site guards rZ!=0).
function jacDouble(X, Y, Z) {
  const a = sqrFp(X), b = sqrFp(Y), c = sqrFp(b);
  const d = mulFp(2n, subFp(subFp(sqrFp(addFp(X, b)), a), c));
  const e = mulFp(3n, a), f = sqrFp(e);
  const nx = subFp(f, mulFp(2n, d));
  const ny = subFp(mulFp(e, subFp(d, nx)), mulFp(8n, c));
  const nz = mulFp(2n, mulFp(Y, Z));
  return [nx, ny, nz];
}

// Mirrors the .cash jacAdd EXACTLY: aZ==0 -> return b; u1==u2&&s1==s2 -> jacDouble(a);
// otherwise add-2007-bl.
function jacAdd(aX, aY, aZ, bX, bY, bZ) {
  if (aZ === 0n) return [bX, bY, bZ];
  const z1z1 = sqrFp(aZ), z2z2 = sqrFp(bZ);
  const u1 = mulFp(aX, z2z2), u2 = mulFp(bX, z1z1);
  const s1 = mulFp(mulFp(aY, bZ), z2z2), s2 = mulFp(mulFp(bY, aZ), z1z1);
  if (u1 === u2 && s1 === s2) return jacDouble(aX, aY, aZ);
  const h = subFp(u2, u1), i2 = sqrFp(mulFp(2n, h)), j = mulFp(h, i2);
  const rr = mulFp(2n, subFp(s2, s1)), vv = mulFp(u1, i2);
  const nx = subFp(subFp(sqrFp(rr), j), mulFp(2n, vv));
  const ny = subFp(mulFp(rr, subFp(vv, nx)), mulFp(2n, mulFp(s1, j)));
  const nz = mulFp(subFp(subFp(sqrFp(addFp(aZ, bZ)), z1z1), z2z2), h);
  return [nx, ny, nz];
}

// ---- state serialization / hash256 commitment ----
const W = 40;
const serialize = (state) =>
  Uint8Array.from(state.flatMap((c) => [...binToFixedLength(bigIntToBinUintLE(c), W)]));
const commit = (state) => binToHex(hash256(serialize(state)));

// ---- load VK vectors (IC points are bare 77-digit JSON numbers -> quote the standalone
//      big-number lines so JSON.parse keeps full precision, then BigInt them) ----
const raw = readFileSync(join(here, '../../bn254-vkx/vkx_vectors.json'), 'utf8');
const v = JSON.parse(raw.replace(/^(\s*)(\d{16,})(,?)\s*$/gm, '$1"$2"$3'));
const ic0 = v.ic0.map(BigInt), ic1 = v.ic1.map(BigInt), ic2 = v.ic2.map(BigInt);
const input0 = BigInt(v.input0), input1 = BigInt(v.input1);
const expected = v.expected.map(BigInt);

// ---- T = IC1 + IC2 and the authoritative vk_x via noble (the independent oracle) ----
const g1 = (o) => bn254.G1.Point.fromAffine({ x: o[0], y: o[1] });
const _T = g1(ic1).add(g1(ic2)).toAffine();
const T = [_T.x, _T.y];
const _vkx = g1(ic0).add(g1(ic1).multiply(input0)).add(g1(ic2).multiply(input1)).toAffine();
if (_vkx.x !== expected[0] || _vkx.y !== expected[1]) throw new Error('noble vs vector mismatch');

// ---------------------------------------------------------------------------
// The reusable EC/field function BODIES, emitted ONCE into the lib/ tower by emitLibs()
// as plain top-level (global) functions.
// ---------------------------------------------------------------------------
const fpLibFuncs = () =>
  `function addFp(int x, int y) returns (int) { return (x + y) % ${P}; }\n` +
  `function subFp(int x, int y) returns (int) { return (x - y + ${P}) % ${P}; }\n` +
  `function mulFp(int x, int y) returns (int) { return (x * y) % ${P}; }\n` +
  `function sqrFp(int x) returns (int) { return (x * x) % ${P}; }`;

const jacDoubleFn = () => `function jacDouble(int x, int y, int z) returns (int, int, int) {
    int a = sqrFp(x);
    int b = sqrFp(y);
    int c = sqrFp(b);
    int d = mulFp(2, subFp(subFp(sqrFp(addFp(x, b)), a), c));
    int e = mulFp(3, a);
    int f = sqrFp(e);
    int nx = subFp(f, mulFp(2, d));
    int ny = subFp(mulFp(e, subFp(d, nx)), mulFp(8, c));
    int nz = mulFp(2, mulFp(y, z));
    return nx, ny, nz;
}`;

const jacAddAffineFn = () => `function jacAddAffine(int aX, int aY, int aZ, int bX, int bY) returns (int, int, int) {
    int rx = bX;
    int ry = bY;
    int rz = 1;
    if (aZ != 0) {
        int z1z1 = sqrFp(aZ);
        int u2 = mulFp(bX, z1z1);
        int s2 = mulFp(mulFp(bY, aZ), z1z1);
        if (aX == u2 && aY == s2) {
            int da = sqrFp(aX);
            int db = sqrFp(aY);
            int dc = sqrFp(db);
            int dd = mulFp(2, subFp(subFp(sqrFp(addFp(aX, db)), da), dc));
            int de = mulFp(3, da);
            int df = sqrFp(de);
            int dnx = subFp(df, mulFp(2, dd));
            int dny = subFp(mulFp(de, subFp(dd, dnx)), mulFp(8, dc));
            int dnz = mulFp(2, mulFp(aY, aZ));
            rx = dnx; ry = dny; rz = dnz;
        } else {
            int h = subFp(u2, aX);
            int i2 = sqrFp(mulFp(2, h));
            int jj = mulFp(h, i2);
            int rr = mulFp(2, subFp(s2, aY));
            int vv = mulFp(aX, i2);
            int anx = subFp(subFp(sqrFp(rr), jj), mulFp(2, vv));
            int any = subFp(mulFp(rr, subFp(vv, anx)), mulFp(2, mulFp(aY, jj)));
            int anz = mulFp(subFp(subFp(sqrFp(addFp(aZ, 1)), z1z1), 1), h);
            rx = anx; ry = any; rz = anz;
        }
    }
    return rx, ry, rz;
}`;

// 2-bit Shamir select over the hardcoded VK constants {IC1, IC2, T=IC1+IC2}.
const selectPointFn = () => `function selectPoint(int b0, int b1) returns (int, int, int) {
    int aX = 0;
    int aY = 0;
    int doAdd = 0;
    if (b0 == 1 && b1 == 1) { aX = ${T[0]}; aY = ${T[1]}; doAdd = 1; }
    else { if (b0 == 1) { aX = ${ic1[0]}; aY = ${ic1[1]}; doAdd = 1; }
           else { if (b1 == 1) { aX = ${ic2[0]}; aY = ${ic2[1]}; doAdd = 1; } } }
    return aX, aY, doAdd;
}`;

function emitLibs() {
  const libdir = join(GEN, 'lib');
  mkdirSync(libdir, { recursive: true });

  const fp = [
    'pragma cashscript ^0.14.0;',
    '',
    '// BN254 base field Fp. Shared by every shamir vk_x chunk (these ops used to',
    '// be replicated inside each chunk). The prime is written as a literal at each',
    '// use site (the compiler folds it; the language has no top-level constants).',
    '',
    fpLibFuncs(),
    '',
  ].join('\n');
  const g1lib = [
    'pragma cashscript ^0.14.0;',
    '',
    '// BN254 G1 Jacobian group law (double / add) over Fp, used by the Shamir',
    '// double-and-add loop. Builds on the base field functions.',
    'import "./Fp.cash";',
    '',
    jacDoubleFn(),
    jacAddAffineFn(),
    '',
  ].join('\n');
  const vk = [
    'pragma cashscript ^0.14.0;',
    '',
    '// VK-specific layer: the 2-bit Shamir point select over the verifying-key',
    '// constants {IC1, IC2, T=IC1+IC2}. GENERATED from the VK vectors. A chunk that',
    '// imports this transitively pulls in the whole tower (Vk -> G1 -> Fp).',
    'import "./G1.cash";',
    '',
    selectPointFn(),
    '',
  ].join('\n');
  writeFileSync(join(libdir, 'Fp.cash'), fp);
  writeFileSync(join(libdir, 'G1.cash'), g1lib);
  writeFileSync(join(libdir, 'Vk.cash'), vk);
  console.error('wrote lib/Fp.cash, lib/G1.cash, lib/Vk.cash');
}

// SER includes the carried public inputs.
const SER = 'hash256(toPaddedBytes(rX, 40) + toPaddedBytes(rY, 40) + toPaddedBytes(rZ, 40)'
  + ' + toPaddedBytes(input0, 40) + toPaddedBytes(input1, 40))';

// BOUNDED LOOP over this chunk's MSB-first bit window [lo,hi). The body is emitted ONCE
// (cashc compiles `for` to a runtime loop), so per-chunk locking size is independent of
// the iteration count. Bit i = hiBit - k with hiBit = 253 - lo (matches runWindow). Bit
// extraction is runtime: `(input0 >> i) % 2` (CashScript `>>` is int-only; no 2^i, no `&`).
function loopLines(lo, hi) {
  const count = hi - lo;
  const hiBit = 253 - lo;
  return `        // bounded MSB-first loop over bit window [${lo},${hi}) -> bit positions
        // ${hiBit} down to ${253 - (hi - 1)} (count ${count}); body compiled ONCE.
        for (int k = 0; k < ${count}; k = k + 1) {
            int i = ${hiBit} - k;
            // double R (guarded rZ != 0, matching the reference)
            if (rZ != 0) {
                (rX, rY, rZ) = jacDouble(rX, rY, rZ);
            }
            // runtime 2-bit Shamir select over VK consts {IC1,IC2,T}, then add
            int b0 = (input0 >> i) % 2;
            int b1 = (input1 >> i) % 2;
            (int aX, int aY, int doAdd) = selectPoint(b0, b1);
            if (doAdd == 1) {
                (rX, rY, rZ) = jacAddAffine(rX, rY, rZ, aX, aY);
            }
        }`;
}

function genCash(idx, ch) {
  const name = `VkxChunk${String(idx).padStart(2, '0')}`;
  const lines = [];
  lines.push('pragma cashscript ^0.14.0;');
  lines.push(`// vk_x chunk ${idx}: Shamir window [${ch.lo},${ch.hi}) (MSB-first bit`
    + ` positions ${253 - ch.lo}..${253 - (ch.hi - 1)}), final=${ch.final ? 'True' : 'False'}.`);
  lines.push('// Public inputs taken at RUNTIME: carried state = (rX,rY,rZ,input0,input1);');
  lines.push('// per-bit add chosen in-script via 2-bit Shamir select over VK consts.');
  lines.push('// EC/field ops come from the shared lib/ tower (Fp -> G1 -> Vk).');
  lines.push('import "./lib/Vk.cash";');
  lines.push(`contract ${name}() {`);
  if (ch.final) {
    lines.push('    function spend(int rX, int rY, int rZ, int input0, int input1, int zInv, bytes unused zeroPadding) {');
  } else {
    lines.push('    function spend(int rX, int rY, int rZ, int input0, int input1, bytes unused zeroPadding) {');
  }
  lines.push(`        require(${SER} == 0x${ch.incoming});`);
  lines.push(loopLines(ch.lo, ch.hi));
  if (ch.final) {
    lines.push('        // fold IC0 (constant term) -- unconditional add of hardcoded VK const');
    lines.push(`        (rX, rY, rZ) = jacAddAffine(rX, rY, rZ, ${ic0[0]}, ${ic0[1]});`);
    lines.push('        // verified inverse-on-stack: zInv supplied, require rZ*zInv == 1');
    lines.push('        require(mulFp(rZ, zInv) == 1);');
    lines.push('        int zInv2 = sqrFp(zInv);');
    lines.push('        int zInv3 = mulFp(zInv2, zInv);');
    lines.push(`        require(mulFp(rX, zInv2) == ${expected[0]});`);
    lines.push(`        require(mulFp(rY, zInv3) == ${expected[1]});`);
  } else {
    lines.push(`        require(${SER} == 0x${ch.outgoing});`);
  }
  lines.push('    }');
  lines.push('}');
  return lines.join('\n') + '\n';
}

// ---- reference execution ----
function addedPoint(i) {
  const bi = BigInt(i);
  const b0 = (input0 >> bi) & 1n;
  const b1 = (input1 >> bi) & 1n;
  if (b0 && b1) return [T[0], T[1]];
  if (b0) return [ic1[0], ic1[1]];
  if (b1) return [ic2[0], ic2[1]];
  return null;
}

function runWindow(lo, hi, rX, rY, rZ) {
  for (let j = lo; j < hi; j++) {
    const i = 253 - j;
    if (rZ !== 0n) [rX, rY, rZ] = jacDouble(rX, rY, rZ);
    const ap = addedPoint(i);
    if (ap) [rX, rY, rZ] = jacAdd(rX, rY, rZ, ap[0], ap[1], 1n);
  }
  return [rX, rY, rZ];
}

// ---------------------------------------------------------------------------
// Op-cost oracle (in-process): compile a candidate chunk (cashc.compileFile resolves the
// ./lib/Vk.cash import) and evaluate it on the real BCH 2026 VM with a maximally-padded
// unlocking, returning the SAME numbers the final vectors will see.
// ---------------------------------------------------------------------------
const OP_COST_TARGET = Number(process.env.OP_COST_TARGET ?? 7300000); // ~7.3M / chunk
const BYTE_BUDGET = Number(process.env.BYTE_BUDGET ?? 9700);
// Final chunk reserves head-room for the IC0 fold + verified-inverse/assert tail.
const FINAL_TAIL_OP = Number(process.env.FINAL_TAIL_OP ?? 900000);

const realVm = createVirtualMachineBch2026(false);
const TARGET_UNLOCK = 10000, OP_PUSHDATA2 = 0x4d;
const pushInt = (n) => {
  const d = bigIntToVmNumber(n);
  if (d.length === 0) return Uint8Array.from([0x00]);
  if (d.length === 1 && d[0] >= 1 && d[0] <= 16) return Uint8Array.from([0x50 + d[0]]);
  if (d.length === 1 && d[0] === 0x81) return Uint8Array.from([0x4f]);
  if (d.length <= 75) return Uint8Array.from([d.length, ...d]);
  if (d.length <= 255) return Uint8Array.from([0x4c, d.length, ...d]);
  return Uint8Array.from([0x4d, d.length & 0xff, (d.length >> 8) & 0xff, ...d]);
};
const padPush = (argLen) => {
  const N = TARGET_UNLOCK - argLen - 3;
  return Uint8Array.from([OP_PUSHDATA2, N & 0xff, (N >> 8) & 0xff, ...new Uint8Array(N)]);
};

function measure(lo, hi, isFinal, incoming, outgoing, incomingState, zInv) {
  const src = genCash(0, { lo, hi, final: isFinal, incoming, outgoing });
  const tmp = join(GEN, '._probe.cash');
  writeFileSync(tmp, src);
  const locking = asmToBytecode(compileFile(tmp).bytecode); // no OP_DROP: trailing unused pad param
  const coords = [...incomingState];
  if (isFinal) coords.push(zInv);
  const argBytes = Uint8Array.from([...coords].reverse().flatMap((c) => [...pushInt(c)]));
  const unlocking = Uint8Array.from([...padPush(argBytes.length), ...argBytes]); // pad first (pushed first)
  const program = createTestAuthenticationProgramBch({ lockingBytecode: locking, unlockingBytecode: unlocking, valueSatoshis: 1000n });
  const state = realVm.evaluate(program);
  const top = state.stack[state.stack.length - 1];
  const accepted = state.error === undefined && state.stack.length === 1 && top !== undefined && top.length === 1 && top[0] === 1;
  return { lockingBytes: locking.length, operationCost: state.metrics.operationCost, accepted };
}

// ---------------------------------------------------------------------------
// Greedy plan with measured op-cost. The hash commitment of each chunk's incoming state is
// baked, so plan + execute in one forward pass: start from R=infinity, binary-search the
// largest window whose compiled op-cost fits the target (op-cost is monotonic in hi), commit.
// ---------------------------------------------------------------------------
function plan() {
  const chunks = [];
  let state = [0n, 1n, 0n, input0, input1]; // R = infinity; inputs carried
  let lo = 0;
  console.error('planning chunks (measuring compiled op-cost per candidate window)...');
  while (lo < ITERS) {
    const [rX0, rY0, rZ0] = state;
    const incoming = commit(state);
    const incomingState = [rX0, rY0, rZ0, input0, input1];

    const measureCandidate = (hi) => {
      const isFinal = hi === ITERS;
      const [rX, rY, rZ] = runWindow(lo, hi, rX0, rY0, rZ0);
      let outgoing = null, zc = null, m;
      if (isFinal) {
        const [, , rZf] = jacAdd(rX, rY, rZ, ic0[0], ic0[1], 1n);
        zc = modpow(rZf, p - 2n, p);
        m = measure(lo, hi, true, incoming, null, incomingState, zc);
      } else {
        outgoing = commit([rX, rY, rZ, input0, input1]);
        m = measure(lo, hi, false, incoming, outgoing, incomingState);
      }
      const tail = isFinal ? FINAL_TAIL_OP : 0;
      const fits = m.accepted && m.lockingBytes <= BYTE_BUDGET && (m.operationCost + tail) <= OP_COST_TARGET;
      return { fits, rec: { hi, isFinal, outgoing, ...m, zInv: zc } };
    };

    let best = null;
    let loB = lo + 1, hiB = ITERS;
    while (loB <= hiB) {
      const mid = (loB + hiB) >> 1;
      const { fits, rec } = measureCandidate(mid);
      if (fits) { best = rec; loB = mid + 1; } else { hiB = mid - 1; }
    }
    if (best === null) best = measureCandidate(lo + 1).rec; // one iter overflows (shouldn't at 7.3M)

    const ch = {
      lo, hi: best.hi, final: best.isFinal,
      incoming, incoming_state: incomingState.map((x) => x.toString()),
      lockingBytes: best.lockingBytes, operationCost: best.operationCost, accepted: best.accepted,
    };
    const [rX, rY, rZ] = runWindow(lo, best.hi, rX0, rY0, rZ0);
    if (best.isFinal) {
      const [rXf, rYf, rZf] = jacAdd(rX, rY, rZ, ic0[0], ic0[1], 1n);
      const zInv = modpow(rZf, p - 2n, p);
      const zInv2 = sqrFp(zInv), zInv3 = mulFp(zInv2, zInv);
      ch.affX = mulFp(rXf, zInv2).toString();
      ch.affY = mulFp(rYf, zInv3).toString();
      ch.zInv = zInv.toString();
      ch.outgoing = null;
      state = [rXf, rYf, rZf, input0, input1];
    } else {
      ch.outgoing = best.outgoing;
      state = [rX, rY, rZ, input0, input1];
    }
    chunks.push(ch);
    console.error(`  chunk ${chunks.length - 1}: [${lo},${best.hi}) iters=${best.hi - lo} `
      + `lock=${best.lockingBytes}B op-cost=${best.operationCost.toLocaleString()} final=${best.isFinal}`);
    lo = best.hi;
  }
  chunks[chunks.length - 1].final = true;
  return chunks;
}

function buildAll() {
  // Emit the shared lib/ tower FIRST: the planner compiles candidate chunks that import
  // lib/Vk.cash, so it must already exist.
  emitLibs();
  const chunks = plan();

  // sanity vs noble
  const final = chunks[chunks.length - 1];
  if (final.affX !== expected[0].toString() || final.affY !== expected[1].toString()) {
    throw new Error(`vk_x mismatch: ${final.affX},${final.affY} != ${expected}`);
  }
  for (let i = 0; i + 1 < chunks.length; i++) {
    if (chunks[i].outgoing !== chunks[i + 1].incoming) throw new Error('continuity break');
  }
  console.error(`noble match (Shamir==noble) OK, ${chunks.length} chunks, `
    + `OP_COST_TARGET=${OP_COST_TARGET.toLocaleString()}, BYTE_BUDGET=${BYTE_BUDGET}, continuity OK`);

  // ---- emit .cash contracts ----
  chunks.forEach((ch, idx) => writeFileSync(join(GEN, `chunk${String(idx).padStart(2, '0')}.cash`), genCash(idx, ch)));

  // remove orphan chunk files from a previous (different) chunk count
  for (const fn of readdirSync(GEN)) {
    const m = /^chunk(\d+)\.cash$/.exec(fn);
    if (m && Number(m[1]) >= chunks.length) { rmSync(join(GEN, fn)); console.error(`removed orphan ${fn}`); }
  }

  // clean up planner scratch
  rmSync(join(GEN, '._probe.cash'), { force: true });

  const manifest = {
    K: BYTE_BUDGET,
    byteBudget: BYTE_BUDGET,
    opCostTarget: OP_COST_TARGET,
    numChunks: chunks.length,
    algorithm: 'shamir-straus-runtime-inputs-reusable-fns',
    input0: Number(input0), input1: Number(input1),
    T: [T[0].toString(), T[1].toString()],
    expected: [expected[0].toString(), expected[1].toString()],
    serializeWidth: W,
    chunks: chunks.map((ch, i) => ({
      idx: i,
      file: `chunk${String(i).padStart(2, '0')}.cash`,
      lo: ch.lo, hi: ch.hi,
      final: ch.final,
      incoming: ch.incoming,
      outgoing: ch.outgoing,
      incoming_state: ch.incoming_state,
      zInv: ch.zInv ?? null,
      plannedLockingBytes: ch.lockingBytes,
      plannedOperationCost: ch.operationCost,
    })),
  };
  writeFileSync(join(GEN, 'manifest.json'), JSON.stringify(manifest, null, 2));
  console.error(`wrote ${chunks.length} chunk .cash files + manifest.json to generated/`);
}

buildAll();
