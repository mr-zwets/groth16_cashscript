// Generator for the BCH-limit-viable, multi-transaction vk_x checkpoint.
//
// Runs the EXACT vkx.cash algorithm (bit-for-bit the noble-validated reference),
// snapshots the full Jacobian state at chunk boundaries, and emits:
//
//   - generated/chunkNN.cash  : one CashScript contract per chunk, self-verifying its
//                               committed incoming/outgoing state via hash256.
//   - generated/manifest.json : ordered chunk metadata (iter range, term, the
//                               INCOMING/OUTGOING hash256 commitments, the provided
//                               incoming state coords for the unlocking vector), plus
//                               input0/input1 and the final expected affine point.
//
// State carried between chunks = the 9 Jacobian coords
// (accX,accY,accZ, bX,bY,bZ, rX,rY,rZ). The loop index range, the active term
// (0 = input0*IC1, 1 = input1*IC2), whether the chunk performs the term fold/reset,
// and input0/input1 are baked per-chunk, so only the 9 coords vary and are the
// thing committed.
//
// JS port of the former gen_chunks.py (the reference vk_x is now @noble/curves bn254,
// consumed via vkx_vectors.json instead of py_ecc).
//
// Serialization (matches the .cash contract byte-for-byte):
//   state = LE(accX,W) || LE(accY,W) || ... || LE(rZ,W),  W = 40 (little-endian).
//   commitment = sha256(sha256(state)).
import { hoistSpendConstants } from '../_hoistconsts.mjs';
import {
  binToHex, bigIntToBinUintLE, binToFixedLength, hash256,
} from '@bitauth/libauth';
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));

const p = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;

const addFp = (x, y) => (x + y) % p;
const subFp = (x, y) => (x - y + p) % p;
const mulFp = (x, y) => (x * y) % p;
const sqrFp = (x) => (x * x) % p;
const modpow = (base, exp, mod) => {
  let r = 1n, b = base % mod, e = exp;
  while (e > 0n) { if (e & 1n) r = (r * b) % mod; b = (b * b) % mod; e >>= 1n; }
  return r;
};

function jacDouble(X, Y, Z) {
  const a = sqrFp(X), b = sqrFp(Y), c = sqrFp(b);
  const d = mulFp(2n, subFp(subFp(sqrFp(addFp(X, b)), a), c));
  const e = mulFp(3n, a), f = sqrFp(e);
  const nx = subFp(f, mulFp(2n, d));
  const ny = subFp(mulFp(e, subFp(d, nx)), mulFp(8n, c));
  const nz = mulFp(2n, mulFp(Y, Z));
  return [nx, ny, nz];
}

function jacAdd(aX, aY, aZ, bX, bY, bZ) {
  const z1z1 = sqrFp(aZ), z2z2 = sqrFp(bZ);
  const u1 = mulFp(aX, z2z2), u2 = mulFp(bX, z1z1);
  const s1 = mulFp(mulFp(aY, bZ), z2z2), s2 = mulFp(mulFp(bY, aZ), z1z1);
  if (u1 === u2 && s1 === s2) return jacDouble(aX, aY, aZ);
  const h = subFp(u2, u1), i2 = sqrFp(mulFp(2n, h)), j = mulFp(h, i2);
  const rr = mulFp(2n, subFp(s2, s1)), v = mulFp(u1, i2);
  const nx = subFp(subFp(sqrFp(rr), j), mulFp(2n, v));
  const ny = subFp(mulFp(rr, subFp(v, nx)), mulFp(2n, mulFp(s1, j)));
  const nz = mulFp(subFp(subFp(sqrFp(addFp(aZ, bZ)), z1z1), z2z2), h);
  return [nx, ny, nz];
}

const W = 40;
const serialize = (state) =>
  Uint8Array.from(state.flatMap((c) => [...binToFixedLength(bigIntToBinUintLE(c), W)]));
const commit = (state) => binToHex(hash256(serialize(state)));

// IC point coords are bare 77-digit JSON numbers -> quote the standalone big-number
// lines so JSON.parse keeps full precision, then BigInt them.
const raw = readFileSync(join(here, '../../bn254-vkx/vkx_vectors.json'), 'utf8');
const v = JSON.parse(raw.replace(/^(\s*)(\d{16,})(,?)\s*$/gm, '$1"$2"$3'));
const ic0 = v.ic0.map(BigInt), ic1 = v.ic1.map(BigInt), ic2 = v.ic2.map(BigInt);
const input0 = BigInt(v.input0), input1 = BigInt(v.input1);
const expected = v.expected.map(BigInt);

const ITERS = 254;
const K = Number(process.env.K ?? 32); // iterations per chunk (32 -> the committed 16-chunk plan)

// Derived chunk contracts + manifest land in generated/ (gitignored); committing the
// generator + .gitignore is enough.
const OUT_DIR = join(here, 'generated');
mkdirSync(OUT_DIR, { recursive: true });

// ---- build chunk boundary plan ----
// A chunk is a contiguous range of double-and-add iterations within ONE term.
// The chunk whose range ends at iteration ITERS performs the term FOLD (acc+=R)
// at its tail; for term 0 it then RESETS R/base to IC2 for term 1. The final
// chunk (end of term 1) does the fold then the inverse -> affine -> assert.
const chunks = []; // each: {term, lo, hi, fold, resetToIc2, final}
for (const term of [0, 1]) {
  let lo = 0;
  while (lo < ITERS) {
    const hi = Math.min(lo + K, ITERS);
    const isTermEnd = hi === ITERS;
    chunks.push({
      term, lo, hi,
      fold: isTermEnd,
      resetToIc2: isTermEnd && term === 0,
      final: isTermEnd && term === 1,
    });
    lo = hi;
  }
}

// ---- execute, capturing the state at every chunk boundary ----
function jacDblBase(bX, bY, bZ) {
  if (bZ !== 0n && bY !== 0n) return jacDouble(bX, bY, bZ);
  return [bX, bY, bZ];
}

function runIter(k, i, rX, rY, rZ, bX, bY, bZ) {
  if (((k >> BigInt(i)) & 1n) === 1n) {
    if (rZ === 0n) { [rX, rY, rZ] = [bX, bY, bZ]; }
    else { [rX, rY, rZ] = jacAdd(rX, rY, rZ, bX, bY, bZ); }
  }
  [bX, bY, bZ] = jacDblBase(bX, bY, bZ);
  return [rX, rY, rZ, bX, bY, bZ];
}

// initial state (entering chunk 0): acc=IC0, R=inf, base=IC1
let state = [ic0[0], ic0[1], 1n, ic1[0], ic1[1], 1n, 0n, 1n, 0n];
for (const ch of chunks) {
  let [accX, accY, accZ, bX, bY, bZ, rX, rY, rZ] = state;
  ch.incoming = commit(state);
  ch.incomingState = state.map((x) => x.toString());
  const k = ch.term === 0 ? input0 : input1;
  for (let i = ch.lo; i < ch.hi; i++) {
    [rX, rY, rZ, bX, bY, bZ] = runIter(k, i, rX, rY, rZ, bX, bY, bZ);
  }
  if (ch.fold) {
    if (rZ !== 0n) { [accX, accY, accZ] = jacAdd(accX, accY, accZ, rX, rY, rZ); }
  }
  if (ch.resetToIc2) {
    [rX, rY, rZ] = [0n, 1n, 0n];
    [bX, bY, bZ] = [ic2[0], ic2[1], 1n];
  }
  const newState = [accX, accY, accZ, bX, bY, bZ, rX, rY, rZ];
  if (ch.final) {
    const zInv = modpow(accZ, p - 2n, p);
    const zInv2 = sqrFp(zInv), zInv3 = mulFp(zInv2, zInv);
    ch.affX = mulFp(accX, zInv2).toString();
    ch.affY = mulFp(accY, zInv3).toString();
    ch.outgoing = null;
  } else {
    ch.outgoing = commit(newState);
  }
  state = newState;
}

// sanity vs noble reference (via the vectors)
const final = chunks[chunks.length - 1];
if (final.affX !== expected[0].toString() || final.affY !== expected[1].toString()) {
  throw new Error(`vk_x mismatch: ${final.affX},${final.affY} != ${expected}`);
}
// continuity: chunk i outgoing == chunk i+1 incoming
for (let i = 0; i + 1 < chunks.length; i++) {
  if (chunks[i].outgoing !== chunks[i + 1].incoming) throw new Error('continuity break');
}
console.error(`noble match OK, ${chunks.length} chunks, K=${K}, continuity OK`);

// ---- emit .cash contracts ----
const P = '21888242871839275222246405745257275088696311157297823662689037894645226208583';

// top-level (global) functions, emitted above the contract
const FP_FUNCS = `function addFp(int x, int y) returns (int) { return (x + y) % ${P}; }
function subFp(int x, int y) returns (int) { int p = ${P}; return (x - y + p) % p; }
function mulFp(int x, int y) returns (int) { return (x * y) % ${P}; }
function sqrFp(int x) returns (int) { return (x * x) % ${P}; }`;

const INVERSE_FUNC = `function inverseFp(int x) returns (int) {
    int p = ${P};
    int e = p - 2;
    int result = 1;
    int current = x % p;
    for (int i = 0; i < 254; i++) {
        if (((e >> i) % 2) == 1) { result = (result * current) % p; }
        current = (current * current) % p;
    }
    return result;
}`;

// Jacobian add of (varPfx) += (basePfx); inlined, mirrors the singleton.
const addBlock = (varPfx, basePfx) => `            int z1z1 = sqrFp(${varPfx}Z);
            int z2z2 = sqrFp(${basePfx}Z);
            int u1 = mulFp(${varPfx}X, z2z2);
            int u2 = mulFp(${basePfx}X, z1z1);
            int s1 = mulFp(mulFp(${varPfx}Y, ${basePfx}Z), z2z2);
            int s2 = mulFp(mulFp(${basePfx}Y, ${varPfx}Z), z1z1);
            if (u1 == u2 && s1 == s2) {
                int a = sqrFp(${varPfx}X);
                int b = sqrFp(${varPfx}Y);
                int c = sqrFp(b);
                int d = mulFp(2, subFp(subFp(sqrFp(addFp(${varPfx}X, b)), a), c));
                int e = mulFp(3, a);
                int f = sqrFp(e);
                int nx = subFp(f, mulFp(2, d));
                int ny = subFp(mulFp(e, subFp(d, nx)), mulFp(8, c));
                int nz = mulFp(2, mulFp(${varPfx}Y, ${varPfx}Z));
                ${varPfx}X = nx; ${varPfx}Y = ny; ${varPfx}Z = nz;
            } else {
                int h = subFp(u2, u1);
                int i2 = sqrFp(mulFp(2, h));
                int j = mulFp(h, i2);
                int rr = mulFp(2, subFp(s2, s1));
                int vv = mulFp(u1, i2);
                int nx = subFp(subFp(sqrFp(rr), j), mulFp(2, vv));
                int ny = subFp(mulFp(rr, subFp(vv, nx)), mulFp(2, mulFp(s1, j)));
                int nz = mulFp(subFp(subFp(sqrFp(addFp(${varPfx}Z, ${basePfx}Z)), z1z1), z2z2), h);
                ${varPfx}X = nx; ${varPfx}Y = ny; ${varPfx}Z = nz;
            }`;

const dblBase = () => `            int a = sqrFp(bX);
            int b = sqrFp(bY);
            int c = sqrFp(b);
            int d = mulFp(2, subFp(subFp(sqrFp(addFp(bX, b)), a), c));
            int e = mulFp(3, a);
            int f = sqrFp(e);
            int nx = subFp(f, mulFp(2, d));
            int ny = subFp(mulFp(e, subFp(d, nx)), mulFp(8, c));
            int nz = mulFp(2, mulFp(bY, bZ));
            bX = nx; bY = ny; bZ = nz;`;

const SER = 'hash256(toPaddedBytes(accX, 40) + toPaddedBytes(accY, 40) + toPaddedBytes(accZ, 40)'
  + ' + toPaddedBytes(bX, 40) + toPaddedBytes(bY, 40) + toPaddedBytes(bZ, 40)'
  + ' + toPaddedBytes(rX, 40) + toPaddedBytes(rY, 40) + toPaddedBytes(rZ, 40))';

function genCash(idx, ch) {
  const k = ch.term === 0 ? input0 : input1;
  const name = `VkxChunk${String(idx).padStart(2, '0')}`;
  const needsInverse = ch.final;
  const lines = [];
  lines.push('pragma cashscript ^0.14.0;');
  lines.push(`// vk_x chunk ${idx}: term ${ch.term}, iterations [${ch.lo},${ch.hi}),`
    + ` fold=${ch.fold ? 'True' : 'False'}, reset_to_ic2=${ch.resetToIc2 ? 'True' : 'False'},`
    + ` final=${ch.final ? 'True' : 'False'}.`);
  lines.push(FP_FUNCS);
  if (needsInverse) lines.push(INVERSE_FUNC);
  lines.push(`contract ${name}() {`);
  lines.push('    function spend(int accX, int accY, int accZ, int bX, int bY, int bZ, int rX, int rY, int rZ, bytes unused zeroPadding) {');
  lines.push(`        require(${SER} == 0x${ch.incoming});`);
  // iteration loop: bake the bits of k for [lo,hi) as a constant scalar window.
  // We shift by the absolute index i, so reuse the singleton's per-bit test.
  lines.push(`        int input = ${k};`);
  lines.push(`        for (int i = ${ch.lo}; i < ${ch.hi}; i = i + 1) {`);
  lines.push('            if (((input >> i) % 2) == 1) {');
  lines.push('                if (rZ == 0) {');
  lines.push('                    rX = bX; rY = bY; rZ = bZ;');
  lines.push('                } else {');
  lines.push(addBlock('r', 'b'));
  lines.push('                }');
  lines.push('            }');
  lines.push('            if (bZ != 0 && bY != 0) {');
  lines.push(dblBase());
  lines.push('            }');
  lines.push('        }');
  if (ch.fold) {
    lines.push('        if (rZ != 0) {');
    lines.push(addBlock('acc', 'r'));
    lines.push('        }');
  }
  if (ch.resetToIc2) {
    lines.push('        rX = 0; rY = 1; rZ = 0;');
    lines.push(`        bX = ${ic2[0]}; bY = ${ic2[1]}; bZ = 1;`);
  }
  if (needsInverse) {
    lines.push('        int zInv = inverseFp(accZ);');
    lines.push('        int zInv2 = sqrFp(zInv);');
    lines.push('        int zInv3 = mulFp(zInv2, zInv);');
    lines.push(`        require(mulFp(accX, zInv2) == ${expected[0]});`);
    lines.push(`        require(mulFp(accY, zInv3) == ${expected[1]});`);
  } else {
    lines.push(`        require(${SER} == 0x${ch.outgoing});`);
  }
  lines.push('    }');
  lines.push('}');
  return hoistSpendConstants(lines.join('\n') + '\n');
}

chunks.forEach((ch, idx) => writeFileSync(join(OUT_DIR, `chunk${String(idx).padStart(2, '0')}.cash`), genCash(idx, ch)));

const manifest = {
  K,
  numChunks: chunks.length,
  input0: Number(input0), input1: Number(input1),
  expected: [expected[0].toString(), expected[1].toString()],
  serializeWidth: W,
  chunks: chunks.map((ch, i) => ({
    idx: i,
    file: `chunk${String(i).padStart(2, '0')}.cash`,
    term: ch.term, lo: ch.lo, hi: ch.hi,
    fold: ch.fold, reset_to_ic2: ch.resetToIc2, final: ch.final,
    incoming: ch.incoming,
    outgoing: ch.outgoing,
    incoming_state: ch.incomingState,
  })),
};
writeFileSync(join(OUT_DIR, 'manifest.json'), JSON.stringify(manifest, null, 2));
console.error(`wrote ${chunks.length} chunk .cash files + manifest.json to generated/`);
