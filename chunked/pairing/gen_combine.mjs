// Combine chunk: boundary = f0 * f1 * f2 * f3 (the 4 single-pair Miller results),
// the pre-final-exp Fp12. Incoming state = the 4 pairs' final (f_i, R_i) = 72 ints
// (the outputs of the 4 Miller chains), hash256-committed; computes the boundary
// with 3 fp12Mul (using only the f parts) and commits hash256(boundary, 12 ints).
// node gen_combine.mjs
import { writeFileSync, mkdirSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  Fp12, singlePairMiller, pairsFor, vec, f12limbs, r6limbs,
  commit, fnExtractor, measureChunk, decl, serExpr,
} from './_millermath.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const GEN = join(here, 'generated');
mkdirSync(GEN, { recursive: true });
const ext = fnExtractor(join(here, '..', '..', 'singleton', 'pairing', 'miller.cash'));
const FNS = ['addFp', 'subFp', 'mulFp', 'fp2Add', 'fp2Sub', 'fp2Mul', 'fp2MulXi', 'fp6Add', 'fp6Sub', 'fp6MulByV', 'fp6Mul', 'fp12Mul'];

// recompute the 4 final (f_i, R_i)
const pairs = pairsFor(vec.publicInputs);
const finals = pairs.map((p) => singlePairMiller(p));
const stateLimbs = (s) => [...f12limbs(s.f), ...r6limbs(s.R)]; // 18 per pair
const incomingLimbs = finals.flatMap(stateLimbs);              // 72
const boundary = finals.reduce((acc, s) => Fp12.mul(acc, s.f), Fp12.ONE);
const outLimbs = f12limbs(boundary);                            // 12

const incoming = commit(incomingLimbs);
const outgoing = commit(outLimbs);

// param names: a<i>_<0..11> (f), r<i>_<0..5> (R)
const aNames = (i) => Array.from({ length: 12 }, (_, j) => `a${i}_${j}`);
const rNames = (i) => Array.from({ length: 6 }, (_, j) => `r${i}_${j}`);
const allParams = []; for (let i = 0; i < 4; i++) { allParams.push(...aNames(i), ...rNames(i)); } // 72, declaration order

const L = [];
L.push('pragma cashscript ^0.13.0;');
L.push('// Combine chunk: boundary = f0*f1*f2*f3 (pre-final-exp Fp12).');
L.push('// incoming = 4x (f_i 12 + R_i 6) = 72 ints; outgoing = boundary (12 ints).');
L.push('contract PairingCombine() {');
L.push(FNS.map(ext).join('\n'));
L.push(`    function spend(${decl(allParams)}) {`);
L.push(`        require(${serExpr(allParams)} == 0x${incoming});`);
const fresh = (() => { let u = 0; return (n) => Array.from({ length: n }, () => `v${u++}`); })();
let acc = aNames(0);
for (let i = 1; i < 4; i++) {
  const nv = fresh(12);
  L.push(`        (${decl(nv)}) = fp12Mul(${acc.join(',')}, ${aNames(i).join(',')});`);
  acc = nv;
}
L.push(`        require(${serExpr(acc)} == 0x${outgoing});`);
L.push('    }');
L.push('}');
const src = L.join('\n') + '\n';
writeFileSync(join(GEN, 'combine.cash'), src);

const m = measureChunk(src, incomingLimbs, join(GEN, `_probe_${process.pid}.cash`));
try { execFileSync('rm', [join(GEN, `_probe_${process.pid}.cash`)]); } catch {}
console.log(`combine.cash: lock=${m.lockingBytes}B op=${m.operationCost.toLocaleString()} accepted=${m.accepted} ${m.error ?? ''}`);
console.log(`boundary first limb = ${outLimbs[0]}`);

// cross-check vs noble pre-final-exp boundary (millerHex)
import('node:fs').then(({ readFileSync }) => {
  const golden = JSON.parse(readFileSync('C:/Users/mathi/Desktop/verifier/src/checkpoints/pairing-vectors.json', 'utf8')).golden.millerHex;
  const goldenFirst = BigInt('0x' + golden.slice(0, 64));
  console.log(`matches golden millerHex first limb: ${goldenFirst === BigInt(outLimbs[0])}`);
});

writeFileSync(join(GEN, 'manifest_combine.json'), JSON.stringify({
  incoming, outgoing, incomingLimbs: incomingLimbs.map(String), boundary: outLimbs.map(String),
  lockingBytes: m.lockingBytes, operationCost: m.operationCost, accepted: m.accepted,
}, null, 2));
