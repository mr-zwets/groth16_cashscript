// Generator for the witnessed-residue final-exponentiation TAIL (ePrint 2024/640) — ONE chunk
// that replaces the 12-chunk hard-part final exponentiation. The fused Miller already folded
// c^-(6x+2), so the tail only needs cheap Frobenius + one multiplicative identity:
//
//   verdict:  fF * w * c^q^2  ==  c^q * c^q^3       (<=> c^lambda == fRaw*w <=> finalExp==1)
//
// Inputs (committed, handed off by the fused Miller's final chunk): fF(12), c(12), cInv(12).
// Witness extra (uncommitted, in the unlocking): w(12). Gates:
//   - c per-limb canonical (0 <= c_j < p)            [12 requires]
//   - c * cInv == ONE  (pins cInv = c^-1, c != 0)     [fp12Mul + 12 requires]
//   - w in the cubic-coset {1, ROOT27, ROOT27^2}      [3-way 12-limb match; tight per 2024/640]
//   - verdict fF*w*c^q2 == c^q*c^q3                    [3 Frobenius + 3 fp12Mul + 12 requires]
//   node gen_finalexp_residue.mjs   emit finalexpres_00.cash + manifest_finalexpres.json
import { hoistSpendConstants } from '../_hoistconsts.mjs';
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { createVirtualMachineBch2026, encodeDataPush, bigIntToVmNumber, numberToBinUint16LE } from '@bitauth/libauth';
import { covIn, decl, commitBin, CATEGORY, TARGET_UNLOCK, OP_PUSHDATA2, compileFileBytecode, pairsFor, vec, millerBatchOps } from './_millermath.mjs';
import { residueWitness, millerFusedOps, fp12limbsOf, COSET27 } from './_residuemath.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const GEN = join(here, 'generated');
const PROBE = join(GEN, '_probe_finalexpres.cash');
const LIB_IMPORT = '../../../singleton/bn254/lib/lazy/Bn254Lazy.cash';
const P = '21888242871839275222246405745257275088696311157297823662689037894645226208583';

const fFn = Array.from({ length: 12 }, (_, i) => `fF${i}`);
const cN = Array.from({ length: 12 }, (_, i) => `c${i}`);
const ciN = Array.from({ length: 12 }, (_, i) => `ci${i}`);
const wN = Array.from({ length: 12 }, (_, i) => `w${i}`);
const COMMIT = [...fFn, ...cN, ...ciN]; // 36 committed limbs (from the fused Miller hand-off)

const ROOT27L = fp12limbsOf(COSET27[1]).map(String);
const ROOT27_2L = fp12limbsOf(COSET27[2]).map(String);
const matchVec = (names, lits) => '(' + names.map((n, i) => `${n} == ${lits[i]}`).join(' && ') + ')';
const ONE_L = ['1', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0'];

function genTail() {
  const L = [];
  L.push('pragma cashscript ^0.14.0;');
  L.push(`import "${LIB_IMPORT}";`);
  L.push('// Witnessed-residue final-exp TAIL (ePrint 2024/640): verdict fF*w*c^q2 == c^q*c^q3.');
  L.push('contract ResidueTail() {');
  L.push(`    function spend(${decl([...COMMIT, ...wN])}, bytes unused zeroPadding) {`);
  L.push(covIn(COMMIT)); // bind [fF, c, cInv] to the spent token / forwarded blob
  L.push(`        int P = ${P};`); // field prime (lazy-lib chunks declare it locally)
  // c per-limb canonical
  L.push('        ' + cN.map((n) => `require(${n} < P);`).join(' '));
  // c * cInv == ONE  (lazy fp12Mul returns an unreduced representative -> compare mod P)
  L.push(`        (${decl(Array.from({ length: 12 }, (_, i) => `p${i}`))}) = fp12Mul(${cN.join(',')}, ${ciN.join(',')});`);
  L.push('        ' + Array.from({ length: 12 }, (_, i) => `require(p${i} % P == ${ONE_L[i]});`).join(' '));
  // w in {1, ROOT27, ROOT27^2}
  L.push(`        require(${matchVec(wN, ONE_L)} || ${matchVec(wN, ROOT27L)} || ${matchVec(wN, ROOT27_2L)});`);
  // Frobenius c^q, c^q^2, c^q^3
  L.push(`        (${decl(Array.from({ length: 12 }, (_, i) => `cq${i}`))}) = fp12Frob1(${cN.join(',')});`);
  L.push(`        (${decl(Array.from({ length: 12 }, (_, i) => `cqq${i}`))}) = fp12Frob2(${cN.join(',')});`);
  L.push(`        (${decl(Array.from({ length: 12 }, (_, i) => `cqqq${i}`))}) = fp12Frob3(${cN.join(',')});`);
  // LHS = fF * w * c^q^2 ; RHS = c^q * c^q^3
  L.push(`        (${decl(Array.from({ length: 12 }, (_, i) => `t${i}`))}) = fp12Mul(${fFn.join(',')}, ${wN.join(',')});`);
  L.push(`        (${decl(Array.from({ length: 12 }, (_, i) => `lhs${i}`))}) = fp12Mul(${Array.from({ length: 12 }, (_, i) => `t${i}`).join(',')}, ${Array.from({ length: 12 }, (_, i) => `cqq${i}`).join(',')});`);
  L.push(`        (${decl(Array.from({ length: 12 }, (_, i) => `rhs${i}`))}) = fp12Mul(${Array.from({ length: 12 }, (_, i) => `cq${i}`).join(',')}, ${Array.from({ length: 12 }, (_, i) => `cqqq${i}`).join(',')});`);
  L.push('        ' + Array.from({ length: 12 }, (_, i) => `require(lhs${i} % P == rhs${i} % P);`).join(' '));
  L.push('    }');
  L.push('}');
  return hoistSpendConstants(L.join('\n') + '\n');
}

// ---- real-VM measurement: commit 36 state limbs, push 36 + 12 (w) ----
const realVm = createVirtualMachineBch2026(false);
const pushInt = (n) => encodeDataPush(bigIntToVmNumber(n));
const padPush = (argLen, target) => { const N = target - argLen - 3; return Uint8Array.from([OP_PUSHDATA2, ...numberToBinUint16LE(N), ...new Uint8Array(N)]); };
function measureTail(src, stateLimbs36, wLimbs12) {
  let raw;
  try { writeFileSync(PROBE, src); raw = compileFileBytecode(PROBE); }
  catch (e) { return { lockingBytes: Infinity, operationCost: Infinity, accepted: false, error: String(e?.message ?? e) }; }
  const locking = Uint8Array.from([...raw]);
  const pushInts = [...stateLimbs36, ...wLimbs12];
  const argBytes = Uint8Array.from([...pushInts].reverse().flatMap((c) => [...pushInt(BigInt(c))]));
  const unlocking = Uint8Array.from([...padPush(argBytes.length, TARGET_UNLOCK), ...argBytes]);
  const tok = (commitment) => ({ amount: 0n, category: CATEGORY, nft: { capability: 'mutable', commitment } });
  const program = {
    inputIndex: 0,
    sourceOutputs: [{ lockingBytecode: locking, valueSatoshis: 1000n, token: tok(commitBin(stateLimbs36.map(BigInt))) }],
    transaction: { version: 2, inputs: [{ outpointTransactionHash: new Uint8Array(32), outpointIndex: 0, sequenceNumber: 0, unlockingBytecode: unlocking }], outputs: [{ lockingBytecode: Uint8Array.from([0x6a]), valueSatoshis: 1000n }], locktime: 0 },
  };
  const st = realVm.evaluate(program);
  const top = st.stack[st.stack.length - 1];
  const accepted = st.error === undefined && st.stack.length === 1 && top !== undefined && top.length === 1 && top[0] === 1;
  return { lockingBytes: locking.length, operationCost: st.metrics.operationCost, accepted, error: st.error ?? null };
}

const src = genTail();
writeFileSync(join(GEN, 'finalexpres_00.cash'), src);
writeFileSync(join(GEN, 'manifest_finalexpres.json'), JSON.stringify({ numChunks: 1, residueTail: true }, null, 2));

if (process.argv[1] && process.argv[1].endsWith('gen_finalexp_residue.mjs')) {
  // self-test on the committed instance
  const pairs = pairsFor(vec.publicInputs.map(BigInt));
  const { boundary: fRaw } = millerBatchOps(pairs);
  const { c, cInv, w } = residueWitness(fRaw);
  const fused = millerFusedOps(pairs, c, cInv);
  const stateLimbs36 = [...fp12limbsOf(fused.boundary), ...fp12limbsOf(c), ...fp12limbsOf(cInv)].map((x) => ((x % BigInt(P)) + BigInt(P)) % BigInt(P));
  const wLimbs12 = fp12limbsOf(w).map(String);
  const m = measureTail(src, stateLimbs36.map(String), wLimbs12);
  console.error(`residue tail: lock=${m.lockingBytes}B op=${m.operationCost.toLocaleString()} accepted=${m.accepted} ${m.error ?? ''}`);
  // negative test: tamper fF -> must reject
  const badState = stateLimbs36.slice(); badState[0] = (badState[0] + 1n) % BigInt(P);
  const mb = measureTail(src, badState.map(String), wLimbs12);
  console.error(`residue tail (tampered fF): accepted=${mb.accepted} (expect false)`);
}
