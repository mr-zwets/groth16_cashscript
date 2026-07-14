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
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { createVirtualMachineBch2026, createVirtualMachineBchSpec, encodeDataPush, bigIntToVmNumber, numberToBinUint16LE, numberToBinUint32LE } from '@bitauth/libauth';
import { covIn, decl, commitBin, CATEGORY, TARGET_UNLOCK, OP_PUSHDATA2, compileFileBytecodeRaw, pairsFor, vec, millerBatchOps } from './_millermath.mjs';
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

// The residue verdict BODY (no contract/covIn wrapper), parameterized by the fp12 limb-name
// arrays so it can be emitted standalone (the ResidueTail chunk) OR inlined at the end of the
// fused-Miller final chunk (chunked/pairing/gen_miller_residue.mjs FUSE_TAIL, folding the separate
// tail input into the last Miller input). `fFnames` are the fF (final Miller f) limbs, `cNames`/
// `ciNames` the residue witness c/cInv (carried Miller state), `wNames` the w witness (uncommitted).
// Gates: c per-limb canonical, c*cInv==ONE, w in {1,ROOT27,ROOT27^2}, verdict fF*w*c^q2==c^q*c^q3.
export function residueVerdictLines(fFnames, cNames, ciNames, wNames) {
  const v = (p) => Array.from({ length: 12 }, (_, i) => `${p}${i}`);
  const L = [];
  L.push(`        int P = ${P};`); // field prime (lazy-lib chunks declare it locally)
  L.push('        ' + cNames.map((n) => `require(${n} < P);`).join(' '));
  const p = v('p');
  L.push(`        (${decl(p)}) = fp12Mul(${cNames.join(',')}, ${ciNames.join(',')});`);
  L.push('        // fp12Mul canonicalizes every returned limb to [0,P), so direct equality is field equality.');
  L.push('        ' + p.map((n, i) => `require(${n} == ${ONE_L[i]});`).join(' '));
  L.push(`        require(${matchVec(wNames, ONE_L)} || ${matchVec(wNames, ROOT27L)} || ${matchVec(wNames, ROOT27_2L)});`);
  const cq = v('cq'), cqq = v('cqq'), cqqq = v('cqqq');
  L.push(`        (${decl(cq)}) = fp12Frob1(${cNames.join(',')});`);
  L.push(`        (${decl(cqq)}) = fp12Frob2(${cNames.join(',')});`);
  L.push(`        (${decl(cqqq)}) = fp12Frob3(${cNames.join(',')});`);
  const t = v('t'), lhs = v('lhs'), rhs = v('rhs');
  L.push(`        (${decl(t)}) = fp12Mul(${fFnames.join(',')}, ${wNames.join(',')});`);
  L.push(`        (${decl(lhs)}) = fp12Mul(${t.join(',')}, ${cqq.join(',')});`);
  L.push(`        (${decl(rhs)}) = fp12Mul(${cq.join(',')}, ${cqqq.join(',')});`);
  L.push('        ' + lhs.map((n, i) => `require(${n} == ${rhs[i]});`).join(' '));
  return L;
}

function genTail() {
  const L = [];
  L.push('pragma cashscript ^0.14.0;');
  L.push(`import "${LIB_IMPORT}";`);
  L.push('// Witnessed-residue final-exp TAIL (ePrint 2024/640): verdict fF*w*c^q2 == c^q*c^q3.');
  L.push('contract ResidueTail() {');
  L.push(`    function spend(${decl([...COMMIT, ...wN])}, bytes unused zeroPadding) {`);
  L.push(covIn(COMMIT)); // bind [fF, c, cInv] to the spent token / forwarded blob
  L.push(...residueVerdictLines(fFn, cN, ciN, wN));
  L.push('    }');
  L.push('}');
  return L.join('\n') + '\n';
}

// ---- real-VM measurement: commit 36 state limbs, push 36 + 12 (w) ----
const realVm = (process.env.BCH_VM === 'spec' ? createVirtualMachineBchSpec : createVirtualMachineBch2026)(false);
const pushInt = (n) => encodeDataPush(bigIntToVmNumber(n));
const OP_PUSHDATA4 = 0x4e;
const padPush = (argLen, target) => {
  const budget = target - argLen;
  if (budget - 3 <= 0xffff) { const N = budget - 3; return Uint8Array.from([OP_PUSHDATA2, ...numberToBinUint16LE(N), ...new Uint8Array(N)]); }
  const N = budget - 5; return Uint8Array.from([OP_PUSHDATA4, ...numberToBinUint32LE(N), ...new Uint8Array(N)]);
};
function measureTail(src, stateLimbs36, wLimbs12) {
  let raw;
  try { writeFileSync(PROBE, src); raw = compileFileBytecodeRaw(PROBE); }
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

// Emit the standalone tail chunk + self-test ONLY when run as the main script (so importing
// residueVerdictLines from gen_miller_residue's FUSE_TAIL path has no file-write side effect).
if (process.argv[1] && process.argv[1].endsWith('gen_finalexp_residue.mjs')) {
  const src = genTail();
  writeFileSync(join(GEN, 'finalexpres_00.cash'), src);
  writeFileSync(join(GEN, 'manifest_finalexpres.json'), JSON.stringify({ numChunks: 1, residueTail: true }, null, 2));
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
