// Build the benchmark vectors for the opcode-optimized singleton, reproducibly from source:
//   1. compile ../groth16.cash with cashc                       -> baseline locking bytecode
//   2. dissect + probe arities + recompile every subroutine     -> optimized locking bytecode
//   3. reuse the committed proof witnesses (interface-identical) -> validate + measure
//   4. write verifier/src/bch/groth16-singleton-opcode-optimized{,-multiproof}-vectors.json
//
// Run:  node singleton/bn254/recompiler/build_vectors_optimized.mjs
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  hexToBin, binToHex, createVirtualMachineBch2026, createTestAuthenticationProgramBch,
} from '@bitauth/libauth';
import { compileFile } from 'cashc';
import { dissect, probeArity, recompileAll, recompileMain, rebuild, evalFull } from './recompiler.mjs';

const MAIN_INARITY = 10; // spend(Ax,Ay,Bxa,Bxb,Bya,Byb,Cx,Cy,in0,in1)

const here = dirname(fileURLToPath(import.meta.url));
const VDIR = join(here, '../../../../verifier/src/bch') + '/';
const STANDARD_BUDGET = (41 + 10_000) * 800;
const realVm = createVirtualMachineBch2026(false);

// 1. compile the singleton -> baseline locking bytecode
console.log('compiling ../groth16.cash ...');
// disableDefSinking: the recompiler re-derives placement per body and golfs better from the
// source-ordered compile
const baselineHex = compileFile(join(here, '../groth16.cash'), { optimizeFor: 'size', disableDefSinking: true }).debug.bytecode;
const baseline = hexToBin(baselineHex);

// 2. recompile
const d = dissect(baseline);
console.log(`dissected ${d.order.length} subroutines; probing arities ...`);
const arity = probeArity(d);
console.log('recompiling subroutines (min of cashc / topo / greedy, diff-tested) ...');
const { override, rows, origBytes, newBytes } = recompileAll(d, arity);
console.log(`subroutine bytes ${origBytes} -> ${newBytes}; ${rows.length}/${d.order.length} bodies optimized`);

// 2b. recompile the main routine too; keep the smallest variant that still
// accepts the valid proof AND rejects the tampered one (validated by splicing).
const base = JSON.parse(readFileSync(VDIR + 'groth16-singleton-vectors.json', 'utf8'));
const mainOrig = rebuild(d, override); // bodies-optimized, original main
let bestMain = null, bestMainLen = Infinity;
for (const strat of ['topo', 'greedy']) {
  let m; try { m = recompileMain(d, arity, MAIN_INARITY, strat); } catch (e) { console.log(`  main (${strat}) failed: ${e.message}`); continue; }
  const spliced = rebuild(d, override, m);
  const acc = evalFull(spliced, hexToBin(base.unlocking)).accepted;
  const rej = !evalFull(spliced, hexToBin(base.invalidUnlocking)).accepted;
  if (acc && rej && m.length < bestMainLen) { bestMain = m; bestMainLen = m.length; }
  console.log(`  main (${strat}): ${m.length} B  accept=${acc} reject=${rej}`);
}
const optimized = bestMain ? rebuild(d, override, bestMain) : mainOrig;
const optimizedHex = binToHex(optimized);
console.log(`full locking bytecode ${baseline.length} -> ${optimized.length} B (main routine ${bestMain ? 'optimized' : 'kept as cashc'})`);

const evalReal = (unl) => { const s = realVm.evaluate(createTestAuthenticationProgramBch({ lockingBytecode: optimized, unlockingBytecode: hexToBin(unl), valueSatoshis: 1000n })); const t = s.stack[s.stack.length - 1]; return { accepted: s.error === undefined && s.stack.length === 1 && t?.length === 1 && t[0] === 1, error: s.error }; };
const looseAccept = evalFull(optimized, hexToBin(base.unlocking));
const looseReject = evalFull(optimized, hexToBin(base.invalidUnlocking));
const realAccept = evalReal(base.unlocking);
const opCost = looseAccept.operationCost;
if (!looseAccept.accepted || looseReject.accepted) throw new Error('optimized contract failed the accept/reject check');

const main = {
  contract: 'Groth16Verify (opcode-optimized recompile of singleton/bn254/groth16.cash)',
  description: 'identical Groth16 verifier (vk_x on-chain + full BN254 pairing == 1) as bch-groth16-singleton, '
    + 'but the locking bytecode is a hand-tuned stack-scheduling recompile of cashc output (recompiler/): cashc '
    + 'altstack park/restore eliminated, ROLL/PICK addressing minimized, multi-item stack ops. Same verdict + same '
    + 'runtime witnesses; ~34% smaller bytecode.',
  lockingOK: optimizedHex,
  unlocking: base.unlocking,
  invalidUnlocking: base.invalidUnlocking,
  lockingBytes: optimized.length,
  unlockingBytes: hexToBin(base.unlocking).length,
  operationCost: opCost,
  realAccepted: realAccept.accepted,
  realError: realAccept.error ?? null,
  inputsNeeded: Math.ceil(opCost / STANDARD_BUDGET),
  looseAccept: looseAccept.accepted,
  rejectInvalid: !looseReject.accepted,
};
writeFileSync(VDIR + 'groth16-singleton-opcode-optimized-vectors.json', JSON.stringify(main, null, 2));

const mpBase = JSON.parse(readFileSync(VDIR + 'groth16-singleton-multiproof-vectors.json', 'utf8'));
let allOk = true;
for (const p of mpBase.proofs) {
  if (!evalFull(optimized, hexToBin(p.unlocking)).accepted) allOk = false;
  if (evalFull(optimized, hexToBin(p.invalidUnlocking)).accepted) allOk = false;
}
if (!allOk) throw new Error('optimized contract failed a multiproof accept/reject');
const mp = { ...mpBase, contract: main.contract, description: 'multiproof set for the opcode-optimized singleton (same distinct proofs, optimized locking).', lockingOK: optimizedHex, lockingBytes: optimized.length };
writeFileSync(VDIR + 'groth16-singleton-opcode-optimized-multiproof-vectors.json', JSON.stringify(mp, null, 2));

console.log(`\nlooseAccept ${looseAccept.accepted}  rejectInvalid ${!looseReject.accepted}  opCost ${opCost.toLocaleString()}  inputsNeeded ${main.inputsNeeded}`);
console.log(`realAccepted ${realAccept.accepted}  realError ${realAccept.error ?? '(none)'}`);
console.log(`multiproof ${mpBase.proofs.length}/${mpBase.proofs.length} accept+reject OK`);
console.log('wrote groth16-singleton-opcode-optimized-vectors.json + -multiproof-vectors.json');
