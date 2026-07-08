// Build the benchmark vectors for the opcode-optimized BLS12-381 singleton, reproducibly
// from source — the BLS counterpart of singleton/bn254/recompiler/build_vectors_optimized.mjs
// and the other end of the bytesize-vs-opcost tradeoff from bch-groth16-bls12381-singleton
// (which stays the plain compiler-output baseline).
//
// Two candidates are built and the smaller verified artifact wins:
//   A. golf pipeline: compile (size objective, no rescheduleStacks, disableDefSinking)
//      -> dissect + probe arities + recompile every subroutine + main -> outline
//   B. rescheduled compile (size objective + rescheduleStacks) -> outline
// so the entry can never come out worse than the outlined compiler output.
//
// Run:  node singleton/bls12-381/build_vectors_optimized.mjs
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  hexToBin, binToHex, bigIntToVmNumber, encodeDataPush,
  createVirtualMachineBch2026, createTestAuthenticationProgramBch,
} from '@bitauth/libauth';
import { compileFile } from 'cashc';
import {
  dissect, probeArity, recompileAll, recompileMain, rebuild, evalFull, setTestInputRange,
} from '../bn254/recompiler/recompiler.mjs';
import { outlineArtifact } from '../bn254/recompiler/outline.mjs';
import { proof, PUBLIC_INPUTS } from './bls_instance.mjs';

const MAIN_INARITY = 10; // spend(Ax,Ay,Bxa,Bxb,Bya,Byb,Cx,Cy,in0,in1)
const BLS_P = 4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787n;
setTestInputRange(BLS_P); // 381-bit random probe/diff-test inputs (BN254 default is 254-bit)

const here = dirname(fileURLToPath(import.meta.url));
const VDIR = join(here, '../../../verifier/src/bch') + '/';
const STANDARD_BUDGET = (41 + 10_000) * 800;
const realVm = createVirtualMachineBch2026(false);

// witnesses (identical runtime interface for every candidate)
const pushInt = (n) => encodeDataPush(bigIntToVmNumber(n));
const unlockingFor = (args) => Uint8Array.from(args.slice().reverse().flatMap((a) => [...pushInt(a)]));
const A = proof.a.toAffine(), B = proof.b.toAffine(), C = proof.c.toAffine();
const proofArgs = (inputs) => [A.x, A.y, B.x.c0, B.x.c1, B.y.c0, B.y.c1, C.x, C.y, ...inputs];
const unlocking = unlockingFor(proofArgs(PUBLIC_INPUTS));
const invalidUnlocking = unlockingFor(proofArgs([PUBLIC_INPUTS[0] + 1n, PUBLIC_INPUTS[1]]));
const mpBase = JSON.parse(readFileSync(VDIR + 'groth16-bls12381-singleton-multiproof-vectors.json', 'utf8'));

const acceptsRejects = (bytes) => evalFull(bytes, unlocking).accepted && !evalFull(bytes, invalidUnlocking).accepted;
const outline = (bytes) => outlineArtifact(bytes, { verify: acceptsRejects, log: console.log }).bytes;

// candidate A: golf pipeline (custom decompile -> reschedule -> recompile), then outline
console.log('candidate A: golf recompile ...');
const baseline = hexToBin(compileFile(join(here, 'groth16.cash'), { optimizeFor: 'size', disableDefSinking: true }).debug.bytecode);
const d = dissect(baseline);
console.log(`  dissected ${d.order.length} subroutines; probing arities ...`);
const arity = probeArity(d);
console.log('  recompiling subroutines (min of cashc / topo / greedy, diff-tested) ...');
const { override, origBytes, newBytes } = recompileAll(d, arity);
console.log(`  subroutine bytes ${origBytes} -> ${newBytes}`);
let bestMain = null, bestMainLen = Infinity;
for (const strat of ['topo', 'greedy']) {
  let m; try { m = recompileMain(d, arity, MAIN_INARITY, strat); } catch (e) { console.log(`  main (${strat}) failed: ${e.message}`); continue; }
  const spliced = rebuild(d, override, m);
  const ok = acceptsRejects(spliced);
  if (ok && m.length < bestMainLen) { bestMain = m; bestMainLen = m.length; }
  console.log(`  main (${strat}): ${m.length} B  ok=${ok}`);
}
const golfed = bestMain ? rebuild(d, override, bestMain) : rebuild(d, override);
if (!acceptsRejects(golfed)) throw new Error('golfed candidate failed the accept/reject check before outlining');
console.log(`  golfed ${baseline.length} -> ${golfed.length} B; outlining ...`);
const candA = outline(golfed);
console.log(`candidate A: ${candA.length} B`);

// candidate B: rescheduled compile, then outline
console.log('candidate B: rescheduled compile ...');
const rescheduled = hexToBin(compileFile(join(here, 'groth16.cash'), { optimizeFor: 'size', rescheduleStacks: true }).debug.bytecode);
console.log(`  compiled ${rescheduled.length} B; outlining ...`);
const candB = outline(rescheduled);
console.log(`candidate B: ${candB.length} B`);

const optimized = candA.length <= candB.length ? candA : candB;
const which = candA.length <= candB.length ? 'A (golf recompile)' : 'B (rescheduled compile)';
console.log(`kept candidate ${which}: ${optimized.length} B`);

// full battery on the winner
const looseAccept = evalFull(optimized, unlocking);
const looseReject = evalFull(optimized, invalidUnlocking);
if (!looseAccept.accepted || looseReject.accepted) throw new Error('optimized contract failed the accept/reject check');
for (const p of mpBase.proofs) {
  if (!evalFull(optimized, hexToBin(p.unlocking)).accepted) throw new Error('optimized contract failed a multiproof accept');
  if (evalFull(optimized, hexToBin(p.invalidUnlocking)).accepted) throw new Error('optimized contract failed a multiproof reject');
}
const st = realVm.evaluate(createTestAuthenticationProgramBch({ lockingBytecode: optimized, unlockingBytecode: unlocking, valueSatoshis: 1000n }));
const top = st.stack[st.stack.length - 1];
const realAccepted = st.error === undefined && st.stack.length === 1 && top?.length === 1 && top[0] === 1;
const opCost = looseAccept.operationCost;
const optimizedHex = binToHex(optimized);

const main = {
  contract: 'Groth16Verify BLS12-381 (opcode-optimized recompile of singleton/bls12-381/groth16.cash)',
  description: 'identical BLS12-381 Groth16 verifier (vk_x on-chain + full pairing == 1) as '
    + 'bch-groth16-bls12381-singleton, but the locking bytecode is the byte-optimized build: min of the golf '
    + 'recompile (bn254/recompiler/) and the rescheduled compile, then repeated instruction sequences outlined '
    + 'into OP_DEFINE bodies (outline.mjs). Same verdict + same runtime witnesses; trades a few percent op-cost '
    + 'for the byte savings.',
  lockingOK: optimizedHex,
  unlocking: binToHex(unlocking),
  invalidUnlocking: binToHex(invalidUnlocking),
  lockingBytes: optimized.length,
  unlockingBytes: unlocking.length,
  operationCost: opCost,
  realAccepted,
  realError: st.error ?? null,
  inputsNeeded: Math.ceil(opCost / STANDARD_BUDGET),
  looseAccept: looseAccept.accepted,
  rejectInvalid: !looseReject.accepted,
};
writeFileSync(VDIR + 'groth16-bls12381-singleton-opcode-optimized-vectors.json', JSON.stringify(main, null, 2));

const mp = {
  ...mpBase,
  contract: main.contract,
  description: 'multiproof set for the opcode-optimized BLS12-381 singleton (same distinct proofs, optimized locking).',
  lockingOK: optimizedHex,
  lockingBytes: optimized.length,
};
writeFileSync(VDIR + 'groth16-bls12381-singleton-opcode-optimized-multiproof-vectors.json', JSON.stringify(mp, null, 2));

console.log(`\nlooseAccept ${looseAccept.accepted}  rejectInvalid ${!looseReject.accepted}  opCost ${opCost.toLocaleString()}  inputsNeeded ${main.inputsNeeded}`);
console.log(`realAccepted ${realAccepted}  realError ${st.error ?? '(none)'}`);
console.log(`multiproof ${mpBase.proofs.length}/${mpBase.proofs.length} accept+reject OK`);
console.log('wrote groth16-bls12381-singleton-opcode-optimized-vectors.json + -multiproof-vectors.json');
