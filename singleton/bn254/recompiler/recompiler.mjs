// Opcode-optimizing recompiler for the BN254 Groth16 singleton.
//
// cashc emits the verifier as a flat list of OP_DEFINE subroutine bodies + a main
// routine. This module takes that compiled locking bytecode, splits each subroutine
// into a value-DAG (decompile.mjs), reschedules the stack operations (schedule.mjs) to
// eliminate cashc's altstack park/restore and minimize ROLL/PICK addressing, and
// recompiles -- keeping, per subroutine, whichever of {cashc original, topo schedule,
// greedy schedule} is smallest AND proven equivalent by a differential test on the
// loosened BCH-2026 VM. See README.md.
import {
  createVirtualMachine, createInstructionSetBch2026, createTestAuthenticationProgramBch,
  ConsensusBch2025, ripemd160, secp256k1, sha1, sha256,
  bigIntToVmNumber, encodeDataPush, vmNumberToBigInt,
} from '@bitauth/libauth';
import { parse, serialize } from './asm.mjs';
import { recompileBodyV2 } from './schedule.mjs';

const DEFINE = 0x89, INVOKE = 0x8a;
const HUGE = Number.MAX_SAFE_INTEGER;
const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;

// Loosened BCH-2026 VM: lifts size/op-cost/stack caps so a single subroutine or the whole
// pairing can run to completion for grading (the real-VM caps are applied separately when
// the benchmark vectors are built).
const loosened = {
  ...ConsensusBch2025, baseInstructionCost: 100, maximumFunctionIdentifierLength: 7,
  maximumMemorySlots: HUGE, maximumStandardLockingBytecodeLength: -1,
  maximumStandardUnlockingBytecodeLength: HUGE, maximumTokenCommitmentLength: 128,
  operationCostBudgetPerByte: HUGE, maximumStackItemLength: HUGE, maximumVmNumberByteLength: HUGE,
  maximumStackDepth: HUGE, maximumControlStackDepth: HUGE, maximumBytecodeLength: HUGE, maximumOperationCount: HUGE,
};
export const looseVm = createVirtualMachine(createInstructionSetBch2026(false, { consensus: loosened, ripemd160, secp256k1, sha1, sha256 }));

const idVal = (o) => {
  if (!o) return null;
  if (o.op === 0) return 0;
  if (o.op >= 0x51 && o.op <= 0x60) return o.op - 0x50;
  if (o.data && o.data.length <= 2) { let v = 0; for (let i = o.data.length - 1; i >= 0; i--) v = (v << 8) | o.data[i]; return v; }
  return null;
};

// Split the locking bytecode into the OP_DEFINE subroutine table + the main routine.
export function dissect(bytes) {
  const ops = parse(bytes);
  const bodies = new Map(); const order = [];
  let i = 0;
  while (i + 2 < ops.length && ops[i].data && ops[i + 2] && ops[i + 2].op === DEFINE) {
    bodies.set(idVal(ops[i + 1]), ops[i].data); order.push(idVal(ops[i + 1])); i += 3;
  }
  return { bodies, order, mainOps: ops.slice(i) };
}

// Reassemble locking bytecode from a (possibly overridden) subroutine table + main routine.
// `mainBytes` (optional) replaces the main routine with a recompiled version.
export function rebuild(d, override, mainBytes) {
  const out = [];
  for (const id of d.order) {
    out.push({ op: 0, data: (override && override.has(id)) ? override.get(id) : d.bodies.get(id) });
    if (id >= 1 && id <= 16) out.push({ op: 0x50 + id });
    else out.push({ op: 0, data: bigIntToVmNumber(BigInt(id)) });
    out.push({ op: DEFINE });
  }
  const main = mainBytes ? parse(mainBytes) : d.mainOps;
  for (const o of main) out.push(o);
  return serialize(out);
}

// Run ONE subroutine in isolation on `inputs`, returning its output stack (bigint[]).
export function runSubroutine(d, targetId, inputs, override) {
  const out = [];
  for (const id of d.order) {
    out.push({ op: 0, data: (override && override.has(id)) ? override.get(id) : d.bodies.get(id) });
    if (id >= 1 && id <= 16) out.push({ op: 0x50 + id });
    else out.push({ op: 0, data: bigIntToVmNumber(BigInt(id)) });
    out.push({ op: DEFINE });
  }
  for (const n of inputs) out.push({ op: 0, data: bigIntToVmNumber(BigInt(n)) });
  if (targetId >= 1 && targetId <= 16) out.push({ op: 0x50 + targetId });
  else out.push({ op: 0, data: bigIntToVmNumber(BigInt(targetId)) });
  out.push({ op: INVOKE });
  const state = looseVm.evaluate(createTestAuthenticationProgramBch({ lockingBytecode: serialize(out), unlockingBytecode: new Uint8Array(), valueSatoshis: 1000n }));
  // The only expected "error" is the benign post-eval clean-stack check; stack is still valid.
  const benign = !state.error || /Non-P2SH|clean stack|exactly one|single/i.test(String(state.error));
  return { stack: state.stack.map((b) => vmNumberToBigInt(b, { maximumVmNumberByteLength: HUGE })), error: benign ? undefined : state.error, operationCost: state.metrics.operationCost };
}

const rnd = (s) => { let x = BigInt(s + 7); for (let i = 0; i < 6; i++) x = (x * 6364136223846793005n + 1442695040888963407n) % P; return x; };

// Determine (inputs -> outputs) arity of every subroutine by probing input counts.
export function probeArity(d) {
  const table = {};
  for (const id of d.order) {
    let maxErr = -1, netBig = 0;
    for (let k = 0; k <= 30; k++) {
      const r = runSubroutine(d, id, Array.from({ length: k }, (_, i) => rnd(i * 31 + id)));
      if (r.error) maxErr = k; else netBig = r.stack.length - k;
    }
    table[id] = { in: maxErr + 1, out: maxErr + 1 + netBig };
  }
  return table;
}

// Differential test: recompiled body must match the original on K random input vectors.
function bodyEquiv(d, id, rec, arity, K = 3) {
  const a = arity[id];
  for (let t = 0; t < K; t++) {
    const inp = Array.from({ length: a.in }, (_, i) => rnd(i * 17 + t * 1009 + id));
    const r0 = runSubroutine(d, id, inp);
    const r1 = runSubroutine(d, id, inp, new Map([[id, rec]]));
    if (r1.error || (r0.stack || []).join() !== (r1.stack || []).join()) return false;
  }
  return true;
}

// Recompile every subroutine; keep the smallest equivalent variant per body.
// Returns { override, rows, origBytes, newBytes }.
export function recompileAll(d, arity, onProgress) {
  const override = new Map();
  let origBytes = 0, newBytes = 0;
  const rows = [];
  for (const id of d.order) {
    const orig = d.bodies.get(id); origBytes += orig.length;
    let best = orig, tag = 'cashc';
    for (const strat of ['topo', 'greedy']) {
      let rec; try { rec = recompileBodyV2(orig, arity, arity[id].in, strat); } catch { continue; }
      if (rec.length < best.length && bodyEquiv(d, id, rec, arity)) { best = rec; tag = strat; }
    }
    override.set(id, best); newBytes += best.length;
    if (tag !== 'cashc') rows.push({ id, orig: orig.length, rec: best.length, tag });
    if (onProgress) onProgress(id, orig.length, best.length, tag);
  }
  return { override, rows, origBytes, newBytes };
}

// Recompile the top-level main routine (the `spend` body). It is decompiled like any other
// body, with require()/verify ops treated as boundaries. `inArity` = number of spend params
// the unlocking supplies (10 for the BN254 singleton). Correctness is validated by the caller
// via a full accept-valid / reject-invalid check, since main is not a value-returning routine.
export function recompileMain(d, arity, inArity, strategy = 'topo', objective = 'bytes') {
  return recompileBodyV2(serialize(d.mainOps), arity, inArity, strategy, objective);
}

// Recompile every subroutine, selecting per body by MEASURED op-cost on the loose VM
// (K fixed pseudo-random input vectors, identical across candidates, so the arithmetic
// term is constant and the measured delta is purely scheduling + body-push bytes).
// Only measured-cheaper AND diff-test-equivalent variants replace the original.
// Chosen overrides accumulate so later bodies are measured against their (possibly
// rescheduled) callees — the comparison stays apples-to-apples per body either way.
export function recompileAllOpcost(d, arity, onProgress, K = 3) {
  const override = new Map();
  const rows = [];
  const measure = (id, cand) => {
    const a = arity[id];
    const m = cand ? new Map([...override, [id, cand]]) : new Map(override);
    let total = 0;
    for (let t = 0; t < K; t++) {
      const inp = Array.from({ length: a.in }, (_, i) => rnd(i * 23 + t * 811 + id));
      const r = m.size ? runSubroutine(d, id, inp, m) : runSubroutine(d, id, inp);
      if (r.error) return Infinity;
      total += Number(r.operationCost);
    }
    return total;
  };
  for (const id of d.order) {
    const orig = d.bodies.get(id);
    let best = null, bestCost = measure(id, null), tag = 'cashc';
    for (const strat of ['topo', 'greedy', 'opcost']) {
      let rec; try { rec = recompileBodyV2(orig, arity, arity[id].in, strat, 'opcost'); } catch { continue; }
      const cost = measure(id, rec);
      if (cost < bestCost && bodyEquiv(d, id, rec, arity)) { best = rec; bestCost = cost; tag = strat; }
    }
    if (best) { override.set(id, best); rows.push({ id, orig: orig.length, rec: best.length, tag }); }
    if (onProgress) onProgress(id, tag);
  }
  return { override, rows };
}

// Evaluate a full (locking, unlocking) pair on the loosened VM -> { accepted, operationCost }.
export function evalFull(locking, unlocking) {
  const state = looseVm.evaluate(createTestAuthenticationProgramBch({ lockingBytecode: locking, unlockingBytecode: unlocking, valueSatoshis: 1000n }));
  const top = state.stack[state.stack.length - 1];
  return {
    accepted: state.error === undefined && state.stack.length === 1 && top !== undefined && top.length === 1 && top[0] === 1,
    error: state.error, operationCost: state.metrics.operationCost,
  };
}
