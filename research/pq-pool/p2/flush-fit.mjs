// Track 9 S0: how many Poseidon2-Gl-8 compressions fit in one flush worker input, measured on a real spend, and the
// flush op-cost table (DESIGN-T9 sec. 2) recomputed from the measurement.
//
// The worker input (shape of the a' pattern: a code blob authenticated by hash, data as pushes):
//   unlocking: <pad> <sib_n lanes> ... <sib_1 lanes> <node lanes> <code>      (pushes only; lanes as VM numbers)
//   locking (P2S, < 201 B): DUP HASH256 <H(code)> EQUALVERIFY 0 DEFINE
//                           <n> TOALTSTACK BEGIN 0 INVOKE FROMALTSTACK 1SUB DUP TOALTSTACK NOT UNTIL FROMALTSTACK DROP
//                           <root lanes 3..0> NUMEQUALVERIFY x4 DROP(pad) 1
// i.e. n chained compressions node <- T(P(sib_i || node)) with the loop and DEFINE overhead included; the pad brings
// the unlocking to exactly 10,000 B (today's standard limit), so the budget is (41 + 10,000) * 800 = 8,032,800.
//   - std: libauth (3.1.0-next.8, unpatched: OP_DEFINE bodies are not charged) BCH 2026 standard VM, whole-tx
//     verification (spendProgram + verifyTx), so the P2S output, the 10,000 B unlocking and the density budget are real;
//   - BCHN-adjusted: libauth op-cost + the OP_DEFINE body bytes (node-check: BCHN charges them as pushed bytes), which
//     must stay <= the budget.
// It also measures the same with the per-input limits raised to 100,000 B (r100 regime of Track 8).
import fs from 'fs';
import {hash256} from '@bitauth/libauth';
import {genPerm, setOptions, permRef, P} from './p2gl8.mjs';
import {asm, Stk} from './lib/asm.mjs';
import {evaluate, verifyTx, spendProgram} from './vm.mjs';

const HERE = new URL('.', import.meta.url).pathname;
setOptions({sbox: 'mid', m4: 'chain', psum: '3dup'});

// compress body: stack [.. sib0..3 node0..3] -> [.. y0..3] = T(P(sib || node))
const x = [...Array(8)].map((_, i) => `in${i}`);
const st = new Stk(x); genPerm(st, x, {out: 4});
export const CODE = st.bytes();
const H = hash256(CODE);

const lane = (seed, i) => (BigInt('0x' + Buffer.from(hash256(Uint8Array.from(Buffer.from(`${seed}/${i}`)))).toString('hex').slice(0, 16)) % P);
const compressRef = (left, right) => permRef([...left, ...right]).slice(0, 4);

export function build(n, unlockTarget) {
  const node0 = [0, 1, 2, 3].map((i) => lane('node', i));
  const sibs = [...Array(n)].map((_, k) => [0, 1, 2, 3].map((i) => lane('sib' + k, i)));
  let node = node0;
  for (let k = 0; k < n; k++) node = compressRef(sibs[k], node);
  const locking = asm('DUP', 'HASH256', H, 'EQUALVERIFY', 0, 'DEFINE',
    n, 'TOALTSTACK', 'BEGIN', 0, 'INVOKE', 'FROMALTSTACK', '1SUB', 'DUP', 'TOALTSTACK', 'NOT', 'UNTIL', 'FROMALTSTACK', 'DROP',
    node[3], 'NUMEQUALVERIFY', node[2], 'NUMEQUALVERIFY', node[1], 'NUMEQUALVERIFY', node[0], 'NUMEQUALVERIFY', 'DROP', 1);
  // pushes: pad first (deepest), then siblings from the last level down to the first, then node0, then the code
  const body = asm(...sibs.slice().reverse().flat(), ...node0, CODE);
  let padLen = Math.max(1, unlockTarget - body.length - 3);
  let unlocking;
  for (let tries = 0; tries < 8; tries++) {   // push-header size depends on the length; settle it exactly
    unlocking = asm(new Uint8Array(padLen).fill(0x55), {raw: body});
    if (unlocking.length === unlockTarget) break;
    padLen += unlockTarget - unlocking.length;
  }
  return {locking, unlocking, n};
}

export function measure(n, {unlock = 10_000, vm = 'bchStd'} = {}) {
  const b = build(n, unlock);
  const outputs = [{lockingBytecode: Uint8Array.from([0x6a]), valueSatoshis: 0n}];
  const prog = spendProgram(b.locking, b.unlocking, outputs);
  const r = evaluate(vm, b.locking, b.unlocking, prog);
  const tx = verifyTx(vm, prog);
  const budget = (41 + b.unlocking.length) * 800;
  return {n, lockingBytes: b.locking.length, unlockingBytes: b.unlocking.length, accepted: r.accepted, error: r.error ? String(r.error) : undefined,
    txVerify: tx === true ? true : String(tx), opCost: r.opCost, defineBytes: CODE.length, bchnAdjusted: r.opCost + CODE.length, budget,
    pctStd: +(100 * r.opCost / budget).toFixed(2), pctBchn: +(100 * (r.opCost + CODE.length) / budget).toFixed(2)};
}

// largest n that passes: libauth standard (whole tx) and BCHN-adjusted <= budget
function maxN(opts) {
  let lo = 1, hi = 2;
  const ok = (n) => { const m = measure(n, opts); return m.accepted && m.txVerify === true && m.bchnAdjusted <= m.budget; };
  while (ok(hi)) { lo = hi; hi *= 2; }
  while (hi - lo > 1) { const mid = (lo + hi) >> 1; if (ok(mid)) lo = mid; else hi = mid; }
  return lo;
}

if (process.argv[1] === new URL(import.meta.url).pathname) main();

function main() {
const res = {stage: 'Track 9 S0', what: 'compressions per flush worker input and the flush op-cost table', codeBytes: CODE.length};
const n10 = maxN({unlock: 10_000, vm: 'bchStd'});
res.today = {nMax: n10, atMax: measure(n10), overMax: measure(n10 + 1)};
// libauth alone (without the DEFINE adjustment) would accept n + 1? record the bare libauth limit as well
res.today.libauthAloneAcceptsOverMax = res.today.overMax.accepted;
// per-compression cost in the loop: slope between n = 4 and n = nMax
const a = measure(4), z = measure(n10);
res.perCompressionInLoop = Math.round((z.opCost - a.opCost) / (n10 - 4));
res.fixedPerInput = {libauth: Math.round(a.opCost - 4 * res.perCompressionInLoop), bchnAdjusted: Math.round(a.opCost - 4 * res.perCompressionInLoop) + CODE.length};
// raised per-input limits (100,000 B unlocking); the unlocking is 99,800 B so that the 1-input tx stays <= 100,000 B
const n100 = maxN({unlock: 99_800, vm: 'r100Std'});
res.raised100k = {nMax: n100, atMax: measure(n100, {unlock: 99_800, vm: 'r100Std'})};

// ---- flush table: perms = (2^k - 1) subtree + (30 - k) path; inputs = ceil(perms / nMax)
res.table = [0, 2, 3, 4, 5, 6].map((k) => {
  const perms = (2 ** k - 1) + (30 - k);
  const op = perms * res.perCompressionInLoop;
  const inputs = Math.ceil(perms / n10);
  return {flush: 2 ** k, k, perms, opCostCompressions: op, opCostWithFixed: op + inputs * res.fixedPerInput.bchnAdjusted,
    inputs10k: inputs, bytesInputs10k: inputs * 10_000, permsPerDeposit: +(perms / 2 ** k).toFixed(2), inputs100k: Math.ceil(perms / n100)};
});
fs.writeFileSync(HERE + 'results/s0-flush.json', JSON.stringify(res, null, 1) + '\n');
console.log(JSON.stringify(res, null, 1));
}
