// Layouts for the generalized generator (genn.mjs):
//   b   one P2SH32 input; redeem = function definitions + main (role 'full'); unlocking = witness + redeem
//   b2  two P2S inputs sharing one code library (DESIGN-T8 §5 b2):
//       input 0: unlocking = lib ‖ its query blobs and records ‖ PT ‖ statement items; locking = template(H_lib)
//       input 1: unlocking = its query blobs and records; locking = the loader template(H_lib), which reads lib and
//                input 0's PT/statement pushes from input 0's unlocking bytecode (OP_INPUTBYTECODE)
// Statement (stmt): pool mode {mode: 'pool', root, ctx: 'tx' | 'witness'}: ROOT a script constant, NF a witness
// item, CTX from the spending transaction's outputs (or a witness item: harness); witness mode {mode: 'witness'}:
// every public value is a witness item (PIW, u64 LE each, each < p).
import {readFileSync} from 'node:fs';
import {hash256} from '@bitauth/libauth';
import {vkxN, encodeN, le8} from './modeln.mjs';
import {buildB, buildB2} from './genn.mjs';
import {p2sh32, pushes} from './vm.mjs';

const exact = (k, x, ctx) => (typeof x === 'number' && !Number.isSafeInteger(x) ? JSON.rawJSON(ctx.source) : x);
export const readVector = (path) => JSON.parse(readFileSync(path, 'utf8'), exact);
const M64 = (1n << 64n) - 1n;
const u64s = (xs) => Buffer.concat(xs.map((x) => le8(((x % (1n << 64n)) + (1n << 64n)) & M64)));

export function stmtFor(vk, pis, {mode, ctx = 'tx'} = {}) {
  mode ??= vk.stmt;
  return mode === 'pool' ? {mode, root: pis.slice(0, 4), ctx} : {mode};
}
const stmtKey = (vk, stmt, extra) => JSON.stringify([vk.SO.batch.toString('hex'), vk.Q, vk.logArities, vk.L, vk.bpow, vk.cpow, vk.qpow, vk.lpow, vk.zk,
  vk.preCap?.toString('hex'), vk.inst.map((I) => [I.logN, I.width, I.dag.nodes.length, I.dag.constraints.length]), stmt.mode, stmt.ctx, (stmt.root ?? []).map(String), extra]);
// statement items in push order (after PT)
function stmtItems(vk, stmt, pis) {
  if (stmt.mode === 'pool') return [u64s(pis.slice(4, 8)), ...(stmt.ctx === 'witness' ? [u64s(pis.slice(8, 12))] : [])];
  return vk.nPub ? [u64s(pis)] : [];
}
const ptList = (vk, enc) => vk.ptItems.map(([k]) => enc.PT[k]);
const groups = (recs, n, RG = 2) => Array.from({length: Math.ceil(n / RG)}, (_, g) => Buffer.concat(recs.slice(g * RG, g * RG + RG)));

// ---------------- layout b ----------------
const cacheB = new Map();
export function programB(vk, stmt, opts = {}) {
  const key = stmtKey(vk, stmt, ['b', opts]);
  if (!cacheB.has(key)) { const built = buildB(vk, stmt, opts); cacheB.set(key, {built, redeem: built.redeem, locking: p2sh32(built.redeem)}); }
  return cacheB.get(key);
}
export function spendBN(vk, stmt, proof, pis, outputs, opts = {}, mutate) {
  const pg = programB(vk, stmt, opts);
  const enc = encodeN(vk, proof, pis.map((x) => ((x % (1n << 64n)) + (1n << 64n)) & M64));
  let items = [...[...enc.L].reverse(), ...enc.records[0].flatMap((recs) => groups(recs, vk.Q)), ...ptList(vk, enc), ...stmtItems(vk, stmt, pis)];
  if (mutate) items = mutate(items, enc);
  const unlocking = pushes([...items, pg.redeem]);
  const prog = {inputIndex: 0, sourceOutputs: [{lockingBytecode: pg.locking, valueSatoshis: 1_000_000n}],
    transaction: {version: 2, locktime: 0, inputs: [{outpointTransactionHash: FUND0, outpointIndex: 0, sequenceNumber: 0, unlockingBytecode: unlocking}], outputs}};
  return {...pg, enc, items, unlocking, prog};
}

// ---------------- layout b2 ----------------
const FUND0 = Uint8Array.from(Buffer.from('7438'.repeat(16), 'hex')), FUND1 = Uint8Array.from(Buffer.from('7439'.repeat(16), 'hex'));
const cacheB2 = new Map();
export function programB2(vk, stmt, QA, opts = {}) {
  const key = stmtKey(vk, stmt, ['b2', QA, opts]);
  if (!cacheB2.has(key)) {
    const built = buildB2(vk, stmt, QA, opts);
    const H = Buffer.from(hash256(built.lib));
    const locking0 = Uint8Array.from(Buffer.concat([built.T.l0.pre, H, built.T.l0.post]));
    const locking1 = Uint8Array.from(Buffer.concat([built.T.l1.pre, H, built.T.l1.post]));
    cacheB2.set(key, {built, lib: built.lib, H, locking0, locking1});
  }
  return cacheB2.get(key);
}
// mutate(items0, items1, enc) -> [items0, items1] (items0[0] is lib); txMutate(tx, sourceOutputs) for graph cases
export function spendB2(vk, stmt, QA, proof, pis, outputs, opts = {}, mutate, txMutate) {
  const pg = programB2(vk, stmt, QA, opts);
  const q0 = pg.built.q0, q1 = pg.built.q1;
  const enc = encodeN(vk, proof, pis.map((x) => ((x % (1n << 64n)) + (1n << 64n)) & M64), [q0, q1]);
  let items0 = [pg.lib, ...q0.map((q) => enc.L[q]).reverse(), ...enc.records[0].flatMap((recs) => groups(recs, q0.length)), ...ptList(vk, enc), ...stmtItems(vk, stmt, pis)];
  let items1 = [...q1.map((q) => enc.L[q]).reverse(), ...enc.records[1].flatMap((recs) => groups(recs, q1.length))];
  if (mutate) [items0, items1] = mutate(items0, items1, enc);
  const unlocking0 = pushes(items0), unlocking1 = pushes(items1);
  let sourceOutputs = [{lockingBytecode: pg.locking0, valueSatoshis: 1_000_000n}, {lockingBytecode: pg.locking1, valueSatoshis: 1_000n}];
  let tx = {version: 2, locktime: 0, inputs: [
    {outpointTransactionHash: FUND0, outpointIndex: 0, sequenceNumber: 0, unlockingBytecode: unlocking0},
    {outpointTransactionHash: FUND1, outpointIndex: 0, sequenceNumber: 0, unlockingBytecode: unlocking1}], outputs};
  if (txMutate) [tx, sourceOutputs] = txMutate(tx, sourceOutputs);
  const progs = tx.inputs.map((_, i) => ({inputIndex: i, sourceOutputs, transaction: tx}));
  return {...pg, enc, items0, items1, unlocking0, unlocking1, tx, sourceOutputs, progs};
}
export {vkxN};
