// Layout (a) accept/reject sweep on the real BCH 2026 VM (standard): the valid transactions are accepted (every
// input), every tampered transaction has at least one rejecting input. Cases: the prover's tamper cases (re-encoded),
// witness manipulations, the input graph, pads, the code, and (P128) the NFT thread between the two transactions.
// usage: node test-a.mjs vectors/<SET>-0.json [vectors/<SET>-1.json (for cross-proof thread cases)]
import {loadVector, makePlan, programA, witnessesA, txsA, evaluateTx} from './layout-a.mjs';
import {gradeA} from './grade-a.mjs';
import {encodeA} from './model.mjs';
import {applyTamper} from './test-model.mjs';
import {sha, le8} from './field.mjs';
import {p2sh32} from './vm.mjs';

const [pathA, pathB] = process.argv.slice(2).filter((x) => x.endsWith('.json'));
const {v, prm, proof} = loadVector(pathA);
const st = Uint8Array.from(proof.subarray(0, 16));
const base = gradeA(prm, proof, {fast: true});
const {plan, pg, pads} = base;
let bad = 0;
const verdict = (txs, vm = 'bchStd') => txs.map((tx) => evaluateTx(tx, vm));
// t0: index of txs[0] in the full plan (thread cases pass tx1 alone), so rejections carry the real tx index
const report = (name, txs, expectOk = false, t0 = 0) => {
  const r = verdict(txs);
  const allOk = r.every((rs) => rs.every((x) => x.accepted));
  const rej = r.flatMap((rs, t) => rs.map((x, i) => [t, i, x]).filter(([, , x]) => !x.accepted)).map(([t, i, x]) => `tx${t + t0}/in${i}: ${String(x.error).slice(0, 50)}`);
  const ok = expectOk ? allOk : !allOk;
  console.log(`  ${name.padEnd(30)} ${allOk ? 'ACCEPT' : 'REJECT'} ${ok ? '' : '<-- UNEXPECTED'} ${rej.slice(0, 2).join(' | ')}${rej.length > 2 ? ` (+${rej.length - 2} inputs)` : ''}`);
  bad += !ok;
};
const commitOf = (enc) => sha(Buffer.from('pq-hash/thread'), enc.tr.G, Uint8Array.of(1));
const build = (enc, {plan: pl = plan, pg: g = pg, mutate, thread} = {}) => {
  if (pl.thread) pl.thread.commitment = thread ?? commitOf(enc);
  let wit = witnessesA(prm, pl, g, enc, pads);
  if (mutate) wit = mutate(wit);
  return txsA(prm, pl, g, wit);
};
console.log(`${pathA}: plan ${JSON.stringify(plan.txs.map((t) => t.qry))}`);
const enc = encodeA(prm, proof);
report('valid', build(enc), true);
// the prover's tamper cases, re-encoded for layout (a); statement patches run against the verifier for that statement
for (const tc of v.tampered ?? []) {
  const tp = applyTamper(proof, tc);
  let txs;
  try {
    const want = tc.want_statement ? Uint8Array.from([...le8(BigInt(tc.want_statement[0])), ...le8(BigInt(tc.want_statement[1]))]) : Uint8Array.from(tp.subarray(0, 16));
    const g = programA(prm, want, plan, {fast: true});
    txs = build(encodeA(prm, tp), {pg: g});
  } catch (err) { console.log(`  ${tc.name.padEnd(30)} REJECT (encoder: ${err.message})`); continue; }
  report(tc.name, txs);
}
// witness and graph manipulations
const flip = (b, i) => { const x = Uint8Array.from(b); x[i < 0 ? x.length + i : i] ^= 1; return x; };
const mut = (name, f, opts = {}) => report(name, build(enc, {mutate: f, ...opts}));
mut('qry_leaf_byte', (w) => { w[0][2][0] = flip(w[0][2][0], 3); return w; });
mut('qry_path_byte', (w) => { w[0][2][1] = flip(w[0][2][1], 100); return w; });
mut('qry_T_hint', (w) => { w[0][2][0] = flip(w[0][2][0], -1); return w; });
mut('qry_inputs_swapped', (w) => { [w[0][2], w[0][3]] = [w[0][3], w[0][2]]; return w; });
mut('qry_queries_swapped', (w) => { const a = w[0][2]; [a[0], a[2]] = [a[2], a[0]]; [a[1], a[3]] = [a[3], a[1]]; return w; });
mut('qry_missing_input', (w) => { w[0].splice(3, 1); return w; });
mut('qry_extra_input', (w) => { w[0].push(w[0][2]); return w; });
mut('qry_nonzero_pad', (w) => { const a = w[0][2]; a[a.length - 1] = Uint8Array.from([...a[a.length - 1], 1]); return w; });
mut('qry_extra_push', (w) => { w[0][2].unshift(new Uint8Array(1)); return w; });
mut('head_fin_byte', (w) => { w[0][0][0] = flip(w[0][0][0], 50); return w; });
mut('head_ood_byte', (w) => { w[0][0][3] = flip(w[0][0][3], 5); return w; });
mut('head_nonce_byte', (w) => { const k = pg.ptOrder.indexOf('NONCE'); w[0][0][k] = flip(w[0][0][k], 0); return w; });
mut('head_nonzero_pad', (w) => { const a = w[0][0]; a[a.length - 1] = Uint8Array.of(0, 7); return w; });
mut('code_byte', (w) => { w[0][1][0] = flip(w[0][1][0], 200); return w; });
// one input under a different locking (graph pin)
{
  const txs = build(enc);
  txs[0].sourceOutputs[3] = {...txs[0].sourceOutputs[3], lockingBytecode: p2sh32(Uint8Array.of(0x51))};
  report('foreign_locking_input', txs);
}
if (plan.thread) {
  // thread: tx1 with a commitment for another G; tx0 without the thread output; tx1 output carrying the category;
  // tx1 spliced with the PT and queries of another proof (B) but the thread NFT of proof A
  report('thread_wrong_commitment', build(enc, {thread: sha(Uint8Array.of(1, 2, 3))}).slice(1), false, 1);
  {
    const txs = build(enc);
    txs[0].transaction.outputs = txs[0].transaction.outputs.slice(0, 1);
    report('thread_tx0_missing_nft', [txs[0]]);
  }
  {
    const txs = build(enc);
    const o = txs[1].transaction.outputs[0];
    txs[1].transaction.outputs = [{...o, token: {...txs[0].transaction.outputs[1].token}}];
    report('thread_tx1_keeps_token', [txs[1]], false, 1);
  }
  if (pathB) {
    const B = loadVector(pathB);
    const encB = encodeA(B.prm, B.proof);
    const pgB = programA(prm, Uint8Array.from(B.proof.subarray(0, 16)), plan, {fast: true});
    const planB = JSON.parse(JSON.stringify(plan)); planB.thread = {category: plan.thread.category};
    const txsB = build(encB, {pg: pgB, plan: planB, thread: commitOf(enc)});   // proof B's tx1 with proof A's thread NFT
    report('thread_splice_tx1_of_B', [txsB[1]], false, 1);
  }
}
console.log(bad ? `${bad} unexpected` : 'all as expected');
process.exit(bad ? 1 : 0);
