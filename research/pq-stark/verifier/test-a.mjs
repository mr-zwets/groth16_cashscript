// Layout (a) accept/reject sweep on the real BCH 2026 VM (standard): the valid transactions are accepted (every
// input), every tampered transaction has at least one rejecting input. Cases: the prover's tamper cases (re-encoded),
// witness manipulations, the input graph, pads, the code, and (two transactions) the NFT thread.
// usage: node test-a.mjs vectors/<A>-0.json [vectors/<A>-1.json (cross-proof thread splice)]
import {loadVector, programA, witnessesA, txsA, evaluateTx, encodeA} from './layout-a.mjs';
import {gradeA} from './grade-a.mjs';
import {casesOf} from './layout-b.mjs';
import {threadCommit} from './gen-a.mjs';
import {p2sh32} from './vm.mjs';
import {sha, Reject} from './model.mjs';

const [pathA, pathB] = process.argv.slice(2).filter((x) => x.endsWith('.json'));
const {v, vk, proof, pis} = loadVector(pathA);
const base = gradeA(vk, proof, pis);
const {plan, pg, pads} = base;
const nc = pg.nc, q0 = nc + 1;   // first QRY input index
let bad = 0, total = 0;
// malformed: the layout (a) encoder flags a byte string that is not a well-formed p3s-v1 proof (production encoders
// refuse it); counted as an encoder-only rejection when the script itself accepts the re-encoded witness
let encoderOnly = 0;
const report = (name, txs, expectOk = false, t0 = 0, malformed = null) => {
  const r = txs.map((tx) => evaluateTx(tx, 'bchStd'));
  const allOk = r.every((rs) => rs.every((x) => x.accepted));
  const rej = r.flatMap((rs, t) => rs.map((x, i) => [t, i, x]).filter(([, , x]) => !x.accepted)).map(([t, i, x]) => `tx${t + t0}/in${i}: ${String(x.error).slice(0, 50)}`);
  const encRej = !expectOk && allOk && malformed;
  const ok = expectOk ? allOk : (!allOk || encRej);
  total++; bad += !ok; encoderOnly += !!encRej;
  console.log(`  ${name.padEnd(44)} ${allOk ? (encRej ? 'REJECT (encoder only: ' + malformed + '; the script accepts the re-encoded witness)' : 'ACCEPT') : 'REJECT'} ${ok ? '' : '<-- UNEXPECTED'} ${rej.slice(0, 2).join(' | ')}${rej.length > 2 ? ` (+${rej.length - 2} inputs)` : ''}`);
};
const build = (enc, {pg: g = pg, mutate, G} = {}) => {
  let wit = witnessesA(vk, plan, g, enc, pads);
  if (mutate) wit = mutate(wit);
  return txsA(vk, plan, g, wit, G ?? enc.G);
};
console.log(`${pathA}: plan ${JSON.stringify(plan.txs.map((t) => t.qry))}, code blobs ${nc}`);
const enc = encodeA(vk, proof, pis);
report('valid', build(enc), true);
for (const c of casesOf(v).slice(1)) {
  const g = programA(vk, c.pis, plan, {codeBlobs: nc});
  const e = encodeA(vk, c.proof, c.pis);
  report(c.name, build(e, {pg: g}), false, 0, e.malformed);
}
const flip = (b, i) => { const x = Buffer.from(b); x[i < 0 ? x.length + i : i] ^= 1; return x; };
const mut = (name, f) => report(name, build(enc, {mutate: f}));
const Q0 = (w) => w[0][q0];
mut('qry: L byte (row)', (w) => { Q0(w)[0] = flip(Q0(w)[0], 3); return w; });
mut('qry: L byte (FRI sibling value)', (w) => { Q0(w)[0] = flip(Q0(w)[0], vk.batchBytes.reduce((a, x) => a + x, 0) + 2); return w; });
mut('qry: path byte (input tree)', (w) => { Q0(w)[1] = flip(Q0(w)[1], 100); return w; });
mut('qry: path byte (last FRI tree)', (w) => { Q0(w)[1] = flip(Q0(w)[1], -5); return w; });
mut('qry: hint T', (w) => { Q0(w)[0] = flip(Q0(w)[0], -1); return w; });
mut('qry: two QRY inputs swapped', (w) => { [w[0][q0], w[0][q0 + 1]] = [w[0][q0 + 1], w[0][q0]]; return w; });
if (plan.txs[0].qry[0][1] - plan.txs[0].qry[0][0] > 1) mut('qry: queries swapped inside an input', (w) => { const a = Q0(w); [a[0], a[2]] = [a[2], a[0]]; [a[1], a[3]] = [a[3], a[1]]; return w; });
mut('qry: L and path swapped', (w) => { const a = Q0(w); [a[0], a[1]] = [a[1], a[0]]; return w; });
mut('qry: input missing', (w) => { w[0].splice(q0 + 1, 1); return w; });
mut('qry: extra input', (w) => { w[0].push(w[0][q0]); return w; });
mut('qry: non-zero pad', (w) => { const a = Q0(w); a[a.length - 1] = Buffer.from([...a[a.length - 1], 1]); return w; });
mut('qry: extra push', (w) => { Q0(w).unshift(Buffer.alloc(1)); return w; });
mut('head: FIN byte', (w) => { const k = pg.ptOrder.indexOf('FIN'); w[0][0][k] = flip(w[0][0][k], 50); return w; });
mut('head: OOD byte', (w) => { const k = pg.ptOrder.indexOf('OOD'); w[0][0][k] = flip(w[0][0][k], 5); return w; });
mut('head: degree_bits byte', (w) => { const k = pg.ptOrder.indexOf('ROOTS'); w[0][0][k] = flip(w[0][0][k], 0); return w; });
if (vk.qpow) mut('head: query PoW byte', (w) => { const k = pg.ptOrder.indexOf('QPOW'); w[0][0][k] = flip(w[0][0][k], 0); return w; });
mut('head: non-zero pad', (w) => { const a = w[0][0]; a[a.length - 1] = Buffer.from([0, 7]); return w; });
mut('code: byte', (w) => { w[0][1][0] = flip(w[0][1][0], 200); return w; });
{
  const txs = build(enc);
  txs[0].sourceOutputs[q0] = {...txs[0].sourceOutputs[q0], lockingBytecode: p2sh32(Uint8Array.of(0x51))};
  report('graph: one input under a foreign locking', txs);
}
if (plan.thread) {
  const other = sha(Buffer.from('another proof'));
  report('thread: tx1 NFT committed to another G', build(enc, {G: other}).slice(1), false, 1);
  {
    const txs = build(enc);
    txs[0].transaction.outputs = txs[0].transaction.outputs.slice(0, 1);
    report('thread: tx0 without the thread NFT', [txs[0]]);
  }
  {
    const txs = build(enc);
    const o = txs[1].transaction.outputs[0];
    txs[1].transaction.outputs = [{...o, token: {...txs[0].transaction.outputs[1].token}}];
    report('thread: tx1 keeps the token', [txs[1]], false, 1);
  }
  {
    // tx1 holding the NFT minted for transaction 2 (wrong k) when there are more than two, else commitment k = 2
    const txs = build(enc);
    const so = txs[1].sourceOutputs[0];
    txs[1].sourceOutputs[0] = {...so, token: {...so.token, nft: {...so.token.nft, commitment: threadCommit(enc.G, 2)}}};
    report('thread: tx1 holds the NFT of another k', [txs[1]], false, 1);
  }
  if (pathB) {
    // tx1 of proof B (its own HEAD/QRY data) carrying the thread NFT of proof A
    const B = loadVector(pathB);
    const encB = encodeA(B.vk, B.proof, B.pis);
    const pgB = programA(vk, B.pis, plan, {codeBlobs: nc});
    const witB = witnessesA(vk, plan, pgB, encB, pads);
    const txsB = txsA(vk, plan, pgB, witB, encB.G);
    const so = txsB[1].sourceOutputs[0];
    txsB[1].sourceOutputs = txsB[1].sourceOutputs.map((x, i) => (i === 0 ? {...so, token: {...so.token, nft: {...so.token.nft, commitment: threadCommit(enc.G, 1)}}} : x));
    report('thread: tx1 of proof B with the NFT of proof A', [txsB[1]], false, 1);
  }
}
console.log(`test-a ${pathA.split('/').pop()}: ${total} cases, ${bad} unexpected, ${encoderOnly} rejected by the encoder only`);
process.exit(bad ? 1 : 0);
