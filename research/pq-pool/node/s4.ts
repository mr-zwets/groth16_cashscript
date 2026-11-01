// Track 9 S4: deposit -> flush -> prove -> withdraw end to end on a fresh stock BCHN v29.1.0 regtest node started
// with POLICY=1 (acceptnonstdtxn=0, default relay policy). Every transaction is checked with libauth (BCH 2026
// standard and consensus per input, BCHN-adjusted op-cost: + the OP_DEFINE body bytes) and with BCHN
// (testmempoolaccept before each send). Reuses S3's pieces (rig.ts, the Funder, the 2-tx withdrawal builder).
//
//   genesis   one pool category CAT = the txid of a funding output at vout 0, P2SH32(OP_1) (so the genesis input is
//             standard and the genesis transaction is policy-tested). The genesis makes exactly two mutable NFTs of
//             CAT: D (empty queue, count 0) and W (empty ring, epoch 0), and no minting NFT. R is built for this
//             pool (S4: R pins the W slot to CAT || 0x01 with prefix 0x57), W holds SHA-256(R).
//   deposits  16 per flush, each a separate transaction spending the previous D output (unconfirmed chain), one block.
//   flush     D, W and 4 worker inputs (P2S); the new root must equal the offline Poseidon2 tree over all deposits.
//   prove     the Track 8 prover with the explicit witness case (../prover, m1@INDEX@0@CTX@WIT): nk, r and the 30
//             siblings of the note in the offline tree; the vector's public values must be (root, NF, CTX).
//   withdraw  S3's 2-tx a' withdrawal, tx1 spending W's current output.
//   wrap      (with --wrap) flushes up to epoch 17: a withdrawal against root 0 is accepted at epoch 16 and another
//             (a different note) is rejected at epoch 17 (W, testmempoolaccept); that note then withdraws against
//             the newest root with a new proof.
//
//   OPCOST_DIR=<datadirs> npx tsx s4.ts --node NAME --vec <S2 vector dir> --prover BIN --cache DIR --out F.jsonl [--wrap]
import { appendFileSync, readFileSync, mkdirSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { binToHex, encodeTransaction, hash160, hexToBin, lockingBytecodeToCashAddress } from '@bitauth/libauth';
import { Chain, Rpc, txidInternal } from './rig.ts';
// @ts-ignore
import { readVector } from '../../pq-stark-batch/onchain/layoutn.mjs';
// @ts-ignore
import { vkxA } from '../../pq-stark-batch/onchain/modela.mjs';
// @ts-ignore
import { makePlanA, spendA, programA, evaluateTxA, verifyTxA } from '../r/layouta.mjs';
// @ts-ignore
import { wSpend, D, PHI, payoutsFor } from '../r/pool.mjs';
// @ts-ignore
import { ctxOf } from '../r/ctx.mjs';
// @ts-ignore
import { tokenOf } from '../w/wtx.mjs';
// @ts-ignore
import { sha256, nfBytes, keyOf } from '../w/smt.mjs';
// @ts-ignore
import { tree, treeRoot, treePath } from '../w/genesis.mjs';
// @ts-ignore
import { makePool4, DState, WState, depositTx, flushTx, noteOf, noteLanes, genesisOutputs, runTx, FUND_LOCKING, FUND_UNLOCK, WORKER_VALUE } from '../d/dpool.mjs';

const rev = (b: Uint8Array) => Uint8Array.from(b).reverse();
const hex = (b: Uint8Array) => binToHex(b);
const OP_1 = Uint8Array.of(0x51);
const J = (x: unknown) => JSON.stringify(x, (_, v) => (typeof v === 'bigint' ? String(v) : v instanceof Uint8Array ? binToHex(v) : v));

const args = process.argv.slice(2);
const opt = (k: string, d?: string) => { const i = args.indexOf(k); return i >= 0 ? args[i + 1]! : d; };
const NAME = opt('--node')!, OUT = opt('--out')!, VEC = opt('--vec')!, PROVER = opt('--prover')!, CACHE = opt('--cache')!;
const WRAP = args.includes('--wrap');
const DIR = process.env.OPCOST_DIR!;
if (!NAME || !OUT || !VEC || !DIR || !PROVER || !CACHE) throw new Error('usage: OPCOST_DIR=.. s4.ts --node NAME --vec DIR --prover BIN --cache DIR --out F.jsonl [--wrap]');
mkdirSync(`${CACHE}/vec`, { recursive: true });
const log = (ev: Record<string, unknown>) => { appendFileSync(OUT, J(ev) + '\n'); };
const say = (s: string) => console.error(s);

// ---------------------------------------------------------------- faucet (S3's Funder: thread-category tokens)
type Tok = { amount: bigint; category: Uint8Array; nft?: { capability: string; commitment: Uint8Array } };
type Out = { lockingBytecode: Uint8Array; valueSatoshis: bigint; token?: Tok };
type OP = { txid: Uint8Array; vout: number }; // txid internal order
class Funder {
  faucet!: { txid: Uint8Array; vout: number; value: bigint; token: Tok };
  constructor(public chain: Chain) {}
  category() { return txidInternal(this.chain.coinbase(1)); }
  async genesis() {
    const cat = this.category();
    const cb = this.chain.pool.find((u: any) => u.cbHeight === 1)!;
    this.chain.pool = this.chain.pool.filter((u) => u !== cb);
    const token: Tok = { amount: 0n, category: rev(cat), nft: { capability: 'minting', commitment: new Uint8Array(0) } };
    const tx = { version: 2, locktime: 0, inputs: [{ outpointTransactionHash: rev(cb.txid), outpointIndex: 0, sequenceNumber: 0xffffffff, unlockingBytecode: new Uint8Array(0) }],
      outputs: [{ lockingBytecode: OP_1, valueSatoshis: 1_000_000n, token }, { lockingBytecode: OP_1, valueSatoshis: cb.value - 1_010_000n }] };
    const raw = encodeTransaction(tx as any); const id = txidInternal(raw);
    const s = await this.chain.submit(this.chain.buildBlock([raw]));
    if (!s.accepted) throw new Error('faucet genesis rejected: ' + s.result);
    this.faucet = { txid: id, vout: 0, value: 1_000_000n, token };
    this.chain.pool.push({ txid: id, vout: 1, value: cb.value - 1_010_000n, locking: OP_1 } as any);
  }
  async fund(outs: Out[]): Promise<OP[]> {
    const needTok = outs.some((o) => o.token);
    const need = outs.reduce((s, o) => s + o.valueSatoshis, 0n) + 1_000_000n;
    const { picked, sum } = this.chain.spendable(need);
    const ins = [...(needTok ? [{ outpointTransactionHash: rev(this.faucet.txid), outpointIndex: this.faucet.vout, sequenceNumber: 0xffffffff, unlockingBytecode: new Uint8Array(0) }] : []),
      ...picked.map((u) => ({ outpointTransactionHash: rev(u.txid), outpointIndex: u.vout, sequenceNumber: 0xffffffff, unlockingBytecode: new Uint8Array(0) }))];
    const chg = sum - need + 1_000_000n - 10_000n;
    const o2 = [...outs, { lockingBytecode: OP_1, valueSatoshis: chg }, ...(needTok ? [{ lockingBytecode: OP_1, valueSatoshis: this.faucet.value, token: this.faucet.token }] : [])];
    const raw = encodeTransaction({ version: 2, locktime: 0, inputs: ins, outputs: o2 } as any); const id = txidInternal(raw);
    const s = await this.chain.submit(this.chain.buildBlock([raw]));
    if (!s.accepted) throw new Error('funding block rejected: ' + s.result);
    this.chain.pool.push({ txid: id, vout: outs.length, value: chg, locking: OP_1 } as any);
    if (needTok) this.faucet = { ...this.faucet, txid: id, vout: outs.length + 1 };
    return outs.map((_, j) => ({ txid: id, vout: j }));
  }
}

// ---------------------------------------------------------------- rpc helpers (as S3)
let chain: Chain; let f: Funder;
const rpc = async (m: string, ...p: unknown[]) => { try { return await chain.rpc.call<any>(m, ...p); } catch (e) { return { rpcError: String((e as Error).message).slice(0, 300) }; } };
const tma = async (raw: Uint8Array) => { const r = await rpc('testmempoolaccept', [hex(raw)]); return Array.isArray(r) ? r[0] : r; };
const disp = (id: Uint8Array) => hex(rev(id));
const ADDR = (() => { const a: any = lockingBytecodeToCashAddress({ bytecode: Uint8Array.of(0xa9, 0x14, ...hash160(OP_1), 0x87), prefix: 'bchreg' } as any); return typeof a === 'string' ? a : a.address; })();
const mineOne = async () => {
  const g = await rpc('generatetoaddress', 1, ADDR); await chain.init();
  const hash = Array.isArray(g) ? g[0] : undefined; const blk = hash ? await rpc('getblock', hash, 1) : undefined;
  const mp = await rpc('getrawmempool');
  return { hash, height: blk?.height, bytes: blk?.size, txids: (blk?.tx ?? []) as string[], mempoolAfter: mp };
};
const send = async (raw: Uint8Array, label: string, force = false) => {
  const t = await tma(raw);
  const s = t?.allowed === true || force ? await rpc('sendrawtransaction', hex(raw)) : undefined;
  const ok = typeof s === 'string' && s === disp(txidInternal(raw));
  return { label, txid: disp(txidInternal(raw)), bytes: raw.length, tma: t, allowed: t?.allowed === true, rejectReason: t?.['reject-reason'], sent: ok, sendResult: ok ? undefined : s };
};
const blockVerdict = async (raws: Uint8Array[]) => { await chain.init(); const blk = chain.buildBlock(raws); const r = await chain.submit(blk); return { accepted: r.accepted, result: r.result }; };
const feeOf = (tx: any) => tx.sourceOutputs.reduce((s: bigint, o: any) => s + o.valueSatoshis, 0n) - tx.transaction.outputs.reduce((s: bigint, o: any) => s + o.valueSatoshis, 0n);
const setOp = (inp: any, op: OP) => { inp.outpointTransactionHash = rev(op.txid); inp.outpointIndex = op.vout; };
const utxo = (op: OP, value: bigint) => ({ txid: rev(op.txid), vout: op.vout, value });

// ---------------------------------------------------------------- pool state (JS) and BCHN's view of it
type PoolSt = { d: any; w: any; dOp: OP; dValue: bigint; wOp: OP; wValue: bigint; notes: any[]; roots: Buffer[] };
let pool: any; let S: PoolSt; let THREAD_CAT: Uint8Array; let CAT: Uint8Array;
const checkUtxo = async (op: OP, value: bigint, commitment: Buffer, locking: Uint8Array) => {
  const o = await rpc('gettxout', disp(op.txid), op.vout, true);
  const ok = !!o && !o.rpcError && BigInt(Math.round(o.value * 1e8)) === value && o.tokenData?.category === disp(CAT) && o.tokenData?.nft?.capability === 'mutable'
    && o.tokenData?.nft?.commitment === hex(commitment) && o.scriptPubKey?.hex === hex(locking);
  return { ok, value: o?.value, commitment: o?.tokenData?.nft?.commitment?.slice(0, 20) };
};
const checkD = () => checkUtxo(S.dOp, S.dValue, S.d.commitment(), pool.Dlocking);
const checkW = () => checkUtxo(S.wOp, S.wValue, S.w.commitment(), pool.Wlocking);
// libauth for the D/W/worker transactions
const libP = (tx: any, roles: (string | null)[]) => {
  const a = runTx(tx, 'bchStd', { pool, roles }), b = runTx(tx, 'bchCons', { pool, roles });
  return { ok: a.ok && b.ok, whole: a.tx, bytes: a.bytes, maxPct: Math.max(...a.ins.map((x: any) => x.pct)), per: a.ins.map((x: any, i: number) => `${roles[i] ?? i}:${x.accepted && b.ins[i].accepted ? 'ok' : 'REJ ' + (x.error ?? b.ins[i].error)}:${x.pct}`) };
};

// ---------------------------------------------------------------- statements, R, withdrawal (S3's builder)
const counts = (vk: any) => { const p = Array.from({ length: Math.ceil(vk.Q / 3) }, (_, i) => Math.min(3, vk.Q - 3 * i)); return [p.slice(0, -1), p.slice(-1)]; };
const GEN = () => ({ nodeCategory: hex(THREAD_CAT), pool: hex(CAT) });
const stmtOf = (v: any) => {
  const vk = vkxA(v); const pis = v.public_values.flat().map(BigInt);
  const plan = { ...makePlanA(vk, counts(vk), { w: true, wCategory: Buffer.from(CAT) }), thread: { category: Buffer.from(THREAD_CAT) } };
  const pg = programA(vk, pis, plan, GEN());
  const payouts: Out[] = v.t9_payouts.map((o: any) => ({ lockingBytecode: hexToBin(o.lockingBytecode), valueSatoshis: BigInt(o.valueSatoshis) }));
  return { v, vk, pis, plan, pg, payouts, proof: Buffer.from(v.proof_hex, 'hex') };
};
const wStateForSpend = () => ({ keys: S.w.keys, slots: S.w.slots, histRoot: S.w.histRoot(), epoch: S.w.epoch, value: S.wValue, outpoint: Buffer.alloc(32), index: 0 });
const build = (v: any) => {
  const s = stmtOf(v);
  const ws = wSpend(pool, wStateForSpend(), s.pis.slice(0, 4), s.pis.slice(4, 8));
  const sp = spendA(s.vk, s.plan, s.proof, s.pis, [ws.out0, ...s.payouts], { w: ws.w, gen: GEN() });
  return { s, ws, sp, tx0: sp.txs[0], tx1: sp.txs[1], K: ws.K as bigint, defineBytes: sp.pg.defineBytes as number, wIdx: sp.pg.wIdx as number } as any;
};
const fundsOf = (b: any) => [...b.tx0.sourceOutputs, ...b.tx1.sourceOutputs.slice(1, b.wIdx)];
const finalize = (b: any, ops: OP[], w: OP) => {
  const n0 = b.tx0.sourceOutputs.length; b.f0 = ops.slice(0, n0); b.f1 = ops.slice(n0, n0 + b.wIdx - 1);
  b.tx0.transaction.inputs.forEach((inp: any, j: number) => setOp(inp, b.f0[j]));
  b.raw0 = encodeTransaction(b.tx0.transaction); b.id0 = txidInternal(b.raw0);
  const ins = b.tx1.transaction.inputs;
  setOp(ins[0], { txid: b.id0, vout: 1 });
  for (let j = 1; j < b.wIdx; j++) setOp(ins[j], b.f1[j - 1]);
  setOp(ins[b.wIdx], w);
  b.raw1 = encodeTransaction(b.tx1.transaction); b.id1 = txidInternal(b.raw1);
  return b;
};
const libR = (tx: any, b: any, final: boolean) => {
  const std = evaluateTxA(tx, 'bchStd'), cons = evaluateTxA(tx, 'bchCons');
  const whole = verifyTxA(tx, 'bchStd');
  const per = std.map((r: any, j: number) => {
    const role = final && j === b.wIdx ? 'W' : j === 0 ? 'HEAD' : j <= b.s.plan.nc ? `CODE${j}` : j === b.s.plan.nc + 1 ? 'FIN' : 'QRY';
    const def = role === 'W' ? 0 : b.defineBytes; const op = Math.max(r.opCost, cons[j].opCost) + def;
    return { role, ok: r.accepted && cons[j].accepted, err: r.error ? String(r.error).slice(0, 120) : cons[j].error ? String(cons[j].error).slice(0, 120) : undefined, pct: +(100 * op / r.budget).toFixed(2), within: op <= r.budget };
  });
  const ok = whole === true && per.every((x: any) => x.ok && x.within);
  const firstReject = per.findIndex((x: any) => !x.ok);
  return { ok, whole: whole === true ? true : String(whole).slice(0, 200), maxPct: Math.max(...per.map((x: any) => x.pct)), firstRejectRole: firstReject >= 0 ? per[firstReject].role : undefined,
    firstRejectErr: firstReject >= 0 ? per[firstReject].err : undefined, W: final ? per[b.wIdx] : undefined };
};

// ---------------------------------------------------------------- pool steps
const depositRound = async (n: number) => {
  const ops = await f.fund(Array.from({ length: n }, () => ({ lockingBytecode: FUND_LOCKING, valueSatoshis: 1_100_000n })));
  const res: any[] = []; let allOk = true;
  for (let j = 0; j < n; j++) {
    const i = S.notes.length;
    const note = { ...noteOf(noteLanes('t9s4 node nk', i), noteLanes('t9s4 node r', i)), index: i };
    const tx = depositTx(pool, { d: S.d, dUtxo: utxo(S.dOp, S.dValue), C: nfBytes(note.leaf), fund: utxo(ops[j]!, 1_100_000n) });
    const raw = encodeTransaction(tx.transaction);
    const l = libP(tx, ['D-deposit', null]);
    const r = await send(raw, `deposit${i}`);
    const ok = l.ok && r.allowed && r.sent;
    allOk &&= ok;
    if (ok) { S.d = tx.d2; S.dOp = { txid: txidInternal(raw), vout: 0 }; S.dValue = tx.transaction.outputs[0].valueSatoshis; S.notes.push(note); }
    res.push({ i, ok, bytes: raw.length, lib: l.ok, tma: r.allowed, reject: r.rejectReason, fee: feeOf(tx) });
    if (!ok) { say(`deposit ${i} FAILED: lib ${JSON.stringify(l.per)} tma ${r.rejectReason}`); break; }
  }
  const blk = await mineOne();
  const d = await checkD();
  const ok = allOk && Array.isArray(blk.mempoolAfter) && blk.mempoolAfter.length === 0 && d.ok;
  log({ ev: 'deposits', ok, n, from: S.notes.length - n, bytes: [Math.min(...res.map((x) => x.bytes)), Math.max(...res.map((x) => x.bytes))], allAllowed: res.every((x) => x.tma), block: { height: blk.height, ntx: blk.txids.length, bytes: blk.bytes }, checkD: d, failures: res.filter((x) => !x.ok) });
  say(`deposits ${S.notes.length - n}..${S.notes.length - 1}: ${ok ? 'OK' : 'FAIL'} (${res.length} tma-allowed ${res.filter((x) => x.tma).length}, block ${blk.height} ${blk.txids.length} txs, D ${d.ok})`);
  if (!ok) throw new Error('deposits failed');
};
const doFlush = async () => {
  const wk = await f.fund(Array.from({ length: 4 }, () => ({ lockingBytecode: pool.WORKER, valueSatoshis: WORKER_VALUE })));
  const tx = flushTx(pool, { d: S.d, w: S.w, dUtxo: utxo(S.dOp, S.dValue), wUtxo: utxo(S.wOp, S.wValue), workers: wk.map((o) => utxo(o, WORKER_VALUE)), keeperFee: 50_000n });
  const raw = encodeTransaction(tx.transaction);
  const l = libP(tx, ['D-flush', null, 'worker', 'worker', 'worker', 'worker']);
  const r = await send(raw, `flush${S.w.epoch}`);
  const blk = await mineOne();
  const id = txidInternal(raw);
  const inBlock = blk.txids.includes(disp(id));
  const p = tx.plan;
  const ok0 = l.ok && r.allowed && r.sent && inBlock;
  if (ok0) { S.d = p.d2; S.w = p.w2; S.dOp = { txid: id, vout: 0 }; S.dValue = tx.transaction.outputs[0].valueSatoshis; S.wOp = { txid: id, vout: 1 }; S.wValue = tx.transaction.outputs[1].valueSatoshis; S.roots.push(p.rootBytes); }
  const off = nfBytes(treeRoot(tree(S.notes.map((x: any) => x.leaf))));
  const d = await checkD(), w = await checkW();
  const ok = ok0 && off.equals(p.rootBytes) && d.ok && w.ok;
  log({ ev: 'flush', ok, epoch: S.w.epoch - 1, slot: p.slot, leaves: S.notes.length, root: p.rootBytes, rootEqualsOffline: off.equals(p.rootBytes), lib: l, bchn: r, fee: feeOf(tx), rate: Number(feeOf(tx)) / raw.length, block: { height: blk.height, inBlock }, checkD: d, checkW: w });
  say(`flush epoch ${S.w.epoch - 1}: ${ok ? 'OK' : 'FAIL'} ${raw.length} B lib ${l.ok} (max ${l.maxPct}%) tma ${r.allowed} ${r.rejectReason ?? ''} root=offline ${off.equals(p.rootBytes)} D ${d.ok} W ${w.ok}`);
  if (!ok) throw new Error('flush failed: ' + JSON.stringify(l.per));
};
// prove note `ni` against root `fi` (the tree of the first 16 (fi + 1) leaves); payout label k
const prove = (ni: number, fi: number, k: number, seed: number) => {
  const note = S.notes[ni];
  const levels = tree(S.notes.slice(0, 16 * (fi + 1)).map((x: any) => x.leaf));
  const root = treeRoot(levels);
  const sibs = treePath(levels, ni);
  const outs = payoutsFor(k), ctx = ctxOf(outs);
  const hex16 = (x: bigint) => BigInt(x).toString(16).padStart(16, '0');
  const wit = [...note.nk, ...note.r, ...sibs.flat()].map(hex16).join('');
  const file = `${CACHE}/vec/m1-t9s4-note${ni}-root${fi}.json`;
  const t0 = Date.now();
  execFileSync('nice', [PROVER, 'prove', '--case', `m1@${ni}@0@${ctx.hex}@${wit}`, '--set', 'Z128+cap=5', '--seed', String(seed), '--out', file], { env: { ...process.env, RAYON_NUM_THREADS: '4' }, stdio: ['ignore', 'ignore', 'inherit'] });
  const ms = Date.now() - t0;
  const v = readVector(file);
  const pv = v.public_values.flat().map(BigInt);
  const want = [...root, ...note.nf, ...ctx.lanes];
  const match = want.every((x: bigint, j: number) => x === pv[j]);
  v.t9_payouts = outs.map((o: any) => ({ lockingBytecode: hex(o.lockingBytecode), valueSatoshis: String(o.valueSatoshis) }));
  log({ ev: 'prove', note: ni, root: fi, ms, proofBytes: v.sizes?.total, publicValuesMatch: match });
  say(`prove note ${ni} against root ${fi}: ${ms} ms, ${v.sizes?.total} B, public values (root, NF, CTX) ${match ? 'match' : 'DIFFER'}`);
  if (!match) throw new Error('public values differ');
  return v;
};
const withdraw = async (v: any, label: string, expect: 'accept' | 'reject') => {
  const b = build(v);
  const ops = await f.fund(fundsOf(b));
  finalize(b, ops, S.wOp);
  const l0 = libR(b.tx0, b, false), l1 = libR(b.tx1, b, true);
  const r0 = await send(b.raw0, `${label}.tx0`);
  const r1 = await send(b.raw1, `${label}.tx1`, expect === 'reject');
  let blk: any, bv: any;
  if (expect === 'accept') {
    blk = await mineOne();
    const inBlock = blk.txids.includes(disp(b.id0)) && blk.txids.includes(disp(b.id1));
    const ok = l0.ok && l1.ok && r0.allowed && r0.sent && r1.allowed && r1.sent && inBlock;
    if (ok) { S.w = S.w.clone(); S.w.keys.push(b.K); S.wValue -= D; S.wOp = { txid: b.id1, vout: 0 }; }
    const w = await checkW();
    log({ ev: 'withdraw', label, expect, ok: ok && w.ok, slot: b.ws.slot, lib0: l0, lib1: l1, bchn0: r0, bchn1: r1, bytes: [b.raw0.length, b.raw1.length], block: { height: blk.height, inBlock }, checkW: w });
    say(`withdraw ${label}: ${ok && w.ok ? 'OK' : 'FAIL'} ${b.raw0.length}+${b.raw1.length} B lib ${l0.ok}/${l1.ok} (max ${Math.max(l0.maxPct, l1.maxPct)}%, W ${l1.W?.pct}%) tma ${r0.allowed}/${r1.allowed} ${r1.rejectReason ?? ''} W ${w.ok}`);
    return ok && w.ok;
  }
  blk = await mineOne();   // tx0 is valid (it does not touch W): mined; tx1 must stay out
  bv = await blockVerdict([b.raw1]);
  const w = await checkW();
  const rejected = l0.ok && r0.sent && !l1.ok && l1.firstRejectRole === 'W' && !r1.allowed && !r1.sent && !bv.accepted && !blk.txids.includes(disp(b.id1)) && w.ok;
  log({ ev: 'withdraw', label, expect, ok: rejected, slot: b.ws.slot, lib0: l0, lib1: l1, bchn0: r0, bchn1: r1, blockVerdict: bv, checkWUnchanged: w });
  say(`withdraw ${label}: ${rejected ? 'REJECTED as expected' : 'UNEXPECTED'} lib ${l1.firstRejectRole}: ${l1.firstRejectErr} | tma ${r1.rejectReason} | block ${bv.result}`);
  return rejected;
};

// ---------------------------------------------------------------- main
const main = async () => {
  const c = +execFileSync('sh', ['-c', `printf '%s' '${NAME}' | cksum | cut -d' ' -f1`]).toString().trim();
  const datadir = `${DIR}/bchn-${NAME}`;
  chain = new Chain(new Rpc(datadir, 39300 + (c % 500) * 2), `${datadir}/regtest/debug.log`);
  await chain.init(); if (chain.height !== 0) throw new Error('fresh node expected');
  const net = await rpc('getnetworkinfo');
  const conf = readFileSync(`${datadir}/bitcoin.conf`, 'utf8');
  if (!/acceptnonstdtxn=0/.test(conf)) throw new Error('POLICY=1 node expected');
  await chain.mine(220);
  f = new Funder(chain); await f.genesis();
  THREAD_CAT = f.category();
  // the pool category: a P2SH32(OP_1) funding output at vout 0
  const [catOp] = await f.fund([{ lockingBytecode: FUND_LOCKING, valueSatoshis: 5_000_000n }]);
  CAT = catOp!.txid;
  const v0 = readVector(`${VEC}/m1-t9-0-Z128_cap5.json`);
  const s0 = stmtOf(v0);
  const R = s0.pg.redeem as Uint8Array, nIn = s0.pg.inCount[s0.pg.inCount.length - 1], wIdx = s0.pg.wIdx;
  pool = makePool4({ CAT: Buffer.from(CAT), R, nIn, wIdx });
  // genesis: D and W, no minting NFT
  const gOuts = genesisOutputs(pool);
  const gtx = { version: 2, locktime: 0, inputs: [{ outpointTransactionHash: rev(catOp!.txid), outpointIndex: 0, sequenceNumber: 0, unlockingBytecode: FUND_UNLOCK }],
    outputs: [...gOuts, { lockingBytecode: FUND_LOCKING, valueSatoshis: 5_000_000n - 200_000n - 5_000n }] };
  const graw = encodeTransaction(gtx as any);
  const gl = runTx({ transaction: gtx, sourceOutputs: [{ lockingBytecode: FUND_LOCKING, valueSatoshis: 5_000_000n }] }, 'bchStd');
  const gs = await send(graw, 'genesis');
  const gblk = await mineOne();
  const gid = txidInternal(graw);
  S = { d: new DState(), w: new WState(), dOp: { txid: gid, vout: 0 }, dValue: 100_000n, wOp: { txid: gid, vout: 1 }, wValue: 100_000n, notes: [], roots: [] };
  const dec = await rpc('getrawtransaction', disp(gid), true);
  const catOuts = (dec?.vout ?? []).filter((o: any) => o.tokenData?.category === disp(CAT));
  const d0 = await checkD(), w0 = await checkW();
  const gOk = gl.ok && gs.allowed && gs.sent && gblk.txids.includes(disp(gid)) && catOuts.length === 2 && catOuts.every((o: any) => o.tokenData?.nft?.capability === 'mutable') && d0.ok && w0.ok;
  log({ ev: 'setup', node: NAME, subversion: net?.subversion, threadCategory: disp(THREAD_CAT), poolCategory: disp(CAT), R: hex(R), Rbytes: R.length, Rsha256: hex(sha256(R)), nIn, wIdx,
    Dredeem: pool.Dredeem.length, Wredeem: pool.Wredeem.length, flushBlob: pool.fblob.length, workerBlob: pool.wblob.length, worker: hex(pool.WORKER), D, PHI, FEE: pool.FEE });
  log({ ev: 'genesis', ok: gOk, txid: disp(gid), bytes: graw.length, lib: gl.ok, bchn: gs, tokenOutputsOfCategory: catOuts.map((o: any) => ({ n: o.n, capability: o.tokenData?.nft?.capability, commitment: o.tokenData?.nft?.commitment?.slice(0, 2) })),
    noMintingNft: catOuts.length === 2 && catOuts.every((o: any) => o.tokenData?.nft?.capability === 'mutable'), checkD: d0, checkW: w0 });
  say(`node ${net?.subversion}; pool ${disp(CAT)}; R ${R.length} B sha256 ${hex(sha256(R)).slice(0, 16)}; genesis ${gOk ? 'OK' : 'FAIL'} tma ${gs.allowed} ${gs.rejectReason ?? ''}`);
  if (!gOk) throw new Error('genesis failed');

  // ===== deposit -> flush (x2) -> prove -> withdraw
  await depositRound(16); await doFlush();
  await depositRound(16); await doFlush();
  const va = prove(3, 0, 1003, 4103), vb = prove(20, 1, 1020, 4120);
  const okA = await withdraw(va, 'note3@root0', 'accept');
  const okB = await withdraw(vb, 'note20@root1', 'accept');
  log({ ev: 'e2e-summary', ok: okA && okB, flushes: S.roots.length, deposits: S.notes.length, withdrawn: S.w.keys.length, Dvalue: S.dValue, Wvalue: S.wValue });

  // ===== wrap: root 0 expires at the flush with epoch counter 16
  if (WRAP) {
    const v5 = prove(5, 0, 1005, 4105), v9 = prove(9, 0, 1009, 4109);
    while (S.w.epoch < 16) { await depositRound(16); await doFlush(); }
    const before = await withdraw(v5, 'note5@root0, epoch 16', 'accept');
    await depositRound(16); await doFlush();
    const slot0 = S.w.slots[0].equals(S.roots[16]!);
    const after = await withdraw(v9, 'note9@root0, epoch 17 (slot 0 overwritten)', 'reject');
    const v9n = prove(9, 16, 1009, 4209);
    const fresh = await withdraw(v9n, 'note9@root16 (new proof)', 'accept');
    log({ ev: 'wrap-summary', ok: before && slot0 && after && fresh, before, slot0IsRoot16: slot0, staleRejected: after, freshAccepted: fresh, flushes: S.roots.length, deposits: S.notes.length });
  }
  log({ ev: 'end', height: chain.height, flushes: S.roots.length, deposits: S.notes.length, withdrawn: S.w.keys.length, Dvalue: S.dValue, Wvalue: S.wValue });
};
main().catch((e) => { console.error(e); log({ ev: 'error', error: String((e as Error).stack ?? e) }); process.exit(1); });
