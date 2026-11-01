// Track 9 S3: the pool's 2-transaction withdrawal (a' tx0 + tx1 with the W state) on a fresh stock BCHN v29.1.0
// regtest node started with POLICY=1 (acceptnonstdtxn=0, default relay policy). Reuses bench research/node-check:
// node.sh and Track 1's rig.ts are copied here unchanged (bench main 1d00508); the faucet (Funder) is nc.ts's,
// adapted. Every transaction below is checked with libauth (BCH 2026 standard and consensus, per input, the R
// inputs BCHN-adjusted by the OP_DEFINE body bytes) and with BCHN (testmempoolaccept before each send).
//
//   genesis   W categories are real token geneses: a mature coinbase (vout 0) is spent into one mutable NFT of
//             category = that coinbase's txid, at W's P2SH32 locking, with the genesis commitment. No minting NFT
//             of that category is ever created (the "burned baton"). The thread category (R's code constant) is
//             the node faucet's (nc.ts), as in Track 8's node check.
//   seq       pool A: statements 0..23, one at a time: tx0, tx1 sent (tx1 with tx0 unconfirmed), mined in one block.
//   replay    pool A, after seq: statement 0 again (NF present). A fresh tx0 is accepted and mined; its tx1 is
//             rejected (libauth: W input; BCHN: testmempoolaccept, sendrawtransaction, and a block holding it),
//             with (a) the honest witness for the current state (a membership path) and (b) a stale witness
//             (the absence path from the genesis state).
//   chain10   pool B (second genesis): statements 0..9; all 20 txs sent unconfirmed, tx1_k spends tx1_{k-1}'s
//             output 0; then one block (BCHN's assembler) must hold all 20.
//   race      pool B: statements 10 (X) and 11 (Y) both build tx1 on the same W outpoint. X wins; Y's tx1 is a
//             mempool conflict; Y rebuilds tx1 on X's (unconfirmed) output 0 with the same proof and the same R
//             unlockings (byte-identical inputs 0..4) and is accepted; one block holds all 4.
//   conflict  pool B: statement 12 relayed twice (two tx0 threads, same proof, same NF) on one W outpoint: the
//             second tx1 is a mempool conflict; rebuilt on the first's unconfirmed output 0 it is rejected by
//             W (NF present) in libauth and BCHN.
//
//   OPCOST_DIR=<datadirs> npx tsx s3.ts --node NAME --vec <dir of m1-t9-<i>-Z128_cap5.json> --out results/s3.jsonl
import { appendFileSync, readFileSync } from 'node:fs';
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
import { genesisState, wSpend, commitmentOf, D, PHI } from '../r/pool.mjs';
// @ts-ignore
import { makePool, tokenOf } from '../w/wtx.mjs';
// @ts-ignore
import { sha256 } from '../w/smt.mjs';

const rev = (b: Uint8Array) => Uint8Array.from(b).reverse();
const hex = (b: Uint8Array) => binToHex(b);
const OP_1 = Uint8Array.of(0x51);
const J = (x: unknown) => JSON.stringify(x, (_, v) => (typeof v === 'bigint' ? String(v) : v instanceof Uint8Array ? binToHex(v) : v));

// ---------------------------------------------------------------- args, node
const args = process.argv.slice(2);
const opt = (k: string, d?: string) => { const i = args.indexOf(k); return i >= 0 ? args[i + 1]! : d; };
const NAME = opt('--node')!, OUT = opt('--out')!, VEC = opt('--vec')!;
const DIR = process.env.OPCOST_DIR!;
if (!NAME || !OUT || !VEC || !DIR) throw new Error('usage: OPCOST_DIR=.. s3.ts --node NAME --vec DIR --out F.jsonl');
const log = (ev: Record<string, unknown>) => { appendFileSync(OUT, J(ev) + '\n'); };
const say = (s: string) => console.error(s);

// ---------------------------------------------------------------- faucet (nc.ts Funder, adapted: thread-category tokens)
type Tok = { amount: bigint; category: Uint8Array; nft?: { capability: string; commitment: Uint8Array } };
type Out = { lockingBytecode: Uint8Array; valueSatoshis: bigint; token?: Tok };
type OP = { txid: Uint8Array; vout: number }; // txid internal order
const CAT_HEIGHT = 1;
class Funder {
  faucet!: { txid: Uint8Array; vout: number; value: bigint; token: Tok };
  constructor(public chain: Chain) {}
  category() { return txidInternal(this.chain.coinbase(CAT_HEIGHT)); }
  async genesis() {
    const cat = this.category();
    const cb = this.chain.pool.find((u: any) => u.cbHeight === CAT_HEIGHT)!;
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
  /** fund outputs in one mined block (submitblock; funding txs are not policy-tested, as in nc.ts) */
  async fund(outs: Out[]): Promise<OP[]> {
    const needTok = outs.some((o) => o.token);
    for (const o of outs) if (o.token && hex(o.token.category) !== hex(this.faucet.token.category)) throw new Error('token of a foreign category');
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

// ---------------------------------------------------------------- statements, R, W
const vecs = Array.from({ length: 24 }, (_, i) => readVector(`${VEC}/m1-t9-${i}-Z128_cap5.json`));
const counts = (vk: any) => { const p = Array.from({ length: Math.ceil(vk.Q / 3) }, (_, i) => Math.min(3, vk.Q - 3 * i)); return [p.slice(0, -1), p.slice(-1)]; };
let THREAD_CAT: Uint8Array; // internal order
const GEN = () => ({ nodeCategory: hex(THREAD_CAT) }); // keys programA's cache (it does not key on the category)
const stmt = (i: number) => {
  const v = vecs[i]; const vk = vkxA(v); const pis = v.public_values.flat().map(BigInt);
  const plan = { ...makePlanA(vk, counts(vk), { w: true }), thread: { category: Buffer.from(THREAD_CAT) } };
  const pg = programA(vk, pis, plan, GEN());
  const payouts: Out[] = v.t9_payouts.map((o: any) => ({ lockingBytecode: hexToBin(o.lockingBytecode), valueSatoshis: BigInt(o.valueSatoshis) }));
  return { v, vk, pis, plan, pg, payouts, proof: Buffer.from(v.proof_hex, 'hex') };
};

type St = { keys: bigint[]; slots: any; histRoot: any; epoch: any; value: bigint; outpoint: Buffer; index: number; txid: Uint8Array /* internal */ };
type Pool = { name: string; pool: any; cat: Uint8Array; st: St; genesisTxid: string };

// one withdrawal attempt: libauth tx objects (outpoints assigned later). stale: build W's witness from these keys.
const build = (i: number, P: Pool, st: St, o: { staleKeys?: bigint[] } = {}) => {
  const s = stmt(i);
  const root = s.pis.slice(0, 4), nf = s.pis.slice(4, 8);
  const ws = wSpend(P.pool, o.staleKeys ? { ...st, keys: o.staleKeys } : st, root, nf);
  // the W input's source is always the real current W output
  ws.w.value = st.value; ws.w.token = tokenOf(P.cat, commitmentOf(st));
  ws.out0.valueSatoshis = st.value - D;
  const sp = spendA(s.vk, s.plan, s.proof, s.pis, [ws.out0, ...s.payouts], { w: ws.w, gen: GEN() });
  if (sp.txs.length !== 2) throw new Error('2-tx plan expected');
  return { i, s, ws, sp, tx0: sp.txs[0], tx1: sp.txs[1], K: ws.K as bigint, defineBytes: sp.pg.defineBytes as number, wIdx: sp.pg.wIdx as number };
};
type B = ReturnType<typeof build> & { f0?: OP[]; f1?: OP[]; raw0?: Uint8Array; raw1?: Uint8Array; id0?: Uint8Array; id1?: Uint8Array };

const fundsOf = (b: B) => [...b.tx0.sourceOutputs, ...b.tx1.sourceOutputs.slice(1, b.wIdx)];
const assignFunds = (bs: B[], ops: OP[]) => { let k = 0; for (const b of bs) { const n0 = b.tx0.sourceOutputs.length; b.f0 = ops.slice(k, k + n0); k += n0; b.f1 = ops.slice(k, k + b.wIdx - 1); k += b.wIdx - 1; } };
const setOp = (inp: any, op: OP) => { inp.outpointTransactionHash = rev(op.txid); inp.outpointIndex = op.vout; };
// tx0 from its funds; tx1: input 0 = tx0:1 (the thread NFT), 1..wIdx-1 funds, wIdx = W's current outpoint
const finalize = (b: B, w: OP) => {
  b.tx0.transaction.inputs.forEach((inp: any, j: number) => setOp(inp, b.f0![j]!));
  b.raw0 = encodeTransaction(b.tx0.transaction); b.id0 = txidInternal(b.raw0);
  const ins = b.tx1.transaction.inputs;
  setOp(ins[0], { txid: b.id0, vout: 1 });
  for (let j = 1; j < b.wIdx; j++) setOp(ins[j], b.f1![j - 1]!);
  setOp(ins[b.wIdx], w);
  b.raw1 = encodeTransaction(b.tx1.transaction); b.id1 = txidInternal(b.raw1);
  return b;
};
const fundBatch = async (f: Funder, bs: B[]) => assignFunds(bs, await f.fund(bs.flatMap(fundsOf)));

// libauth: every input on BCH 2026 standard and consensus, the whole tx (standard); R inputs + DEFINE bytes
const lib = (tx: any, b: B, final: boolean) => {
  const std = evaluateTxA(tx, 'bchStd'), cons = evaluateTxA(tx, 'bchCons');
  const whole = verifyTxA(tx, 'bchStd');
  const per = std.map((r: any, j: number) => {
    const role = final && j === b.wIdx ? 'W' : j === 0 ? 'HEAD' : j <= b.s.plan.nc ? `CODE${j}` : j === b.s.plan.nc + 1 ? 'FIN' : 'QRY';
    const def = role === 'W' ? 0 : b.defineBytes; const op = Math.max(r.opCost, cons[j].opCost) + def;
    return { role, std: r.accepted, cons: cons[j].accepted, err: r.error ? String(r.error).slice(0, 160) : cons[j].error ? String(cons[j].error).slice(0, 160) : undefined,
      unlocking: r.unlocking, opBchnAdj: op, budget: r.budget, pct: +(100 * op / r.budget).toFixed(2), within: op <= r.budget };
  });
  const ok = whole === true && per.every((x: any) => x.std && x.cons && x.within);
  const firstReject = per.findIndex((x: any) => !(x.std && x.cons));
  return { ok, whole: whole === true ? true : String(whole).slice(0, 200), maxPct: Math.max(...per.map((x: any) => x.pct)), firstReject, firstRejectRole: firstReject >= 0 ? per[firstReject].role : undefined,
    firstRejectErr: firstReject >= 0 ? per[firstReject].err : undefined, W: final ? per[b.wIdx] : undefined, per: per.map((x: any) => `${x.role}:${x.std && x.cons ? 'ok' : 'REJ'}:${x.pct}`) };
};

// ---------------------------------------------------------------- rpc helpers
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
// send = testmempoolaccept, then sendrawtransaction (only if allowed, unless force)
const send = async (raw: Uint8Array, label: string, force = false) => {
  const t = await tma(raw);
  const s = t?.allowed === true || force ? await rpc('sendrawtransaction', hex(raw)) : undefined;
  const ok = typeof s === 'string' && s === disp(txidInternal(raw));
  return { label, txid: disp(txidInternal(raw)), bytes: raw.length, tma: t, allowed: t?.allowed === true, rejectReason: t?.['reject-reason'], sent: ok, sendResult: ok ? undefined : s };
};
// a block holding exactly these txs, built by the rig and submitted (the BCHN block verdict of a rejected tx)
const blockVerdict = async (raws: Uint8Array[]) => { await chain.init(); const blk = chain.buildBlock(raws); const r = await chain.submit(blk); return { accepted: r.accepted, result: r.result }; };
const feeOf = (tx: any) => tx.sourceOutputs.reduce((s: bigint, o: any) => s + o.valueSatoshis, 0n) - tx.transaction.outputs.reduce((s: bigint, o: any) => s + o.valueSatoshis, 0n);
// BCHN's view of W's current output (mempool included) against the JS state
const checkW = async (P: Pool) => {
  const o = await rpc('gettxout', disp(P.st.txid), P.st.index, true);
  const want = hex(commitmentOf(P.st));
  const ok = !!o && !o.rpcError && BigInt(Math.round(o.value * 1e8)) === P.st.value && o.tokenData?.category === disp(P.cat) && o.tokenData?.nft?.capability === 'mutable' && o.tokenData?.nft?.commitment === want
    && o.scriptPubKey?.hex === hex(P.pool.locking);
  return { ok, gettxout: o?.rpcError ? o : { value: o?.value, confirmations: o?.confirmations, tokenData: o?.tokenData, script: o?.scriptPubKey?.hex?.slice(0, 16) }, wantCommitment: want };
};
const advance = (P: Pool, b: B) => { P.st = { ...P.st, keys: [...P.st.keys, b.K], value: P.st.value - D, txid: b.id1!, outpoint: Buffer.from(b.id1!), index: 0 }; };

// W genesis: spend a mature coinbase (vout 0) into one mutable NFT of category = its txid; no minting NFT
const wGenesis = async (name: string, R: Uint8Array, nIn: number, wIdx: number, value: bigint): Promise<Pool> => {
  await chain.init();
  const nextH = chain.height + 1;
  const cb = chain.pool.find((u: any) => u.cbHeight !== undefined && u.vout === 0 && nextH - u.cbHeight >= 100 && u.value > value + 1_000_000n)!;
  chain.pool = chain.pool.filter((u) => u !== cb);
  const cat = cb.txid; // internal order
  const pool = makePool({ R, CAT: Buffer.from(cat), nIn, wIdx });
  const st0: St = { ...genesisState(value), txid: new Uint8Array(32), index: 0 } as any;
  const out0 = { lockingBytecode: pool.locking, valueSatoshis: value, token: tokenOf(Buffer.from(cat), commitmentOf(st0)) };
  const tx = { version: 2, locktime: 0, inputs: [{ outpointTransactionHash: rev(cb.txid), outpointIndex: 0, sequenceNumber: 0xffffffff, unlockingBytecode: new Uint8Array(0) }],
    outputs: [out0, { lockingBytecode: OP_1, valueSatoshis: cb.value - value - 10_000n }] };
  const raw = encodeTransaction(tx as any); const id = txidInternal(raw);
  const s = await chain.submit(chain.buildBlock([raw]));
  if (!s.accepted) throw new Error('W genesis rejected: ' + s.result);
  chain.pool.push({ txid: id, vout: 1, value: cb.value - value - 10_000n, locking: OP_1 } as any);
  const P: Pool = { name, pool, cat, st: { ...st0, txid: id, outpoint: Buffer.from(id), index: 0 }, genesisTxid: disp(id) };
  // the genesis tx as BCHN decoded it: exactly one output of category cat, capability mutable
  const dec = await rpc('getrawtransaction', disp(id), true);
  const catOuts = (dec?.vout ?? []).filter((o: any) => o.tokenData?.category === disp(cat));
  const w = await checkW(P);
  log({ ev: 'w-genesis', pool: name, txid: disp(id), category: disp(cat), Wredeem: pool.redeem.length, Wlocking: hex(pool.locking), HR: hex(pool.HR), value,
    tokenOutputsOfCategory: catOuts.map((o: any) => ({ n: o.n, capability: o.tokenData?.nft?.capability })), noMintingNft: catOuts.length === 1 && catOuts[0].tokenData?.nft?.capability === 'mutable', checkW: w });
  if (!w.ok || catOuts.length !== 1) throw new Error('W genesis check failed');
  say(`W genesis ${name}: ${disp(id)} category ${disp(cat)}`);
  return P;
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
  const s0 = stmt(0);
  const R = s0.pg.redeem as Uint8Array, nIn = s0.pg.inCount[s0.pg.inCount.length - 1], wIdx = s0.pg.wIdx;
  log({ ev: 'setup', node: NAME, subversion: net?.subversion, acceptnonstdtxn: 0, threadCategory: disp(THREAD_CAT), R: hex(R), Rbytes: R.length, Rsha256: hex(sha256(R)), nIn, wIdx, defineBytes: s0.pg.defineBytes, D, PHI });
  say(`node ${net?.subversion}; R ${R.length} B sha256 ${hex(sha256(R)).slice(0, 16)}; thread category ${disp(THREAD_CAT)}`);
  const samePg = (b: B) => { if (hex(b.s.pg.redeem) !== hex(R)) throw new Error(`statement ${b.i}: R differs`); };

  // ================= seq: pool A, statements 0..23
  const A = await wGenesis('A', R, nIn, wIdx, 30n * D);
  let seqOk = 0;
  for (let i = 0; i < 24; i++) {
    const b: B = build(i, A, A.st); samePg(b);
    await fundBatch(f, [b]); finalize(b, { txid: A.st.txid, vout: A.st.index });
    const l0 = lib(b.tx0, b, false), l1 = lib(b.tx1, b, true);
    const r0 = await send(b.raw0!, `seq${i}.tx0`), r1 = await send(b.raw1!, `seq${i}.tx1`);
    const blk = await mineOne();
    const inBlock = blk.txids.includes(disp(b.id0!)) && blk.txids.includes(disp(b.id1!));
    const ok = l0.ok && l1.ok && r0.allowed && r0.sent && r1.allowed && r1.sent && inBlock && Array.isArray(blk.mempoolAfter) && blk.mempoolAfter.length === 0;
    if (ok) advance(A, b);
    const w = await checkW(A);
    if (ok && w.ok) seqOk++;
    log({ ev: 'seq', i, ok: ok && w.ok, slot: b.ws.slot, lib0: l0, lib1: l1, bchn0: r0, bchn1: r1, fee0: feeOf(b.tx0), fee1: feeOf(b.tx1),
      rate0: Number(feeOf(b.tx0)) / b.raw0!.length, rate1: Number(feeOf(b.tx1)) / b.raw1!.length, block: { height: blk.height, bytes: blk.bytes, ntx: blk.txids.length, inBlock }, checkW: w });
    say(`seq ${i}: ${ok && w.ok ? 'OK' : 'FAIL'} ${b.raw0!.length}+${b.raw1!.length} B lib ${l0.ok}/${l1.ok} (max ${Math.max(l0.maxPct, l1.maxPct)}%, W ${l1.W?.pct}%) tma ${r0.allowed}/${r1.allowed} ${r0.rejectReason ?? ''}${r1.rejectReason ?? ''} block ${inBlock}`);
    if (!ok) throw new Error(`seq ${i} failed`);
  }
  log({ ev: 'seq-summary', accepted: seqOk, of: 24, Wvalue: A.st.value, spent: A.st.keys.length });

  // ================= replay: pool A, statement 0 again (NF present)
  {
    const b: B = build(0, A, A.st);
    if (!b.ws.present) throw new Error('replay: NF should be present');
    await fundBatch(f, [b]); finalize(b, { txid: A.st.txid, vout: A.st.index });
    const l0 = lib(b.tx0, b, false);
    const r0 = await send(b.raw0!, 'replay.tx0');
    const blk0 = await mineOne();
    const variants: any[] = [];
    for (const [name, bb] of [['present-path', b], ['stale-witness', (() => { const s: B = build(0, A, A.st, { staleKeys: [] }); s.f0 = b.f0; s.f1 = b.f1; finalize(s, { txid: A.st.txid, vout: A.st.index });
      // the same tx0 (byte-identical): its thread NFT is still unspent
      if (hex(s.raw0!) !== hex(b.raw0!)) throw new Error('stale: tx0 differs'); return s; })()]] as [string, B][]) {
      const l1 = lib(bb.tx1, bb, true);
      const r1 = await send(bb.raw1!, `replay.${name}.tx1`, true);
      const bv = await blockVerdict([bb.raw1!]);
      const rejected = !l1.ok && l1.firstRejectRole === 'W' && !r1.allowed && !r1.sent && !bv.accepted;
      variants.push({ name, rejected, lib1: l1, bchn1: r1, block: bv });
      say(`replay ${name}: ${rejected ? 'REJECTED as expected' : 'UNEXPECTED'} lib ${l1.firstRejectRole}: ${l1.firstRejectErr} | tma ${r1.rejectReason} | send ${JSON.stringify(r1.sendResult)?.slice(0, 120)} | block ${bv.result}`);
    }
    const w = await checkW(A);
    log({ ev: 'replay', pool: 'A', i: 0, tx0: { lib: l0, bchn: r0, mined: blk0.txids.includes(disp(b.id0!)) }, variants, Wunchanged: w });
  }

  // ================= chain10: pool B, statements 0..9, 20 txs unconfirmed, one block
  const Bp = await wGenesis('B', R, nIn, wIdx, 20n * D);
  {
    const bs: B[] = []; let st = Bp.st;
    for (let i = 0; i < 10; i++) { const b: B = build(i, Bp, st); samePg(b); bs.push(b); st = { ...st, keys: [...st.keys, b.K], value: st.value - D }; }
    await fundBatch(f, bs);
    const steps: any[] = []; const libs: any[] = [];
    for (const b of bs) {
      finalize(b, { txid: Bp.st.txid, vout: Bp.st.index });
      const l0 = lib(b.tx0, b, false), l1 = lib(b.tx1, b, true);
      const r0 = await send(b.raw0!, `chain${b.i}.tx0`), r1 = await send(b.raw1!, `chain${b.i}.tx1`);
      const mpe = await rpc('getmempoolentry', disp(b.id1!));
      advance(Bp, b);
      const w = await checkW(Bp);
      libs.push({ i: b.i, ok0: l0.ok, ok1: l1.ok, maxPct: Math.max(l0.maxPct, l1.maxPct), W: l1.W });
      steps.push({ i: b.i, r0, r1, depends: mpe?.depends, wUnconfirmed: w });
      say(`chain ${b.i}: lib ${l0.ok}/${l1.ok} tma ${r0.allowed}/${r1.allowed} sent ${r0.sent}/${r1.sent} W' in mempool ${w.ok} depends ${mpe?.depends?.length}`);
    }
    const info = await rpc('getmempoolinfo');
    const blk = await mineOne();
    const all = bs.every((b) => blk.txids.includes(disp(b.id0!)) && blk.txids.includes(disp(b.id1!)));
    const w = await checkW(Bp);
    const ok = libs.every((x) => x.ok0 && x.ok1) && steps.every((x) => x.r0.allowed && x.r0.sent && x.r1.allowed && x.r1.sent) && all && Array.isArray(blk.mempoolAfter) && blk.mempoolAfter.length === 0 && w.ok;
    log({ ev: 'chain10', ok, libs, steps, mempoolInfo: info, block: { height: blk.height, bytes: blk.bytes, ntx: blk.txids.length, allIncluded: all, mempoolAfter: blk.mempoolAfter },
      bytes: bs.reduce((s, b) => s + b.raw0!.length + b.raw1!.length, 0), checkW: w });
    say(`chain10: ${ok ? 'OK' : 'FAIL'} block ${blk.height} ${blk.txids.length} txs (${blk.bytes} B), all 20 included ${all}, mempool after ${JSON.stringify(blk.mempoolAfter)}`);
  }

  // ================= race: pool B, statements 10 (X) and 11 (Y) on one W outpoint
  {
    const W0 = { txid: Bp.st.txid, vout: Bp.st.index }; const st0 = Bp.st;
    const X: B = build(10, Bp, st0), Y: B = build(11, Bp, st0);
    await fundBatch(f, [X, Y]); finalize(X, W0); finalize(Y, W0);
    const lX = [lib(X.tx0, X, false), lib(X.tx1, X, true)], lY = [lib(Y.tx0, Y, false), lib(Y.tx1, Y, true)];
    const sX0 = await send(X.raw0!, 'raceX.tx0'), sY0 = await send(Y.raw0!, 'raceY.tx0');
    const sX1 = await send(X.raw1!, 'raceX.tx1');
    const sY1 = await send(Y.raw1!, 'raceY.tx1(loser)', true);
    advance(Bp, X);
    // Y rebuilds tx1 on X's unconfirmed output 0: same proof, same R inputs (not re-proved)
    const Y2: B = build(11, Bp, Bp.st); Y2.f0 = Y.f0; Y2.f1 = Y.f1; finalize(Y2, { txid: Bp.st.txid, vout: Bp.st.index });
    const sameTx0 = hex(Y2.raw0!) === hex(Y.raw0!);
    const sameR = Array.from({ length: Y.wIdx }, (_, j) => hex(Y2.tx1.transaction.inputs[j].unlockingBytecode) === hex(Y.tx1.transaction.inputs[j].unlockingBytecode)
      && hex(Y2.tx1.transaction.inputs[j].outpointTransactionHash) === hex(Y.tx1.transaction.inputs[j].outpointTransactionHash) && Y2.tx1.transaction.inputs[j].outpointIndex === Y.tx1.transaction.inputs[j].outpointIndex).every(Boolean);
    const samePayout = J(Y2.tx1.transaction.outputs.slice(1)) === J(Y.tx1.transaction.outputs.slice(1));
    const lY2 = lib(Y2.tx1, Y2, true);
    const sY2 = await send(Y2.raw1!, 'raceY.tx1(rebuilt)');
    advance(Bp, Y2);
    const blk = await mineOne();
    const inc = [X.id0, Y.id0, X.id1, Y2.id1].map((x) => blk.txids.includes(disp(x!)));
    const w = await checkW(Bp);
    const ok = lX.every((l) => l.ok) && lY.every((l) => l.ok) && lY2.ok && sX0.sent && sY0.sent && sX1.sent && !sY1.sent && sY2.allowed && sY2.sent && sameTx0 && sameR && samePayout && inc.every(Boolean) && w.ok
      && !blk.txids.includes(disp(Y.id1!));
    log({ ev: 'race', ok, libX: lX, libY: lY, libYrebuilt: lY2, bchn: { X0: sX0, Y0: sY0, X1: sX1, Y1loser: sY1, Y1rebuilt: sY2 },
      rebuilt: { sameTx0, sameRInputs: sameR, samePayouts: samePayout, wInputChanged: hex(Y2.tx1.transaction.inputs[Y.wIdx].outpointTransactionHash) !== hex(Y.tx1.transaction.inputs[Y.wIdx].outpointTransactionHash), tx1Bytes: [Y.raw1!.length, Y2.raw1!.length] },
      block: { height: blk.height, ntx: blk.txids.length, included: inc, loserIncluded: blk.txids.includes(disp(Y.id1!)), mempoolAfter: blk.mempoolAfter }, checkW: w });
    say(`race: ${ok ? 'OK' : 'FAIL'} loser tma ${sY1.rejectReason} send ${JSON.stringify(sY1.sendResult)?.slice(0, 100)}; rebuilt (same tx0 ${sameTx0}, same R inputs ${sameR}) tma ${sY2.allowed} sent ${sY2.sent}; block ${inc}`);
  }

  // ================= conflict: pool B, statement 12 relayed twice (same NF) on one W outpoint
  {
    const W0 = { txid: Bp.st.txid, vout: Bp.st.index }; const st0 = Bp.st;
    const a: B = build(12, Bp, st0), c2: B = build(12, Bp, st0);
    await fundBatch(f, [a, c2]); finalize(a, W0); finalize(c2, W0);
    const la = [lib(a.tx0, a, false), lib(a.tx1, a, true)], lc = [lib(c2.tx0, c2, false), lib(c2.tx1, c2, true)];
    const sa0 = await send(a.raw0!, 'confA.tx0'), sc0 = await send(c2.raw0!, 'confB.tx0');
    const sa1 = await send(a.raw1!, 'confA.tx1');
    const sc1 = await send(c2.raw1!, 'confB.tx1(conflict)', true);
    advance(Bp, a);
    // B rebuilds on A's unconfirmed output 0: the NF is now present there
    const c3: B = build(12, Bp, Bp.st); c3.f0 = c2.f0; c3.f1 = c2.f1; finalize(c3, { txid: Bp.st.txid, vout: Bp.st.index });
    const lc3 = lib(c3.tx1, c3, true);
    const sc3 = await send(c3.raw1!, 'confB.tx1(rebuilt, NF present)', true);
    const blk = await mineOne();
    const bv = await blockVerdict([c3.raw1!]);
    const w = await checkW(Bp);
    const ok = la.every((l) => l.ok) && lc.every((l) => l.ok) && sa0.sent && sc0.sent && sa1.sent && !sc1.sent && c3.ws.present && !lc3.ok && lc3.firstRejectRole === 'W' && !sc3.allowed && !sc3.sent && !bv.accepted
      && blk.txids.includes(disp(a.id1!)) && !blk.txids.includes(disp(c3.id1!)) && w.ok;
    log({ ev: 'conflict', ok, libA: la, libB: lc, libBrebuilt: lc3, bchn: { A0: sa0, B0: sc0, A1: sa1, B1conflict: sc1, B1rebuilt: sc3 }, blockVerdictRebuilt: bv,
      block: { height: blk.height, ntx: blk.txids.length, mempoolAfter: blk.mempoolAfter }, checkW: w });
    say(`conflict: ${ok ? 'OK' : 'FAIL'} 2nd tx1 tma ${sc1.rejectReason}; rebuilt: lib ${lc3.firstRejectRole}: ${lc3.firstRejectErr} | tma ${sc3.rejectReason} | block ${bv.result}`);
  }
  log({ ev: 'end', height: chain.height, Avalue: A.st.value, Aspent: A.st.keys.length, Bvalue: Bp.st.value, Bspent: Bp.st.keys.length });
};
main().catch((e) => { console.error(e); log({ ev: 'error', error: String((e as Error).stack ?? e) }); process.exit(1); });
