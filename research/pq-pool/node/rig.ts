// BCHN regtest timing rig: replays arbitrary consensus-valid transactions ("workloads") on a stock
// BCHN v29.1.0 regtest node and measures script-validation time per block from the node's own
// -debug=bench "Verify N txins" log line.
//
// Method (see BCHN.md): every block is built here (no wallet, no mempool). Coinbases pay to bare
// OP_1, so funding needs no signatures. For a workload we (1) fund K copies of its source outputs
// in a funding block, (2) build a block holding the K workload txs (fresh outpoints, so no cache can
// hold them), (3) call `validateblocktemplate` on it R times (TestBlockValidity -> ConnectBlock with
// fJustCheck: full script checks, no state change) and parse "Verify" each time, (4) submitblock it
// once (also timed) and check the tip moved (accept) or the reject reason (reject).
// Op-cost of the exact bytes is computed with libauth's BCH 2026 VM (nonstandard mode) per input.
import { readFileSync, statSync, openSync, readSync, closeSync } from 'node:fs';
import {
  binToHex,
  createVirtualMachineBch2026,
  decodeTransaction,
  decodeTransactionOutputs,
  encodeDataPush,
  encodeTransaction,
  generateSigningSerializationBch,
  hash160,
  hash256,
  hexToBin,
  secp256k1,
  sha256,
  bigIntToVmNumber,
  decodeAuthenticationInstructions,
} from '@bitauth/libauth';

// ---------------------------------------------------------------- types
export interface WlInput {
  sourceLocking: Uint8Array;
  valueSatoshis: bigint;
  unlocking: Uint8Array;
  sequenceNumber: number;
  /** if set, the unlocking bytecode is produced after outpoints are known (signature baselines) */
  sign?: { kind: 'p2pkh-ecdsa' | 'p2pkh-schnorr' | 'bms-1of3-ecdsa-bottom' | 'p2pk-schnorr' | 'p2pk-ecdsa'; key: Uint8Array };
  /** generic re-sign (VMB vectors): unlocking = these pushes, signatures recomputed over `sourceLocking` */
  resign?: ({ raw: Uint8Array } | { alg: 'ecdsa' | 'schnorr'; key: Uint8Array; hashType: number })[];
}
export interface Workload {
  id: string;
  description: string;
  expect: 'accept' | 'reject';
  version: number;
  locktime: number;
  inputs: WlInput[];
  outputs: { locking: Uint8Array; valueSatoshis: bigint }[];
  group?: string;
}
type Tx = Parameters<typeof encodeTransaction>[0];

// ---------------------------------------------------------------- rpc
export class Rpc {
  private auth: string;
  constructor(public datadir: string, public port: number) {
    this.auth = 'Basic ' + Buffer.from(readFileSync(`${datadir}/regtest/.cookie`, 'utf8').trim()).toString('base64');
  }
  async call<T = any>(method: string, ...params: unknown[]): Promise<T> {
    const r = await fetch(`http://127.0.0.1:${this.port}/`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: this.auth },
      body: JSON.stringify({ jsonrpc: '1.0', id: 1, method, params }),
    });
    const j: any = await r.json();
    if (j.error) throw new Error(`${method}: ${JSON.stringify(j.error)}`);
    return j.result as T;
  }
}

// ---------------------------------------------------------------- encoding helpers
const u32le = (n: number) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n >>> 0, true); return b; };
const cat = (...a: Uint8Array[]) => { const o = new Uint8Array(a.reduce((s, x) => s + x.length, 0)); let p = 0; for (const x of a) { o.set(x, p); p += x.length; } return o; };
const varint = (n: number) => n < 0xfd ? Uint8Array.of(n) : n <= 0xffff ? Uint8Array.of(0xfd, n & 0xff, n >> 8) : cat(Uint8Array.of(0xfe), u32le(n));
const rev = (b: Uint8Array) => Uint8Array.from(b).reverse();
export const txidInternal = (raw: Uint8Array) => hash256(raw); // internal byte order
const cmpBytes = (a: Uint8Array, b: Uint8Array) => { for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return a[i]! - b[i]!; return 0; };
// CScript() << n  (BIP34 height push)
const scriptNum = (n: number) => n === 0 ? Uint8Array.of(0) : n <= 16 ? Uint8Array.of(0x50 + n) : encodeDataPush(bigIntToVmNumber(BigInt(n)));
const merkleRoot = (ids: Uint8Array[]) => {
  let level = ids;
  while (level.length > 1) {
    const next: Uint8Array[] = [];
    for (let i = 0; i < level.length; i += 2) next.push(hash256(cat(level[i]!, level[i + 1] ?? level[i]!)));
    level = next;
  }
  return level[0]!;
};
const OP_1 = Uint8Array.of(0x51);

// ---------------------------------------------------------------- vm (op-cost of the exact bytes)
const vm = createVirtualMachineBch2026(false);
export interface OpCostReport { ok: boolean; error?: string; perInput: number[]; total: number; unlockingBytes: number[]; budget: number[] }
export const libauthOpCost = (tx: Tx, sourceOutputs: { lockingBytecode: Uint8Array; valueSatoshis: bigint }[]): OpCostReport => {
  const v = vm.verify({ transaction: tx as any, sourceOutputs: sourceOutputs as any });
  const perInput = tx.inputs.map((_, i) => vm.evaluate({ inputIndex: i, sourceOutputs: sourceOutputs as any, transaction: tx as any }).metrics.operationCost);
  const unlockingBytes = tx.inputs.map((i) => i.unlockingBytecode.length);
  return {
    ok: v === true,
    error: v === true ? undefined : String(v),
    perInput,
    total: perInput.reduce((s, x) => s + x, 0),
    unlockingBytes,
    budget: unlockingBytes.map((u) => (41 + u) * 800),
  };
};

// ---------------------------------------------------------------- signing (baselines)
const SIGHASH_ALL_FORKID = 0x41;
const sighash = (tx: Tx, sourceOutputs: any[], inputIndex: number, covered: Uint8Array) =>
  hash256(generateSigningSerializationBch({ inputIndex, sourceOutputs, transaction: tx as any } as any, {
    coveredBytecode: covered,
    signingSerializationType: Uint8Array.of(SIGHASH_ALL_FORKID),
  }));
export const pubkeyOf = (k: Uint8Array) => secp256k1.derivePublicKeyCompressed(k) as Uint8Array;
export const p2pkhLocking = (pk: Uint8Array) => cat(Uint8Array.of(0x76, 0xa9, 0x14), hash160(pk), Uint8Array.of(0x88, 0xac));
export const p2pkLocking = (pk: Uint8Array) => cat(encodeDataPush(pk), Uint8Array.of(0xac));
export const bms1of3Locking = (pks: Uint8Array[]) => cat(Uint8Array.of(0x51), ...pks.map(encodeDataPush), Uint8Array.of(0x53, 0xae));
const signInputs = (tx: Tx, sourceOutputs: any[], inputs: WlInput[]) => {
  inputs.forEach((inp, i) => {
    if (inp.resign) {
      const pushes = inp.resign.map((p) => {
        if ('raw' in p) return encodeDataPush(p.raw);
        const h = hash256(generateSigningSerializationBch({ inputIndex: i, sourceOutputs, transaction: tx as any } as any, { coveredBytecode: inp.sourceLocking, signingSerializationType: Uint8Array.of(p.hashType) }));
        const sig = p.alg === 'ecdsa' ? secp256k1.signMessageHashDER(p.key, h) : secp256k1.signMessageHashSchnorr(p.key, h);
        return encodeDataPush(cat(sig as Uint8Array, Uint8Array.of(p.hashType)));
      });
      tx.inputs[i]!.unlockingBytecode = cat(...pushes);
      return;
    }
    if (!inp.sign) return;
    const h = sighash(tx, sourceOutputs, i, inp.sourceLocking);
    const { kind, key } = inp.sign;
    const ecdsa = () => cat(secp256k1.signMessageHashDER(key, h) as Uint8Array, Uint8Array.of(SIGHASH_ALL_FORKID));
    const schnorr = () => cat(secp256k1.signMessageHashSchnorr(key, h) as Uint8Array, Uint8Array.of(SIGHASH_ALL_FORKID));
    let u: Uint8Array;
    if (kind === 'p2pkh-ecdsa') u = cat(encodeDataPush(ecdsa()), encodeDataPush(pubkeyOf(key)));
    else if (kind === 'p2pkh-schnorr') u = cat(encodeDataPush(schnorr()), encodeDataPush(pubkeyOf(key)));
    else if (kind === 'p2pk-ecdsa') u = encodeDataPush(ecdsa());
    else if (kind === 'p2pk-schnorr') u = encodeDataPush(schnorr());
    else u = cat(Uint8Array.of(0x00), encodeDataPush(ecdsa())); // legacy-mode 1-of-3, sig for the bottom key
    tx.inputs[i]!.unlockingBytecode = u;
  });
};

// ---------------------------------------------------------------- chain state + block building
interface Utxo { txid: Uint8Array; vout: number; value: bigint; locking: Uint8Array; cbHeight?: number }
export class Chain {
  tipHash!: Uint8Array; // internal order
  height = 0;
  time = 0;
  bits = 0x207fffff;
  pool: Utxo[] = []; // OP_1 utxos
  constructor(public rpc: Rpc, public debugLog: string) {}
  async init() {
    const info = await this.rpc.call('getblockchaininfo');
    this.height = info.blocks;
    this.tipHash = rev(hexToBin(info.bestblockhash));
    const hdr = await this.rpc.call('getblockheader', info.bestblockhash);
    this.time = Math.max(hdr.time, Math.floor(Date.now() / 1000) - 3600);
    this.bits = parseInt(hdr.bits, 16);
  }
  subsidy(h: number) { const halvings = Math.floor(h / 150); return halvings >= 64 ? 0n : 5_000_000_000n >> BigInt(halvings); }
  coinbase(h: number) {
    const script = cat(scriptNum(h), encodeDataPush(new TextEncoder().encode('opcost-timing-rig')));
    const tx: Tx = {
      version: 2, locktime: 0,
      inputs: [{ outpointTransactionHash: new Uint8Array(32), outpointIndex: 0xffffffff, sequenceNumber: 0xffffffff, unlockingBytecode: script }],
      outputs: [{ lockingBytecode: OP_1, valueSatoshis: this.subsidy(h) }],
    };
    return encodeTransaction(tx);
  }
  /** assemble + grind a block on the current tip; txs are raw encodings (CTOR-sorted here) */
  buildBlock(txs: Uint8Array[]) {
    const h = this.height + 1;
    const cb = this.coinbase(h);
    const sorted = txs.map((raw) => ({ raw, id: txidInternal(raw) })).sort((a, b) => cmpBytes(rev(a.id), rev(b.id))); // CTOR: ascending txid as a uint256 (display order)
    const ids = [txidInternal(cb), ...sorted.map((t) => t.id)];
    const root = merkleRoot(ids);
    const time = Math.max(this.time + 1, Math.floor(Date.now() / 1000) - 3600);
    const exp = this.bits >>> 24, mant = BigInt(this.bits & 0xffffff);
    const target = mant << BigInt(8 * (exp - 3));
    let nonce = 0, header: Uint8Array;
    for (;;) {
      header = cat(u32le(0x20000000), this.tipHash, root, u32le(time), u32le(this.bits), u32le(nonce));
      const hv = BigInt('0x' + binToHex(rev(hash256(header))));
      if (hv <= target) break;
      nonce++;
    }
    const body = cat(header, varint(1 + sorted.length), cb, ...sorted.map((t) => t.raw));
    return { hex: binToHex(body), hash: hash256(header), height: h, time, cbTxid: ids[0]!, bytes: body.length };
  }
  async submit(block: ReturnType<Chain['buildBlock']>) {
    const r = await this.rpc.call('submitblock', block.hex);
    const best = await this.rpc.call<string>('getbestblockhash');
    const accepted = best === binToHex(rev(block.hash));
    if (accepted) {
      this.tipHash = block.hash; this.height = block.height; this.time = block.time;
      this.pool.push({ txid: block.cbTxid, vout: 0, value: this.subsidy(block.height), locking: OP_1, cbHeight: block.height });
    }
    return { accepted, result: r as string | null };
  }
  async mine(n: number) { for (let i = 0; i < n; i++) { const s = await this.submit(this.buildBlock([])); if (!s.accepted) throw new Error('mine: ' + s.result); } }
  spendable(need: bigint) {
    const nextH = this.height + 1;
    const ok = (u: Utxo) => u.cbHeight === undefined || nextH - u.cbHeight >= 100;
    const picked: Utxo[] = []; let sum = 0n;
    // prefer large utxos
    const cands = this.pool.filter(ok).sort((a, b) => (b.value > a.value ? 1 : b.value < a.value ? -1 : 0));
    for (const u of cands) { picked.push(u); sum += u.value; if (sum >= need) break; }
    if (sum < need) throw new Error(`pool exhausted: need ${need}, have ${sum}`);
    this.pool = this.pool.filter((u) => !picked.includes(u));
    return { picked, sum };
  }
  /** fund the given outputs (any lockings) in one or more funding txs, mined in one block; returns the outpoints */
  async fund(outs: { locking: Uint8Array; value: bigint }[]) {
    const res: { txid: Uint8Array; vout: number }[] = [];
    const txs: Uint8Array[] = [];
    const change: Utxo[] = [];
    let i = 0;
    while (i < outs.length) {
      // chunk by bytes (< 900 kB per funding tx) and count
      const chunk: typeof outs = []; let bytes = 0;
      while (i < outs.length && chunk.length < 20000 && bytes + outs[i]!.locking.length + 12 < 900_000) { chunk.push(outs[i]!); bytes += outs[i]!.locking.length + 12; i++; }
      const need = chunk.reduce((s, o) => s + o.value, 0n) + 1_000_000n;
      const { picked, sum } = this.spendable(need);
      const tx: Tx = {
        version: 2, locktime: 0,
        inputs: picked.map((u) => ({ outpointTransactionHash: rev(u.txid), outpointIndex: u.vout, sequenceNumber: 0xffffffff, unlockingBytecode: new Uint8Array(0) })),
        outputs: [...chunk.map((o) => ({ lockingBytecode: o.locking, valueSatoshis: o.value })), { lockingBytecode: OP_1, valueSatoshis: sum - need + 1_000_000n - 10_000n }],
      };
      const raw = encodeTransaction(tx);
      const id = txidInternal(raw);
      chunk.forEach((_, j) => res.push({ txid: id, vout: j }));
      change.push({ txid: id, vout: chunk.length, value: sum - need + 1_000_000n - 10_000n, locking: OP_1 });
      txs.push(raw);
    }
    const b = this.buildBlock(txs);
    const s = await this.submit(b);
    if (!s.accepted) throw new Error('funding block rejected: ' + s.result);
    this.pool.push(...change);
    return res;
  }
  // ---- log tail for -debug=bench
  private logPos = 0;
  markLog() { this.logPos = statSync(this.debugLog).size; }
  readLog() {
    const size = statSync(this.debugLog).size;
    const fd = openSync(this.debugLog, 'r'); const buf = Buffer.alloc(size - this.logPos);
    readSync(fd, buf, 0, buf.length, this.logPos); closeSync(fd); this.logPos = size;
    return buf.toString('utf8');
  }
}

const parseBench = (log: string) => {
  // BCHN: "    - Verify %u txins: %.2fms (%.3fms/txin) [...]" and "      - Connect %u transactions: %.2fms ..."
  const verify = [...log.matchAll(/- Verify (\d+) txins: ([\d.]+)ms/g)].map((m) => ({ txins: +m[1]!, ms: +m[2]! }));
  const connect = [...log.matchAll(/- Connect (\d+) transactions: ([\d.]+)ms/g)].map((m) => ({ txs: +m[1]!, ms: +m[2]! }));
  const sanity = [...log.matchAll(/- Sanity checks: ([\d.]+)ms/g)].map((m) => +m[1]!);
  return { verify, connect, sanity };
};

// ---------------------------------------------------------------- workload -> concrete txs
export const instantiate = (wl: Workload, outpoints: { txid: Uint8Array; vout: number }[]) => {
  const tx: Tx = {
    version: wl.version, locktime: wl.locktime,
    inputs: wl.inputs.map((inp, i) => ({ outpointTransactionHash: rev(outpoints[i]!.txid), outpointIndex: outpoints[i]!.vout, sequenceNumber: inp.sequenceNumber, unlockingBytecode: inp.unlocking })),
    outputs: wl.outputs.map((o) => ({ lockingBytecode: o.locking, valueSatoshis: o.valueSatoshis })),
  };
  const sourceOutputs = wl.inputs.map((i) => ({ lockingBytecode: i.sourceLocking, valueSatoshis: i.valueSatoshis }));
  signInputs(tx, sourceOutputs, wl.inputs);
  return { tx, sourceOutputs, raw: encodeTransaction(tx) };
};

const stats = (xs: number[]) => {
  const s = [...xs].sort((a, b) => a - b); const n = s.length;
  const med = n % 2 ? s[(n - 1) / 2]! : (s[n / 2 - 1]! + s[n / 2]!) / 2;
  return { median: med, min: s[0]!, max: s[n - 1]!, n, spreadPct: med > 0 ? ((s[n - 1]! - s[0]!) / med) * 100 : 0 };
};

export interface RunOpts { reps: number; targetOpCost: number; maxCopies: number; maxBlockBytes: number; minCopies?: number }
export const runWorkload = async (chain: Chain, wl: Workload, opts: RunOpts) => {
  // 1) op-cost + expected result of one concrete copy (with placeholder outpoints first to size K)
  const probe = instantiate(wl, wl.inputs.map((_, i) => ({ txid: sha256.hash(Uint8Array.of(i, 7)), vout: i })));
  const oc0 = libauthOpCost(probe.tx, probe.sourceOutputs);
  const perTx = Math.max(oc0.total, 1);
  let K = Math.ceil(opts.targetOpCost / perTx);
  K = Math.max(opts.minCopies ?? 1, Math.min(K, opts.maxCopies, Math.max(1, Math.floor(opts.maxBlockBytes / probe.raw.length))));
  if (wl.expect === 'reject') K = 1;
  // 2) fund K copies
  const outs = Array.from({ length: K }, () => wl.inputs.map((i) => ({ locking: i.sourceLocking, value: i.valueSatoshis }))).flat();
  const ops = await chain.fund(outs);
  const copies = Array.from({ length: K }, (_, k) => instantiate(wl, ops.slice(k * wl.inputs.length, (k + 1) * wl.inputs.length)));
  // op-cost of the exact bytes submitted (first copy; all copies differ only in outpoints/signatures)
  const oc = libauthOpCost(copies[0]!.tx, copies[0]!.sourceOutputs);
  const block = chain.buildBlock(copies.map((c) => c.raw));
  const txins = K * wl.inputs.length; // BCHN's "Verify N txins" counts non-coinbase inputs
  // 3) repeated validateblocktemplate
  const verifyMs: number[] = []; const wallMs: number[] = []; const connectMs: number[] = []; const sanityMs: number[] = []; let vbtResult: unknown = undefined; let vbtError: string | undefined;
  const reps = wl.expect === 'reject' ? Math.min(opts.reps, 3) : opts.reps;
  // per-rep verdict: validateblocktemplate result/error and whether BCHN printed the Verify line (printed only after
  // all script checks pass) -- recorded for every rep, not only the last
  const repVerdicts: { ok: boolean; error?: string; verifyLine: boolean }[] = [];
  // for expected rejections: BCHN's script error string via testmempoolaccept (block validation only reports
  // "blk-bad-inputs, parallel script check failed"); mempool uses standard flags, so this is the standard-mode verdict
  let mempoolReject: unknown = undefined;
  if (wl.expect === 'reject') {
    try { mempoolReject = await chain.rpc.call('testmempoolaccept', [binToHex(copies[0]!.raw)]); } catch (e) { mempoolReject = { rpcError: String((e as Error).message) }; }
  }
  for (let r = 0; r < reps; r++) {
    chain.markLog();
    const t0 = process.hrtime.bigint();
    let repErr: string | undefined;
    try { vbtResult = await chain.rpc.call('validateblocktemplate', block.hex); vbtError = undefined; } catch (e) { vbtError = String((e as Error).message); repErr = vbtError; }
    const t1 = process.hrtime.bigint();
    await new Promise((res) => setTimeout(res, 5));
    const b = parseBench(chain.readLog());
    wallMs.push(Number(t1 - t0) / 1e6);
    const v = b.verify.find((x) => x.txins === txins);
    repVerdicts.push({ ok: repErr === undefined && vbtResult === true, error: repErr, verifyLine: !!v });
    if (v) verifyMs.push(v.ms);
    const c = b.connect.find((x) => x.txs === K + 1); if (c) connectMs.push(c.ms);
    if (b.sanity.length) sanityMs.push(b.sanity[b.sanity.length - 1]!);
  }
  // 4) submit once (timed); check result
  chain.markLog();
  const t0 = process.hrtime.bigint();
  const sub = await chain.submit(block);
  const t1 = process.hrtime.bigint();
  await new Promise((res) => setTimeout(res, 5));
  const sb = parseBench(chain.readLog());
  const subVerify = sb.verify.find((x) => x.txins === txins)?.ms;
  const bchnAccepted = sub.accepted;
  const asExpected = (wl.expect === 'accept') === bchnAccepted && (wl.expect === 'accept') === oc.ok;
  const vs = verifyMs.length ? stats(verifyMs) : undefined;
  const perTxNs = vs ? (vs.median * 1e6) / K : undefined;
  return {
    id: wl.id, group: wl.group, description: wl.description, expect: wl.expect,
    libauthOk: oc.ok, libauthError: oc.error,
    bchnAccepted, submitResult: sub.result, vbtResult, vbtError, asExpected, repVerdicts, mempoolReject,
    repsAllAsExpected: repVerdicts.every((v) => v.ok === (wl.expect === 'accept') && v.verifyLine === (wl.expect === 'accept')),
    txBytes: copies[0]!.raw.length, inputs: wl.inputs.length, copies: K, blockBytes: block.bytes, txinsInBlock: txins,
    opCostPerTx: oc.total, opCostPerInput: oc.perInput, unlockingBytes: oc.unlockingBytes, budgetPerInput: oc.budget,
    opCostOverBudgetMax: Math.max(...oc.perInput.map((c, i) => c / oc.budget[i]!)),
    verifyMs: verifyMs, verifyStats: vs, connectLoopStats: connectMs.length ? stats(connectMs) : undefined, sanityStats: sanityMs.length ? stats(sanityMs) : undefined, vbtWallMs: stats(wallMs), submitVerifyMs: subVerify, submitWallMs: Number(t1 - t0) / 1e6,
    nsPerTx: perTxNs,
    nsPerOpCost: perTxNs !== undefined && oc.total > 0 ? perTxNs / oc.total : undefined,
    nsPerTxByte: perTxNs !== undefined ? perTxNs / copies[0]!.raw.length : undefined,
  };
};

// ---------------------------------------------------------------- workload loaders
/** libauth VMB test vector: [shortId, description, unlockingAsm, lockingAsm, txHex, sourceOutputsHex, inputIndex?] */
export const fromVmb = (v: any[], expect: 'accept' | 'reject', group: string): Workload | string => {
  const tx = decodeTransaction(hexToBin(v[4])); if (typeof tx === 'string') return 'decode tx: ' + tx;
  const so = decodeTransactionOutputs(hexToBin(v[5])); if (typeof so === 'string') return 'decode utxos: ' + so;
  if (so.some((o: any) => o.token) || tx.outputs.some((o: any) => o.token)) return 'uses CashTokens (not replayable without token genesis)';
  const inputs: WlInput[] = [];
  for (let i = 0; i < tx.inputs.length; i++) {
    const r = resignInput(tx as Tx, so as any, i);
    if (typeof r === 'string') return `input ${i}: ${r}`;
    inputs.push(r);
  }
  return {
    id: v[0], description: v[1], expect, group, version: tx.version, locktime: tx.locktime, inputs,
    outputs: tx.outputs.map((o) => ({ locking: o.lockingBytecode, valueSatoshis: o.valueSatoshis })),
  };
};
// Signature-bearing inputs commit to their (fake) outpoints, so they cannot be replayed verbatim on a real chain.
// We re-key them: every original public key P maps to a rig key k(P) = sha256(P); the locking script is rebuilt
// with k(P)'s public key at the same position, and each signature is re-created with the same algorithm
// (ECDSA/Schnorr, from the original length), the same sighash type and the same key slot (legacy multisig slots
// are found by verifying the original signature against each original key). The evaluated opcodes, signature
// kinds and verification counts are unchanged; only key/signature bytes differ.
const rigKey = (pk: Uint8Array) => sha256.hash(cat(new TextEncoder().encode('opcost-timing-rig rekey'), pk));
const pushesOf = (b: Uint8Array) => {
  const ins = decodeAuthenticationInstructions(b) as any[];
  if (ins.some((x) => x.malformed || x.opcode > 0x4e && x.opcode !== 0x4f && !(x.opcode >= 0x51 && x.opcode <= 0x60))) return undefined;
  return ins.map((x) => (x.data !== undefined ? x.data as Uint8Array : x.opcode === 0 ? new Uint8Array(0) : x.opcode === 0x4f ? Uint8Array.of(0x81) : Uint8Array.of(x.opcode - 0x50)));
};
const isSigLike = (d: Uint8Array) => d.length === 65 || (d.length >= 9 && d.length <= 73 && d[0] === 0x30);
const resignInput = (tx: Tx, so: { lockingBytecode: Uint8Array; valueSatoshis: bigint }[], i: number): WlInput | string => {
  const L = so[i]!.lockingBytecode; const U = tx.inputs[i]!.unlockingBytecode;
  const plain: WlInput = { sourceLocking: L, valueSatoshis: so[i]!.valueSatoshis, unlocking: U, sequenceNumber: tx.inputs[i]!.sequenceNumber };
  const pushes = pushesOf(U);
  if (!pushes || !pushes.some((d) => d && isSigLike(d))) return plain; // no signature: replay verbatim
  const algOf = (sig: Uint8Array) => (sig.length === 65 ? 'schnorr' as const : 'ecdsa' as const);
  const origHash = (ht: number) => hash256(generateSigningSerializationBch({ inputIndex: i, sourceOutputs: so, transaction: tx as any } as any, { coveredBytecode: L, signingSerializationType: Uint8Array.of(ht) }));
  const verifies = (sig: Uint8Array, pk: Uint8Array) => {
    const body = sig.slice(0, -1); const h = origHash(sig[sig.length - 1]!);
    return sig.length === 65 ? secp256k1.verifySignatureSchnorr(body, pk, h) : secp256k1.verifySignatureDER(body, pk, h);
  };
  // P2PKH
  if (L.length === 25 && L[0] === 0x76 && L[1] === 0xa9 && L[2] === 0x14 && L[23] === 0x88 && L[24] === 0xac && pushes.length === 2) {
    const [sig, pk] = pushes as Uint8Array[];
    if (!verifies(sig!, pk!)) return 'P2PKH signature does not verify against the original tx';
    const k = rigKey(pk!);
    return { ...plain, sourceLocking: p2pkhLocking(pubkeyOf(k)), resign: [{ alg: algOf(sig!), key: k, hashType: sig![sig!.length - 1]! }, { raw: pubkeyOf(k) }] };
  }
  // bare P2PK (compressed key)
  if (L.length === 35 && L[0] === 0x21 && L[34] === 0xac && pushes.length === 1) {
    const sig = pushes[0]!; const pk = L.slice(1, 34);
    if (!verifies(sig, pk)) return 'P2PK signature does not verify';
    const k = rigKey(pk);
    return { ...plain, sourceLocking: p2pkLocking(pubkeyOf(k)), resign: [{ alg: algOf(sig), key: k, hashType: sig[sig.length - 1]! }] };
  }
  // bare m-of-n multisig with compressed keys: <m> <pk>... <n> OP_CHECKMULTISIG
  const lp = decodeAuthenticationInstructions(L) as any[];
  if (lp.length >= 4 && lp[lp.length - 1].opcode === 0xae && lp.slice(1, -2).every((x) => x.data?.length === 33)) {
    const pks = lp.slice(1, -2).map((x) => x.data as Uint8Array);
    const ks = pks.map(rigKey);
    const newL = cat(L.slice(0, 1), ...ks.map((k) => encodeDataPush(pubkeyOf(k))), L.slice(L.length - 2));
    const dummy = pushes[0]!; const sigs = pushes.slice(1) as Uint8Array[];
    let slots: number[];
    if (dummy.length === 0) {
      // legacy mode: keys are consumed top-down; assign each sig to the key it verifies against (same order)
      slots = []; let k = pks.length - 1;
      for (let s = sigs.length - 1; s >= 0; s--) { while (k >= 0 && !verifies(sigs[s]!, pks[k]!)) k--; if (k < 0) return 'multisig signature slot not found'; slots.unshift(k); k--; }
    } else {
      let bits = 0; dummy.forEach((b, j) => (bits |= b << (8 * j)));
      slots = pks.map((_, j) => j).filter((j) => (bits >> j) & 1);
      if (slots.length !== sigs.length) return 'checkbits mismatch';
    }
    return { ...plain, sourceLocking: newL, resign: [{ raw: dummy }, ...sigs.map((sig, s) => ({ alg: algOf(sig), key: ks[slots[s]!]!, hashType: sig[sig.length - 1]! }))] };
  }
  return 'signature-bearing input of an unsupported shape (cannot re-sign)';
};
/** generic JSON workload (hex fields), the format other tasks can emit */
export const fromJson = (w: any): Workload => ({
  id: w.id, description: w.description ?? '', expect: w.expect ?? 'accept', group: w.group,
  version: w.version ?? 2, locktime: w.locktime ?? 0,
  inputs: w.inputs.map((i: any) => ({ sourceLocking: hexToBin(i.sourceLockingHex), valueSatoshis: BigInt(i.valueSatoshis ?? 1000), unlocking: hexToBin(i.unlockingHex), sequenceNumber: i.sequenceNumber ?? 0 })),
  outputs: (w.outputs ?? [{ lockingHex: '6a', valueSatoshis: 0 }]).map((o: any) => ({ locking: hexToBin(o.lockingHex), valueSatoshis: BigInt(o.valueSatoshis ?? 0) })),
});
