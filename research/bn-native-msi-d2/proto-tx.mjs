// Run the glue prototype in a real n-input bch-2026 transaction (consensus + standard VMs) and measure
// per-input op cost, budget and sizes.   node proto-tx.mjs [n] [pad0,pad1,...]
import assert from 'node:assert/strict';
import {createVirtualMachineBch2026, encodeDataPush, hash256} from '@bitauth/libauth';
import {FIXTURES} from '../../chunked/bn254/sound-si-gls/math.mjs';
import {prove, le32} from '../../chunked/bn254/sound-si-gls/protocol.mjs';
import {dispatcher, inputProgram, sha, T_SIZE, WS_SIZE, WQ_SIZE, H_SIZE} from './glue.mjs';

const n = Number(process.argv[2] ?? 4);
const pads = (process.argv[3] ?? '').split(',').filter(Boolean).map(Number);
const seg = Array.from({length: n}, (_, j) => Math.floor(T_SIZE / n) + (j < T_SIZE % n ? 1 : 0));
const w = prove(FIXTURES.fixtures[0]);
const WQ = Buffer.concat([Buffer.alloc(WQ_SIZE - w.WQ.length), w.WQ]); // fixed width: leading zero words
const T = Buffer.concat([w.WS, WQ]); assert.equal(T.length, T_SIZE);
const D = []; { let o = 0; for (const d of seg) { D.push(T.subarray(o, o + d)); o += d; } }
const H = Array.from({length: n}, (_, i) => (i === n - 1 ? Buffer.alloc(0) : Buffer.concat([1n, 2n, 3n, 4n, 5n, 6n, 7n].map(le32))));
const K = Array.from({length: n}, (_, i) => inputProgram({seg, i, padCode: pads[i] ?? 0}));
const Delta = dispatcher(K.map((k) => sha(k.code)));
const locking = Uint8Array.from([0xaa, 0x20, ...hash256(Delta), 0x87]);
const push = (b) => [...encodeDataPush(Uint8Array.from(b))];
const unl = K.map((k, i) => Uint8Array.from([...push(D[i]), ...push(H[i]), ...push(k.code), ...push(Delta)]));
const tx = {version: 2, locktime: 0, inputs: unl.map((u, j) => ({outpointTransactionHash: new Uint8Array(32), outpointIndex: j, sequenceNumber: 0, unlockingBytecode: u})),
  outputs: [{lockingBytecode: Uint8Array.of(0x6a), valueSatoshis: 0n}]};
const sourceOutputs = unl.map(() => ({lockingBytecode: locking, valueSatoshis: 1000n}));
const out = {n, seg, delta: Delta.length, inputs: []};
for (const [mode, std] of [['consensus', false], ['standard', true]]) {
  const vm = createVirtualMachineBch2026(std);
  const v = vm.verify({transaction: tx, sourceOutputs});
  out[mode] = v === true ? 'accepted' : String(v);
  unl.forEach((u, i) => {
    const st = vm.evaluate({inputIndex: i, sourceOutputs, transaction: tx});
    const row = out.inputs[i] ?? (out.inputs[i] = {i, unlocking: u.length, K: K[i].code.length, pad: pads[i] ?? 0, budget: (41 + u.length) * 800});
    row[mode] = st.metrics.operationCost; row.err = st.error ?? row.err;
  });
}
// per-section cost (standard): debug trace, top-level of K_i
const vm = createVirtualMachineBch2026(true);
for (const [i, k] of K.entries()) {
  const tr = vm.debug({inputIndex: i, sourceOutputs, transaction: tx});
  const kLen = (await import('@bitauth/libauth')).decodeAuthenticationInstructions(k.code).length;
  let prev = 0, sec = 'dispatcher+p2sh'; const by = {};
  const {decodeAuthenticationInstructions, encodeAuthenticationInstruction} = await import('@bitauth/libauth');
  const ins = decodeAuthenticationInstructions(k.code); const offs = []; { let o = 0; for (const x of ins) { offs.push(o); o += encodeAuthenticationInstruction(x).length; } }
  const ms = Object.entries(k.marks).sort((a, b) => a[1] - b[1]);
  for (const s of tr) { const c = s.metrics?.operationCost ?? 0; const d = c - prev; prev = c;
    if (s.instructions?.length === kLen) { let nm = 'prologue'; for (const [m, off] of ms) if (off <= offs[Math.max(0, s.ip - 1)]) nm = m; sec = nm; }
    by[sec] = (by[sec] ?? 0) + d; }
  out.inputs[i].sections = by;
}
console.log(JSON.stringify(out, null, 1));
