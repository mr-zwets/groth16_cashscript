// Multi-input glue on the real bch-2026 VM (standard and consensus): every input's redeem is the same tiny
// loader template  <K> <i> LOADER ; LOADER reads the shared program blob from input 0's unlocking (first push),
// checks SHA256(blob) == K, OP_DEFINEs it and invokes it. The shared program pins the whole transaction:
// input count, and for every j: OP_UTXOBYTECODE(j) == P2SH32(<K> <j> LOADER), rebuilt from K (on the stack) and
// the LOADER bytes (baked in the program) -- no hash fixed point. It then reads a sibling's committed data field
// by introspection and checks an equality claim, as the Miller inputs do with the head's values.
//   node glue.mjs  -> validates the tx (all inputs, standard) and reports op cost / bytes of the glue.
import assert from 'node:assert/strict';
import {createVirtualMachineBch2026, encodeDataPush, bigIntToVmNumber, hash256, encodeTransactionBch} from '@bitauth/libauth';
import {createHash} from 'node:crypto';
const sha256 = (b) => Uint8Array.from(createHash('sha256').update(b).digest());
import {OP, pushNum, pushData} from './asm.mjs';

const vmStd = createVirtualMachineBch2026(true), vmCons = createVirtualMachineBch2026(false);
const OPX = {INPUTINDEX: 0xc0, ACTIVEBYTECODE: 0xc1, TXINPUTCOUNT: 0xc3, UTXOBYTECODE: 0xc7, INPUTBYTECODE: 0xca, HASH256: 0xaa, SHA256: 0xa8, CAT: 0x7e};
const N = Number(process.env.NIN ?? 4);
const HDR = (len) => encodeDataPush(new Uint8Array(len)).length - len; // push header length of the blob
// ---- the shared program (as a function body). Entry stack: [..witness.., K, i] ----
function program(LOADER, blobLen) {
  const c = [];
  // nested function defined inside the invoked program (checks that OP_DEFINE works inside OP_INVOKE)
  const sq = [OP.DUP, 0x95]; c.push(...pushData(sq), ...pushNum(2), OP.DEFINE);
  // 1. input count
  c.push(OPX.TXINPUTCOUNT, ...pushNum(N), OP.NUMEQUALVERIFY);
  // 2. pin every input j: UTXOBYTECODE(j) == aa20 || HASH256(0x20 || K || <j> || LOADER) || 87     (K at depth 1)
  for (let j = 0; j < N; j++) {
    c.push(...pushData([0x20])); // [.., K, i, 0x20]
    // fetch K: stack [.., K, i, 0x20] -> pick depth 2
    c.push(...pushNum(2), OP.PICK, OPX.CAT); // 0x20 || K
    c.push(...pushData([...pushNum(j), ...LOADER]), OPX.CAT, OPX.HASH256);
    c.push(...pushData([0xaa, 0x20]), OP.SWAP, OPX.CAT, ...pushData([0x87]), OPX.CAT);
    c.push(...pushNum(j), OPX.UTXOBYTECODE, OP.EQUALVERIFY);
  }
  // 3. read input 0's second push (a 96-byte field after the blob) and check a claim: 2nd push == sha256-derived?
  //    here: every input checks that input 0's field F satisfies F[0..48] squared mod 2^8 equals ... (just exercise reads)
  c.push(...pushNum(0), OPX.INPUTBYTECODE, ...pushNum(HDR(blobLen) + blobLen + 2), OP.SPLIT, OP.NIP, ...pushNum(96), OP.SPLIT, OP.DROP);
  c.push(...pushNum(48), OP.SPLIT, OP.BIN2NUM, OP.SWAP, OP.BIN2NUM, ...pushNum(2), OP.INVOKE, OP.SWAP, ...pushNum(2), OP.INVOKE, OP.NUMEQUALVERIFY);
  // 4. drop K, i and leave TRUE
  c.push(OP.TRUE, OP.TOALT, OP.BEGIN, OP.DROP, OP.DEPTH, OP.NOT, OP.UNTIL, OP.FROMALT); // clean stack (loop)
  return Uint8Array.from(c);
}
// LOADER: [K, i] -> read input 0 unlocking, take the first push (PUSHDATA2 blob: header 3 bytes), check, define, invoke
function loader(blobLen) {
  return Uint8Array.from([...pushNum(0), OPX.INPUTBYTECODE, ...pushNum(HDR(blobLen)), OP.SPLIT, OP.NIP, ...pushNum(blobLen), OP.SPLIT, OP.DROP,
    OP.DUP, OPX.SHA256, ...pushNum(3), OP.PICK, OP.EQUALVERIFY, ...pushNum(1), OP.DEFINE, ...pushNum(1), OP.INVOKE]);
}
// fixed point: the blob length appears in LOADER; iterate (lengths stabilize)
let blobLen = 400, blob, L;
for (let it = 0; it < 5; it++) { L = loader(blobLen); blob = program(L, blobLen); if (blob.length === blobLen) break; blobLen = blob.length; }
assert.equal(blob.length, blobLen);
const K = sha256(blob);
const redeem = (j) => Uint8Array.from([...pushData(K), ...pushNum(j), ...L]);
const p2sh = (r) => Uint8Array.from([0xaa, 0x20, ...hash256(r), 0x87]);
// a 96-byte field with two equal-square halves (x, -x as unsigned... use x, x)
const x = 0x1234567890abcdefn; const half = Uint8Array.from(Buffer.concat([Buffer.from(bigIntToVmNumber(x)), Buffer.alloc(48 - bigIntToVmNumber(x).length)]));
const field = Uint8Array.from([...half, ...half]);
const pad = Number(process.env.PAD ?? 2000);
const unlock = (j) => Uint8Array.from([...(j === 0 ? [...encodeDataPush(blob), ...encodeDataPush(field)] : []), ...encodeDataPush(new Uint8Array(pad).fill(1)), ...encodeDataPush(redeem(j))]);
// blob push must use PUSHDATA2 (3-byte header) for the fixed offset
const sourceOutputs = Array.from({length: N}, (_, j) => ({lockingBytecode: p2sh(redeem(j)), valueSatoshis: 10000n}));
const transaction = {version: 2, locktime: 0, inputs: Array.from({length: N}, (_, j) => ({outpointIndex: j, outpointTransactionHash: new Uint8Array(32).fill(7), sequenceNumber: 0, unlockingBytecode: unlock(j)})),
  outputs: [{lockingBytecode: Uint8Array.of(0x6a), valueSatoshis: 0n}]};
for (const [name, vm] of [['standard', vmStd], ['consensus', vmCons]]) {
  const res = vm.verify({sourceOutputs, transaction});
  assert.equal(res, true, name + ': ' + res);
  const ops = transaction.inputs.map((_, j) => vm.evaluate({inputIndex: j, sourceOutputs, transaction}).metrics.operationCost);
  console.log(name, 'tx valid; op per input', ops.join(', '));
}
// negative: a wrong-code input (different K) breaks the pins; a reordered tx is rejected
{ const bad = {...transaction, inputs: [transaction.inputs[1], transaction.inputs[0], ...transaction.inputs.slice(2)]}; const so = [sourceOutputs[1], sourceOutputs[0], ...sourceOutputs.slice(2)];
  assert.notEqual(vmStd.verify({sourceOutputs: so, transaction: bad}), true, 'reordered inputs rejected'); }
{ const blob2 = Uint8Array.from(blob); blob2[blob2.length - 1] ^= 1; const t2 = {...transaction, inputs: transaction.inputs.map((inp, j) => (j === 0 ? {...inp, unlockingBytecode: Uint8Array.from([...encodeDataPush(blob2), ...encodeDataPush(field), ...encodeDataPush(new Uint8Array(pad).fill(1)), ...encodeDataPush(redeem(0))])} : inp))};
  assert.notEqual(vmStd.verify({sourceOutputs, transaction: t2}), true, 'tampered program rejected'); }
console.log('blob', blob.length, 'B; loader', L.length, 'B; redeem', redeem(0).length, 'B; tx', encodeTransactionBch(transaction).length, 'B');
// glue op estimate per input: loader (read+hash+define) + pins (N inputs) + one field read
