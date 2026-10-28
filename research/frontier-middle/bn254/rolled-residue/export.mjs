// Bench vectors for the T2 research singleton (one P2SH32 input): the EXISTING BN254 singleton proof set of the bench
// (src/checkpoints/pairing-vectors.json committed proof; src/bch/groth16-singleton-multiproof-vectors.json extra proofs
// and its dense worst-case proof), and as invalid vectors exactly the bench's existing invalid statements for those
// proofs (tampered public inputs: pairing-vectors invalid.publicInputs and each multiproof invalidUnlocking), with the
// prover's best witness for the false statement. No new attack inputs.
//   node export.mjs vectors.json
import assert from 'node:assert/strict';
import {readFileSync, writeFileSync} from 'node:fs';
import {hexToBin, vmNumberToBigInt} from '@bitauth/libauth';
import {VEC, VDIR} from './math.mjs';
import {prove} from './protocol.mjs';
import {p2sh32, encodeUnlocking, spend} from './vm.mjs';
assert.equal(process.argv.length, 3, 'usage: node export.mjs vectors.json');
const redeem = Buffer.from(readFileSync(new URL('./redeem.hex', import.meta.url), 'utf8').trim(), 'hex'); const locking = Buffer.from(p2sh32(redeem));
// the plain singleton's unlocking: pushes Ax Ay Bxa Bxb Bya Byb Cx Cy in0 in1 (minimal numbers, reversed)
function parseProofUnlocking(hex) {
  const b = hexToBin(hex); const vals = []; let i = 0;
  while (i < b.length) { const op = b[i++];
    if (op === 0x00) vals.push(0n); else if (op === 0x4f) vals.push(-1n); else if (op >= 0x51 && op <= 0x60) vals.push(BigInt(op - 0x50));
    else { let len; if (op <= 75) len = op; else if (op === 0x4c) len = b[i++]; else if (op === 0x4d) { len = b[i] | (b[i + 1] << 8); i += 2; } else throw new Error('push?'); vals.push(vmNumberToBigInt(b.slice(i, i + len), {requireMinimalEncoding: false})); i += len; } }
  const d = vals.reverse().map(String);
  return {proof: {a: {x: d[0], y: d[1]}, b: {x: {c0: d[2], c1: d[3]}, y: {c0: d[4], c1: d[5]}}, c: {x: d[6], y: d[7]}}, publicInputs: [d[8], d[9]]};
}
const mp = JSON.parse(readFileSync(VDIR + '/src/bch/groth16-singleton-multiproof-vectors.json', 'utf8'));
const step = (u, label) => ({label, locking: locking.toString('hex'), unlocking: Buffer.from(u).toString('hex'), checkpoint: 'verify'});
const run = (fx, label) => { const w = prove(fx); const u = encodeUnlocking([w.W, redeem]); const x = spend(locking, u); assert.ok(x.accepted, label + ': ' + x.error); return [step(u, label)]; };
const bad = (fx, label) => { const w = prove(fx, {forge: true}); const u = encodeUnlocking([w.W, redeem]); assert.ok(!spend(locking, u).accepted, label + ' accepted'); return [step(u, 'invalid: ' + label)]; };
const committed = {proof: VEC.proof, publicInputs: VEC.publicInputs};
const extras = mp.proofs.filter((x) => !x.committed).map((x) => parseProofUnlocking(x.unlocking));
const worst = parseProofUnlocking(mp.worstCaseProof.unlocking);
const invalid = [bad({proof: VEC.proof, publicInputs: VEC.invalid.publicInputs}, 'committed proof, tampered public inputs (pairing-vectors invalid)'),
  ...mp.proofs.filter((x) => x.invalidUnlocking).map((x, i) => bad(parseProofUnlocking(x.invalidUnlocking), `multiproof ${i} invalidUnlocking (tampered public inputs)`)),
  ...(mp.worstCaseProof.invalidUnlocking ? [bad(parseProofUnlocking(mp.worstCaseProof.invalidUnlocking), 'worst-case proof invalidUnlocking')] : [])];
writeFileSync(process.argv[2], JSON.stringify({steps: run(committed, 'committed'), extraValidProofs: extras.map((fx, i) => run(fx, 'extra ' + i)), worstCaseProof: run(worst, 'worst case (dense inputs)'), invalid}, null, 1) + '\n');
console.log('wrote', process.argv[2], 'extras', extras.length, 'invalid', invalid.length, 'worst inputs', worst.publicInputs.map((x) => x.slice(0, 8)).join(','));
