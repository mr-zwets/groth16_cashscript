// Track 12: the RISC Zero Groth16 key folded for the RELEASED control root (risc0 v3.0.x / risc0-ethereum v3.0.1).
//
// Track 11's risc0.fixtures.json folds the control root of risc0-ethereum main @ fe5adc30 (b1f64013…, = risc0 main
// @ fc0222ab, unreleased). Receipts made with the released risc0-zkvm 3.0.x verify under CONTROL_ROOT a54dc85a…
// (risc0 v3.0.6 risc0/circuit/recursion/src/control_id.rs; risc0-ethereum v3.0.1 contracts/src/groth16/ControlID.sol,
// both vendored in ./upstream with git blob ids in ./upstream/SOURCES.md). The Groth16 VK itself is the same file
// (risc0-ethereum v3.0.1 Groth16Verifier.sol has git blob 0023123c, identical to Track 11's pinned copy).
// This script re-folds the UPSTREAM 5-input VK (Track 11's vkUpstream) with that root and the unchanged
// BN254_CONTROL_ID, and checks with noble that the real TestReceiptV3_0 (risc0-ethereum test receipt) verifies under
// the 5-input statement AND the folded 2-input statement, and that the V5_0 receipt (other root) fails both.
//
//   node fold-risc0.mjs     -> writes risc0-v3.fixtures.json (deterministic)
import assert from 'node:assert/strict';
import {readFileSync, writeFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {bn254} from '@noble/curves/bn254.js';
import {splitDigest, claimDigest} from '../real-keys/claims.mjs';

const T11 = JSON.parse(readFileSync(new URL('../real-keys/risc0.fixtures.json', import.meta.url)));
const ctl = readFileSync(new URL('./upstream/risc0-ethereum-v3.0.1-ControlID.sol', import.meta.url), 'utf8');
const rs = readFileSync(new URL('./upstream/risc0-v3.0.6-control_id.rs', import.meta.url), 'utf8');
const hex32 = (name) => { const m = ctl.match(new RegExp(name + ' = hex"([0-9a-f]{64})"')); assert.ok(m, name); return m[1]; };
const ROOT = hex32('CONTROL_ROOT'), BN_ID = hex32('BN254_CONTROL_ID');
assert.equal(ROOT, 'a54dc85ac99f851c92d7c96d7318af41dbe7c0194edfcc37eb4d422a998c1f56');
assert.ok(rs.replace(/\s+/g, '').includes(`ALLOWED_CONTROL_ROOT:Digest=digest!("${ROOT}")`), 'risc0 v3.0.6 control_id.rs pins the same root');
assert.equal(BigInt('0x' + BN_ID).toString(), T11.folded.BN254_CONTROL_ID, 'BN254_CONTROL_ID unchanged');

const {Fp2} = bn254.fields; const r = bn254.fields.Fr.ORDER; const F12 = bn254.fields.Fp12;
const g1 = (P) => bn254.G1.Point.fromAffine({x: BigInt(P.x), y: BigInt(P.y)});
const g2 = (P) => bn254.G2.Point.fromAffine({x: Fp2.fromBigTuple([BigInt(P.x.c0), BigInt(P.x.c1)]), y: Fp2.fromBigTuple([BigInt(P.y.c0), BigInt(P.y.c1)])});
const js1 = (P) => { const a = P.toAffine(); return {x: a.x.toString(), y: a.y.toString()}; };
const U = T11.vkUpstream; const vk = {alpha: g1(U.alpha), beta: g2(U.beta), gamma: g2(U.gamma), delta: g2(U.delta), ic: U.ic.map(g1)};
const groth16 = (ic, inputs, pf) => {
  if (!inputs.every((x) => x >= 0n && x < r)) return false;
  let vx = ic[0]; inputs.forEach((x, i) => { if (x) vx = vx.add(ic[i + 1].multiply(x)); });
  return F12.eql(bn254.pairing(g1(pf.a), g2(pf.b)), F12.mul(F12.mul(bn254.pairing(vk.alpha, vk.beta), bn254.pairing(vx, vk.gamma)), bn254.pairing(g1(pf.c), vk.delta)));
};
const [CR0, CR1] = splitDigest(Buffer.from(ROOT, 'hex')); const ID = BigInt('0x' + BN_ID);
const IC0 = vk.ic[0].add(vk.ic[1].multiply(CR0)).add(vk.ic[2].multiply(CR1)).add(vk.ic[5].multiply(ID));
const icF = [IC0, vk.ic[3], vk.ic[4]];
const all = [...T11.fixtures, ...T11.otherVersionReceipts];
const fixtures = [], others = [];
for (const rc of all) {
  const [c0, c1] = splitDigest(claimDigest(Buffer.from(rc.imageId, 'hex'), Buffer.from(rc.journalHex, 'hex')));
  assert.deepEqual([c0.toString(), c1.toString()], rc.publicInputs);
  const full = groth16(vk.ic, [CR0, CR1, c0, c1, ID], rc.proof), folded = groth16(icF, [c0, c1], rc.proof);
  assert.equal(full, folded, rc.id + ': 5-input and folded verdicts agree');
  const {fixture, verifiesUnderPinnedControlRoot, verifiesUnderControlRoot, ...e} = rc;
  if (full) fixtures.push({fixture: fixtures.length, ...e, verifiesUnderReleasedControlRoot: true}); else others.push({...e, verifiesUnderReleasedControlRoot: false});
}
assert.deepEqual(fixtures.map((x) => x.id), ['risc0-test-receipt-V3_0'], 'exactly the V3_0 test receipt verifies under the released root');
const vkj = {alpha: U.alpha, beta: U.beta, gamma: U.gamma, delta: U.delta, ic: icF.map(js1)};
const out = {
  system: 'RISC Zero Groth16 receipt verifier, RELEASED control root (risc0-zkvm 3.0.x, risc0-ethereum v3.0.1), control root and BN254 control id folded into IC0',
  vk: vkj, vkJsonSha256: createHash('sha256').update(JSON.stringify(vkj)).digest('hex'), vkUpstream: U,
  folded: {CONTROL_ROOT: ROOT, CONTROL_ROOT_0: CR0.toString(), CONTROL_ROOT_1: CR1.toString(), BN254_CONTROL_ID: ID.toString(), rule: T11.folded.rule},
  publicInputs: T11.publicInputs,
  provenance: {vk: 'Track 11 vkUpstream (risc0-ethereum fe5adc30 Groth16Verifier.sol, git blob 0023123c = the v3.0.1 file)',
    controlRoot: 'risc0/risc0-ethereum v3.0.1 (365e7b2d) contracts/src/groth16/ControlID.sol; risc0/risc0 v3.0.6 (1cc70cf0) risc0/circuit/recursion/src/control_id.rs',
    receipts: 'Track 11 risc0.fixtures.json (risc0-ethereum fe5adc30 contracts/test/TestReceiptV*.sol)'},
  fixtures, otherVersionReceipts: others,
};
writeFileSync(new URL('./risc0-v3.fixtures.json', import.meta.url), JSON.stringify(out, null, 1) + '\n');
console.log(`risc0-v3: control root ${ROOT.slice(0, 8)}…; ${fixtures.map((x) => x.id).join(', ')} verifies (5-input and folded); ${others.length} others do not`);
