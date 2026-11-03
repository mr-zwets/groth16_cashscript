// Track 11 (real keys): derive the two real BN254 Groth16 verifying keys and their published proof fixtures from the
// pinned upstream files in ./upstream (copied verbatim; provenance in ./upstream/SOURCES.md), check every proof with
// noble's pairing against the FULL upstream statement, and write the fixture files that ../sound-si-gls/math.mjs loads
// when BN_VK_FIXTURES points at them.
//
//   node extract.mjs        -> writes sp1-v5.fixtures.json, risc0.fixtures.json (deterministic)
//
// SP1 v5 (sp1-contracts v5.0.0 Groth16Verifier.sol + SP1VerifierGroth16.sol): plain gnark Groth16, 2 public inputs
//   [programVKey, sha256(publicValues) & (2^253 - 1)], each required < r by publicInputMSM. The contract stores
//   -beta, -gamma, -delta (BETA_NEG_*, ...); we negate back. Proof = 4-byte selector ‖ uint256[8]
//   (A.x, A.y, B.x.c1, B.x.c0, B.y.c1, B.y.c0, C.x, C.y), EIP-197 order (imaginary part first).
// RISC Zero (risc0-ethereum Groth16Verifier.sol + ControlID.sol + RiscZeroGroth16Verifier.sol): snarkjs Groth16 with
//   5 public inputs [CONTROL_ROOT_0, CONTROL_ROOT_1, claim0, claim1, BN254_CONTROL_ID]. Three of them are constants of
//   the deployed verifier (control root halves, bn254 control id), so we fold them into the constant term:
//     IC0' = IC0 + cr0·IC1 + cr1·IC2 + id·IC5,  IC' = [IC0', IC3, IC4],  public inputs (claim0, claim1).
//   This is exactly the 5-input statement with those three inputs fixed (vk_x is linear in the inputs), and it is
//   checked below by verifying every receipt both ways (5-input upstream statement and 2-input folded statement).
import assert from 'node:assert/strict';
import {readFileSync, writeFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {bn254} from '@noble/curves/bn254.js';
import * as CL from './claims.mjs';

const U = (f) => readFileSync(new URL('./upstream/' + f, import.meta.url), 'utf8');
const sha = (b) => createHash('sha256').update(b).digest();
const {Fp, Fr, Fp2} = bn254.fields; const p = Fp.ORDER, r = Fr.ORDER;
const G1 = bn254.G1.Point, G2 = bn254.G2.Point;
const consts = (src) => Object.fromEntries([...src.matchAll(/uint256 constant (\w+) = (0x[0-9a-fA-F]+|\d+);/g)].map(([, k, v]) => [k, BigInt(v)]));
const g1 = (x, y) => G1.fromAffine({x, y});
const g2 = (x0, x1, y0, y1) => G2.fromAffine({x: Fp2.fromBigTuple([x0, x1]), y: Fp2.fromBigTuple([y0, y1])});
const js1 = (P) => { const a = P.toAffine(); return {x: a.x.toString(), y: a.y.toString()}; };
const js2 = (P) => { const a = P.toAffine(); return {x: {c0: a.x.c0.toString(), c1: a.x.c1.toString()}, y: {c0: a.y.c0.toString(), c1: a.y.c1.toString()}}; };
const words = (hex) => { assert.equal(hex.length % 64, 0); return Array.from({length: hex.length / 64}, (_, i) => BigInt('0x' + hex.slice(64 * i, 64 * i + 64))); };
// Groth16: e(A, B) = e(alpha, beta) e(vk_x, gamma) e(C, delta), vk_x = IC0 + sum x_i IC_{i+1}; inputs must be < r
const groth16 = (vk, inputs, A, B, C) => {
  assert.equal(inputs.length + 1, vk.ic.length);
  if (!inputs.every((x) => x >= 0n && x < r)) return false;
  let vx = vk.ic[0]; inputs.forEach((x, i) => { if (x) vx = vx.add(vk.ic[i + 1].multiply(x)); });
  const F12 = bn254.fields.Fp12;
  const lhs = bn254.pairing(A, B), rhs = F12.mul(F12.mul(bn254.pairing(vk.alpha, vk.beta), bn254.pairing(vx, vk.gamma)), bn254.pairing(C, vk.delta));
  return F12.eql(lhs, rhs);
};
const vkJson = (vk) => ({alpha: js1(vk.alpha), beta: js2(vk.beta), gamma: js2(vk.gamma), delta: js2(vk.delta), ic: vk.ic.map(js1)});
const proofJson = (A, B, C) => ({a: js1(A), b: js2(B), c: js1(C)});
const vkDigest = (j) => sha(JSON.stringify(j)).toString('hex');

// ---------------------------------------------------------------- SP1 v5 ----------------------------------------------
const sp1Src = U('sp1-v5.0.0-Groth16Verifier.sol'), sp1Wrap = U('sp1-v5.0.0-SP1VerifierGroth16.sol');
const S = consts(sp1Src);
assert.equal(S.P, p); assert.equal(S.R, r);
const SELECTOR = sp1Wrap.match(/return 0x([0-9a-f]{64});/)[1].slice(0, 8); assert.equal(SELECTOR, 'a4594c59');
const sp1Vk = {
  alpha: g1(S.ALPHA_X, S.ALPHA_Y),
  beta: g2(S.BETA_NEG_X_0, S.BETA_NEG_X_1, S.BETA_NEG_Y_0, S.BETA_NEG_Y_1).negate(),
  gamma: g2(S.GAMMA_NEG_X_0, S.GAMMA_NEG_X_1, S.GAMMA_NEG_Y_0, S.GAMMA_NEG_Y_1).negate(),
  delta: g2(S.DELTA_NEG_X_0, S.DELTA_NEG_X_1, S.DELTA_NEG_Y_0, S.DELTA_NEG_Y_1).negate(),
  ic: [g1(S.CONSTANT_X, S.CONSTANT_Y), g1(S.PUB_0_X, S.PUB_0_Y), g1(S.PUB_1_X, S.PUB_1_Y)],
};
const MASK253 = (1n << 253n) - 1n;
const sp1Digest = (pv) => BigInt('0x' + sha(pv).toString('hex')) & MASK253; // hashPublicValues
// published SP1 v5 Groth16 proofs (4-byte selector a4594c59): [id, source, programVKey hex, publicValues hex, proof hex]
const grab = (src, re) => { const m = src.match(re); assert.ok(m, 'pattern ' + re); return m[1]; };
const sil = U('sp1-fixture-silvana-lib.rs'), spa = JSON.parse(U('sp1-fixture-sparsity-gcp_proof.json')), pes = U('sp1-fixture-pessina-TransferForm.tsx');
const SP1_RAW = [
  ['silvana-add', 'SilvanaOne/zk-tests@c2ec296b580ff54df71c7f81970cd329358edeec packages/sp1/add/arbitrum/src/lib.rs (test_groth16_verifier_directly)',
    grab(sil, /let vkey_hex = "0x([0-9a-f]{64})"/), grab(sil, /let public_values_hex = "([0-9a-f]+)"/), grab(sil, /let proof_hex = "([0-9a-f]+)"/)],
  ['sparsity-tdx-gcp', 'sparsity-xyz/zkp-tee-tutorial@33117da00d8cbfbab5df3ebac1df3ffeb73354c7 modules/02-tdx-gcp/gcp_proof.json',
    spa.program_id, spa.journal, spa.proof],
  ['pessina-solana-aa', 'Pessina/hackathon@d5f08571088dec1f4c4cfee2182e322e6a736f26 zk-solana-aa-client/components/TransferForm.tsx (proofResult)',
    grab(pes, /verification_key:\s*"0x([0-9a-f]{64})"/), grab(pes, /public_outputs_bytes:\s*"([0-9a-f]+)"/), grab(pes, /proof:\s*"([0-9a-f]+)"/)],
];
const sp1Proof = (hex) => {
  assert.equal(hex.slice(0, 8), SELECTOR, 'SP1 v5 selector'); const w = words(hex.slice(8)); assert.equal(w.length, 8);
  return {A: g1(w[0], w[1]), B: g2(w[3], w[2], w[5], w[4]), C: g1(w[6], w[7])};
};
const sp1Fixtures = SP1_RAW.map(([id, source, vkey, pvHex, proofHex], i) => {
  const {A, B, C} = sp1Proof(proofHex); const n0 = BigInt('0x' + vkey), n1 = sp1Digest(Buffer.from(pvHex, 'hex'));
  assert.ok(n0 < r && n1 < r); assert.deepEqual(CL.sp1Inputs(vkey, Buffer.from(pvHex, 'hex')), [n0, n1], 'claims.mjs agrees');
  assert.ok(groth16(sp1Vk, [n0, n1], A, B, C), `${id}: verifies under the SP1 v5 VK`);
  assert.ok(!groth16(sp1Vk, [n1, n0], A, B, C), `${id}: swapped inputs must fail`);
  return {fixture: i, id, source, programVKey: '0x' + vkey, publicValuesHex: pvHex, proofHex,
    publicInputs: [n0.toString(), n1.toString()], proof: proofJson(A, B, C)};
});
const sp1Vkj = vkJson(sp1Vk);
writeFileSync(new URL('./sp1-v5.fixtures.json', import.meta.url), JSON.stringify({
  system: 'SP1 v5.0.0 Groth16 (gnark), verifier hash 0xa4594c59bbc142f3b81c3ecb7f50a7c34bc9af7c4c444b5d48b795427e285913',
  vk: sp1Vkj, vkJsonSha256: vkDigest(sp1Vkj),
  publicInputs: ['n0 = uint256(programVKey)', 'n1 = uint256(sha256(publicValues)) & (2^253 - 1)'],
  provenance: {vk: 'succinctlabs/sp1-contracts@512b5e029abc27f6e46a3c7eba220dac83ecc306 contracts/src/v5.0.0/Groth16Verifier.sol (BETA/GAMMA/DELTA stored negated; negated back here)',
    wrapper: 'contracts/src/v5.0.0/SP1VerifierGroth16.sol (same commit): selector, hashPublicValues, inputs order'},
  fixtures: sp1Fixtures,
}, null, 1) + '\n');
console.log(`SP1 v5: ${sp1Fixtures.length} published proofs verify (noble), vk json sha256 ${vkDigest(sp1Vkj).slice(0, 16)}`);

// ---------------------------------------------------------------- RISC Zero -------------------------------------------
const rzSrc = U('risc0-Groth16Verifier.sol'), rzCtl = U('risc0-ControlID.sol');
const Z = consts(rzSrc); assert.equal(Z.r, r); assert.equal(Z.q, p);
// snarkjs constants: x1 = imaginary (c1), x2 = real (c0); checked by the receipts below (exactly one orientation verifies)
const rzVk = {alpha: g1(Z.alphax, Z.alphay), beta: g2(Z.betax2, Z.betax1, Z.betay2, Z.betay1), gamma: g2(Z.gammax2, Z.gammax1, Z.gammay2, Z.gammay1),
  delta: g2(Z.deltax2, Z.deltax1, Z.deltay2, Z.deltay1), ic: [0, 1, 2, 3, 4, 5].map((i) => g1(Z[`IC${i}x`], Z[`IC${i}y`]))};
// SP1 v5 and RISC Zero share alpha, beta, gamma (both from public ceremonies' common part?): recorded, not relied on
const shared = ['alpha', 'beta', 'gamma', 'delta'].filter((k) => rzVk[k].equals(sp1Vk[k]));
const hex32 = (name) => grab(rzCtl, new RegExp(name + ' = hex"([0-9a-f]{64})"'));
const CONTROL_ROOT = Buffer.from(hex32('CONTROL_ROOT'), 'hex'), BN254_CONTROL_ID = BigInt('0x' + hex32('BN254_CONTROL_ID'));
const le = (b) => BigInt('0x' + Buffer.from(b).reverse().toString('hex'));
// splitDigest(d): reversed = byteswap(d); (low 128 bits, high 128 bits) = (LE(d[0:16]), LE(d[16:32]))
const split = (d) => [le(d.subarray(0, 16)), le(d.subarray(16, 32))];
const [CR0, CR1] = split(CONTROL_ROOT);
// ReceiptClaimLib.ok(imageId, journalDigest).digest()
const tag = (s) => sha(Buffer.from(s));
const u16be = (v) => Buffer.from([v >> 8, v & 255]);
const outputDigest = (jd) => sha(Buffer.concat([tag('risc0.Output'), jd, Buffer.alloc(32), Buffer.from([2, 0])]));
const SYSTEM_STATE_ZERO = Buffer.from('a3acc27117418996340b84e5a90f3ef4c49d22c79e44aad822ec9c313e1eb8e2', 'hex');
assert.deepEqual(sha(Buffer.concat([tag('risc0.SystemState'), Buffer.alloc(32), Buffer.alloc(4), Buffer.from([1, 0])])), SYSTEM_STATE_ZERO);
const claimDigest = (imageId, journal) => sha(Buffer.concat([tag('risc0.ReceiptClaim'), Buffer.alloc(32), imageId, SYSTEM_STATE_ZERO,
  outputDigest(sha(journal)), Buffer.alloc(4), Buffer.alloc(4), Buffer.from([4, 0])]));
const seal = (hex) => { const w = words(hex.slice(8)); assert.equal(w.length, 8); return {sel: hex.slice(0, 8), A: g1(w[0], w[1]), B: g2(w[3], w[2], w[5], w[4]), C: g1(w[6], w[7])}; };
const receipt = (v) => { const s = U(`risc0-TestReceiptV${v}.sol`);
  return {v, seal: grab(s, /SEAL =\s*hex"([0-9a-f]+)"/), journal: grab(s, /JOURNAL = hex"([0-9a-f]*)"/), imageId: grab(s, /IMAGE_ID = hex"([0-9a-f]{64})"/)}; };
const fold = (cr0, cr1, id) => { let k = rzVk.ic[0].add(rzVk.ic[1].multiply(cr0)).add(rzVk.ic[2].multiply(cr1)).add(rzVk.ic[5].multiply(id)); return k; };
const rzFolded = {...rzVk, ic: [fold(CR0, CR1, BN254_CONTROL_ID), rzVk.ic[3], rzVk.ic[4]]};
// risc0-ethereum contracts/src/groth16/ControlID.sol history (git log; BN254_CONTROL_ID unchanged throughout): [commit, CONTROL_ROOT]
const CONTROL_ROOT_HISTORY = [
  ['0dd148c38b7f40a5a49616b1eb71f05cc143f0da', 'b1f64013f70bbb386a8b3a3d63552c5cb5ea4a549ec7fb1ecc2a031dbf488167'],
  ['bd83fe1faba644e331123e199eed0babcdf396e9', 'ab0e9172f4306b6a3b2250055036565c2421683b39ee6c20366d17350756ad19'],
  ['422836247c0a1c0b21e10051977a26bb71888cb0', 'eaa9781258978a50eedc56067be88673133e41277ab2fa3ed477e7598886413b'],
  ['deee1b774b34b29244b27c5f107228f996293e5c', 'c9cd2d004642e46838bdef0c4f426d2608af844fd193ee594658ce5947faa218'],
  ['274eccaf5dcfa825eb3e1c6ad3292b6adc7b84bb', 'a54dc85ac99f851c92d7c96d7318af41dbe7c0194edfcc37eb4d422a998c1f56'],
  ['6c4fb31378a393d6c3de66f78a4f36b9c9deaba2', 'ce52bf56033842021af3cf6db8a50d1b7535c125a34f1a22c6fdcf002c5a1529'],
  ['dc9d181c15a1a83c1298cce9a67203a21162dd5e', '884389273e128b32475b334dec75ee619b77cb33d41c332021fe7e44c746ee60'],
  ['90877d9a2e8cac579ef137296380b1a6af817871', '539032186827b06719244873b17b2d4c122e2d02cfb1994fe958b2523b844576'],
  ['b469761b70c04eaad57f872de5b4b0db8f708bed', 'f709b76b730c1d31d748c9763745482e8e37f256c07b5e5682d1a45b76746519'],
  ['eef3265ec9750d0e87c0801d0f7fbf7d36b4d5c0', '1193543e87956d31c39a87145e84332461dab71dc450b74507381f2d18e43447'],
  ['fea5f5d76d92fc2949282e8b7447eb330c38d9ae', '91d639615549c55dc491e60a5c3d9d301c364549c3372023fddbf406202af45b'],
  ['bc08c4e43c819e65030de29f718b610d69d6af3f', 'd640cb16af201a715881c24d3e884718d56fa752fb5da55f2547f5295403d650'],
];
assert.equal(CONTROL_ROOT_HISTORY[0][1], CONTROL_ROOT.toString('hex'));
const rzFixtures = [], rzOther = [];
for (const v of ['5_0', '3_0', '2_2', '2_1', '2_0']) {
  const rc = receipt(v); const {A, B, C, sel} = seal(rc.seal);
  const cd = claimDigest(Buffer.from(rc.imageId, 'hex'), Buffer.from(rc.journal, 'hex')); const [c0, c1] = split(cd);
  assert.deepEqual(CL.risc0Inputs(rc.imageId, Buffer.from(rc.journal, 'hex')), [c0, c1], 'claims.mjs agrees');
  const full = groth16(rzVk, [CR0, CR1, c0, c1, BN254_CONTROL_ID], A, B, C), folded = groth16(rzFolded, [c0, c1], A, B, C);
  assert.equal(full, folded, `receipt V${v}: 5-input and folded verdicts agree`);
  const entry = {id: `risc0-test-receipt-V${v}`, source: `risc0/risc0-ethereum@fe5adc304262eec32986246a29e46c9a250cd7e9 contracts/test/TestReceiptV${v}.sol`,
    selector: sel, imageId: rc.imageId, journalHex: rc.journal, claimDigest: cd.toString('hex'),
    publicInputs: [c0.toString(), c1.toString()], proof: proofJson(A, B, C), verifiesUnderPinnedControlRoot: full};
  if (!full) { // which historical risc0-ethereum ControlID.sol does this receipt belong to? (same Groth16 VK, other control root)
    const hit = CONTROL_ROOT_HISTORY.find(([, root]) => { const [h0, h1] = split(Buffer.from(root, 'hex')); return groth16(rzVk, [h0, h1, c0, c1, BN254_CONTROL_ID], A, B, C); });
    entry.verifiesUnderControlRoot = hit ? {commit: hit[0], controlRoot: hit[1]} : null; }
  if (full) rzFixtures.push({fixture: rzFixtures.length, ...entry}); else rzOther.push(entry);
}
assert.ok(rzFixtures.length >= 1, 'the current test receipt verifies under the pinned control root');
assert.ok(!groth16(rzFolded, [BigInt(rzFixtures[0].publicInputs[1]), BigInt(rzFixtures[0].publicInputs[0])], ...['a', 'b', 'c'].map((k) => k === 'b' ? g2(...['x', 'y'].flatMap((c) => [BigInt(rzFixtures[0].proof.b[c].c0), BigInt(rzFixtures[0].proof.b[c].c1)])) : g1(BigInt(rzFixtures[0].proof[k].x), BigInt(rzFixtures[0].proof[k].y)))), 'swapped claim halves fail');
const rzVkj = vkJson(rzFolded);
writeFileSync(new URL('./risc0.fixtures.json', import.meta.url), JSON.stringify({
  system: 'RISC Zero Groth16 receipt verifier (risc0-ethereum RiscZeroGroth16Verifier VERSION 5.0.0-rc.1), control root and BN254 control id folded into IC0',
  vk: rzVkj, vkJsonSha256: vkDigest(rzVkj),
  vkUpstream: vkJson(rzVk),
  folded: {CONTROL_ROOT: CONTROL_ROOT.toString('hex'), CONTROL_ROOT_0: CR0.toString(), CONTROL_ROOT_1: CR1.toString(), BN254_CONTROL_ID: BN254_CONTROL_ID.toString(),
    rule: "IC0' = IC0 + CONTROL_ROOT_0·IC1 + CONTROL_ROOT_1·IC2 + BN254_CONTROL_ID·IC5; IC' = [IC0', IC3, IC4]"},
  publicInputs: ['n0 = claim0 = LE(claimDigest[0:16])', 'n1 = claim1 = LE(claimDigest[16:32])', 'claimDigest = ReceiptClaimLib.ok(imageId, sha256(journal)).digest()'],
  sharedWithSp1V5: shared,
  provenance: {vk: 'risc0/risc0-ethereum@fe5adc304262eec32986246a29e46c9a250cd7e9 contracts/src/groth16/Groth16Verifier.sol',
    controlId: 'same commit, contracts/src/groth16/ControlID.sol (last changed in 0dd148c38b7f40a5a49616b1eb71f05cc143f0da, 2026-01-23)',
    wrapper: 'contracts/src/groth16/RiscZeroGroth16Verifier.sol (splitDigest, input order)', receipts: 'contracts/test/TestReceiptV*.sol'},
  fixtures: rzFixtures, otherVersionReceipts: rzOther,
}, null, 1) + '\n');
console.log(`RISC Zero: ${rzFixtures.length} receipt(s) verify under the pinned control root (both 5-input and folded); ${rzOther.length} older receipts do not (${rzOther.map((x) => x.id + (x.verifiesUnderControlRoot ? ' [valid under ' + x.verifiesUnderControlRoot.commit.slice(0, 8) + ']' : ' [no listed root]')).join(', ')}); shared VK parts with SP1 v5: ${shared.join(', ') || 'none'}`);
