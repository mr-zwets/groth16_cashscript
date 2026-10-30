// Checks the SRS points baked into the CashVM verifier against the Aztec Ignition ceremony.
//
//   node srs-check.mjs                 # pinned ceremony [x]_2
//   SRS_CACHE=dir node srs-check.mjs   # also re-read [x]_2 from the downloaded manifest.json (sha256-pinned)
//
// The verifier uses three SRS points: [1]_1, [1]_2 and [x]_2. [1]_1 and [1]_2 are the standard BN254 generators.
// [x]_2 enters the scripts only through the fixed-G2 Miller chain of the KZG pairing: 88 baked slopes per chain
// (single input: raw slope pile pieces in the redeem; today's chain: the SHA-256 of each SI role's slope slice,
// and the affine x, y of [x]_2 and the x of psi([x]_2), pushed as script numbers by the SI code). This script
//   1. takes [x]_2 from the ceremony (pinned below; the same four words as manifest.json crs.t2 and the G2 point
//      hardcoded in Aztec's barretenberg Solidity verifiers), independently of the vectors;
//   2. checks that every VK in vectors/ (and the prover track's vectors/, if present) carries exactly
//      [1]_1, [1]_2 and that [x]_2;
//   3. recomputes the chain constants from the ceremony point, builds the single-input redeem and the
//      multi-input chain for every circuit, and checks that every constant derived from [x]_2 is in them
//      (slope pieces / slice hashes, and the minimal number pushes of x([x]_2), y([x]_2), x(psi([x]_2)));
//   4. control: the constants of a different G2 point are not in them.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {existsSync, readFileSync} from 'node:fs';
import {join} from 'node:path';
import {G1, G2, F2, mod, chainConsts} from './math.mjs';
import {parseVK, loadVectors, le32, PROVER_DIR} from './plonk.mjs';
import {buildRedeem, D_PIECE} from './script.mjs';
import {pushNum} from './asm.mjs';
import {makePlan, buildMulti, dsSlice, planOpts} from './multi.mjs';

const IGNITION_T2 = { // x.c0, x.c1, y.c0, y.c1
  x0: 0x0118c4d5b837bcc2bc89b5b398b5974e9f5944073b32078b7e231fec938883b0n,
  x1: 0x260e01b251f6f1c7e7ff4e580791dee8ea51d87a358e038b4efe30fac09383c1n,
  y0: 0x22febda3c0c0632a56475b4214e5615e11e6dd3f96e6cea2854a87d4dacc5e55n,
  y1: 0x04fc6369f7110fe3d25156c1bb9a72859cf2a04641f99ba4ee413c80da6a5fe4n,
};
const MANIFEST_SHA256 = 'd231a1defd9804721ded32c75dd6f956efbf61c254b3ebcec4bb6596ba9941b8';
const sha = (b) => createHash('sha256').update(b).digest();
const ok = (c, what) => { assert.ok(c, what); console.log('ok  ', what); };

if (process.env.SRS_CACHE) {
  const m = readFileSync(join(process.env.SRS_CACHE, 'manifest.json'));
  ok(sha(m).toString('hex') === MANIFEST_SHA256, 'manifest.json sha256 ' + MANIFEST_SHA256);
  const t2 = JSON.parse(m).crs.t2.map(BigInt);
  ok(t2.join() === [IGNITION_T2.x0, IGNITION_T2.x1, IGNITION_T2.y0, IGNITION_T2.y1].join(), 'manifest crs.t2 = pinned [x]_2');
}
const T2 = G2.fromAffine({x: F2.create({c0: IGNITION_T2.x0, c1: IGNITION_T2.x1}), y: F2.create({c0: IGNITION_T2.y0, c1: IGNITION_T2.y1})});
T2.assertValidity();
ok(true, 'ceremony [x]_2 is on the twist and in G2');

const le = (x) => le32(mod(x));
const stepBytes = (A, B, j) => Buffer.concat([A.lams[j], B.lams[j]].flatMap((l) => [le(l.c0), le(l.c1)]));
const piles = (A, B) => { const steps = Array.from({length: 88}, (_, j) => stepBytes(A, B, j)); const out = [];
  for (let i = 0; i < 88; i += D_PIECE) out.push(Buffer.concat(steps.slice(i, i + D_PIECE))); return out; };
const CA = chainConsts(G2.BASE), CB = chainConsts(T2);
const CTRL = chainConsts(G2.BASE.multiply(7n)); // control: another G2 point
// the [x]_2 point constants the SI code pushes as numbers: x and y of [x]_2 (chain start), x of psi([x]_2) (terminal)
const numPushes = (C) => [C.aff.x.c0, C.aff.x.c1, C.aff.y.c0, C.aff.y.c1, C.psi1x.c0, C.psi1x.c1].map((v) => Buffer.from(pushNum(mod(v))));

for (const name of ['mul2', 'merkle16', 'range64', 'merkle16rc']) { // v1 and BSB22 (v2-bsb22) vectors
  const V = loadVectors(name);
  const pv = join(PROVER_DIR, 'vectors', name + '.json');
  if (existsSync(pv)) ok(JSON.parse(readFileSync(pv)).vk.hex === V.vk.hex, `${name}: verifier vectors/ VK = prover track VK`);
  ok(V.srs && V.srs.unsafe === false, `${name}: vectors are marked as ceremony SRS (${V.srs?.ceremony?.slice(0, 40)}...)`);
  const vk = parseVK(V.vk.hex); // asserts [1]_1 = G1.BASE and [1]_2 = G2.BASE
  const b = Buffer.from(V.vk.hex, 'hex');
  ok(G1.fromAffine({x: BigInt('0x' + b.subarray(624, 656).toString('hex')), y: BigInt('0x' + b.subarray(656, 688).toString('hex'))}).equals(G1.BASE) && vk.g2.equals(G2.BASE), `${name}: VK [1]_1, [1]_2 = BN254 generators`);
  ok(vk.g2x.equals(T2), `${name}: VK [x]_2 = Ignition [x]_2`);

  // single input: every slope pile piece is a data push of the redeem
  const {redeem} = buildRedeem(vk);
  const R = Buffer.from(redeem);
  const pp = piles(CA, CB);
  ok(pp.every((x) => R.indexOf(x) >= 0), `${name}: single-input redeem (${R.length} B) holds all ${pp.length} slope pieces of the ceremony chain`);
  ok(piles(CA, CTRL).every((x) => R.indexOf(x) < 0), `${name}: control: no slope piece of another G2 point is in it`);
  ok(numPushes(CB).every((x) => R.indexOf(x) >= 0), `${name}: single-input redeem pushes x, y of [x]_2 and x of psi([x]_2) (6 numbers)`);
  ok(numPushes(CTRL).every((x) => R.indexOf(x) < 0), `${name}: control: none of those 6 numbers of another G2 point is in it`);

  // today's chain: each SI role checks SHA256(its slope slice) against a baked hash
  const plan = makePlan(vk, planOpts(vk, name)), built = buildMulti(vk, plan);
  const all = Buffer.concat([built.code, ...built.cb, built.redeem].map((x) => Buffer.from(x)));
  const si = plan.roles.filter((ro) => ro.kind === 'SI');
  const CH = {a: CA, b: CB}, CHc = {a: CA, b: CTRL};
  ok(si.every((ro) => all.indexOf(sha(dsSlice(CH, ro))) >= 0), `${name}: chain scripts (${all.length} B) hold SHA256 of all ${si.length} SI slope slices of the ceremony chain`);
  ok(si.every((ro) => all.indexOf(sha(dsSlice(CHc, ro))) < 0), `${name}: control: no slice hash of another G2 point is in them`);
  ok(numPushes(CB).every((x) => all.indexOf(x) >= 0), `${name}: chain scripts push x, y of [x]_2 and x of psi([x]_2) (6 numbers)`);
  ok(numPushes(CTRL).every((x) => all.indexOf(x) < 0), `${name}: control: none of those 6 numbers of another G2 point is in them`);
}
console.log('OK: the verifier\'s SRS constants are the Aztec Ignition ceremony\'s');
