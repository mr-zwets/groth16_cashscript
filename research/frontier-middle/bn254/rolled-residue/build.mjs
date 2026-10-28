// Build the T2 redeem (deterministic, twice), smoke-spend the committed proof on the budget-loosened BCH 2026 VM.
//   node build.mjs  -> redeem.hex, build.json
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {writeFileSync} from 'node:fs';
import {VEC} from './math.mjs';
import {prove} from './protocol.mjs';
import {buildRedeem} from './script.mjs';
import {p2sh32, encodeUnlocking, spend} from './vm.mjs';
const sha = (b) => createHash('sha256').update(b).digest('hex');
const b1 = buildRedeem(); const b2 = buildRedeem(); assert.deepEqual(Buffer.from(b1.redeem), Buffer.from(b2.redeem), 'deterministic build');
const redeem = Buffer.from(b1.redeem), locking = Buffer.from(p2sh32(redeem));
const w = prove({proof: VEC.proof, publicInputs: VEC.publicInputs}); const u = encodeUnlocking([w.W, redeem]);
const runs = Object.fromEntries(['consensus', 'standard'].map((m) => { const x = spend(locking, u, m); return [m, {accepted: x.accepted, opCost: x.opCost, error: x.error}]; }));
const bad = prove({proof: VEC.proof, publicInputs: VEC.invalid.publicInputs}, {forge: true}); const xb = spend(locking, encodeUnlocking([bad.W, redeem]));
const out = {redeemBytes: redeem.length, redeemSha256: sha(redeem), lockingHex: locking.toString('hex'), unlockingBytes: u.length, committed: runs, invalidInputsRejected: !xb.accepted, invalidError: xb.error,
  sections: b1.info.sections, functions: b1.info.funcs, prologue: b1.info.prologue};
writeFileSync(new URL('./redeem.hex', import.meta.url), redeem.toString('hex') + '\n');
writeFileSync(new URL('./build.json', import.meta.url), JSON.stringify(out, null, 1) + '\n');
console.log(JSON.stringify({redeem: redeem.length, sha: out.redeemSha256, unlocking: u.length, ...runs, invalidRejected: !xb.accepted, invalidError: xb.error}));
assert.ok(runs.consensus.accepted && runs.standard.accepted, 'committed proof rejected'); assert.ok(!xb.accepted, 'tampered inputs accepted');
