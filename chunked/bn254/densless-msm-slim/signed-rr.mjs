import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';

// For canonical field inputs rr=s2-aY is congruent to s2+P-aY. The
// squared rr leaves nx canonical; the existing signed ny remainder normalizer
// yields the same canonical ny. h and nz are unchanged. The retained P stays
// in its original stack slot; only its duplicate and the rr bias addition go.
export function compactSignedRr(body) {
  assert.equal(body.length, 145, 'signed-rr MADD body length changed');
  assert.equal(createHash('sha256').update(body).digest('hex'),
    '6d5cbba716993b231aafad6de09d139ffcfa365d73a79c937e7802030bc870ef',
    'signed-rr MADD fingerprint changed');
  assert.equal(body.subarray(32, 34).toString('hex'), '7893', 'rr prime bias site changed');
  return Buffer.concat([body.subarray(0, 32), body.subarray(34)]);
}
