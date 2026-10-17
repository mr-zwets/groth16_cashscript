import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {decodeAuthenticationInstructions, encodeAuthenticationInstruction} from '@bitauth/libauth';

// The checked eight-word cleanup retains words 3..6 and all lower prefixes.
// Match the whole block independently of fixed-point code-length literals.
const cleanup = Buffer.from('75547a75547a75547a75', 'hex');
const replacement = Buffer.from('577a6d716d', 'hex');
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
export function compactExecutorCleanup(stage) {
  assert.equal(sha(cleanup), '9ad51c1b25bfd6edf5ac3b81b5310b5216611653a518fc271e0154ba68ec698f');
  assert.equal(sha(replacement), 'b0d1d394d9f126e8c11dea3b3082fdfd3be6c02ab6961eb447a0fc826df980dd');
  const at = stage.indexOf(cleanup);
  assert(at >= 0 && stage.indexOf(cleanup, at + 1) === -1, 'unreviewed executor cleanup');
  let offset = 0;
  const boundaries = new Set([0]);
  for (const instruction of decodeAuthenticationInstructions(stage)) {
    offset += encodeAuthenticationInstruction(instruction).length;
    boundaries.add(offset);
  }
  assert.equal(offset, stage.length);
  assert(boundaries.has(at) && boundaries.has(at + cleanup.length));
  return Buffer.concat([stage.subarray(0, at), replacement, stage.subarray(at + cleanup.length)]);
}
