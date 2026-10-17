import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {decodeAuthenticationInstructions, encodeAuthenticationInstruction} from '@bitauth/libauth';

// The independently checked middle keeps the same words, guards and helper call.
// 6 PICK 7 PICK copies zInv twice; 6 PICK DUP removes only the literal 7.
const middle = Buffer.from('757b7b727c202f03e573e0e1f724ad6698787699542b23c3bfcc0275fac1c0676cde0308590120293eae6738c05eb3abeefaffb3ca7e54088b0ee1675770617fba5ed9f55b9b0753795579577902ca008a5779952047fd7cd8168c203c8dca7168916a81975d588181b64550b829a031e1724e643097519d56795779952047fd7cd8168c203c8dca7168916a81975d588181b64550b829a031e1724e64309753ca76537f75034dc00188537a5279952047fd7cd8168c203c8dca7168916a81975d588181b64550b829a031e1724e6430977802a3007f750283007f77819d7b7b577a952047fd7cd8168c203c8dca7168916a81975d588181b64550b829a031e1724e643097952047fd7cd8168c203c8dca7168916a81975d588181b64550b829a031e1724e6430977c02c3007f7502a3007f77819d0000000000', 'hex');
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
export function compactInverseCopy(stage) {
  assert.equal(sha(middle), '8fd4dc673fa737bf5343813441475970a5e342abb3ff42ca78fd2279584d9a4c');
  const at = stage.indexOf(middle);
  assert(at >= 0 && stage.indexOf(middle, at + 1) === -1, 'unreviewed terminal middle');
  let offset = 0;
  const boundaries = new Set([0]);
  for (const instruction of decodeAuthenticationInstructions(stage)) {
    offset += encodeAuthenticationInstruction(instruction).length;
    boundaries.add(offset);
  }
  assert.equal(offset, stage.length);
  for (const point of [at, at + 122, at + 124, at + middle.length]) assert(boundaries.has(point));
  assert.equal(stage.subarray(at + 120, at + 124).toString('hex'), '56795779');
  const replacement = Buffer.concat([middle.subarray(0, 122), Buffer.from([118]), middle.subarray(124)]);
  assert.equal(sha(replacement), '0fd3d151327c187631f02a59e3a43de633951edb7c5d90c245248e6843362003');
  return Buffer.concat([stage.subarray(0, at), replacement, stage.subarray(at + middle.length)]);
}
