import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';

const normal = body => body.trim().split(/\s+/).join(' ');
const sha = body => createHash('sha256').update(body).digest('hex');

// MUL is commutative before the unchanged signed remainder. Both paths still
// require two numeric words; lower main/alternate frames and all checks remain.
export function compactCommutativeMul(source) {
  const find = name => {
    const found = source.functions.filter(f => f.name === name);
    assert.equal(found.length, 1, `ambiguous shared helper ${name}`);
    return found[0];
  };
  const mul = find('sharedSequence4'), prime = find('baseFieldConstant');
  assert.equal(mul.originalId, 14, 'shared multiplication key changed');
  assert.equal(normal(mul.body), 'OP_MUL CALL baseFieldConstant OP_MOD',
    'shared multiplication ABI or checks changed');
  assert.equal(prime.originalId, 7, 'shared field constant key changed');
  assert.equal(normal(prime.body), 'NUM BASE_FIELD', 'shared field constant changed');
  const caller = find('sharedSequence3'), body = normal(caller.body);
  assert.equal(caller.originalId, 18, 'shared caller key changed');
  assert.equal(sha(body), '9a337b85905af515dfe67e978f1e7288dd02210f067efe049b72e97b262df729',
    'shared caller body changed');
  const pattern = 'OP_SWAP CALL sharedSequence4';
  assert.equal(body.split(pattern).length - 1, 1, 'shared multiplication swap site changed');
  return {...source, functions: source.functions.map(f => f === caller
    ? {...f, body: body.replace(pattern, 'CALL sharedSequence4')} : f)};
}
