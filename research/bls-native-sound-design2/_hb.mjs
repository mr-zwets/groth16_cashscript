import {createVirtualMachineBchSpec, encodeDataPush, bigIntToVmNumber} from '@bitauth/libauth';
import {Asm, Kernel, OP} from './asm.mjs';
import {p, mod} from './blsmath.mjs';
import {le} from './protocol.mjs';
const vm = createVirtualMachineBchSpec(false);
const W = 48, NQ = 132; const q = Array.from({length: NQ}, (_, i) => mod(BigInt(i + 7) ** 51n)); const QS = Buffer.concat(q.map((x) => le(x, W)));
const z = mod(123456789n ** 9n); const z2 = mod(z * z), z4 = mod(z2 * z2), z6 = mod(z4 * z2), z8 = mod(z4 * z4);
function build(variant, nDummy) {
  const names = ['p', ...Array.from({length: nDummy}, (_, i) => 'd' + i), 'z2', 'z4', 'z6b', 'z8', 'QS'];
  const a = new Asm(names);
  a.defLocal('P', 0, 1, (s) => s.push(p, 'p'));
  a.defLocal('RD', 1, 2, (s) => { s.push(W).op(OP.SPLIT, 2, 'w', 'rest').roll('w').pushBytes([0]).op(OP.CAT, 2, 'w0').op(OP.BIN2NUM, 1, 'v'); s.pick('v').invoke('P', ['p']).op(OP.LESSTHAN, 2, 'ok').op(OP.VERIFY, 1).roll('rest'); });
  a.push(0, 'acc');
  const body = (s) => {
    s.roll('QS').push(4 * W).op(OP.SPLIT, 2, 'Q4', 'QS').roll('Q4');
    for (let jj = 0; jj < 4; jj++) s.invoke('RD', ['q' + jj, 'Q4']);
    s.drop('Q4');
    const k = new Kernel(); const I = (n) => k.in(n), E = (n) => k.env(n);
    k.output(k.mod(k.sum(k.mul(I('acc'), E('z8')), k.mul(I('q0'), E('z6b')), k.mul(I('q1'), E('z4')), k.mul(I('q2'), E('z2')), I('q3')))); s.kernel(k, ['acc'], {iters: 300});
    s.pick('QS', 'QSc').op(OP.SIZE, 1, 'QSc', 'qs').op(OP.NIP, 2, 'qs').op(OP.NOT, 1, 'done');
  };
  if (variant === 'loop') a.loop(body); else { for (let i = 0; i < NQ / 4; i++) { const s = a; body(s); s.drop('done'); } }
  return a;
}
for (const [variant, nd] of [['loop', 0], ['loop', 100], ['unrolled', 100]]) {
  const a = build(variant, nd); const code = Uint8Array.from([...a.prologue(), ...a.code]);
  const pushes = [bigIntToVmNumber(p), ...Array.from({length: nd}, () => bigIntToVmNumber(mod(99n ** 40n))), ...[z2, z4, z6, z8].map((v) => bigIntToVmNumber(v)), QS];
  const unl = Uint8Array.from(pushes.flatMap((b) => [...encodeDataPush(b)]));
  const prog = (lock) => ({inputIndex: 0, sourceOutputs: [{lockingBytecode: lock, valueSatoshis: 1000n}], transaction: {version: 2, locktime: 0, inputs: [{outpointIndex: 0, outpointTransactionHash: new Uint8Array(32), sequenceNumber: 0, unlockingBytecode: unl}], outputs: [{lockingBytecode: Uint8Array.of(0x6a), valueSatoshis: 0n}]}});
  const b = vm.evaluate(prog(Uint8Array.of())), st = vm.evaluate(prog(code));
  let acc = 0n; for (const x of q) acc = mod(acc * z2 + x);
  console.log(variant, nd, 'op', st.metrics.operationCost - b.metrics.operationCost, 'err', st.error?.slice(0, 60), 'per word', Math.round((st.metrics.operationCost - b.metrics.operationCost) / NQ));
}
