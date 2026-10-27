// native-bls-design1, item A9 prototype (read-only design evidence): bit-plane GT-GLS binding.
// (1) exhaustive check of the 8-byte gather (v*M) >> (56+i) mod 256 == sum_j [b_j != 0] 2^(7-j), b_j in {0, 2^i};
// (2) the bytecode below computes acc = sum_i |x|^i a_i == sum_g 2^(63-g) TB[N[g]] on random/extreme nibble strings (VM);
// (3) its op cost (standard) against the current per-byte loop (284k + TA 9k for both groups at forced:44d3).
//   node design1/binding-proto.mjs
import assert from 'node:assert/strict';
import {OP, pushNum, pushData} from '../asm.mjs';
import {createVirtualMachineBch2026} from '@bitauth/libauth';
import {txOf} from '../vm.mjs';
const AX = 0xd201000000010000n, M = 0x8040201008040201n;
// (1) exhaustive gather check
for (let i = 0; i < 4; i++) for (let pat = 0; pat < 256; pat++) {
  let v = 0n; for (let j = 0; j < 8; j++) if (pat >> j & 1) v += (1n << BigInt(i)) << BigInt(8 * j);
  const w = ((v * M) >> BigInt(56 + i)) & 255n; let want = 0n; for (let j = 0; j < 8; j++) if (pat >> j & 1) want += 1n << BigInt(7 - j);
  assert.equal(w, want);
}
// reference: acc = sum_g 2^(63-g) TB[N[g]], TB[m] = sum_{i in m} |x|^i
const TB = (m) => [0, 1, 2, 3].reduce((s, i) => s + (m >> i & 1 ? AX ** BigInt(i) : 0n), 0n);
const ref = (N) => N.reduce((s, m, g) => s + (1n << BigInt(63 - g)) * TB(m), 0n);
// bytecode: stack [n, N] -> [] (NUMEQUALVERIFY), one group
const mask = (i) => pushData(Buffer.alloc(8, 1 << i));
const block = (i) => [OP.DUP, ...mask(i), OP.AND, OP.BIN2NUM, ...pushNum(M), OP.MUL, ...pushNum(56 + i), OP.RSHIFTNUM, ...pushNum(256), OP.MOD,
  ...pushNum(5), OP.ROLL, ...pushNum(8), OP.LSHIFTNUM, OP.ADD, OP.SWAP];
const code = [
  OP.TOALT, 0x00, 0x00, 0x00, 0x00, OP.FROMALT,                  // [n, a0 a1 a2 a3, N]
  OP.BEGIN, ...pushNum(8), OP.SPLIT, OP.TOALT,                    // [.., chunk] alt [N']
  ...block(0), ...block(1), ...block(2), ...block(3), OP.DROP, OP.FROMALT, OP.DUP, OP.SIZE, OP.NIP, OP.NOT, OP.UNTIL, OP.DROP,
  // Horner: ((a3 x + a2) x + a1) x + a0
  ...pushNum(AX), OP.MUL, OP.ADD, ...pushNum(AX), OP.MUL, OP.ADD, ...pushNum(AX), OP.MUL, OP.ADD, OP.NUMEQUALVERIFY, OP.TRUE];
const vm = createVirtualMachineBch2026(true);
const rnd = (n) => Array.from({length: n}, () => Math.floor(Math.random() * 16));
const cases = [Array(64).fill(0), Array(64).fill(15), [...Array(8).fill(0), ...Array(56).fill(15)], ...Array.from({length: 20}, () => rnd(64)), Array.from({length: 64}, (_, g) => 1 << (g % 4))];
let opMax = 0;
for (const N of cases) {
  const n = ref(N); const nb = []; let x = n; while (x > 0n) { nb.push(Number(x & 255n)); x >>= 8n; } if (nb.length && nb.at(-1) & 0x80) nb.push(0);
  const unl = Uint8Array.from([...pushData(nb.length ? nb : []), ...pushData(Buffer.from(N))]);
  const ctx = txOf([unl], [Uint8Array.from(code)]);
  const st = vm.evaluate({inputIndex: 0, sourceOutputs: ctx.sourceOutputs, transaction: ctx.transaction});
  assert.equal(st.error, undefined, st.error); opMax = Math.max(opMax, st.metrics.operationCost);
  // a wrong n must fail
  const unl2 = Uint8Array.from([...pushData(nb.length ? [nb[0] ^ 1, ...nb.slice(1)] : [1]), ...pushData(Buffer.from(N))]);
  const ctx2 = txOf([unl2], [Uint8Array.from(code)]);
  assert.ok(vm.evaluate({inputIndex: 0, sourceOutputs: ctx2.sourceOutputs, transaction: ctx2.transaction}).error);
}
console.log('gather exhaustive ok; VM equality ok on', cases.length, 'nibble strings; code', code.length, 'B; op per group (max, incl. pushes of n, N and the locking overhead)', opMax);
