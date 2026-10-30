// The CTX introspection block (ctx.mjs ctxCode) against the JS serialization (ctxOf) on transactions with plain
// outputs, token outputs (fungible, NFT with and without capability and commitment) and long locking bytecode.
// usage: node test-ctx.mjs   (exit 1 on a mismatch)
import {asm} from './lib/asm.mjs';
import {ctxCode, ctxOf} from './ctx.mjs';
import {evaluate, spendProgram} from './vm.mjs';

const p2pkh = (b) => Uint8Array.from([0x76, 0xa9, 0x14, ...Array(20).fill(b), 0x88, 0xac]);
const cat = (b) => Uint8Array.from(Array.from({length: 32}, (_, i) => (b + i) & 0xff));
const sets = [
  [{lockingBytecode: p2pkh(1), valueSatoshis: 99_000n}],
  [{lockingBytecode: p2pkh(2), valueSatoshis: 50_000n}, {lockingBytecode: Uint8Array.of(0x6a, 4, 1, 2, 3, 4), valueSatoshis: 0n}],
  [{lockingBytecode: p2pkh(3), valueSatoshis: 1000n, token: {category: cat(7), amount: 123456789n}},
    {lockingBytecode: p2pkh(4), valueSatoshis: 1000n, token: {category: cat(9), amount: 0n, nft: {capability: 'none', commitment: Uint8Array.of(1, 2, 3)}}},
    {lockingBytecode: p2pkh(5), valueSatoshis: 1000n, token: {category: cat(11), amount: 5n, nft: {capability: 'mutable', commitment: Uint8Array.from(Array(128).fill(0xee))}}},
    {lockingBytecode: p2pkh(6), valueSatoshis: 1000n, token: {category: cat(13), amount: 0n, nft: {capability: 'minting', commitment: Uint8Array.of()}}}],
  [{lockingBytecode: Uint8Array.from(Array(300).fill(0x51)), valueSatoshis: 2n ** 40n}],
];
let bad = 0;
for (const outs of sets) {
  const c = ctxOf(outs);
  const locking = asm({raw: ctxCode()}, Uint8Array.from(c.bytes), 'EQUAL');
  const r = evaluate('looseStd', locking, Uint8Array.of(), spendProgram(locking, Uint8Array.of(), outs));
  // the same block must not match another output set
  const other = ctxOf([...outs.slice(1), outs[0]].length > 1 ? [...outs.slice(1), outs[0]] : [{...outs[0], valueSatoshis: outs[0].valueSatoshis + 1n}]);
  const lo = asm({raw: ctxCode()}, Uint8Array.from(other.bytes), 'EQUAL');
  const r2 = evaluate('looseStd', lo, Uint8Array.of(), spendProgram(lo, Uint8Array.of(), outs));
  const ok = r.accepted && !r2.accepted;
  if (!ok) bad++;
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${outs.length} output(s): CTX ${c.lanes.map((x) => x.toString(16)).join(',')} vm ${r.accepted} ${r.error ?? ''} / other set rejected ${!r2.accepted}`);
}
console.log(`test-ctx: ${sets.length} transactions, ${bad} mismatches`);
process.exit(bad ? 1 : 0);
