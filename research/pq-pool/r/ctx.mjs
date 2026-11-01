// Track 9 S2 (copy of Track 8 onchain/ctx.mjs, changed): CTX binds a proof to the spending transaction's outputs
// [1..] (DESIGN-T9 sec. 0/3: the W-state output at index 0 is excluded, so a proof does not depend on the pool state
// and a relayer can rebuild the final transaction after a race without re-proving). The serialization is Track 8's
// (../../pq-stark-batch/prover/FORMAT.md "CTX serialization") applied to the outputs 1 .. n-1 with count n - 1:
//
//   ser   = u32 LE (output count - 1) ‖ for each output 1 .. n-1, in order:
//             value          u64 LE (OP_OUTPUTVALUE)
//             category       u8 length ‖ bytes (OP_OUTPUTTOKENCATEGORY: 0, 32 or 33 bytes, capability byte included)
//             commitment     u16 LE length ‖ bytes (OP_OUTPUTTOKENCOMMITMENT)
//             token amount   u64 LE (OP_OUTPUTTOKENAMOUNT, 0 without fungible tokens)
//             locking        u32 LE length ‖ bytecode (OP_OUTPUTBYTECODE)
//   h     = SHA-256(ser)
//   CTX_k = little-endian integer of h[7k .. 7k+7), k = 0..3 (each < 2^56); the transcript observes CTX_k as u64 LE,
//           i.e. the bytes h[7k .. 7k+7) ‖ 0x00.
// Every field is fixed-length or length-prefixed, so ser is injective in the outputs' introspectable content.
import {createHash} from 'node:crypto';
import {asm} from '../../pq-stark-batch/onchain/lib/asm.mjs';

const B0 = Uint8Array.of(0);
// script: [] -> [CTXB] (32 bytes: the four CTX lanes as the transcript observes them). The loop runs at least once,
// so a transaction with one output (output 0 only) fails at OUTPUTVALUE: a withdrawal needs a payout output.
export function ctxCode() {
  return asm(
    'TXOUTPUTCOUNT', 'DUP', '1SUB', 4, 'NUM2BIN', 'SWAP', 1,             // ser n i = 1
    'BEGIN',
    'DUP', 'OUTPUTVALUE', 8, 'NUM2BIN',
    'OVER', 'OUTPUTTOKENCATEGORY', 'SIZE', 1, 'NUM2BIN', 'SWAP', 'CAT', 'CAT',
    'OVER', 'OUTPUTTOKENCOMMITMENT', 'SIZE', 2, 'NUM2BIN', 'SWAP', 'CAT', 'CAT',
    'OVER', 'OUTPUTTOKENAMOUNT', 8, 'NUM2BIN', 'CAT',
    'OVER', 'OUTPUTBYTECODE', 'SIZE', 4, 'NUM2BIN', 'SWAP', 'CAT', 'CAT', // ser n i rec
    3, 'ROLL', 'SWAP', 'CAT', 'ROT', 'ROT', '1ADD',                       // ser' n i+1
    '2DUP', 'NUMEQUAL', 'UNTIL',
    'DROP', 'DROP', 'SHA256',
    7, 'SPLIT', 7, 'SPLIT', 7, 'SPLIT', 7, 'SPLIT', 'DROP',               // h0 h1 h2 h3
    B0, 'CAT', 'SWAP', B0, 'CAT', 'SWAP', 'CAT', 'SWAP', B0, 'CAT', 'SWAP', 'CAT', 'SWAP', B0, 'CAT', 'SWAP', 'CAT',
  );
}

const u = (n, len) => { const b = Buffer.alloc(len); let v = BigInt(n); for (let i = 0; i < len; i++) { b[i] = Number(v & 0xffn); v >>= 8n; } return b; };
// the category bytes OP_OUTPUTTOKENCATEGORY pushes (libauth: token.category reversed = OP_HASH256 order, plus the
// capability byte 0x01 mutable / 0x02 minting when the NFT has one); checked against the VM in test-ctx.mjs
export function categoryBytes(token) {
  if (!token) return Buffer.alloc(0);
  const cat = Buffer.from(token.category).reverse();
  const cap = token.nft?.capability === 'mutable' ? [1] : token.nft?.capability === 'minting' ? [2] : [];
  return Buffer.concat([cat, Buffer.from(cap)]);
}
export function serializeOutputs(outputs) {
  const parts = [u(outputs.length, 4)];
  for (const o of outputs) {
    const cat = categoryBytes(o.token), com = Buffer.from(o.token?.nft?.commitment ?? []), lb = Buffer.from(o.lockingBytecode);
    parts.push(u(o.valueSatoshis, 8), u(cat.length, 1), cat, u(com.length, 2), com, u(o.token?.amount ?? 0n, 8), u(lb.length, 4), lb);
  }
  return Buffer.concat(parts);
}
// CTX of a final transaction's full output list (output 0 = the W-state output, excluded)
export const ctxOfTx = (outputs) => ctxOf(outputs.slice(1));
// CTX of the outputs [1..] given as a list (the serialization is the Track 8 one over this list)
export function ctxOf(outputs) {
  const h = createHash('sha256').update(serializeOutputs(outputs)).digest();
  const lanes = [0, 1, 2, 3].map((k) => { let v = 0n; for (let i = 6; i >= 0; i--) v = (v << 8n) | BigInt(h[7 * k + i]); return v; });
  return {hash: h, hex: h.toString('hex'), lanes, bytes: Buffer.concat([0, 1, 2, 3].map((k) => Buffer.concat([h.subarray(7 * k, 7 * k + 7), B0])))};
}
