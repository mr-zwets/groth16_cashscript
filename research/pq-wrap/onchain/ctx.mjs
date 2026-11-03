// CTX: the M1 public values CTX[0..4] bind a proof to the spending transaction's outputs (AIR-SPEC §3.1; the exact
// serialization is fixed here and recorded in ../prover/FORMAT.md "CTX serialization").
//
//   ser   = u32 LE output count ‖ for each output, in order:
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
import {asm} from './lib/asm.mjs';

const B0 = Uint8Array.of(0);
// script: [] -> [CTXB] (32 bytes: the four CTX lanes as the transcript observes them)
export function ctxCode() {
  return asm(
    'TXOUTPUTCOUNT', 'DUP', 4, 'NUM2BIN', 'SWAP', 0,                     // ser n i
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
export function ctxOf(outputs) {
  const h = createHash('sha256').update(serializeOutputs(outputs)).digest();
  const lanes = [0, 1, 2, 3].map((k) => { let v = 0n; for (let i = 6; i >= 0; i--) v = (v << 8n) | BigInt(h[7 * k + i]); return v; });
  return {hash: h, hex: h.toString('hex'), lanes, bytes: Buffer.concat([0, 1, 2, 3].map((k) => Buffer.concat([h.subarray(7 * k, 7 * k + 7), B0])))};
}
