// Track 9 S1: the SMT library in CashVM script and the W-state covenant (DESIGN-T9 sec. 1-3), static history.
//
// smtCode():      [S B L K8] -> [O N]   S = non-Z siblings (level 0 first), B = 8 B bitmap, L = the lowest set bit
//                 of B (64 if B = 0; a witness, checked), K8 = 8 B key; O = the root with K's leaf = Z (absence),
//                 N = the root with K's leaf = ONE (after insert). Two 2026 loops over the 64 levels:
//                   A (levels 0..L-1): every sibling is Z, so O stays Z and only N is hashed (with Z);
//                   B (levels L..63):  the sibling is the next 32 B of S if its bitmap bit is set, else Z; O and N
//                                      are both hashed (O != Z from level L on, so H = SHA-256 there).
//                 Checks: K8 and B are 8 B; 0 <= L <= 64 and L is exactly the number of trailing zero bits of
//                 B + 2^64; a sent sibling is not Z; every bit of B and every byte of S is used.
// ringCode():     4 unrolled levels: ROOT, slot, 128 B of siblings -> histRoot candidate.
// buildW(params): the W-state redeem script (P2SH32). Withdraw branch (S1) below; S4 adds the flush branch
//   (flushBranch, taken when W's unlocking holds the redeem only). The withdraw branch:
//   1. graph: TXINPUTCOUNT = nIn, INPUTINDEX = wIdx, SHA-256(input 0's locking) = HR (R, the verifier's P2S locking)
//   2. own token: category = CAT || 0x01 (mutable); commitment = 0x57 || nfRoot || histRoot || epoch
//   3. reads HEAD's unlocking (input 0) with OP_INPUTBYTECODE: its last pushes are the fixed tail `tail` (default
//      ROOT, NF, CTXW, 32 B each); every push header is checked (0x20). Minimal pushes are consensus and R checks
//      every HEAD item's size, so this suffix is exactly those items.
//   4. ROOT != Z and ROOT is slot `slot` (0..15) of the ring committed by histRoot (4 siblings, 128 B)
//   5. SMT: K = SHA-256("t9NF" || NF)[0..8); O must equal nfRoot (NF absent); N is the new nfRoot
//   6. output 0: same locking (P2SH32 of this redeem), category CAT || 0x01, no fungible amount, commitment
//      0x57 || N || histRoot || epoch (copied bytes), value = own value - D
// W unlocking (bottom first): S, B, L, HS (128 B), slot, redeem.
// With S2's R not yet built, the tests use a stand-in R (stubR) that only checks the sizes of its three pushes.
import {asm, Stk} from '../p2/lib/asm.mjs';
import {NF_TAG} from './smt.mjs';

const B01 = Uint8Array.of(1);
const ZERO32 = [0, 32, 'NUM2BIN'];
const ONE32 = [1, 32, 'NUM2BIN'];

// [S B L K8] -> [O N]
export function smtCode() {
  return asm(
    'SIZE', 8, 'NUMEQUALVERIFY', B01, 'CAT', 'BIN2NUM',          // S B L K      K = K8 + 2^64 (sentinel)
    'ROT', 'SIZE', 8, 'NUMEQUALVERIFY', B01, 'CAT', 'BIN2NUM',   // S L K X      X = B + 2^64
    'ROT',                                                       // S K X L
    'DUP', 0, 65, 'WITHIN', 'VERIFY',
    '2DUP', 'RSHIFTNUM', 'DUP', 2, 'MOD', 'VERIFY',              // S K X L Xr   Xr = X >> L is odd
    '2DUP', 'SWAP', 'LSHIFTNUM', 3, 'ROLL', 'NUMEQUALVERIFY',    // S K L Xr     Xr << L = X
    'ROT', 'ROT', ZERO32, 'ROT', ONE32, 3, 'ROLL',               // S Xr Z K N L
    // loop A: L levels, sibling Z, N only
    'DUP', 'IF',
    'BEGIN',                                                     // .. Z K N c
    '1SUB', 'ROT', 'DUP', 2, 'DIV', 'SWAP', 2, 'MOD',            // .. Z N c' K' d
    3, 'ROLL', 4, 'PICK', 'ROT', 'IF', 'SWAP', 'ENDIF', 'CAT', 'SHA256', // .. Z c' K' N'
    'ROT', 'DUP', 'NOT', 'UNTIL',                                // .. Z K' N' c'
    'ENDIF', 'DROP',                                             // S Xr Z K N
    2, 'PICK', 'SWAP', 5, 'ROLL', 5, 'ROLL',                     // Z K O N S Br    (O = Z, Br = Xr)
    // loop B: levels L..63 (none if L = 64)
    4, 'PICK', 1, 'NUMNOTEQUAL', 'IF',
    'BEGIN',
    'DUP', 2, 'MOD', 32, 'MUL', 'ROT', 'SWAP', 'SPLIT',          // Z K O N B taken S'
    'ROT', 2, 'DIV', 'TOALTSTACK', 'TOALTSTACK',                 // Z K O N taken     alt: B' S'
    'DUP', 5, 'PICK', 'EQUAL', 'NOT', 'VERIFY',                  // a sent sibling is not Z
    4, 'PICK', 'CAT', 32, 'SPLIT', 'DROP',                       // Z K O N sib       (taken, or Z if none)
    3, 'ROLL', 'DUP', 2, 'DIV', 'TOALTSTACK', 2, 'MOD',          // Z O N sib d       alt: B' S' K'
    'IF', 'TUCK', 'SWAP', 'CAT', 'SHA256', 'ROT', 'ROT', 'SWAP', 'CAT', 'SHA256',  // Z N' O'  (sib on the left)
    'ELSE', 'TUCK', 'CAT', 'SHA256', 'ROT', 'ROT', 'CAT', 'SHA256',                // Z N' O'  (sib on the right)
    'ENDIF',
    'SWAP', 'FROMALTSTACK', 'ROT', 'ROT', 'FROMALTSTACK', 'FROMALTSTACK',           // Z K' O' N' S' B'
    4, 'PICK', 1, 'NUMEQUAL', 'UNTIL',
    'ENDIF',
    1, 'NUMEQUALVERIFY', 0, 'EQUALVERIFY',                       // every bit of B and byte of S used
    'ROT', 1, 'NUMEQUALVERIFY', 'ROT', 'DROP',                   // O N    (64 levels: K = 1)
  );
}

export const DEFAULT_TAIL = [['ROOT', 32], ['NF', 32], ['CTXW', 32]];
export const D_DEFAULT = 1_000_000n;   // DESIGN-T9 maintainer decision 7: D = 0.01 BCH

export const FEE_DEFAULT = 10_000n, BATCH = 16;   // Track 9 S4: flush fee f per deposit (regtest), 2^k = 16

// Track 9 S4: the flush branch (W's unlocking is the redeem only, DEPTH 0). W is input 1 of a flush; input 0 must be
// the real D (category CAT || 0x01, commitment prefix 0x44) and output 0's value must be D's value - 16 (D + f),
// which only D's flush branch allows (D's deposit branch adds D + f; D has no other branch). D's flush code checks
// the ring update (histRoot', epoch + 1) of output 1. W checks its own output 1 as well: its locking, CAT || 0x01,
// no fungible amount, prefix 0x57 and nfRoot unchanged, value = own + 16 D.
function flushBranch(CAT01, D, FEE) {
  return asm(
    'INPUTINDEX', 1, 'NUMEQUALVERIFY',
    'INPUTINDEX', 'UTXOTOKENCATEGORY', CAT01, 'EQUALVERIFY',
    0, 'UTXOTOKENCATEGORY', CAT01, 'EQUALVERIFY',
    0, 'UTXOTOKENCOMMITMENT', 1, 'SPLIT', 'DROP', Uint8Array.of(0x44), 'EQUALVERIFY',
    0, 'OUTPUTVALUE', 0, 'UTXOVALUE', BigInt(BATCH) * (D + FEE), 'SUB', 'NUMEQUALVERIFY',
    1, 'OUTPUTBYTECODE', 'INPUTINDEX', 'UTXOBYTECODE', 'EQUALVERIFY',
    1, 'OUTPUTTOKENCATEGORY', CAT01, 'EQUALVERIFY',
    1, 'OUTPUTTOKENAMOUNT', 0, 'NUMEQUALVERIFY',
    1, 'OUTPUTTOKENCOMMITMENT', 33, 'SPLIT', 'DROP', 'INPUTINDEX', 'UTXOTOKENCOMMITMENT', 33, 'SPLIT', 'DROP', 'EQUALVERIFY',
    1, 'OUTPUTVALUE', 'INPUTINDEX', 'UTXOVALUE', BigInt(BATCH) * D, 'ADD', 'NUMEQUAL');
}

// params: {HR (32 B), CAT (32 B, internal order), D, nIn, wIdx, tail, FEE, flush (default true: the S4 flush branch)}
export function buildW({HR, CAT, D = D_DEFAULT, nIn = 2, wIdx = 1, tail = DEFAULT_TAIL, FEE = FEE_DEFAULT, flush = true}) {
  if (HR.length !== 32 || CAT.length !== 32) throw new Error('HR and CAT are 32 B');
  if (wIdx === 0) throw new Error('input 0 is HEAD');
  const CAT01 = Uint8Array.from([...CAT, 1]);
  const s = new Stk(['S', 'B', 'L', 'HS', 'slot']);
  // 1. graph
  s.emit('TXINPUTCOUNT', nIn, 'NUMEQUALVERIFY', 'INPUTINDEX', wIdx, 'NUMEQUALVERIFY',
    0, 'UTXOBYTECODE', 'SHA256', Uint8Array.from(HR), 'EQUALVERIFY');
  // 2. own token
  s.emit('INPUTINDEX', 'UTXOTOKENCATEGORY', CAT01, 'EQUALVERIFY');
  s.raw(['INPUTINDEX', 'UTXOTOKENCOMMITMENT', 1, 'SPLIT', 'SWAP', Uint8Array.of(0x57), 'EQUALVERIFY', 32, 'SPLIT'], 0, ['nfRoot', 'rest']);
  // 3. HEAD tail
  const tailLen = tail.reduce((a, [, len]) => a + len + 1, 0);
  if (tail.some(([, len]) => len < 1 || len > 75)) throw new Error('tail items are 1..75 B (one-byte push headers)');
  s.raw([0, 'INPUTBYTECODE', 'SIZE', tailLen, 'SUB', 'SPLIT', 'NIP'], 0, ['tail']);
  tail.forEach(([name, len], i) => {
    const last = i === tail.length - 1;
    s.raw([1, 'SPLIT', 'SWAP', Uint8Array.of(len), 'EQUALVERIFY'], 1, [last ? name : 'tail']);
    if (!last) s.raw([len, 'SPLIT'], 1, [name, 'tail']);
  });
  for (const [name] of tail) if (name !== 'ROOT' && name !== 'NF') s.drop(name);
  // 4. ring
  s.pick('ROOT'); s.raw([ZERO32, 'EQUAL', 'NOT', 'VERIFY'], 1);
  s.pick('slot'); s.raw([0, 16, 'WITHIN', 'VERIFY'], 1);
  s.pick('HS'); s.raw(['SIZE', 'NIP', 128, 'NUMEQUALVERIFY'], 1);
  s.roll('ROOT'); s.rename('ROOT', 'node');
  for (let l = 0; l < 4; l++) {
    s.roll('HS'); s.raw([32, 'SPLIT', 'SWAP'], 1, ['HS', 'sib']);
    s.roll('slot'); s.raw(['DUP', 2, 'DIV', 'SWAP', 2, 'MOD'], 1, ['slot', 'bit']);
    s.roll('node'); s.roll('sib'); s.roll('bit');
    s.raw(['IF', 'SWAP', 'ENDIF', 'CAT', 'SHA256'], 3, ['node']);
  }
  s.drop('HS'); s.drop('slot');   // HS is empty (128 B checked), slot' = 0 (0 <= slot < 16)
  s.pick('rest'); s.raw([32, 'SPLIT', 'DROP'], 1, ['histRoot']);
  s.roll('node'); s.raw(['EQUALVERIFY'], 2);
  // 5. SMT
  s.roll('NF'); s.raw([Uint8Array.from(NF_TAG), 'SWAP', 'CAT', 'SHA256', 8, 'SPLIT', 'DROP'], 1, ['K8']);
  s.roll('S'); s.roll('B'); s.roll('L'); s.roll('K8');
  s.raw([{raw: smtCode()}], 4, ['O', 'N']);
  s.roll('O'); s.roll('nfRoot'); s.raw(['EQUALVERIFY'], 2);
  // 6. output 0
  s.emit(0, 'OUTPUTBYTECODE', 'INPUTINDEX', 'UTXOBYTECODE', 'EQUALVERIFY');
  s.emit(0, 'OUTPUTTOKENCATEGORY', CAT01, 'EQUALVERIFY');
  s.emit(0, 'OUTPUTTOKENAMOUNT', 0, 'NUMEQUALVERIFY');
  if (s.st.join() !== 'rest,N') throw new Error('W: expected rest,N; got ' + s.st.join());
  s.raw([Uint8Array.of(0x57), 'SWAP', 'CAT', 'SWAP', 'CAT', 0, 'OUTPUTTOKENCOMMITMENT', 'EQUALVERIFY'], 2);
  if (s.st.length) throw new Error('W: stack not empty: ' + s.st.join(','));
  s.emit(0, 'OUTPUTVALUE', 'INPUTINDEX', 'UTXOVALUE', BigInt(D), 'SUB', 'NUMEQUAL');
  if (!flush) return s.bytes();
  return asm('DEPTH', 0, 'NUMEQUAL', 'IF', {raw: flushBranch(CAT01, BigInt(D), BigInt(FEE))}, 'ELSE', {raw: s.bytes()}, 'ENDIF');
}

// test stand-in for S2's R (P2S): three pushes of 32 B (ROOT, NF, CTXW), sizes checked, nothing else
export function stubR() {
  return asm('DEPTH', 3, 'NUMEQUALVERIFY', 'SIZE', 32, 'NUMEQUALVERIFY', 'DROP', 'SIZE', 32, 'NUMEQUALVERIFY', 'DROP',
    'SIZE', 32, 'NUMEQUALVERIFY', 'DROP', 1);
}

// SMT library harness (locking): unlocking pushes nfRoot newRoot S B L K8; accepts iff O = nfRoot and N = newRoot
export function smtHarness() { return asm({raw: smtCode()}, 'ROT', 'EQUALVERIFY', 'EQUAL'); }
