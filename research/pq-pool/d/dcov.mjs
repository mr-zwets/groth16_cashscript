// Track 9 S4: the D-state covenant, its flush coordinator and the flush worker (DESIGN-T9 sec. 2, sec. 6 S4).
//
// D-state commitment (65 B): 0x44 || queue (32) || depHash (32)
//   queue   = SHA-256(len (1 B) || chain), chain' = SHA-256(chain || C) per deposit, from chain = Z (32 zero bytes)
//             after each flush; len < 2^k before a deposit (k = 4)
//   depHash = SHA-256(count (4 B LE) || F), count = leaves in the tree (a multiple of 16), F = the frontier at levels
//             4..29 (26 x 32 B): F[l] = the left node at level l if bit l of count is 1, else Z
// Node and leaf bytes are 4 lanes u64 LE (the HEAD ROOT push format). The deposit tree is Poseidon2-Gl-8, depth 30,
// leaf i at index i, zero hashes on the right (w/genesis.mjs).
//
// One pool category CAT: the genesis transaction makes exactly two mutable NFTs of CAT, D (prefix 0x44) and W
// (prefix 0x57), and no minting NFT (the L1 trust anchor, checked off chain). Each covenant pins its successor (its
// own locking, CAT || 0x01, prefix), so "CAT || 0x01 with prefix 0x44 / 0x57" identifies the real D / W.
//
// buildD (P2SH32 redeem), D at input 0, its successor at output 0 (locking, category CAT || 0x01, no fungible amount):
//   deposit (unlocking C len chain; 3 items): SHA-256(len || chain) = queue, 0 <= len < 16, C is 32 B with every
//     lane < p; output 0 commitment 0x44 || SHA-256(len+1 || SHA-256(chain || C)) || depHash, value = in + D + f
//   flush (unlocking LV FR count MID RING BLOB; 6 items): BLOB is checked against its HASH256 and run as function 2
//     (flushBlob below); it returns the output 0 commitment and value
// flushBlob (pool independent; reads CAT from D's own input):
//   - queue: the 16 leaves LV re-derive chain from Z, SHA-256(0x10 || chain) = queue (so len = 16: premature
//     flushes fail)
//   - depHash: SHA-256(count || FR) = depHash, count % 16 = 0, count <= 2^30 - 16
//   - W at input 1: category = D's category, commitment prefix 0x57; ring: RING = OLD || 4 siblings, slot =
//     epoch mod 16; OLD with the siblings hashes to histRoot; ROOT with the same siblings gives histRoot'
//   - workers at inputs 2..5: locking = WORKER and the first push of each unlocking = the IO program the blob
//     builds from LV, count, FR, the zero hashes and the boundary nodes MID = A8 || B4 || H11 || H23 || ROOT || X
//     (worker 1: the trees of leaves 0-7 and 8-11; worker 2: leaves 12-15, the subtree root and path levels 4-10;
//     worker 3: levels 11-22; worker 4: levels 23-29 and ROOT). X is the node entering level l0 (the lowest zero
//     bit of count at or above 4), exported by the worker that holds level l0 and written to F'[l0]
//   - output 1 (W'): W's locking and category, no fungible amount, commitment 0x57 || nfRoot || histRoot' ||
//     epoch + 1, value = W's value + 16 D
//   - returns: commitment 0x44 || SHA-256(0x00 || Z) || SHA-256(count + 16 || F') and value = in - 16 (D + f); the
//     rest (16 f plus the worker inputs) is the keeper's, in any output the keeper chooses
// The worker (P2S, 43 B): DEPTH 3 NUMEQUALVERIFY DUP HASH256 <H(WBLOB)> EQUALVERIFY 1 DEFINE 1 INVOKE; unlocking
//   IO PAD WBLOB. WBLOB defines the compression T(P(a || b)) (S0's code) and interprets IO, a byte program over a
//   stack of nodes: 0x01 lit (push the 32 B literal, every lane < p), 0x02 (compress: [a b] -> T(P(a || b))),
//   0x03 (swap the top two nodes), 0x04 lit (pop the top node, it must equal the literal); the node stack must be
//   empty at the end.
import {hash256} from '@bitauth/libauth';
import {asm, Stk} from '../p2/lib/asm.mjs';
import {genPerm, P} from '../p2/p2gl8.mjs';
import {ZH} from '../w/genesis.mjs';
import {nfBytes, sha256} from '../w/smt.mjs';

export const K_LOG = 4, BATCH = 16, TREE_DEPTH = 30;
export const PATH_LO = K_LOG, NLEVEL = TREE_DEPTH - K_LOG;            // path levels 4..29 (26)
export const D_DEFAULT = 1_000_000n, FEE_DEFAULT = 10_000n;           // D = 0.01 BCH (maintainer decision 7); f: regtest
export const MAX_COUNT = 2 ** 30 - 16;
export const CUTS = [11, 23];                                         // the first path level of workers 3 and 4
export const WORKER_INPUT0 = 2, NWORKER = 4;
export const OP_L = 1, OP_C = 2, OP_S = 3, OP_E = 4;
const B0 = Uint8Array.of(0);
const ZERO32 = [0, 32, 'NUM2BIN'];
const SEL = ['IF', 'DROP', 'ELSE', 'NIP', 'ENDIF'];                    // [x y cond] -> cond ? x : y
export const ZHB = ZH.map((z) => nfBytes(z));                          // zero hashes as node bytes, level 0..30
export const Q0 = sha256(Uint8Array.from([0, ...new Uint8Array(32)]));   // the empty queue

// [lit] -> [l0 l1 l2 l3]: every lane < p
const decode4 = [8, 'SPLIT', 'SWAP', B0, 'CAT', 'BIN2NUM', 'DUP', P, 'LESSTHAN', 'VERIFY', 'SWAP',
  8, 'SPLIT', 'SWAP', B0, 'CAT', 'BIN2NUM', 'DUP', P, 'LESSTHAN', 'VERIFY', 'SWAP',
  8, 'SPLIT', 'SWAP', B0, 'CAT', 'BIN2NUM', 'DUP', P, 'LESSTHAN', 'VERIFY', 'SWAP',
  B0, 'CAT', 'BIN2NUM', 'DUP', P, 'LESSTHAN', 'VERIFY'];
// [lit] -> []: 32 B, every lane < p
const laneCheck = ['SIZE', 32, 'NUMEQUALVERIFY', ...decode4, '2DROP', '2DROP'];

// ---------------------------------------------------------------- worker
// compression body: [.. a0 a1 a2 a3 b0 b1 b2 b3] -> [.. y0 y1 y2 y3] = T(P(a || b))
export function compressCode() {
  const x = [...Array(8)].map((_, i) => `in${i}`);
  const st = new Stk(x);
  const o = genPerm(st, x, {out: 4});
  if (st.st.length !== 4 || o.some((n, i) => st.st[i] !== n)) throw new Error('compress: bad final stack');
  return st.bytes();
}
export function workerBlob() {
  return asm(compressCode(), 0, 'DEFINE',
    'DROP', 'TOALTSTACK',                                              // PAD dropped, IO to the alt stack
    'BEGIN',
    'FROMALTSTACK', 1, 'SPLIT', 'SWAP',                                // .. IO' op
    'DUP', OP_C, 'NUMEQUAL', 'IF', 'DROP', 'TOALTSTACK', 0, 'INVOKE',
    'ELSE', 'DUP', OP_S, 'NUMEQUAL', 'IF', 'DROP', 'TOALTSTACK', 7, 'ROLL', 7, 'ROLL', 7, 'ROLL', 7, 'ROLL',
    'ELSE', 'SWAP', 32, 'SPLIT', 'TOALTSTACK', ...decode4,              // .. op l0 l1 l2 l3
    4, 'ROLL', 'DUP', OP_L, 'NUMEQUAL', 'IF', 'DROP',
    'ELSE', OP_E, 'NUMEQUALVERIFY', 4, 'ROLL', 'NUMEQUALVERIFY', 3, 'ROLL', 'NUMEQUALVERIFY', 2, 'ROLL', 'NUMEQUALVERIFY', 'NUMEQUALVERIFY',
    'ENDIF', 'ENDIF', 'ENDIF',
    'FROMALTSTACK', 'DUP', 'SIZE', 'NIP', 'NOT', 'SWAP', 'TOALTSTACK',
    'UNTIL',
    'FROMALTSTACK', 'DROP', 'DEPTH', 0, 'NUMEQUALVERIFY', 1);
}
export const workerLocking = (blob) => asm('DEPTH', 3, 'NUMEQUALVERIFY', 'DUP', 'HASH256', hash256(blob), 'EQUALVERIFY', 1, 'DEFINE', 1, 'INVOKE');

// ---------------------------------------------------------------- flush coordinator
// one path level: [.. io Fp X found c FRr ZHr] -> same names, updated
const REGION = ['io', 'Fp', 'X', 'found', 'c', 'FRr', 'ZHr'];
function levelFn() {
  const s = new Stk(REGION);
  s.roll('ZHr'); s.raw([32, 'SPLIT', 'SWAP'], 1, ['ZHr', 'zh']);
  s.roll('FRr'); s.raw([32, 'SPLIT', 'SWAP'], 1, ['FRr', 'fl']);
  s.pick('c'); s.raw([2, 'MOD'], 1, ['b']);
  s.roll('c'); s.raw([2, 'DIV'], 1, ['c']);
  s.pick('b'); s.pick('found'); s.raw(['BOOLOR', 'NOT'], 2, ['isl0']);              // the lowest zero bit
  // F'[l] = found ? F[l] : (b ? Z : X)
  s.raw(ZERO32, 0, ['z']); s.pick('X'); s.pick('b'); s.raw(SEL, 3, ['inner']);
  s.pick('fl'); s.roll('inner'); s.pick('found'); s.raw(SEL, 3, ['piece']);
  s.roll('Fp'); s.roll('piece'); s.raw(['CAT'], 2, ['Fp']);
  // found' = found or not b
  s.pick('b'); s.raw(['NOT'], 1, ['nb']); s.roll('found'); s.roll('nb'); s.raw(['BOOLOR'], 2, ['found']);
  // io += (l0 ? 04 X 01 X : '') || (b ? 01 F[l] 03 02 : 01 ZH[l] 02)
  s.raw([Uint8Array.of(OP_E)], 0, ['t']); s.pick('X'); s.raw(['CAT', Uint8Array.of(OP_L), 'CAT'], 2, ['t']); s.pick('X'); s.raw(['CAT'], 2, ['t']);
  s.raw([0], 0, ['e']); s.roll('isl0'); s.raw(SEL, 3, ['pre']);
  s.roll('io'); s.roll('pre'); s.raw(['CAT'], 2, ['io']);
  s.raw([Uint8Array.of(OP_L)], 0, ['m1']); s.roll('fl'); s.raw(['CAT', Uint8Array.of(OP_S, OP_C), 'CAT'], 2, ['m1']);
  s.raw([Uint8Array.of(OP_L)], 0, ['m0']); s.roll('zh'); s.raw(['CAT', Uint8Array.of(OP_C), 'CAT'], 2, ['m0']);
  s.roll('b'); s.raw(SEL, 3, ['main']);
  s.roll('io'); s.roll('main'); s.raw(['CAT'], 2, ['io']);
  s.arrange(REGION);
  return s.bytes();
}

// the expected IO templates of workers 1 and 2's subtree part (L i = leaf i, 'A8' etc. = MID items)
export const W1_TEMPLATE = ['L0', 'L1', 'C', 'L2', 'L3', 'C', 'C', 'L4', 'L5', 'C', 'L6', 'L7', 'C', 'C', 'C',
  'L8', 'L9', 'C', 'L10', 'L11', 'C', 'C', 'E:B4', 'E:A8'];
export const W2_TEMPLATE = ['L:A8', 'L:B4', 'L12', 'L13', 'C', 'L14', 'L15', 'C', 'C', 'C', 'C'];

export function flushBlob({D = D_DEFAULT, FEE = FEE_DEFAULT, WORKER}) {
  const s = new Stk(['LV', 'FR', 'count', 'MID', 'RING', 'queue', 'dep']);
  const fns = asm(levelFn(), 3, 'DEFINE');
  s.emit({raw: fns});
  s.emit('DEPTH', 7, 'NUMEQUALVERIFY');
  // queue: 16 leaves from chain = Z
  s.pick('LV'); s.raw(['SIZE', 32 * BATCH, 'NUMEQUALVERIFY', ...ZERO32, 'BEGIN', 'SWAP', 32, 'SPLIT', 'ROT', 'ROT', 'CAT', 'SHA256', 'OVER', 'SIZE', 'NIP', 'NOT', 'UNTIL', 'NIP',
    Uint8Array.of(BATCH), 'SWAP', 'CAT', 'SHA256'], 1, ['qc']);
  s.roll('queue'); s.raw(['EQUALVERIFY'], 2);
  // depHash
  s.pick('count'); s.raw(['DUP', BATCH, 'MOD', 0, 'NUMEQUALVERIFY', 0, MAX_COUNT + 1, 'WITHIN', 'VERIFY'], 1);
  s.pick('count'); s.raw([4, 'NUM2BIN'], 1, ['c4']); s.pick('FR'); s.raw(['SIZE', 32 * NLEVEL, 'NUMEQUALVERIFY', 'CAT', 'SHA256'], 2, ['dh']);
  s.roll('dep'); s.raw(['EQUALVERIFY'], 2);
  // MID
  s.roll('MID'); s.raw(['SIZE', 192, 'NUMEQUALVERIFY', 32, 'SPLIT', 32, 'SPLIT', 32, 'SPLIT', 32, 'SPLIT', 32, 'SPLIT'], 1, ['A8', 'B4', 'H11', 'H23', 'ROOT', 'X']);
  // W at input 1 (the real W: D's category, prefix 0x57)
  s.emit(1, 'UTXOTOKENCATEGORY', 'INPUTINDEX', 'UTXOTOKENCATEGORY', 'EQUALVERIFY');
  s.raw([1, 'UTXOTOKENCOMMITMENT', 'SIZE', 69, 'NUMEQUALVERIFY', 1, 'SPLIT', 'SWAP', Uint8Array.of(0x57), 'EQUALVERIFY', 32, 'SPLIT', 32, 'SPLIT', 'BIN2NUM'], 0, ['nfRoot', 'hist', 'epoch']);
  // ring: OLD -> histRoot, ROOT -> histRoot' with the same 4 siblings
  s.roll('RING'); s.raw(['SIZE', 160, 'NUMEQUALVERIFY', 32, 'SPLIT'], 1, ['o', 'HS']);
  s.pick('ROOT', 'n');
  s.pick('epoch'); s.raw([16, 'MOD'], 1, ['slot']);
  for (let l = 0; l < 4; l++) {
    s.roll('HS'); s.raw([32, 'SPLIT', 'SWAP'], 1, ['HS', 'sib']);
    s.roll('slot'); s.raw(['DUP', 2, 'DIV', 'SWAP', 2, 'MOD'], 1, ['slot', 'bit']);
    s.roll('o'); s.pick('sib'); s.pick('bit'); s.raw(['IF', 'SWAP', 'ENDIF', 'CAT', 'SHA256'], 3, ['o']);
    s.roll('n'); s.roll('sib'); s.roll('bit'); s.raw(['IF', 'SWAP', 'ENDIF', 'CAT', 'SHA256'], 3, ['n']);
  }
  s.drop('HS'); s.drop('slot');
  s.roll('o'); s.roll('hist'); s.raw(['EQUALVERIFY'], 2);
  // output 1 = W'
  s.emit(1, 'OUTPUTBYTECODE', 1, 'UTXOBYTECODE', 'EQUALVERIFY', 1, 'OUTPUTTOKENCATEGORY', 1, 'UTXOTOKENCATEGORY', 'EQUALVERIFY',
    1, 'OUTPUTTOKENAMOUNT', 0, 'NUMEQUALVERIFY');
  s.raw([Uint8Array.of(0x57)], 0, ['wc']); s.roll('nfRoot'); s.raw(['CAT'], 2, ['wc']); s.roll('n'); s.raw(['CAT'], 2, ['wc']);
  s.roll('epoch'); s.raw(['1ADD', 4, 'NUM2BIN', 'CAT', 1, 'OUTPUTTOKENCOMMITMENT', 'EQUALVERIFY'], 2);
  s.emit(1, 'OUTPUTVALUE', 1, 'UTXOVALUE', BigInt(BATCH) * D, 'ADD', 'NUMEQUALVERIFY');
  // the leaves
  s.roll('LV');
  for (let i = 0; i < BATCH - 1; i++) s.raw([32, 'SPLIT'], 1, [`c${i}`, 'LV']);
  s.rename('LV', `c${BATCH - 1}`);
  // IO emission: pending constant bytes are merged into one push
  let pend = [];
  const flushPend = () => { if (pend.length) { s.roll('io'); s.raw([Uint8Array.from(pend), 'CAT'], 1, ['io']); pend = []; } };
  const item = (name, keep) => { flushPend(); s.roll('io'); s.get(name, keep); s.raw(['CAT'], 2, ['io']); };
  const tmpl = (tokens, keepSet) => {
    for (const t of tokens) {
      if (t === 'C') pend.push(OP_C);
      else if (t.startsWith('E:') || t.startsWith('L:')) { pend.push(t[0] === 'E' ? OP_E : OP_L); item(t.slice(2), keepSet.has(t.slice(2))); }
      else if (t.startsWith('L')) { pend.push(OP_L); item(`c${+t.slice(1)}`, false); }
      else throw new Error('template ' + t);
    }
  };
  const finish = (input) => {
    flushPend();
    s.roll('io');
    s.raw(['SIZE', 2, 'NUM2BIN', Uint8Array.of(0x4d), 'SWAP', 'CAT', 'SWAP', 'CAT', 'DUP', 'SIZE', 'NIP', input, 'INPUTBYTECODE', 'SWAP', 'SPLIT', 'DROP', 'EQUALVERIFY'], 1);
    s.emit(input, 'UTXOBYTECODE', Uint8Array.from(WORKER), 'EQUALVERIFY');
  };
  // worker 1
  s.raw([0], 0, ['io']); tmpl(W1_TEMPLATE, new Set(['A8', 'B4'])); finish(WORKER_INPUT0);
  // worker 2: subtree root, then path levels 4..10
  s.raw([0], 0, ['io']); tmpl(W2_TEMPLATE, new Set());
  flushPend();
  s.raw([0], 0, ['Fp']); s.raw([0], 0, ['found']);
  s.pick('count'); s.raw([K_LOG, 'RSHIFTNUM'], 1, ['c']);
  s.roll('FR'); s.rename('FR', 'FRr');
  s.raw([Uint8Array.from(Buffer.concat(ZHB.slice(PATH_LO, TREE_DEPTH)))], 0, ['ZHr']);
  const levels = (n) => { for (let i = 0; i < n; i++) { for (const x of REGION) s.roll(x); s.raw([3, 'INVOKE'], REGION.length, REGION); } };
  levels(CUTS[0] - PATH_LO);
  pend.push(OP_E); item('H11', true); finish(WORKER_INPUT0 + 1);
  // worker 3: levels 11..22
  s.raw([0], 0, ['io']); pend.push(OP_L); item('H11', false);
  levels(CUTS[1] - CUTS[0]);
  pend.push(OP_E); item('H23', true); finish(WORKER_INPUT0 + 2);
  // worker 4: levels 23..29, ROOT
  s.raw([0], 0, ['io']); pend.push(OP_L); item('H23', false);
  levels(TREE_DEPTH - CUTS[1]);
  pend.push(OP_E); item('ROOT', false); finish(WORKER_INPUT0 + 3);
  // D' commitment and value
  for (const x of ['ZHr', 'FRr', 'c', 'found', 'X']) s.drop(x);
  s.roll('count'); s.raw([BATCH, 'ADD', 4, 'NUM2BIN'], 1, ['c4']); s.roll('Fp'); s.raw(['CAT', 'SHA256'], 2, ['dh']);
  s.raw([Uint8Array.from([0x44, ...Q0])], 0, ['com']); s.roll('dh'); s.raw(['CAT'], 2, ['com']);
  s.emit('INPUTINDEX', 'UTXOVALUE', BigInt(BATCH) * (D + FEE), 'SUB'); s.st.push('val');
  if (s.st.join() !== 'com,val') throw new Error('flush blob: final stack ' + s.st.join());
  return s.bytes();
}

// ---------------------------------------------------------------- D redeem
function depositCode(D, FEE) {
  const s = new Stk(['C', 'len', 'chain', 'queue', 'dep']);
  s.pick('len'); s.raw([0, BATCH, 'WITHIN', 'VERIFY'], 1);
  s.pick('len'); s.raw([1, 'NUM2BIN'], 1, ['l1']); s.pick('chain'); s.raw(['SIZE', 32, 'NUMEQUALVERIFY', 'CAT', 'SHA256'], 2, ['qh']);
  s.roll('queue'); s.raw(['EQUALVERIFY'], 2);
  s.pick('C'); s.raw(laneCheck, 1);
  s.roll('chain'); s.roll('C'); s.raw(['CAT', 'SHA256'], 2, ['chain']);
  s.roll('len'); s.raw(['1ADD', 1, 'NUM2BIN'], 1, ['l1']); s.roll('chain'); s.raw(['CAT', 'SHA256'], 2, ['q2']);
  s.raw([Uint8Array.of(0x44)], 0, ['com']); s.roll('q2'); s.raw(['CAT'], 2, ['com']); s.roll('dep'); s.raw(['CAT'], 2, ['com']);
  s.emit('INPUTINDEX', 'UTXOVALUE', D + FEE, 'ADD'); s.st.push('val');
  if (s.st.join() !== 'com,val') throw new Error('deposit: final stack ' + s.st.join());
  return s.bytes();
}
export function buildD({CAT, D = D_DEFAULT, FEE = FEE_DEFAULT, HF}) {
  if (CAT.length !== 32 || HF.length !== 32) throw new Error('CAT and HF are 32 B');
  const CAT01 = Uint8Array.from([...CAT, 1]);
  return asm(
    'INPUTINDEX', 0, 'NUMEQUALVERIFY',
    'INPUTINDEX', 'UTXOTOKENCATEGORY', CAT01, 'EQUALVERIFY',
    0, 'OUTPUTBYTECODE', 'INPUTINDEX', 'UTXOBYTECODE', 'EQUALVERIFY',
    0, 'OUTPUTTOKENCATEGORY', CAT01, 'EQUALVERIFY',
    0, 'OUTPUTTOKENAMOUNT', 0, 'NUMEQUALVERIFY',
    'INPUTINDEX', 'UTXOTOKENCOMMITMENT', 'SIZE', 65, 'NUMEQUALVERIFY', 1, 'SPLIT', 'SWAP', Uint8Array.of(0x44), 'EQUALVERIFY', 32, 'SPLIT',
    'DEPTH', 5, 'NUMEQUAL', 'IF', {raw: depositCode(D, FEE)},
    'ELSE', 'DEPTH', 8, 'NUMEQUALVERIFY', 2, 'ROLL', 'DUP', 'HASH256', Uint8Array.from(HF), 'EQUALVERIFY', 2, 'DEFINE', 2, 'INVOKE', 'ENDIF',
    0, 'OUTPUTVALUE', 'NUMEQUALVERIFY', 0, 'OUTPUTTOKENCOMMITMENT', 'EQUAL');
}

// all pool-independent code: the worker blob and locking, the flush blob and its hash
export function codeSet({D = D_DEFAULT, FEE = FEE_DEFAULT} = {}) {
  const wblob = workerBlob(), WORKER = workerLocking(wblob);
  const fblob = flushBlob({D, FEE, WORKER});
  // BCHN charges OP_DEFINE body bytes: the worker defines WBLOB and the compression; D's flush defines the flush
  // blob and the level function
  return {wblob, WORKER, fblob, HF: hash256(fblob), D, FEE, compressLen: compressCode().length, fblobLevelFn: levelFn().length};
}
