// Track 9 S1: the static genesis history (DESIGN-T9 sec. 6 S1: no deposits; the genesis tree is built offline,
// histRoot is seeded, W is funded at genesis).
//
// Notes: 2^k = 16 leaves per epoch (k = 4), two genesis epochs (32 notes), so that S2's 24 re-proved statements can
// each use a distinct note. Note i: nk_i and r_i are 4 lanes < p from SHA-256 (rejection sampling), and with the M1
// relation (prover/src/stmt.rs, AIR-SPEC sec. 3):
//   NF = T(P(nk || 0,0,0,TAG_NF)),  leaf = T(P(NF || r)),  node = T(P(sib || node)) if bit = 1 else T(P(node || sib))
// Deposit tree: Poseidon2-Gl-8, depth 30, leaf i at index i (bit l of i = side at level l, level 0 at the leaves),
// empty subtrees are zero hashes: Z_0 = (0,0,0,0), Z_{l+1} = T(P(Z_l || Z_l)) (the flush's "zero-hashes on the right").
// Epoch e's root = the tree of the first 16 (e + 1) leaves. Ring slot e = epoch e's root (ROOT bytes: 4 lanes u64 LE,
// the HEAD push format); the other 14 slots are Z. W genesis commitment: nfRoot = Z (empty set), histRoot, epoch = 2.
import {permRef, P} from '../p2/p2gl8.mjs';
import {sha256, nfBytes, Z, ringRoot, ringPath, encodeW, keyOf} from './smt.mjs';

export const TAG_NF = 0x7663_2E6E_6676_3031n;   // stmt.rs TAG_NF, ASCII "vc.nfv01"
export const TREE_DEPTH = 30, EPOCH_LEAVES = 16, GENESIS_EPOCHS = 2;
const compress = (a, b) => permRef([...a, ...b]).slice(0, 4);

function lanes(tag, i) {
  const out = [];
  for (let j = 0; out.length < 4; j++) {
    const v = sha256(Buffer.from(`${tag}/${i}/${j}`)).readBigUInt64LE(0);
    if (v < P) out.push(v);
  }
  return out;
}

export const ZH = [[0n, 0n, 0n, 0n]];
for (let l = 0; l < TREE_DEPTH; l++) ZH.push(compress(ZH[l], ZH[l]));

// levels of the tree of `leaves` (index 0..n-1, the rest empty): levels[l] = the non-empty prefix of level l
export function tree(leaves) {
  const levels = [leaves.map((x) => [...x])];
  for (let l = 0; l < TREE_DEPTH; l++) {
    const cur = levels[l], nxt = [];
    for (let i = 0; i < cur.length; i += 2) nxt.push(compress(cur[i], cur[i + 1] ?? ZH[l]));
    levels.push(nxt);
  }
  return levels;
}
export const treeRoot = (levels) => levels[TREE_DEPTH][0] ?? ZH[TREE_DEPTH];
export function treePath(levels, idx) {
  return Array.from({length: TREE_DEPTH}, (_, l) => levels[l][(idx >> l) ^ 1] ?? ZH[l]);
}
export function rootFromPath(leaf, idx, sibs) {
  let node = leaf;
  sibs.forEach((s, l) => { node = ((idx >> l) & 1) ? compress(s, node) : compress(node, s); });
  return node;
}

export function genesis() {
  const n = EPOCH_LEAVES * GENESIS_EPOCHS;
  const notes = Array.from({length: n}, (_, i) => {
    const nk = lanes('t9 genesis nk', i), r = lanes('t9 genesis r', i);
    const nf = compress(nk, [0n, 0n, 0n, TAG_NF]);
    return {index: i, nk, r, nf, leaf: compress(nf, r)};
  });
  const epochs = Array.from({length: GENESIS_EPOCHS}, (_, e) => {
    const levels = tree(notes.slice(0, EPOCH_LEAVES * (e + 1)).map((x) => x.leaf));
    return {epoch: e, slot: e % 16, leaves: EPOCH_LEAVES * (e + 1), levels, root: treeRoot(levels)};
  });
  const slots = Array.from({length: 16}, (_, i) => (i < GENESIS_EPOCHS ? nfBytes(epochs[i].root) : Z));
  const histRoot = ringRoot(slots);
  const state = {nfRoot: Z, histRoot, epoch: GENESIS_EPOCHS};
  for (const note of notes) {
    // a note is proved against the first epoch root that contains it
    const e = Math.floor(note.index / EPOCH_LEAVES);
    note.epoch = e; note.slot = epochs[e].slot;
    note.siblings = treePath(epochs[e].levels, note.index);
    note.root = epochs[e].root;
    if (rootFromPath(note.leaf, note.index, note.siblings).some((x, j) => x !== note.root[j])) throw new Error('genesis path');
    note.key = keyOf(nfBytes(note.nf));
  }
  return {notes, epochs, slots, histRoot, state, commitment: encodeW(state), ringPathOf: (slot) => ringPath(slots, slot)};
}

if (process.argv[1] === new URL(import.meta.url).pathname) {
  const fs = await import('node:fs');
  const g = genesis();
  const s = (xs) => xs.map(String);
  const out = {
    stage: 'Track 9 S1', what: 'static genesis history: 2 epochs x 16 notes, Poseidon2-Gl-8 depth-30 tree, 16-slot ring',
    relation: 'NF = T(P(nk || 0,0,0,TAG_NF)); leaf = T(P(NF || r)); node = T(P(sib || node)) if bit else T(P(node || sib)); bit l = (index >> l) & 1',
    tagNF: TAG_NF.toString(), zeroHashes: g.epochs.length ? ZH.map(s) : [],
    epochs: g.epochs.map((e) => ({epoch: e.epoch, slot: e.slot, leaves: e.leaves, root: s(e.root), rootBytes: nfBytes(e.root).toString('hex')})),
    slots: g.slots.map((x) => x.toString('hex')), histRoot: g.histRoot.toString('hex'),
    wGenesis: {commitment: g.commitment.toString('hex'), nfRoot: Z.toString('hex'), epoch: g.state.epoch},
    notes: g.notes.map((x) => ({index: x.index, epoch: x.epoch, slot: x.slot, nk: s(x.nk), r: s(x.r), nf: s(x.nf), nfBytes: nfBytes(x.nf).toString('hex'),
      key: x.key.toString(), leaf: s(x.leaf), root: s(x.root), siblings: x.siblings.map(s)})),
  };
  const dir = new URL('./results/', import.meta.url).pathname;
  fs.mkdirSync(dir, {recursive: true});
  fs.writeFileSync(dir + 'genesis.json', JSON.stringify(out, null, 1) + '\n');
  console.log('epoch roots', out.epochs.map((e) => e.rootBytes.slice(0, 16)), 'histRoot', out.histRoot.slice(0, 16));
}
