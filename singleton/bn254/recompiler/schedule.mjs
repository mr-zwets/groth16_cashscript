// Scheduler v2: use-count greedy. Beats cashc by accessing buried operands with a
// single ROLL/PICK instead of park-to-alt/restore, and consuming last-use values in
// place (ROLL = move) rather than copy-then-clean.
import { serialize } from './asm.mjs';
import { decompile } from './decompile.mjs';

const PICK = 0x79, ROLL = 0x7a, TOALT = 0x6b, FROMALT = 0x6c, DROP = 0x75, INVOKE = 0x8a;

function pushNumOps(n) {
  if (n === 0) return [{ op: 0x00 }];
  if (n >= 1 && n <= 16) return [{ op: 0x50 + n }];
  const bytes = []; let v = n; while (v > 0) { bytes.push(v & 0xff); v >>= 8; }
  if (bytes[bytes.length - 1] & 0x80) bytes.push(0x00);
  return [{ op: 0, data: Uint8Array.from(bytes) }];
}
// minimal push of an arbitrary const byte-string (VM minimal-encoding rules)
function pushDataOps(data) {
  if (data.length === 0) return [{ op: 0x00 }];
  if (data.length === 1) {
    const b = data[0];
    if (b >= 1 && b <= 16) return [{ op: 0x50 + b }];
    if (b === 0x81) return [{ op: 0x4f }]; // OP_1NEGATE
  }
  return [{ op: 0, data }];
}

const keyOf = (ref) => {
  if (ref.k === 'in') return 'm' + ref.i;
  if (ref.k === 'ain') return 'a' + ref.i;
  if (ref.k === 'out') return 'n' + ref.node.id + '_' + ref.j;
  return null; // const
};

export function emitBlockV2(block, arity, strategy = 'topo') {
  const { entryDepth: n, entryAlt: p, exit, exitAlt } = block;
  const out = [];
  let stk = []; // array of keys (strings); top = last

  // topo order of needed nodes (memoized -- safe on shared DAGs)
  const visited = new Set(); const order = [];
  const visitRef = (r) => { if (r.k === 'out') visitNode(r.node); };
  function visitNode(node) { if (visited.has(node.id)) return; visited.add(node.id); for (const r of node.ins) visitRef(r); order.push(node); }
  for (const r of exit) visitRef(r);
  for (const r of exitAlt) visitRef(r);

  // OPT A: if the entry altstack is pure passthrough (exitAlt is exactly the entry alt
  // slots in order, and no node/exit-main reads an alt slot), leave it on the altstack
  // untouched -- emit zero alt ops. Derive alt-usage from the memoized node list + exit
  // refs (a naive DAG recursion would blow up exponentially on shared finalExp graphs).
  let altRefdElsewhere = exit.some((r) => r.k === 'ain') ||
    order.some((nd) => nd.ins.some((r) => r.k === 'ain'));
  const exitAltPass = exitAlt.length === p && exitAlt.every((r, i) => r.k === 'ain' && r.i === i);
  const altPass = exitAltPass && !altRefdElsewhere;

  // 1. seed entry main slots; flatten alt onto main only if not passthrough
  for (let i = 0; i < n; i++) stk.push('m' + i);
  if (!altPass) for (let i = 0; i < p; i++) { out.push({ op: FROMALT }); stk.push('a' + (p - 1 - i)); }

  // node-input use counts + exit need counts (per key)
  const useCount = new Map(); const exitNeed = new Map();
  const bump = (m, k) => { if (k) m.set(k, (m.get(k) || 0) + 1); };
  for (const node of order) for (const r of node.ins) bump(useCount, keyOf(r));
  for (const r of exit) bump(exitNeed, keyOf(r));
  for (const r of exitAlt) bump(exitNeed, keyOf(r));

  const topmostIndex = (key) => { for (let i = stk.length - 1; i >= 0; i--) if (stk[i] === key) return i; return -1; };
  const deepestIndex = (key) => { for (let i = 0; i < stk.length; i++) if (stk[i] === key) return i; return -1; };
  const bring = (key, move) => {
    // COPY targets the shallowest occurrence (cheapest); a consuming MOVE targets the
    // deepest (original) so any freshly-staged copies on top are preserved.
    const idx = move ? deepestIndex(key) : topmostIndex(key);
    if (idx < 0) throw new Error('value not on stack: ' + key + ' | stk=[' + stk.join(',') + ']');
    const depth = stk.length - 1 - idx;
    if (move) {
      // 1-byte ops for shallow moves: depth0=nop, 1=SWAP, 2=ROT; else ROLL
      if (depth === 0) { /* already on top */ }
      else if (depth === 1) { out.push({ op: 0x7c }); }       // SWAP
      else if (depth === 2) { out.push({ op: 0x7b }); }       // ROT
      else { for (const o of [...pushNumOps(depth), { op: ROLL }]) out.push(o); }
      stk.splice(idx, 1); stk.push(key);
    } else {
      // depth0=DUP, depth1=OVER; else PICK
      if (depth === 0) { out.push({ op: 0x76 }); }             // DUP
      else if (depth === 1) { out.push({ op: 0x78 }); }        // OVER
      else { for (const o of [...pushNumOps(depth), { op: PICK }]) out.push(o); }
      stk.push(key);
    }
  };
  const bringRef = (ref, consumeContext) => {
    if (ref.k === 'const') { for (const o of pushDataOps(ref.data)) out.push(o); stk.push('#k'); return; }
    const k = keyOf(ref);
    if (consumeContext) {
      const remNode = useCount.get(k) || 0;            // node-input uses remaining (incl. this)
      const survives = remNode > 1 || (exitNeed.get(k) || 0) > 0;
      bring(k, !survives);
      useCount.set(k, remNode - 1);
    } else {
      const remExit = exitNeed.get(k);                 // exit placement
      const survives = remExit > 1;
      bring(k, !survives);
      exitNeed.set(k, remExit - 1);
    }
  };

  // 2. compute nodes, in dependency-respecting order chosen by `strategy`.
  const remaining = new Set(order.map((nd) => nd.id));
  const inputNodeIds = (nd) => nd.ins.filter((r) => r.k === 'out').map((r) => r.node.id);
  const ready = () => order.filter((nd) => remaining.has(nd.id) && inputNodeIds(nd).every((id) => !remaining.has(id)));
  // cost-accurate greedy: estimate the bytes to fetch a node's operands given the
  // current stack, rewarding depth-0 last-use (free move) and shallow access.
  const pushBytesForDepth = (dep) => (dep <= 16 ? 1 : 2);
  const fetchCost = (nd) => nd.ins.reduce((s, r) => {
    if (r.k === 'const') return s + (r.data.length <= 16 && (r.data.length !== 1 || (r.data[0] >= 1 && r.data[0] <= 16) || r.data[0] === 0x81) ? 1 : r.hdr ? r.hdr + r.data.length : 1 + r.data.length);
    const k = keyOf(r);
    const idx = topmostIndex(k);
    if (idx < 0) return s;
    const dep = stk.length - 1 - idx;
    const lastUse = (useCount.get(k) || 0) <= 1 && (exitNeed.get(k) || 0) === 0;
    if (lastUse) return s + (dep === 0 ? 0 : dep <= 2 ? 1 : pushBytesForDepth(dep) + 1); // SWAP/ROT or push+ROLL
    return s + (dep <= 1 ? 1 : pushBytesForDepth(dep) + 1);                               // DUP/OVER or push+PICK
  }, 0);
  while (remaining.size) {
    const cands = ready();
    let node;
    if (strategy === 'greedy') {
      node = cands[0]; let best = fetchCost(cands[0]);
      for (const c of cands) { const d = fetchCost(c); if (d < best) { best = d; node = c; } }
    } else { node = cands[0]; } // topo: first remaining ready node (== original topo order)
    remaining.delete(node.id);
    for (const r of node.ins) bringRef(r, true);       // bring nin inputs to top
    const nin = node.ins.length;
    const m = node.k === 'invoke' ? arity[node.invId].out : 1;
    if (node.k === 'invoke') { for (const o of [...pushNumOps(node.invId), { op: INVOKE }]) out.push(o); }
    else out.push({ op: node.code });
    stk.length -= nin;
    for (let j = 0; j < m; j++) stk.push('n' + node.id + '_' + j);
  }

  // 3. assemble exit on top. If alt is passthrough, only exit-main is built here
  // (alt values stay on the altstack); else build exit-main ++ reverse(exit-alt).
  const desired = altPass ? [...exit] : [...exit, ...exitAlt.slice().reverse()];
  const K = desired.length;
  // Fast path: if the top K cells already equal desired (in order) with each value
  // appearing exactly its needed number of times among them, skip rebuilding -- just
  // honor exitNeed multiplicity by checking the suffix already matches.
  const desiredKeys = desired.map((r) => r.k === 'const' ? null : keyOf(r));
  let inPlace = stk.length >= K && desiredKeys.every((dk, i) => dk !== null && stk[stk.length - K + i] === dk);
  if (!inPlace) for (const r of desired) bringRef(r, false);

  // 4. clean buried junk below the K exit items. Skip if none; else pick the cheaper of
  // alt round-trip (2K+L) vs roll-drop each junk (~3-4 each).
  const L = stk.length - K;
  if (L > 0) {
    if (2 * K + L <= 4 * L) {
      for (let i = 0; i < K; i++) out.push({ op: TOALT });
      for (let i = 0; i < L; i++) out.push({ op: DROP });
      for (let i = 0; i < K; i++) out.push({ op: FROMALT });
      stk = stk.slice(stk.length - K);
    } else {
      // roll each bottom junk item to top and drop
      for (let i = 0; i < L; i++) { for (const o of pushNumOps(stk.length - 1)) out.push(o); out.push({ op: ROLL }, { op: DROP }); stk.splice(0, 1); }
    }
  }

  // 5. push exit-alt onto altstack (unless it already lives there via passthrough)
  if (!altPass) for (let i = 0; i < exitAlt.length; i++) out.push({ op: TOALT });

  return out;
}

// Peephole: collapse adjacent single-item stack ops into one multi-item op.
// All rewrites are provably stack-equivalent (and validated by diff-test + verify):
//   OVER OVER            -> 2DUP   (copy top pair)
//   <2> PICK x3          -> 3DUP   (copy top triple)
//   SWAP OVER            -> TUCK
//   SWAP DROP            -> NIP
//   <3> PICK <3> PICK    -> 2OVER  (copy depth-2,3 pair)
//   <3> ROLL <3> ROLL    -> 2SWAP  (move depth-2,3 pair to top)
//   <5> ROLL <5> ROLL    -> 2ROT   (move depth-4,5 pair to top)
function peepholeMulti(ops) {
  const isN = (o, n) => o && o.data === undefined && o.op === 0x50 + n;
  const isOp = (o, c) => o && o.data === undefined && o.op === c;
  let changed = true;
  while (changed) {
    changed = false;
    const out = [];
    for (let i = 0; i < ops.length; i++) {
      const a = ops[i], b = ops[i + 1], c = ops[i + 2], e = ops[i + 3], f = ops[i + 4], g = ops[i + 5];
      if (isN(a, 2) && isOp(b, 0x79) && isN(c, 2) && isOp(e, 0x79) && isN(f, 2) && isOp(g, 0x79)) { out.push({ op: 0x6f }); i += 5; changed = true; continue; } // <2>PICK x3 -> 3DUP
      if (isOp(a, 0x78) && isOp(b, 0x78)) { out.push({ op: 0x6e }); i += 1; changed = true; continue; }            // OVER OVER -> 2DUP
      if (isOp(a, 0x7c) && isOp(b, 0x78)) { out.push({ op: 0x7d }); i += 1; changed = true; continue; }            // SWAP OVER -> TUCK
      if (isOp(a, 0x7c) && isOp(b, 0x75)) { out.push({ op: 0x77 }); i += 1; changed = true; continue; }            // SWAP DROP -> NIP
      if (isN(a, 3) && isOp(b, 0x79) && isN(c, 3) && isOp(e, 0x79)) { out.push({ op: 0x70 }); i += 3; changed = true; continue; } // 2OVER
      if (isN(a, 3) && isOp(b, 0x7a) && isN(c, 3) && isOp(e, 0x7a)) { out.push({ op: 0x72 }); i += 3; changed = true; continue; } // 2SWAP
      if (isN(a, 5) && isOp(b, 0x7a) && isN(c, 5) && isOp(e, 0x7a)) { out.push({ op: 0x71 }); i += 3; changed = true; continue; } // 2ROT
      out.push(a);
    }
    ops = out;
  }
  return ops;
}

export function recompileBodyV2(body, arity, inArity, strategy = 'topo') {
  const items = decompile(body, arity, inArity);
  let ops = [];
  for (const it of items) {
    if (it.block) {
      // Per-block min(cashc raw, rescheduled): both reproduce the block's entry->exit
      // transform AND its boundary layout, so they compose; keep whichever is smaller.
      // This makes the recompile never worse than cashc on any block (e.g. low-shuffle
      // straight-line regions keep the original; shuffle-heavy loop bodies get rewritten).
      const mine = emitBlockV2(it.block, arity, strategy);
      const chosen = serialize(mine).length < serialize(it.block.rawOps).length ? mine : it.block.rawOps;
      for (const o of chosen) ops.push(o);
    } else ops.push({ op: it.ctrl });
  }
  ops = peepholeMulti(ops);
  return serialize(ops);
}
