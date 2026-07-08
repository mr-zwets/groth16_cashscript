// Roadmap items 6+7 spike (2026-07-08): depth-layout census + 16-hot greedy oracle
// (item 6, verdict: lever closed) and repeated-sequence outlining scan (item 7,
// verdict: BUILD; verified -23.1% BN254 golfed / -26.8% BLS with APPLY=1).
//   node outline_spike.mjs [vector-json]          census + oracle + scan
//   APPLY=1 node outline_spike.mjs [vector-json]  also rewrite the artifact and verify
//     (accept valid / reject tampered / all multiproof witnesses) on the loose VM.
// Default artifact: the flagship byte-scored groth16-singleton-opcode-optimized vectors.
// See cashc-optimization-roadmap.md items 6-7 for the measured numbers and verdicts.
import { readFileSync } from 'node:fs';
import { parse } from './asm.mjs';

const VEC = process.argv[2] ?? 'C:/Users/mathi/Desktop/verifier/src/bch/groth16-singleton-opcode-optimized-vectors.json';
const vec = JSON.parse(readFileSync(VEC, 'utf8'));
const hexToBin = (h) => Uint8Array.from(h.match(/../g).map((b) => parseInt(b, 16)));
const artifact = hexToBin(vec.lockingOK ?? vec.locking);
console.log('artifact bytes:', artifact.length);

const OP = {
  IF: 0x63, NOTIF: 0x64, BEGIN: 0x65, UNTIL: 0x66, ELSE: 0x67, ENDIF: 0x68,
  VERIFY: 0x69, TOALT: 0x6b, FROMALT: 0x6c, DROP2: 0x6d, DUP2: 0x6e, DUP3: 0x6f,
  OVER2: 0x70, ROT2: 0x71, SWAP2: 0x72, IFDUP: 0x73, DEPTH: 0x74, DROP: 0x75,
  DUP: 0x76, NIP: 0x77, OVER: 0x78, PICK: 0x79, ROLL: 0x7a, ROT: 0x7b,
  SWAP: 0x7c, TUCK: 0x7d, DEFINE: 0x89, INVOKE: 0x8a,
  EQUALVERIFY: 0x88, NUMEQUALVERIFY: 0x9d, CHECKSIGVERIFY: 0xad, CHECKMULTISIGVERIFY: 0xaf,
  ACTIVEBYTECODE: 0xc1,
};
// value ops: opcode -> [pops, pushes] (from decompile.mjs, extended)
const VALOP = new Map([
  [0x7e,[2,1]],[0x7f,[2,2]],[0x80,[2,1]],[0x81,[1,1]],[0x82,[1,2]],[0x84,[2,1]],[0x85,[2,1]],
  [0x86,[2,1]],[0x87,[2,1]],[0x8b,[1,1]],[0x8c,[1,1]],[0x8d,[2,1]],[0x8e,[2,1]],[0x8f,[1,1]],
  [0x90,[1,1]],[0x91,[1,1]],[0x92,[1,1]],[0x93,[2,1]],[0x94,[2,1]],[0x95,[2,1]],[0x96,[2,1]],
  [0x97,[2,1]],[0x9a,[2,1]],[0x9b,[2,1]],[0x9c,[2,1]],[0x9e,[2,1]],[0x9f,[2,1]],[0xa0,[2,1]],
  [0xa1,[2,1]],[0xa2,[2,1]],[0xa3,[2,1]],[0xa4,[2,1]],[0xa5,[3,1]],[0xa6,[1,1]],[0xa7,[1,1]],
  [0xa8,[1,1]],[0xa9,[1,1]],[0xaa,[1,1]],[0xbc,[1,1]],
  [0xc0,[0,1]],[0xc1,[0,1]],[0xc2,[0,1]],[0xc3,[0,1]],[0xc4,[0,1]],[0xc5,[0,1]],
  [0xc6,[1,1]],[0xc7,[1,1]],[0xc8,[1,1]],[0xc9,[1,1]],[0xca,[1,1]],[0xcb,[1,1]],
  [0xcc,[1,1]],[0xcd,[1,1]],[0xce,[1,1]],[0xcf,[1,1]],[0xd0,[1,1]],[0xd1,[1,1]],[0xd2,[1,1]],[0xd3,[1,1]],
]);
const numOf = (o) => {
  if (o.data !== undefined) { let n = 0; for (let i = o.data.length - 1; i >= 0; i--) n = (n << 8) | o.data[i]; return n; }
  if (o.op === 0) return 0;
  if (o.op >= 0x51 && o.op <= 0x60) return o.op - 0x50;
  if (o.op === 0x4f) return -1;
  return undefined;
};
const isConst = (o) => o.data !== undefined || o.op === 0 || o.op === 0x4f || (o.op >= 0x51 && o.op <= 0x60);

// ---- dissect DEFINE table + main ----
function dissect(bytes) {
  const ops = parse(bytes);
  const bodies = new Map(); const order = [];
  let i = 0;
  while (i + 2 < ops.length && ops[i].data && ops[i + 2] && ops[i + 2].op === OP.DEFINE) {
    const id = numOf(ops[i + 1]);
    bodies.set(id, parse(ops[i].data)); order.push(id); i += 3;
  }
  return { bodies, order, mainOps: ops.slice(i) };
}
const D = dissect(artifact);
console.log('bodies:', D.bodies.size, ' main instr:', D.mainOps.length);

// ---- body arity via underflow-materializing simulation ----
const arity = new Map(); // id -> {inN, outN}
let UID = 0;
function simulate(ops, opts) {
  // opts: {record(access)? , regionKey, onRegion(key)}
  const rec = opts?.record;
  let region = opts?.regionKey ?? '?';
  const loopStack = [];
  let stack = []; let alt = [];
  let inN = 0;
  const snapshots = [];
  let unknownDepth = 0, computedRoll = 0;
  const need = (k) => { while (stack.length < k) { stack.unshift({ id: --UID, in: ++inN }); } };
  const fresh = () => ({ id: ++UID });
  for (let i = 0; i < ops.length; i++) {
    const o = ops[i];
    if (isConst(o)) {
      // lookahead: const feeding PICK/ROLL/INVOKE handled by that op
      const nx = ops[i + 1];
      if (nx && (nx.op === OP.PICK || nx.op === OP.ROLL)) {
        const d = numOf(o);
        if (d === undefined) { unknownDepth++; stack.push(fresh()); continue; }
        need(d + 1);
        const v = stack[stack.length - 1 - d];
        rec?.({ v: v.id, d, w: d <= 16 ? 1 : (o.hdr + (o.data?.length ?? 0)), region, roll: nx.op === OP.ROLL });
        if (nx.op === OP.ROLL) { stack.splice(stack.length - 1 - d, 1); stack.push(v); }
        else stack.push(v); // PICK: copy aliases same value
        i++; continue;
      }
      if (nx && nx.op === OP.INVOKE) {
        const id = numOf(o);
        const a = arity.get(id);
        if (!a) { // unknown callee: give up identity of whole stack
          stack = stack.map(fresh);
        } else {
          need(a.inN);
          stack.splice(stack.length - a.inN, a.inN);
          for (let k = 0; k < a.outN; k++) stack.push(fresh());
        }
        i++; continue;
      }
      stack.push(fresh()); continue;
    }
    const op = o.op;
    if (VALOP.has(op)) { const [p, q] = VALOP.get(op); need(p); stack.splice(stack.length - p, p); for (let k = 0; k < q; k++) stack.push(fresh()); continue; }
    switch (op) {
      case OP.DUP: need(1); stack.push(stack[stack.length - 1]); break;
      case OP.OVER: need(2); stack.push(stack[stack.length - 2]); break;
      case OP.SWAP: { need(2); const n = stack.length; [stack[n - 1], stack[n - 2]] = [stack[n - 2], stack[n - 1]]; break; }
      case OP.ROT: { need(3); const v = stack.splice(stack.length - 3, 1)[0]; stack.push(v); break; }
      case OP.TUCK: { need(2); const n = stack.length; stack.splice(n - 2, 0, stack[n - 1]); break; }
      case OP.NIP: need(2); stack.splice(stack.length - 2, 1); break;
      case OP.DROP: need(1); stack.pop(); break;
      case OP.DROP2: need(2); stack.pop(); stack.pop(); break;
      case OP.DUP2: need(2); stack.push(stack[stack.length - 2], stack[stack.length - 2]); break;
      case OP.DUP3: need(3); stack.push(stack[stack.length - 3], stack[stack.length - 3], stack[stack.length - 3]); break;
      case OP.OVER2: need(4); stack.push(stack[stack.length - 4], stack[stack.length - 4]); break;
      case OP.SWAP2: { need(4); const n = stack.length; const a1 = stack.splice(n - 4, 2); stack.push(...a1); break; }
      case OP.ROT2: { need(6); const a1 = stack.splice(stack.length - 6, 2); stack.push(...a1); break; }
      case OP.TOALT: need(1); alt.push(stack.pop()); break;
      case OP.FROMALT: if (alt.length === 0) alt.unshift({ id: --UID }); stack.push(alt.pop()); break;
      case OP.DEPTH: stack.push(fresh()); break;
      case OP.VERIFY: need(1); stack.pop(); break;
      case OP.EQUALVERIFY: case OP.NUMEQUALVERIFY: need(2); stack.pop(); stack.pop(); break;
      case OP.IF: case OP.NOTIF:
        need(1); stack.pop();
        snapshots.push({ stack: stack.slice(), alt: alt.slice() });
        break;
      case OP.ELSE: { const s = snapshots[snapshots.length - 1]; stack = s.stack.slice(); alt = s.alt.slice(); break; }
      case OP.ENDIF: snapshots.pop(); break;
      case OP.BEGIN:
        loopStack.push(region); region = region + '/L' + i;
        opts?.onRegion?.(region);
        break;
      case OP.UNTIL: need(1); stack.pop(); region = loopStack.pop(); break;
      case OP.PICK: case OP.ROLL: // computed depth
        computedRoll++; need(2); stack.pop(); if (op === OP.ROLL) { stack = stack.map(fresh); stack.pop(); } else { stack.pop(); stack.push(fresh()); }
        stack.push(fresh());
        break;
      case OP.INVOKE: // computed id (shouldn't happen)
        stack = stack.map(fresh); break;
      default:
        // unknown opcode: assume [0,0] but log
        if (!simulate.warned?.has(op)) { (simulate.warned ??= new Set()).add(op); console.log('  ?? unmodeled opcode 0x' + op.toString(16), 'treated as no-op'); }
    }
  }
  return { inN, outN: stack.length, unknownDepth, computedRoll };
}

// arity fixpoint over bodies (callees may be defined later; iterate)
for (let pass = 0; pass < 5; pass++) {
  let changed = false;
  for (const id of D.order) {
    const r = simulate(D.bodies.get(id));
    const prev = arity.get(id);
    if (!prev || prev.inN !== r.inN || prev.outN !== r.outN) { arity.set(id, { inN: r.inN, outN: r.outN }); changed = true; }
  }
  if (!changed) break;
}

// ---- census with recording ----
const accesses = []; // {v,d,w,region,roll}
for (const id of D.order) simulate(D.bodies.get(id), { record: (a) => accesses.push(a), regionKey: 'body' + id });
simulate(D.mainOps, { record: (a) => accesses.push(a), regionKey: 'main' });

const total2B = accesses.filter((a) => a.w > 1);
console.log('\n--- depth census ---');
console.log('total <depth> PICK/ROLL pairs:', accesses.length);
console.log('2-byte depth pushes:', total2B.length, '=> theoretical ceiling if ALL shallow:', total2B.reduce((s, a) => s + a.w - 1, 0), 'B');
const hist = {};
for (const a of accesses) { const b = a.d <= 2 ? '0-2' : a.d <= 8 ? '3-8' : a.d <= 16 ? '9-16' : a.d <= 32 ? '17-32' : a.d <= 64 ? '33-64' : '65+'; hist[b] = (hist[b] ?? 0) + 1; }
console.log('depth histogram:', JSON.stringify(hist));

// ---- greedy oracle per region ----
const regions = new Map();
for (const a of accesses) {
  if (!regions.has(a.region)) regions.set(a.region, new Map());
  const vm = regions.get(a.region);
  if (!vm.has(a.v)) vm.set(a.v, { deep: 0, deepBytes: 0, shallow916: 0, shallow38: 0 });
  const e = vm.get(a.v);
  if (a.w > 1) { e.deep++; e.deepBytes += a.w - 1; } else if (a.d >= 9) e.shallow916++; else if (a.d >= 3) e.shallow38++;
}
let oracleGross = 0, demotionPenalty = 0, relayout = 0, regionsWithWin = 0;
const detail = [];
for (const [rk, vm] of regions) {
  const vals = [...vm.values()];
  const cands = vals.filter((v) => v.deepBytes > 0).sort((a, b) => b.deepBytes - a.deepBytes);
  const promoted = cands.slice(0, 16);
  const gross = promoted.reduce((s, v) => s + v.deepBytes, 0);
  if (gross === 0) continue;
  // non-promoted values' currently-shallow (depth 9..16) accesses are at risk of demotion
  const promotedSet = new Set(promoted);
  const penalty = vals.filter((v) => !promotedSet.has(v)).reduce((s, v) => s + v.shallow916, 0);
  const re = 2 * Math.min(promoted.length, 16) * 2.5; // setup+teardown permutation per region
  oracleGross += gross; demotionPenalty += penalty; relayout += re; regionsWithWin++;
  detail.push({ rk, gross, penalty, re, values: vm.size, deepVals: cands.length });
}
detail.sort((a, b) => b.gross - a.gross);
console.log('\n--- greedy 16-hot oracle (per region, fixed layout) ---');
console.log('regions with any deep-access win:', regionsWithWin);
console.log('gross promotion saving:', oracleGross, 'B');
console.log('demotion-risk penalty (shallow 9-16 accesses of non-promoted):', demotionPenalty, 'B');
console.log('relayout estimate (2 x 16 x 2.5 B per region):', Math.round(relayout), 'B');
console.log('NET oracle range:', oracleGross - demotionPenalty - Math.round(relayout), '..', oracleGross - Math.round(relayout), 'B  (build threshold: 300 B)');
console.log('top regions:');
for (const d of detail.slice(0, 12)) console.log(`  ${d.rk.padEnd(28)} gross=${String(d.gross).padStart(4)} penalty=${String(d.penalty).padStart(4)} values=${d.values} deepVals=${d.deepVals}`);

// ---- outlining scan (item 7) ----
console.log('\n--- outlining scan ---');
// tokenize each script unit into instruction byte-strings
const units = [['main', D.mainOps], ...D.order.map((id) => ['body' + id, D.bodies.get(id)])];
const CTRL = new Set([OP.IF, OP.NOTIF, OP.ELSE, OP.ENDIF, OP.BEGIN, OP.UNTIL]);
const encode = (o) => { // canonical bytes of one instruction
  if (o.data !== undefined) { const h = o.data.length <= 75 ? [o.data.length] : o.data.length <= 255 ? [76, o.data.length] : [77, o.data.length & 255, o.data.length >> 8]; return Uint8Array.from([...h, ...o.data]); }
  return Uint8Array.from([o.op]);
};
const toks = units.map(([name, ops]) => ({ name, ops, enc: ops.map(encode), bytes: ops.map((o) => encode(o).length) }));
// candidate n-grams: instruction sequences, byteLen >= 5, balanced ctrl, no DEFINE/ACTIVEBYTECODE/UNTIL
const table = new Map(); // key -> {len, byteLen, sites: [unitIdx, start]}
for (let u = 0; u < toks.length; u++) {
  const { ops, enc, bytes } = toks[u];
  for (let s = 0; s < ops.length; s++) {
    let byteLen = 0, bal = 0, ok = true, key = '';
    for (let L = 0; L < Math.min(64, ops.length - s); L++) {
      const o = ops[s + L];
      if (o.op === OP.DEFINE || o.op === OP.ACTIVEBYTECODE || o.op === OP.BEGIN || o.op === OP.UNTIL) { ok = false; }
      if (o.op === OP.IF || o.op === OP.NOTIF) bal++;
      if (o.op === OP.ELSE && bal === 0) ok = false;
      if (o.op === OP.ENDIF) bal--;
      if (bal < 0) ok = false;
      if (!ok) break;
      byteLen += bytes[s + L];
      key += Buffer.from(enc[s + L]).toString('latin1');
      if (byteLen >= 5 && bal === 0 && L >= 1) {
        if (!table.has(key)) table.set(key, { len: L + 1, byteLen, sites: [] });
        table.get(key).sites.push([u, s]);
      }
    }
  }
}
// net saving model: id >= 17 (2-byte push) => invoke site 3 B; define frame = pushHeader + body + idPush(2) + 1
const defineOverhead = (L) => (L <= 75 ? 1 : L <= 255 ? 2 : 3) + 2 + 1;
const net = (c, k) => k * c.byteLen - defineOverhead(c.byteLen) - c.byteLen - k * 3;
// greedy non-overlapping selection
const covered = toks.map(({ ops }) => new Array(ops.length).fill(false));
let totalSaved = 0; const chosen = [];
const cands = [...table.values()].filter((c) => c.sites.length >= 2 && net(c, c.sites.length) > 0);
cands.sort((a, b) => net(b, b.sites.length) - net(a, a.sites.length));
for (const c of cands) {
  const free = c.sites.filter(([u, s]) => { for (let i = 0; i < c.len; i++) if (covered[u][s + i]) return false; return true; });
  // drop overlapping occurrences within the same candidate (e.g. periodic sequences)
  const picked = [];
  const lastEnd = new Map();
  for (const [u, s] of free) { const le = lastEnd.get(u) ?? -1; if (s > le) { picked.push([u, s]); lastEnd.set(u, s + c.len - 1); } }
  const n = net(c, picked.length);
  if (picked.length < 2 || n <= 0) continue;
  for (const [u, s] of picked) for (let i = 0; i < c.len; i++) covered[u][s + i] = true;
  totalSaved += n; chosen.push({ byteLen: c.byteLen, len: c.len, k: picked.length, n, u: picked[0][0], s: picked[0][1], sites: picked });
}
console.log('candidates with positive net:', cands.length, ' chosen (non-overlapping):', chosen.length);
console.log('TOTAL outlining net saving:', totalSaved, 'B =', (totalSaved / artifact.length * 100).toFixed(2) + '% (build threshold ~1% =', Math.round(artifact.length / 100), 'B)');
chosen.sort((a, b) => b.n - a.n);
const NAMES = { 0x69:'VERIFY',0x6b:'TOALT',0x6c:'FROMALT',0x6d:'2DROP',0x6e:'2DUP',0x70:'2OVER',0x71:'2ROT',0x72:'2SWAP',0x75:'DROP',0x76:'DUP',0x77:'NIP',0x78:'OVER',0x79:'PICK',0x7a:'ROLL',0x7b:'ROT',0x7c:'SWAP',0x7d:'TUCK',0x7e:'CAT',0x7f:'SPLIT',0x80:'NUM2BIN',0x81:'BIN2NUM',0x82:'SIZE',0x87:'EQUAL',0x88:'EQUALVERIFY',0x8a:'INVOKE',0x8b:'1ADD',0x8c:'1SUB',0x8f:'NEGATE',0x90:'ABS',0x91:'NOT',0x93:'ADD',0x94:'SUB',0x95:'MUL',0x96:'DIV',0x97:'MOD',0x9c:'NUMEQUAL',0x9d:'NUMEQUALVERIFY',0x9f:'LT',0xa0:'GT',0xa3:'MIN',0xa4:'MAX',0xaa:'HASH256',0x63:'IF',0x64:'NOTIF',0x67:'ELSE',0x68:'ENDIF' };
const disasm = (ops) => ops.map((o) => o.data !== undefined ? (o.data.length <= 4 ? '<' + Buffer.from(o.data).toString('hex') + '>' : `<${o.data.length}B>`) : o.op === 0 ? '<0>' : (o.op >= 0x51 && o.op <= 0x60) ? '<' + (o.op - 0x50) + '>' : (NAMES[o.op] ?? '0x' + o.op.toString(16))).join(' ');
for (const c of chosen.slice(0, 15)) {
  const seq = toks[c.u].ops.slice(c.s, c.s + c.len);
  console.log(`  seq ${String(c.byteLen).padStart(3)} B x${c.k}  net ${c.n} B   [${toks[c.u].name}]  ${disasm(seq)}`);
}

// ---- APPLY=1: rewrite the artifact with all chosen outlines and verify ----
if (process.env.APPLY === '1') {
  const { serialize } = await import('./asm.mjs');
  const { evalFull } = await import('./recompiler.mjs');
  const maxId = Math.max(...D.order);
  console.log('\n--- APPLY: rewriting artifact ---');
  console.log('existing ids: 0..' + maxId, ' new ids:', maxId + 1, '..', maxId + chosen.length);
  const encodeIdPush = (id) => { // minimal VM-number data push
    if (id === 0) return [{ op: 0, hdr: 1 }];
    if (id <= 16) return [{ op: 0x50 + id, hdr: 1 }];
    const data = [];
    let n = id;
    while (n > 0) { data.push(n & 0xff); n >>= 8; }
    if (data[data.length - 1] & 0x80) data.push(0);
    return [{ op: data.length, hdr: 1, data: Uint8Array.from(data) }];
  };
  // per-unit replacements
  const repl = toks.map(() => []);
  const newBodies = [];
  chosen.forEach((c, idx) => {
    const id = maxId + 1 + idx;
    newBodies.push({ id, ops: toks[c.u].ops.slice(c.s, c.s + c.len) });
    for (const [u, s] of c.sites) repl[u].push({ s, len: c.len, id });
  });
  const rewritten = toks.map((t, u) => {
    let ops = t.ops.slice();
    for (const r of repl[u].sort((a, b) => b.s - a.s)) {
      ops.splice(r.s, r.len, ...encodeIdPush(r.id), { op: OP.INVOKE, hdr: 1 });
    }
    return { name: t.name, ops };
  });
  // rebuild: defines (old bodies, possibly rewritten) + new bodies + main
  const frames = [];
  for (const t of rewritten) {
    if (t.name === 'main') continue;
    const id = Number(t.name.slice(4));
    frames.push({ id, body: serialize(t.ops) });
  }
  for (const nb of newBodies) frames.push({ id: nb.id, body: serialize(nb.ops) });
  const chunks = [];
  for (const f of frames) {
    const b = f.body;
    const hdr = b.length <= 75 ? [b.length] : b.length <= 255 ? [76, b.length] : [77, b.length & 255, b.length >> 8];
    chunks.push(Uint8Array.from(hdr), b);
    for (const p of encodeIdPush(f.id)) chunks.push(p.data !== undefined ? Uint8Array.from([p.data.length, ...p.data]) : Uint8Array.from([p.op]));
    chunks.push(Uint8Array.from([OP.DEFINE]));
  }
  chunks.push(serialize(rewritten.find((t) => t.name === 'main').ops));
  let total = chunks.reduce((s, c) => s + c.length, 0);
  const out = new Uint8Array(total);
  let o = 0; for (const c of chunks) { out.set(c, o); o += c.length; }
  console.log('rewritten artifact:', out.length, 'B (was', artifact.length, 'B) saving', artifact.length - out.length, 'B =', ((artifact.length - out.length) / artifact.length * 100).toFixed(2) + '%');
  const acc = evalFull(out, hexToBin(vec.unlocking));
  const rej = evalFull(out, hexToBin(vec.invalidUnlocking));
  console.log('accept(valid):', acc.accepted, acc.error ?? '', ' opCost:', acc.operationCost?.toLocaleString?.() ?? acc.operationCost);
  console.log('reject(invalid):', !rej.accepted);
  const mpPath = VEC.replace('-vectors.json', '-multiproof-vectors.json');
  try {
    const mp = JSON.parse(readFileSync(mpPath, 'utf8'));
    const proofs = mp.proofs ?? mp.vectors ?? mp;
    let ok = 0, bad = 0;
    for (const p of proofs) {
      if (!p.unlocking) continue;
      if (evalFull(out, hexToBin(p.unlocking)).accepted) ok++; else bad++;
    }
    console.log('multiproof: accepted', ok, ' failed', bad);
  } catch (e) { console.log('multiproof check skipped:', e.message.slice(0, 80)); }
}
