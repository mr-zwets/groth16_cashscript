// Auto-outlining post-pass (roadmap item 7): factor repeated instruction subsequences
// of an assembled locking artifact into OP_DEFINE bodies invoked from each repeat site.
//
// The transformation is byte-exact by construction: an outlined body contains exactly
// the instruction bytes it replaces, and OP_INVOKE executes them on the same shared
// stack, so any stack context that was valid for the inline sequence is valid for the
// call. Candidate constraints keep that argument airtight:
//   - instruction-boundary aligned, 2..64 instructions, >= 5 bytes;
//   - balanced control flow (IF/NOTIF..ENDIF nesting closed inside the sequence, no
//     bare ELSE/ENDIF), no BEGIN/UNTIL (loop back-edges cannot be split);
//   - no OP_DEFINE (nested definition is invalid) and no OP_ACTIVEBYTECODE (its result
//     differs inside a function body vs inline).
//
// Selection is greedy per pass (best net saving first, non-overlapping sites), and
// passes iterate to a fixpoint so outlined bodies are themselves scanned (outline of
// outlines). Net model per candidate: k sites of L bytes collapse to k id-push+INVOKE
// call sites plus one define frame; the id-push length is priced with the actually
// allocated id, and a candidate is dropped if its net is no longer positive.
//
// Verification: the caller passes `verify(bytes) -> bool` (typically: committed valid
// witness accepts AND tampered witness rejects on the loosened VM). Each pass's batch
// of rewrites is verified together; if a batch fails, the pass re-applies its rewrites
// one at a time, verifying each, and drops the offender(s) - so every kept rewrite is
// covered by a passing verification. A failure has never been observed (the rewrite is
// byte-exact); the machinery is a safety net.
//
// This pass trades executed op-cost (one id push + OP_INVOKE per dynamic call) for
// static bytes. Use it on byte-scored artifacts only; never on op-bound builds.
import { parse, serialize } from './asm.mjs';

const OP = {
  IF: 0x63, NOTIF: 0x64, BEGIN: 0x65, UNTIL: 0x66, ELSE: 0x67, ENDIF: 0x68,
  DEFINE: 0x89, INVOKE: 0x8a, ACTIVEBYTECODE: 0xc1,
};
const MAX_ID = 999;          // VM function-identifier ceiling
const MAX_SEQ_INSTRS = 64;   // longest candidate sequence considered
const MIN_SEQ_BYTES = 5;     // below this a define frame can never pay

const numOf = (o) => {
  if (o.data !== undefined) { let n = 0; for (let i = o.data.length - 1; i >= 0; i--) n = (n << 8) | o.data[i]; return n; }
  if (o.op === 0) return 0;
  if (o.op >= 0x51 && o.op <= 0x60) return o.op - 0x50;
  return undefined;
};

// minimal VM-number push for a function id, as an asm.mjs op object
function idPushOp(id) {
  if (id === 0) return { op: 0, hdr: 1 };
  if (id <= 16) return { op: 0x50 + id, hdr: 1 };
  const data = [];
  let n = id;
  while (n > 0) { data.push(n & 0xff); n >>= 8; }
  if (data[data.length - 1] & 0x80) data.push(0);
  return { op: data.length, hdr: 1, data: Uint8Array.from(data) };
}
const idPushLen = (id) => (id <= 16 ? 1 : idPushOp(id).data.length + 1);
const pushHeaderLen = (n) => (n <= 75 ? 1 : n <= 255 ? 2 : 3);
const instrLen = (o) => (o.data !== undefined ? pushHeaderLen(o.data.length) + o.data.length : 1);

// split an artifact into its OP_DEFINE frame table + main routine
export function dissectArtifact(bytes) {
  const ops = parse(bytes);
  const frames = []; // {id, ops} in table order
  let i = 0;
  while (i + 2 < ops.length && ops[i].data !== undefined && ops[i + 2].op === OP.DEFINE) {
    const id = numOf(ops[i + 1]);
    if (id === undefined) break;
    frames.push({ id, ops: parse(ops[i].data) });
    i += 3;
  }
  return { frames, main: ops.slice(i) };
}

export function rebuildArtifact({ frames, main }) {
  const chunks = [];
  for (const f of frames) {
    const body = serialize(f.ops);
    const hdr = body.length <= 75 ? [body.length] : body.length <= 255 ? [76, body.length] : [77, body.length & 255, body.length >> 8];
    chunks.push(Uint8Array.from(hdr), body, serialize([idPushOp(f.id)]), Uint8Array.from([OP.DEFINE]));
  }
  chunks.push(serialize(main));
  const total = chunks.reduce((s, c) => s + c.length, 0);
  const out = new Uint8Array(total);
  let o = 0; for (const c of chunks) { out.set(c, o); o += c.length; }
  return out;
}

// one scan: greedy non-overlapping candidate set over all units (bodies + main)
function scanOnce(units, nextId) {
  const keyed = units.map(({ ops }) => ({ ops, enc: ops.map((o) => Buffer.from(serialize([o])).toString('latin1')), len: ops.map(instrLen) }));
  const table = new Map(); // key -> {nInstr, byteLen, sites: [u, start]}
  for (let u = 0; u < keyed.length; u++) {
    const { ops, enc, len } = keyed[u];
    for (let s = 0; s < ops.length; s++) {
      let byteLen = 0, bal = 0, key = '';
      for (let L = 0; L < Math.min(MAX_SEQ_INSTRS, ops.length - s); L++) {
        const o = ops[s + L];
        if (o.op === OP.DEFINE || o.op === OP.ACTIVEBYTECODE || o.op === OP.BEGIN || o.op === OP.UNTIL) break;
        if (o.op === OP.ELSE && bal === 0) break;
        if (o.op === OP.IF || o.op === OP.NOTIF) bal++;
        if (o.op === OP.ENDIF) { bal--; if (bal < 0) break; }
        byteLen += len[s + L];
        key += enc[s + L];
        if (byteLen >= MIN_SEQ_BYTES && bal === 0 && L >= 1) {
          let c = table.get(key);
          if (!c) table.set(key, c = { nInstr: L + 1, byteLen, sites: [] });
          c.sites.push([u, s]);
        }
      }
    }
  }
  // net saving with the id this candidate would actually get (ids grow as we pick)
  const netAt = (c, k, id) => {
    const site = idPushLen(id) + 1;
    return k * c.byteLen - k * site - (pushHeaderLen(c.byteLen) + c.byteLen + idPushLen(id) + 1);
  };
  const covered = keyed.map(({ ops }) => new Array(ops.length).fill(false));
  const cands = [...table.values()].filter((c) => c.sites.length >= 2 && netAt(c, c.sites.length, nextId) > 0);
  cands.sort((a, b) => netAt(b, b.sites.length, nextId) - netAt(a, a.sites.length, nextId));
  const chosen = [];
  let id = nextId;
  for (const c of cands) {
    if (id > MAX_ID) break;
    // non-overlapping sites: against already-chosen candidates and within this one
    const picked = [];
    const lastEnd = new Map();
    outer: for (const [u, s] of c.sites) {
      for (let i = 0; i < c.nInstr; i++) if (covered[u][s + i]) continue outer;
      const le = lastEnd.get(u) ?? -1;
      if (s > le) { picked.push([u, s]); lastEnd.set(u, s + c.nInstr - 1); }
    }
    const n = netAt(c, picked.length, id);
    if (picked.length < 2 || n <= 0) continue;
    for (const [u, s] of picked) for (let i = 0; i < c.nInstr; i++) covered[u][s + i] = true;
    chosen.push({ id, nInstr: c.nInstr, byteLen: c.byteLen, sites: picked, net: n, ops: units[picked[0][0]].ops.slice(picked[0][1], picked[0][1] + c.nInstr) });
    id++;
  }
  return chosen;
}

// apply a set of chosen candidates to a dissected artifact (units = frames + main)
function applyChosen(dis, units, chosen) {
  const repl = units.map(() => []);
  for (const c of chosen) for (const [u, s] of c.sites) repl[u].push({ s, nInstr: c.nInstr, id: c.id });
  const frames = dis.frames.map((f, i) => ({ id: f.id, ops: spliceUnit(units[i].ops, repl[i]) }));
  const main = spliceUnit(units[units.length - 1].ops, repl[units.length - 1]);
  for (const c of chosen) frames.push({ id: c.id, ops: c.ops });
  return { frames, main };
}
function spliceUnit(ops, repls) {
  if (repls.length === 0) return ops;
  const out = ops.slice();
  for (const r of repls.sort((a, b) => b.s - a.s)) out.splice(r.s, r.nInstr, idPushOp(r.id), { op: OP.INVOKE, hdr: 1 });
  return out;
}

/**
 * Outline repeated instruction sequences of `bytes` to a fixpoint.
 * opts.verify(candidateBytes) -> bool: accept/reject gate run on every pass's batch;
 *   on failure the pass isolates per rewrite. No verify => structural-only (not for
 *   production vectors).
 * opts.log: progress logger (e.g. console.log).
 * Returns { bytes, passes: [{candidates, saved}], saved }.
 */
export function outlineArtifact(bytes, opts = {}) {
  const log = opts.log ?? (() => {});
  let cur = bytes;
  const passes = [];
  for (let pass = 1; ; pass++) {
    const dis = dissectArtifact(cur);
    const units = [...dis.frames.map((f) => ({ ops: f.ops })), { ops: dis.main }];
    const nextId = Math.max(-1, ...dis.frames.map((f) => f.id)) + 1;
    const chosen = scanOnce(units, nextId);
    if (chosen.length === 0) break;
    let candidate = rebuildArtifact(applyChosen(dis, units, chosen));
    let kept = chosen;
    if (opts.verify && !opts.verify(candidate)) {
      log(`  outline pass ${pass}: batch verification FAILED, isolating per rewrite ...`);
      kept = [];
      let good = cur;
      for (const c of chosen) {
        const dg = dissectArtifact(good);
        const ug = [...dg.frames.map((f) => ({ ops: f.ops })), { ops: dg.main }];
        // re-locate this candidate's sequence in the current artifact by rescanning
        const re = scanOnce(ug, Math.max(-1, ...dg.frames.map((f) => f.id)) + 1)
          .find((x) => x.byteLen === c.byteLen && x.nInstr === c.nInstr && Buffer.from(serialize(x.ops)).equals(Buffer.from(serialize(c.ops))));
        if (!re) continue;
        const trial = rebuildArtifact(applyChosen(dg, ug, [re]));
        if (opts.verify(trial)) { good = trial; kept.push(re); }
        else log(`  outline: dropped a ${re.byteLen} B x${re.sites.length} rewrite (verification failed)`);
      }
      candidate = good;
      if (kept.length === 0) break;
    }
    const saved = cur.length - candidate.length;
    if (saved <= 0) break;
    log(`  outline pass ${pass}: ${kept.length} sequences, ${cur.length} -> ${candidate.length} B (-${saved})`);
    passes.push({ candidates: kept.length, saved });
    cur = candidate;
  }
  return { bytes: cur, passes, saved: bytes.length - cur.length };
}
