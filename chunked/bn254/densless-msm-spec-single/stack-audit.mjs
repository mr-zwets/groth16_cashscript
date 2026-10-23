// Static stack-ownership audit of the merged single-input program.
//
// The merged redeem runs the five former inputs' programs one after another on one stack.
// Their soundness argument is unchanged only if every stage reads exactly the values it read
// as a separate input. This audit abstractly interprets the whole redeem (function calls
// inlined, constant-folded loop counters and stack depths, both arms of every branch whose
// condition is witness-dependent) over a stack whose initial items are labelled with the
// stage that owns them. It fails if any instruction of stage S touches (pops, picks, rolls,
// permutes or consumes) an item that carries a label other than S's own items or values S
// computed itself, unless that exact (stage, label) access is in `allowed` (the explicit
// hand-off points: the shared genesis block, the genesis copy of header 0, the glue code
// that moves each executor's fixed table and header). It also requires every PICK/ROLL depth
// to be a compile-time constant and every branch to rejoin with the same stack height.
import assert from 'node:assert/strict';
import {OpcodesBCH} from '@bitauth/libauth';
import {isPush, numberOf} from './ir.mjs';

const O = OpcodesBCH;
// [pops, pushes] for opcodes whose outputs are fresh values (no identity flow).
const FRESH = {
  OP_ADD: [2, 1], OP_SUB: [2, 1], OP_MUL: [2, 1], OP_DIV: [2, 1], OP_MOD: [2, 1], OP_BOOLAND: [2, 1], OP_BOOLOR: [2, 1],
  OP_NUMEQUAL: [2, 1], OP_NUMNOTEQUAL: [2, 1], OP_LESSTHAN: [2, 1], OP_LESSTHANOREQUAL: [2, 1], OP_GREATERTHAN: [2, 1],
  OP_GREATERTHANOREQUAL: [2, 1], OP_EQUAL: [2, 1], OP_CAT: [2, 1], OP_SPLIT: [2, 2], OP_NUM2BIN: [2, 1], OP_RSHIFTNUM: [2, 1],
  OP_LSHIFTNUM: [2, 1], OP_MIN: [2, 1], OP_MAX: [2, 1], OP_AND: [2, 1], OP_OR: [2, 1], OP_XOR: [2, 1],
  OP_NUMEQUALVERIFY: [2, 0], OP_EQUALVERIFY: [2, 0], OP_VERIFY: [1, 0],
  OP_1ADD: [1, 1], OP_1SUB: [1, 1], OP_NEGATE: [1, 1], OP_ABS: [1, 1], OP_NOT: [1, 1], OP_0NOTEQUAL: [1, 1],
  OP_BIN2NUM: [1, 1], OP_REVERSEBYTES: [1, 1], OP_HASH256: [1, 1], OP_SHA256: [1, 1], OP_HASH160: [1, 1],
  OP_INPUTBYTECODE: [1, 1], OP_UTXOBYTECODE: [1, 1], OP_OUTPOINTINDEX: [1, 1], OP_WITHIN: [3, 1],
  OP_INPUTINDEX: [0, 1], OP_TXINPUTCOUNT: [0, 1], OP_ACTIVEBYTECODE: [0, 1],
};
const FOLD = {
  OP_ADD: (a, b) => a + b, OP_SUB: (a, b) => a - b, OP_MUL: (a, b) => a * b,
  OP_NUMEQUAL: (a, b) => BigInt(a === b), OP_NUMNOTEQUAL: (a, b) => BigInt(a !== b), OP_LESSTHAN: (a, b) => BigInt(a < b),
  OP_LESSTHANOREQUAL: (a, b) => BigInt(a <= b), OP_GREATERTHAN: (a, b) => BigInt(a > b), OP_GREATERTHANOREQUAL: (a, b) => BigInt(a >= b),
  OP_BOOLAND: (a, b) => BigInt(a !== 0n && b !== 0n), OP_BOOLOR: (a, b) => BigInt(a !== 0n || b !== 0n),
  OP_1ADD: (a) => a + 1n, OP_1SUB: (a) => a - 1n, OP_NOT: (a) => BigInt(a === 0n), OP_0NOTEQUAL: (a) => BigInt(a !== 0n),
};
const OPNAME = Object.fromEntries(Object.entries(O).filter(([k]) => isNaN(Number(k))).map(([k, v]) => [v, k]));

const item = (labels, v) => ({labels: new Set(labels), v});
const fresh = (stage, v) => item([`@${stage}`], v);

export function audit({defs, main}, {stack: init, alt: initAlt = [], allowed = [], maxSteps = 5e7}) {
  const allow = new Set(allowed.map(([s, l]) => `${s}|${l}`));
  const violations = new Map();
  const touches = new Map(); // label -> Set(stage)
  let steps = 0;
  const runtime = new Map(); // functions defined while running: key -> body item
  const where = [];
  const touch = (stage, it, what) => {
    for (const l of it.labels) {
      if (!touches.has(l)) touches.set(l, new Set());
      touches.get(l).add(stage);
      if (stage === 'glue') continue; // the hand-off code between stages may move anything
      // initial items are labelled owner/name; values computed by a stage are labelled @stage
      const owner = l.startsWith('@') ? l.slice(1) : l.split('/')[0];
      if (owner === stage || allow.has(`${stage}|${l}`)) continue;
      violations.set(`${stage} touches ${l} (${what})`, (violations.get(`${stage} touches ${l} (${what})`) ?? []).concat([where.join('>')]));
    }
  };
  const merge = (a, b) => {
    assert.equal(a.st.length, b.st.length, 'branch arms leave different stack heights');
    assert.equal(a.alt.length, b.alt.length, 'branch arms leave different altstack heights');
    const m = (x, y) => (x === y ? x : item([...x.labels, ...y.labels], x.v !== undefined && x.v === y.v ? x.v : undefined));
    return {st: a.st.map((x, i) => m(x, b.st[i])), alt: a.alt.map((x, i) => m(x, b.alt[i]))};
  };
  const same = (a, b) => a.st.length === b.st.length && a.alt.length === b.alt.length &&
    a.st.every((x, i) => x === b.st[i] || (x.v === b.st[i].v && [...x.labels].every((l) => b.st[i].labels.has(l)) && x.labels.size === b.st[i].labels.size)) &&
    a.alt.every((x, i) => x === b.alt[i] || ([...x.labels].every((l) => b.alt[i].labels.has(l)) && x.labels.size === b.alt[i].labels.size));

  // Execute `code` (array of instructions) on state s. Returns the new state.
  const run = (code, s0, stage, depth = 0) => {
    assert(depth < 200, 'call depth');
    let s = {st: [...s0.st], alt: [...s0.alt]};
    let i = 0;
    const pop = (what) => { assert(s.st.length > 0, `stack underflow at ${what}`); const it = s.st.pop(); touch(stage, it, what); return it; };
    const peek = (n, what) => { assert(s.st.length > n, `stack underflow at ${what}`); const it = s.st[s.st.length - 1 - n]; touch(stage, it, what); return it; };
    // find matching ELSE/ENDIF or UNTIL
    const scan = (from, open, closers) => {
      let d = 0;
      for (let j = from; j < code.length; j++) {
        const x = code[j];
        if (x.call !== undefined || x.fnref !== undefined || x.pseudo !== undefined) continue;
        if (open.includes(x.opcode)) d++;
        else if (closers.includes(x.opcode)) { if (d === 0) return j; if (x.opcode !== O.OP_ELSE) d--; }
      }
      throw new Error('unbalanced control flow');
    };
    while (i < code.length) {
      if (++steps > maxSteps) throw new Error('audit step limit');
      const x = code[i];
      where[depth] = i; where.length = depth + 1;
      if (x.pseudo === 'stage') { stage = x.stage; i++; continue; }
      if (x.pseudo === 'pick' || x.pseudo === 'roll') {
        // a designated hand-off: the unique item carrying exactly this label, at a depth that
        // must be the same on every path (recorded for the encoder)
        const hits = s.st.map((it, k) => (it.labels.size === 1 && it.labels.has(x.label) ? k : -1)).filter((k) => k >= 0);
        assert.equal(hits.length, 1, `${stage}: ${x.pseudo} ${x.label} must find exactly one item`);
        const d = s.st.length - 1 - hits[0];
        (x.depths ??= new Set()).add(d);
        const it = peek(d, `${x.pseudo} ${x.label}`);
        if (x.pseudo === 'roll') s.st.splice(hits[0], 1);
        s.st.push(it); i++; continue;
      }
      if (x.call !== undefined && runtime.has(x.call)) {
        // a function whose body is one data push (defined by the glue): pushes a copy of it
        s.st.push(item([`fn/${x.call}`])); i++; continue;
      }
      if (x.call !== undefined) {
        const body = defs.get(x.call);
        assert(body, `call to undefined ${x.call}`);
        if (body.length && body[0].opcode === O.OP_INVOKE && body[0].call === undefined) {
          // dynamic invoker: callee identifier is on top of the stack
          const f = pop('dynamic callee');
          assert(f.fnref, `dynamic invoke of ${x.call} without a constant callee`);
          s = run(defs.get(f.fnref), s, stage, depth + 1);
          s = run(body.slice(1), s, stage, depth + 1);
        } else s = run(body, s, stage, depth + 1);
        i++; continue;
      }
      if (x.fnref !== undefined) { s.st.push({labels: new Set([`@${stage}`]), fnref: x.fnref}); i++; continue; }
      const n = OPNAME[x.opcode];
      if (isPush(x)) {
        let v; try { v = numberOf(x); } catch { v = undefined; }
        if (x.data !== undefined && x.data.length > 8) v = undefined;
        s.st.push(fresh(stage, v)); i++; continue;
      }
      switch (n) {
        case 'OP_IF': case 'OP_NOTIF': {
          const c = pop(n);
          const elseAt = scan(i + 1, [O.OP_IF, O.OP_NOTIF], [O.OP_ELSE, O.OP_ENDIF]);
          const endAt = code[elseAt].opcode === O.OP_ELSE ? scan(elseAt + 1, [O.OP_IF, O.OP_NOTIF], [O.OP_ENDIF]) : elseAt;
          const thenCode = code.slice(i + 1, elseAt), elseCode = elseAt === endAt ? [] : code.slice(elseAt + 1, endAt);
          if (c.v !== undefined) {
            const take = (c.v !== 0n) === (n === 'OP_IF');
            s = run(take ? thenCode : elseCode, s, stage, depth + 1);
          } else s = merge(run(thenCode, s, stage, depth + 1), run(elseCode, s, stage, depth + 1));
          i = endAt + 1; continue;
        }
        case 'OP_BEGIN': {
          const untilAt = scan(i + 1, [O.OP_BEGIN], [O.OP_UNTIL]);
          const body = code.slice(i + 1, untilAt);
          for (let iter = 0; ; iter++) {
            assert(iter < 100000, 'loop bound');
            const before = s;
            s = run(body, s, stage, depth + 1);
            const c = pop('OP_UNTIL');
            if (c.v !== undefined) { if (c.v !== 0n) break; continue; }
            // witness-dependent trip count: iterate to a fixpoint of the abstract state
            const joined = merge(before, s);
            if (same(joined, before)) { s = joined; break; }
            s = joined;
          }
          i = untilAt + 1; continue;
        }
        case 'OP_PICK': case 'OP_ROLL': {
          const d = pop(n);
          assert(d.v !== undefined, `${stage}: non-constant ${n} depth`);
          const k = Number(d.v);
          const it = peek(k, `${n} ${k}`);
          if (n === 'OP_ROLL') s.st.splice(s.st.length - 1 - k, 1);
          s.st.push(it); i++; continue;
        }
        case 'OP_DEPTH': s.st.push(fresh(stage, BigInt(s.st.length))); i++; continue;
        case 'OP_DEFINE': {
          const id = pop(n), body = pop(n);
          assert(id.fnref !== undefined && !defs.has(id.fnref) && !runtime.has(id.fnref), `${stage}: OP_DEFINE needs a fresh constant identifier`);
          assert.equal(stage, 'glue', 'only the glue defines functions at run time');
          runtime.set(id.fnref, body); i++; continue;
        }
        case 'OP_DUP': s.st.push(peek(0, n)); i++; continue;
        case 'OP_OVER': s.st.push(peek(1, n)); peek(0, n); i++; continue;
        case 'OP_2DUP': { const a = peek(1, n), b = peek(0, n); s.st.push(a, b); i++; continue; }
        case 'OP_3DUP': { const a = peek(2, n), b = peek(1, n), c = peek(0, n); s.st.push(a, b, c); i++; continue; }
        case 'OP_2OVER': { const a = peek(3, n), b = peek(2, n); peek(1, n); peek(0, n); s.st.push(a, b); i++; continue; }
        case 'OP_DROP': pop(n); i++; continue;
        case 'OP_2DROP': pop(n); pop(n); i++; continue;
        case 'OP_NIP': { const a = pop(n); pop(n); s.st.push(a); i++; continue; }
        case 'OP_SWAP': { const a = pop(n), b = pop(n); s.st.push(a, b); i++; continue; }
        case 'OP_TUCK': { const a = pop(n), b = pop(n); s.st.push(a, b, a); i++; continue; }
        case 'OP_ROT': { const c = pop(n), b = pop(n), a = pop(n); s.st.push(b, c, a); i++; continue; }
        case 'OP_2SWAP': { const d4 = pop(n), c = pop(n), b = pop(n), a = pop(n); s.st.push(c, d4, a, b); i++; continue; }
        case 'OP_2ROT': { const f = pop(n), e = pop(n), d4 = pop(n), c = pop(n), b = pop(n), a = pop(n); s.st.push(c, d4, e, f, a, b); i++; continue; }
        case 'OP_TOALTSTACK': s.alt.push(pop(n)); i++; continue;
        case 'OP_FROMALTSTACK': { assert(s.alt.length > 0, `${stage}: altstack underflow`); const it = s.alt.pop(); touch(stage, it, n); s.st.push(it); i++; continue; }
        case 'OP_SIZE': { const a = peek(0, n); s.st.push(fresh(stage, undefined)); void a; i++; continue; }
        case 'OP_INVOKE': throw new Error(`${stage}: unexpected dynamic OP_INVOKE`);
        case 'OP_ELSE': case 'OP_ENDIF': case 'OP_UNTIL': throw new Error(`stray ${n}`);
        default: {
          const e = FRESH[n];
          assert(e, `${stage}: no stack model for ${n}`);
          const args = [];
          for (let k = 0; k < e[0]; k++) args.unshift(pop(n));
          let v;
          if (FOLD[n] && args.every((a) => a.v !== undefined)) v = FOLD[n](...args.map((a) => a.v));
          if (n === 'OP_VERIFY' || n.endsWith('VERIFY')) { /* no output */ }
          for (let k = 0; k < e[1]; k++) s.st.push(fresh(stage, k === 0 ? v : undefined));
          i++; continue;
        }
      }
    }
    return s;
  };
  const s0 = {st: init.map((l) => item([l])), alt: initAlt.map((l) => item([l]))};
  const end = run(main, s0, 'glue');
  return {violations: [...violations.keys()], sites: violations, touches, final: end, steps};
}
