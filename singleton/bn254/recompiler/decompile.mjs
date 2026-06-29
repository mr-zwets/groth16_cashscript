// Decompiler: a subroutine body -> linear sequence of [Block | CtrlOp].
// Each Block is a straight-line segment: it transforms an entry stack of
// `entryDepth` opaque slots into an exit stack of value-DAGs over those slots.
// Control opcodes (IF/NOTIF/ELSE/ENDIF/BEGIN/UNTIL) are recorded verbatim between
// blocks. Because each block's entry stack is relabeled as fresh slots and we
// preserve the physical stack layout at every boundary, blocks can be
// re-scheduled independently and recomposed with the control opcodes unchanged.
import { parse } from './asm.mjs';

const OPC = {
  TOALT: 0x6b, FROMALT: 0x6c, '2DROP': 0x6d, '2DUP': 0x6e,
  '2OVER': 0x70, '2ROT': 0x71, '2SWAP': 0x72, NIP: 0x77, OVER: 0x78,
  PICK: 0x79, ROLL: 0x7a, ROT: 0x7b, SWAP: 0x7c, TUCK: 0x7d,
  DROP: 0x75, DUP: 0x76,
  IF: 0x63, NOTIF: 0x64, BEGIN: 0x65, UNTIL: 0x66, ELSE: 0x67, ENDIF: 0x68,
  INVOKE: 0x8a, DEFINE: 0x89, NUMEQUALVERIFY: 0x9d, VERIFY: 0x69, EQUALVERIFY: 0x88,
};
// NUMEQUALVERIFY/EQUALVERIFY (pop 2) and VERIFY (pop 1) are side-effecting checks (require()).
// They produce no stack value, so we treat them as block boundaries emitted verbatim (like
// IF): the preceding block leaves the operands on top, the verify consumes them. This keeps
// the value-DAG pure within each block and lets the main routine be recompiled.
const CTRL = new Set([OPC.IF, OPC.NOTIF, OPC.BEGIN, OPC.UNTIL, OPC.ELSE, OPC.ENDIF, OPC.NUMEQUALVERIFY, OPC.VERIFY, OPC.EQUALVERIFY]);
// value-producing binary/unary ops: opcode -> {in, out}
const VALOP = new Map([
  [0x8b, [1, 1]], [0x91, [1, 1]],                       // 1ADD, NOT
  [0x8d, [2, 1]], [0x8e, [2, 1]],                       // LSHIFTNUM, RSHIFTNUM
  [0x93, [2, 1]], [0x94, [2, 1]], [0x95, [2, 1]], [0x96, [2, 1]], [0x97, [2, 1]], // ADD SUB MUL DIV MOD
  [0x9a, [2, 1]], [0x9b, [2, 1]], [0x9c, [2, 1]], [0x9e, [2, 1]], [0x9f, [2, 1]], // BOOLAND BOOLOR NUMEQUAL NUMNOTEQUAL LESSTHAN
  [0xa0, [2, 1]], [0xa1, [2, 1]], [0xa2, [2, 1]],       // GT LE GE
]);

// numeric value of a const-push op (for PICK/ROLL/INVOKE id args)
function constNum(ref) {
  if (ref.k !== 'const') return null;
  const d = ref.data;
  if (d.length === 0) return 0;
  // minimal little-endian signed VM number
  let n = 0n; for (let i = d.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(d[i] & (i === d.length - 1 ? 0x7f : 0xff));
  if (d[d.length - 1] & 0x80) n = -n;
  return Number(n);
}

let UID = 0;
const freshNode = (props) => ({ id: ++UID, ...props });

export function decompile(body, arity, inArity = 0) {
  const ops = parse(body);
  const items = []; // {block:{entryDepth, exit:[refs], rawOps:[...]}} or {ctrl:opcode}
  let main = new Array(inArity).fill(null); // body starts with its input args on the stack
  let alt = [];      // symbolic alt stack (top = last)
  let entryDepth = 0, entryAlt = 0;
  let rawStart = 0;  // index into ops where current block began
  const ctrlDepth = []; // for IF/ELSE/ENDIF reconciliation: {m, a} depths at IF (for else)

  // relabel current main+alt stacks as fresh entry slots
  function beginBlock() {
    entryDepth = main.length; entryAlt = alt.length;
    main = main.map((_, i) => ({ k: 'in', i }));
    alt = alt.map((_, i) => ({ k: 'ain', i }));
  }
  function closeBlock(opIndexEnd) {
    items.push({ block: { entryDepth, entryAlt, exit: main.slice(), exitAlt: alt.slice(), rawOps: ops.slice(rawStart, opIndexEnd) } });
  }

  beginBlock();
  for (let i = 0; i < ops.length; i++) {
    const o = ops[i];
    const op = o.op;
    if (CTRL.has(op)) {
      // close straight-line block up to (not including) this ctrl op
      closeBlock(i);
      // apply ctrl op stack effect symbolically
      if (op === OPC.IF || op === OPC.NOTIF) { main.pop(); ctrlDepth.push({ m: main.length, a: alt.length }); }
      else if (op === OPC.ELSE) { const s = ctrlDepth[ctrlDepth.length - 1]; main.length = s.m; alt.length = s.a; }
      else if (op === OPC.ENDIF) { ctrlDepth.pop(); }
      else if (op === OPC.BEGIN) { /* no stack effect */ }
      else if (op === OPC.UNTIL) { main.pop(); }
      else if (op === OPC.VERIFY) { main.pop(); }
      else if (op === OPC.NUMEQUALVERIFY || op === OPC.EQUALVERIFY) { main.pop(); main.pop(); }
      items.push({ ctrl: op });
      rawStart = i + 1;
      beginBlock();
      continue;
    }
    // ---- straight-line op: update symbolic stack ----
    if (o.data !== undefined) { main.push({ k: 'const', data: o.data }); continue; }
    switch (op) {
      case 0x00: main.push({ k: 'const', data: new Uint8Array() }); break;       // OP_0
      case 0x4f: main.push({ k: 'const', data: Uint8Array.from([0x81]) }); break; // OP_1NEGATE
      default:
        if (op >= 0x51 && op <= 0x60) { main.push({ k: 'const', data: Uint8Array.from([op - 0x50]) }); break; }
        if (op === OPC.DUP) { main.push(main[main.length - 1]); break; }
        if (op === OPC.DROP) { main.pop(); break; }
        if (op === OPC['2DROP']) { main.pop(); main.pop(); break; }
        if (op === OPC['2DUP']) { const b = main[main.length - 1], a = main[main.length - 2]; main.push(a, b); break; }
        if (op === OPC.OVER) { main.push(main[main.length - 2]); break; }
        if (op === OPC['2OVER']) { const a = main[main.length - 4], b = main[main.length - 3]; main.push(a, b); break; }
        if (op === OPC.SWAP) { const n = main.length; [main[n - 1], main[n - 2]] = [main[n - 2], main[n - 1]]; break; }
        if (op === OPC['2SWAP']) { const n = main.length; const a = main[n - 4], b = main[n - 3], c = main[n - 2], dd = main[n - 1]; main[n - 4] = c; main[n - 3] = dd; main[n - 2] = a; main[n - 1] = b; break; }
        if (op === OPC.ROT) { const n = main.length; const a = main[n - 3]; main[n - 3] = main[n - 2]; main[n - 2] = main[n - 1]; main[n - 1] = a; break; }
        if (op === OPC['2ROT']) { const n = main.length; const a = main[n - 6], b = main[n - 5]; for (let k = n - 6; k < n - 2; k++) main[k] = main[k + 2]; main[n - 2] = a; main[n - 1] = b; break; }
        if (op === OPC.TUCK) { const n = main.length; const b = main[n - 1], a = main[n - 2]; main[n - 2] = b; main[n - 1] = a; main.push(b); break; }
        if (op === OPC.NIP) { main.splice(main.length - 2, 1); break; }
        if (op === OPC.TOALT) { alt.push(main.pop()); break; }
        if (op === OPC.FROMALT) { main.push(alt.pop()); break; }
        if (op === OPC.PICK) { const n = constNum(main.pop()); main.push(main[main.length - 1 - n]); break; }
        if (op === OPC.ROLL) { const n = constNum(main.pop()); const idx = main.length - 1 - n; const v = main.splice(idx, 1)[0]; main.push(v); break; }
        if (op === OPC.INVOKE) {
          const id = constNum(main.pop());
          const a = arity[id]; if (!a) throw new Error('unknown invoke id ' + id);
          const ins = []; for (let k = 0; k < a.in; k++) ins.unshift(main.pop());
          const node = freshNode({ k: 'invoke', invId: id, ins });
          for (let j = 0; j < a.out; j++) main.push({ k: 'out', node, j });
          break;
        }
        if (VALOP.has(op)) {
          const [nin, nout] = VALOP.get(op);
          const ins = []; for (let k = 0; k < nin; k++) ins.unshift(main.pop());
          const node = freshNode({ k: 'prim', code: op, ins });
          for (let j = 0; j < nout; j++) main.push({ k: 'out', node, j });
          break;
        }
        throw new Error('unhandled opcode 0x' + op.toString(16) + ' at ' + i);
    }
  }
  closeBlock(ops.length);
  return items;
}
