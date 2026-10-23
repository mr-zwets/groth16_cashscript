// Single-input BN254 Groth16 verifier for the proposed bch-spec VM: the five programs of
// densless-msm-spec (genesis + vk_x MSM, three executors, terminal) merged into one P2SH32
// redeem that runs them in sequence on one stack. See README.md for the layout and the
// soundness argument; stack-audit.mjs checks the stage isolation it relies on.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {writeFileSync} from 'node:fs';
import {pathToFileURL} from 'node:url';
import {OpcodesBCH} from '@bitauth/libauth';
import {loadSources, editSymbolic} from './sources.mjs';
import {encodeBody, encodeDefinition, op, pushData, pushNumber, replaceOnce} from './ir.mjs';
import {audit} from './stack-audit.mjs';
import {dedupe, inlineCheap, inlineExact, poolConstants} from './optimize.mjs';

const hash256 = (b) => createHash('sha256').update(createHash('sha256').update(b).digest()).digest();
const sha256 = (b) => createHash('sha256').update(b).digest();

// ---- unlocking layout (bottom of the stack first) -------------------------------------------
// The selector is the first push: the terminal reads its opcode byte (0x00, 0x51 or 0x52) at
// offset 0 of this input's unlocking. Genesis push 0 is pushed without vk_x (bytes 128..192):
// the MSM returns vk_x and the glue splices it back in (see `main`).
// The terminal's last 24 values (c^-1 and c, reversed) are not pushed: they are decoded from a
// copy of genesis push 18, which holds the same 24 field elements (c || c^-1, big-endian).
export const TERMINAL_VALUES = 26;
export const layout = [
  'genesis/sel', 'terminal/Q',
  ...Array.from({length: TERMINAL_VALUES}, (_, i) => `terminal/v${i}`),
  'exec2/FT', 'exec2/W', 'exec1/FT', 'exec1/W', 'exec0/FT', 'exec0/W',
  ...Array.from({length: 17}, (_, i) => `genesis/p${i + 2}`), 'genesis/Grest',
  'msm/zInv', 'msm/w', 'msm/n1', 'msm/n0',
];
export const pushIndex = (label) => layout.indexOf(label);

// ---- edits to the shared executor program (symbolic) -----------------------------------------
function sharedMainEdits(text) {
  // stage index from the caller instead of OP_INPUTINDEX; the <3 check guarded the input index
  // The per-input constants (input index, two schedule words, two loop bounds) were selected by
  // OP_INPUTINDEX; each stage call now pushes its own (STAGE_CONSTANTS), with the base-field
  // constant first, exactly the stack the dispatch produced.
  text = editSymbolic(text, `CALL baseFieldConstant OP_INPUTINDEX OP_DUP OP_3 OP_LESSTHAN OP_VERIFY OP_PUSHBYTES_5 0x2110012141
    OP_OVER OP_1 OP_NUMEQUAL OP_IF OP_PUSHBYTES_6 0x004208018400 OP_NIP OP_ENDIF OP_OVER OP_2 OP_NUMEQUAL OP_IF OP_PUSHBYTES_6
    0x400402418800 OP_NIP OP_ENDIF OP_4 OP_2 OP_PICK OP_1 OP_NUMEQUAL OP_IF OP_DROP OP_14 OP_ENDIF OP_2 OP_PICK OP_2 OP_NUMEQUAL
    OP_IF OP_PUSHBYTES_1 0x18 OP_NIP OP_ENDIF OP_10 OP_3 OP_PICK OP_1 OP_NUMEQUAL OP_IF OP_DROP OP_10 OP_ENDIF OP_3 OP_PICK OP_2
    OP_NUMEQUAL OP_IF OP_DROP OP_11 OP_ENDIF`, '', 'stage dispatch');
  // own fixed table: was read from this input's unlocking; now handed over on the altstack
  text = editSymbolic(text, `OP_0 OP_4 OP_PICK OP_0 OP_NUMEQUAL OP_IF OP_PUSHBYTES_2 0xa003 OP_PUSHBYTES_2 0x970e OP_0 CALL
    readBoundedInputSlice OP_NIP OP_ENDIF OP_4 OP_PICK OP_1 OP_NUMEQUAL OP_IF OP_PUSHBYTES_2 0x4003 OP_PUSHBYTES_2 0x0a0e OP_1 CALL
    readBoundedInputSlice OP_NIP OP_ENDIF OP_4 OP_PICK OP_2 OP_NUMEQUAL OP_IF OP_PUSHBYTES_2 0xa003 OP_PUSHBYTES_2 0x630d OP_2 CALL
    readBoundedInputSlice OP_NIP OP_ENDIF`, 'OP_FROMALTSTACK', 'fixed table');
  // genesis push 0: was read from input 3; now the G function (marker replaced in assembleAll)
  text = editSymbolic(text, 'OP_PUSHBYTES_2 0xc001 OP_3 OP_3 CALL readBoundedInputSlice', 'OP_DEPTH OP_1SUB OP_PICK', 'genesis block');
  // next input's header: no longer exists (the computed header is handed over instead)
  text = editSymbolic(text, `OP_0 OP_6 OP_PICK OP_0 OP_NUMEQUAL OP_IF OP_PUSHBYTES_2 0x2801 OP_3 OP_1 CALL readBoundedInputSlice
    OP_NIP OP_ENDIF OP_6 OP_PICK OP_1 OP_NUMEQUAL OP_IF OP_PUSHBYTES_2 0x2801 OP_3 OP_2 CALL readBoundedInputSlice OP_NIP OP_ENDIF
    OP_6 OP_PICK OP_2 OP_NUMEQUAL OP_IF OP_PUSHBYTES_2 0x2801 OP_3 OP_4 CALL readBoundedInputSlice OP_NIP OP_ENDIF`, 'OP_0', 'next header');
  // the fixed-table presence check only validated the input-index dispatch
  text = editSymbolic(text, 'OP_2 OP_PICK OP_SIZE OP_NIP OP_0 OP_GREATERTHAN OP_VERIFY', '', 'dispatch check');
  // computed next header: was compared with the next input's header push; now handed over
  text = editSymbolic(text, 'OP_PUSHBYTES_1 0x76 OP_ROLL OP_EQUALVERIFY', 'OP_TOALTSTACK OP_PUSHBYTES_1 0x75 OP_ROLL OP_DROP', 'header hand-off');
  // the result is no longer an input's final stack item
  text = editSymbolic(text, 'OP_2DROP OP_2DROP OP_2DROP OP_2DROP OP_2DROP OP_1', 'OP_2DROP OP_2DROP OP_2DROP OP_2DROP OP_2DROP', 'result');
  return text;
}

// [index, schedule word, second schedule word, two loop bounds] per executor, as selected by
// the dispatch the shared program ran on OP_INPUTINDEX 0, 1, 2.
export const STAGE_CONSTANTS = [
  [0, '2110012141', 4, 10], [1, '004208018400', 14, 10], [2, '400402418800', 24, 11],
];

function terminalMainEdits(text) {
  // genesis push 0: was read from input 3; now the G function (marker replaced in assembleAll)
  text = editSymbolic(text, 'OP_3 OP_INPUTBYTECODE OP_3 OP_SPLIT OP_NIP OP_PUSHBYTES_2 0xc001 OP_SPLIT OP_DROP',
    'OP_DEPTH OP_1SUB OP_PICK', 'genesis block');
  // own header push 0: now the header executor 2 computed, handed over on the altstack
  text = editSymbolic(text, 'OP_PUSHBYTES_1 0x3b OP_ROLL OP_PUSHBYTES_1 0x28 OP_SPLIT', 'OP_FROMALTSTACK OP_PUSHBYTES_1 0x28 OP_SPLIT', 'header');
  // quotient: executors' slices + own slice, now one push holding the same concatenation
  text = editSymbolic(text, `OP_0 OP_INPUTBYTECODE OP_PUSHBYTES_2 0x3a12 OP_SPLIT OP_NIP OP_PUSHBYTES_2 0xe004 OP_SPLIT OP_DROP OP_1
    OP_INPUTBYTECODE OP_PUSHBYTES_2 0x4d11 OP_SPLIT OP_NIP OP_PUSHBYTES_2 0xe004 OP_SPLIT OP_DROP OP_2 OP_INPUTBYTECODE OP_PUSHBYTES_2
    0x0611 OP_SPLIT OP_NIP OP_PUSHBYTES_2 0xe004 OP_SPLIT OP_DROP OP_ROT OP_ROT OP_CAT OP_SWAP OP_CAT OP_PUSHBYTES_1 0x4f OP_ROLL
    OP_CAT`, 'OP_PUSHBYTES_1 0x4e OP_ROLL', 'quotient');
  // selector opcode byte: genesis push 1 at offset 451 of input 3; now this input's first push,
  // so its opcode is byte 0 of this input's own unlocking
  text = editSymbolic(text, 'OP_3 OP_INPUTBYTECODE OP_PUSHBYTES_2 0xc301 OP_SPLIT OP_NIP OP_1 OP_SPLIT OP_DROP',
    'OP_INPUTINDEX OP_INPUTBYTECODE OP_1 OP_SPLIT OP_DROP', 'selector');
  // five-input structure and worker-locking pins: no other inputs any more
  text = editSymbolic(text, `OP_TXINPUTCOUNT OP_5 OP_EQUALVERIFY OP_INPUTINDEX OP_OUTPOINTINDEX OP_INPUTINDEX OP_EQUALVERIFY
    OP_INPUTINDEX OP_4 OP_EQUALVERIFY OP_0 OP_UTXOBYTECODE OP_HASH256 OP_1 OP_UTXOBYTECODE OP_HASH256 OP_2 OP_UTXOBYTECODE
    OP_HASH256 OP_3 OP_UTXOBYTECODE OP_HASH256 OP_CAT OP_CAT OP_CAT OP_HASH256 DATA workerLockingRoot OP_EQUALVERIFY`, '', 'worker pins');
  return text;
}

const stage = (name) => ({pseudo: 'stage', stage: name});
const OPS = (s) => s.trim().split(/\s+/).map(op);

// Malleability pins for the issue-39 classes that survive the merge (see README.md):
//  - the terminal's ten boundary-line evaluations (its values 0..9) enter only as a product, so
//    any permutation was accepted; they must now be in ascending numeric order;
//  - fixed-table limbs were accepted with the sign bit set or + p; every 32-byte limb of each
//    executor's fixed table must now be a canonical field element (0 <= x < p).
export const PINS = process.env.SINGLE_PINS !== '0';

export function assembleAll({pins = PINS} = {}) {
  const base = loadSources();
  const S = loadSources({sharedMain: sharedMainEdits(base.raw.shared.main), terminalMain: terminalMainEdits(base.raw.terminal.main)});
  // ---- genesis main edits (instruction level, on the sliced program) ----
  const g = S.g.main;
  assert.equal(g[0].opcode, OpcodesBCH.OP_DROP); g.shift(); // no zero pad any more
  replaceOnce(g, [{num: 0x12}, 'OP_ROLL', {call: 'g:17'}], [{call: 'rt:G'}, {call: 'g:17'}], 'genesis G');
  replaceOnce(S.s.main, ['OP_DEPTH', 'OP_1SUB', 'OP_PICK'], [{call: 'rt:G'}], 'shared G');
  replaceOnce(S.t.main, ['OP_DEPTH', 'OP_1SUB', 'OP_PICK'], [{call: 'rt:G'}], 'terminal G');
  replaceOnce(g, [{num: 0x3f}, 'OP_ROLL', 'OP_1', 'OP_NUM2BIN'], [{pseudo: 'roll', label: 'genesis/sel'}, op('OP_1'), op('OP_NUM2BIN')], 'genesis selector');
  // header 0: genesis builds all 296 bytes and required them to equal input 0's header push;
  // the built header is handed to executor 0 instead (the read becomes a placeholder slot)
  replaceOnce(g, ['OP_0', 'OP_INPUTBYTECODE', 'OP_3', 'OP_SPLIT', 'OP_NIP', {data: '2801'}, 'OP_SPLIT', 'OP_DROP'],
    [op('OP_0')], 'genesis header 0 read');
  replaceOnce(g, ['OP_CAT', 'OP_CAT', 'OP_CAT', 'OP_EQUALVERIFY', 'OP_2DROP', 'OP_2DROP'],
    [...OPS('OP_CAT OP_CAT OP_CAT OP_TOALTSTACK OP_DROP OP_2DROP OP_2DROP')], 'genesis header 0 hand-off');
  // ---- shared executor: its main becomes a function, its reader helper is now unused ----
  const defs = new Map([...S.g.defs, ...S.m.defs, ...S.s.defs, ...S.t.defs]);
  // the MSM library function is the one call of the compiled contract's spend body
  const msmCall = S.m.main.filter((x) => x.call !== undefined);
  assert.equal(msmCall.length, 1, 'MSM contract body must make exactly one call');
  const vkxMsm = msmCall[0].call;
  defs.delete('s:9'); // readBoundedInputSlice
  defs.set('s:main', S.s.main);
  // previous header from the altstack on top of this executor's witness, its fixed table to the
  // altstack, then the constants the shared program's dispatch selected for this input index
  if (pins) defs.set('pin:canonicalLimbs', [
    op('OP_BEGIN'), pushNumber(32), ...OPS('OP_SPLIT OP_SWAP OP_BIN2NUM OP_0'), {call: 's:7'},
    ...OPS('OP_WITHIN OP_VERIFY OP_SIZE OP_NOT OP_UNTIL OP_DROP'),
  ]);
  const execStage = (k) => [
    ...OPS('OP_FROMALTSTACK OP_ROT'), ...(pins ? [op('OP_DUP'), {call: 'pin:canonicalLimbs'}] : []), op('OP_TOALTSTACK'),
    stage(`exec${k}`), {call: 's:7'},
    pushNumber(STAGE_CONSTANTS[k][0]), pushData(Buffer.from(STAGE_CONSTANTS[k][1], 'hex')),
    pushNumber(STAGE_CONSTANTS[k][2]), pushNumber(STAGE_CONSTANTS[k][3]), {call: 's:main'}, stage('glue'),
  ];
  const dropResult = (body, label) => { assert.equal(body.at(-1).opcode, OpcodesBCH.OP_1, label); return body.slice(0, -1); };
  const main = [
    // The MSM runs first on its four pushes and returns vk_x; the glue splices it into genesis
    // push 0 at bytes 128..192 (where the 5-input MSM compared it), requires the block to be
    // exactly 448 bytes and defines function G: one push of that block (so G is a single push
    // and nothing else). Genesis, the executors and the terminal call G where they used to read
    // genesis push 0. Then a copy of genesis push 18 is parked for the terminal and genesis runs
    // on its own pushes. Stages end with nothing left (each former input's final OP_1 is
    // dropped) or abort.
    stage('msm'), {call: vkxMsm},
    stage('glue'), op('OP_SWAP'), pushNumber(128), ...OPS('OP_SPLIT OP_ROT OP_SWAP OP_CAT OP_CAT OP_SIZE'), pushNumber(448),
    op('OP_NUMEQUALVERIFY'), pushData(Buffer.from('4dc001', 'hex')), ...OPS('OP_SWAP OP_CAT'), {fnref: 'rt:G'}, op('OP_DEFINE'),
    ...OPS('OP_DUP OP_TOALTSTACK'),
    stage('genesis'), ...dropResult(g, 'genesis result'), stage('glue'),
    ...execStage(0), ...execStage(1), ...execStage(2),
    // terminal: header 3 stays on the altstack; decode genesis push 18 into the 24 values the
    // terminal used to take as its last pushes (c^-1 reversed, then c reversed, c[0] on top).
    // Genesis requires push 18 to be exactly 24 x 32 bytes.
    stage('terminal'),
    // values 0..9 ascending: value i sits at depth 25 - i; compare depths c, c - 1 for c = 25..17
    ...(pins ? [pushNumber(25), ...OPS('OP_BEGIN OP_DUP OP_1ADD OP_PICK OP_OVER OP_1ADD OP_PICK OP_LESSTHANOREQUAL OP_VERIFY OP_1SUB OP_DUP OP_16 OP_NUMEQUAL OP_UNTIL OP_DROP')] : []),
    ...OPS('OP_FROMALTSTACK OP_FROMALTSTACK OP_SWAP OP_TOALTSTACK OP_0 OP_TOALTSTACK OP_BEGIN OP_SIZE'),
    pushNumber(32), ...OPS('OP_SUB OP_SPLIT OP_REVERSEBYTES OP_BIN2NUM OP_SWAP OP_FROMALTSTACK OP_1ADD OP_DUP OP_TOALTSTACK'),
    pushNumber(24), ...OPS('OP_NUMEQUAL OP_UNTIL OP_FROMALTSTACK OP_2DROP'),
    ...S.t.main,
  ];
  return {defs, main};
}

// Stage-isolation rules for the audit: every cross-stage read must be one of these.
export const allowed = [
  ['genesis', 'fn/rt:G'], ['exec0', 'fn/rt:G'], ['exec1', 'fn/rt:G'], ['exec2', 'fn/rt:G'], ['terminal', 'fn/rt:G'],
  ['exec0', '@genesis'], ['terminal', 'genesis/p18'],
  ['exec1', '@exec0'], ['exec2', '@exec1'], ['terminal', '@exec2'],
];

// Identifier assignment: most-referenced functions get the 1-byte encodings (OP_0..OP_16,
// OP_1NEGATE), then 2-byte pushes, and so on.
const ID_ORDER = [0n, ...Array.from({length: 16}, (_, i) => BigInt(i + 1)), -1n,
  ...Array.from({length: 111}, (_, i) => BigInt(i + 17)), ...Array.from({length: 126}, (_, i) => BigInt(-(i + 2)))];
export function assignIds(defs, main) {
  // static definitions plus functions the glue defines at run time (an fnref in main)
  const runtime = main.filter((x) => x.fnref !== undefined && !defs.has(x.fnref)).map((x) => x.fnref);
  const refs = new Map([...defs.keys(), ...runtime].map((k) => [k, 1]));
  const count = (body) => body.forEach((x) => {
    const k = x.call ?? x.fnref;
    if (k !== undefined) { assert(refs.has(k), `undefined function ${k}`); refs.set(k, refs.get(k) + 1); }
  });
  defs.forEach(count); count(main);
  const order = [...refs.entries()].sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : 1));
  assert(order.length <= ID_ORDER.length);
  return new Map(order.map(([k], i) => [k, ID_ORDER[i]]));
}

const lower = (body) => body.flatMap((x) => {
  if (x.pseudo === 'stage') return [];
  if (x.pseudo === 'pick' || x.pseudo === 'roll') {
    assert(x.depths && x.depths.size === 1, `${x.pseudo} ${x.label}: depth not fixed by the audit`);
    return [pushNumber([...x.depths][0]), op(x.pseudo === 'pick' ? 'OP_PICK' : 'OP_ROLL')];
  }
  return [x];
});

export function build({optimize = true, pins = PINS} = {}) {
  let {defs, main} = assembleAll({pins});
  if (optimize) {
    main = poolConstants(defs, main);
    main = dedupe(defs, main);
    main = inlineCheap(defs, main, 1.5);
    main = inlineExact(defs, main, (d, m) => {
      const ids = assignIds(d, m), idOf = (k) => ids.get(k);
      const approx = (b) => b.flatMap((x) => (x.pseudo === 'stage' ? [] : x.pseudo ? [pushNumber(99), op('OP_PICK')] : [x]));
      return [...d.entries()].reduce((a, [k, b]) => a + encodeDefinition(encodeBody(approx(b), idOf), idOf(k)).length, 0) + encodeBody(approx(m), idOf).length;
    });
  }
  const result = audit({defs, main}, {stack: layout, allowed});
  assert.deepEqual(result.violations, [], `stage isolation violated:\n${result.violations.join('\n')}`);
  assert.equal(result.final.st.length, 1, 'redeem must leave exactly one item');
  const ids = assignIds(defs, main);
  const idOf = (k) => ids.get(k);
  const definitions = [...defs.entries()].sort((a, b) => (idOf(a[0]) < idOf(b[0]) ? -1 : 1))
    .map(([k, body]) => encodeDefinition(encodeBody(lower(body), idOf), idOf(k)));
  const redeem = Buffer.concat([...definitions, encodeBody(lower(main), idOf)]);
  // size breakdown: definitions by origin namespace, main by stage
  const sizes = {};
  [...defs.entries()].sort((a, b) => (idOf(a[0]) < idOf(b[0]) ? -1 : 1)).forEach(([k], i) => {
    const ns = `defs:${k.split(':')[0]}`; sizes[ns] = (sizes[ns] ?? 0) + definitions[i].length;
  });
  let current = 'glue';
  for (const x of main) {
    if (x.pseudo === 'stage') { current = x.stage; continue; }
    sizes[`main:${current}`] = (sizes[`main:${current}`] ?? 0) + encodeBody(lower([x]), idOf).length;
  }
  const locking = Buffer.concat([Buffer.from([OpcodesBCH.OP_HASH256, 0x20]), hash256(redeem), Buffer.from([OpcodesBCH.OP_EQUAL])]);
  return {redeem, locking, ids, audit: result, defs, main, sizes};
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const {redeem, locking, audit: a, ids, sizes} = build();
  console.log(sizes);
  console.log(`redeem ${redeem.length} B, ${ids.size} functions, sha256 ${sha256(redeem).toString('hex')}, audit steps ${a.steps}`);
  if (process.argv[2]) writeFileSync(process.argv[2], JSON.stringify({redeem: redeem.toString('hex'), locking: locking.toString('hex'), layout}, null, 2) + '\n');
}
