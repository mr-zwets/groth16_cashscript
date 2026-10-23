// Function-aware intermediate form for merging several BCH 2026 programs into one script.
//
// parse(bytes, ns) splits a program into its OP_DEFINE'd functions and its main body. Every
// static call `<id> OP_INVOKE` becomes {call: key} and every definition is recorded under
// key = `${ns}:${id}`, so programs written against separate function tables can be combined
// and their identifiers reassigned without collisions. Dynamic invokers (a body starting
// with a bare OP_INVOKE, the callee coming from the caller's stack) are listed in
// `dynamic`; the identifier pushed right before a call to one becomes {fnref: key}.
//
// emit(ir, idOf) is the inverse for a chosen identifier assignment.
import assert from 'node:assert/strict';
import {OpcodesBCH, bigIntToVmNumber, decodeAuthenticationInstructions, encodeAuthenticationInstruction, encodeDataPush, vmNumberToBigInt} from '@bitauth/libauth';

const {OP_DEFINE, OP_INVOKE, OP_0, OP_1, OP_16, OP_1NEGATE} = OpcodesBCH;

export const numberOf = (ins) => {
  if (ins.opcode === OP_0) return 0n;
  if (ins.opcode === OP_1NEGATE) return -1n;
  if (ins.opcode >= OP_1 && ins.opcode <= OP_16) return BigInt(ins.opcode - OP_1 + 1);
  assert(ins.data !== undefined, 'expected a constant push');
  return vmNumberToBigInt(ins.data, {requireMinimalEncoding: true});
};
export const isPush = (ins) => ins !== undefined && ins.call === undefined && ins.fnref === undefined && ins.pseudo === undefined &&
  (ins.opcode <= 96 && ins.opcode !== 80) && ins.opcode !== undefined;
export const pushNumber = (n) => decodeAuthenticationInstructions(encodeDataPush(bigIntToVmNumber(BigInt(n))))[0];
export const op = (name) => {
  assert(Number.isInteger(OpcodesBCH[name]), `unknown opcode ${name}`);
  return {opcode: OpcodesBCH[name]};
};
export const pushData = (bytes) => decodeAuthenticationInstructions(encodeDataPush(Uint8Array.from(bytes)))[0];

export function parse(bytes, ns, dynamic = new Set()) {
  const defs = new Map();
  const walk = (code) => {
    const ins = decodeAuthenticationInstructions(code);
    assert(!ins.some((x) => x.malformed), `${ns}: malformed bytecode`);
    const out = [];
    for (let i = 0; i < ins.length; i++) {
      const x = ins[i];
      if (x.opcode === OP_DEFINE) {
        const id = out.pop(), body = out.pop();
        assert(isPush(id) && body && body.data !== undefined, `${ns}: OP_DEFINE needs <body> <id>`);
        const key = `${ns}:${numberOf(id)}`;
        assert(!defs.has(key), `${ns}: duplicate definition ${key}`);
        defs.set(key, null); // reserve (recursion-safe)
        defs.set(key, walk(body.data));
      } else if (x.opcode === OP_INVOKE) {
        if (out.length === 0 || !isPush(out.at(-1))) { out.push({opcode: OP_INVOKE}); continue; } // dynamic site
        const key = `${ns}:${numberOf(out.pop())}`;
        if (dynamic.has(key)) {
          assert(isPush(out.at(-1)), `${ns}: dynamic invoker ${key} needs a constant callee`);
          out.push({fnref: `${ns}:${numberOf(out.pop())}`});
        }
        out.push({call: key});
      } else out.push(x);
    }
    return out;
  };
  const main = walk(bytes);
  return {defs, main};
}

// Encode a body; idOf(key) returns the final identifier (a bigint).
export function encodeBody(body, idOf) {
  const parts = [];
  for (const x of body) {
    if (x.call !== undefined) { parts.push(encodeDataPush(bigIntToVmNumber(idOf(x.call))), Uint8Array.of(OP_INVOKE)); continue; }
    if (x.fnref !== undefined) { parts.push(encodeDataPush(bigIntToVmNumber(idOf(x.fnref)))); continue; }
    assert(x.pseudo === undefined, `unlowered pseudo-op ${x.pseudo}`);
    parts.push(encodeAuthenticationInstruction(x));
  }
  return Buffer.concat(parts.map((p) => Buffer.from(p)));
}

export const encodeDefinition = (body, id) => Buffer.concat([
  Buffer.from(encodeDataPush(body)), Buffer.from(encodeDataPush(bigIntToVmNumber(id))), Buffer.of(OP_DEFINE),
]);

// Replace exactly one occurrence of the instruction pattern `from` (array of matchers) in
// `body` with `to`. Matchers: an opcode name, or {data: hex}, or {num: n}.
const matches = (x, m) => {
  if (typeof m === 'string') return x.call === undefined && x.fnref === undefined && x.opcode === OpcodesBCH[m] && (x.data === undefined || x.data.length === 0 || x.opcode > 78);
  if (m.call !== undefined) return x.call === m.call;
  if (m.num !== undefined) return isPush(x) && numberOf(x) === BigInt(m.num);
  if (m.data !== undefined) return x.data !== undefined && Buffer.from(x.data).toString('hex') === m.data;
  throw new Error('bad matcher');
};
export function findAll(body, pattern) {
  const hits = [];
  for (let i = 0; i + pattern.length <= body.length; i++) if (pattern.every((m, j) => matches(body[i + j], m))) hits.push(i);
  return hits;
}
export function replaceOnce(body, pattern, replacement, label) {
  const hits = findAll(body, pattern);
  assert.equal(hits.length, 1, `${label}: pattern must occur exactly once (found ${hits.length})`);
  body.splice(hits[0], pattern.length, ...replacement);
  return hits[0];
}
