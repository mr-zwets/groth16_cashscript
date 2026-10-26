// Per-input op decomposition from a VM debug trace (diagnostics VM, no budget): prefix (pins, reads, head work, setup,
// start), the cost of every event (from one AFFDBL entry to the next; the last one to the loop exit, boundaries and
// additions included), and the suffix (claims / terminal, clean stack). Used by layout.mjs.
//   WIT=committed|dense|forced:<nq> node measure.mjs [out.json]
import {writeFileSync} from 'node:fs';
import {encodeAuthenticationInstructions} from '@bitauth/libauth';
import {buildAll} from './script.mjs';
import {createHash} from 'node:crypto';
import {FIXTURES, mint, r, synthetic} from './math.mjs';
import {prove, txPushes, ROLES, CUTS} from './protocol.mjs';
import {statementFor, maxSlots, ALL15} from './worst.mjs';
import {p2sh32, txOf, unlockingsFor, VM_UNLIMITED} from './vm.mjs';

export function witnessFor(spec) {
  if (spec === 'dense') return prove(mint(statementFor(Array(64).fill(2)).ns));
  // forced:<nq>[:<i>] / all15[:<i>]: the forced statements (worst.mjs), with B and C derived from the statement (mint) or,
  // with an index i, random B and C (the op cost moves by ~2k op with B and C)
  const bcOf = (tag) => { const h = (x) => BigInt('0x' + createHash('sha256').update('measure-bc:' + tag + x).digest('hex')) % r; return [1n + h(0) % (r - 1n), 1n + h(1) % (r - 1n)]; };
  const withBC = (ns, i) => (i === undefined ? mint(ns) : synthetic(ns, ...bcOf(spec)));
  if (spec.startsWith('forced:')) { const [, nq, i] = spec.split(':'); return prove(withBC(statementFor(maxSlots(Number(nq))).ns, i)); }
  if (spec.startsWith('all15')) { const [, i] = spec.split(':'); return prove(withBC([ALL15, ALL15], i)); }
  if (spec.startsWith('sweep:')) return import('./sweep.mjs').then(({sweepCases}) => prove(sweepCases().find((c) => c.label === spec.slice(6)).fx));
  if (spec.startsWith('random:')) { const h = (x) => BigInt('0x' + createHash('sha256').update('measure:' + spec + x).digest('hex')) % r;
    return prove(synthetic([h(0), h(1)], 1n + h(2) % (r - 1n), 1n + h(3) % (r - 1n))); }
  return prove(FIXTURES[spec]);
}
export function measure(b, w, mode = 'standard') {
  const names = new Map(); for (const [n, f] of b.info.ctx.funcs) if (f.code) names.set(Buffer.from(f.code).toString('hex'), n);
  b.info.roleCode.forEach((c, i) => names.set(Buffer.from(c).toString('hex'), 'ROLE' + i));
  const un = unlockingsFor(txPushes(w, b.blob), b.R); const ctx = txOf(un, un.map(() => p2sh32(b.R)));
  const LOOPSET = new Set(['LOOP', 'AFFDBL', 'AFFADD', 'DSTEP', 'BND']);
  return ROLES.map((ro, i) => {
    const tr = VM_UNLIMITED[mode].debug({inputIndex: i, sourceOutputs: ctx.sourceOutputs, transaction: ctx.transaction});
    const cache = new WeakMap(); const nameOf = (ins) => { if (!ins) return '?'; if (!cache.has(ins)) cache.set(ins, names.get(Buffer.from(encodeAuthenticationInstructions(ins)).toString('hex')) ?? '?'); return cache.get(ins); };
    const starts = []; let loopEnd = 0, total = 0;
    for (const s of tr) { const c = s.metrics?.operationCost ?? 0; total = c; const n = nameOf(s.instructions); if (n === 'AFFDBL' && s.ip === 0) starts.push(c); if (LOOPSET.has(n)) loopEnd = c; }
    if (starts.length !== ro.events.length) throw new Error(`input ${i}: ${starts.length} event starts, expected ${ro.events.length}`);
    const ok = tr.at(-1).error === undefined;
    const events = ro.events.map((e, k) => ({e, op: (k + 1 < starts.length ? starts[k + 1] : loopEnd) - starts[k]}));
    return {i, ok, error: tr.at(-1).error ?? null, U: un[i].length, total, prefix: starts[0], suffix: total - loopEnd, events};
  });
}
if (import.meta.url === `file://${process.argv[1]}`) {
  const b = buildAll(); const out = {CUTS, blob: b.blob.length, R: b.R.length, wit: {}};
  for (const spec of (process.env.WIT ?? 'committed,dense').split(',')) {
    const w = witnessFor(spec); out.wit[spec] = {nq: w.nq, inputs: measure(b, w)};
    for (const x of out.wit[spec].inputs) console.log(spec, 'in' + x.i, x.ok ? 'ok' : x.error, 'U', x.U, 'total', x.total, 'prefix', x.prefix, 'suffix', x.suffix, 'events', x.events.map((v) => Math.round(v.op / 1000)).join(' '));
  }
  if (process.argv[2]) writeFileSync(process.argv[2], JSON.stringify(out, null, 1));
}
