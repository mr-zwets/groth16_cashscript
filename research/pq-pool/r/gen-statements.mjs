#!/usr/bin/env node
// Track 9 S2: the 24 M1 statements re-proved for the pool (circuit unchanged). Statement i uses genesis note i
// (../w/results/genesis.json: notes 0-15 in epoch 0 / ring slot 0, notes 16-23 in epoch 1 / slot 1) with an explicit
// witness (nk, r, 30 siblings) and CTX = SHA-256 of the final transaction's outputs [1..] (ctx.mjs): one payout of
// D - PHI to a P2PKH derived from i (pool.mjs payoutsFor). The prover is the Track 8 prover with one witness change
// (../prover, case m1@LEAF@0@CTXHASH@WIT). Each vector must carry ROOT = the note's epoch root, NF = the note's NF
// and the outputs' CTX (checked here: this also checks S1's JS Poseidon2 genesis against the Rust prover).
// Writes OUTDIR/m1-t9-<i>-<set>[-seed2].json = the prover's vector plus t9_payouts, t9_ctx, t9_note.
// usage: node gen-statements.mjs --bin PROVER --set Z128+cap=5 --outdir DIR [--first 0 --count 24] [--seed-base 900]
//        [--suffix -seed2]
import {execFileSync} from 'node:child_process';
import {readFileSync, writeFileSync, mkdirSync} from 'node:fs';
import {ctxOf} from './ctx.mjs';
import {G, payoutsFor} from './pool.mjs';

const args = process.argv.slice(2);
const opt = (k, d) => { const i = args.indexOf(k); return i >= 0 ? args[i + 1] : d; };
const bin = opt('--bin'), set = opt('--set', 'Z128+cap=5'), outdir = opt('--outdir'), count = +opt('--count', 24), first = +opt('--first', 0);
const seedBase = +opt('--seed-base', 900), suffix = opt('--suffix', '');
mkdirSync(outdir, {recursive: true});
const hex16 = (x) => BigInt(x).toString(16).padStart(16, '0');
const jsonOut = (o) => o.map((x) => ({lockingBytecode: Buffer.from(x.lockingBytecode).toString('hex'), valueSatoshis: x.valueSatoshis.toString()}));
for (let i = first; i < first + count; i++) {
  const note = G.notes[i];
  const outs = payoutsFor(i), ctx = ctxOf(outs);
  const wit = [...note.nk, ...note.r, ...note.siblings.flat()].map(hex16).join('');
  const name = `m1-t9-${i}-${set.replace(/\+/g, '_').replace(/=/g, '')}${suffix}`;
  const file = `${outdir}/${name}.json`;
  const t0 = Date.now();
  execFileSync('nice', [bin, 'prove', '--case', `m1@${note.index}@0@${ctx.hex}@${wit}`, '--set', set, '--seed', String(seedBase + i), '--out', file], {env: {...process.env, RAYON_NUM_THREADS: '4'}, stdio: ['ignore', 'ignore', 'inherit']});
  const raw = readFileSync(file, 'utf8');
  const v = JSON.parse(raw);
  const pv = v.public_values.flat().map(BigInt);
  const want = [...note.root, ...note.nf, ...ctx.lanes];
  const bad = want.map((x, k) => (x === pv[k] ? null : k)).filter((k) => k !== null);
  if (bad.length) throw new Error(`${name}: public values ${bad} differ from the genesis note / outputs (ROOT 0-3, NF 4-7, CTX 8-11)`);
  writeFileSync(file, raw.replace(/\}\s*$/, `,"t9_payouts":${JSON.stringify(jsonOut(outs))},"t9_ctx":"${ctx.hex}","t9_note":${i}}\n`));
  console.log(`${name}: note ${i} (leaf ${note.index}, slot ${note.slot}) seed ${seedBase + i} ROOT ok NF ok CTX ok, ${v.sizes.total} B, ${Date.now() - t0} ms`);
}
