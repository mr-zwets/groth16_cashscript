#!/usr/bin/env node
// gen-statements.mjs: transaction-bound M1 statements for layout (b). For each statement: the spending transaction's
// outputs (one P2PKH payment; statement k pays to HASH160-like bytes derived from k), CTX = SHA-256 of their
// serialization (ctx.mjs), then the release prover proves m1@LEAF@WSEED@CTXHASH under the given set with ZK seed
// SEED. Writes OUTDIR/<name>.json = the prover's vector plus `s4_outputs` (the outputs, JSON-safe) and `s4_ctx`.
// Runs the prover one at a time (RAYON_NUM_THREADS=4, nice).
// usage: node gen-statements.mjs --bin PROVER --set Z128 --outdir DIR --count K [--first I] [--leaves 0,1073741823,...] [--tag s7]
import {execFileSync} from 'node:child_process';
import {readFileSync, writeFileSync, mkdirSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {ctxOf} from './ctx.mjs';

const args = process.argv.slice(2);
const opt = (k, d) => { const i = args.indexOf(k); return i >= 0 ? args[i + 1] : d; };
const bin = opt('--bin'), set = opt('--set', 'Z128'), outdir = opt('--outdir'), count = +opt('--count', 1), first = +opt('--first', 0);
const leaves = opt('--leaves', '').split(',').filter(Boolean).map(Number);
const stmtKind = opt('--stmt', 'm1');   // m1 (S4) or m2 (S5/S6: T_hash + T_ctl, its public values in instance 1)
const tag = opt('--tag', stmtKind === 'm1' ? 's4' : 's5');   // S7: --tag s7 (same statements as S4, other VK)
mkdirSync(outdir, {recursive: true});
const h = (s) => createHash('sha256').update(s).digest();
export const outputsFor = (k) => [{lockingBytecode: Uint8Array.from([0x76, 0xa9, 0x14, ...h(`t8s4 recipient ${k}`).subarray(0, 20), 0x88, 0xac]), valueSatoshis: 900_000n}];
const jsonOut = (o) => o.map((x) => ({lockingBytecode: Buffer.from(x.lockingBytecode).toString('hex'), valueSatoshis: x.valueSatoshis.toString()}));
for (let i = first; i < first + count; i++) {
  const leaf = leaves[i - first] ?? (h(`t8s4 leaf ${i}`).readUInt32LE(0) & 0x3fffffff);
  const wseed = 4000 + i, seed = 400 + i;
  const outs = outputsFor(i), ctx = ctxOf(outs);
  const name = `${stmtKind}-${tag}-${i}-${set.replace(/\+/g, '_').replace(/=/g, '')}`;
  const file = `${outdir}/${name}.json`;
  const t0 = Date.now();
  execFileSync('nice', [bin, 'prove', '--case', `${stmtKind}@${leaf}@${wseed}@${ctx.hex}`, '--set', set, '--seed', String(seed), '--out', file], {env: {...process.env, RAYON_NUM_THREADS: '4'}, stdio: ['ignore', 'ignore', 'inherit']});
  const raw = readFileSync(file, 'utf8');
  const v = JSON.parse(raw);
  const got = v.public_values.flat().slice(8).map(BigInt);
  if (got.some((x, k) => x !== ctx.lanes[k])) throw new Error(`${name}: CTX in the proof differs from the outputs' CTX`);
  // append the S4 fields without re-serializing the prover's JSON (it holds integers beyond 2^53)
  writeFileSync(file, raw.replace(/\}\s*$/, `,"s4_outputs":${JSON.stringify(jsonOut(outs))},"s4_ctx":"${ctx.hex}","s4_leaf":${leaf},"s4_wseed":${wseed}}\n`));
  console.log(`${name}: leaf ${leaf} wseed ${wseed} seed ${seed} ctx ${ctx.hex.slice(0, 16)}.. ${v.sizes.total} B, ${Date.now() - t0} ms`);
}
