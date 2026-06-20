// CHECKPOINT #2: grade singleton/bls12-381/miller4.cash (4-pair Groth16 Miller
// boundary) against noble's millerLoopBatch(.,false) on the deterministic valid
// instance, on the loosened BCH 2026 VM. Heavy (~1B op-cost).
// Run: node singleton/bls12-381/miller4.mjs
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { compileTemplate, runVectors } from './_harness.mjs';
import { vkx, grothPairs, pairRow, boundaryFor, f12 } from './bls_instance.mjs';

const here = dirname(fileURLToPath(import.meta.url));

const pairs = grothPairs(vkx);
const args = pairs.flatMap(pairRow);
const boundary = boundaryFor(pairs);
args.push(...f12(boundary));

const template = compileTemplate(join(here, 'miller4.cash'));
console.log(`Miller 4-pair (cp#2): contract ${template.length}B (very slow, ~1B op-cost)`);
const ok = runVectors('miller4 boundary == noble', template, [args], { tamperIndex: 24 });
process.exit(ok ? 0 : 1);
