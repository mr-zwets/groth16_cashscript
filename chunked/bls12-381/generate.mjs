// One-command orchestrator: regenerate ALL chunked BLS12-381 artifacts + benchmark
// vectors. Everything in generated/ is git-ignored (reproducible). Several minutes:
// each chunk is sized by compiling with the custom cashc and measuring real-VM
// op-cost. node generate.mjs
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const run = (script, args = []) => { console.error(`\n=== ${script} ${args.join(' ')} ===`); execFileSync('node', [join(here, script), ...args], { stdio: 'inherit' }); };

run('gen_vkx.mjs');                         // vk_x covenant chunks
run('gen_miller.mjs');                      // batched 4-pair Miller loop (shared fp12Sqr; no combine)
run('gen_finalexp.mjs');                    // final exponentiation -> verdict
run('build_vectors.mjs');                   // -> vkx-bls12381-chunked-covenant-vectors.json
run('build_vectors_pairing.mjs');           // -> pairing- + groth16-bls12381-chunked-vectors.json
console.error('\nall BLS12-381 chunked artifacts + vectors regenerated.');
