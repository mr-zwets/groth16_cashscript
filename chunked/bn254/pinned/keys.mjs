// Track 12: select the BN254 verifying key for this process, then load the verifier modules.
//   'sp1-v5' | 'risc0'  the real production keys of Track 11 (../real-keys/*.fixtures.json, provenance there);
//                       'risc0' folds risc0-ethereum main's control root b1f64013 (= risc0 main @ fc0222ab, unreleased)
//   'risc0-v3'          the same RISC Zero Groth16 VK folded for the RELEASED control root a54dc85a (risc0-zkvm 3.0.x,
//                       risc0-ethereum v3.0.1): ./risc0-v3.fixtures.json, written by fold-risc0.mjs
//   'test'              the reviewed build's own fixture VK (densless-recovered), whose trapdoor scalars are published
//                       in zk-verifier-bench (src/checkpoints/pairing-vectors.json): ../sound-si-gls/mint.mjs mints
//                       valid proofs for ANY statement under it. Used only to test the template with proofs of its
//                       exact statement; a deployment must use a real key.
// ../sound-si-gls/math.mjs reads the key once at import, so one process = one key.
import assert from 'node:assert/strict';
import {fileURLToPath} from 'node:url';

export const KEYS = {'sp1-v5': '../real-keys/sp1-v5.fixtures.json', risc0: '../real-keys/risc0.fixtures.json', 'risc0-v3': './risc0-v3.fixtures.json', test: null};
let loaded = null;
export async function loadKey(key) {
  assert.ok(key in KEYS, 'key: ' + Object.keys(KEYS).join(' | '));
  if (loaded) { assert.equal(loaded.key, key, 'one key per process'); return loaded; }
  if (KEYS[key]) process.env.BN_VK_FIXTURES = fileURLToPath(new URL(KEYS[key], import.meta.url)); else delete process.env.BN_VK_FIXTURES;
  const math = await import('../sound-si-gls/math.mjs');
  const proto = await import('../bn-native-sound/protocol.mjs');
  const script = await import('../bn-native-sound/script.mjs');
  const tx = await import('../bn-native-sound/transaction.mjs');
  const vm = await import('../bn-native-sound/vm.mjs');
  const tpl = await import('./template.mjs');
  const mint = key === 'test' ? await import('../sound-si-gls/mint.mjs') : null;
  loaded = {key, math, proto, script, tx, vm, tpl, mint};
  return loaded;
}
