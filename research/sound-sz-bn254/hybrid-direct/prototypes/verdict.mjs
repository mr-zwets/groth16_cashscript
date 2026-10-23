// Measure the terminal torus verdict on a 6-limb G_J (minop's torusFrob1/2 + fp6MulRaw, adapted
// to the 6-limb state: 4 fp6MulRaw instead of fp12MulTorus + 3 fp6MulRaw). Compiled with the
// repository's default cashc (same as minop) and with the zk-language fork; both measured.
// Compilers: CASHC = path of cashc's dist/index.js (default: the repo's `cashc` dependency, which
// must be built: link:../cashscript/packages/cashc),
// CASHC_ZK = the zk-language fork's dist/index.js (skipped when unset).
// Usage: CASHC=<path>/dist/index.js CASHC_ZK=<path>/dist/index.js node verdict.mjs
import {pathToFileURL} from 'node:url';
import {run, asm, num, P} from './sscomp.mjs';
import {makeWitness} from './witness.mjs';
const here = new URL('.', import.meta.url).pathname;
const out = {};
const compilers = [['cashc-default', process.env.CASHC ? pathToFileURL(process.env.CASHC).href : 'cashc']];
if (process.env.CASHC_ZK) compilers.push(['cashc-zk', pathToFileURL(process.env.CASHC_ZK).href]);
for (const [name, path] of compilers) {
  try {
    const {compileFile, utils} = await import(path);
    const bytes = utils.asmToBytecode(compileFile(here + 'verdict.cash', {rescheduleStacks: true}).bytecode);
    const res = [];
    for (const fi of [0, 1, 2]) {
      const w = makeWitness(fi, 'proj'); const G = w.states.at(-1);
      const args = [...G, ...w.u];
      const pushes = args.slice().reverse().map(num);
      const a = run(pushes, bytes), b = run(pushes, asm('1'));
      const bad = [...args]; bad[0] = (bad[0] + 1n) % P;
      const t = run(bad.slice().reverse().map(num), bytes);
      // the bare contract leaves the 12 pushed arguments' clean-stack error as the only 'error' on success
      const ok = (x) => !x.err || /unexpected number/.test(x.err);
      res.push({fi, op: a.cost - b.cost, accepted: ok(a), tamperedRejected: !ok(t)});
    }
    out[name] = {bytes: bytes.length, res};
  } catch (e) { out[name] = {error: String(e).slice(0, 300)}; }
}
console.log(JSON.stringify(out, null, 1));
// a compiler that failed to load or compile is a failed reproduction, not a result
if (Object.values(out).some((o) => o.error || o.res?.some((r) => !r.accepted || !r.tamperedRejected))) process.exitCode = 1;
