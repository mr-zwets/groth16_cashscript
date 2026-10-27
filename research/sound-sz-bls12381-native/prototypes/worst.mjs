// Worker op on a dense-nibble statement (random large public inputs, B = 7 G2): the GLS worst case per event.
import {runWorker} from './worker.mjs';
import {mintProof} from './protocol.mjs';
import {r} from './math.mjs';
const pf = mintProof(r - 0x1d2c3b4a5968778695a4b3c2d1e0f0e1d2c3b4a5968778695a4b3c2d1e0fn, 0x3a5b7c9d1e2f40516273849506a7b8c9dae0f1a2b3c4d5e6f708192a3b4c5dn, 101n, 7n);
for (const [j0, j1] of [[0, 4], [12, 20], [24, 32]]) { const x = runWorker(pf, j0, j1, () => true, {quiet: true}); console.log(`[${j0},${j1}) events ${x.nEvents} gls/event ${Math.round(x.by['ev-gls'] / x.nEvents)} dbl/event ${Math.round(x.by['ev-dbl'] / x.nEvents)} dstep ${Math.round(x.by['ev-dstep'] / (x.nEvents + x.nAdds))} bound/chunk ${Math.round((x.by.bound ?? 0) / (x.nChunks - (x.terminal ? 1 : 0)))} total ${x.total}`); }
