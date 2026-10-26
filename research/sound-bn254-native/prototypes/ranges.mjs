// Measures the loop op cost of every chunk-aligned event range [a, b) in both modes (fixture 0 by default),
// so the layout model can price any split into inputs: ranges.json[mode][a][b] = op.
//   FIX=0 node research/sound-bn254-native/prototypes/ranges.mjs > research/sound-bn254-native/prototypes/ranges.json
import {measureRange, fixtureData} from './loop.mjs';
const data = fixtureData(Number(process.env.FIX ?? 0));
const cuts = []; for (let e = 0; e <= 64; e += 2) cuts.push(e); cuts.push(65);
// per-chunk costs are additive up to a constant per range (measured: sums of thirds match the whole within 0.3%),
// so measure single chunks and the whole loop; the model sums chunk costs and adds the per-range constant
const out = {fixture: Number(process.env.FIX ?? 0), chunks: {}, whole: {}};
for (const mode of ['affine', 'affineN', 'affineAN', 'proj']) {
  out.chunks[mode] = [];
  for (let i = 0; i + 1 < cuts.length; i++) out.chunks[mode].push(measureRange(mode, cuts[i], cuts[i + 1], data).loopOp);
  out.whole[mode] = measureRange(mode, 0, 65, data).loopOp;
  const sum = out.chunks[mode].reduce((x, y) => x + y, 0);
  out[mode + 'PerRangeConst'] = Math.round((sum - out.whole[mode]) / (cuts.length - 2)); // overhead per extra range start
}
console.log(JSON.stringify(out, null, 1));
