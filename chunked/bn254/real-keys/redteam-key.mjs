// Track 11: run the bn-native-sound rejection suite (redteam-core.mjs, a documented copy) against a real key.
//   node redteam-key.mjs sp1-v5|risc0 <key>.redteam.json [<key>.redteam-report.json]
import {selectKey} from './build-key.mjs';
const [key, ...rest] = process.argv.slice(2);
selectKey(key); process.env.RK_KEY = key; process.argv = [process.argv[0], process.argv[1], ...rest];
await import('./redteam-core.mjs');
