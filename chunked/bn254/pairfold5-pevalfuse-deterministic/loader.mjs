import {executor as legacyExecutor} from '../leader-recovered/loader.mjs';
export {p2sh} from '../leader-recovered/loader.mjs';
export const executor = `OP_DROP ${legacyExecutor}`;
