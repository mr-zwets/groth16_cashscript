// The unmodified programs the single-input verifier is assembled from, each parsed into the
// function-aware form of ir.mjs under its own namespace:
//   s: kallisti's shared executor program (densless-recovered/shared.mjs)
//   g: the densless genesis with the dead vk_x predicate sliced out (densless-msm/genesis-slice)
//   t: the densless terminal (densless-recovered/terminal.mjs)
//   m: the cashc-compiled GLV Straus vk_x MSM as a library function (msm-single.mjs: the
//      math of pairfold5-msm/vkx-msm.mjs sourceFull, returning vk_x, tables built on-chain)
// s, g and t are byte-for-byte the programs of the 5-input densless-msm-spec entry; the
// edits that merge them are applied in build.mjs.
import assert from 'node:assert/strict';
import {bigIntToVmNumber, encodeDataPush, OpcodesBCH} from '@bitauth/libauth';
import {assemble} from './assemble.mjs';
import {compile as compileMsm} from './msm-single.mjs';
import {sliceGenesis} from '../densless-msm/genesis-slice.mjs';
import * as shared from '../densless-recovered/shared.mjs';
import * as genesis from '../densless-recovered/genesis.mjs';
import * as terminal from '../densless-recovered/terminal.mjs';
import {deploymentTag} from '../densless-recovered/constants.mjs';
import {parse} from './ir.mjs';

// Assemble a symbolic program exactly as densless-msm-spec/build.mjs does (same assembler).
export function assembleProgram(source, constants, main = source.main) {
  const identifiers = new Map(source.functions.map((f) => [f.name, f.originalId]));
  return Buffer.concat([
    assemble(source.prefix, identifiers, constants),
    ...source.functions.map((f) => Buffer.from([
      ...encodeDataPush(assemble(f.body, identifiers, constants)),
      ...encodeDataPush(bigIntToVmNumber(BigInt(f.originalId))), OpcodesBCH.OP_DEFINE,
    ])),
    assemble(main, identifiers, constants),
  ]);
}

// Replace exactly one occurrence of a symbolic token sequence.
export function editSymbolic(text, from, to, label) {
  const norm = (s) => s.trim().split(/\s+/).join(' ');
  const t = ` ${norm(text)} `, f = ` ${norm(from)} `;
  const first = t.indexOf(f);
  assert(first >= 0 && t.indexOf(f, first + 1) < 0, `${label}: symbolic pattern must occur exactly once`);
  return (t.slice(0, first) + ` ${norm(to)} ` + t.slice(first + f.length)).trim();
}

export const genesisDynamic = new Set(['g:28', 'g:29']);

export function loadSources({sharedMain = shared.main, terminalMain = terminal.main} = {}) {
  const constants = {deploymentTag, workerLockingRoot: Buffer.alloc(32), sharedHash256: Buffer.alloc(32)};
  const sliced = sliceGenesis(assembleProgram(genesis, constants));
  return {
    s: parse(assembleProgram(shared, constants, sharedMain), 's'),
    g: parse(sliced, 'g', genesisDynamic),
    t: parse(assembleProgram(terminal, constants, terminalMain), 't'),
    m: parse(compileMsm(), 'm'),
    raw: {shared, terminal},
  };
}
