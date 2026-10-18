import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {flattenBinArray, hexToBin} from '@bitauth/libauth';

// Fixed compiler-body hashes bind these independently checked instruction replacements.
// Cached recipes retain P at their first selected literal and move it within the owned
// frame, and consumes it at its last selected use. Caller frames and guard order stay fixed.
const dblSha = '835c258d55b8a2efd642ddbe0c29814502acfc28eac8849b6f3529ed363ddf85';
const maddSha = 'e50879bb07f15ca1227c9c5f19bb1d7c9381b66f643a0aa00d5b9578c1dab538';
const recipes = {
  [dblSha]: {
    "bodySha256": "4e3b86b609032b3cda1823349f40433ef8912c082951bba7d42fbfecef0ceaca",
    "edits": [
      [
        3,
        36,
        "2047fd7cd8168c203c8dca7168916a81975d588181b64550b829a031e1724e64307d"
      ],
      [
        37,
        39,
        "5379"
      ],
      [
        39,
        41,
        "76"
      ],
      [
        42,
        75,
        "5279"
      ],
      [
        79,
        112,
        "5379"
      ],
      [
        114,
        116,
        "557a"
      ],
      [
        119,
        152,
        "5379"
      ],
      [
        153,
        154,
        "72"
      ],
      [
        156,
        157,
        "7d"
      ],
      [
        159,
        192,
        "78"
      ],
      [
        194,
        196,
        "5479"
      ],
      [
        232,
        265,
        "7c"
      ]
    ]
  },
  [maddSha]: {
    "bodySha256": "d08b357f43e3b9df7c7ae60f997042f69761de6a491d4275a4e9683d654f59db",
    "edits": [
      [
        4,
        37,
        "2047fd7cd8168c203c8dca7168916a81975d588181b64550b829a031e1724e64307d"
      ],
      [
        38,
        40,
        "557a"
      ],
      [
        42,
        75,
        "5279"
      ],
      [
        77,
        79,
        "5479"
      ],
      [
        81,
        82,
        "7b7b"
      ],
      [
        82,
        84,
        "5579"
      ],
      [
        85,
        118,
        "78"
      ],
      [
        119,
        121,
        "567a"
      ],
      [
        122,
        155,
        "78"
      ],
      [
        156,
        189,
        "78"
      ],
      [
        190,
        192,
        "5479"
      ],
      [
        231,
        232,
        "727c"
      ],
      [
        232,
        265,
        "78"
      ],
      [
        266,
        268,
        "5479"
      ],
      [
        272,
        305,
        "5279"
      ],
      [
        308,
        341,
        "5379"
      ],
      [
        342,
        344,
        "547a"
      ],
      [
        347,
        349,
        "567a"
      ],
      [
        350,
        383,
        "5479"
      ],
      [
        390,
        423,
        "5479"
      ],
      [
        426,
        459,
        "5479"
      ],
      [
        460,
        462,
        "557a"
      ],
      [
        529,
        531,
        "717c"
      ],
      [
        531,
        533,
        "547a"
      ],
      [
        533,
        535,
        "957b7c94"
      ],
      [
        535,
        568,
        "78"
      ],
      [
        569,
        570,
        "547a547a"
      ],
      [
        571,
        604,
        "7b"
      ]
    ]
  }
};
// Choose the cache/byte-cost tradeoff once for both builder and producer.
export const cacheProfile = process.env.SLIM_CACHE ?? 'floating';
const rawBodies = new Map([
  ['floating', []],
  ['orbit', []],
  ['orbit-retained', []],
  ['raw-dbl', [dblSha]],
  ['raw-madd', [maddSha]],
  ['raw-both', [dblSha, maddSha]],
]).get(cacheProfile);
assert(rawBodies, 'unknown SLIM_CACHE profile');
const sha = bytes => createHash('sha256').update(bytes).digest('hex');

export function cachePrimeLiterals(body) {
  const inputSha = sha(body);
  const cached = recipes[inputSha];
  assert(cached, 'unreviewed prime-cache helper body');
  // Raw-both also removes a duplicate index selection: 2PICK3PICK -> 2PICKDUP.
  const recipe = cacheProfile === 'raw-both' && inputSha === dblSha
    ? {bodySha256: '75f3585c32c76cd97deb5b40319ddd8ebf20578e099263de2fca365b5dc80612', edits: [[39, 41, '76']]}
    : rawBodies.includes(inputSha) ? {bodySha256: inputSha, edits: []} : cached;
  const parts = [];
  let at = 0;
  for (const [start, stop, hex] of recipe.edits) {
    assert(at <= start && start < stop && stop <= body.length);
    parts.push(body.slice(at, start), hexToBin(hex));
    at = stop;
  }
  parts.push(body.slice(at));
  const result = flattenBinArray(parts);
  assert.equal(sha(result), recipe.bodySha256);
  return result;
}
