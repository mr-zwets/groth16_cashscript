// Public BN254 curve parameter and deterministic field moduli.
export const BN_X = 4965661367192848881n;
export const BASE_FIELD = 36n * BN_X ** 4n + 36n * BN_X ** 3n + 24n * BN_X ** 2n + 6n * BN_X + 1n;
export const SCALAR_FIELD = 36n * BN_X ** 4n + 36n * BN_X ** 3n + 18n * BN_X ** 2n + 6n * BN_X + 1n;

// Public fixed deployment literal embedded in the recovered genesis program.
// Historical derivation is unknown; do not assume it is a hash of the public VK.
export const deploymentTag = Buffer.from('9c1f30d6d0762b66a52c266e919b1fa2523e199857083d4090abeddb45c41f66', 'hex');

export const layout = {
  fragmentOffset: 302,
  fragmentLengths: [867, 1156, 810],
  quotientLengths: [1248, 1248, 1248],
  quotientSuffixLengths: [0, 0, 0],
  quotientSuffixBytes: [0x5a, 0x79, 0x98],
  executorPaddingLengths: [0, 0, 0],
  terminalPaddingLength: 0,
};
