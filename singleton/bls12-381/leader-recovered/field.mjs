// The exact negative BLS seed, field prime and full final exponent.
export const BLS_X = -0xd201000000010000n;
export const scalarPrime = BLS_X ** 4n - BLS_X ** 2n + 1n;
export const fieldPrime = (BLS_X - 1n) ** 2n * scalarPrime / 3n + BLS_X;
export const finalExponent = (fieldPrime ** 12n - 1n) / scalarPrime;
if ((BLS_X - 1n) ** 2n * scalarPrime % 3n !== 0n ||
    (fieldPrime ** 12n - 1n) % scalarPrime !== 0n ||
    finalExponent.toString(2).length !== 4314) {
  throw new Error('invalid recovered BLS parameter derivation');
}
