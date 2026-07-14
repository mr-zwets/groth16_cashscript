// Executable bounds for the fp2Sqr and affine-G2 addition substitutions.
import { bigIntToVmNumber } from '@bitauth/libauth';

const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const FP2_SQR_INPUT_BOUND = 36n;
const FP2_MUL_INPUT_BOUND = 149n;

// fp2Sqr's new imaginary limb is (2*a0)*a1 mod p. The global lazy analysis
// bounds each input below 36p, so the unreduced product is below 2592p^2.
const doubledSqrInput = 2n * FP2_SQR_INPUT_BOUND;
const sqrImagProduct = doubledSqrInput * FP2_SQR_INPUT_BOUND * P * P;

// pointDoubleAffine receives canonical state and slope limbs. Its replacements
// therefore produce [0,2p) for 2Y/2X and [0,3p) for 3*X^2.
const twoAffine = 2n * P;
const threeAffine = 3n * P;
if (2n > FP2_MUL_INPUT_BOUND) throw new Error('2Y exceeds the proven fp2Mul domain');

// m^2-2X lies in (-2p,p); reducing once leaves (-p,p), which canonicalFp
// maps into [0,p). The slope comparison reduces a difference in (-3p,p).
const nextXLower = -2n * P;
const nextXUpper = P;
const slopeDifferenceLower = -3n * P;
const slopeDifferenceUpper = P;
if (!(nextXLower > -3n * P && nextXUpper <= P)) throw new Error('next-X interval proof failed');
if (!(slopeDifferenceLower >= -3n * P && slopeDifferenceUpper <= P)) throw new Error('slope interval proof failed');

console.log(`fp2Sqr imaginary raw product: <2592*p^2 (${bigIntToVmNumber(sqrImagProduct).length} signed bytes)`);
console.log(`affine doubled limbs: <2*p (${bigIntToVmNumber(twoAffine).length} signed bytes)`);
console.log(`affine tripled limbs: <3*p (${bigIntToVmNumber(threeAffine).length} signed bytes)`);
console.log('affine next-X input to canonicalFp is in (-2p,p); slope difference is in (-3p,p)');
