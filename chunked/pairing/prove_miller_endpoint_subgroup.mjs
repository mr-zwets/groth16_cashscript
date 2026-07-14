// Executable algebraic proof for the subgroup check fused into runtime-B Miller post-processing.
//
// On the full BN254 twist group, the twist Frobenius psi satisfies
//   U(psi) = psi^4 - psi^2 + 1 = 0.
// The Miller endpoint before post-processing is R=[s]B for s=6x+2. Define
//   G(T) = T^3 - T^2 + T + s.
// Then G(psi)B=0 is exactly R+psi(B)-psi^2(B)+psi^3(B)=0.
//
// The resultant proves the converse on every rational twist point, not only sampled points:
//   Res(U,G)=36r.
// The twist group has order r*h2, with gcd(36r,h2)=1, so Bezout over Z[T] makes G(psi)
// invertible on the h2-primary subgroup. On r-torsion psi acts as z=6x^2 and G(z)=0 mod r.
// Therefore ker G(psi) on E'(Fp2) is exactly the order-r G2 subgroup.

const X = 4965661367192848881n;
const S = 6n * X + 2n;
const R = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const H2 = 21888242871839275222246405745257275088844257914179612981679871602714643921549n;
const GROUP_ORDER = R * H2;
const EXPECTED_RESULTANT = 787976743386213908000870606829261903187741118414977236373135350716729105842212n;

const U = [1n, 0n, -1n, 0n, 1n]; // ascending coefficients: 1-T^2+T^4
const G = [S, 1n, -1n, 1n];      // s+T-T^2+T^3

function gcd(a, b) {
  while (b !== 0n) [a, b] = [b, a % b];
  return a < 0n ? -a : a;
}

// Fraction-free Bareiss determinant: every division is exact over this integer matrix.
function determinant(matrix) {
  const a = matrix.map((row) => row.slice());
  let sign = 1n;
  let previousPivot = 1n;
  for (let k = 0; k < a.length - 1; k++) {
    let pivotRow = k;
    while (pivotRow < a.length && a[pivotRow][k] === 0n) pivotRow += 1;
    if (pivotRow === a.length) return 0n;
    if (pivotRow !== k) {
      [a[pivotRow], a[k]] = [a[k], a[pivotRow]];
      sign = -sign;
    }
    const pivot = a[k][k];
    for (let i = k + 1; i < a.length; i++) {
      for (let j = k + 1; j < a.length; j++) {
        a[i][j] = (a[i][j] * pivot - a[i][k] * a[k][j]) / previousPivot;
      }
    }
    previousPivot = pivot;
  }
  return sign * a[a.length - 1][a.length - 1];
}

function resultant(f, g) {
  const fDegree = f.length - 1;
  const gDegree = g.length - 1;
  const size = fDegree + gDegree;
  const matrix = Array.from({ length: size }, () => Array(size).fill(0n));
  const fDescending = f.slice().reverse();
  const gDescending = g.slice().reverse();
  for (let row = 0; row < gDegree; row++) {
    fDescending.forEach((coefficient, column) => { matrix[row][row + column] = coefficient; });
  }
  for (let row = 0; row < fDegree; row++) {
    gDescending.forEach((coefficient, column) => { matrix[gDegree + row][row + column] = coefficient; });
  }
  const value = determinant(matrix);
  return value < 0n ? -value : value;
}

const mainResultant = resultant(U, G);
if (mainResultant !== EXPECTED_RESULTANT || mainResultant !== 36n * R) {
  throw new Error('unexpected Res(U,G)');
}
if (gcd(R, H2) !== 1n || gcd(mainResultant, H2) !== 1n) {
  throw new Error('G(psi) is not proven invertible on the cofactor subgroup');
}
if (R % 6n !== 1n || H2 % 6n !== 1n || GROUP_ORDER !== R * H2) {
  throw new Error('unexpected BN254 twist-order factors');
}

const z = (6n * X * X) % R;
const uAtZ = (z ** 4n - z * z + 1n) % R;
const gAtZ = (z ** 3n - z * z + z + S) % R;
if (uAtZ !== 0n || gAtZ !== 0n) {
  throw new Error('G(psi) does not kill the r-torsion eigenspace');
}
if (gcd(mainResultant, GROUP_ORDER) !== R) {
  throw new Error('the rational-point kernel is not exactly the r-torsion subgroup');
}

// The two Miller post-processing additions must not encounter equal/inverse exceptional cases
// for any nonzero rational twist point. Their four difference polynomials have resultants coprime
// to the complete twist-group order, so none can kill a nonzero B.
const exceptionalPolynomials = [
  [S, -1n],      // [s]B = psi(B)
  [S, 1n],       // [s]B = -psi(B)
  [S, 1n, 1n],  // [s]B+psi(B) = -psi^2(B)
  [S, 1n, -1n], // [s]B+psi(B) = psi^2(B)
];
if (exceptionalPolynomials.some((polynomial) => gcd(resultant(U, polynomial), GROUP_ORDER) !== 1n)) {
  throw new Error('a Miller post-processing exceptional case is reachable');
}

console.log('Miller endpoint subgroup proof passed');
console.log(`Res(U,G) = ${mainResultant} = 36*r`);
console.log('ker G(psi) on E\'(Fp2) is exactly G2[r]; post-processing additions are nonexceptional');
