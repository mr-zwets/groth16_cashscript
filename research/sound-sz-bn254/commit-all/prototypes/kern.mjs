// Hand-scheduled kernel formulas (lazy reduction), written against the abstract ops `k` of lib.mjs.
// Fp2 = Fp[u]/(u^2+1); values are [c0, c1]. A line (cy, cx, cb) in Fp2^3 is evaluated at +-z as
//   e0 = eps(cy)*yP  (even part),  T = eps(cx)*xP*z + eps(cb)*z^3  (odd part),  l(+-z) = e0 +- T,
// with eps(a) = a0 + a1*(z^6 - 9). Per-pair constants (computed once in setup):
//   yP, yPu = yP*u_z, xz = xP*z, xzu = xz*u_z, xz3 = 3*xz, xz6u = 6*xz*u_z, z3 = z^3, z3u = z^3*u_z.
import {P} from './lib.mjs';
const inv = (a) => { let [r0, r1, t0, t1] = [P, ((a % P) + P) % P, 0n, 1n]; while (r1) { const q = r0 / r1; [r0, r1] = [r1, r0 - q * r1]; [t0, t1] = [t1, t0 - q * t1]; } return ((t0 % P) + P) % P; };
export const KAPPA = (9n * inv(82n)) % P; // 3b' = 9/(9+u) = KAPPA * (9 - u)

const mulRaw = (k, [a0, a1], [b0, b1]) => [k.sub(k.mul(a0, b0), k.mul(a1, b1)), k.add(k.mul(a0, b1), k.mul(a1, b0))];
const red = (k, [a, b]) => [k.mod(a), k.mod(b)];
export const f2mul = (k, a, b) => red(k, mulRaw(k, a, b));
export const f2sqrRaw = (k, [a0, a1]) => [k.mul(k.add(a0, a1), k.sub(a0, a1)), k.mul(k.add(a0, a0), a1)];
const mulK = (k, [a0, a1], [c0, c1]) => [k.sub(k.mulc(a0, c0), k.mulc(a1, c1)), k.add(k.mulc(a0, c1), k.mulc(a1, c0))];

export const foldSq = (k, Up, Um) => [k.mod(k.mul(Up, Up)), k.mod(k.mul(Um, Um))];
export const foldMul = (k, Up, Um, lp, lm) => [k.mod(k.mul(Up, lp)), k.mod(k.mul(Um, lm))];

// ---- projective doubling + line (homogeneous, b' = 3/(9+u)), scaled by 4 so no halving.
// X3 = 2XY(B-F), Y3 = (B+F)^2 - 12E^2, Z3 = 4BH with B = Y^2, C = Z^2, E = 3b'C, F = 3E,
// H = (Y+Z)^2 - B - C (= 2YZ). Line (cy, cx, cb) = (H, -3X^2, B - E) = H * (1, -lambda, lambda*x - y).
export function projDbl(k, {X, Y, Z}, c) {
  const XY = red(k, mulRaw(k, X, Y));
  const B = red(k, [k.mul(k.add(Y[0], Y[1]), k.sub(Y[0], Y[1])), k.mul(k.add(Y[0], Y[0]), Y[1])]);
  const C = red(k, [k.mul(k.add(Z[0], Z[1]), k.sub(Z[0], Z[1])), k.mul(k.add(Z[0], Z[0]), Z[1])]);
  const E = [k.mod(k.mulc(k.add(k.mulc(C[0], 9), C[1]), KAPPA)), k.mod(k.mulc(k.sub(k.mulc(C[1], 9), C[0]), KAPPA))];
  const F = [k.mulc(E[0], 3), k.mulc(E[1], 3)];
  const BmF = [k.sub(B[0], F[0]), k.sub(B[1], F[1])], G = [k.add(B[0], F[0]), k.add(B[1], F[1])];
  const xr = mulRaw(k, XY, BmF); const X3 = [k.mod(k.mulc(xr[0], 2)), k.mod(k.mulc(xr[1], 2))];
  const Y3 = [k.mod(k.sub(k.mul(k.add(G[0], G[1]), k.sub(G[0], G[1])), k.mulc(k.mul(k.add(E[0], E[1]), k.sub(E[0], E[1])), 12))),
    k.mod(k.sub(k.mulc(k.mul(G[0], G[1]), 2), k.mulc(k.mul(E[0], E[1]), 24)))];
  const S = [k.add(Y[0], Z[0]), k.add(Y[1], Z[1])];
  const H = [k.mod(k.sub(k.mul(k.add(S[0], S[1]), k.sub(S[0], S[1])), k.add(B[0], C[0]))), k.mod(k.sub(k.mul(k.add(S[0], S[0]), S[1]), k.add(B[1], C[1])))];
  const zr = mulRaw(k, B, H); const Z3 = [k.mod(k.mulc(zr[0], 4)), k.mod(k.mulc(zr[1], 4))];
  // line at +-z: e0 = H0*yP + H1*yPu ; T = -(XX0*xz3 + X0X1*xz6u) + (B0-E0)*z3 + (B1-E1)*z3u, XX0 = X0^2 - X1^2 unreduced
  const XX0 = k.mul(k.add(X[0], X[1]), k.sub(X[0], X[1])), X01 = k.mul(X[0], X[1]);
  const e0 = k.add(k.mul(H[0], c.yP), k.mul(H[1], c.yPu));
  const T = k.sub(k.add(k.mul(k.sub(B[0], E[0]), c.z3), k.mul(k.sub(B[1], E[1]), c.z3u)), k.add(k.mul(XX0, c.xz3), k.mul(X01, c.xz6u)));
  return {X: X3, Y: Y3, Z: Z3, lp: k.mod(k.add(e0, T)), lm: k.mod(k.sub(e0, T))};
}
// ---- projective + affine mixed addition and line (Q affine).
// theta = Y - yQ Z, lam = X - xQ Z, C = theta^2, D = lam^2, E = lam D, F = Z C, G = X D, H = E + F - 2G,
// X3 = lam H, Y3 = theta (G - H) - Y E, Z3 = Z E. Line (cy, cx, cb) = (lam, -theta, theta xQ - lam yQ).
export function projAdd(k, {X, Y, Z}, Q, c) {
  const yz = mulRaw(k, Q.y, Z), xz = mulRaw(k, Q.x, Z);
  const th = [k.mod(k.sub(Y[0], yz[0])), k.mod(k.sub(Y[1], yz[1]))], la = [k.mod(k.sub(X[0], xz[0])), k.mod(k.sub(X[1], xz[1]))];
  const C = red(k, f2sqrRaw(k, th)), D = red(k, f2sqrRaw(k, la));
  const E = f2mul(k, la, D), F = f2mul(k, Z, C), G = f2mul(k, X, D);
  const H = [k.sub(k.add(E[0], F[0]), k.add(G[0], G[0])), k.sub(k.add(E[1], F[1]), k.add(G[1], G[1]))];
  const X3 = f2mul(k, la, H);
  const a = mulRaw(k, th, [k.sub(G[0], H[0]), k.sub(G[1], H[1])]), b = mulRaw(k, Y, E);
  const Y3 = [k.mod(k.sub(a[0], b[0])), k.mod(k.sub(a[1], b[1]))];
  const Z3 = f2mul(k, Z, E);
  const p1 = mulRaw(k, th, Q.x), p2 = mulRaw(k, la, Q.y);
  const cb = [k.mod(k.sub(p1[0], p2[0])), k.mod(k.sub(p1[1], p2[1]))];
  const e0 = k.add(k.mul(la[0], c.yP), k.mul(la[1], c.yPu));
  const T = k.sub(k.add(k.mul(cb[0], c.z3), k.mul(cb[1], c.z3u)), k.add(k.mul(th[0], c.xz), k.mul(th[1], c.xzu)));
  return {X: X3, Y: Y3, Z: Z3, lp: k.mod(k.add(e0, T)), lm: k.mod(k.sub(e0, T))};
}
// ---- affine step with a slope (witnessed for B: checked; baked for delta: trusted constant).
// dbl: check 2*lam*y == 3*x^2 ; add: check (qx - x) != 0 and lam*(qx - x) == qy - y.
// x' = lam^2 - x - x2 (x2 = x for dbl, qx for add), b = lam*x - y, y' = b - lam*x'. Unit line (1, -lam, b):
// l(+-z) = yP +- T, T = -(l0*xz + l1*xzu) + b0*z3 + b1*z3u.
export function affStep(k, {x, y}, lam, c, {check = null, Q = null, qx = null} = {}) {
  const x2 = Q ? Q.x : qx;
  if (check === 'dbl') {
    const ly = mulRaw(k, lam, y), xx = f2sqrRaw(k, x);
    k.eqz(k.sub(k.add(ly[0], ly[0]), k.mulc(xx[0], 3))); k.eqz(k.sub(k.add(ly[1], ly[1]), k.mulc(xx[1], 3)));
  } else if (check === 'add') {
    const d = [k.sub(Q.x[0], x[0]), k.sub(Q.x[1], x[1])]; k.nz2(d[0], d[1]);
    const ld = mulRaw(k, lam, d); k.eqz(k.sub(ld[0], k.sub(Q.y[0], y[0]))); k.eqz(k.sub(ld[1], k.sub(Q.y[1], y[1])));
  }
  const l2 = f2sqrRaw(k, lam);
  const nx = x2 ? [k.mod(k.sub(l2[0], k.add(x[0], x2[0]))), k.mod(k.sub(l2[1], k.add(x[1], x2[1])))]
    : [k.mod(k.sub(l2[0], k.add(x[0], x[0]))), k.mod(k.sub(l2[1], k.add(x[1], x[1])))];
  const lx = mulRaw(k, lam, x); const b = [k.mod(k.sub(lx[0], y[0])), k.mod(k.sub(lx[1], y[1]))];
  const lnx = mulRaw(k, lam, nx); const ny = [k.mod(k.sub(b[0], lnx[0])), k.mod(k.sub(b[1], lnx[1]))];
  const T = k.mod(k.sub(k.add(k.mul(b[0], c.z3), k.mul(b[1], c.z3u)), k.add(k.mul(lam[0], c.xz), k.mul(lam[1], c.xzu))));
  return {x: nx, y: ny, lp: k.add(c.yP, T), lm: k.sub(c.yP, T)};
}
// ---- fully baked line (lambda, b): only the evaluation
export function bakedLine(k, lam, b, c) {
  const T = k.mod(k.sub(k.add(k.mul(b[0], c.z3), k.mul(b[1], c.z3u)), k.add(k.mul(lam[0], c.xz), k.mul(lam[1], c.xzu))));
  return {lp: k.add(c.yP, T), lm: k.sub(c.yP, T)};
}
// ---- psi on the twist: (conj(x) * PX, conj(y) * PY)
export function psiK(k, {x, y}, PX, PY) {
  const cx = [x[0], k.neg(x[1])], cy = [y[0], k.neg(y[1])];
  return {x: red(k, mulK(k, cx, [PX.c0, PX.c1])), y: red(k, mulK(k, cy, [PY.c0, PY.c1]))};
}
