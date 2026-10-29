// Reference arithmetic (JS BigInt) for the pq-hash on-chain verifier: Goldilocks and F_p[u]/(u^e - 7), e = 2 or 3.
// Independent of the prover's Python; checked against the vectors' derived values in model.mjs.
import {createHash} from 'node:crypto';

export const P = (1n << 64n) - (1n << 32n) + 1n;
export const W = 7n;
export const md = (a) => ((a % P) + P) % P;
export function powp(b, e) { let r = 1n; b = md(b); e = BigInt(e); while (e > 0n) { if (e & 1n) r = r * b % P; b = b * b % P; e >>= 1n; } return r; }
export const invp = (a) => { if (md(a) === 0n) throw new Error('inverse of 0'); return powp(a, P - 2n); };
export const rou = (k) => powp(7n, (P - 1n) / BigInt(k));

export const sha = (...parts) => Uint8Array.from(createHash('sha256').update(Buffer.concat(parts.map((x) => Buffer.from(x)))).digest());
export const leNum = (b) => { let v = 0n; for (let i = b.length - 1; i >= 0; i--) v = (v << 8n) | BigInt(b[i]); return v; };
export const le8 = (v) => { const b = new Uint8Array(8); v = BigInt(v); for (let i = 0; i < 8; i++) b[i] = Number((v >> BigInt(8 * i)) & 255n); return b; };
export const u16 = (v) => Uint8Array.of(v & 255, v >> 8);
export const cat = (...xs) => { const n = xs.reduce((a, x) => a + x.length, 0); const o = new Uint8Array(n); let i = 0; for (const x of xs) { o.set(x, i); i += x.length; } return o; };
export const hex = (b) => Buffer.from(b).toString('hex');
export const fromHex = (h) => Uint8Array.from(Buffer.from(h, 'hex'));

export function Ext(e) {
  const F = {
    e,
    zero: Array(e).fill(0n),
    one: [1n, ...Array(e - 1).fill(0n)],
    lift: (a) => [md(a), ...Array(e - 1).fill(0n)],
    add: (a, b) => a.map((x, i) => md(x + b[i])),
    sub: (a, b) => a.map((x, i) => md(x - b[i])),
    smul: (a, k) => a.map((x) => md(x * k)),
    red: (a) => a.map(md),
    mul: (a, b) => (e === 2
      ? [md(a[0] * b[0] + W * a[1] * b[1]), md(a[0] * b[1] + a[1] * b[0])]
      : [md(a[0] * b[0] + W * (a[1] * b[2] + a[2] * b[1])), md(a[0] * b[1] + a[1] * b[0] + W * a[2] * b[2]), md(a[0] * b[2] + a[1] * b[1] + a[2] * b[0])]),
    eq: (a, b) => a.every((x, i) => md(x - b[i]) === 0n),
    dec: (buf, o) => Array.from({length: e}, (_, i) => leNum(buf.subarray(o + 8 * i, o + 8 * i + 8))), // raw (unreduced)
    fromDigest: (d) => { let v = leNum(d); const out = []; for (let i = 0; i < e; i++) { out.push(v % P); v /= P; } return out; },
  };
  F.pow = (a, k) => { let r = F.one, b = a; k = BigInt(k); while (k > 0n) { if (k & 1n) r = F.mul(r, b); b = F.mul(b, b); k >>= 1n; } return r; };
  F.inv = (a) => {
    if (e === 2) { const n = md(a[0] * a[0] - W * a[1] * a[1]); const ni = invp(n); return [md(a[0] * ni), md(-a[1] * ni)]; }
    const [a0, a1, a2] = a;
    const b0 = md(a0 * a0 - W * a1 * a2), b1 = md(W * a2 * a2 - a0 * a1), b2 = md(a1 * a1 - a0 * a2);
    const ni = invp(md(a0 * b0 + W * (a2 * b1 + a1 * b2)));
    return [b0, b1, b2].map((x) => md(x * ni));
  };
  return F;
}
