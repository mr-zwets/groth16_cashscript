// Unit tests of the shared functions of gen.mjs on the loosened BCH 2026 VM against JS references.
import {readFileSync} from 'node:fs';
import {asm} from './lib/asm.mjs';
import {makeParams} from './params.mjs';
import {buildB} from './gen.mjs';
import {P, md, powp, rou, Ext, le8, leNum, sha, cat} from './field.mjs';
import {deepConsts, normAdj} from './model.mjs';
import {evaluate, p2sh32, pushes} from './vm.mjs';
import {bigIntToVmNumber} from '@bitauth/libauth';

const nb = (v) => bigIntToVmNumber(BigInt(v));
let seed = 12345n;
const rnd = (m = P) => { seed = (seed * 6364136223846793005n + 1442695040888963407n) & ((1n << 128n) - 1n); return (seed >> 32n) % m; };

export function runFn(built, name, args, outs, extraDefs = []) {
  const defs = [...built.fns].filter(([n]) => n === name || extraDefs.includes(n)).map(([, f]) => asm(f.body, f.id, 'DEFINE'));
  const f = built.fns.get(name);
  const checks = [...outs].reverse().map((o) => (o instanceof Uint8Array ? asm(o, 'EQUALVERIFY') : asm(o, 'NUMEQUALVERIFY')));
  const redeem = Uint8Array.from([...defs.flatMap((d) => [...d]), ...asm(f.id, 'INVOKE'), ...checks.flatMap((c) => [...c]), ...asm(1)]);
  const unl = pushes([...args.map((x) => (x instanceof Uint8Array ? x : nb(x))), redeem]);
  return evaluate('looseStd', p2sh32(redeem), unl);
}

const v = JSON.parse(readFileSync(process.argv[2] ?? '../prover/vectors/P128-0.json', 'utf8'));
const prm = makeParams(v.params);
const built = buildB(prm, Buffer.from(v.proof, 'hex').subarray(0, 16));
const e = prm.e, F = Ext(e);
let bad = 0;
const test = (name, args, outs, extra) => { const r = runFn(built, name, args, outs, extra); console.log(name.padEnd(8), r.accepted ? 'ok' : 'FAIL ' + r.error, r.opCost); bad += !r.accepted; };
const A = Array.from({length: e}, () => rnd()), B = Array.from({length: e}, () => rnd()), s = rnd();
test('MM', [A[0], B[0]], [md(A[0] * B[0])]);
test('MULE', [...A, ...B], F.mul(A, B));
test('SQE', A, F.mul(A, A));
test('MULF', [...A, s], F.smul(A, s));
{ const d = sha(Uint8Array.of(1, 2, 3)); test('E', [d], F.fromDigest(d)); }
{ const u = Array.from({length: e}, () => rnd(1n << 64n)), w = Array.from({length: e}, () => rnd(1n << 64n)), g = Array.from({length: e}, () => rnd());
  test('PAIR', [...u, ...w, ...g], F.add(F.add(F.red(u), F.red(w)), F.mul(g, F.sub(F.red(u), F.red(w))))); }
{ const z = Array.from({length: e}, () => rnd()); const dc = deepConsts(prm, z)[0]; const x = rnd();
  const na = normAdj(prm, x, dc);
  const args = e === 3 ? [x, md(-dc.z0), dc.z1, dc.z2, dc.K0, dc.K1, dc.K2, dc.cA, dc.cB] : [x, md(-dc.z0), dc.cN];
  test('NA', args, e === 3 ? [na.N, ...na.adj] : [na.N, na.adj[0]]);
  // the norm/adjugate are those of x - z
  const xz = F.sub(F.lift(x), z); const inv = F.inv(xz); const chk = F.smul(na.adj, powp(na.N, P - 2n));
  console.log('NA inverse matches', F.eq(inv, chk)); bad += !F.eq(inv, chk);
}
{ // HORN
  const acc = Array.from({length: e}, () => rnd()), u = Array.from({length: e}, () => rnd(1n << 133n)), Y = rnd();
  const Pk = u.reduce((t, x, i) => t + (x << BigInt(136 * i)), 0n);
  test('HORN', [...acc, Pk, Y], acc.map((x, i) => md(x * Y + u[i]))); }
{ const y = rnd(); test('POWS', [y], Array.from({length: built.G}, (_, k) => powp(y, k + 1))); }
{ const v0 = rnd(1n << BigInt(Math.log2(prm.sizes[1]))); test('XPOW', [v0], [md(7n * powp(rou(prm.sizes[0]), v0))]); test('XPOW', [0n], [7n]); }
{ const b = Uint8Array.from(Array.from({length: 64}, () => Number(rnd(256n)))); test('PARSE8', [b], Array.from({length: 8}, (_, i) => leNum(b.subarray(8 * i, 8 * i + 8)))); }
console.log(bad ? `${bad} failures` : 'all ok');
