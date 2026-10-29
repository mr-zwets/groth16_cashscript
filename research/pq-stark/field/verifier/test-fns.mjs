// Unit tests of the shared functions of gen.mjs on the loosened BCH 2026 VM against JS references: the Track 4
// functions (legacy build: fp 'grp', fold 'pair', deep 'pt', no xtab) and the Track 5 field-cost ones (default build).
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
const LEGACY = {fp: 'grp', fold: 'pair', deep: 'pt', xtab: false};
let built = buildB(prm, Buffer.from(v.proof, 'hex').subarray(0, 16), LEGACY);
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
  test('PAIR', [...g, ...u, ...w], F.add(F.add(F.red(u), F.red(w)), F.mul(g, F.sub(F.red(u), F.red(w)))), ['MULE']); }
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

// ---------------- Track 5 functions (default build) ----------------
built = buildB(prm, Buffer.from(v.proof, 'hex').subarray(0, 16));
const SK = 26, pk = (vals, sb) => vals.reduce((t, x, i) => t + (x << BigInt(8 * sb * i)), 0n);
const cols = (b, sb) => Array.from({length: e}, (_, k) => pk(Array.from({length: e}, (_, j) => (j >= k ? b[j - k] : 7n * b[j - k + e])), sb));
{ const b = Array.from({length: e}, () => rnd()); test('COLSK', b, cols(b, SK)); test('PACK', b, [pk(b, 17)]); test('COLS', b, cols(b, 17)); }
{ const u = Array.from({length: e}, () => rnd(1n << 64n)), w = Array.from({length: e}, () => rnd(1n << 64n)), beta = Array.from({length: e}, () => rnd()), xi = rnd();
  const exp = F.add(F.add(F.red(u), F.red(w)), F.mul(F.smul(beta, xi), F.sub(F.red(u), F.red(w))));
  // PAIRK leaves a packed, unreduced value: check it through UR
  const fnsU = [...built.fns];
  const defs = fnsU.filter(([n]) => n === 'PAIRK' || n === 'UR').map(([, f]) => asm(f.body, f.id, 'DEFINE'));
  const checks = [...exp].reverse().map((o) => asm(o, 'NUMEQUALVERIFY'));
  const redeem = Uint8Array.from([...defs.flatMap((d) => [...d]), ...asm(built.fns.get('PAIRK').id, 'INVOKE', built.fns.get('UR').id, 'INVOKE'), ...checks.flatMap((c) => [...c]), ...asm(1)]);
  const rr = evaluate('looseStd', p2sh32(redeem), pushes([...[...cols(beta, SK), xi, pk(u, SK), pk(w, SK)].map(nb), redeem]));
  console.log('PAIRK+UR', rr.accepted ? 'ok' : 'FAIL ' + rr.error, rr.opCost); bad += !rr.accepted;
  // extreme inputs: all leaf values 2^64 - 1
  const m = Array(e).fill((1n << 64n) - 1n);
  const exp2 = F.add(F.add(F.red(m), F.red(m)), F.mul(F.smul(beta, xi), F.sub(F.red(m), F.red(m))));
  const rr2 = evaluate('looseStd', p2sh32(Uint8Array.from([...defs.flatMap((d) => [...d]), ...asm(built.fns.get('PAIRK').id, 'INVOKE', built.fns.get('UR').id, 'INVOKE'), ...[...exp2].reverse().flatMap((o) => [...asm(o, 'NUMEQUALVERIFY')]), ...asm(1)])),
    pushes([...[...cols(beta, SK), xi, pk(m, SK), pk(m, SK)].map(nb), Uint8Array.from([...defs.flatMap((d) => [...d]), ...asm(built.fns.get('PAIRK').id, 'INVOKE', built.fns.get('UR').id, 'INVOKE'), ...[...exp2].reverse().flatMap((o) => [...asm(o, 'NUMEQUALVERIFY')]), ...asm(1)])]));
  console.log('PAIRK max', rr2.accepted ? 'ok' : 'FAIL ' + rr2.error); bad += !rr2.accepted;
}
{ const X = rnd(1n << 64n), Y = rnd(1n << 64n), H0 = Array.from({length: e}, () => rnd(1n << 64n)), H1 = Array.from({length: e}, () => rnd(1n << 64n));
  const a1 = Array.from({length: e}, () => rnd()), a2 = Array.from({length: e}, () => rnd()), n1 = rnd(), n2 = rnd();
  const g = [0, 1, 2, 3, 4].map(() => Array.from({length: e}, () => rnd())), C1 = Array.from({length: e}, () => rnd()), C2 = Array.from({length: e}, () => rnd());
  const num1 = F.sub(F.add(F.add(F.smul(g[0], X), F.smul(g[1], Y)), F.add(F.mul(g[3], F.red(H0)), F.mul(g[4], F.red(H1)))), C1);
  const f0 = F.add(F.mul(num1, F.smul(a1, n1)), F.mul(F.sub(F.smul(g[2], X), C2), F.smul(a2, n2)));
  test('DPK', [X, Y, ...H0, ...H1, ...a1, n1, ...a2, n2, pk(g[0], 17), pk(g[1], 17), ...cols(g[3], 17), ...cols(g[4], 17), pk(C1.map((x) => P - x), 17), pk(g[2], 17), pk(C2.map((x) => P - x), 17)], [pk(f0, SK)]); }
{ const vals = Array.from({length: 8}, () => Array.from({length: e}, () => rnd(1n << 64n)));
  const blob = Uint8Array.from(vals.flatMap((x) => x.flatMap((c) => [...le8(c)])));
  test('PKL', [blob], vals.map((x) => pk(x, SK)));
  const mx = Array.from({length: 2}, () => Array(e).fill((1n << 64n) - 1n));
  test('PKL', [Uint8Array.from(mx.flatMap((x) => x.flatMap((c) => [...le8(c)])))], mx.map((x) => pk(x, SK))); }
{ const u = Array.from({length: e}, () => rnd(1n << 200n)); test('UR', [pk(u, SK)], u.map(md)); }
{ const y = rnd(), k = rnd(); test('PW', [k, y], [k, md(k * y), y]); }
{ const t = Array.from({length: e}, () => rnd(1n << 133n)), rr = Array.from({length: e}, () => rnd(1n << 133n)), Y = rnd();
  const tb = t.map((x) => { const b = new Uint8Array(17); for (let i = 0; i < 17; i++) b[i] = Number((x >> BigInt(8 * i)) & 255n); return b; });
  test('HG', [...tb, ...rr, Y], [...rr.map((x, i) => md(x * Y + t[i])), Y]); }
console.log(bad ? `${bad} failures` : 'all ok');
