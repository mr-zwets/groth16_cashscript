// node cmp.mjs new.json ref.json...: byte compare; else compare locking bytecodes
import {readFileSync} from 'node:fs'; import {createHash} from 'node:crypto';
const [a, ...refs] = process.argv.slice(2); const A = readFileSync(a);
const lockings = (j) => { const s = new Set(); const walk = (o) => { if (Array.isArray(o)) o.forEach(walk); else if (o && typeof o === 'object') for (const [k, v] of Object.entries(o)) { if (/locking|redeem|program/i.test(k) && typeof v === 'string') s.add(k + ':' + createHash('sha256').update(v).digest('hex').slice(0, 16)); else walk(v); } }; walk(j); return [...s].sort(); };
for (const r of refs) { const B = readFileSync(r); if (A.equals(B)) { console.log('IDENTICAL', r); continue; }
  const la = lockings(JSON.parse(A)), lb = lockings(JSON.parse(B));
  console.log('DIFFER', r, 'lockings/redeems equal:', JSON.stringify(la) === JSON.stringify(lb), la.length, lb.length); }
