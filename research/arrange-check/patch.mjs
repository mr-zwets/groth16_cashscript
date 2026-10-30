// usage: node patch.mjs detect|fix asm.mjs...
//   detect: keep the old behaviour, but log every arrange() call where the Track 7 fix would lower k, and every roll()
//           whose old symbolic splice (st.length-1-d, d counting pile pieces) removes a different item than idx(name).
//           (A negative splice index clamps to 0; when the item is the bottom one that is still correct: 'negidx-benign'.)
//   fix:    the Track 7 arrange() fix, and the Track 6 roll() symbolic-index fix where the copy lacks it.
import {readFileSync, writeFileSync} from 'node:fs';
const [mode, ...files] = process.argv.slice(2);
const A = 'const win = this.st.slice(-n); while (k < n && win[k] === names[k]) k++;';
const R = /roll\(name\) \{ const d = this\.depth\(name\);/;
for (const f of files) {
  let s = readFileSync(f, 'utf8');
  if (!s.includes(A)) throw new Error('arrange pattern missing ' + f);
  if (mode === 'detect') {
    s = s.replace(A, A + `\n    { let k2 = k; while (k2 > 0 && !win.slice(k2).every((x) => names.slice(k2).includes(x))) k2--; if (k2 !== k) { globalThis.__asmchk = (globalThis.__asmchk ?? 0) + 1; console.error('ASMCHK arrange k ' + k + '->' + k2 + ' names=' + names.join(',') + ' win=' + win.join(',')); } }`);
    s = s.replace(R, `roll(name) { const d = this.depth(name); { const L = this.st.length, s0 = L - 1 - d, eff = s0 < 0 ? Math.max(L + s0, 0) : s0; if (eff !== this.idx(name)) { globalThis.__asmchk = (globalThis.__asmchk ?? 0) + 1; console.error('ASMCHK roll-WRONG ' + name + ' d=' + d + ' removes ' + this.st[eff]); } else if (s0 !== this.idx(name)) console.error('ASMCHK roll-negidx-benign ' + name); }`);
    s += `\nprocess.on('exit', () => console.error('ASMCHK total triggers: ' + (globalThis.__asmchk ?? 0) + ' [${f}]'));\n`;
  } else {
    s = s.replace(A, A + `\n    // arrange-check fix (same as Track 7): the kept prefix must have only items that are rolled anyway above it (else they would stay in between)\n    while (k > 0 && !win.slice(k).every((x) => names.slice(k).includes(x))) k--;`);
    if (R.test(s) && !/splice\(this\.idx\(name\), 1\)/.test(s.match(/roll\(name\) \{[^\n]*/)[0]))
      s = s.replace(/(roll\(name\) \{ const d = this\.depth\(name\))(;[^\n]*?)this\.st\.splice\(this\.st\.length - 1 - d, 1\);([^\n]*)/, (m, a, b, c) => `${a}, i = this.idx(name)${b}this.st.splice(i, 1);${c} // arrange-check: symbolic index (piles may sit above the item), as in the Track 6 fix`);
  }
  writeFileSync(f, s);
}
