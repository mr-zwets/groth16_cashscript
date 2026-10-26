// Symbolic-stack hand assembler: tracks item names so PICK/ROLL depths are computed, picks the
// cheapest stack opcode (DUP/OVER/SWAP/ROT), and supports table lookups by a runtime index.
import {OP, pushNum} from './dsl.mjs';
export class Asm {
  constructor(names) { this.st = names.slice(); this.code = []; this.n = 0; }
  fresh(base = 't') { return `${base}#${this.n++}`; }
  depth(name) { const i = this.st.lastIndexOf(name); if (i < 0) throw new Error('no item ' + name + ' in ' + this.st.slice(-12).join(',')); return this.st.length - 1 - i; }
  emit(...b) { this.code.push(...b); }
  pick(name, as) { const d = this.depth(name); if (d === 0) this.emit(OP.DUP); else if (d === 1) this.emit(OP.OVER); else this.emit(...pushNum(d), OP.PICK); this.st.push(as ?? name); return this; }
  roll(name) { const d = this.depth(name); if (d === 1) this.emit(OP.SWAP); else if (d === 2) this.emit(OP.ROT); else if (d > 2) this.emit(...pushNum(d), OP.ROLL); this.st.splice(this.st.length - 1 - d, 1); this.st.push(name); return this; }
  push(v, name) { this.emit(...pushNum(v)); this.st.push(name ?? this.fresh('c')); return this; }
  pushBytes(bytes, name, enc) { this.emit(...enc(bytes)); this.st.push(name); return this; }
  // generic op: pops k items, pushes named results
  op(code, pops, ...outs) { this.emit(code); for (let i = 0; i < pops; i++) this.st.pop(); this.st.push(...outs); return this; }
  bin(code, out) { return this.op(code, 2, out ?? this.fresh()); }
  rename(name) { this.st[this.st.length - 1] = name; return this; }
  drop() { this.emit(OP.DROP); this.st.pop(); return this; }
  // top item is an index i (consumed); push table[i] where table entry n has name `${tbl}[n]`, entries
  // laid out with [n] at depth(depth of [0]) + n.
  lookup(tbl, out) {
    this.st.pop(); const d0 = this.depth(`${tbl}[0]`); // depth after removing the index
    if (this.depth(`${tbl}[1]`) !== d0 + 1) throw new Error('table layout ' + tbl);
    this.st.push('__idx'); this.emit(...pushNum(d0), OP.ADD, OP.PICK); this.st.pop(); this.st.push(out); return this;
  }
  // bring named items to the top in the given order (moving them)
  arrange(names) { for (const n of names) this.roll(n); return this; }
  bytes() { return Uint8Array.from(this.code); }
}
