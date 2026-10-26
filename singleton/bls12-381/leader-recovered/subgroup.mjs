import assert from 'node:assert/strict';
import {bigIntToVmNumber} from '@bitauth/libauth';
import {scalarPrime, BLS_X} from './field.mjs';

const integer = value => {
  const n = BigInt(value);
  if (n >= 0n && n <= 16n) return `OP_${n}`;
  if (n === -1n) return 'OP_1NEGATE';
  const bytes = Buffer.from(bigIntToVmNumber(n));
  assert(bytes.length <= 255);
  return `${bytes.length < 76 ? 'OP_PUSHBYTES_'+bytes.length : 'OP_PUSHDATA_1 '+bytes.length} 0x${bytes.toString('hex')}`;
};
const drop = count => `${'OP_2DROP '.repeat(Math.floor(count / 2))}${count % 2 ? 'OP_DROP' : ''}`;

// A small stack emitter for the ordinary Jacobian formulas. Every temporary has
// one named stack owner; functions consume exactly their declared arguments.
export class Stack {
  constructor(names, dimension) {
    this.stack = [...names]; this.dimension = dimension; this.code = []; this.serial = 0;
  }
  fork() {
    const branch = new Stack(this.stack, this.dimension);
    branch.serial = this.serial;
    return branch;
  }
  emit(text) { this.code.push(text); }
  copy(names) {
    for (const name of names) {
      const index = this.stack.lastIndexOf(name);
      assert(index !== -1, `unknown stack value ${name}`);
      this.emit(`${integer(this.stack.length - 1 - index)} OP_PICK`);
      this.stack.push(name);
    }
  }
  result(count, consumed) {
    this.stack.splice(this.stack.length - consumed, consumed);
    const names = Array.from({length: count}, () => `t${this.serial++}`);
    this.stack.push(...names); return names;
  }
  constant(value) {
    for (let i = 0; i < this.dimension; i++) this.emit(integer(i ? 0 : value));
    return this.result(this.dimension, 0);
  }
  op(kind, a, b) {
    const d = this.dimension;
    assert(a.length === d && b.length === d);
    if (kind === 'mul' || (d === 2 && kind === 'add')) {
      this.copy(a); this.copy(b);
      this.emit(kind === 'mul'
        ? (d === 1 ? 'CALL mulFp' : 'OP_SWAP OP_2SWAP OP_SWAP CALL fp2Mul')
        : 'CALL fp2Add OP_SWAP');
      return this.result(d, 2 * d);
    }
    const out = [];
    for (let i = 0; i < d; i++) {
      this.copy([a[i], b[i]]);
      this.emit(kind === 'add' ? 'OP_ADD CALL fieldPrime OP_MOD'
        : 'OP_SUB CALL fieldPrime OP_ADD CALL fieldPrime OP_MOD');
      out.push(...this.result(1, 2));
    }
    return out;
  }
  add(a, b) { return this.op('add', a, b); }
  sub(a, b) { return this.op('sub', a, b); }
  mul(a, b) { return this.op('mul', a, b); }
  sqr(a) { return this.mul(a, a); }
  scale(a, n) { return this.mul(a, this.constant(n)); }
  equal(a, b) {
    for (let i = 0; i < a.length; i++) {
      this.copy([a[i], b[i]]); this.emit('OP_NUMEQUAL'); this.result(1, 2);
      if (i) { this.emit('OP_BOOLAND'); this.result(1, 2); }
    }
  }
  zero(a) { this.equal(a, this.constant(0)); }
  call(name, args, outputs) {
    this.copy(args); this.emit(`CALL ${name}`); return this.result(outputs, args.length);
  }
  finish(outputs) {
    this.copy(outputs);
    this.emit('OP_TOALTSTACK '.repeat(outputs.length));
    this.stack.splice(this.stack.length - outputs.length, outputs.length);
    this.emit(drop(this.stack.length));
    this.emit('OP_FROMALTSTACK '.repeat(outputs.length));
    return this.code.join('\n');
  }
}

const coordinates = d => ['X', 'Y', 'Z', 'Qx', 'Qy'].map(name =>
  Array.from({length: d}, (_, i) => `${name}${i}`));

function doubling(d) {
  const [x, y, z] = coordinates(d), s = new Stack([...x, ...y, ...z], d);
  const a = s.sqr(x), b = s.sqr(y), c = s.sqr(b);
  const delta = s.scale(s.sub(s.sub(s.sqr(s.add(x, b)), a), c), 2);
  const e = s.scale(a, 3), f = s.sqr(e);
  const nx = s.sub(f, s.scale(delta, 2));
  const ny = s.sub(s.mul(e, s.sub(delta, nx)), s.scale(c, 8));
  const nz = s.scale(s.mul(y, z), 2);
  return s.finish([...nx, ...ny, ...nz]);
}

function addition(d, doubleName) {
  const [x, y, z, qx, qy] = coordinates(d);
  const head = new Stack([...x, ...y, ...z, ...qx, ...qy], d);
  head.zero(z); head.stack.pop(); head.emit('OP_IF');
  const infinity = head.fork(), one = infinity.constant(1);
  const first = infinity.finish([...qx, ...qy, ...one]);
  const finite = head.fork(), z2 = finite.sqr(z);
  const u2 = finite.mul(qx, z2), s2 = finite.mul(finite.mul(qy, z), z2);
  finite.equal(x, u2); finite.equal(y, s2);
  finite.emit('OP_BOOLAND'); finite.result(1, 2); finite.stack.pop(); finite.emit('OP_IF');
  const same = finite.fork();
  const doubled = same.call(doubleName, [...x, ...y, ...z], 3 * d);
  const equal = same.finish(doubled);
  const other = finite.fork();
  const h = other.sub(u2, x), i = other.sqr(other.scale(h, 2)), j = other.mul(h, i);
  const rr = other.scale(other.sub(s2, y), 2), v = other.mul(x, i);
  const nx = other.sub(other.sub(other.sqr(rr), j), other.scale(v, 2));
  const ny = other.sub(other.mul(rr, other.sub(v, nx)), other.scale(other.mul(y, j), 2));
  const nz = other.scale(other.mul(z, h), 2);
  return `${head.code.join('\n')}\n${first}\nOP_ELSE\n${finite.code.join('\n')}
    ${equal}\nOP_ELSE\n${other.finish([...nx, ...ny, ...nz])}\nOP_ENDIF\nOP_ENDIF`;
}

function membership(d, doubleName, addName) {
  const [x, y, z] = coordinates(d);
  const s = new Stack([...x, ...y], d);
  s.copy([...x, ...y]); s.constant(1);
  // r has 255 bits. Seed R=P at its leading 1; process the remaining 254 bits.
  assert.equal(scalarPrime.toString(2).length, 255);
  s.emit(`${integer(253)} OP_BEGIN OP_TOALTSTACK CALL ${doubleName}
    OP_FROMALTSTACK ${integer(scalarPrime)} OP_OVER OP_RSHIFTNUM OP_2 OP_MOD
    OP_1 OP_NUMEQUAL OP_IF OP_TOALTSTACK`);
  const loop = new Stack([...x, ...y, ...x.map(n => 'R' + n),
    ...y.map(n => 'R' + n), ...z.map(n => 'R' + n)], d);
  loop.copy([...x, ...y]);
  s.emit(`${loop.code.join('\n')} CALL ${addName} OP_FROMALTSTACK OP_ENDIF
    OP_1SUB OP_DUP OP_0 OP_LESSTHAN OP_UNTIL OP_DROP
    ${'OP_0 OP_NUMEQUALVERIFY '.repeat(d)} ${drop(2 * d)}`);
  // Return the original affine point unchanged after proving [r]P=O.
  return s.code.join('\n');
}

const inverseMod = (a, p) => {
  let [r,s,x,y]=[p,a,0n,1n];
  while(s!==0n){const q=r/s;[r,s]=[s,r-q*s];[x,y]=[y,x-q*y];}
  assert.equal(r,1n);return (x%p+p)%p;
};
const h1=(BLS_X-1n)**2n/3n;
const h2=(BLS_X**8n-4n*BLS_X**7n+5n*BLS_X**6n-4n*BLS_X**4n+6n*BLS_X**3n-4n*BLS_X**2n-4n*BLS_X+13n)/9n;
export const projectionScalars=[h1,h2].map(h=>h*inverseMod(h,scalarPrime));

function fp2Inverse() {
  const s=new Stack(['a','b'],1);
  const norm=s.add(s.sqr(['a']),s.sqr(['b']));
  s.copy(norm);s.emit('CALL fieldPrime OP_2 OP_SUB OP_SWAP CALL powFp');
  const inv=s.result(1,1),a=s.mul(['a'],inv),b=s.sub(s.constant(0),s.mul(['b'],inv));
  return s.finish([...a,...b]);
}

function affine(d) {
  const [x,y,z]=coordinates(d),s=new Stack([...x,...y,...z],d);
  s.zero(z);s.stack.pop();s.emit('OP_IF');
  const identity=s.fork(),zeros=[...identity.constant(0),...identity.constant(0)];
  const infinity=identity.finish(zeros),finite=s.fork();let inverse;
  if(d===1){finite.copy(z);finite.emit('CALL fieldPrime OP_2 OP_SUB OP_SWAP CALL powFp');inverse=finite.result(1,1);}
  else inverse=finite.call('projectFp2Inverse',z,2);
  const z2=finite.sqr(inverse),z3=finite.mul(z2,inverse);
  return `${s.code.join('\n')} ${infinity} OP_ELSE ${finite.finish([...finite.mul(x,z2),...finite.mul(y,z3)])} OP_ENDIF`;
}

function projection(d,scalar,doubleName,addName,affineName) {
  const [x,y,z]=coordinates(d),s=new Stack([...x,...y],d);
  s.copy([...x,...y]);s.constant(1);
  s.emit(`${integer(scalar.toString(2).length-2)} OP_BEGIN OP_TOALTSTACK CALL ${doubleName}
    OP_FROMALTSTACK ${integer(scalar)} OP_OVER OP_RSHIFTNUM OP_2 OP_MOD
    OP_1 OP_NUMEQUAL OP_IF OP_TOALTSTACK`);
  const loop=new Stack([...x,...y,...x.map(n=>'R'+n),...y.map(n=>'R'+n),...z.map(n=>'R'+n)],d);
  loop.copy([...x,...y]);
  s.emit(`${loop.code.join('\n')} CALL ${addName} OP_FROMALTSTACK OP_ENDIF
    OP_1SUB OP_DUP OP_0 OP_LESSTHAN OP_UNTIL OP_DROP CALL ${affineName}`);
  const end=new Stack([...x,...y,...x.map(n=>'R'+n),...y.map(n=>'R'+n)],d);
  const finish=end.finish([...x.map(n=>'R'+n),...y.map(n=>'R'+n)]);
  const body=s.code.join('\n')+' '+finish;
  // The MSM's internal affine O is (0,0); it already belongs to the r component.
  return d===1?`OP_2DUP OP_0 OP_NUMEQUAL OP_SWAP OP_0 OP_NUMEQUAL OP_BOOLAND OP_NOT OP_IF ${body} OP_ENDIF`:body;
}

export function projectionDeclarations(identifiers) {
  const result=[];
  const add=(name,id,body)=>{assert(!identifiers.has(name));assert(![...identifiers.values()].includes(id));identifiers.set(name,id);result.push({name,body});};
  add('projectFp2Inverse',130,fp2Inverse());
  for(const [d,first]of [[1,121],[2,125]]){
    const name='projectG'+d,doubleName=name+'Double',addName=name+'Add',affineName=name+'Affine';
    add(doubleName,first,doubling(d));add(addName,first+1,addition(d,doubleName));
    add(affineName,first+2,affine(d));
    add(name,first+3,projection(d,projectionScalars[d-1],doubleName,addName,affineName));
  }
  return result;
}
