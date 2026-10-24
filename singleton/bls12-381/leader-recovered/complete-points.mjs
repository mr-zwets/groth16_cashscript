import {Stack} from './subgroup.mjs';
import {fieldPrime as p} from './field.mjs';

// The decoder consumes [ySign, normSign, xImaginary, xReal], and returns
// [yReal, yImaginary]. Both square-root charts retain the existing sign ABI.
export function completeG2Decoder() {
  const s=new Stack(['ySign','normSign','xi','xr'],2);
  const scalar=(kind,a,b)=>{
    s.copy([a,b]);
    s.emit(kind==='mul'?'CALL mulFp':kind==='add'
      ?'OP_ADD CALL fieldPrime OP_MOD':'OP_SUB CALL fieldPrime OP_ADD CALL fieldPrime OP_MOD');
    return s.result(1,2)[0];
  };
  const constant=n=>{
    // The stack emitter's field constant owns both limbs; use its real limb.
    return s.constant(n)[0];
  };
  const invoke=(name,a)=>{s.copy([a]);s.emit(name==='inverse'
    ?'CALL fieldPrime OP_2 OP_SUB OP_SWAP CALL powFp':`CALL ${name}`);return s.result(1,1)[0];};
  const sign=(value,flag)=>{
    s.copy([value,flag,value]);
    s.emit('OP_2 OP_MUL CALL fieldPrime OP_SWAP OP_SUB OP_MUL OP_ADD CALL fieldPrime OP_ADD CALL fieldPrime OP_MOD');
    return s.result(1,3)[0];
  };
  const rhs=s.mul(s.sqr(['xr','xi']),['xr','xi']);
  s.emit('OP_4 OP_4');const curveB=s.result(2,0);
  const [a,b]=s.add(rhs,curveB);
  const norm=sign(invoke('sqrtFp',scalar('add',scalar('mul',a,a),scalar('mul',b,b))),'normSign');
  const u=sign(invoke('sqrtFp',scalar('mul',scalar('add',norm,a),constant((p+1n)/2n))),'ySign');
  s.copy([u]);s.emit('OP_0 OP_NUMEQUAL OP_IF');s.result(0,1);
  const before=s.stack.slice(),code=s.code.slice(),serial=s.serial;
  const finish=(real,imaginary)=>{
    s.equal([scalar('sub',scalar('mul',real,real),scalar('mul',imaginary,imaginary))],[a]);
    s.emit('OP_VERIFY');s.result(0,1);
    s.equal([scalar('mul',constant(2),scalar('mul',real,imaginary))],[b]);
    s.emit('OP_VERIFY');s.result(0,1);s.finish([real,imaginary]);
  };
  s.copy([b]);s.emit('OP_0 OP_NUMEQUALVERIFY');s.result(0,1);
  const zero=constant(0),v=sign(invoke('sqrtFp',scalar('sub',zero,a)),'ySign');
  finish(zero,v);
  const zeroCode=s.code.slice(code.length);
  s.stack=before;s.code=code;s.serial=serial;
  s.emit(zeroCode.join('\n'));s.emit('OP_ELSE');
  const imaginary=scalar('mul',b,invoke('inverse',scalar('mul',constant(2),u)));
  finish(u,imaginary);s.emit('OP_ENDIF');
  return s.code.join('\n');
}
