import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync,writeFileSync,mkdirSync} from 'node:fs';
import {createRequire} from 'node:module';
import {resolve,join} from 'node:path';
import {pathToFileURL} from 'node:url';
const [benchmark,output]=process.argv.slice(2);
assert(benchmark&&output&&process.argv.length===4,'usage: node build.mjs benchmark-repo new-output-dir');
const entry=createRequire(resolve(benchmark,'package.json')).resolve('@bitauth/libauth');
const lib=await import(pathToFileURL(entry).href);
const {OpcodesBCH:O,encodeDataPush,bigIntToVmNumber}=lib;
const read=name=>readFileSync(new URL(name,import.meta.url));
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const asm=read('./repaired-body.asm').toString('utf8');
const body=Buffer.concat(asm.trim().split(/\s+/).map(token=>{
  if(token.startsWith('OP_')){assert(Number.isInteger(O[token]),token);return Buffer.from([O[token]])}
  assert(/^(?:[0-9a-f]{2})+$/.test(token),token);
  return Buffer.from(encodeDataPush(Buffer.from(token,'hex')));
}));
assert.equal(body.length,8539);
assert.equal(sha(body),'5276a859c7c087b7cba6b2e9d17944bae14157d30c74fabb74c3958b4d7f7296');
const p=21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const r=21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const push=n=>Buffer.from(encodeDataPush(bigIntToVmNumber(BigInt(n))));
const parts=[Buffer.from([O.OP_DEPTH]),push(10),Buffer.from([O.OP_NUMEQUALVERIFY])];
const owners=[];
for(let depth=0;depth<10;depth++){
  const bound=depth<8?p:r;
  // PICK copies the actual top-relative ABI word. WITHIN consumes only the copy.
  const gate=Buffer.concat([push(depth),Buffer.from([O.OP_PICK,O.OP_0]),push(bound),Buffer.from([O.OP_WITHIN,O.OP_VERIFY])]);
  owners.push({depth,argument:['Ax','Ay','Bxa','Bxb','Bya','Byb','Cx','Cy','in0','in1'][depth],lower:'0',upper:String(bound),gateHex:gate.toString('hex')});
  parts.push(gate);
}
const prefix=Buffer.concat(parts),guarded=Buffer.concat([prefix,body]);
const result={schema:'bn254-archived-singleton-canonical-guard-transfer/v1',bodyBytes:body.length,bodySha256:sha(body),assemblySha256:sha(read('./repaired-body.asm')),prefixBytes:prefix.length,prefixSha256:sha(prefix),guardedBytes:guarded.length,guardedSha256:sha(guarded),arity:10,owners,lemma:'DEPTH requires exactly ten words. Each gate copies depth d, enforces 0 <= word < its field/scalar modulus using WITHIN and VERIFY, and restores the entire original ten-word stack. No function/altstack/control state is installed. The unchanged 8539-byte compiled body therefore receives exactly its proved canonical ten-argument ABI.',pointDomain:'Finite canonical external A/C on G1 and finite strict-G2 B; reconstructed vk_x may be neutral. Existing body owns curve/subgroup/equation checks.',scriptSource:'Existing compiled body only, followed unchanged after a new canonical-input predicate prefix; no compiler invocation or optimization.',vmPackage:'@bitauth/libauth@3.1.0-next.8',vmPackageEntrySha256:sha(readFileSync(entry))};
mkdirSync(output,{recursive:false});
for(const [name,bytes] of [['repaired-body.hex',body],['guard-prefix.hex',prefix],['compiled-locking.hex',guarded]])writeFileSync(join(output,name),bytes.toString('hex')+'\n',{flag:'wx'});
writeFileSync(join(output,'guard-transfer.json'),JSON.stringify(result,null,2)+'\n',{flag:'wx'});
console.log(JSON.stringify({guardedBytes:guarded.length,guardedSha256:sha(guarded)}));
