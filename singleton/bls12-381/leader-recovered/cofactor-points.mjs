import {OpcodesBCH,encodeDataPush,bigIntToVmNumber} from '@bitauth/libauth';
import {checkedPoints} from './point-checks.mjs';
import {candidateIdentifiers} from './compact.mjs';
import {assemble} from './build.mjs';
import {Stack,projectionDeclarations} from './subgroup.mjs';

export function cofactorPoints() {
  const base=checkedPoints(),identifiers=new Map(candidateIdentifiers);
  const helpers=projectionDeclarations(identifiers);
  const frame=new Stack(['Py','Px','Qy1','Qy0','Qx1','Qx0'],1);
  const p=frame.call('projectG1',['Px','Py'],2),q=frame.call('projectG2',['Qx0','Qx1','Qy0','Qy1'],4);
  const project=frame.finish([p[1],p[0],q[3],q[2],q[1],q[0]]);
  const declarations=base.declarations.map(original=>original.name!=='millerLoop'?original:{...original,body:`${project}
    OP_4 OP_PICK OP_0 OP_NUMEQUAL OP_6 OP_PICK OP_0 OP_NUMEQUAL OP_BOOLAND
    OP_1 OP_PICK OP_0 OP_NUMEQUAL OP_3 OP_PICK OP_0 OP_NUMEQUAL OP_BOOLAND
    OP_4 OP_PICK OP_0 OP_NUMEQUAL OP_BOOLAND OP_5 OP_PICK OP_0 OP_NUMEQUAL OP_BOOLAND OP_BOOLOR
    OP_IF OP_2DROP OP_2DROP OP_2DROP CALL stackSequence51 OP_ELSE ${original.body} OP_ENDIF`
  }).concat(helpers).map(f=>({...f,bytecode:assemble(f.body,identifiers)}));
  const prefix=declarations.flatMap(f=>[...encodeDataPush(f.bytecode),...encodeDataPush(bigIntToVmNumber(BigInt(identifiers.get(f.name)))),OpcodesBCH.OP_DEFINE]);
  return {...base,identifiers,declarations,bytecode:Uint8Array.from([...prefix,...base.mainBytecode])};
}
