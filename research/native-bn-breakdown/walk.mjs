const D=new URL('../../chunked/bn254/bn-native-sound/', import.meta.url).href;
const {decodeAuthenticationInstructions:dec, encodeAuthenticationInstruction:enc}=await import('@bitauth/libauth');
const {buildProgram}=await import(D+'script.mjs');
const prog=buildProgram();
const per={};
const walk=(bytes,top,name)=>{const ins=dec(bytes); let fi=0;
 ins.forEach((x,i)=>{const n=enc(x).length,d=x.data;
  if(top&&d&&d.length>40&&ins[i+2]?.opcode===0x89){per.defOverhead=(per.defOverhead??0)+n-d.length+enc(ins[i+1]).length+1; const id=Number(ins[i+1].opcode>=0x51&&ins[i+1].opcode<=0x60?ins[i+1].opcode-0x50:ins[i+1].data?.[0]); walk(d,false,'f'+id); return;}
  if(top&&i>0&&ins[i-1].data&&ins[i-1].data.length>40) return; // id push counted
  if(top&&x.opcode===0x89) return;
  const o=per[name]??={const:0,data:0,code:0};
  if(d&&d.length>=31&&d.length<=33)o.const+=n; else if(d&&d.length>4)o.data+=n; else o.code+=n;});};
walk(prog.code,true,'top');
const ids=Object.fromEntries(Object.entries(prog.info.funcs).map(([k,v])=>['f'+v.id,k])); ids['f22']='role0';ids['f23']='role1';ids['f24']='role2';
let T={const:0,data:0,code:0}; for(const[k,v]of Object.entries(per)){if(typeof v==='number'){console.log(k,v);continue;} console.log((ids[k]??k).padEnd(8),JSON.stringify(v)); for(const q in T)T[q]+=v[q];}
console.log('total',JSON.stringify(T), T.const+T.data+T.code+per.defOverhead);
