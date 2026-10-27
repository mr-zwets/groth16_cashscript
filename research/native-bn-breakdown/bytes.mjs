const D=new URL('../../chunked/bn254/bn-native-sound/', import.meta.url).href;
const {buildProgram}=await import(D+'script.mjs');
const prog=buildProgram();
console.log('code',prog.code.length,'prologue',prog.info.prologue,'roles',prog.info.roles,'roleId',prog.info.roleId);
const f=prog.info.funcs; let s=0; for(const[k,v]of Object.entries(f)){s+=v.bytes;} console.log('shared func bodies',s, JSON.stringify(f));
for(let i=0;i<3;i++){const L=prog.info.roles[i];const m=prog.marks.filter(x=>x.role===i).sort((a,b)=>a.roff-b.roff);
 const out=[];for(let j=0;j<m.length;j++){const e=j+1<m.length?m[j+1].roff:L;out.push(`${m[j].name}=${e-m[j].roff}`);} console.log('role',i,L,out.join(' '));}
console.log('R',prog.R.length,'lay',JSON.stringify(prog.lay.off));
