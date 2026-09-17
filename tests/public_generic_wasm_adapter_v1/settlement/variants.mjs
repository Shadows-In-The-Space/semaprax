import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { pathToFileURL, fileURLToPath } from 'node:url';
import { resolve } from 'node:path';
import { canonical, fieldsInput, payloads, requireError } from './runner.mjs';
import { memoryGrowth } from './hostility.mjs';

export async function variant(dir,name) {
  const {Provider} = await import(pathToFileURL(resolve(dir,'dist/wasm-provider.js')).href);
  const bytes=new Uint8Array(readFileSync(resolve(dir,'reference.wasm')));
  const expected={ 'malformed-module':'module-compile','unexpected-import':'module-imports',
    'extra-export':'module-exports','missing-endpoint':'module-exports','wrong-export-kind':'module-exports',
    'shared-memory':'module-memory','zero-memory':'module-memory','oversized-memory':'module-memory','start-trap':'module-instance' };
  if(name in expected){
    assert.equal(WebAssembly.validate(bytes),name!=='malformed-module','malformation must be deliberate');
    await assert.rejects(Provider.open(bytes),error=>{
      requireError(error,{kind:'provider-mismatch',reason:expected[name]});return true;
    });
    return {case_id:name,primary:{kind:'provider-mismatch',reason:expected[name]},provider_created:false};
  }
  if(name==='grow-limit')return memoryGrowth({Provider,bytes});
  const p=await Provider.open(bytes);const input=fieldsInput(2,payloads(2,0));
  if(name==='endpoint-trap'){
    assert.throws(()=>p.transform(input),error=>{requireError(error,{kind:'execution-failed',status:11});return true;});
    assert.equal(p.settlement().endpoint_calls,1);assert.deepEqual(p.settlement().release_order,['input']);
  } else {
    assert.ok(['endpoint-grow','module-exact-max'].includes(name),'unknown fixture');
    assert.deepEqual(p.transform(input),fieldsInput(2,payloads(2,0).map(x=>x.reverse())));
    assert.equal(p.settlement().endpoint_calls,2);
    if(name==='module-exact-max')assert.equal(bytes.length,16777216);
  }
  assert.equal(Provider.diagnostics.liveAllocations(p),0);assert.equal(Provider.diagnostics.liveHandles(p),0);
  assert.equal(Provider.diagnostics.releasedMemoryIsZero(p),true);p.close();
  return {case_id:name,report:p.settlement(),released_memory_zero:true};
}
if(process.argv[1] && resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  const [dir,name]=process.argv.slice(2);console.log(JSON.stringify(canonical(await variant(dir,name))));
}
