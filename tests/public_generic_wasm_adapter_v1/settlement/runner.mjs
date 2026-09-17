// Harness-only Node imports. The generated runtime has no Node dependency.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { pathToFileURL, fileURLToPath } from 'node:url';
import { resolve } from 'node:path';

export function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value !== null && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort().map(k=>[k,canonical(value[k])]));
  return value;
}
export function digest(domain,bytes) {
  const length=Buffer.alloc(8);length.writeBigUInt64LE(BigInt(bytes.length));
  return 'sha256:'+createHash('sha256').update(domain+'\0','ascii').update(length).update(bytes).digest('hex');
}
export function payloads(fields,recipe) {
  return Array.from({length:fields},(_,leaf)=>{
    const size=recipe===1||(recipe===2&&leaf===0)?0:recipe===3?65536:recipe===4&&leaf===0?65537:5+leaf%3;
    return Uint8Array.from({length:size},(_,i)=>i%3===0?0:(leaf*31+i*17)&255);
  });
}
export function fieldsInput(fields,leaves) {
  return Object.fromEntries(Array.from({length:fields},(_,i)=>['field_'+Buffer.from('settlement.field'+i).toString('hex'),leaves[i]]));
}
export function independentCarrier(leaves) {
  const out=Buffer.alloc(8+8*leaves.length+leaves.reduce((n,v)=>n+v.length,0));
  out.writeBigUInt64LE(BigInt(leaves.length));let p=8;
  for(const leaf of leaves){out.writeBigUInt64LE(BigInt(leaf.length),p);p+=8;out.set(leaf,p);p+=leaf.length;}
  return out;
}
export function requireError(error,expected) {
  assert.equal(error?.name,'SemapraxPublicGenericException','must be a typed error, not a host exception');
  assert.deepEqual(error.detail,expected);
}
export async function loadPackage(dir) {
  const url=name=>pathToFileURL(resolve(dir,'dist',name+'.js')).href;
  const provider=await import(url('wasm-provider'));
  const codec=await import(url('carrier'));
  const descriptor=await import(url('descriptor'));
  const bytes=new Uint8Array(readFileSync(resolve(dir,'reference.wasm')));
  assert.ok(WebAssembly.validate(bytes),'real fixture binary must validate');
  return {...provider,codec,descriptor,bytes};
}

export async function matrix(pkg,cases) {
  const {Provider,codec,bytes}=pkg;
  const rows=[];
  for(const c of cases){
    const p=await Provider.open(bytes);
    const leaves=payloads(c.fields,c.recipe),input=fieldsInput(c.fields,leaves);
    assert.equal(digest('semaprax.public-generic-consumer-settlement-corpus.v1/input',independentCarrier(leaves)),c.input_carrier_digest,c.case_id+': shared input');
    if(c.legacy>=0) Provider.diagnostics.injectFailure(p,c.legacy);
    Provider.diagnostics.injectEvents(p,c.injections);
    Provider.diagnostics.mutateNextExport(p,c.export_mutation);
    let output=null,error=null;
    try {output=p.transform(input);} catch(e){error=e;}
    const report=p.settlement();
    assert.deepEqual(report,c.expected,c.case_id+': literal lifecycle/counters');
    let resultDigest=null;
    if(c.expected.accepted){
      assert.equal(error,null,c.case_id+': unexpectedly failed');
      const result=Object.values(output);
      const expected=leaves.map(v=>Uint8Array.from(v).reverse());
      assert.deepEqual(result,expected,c.case_id+': exact returned payload bytes');
      resultDigest=digest('semaprax.public-generic-consumer-settlement-corpus.v1/result',independentCarrier(result));
      assert.equal(resultDigest,c.result_carrier_digest,c.case_id+': shared result');
      assert.deepEqual(codec.decodeOutput(independentCarrier(result)),output);
      for(let i=0;i<result.length;i++){leaves[i].fill(0xff);assert.deepEqual(result[i],expected[i],'no input or memory aliases');}
    } else {
      assert.equal(output,null,c.case_id+': partial result must not escape');
      requireError(error,c.expected.primary);
      assert.deepEqual(error.secondaryCleanupStatuses,c.expected.secondary_cleanup_statuses,c.case_id+': exception secondary status');
    }
    assert.ok(Provider.diagnostics.releasedMemoryIsZero(p),c.case_id+': actual released Wasm bytes not zero');
    p.close();p.close();
    assert.equal(Provider.diagnostics.liveAllocations(p),0);assert.equal(Provider.diagnostics.liveHandles(p),0);
    rows.push({case_id:c.case_id,input_carrier_digest:c.input_carrier_digest,result_carrier_digest:resultDigest,
      report, released_memory_zero:true, close_status:0});
  }
  return rows;
}

if(process.argv[1] && resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  const [dir,manifestFile,countText]=process.argv.slice(2);
  const manifest=JSON.parse(readFileSync(manifestFile,'utf8'));
  const pkg=await loadPackage(dir);
  const rows=await matrix(pkg,manifest.cases.filter(c=>c.fields===Number(countText)));
  console.log(JSON.stringify(canonical(rows)));
}
