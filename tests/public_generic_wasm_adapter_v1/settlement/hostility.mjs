import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';
// Test-only host/runtime checks. No host machinery enters the generated client.
import assert from 'node:assert/strict';
import { canonical, fieldsInput, independentCarrier, loadPackage, payloads, requireError } from './runner.mjs';

export const HOST_CASES = Object.freeze([
  'module-object-refused', 'module-digest-refused', 'module-snapshot-before-await',
  'module-detach-after-open', 'module-subrange-views', 'module-shared-resizable-detached',
  'module-first-over-bound', 'private-descriptor-authority', 'private-binding-authority',
  'descriptor-refusal-precedence', 'input-getter-not-executed', 'input-closed-fields',
  'input-intrinsic-byte-brand', 'input-buffer-lifetime', 'input-local-failure-clears-injection',
  'codec-count-and-length-bounds', 'codec-last-leaf-preflight', 'codec-output-independence',
  'one-inflight-owner', 'reentrant-input-refused', 'handle-private-brand', 'handle-role-and-staleness',
  'provider-recreation', 'close-preserves-live-owner', 'export-retry-no-reexecution',
  'release-error-invalidates-owner', 'cleanup-primary-and-secondary', 'settlement-immutable',
  'generation-exact-and-first-over', 'trace-bound-cleanup', 'invalid-injection-refused',
  'repeated-provider-calls',
]);

export async function hostility(pkg, only = null, repeats = 64) {
  const { Provider, OpaqueHandle, codec, descriptor, bytes } = pkg;
  const D = Provider.diagnostics;
  const fresh = () => fieldsInput(2, payloads(2, 0));
  const keys = Object.keys(fresh());
  const rows = [];
  async function check(name, fn) {
    if (only && only !== name) return;
    try { const observations = await fn(); rows.push({ case_id: name, ...observations }); }
    catch (e) {
      if (e instanceof assert.AssertionError) throw new assert.AssertionError({
        message:name + ': ' + e.message,actual:e.actual,expected:e.expected,operator:e.operator});
      throw e;
    }
  }
  function expect(fn, detail) { assert.throws(fn, e => { requireError(e, detail); return true; }); }
  async function reject(value, detail, options) {
    await assert.rejects(Provider.open(value, options), e => { requireError(e, detail); return true; });
  }
  async function owned(fn) {
    const p = await Provider.open(bytes);
    const observation = await fn(p);
    assert.equal(D.liveAllocations(p), 0, 'allocation must settle');
    assert.equal(D.liveHandles(p), 0, 'handle must settle');
    assert.equal(D.liveBytes(p), 0, 'bytes must settle');
    assert.equal(D.releasedMemoryIsZero(p), true, 'released memory must actually be zero');
    p.close(); p.close();
    return { ...observation, live_allocations: D.liveAllocations(p), live_handles: D.liveHandles(p),
      live_bytes: D.liveBytes(p), released_memory_zero: D.releasedMemoryIsZero(p) };
  }
  const bad = reason => ({kind:'carrier-rejected',reason});
  const cap = reason => ({kind:'capacity-exceeded',reason});
  const moduleError = reason => ({kind:'provider-mismatch',reason});
  const fault = (event,leaf=null) => ({event,leaf});

  await check('module-object-refused', async () => {
    await reject(await WebAssembly.compile(bytes), moduleError('module-bytes-required'));
    // A different, valid module has the same entry/export surface. A custom
    // section changes its authenticated bytes, not its computation.
    const different = Uint8Array.from([...bytes,0,2,1,120]);
    assert.ok(WebAssembly.validate(different));
    await reject(await WebAssembly.compile(different),moduleError('module-bytes-required'));
    return { rejected_modules:2, provider_created:false };
  });
  await check('module-digest-refused', async () => {
    const different=Uint8Array.from([...bytes,0,2,1,120]);
    await reject(different,moduleError('module-digest'));
    await reject(new Uint8Array(0),moduleError('module-digest'));
    return { rejected_buffers:2, provider_created:false };
  });
  await check('module-snapshot-before-await', async () => {
    const source=bytes.slice(), pending=Provider.open(source); source.fill(0);
    let p; await assert.doesNotReject(async()=>{p=await pending;},'snapshot must execute authenticated bytes');
    assert.deepEqual(p.transform(fresh()),fieldsInput(2,payloads(2,0).map(x=>x.reverse())));
    assert.equal(D.releasedMemoryIsZero(p),true); p.close();
    return { endpoint_calls:D.snapshot(p).endpoint_calls, live_allocations:D.liveAllocations(p) };
  });
  await check('module-detach-after-open', async () => {
    const source=bytes.slice(),pending=Provider.open(source);
    structuredClone(source.buffer,{transfer:[source.buffer]});
    const p=await pending; p.transform(fresh()); p.close();
    assert.equal(D.liveAllocations(p),0);
    return { endpoint_calls:D.snapshot(p).endpoint_calls, live_allocations:0 };
  });
  await check('module-subrange-views', async () => {
    const source=new Uint8Array(bytes.length+19);source.set(bytes,9);
    for(const value of [source.subarray(9,9+bytes.length),new DataView(source.buffer,9,bytes.length),
      Buffer.from(source.buffer,9,bytes.length)]) {
      const p=await Provider.open(value);p.transform(fresh());p.close();assert.equal(D.liveAllocations(p),0);
    }
    return { exact_subranges:3, live_allocations:0 };
  });
  await check('module-shared-resizable-detached', async () => {
    const detached=bytes.slice();structuredClone(detached.buffer,{transfer:[detached.buffer]});
    const resizable=new ArrayBuffer(bytes.length,{maxByteLength:bytes.length+1});new Uint8Array(resizable).set(bytes);
    for(const value of [new SharedArrayBuffer(bytes.length),new Uint8Array(new SharedArrayBuffer(bytes.length)),
      resizable,new Uint8Array(resizable),detached,{},null]) await reject(value,moduleError('module-buffer'));
    return { rejected_buffers:7, provider_created:false };
  });
  await check('module-first-over-bound', async () => {
    await reject(new Uint8Array(16777217),moduleError('module-bound'));
    return { bound:16777216, rejected_bytes:16777217, provider_created:false };
  });
  await check('private-descriptor-authority', async () => {
    const original=descriptor.TRUSTED_DESCRIPTOR_BYTES.slice();
    const changed=original.slice();changed[changed.length-1]^=1;
    descriptor.TRUSTED_DESCRIPTOR_BYTES.set(changed);
    try {
      await reject(bytes,{kind:'descriptor-rejected',reason:'descriptor-replay'},{descriptorBytes:changed});
      const p=await Provider.open(bytes);p.transform(fresh());p.close();assert.equal(D.liveAllocations(p),0);
    } finally {descriptor.TRUSTED_DESCRIPTOR_BYTES.set(original);}
    return { mutated_public_copy_rejected:true, default_private_copy_accepted:true };
  });
  await check('private-binding-authority', async () => {
    const original=descriptor.TRUSTED_BINDING_BYTES.slice();const changed=original.slice();changed[changed.length-1]^=1;
    descriptor.TRUSTED_BINDING_BYTES.set(changed);
    try {await reject(bytes,moduleError('binding-replay'),{bindingBytes:changed});
      const p=await Provider.open(bytes);p.transform(fresh());p.close();assert.equal(D.liveAllocations(p),0);
    } finally {descriptor.TRUSTED_BINDING_BYTES.set(original);}
    return { mutated_public_copy_rejected:true, default_private_copy_accepted:true };
  });
  await check('descriptor-refusal-precedence', async () => {
    await reject({}, {kind:'descriptor-rejected',reason:'descriptor-bound'}, {descriptorBytes:new Uint8Array(131073)});
    await reject({}, {kind:'descriptor-rejected',reason:'descriptor-framing'}, {descriptorBytes:new Uint8Array(0)});
    await reject({},moduleError('binding-bound'),{bindingBytes:new Uint8Array(262145)});
    const [a,b]=descriptor.trustedDescriptorAndBinding();a.fill(0);b.fill(0);
    const p=await Provider.open(bytes);p.close();return { exact_precedence_checks:3, private_copy_isolation:true };
  });
  await check('input-getter-not-executed',()=>owned(p=>{
    let reads=0;const input=fresh();Object.defineProperty(input,keys[0],{get(){reads++;return new Uint8Array(5);}});
    expect(()=>p.transform(input),bad('input-field'));assert.equal(reads,0,'must not invoke the field getter');
    return { getter_calls:reads, endpoint_calls:D.snapshot(p).endpoint_calls };
  }));
  await check('input-closed-fields',()=>owned(p=>{
    const missing=fresh();delete missing[keys[0]];
    const extra={...fresh(),extra:new Uint8Array(0)};
    const symbol=fresh();symbol[Symbol('extra')]=0;
    for(const input of [missing,extra,symbol]) expect(()=>p.transform(input),bad('input-field'));
    for(const input of [null,[],new Date(),Object.create(fresh())]) expect(()=>p.transform(input),bad('input-shape'));
    let genuine;try{codec.encodeInput({});}catch(error){genuine=error;}
    const forged=new genuine.constructor({kind:'forged'});
    for(const thrown of [Error('arbitrary host failure'),forged]){
      const proxy=new Proxy(fresh(),{ownKeys(){throw thrown;}});
      expect(()=>p.transform(proxy),bad('input-shape'));
    }
    const reversed=Object.fromEntries(Object.entries(fresh()).reverse());
    assert.deepEqual(p.transform(reversed),fieldsInput(2,payloads(2,0).map(x=>x.reverse())));
    const nullProto=Object.assign(Object.create(null),fresh());p.transform(nullProto);
    return { rejected_shapes:9, canonical_key_order:true, null_prototype_accepted:true };
  }));
  await check('input-intrinsic-byte-brand',()=>owned(p=>{
    let reads=0;class HostileBytes extends Uint8Array {
      get length(){reads++;return Number.MAX_SAFE_INTEGER;} get buffer(){reads++;throw Error('getter');}
      get [Symbol.toStringTag](){reads++;return 'bogus';} [Symbol.iterator](){reads++;throw Error('iterator');}
      slice(){reads++;throw Error('slice');}
    }
    const input=fresh();input[keys[0]]=new HostileBytes([1,0,2]);
    assert.deepEqual(p.transform(input)[keys[0]],new Uint8Array([2,0,1]));assert.equal(reads,0);
    for(const value of [{length:3,[Symbol.toStringTag]:'Uint8Array'},new Uint16Array(2),new DataView(new ArrayBuffer(2)),
      new Proxy(new Uint8Array(2),{}),[]]) {const invalid=fresh();invalid[keys[0]]=value;expect(()=>p.transform(invalid),bad('input-bytes'));}
    return { attacker_methods_called:reads, rejected_forged_views:5 };
  }));
  await check('input-buffer-lifetime',()=>owned(p=>{
    const detached=new Uint8Array(3);structuredClone(detached.buffer,{transfer:[detached.buffer]});
    for(const value of [detached,new Uint8Array(new SharedArrayBuffer(3)),new Uint8Array(new ArrayBuffer(3,{maxByteLength:4}))]){
      const invalid=fresh();invalid[keys[0]]=value;expect(()=>p.transform(invalid),bad('input-bytes'));
    }
    const source=new Uint8Array([7,1,0,2,9]);const input=fresh();input[keys[0]]=source.subarray(1,4);
    const prepared=D.prepareInput(p,input);source.fill(0xff);const result=D.call(p,prepared);
    assert.deepEqual(D.exportResult(p,result)[keys[0]],new Uint8Array([2,0,1]));D.releaseResult(p,result);
    return { rejected_buffers:3, exact_input_snapshot:true };
  }));
  await check('input-local-failure-clears-injection',()=>owned(p=>{
    for(const mode of ['legacy','events']){
      if(mode==='legacy')D.injectFailure(p,3);else D.injectEvents(p,[fault('endpoint-started',0)]);
      expect(()=>p.transform({}),bad('input-field'));
      let actual;assert.doesNotThrow(()=>{actual=p.transform(fresh());},'unhit failure must not reach next call');
      assert.deepEqual(actual,fieldsInput(2,payloads(2,0).map(x=>x.reverse())));
    }
    return { unhit_failure_plans_cleared:2, endpoint_calls:D.snapshot(p).endpoint_calls };
  }));
  await check('codec-count-and-length-bounds',()=>{
    for(const n of [0,257])expect(()=>codec.encodeLeaves(Array.from({length:n},()=>new Uint8Array(0))),cap('leaf-count'));
    expect(()=>codec.encodeLeaves([new Uint8Array(65537)]),cap('leaf-bytes'));
    expect(()=>codec.locateLeaves(new Uint8Array(16779273),2),{kind:'result-rejected',reason:'carrier-bytes'});
    const valid=independentCarrier(payloads(2,0));
    for(const length of [0,7,8,15,valid.length-1]) expect(()=>codec.decodeLeaves(valid.subarray(0,length),2),{kind:'result-rejected',reason:'carrier-framing'});
    const count=Uint8Array.from(valid);new DataView(count.buffer).setBigUint64(0,3n,true);
    expect(()=>codec.decodeLeaves(count,2),{kind:'result-rejected',reason:'carrier-count'});
    const huge=Uint8Array.from(valid);new DataView(huge.buffer).setBigUint64(8,0xffffffffffffffffn,true);
    expect(()=>codec.decodeLeaves(huge,2),{kind:'result-rejected',reason:'leaf-bytes'});
    expect(()=>codec.decodeLeaves(Uint8Array.from([...valid,0]),2),{kind:'result-rejected',reason:'carrier-trailing'});
    return { exact_refusals:12 };
  });
  await check('codec-last-leaf-preflight',()=>{
    const valid=Uint8Array.from(independentCarrier(payloads(2,0)));
    const wire=new DataView(valid.buffer);wire.setBigUint64(8+8+5,65537n,true);
    let copies=0;const original=Uint8Array.prototype.slice;
    Uint8Array.prototype.slice=function(...args){copies++;return Reflect.apply(original,this,args);};
    try {expect(()=>codec.decodeLeaves(valid,2),{kind:'result-rejected',reason:'leaf-bytes'});}finally{Uint8Array.prototype.slice=original;}
    assert.equal(copies,0,'last-leaf validation must precede every payload allocation');
    return { copied_payload_leaves:copies };
  });
  await check('codec-output-independence',()=>{
    const valid=Uint8Array.from(independentCarrier(payloads(2,0)));const decoded=codec.decodeLeaves(valid,2);
    const expected=decoded.map(x=>x.slice());valid.fill(0);assert.deepEqual(decoded,expected);
    decoded[0].fill(255);assert.deepEqual(decoded[1],expected[1]);
    return { independent_payloads:2 };
  });
  await check('one-inflight-owner',()=>owned(p=>{
    const a=D.prepareInput(p,fresh());const snapshot=D.snapshot(p);
    expect(()=>D.prepareInput(p,fresh()),bad('provider-busy'));assert.deepEqual(D.snapshot(p),snapshot);
    expect(()=>p.transform(fresh()),bad('provider-busy'));assert.deepEqual(D.snapshot(p),snapshot);
    D.releaseInput(p,a);p.transform(fresh());
    return { rejected_competing_calls:2, later_independent_call:true };
  }));
  await check('reentrant-input-refused',()=>owned(p=>{
    let attempted=0;const original=fresh();const proxy=new Proxy(original,{ownKeys(target){attempted++;
      expect(()=>p.transform(fresh()),bad('provider-busy'));return Reflect.ownKeys(target);}});
    p.transform(proxy);assert.equal(attempted,1);return { reentrant_calls_refused:attempted, endpoint_calls:D.snapshot(p).endpoint_calls };
  }));
  await check('handle-private-brand',()=>owned(p=>{
    const a=D.prepareInput(p,fresh());
    for(const invalid of [null,{},Object.create(OpaqueHandle.prototype),new Proxy(a,{})])expect(()=>D.call(p,invalid),bad('handle-invalid'));
    expect(()=>D.call(p,D.foreignHandle(0,a.generation())),bad('handle-provider'));
    a.id=()=>99;a.generation=()=>99;a.belongsTo=()=>false;
    const result=D.call(p,a);assert.deepEqual(D.exportResult(p,result),fieldsInput(2,payloads(2,0).map(x=>x.reverse())));D.releaseResult(p,result);
    return { rejected_forged_handles:5, overridden_methods_ignored:true };
  }));
  await check('handle-role-and-staleness',()=>owned(p=>{
    const input=D.prepareInput(p,fresh());expect(()=>D.exportResult(p,input),bad('handle-kind'));
    const result=D.call(p,input);expect(()=>D.call(p,result),bad('handle-kind'));
    expect(()=>D.releaseInput(p,input),bad('handle-kind'));D.releaseResult(p,result);
    expect(()=>D.releaseResult(p,result),bad('handle-invalid'));
    const second=D.prepareInput(p,fresh());expect(()=>D.call(p,input),bad('handle-invalid'));D.releaseInput(p,second);
    return { lifecycle_refusals:5 };
  }));
  await check('provider-recreation',async()=>{
    const a=await Provider.open(bytes);const input=D.prepareInput(a,fresh());D.releaseInput(a,input);a.close();
    const b=await Provider.open(bytes);expect(()=>D.call(b,input),bad('handle-provider'));
    b.transform(fresh());b.close();return { stale_generation_refused:true, first_live:D.liveAllocations(a),second_live:D.liveAllocations(b) };
  });
  await check('close-preserves-live-owner',()=>owned(p=>{
    const input=D.prepareInput(p,fresh());expect(()=>p.close(),{kind:'release-failed',status:7});
    const result=D.call(p,input);expect(()=>p.close(),{kind:'release-failed',status:7});
    D.exportResult(p,result);D.releaseResult(p,result);return { refused_close_retries:2 };
  }));
  await check('export-retry-no-reexecution',()=>owned(p=>{
    const result=D.call(p,D.prepareInput(p,fresh()));const calls=D.snapshot(p).endpoint_calls;
    D.injectEvents(p,[fault('export-pending')]);expect(()=>D.exportResult(p,result),{kind:'execution-failed',status:11});
    assert.equal(D.liveHandles(p),1);const a=D.exportResult(p,result);const b=D.exportResult(p,result);
    assert.deepEqual(a,b);assert.notEqual(a[keys[0]].buffer,b[keys[0]].buffer);
    assert.equal(D.snapshot(p).endpoint_calls,calls,'export retry must not execute endpoint');D.releaseResult(p,result);
    return { endpoint_calls:calls, successful_exports:2, failed_exports:1 };
  }));
  await check('release-error-invalidates-owner',()=>owned(p=>{
    const input=D.prepareInput(p,fresh());D.injectEvents(p,[fault('input-release')]);
    expect(()=>D.releaseInput(p,input),{kind:'release-failed',status:11});expect(()=>D.releaseInput(p,input),bad('handle-invalid'));
    const result=D.call(p,D.prepareInput(p,fresh()));D.injectEvents(p,[fault('result-release')]);
    expect(()=>D.releaseResult(p,result),{kind:'release-failed',status:11});expect(()=>D.exportResult(p,result),bad('handle-invalid'));
    return { explicit_release_failures:2 };
  }));
  await check('cleanup-primary-and-secondary',()=>owned(p=>{
    D.injectEvents(p,[fault('result-release')]);expect(()=>p.transform(fresh()),{kind:'release-failed',status:11});
    assert.equal(p.settlement().accepted,false);assert.deepEqual(p.settlement().secondary_cleanup_statuses,[]);
    D.injectEvents(p,[fault('export-pending'),fault('result-release')]);
    let caught;try{p.transform(fresh());}catch(e){caught=e;}
    requireError(caught,{kind:'execution-failed',status:11});assert.deepEqual(caught.secondaryCleanupStatuses,[11]);
    assert.deepEqual(p.settlement().secondary_cleanup_statuses,[11]);return { primary_kind:caught.detail.kind, secondary:[11] };
  }));
  await check('settlement-immutable',()=>owned(p=>{
    p.transform(fresh());const report=p.settlement();
    assert.throws(()=>{report.accepted=false;},TypeError);assert.throws(()=>report.release_order.push('bad'),TypeError);
    assert.throws(()=>{report.trace[0].event='bad';},TypeError);const snap=D.snapshot(p);assert.throws(()=>snap.trace.push({}),TypeError);
    p.transform(fresh());assert.notEqual(p.settlement(),report);assert.equal(report.endpoint_calls,2);
    return { frozen_reports:true, prior_report_stable:true };
  }));
  await check('generation-exact-and-first-over',()=>owned(p=>{
    D.setNextGeneration(p,0xffffffff);p.transform(fresh());
    expect(()=>p.transform(fresh()),cap('generation'));assert.equal(D.snapshot(p).endpoint_calls,0);
    expect(()=>D.setNextGeneration(p,1),bad('failure-injection'));
    return { last_generation:0xffffffff, refused_reuse:true };
  }));
  await check('trace-bound-cleanup',()=>owned(p=>{
    const result=D.call(p,D.prepareInput(p,fresh()));let exported=0;
    for(;;){try{D.exportResult(p,result);exported++;}catch(e){requireError(e,cap('trace-events'));break;}}
    assert.equal(D.snapshot(p).trace.length,4094);assert.equal(D.liveHandles(p),1);
    D.releaseResult(p,result);assert.equal(D.snapshot(p).trace.length,4095);assert.equal(D.snapshot(p).endpoint_calls,2);
    return { successful_exports:exported, final_trace_events:D.snapshot(p).trace.length, endpoint_calls:2 };
  }));
  await check('invalid-injection-refused',()=>owned(p=>{
    const points=[null,{},[{event:'unknown',leaf:null}],[fault('endpoint-started',2)],
      [fault('input-release',0)],[fault('input-release'),fault('input-release')],
      [fault('input-release'),fault('result-release'),fault('export-pending')],[{event:'input-release',leaf:null,extra:0}]];
    for(const value of points)expect(()=>D.injectEvents(p,value),bad('failure-injection'));
    for(const n of [-1,8,1.5,NaN])expect(()=>D.injectFailure(p,n),bad('failure-injection'));
    p.transform(fresh());return { rejected_injection_specs:12 };
  }));
  await check('repeated-provider-calls',()=>owned(p=>{
    assert.ok(Number.isInteger(repeats)&&repeats>=1&&repeats<=8192);
    for(let i=0;i<repeats;i++){
      const original=fresh();const expected=fieldsInput(2,Object.values(original).map(x=>x.slice().reverse()));
      assert.deepEqual(p.transform(original),expected);assert.equal(D.liveAllocations(p),0);assert.equal(D.liveHandles(p),0);
      assert.equal(D.releasedMemoryIsZero(p),true);assert.equal(p.settlement().endpoint_calls,2);
    }
    return { repetitions:repeats, calls_per_iteration:2 };
  }));
  assert.equal(rows.length,only?1:HOST_CASES.length,'closed host case inventory');
  assert.deepEqual(rows.map(x=>x.case_id),only?[only]:HOST_CASES);
  return rows;
}

// A one-page authenticated fixture proves actual WebAssembly.Memory.grow
// refusal is mapped before any allocation obligation is committed.
export async function memoryGrowth(pkg) {
  const {Provider,bytes}=pkg;const p=await Provider.open(bytes);
  assert.throws(()=>p.transform(fieldsInput(2,payloads(2,3))),e=>{
    requireError(e,{kind:'capacity-exceeded',reason:'memory-growth'});return true;
  });
  const report=p.settlement();assert.equal(report.endpoint_calls,0);assert.equal(report.peak_allocations,0);
  assert.equal(report.live_allocations,0);assert.equal(report.live_handles,0);assert.equal(report.retained_pages,1);
  p.transform(fieldsInput(2,payloads(2,0)));assert.equal(Provider.diagnostics.releasedMemoryIsZero(p),true);p.close();
  return {case_id:'actual-memory-growth-refusal',refusal_report:report,subsequent_call_succeeded:true};
}

if(process.argv[1] && resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  const [dir,mode='host',only,repeats='64']=process.argv.slice(2);const pkg=await loadPackage(dir);
  const result=mode==='grow'?await memoryGrowth(pkg):await hostility(pkg,only||null,Number(repeats));
  console.log(JSON.stringify(canonical(result)));
}
