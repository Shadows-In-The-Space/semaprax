#!/usr/bin/env python3
"""Bounded host-caller cases over the EXISTING C/C++ semantic recipes.

The oracle is a literal host event contract, not an interpreter of provider code.
Expected result bytes come from the existing independent recipe helper.
Host events/resources are not silently normalized into native logical evidence.
"""
from __future__ import annotations
from public_generic_consumer_cases import carrier, manifest as shared_manifest, SCHEMA as SHARED_SCHEMA
from public_generic_settlement_evidence import canonical, digest, require

SCHEMA = 'semaprax.public-generic-typescript-settlement-corpus.v1'
ROUTE = 'typescript-host-owned-wasm-reference'
ALLOCATIONS = ['input-allocation-started', 'input-allocation-committed',
               'result-allocation-started', 'result-allocation-committed']
LEAF_EVENTS = ['endpoint-started','endpoint-finished','result-leaf-copy-started','result-leaf-copied']
EVENTS = ['input-validated', 'input-allocation-started', 'input-allocation-committed',
    'input-payload-copied', 'input-prepared', 'input-transfer-pending', 'input-transfer-committed',
    'endpoint-started', 'endpoint-finished', 'input-release', 'result-allocation-started',
    'result-allocation-committed', 'result-leaf-copy-started', 'result-leaf-copied',
    'result-prepared', 'result-commit-pending', 'export-pending', 'export-copied', 'result-release']
LEGACY = {'input-validated':0,'input-allocation-committed':1,'input-payload-copied':2,
          'input-release':4,'result-allocation-committed':5,'result-prepared':6,'export-copied':7}


def expected(case: dict) -> dict:
    length = len(carrier(case['fields'],case['recipe'],False))
    trace = []; releases = []; secondary = []
    live = None; peak = 0; endpoint = 0; primary = None
    remaining = [tuple((p['event'],p['leaf'])) for p in case['injections']]
    def event(label, leaf=None):
        nonlocal live, peak, endpoint, primary
        if label == 'input-allocation-committed': live='input'; peak=1
        if label == 'result-allocation-committed': live='result'; peak=1
        if label in ['input-release','result-release']:
            releases.append(label.split('-')[0]); live=None
        trace.append(dict(ordinal=len(trace),event=label,leaf=leaf))
        fault=(label,leaf)
        if fault in remaining:
            remaining.remove(fault)
            detail=dict(kind='release-failed' if label.endswith('-release') else 'execution-failed',
                        status=10 if label in ALLOCATIONS else 11)
            if primary is None: primary=detail
            else: secondary.append(detail['status'])
            return False
        if primary is not None: return False
        if case['legacy'] >= 0 and LEGACY.get(label) == case['legacy']:
            primary=dict(kind='execution-failed',status=case['legacy']);return False
        return True
    def sequence():
        nonlocal endpoint, primary
        for label in ['input-validated','input-allocation-started','input-allocation-committed',
                      'input-payload-copied','input-prepared','input-transfer-pending','input-transfer-committed']:
            if not event(label):return
        for leaf in range(case['fields']):
            if not event('endpoint-started',leaf):return
            endpoint += 1
            if not event('endpoint-finished',leaf):return
        if case['legacy'] == 3:primary=dict(kind='execution-failed',status=3);return
        for label in ['input-release','result-allocation-started','result-allocation-committed']:
            if not event(label):return
        for leaf in range(case['fields']):
            for label in ['result-leaf-copy-started','result-leaf-copied']:
                if not event(label,leaf):return
        for label in ['result-prepared','result-commit-pending','result-committed','export-pending']:
            if not event(label):return
        mutation=case['export_mutation']
        if mutation:
            primary=({'kind':'result-rejected','reason':{1:'carrier-framing',2:'carrier-count',5:'carrier-framing',6:'carrier-trailing'}[mutation]}
                if mutation in [1,2,5,6] else {'kind':'capacity-exceeded','reason':'leaf-bytes'})
            return
        event('export-copied')
    if case['recipe'] == 4:
        primary=dict(kind='capacity-exceeded',reason='leaf-bytes')
    else:
        sequence()
        if live is not None:event(live+'-release')
    return dict(accepted=primary is None,primary=primary,secondary_cleanup_statuses=secondary,
        endpoint_calls=endpoint,live_allocations=0,live_handles=0,live_bytes=0,
        peak_allocations=peak,peak_bytes=length if peak else 0,
        zeroed_bytes=length*len(releases),retained_pages=max(1,(length+65535)//65536) if peak else 1,
        release_order=releases,trace=trace)


def cases() -> list[dict]:
    result=[]
    def add(name,fields=2,recipe=0,injections=(),legacy=-1,mutation=0,shared=None):
        case=dict(case_id=name,fields=fields,recipe=recipe,injections=[dict(event=e,leaf=l) for e,l in injections],
                  legacy=legacy,export_mutation=mutation,shared_case_id=shared)
        case['input_carrier_digest']=digest(SHARED_SCHEMA+'/input',carrier(fields,recipe,False))
        case['expected']=expected(case)
        case['result_carrier_digest']=digest(SHARED_SCHEMA+'/result',carrier(fields,recipe,True)) if case['expected']['accepted'] else None
        result.append(case)
    for base in shared_manifest()['cases'][:7]:
        add(base['case_id'],fields=base['fields'],recipe=base['recipe'],shared=base['case_id'])
    for legacy in range(8):add(f'legacy_{legacy}',legacy=legacy)
    for recipe in range(3):
        for event in EVENTS:
            for leaf in range(2) if event in LEAF_EVENTS else [None]:
                label='whole' if leaf is None else str(leaf)
                add(f'r{recipe}_{event}_{label}',recipe=recipe,injections=[(event,leaf)])
    # The first failure stays primary while actual input/result cleanup runs.
    for event,leaf,release in [
        ('input-allocation-committed',None,'input-release'),
        ('input-payload-copied',None,'input-release'),
        ('input-transfer-pending',None,'input-release'),
        ('input-transfer-committed',None,'input-release'),
        ('endpoint-started',0,'input-release'),('endpoint-finished',1,'input-release'),
        ('result-allocation-committed',None,'result-release'),
        ('result-leaf-copy-started',1,'result-release'),('result-leaf-copied',1,'result-release'),
        ('result-commit-pending',None,'result-release'),('export-pending',None,'result-release'),
        ('export-copied',None,'result-release')]:
        add(f'compound_{event}',injections=[(event,leaf),(release,None)])
    for mutation in range(1,7):
        for cleanup in [False,True]:
            add(f'export_mutation_{mutation}_cleanup_{int(cleanup)}',mutation=mutation,
                injections=[('result-release',None)] if cleanup else [])
    require(len({row['case_id'] for row in result})==len(result),'duplicate-case')
    return result


def manifest() -> dict:
    return dict(schema=SCHEMA,route=ROUTE,profile='flat-owned-bytes-reference-fixture.v1',
        shared_manifest_digest=digest(SCHEMA+'/shared-manifest',canonical(shared_manifest())),
        synchronous=True,cancellation=False,concurrent_calls=False,cases=cases())


if __name__=='__main__':
    import sys
    sys.stdout.buffer.write(canonical(manifest()))
