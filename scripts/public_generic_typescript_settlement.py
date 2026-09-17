#!/usr/bin/env python3
"""Type-check and execute the host-owned TypeScript/Wasm reference caller.

The endpoint is the existing hand-assembled bytecode fixture, NOT a compiled
Semaprax provider ABI. All ownership remains in the generated host wrapper.
Replay executes trusted sources afresh, never submitted code or binary bytes.
"""
from __future__ import annotations
import argparse
import copy
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

import public_generic_typescript_fixture as fixture
from public_generic_typescript_cases import manifest, ROUTE
from public_generic_settlement_evidence import canonical, digest, read_bounded, read_canonical, require

ROOT = Path(__file__).resolve().parents[1]
TESTS = ROOT / 'tests/public_generic_wasm_adapter_v1/settlement'
PINNED = ROOT / 'tests/fixtures/public-generic-typescript-settlement-v1/cases.json'
SCHEMA = 'semaprax.public-generic-typescript-settlement-evidence.v1'
MAX_EVIDENCE = 8 * 1024 * 1024
MODES = [('liftoff', ['--liftoff-only', '--no-wasm-lazy-compilation']),
         ('turbofan', ['--no-liftoff', '--no-wasm-lazy-compilation'])]


def run(command: list[str], cwd: Path) -> str:
    completed = subprocess.run(command, cwd=cwd, text=True, capture_output=True, timeout=240)
    require(completed.returncode == 0,
            f'command-failed:{command!r}:exit={completed.returncode}\n{completed.stdout}\n{completed.stderr}')
    require(not completed.stderr, f'unexpected-stderr:{completed.stderr[:1000]}')
    return completed.stdout


def source_files() -> list[Path]:
    paths = list(TESTS.glob('*.mjs'))
    paths += list((ROOT/'src/public_generic_consumer/typescript_calling').rglob('*.txt'))
    paths += list((ROOT/'src/public_generic_consumer/typescript_calling').rglob('*.rs'))
    paths += [ROOT/'src/public_generic_consumer/typescript_calling.rs',
              ROOT/'tests/public_generic_wasm_adapter_v1/reference_wasm_module.rs',
              ROOT/'tests/public_generic_wasm_adapter_v1/typescript_settlement.rs', PINNED,
              ROOT/'tests/fixtures/public-generic-consumer-settlement-v1/cases.json']
    paths += [ROOT/'scripts'/name for name in ['public_generic_typescript_fixture.py',
        'public_generic_typescript_cases.py','public_generic_typescript_settlement.py',
        'public_generic_consumer_cases.py','public_generic_consumer_fixture.py',
        'public_generic_settlement_evidence.py']]
    return sorted(set(paths))


def write_subjects(output: Path) -> dict:
    rows = []
    for label, (count, module) in fixture.subjects().items():
        fixture.write(output/label, count, module)
        rows.append(dict(label=label, fields=count))
    (output/'subjects.json').write_bytes(canonical(rows))
    return dict(subjects=rows)


def prepare(work: Path, generated: Path | None, tsc: str) -> dict:
    packages = {}
    for label, (count, module) in fixture.subjects().items():
        directory = work/label
        expected = fixture.render(count, module)
        if generated:
            for name, text in expected.items():
                require(read_bounded(generated/label/name,4*1024*1024) == text.encode('utf-8'),
                        f'generator-template-drift:{label}:{name}')
            require(read_bounded(generated/label/'reference.wasm',16777216) == module,
                    f'generator-module-drift:{label}')
        fixture.write(directory, count, module)
        # When --generated is selected, execute those checked files themselves.
        if generated:
            for name in expected:
                shutil.copyfile(generated/label/name,directory/name)
        run([tsc,'-p','tsconfig.json'],directory)
        packages[label] = dict(fields=count,
            module_digest=digest(fixture.DOMAIN,module),
            source_digests={name:digest(SCHEMA+'/package-source',text.encode('utf-8')) for name,text in expected.items()},
            javascript_digests={str(p.relative_to(directory)):digest(SCHEMA+'/javascript',p.read_bytes())
                for p in sorted((directory/'dist').glob('*.js'))})
    return packages


def json_run(command: list[str], cwd: Path):
    data=run(command,cwd).encode('utf-8')
    return read_canonical(data,MAX_EVIDENCE)


def compare_native(observed: dict, trusted: dict, args: argparse.Namespace) -> dict:
    # Never accept an external receipt as authority. Recompile the C and C++
    # callers using their existing owner, then compare only genuinely shared
    # semantic fields. Their lifecycle traces and peaks are target-local.
    import public_generic_consumer_settlement as native
    expected=native.execute(
        argparse.Namespace(cc=args.cc,cxx=args.cxx,sanitizers=False,case=None,generated=None),
        case_ids=[c['shared_case_id'] for c in trusted['cases'] if c['shared_case_id'] is not None])
    native.negative_controls(expected)
    selected=[]
    for case in trusted['cases']:
        if case['shared_case_id'] is None:
            continue
        candidates=[r for r in expected['records'] if r['case_id']==case['shared_case_id']]
        require(len(candidates)==4,'missing-native-shared-route')
        for record in candidates:
            for mode,_ in MODES:
                actual=next(row for row in observed[mode]['matrix'] if row['case_id']==case['case_id'])
                require(record['input_digest']==actual['input_carrier_digest'],'shared-input-carrier')
                require(record['result_digest']==actual['result_carrier_digest'],'shared-result-carrier')
                require((record['status']==0)==actual['report']['accepted'],'shared-acceptance')
                require((record['endpoint']!=0)==(actual['report']['endpoint_calls']!=0),'shared-execution')
                if record['status']!=0:
                    require(record['status']==4 and actual['report']['primary']==
                            dict(kind='capacity-exceeded',reason='leaf-bytes'),'shared-capacity-status')
            selected.append(record)
    return dict(native_evidence_digest=digest(SCHEMA+'/fresh-native-evidence',canonical(expected)),
        records=selected, shared_cases=7, checked_comparisons=len(selected)*len(MODES),
        equal_fields=['input-carrier','result-carrier','acceptance','endpoint-invoked','capacity-category'],
        noncomparable_fields=['per-leaf endpoint call count','host frame trace versus native trace',
                              'host frame release versus native leaf release','resource peaks'])


def execute(args: argparse.Namespace) -> dict:
    require(1<=args.repeats<=8192,'repeat-bound')
    require(shutil.which(args.node) is not None,'missing-required-node')
    require(shutil.which(args.tsc) is not None,'missing-required-tsc')
    node=run([args.node,'--version'],ROOT).strip()
    require(node.startswith('v22.'),'required-node-22')
    tsc=run([args.tsc,'--version'],ROOT).strip()
    require(tsc=='Version 5.8.3','required-typescript-5.8.3')
    trusted=manifest()
    require(read_bounded(PINNED,1024*1024)==canonical(trusted),'stale-typescript-manifest')
    observed={}
    with tempfile.TemporaryDirectory(prefix='spx-ts-settlement-') as tmp:
        work=Path(tmp)
        packages=prepare(work,args.generated,args.tsc)
        legacy=[]
        for count in [1,2,256]:
            text=run([args.node,'test/round-trip.mjs','reference.wasm'],work/f'fields-{count}')
            require(text.endswith('14 test(s) passed\n') and text.count('ok - ') == 14,'legacy-regression')
            legacy.append(dict(fields=count,passed=14))
        for mode,flags in MODES:
            command=[args.node,*flags]
            matrix=[]
            for count in [1,2,256]:
                matrix+=json_run([*command,str(TESTS/'runner.mjs'),str(work/f'fields-{count}'),str(PINNED),str(count)],ROOT)
            matrix.sort(key=lambda r: next(i for i,c in enumerate(trusted['cases']) if c['case_id']==r['case_id']))
            require(len(matrix)==len(trusted['cases']),'missing-matrix-cases')
            for row in matrix:
                row['trace_digest']=digest(SCHEMA+'/host-trace',canonical(row['report']['trace']))
                row['release_order_digest']=digest(SCHEMA+'/host-release',canonical(row['report']['release_order']))
            hostile=json_run([*command,str(TESTS/'hostility.mjs'),str(work/'fields-2'),'host','',str(args.repeats)],ROOT)
            variants=[json_run([*command,str(TESTS/'variants.mjs'),str(work/name),name],ROOT)
                      for name in fixture.module_variants()]
            observed[mode]=dict(matrix=matrix,hostility=hostile,variants=variants)
            require(len(hostile)==32 and len(variants)==13,'host-case-inventory')
            print(f'{mode}: {len(matrix)} settlement + {len(hostile)} hostility + {len(variants)} module cases passed',flush=True)
        require(observed['liftoff']==observed['turbofan'],'wasm-tier-divergence')
    cross=compare_native(observed,trusted,args) if args.native else None
    return dict(schema=SCHEMA,route=ROUTE,provenance='rust-generator-checked' if args.generated else 'production-template-fixture',
        corpus_digest=digest(SCHEMA+'/corpus',canonical(trusted)),toolchains=dict(node=node,typescript=tsc),
        configurations=[dict(engine=name,flags=flags) for name,flags in MODES],repeats=args.repeats,
        packages=packages,legacy=legacy,observations=observed,native_comparison=cross,
        source_digests={str(p.relative_to(ROOT)):digest(SCHEMA+'/source',p.read_bytes()) for p in source_files()})


def verify(data: bytes, expected: dict) -> None:
    read_canonical(data,MAX_EVIDENCE)
    require(data==canonical(expected),'trusted-replay-mismatch')


def negative_controls(expected: dict) -> int:
    count=0
    def rejected(data: bytes):
        nonlocal count
        try:
            verify(data,expected)
        except (ValueError,TypeError,KeyError,RecursionError):
            count+=1
            return
        raise AssertionError('typescript-evidence-mutation-accepted')
    baseline=canonical(expected)
    for data in [baseline[:-1],baseline+b' ',baseline+b'{}\n',b' '*(MAX_EVIDENCE+1),
                 b'{"schema":"x",'+baseline[1:], b'{"unknown":0,'+baseline[1:]]:rejected(data)
    for key in expected:
        altered=copy.deepcopy(expected);del altered[key];rejected(canonical(altered))
        altered=copy.deepcopy(expected);altered[key]='other-subject';rejected(canonical(altered))
    first=expected['observations']['liftoff']['matrix'][0]
    for key in first:
        for op in ['delete','replace']:
            altered=copy.deepcopy(expected);row=altered['observations']['liftoff']['matrix'][0]
            if op=='delete':del row[key]
            else:row[key]='reminted-other-case'
            rejected(canonical(altered))
    for key,value in first['report'].items():
        for op in ['delete','replace']:
            altered=copy.deepcopy(expected);row=altered['observations']['liftoff']['matrix'][0]['report']
            if op=='delete':del row[key]
            else:row[key]=False if type(value) is int else 1 if type(value) is bool else 'other-value'
            rejected(canonical(altered))
    altered=copy.deepcopy(expected)
    row=altered['observations']['liftoff']['matrix'][0];row['report']['trace']=[]
    row['trace_digest']=digest(SCHEMA+'/host-trace',canonical([]));rejected(canonical(altered))
    altered=copy.deepcopy(expected)
    row=altered['observations']['liftoff']['matrix'][0];row['report']['release_order']=[]
    row['release_order_digest']=digest(SCHEMA+'/host-release',canonical([]));rejected(canonical(altered))
    for key in ['matrix','hostility','variants']:
        altered=copy.deepcopy(expected);altered['observations']['liftoff'][key].reverse();rejected(canonical(altered))
    for key in ['module_digest','source_digests','javascript_digests']:
        altered=copy.deepcopy(expected);altered['packages']['fields-2'][key]='other-provider';rejected(canonical(altered))
    altered=copy.deepcopy(expected);altered['observations']['turbofan']['matrix']=[];rejected(canonical(altered))
    print(f'{count} strict evidence negative controls rejected',flush=True)
    return count


def main() -> int:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--node',default=os.environ.get('NODE','node'))
    p.add_argument('--tsc',default=os.environ.get('SPX_PG_TSC',os.environ.get('TSC','tsc')))
    p.add_argument('--cc',default=os.environ.get('CC','clang'))
    p.add_argument('--cxx',default=os.environ.get('CXX','clang++'))
    p.add_argument('--generated',type=Path,help='all actual Rust-generator files, under subject labels')
    p.add_argument('--repeats',type=int,default=64)
    p.add_argument('--native',action='store_true',help='fresh native C/C++ builds for seven shared semantic cases')
    p.add_argument('--output',required=True,type=Path)
    p.add_argument('--replay',type=Path)
    p.add_argument('--write-subjects',action='store_true',help='prepare labelled byte fixtures for the Cargo bridge; not a passing gate')
    args=p.parse_args()
    try:
        if args.write_subjects:
            write_subjects(args.output)
            return 0
        result=execute(args)
        if args.replay:
            verify(read_bounded(args.replay,MAX_EVIDENCE),result)
            print('Independent trusted TypeScript/Wasm re-execution replay passed',flush=True)
        negative_controls(result)
        args.output.mkdir(parents=True,exist_ok=True)
        (args.output/'typescript-settlement.json').write_bytes(canonical(result))
        print(f'{sum(len(group) for mode in result["observations"].values() for group in mode.values())} checked execution records')
        return 0
    except (ValueError,TypeError,OSError,subprocess.TimeoutExpired) as error:
        print(str(error),file=sys.stderr)
        return 1

if __name__=='__main__':raise SystemExit(main())
