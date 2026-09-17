#!/usr/bin/env python3
"""Real native C11/C++17 caller settlement; strict evidence with trusted replay.

Default runs instantiate the SAME production text assets for a clearly named
flat test fixture. --generated verifies actual Rust-generator output byte for
byte before using it. Neither route asserts generic compiler/PG-7 completion.
Submitted evidence is data only: replay recompiles this checkout's trusted
sources and compares all records. It never executes submitted binaries.
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
from typing import Any

import public_generic_consumer_fixture as fixture
from public_generic_consumer_cases import PARAMS, carrier, cases_header, manifest
from public_generic_settlement_evidence import canonical, digest, read_bounded, read_canonical, require, c_array

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'tests/public_generic_native_adapter_v1'
TESTS = NATIVE / 'consumer_settlement'
SCHEMA = 'semaprax.public-generic-consumer-settlement-evidence.v1'
FIELDS = ['case_id','status','native','release','endpoint','exports','native_peak','native_peak_bytes',
          'native_peak_handles','native_live','native_live_bytes','native_live_handles','trace',
          'native_release','secondary','client_peak','client_peak_bytes','client_live','client_live_bytes','client_release']
MAX_EVIDENCE = 8 * 1024 * 1024


def run(command: list[str], cwd: Path) -> str:
    env = dict(os.environ, ASAN_OPTIONS='detect_leaks=1:halt_on_error=1', UBSAN_OPTIONS='halt_on_error=1')
    output = subprocess.run(command, cwd=cwd, env=env, text=True, capture_output=True, timeout=180)
    if output.returncode:
        raise RuntimeError(f'exit {output.returncode}: {command!r}\n{output.stdout}\n{output.stderr}')
    require(not output.stderr, f'unexpected-stderr: {output.stderr[:1000]}')
    return output.stdout


def receipt(text: str, case: dict) -> dict:
    require(text.endswith('\n') and len(text) < 262144 and text.startswith('CASE '), 'receipt-framing')
    pairs = text.rstrip('\n')[5:].split(' ')
    require(len(pairs) == len(FIELDS), 'receipt-field-count')
    parsed: dict[str, Any] = {}
    for name, pair in zip(FIELDS, pairs):
        require(pair.startswith(name + '='), 'receipt-field-order')
        value = pair[len(name) + 1:]
        if name == 'case_id':
            require(value == case['case_id'], 'receipt-case')
            parsed[name] = value
        elif name in ['trace','native_release','secondary','client_release']:
            require(len(value) <= 131072, 'receipt-list-bound')
            items = [] if value == '' else value.split(',')
            require(len(items) <= 4096, 'receipt-list-count')
            def integer(item: str) -> int:
                require(item.isascii() and item.isdecimal() and str(int(item)) == item, 'receipt-integer')
                require(int(item) <= 2**32-1, 'receipt-integer-bound')
                return int(item)
            if name == 'native_release':
                parsed[name] = [list(map(integer, v.split(':'))) for v in items]
                require(all(len(v) == 2 and v[0] <= 1 and v[1] < case['fields'] for v in parsed[name]), 'receipt-leaf')
            else:
                parsed[name] = list(map(integer, items))
                if name == 'trace': require(all(v <= 14 for v in parsed[name]), 'receipt-trace')
                if name == 'secondary': require(all(v == 11 for v in parsed[name]), 'receipt-secondary')
        else:
            require(value.isascii() and value.isdecimal() and str(int(value)) == value, 'receipt-integer')
            parsed[name] = int(value)
            require(parsed[name] <= 1024 * 1024 * 1024, 'receipt-counter-bound')
    for field, expectation in [('status','expected_status'),('native','expected_native'),('release','expected_release'),('endpoint','endpoint')]:
        require(parsed[field] == case[expectation], f'{case["case_id"]}:{field}')
    for field in ['native_live','native_live_bytes','native_live_handles','client_live','client_live_bytes']:
        require(parsed[field] == 0, f'{case["case_id"]}:leak:{field}')
    if case['endpoint'] == 0:
        require(parsed['exports'] == 0, 'pre-execution-export')
    return parsed


def source_files() -> list[Path]:
    paths = [ROOT / 'src/public_generic_abi/native/provider_body.c', ROOT / 'src/public_generic_abi/native/spx_pg_v1.h',
             NATIVE / 'allocations.c', NATIVE / 'settlement_corpus/observations.c']
    for family in ['c_calling','cxx_calling']:
        paths += [ROOT / 'src/public_generic_consumer' / (family + '.rs'), ROOT / 'src/public_generic_consumer' / family / 'render.rs']
        paths += sorted((ROOT / 'src/public_generic_consumer' / family / 'render').glob('*.txt'))
    paths += sorted(TESTS.glob('*.*'))
    paths += [Path(__file__), ROOT/'scripts/public_generic_consumer_fixture.py', ROOT/'scripts/public_generic_consumer_cases.py',
              ROOT/'scripts/public_generic_settlement_evidence.py']
    return sorted(set(paths))


def prepare(work: Path, fields: int, rows: list[dict], generated: Path | None) -> None:
    work.mkdir(parents=True)
    expected = fixture.render(fields)
    for name, text in expected.items():
        data = text.encode('utf-8')
        if generated is not None:
            actual = read_bounded(generated / str(fields) / name, 4 * 1024 * 1024)
            require(actual == data, f'generator-template-drift:{fields}:{name}')
            data = actual
        path = work / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    for name in ['hooks.h','client.c']:
        shutil.copyfile(TESTS / name, work / name)
    (work/'cases.inc').write_text(cases_header(rows))
    fields_names = ['field_' + value.encode().hex() for value in fixture.identities(fields)]
    for suffix in ['c','cpp']:
        driver = (TESTS/f'driver.{suffix}').read_text().replace('@COUNT@', str(fields))
        driver = driver.replace('@INPUT_REFS@', ','.join('&input.'+n for n in fields_names))
        driver = driver.replace('@OUTPUT_REFS@', ','.join('&output.'+n for n in fields_names))
        driver = driver.replace('@CPP_INPUT_REFS@', ','.join('&input.'+n for n in fields_names))
        driver = driver.replace('@CPP_VIEWS@', ','.join('first.'+n+'()' for n in fields_names))
        (work/f'driver.{suffix}').write_text(driver)
    descriptor, binding = fixture.bindings()
    provider = (NATIVE/'allocations.c').read_text() + '\n' + (NATIVE/'settlement_corpus/observations.c').read_text()
    provider += '\n#include "spx_pg_v1.h"\n' + c_array('SPX_PG_TRUSTED_DESCRIPTOR_BYTES', descriptor, 'SPX_PG_TRUSTED_DESCRIPTOR_LEN')
    provider += c_array('SPX_PG_TRUSTED_BINDING_BYTES', binding, 'SPX_PG_TRUSTED_BINDING_LEN')
    provider += '\n#define spx_pg_result_export_v1 consumer_real_export\n#define spx_pg_provider_close_v1 consumer_real_close\n'
    provider += (ROOT/'src/public_generic_abi/native/provider_body.c').read_text()
    provider += '\n' + (TESTS/'provider.c').read_text()
    (work/'provider.c').write_text(provider)
    # Define client allocator macros only AFTER system declarations. Provider
    # keeps its independent allocator; C++ calls the instrumented C allocator.
    (work/'consumer.c').write_text('#include "hooks.h"\n#define malloc consumer_test_malloc\n#define free consumer_test_free\n#include "spx_pg_calling_consumer.c"\n')


def build(work: Path, cc: str, cxx: str, flags: list[str]) -> dict[str, Path]:
    common = ['-Wall','-Wextra','-Werror','-I.', *flags]
    for source in ['provider.c','consumer.c','client.c','driver.c']:
        run([cc,'-std=c11',*common,'-c',source,'-o',source+'.o'], work)
    run([cxx,'-std=c++17',*common,'-c','driver.cpp','-o','driver.cpp.o'],work)
    binaries = {}
    for route, driver, compiler in [('c11','driver.c',cc),('cpp17','driver.cpp',cxx)]:
        binary = f'consumer-{route}'
        run([compiler,*flags,'provider.c.o','consumer.c.o','client.c.o',driver+'.o','-o',binary], work)
        binaries[route] = work / binary
    return binaries


def execute(args: argparse.Namespace, *, case_ids: list[str] | None = None) -> dict:
    trusted = manifest()
    pinned = ROOT/'tests/fixtures/public-generic-consumer-settlement-v1/cases.json'
    require(read_bounded(pinned, 512*1024) == canonical(trusted), 'stale-consumer-manifest')
    rows = trusted['cases']
    selected = rows if args.case is None else [c for c in rows if c['case_id'] == args.case]
    if case_ids is not None:
        require(args.case is None and len(case_ids) == len(set(case_ids)), 'invalid-case-selection')
        require(set(case_ids).issubset({c['case_id'] for c in rows}), 'unknown-case-selection')
        selected = [c for c in rows if c['case_id'] in case_ids]
    require(selected, 'unknown-case')
    configurations = [('O0',['-O0']),('O2',['-O2'])]
    if args.sanitizers: configurations += [('ASanUBSan',['-O1','-g0','-fsanitize=address,undefined','-fno-omit-frame-pointer'])]
    observed = []
    by_route_case = {}
    shared = {}
    with tempfile.TemporaryDirectory(prefix='spx-consumer-settlement-') as tmp:
        for opt, flags in configurations:
            for count in sorted({c['fields'] for c in selected}):
                work = Path(tmp) / f'{opt}-{count}'
                local = [c for c in selected if c['fields'] == count]
                prepare(work, count, local, args.generated)
                programs = build(work,args.cc,args.cxx,flags)
                for route, program in programs.items():
                    binary_digest = digest(SCHEMA+'/executable', program.read_bytes())
                    for case in local:
                        if route not in case['routes']: continue
                        output_path = work/'result.bin'
                        output_path.unlink(missing_ok=True)
                        text = run([str(program),case['case_id'],str(output_path)],work)
                        record = receipt(text,case)
                        if case['expected_status'] == 0:
                            actual = read_bounded(output_path, 16*1024*1024+2056)
                            require(actual == carrier(count,case['recipe'],True), f'{case["case_id"]}:semantic-result')
                            result_digest = digest(trusted['schema']+'/result',actual)
                            require(result_digest == case['result_digest'], 'result-digest')
                        else:
                            require(not output_path.exists(), 'partial-result-exposed')
                            result_digest = None
                        key = (route,case['case_id'])
                        if key in by_route_case: require(by_route_case[key] == record, f'optimization-divergence:{key}')
                        else: by_route_case[key] = record
                        # The provider sees identical input/calls. Client-side
                        # allocation counts are target-local, but never omitted.
                        comparable = {k:v for k,v in record.items() if not k.startswith('client_')}
                        if len(case['routes']) == 2:
                            if case['case_id'] in shared: require(shared[case['case_id']] == comparable, f'route-divergence:{case["case_id"]}')
                            else: shared[case['case_id']] = comparable
                        record.update(engine_id=f'{route}-{opt}', executable_digest=binary_digest,
                            input_digest=case['input_digest'],result_digest=result_digest,
                            trace_digest=digest(SCHEMA+'/trace',canonical(record['trace'])),
                            release_digest=digest(SCHEMA+'/release',canonical(record['native_release'])))
                        # Keep equality baselines independent from appended evidence fields.
                        by_route_case[key] = {k:record[k] for k in FIELDS}
                        observed.append(record)
            print(f'{opt}: {sum(1 for c in selected for _ in c["routes"])} real consumer executions passed', flush=True)
    sources = {str(p.relative_to(ROOT)): digest(SCHEMA+'/source',p.read_bytes()) for p in source_files()}
    descriptor,binding=fixture.bindings()
    return dict(schema=SCHEMA, corpus_digest=digest(SCHEMA+'/corpus',canonical(trusted)),
        route='rust-generator-checked' if args.generated else 'production-template-fixture',
        source_digests=sources, descriptor_digest=digest(SCHEMA+'/descriptor',descriptor),
        provider_binding_digest=digest(SCHEMA+'/binding',binding),
        configurations=[v[0] for v in configurations], records=observed)


def verify(data: bytes, expected: dict) -> None:
    read_canonical(data,MAX_EVIDENCE)
    require(data == canonical(expected), 'trusted-replay-mismatch')


def negative_controls(expected: dict) -> int:
    count=0
    def rejected(data):
        nonlocal count
        try: verify(data,expected)
        except (ValueError,TypeError,KeyError): count+=1;return
        raise AssertionError('evidence-mutation-accepted')
    baseline=canonical(expected)
    rejected(baseline[:-1]);rejected(baseline+b' ');rejected(baseline+b'{}\n')
    for key in expected:
        changed=copy.deepcopy(expected);del changed[key];rejected(canonical(changed))
    for key in expected['records'][0]:
        changed=copy.deepcopy(expected);del changed['records'][0][key];rejected(canonical(changed))
        changed=copy.deepcopy(expected)
        val=changed['records'][0][key]
        changed['records'][0][key]=not val if type(val) is bool else val+1 if type(val) is int else [] if val is None else 'reminted-wrong-case'
        rejected(canonical(changed))
    changed=copy.deepcopy(expected);changed['records'][0]['native_live']=False;rejected(canonical(changed))
    changed=copy.deepcopy(expected);changed['records'].reverse();rejected(canonical(changed))
    changed=copy.deepcopy(expected);changed['extra']=0;rejected(canonical(changed))
    # Unkeyed hashes may be reminted by an attacker; checked runtime replay,
    # rather than hashes alone, is the authority.
    changed=copy.deepcopy(expected);changed['records'][0]['trace']=[13]
    changed['records'][0]['trace_digest']=digest(SCHEMA+'/trace',canonical([13]));rejected(canonical(changed))
    # Parse hostile receipts separately from envelope equality. All fields
    # remain mandatory, ordered and bounded before conversion/comparison.
    first = expected['records'][0]
    trusted_case = next(c for c in manifest()['cases'] if c['case_id'] == first['case_id'])
    def render_receipt(record):
        parts=[]
        for key in FIELDS:
            value=record[key]
            if key=='native_release': value=','.join(':'.join(map(str,v)) for v in value)
            elif isinstance(value,list): value=','.join(map(str,value))
            parts.append(key+'='+str(value))
        return 'CASE '+' '.join(parts)+'\n'
    valid=render_receipt(first)
    receipt(valid,trusted_case)
    bad=[valid[:-1],valid+'extra=1',valid.replace('CASE ','case ',1),valid.replace(' native=0',' native=00'),
         valid.replace(' native=0',' native=-1'),valid.replace(' native=0',' native=False'),
         valid.replace(' native=0',' unknown=0'),valid.replace(' native=0',' status=0'),
         valid.replace(' native=0',''),valid.replace(' native=0 release=0',' release=0 native=0')]
    for field,value in [('native_live',1),('client_live',1),('client_peak',1073741825),
                        ('trace',[15]),('trace',[0]*4097),('secondary',[99]),
                        ('native_release',[[2,0]]),('native_release',[[0,trusted_case['fields']]])]:
        changed=copy.deepcopy(first);changed[field]=value;bad.append(render_receipt(changed))
    for data in bad:
        try: receipt(data,trusted_case)
        except (ValueError,TypeError,KeyError): count+=1;continue
        raise AssertionError('receipt-mutation-accepted')
    rejected(b' ' * (MAX_EVIDENCE+1))
    print(f'{count} evidence and receipt negative controls rejected',flush=True)
    return count


def main() -> int:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--cc',default=os.environ.get('CC','clang'))
    p.add_argument('--cxx',default=os.environ.get('CXX','clang++'))
    p.add_argument('--sanitizers',action='store_true')
    p.add_argument('--generated',type=Path,help='actual Cargo-generated fixtures, subdirectories 1, 2, 3, 256')
    p.add_argument('--case',help='focused local probe; not a full gate')
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--replay',type=Path)
    args=p.parse_args()
    try:
        for name in [args.cc,args.cxx]: require(shutil.which(name) is not None,'missing-required-compiler:'+name)
        expected=execute(args)
        if args.replay: verify(read_bounded(args.replay,MAX_EVIDENCE),expected);print('Independent trusted recompilation replay passed')
        negative_controls(expected)
        args.output.mkdir(parents=True,exist_ok=True)
        (args.output/'consumer-settlement.json').write_bytes(canonical(expected))
        print(f'{len(expected["records"])} checked records; {args.output / "consumer-settlement.json"}')
        return 0
    except (ValueError,RuntimeError,OSError,subprocess.TimeoutExpired) as error:
        print(str(error),file=sys.stderr);return 1

if __name__=='__main__': raise SystemExit(main())
