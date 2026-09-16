#!/usr/bin/env python3
"""Compile intentional consumer regressions; require the intended assertion.

A compile error, missing tool, generic crash or sanitizer startup failure is
NOT a passing negative control. Each case first executes its unchanged caller.
Only temporary generated files are mutated; repository sources stay untouched.
"""
from __future__ import annotations
import argparse
import subprocess
import tempfile
from pathlib import Path
from public_generic_consumer_cases import manifest
from public_generic_consumer_fixture import identities
from public_generic_consumer_settlement import build, prepare, receipt, run
from public_generic_settlement_evidence import require


def replace(path: Path, old: str, new: str) -> None:
    source=path.read_text()
    require(source.count(old)==1, 'mutation-anchor:'+old[:60])
    path.write_text(source.replace(old,new))


def main() -> None:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cc',default='clang')
    parser.add_argument('--cxx',default='clang++')
    args=parser.parse_args()
    rows={c['case_id']:c for c in manifest()['cases']}
    tests=[
        ('masked-release','release_r0_l1','c11','status == consumer_case->expected_status'),
        ('overwritten-primary','hostile_export_1_cleanup_1','c11','status == consumer_case->expected_status'),
        ('forward-input','two_leaves_embedded_zero','c11','input_release_indices[i - 1] > input_release_indices[i]'),
        ('forward-output','two_leaves_embedded_zero','c11','owned.leaf < last_result_leaf'),
        ('forward-partial-decode','partial_decoder_two_completed_leaves','c11','owned.leaf < last_result_leaf'),
        ('unbounded-export-size','hostile_export_3_cleanup_0','c11','size > 0 && size <= 16779272u'),
        ('orphaned-close','close_refusal_then_retry','c11','native == 7 && consumer != NULL'),
        ('eager-decode-allocation','hostile_export_9_cleanup_0','c11','!decode_forbidden'),
        ('forward-cpp-staging','cpp_staging_two_completed_leaves','cpp17','owned.leaf < last_staged_leaf'),
        ('lost-move-owner','cpp_move_retains_both_owners_on_close_refusal','cpp17','provider.valid() && other.valid()'),
        ('sticky-cpp-injection','local_refusal_clears_injection','cpp17','status == consumer_case->expected_status'),
    ]
    with tempfile.TemporaryDirectory(prefix='spx-consumer-mutants-') as tmp:
        for name,case_id,route,assertion in tests:
            case=rows[case_id];work=Path(tmp)/name
            prepare(work,case['fields'],[case],None)
            binaries=build(work,args.cc,args.cxx,['-O2'])
            receipt(run([str(binaries[route]),case_id,str(work/'result.bin')],work),case)
            source=work/'spx_pg_calling_consumer.c'
            header=work/'include/semaprax_public_generic_v1.hpp'
            fields=['field_'+n.encode().hex() for n in identities(case['fields'])]
            if name=='masked-release':
                replace(source,'            outcome.primary_status = SPX_PG_CONSUMER_RELEASE_FAILED;\n            outcome.native_status = outcome.release_status;', '            /* deliberately hide the release failure */')
            elif name=='overwritten-primary':
                replace(source,' && outcome.primary_status == SPX_PG_CONSUMER_OK)', ')')
            elif name=='forward-input':
                replace(source,'for (size_t i = FIELD_COUNT; i-- > 0;)', 'for (size_t i = 0; i < FIELD_COUNT; ++i)')
            elif name=='forward-output':
                lines=[f'    spx_pg_owned_bytes_free(&output->{n});\n' for n in fields]
                replace(source,''.join(reversed(lines)),''.join(lines))
            elif name=='forward-partial-decode':
                replace(source,'''    while (count != 0) {
        --count;
        free(leaves[count].data);
        leaves[count].data = NULL;
        leaves[count].len = 0;
    }''','''    for (size_t index = 0; index < count; ++index) {
        free(leaves[index].data);
        leaves[index].data = NULL;
        leaves[index].len = 0;
    }''')
            elif name=='unbounded-export-size':
                replace(source,'required < 8u + 8u * FIELD_COUNT || required > SPX_PG_CCC_MAX_FRAME_BYTES', 'required < 8u + 8u * FIELD_COUNT')
            elif name=='orphaned-close':
                replace(source,'if ((*consumer)->provider == NULL)', 'if (1)')
            elif name=='eager-decode-allocation':
                replace(source,'    /* Validate the ENTIRE layout before creating any owned result leaf. */', '    leaves[0].data = (uint8_t *)malloc(1); /* deliberately too early */')
            elif name=='forward-cpp-staging':
                lines=[f'        ::spx_pg_owned_bytes_free(&c_input.{n});\n' for n in fields]
                replace(header,''.join(reversed(lines)),''.join(lines))
            elif name=='lost-move-owner':
                replace(header,'if (!close_checked()) return *this;', '(void)close_checked();')
            elif name=='sticky-cpp-injection':
                replace(header,'~InjectionScope() noexcept { ::spx_pg_consumer_test_clear_failure_injection(); }', '~InjectionScope() noexcept { (void)0; }')
            binaries=build(work,args.cc,args.cxx,['-O2'])
            failed=subprocess.run([str(binaries[route]),case_id,str(work/'mutant.bin')],cwd=work,capture_output=True,text=True,timeout=60)
            require(failed.returncode!=0 and assertion in failed.stderr, f'wrong-mutation-failure:{name}:{failed.stderr}')
            print(f'{name}: baseline passed; compiled mutant rejected by {assertion}',flush=True)
    print(f'{len(tests)} compiled semantic mutants rejected by their intended assertions')

if __name__=='__main__': main()
