#!/usr/bin/env python3
"""Compiled negative controls: deliberately break generated host-call assets.

A mutant counts only when strict tsc succeeds and the selected named runtime
assertion rejects it. Compile failures, timeouts and arbitrary exceptions fail
this gate rather than being counted as caught behavioral defects.
"""
from __future__ import annotations
import argparse
import os
from pathlib import Path
import subprocess
import sys
import tempfile

from public_generic_typescript_fixture import render, wasm_bytes
from public_generic_typescript_settlement import ROOT, TESTS, run
from public_generic_settlement_evidence import canonical, digest, require

PROVIDER='src/wasm-provider.ts'
DESCRIPTOR='src/descriptor.ts'
CARRIER='src/carrier.ts'
MUTATIONS=[
    ('skip-module-digest',PROVIDER,[('await verifyModuleArtifactDigest(bytes);','void verifyModuleArtifactDigest; // intentionally omit authentication')],'module-digest-refused'),
    ('mutable-module-alias',PROVIDER,[('const bytes = snapshotModuleBytes(moduleOrBytes);','const bytes = (void snapshotModuleBytes, moduleOrBytes as Uint8Array);')],'module-snapshot-before-await'),
    ('mutable-descriptor-authority',DESCRIPTOR,[('EXPECTED_DESCRIPTOR_BYTES = TRUSTED_DESCRIPTOR_BYTES.slice()','EXPECTED_DESCRIPTOR_BYTES = TRUSTED_DESCRIPTOR_BYTES')],'private-descriptor-authority'),
    ('mutable-binding-authority',DESCRIPTOR,[('EXPECTED_BINDING_BYTES = TRUSTED_BINDING_BYTES.slice()','EXPECTED_BINDING_BYTES = TRUSTED_BINDING_BYTES')],'private-binding-authority'),
    ('execute-input-getter',CARRIER,[('if (!property || !("value" in property)) throw inputRejected("input-field");','if (!property) throw inputRejected("input-field");'),
        ('leaves.push(byteView(property.value));','leaves.push(byteView(Reflect.get(value, name)));')],'input-getter-not-executed'),
    ('unhit-injection-carryover',PROVIDER,[('this.#armed = []; this.#armedLegacy = null;','this.#armed = []; // intentionally retain armed legacy failure')],'input-local-failure-clears-injection'),
    ('suppress-release-primary',PROVIDER,[('if (!primary) return cleanup;','if (!primary) return null;')],'cleanup-primary-and-secondary'),
    ('overwrite-earlier-primary',PROVIDER,[('primary.recordSecondaryCleanup(status); this.#secondary.push(status);\n    return primary;',
        'primary.recordSecondaryCleanup(status); this.#secondary.push(status);\n    return cleanup;')],'cleanup-primary-and-secondary'),
    ('skip-physical-zeroing',PROVIDER,[('this.view().fill(0, span.offset, span.offset + span.length);','// intentionally skip physical zeroing')],'input-buffer-lifetime'),
    ('publish-wrong-result',PROVIDER,[('this.#event("result-prepared");',
        'this.#allocator.view()[resultSpan.length - 1] = (this.#allocator.view()[resultSpan.length - 1] ?? 0) ^ 1;\n      this.#event("result-prepared");')],'module-snapshot-before-await'),
    ('copy-before-full-frame-validation',CARRIER,[('const spans = locateLeaves(checked, expectedCount);',
        'const premature = checked.slice(16, 17); void premature;\n  const spans = locateLeaves(checked, expectedCount);')],'codec-last-leaf-preflight'),
    ('wrong-trace-bound',PROVIDER,[('const MAX_TRACE_EVENTS = 4096;','const MAX_TRACE_EVENTS = 4095;')],'trace-bound-cleanup'),
]


def execute(node: str, tsc: str) -> list[dict]:
    require(run([tsc,'--version'],ROOT).strip()=='Version 5.8.3','required-typescript-5.8.3')
    results=[]
    with tempfile.TemporaryDirectory(prefix='spx-ts-mutants-') as tmp:
        baseline=Path(tmp)/'positive-control'
        for name,text in render(2,wasm_bytes()).items():
            path=baseline/name;path.parent.mkdir(parents=True,exist_ok=True)
            path.write_text(text,encoding='utf-8',newline='\n')
        (baseline/'reference.wasm').write_bytes(wasm_bytes())
        run([tsc,'-p','tsconfig.json'],baseline)
        run([node,str(TESTS/'hostility.mjs'),str(baseline)],ROOT)
        print('Unmodified positive control: typechecked; all 32 host groups passed',flush=True)
        for label,path,edits,case in MUTATIONS:
            work=Path(tmp)/label
            files=render(2,wasm_bytes())
            for old,new in edits:
                require(old in files[path],f'stale-mutation:{label}')
                files[path]=files[path].replace(old,new,1)
            for name,text in files.items():
                file=work/name;file.parent.mkdir(parents=True,exist_ok=True)
                file.write_text(text,encoding='utf-8',newline='\n')
            (work/'reference.wasm').write_bytes(wasm_bytes())
            # A compile failure is NOT a successful negative control.
            run([tsc,'-p','tsconfig.json'],work)
            output=subprocess.run([node,str(TESTS/'hostility.mjs'),str(work),'host',case],
                cwd=ROOT,text=True,capture_output=True,timeout=30)
            require(output.returncode!=0 and 'AssertionError [ERR_ASSERTION]' in output.stderr
                and case+':' in output.stderr,f'wrong-mutation-failure:{label}\n{output.stdout}\n{output.stderr}')
            results.append(dict(mutation_id=label,case_id=case,typechecked=True,rejected_by_assertion=True,
                mutated_source_digest=digest('semaprax.public-generic-typescript-mutant.v1',files[path].encode('utf-8'))))
            print(f'{label}: typechecked; named {case} assertion rejected mutant',flush=True)
    return results


def main() -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--node',default=os.environ.get('NODE','node'))
    parser.add_argument('--tsc',default=os.environ.get('SPX_PG_TSC',os.environ.get('TSC','tsc')))
    parser.add_argument('--output',type=Path)
    args=parser.parse_args()
    try:
        rows=execute(args.node,args.tsc)
        if args.output:
            args.output.parent.mkdir(parents=True,exist_ok=True)
            args.output.write_bytes(canonical(rows))
        print(f'{len(rows)} independently compiled behavioral mutants rejected')
        return 0
    except (ValueError,OSError,subprocess.TimeoutExpired) as error:
        print(str(error),file=sys.stderr)
        return 1

if __name__=='__main__':raise SystemExit(main())
