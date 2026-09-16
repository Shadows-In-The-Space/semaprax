#!/usr/bin/env python3
"""Closed, independently expected caller settlement cases (test-only v1).

The same logical/physical IDs drive both clients. Caller-owned allocations
have route-local ordinals; they are never relabelled as provider events.
"""
from __future__ import annotations
from functools import lru_cache
import struct
from public_generic_settlement_evidence import canonical, digest, require

SCHEMA = 'semaprax.public-generic-consumer-settlement-corpus.v1'
PROFILE = 'flat-owned-bytes-reference-fixture.v1'
PARAMS = ['recipe', 'logical', 'phase', 'phase_leaf', 'release_leaf', 'export_mutation',
          'client_failure', 'input_mutation', 'expected_status', 'expected_native', 'expected_release', 'endpoint']


def cases() -> list[dict]:
    result = []
    def add(name, *, fields=2, routes=('c11', 'cpp17'), **changes):
        row = dict(recipe=0, logical=-1, phase=-1, phase_leaf=-1, release_leaf=-1,
                   export_mutation=0, client_failure=0, input_mutation=0,
                   expected_status=0, expected_native=0, expected_release=0, endpoint=1)
        require(set(changes) <= set(PARAMS), 'unknown-case-parameter')
        row.update(changes)
        row = dict(case_id=name, fields=fields, routes=list(routes), **row)
        row['input_digest'] = digest(SCHEMA + '/input', carrier(fields, row['recipe'], False))
        row['result_digest'] = digest(SCHEMA + '/result', carrier(fields, row['recipe'], True)) if row['expected_status'] == 0 else None
        result.append(row)
    add('minimal', fields=1)
    add('two_leaves_embedded_zero')
    add('all_empty', recipe=1)
    add('empty_then_nonempty', recipe=2)
    add('max_leaf', fields=1, recipe=3)
    add('max_total_and_leaf_count', fields=256, recipe=3)
    add('first_over_leaf', recipe=4, expected_status=4, endpoint=0)
    add('close_refusal_then_retry', input_mutation=20)
    add('local_refusal_clears_injection', input_mutation=22)
    add('cpp_move_retains_both_owners_on_close_refusal', routes=('cpp17',), input_mutation=23)
    add('partial_decoder_two_completed_leaves', fields=3, client_failure=5, expected_status=7)
    add('cpp_staging_two_completed_leaves', fields=3, routes=('cpp17',), client_failure=102, expected_status=7, endpoint=0)
    add('eight_independent_calls', input_mutation=21, endpoint=8)
    for name, mutation, status in [('missing_payload',1,3),('noncanonical_empty',2,3),
                                  ('duplicate_owner',3,3),('size_max',4,4),
                                  ('null_client',5,8),('null_output',6,8),('null_input',7,8)]:
        add(name, routes=('c11',), input_mutation=mutation, expected_status=status, endpoint=0)
    for name, mutation, status in [('wrong_descriptor',10,1),('wrong_binding',11,2),('client_open_allocation',12,7)]:
        add(name, input_mutation=mutation, expected_status=status, endpoint=0)
    # Independently pinned normalized native statuses from Logical Carrier v1.
    native = [10, 10, 10, 10, 10, 7, 11, 11, 10, 10, 11, 11, 11, 11]
    for ordinal, raw in enumerate(native):
        # Prepare maps malformed carrier to CarrierRejected and capacities to
        # CapacityExceeded; allocation/contract remains ExecutionFailed.
        status = 3 if ordinal == 5 else 5
        add(f'logical_{ordinal:02}', logical=ordinal, expected_status=status,
            expected_native=raw, endpoint=int(ordinal >= 7))
    for recipe in [0, 1, 2]:
        for phase in range(7):
            leaves = range(2) if phase in [0,1,2,6] else [-1]
            for leaf in leaves:
                raw = 10 if phase in [0,1] else 11
                add(f'physical_r{recipe}_p{phase}_l{leaf + 1}', recipe=recipe, phase=phase,
                    phase_leaf=leaf, expected_status=5, expected_native=raw)
        for leaf in range(2):
            add(f'release_r{recipe}_l{leaf}', recipe=recipe, release_leaf=leaf,
                expected_status=9, expected_native=11, expected_release=11)
    # Result-staging cleanup must never turn AllocationFailure into success
    # or ContractFailure. The native call retains secondary cleanup evidence.
    for phase in [0,1,2,3,4]:
        leaf = 1 if phase < 3 else -1
        release = 0 if phase == 0 else 1
        add(f'staging_and_release_p{phase}', phase=phase, phase_leaf=leaf, release_leaf=release,
            expected_status=5, expected_native=10 if phase < 2 else 11)
    for mutation in range(1, 11):
        for cleanup in [False, True]:
            add(f'hostile_export_{mutation}_cleanup_{int(cleanup)}', export_mutation=mutation,
                release_leaf=1 if cleanup else -1, expected_status=6,
                expected_release=11 if cleanup else 0)
    for failure in [1,2,3,4]:
        for cleanup in [False,True] if failure > 1 else [False]:
            add(f'client_allocation_{failure}_cleanup_{int(cleanup)}', client_failure=failure,
                release_leaf=1 if cleanup else -1, expected_status=7,
                expected_release=11 if cleanup else 0, endpoint=int(failure > 1))
    for ordinal in [100,101]:
        add(f'cpp_staging_allocation_{ordinal - 99}', routes=('cpp17',), client_failure=ordinal,
            expected_status=7, endpoint=0)
    # Consumer copy-out failure after commit must retain both statuses.
    for phase in [5,6]:
        add(f'export_and_release_p{phase}', phase=phase, phase_leaf=0 if phase == 6 else -1,
            release_leaf=1, expected_status=5, expected_native=11, expected_release=11)
    require(len({c['case_id'] for c in result}) == len(result), 'duplicate-case')
    return result


@lru_cache(maxsize=16)
def carrier(fields: int, recipe: int, reverse: bool) -> bytes:
    require(1 <= fields <= 256 and 0 <= recipe <= 4, 'recipe-bound')
    parts = [struct.pack('<Q', fields)]
    for leaf in range(fields):
        size = (0 if recipe == 1 or (recipe == 2 and leaf == 0) else
                65536 if recipe == 3 else 65537 if recipe == 4 and leaf == 0 else 5 + leaf % 3)
        # Pattern has period lcm(3,256); no C-string assumptions.
        pattern = bytes(0 if i % 3 == 0 else (leaf * 31 + i * 17) & 255 for i in range(768))
        payload = (pattern * ((size + 767) // 768))[:size]
        parts += [struct.pack('<Q', size), payload[::-1] if reverse else payload]
    return b''.join(parts)


def manifest() -> dict:
    return dict(schema=SCHEMA, profile=PROFILE, routes=['c11','cpp17'],
                synchronous=True, cancellation=False, cases=cases())


def cases_header(rows: list[dict]) -> str:
    return ('static const struct consumer_case cases[] = {\n' + ''.join(
        '    {"' + row['case_id'] + '",' + ','.join(str(row[k]) for k in PARAMS) + '},\n'
        for row in rows) + '};\n')


if __name__ == '__main__':
    import sys
    sys.stdout.buffer.write(canonical(manifest()))
